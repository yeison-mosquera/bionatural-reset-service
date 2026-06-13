require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const https = require('https');

const app = express();
app.use(express.json());
app.use(cors({ origin: true, credentials: true }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ── Migración automática al iniciar ──────────────────────────────────────────
async function runMigrations() {
  // Tabla password_reset_codes
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS password_reset_codes (
        id         SERIAL PRIMARY KEY,
        email      TEXT NOT NULL,
        "codeHash" TEXT NOT NULL,
        "expiresAt" TIMESTAMPTZ NOT NULL,
        used       BOOLEAN NOT NULL DEFAULT false,
        "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    console.log('✅ Migración OK: tabla password_reset_codes verificada');
  } catch (e) {
    console.error('⚠️  Migración password_reset_codes:', e.message);
  }

  // Columna fcm_token en users
  try {
    await pool.query(`
      ALTER TABLE users
      ADD COLUMN IF NOT EXISTS fcm_token TEXT
    `);
    console.log('✅ Migración OK: columna fcm_token verificada en users');
  } catch (e) {
    console.error('⚠️  Migración fcm_token:', e.message);
  }
}

// ── Explorar DB ───────────────────────────────────────────────────────────────
app.get('/db-tables', async (req, res) => {
  const r = await pool.query(`SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY table_name`);
  res.json(r.rows);
});

app.get('/db-columns/:table', async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT column_name, data_type FROM information_schema.columns WHERE table_name=$1 ORDER BY ordinal_position`,
      [req.params.table]
    );
    res.json(r.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/notifications/send', async (req, res) => {
  const { token, title, body, data } = req.body;
  if (!token || !title || !body) {
    return res.status(400).json({ success: false, message: 'token, title y body requeridos' });
  }

  const fcmServerKey = process.env.FCM_SERVER_KEY;
  if (!fcmServerKey) {
    return res.status(500).json({ success: false, message: 'FCM_SERVER_KEY no configurada en .env' });
  }

  const payload = JSON.stringify({
    to: token,
    notification: { title, body, sound: 'default' },
    data: data || {},
    priority: 'high',
  });

  const options = {
    hostname: 'fcm.googleapis.com',
    path: '/fcm/send',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `key=${fcmServerKey}`,
      'Content-Length': Buffer.byteLength(payload),
    },
  };

  const fcmReq = https.request(options, (fcmRes) => {
    let data = '';
    fcmRes.on('data', chunk => data += chunk);
    fcmRes.on('end', () => {
      const result = JSON.parse(data);
      if (result.success > 0) {
        console.log(`Notificación enviada a token: ${token.substring(0, 20)}...`);
        res.json({ success: true, result });
      } else {
        console.error('FCM error:', result);
        res.status(400).json({ success: false, result });
      }
    });
  });

  fcmReq.on('error', (e) => {
    console.error('Error FCM:', e.message);
    res.status(500).json({ success: false, message: e.message });
  });

  fcmReq.write(payload);
  fcmReq.end();
});

// ── Obtener FCM token de un cliente por email ─────────────────────────────────
app.get('/api/notifications/token/:email', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT fcm_token FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1',
      [req.params.email]
    );
    if (result.rows.length === 0 || !result.rows[0].fcm_token) {
      return res.status(404).json({ success: false, message: 'Token no encontrado' });
    }
    res.json({ success: true, token: result.rows[0].fcm_token });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ── Guardar FCM token del dispositivo ────────────────────────────────────────
app.post('/api/notifications/register-token', async (req, res) => {
  const { email, fcmToken } = req.body;
  if (!email || !fcmToken) {
    return res.status(400).json({ success: false, message: 'email y fcmToken requeridos' });
  }
  try {
    await pool.query(
      'UPDATE users SET fcm_token = $1, "updatedAt" = NOW() WHERE LOWER(email) = LOWER($2)',
      [fcmToken, email]
    );
    console.log(`Token FCM registrado para ${email}`);
    res.json({ success: true, message: 'Token registrado' });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ── Forgot Password: genera OTP, lo guarda en DB y envía email con Brevo ─────
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ success: false, message: 'email requerido' });
  }

  try {
    // Verificar que el usuario existe
    const userResult = await pool.query(
      'SELECT id FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1',
      [email]
    );
    if (userResult.rows.length === 0) {
      // Respuesta genérica por seguridad (no revelar si el correo existe)
      return res.json({ success: true, message: 'Si el correo existe, recibirás un código.' });
    }

    // Generar código de 6 dígitos
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const codeHash = await bcrypt.hash(code, 10);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutos

    // Borrar códigos anteriores del mismo email
    await pool.query('DELETE FROM password_reset_codes WHERE email = $1', [email.toLowerCase()]);

    // Guardar nuevo código hasheado
    await pool.query(
      'INSERT INTO password_reset_codes (email, "codeHash", "expiresAt", used, "createdAt") VALUES ($1, $2, $3, false, NOW())',
      [email.toLowerCase(), codeHash, expiresAt]
    );

    // Enviar email con Brevo
    const brevoApiKey = process.env.BREVO_API_KEY;
    const fromEmail   = process.env.EMAIL_FROM || 'biosoft28@gmail.com';
    const fromName    = process.env.EMAIL_FROM_NAME || 'BioNatural';

    if (!brevoApiKey) {
      console.error('BREVO_API_KEY no configurada');
      return res.status(500).json({ success: false, message: 'Servicio de email no configurado' });
    }

    const emailPayload = JSON.stringify({
      sender:      { name: fromName, email: fromEmail },
      to:          [{ email: email }],
      subject:     'Código de recuperación - BioNatural',
      htmlContent: `
        <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;padding:32px;background:#f8fafb;border-radius:16px;">
          <div style="text-align:center;margin-bottom:20px;">
            <h1 style="color:#1F7A34;margin:0;">🌿 BioNatural</h1>
          </div>
          <div style="background:#fff;border-radius:12px;padding:28px;">
            <h2 style="color:#0F172A;margin-top:0;">Recupera tu contraseña</h2>
            <p style="color:#475569;">Usa este código en la app. <strong>Expira en 15 minutos.</strong></p>
            <div style="text-align:center;margin:24px 0;">
              <span style="display:inline-block;background:#1F7A34;color:#fff;font-size:34px;font-weight:700;letter-spacing:10px;padding:16px 28px;border-radius:12px;">${code}</span>
            </div>
            <p style="color:#94A3B8;font-size:13px;text-align:center;">Si no lo solicitaste, ignora este mensaje.</p>
          </div>
        </div>
      `,
    });

    await new Promise((resolve, reject) => {
      const options = {
        hostname: 'api.brevo.com',
        path:     '/v3/smtp/email',
        method:   'POST',
        headers: {
          'accept':       'application/json',
          'content-type': 'application/json',
          'api-key':      brevoApiKey,
          'Content-Length': Buffer.byteLength(emailPayload),
        },
      };
      const req2 = https.request(options, (r) => {
        let data = '';
        r.on('data', chunk => data += chunk);
        r.on('end', () => {
          if (r.statusCode >= 300) reject(new Error(`Brevo ${r.statusCode}: ${data}`));
          else resolve(data);
        });
      });
      req2.on('error', reject);
      req2.write(emailPayload);
      req2.end();
    });

    console.log(`✅ OTP enviado a ${email}`);
    res.json({ success: true, message: 'Código enviado. Revisa tu bandeja de entrada.' });
  } catch (e) {
    console.error('forgot-password error:', e.message);
    res.status(500).json({ success: false, message: 'No se pudo enviar el código. Intenta de nuevo.' });
  }
});

// ── Guardar OTP hasheado en password_reset_codes ──────────────────────────────
// (Compatibilidad con clientes que llaman save-otp directamente)
app.post('/api/auth/save-otp', async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) {
    return res.status(400).json({ success: false, message: 'email y code requeridos' });
  }
  try {
    const codeHash = await bcrypt.hash(code, 10);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    // Borrar códigos anteriores del mismo email
    await pool.query('DELETE FROM password_reset_codes WHERE email = $1', [email.toLowerCase()]);

    // Insertar nuevo código
    await pool.query(
      'INSERT INTO password_reset_codes (email, "codeHash", "expiresAt", used, "createdAt") VALUES ($1, $2, $3, false, NOW())',
      [email.toLowerCase(), codeHash, expiresAt]
    );

    console.log(`OTP guardado para ${email}`);
    res.json({ success: true, message: 'OTP guardado' });
  } catch (e) {
    console.error('save-otp error:', e.message);
    res.status(500).json({ success: false, message: e.message });
  }
});

// ── Reset Password ─────────────────────────────────────────────────────────────
app.post('/api/auth/reset-password', async (req, res) => {
  const { email, code, password } = req.body;
  if (!email || !code || !password) {
    return res.status(400).json({ success: false, message: 'email, code y password requeridos' });
  }
  try {
    // Buscar código activo para ese email
    const codeResult = await pool.query(
      'SELECT * FROM password_reset_codes WHERE email = $1 AND used = false ORDER BY "createdAt" DESC LIMIT 1',
      [email.toLowerCase()]
    );

    if (codeResult.rows.length === 0) {
      return res.status(400).json({ success: false, message: 'No hay un código activo para este correo' });
    }

    const record = codeResult.rows[0];

    // Verificar expiración
    if (new Date(record.expiresAt) < new Date()) {
      return res.status(400).json({ success: false, message: 'El código ha expirado. Solicita uno nuevo.' });
    }

    // Verificar código con bcrypt
    const isValid = await bcrypt.compare(code, record.codeHash);
    if (!isValid) {
      return res.status(400).json({ success: false, message: 'Código inválido' });
    }

    // Verificar que el usuario existe
    const userResult = await pool.query(
      'SELECT * FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1',
      [email]
    );
    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
    }

    // Hashear nueva contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Actualizar contraseña
    await pool.query(
      'UPDATE users SET password = $1, "updatedAt" = NOW() WHERE LOWER(email) = LOWER($2)',
      [hashedPassword, email]
    );

    // Marcar código como usado
    await pool.query(
      'UPDATE password_reset_codes SET used = true WHERE id = $1',
      [record.id]
    );

    console.log(`Contraseña actualizada para ${email}`);
    res.json({ success: true, message: 'Contraseña actualizada correctamente' });
  } catch (e) {
    console.error('reset-password error:', e.message);
    res.status(500).json({ success: false, message: e.message });
  }
});

app.get('/health', (_, res) => res.json({ status: 'OK', service: 'BioNatural Reset Service', port: 3001 }));

// Ejecutar migraciones y luego iniciar el servidor
const PORT = process.env.PORT || 3001;
runMigrations().then(() => {
  app.listen(PORT, () => {
    console.log(`🌿 BioNatural Reset Service en http://localhost:${PORT}`);
    console.log('  POST /api/auth/save-otp                  — guarda OTP en DB');
    console.log('  POST /api/auth/reset-password            — verifica OTP y cambia contraseña');
    console.log('  POST /api/notifications/register-token   — guarda token FCM del cliente');
    console.log('  POST /api/notifications/send             — envía push via FCM');
    console.log('  GET  /api/notifications/token/:email     — obtiene token FCM de un cliente');
  });
});
