'use strict';

/**
 * Rutas de administración — Mediciones ISOC LAC.
 *
 *  GET  /admin                        Página de login + panel (estático).
 *  POST /admin/api/login              { username, password } -> cookie de sesión.
 *  POST /admin/api/logout             Invalida la sesión.
 *  GET  /admin/api/whoami             Sesión actual (401 si no hay).
 *  POST /admin/api/forgot-password    { username } -> genera contraseña nueva y
 *    la envía por correo (super_admin: a SUPER_ADMIN_RECOVERY_EMAIL; admin:
 *    a su email registrado). Respuesta genérica siempre, exista o no el
 *    usuario — no permite enumerar cuentas. Rate-limited.
 *
 *  GET/POST      /admin/api/content/:type        (type = blog|events|materials)
 *  PUT/DELETE    /admin/api/content/:type/:id
 *    CRUD completo (incluye borradores). Requiere sesión válida (admin o
 *    super_admin).
 *
 *  GET/POST      /admin/api/users     POST: { username, email } — la
 *    contraseña la genera el sistema y se envía por correo al email dado,
 *    nunca se recibe ni se muestra en el panel.
 *  DELETE        /admin/api/users/:id
 *    Gestión de cuentas admin. Requiere sesión con rol super_admin.
 *
 * Todas las rutas de escritura exigen sesión — sin excepciones. Sin CORS
 * (same-origin, consumido únicamente por /admin servido por este mismo
 * servidor) y sin stack traces en las respuestas de error.
 */

const fs = require('fs');
const path = require('path');
const {
  verifyCredentials, createSession, destroySession, validateSession,
  getCookie, COOKIE_NAME, SESSION_TTL_MS, listAdminUsers, createAdminUser, deleteAdminUser,
  previewPasswordReset,
} = require('../logic/auth/adminAuth.adapter');
const { createRateLimiter } = require('../logic/auth/rateLimiter');
const { validateContentInput } = require('../logic/validators/contentInput.validator');
const contentStore = require('../logic/adapters/contentStore.adapter');
// Se usa como objeto (no desestructurado) a propósito: permite a los tests
// reemplazar emailAdapter.sendMail por un stub sin tocar este módulo.
const emailAdapter = require('../logic/adapters/email.adapter');
const { injectI18nVersion } = require('../logic/adapters/i18nVersion.adapter');

const CONTENT_TYPES = new Set(['blog', 'events', 'materials']);
const MAX_BODY_BYTES = 1 * 1024 * 1024; // 1 MB — payloads de texto, sin adjuntos binarios

const loginLimiter = createRateLimiter({ maxAttempts: 5, windowMs: 15 * 60 * 1000 });
const forgotPasswordLimiter = createRateLimiter({ maxAttempts: 3, windowMs: 30 * 60 * 1000 });

// Dirección fija a la que se notifica cualquier recuperación de la cuenta
// super_admin (esa cuenta no tiene email propio, vive en variables de
// entorno) — configurable, nunca hardcodeada sin posibilidad de cambio.
const SUPER_ADMIN_RECOVERY_EMAIL = process.env.SUPER_ADMIN_RECOVERY_EMAIL || 'corpeceorg@gmail.com';

function sendJson(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}

function clientIp(req) {
  return req.socket?.remoteAddress || 'unknown';
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    let tooLarge = false;
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > MAX_BODY_BYTES) {
        tooLarge = true;
        req.destroy();
      }
    });
    req.on('end', () => {
      if (tooLarge) return reject(new Error('payload_too_large'));
      try {
        resolve(JSON.parse(data || '{}'));
      } catch {
        resolve({});
      }
    });
    req.on('error', reject);
  });
}

function requireSession(req, res) {
  const session = validateSession(req);
  if (!session) {
    sendJson(res, 401, { error: 'unauthorized' });
    return null;
  }
  return session;
}

function requireSuperAdmin(req, res) {
  const session = requireSession(req, res);
  if (!session) return null;
  if (session.role !== 'super_admin') {
    sendJson(res, 403, { error: 'forbidden', message: 'Solo el super administrador puede gestionar usuarios.' });
    return null;
  }
  return session;
}

function serveAdminPage(res) {
  const filePath = path.join(__dirname, '..', 'admin.html');
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) return sendJson(res, 500, { error: 'admin_page_not_found' });
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(injectI18nVersion(data));
  });
}

async function handleLogin(req, res) {
  const ip = clientIp(req);
  const limit = loginLimiter.check(ip);
  if (!limit.allowed) {
    return sendJson(res, 429, {
      error: 'too_many_attempts',
      message: 'Demasiados intentos de inicio de sesión. Intente de nuevo más tarde.',
    });
  }

  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return sendJson(res, 400, { error: 'invalid_body' });
  }

  const auth = verifyCredentials(body.username, body.password);
  if (!auth) {
    return sendJson(res, 401, { error: 'invalid_credentials' });
  }

  const { cookieValue } = createSession(auth.username, auth.role);
  res.setHeader('Set-Cookie',
    `${COOKIE_NAME}=${encodeURIComponent(cookieValue)}; HttpOnly;${secureFlag()} SameSite=Strict; Path=/admin; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`);
  return sendJson(res, 200, { username: auth.username, role: auth.role });
}

function handleLogout(req, res) {
  const cookieValue = getCookie(req, COOKIE_NAME);
  if (cookieValue) destroySession(cookieValue);
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=;${secureFlag()} HttpOnly; SameSite=Strict; Path=/admin; Max-Age=0`);
  return sendJson(res, 200, { ok: true });
}

// Cookie "Secure" requiere HTTPS entre navegador y origen. En producción el
// portal solo se sirve por https://mediciones.isoc.org.ec (TLS termina en el
// túnel Cloudflare) así que el navegador la respeta igual. Para pruebas
// locales por http://localhost se puede desactivar con ADMIN_COOKIE_INSECURE=1.
function secureFlag() {
  return process.env.ADMIN_COOKIE_INSECURE === '1' ? '' : ' Secure;';
}

function handleWhoami(req, res) {
  const session = validateSession(req);
  if (!session) return sendJson(res, 401, { error: 'unauthorized' });
  return sendJson(res, 200, session);
}

// Respuesta genérica SIEMPRE (exista o no el usuario) — evita que el
// endpoint sirva para enumerar nombres de usuario válidos.
const FORGOT_PASSWORD_GENERIC_RESPONSE = {
  ok: true,
  message: 'Si el usuario existe, se envió un correo con instrucciones.',
};

async function handleForgotPassword(req, res) {
  const ip = clientIp(req);
  const limit = forgotPasswordLimiter.check(ip);
  if (!limit.allowed) {
    return sendJson(res, 429, {
      error: 'too_many_attempts',
      message: 'Demasiadas solicitudes de recuperación. Intente de nuevo más tarde.',
    });
  }

  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return sendJson(res, 400, { error: 'invalid_body' });
  }

  const preview = previewPasswordReset(body.username);
  if (!preview) return sendJson(res, 200, FORGOT_PASSWORD_GENERIC_RESPONSE);

  const to = preview.role === 'super_admin' ? SUPER_ADMIN_RECOVERY_EMAIL : preview.email;
  try {
    await emailAdapter.sendMail({
      to,
      subject: 'Nueva contraseña — Administración Mediciones ISOC-LAC',
      text: `Se generó una nueva contraseña para el usuario "${preview.username}":\n\n${preview.plainPassword}\n\nInicia sesión en /admin. Si no solicitaste esto, contacta al administrador del portal.`,
    });
    // Solo se invalida la contraseña anterior si el correo salió — evita
    // dejar la cuenta sin contraseña conocida por nadie ante un fallo SMTP.
    preview.commit();
  } catch (error) {
    console.error('No se pudo enviar el correo de recuperación — contraseña anterior conservada:', error.message);
  }

  return sendJson(res, 200, FORGOT_PASSWORD_GENERIC_RESPONSE);
}

// ─── CRUD de contenido ─────────────────────────────────────────────────────

async function handleContentCollection(req, res, type) {
  if (req.method === 'GET') {
    return sendJson(res, 200, { items: contentStore.listAll(type) });
  }
  if (req.method === 'POST') {
    let body;
    try {
      body = await readJsonBody(req);
    } catch {
      return sendJson(res, 400, { error: 'invalid_body' });
    }
    const { errors, data } = validateContentInput(type, body);
    if (errors.length) return sendJson(res, 400, { error: 'validation_failed', fields: errors });
    const published = body.published === true;
    const item = contentStore.createItem(type, { ...data, published });
    return sendJson(res, 201, { item });
  }
  return sendJson(res, 405, { error: 'method_not_allowed' });
}

async function handleContentItem(req, res, type, id) {
  if (req.method === 'PUT') {
    let body;
    try {
      body = await readJsonBody(req);
    } catch {
      return sendJson(res, 400, { error: 'invalid_body' });
    }
    const existing = contentStore.getItem(type, id);
    if (!existing) return sendJson(res, 404, { error: 'not_found' });
    const { errors, data } = validateContentInput(type, { ...existing, ...body });
    if (errors.length) return sendJson(res, 400, { error: 'validation_failed', fields: errors });
    const published = typeof body.published === 'boolean' ? body.published : existing.published;
    const item = contentStore.updateItem(type, id, { ...data, published });
    return sendJson(res, 200, { item });
  }
  if (req.method === 'DELETE') {
    const ok = contentStore.deleteItem(type, id);
    if (!ok) return sendJson(res, 404, { error: 'not_found' });
    return sendJson(res, 200, { ok: true });
  }
  return sendJson(res, 405, { error: 'method_not_allowed' });
}

// ─── Gestión de usuarios admin (solo super_admin) ──────────────────────────

async function handleUsersCollection(req, res) {
  if (req.method === 'GET') {
    return sendJson(res, 200, { users: listAdminUsers() });
  }
  if (req.method === 'POST') {
    let body;
    try {
      body = await readJsonBody(req);
    } catch {
      return sendJson(res, 400, { error: 'invalid_body' });
    }
    let created;
    try {
      created = createAdminUser(body.username, body.email);
    } catch (error) {
      return sendJson(res, 400, { error: error.message || 'create_failed' });
    }

    const { plainPassword, ...user } = created;
    try {
      await emailAdapter.sendMail({
        to: user.email,
        subject: 'Acceso creado — Administración Mediciones ISOC-LAC',
        text: `Se creó una cuenta de administrador para ti en el portal Mediciones ISOC-LAC.\n\nUsuario: ${user.username}\nContraseña: ${plainPassword}\n\nInicia sesión en /admin con estos datos.`,
      });
    } catch (error) {
      // Sin correo, nadie conoce la contraseña generada — revertir la
      // creación en vez de dejar una cuenta huérfana e inutilizable.
      deleteAdminUser(user.id);
      return sendJson(res, 502, {
        error: 'email_send_failed',
        message: 'No se pudo enviar el correo con la contraseña. La cuenta no fue creada — verifique la configuración SMTP e intente de nuevo.',
      });
    }
    return sendJson(res, 201, { user });
  }
  return sendJson(res, 405, { error: 'method_not_allowed' });
}

function handleUserItem(req, res, id) {
  if (req.method === 'DELETE') {
    const ok = deleteAdminUser(id);
    if (!ok) return sendJson(res, 404, { error: 'not_found' });
    return sendJson(res, 200, { ok: true });
  }
  return sendJson(res, 405, { error: 'method_not_allowed' });
}

// ─── Router ─────────────────────────────────────────────────────────────

async function handleAdminRequest(req, res, parsed) {
  const segments = parsed.pathname.split('/').filter(Boolean); // ['admin', 'api'?, ...]

  if (segments.length === 1) {
    return serveAdminPage(res);
  }

  if (segments[1] !== 'api') {
    return sendJson(res, 404, { error: 'not_found' });
  }

  // /admin/api/login /admin/api/logout /admin/api/whoami /admin/api/forgot-password — sin sesión previa
  if (segments[2] === 'login' && req.method === 'POST') return handleLogin(req, res);
  if (segments[2] === 'logout' && req.method === 'POST') return handleLogout(req, res);
  if (segments[2] === 'whoami' && req.method === 'GET') return handleWhoami(req, res);
  if (segments[2] === 'forgot-password' && req.method === 'POST') return handleForgotPassword(req, res);

  // /admin/api/content/:type[/:id]
  if (segments[2] === 'content') {
    const session = requireSession(req, res);
    if (!session) return;
    const type = segments[3];
    const id = segments[4];
    if (!CONTENT_TYPES.has(type)) return sendJson(res, 404, { error: 'not_found' });
    if (id) return handleContentItem(req, res, type, id);
    return handleContentCollection(req, res, type);
  }

  // /admin/api/users[/:id] — solo super_admin
  if (segments[2] === 'users') {
    const session = requireSuperAdmin(req, res);
    if (!session) return;
    const id = segments[3];
    if (id) return handleUserItem(req, res, id);
    return handleUsersCollection(req, res);
  }

  return sendJson(res, 404, { error: 'not_found' });
}

module.exports = { handleAdminRequest };
