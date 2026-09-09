'use strict';

/**
 * Autenticación de administración — Mediciones ISOC LAC.
 *
 * Dos roles, sin base de datos:
 *   - super_admin: UNA sola cuenta, credenciales fijas en variables de
 *     entorno (ADMIN_USERNAME / ADMIN_PASSWORD_HASH). No se puede crear,
 *     editar ni borrar desde el panel — es el usuario "de arranque".
 *   - admin: cuentas adicionales creadas por el super_admin, persistidas en
 *     data/content/admin_users.json (mismo patrón que contentStore.adapter).
 *     Pueden gestionar Blog/Eventos/Materiales pero NO usuarios.
 *
 * Sesión: cookie HttpOnly firmada con HMAC-SHA256 (SESSION_SECRET) + Map en
 * memoria de sesiones activas (aceptable perderlas en un reinicio del
 * proceso, igual que los jobs de validación DNS — el admin vuelve a
 * loguearse). Contraseñas con scrypt + comparación timing-safe.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR, 'content')
  : path.resolve(__dirname, '../../data/content');

const USERS_PATH = path.join(DATA_DIR, 'admin_users.json');
const ENV_PATH = process.env.ENV_FILE_PATH || path.resolve(__dirname, '../../.env');

const PASSWORD_CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*';

// ─── Generación de contraseñas seguras ─────────────────────────────────────

function generateSecurePassword(length = 20) {
  const bytes = crypto.randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i += 1) {
    out += PASSWORD_CHARSET[bytes[i] % PASSWORD_CHARSET.length];
  }
  return out;
}

const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 horas
const COOKIE_NAME = 'mediciones_admin_sid';

const sessions = new Map(); // sessionId -> { username, role, expiresAt }

function ensureDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

// ─── Hashing de contraseñas ─────────────────────────────────────────────────

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password, salt, 64);
  return `${salt.toString('hex')}:${derived.toString('hex')}`;
}

function verifyPassword(password, storedHash) {
  if (!storedHash || typeof storedHash !== 'string' || !storedHash.includes(':')) return false;
  const [saltHex, hashHex] = storedHash.split(':');
  try {
    const salt = Buffer.from(saltHex, 'hex');
    const expected = Buffer.from(hashHex, 'hex');
    const derived = crypto.scryptSync(password, salt, expected.length);
    return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}

// ─── Usuarios admin (rol "admin", creados por el super_admin) ─────────────

function readUsers() {
  ensureDir();
  try {
    return JSON.parse(fs.readFileSync(USERS_PATH, 'utf8'));
  } catch {
    return [];
  }
}

function writeUsers(users) {
  ensureDir();
  fs.writeFileSync(USERS_PATH, JSON.stringify(users, null, 2));
}

function listAdminUsers() {
  return readUsers().map(({ id, username, email, createdAt }) => ({ id, username, email, createdAt }));
}

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function createAdminUser(username, email) {
  const users = readUsers();
  const normalizedUser = String(username || '').trim();
  const normalizedEmail = String(email || '').trim().toLowerCase();
  if (!normalizedUser) throw new Error('username_required');
  if (!normalizedEmail || !EMAIL_REGEX.test(normalizedEmail)) throw new Error('email_invalid');
  if (users.some((u) => u.username.toLowerCase() === normalizedUser.toLowerCase())) {
    throw new Error('username_taken');
  }

  const plainPassword = generateSecurePassword();
  const user = {
    id: crypto.randomUUID(),
    username: normalizedUser,
    email: normalizedEmail,
    passwordHash: hashPassword(plainPassword),
    createdAt: new Date().toISOString(),
  };
  users.push(user);
  writeUsers(users);
  return { id: user.id, username: user.username, email: user.email, createdAt: user.createdAt, plainPassword };
}

function deleteAdminUser(id) {
  const users = readUsers();
  const next = users.filter((u) => u.id !== id);
  if (next.length === users.length) return false;
  writeUsers(next);
  return true;
}

// ─── Recuperación / rotación de contraseña ─────────────────────────────────
// Genera una contraseña nueva y la persiste. Para el super_admin reescribe
// ADMIN_PASSWORD_HASH en el .env (en memoria y en disco, para que sobreviva
// un reinicio); para un admin normal actualiza su registro en
// admin_users.json. No envía el correo — eso es responsabilidad de la ruta,
// que conoce a qué dirección notificar en cada caso.

function updateSuperAdminPasswordHash(newHash) {
  process.env.ADMIN_PASSWORD_HASH = newHash;
  let lines = [];
  try {
    lines = fs.readFileSync(ENV_PATH, 'utf8').split('\n');
  } catch {
    lines = [];
  }
  let found = false;
  const next = lines.map((line) => {
    if (/^ADMIN_PASSWORD_HASH=/.test(line)) {
      found = true;
      return `ADMIN_PASSWORD_HASH=${newHash}`;
    }
    return line;
  });
  if (!found) next.push(`ADMIN_PASSWORD_HASH=${newHash}`);
  fs.writeFileSync(ENV_PATH, next.join('\n'));
}

// Devuelve la contraseña nueva y un commit() para persistirla — separado a
// propósito: la ruta debe confirmar que el correo de aviso salió ANTES de
// invalidar la contraseña anterior, para no dejar la cuenta bloqueada sin
// que nadie conozca la contraseña nueva si el envío de correo falla.
function previewPasswordReset(username) {
  const normalized = String(username || '').trim();
  if (!normalized) return null;

  const superUsername = process.env.ADMIN_USERNAME || '';
  if (superUsername && normalized.toLowerCase() === superUsername.toLowerCase()) {
    const plainPassword = generateSecurePassword();
    return {
      role: 'super_admin',
      username: superUsername,
      plainPassword,
      commit: () => updateSuperAdminPasswordHash(hashPassword(plainPassword)),
    };
  }

  const users = readUsers();
  const idx = users.findIndex((u) => u.username.toLowerCase() === normalized.toLowerCase());
  if (idx === -1) return null;

  const plainPassword = generateSecurePassword();
  return {
    role: 'admin',
    username: users[idx].username,
    email: users[idx].email,
    plainPassword,
    commit: () => {
      const fresh = readUsers();
      const freshIdx = fresh.findIndex((u) => u.id === users[idx].id);
      if (freshIdx === -1) return;
      fresh[freshIdx] = { ...fresh[freshIdx], passwordHash: hashPassword(plainPassword) };
      writeUsers(fresh);
    },
  };
}

// ─── Verificación de credenciales ───────────────────────────────────────────

function verifyCredentials(username, password) {
  const normalized = String(username || '').trim();
  if (!normalized || !password) return null;

  const superUsername = process.env.ADMIN_USERNAME || '';
  const superHash = process.env.ADMIN_PASSWORD_HASH || '';
  if (superUsername && superHash && normalized.toLowerCase() === superUsername.toLowerCase()) {
    return verifyPassword(String(password), superHash)
      ? { username: superUsername, role: 'super_admin' }
      : null;
  }

  const user = readUsers().find((u) => u.username.toLowerCase() === normalized.toLowerCase());
  if (!user) return null;
  return verifyPassword(String(password), user.passwordHash)
    ? { username: user.username, role: 'admin' }
    : null;
}

// ─── Sesiones ────────────────────────────────────────────────────────────

function sign(value) {
  const secret = process.env.SESSION_SECRET || '';
  return crypto.createHmac('sha256', secret).update(value).digest('hex');
}

function createSession(username, role) {
  const sessionId = crypto.randomUUID();
  const expiresAt = Date.now() + SESSION_TTL_MS;
  sessions.set(sessionId, { username, role, expiresAt });
  const cookieValue = `${sessionId}.${sign(sessionId)}`;
  return { cookieValue, expiresAt };
}

function destroySession(cookieValue) {
  const sessionId = parseCookieValue(cookieValue);
  if (sessionId) sessions.delete(sessionId);
}

function parseCookieValue(cookieValue) {
  if (!cookieValue || typeof cookieValue !== 'string') return null;
  const [sessionId, signature] = cookieValue.split('.');
  if (!sessionId || !signature) return null;
  const expected = sign(sessionId);
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return sessionId;
}

function getCookie(req, name) {
  const header = req.headers.cookie || '';
  const parts = header.split(';').map((p) => p.trim());
  for (const part of parts) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq) === name) return decodeURIComponent(part.slice(eq + 1));
  }
  return null;
}

function validateSession(req) {
  const cookieValue = getCookie(req, COOKIE_NAME);
  const sessionId = parseCookieValue(cookieValue);
  if (!sessionId) return null;
  const session = sessions.get(sessionId);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionId);
    return null;
  }
  return { username: session.username, role: session.role };
}

module.exports = {
  COOKIE_NAME,
  SESSION_TTL_MS,
  generateSecurePassword,
  hashPassword,
  verifyPassword,
  verifyCredentials,
  createSession,
  destroySession,
  validateSession,
  getCookie,
  listAdminUsers,
  createAdminUser,
  deleteAdminUser,
  previewPasswordReset,
};
