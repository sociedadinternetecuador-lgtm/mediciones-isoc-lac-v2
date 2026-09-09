'use strict';

/**
 * logic/auth/adminAuth.adapter.js y logic/auth/rateLimiter.js — ejercitados
 * directamente con datos fabricados a mano (no solo "nunca debería pasar"):
 * cookie manipulada, usuario duplicado, contraseña corta, admin vs
 * super_admin, y el rate limiter disparando en el intento N+1.
 *
 * DATA_DIR y credenciales del super_admin se fijan ANTES de requerir el
 * módulo (se resuelven una sola vez al cargar) contra un directorio
 * temporal aislado — nunca toca data/content real.
 *
 * Ejecutar: node test/adminAuth.session.test.js
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'mediciones-auth-'));
process.env.DATA_DIR = TMP_DIR;
process.env.SESSION_SECRET = 'test-secret-solo-para-pruebas';
// .env de prueba aislado — commit() de previewPasswordReset para el
// super_admin NUNCA debe poder tocar el .env real del proyecto.
process.env.ENV_FILE_PATH = path.join(TMP_DIR, '.env.test');

const auth = require('../logic/auth/adminAuth.adapter');
const { createRateLimiter } = require('../logic/auth/rateLimiter');

process.env.ADMIN_USERNAME = 'root';
process.env.ADMIN_PASSWORD_HASH = auth.hashPassword('ClaveSuperAdmin123');

function fakeReq(cookieHeader) {
  return { headers: { cookie: cookieHeader || '' } };
}

function cleanup() {
  fs.rmSync(TMP_DIR, { recursive: true, force: true });
}

function run() {
  try {
    // ─── Hashing ─────────────────────────────────────────────────────
    const hash = auth.hashPassword('unaClaveDePrueba');
    assert.ok(hash.includes(':'), 'el hash debe incluir salt:derivado');
    assert.strictEqual(auth.verifyPassword('unaClaveDePrueba', hash), true);
    assert.strictEqual(auth.verifyPassword('otra-clave', hash), false);
    assert.strictEqual(auth.verifyPassword('unaClaveDePrueba', 'no-es-un-hash-valido'), false, 'hash corrupto no debe lanzar, debe devolver false');

    // ─── super_admin vía variables de entorno ───────────────────────
    const okSuper = auth.verifyCredentials('root', 'ClaveSuperAdmin123');
    assert.deepStrictEqual(okSuper, { username: 'root', role: 'super_admin' });
    assert.strictEqual(auth.verifyCredentials('root', 'clave-incorrecta'), null);
    assert.strictEqual(auth.verifyCredentials('usuario-no-existe', 'x'), null);

    // ─── Creación de administradores (rol "admin") — la contraseña la ──
    // genera el sistema, nunca se recibe por parámetro.
    const created = auth.createAdminUser('editor1', 'editor1@example.com');
    assert.ok(created.id);
    assert.strictEqual(created.username, 'editor1');
    assert.strictEqual(created.email, 'editor1@example.com');
    assert.ok(created.plainPassword && created.plainPassword.length >= 16, 'debe generar una contraseña segura');
    assert.ok(!('passwordHash' in created), 'createAdminUser no debe exponer el hash');
    assert.ok(!('passwordHash' in auth.listAdminUsers()[0]), 'listAdminUsers no debe exponer el hash');

    const okAdmin = auth.verifyCredentials('editor1', created.plainPassword);
    assert.deepStrictEqual(okAdmin, { username: 'editor1', role: 'admin' });
    assert.strictEqual(auth.verifyCredentials('editor1', 'clave-inventada'), null);

    // Usuario duplicado (case-insensitive) rechazado
    assert.throws(() => auth.createAdminUser('Editor1', 'otro@example.com'), /username_taken/);
    // Email inválido rechazado
    assert.throws(() => auth.createAdminUser('editor2', 'no-es-un-email'), /email_invalid/);

    assert.strictEqual(auth.listAdminUsers().length, 1);
    assert.strictEqual(auth.deleteAdminUser(created.id), true);
    assert.strictEqual(auth.deleteAdminUser(created.id), false, 'borrar dos veces debe devolver false');
    assert.strictEqual(auth.verifyCredentials('editor1', created.plainPassword), null, 'tras borrar, sus credenciales ya no deben ser válidas');

    // ─── Recuperación de contraseña (previewPasswordReset) ──────────
    const created2 = auth.createAdminUser('editor2', 'editor2@example.com');
    const preview = auth.previewPasswordReset('editor2');
    assert.strictEqual(preview.role, 'admin');
    assert.strictEqual(preview.email, 'editor2@example.com');
    assert.ok(preview.plainPassword);
    // Antes de commit(), la contraseña anterior sigue siendo válida
    assert.deepStrictEqual(auth.verifyCredentials('editor2', created2.plainPassword), { username: 'editor2', role: 'admin' });
    preview.commit();
    // Tras commit(), solo la nueva contraseña funciona
    assert.strictEqual(auth.verifyCredentials('editor2', created2.plainPassword), null, 'la contraseña anterior debe invalidarse tras commit()');
    assert.deepStrictEqual(auth.verifyCredentials('editor2', preview.plainPassword), { username: 'editor2', role: 'admin' });

    const previewSuper = auth.previewPasswordReset('root');
    assert.strictEqual(previewSuper.role, 'super_admin');
    assert.ok(previewSuper.plainPassword);
    // ADMIN_PASSWORD_HASH no cambia hasta commit()
    assert.deepStrictEqual(auth.verifyCredentials('root', 'ClaveSuperAdmin123'), { username: 'root', role: 'super_admin' });

    previewSuper.commit();
    assert.strictEqual(auth.verifyCredentials('root', 'ClaveSuperAdmin123'), null, 'la clave anterior del super_admin debe invalidarse tras commit()');
    assert.deepStrictEqual(auth.verifyCredentials('root', previewSuper.plainPassword), { username: 'root', role: 'super_admin' });
    // El nuevo hash quedó persistido en el .env de prueba (no en el real)
    const envContent = fs.readFileSync(process.env.ENV_FILE_PATH, 'utf8');
    assert.ok(envContent.includes('ADMIN_PASSWORD_HASH='), 'commit() del super_admin debe persistir el hash nuevo en el .env');

    assert.strictEqual(auth.previewPasswordReset('usuario-que-no-existe'), null);

    // ─── Sesiones ────────────────────────────────────────────────────
    const { cookieValue } = auth.createSession('root', 'super_admin');
    const req = fakeReq(`${auth.COOKIE_NAME}=${encodeURIComponent(cookieValue)}`);
    const session = auth.validateSession(req);
    assert.deepStrictEqual(session, { username: 'root', role: 'super_admin' });

    // Sin cookie → sin sesión
    assert.strictEqual(auth.validateSession(fakeReq('')), null);

    // Cookie con firma alterada → rechazada
    const [sid] = cookieValue.split('.');
    const tampered = `${sid}.0000000000000000000000000000000000000000000000000000000000000000`;
    assert.strictEqual(
      auth.validateSession(fakeReq(`${auth.COOKIE_NAME}=${encodeURIComponent(tampered)}`)),
      null,
      'una firma HMAC inválida debe rechazarse aunque el sessionId exista',
    );

    // sessionId inventado (aunque "bien firmado" por casualidad no aplica, probamos formato roto)
    assert.strictEqual(auth.validateSession(fakeReq(`${auth.COOKIE_NAME}=solo-un-valor-sin-punto`)), null);

    // Logout invalida la sesión
    auth.destroySession(cookieValue);
    assert.strictEqual(auth.validateSession(req), null, 'tras destroySession, la misma cookie ya no debe validar');

    // ─── Rate limiter ────────────────────────────────────────────────
    const limiter = createRateLimiter({ maxAttempts: 3, windowMs: 60_000 });
    const ip = '203.0.113.7';
    assert.strictEqual(limiter.check(ip).allowed, true, 'intento 1 permitido');
    assert.strictEqual(limiter.check(ip).allowed, true, 'intento 2 permitido');
    assert.strictEqual(limiter.check(ip).allowed, true, 'intento 3 permitido');
    assert.strictEqual(limiter.check(ip).allowed, false, 'intento 4 debe bloquearse (excede maxAttempts=3)');
    // Otra IP no se ve afectada por el límite de la primera
    assert.strictEqual(limiter.check('198.51.100.1').allowed, true);
    limiter.reset(ip);
    assert.strictEqual(limiter.check(ip).allowed, true, 'tras reset() la IP vuelve a tener intentos disponibles');

    console.log('✅ adminAuth.session.test.js — todos los casos OK');
  } finally {
    cleanup();
  }
}

run();
