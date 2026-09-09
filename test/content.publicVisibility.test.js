'use strict';

/**
 * Prueba de extremo a extremo (servidor HTTP real, mismo patrón que
 * downloads.integrityGuard.test.js) de la separación público/administrativo:
 *
 *   - Sin sesión, /admin/api/content/* y /admin/api/users deben rechazar
 *     (401), incluso con payloads bien formados.
 *   - Un item recién creado nace en borrador y NO debe aparecer en
 *     /content/:type (público) aunque sí en /admin/api/content/:type.
 *   - Al publicarlo, debe aparecer en ambos.
 *   - Un admin (no super_admin) no puede gestionar usuarios (403).
 *
 * DATA_DIR temporal y aislado — nunca toca data/content real.
 *
 * Ejecutar: node test/content.publicVisibility.test.js
 */

const assert = require('assert');
const http = require('http');
const os = require('os');
const path = require('path');
const fs = require('fs');
const { URL } = require('url');

const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'mediciones-visibility-'));
process.env.DATA_DIR = TMP_DIR;
process.env.SESSION_SECRET = 'test-secret-solo-para-pruebas';
// La recuperación del super_admin reescribe ADMIN_PASSWORD_HASH en disco —
// jamás debe apuntar al .env real del proyecto durante un test.
process.env.ENV_FILE_PATH = path.join(TMP_DIR, '.env.test');

const { hashPassword } = require('../logic/auth/adminAuth.adapter');
process.env.ADMIN_USERNAME = 'root';
process.env.ADMIN_PASSWORD_HASH = hashPassword('ClaveSuperAdmin123');
process.env.ADMIN_COOKIE_INSECURE = '1'; // el test corre sobre http://localhost, no https

const { handleContentRequest } = require('../routes/content.routes');
const { handleAdminRequest } = require('../routes/admin.routes');

// Sin SMTP real en tests CI-safe: se reemplaza sendMail por un stub que
// registra los envíos (para poder aseverar destinatario/asunto) en vez de
// tocar la red. admin.routes.js llama a emailAdapter.sendMail (no
// desestructurado) precisamente para permitir este reemplazo.
const emailAdapter = require('../logic/adapters/email.adapter');
const sentEmails = [];
emailAdapter.sendMail = async (msg) => { sentEmails.push(msg); };

function startTestServer() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname.startsWith('/content')) return handleContentRequest(req, res, url);
      if (url.pathname.startsWith('/admin')) return handleAdminRequest(req, res, url);
      res.writeHead(404); res.end();
    });
    server.listen(0, () => resolve(server));
  });
}

function request(baseUrl, method, path, { body, cookie } = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const headers = { 'Content-Type': 'application/json' };
    if (data) headers['Content-Length'] = Buffer.byteLength(data);
    if (cookie) headers['Cookie'] = cookie;

    const req = http.request(`${baseUrl}${path}`, { method, headers }, (res) => {
      let out = '';
      res.on('data', (c) => { out += c; });
      res.on('end', () => {
        let parsed = {};
        try { parsed = JSON.parse(out || '{}'); } catch {}
        resolve({ status: res.statusCode, body: parsed, setCookie: res.headers['set-cookie'] });
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

function cookieFromSetCookie(setCookieArray) {
  if (!setCookieArray || !setCookieArray.length) return null;
  return setCookieArray[0].split(';')[0];
}

async function run() {
  const server = await startTestServer();
  const port = server.address().port;
  const baseUrl = `http://localhost:${port}`;

  try {
    // ─── Sin sesión: todo lo administrativo rechaza ─────────────────
    const noAuthGet = await request(baseUrl, 'GET', '/admin/api/content/blog');
    assert.strictEqual(noAuthGet.status, 401);

    const noAuthPost = await request(baseUrl, 'POST', '/admin/api/content/blog',
      { body: { title: 'x', summary: 'y', url: 'https://x.test' } });
    assert.strictEqual(noAuthPost.status, 401, 'crear contenido sin sesión debe rechazar aunque el payload sea válido');

    const noAuthUsers = await request(baseUrl, 'GET', '/admin/api/users');
    assert.strictEqual(noAuthUsers.status, 401);

    // ─── Login super_admin ──────────────────────────────────────────
    const login = await request(baseUrl, 'POST', '/admin/api/login',
      { body: { username: 'root', password: 'ClaveSuperAdmin123' } });
    assert.strictEqual(login.status, 200);
    const cookie = cookieFromSetCookie(login.setCookie);
    assert.ok(cookie, 'login exitoso debe fijar cookie de sesión');

    // ─── Crear en borrador (blog, events, materials) ────────────────
    const created = await request(baseUrl, 'POST', '/admin/api/content/blog',
      { cookie, body: { title: 'Artículo de prueba', summary: 'resumen', url: 'https://x.test/a', category: 'DNSSEC' } });
    assert.strictEqual(created.status, 201);
    assert.strictEqual(created.body.item.published, false);
    const itemId = created.body.item.id;

    await request(baseUrl, 'POST', '/admin/api/content/events',
      { cookie, body: { title: 'Webinar', date: '2026-09-01' } });
    await request(baseUrl, 'POST', '/admin/api/content/materials',
      { cookie, body: { title: 'Guía', description: 'detalle', url: 'https://x.test/g.pdf' } });

    // ─── Público NO ve borradores ────────────────────────────────────
    const publicBlogDraft = await request(baseUrl, 'GET', '/content/blog');
    assert.strictEqual(publicBlogDraft.status, 200);
    assert.deepStrictEqual(publicBlogDraft.body.items, [], 'un borrador nunca debe aparecer en /content/blog');

    const publicEventsDraft = await request(baseUrl, 'GET', '/content/events');
    assert.deepStrictEqual(publicEventsDraft.body.items, []);

    const publicMaterialsDraft = await request(baseUrl, 'GET', '/content/materials');
    assert.deepStrictEqual(publicMaterialsDraft.body.items, []);

    // ─── Admin SÍ ve el borrador ─────────────────────────────────────
    const adminBlogList = await request(baseUrl, 'GET', '/admin/api/content/blog', { cookie });
    assert.strictEqual(adminBlogList.body.items.length, 1);
    assert.strictEqual(adminBlogList.body.items[0].published, false);

    // ─── Publicar y confirmar visibilidad pública ───────────────────
    const publish = await request(baseUrl, 'PUT', `/admin/api/content/blog/${itemId}`,
      { cookie, body: { published: true } });
    assert.strictEqual(publish.status, 200);
    assert.strictEqual(publish.body.item.published, true);

    const publicBlogAfter = await request(baseUrl, 'GET', '/content/blog');
    assert.strictEqual(publicBlogAfter.body.items.length, 1);
    assert.strictEqual(publicBlogAfter.body.items[0].title, 'Artículo de prueba');
    assert.strictEqual('published' in publicBlogAfter.body.items[0], false, 'la respuesta pública no debe incluir el campo published');

    // ─── validación: url inválida rechaza con 400 ────────────────────
    const badUrl = await request(baseUrl, 'POST', '/admin/api/content/blog',
      { cookie, body: { title: 'x', summary: 'y', url: 'no-es-una-url' } });
    assert.strictEqual(badUrl.status, 400);
    assert.strictEqual(badUrl.body.error, 'validation_failed');

    // ─── Creación de admin: requiere email, la contraseña la genera y
    // envía el sistema — nunca se recibe por parámetro ni se expone ────
    const editorCreate = await request(baseUrl, 'POST', '/admin/api/users',
      { cookie, body: { username: 'editor1', email: 'editor1@example.com' } });
    assert.strictEqual(editorCreate.status, 201);
    assert.strictEqual(editorCreate.body.user.email, 'editor1@example.com');
    assert.strictEqual('plainPassword' in editorCreate.body.user, false, 'la contraseña generada nunca debe viajar en la respuesta HTTP');

    assert.strictEqual(sentEmails.length, 1, 'debe haberse enviado un correo con la contraseña del nuevo admin');
    assert.strictEqual(sentEmails[0].to, 'editor1@example.com');
    const editorPassword = sentEmails[0].text.match(/Contraseña: (\S+)/)[1];

    const editorLogin = await request(baseUrl, 'POST', '/admin/api/login',
      { body: { username: 'editor1', password: editorPassword } });
    assert.strictEqual(editorLogin.status, 200, 'la contraseña enviada por correo debe funcionar para iniciar sesión');
    const editorCookie = cookieFromSetCookie(editorLogin.setCookie);

    const editorTriesUsers = await request(baseUrl, 'GET', '/admin/api/users', { cookie: editorCookie });
    assert.strictEqual(editorTriesUsers.status, 403, 'un admin normal no puede listar/gestionar usuarios');

    const editorCanCreateContent = await request(baseUrl, 'POST', '/admin/api/content/events',
      { cookie: editorCookie, body: { title: 'Evento de editor1' } });
    assert.strictEqual(editorCanCreateContent.status, 201, 'un admin normal sí puede gestionar contenido');

    // ─── Email inválido rechaza la creación (400), sin enviar correo ──
    const badEmail = await request(baseUrl, 'POST', '/admin/api/users',
      { cookie, body: { username: 'editor2', email: 'no-es-un-email' } });
    assert.strictEqual(badEmail.status, 400);
    assert.strictEqual(sentEmails.length, 1, 'un email inválido no debe disparar ningún envío');

    // ─── Recuperación de contraseña: respuesta genérica siempre ──────
    const forgotUnknown = await request(baseUrl, 'POST', '/admin/api/forgot-password', { body: { username: 'no-existe' } });
    assert.strictEqual(forgotUnknown.status, 200);
    assert.strictEqual(sentEmails.length, 1, 'un usuario inexistente no debe disparar ningún envío');

    const forgotEditor = await request(baseUrl, 'POST', '/admin/api/forgot-password', { body: { username: 'editor1' } });
    assert.strictEqual(forgotEditor.status, 200);
    assert.strictEqual(sentEmails.length, 2);
    assert.strictEqual(sentEmails[1].to, 'editor1@example.com', 'la recuperación de un admin normal va a su propio email');
    const editorNewPassword = sentEmails[1].text.match(/\n\n(\S+)\n/)[1];

    const oldPasswordLogin = await request(baseUrl, 'POST', '/admin/api/login', { body: { username: 'editor1', password: editorPassword } });
    assert.strictEqual(oldPasswordLogin.status, 401, 'tras la recuperación, la contraseña anterior ya no debe funcionar');
    const newPasswordLogin = await request(baseUrl, 'POST', '/admin/api/login', { body: { username: 'editor1', password: editorNewPassword } });
    assert.strictEqual(newPasswordLogin.status, 200);

    const forgotSuper = await request(baseUrl, 'POST', '/admin/api/forgot-password', { body: { username: 'root' } });
    assert.strictEqual(forgotSuper.status, 200);
    assert.strictEqual(sentEmails.length, 3);
    assert.strictEqual(sentEmails[2].to, 'corpeceorg@gmail.com', 'la recuperación del super_admin siempre va a la dirección fija configurada');

    // ─── Logout invalida la sesión ───────────────────────────────────
    await request(baseUrl, 'POST', '/admin/api/logout', { cookie });
    const afterLogout = await request(baseUrl, 'GET', '/admin/api/whoami', { cookie });
    assert.strictEqual(afterLogout.status, 401);

    console.log('✅ content.publicVisibility.test.js — todos los casos OK');
  } finally {
    server.close();
    fs.rmSync(TMP_DIR, { recursive: true, force: true });
  }
}

run().catch((err) => {
  console.error('❌ content.publicVisibility.test.js FALLÓ:', err);
  process.exit(1);
});
