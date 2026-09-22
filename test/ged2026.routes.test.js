'use strict';

/**
 * Prueba de extremo a extremo (servidor HTTP real, mismo patrón que
 * content.publicVisibility.test.js) del módulo GED2026:
 *
 *   - Sin sesión, /admin/api/ged2026/* rechaza (401).
 *   - Importación CSV: cuenta importados/duplicados/inválidos/omitidos.
 *   - excluded sin exclusion_reason rechaza (400); con motivo, acepta.
 *   - El resumen público (/ged2026/api/v1/summary) refleja los conteos y
 *     NUNCA expone dominios individuales, notas ni exclusion_reason.
 *
 * DATA_DIR temporal y aislado — nunca toca data/ged2026 real.
 *
 * Ejecutar: node test/ged2026.routes.test.js
 */

const assert = require('assert');
const http = require('http');
const os = require('os');
const path = require('path');
const fs = require('fs');
const { URL } = require('url');

const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'mediciones-ged2026-e2e-'));
process.env.DATA_DIR = TMP_DIR;
process.env.SESSION_SECRET = 'test-secret-solo-para-pruebas';
process.env.ENV_FILE_PATH = path.join(TMP_DIR, '.env.test');

// La importación/alta de dominios normaliza vía Public Suffix List — se
// precarga la copia ya descargada en data/psl_cache/ del proyecto para
// mantener el test CI-safe (sin red), igual que en
// ged2026Domains.normalize.test.js.
fs.mkdirSync(path.join(TMP_DIR, 'psl_cache'), { recursive: true });
fs.copyFileSync(
  path.resolve(__dirname, '../data/psl_cache/public_suffix_list.dat'),
  path.join(TMP_DIR, 'psl_cache', 'public_suffix_list.dat'),
);

const { hashPassword } = require('../logic/auth/adminAuth.adapter');
process.env.ADMIN_USERNAME = 'root';
process.env.ADMIN_PASSWORD_HASH = hashPassword('ClaveSuperAdmin123');
process.env.ADMIN_COOKIE_INSECURE = '1';

const { handleGed2026Request } = require('../routes/ged2026.routes');
const { handleAdminRequest } = require('../routes/admin.routes');

function startTestServer() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname.startsWith('/ged2026')) return handleGed2026Request(req, res, url);
      if (url.pathname.startsWith('/admin')) return handleAdminRequest(req, res, url);
      res.writeHead(404); res.end();
    });
    server.listen(0, () => resolve(server));
  });
}

function request(baseUrl, method, reqPath, { body, cookie, origin } = {}) {
  return new Promise((resolve, reject) => {
    const data = body !== undefined ? JSON.stringify(body) : null;
    const headers = { 'Content-Type': 'application/json' };
    if (data) headers['Content-Length'] = Buffer.byteLength(data);
    if (cookie) headers['Cookie'] = cookie;
    if (origin) headers['Origin'] = origin;

    const req = http.request(`${baseUrl}${reqPath}`, { method, headers }, (res) => {
      let out = '';
      res.on('data', (c) => { out += c; });
      res.on('end', () => {
        let parsed = {};
        try { parsed = JSON.parse(out || '{}'); } catch {}
        resolve({ status: res.statusCode, body: parsed, setCookie: res.headers['set-cookie'], headers: res.headers });
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

const IMPORT_CSV = [
  'domain,category,source,notes',
  'banco.ec,financiero,manual,ok',
  'universidad.edu.ec,educacion,manual,ok',
  'banco.ec,financiero,manual,duplicado',
  '',
  'not a domain here,invalid,manual,x',
].join('\n');

async function run() {
  const server = await startTestServer();
  const port = server.address().port;
  const baseUrl = `http://localhost:${port}`;

  try {
    // ─── Sin sesión: todo lo administrativo de GED2026 rechaza ──────
    const noAuthGet = await request(baseUrl, 'GET', '/admin/api/ged2026/domains');
    assert.strictEqual(noAuthGet.status, 401);
    const noAuthImport = await request(baseUrl, 'POST', '/admin/api/ged2026/domains/import', { body: { csv: 'x.ec' } });
    assert.strictEqual(noAuthImport.status, 401, 'importar sin sesión debe rechazar aunque el payload sea válido');
    const noAuthBulkUpdate = await request(baseUrl, 'POST', '/admin/api/ged2026/domains/bulk-update', { body: { csv: 'domain\nx.ec' } });
    assert.strictEqual(noAuthBulkUpdate.status, 401, 'actualizar en bloque sin sesión debe rechazar');

    // ─── Login ────────────────────────────────────────────────────
    const login = await request(baseUrl, 'POST', '/admin/api/login', { body: { username: 'root', password: 'ClaveSuperAdmin123' } });
    assert.strictEqual(login.status, 200);
    const cookie = cookieFromSetCookie(login.setCookie);
    assert.ok(cookie);

    // ─── Antes de importar: resumen público en cero ─────────────────
    const summaryBefore = await request(baseUrl, 'GET', '/ged2026/api/v1/summary', { origin: 'https://isoc.org.ec' });
    assert.strictEqual(summaryBefore.status, 200);
    assert.strictEqual(summaryBefore.body.total_domains, 0);
    assert.strictEqual(summaryBefore.body.updated_at, null);
    assert.strictEqual(summaryBefore.headers['access-control-allow-origin'], 'https://isoc.org.ec',
      'el portal (otro origen) necesita esta cabecera para poder leer la respuesta desde el navegador');

    // ─── CORS: el dominio raíz redirige a "www" en producción — el Origen
    // real que envía el navegador es el de "www", debe reflejarse igual ──
    const summaryWww = await request(baseUrl, 'GET', '/ged2026/api/v1/summary', { origin: 'https://www.isoc.org.ec' });
    assert.strictEqual(summaryWww.headers['access-control-allow-origin'], 'https://www.isoc.org.ec');

    // ─── CORS: un origen no listado nunca se refleja ─────────────────
    const summaryUnknownOrigin = await request(baseUrl, 'GET', '/ged2026/api/v1/summary', { origin: 'https://evil.test' });
    assert.strictEqual(summaryUnknownOrigin.headers['access-control-allow-origin'], undefined,
      'un origen fuera de la lista permitida nunca debe reflejarse en la cabecera CORS');

    // ─── Importación CSV ──────────────────────────────────────────
    const imported = await request(baseUrl, 'POST', '/admin/api/ged2026/domains/import', { cookie, body: { csv: IMPORT_CSV } });
    assert.strictEqual(imported.status, 200);
    assert.strictEqual(imported.body.importados, 2);
    assert.strictEqual(imported.body.duplicados, 1);
    assert.strictEqual(imported.body.invalidos, 1);
    assert.strictEqual(imported.body.omitidos, 1, 'la línea en blanco debe contarse como omitida');

    // ─── Admin ve los 2 dominios importados ──────────────────────
    const adminList = await request(baseUrl, 'GET', '/admin/api/ged2026/domains', { cookie });
    assert.strictEqual(adminList.body.items.length, 2);
    const banco = adminList.body.items.find((d) => d.normalized_domain === 'banco.ec');
    assert.ok(banco, 'banco.ec debe existir tras la importación');
    assert.strictEqual(banco.fuente, 'manual', 'la columna source del CSV debe respetarse');
    assert.strictEqual(banco.notas, 'ok');

    // ─── Resumen público refleja el total, sin datos por dominio ────
    const summaryAfterImport = await request(baseUrl, 'GET', '/ged2026/api/v1/summary');
    assert.strictEqual(summaryAfterImport.body.total_domains, 2);
    assert.strictEqual(summaryAfterImport.body.active_domains, 2);
    assert.strictEqual(summaryAfterImport.body.counts_by_estado_seleccion.candidate, 2);
    assert.strictEqual('items' in summaryAfterImport.body, false, 'el resumen público nunca debe traer un listado de dominios');
    assert.ok(summaryAfterImport.body.updated_at, 'importar debe actualizar el updated_at del proyecto');

    // ─── excluded sin exclusion_reason rechaza ───────────────────
    const excludeNoReason = await request(baseUrl, 'PUT', `/admin/api/ged2026/domains/${banco.id}`,
      { cookie, body: { estado_seleccion: 'excluded' } });
    assert.strictEqual(excludeNoReason.status, 400);
    assert.strictEqual(excludeNoReason.body.error, 'validation_failed');
    assert.ok(excludeNoReason.body.fields.includes('exclusion_reason_required'));

    // ─── excluded CON exclusion_reason se acepta ─────────────────
    const excludeOk = await request(baseUrl, 'PUT', `/admin/api/ged2026/domains/${banco.id}`,
      { cookie, body: { estado_seleccion: 'excluded', exclusion_reason: 'not_relevant', notas: 'contiene: coma, y todo' } });
    assert.strictEqual(excludeOk.status, 200);
    assert.strictEqual(excludeOk.body.item.estado_seleccion, 'excluded');
    assert.strictEqual(excludeOk.body.item.notas, 'contiene: coma, y todo', 'el update no debe perder texto libre con comas');

    // ─── El resumen público refleja la exclusión sin exponerla en detalle ──
    const summaryAfterExclude = await request(baseUrl, 'GET', '/ged2026/api/v1/summary');
    assert.strictEqual(summaryAfterExclude.body.counts_by_estado_seleccion.excluded, 1);
    assert.strictEqual(summaryAfterExclude.body.active_domains, 2, 'excluir no cambia por sí solo el flag activo');
    assert.strictEqual(JSON.stringify(summaryAfterExclude.body).includes('not_relevant'), false,
      'exclusion_reason es un detalle interno, nunca debe aparecer en el resumen público');
    assert.strictEqual(JSON.stringify(summaryAfterExclude.body).includes('contiene: coma'), false,
      'notas es un detalle interno, nunca debe aparecer en el resumen público');

    // ─── Dominio inválido en alta manual rechaza con 400 ─────────
    const badManual = await request(baseUrl, 'POST', '/admin/api/ged2026/domains', { cookie, body: { domain: 'no es un dominio' } });
    assert.strictEqual(badManual.status, 400);
    assert.strictEqual(badManual.body.error, 'domain_invalid');

    // ─── Alta manual duplicada rechaza con 409 ────────────────────
    const dupManual = await request(baseUrl, 'POST', '/admin/api/ged2026/domains', { cookie, body: { domain: 'universidad.edu.ec' } });
    assert.strictEqual(dupManual.status, 409);

    // ─── Dashboard interno agrega por TLD/categoría/estado ───────
    const dashboard = await request(baseUrl, 'GET', '/admin/api/ged2026/dashboard', { cookie });
    assert.strictEqual(dashboard.status, 200);
    assert.strictEqual(dashboard.body.total_domains, 2);
    assert.strictEqual(dashboard.body.by_tld.ec, 1, 'universidad.edu.ec cuenta bajo su propio sufijo, no bajo "ec"');
    assert.ok('edu.ec' in dashboard.body.by_tld);

    // ─── Actualización masiva: UPDATE de un dominio ya existente ─────
    // banco.ec (banco) quedó 'excluded' más arriba; el lote lo reincorpora
    // y anota institutional_relevance — columnas en cualquier orden.
    const bulkUpdateExisting = await request(baseUrl, 'POST', '/admin/api/ged2026/domains/bulk-update', {
      cookie,
      body: { csv: 'notas,domain,estado_seleccion,institutional_relevance\nInstitución verificada,banco.ec,shortlisted,alta' },
    });
    assert.strictEqual(bulkUpdateExisting.status, 200);
    assert.strictEqual(bulkUpdateExisting.body.actualizados, 1);
    assert.strictEqual(bulkUpdateExisting.body.creados, 0);

    const domainsAfterBulk = await request(baseUrl, 'GET', '/admin/api/ged2026/domains', { cookie });
    const bancoUpdated = domainsAfterBulk.body.items.find((d) => d.normalized_domain === 'banco.ec');
    assert.strictEqual(bancoUpdated.estado_seleccion, 'shortlisted');
    assert.strictEqual(bancoUpdated.notas, 'Institución verificada');
    assert.deepStrictEqual(bancoUpdated.atributos_relevancia.institutional_relevance, { value: 'alta', method: 'clasificado_manual' });
    assert.strictEqual(bancoUpdated.atributos_relevancia.traffic_rank, null, 'un campo de relevancia no tocado en el lote no debe alterarse');

    // ─── Actualización masiva: CREATE (upsert) de un dominio que no existía ──
    const bulkUpdateNew = await request(baseUrl, 'POST', '/admin/api/ged2026/domains/bulk-update', {
      cookie,
      body: { csv: 'domain,estado_seleccion,institutional_relevance\niess.gob.ec,shortlisted,alta' },
    });
    assert.strictEqual(bulkUpdateNew.status, 200);
    assert.strictEqual(bulkUpdateNew.body.creados, 1);
    assert.strictEqual(bulkUpdateNew.body.actualizados, 0);

    const summaryAfterBulk = await request(baseUrl, 'GET', '/ged2026/api/v1/summary');
    assert.strictEqual(summaryAfterBulk.body.total_domains, 3, 'iess.gob.ec debe sumarse al universo total');
    assert.strictEqual(summaryAfterBulk.body.counts_by_estado_seleccion.shortlisted, 2);

    // ─── Actualización masiva: fila con dominio inválido no rompe el lote ──
    const bulkUpdateMixed = await request(baseUrl, 'POST', '/admin/api/ged2026/domains/bulk-update', {
      cookie,
      body: { csv: 'domain,notas\nno es un dominio,x\nuniversidad.edu.ec,Nota agregada por lote' },
    });
    assert.strictEqual(bulkUpdateMixed.status, 200);
    assert.strictEqual(bulkUpdateMixed.body.invalidos, 1);
    assert.strictEqual(bulkUpdateMixed.body.actualizados, 1);

    console.log('✅ ged2026.routes.test.js — todos los casos OK');
  } finally {
    server.close();
    fs.rmSync(TMP_DIR, { recursive: true, force: true });
  }
}

run().catch((err) => {
  console.error('❌ ged2026.routes.test.js FALLÓ:', err);
  process.exit(1);
});
