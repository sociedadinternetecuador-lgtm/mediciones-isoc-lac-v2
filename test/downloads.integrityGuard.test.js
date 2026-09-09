'use strict';

/**
 * Verifica que los endpoints de descarga (/download y /download-zip) usan
 * REALMENTE el flag integrity.passed antes de servir archivos — no solo la
 * UI (que ocultaba los botones, pero un cliente que llame a la API
 * directamente no pasaba por esa validación).
 *
 * Se corre un job DNS real y pequeño hasta completarlo, y luego se muta
 * DIRECTAMENTE integrity.passed a false sobre el objeto job ya en memoria
 * (mismo objeto que devuelve getJob(), sin tocar ninguna lógica de
 * producción de Normalización/DNS) para simular una corrida inconsistente
 * y comprobar que el mecanismo de protección la bloquea de verdad.
 *
 * Ejecutar: node test/downloads.integrityGuard.test.js
 */

const assert = require('assert');
const http = require('http');
const { URL } = require('url');

const { handleDatasetRequest } = require('../routes/datasetPreparation.routes');
const { getJob } = require('../logic/orchestrators/dnsValidationJob.orchestrator');

function startTestServer() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const url = new URL(req.url, 'http://localhost');
      handleDatasetRequest(req, res, url);
    });
    server.listen(0, () => resolve(server));
  });
}

function post(baseUrl, path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request(`${baseUrl}${path}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
    }, (res) => {
      let out = '';
      res.on('data', (c) => { out += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(out || '{}') }));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

function getRaw(baseUrl, path) {
  return new Promise((resolve, reject) => {
    http.get(`${baseUrl}${path}`, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, buf: Buffer.concat(chunks) }));
    }).on('error', reject);
  });
}

function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

async function run() {
  const server = await startTestServer();
  const port = server.address().port;
  const baseUrl = `http://localhost:${port}`;

  try {
    console.log('Ejecutando un job DNS real y pequeño...');
    const start = await post(baseUrl, '/dataset/validate-dns', {
      domains: ['isoc.org.ec', 'corpece.org.ec'],
      tld: 'ec',
      source: {},
      normalize: { stats: {}, rejected: [] },
    });
    const jobId = start.body.jobId;

    let statusBody;
    for (let i = 0; i < 30; i++) {
      await sleep(1000);
      const r = await getRaw(baseUrl, `/dataset/validate-dns/${jobId}`);
      statusBody = JSON.parse(r.buf.toString('utf-8'));
      if (statusBody.status !== 'running') break;
    }
    assert.strictEqual(statusBody.status, 'completed');
    assert.strictEqual(statusBody.resultsPackage.integrity.passed, true, 'la corrida real debe ser consistente antes de simular el fallo');
    console.log('Job completado con integridad real OK. Simulando una corrida inconsistente...');

    // Mutación directa sobre el objeto job en memoria (mismo objeto que
    // devuelve getJob) — NO se toca ninguna lógica de producción, solo se
    // fuerza el flag para probar que el mecanismo de protección reacciona.
    const job = getJob(jobId);
    job.resultsPackage.integrity.passed = false;

    const sampleFile = Object.keys(job.resultsPackage.files).find((f) => !f.includes('/'));

    const fileDownload = await getRaw(baseUrl, `/dataset/validate-dns/${jobId}/download/${encodeURIComponent(sampleFile)}`);
    const zipDownload = await getRaw(baseUrl, `/dataset/validate-dns/${jobId}/download-zip`);

    console.log(`\nDescarga de "${sampleFile}" con integridad forzada a false -> HTTP ${fileDownload.status}`);
    console.log(`Descarga del ZIP con integridad forzada a false -> HTTP ${zipDownload.status}`);

    assert.notStrictEqual(fileDownload.status, 200, 'la descarga individual NO debe responder 200 cuando integrity.passed es false');
    assert.notStrictEqual(zipDownload.status, 200, 'la descarga del ZIP NO debe responder 200 cuando integrity.passed es false');

    // Confirmar que la respuesta de error no contiene el contenido del
    // archivo (no se filtra el archivo disfrazado de error).
    const fileBodyText = fileDownload.buf.toString('utf-8');
    let fileBodyJson = null;
    try { fileBodyJson = JSON.parse(fileBodyText); } catch { /* no era JSON */ }
    assert.ok(fileBodyJson && fileBodyJson.error, 'la respuesta bloqueada debe ser un error JSON explícito, no el archivo');

    console.log('\n=== PASS: los endpoints de descarga rechazan la corrida cuando integrity.passed === false ===');
  } finally {
    server.close();
  }
}

run().catch((error) => {
  console.error('FAIL', error);
  process.exit(1);
});
