'use strict';

/**
 * Prueba EN VIVO (requiere red real, no es parte de "npm test") que
 * demuestra mediante INSTRUMENTACIÓN — no tiempos de respuesta — que las
 * descargas de "Resultados y descarga" no ejecutan ninguna consulta DNS
 * nueva.
 *
 * Mecanismo: se envuelve dnsQuery() de logic/adapters/rawDns.adapter.js
 * (la función de más bajo nivel que realmente abre el socket UDP/TCP hacia
 * los resolvers) ANTES de requerir cualquier módulo que la use. Como
 * dnsValidation.validator.js hace `const { dnsQuery } = require(...)` en su
 * primera carga, capturar el módulo y sobreescribir su propiedad `dnsQuery`
 * antes de ese primer require hace que la referencia capturada sea la
 * versión instrumentada — sin tocar ningún archivo de producción.
 *
 * Se ejercitan los handlers REALES de rutas (routes/datasetPreparation.routes.js)
 * vía un servidor HTTP propio, no una reimplementación.
 *
 * Ejecutar manualmente: node test/dnsDownloads.noDnsCalls.test.js
 */

const assert = require('assert');
const http = require('http');
const { URL } = require('url');

// 1) Instrumentar ANTES de requerir nada que dependa de rawDns.adapter.
const rawDns = require('../logic/adapters/rawDns.adapter');
let dnsCallCount = 0;
const originalDnsQuery = rawDns.dnsQuery;
rawDns.dnsQuery = function instrumentedDnsQuery(...args) {
  dnsCallCount += 1;
  return originalDnsQuery.apply(this, args);
};

// 2) Ahora sí, requerir los handlers reales — heredan la versión instrumentada.
const { handleDatasetRequest } = require('../routes/datasetPreparation.routes');

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
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
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
    console.log('Ejecutando un job DNS real hasta completarlo (esto SÍ debe generar llamadas a dnsQuery)...');
    const start = await post(baseUrl, '/dataset/validate-dns', {
      domains: ['isoc.org.ec', 'corpece.org.ec', 'nic.ec', 'nxdomain-test-nodns-check.ec'],
      tld: 'ec',
      source: {},
      normalize: { stats: {}, rejected: [] },
    });
    const jobId = start.body.jobId;

    let job;
    for (let i = 0; i < 30; i++) {
      await sleep(1000);
      const r = await getRaw(baseUrl, `/dataset/validate-dns/${jobId}`);
      job = JSON.parse(r.buf.toString('utf-8'));
      if (job.status !== 'running') break;
    }
    assert.strictEqual(job.status, 'completed', 'el job de referencia debe completarse');
    console.log(`Job completado. Llamadas a dnsQuery durante la validación: ${dnsCallCount} (se esperan > 0).`);
    assert.ok(dnsCallCount > 0, 'la validación DNS real debe haber generado llamadas a dnsQuery (si esto falla, la instrumentación no está enganchada correctamente)');

    // 2) Reiniciar el contador — desde aquí, CERO llamadas nuevas son aceptables.
    dnsCallCount = 0;
    console.log('\nContador de dnsQuery reiniciado a 0. Iniciando descargas...');

    const topLevelFiles = job.resultsPackage.file_list.filter((f) => !f.includes('/'));
    const timings = [];

    for (const filename of topLevelFiles) {
      const t0 = process.hrtime.bigint();
      const r = await getRaw(baseUrl, `/dataset/validate-dns/${jobId}/download/${encodeURIComponent(filename)}`);
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      timings.push({ filename, ms });
      assert.strictEqual(r.status, 200, `descarga de ${filename} debe responder 200`);
    }
    console.log(`Descargados ${topLevelFiles.length} archivos individuales (incluye metadata.json).`);

    for (let i = 0; i < 3; i++) {
      const t0 = process.hrtime.bigint();
      const r = await getRaw(baseUrl, `/dataset/validate-dns/${jobId}/download-zip`);
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      timings.push({ filename: `zip_intento_${i + 1}`, ms });
      assert.strictEqual(r.status, 200, 'la descarga del ZIP debe responder 200');
    }
    console.log('Generado/descargado el ZIP 3 veces.');

    console.log('\n--- Tiempos (información adicional, NO es la evidencia principal) ---');
    for (const t of timings) console.log(`  ${t.filename}: ${t.ms.toFixed(2)} ms`);

    console.log(`\nLlamadas NUEVAS a dnsQuery durante todas las descargas: ${dnsCallCount}`);
    assert.strictEqual(dnsCallCount, 0, 'no debe haber ninguna llamada nueva a dnsQuery durante las descargas');

    console.log('\n=== PASS: cero consultas DNS durante las descargas (verificado por instrumentación, no por tiempos) ===');
  } finally {
    server.close();
  }
}

run().catch((error) => {
  console.error('FAIL', error);
  process.exit(1);
});
