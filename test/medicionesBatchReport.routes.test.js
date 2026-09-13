'use strict';

/**
 * Prueba de extremo a extremo (servidor HTTP real, mismo patrón que
 * content.publicVisibility.test.js) de routes/medicionesBatchReport.routes.js.
 *
 * El PDF depende de un servicio externo (mdtopdf en server1:8600) — para
 * que el test sea CI-safe (sin red real) se reemplaza global.fetch por un
 * stub que registra la llamada y devuelve un PDF fabricado, y se restaura
 * al terminar.
 *
 * Ejecutar: node test/medicionesBatchReport.routes.test.js
 */

const assert = require('assert');
const http = require('http');
const { URL } = require('url');

const { handleMedicionesBatchReportRequest } = require('../routes/medicionesBatchReport.routes');

function startTestServer() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname.startsWith('/mediciones-batch')) {
        return handleMedicionesBatchReportRequest(req, res, url);
      }
      res.writeHead(404); res.end();
    });
    server.listen(0, () => resolve(server));
  });
}

function requestJson(baseUrl, method, path, body) {
  return new Promise((resolve, reject) => {
    const data = body !== undefined ? JSON.stringify(body) : null;
    const headers = { 'Content-Type': 'application/json' };
    if (data) headers['Content-Length'] = Buffer.byteLength(data);

    const req = http.request(`${baseUrl}${path}`, { method, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        const contentType = res.headers['content-type'] || '';
        if (contentType.includes('application/json')) {
          let parsed = {};
          try { parsed = JSON.parse(buf.toString('utf8') || '{}'); } catch {}
          resolve({ status: res.statusCode, headers: res.headers, body: parsed });
        } else {
          resolve({ status: res.statusCode, headers: res.headers, buffer: buf });
        }
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

const SAMPLE_PAYLOAD = {
  meta: {
    generated_at: '2026-09-08T00:00:00.000Z',
    selected_checks: ['mx', 'dmarc'],
    domain_count: 2,
    source: { mode: 'paste', filename: null },
  },
  domains: [
    {
      domain: 'nic.uy',
      dns_validation: { final_status: 'VALID', review_subtype: null, discrepancy: false },
      dnssec: { domain: 'nic.uy', dnssec: { final_status: 'ok', executive_summary: { risk_level: 'bajo', action_required: false } } },
      checks: {
        mx: { label: 'MX', status: 'ok', details: 'mail.nic.uy' },
        dmarc: { label: 'DMARC', status: 'ok', details: 'v=DMARC1' },
      },
    },
    {
      domain: 'no-existe.example',
      dns_validation: { final_status: 'NXDOMAIN', review_subtype: null, discrepancy: false },
      dnssec: { error: 'NXDOMAIN' },
      checks: {
        mx: { label: 'MX', status: 'error', details: 'NXDOMAIN' },
        dmarc: { label: 'DMARC', status: 'error', details: 'NXDOMAIN' },
      },
    },
  ],
  comparative: {
    checks_summary: {
      mx: { label: 'MX', positive: 1, negative: 0 },
      dmarc: { label: 'DMARC', positive: 1, negative: 0 },
    },
    dns_validation_summary: { VALID: 1, NXDOMAIN: 1, REVIEW: 0 },
    dnssec_aggregate: { country: 'Lote analizado', semaphore: 'insufficient', adoptionRate: null, total: 2, structural: 0, actionable: 0, warnings: [] },
  },
};

async function run() {
  const originalFetch = global.fetch;
  const fetchCalls = [];
  const FAKE_PDF_BYTES = Buffer.from('%PDF-1.4 contenido-falso-para-test');

  global.fetch = async (url, options) => {
    fetchCalls.push({ url, options });
    return {
      ok: true,
      status: 200,
      arrayBuffer: async () => FAKE_PDF_BYTES.buffer.slice(
        FAKE_PDF_BYTES.byteOffset, FAKE_PDF_BYTES.byteOffset + FAKE_PDF_BYTES.byteLength,
      ),
      text: async () => '',
    };
  };

  const server = await startTestServer();
  const port = server.address().port;
  const baseUrl = `http://localhost:${port}`;

  try {
    // ─── POST guarda y devuelve reportId + URLs ─────────────────────
    const created = await requestJson(baseUrl, 'POST', '/mediciones-batch/report', SAMPLE_PAYLOAD);
    assert.strictEqual(created.status, 201);
    assert.ok(created.body.reportId, 'debe devolver un reportId');
    assert.strictEqual(created.body.jsonUrl, `/mediciones-batch/report/${created.body.reportId}/export?format=json`);
    assert.strictEqual(created.body.pdfUrl, `/mediciones-batch/report/${created.body.reportId}/export?format=pdf`);
    const { reportId } = created.body;

    // ─── payload inválido rechaza con 400 ───────────────────────────
    const invalid = await requestJson(baseUrl, 'POST', '/mediciones-batch/report', { foo: 'bar' });
    assert.strictEqual(invalid.status, 400);
    assert.strictEqual(invalid.body.error, 'invalid_payload');

    // ─── límite de 20 dominios por análisis (impide bypass del frontend) ─
    const makeDomainsPayload = (n) => ({
      ...SAMPLE_PAYLOAD,
      domains: Array.from({ length: n }, (_, i) => ({ ...SAMPLE_PAYLOAD.domains[0], domain: `dominio${i}.example` })),
    });

    const exactly20 = await requestJson(baseUrl, 'POST', '/mediciones-batch/report', makeDomainsPayload(20));
    assert.strictEqual(exactly20.status, 201, '20 dominios debe permitirse (límite inclusive)');

    const exceeds21 = await requestJson(baseUrl, 'POST', '/mediciones-batch/report', makeDomainsPayload(21));
    assert.strictEqual(exceeds21.status, 400);
    assert.strictEqual(exceeds21.body.error, 'DOMAIN_LIMIT_EXCEEDED');
    assert.strictEqual(exceeds21.body.received_count, 21);
    assert.strictEqual(exceeds21.body.max_allowed, 20);

    const exceeds400 = await requestJson(baseUrl, 'POST', '/mediciones-batch/report', makeDomainsPayload(400));
    assert.strictEqual(exceeds400.status, 400);
    assert.strictEqual(exceeds400.body.error, 'DOMAIN_LIMIT_EXCEEDED');
    assert.strictEqual(exceeds400.body.received_count, 400);

    // ─── GET ?format=json de un id existente devuelve el payload ────
    const jsonExport = await requestJson(baseUrl, 'GET', `/mediciones-batch/report/${reportId}/export?format=json`);
    assert.strictEqual(jsonExport.status, 200);
    assert.strictEqual(jsonExport.headers['content-disposition'].includes('attachment'), true);
    assert.deepStrictEqual(jsonExport.body.domains, SAMPLE_PAYLOAD.domains);
    assert.strictEqual(jsonExport.body.meta.domain_count, 2);
    assert.ok(jsonExport.body.export_meta, 'el export JSON debe incluir metadata de exportación');

    // ─── GET de un id inexistente devuelve 404 ──────────────────────
    const notFound = await requestJson(baseUrl, 'GET', '/mediciones-batch/report/no-existe/export?format=json');
    assert.strictEqual(notFound.status, 404);
    assert.strictEqual(notFound.body.error, 'report_not_found');

    // ─── formato inválido devuelve 400 ──────────────────────────────
    const badFormat = await requestJson(baseUrl, 'GET', `/mediciones-batch/report/${reportId}/export?format=xml`);
    assert.strictEqual(badFormat.status, 400);

    // ─── GET ?format=pdf arma la request multipart y cachea el buffer ─
    const pdfExport = await requestJson(baseUrl, 'GET', `/mediciones-batch/report/${reportId}/export?format=pdf`);
    assert.strictEqual(pdfExport.status, 200);
    assert.strictEqual(pdfExport.headers['content-type'], 'application/pdf');
    assert.ok(pdfExport.buffer.equals(FAKE_PDF_BYTES), 'debe servir el PDF devuelto por mdtopdf');

    assert.strictEqual(fetchCalls.length, 1, 'debe haber llamado a mdtopdf exactamente una vez');
    const call = fetchCalls[0];
    assert.strictEqual(call.url, `${process.env.MDTOPDF_URL || 'http://server1:8600'}/api/convert`);
    assert.strictEqual(call.options.method, 'POST');
    assert.ok(call.options.body instanceof FormData, 'debe enviar un FormData multipart');
    const sentFile = call.options.body.get('file');
    assert.ok(sentFile, 'el FormData debe incluir el campo "file"');
    assert.strictEqual(sentFile.name, 'reporte-mediciones.md');
    const sentMarkdown = await sentFile.text();
    assert.ok(sentMarkdown.startsWith('---\n'), 'el archivo enviado debe ser el Markdown con frontmatter');

    // ─── Segunda descarga de PDF usa la caché (no vuelve a llamar a fetch) ─
    const pdfExportAgain = await requestJson(baseUrl, 'GET', `/mediciones-batch/report/${reportId}/export?format=pdf`);
    assert.strictEqual(pdfExportAgain.status, 200);
    assert.ok(pdfExportAgain.buffer.equals(FAKE_PDF_BYTES));
    assert.strictEqual(fetchCalls.length, 1, 'la segunda descarga debe usar el buffer cacheado, sin llamar de nuevo a mdtopdf');

    console.log('✅ medicionesBatchReport.routes.test.js — todos los casos OK');
  } finally {
    server.close();
    global.fetch = originalFetch;
  }
}

run().catch((err) => {
  console.error('❌ medicionesBatchReport.routes.test.js FALLÓ:', err);
  process.exit(1);
});
