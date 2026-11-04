'use strict';

/**
 * Pruebas del adaptador hacia Observatorio DNSSEC v2 — sin red real.
 * Ejecutar: node test/dnsvizAdapter.test.js
 */

const assert = require('assert');
const dnsviz = require('../logic/adapters/dnsviz.adapter');

async function run() {
  // --- sin URL configurada: degrada a available:false, no lanza ---
  {
    delete process.env.DNSVIZ_OBSERVATORIO_URL;
    assert.strictEqual(dnsviz.isConfigured(), false);
    const res = await dnsviz.runFullAnalysis('example.com');
    assert.strictEqual(res.available, false);
    assert.strictEqual(res.reason, 'DNSVIZ_OBS_NOT_CONFIGURED');
  }

  process.env.DNSVIZ_OBSERVATORIO_URL = 'https://dnssec.corpece.org.ec';

  // --- flujo feliz: queued -> running -> done -> result.json ---
  {
    const calls = [];
    const fetchImpl = async (url) => {
      calls.push(url.pathname);
      if (url.pathname === '/analyze') {
        return { statusCode: 202, body: JSON.stringify({ id: 'abc123', status: 'queued' }) };
      }
      if (url.pathname === '/analyze/abc123/status') {
        const isFirst = calls.filter((p) => p.endsWith('/status')).length === 1;
        return {
          statusCode: 200,
          body: JSON.stringify({ status: isFirst ? 'running' : 'done', progress: isFirst ? 40 : 100 })
        };
      }
      if (url.pathname === '/analyze/abc123/result.json') {
        return {
          statusCode: 200,
          body: JSON.stringify({
            domain: 'example.com',
            structured_view: {
              zones: [
                { name: 'example.com', classification: { is_target: true }, errors: [{ code: 'RRSIG_EXPIRED' }], warnings: [] },
                { name: 'com', classification: { is_target: false }, errors: [{ code: 'SOMETHING_ELSE' }], warnings: [] }
              ]
            }
          })
        };
      }
      throw new Error('ruta inesperada: ' + url.pathname);
    };

    const res = await dnsviz.runFullAnalysis('example.com', { fetchImpl, pollIntervalMs: 1 });
    assert.strictEqual(res.available, true);
    assert.strictEqual(res.id, 'abc123');

    const signal = dnsviz.extractCryptoValidationSignal(res.result);
    assert.strictEqual(signal.hasCryptoFailure, true, 'RRSIG_EXPIRED en la zona del dominio debe contar como fallo criptográfico');
    assert.strictEqual(signal.issues.length, 1);
  }

  // --- error solo en zona ancestro: no debe contar como fallo del dominio ---
  {
    const result = {
      structured_view: {
        zones: [
          { name: 'example.com', classification: { is_target: true }, errors: [], warnings: [] },
          { name: 'com', classification: { is_target: false }, errors: [{ code: 'DNSKEY_MISSING' }], warnings: [] }
        ]
      }
    };
    const signal = dnsviz.extractCryptoValidationSignal(result);
    assert.strictEqual(signal.hasCryptoFailure, false);
  }

  // --- regresión real: UNABLE_TO_RETRIEVE_DNSSEC_RECORDS es operativo, NO
  // criptográfico, aunque contenga la subcadena "DS" (de "RECOR-DS") que
  // matchearía por accidente contra CRYPTO_DNSSEC_HINTS. Encontrado
  // probando en vivo contra isoc.org el 2026-11-04 — sin esta exclusión,
  // cualquier timeout/fallo de transporte se reportaba como fallo de firma.
  {
    const result = {
      structured_view: {
        zones: [
          { name: 'example.com', classification: { is_target: true }, errors: [{ code: 'UNABLE_TO_RETRIEVE_DNSSEC_RECORDS' }], warnings: [] }
        ]
      }
    };
    const signal = dnsviz.extractCryptoValidationSignal(result);
    assert.strictEqual(signal.hasCryptoFailure, false, 'UNABLE_TO_RETRIEVE_DNSSEC_RECORDS es operativo, no debe contar como fallo criptográfico');
  }

  // --- error de análisis (status: error) ---
  {
    const fetchImpl = async (url) => {
      if (url.pathname === '/analyze') return { statusCode: 202, body: JSON.stringify({ id: 'x1' }) };
      return { statusCode: 200, body: JSON.stringify({ status: 'error', message: 'dnsviz probe falló' }) };
    };
    const res = await dnsviz.runFullAnalysis('bad-domain.test', { fetchImpl, pollIntervalMs: 1 });
    assert.strictEqual(res.available, false);
    assert.strictEqual(res.reason, 'DNSVIZ_OBS_ANALYSIS_FAILED');
  }

  // --- servicio caído (network error / facturación, etc.): nunca lanza ---
  {
    const fetchImpl = async () => {
      const err = new Error('boom');
      throw err;
    };
    const res = await dnsviz.runFullAnalysis('example.com', { fetchImpl });
    assert.strictEqual(res.available, false);
    assert.strictEqual(res.reason, 'DNSVIZ_OBS_NETWORK_ERROR');
  }

  delete process.env.DNSVIZ_OBSERVATORIO_URL;
  console.log('dnsvizAdapter.test.js: OK');
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
