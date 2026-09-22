'use strict';

/**
 * checkDomainLiveness() — mismo estilo de mocking que
 * test/safeWebFetch.adapter.test.js (lookup/requestImpl inyectados, sin red
 * real), fuerza cada uno de los 9 estado_validacion de forma determinista.
 *
 * Ejecutar: node test/ged2026Liveness.classify.test.js
 */

const assert = require('assert');
const { checkDomainLiveness } = require('../logic/adapters/ged2026Liveness.adapter');

function lookup(address) {
  return async () => [{ address, family: address.includes(':') ? 6 : 4 }];
}

function lookupThrows(code) {
  return async () => {
    throw Object.assign(new Error(code), { code });
  };
}

function requestFromMap(map) {
  return async (url) => {
    const key = url.toString();
    const value = map[key];
    if (!value) throw new Error(`Unexpected request: ${key}`);
    if (value.throwCode) throw Object.assign(new Error(value.throwCode), { code: value.throwCode });
    return { url: key, statusCode: value.statusCode, headers: value.headers || {}, body: value.body || '' };
  };
}

async function run() {
  // ─── https_ok ─────────────────────────────────────────────────────
  const httpsOk = await checkDomainLiveness('good.test', {
    lookup: lookup('93.184.216.34'),
    requestImpl: requestFromMap({ 'https://good.test/': { statusCode: 200, headers: {} } }),
  });
  assert.strictEqual(httpsOk.estado_validacion, 'https_ok');

  // ─── http_ok (fallback cuando https falla sin código clasificable) ──
  const httpOk = await checkDomainLiveness('onlyhttp.test', {
    lookup: lookup('93.184.216.34'),
    requestImpl: requestFromMap({
      'https://onlyhttp.test/': { throwCode: 'SOME_UNCLASSIFIED_ERROR' },
      'http://onlyhttp.test/': { statusCode: 200, headers: {} },
    }),
  });
  assert.strictEqual(httpOk.estado_validacion, 'http_ok');

  // ─── redirect (el destino final cambia de host) ──────────────────
  const redirect = await checkDomainLiveness('redirect.test', {
    lookup: lookup('93.184.216.34'),
    requestImpl: requestFromMap({
      'https://redirect.test/': { statusCode: 301, headers: { location: 'https://other.test/' } },
      'https://other.test/': { statusCode: 200, headers: {} },
    }),
  });
  assert.strictEqual(redirect.estado_validacion, 'redirect');

  // ─── timeout (https y http agotan tiempo) ────────────────────────
  const timeout = await checkDomainLiveness('slow.test', {
    lookup: lookup('93.184.216.34'),
    requestImpl: requestFromMap({
      'https://slow.test/': { throwCode: 'WEBFETCH_TOTAL_TIMEOUT' },
      'http://slow.test/': { throwCode: 'WEBFETCH_TOTAL_TIMEOUT' },
    }),
  });
  assert.strictEqual(timeout.estado_validacion, 'timeout');

  // ─── tls_error (https falla por TLS, http también falla sin clasificar) ──
  const tlsError = await checkDomainLiveness('badtls.test', {
    lookup: lookup('93.184.216.34'),
    requestImpl: requestFromMap({
      'https://badtls.test/': { throwCode: 'CERT_HAS_EXPIRED' },
      'http://badtls.test/': { throwCode: 'SOME_UNCLASSIFIED_ERROR' },
    }),
  });
  assert.strictEqual(tlsError.estado_validacion, 'tls_error');

  // ─── inactive vía IP bloqueada en la resolución DNS ───────────────
  const blocked = await checkDomainLiveness('internal.test', {
    lookup: lookup('127.0.0.1'),
    requestImpl: requestFromMap({}),
  });
  assert.strictEqual(blocked.estado_validacion, 'inactive');

  // ─── inactive vía conexión rechazada en ambos protocolos ─────────
  const refused = await checkDomainLiveness('refused.test', {
    lookup: lookup('93.184.216.34'),
    requestImpl: requestFromMap({
      'https://refused.test/': { throwCode: 'ECONNREFUSED' },
      'http://refused.test/': { throwCode: 'ECONNREFUSED' },
    }),
  });
  assert.strictEqual(refused.estado_validacion, 'inactive');

  // ─── dns_error (fallo de resolución no clasificado como bloqueado) ──
  const dnsError = await checkDomainLiveness('noresolve.test', {
    lookup: lookupThrows('EAI_AGAIN'),
    requestImpl: requestFromMap({}),
  });
  assert.strictEqual(dnsError.estado_validacion, 'dns_error');

  // ─── unknown (ambos protocolos fallan sin código clasificable) ───
  const unknown = await checkDomainLiveness('mystery.test', {
    lookup: lookup('93.184.216.34'),
    requestImpl: requestFromMap({
      'https://mystery.test/': { throwCode: 'SOME_UNCLASSIFIED_ERROR' },
      'http://mystery.test/': { throwCode: 'ANOTHER_UNCLASSIFIED_ERROR' },
    }),
  });
  assert.strictEqual(unknown.estado_validacion, 'unknown');

  console.log('✅ ged2026Liveness.classify.test.js — todos los casos OK');
}

run().catch((err) => {
  console.error('❌ ged2026Liveness.classify.test.js FALLÓ:', err);
  process.exit(1);
});
