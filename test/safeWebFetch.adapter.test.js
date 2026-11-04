'use strict';

const assert = require('assert');
const http = require('http');
const {
  fetchSafePage,
  resolveFinalWebTarget,
  isBlockedIp,
  validateUrlPolicy
} = require('../logic/adapters/safeWebFetch.adapter');

function lookup(address) {
  return async () => [{ address, family: address.includes(':') ? 6 : 4 }];
}

function requestFromMap(map) {
  return async (url) => {
    const key = url.toString();
    const value = map[key];
    if (!value) throw new Error(`Unexpected request: ${key}`);
    return {
      url: key,
      statusCode: value.statusCode,
      headers: value.headers || {},
      body: value.body || ''
    };
  };
}

async function rejectsWithCode(fn, code) {
  let err = null;
  try {
    await fn();
  } catch (e) {
    err = e;
  }
  assert(err, `Expected ${code}`);
  assert.strictEqual(err.code, code);
}

async function run() {
  const resolved = await resolveFinalWebTarget('https://example.test', {
    method: 'HEAD',
    lookup: lookup('93.184.216.34'),
    requestImpl: requestFromMap({
      'https://example.test/': {
        statusCode: 301,
        headers: { location: 'https://www.example.test/' }
      },
      'https://www.example.test/': {
        statusCode: 200,
        headers: { 'strict-transport-security': 'max-age=31536000' },
        body: '<html>ok</html>'
      }
    })
  });

  assert.strictEqual(resolved.finalUrl, 'https://www.example.test/');
  assert.strictEqual(resolved.response.statusCode, 200);
  assert.strictEqual(resolved.response.headers['strict-transport-security'], 'max-age=31536000');
  assert.deepStrictEqual(resolved.chain.map((entry) => entry.statusCode), [301, 200]);

  await rejectsWithCode(() => resolveFinalWebTarget('https://internal.test', {
    lookup: lookup('127.0.0.1'),
    requestImpl: requestFromMap({})
  }), 'WEBFETCH_BLOCKED_IP');

  await rejectsWithCode(() => resolveFinalWebTarget('https://example.test', {
    lookup: lookup('93.184.216.34'),
    requestImpl: requestFromMap({
      'https://example.test/': {
        statusCode: 302,
        headers: { location: 'http://169.254.169.254/latest/meta-data' }
      }
    })
  }), 'WEBFETCH_BLOCKED_IP');

  assert.strictEqual(isBlockedIp('10.0.0.1'), true);
  assert.strictEqual(isBlockedIp('172.16.0.1'), true);
  assert.strictEqual(isBlockedIp('192.168.1.1'), true);
  assert.strictEqual(isBlockedIp('::1'), true);
  assert.strictEqual(isBlockedIp('fe80::1'), true);
  assert.strictEqual(isBlockedIp('2606:2800:220:1:248:1893:25c8:1946'), false);

  assert.throws(() => validateUrlPolicy(new URL('ftp://example.test')), /Protocolo/);
  assert.throws(() => validateUrlPolicy(new URL('https://example.test:8443')), /Puerto/);

  // (2026-11-04) — regresión real: requestPage() (la implementación REAL
  // usada cuando no se inyecta requestImpl, a diferencia de todos los casos
  // de arriba) no enviaba ningún User-Agent. Confirmado en vivo contra
  // isoc.org.ec/www.isoc.org.ec: sin User-Agent, Cloudflare responde 429
  // (bloqueo de bot); con un User-Agent identificable, 200 normal.
  // No hace falta un servidor real: basta con interceptar http.request()
  // (lo que requestPage() llama internamente) para capturar los headers que
  // arma, dejando que la conexión falle rápido (ECONNREFUSED, puerto 80
  // local casi nunca tiene nada escuchando) — no nos interesa la respuesta,
  // solo qué headers se intentaron enviar.
  await (async () => {
    const originalRequest = http.request;
    let capturedHeaders = null;
    http.request = function (options, callback) {
      capturedHeaders = options.headers;
      return originalRequest.call(http, options, callback);
    };
    try {
      // 192.0.2.0/24 (TEST-NET-1, RFC 5737) — no está en ningún rango
      // bloqueado por isBlockedIp (no es privado/loopback/link-local), así
      // que pasa esa validación y llega a requestPage(); no es enrutable en
      // la práctica, así que la conexión falla rápido o por timeout (1s).
      await fetchSafePage('http://example-test.invalid/', {
        method: 'HEAD',
        timeoutMs: 1000,
        lookup: lookup('192.0.2.1')
      }).catch(() => {});
    } finally {
      http.request = originalRequest;
    }
    assert.ok(capturedHeaders, 'requestPage() debería haber armado los headers antes de intentar conectar');
    assert.ok(
      typeof capturedHeaders['User-Agent'] === 'string' && capturedHeaders['User-Agent'].length > 0,
      `requestPage() debe enviar un User-Agent no vacío (recibido: ${JSON.stringify(capturedHeaders['User-Agent'])})`
    );
  })();
  console.log('PASS requestPage_envia_user_agent_real');

  console.log('PASS safeWebFetch.adapter');
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
