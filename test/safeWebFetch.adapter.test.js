'use strict';

const assert = require('assert');
const {
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

  console.log('PASS safeWebFetch.adapter');
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
