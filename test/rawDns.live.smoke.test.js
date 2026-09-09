'use strict';

/**
 * Prueba de humo EN VIVO (requiere red real) del adaptador DNS crudo
 * (logic/adapters/rawDns.adapter.js). A diferencia de los tests de
 * paridad (datasetDomains.parity, dnsValidation.classify.parity), esta
 * prueba SÍ depende de la red y del estado real de Internet — por eso no
 * está en el script "test" de package.json. Ejecutar manualmente:
 *
 *   node test/rawDns.live.smoke.test.js
 *
 * Casos cubiertos:
 *  - Preflight real contra Cloudflare y Google (". NS").
 *  - VALID real (isoc.org.ec) y NXDOMAIN real (dominio inventado).
 *  - CD=1 efectivo: dnssec-failed.org (dominio de prueba público con
 *    DNSSEC deliberadamente roto) debe dar NOERROR con CD=1, aunque SIN
 *    CD=1 los mismos resolvers respondan SERVFAIL (verificado también
 *    aquí con una consulta de contraste sin el flag).
 *  - Timeout real contra una IP de TEST-NET (RFC 5737, no debe responder).
 */

const assert = require('assert');
const dgram = require('dgram');
const dnsPacket = require('dns-packet');
const { dnsQuery } = require('../logic/adapters/rawDns.adapter');

function queryWithoutCD(server, name, rtype, timeoutMs) {
  return new Promise((resolve, reject) => {
    const id = Math.floor(Math.random() * 65535);
    const buf = dnsPacket.encode({
      type: 'query',
      id,
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{ type: rtype, name, class: 'IN' }],
    });
    const socket = dgram.createSocket('udp4');
    const timer = setTimeout(() => { socket.close(); reject(new Error('timeout')); }, timeoutMs);
    socket.on('message', (msg) => {
      const decoded = dnsPacket.decode(msg);
      if (decoded.id !== id) return;
      clearTimeout(timer);
      socket.close();
      resolve(decoded);
    });
    socket.on('error', (err) => { clearTimeout(timer); reject(err); });
    socket.send(buf, 0, buf.length, 53, server);
  });
}

async function run() {
  console.log('--- Preflight real (". NS") ---');
  const cf = await dnsQuery('cloudflare', '1.1.1.1', '.', 'NS', 2500, 0);
  const gg = await dnsQuery('google', '8.8.8.8', '.', 'NS', 2500, 0);
  assert.strictEqual(cf.rcode, 'NOERROR', 'preflight cloudflare debe ser NOERROR');
  assert.strictEqual(gg.rcode, 'NOERROR', 'preflight google debe ser NOERROR');
  console.log('PASS preflight NOERROR en ambos resolvers');

  console.log('\n--- VALID real ---');
  const valid = await dnsQuery('cloudflare', '1.1.1.1', 'isoc.org.ec', 'NS', 2500, 1);
  assert.strictEqual(valid.rcode, 'NOERROR', 'isoc.org.ec debe ser NOERROR');
  console.log('PASS isoc.org.ec -> NOERROR');

  console.log('\n--- NXDOMAIN real ---');
  const nx = await dnsQuery('cloudflare', '1.1.1.1', 'nxdomain-test-parity-check-999.ec', 'NS', 2500, 1);
  assert.strictEqual(nx.rcode, 'NXDOMAIN', 'dominio inventado debe ser NXDOMAIN');
  console.log('PASS dominio inventado -> NXDOMAIN');

  console.log('\n--- CD=1 efectivo (dnssec-failed.org) ---');
  const withCd = await dnsQuery('cloudflare', '1.1.1.1', 'dnssec-failed.org', 'NS', 2500, 1);
  assert.strictEqual(withCd.rcode, 'NOERROR', 'con CD=1 debe ser NOERROR (checking disabled)');
  const withoutCd = await queryWithoutCD('1.1.1.1', 'dnssec-failed.org', 'NS', 2500);
  assert.strictEqual(withoutCd.rcode, 'SERVFAIL', 'sin CD=1, un resolver validador debe dar SERVFAIL');
  console.log('PASS con CD=1 -> NOERROR; sin CD=1 -> SERVFAIL (confirma que el flag es efectivo)');

  console.log('\n--- Timeout real (IP de TEST-NET, RFC 5737) ---');
  const start = Date.now();
  const timeoutResult = await dnsQuery('blackhole', '192.0.2.1', 'isoc.org.ec', 'NS', 1200, 1);
  const elapsed = Date.now() - start;
  assert.strictEqual(timeoutResult.rcode, 'TIMEOUT');
  assert.strictEqual(timeoutResult.attempts, 2, 'retries=1 debe producir 2 intentos');
  assert.ok(elapsed >= 2 * 1200 - 200, 'cada intento debe tardar ~timeout completo (no acumulado a la baja)');
  console.log(`PASS timeout tras 2 intentos (${elapsed}ms)`);

  console.log('\n=== TODAS LAS PRUEBAS DE HUMO EN VIVO PASARON ===');
}

run().catch((error) => {
  console.error('FAIL', error.message);
  process.exit(1);
});
