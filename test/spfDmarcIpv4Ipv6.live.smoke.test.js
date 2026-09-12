'use strict';

/**
 * Prueba de humo EN VIVO (requiere red real) del fix de Fase 1
 * (2026-09-12): spf/dmarc/ipv4/ipv6 pasaron de llamar a
 * https://dns.google/resolve y https://ipapi.co directo desde el
 * navegador (index.html) a resolverse en el backend con
 * dns.resolveTxt/resolve4/resolve6 nativos (handleSpf/handleDmarc/
 * handleIpv4/handleIpv6 en server.js), mismo patrón que handleMx/
 * handleCaa. Causa raíz del "Servicio no disponible" uniforme en los
 * 20/20 dominios de la auditoría: la llamada nunca llegaba a este
 * servidor, así que no quedaba ningún log ni control server-side. No
 * está en el script "test" de package.json — depende del estado real
 * de Internet, mismo criterio que domainChecks.live.smoke.test.js.
 *
 * Ejecutar manualmente (con el servidor local corriendo):
 *   PORT=3500 node server.js &
 *   node test/spfDmarcIpv4Ipv6.live.smoke.test.js
 */

const assert = require('assert');

const BASE = process.env.MEDICIONES_TEST_BASE || 'http://localhost:3500';

async function getJSON(path) {
  const res = await fetch(`${BASE}${path}`);
  return res.json();
}

async function run() {
  // ── SPF: dominio real y estable con SPF conocido (google.com) ──────────
  const spfFound = await getJSON('/spf/google.com');
  assert.strictEqual(spfFound.error, undefined, `spf/google.com no debe fallar: ${spfFound.error}`);
  assert.strictEqual(spfFound.found, true, 'google.com tiene un registro SPF real y estable');

  // Dominio del propio experimento (nic.uy, registro .uy) — validación
  // cruzada contra un dominio real usado en la auditoría, no solo un
  // gigante tecnológico.
  const spfNicUy = await getJSON('/spf/nic.uy');
  assert.strictEqual(spfNicUy.error, undefined, `spf/nic.uy no debe fallar: ${spfNicUy.error}`);
  assert.strictEqual(typeof spfNicUy.found, 'boolean');

  // Dominio inexistente (NXDOMAIN): debe dar found:false SIN error, no
  // un "Servicio no disponible" genérico.
  const spfInexistente = await getJSON('/spf/dominio-que-no-existe-xyz123abc.ec');
  assert.strictEqual(spfInexistente.error, undefined, 'NXDOMAIN no debe reportarse como error de medición');
  assert.strictEqual(spfInexistente.found, false);

  // ── DMARC: mismo patrón ─────────────────────────────────────────────────
  const dmarcFound = await getJSON('/dmarc/google.com');
  assert.strictEqual(dmarcFound.error, undefined, `dmarc/google.com no debe fallar: ${dmarcFound.error}`);
  assert.strictEqual(dmarcFound.found, true, 'google.com tiene un registro DMARC real y estable');

  const dmarcInexistente = await getJSON('/dmarc/dominio-que-no-existe-xyz123abc.ec');
  assert.strictEqual(dmarcInexistente.error, undefined);
  assert.strictEqual(dmarcInexistente.found, false);

  // ── IPv4 ────────────────────────────────────────────────────────────────
  const ipv4Found = await getJSON('/ipv4/google.com');
  assert.strictEqual(ipv4Found.error, undefined, `ipv4/google.com no debe fallar: ${ipv4Found.error}`);
  assert.ok(Array.isArray(ipv4Found.ips) && ipv4Found.ips.length > 0, 'google.com debe tener direcciones IPv4');
  assert.ok(Array.isArray(ipv4Found.geos), 'debe traer el arreglo geos aunque esté vacío o parcial');

  const ipv4Inexistente = await getJSON('/ipv4/dominio-que-no-existe-xyz123abc.ec');
  assert.strictEqual(ipv4Inexistente.error, undefined);
  assert.deepStrictEqual(ipv4Inexistente.ips, []);

  // ── IPv6 (google.com es dual-stack, estable) ───────────────────────────
  const ipv6Found = await getJSON('/ipv6/google.com');
  assert.strictEqual(ipv6Found.error, undefined, `ipv6/google.com no debe fallar: ${ipv6Found.error}`);
  assert.ok(Array.isArray(ipv6Found.ips) && ipv6Found.ips.length > 0, 'google.com debe tener direcciones IPv6 (dual-stack)');

  const ipv6Inexistente = await getJSON('/ipv6/dominio-que-no-existe-xyz123abc.ec');
  assert.strictEqual(ipv6Inexistente.error, undefined);
  assert.deepStrictEqual(ipv6Inexistente.ips, []);

  console.log('✅ spfDmarcIpv4Ipv6.live.smoke.test.js — todos los casos OK');
}

run().catch((e) => {
  console.error('❌ spfDmarcIpv4Ipv6.live.smoke.test.js falló:', e.message);
  process.exit(1);
});
