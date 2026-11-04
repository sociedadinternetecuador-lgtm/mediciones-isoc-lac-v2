'use strict';

/**
 * Prueba manual EN VIVO contra el Observatorio DNSSEC v2 real (requiere red
 * real y que el servicio esté arriba). No es parte de "npm test".
 *
 * Ejecutar: DNSVIZ_OBSERVATORIO_URL=https://dnssec.corpece.org.ec node test/dnsvizAdapter.live.smoke.test.js
 */

const assert = require('assert');
const dnsviz = require('../logic/adapters/dnsviz.adapter');

async function run() {
  if (!dnsviz.isConfigured()) {
    console.error('Falta DNSVIZ_OBSERVATORIO_URL en el entorno — prueba omitida.');
    process.exit(1);
  }

  console.log('Corriendo análisis real (puede tardar ~60-90s)...');
  const res = await dnsviz.runFullAnalysis('isoc.org', { maxWaitMs: 120000 });
  console.log('available:', res.available, res.reason || '');
  assert.ok(res.available, 'el análisis debería completarse contra el servicio real');
  assert.ok(res.result && res.result.structured_view, 'debe traer structured_view');

  const signal = dnsviz.extractCryptoValidationSignal(res.result);
  console.log('Señal criptográfica para isoc.org:', JSON.stringify(signal, null, 2));

  console.log('dnsvizAdapter.live.smoke.test.js: OK');
}

run().catch((e) => {
  console.error('FALLÓ:', e);
  process.exit(1);
});
