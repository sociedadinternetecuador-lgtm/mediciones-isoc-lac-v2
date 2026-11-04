'use strict';

/**
 * Prueba manual EN VIVO (requiere red real y PULSE_API_KEY, no es parte de "npm test").
 * Confirma contra la API real de ISOC Pulse, no contra documentación.
 *
 * Ejecutar: PULSE_API_KEY=xxxx node test/pulseAdapter.live.smoke.test.js
 */

const assert = require('assert');
const pulse = require('../logic/adapters/pulse.adapter');

async function run() {
  if (!pulse.isConfigured()) {
    console.error('Falta PULSE_API_KEY en el entorno — prueba omitida.');
    process.exit(1);
  }

  const roa = await pulse.getRoaCoverage('ec', { startDate: '2026-10-20', endDate: '2026-10-26' });
  assert.ok(Array.isArray(roa.data) && roa.data.length > 0, 'ROA Ecuador debe traer datos');
  assert.ok(typeof roa.data[0].value === 'number');
  console.log('ROA Ecuador OK:', roa.data[0]);

  const dnssec = await pulse.getDnssecAdoption('py', { startDate: '2026-10-26', endDate: '2026-11-01' });
  assert.ok(Array.isArray(dnssec.data) && dnssec.data.length > 0, 'DNSSEC Paraguay debe traer datos');
  assert.ok(typeof dnssec.data[0].signed === 'boolean');
  console.log('DNSSEC Paraguay OK:', dnssec.data[0]);

  const resilience = await pulse.getResilience('py', { year: 2025 });
  assert.ok(Array.isArray(resilience.data), 'Resilience debe traer un arreglo (puede estar vacío según año/trimestre)');
  console.log('Resilience Paraguay OK:', resilience.data[0] || '(sin datos para ese año/trimestre)');

  console.log('pulseAdapter.live.smoke.test.js: OK');
}

run().catch((e) => {
  console.error('FALLÓ:', e);
  process.exit(1);
});
