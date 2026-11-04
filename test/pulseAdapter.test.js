'use strict';

/**
 * Pruebas del adaptador de ISOC Pulse — sin red real. La función de fetch se inyecta
 * (mismo patrón que resolvePublicAddresses(hostname, lookup) en safeWebFetch.adapter.js),
 * así que estas pruebas corren en CI sin depender de pulse-api.internetsociety.org.
 *
 * Ejecutar: node test/pulseAdapter.test.js
 */

const assert = require('assert');
const pulse = require('../logic/adapters/pulse.adapter');

async function run() {
  // --- sin API key configurada: debe fallar con código propio, no con un error genérico ---
  {
    delete process.env.PULSE_API_KEY;
    pulse.clearCache();
    assert.strictEqual(pulse.isConfigured(), false);

    let threw = null;
    try {
      await pulse.getRoaCoverage('ec', { startDate: '2026-10-01', endDate: '2026-10-02' });
    } catch (e) {
      threw = e;
    }
    assert.ok(threw, 'debe lanzar cuando no hay API key');
    assert.strictEqual(threw.code, 'PULSE_NOT_CONFIGURED');
  }

  process.env.PULSE_API_KEY = 'test-token';
  pulse.clearCache();

  // --- respuesta real confirmada en vivo (2026-11-04) para ROA de Ecuador ---
  {
    const fakeRoaResponse = {
      statusCode: 200,
      body: JSON.stringify({
        data: [
          { date: '2026-10-26', value: 0.9684 },
          { date: '2026-10-25', value: 0.9682 }
        ],
        deprecations: null
      })
    };
    let calledWith = null;
    const fetchImpl = async (url, options) => {
      calledWith = { url: url.toString(), options };
      return fakeRoaResponse;
    };

    const result = await pulse.getRoaCoverage('ec', {
      startDate: '2026-10-25',
      endDate: '2026-10-26',
      fetchImpl
    });

    assert.strictEqual(result.data.length, 2);
    assert.strictEqual(result.data[0].value, 0.9684);
    assert.ok(calledWith.url.includes('/roa/country/ec'));
    assert.ok(calledWith.url.includes('start_date=2026-10-25'));
    assert.strictEqual(calledWith.options.apiKey, 'test-token');
  }

  // --- resilience exige país en mayúsculas — el adaptador lo normaliza solo ---
  {
    let calledUrl = null;
    const fetchImpl = async (url) => {
      calledUrl = url.toString();
      return { statusCode: 200, body: JSON.stringify({ data: [] }) };
    };
    await pulse.getResilience('py', { year: 2025, fetchImpl });
    assert.ok(calledUrl.includes('country=PY'), `esperaba país en mayúsculas, recibido: ${calledUrl}`);
  }

  // --- 401/403 del lado de Pulse se traduce a código propio, no se propaga crudo ---
  {
    pulse.clearCache();
    const fetchImpl = async () => ({ statusCode: 401, body: '{"detail":"invalid token"}' });
    let threw = null;
    try {
      await pulse.getDnssecAdoption('py', { startDate: '2026-11-01', endDate: '2026-11-01', fetchImpl });
    } catch (e) {
      threw = e;
    }
    assert.ok(threw);
    assert.strictEqual(threw.code, 'PULSE_UNAUTHORIZED');
  }

  // --- caché: una segunda llamada con los mismos parámetros no debe volver a invocar fetchImpl ---
  {
    pulse.clearCache();
    let callCount = 0;
    const fetchImpl = async () => {
      callCount += 1;
      return { statusCode: 200, body: JSON.stringify({ data: [{ date: '2026-11-01', value: 0.5 }] }) };
    };
    await pulse.getIpv6Adoption('ec', { startDate: '2026-11-01', endDate: '2026-11-01', fetchImpl });
    await pulse.getIpv6Adoption('ec', { startDate: '2026-11-01', endDate: '2026-11-01', fetchImpl });
    assert.strictEqual(callCount, 1, 'la segunda llamada debe servirse desde caché');
  }

  // --- timeout/errores de red se traducen a código propio ---
  {
    pulse.clearCache();
    const fetchImpl = async () => {
      const err = new Error('boom');
      err.code = 'PULSE_TIMEOUT';
      throw err;
    };
    let threw = null;
    try {
      await pulse.getRoaCoverage('ec', { startDate: '2026-11-01', endDate: '2026-11-01', fetchImpl });
    } catch (e) {
      threw = e;
    }
    assert.ok(threw);
    assert.strictEqual(threw.code, 'PULSE_TIMEOUT');
  }

  delete process.env.PULSE_API_KEY;
  console.log('pulseAdapter.test.js: OK');
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
