'use strict';

/**
 * Tests del check `rpki` de MEDICIONES tras su enriquecimiento en Fase 2
 * (2026-09-15) — ver IMPLEMENTACION_MEDICIONES_FASE2_ROUTING_RPKI.md.
 *
 * No se crea un check `routing` separado: Paraguay/upstream lo implementa
 * como una simple repetición de la misma `rpkiValidity()` ya usada por
 * `rpki`, con un único dato adicional real (los orígenes ASN/prefijo
 * observados vía Team Cymru — visibilidad MOAS). Ese dato se incorporó
 * directamente a `rpki` (campo `routes` por IP) en vez de duplicar el
 * check completo.
 *
 * CI-safe: nada de esto toca la red real. dns.resolve4/resolve6/resolveNs/
 * resolveTxt e https.request (usados por resolveAddresses,
 * domainHasNoAddressButIsRealZone, resolveOriginRoutesViaCymru y fetchJSON)
 * se reemplazan por mocks — mismo patrón que test/medicionesMailChecks.test.js.
 *
 * Ejecutar: node test/medicionesRpkiCheck.test.js
 */

const assert = require('assert');
const dns = require('dns').promises;
const https = require('https');
const { EventEmitter } = require('events');

const {
  handleRpki,
  rpkiValidity,
  ipToCymruQuery,
  resolveOriginRoutesViaCymru
} = require('../server');

// ─── Fake response object ──────────────────────────────────────────────
function fakeRes() {
  const res = {
    statusCode: null,
    body: null,
    writeHead(status) { res.statusCode = status; },
    end(payload) { res.body = JSON.parse(payload); }
  };
  return res;
}

// ─── Mocks de DNS ───────────────────────────────────────────────────────
function mockAddresses({ v4 = [], v6 = [], ns = [] } = {}) {
  dns.resolve4 = async () => (v4.length ? v4 : Promise.reject(Object.assign(new Error('ENODATA'), { code: 'ENODATA' })));
  dns.resolve6 = async () => (v6.length ? v6 : Promise.reject(Object.assign(new Error('ENODATA'), { code: 'ENODATA' })));
  dns.resolveNs = async () => (ns.length ? ns : Promise.reject(Object.assign(new Error('ENODATA'), { code: 'ENODATA' })));
}

// txtByIp: { [ip]: rows } donde rows es lo que devolvería dns.resolveTxt
// (array de arrays de strings) o un Error para forzar un fallo de consulta.
function mockCymruTxt(txtByIp) {
  dns.resolveTxt = async query => {
    const ip = Object.keys(txtByIp).find(candidate => query.startsWith(cymruPrefix(candidate)));
    const entry = ip ? txtByIp[ip] : undefined;
    if (entry instanceof Error) throw entry;
    if (!entry) throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
    return entry;
  };
}
function cymruPrefix(ip) {
  // Reconstruye el mismo prefijo de consulta que ipToCymruQuery genera,
  // para poder mapear query -> IP en el mock sin duplicar la lógica exacta.
  const query = ipToCymruQuery(ip);
  return query.split('.').slice(0, 4).join('.');
}

// ─── Mock de https.request (RIPEstat network-info / rpki-validation) ───
// resolver(url: URL) -> { body } | { error } | { timeout: true } | undefined
function mockRipe(resolver) {
  https.request = (url, options, callback) => {
    const target = typeof url === 'string' ? new URL(url) : url;
    const req = new EventEmitter();
    req.write = () => {};
    req.setTimeout = (ms, cb) => { req._onTimeout = cb; };
    req.destroy = err => { req.emit('error', err || new Error('destroyed')); };
    req.on('error', () => {}); // evita "Unhandled 'error' event" si nadie más escucha aún
    req.end = () => {
      process.nextTick(() => {
        let spec;
        try { spec = resolver(target); } catch (e) { req.emit('error', e); return; }
        if (!spec) { req.emit('error', new Error(`mock: sin respuesta configurada para ${target.href}`)); return; }
        if (spec.timeout) { if (req._onTimeout) req._onTimeout(); return; }
        if (spec.error) { req.emit('error', spec.error); return; }
        const resStream = new EventEmitter();
        callback(resStream);
        process.nextTick(() => {
          resStream.emit('data', typeof spec.body === 'string' ? spec.body : JSON.stringify(spec.body));
          resStream.emit('end');
        });
      });
    };
    return req;
  };
}

function networkInfoBody(asn, prefix) {
  return { data: { asns: [String(asn)], prefix } };
}
function validationBody(status) {
  return { data: { status, validating_roas: [] } };
}

async function run() {
  // ── ipToCymruQuery: formato de consulta correcto para IPv4 e IPv6 ──
  {
    assert.strictEqual(ipToCymruQuery('8.8.8.8'), '8.8.8.origin.asn.cymru.com');
    // 2001:4860:4860::8888 -> primeros 48 bits: 2001:4860:4860
    const q6 = ipToCymruQuery('2001:4860:4860::8888');
    assert.ok(q6.endsWith('.origin6.asn.cymru.com'));
    assert.strictEqual(q6.split('.').length, 16); // 12 nibbles + origin6.asn.cymru.com
    console.log('PASS rpki_cymru_query_ipv4_ipv6');
  }

  // ── IPv4 VALID ──
  {
    mockAddresses({ v4: ['8.8.8.8'] });
    mockCymruTxt({ '8.8.8.8': [['15169 | 8.8.8.0/24 | US | arin | 1992-12-01']] });
    mockRipe(url => (
      url.pathname.includes('rpki-validation') ? { body: validationBody('valid') } : undefined
    ));
    const res = fakeRes();
    await handleRpki('example.com', res);
    assert.strictEqual(res.body.results.length, 1);
    assert.strictEqual(res.body.results[0].state, 'valid');
    assert.strictEqual(res.body.results[0].family, 4);
    assert.strictEqual(res.body.results[0].asn, 15169);
    assert.strictEqual(res.body.valid, true);
    console.log('PASS rpki_ipv4_valid');
  }

  // ── IPv4 INVALID (invalid_asn) ──
  {
    mockAddresses({ v4: ['1.1.1.1'] });
    mockCymruTxt({ '1.1.1.1': [['13335 | 1.1.1.0/24 | US | arin | 2010-07-14']] });
    mockRipe(url => (
      url.pathname.includes('rpki-validation') ? { body: validationBody('invalid_asn') } : undefined
    ));
    const res = fakeRes();
    await handleRpki('example.com', res);
    assert.strictEqual(res.body.results[0].state, 'invalid_asn');
    assert.strictEqual(res.body.valid, false);
    console.log('PASS rpki_ipv4_invalid_asn');
  }

  // ── IPv4 NOT_FOUND / sin ROA (unknown) — nunca debe verse como invalid ──
  {
    mockAddresses({ v4: ['203.0.113.9'] });
    mockCymruTxt({ '203.0.113.9': [['64512 | 203.0.113.0/24 | ZZ | example | 2020-01-01']] });
    mockRipe(url => (
      url.pathname.includes('rpki-validation') ? { body: validationBody('unknown') } : undefined
    ));
    const res = fakeRes();
    await handleRpki('example.com', res);
    assert.strictEqual(res.body.results[0].state, 'unknown');
    assert.strictEqual(res.body.valid, false);
    console.log('PASS rpki_ipv4_not_found_unknown');
  }

  // ── IPv6 VALID ──
  {
    mockAddresses({ v6: ['2001:4860:4860::8888'] });
    mockCymruTxt({ '2001:4860:4860::8888': [['15169 | 2001:4860::/32 | US | arin | 2005-03-14']] });
    mockRipe(url => (
      url.pathname.includes('rpki-validation') ? { body: validationBody('valid') } : undefined
    ));
    const res = fakeRes();
    await handleRpki('example.com', res);
    assert.strictEqual(res.body.results[0].family, 6);
    assert.strictEqual(res.body.results[0].state, 'valid');
    console.log('PASS rpki_ipv6_valid');
  }

  // ── IPv6 INVALID (invalid_length) ──
  {
    mockAddresses({ v6: ['2606:4700:4700::1111'] });
    mockCymruTxt({ '2606:4700:4700::1111': [['13335 | 2606:4700::/32 | US | arin | 2011-11-01']] });
    mockRipe(url => (
      url.pathname.includes('rpki-validation') ? { body: validationBody('invalid_length') } : undefined
    ));
    const res = fakeRes();
    await handleRpki('example.com', res);
    assert.strictEqual(res.body.results[0].state, 'invalid_length');
    console.log('PASS rpki_ipv6_invalid_length');
  }

  // ── Múltiples IPs, mismo ASN (ambas válidas) ──
  {
    mockAddresses({ v4: ['9.9.9.9', '9.9.9.10'] });
    mockCymruTxt({
      '9.9.9.9': [['19281 | 9.9.9.0/24 | US | arin | 2018-01-01']],
      '9.9.9.10': [['19281 | 9.9.9.0/24 | US | arin | 2018-01-01']]
    });
    mockRipe(url => (
      url.pathname.includes('rpki-validation') ? { body: validationBody('valid') } : undefined
    ));
    const res = fakeRes();
    await handleRpki('example.com', res);
    assert.strictEqual(res.body.results.length, 2);
    assert.ok(res.body.results.every(r => r.state === 'valid' && r.asn === 19281));
    assert.strictEqual(res.body.valid, true);
    console.log('PASS rpki_multiples_ips_mismo_asn');
  }

  // ── Múltiples IPs, ASNs distintos, mezcla VALID/INVALID ──
  {
    mockAddresses({ v4: ['1.0.0.1'], v6: ['2606:4700:4700::1001'] });
    mockCymruTxt({
      '1.0.0.1': [['13335 | 1.0.0.0/24 | US | arin | 2011-08-11']],
      '2606:4700:4700::1001': [['64500 | 2606:4700::/32 | ZZ | example | 2011-11-01']]
    });
    mockRipe(url => {
      if (!url.pathname.includes('rpki-validation')) return undefined;
      const resource = url.searchParams.get('resource');
      return { body: validationBody(resource === '13335' ? 'valid' : 'invalid_asn') };
    });
    const res = fakeRes();
    await handleRpki('example.com', res);
    const byIp = Object.fromEntries(res.body.results.map(r => [r.ip, r.state]));
    assert.strictEqual(byIp['1.0.0.1'], 'valid');
    assert.strictEqual(byIp['2606:4700:4700::1001'], 'invalid_asn');
    assert.strictEqual(res.body.valid, false); // una IP inválida basta para invalidar el conjunto
    console.log('PASS rpki_mix_valid_invalid_multi_asn');
  }

  // ── Múltiples IPs, mezcla VALID/UNKNOWN (sin ningún inválido) ──
  // El frontend (case 'rpki', index.html) debe representar esto como INFO,
  // nunca como PASS (no todas están confirmadas 'valid') ni como FAIL (no
  // hay ningún invalid_asn/invalid_length real) — se verifica aquí que el
  // backend entrega ambos estados sin colapsarlos ni ocultar la mezcla.
  {
    mockAddresses({ v4: ['9.9.9.20', '203.0.113.20'] });
    mockCymruTxt({
      '9.9.9.20': [['19281 | 9.9.9.0/24 | US | arin | 2018-01-01']],
      '203.0.113.20': [['64520 | 203.0.113.0/24 | ZZ | example | 2020-01-01']]
    });
    mockRipe(url => {
      if (!url.pathname.includes('rpki-validation')) return undefined;
      const resource = url.searchParams.get('resource');
      return { body: validationBody(resource === '19281' ? 'valid' : 'unknown') };
    });
    const res = fakeRes();
    await handleRpki('example.com', res);
    const byIp = Object.fromEntries(res.body.results.map(r => [r.ip, r.state]));
    assert.strictEqual(byIp['9.9.9.20'], 'valid');
    assert.strictEqual(byIp['203.0.113.20'], 'unknown');
    assert.strictEqual(res.body.valid, false); // no todas confirmadas 'valid' -> nunca PASS
    console.log('PASS rpki_mix_valid_unknown');
  }

  // ── Dominio sin ninguna dirección IP (no existe / sin A ni AAAA) ──
  {
    mockAddresses({}); // v4/v6/ns todos vacíos -> ENODATA en los tres
    const res = fakeRes();
    await handleRpki('inexistente.example', res);
    assert.ok(res.body.error);
    assert.strictEqual(res.body.error_code, undefined);
    console.log('PASS rpki_dominio_sin_direcciones');
  }

  // ── Dominio con zona real (tiene NS) pero sin A/AAAA ──
  {
    mockAddresses({ ns: ['ns1.example.gob.ec'] });
    const res = fakeRes();
    await handleRpki('sub.gob.ec', res);
    assert.strictEqual(res.body.error_code, 'WEBFETCH_NO_ADDRESS_RECORD');
    console.log('PASS rpki_zona_real_sin_direccion');
  }

  // ── Error de medición: la validación ROA en sí falla (red/formato) ──
  // Se conoce el ASN/prefijo (Cymru respondió) pero rpki-validation nunca
  // responde con datos usables -> 'error', nunca 'unknown' silencioso.
  {
    mockAddresses({ v4: ['198.51.100.7'] });
    mockCymruTxt({ '198.51.100.7': [['64513 | 198.51.100.0/24 | ZZ | example | 2020-01-01']] });
    mockRipe(url => (
      url.pathname.includes('rpki-validation') ? { error: new Error('ECONNRESET') } : undefined
    ));
    const res = fakeRes();
    await handleRpki('example.com', res);
    assert.strictEqual(res.body.results[0].state, 'error');
    assert.strictEqual(res.body.results[0].asn, 64513); // el ASN sí se conocía
    console.log('PASS rpki_error_medicion_validacion_roa');
  }

  // ── Timeout en la validación ROA ──
  {
    mockAddresses({ v4: ['198.51.100.8'] });
    mockCymruTxt({ '198.51.100.8': [['64514 | 198.51.100.0/24 | ZZ | example | 2020-01-01']] });
    mockRipe(url => (
      url.pathname.includes('rpki-validation') ? { timeout: true } : undefined
    ));
    const res = fakeRes();
    await handleRpki('example.com', res);
    assert.strictEqual(res.body.results[0].state, 'error');
    console.log('PASS rpki_timeout_validacion_roa');
  }

  // ── IP privada/interna: bloqueada, nunca sale a Cymru/RIPEstat ──
  {
    mockAddresses({ v4: ['10.1.2.3'] });
    dns.resolveTxt = async () => { throw new Error('no debería llamarse — IP privada'); };
    https.request = () => { throw new Error('no debería llamarse — IP privada'); };
    const res = fakeRes();
    await handleRpki('intranet.example', res);
    assert.strictEqual(res.body.results[0].state, 'blocked');
    assert.strictEqual(res.body.results[0].asn, null);
    assert.strictEqual(res.body.valid, false); // NOT_APPLICABLE en el frontend, nunca PASS
    console.log('PASS rpki_ip_privada_bloqueada');
  }

  // ── Respuesta externa malformada: sin datos usables -> 'unknown', no crash ──
  {
    mockAddresses({ v4: ['192.0.2.55'] });
    mockCymruTxt({}); // Cymru no tiene datos para esta IP (bloque de documentación)
    mockRipe(url => (
      url.pathname.includes('network-info') ? { body: { data: {} } } : undefined
    ));
    const res = fakeRes();
    await handleRpki('example.com', res);
    assert.strictEqual(res.body.results[0].state, 'unknown');
    assert.strictEqual(res.body.results[0].asn, null);
    console.log('PASS rpki_respuesta_externa_malformada');
  }

  // ── Ambas fuentes de origen fallan por completo -> error de medición ──
  // (no "sin ROA": nunca se pudo determinar siquiera el ASN/prefijo)
  {
    mockAddresses({ v4: ['192.0.2.66'] });
    mockCymruTxt({ '192.0.2.66': new Error('ESERVFAIL') });
    mockRipe(url => (
      url.pathname.includes('network-info') ? { error: new Error('ECONNRESET') } : undefined
    ));
    const res = fakeRes();
    await handleRpki('example.com', res);
    assert.strictEqual(res.body.results[0].state, 'error');
    console.log('PASS rpki_ambas_fuentes_origen_fallan');
  }

  // ── Cymru falla/vacío -> fallback correcto a RIPEstat network-info ──
  {
    mockAddresses({ v4: ['192.0.2.77'] });
    mockCymruTxt({}); // sin datos en Cymru para esta IP
    mockRipe(url => {
      if (url.pathname.includes('network-info')) return { body: networkInfoBody(64515, '192.0.2.0/24') };
      if (url.pathname.includes('rpki-validation')) return { body: validationBody('valid') };
      return undefined;
    });
    const res = fakeRes();
    await handleRpki('example.com', res);
    assert.strictEqual(res.body.results[0].state, 'valid');
    assert.strictEqual(res.body.results[0].asn, 64515);
    console.log('PASS rpki_fallback_cymru_a_ripestat');
  }

  // ── Visibilidad de múltiples orígenes (MOAS) vía Cymru ──
  {
    mockAddresses({ v4: ['192.0.2.88'] });
    mockCymruTxt({
      '192.0.2.88': [
        ['64516 | 192.0.2.0/24 | ZZ | example | 2020-01-01'],
        ['64517 | 192.0.2.0/24 | ZZ | example | 2021-06-01']
      ]
    });
    mockRipe(url => (
      url.pathname.includes('rpki-validation') ? { body: validationBody('valid') } : undefined
    ));
    const { routes, asn } = await rpkiValidity('192.0.2.88');
    assert.strictEqual(routes.length, 2);
    assert.strictEqual(asn, 64516); // se usa el primer origen observado para validar
    assert.deepStrictEqual(routes.map(r => r.asn), [64516, 64517]);
    console.log('PASS rpki_moas_multiples_origenes_visibles');
  }

  // ── resolveOriginRoutesViaCymru: propaga el fallo de DNS tal cual ──
  // (rpkiValidity es quien decide tratarlo como "sin ruta" vía su propio
  // try/catch — ya cubierto arriba en rpki_fallback_cymru_a_ripestat y
  // rpki_ambas_fuentes_origen_fallan).
  {
    dns.resolveTxt = async () => { throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }); };
    await assert.rejects(() => resolveOriginRoutesViaCymru('203.0.113.200'), { code: 'ENOTFOUND' });
    console.log('PASS rpki_cymru_dns_falla_propaga_error');
  }

  console.log('\nOK — rpki (Fase 2, enriquecido con Cymru/MOAS): todos los casos pasaron.');
}

run().catch(e => {
  console.error('FALLÓ:', e);
  process.exitCode = 1;
});
