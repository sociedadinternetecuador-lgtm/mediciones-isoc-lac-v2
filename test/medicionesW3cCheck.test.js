'use strict';

/**
 * Tests del check `w3c` de MEDICIONES — Fase 3 (2026-09-16). Ver
 * IMPLEMENTACION_MEDICIONES_FASE3_W3C.md.
 *
 * `w3c` fue reescrito por completo: ya no envía `doc=https://dominio` al
 * validador (dejando que el propio validator.w3.org decida qué descargar,
 * sin guard de destinos privados ni fallback HTTP), sino que obtiene el
 * HTML con el mismo mecanismo seguro que el resto de checks del sitio
 * (fetchWebsite -> resolveFinalWebTarget -> fetchSafePage, con guard de
 * IPs privadas/loopback/link-local/ULA en cada salto de redirección) y
 * envía ese HTML como cuerpo POST al validador Nu — el validador nunca
 * conoce la URL/dominio real, solo bytes de HTML.
 *
 * CI-safe: nada de esto toca la red real. dns.lookup (usado por
 * resolvePublicAddresses dentro de fetchWebsite) e https.request/
 * http.request (usados tanto por requestPage — la obtención del HTML —
 * como por fetchJSON — la llamada POST al validador Nu) se reemplazan por
 * mocks, discriminando por la forma de invocación (2 argumentos =
 * requestPage/HTML del sitio; 3 argumentos = fetchJSON/validador Nu).
 *
 * Ejecutar: node test/medicionesW3cCheck.test.js
 */

const assert = require('assert');
const dns = require('dns').promises;
const http = require('http');
const https = require('https');
const net = require('net');
const { EventEmitter } = require('events');

const { handleW3C } = require('../server');

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

// ─── Mock de resolución DNS (usado por resolvePublicAddresses) ─────────
function mockLookup(ip) {
  dns.lookup = async (hostname, options) => {
    const family = net.isIP(ip);
    if (options && options.all) return [{ address: ip, family }];
    return { address: ip, family };
  };
}
function mockLookupFails() {
  dns.lookup = async () => { throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }); };
}

// Variante por host: permite que el dominio original resuelva a una IP
// pública y el destino de una redirección resuelva a otra distinta (p.ej.
// privada) — resolvePublicAddresses se llama de nuevo, con el nuevo
// hostname, en cada salto de redirección.
function mockLookupByHost(map) {
  dns.lookup = async (hostname, options) => {
    const ip = map[hostname];
    if (!ip) throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
    const family = net.isIP(ip);
    if (options && options.all) return [{ address: ip, family }];
    return { address: ip, family };
  };
}

// hasNoAddressRecordAtAll() (safeWebFetch.adapter.js), llamada por
// resolvePublicAddresses cuando dns.lookup falla con ENOTFOUND, decide si
// reclasifica el error a WEBFETCH_NO_ADDRESS_RECORD consultando
// dns.resolve4/resolve6 directamente — exige ENODATA en AMBOS (zona real,
// consulta resuelta, sin respuesta) para reclasificar. Sin mockear estas
// dos funciones, ese chequeo golpearía DNS real — se mockean siempre junto
// con mockLookupFails() para que los tests no dependan de red real.
function mockResolve4And6(code) {
  const err = () => Object.assign(new Error(code), { code });
  dns.resolve4 = async () => { throw err(); };
  dns.resolve6 = async () => { throw err(); };
}

// ─── Mock de https.request/http.request ─────────────────────────────────
// `site(target)` resuelve las llamadas de requestPage (2 args: opciones
// planas con hostname/path/protocol, callback) -> el HTML del propio sitio.
// `nu(url)` resuelve las llamadas de fetchJSON (3 args: URL, opciones,
// callback) -> la respuesta del validador Nu. Cada resolver devuelve
// { statusCode, headers, body } | { error } | { timeout: true } | undefined.
function mockHttpLayer({ site, nu }) {
  function handler(...args) {
    const isPageCall = args.length === 2;
    const callback = args[args.length - 1];
    const target = args[0];
    const req = new EventEmitter();
    req.write = () => {};
    req.setTimeout = (ms, cb) => { req._onTimeout = cb; };
    req.destroy = err => req.emit('error', err || new Error('destroyed'));
    req.on('error', () => {});
    req.end = () => {
      process.nextTick(() => {
        let spec;
        try {
          spec = isPageCall ? site(target) : nu(target);
        } catch (e) { req.emit('error', e); return; }
        if (!spec) { req.emit('error', new Error(`mock: sin respuesta configurada (${isPageCall ? 'site' : 'nu'})`)); return; }
        if (spec.timeout) { if (req._onTimeout) req._onTimeout(); return; }
        if (spec.error) { req.emit('error', spec.error); return; }
        const resStream = new EventEmitter();
        resStream.statusCode = spec.statusCode || 200;
        resStream.headers = spec.headers || {};
        callback(resStream);
        process.nextTick(() => {
          const raw = typeof spec.body === 'string' ? spec.body : JSON.stringify(spec.body || {});
          resStream.emit('data', Buffer.from(raw, 'utf8'));
          resStream.emit('end');
        });
      });
    };
    return req;
  }
  https.request = handler;
  http.request = handler;
}

function okSite(html) {
  return () => ({ statusCode: 200, headers: {}, body: html || '<!DOCTYPE html><html><head><title>x</title></head><body></body></html>' });
}
function nuMessages(messages) {
  return () => ({ body: { url: 'about:blank', messages } });
}

async function run() {
  // ── 0 errores / 0 warnings -> el backend reporta errors=0, warnings=0 ──
  {
    mockLookup('93.184.216.34');
    mockHttpLayer({ site: okSite(), nu: nuMessages([]) });
    const res = fakeRes();
    await handleW3C('sitio-cero.example', res);
    assert.strictEqual(res.body.errors, 0);
    assert.strictEqual(res.body.warnings, 0);
    assert.strictEqual(res.body.incomplete, false);
    console.log('PASS w3c_cero_errores_cero_warnings');
  }

  // ── 0 errores, con warnings reales (type:'info', subType:'warning') ──
  {
    mockLookup('93.184.216.34');
    mockHttpLayer({
      site: okSite(),
      nu: nuMessages([
        { type: 'info', subType: 'warning', message: 'Consider adding a "lang" attribute.' }
      ])
    });
    const res = fakeRes();
    await handleW3C('sitio-warn.example', res);
    assert.strictEqual(res.body.errors, 0);
    assert.strictEqual(res.body.warnings, 1);
    console.log('PASS w3c_cero_errores_con_warnings');
  }

  // ── Errores reales de conformidad ──
  {
    mockLookup('93.184.216.34');
    mockHttpLayer({
      site: okSite(),
      nu: nuMessages([
        { type: 'error', message: 'Element "head" is missing a required instance of child element "title".' },
        { type: 'error', message: 'An "img" element must have an "alt" attribute.' }
      ])
    });
    const res = fakeRes();
    await handleW3C('sitio-errores.example', res);
    assert.strictEqual(res.body.errors, 2);
    console.log('PASS w3c_con_errores');
  }

  // ── Mensajes puramente informativos (type:'info' SIN subType) no cuentan
  // como warning — distinción que ni Ecuador (antes) ni Paraguay hacían ──
  {
    mockLookup('93.184.216.34');
    mockHttpLayer({
      site: okSite(),
      nu: nuMessages([{ type: 'info', message: 'Mensaje puramente informativo, sin subType.' }])
    });
    const res = fakeRes();
    await handleW3C('sitio-info.example', res);
    assert.strictEqual(res.body.warnings, 0);
    assert.strictEqual(res.body.errors, 0);
    console.log('PASS w3c_info_puro_no_cuenta_como_warning');
  }

  // ── non-document-error -> incomplete=true (el conteo ya no es fiable) ──
  {
    mockLookup('93.184.216.34');
    mockHttpLayer({
      site: okSite(),
      nu: nuMessages([
        { type: 'error', message: 'Algo se detectó antes del corte.' },
        { type: 'non-document-error', message: 'Fatal Error: cannot recover.' }
      ])
    });
    const res = fakeRes();
    await handleW3C('sitio-incompleto.example', res);
    assert.strictEqual(res.body.incomplete, true);
    console.log('PASS w3c_non_document_error_marca_incomplete');
  }

  // ── Timeout del validador Nu ──
  {
    mockLookup('93.184.216.34');
    mockHttpLayer({ site: okSite(), nu: () => ({ timeout: true }) });
    const res = fakeRes();
    await handleW3C('sitio-timeout.example', res);
    assert.strictEqual(res.body.error_code, 'W3C_VALIDATOR_UNAVAILABLE');
    console.log('PASS w3c_timeout_validador');
  }

  // ── Servicio externo devuelve error de transporte real (5xx simulado
  // como fallo de conexión / cuerpo no-JSON, ya que fetchJSON solo parsea
  // el cuerpo y no revisa el status code) ──
  {
    mockLookup('93.184.216.34');
    mockHttpLayer({
      site: okSite(),
      nu: () => ({ statusCode: 503, body: '<html>Service Unavailable</html>' })
    });
    const res = fakeRes();
    await handleW3C('sitio-5xx.example', res);
    assert.strictEqual(res.body.error_code, 'W3C_VALIDATOR_UNAVAILABLE');
    console.log('PASS w3c_validador_5xx_respuesta_no_json');
  }

  // ── Respuesta bien formada como JSON pero sin campo "messages" ──
  {
    mockLookup('93.184.216.34');
    mockHttpLayer({ site: okSite(), nu: () => ({ body: {} }) });
    const res = fakeRes();
    await handleW3C('sitio-malformado.example', res);
    assert.strictEqual(res.body.error_code, 'W3C_INVALID_RESPONSE');
    console.log('PASS w3c_respuesta_malformada_sin_messages');
  }

  // ── Sitio inexistente (NXDOMAIN real: resolve4/resolve6 también fallan
  // con ENOTFOUND, no ENODATA) -> error genérico, NUNCA se reclasifica
  // como WEBFETCH_NO_ADDRESS_RECORD (esa reclasificación exige ENODATA en
  // ambos, no ENOTFOUND) -> queda en la vía de MEASUREMENT_ERROR, no en
  // NOT_APPLICABLE. Confirma que "dominio inexistente" y "zona real sin
  // web" no se confunden entre sí. ──
  {
    mockLookupFails();
    mockResolve4And6('ENOTFOUND');
    const res = fakeRes();
    await handleW3C('inexistente.example', res);
    assert.ok(res.body.error);
    assert.notStrictEqual(res.body.error_code, 'WEBFETCH_NO_ADDRESS_RECORD');
    assert.strictEqual(res.body.errors, undefined);
    console.log('PASS w3c_sitio_inexistente_nxdomain');
  }

  // ── Zona real delegada, pero sin ningún registro A/AAAA (ENODATA en
  // ambos) -> SÍ se reclasifica como WEBFETCH_NO_ADDRESS_RECORD, que el
  // frontend (NOT_APPLICABLE_CODES en index.html) mapea a NOT_APPLICABLE:
  // no hay sitio web que validar, no es un fallo de medición. ──
  {
    mockLookupFails();
    mockResolve4And6('ENODATA');
    const res = fakeRes();
    await handleW3C('zona-sin-web.example', res);
    assert.strictEqual(res.body.error_code, 'WEBFETCH_NO_ADDRESS_RECORD');
    console.log('PASS w3c_zona_real_sin_web_not_applicable');
  }

  // ── Redirección: se valida la URL final, no la inicial ──
  {
    mockLookup('93.184.216.34');
    let call = 0;
    mockHttpLayer({
      site: target => {
        call += 1;
        if (call === 1) {
          return { statusCode: 301, headers: { location: 'https://www.sitio-redirect.example/' } };
        }
        return { statusCode: 200, headers: {}, body: '<!DOCTYPE html><html><head><title>ok</title></head><body></body></html>' };
      },
      nu: nuMessages([])
    });
    const res = fakeRes();
    await handleW3C('sitio-redirect.example', res);
    assert.strictEqual(res.body.url, 'https://www.sitio-redirect.example/');
    assert.strictEqual(res.body.errors, 0);
    console.log('PASS w3c_sigue_redireccion_valida_url_final');
  }

  // ── Redirección hacia un destino privado: se bloquea al resolver el
  // nuevo host antes de seguir la redirección, en ambos esquemas (https y
  // su fallback http) — nunca se llega a solicitar el destino interno. ──
  {
    mockLookupByHost({
      'sitio-redirect-privado.example': '93.184.216.34',
      'internal.sitio-redirect-privado.example': '10.9.9.9'
    });
    mockHttpLayer({
      site: target => {
        if (target.hostname === 'internal.sitio-redirect-privado.example') {
          throw new Error('no debería llamarse — la redirección apunta a un destino privado');
        }
        return { statusCode: 302, headers: { location: 'https://internal.sitio-redirect-privado.example/' } };
      },
      nu: () => { throw new Error('no debería llamarse — la redirección apunta a un destino privado'); }
    });
    const res = fakeRes();
    await handleW3C('sitio-redirect-privado.example', res);
    assert.strictEqual(res.body.error_code, 'WEBFETCH_BLOCKED_IP');
    console.log('PASS w3c_redirect_a_privado_bloqueado');
  }

  // ── Destino privado bloqueado (DNS resuelve a una IP interna) ──
  {
    mockLookup('10.1.2.3');
    mockHttpLayer({ site: () => { throw new Error('no debería llamarse — IP privada'); }, nu: () => { throw new Error('no debería llamarse — IP privada'); } });
    const res = fakeRes();
    await handleW3C('intranet.example', res);
    assert.strictEqual(res.body.error_code, 'WEBFETCH_BLOCKED_IP');
    console.log('PASS w3c_destino_privado_bloqueado');
  }

  // ── El sitio responde pero sin cuerpo HTML (nada que validar) ──
  {
    mockLookup('93.184.216.34');
    mockHttpLayer({ site: () => ({ statusCode: 200, headers: {}, body: '' }), nu: () => { throw new Error('no debería llamarse — sin HTML'); } });
    const res = fakeRes();
    await handleW3C('vacio.example', res);
    assert.strictEqual(res.body.error_code, 'W3C_EMPTY_BODY');
    console.log('PASS w3c_cuerpo_vacio');
  }

  // ── Cap de mensajes: más de 40, se recorta pero se informa el total real ──
  {
    mockLookup('93.184.216.34');
    const many = Array.from({ length: 55 }, (_, i) => ({ type: 'error', message: `Error #${i}` }));
    mockHttpLayer({ site: okSite(), nu: nuMessages(many) });
    const res = fakeRes();
    await handleW3C('sitio-cap.example', res);
    assert.strictEqual(res.body.errors, 55);
    assert.strictEqual(res.body.messagesTotal, 55);
    assert.strictEqual(res.body.messages.length, 40);
    console.log('PASS w3c_cap_de_mensajes');
  }

  console.log('\nOK — w3c (Fase 3, validación HTML W3C/Nu): todos los casos pasaron.');
}

run().catch(e => {
  console.error('FALLÓ:', e);
  process.exitCode = 1;
});
