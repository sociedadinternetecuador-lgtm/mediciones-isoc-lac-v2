'use strict';

/**
 * Tests de los 3 checks de correo de MEDICIONES (maildnssec, mailipv6,
 * starttls) — Fase 1 (2026-09-15), revisados (2026-09-16) tras la
 * validación crítica frente al upstream Paraguay. Ver
 * AUDITORIA_CHECKS_FALTANTES_MEDICIONES.md e
 * IMPLEMENTACION_MEDICIONES_FASE1_CORREO.md.
 *
 * CI-safe: nada de esto toca la red real. dns.resolveMx/resolve6,
 * https.request (usado por checkAuthenticatedResolution() vía fetchJSON),
 * net.createConnection y tls.connect (usados por probeStarttls()) se
 * reemplazan por mocks — mismo patrón que ya usa
 * test/content.publicVisibility.test.js con emailAdapter.sendMail.
 *
 * STARTTLS_TIMEOUT_MS se fija bajo por variable de entorno ANTES de
 * requerir server.js (se lee una sola vez al cargar el módulo).
 *
 * Ejecutar: node test/medicionesMailChecks.test.js
 */

process.env.STARTTLS_TIMEOUT_MS = '50';

const assert = require('assert');
const dns = require('dns').promises;
const net = require('net');
const https = require('https');
const tls = require('tls');
const { EventEmitter } = require('events');

const safeWebFetchAdapter = require('../logic/adapters/safeWebFetch.adapter');
const { handleMailDnssec, handleMailIpv6, handleStarttls, MAX_MX_PROBED } = require('../server');

// ─── Fake response object (captura status/body, no abre nada real) ────────
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
function mockResolveMx(impl) { dns.resolveMx = impl; }
function mockResolve6(impl) { dns.resolve6 = impl; }

function enodata() { return Object.assign(new Error('ENODATA'), { code: 'ENODATA' }); }
function enotfound() { return Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }); }
function servfail() { return Object.assign(new Error('ESERVFAIL'), { code: 'ESERVFAIL' }); }

// ─── Mock de https.request (para checkAuthenticatedResolution -> fetchJSON) ─
// dnsResponses(name, type) -> objeto respuesta estilo dns.google, o null
// (fuerza un error de red, no un Status DNS).
function mockHttpsForAuthCheck(dnsResponses) {
  https.request = (url, options, callback) => {
    const target = typeof url === 'string' ? new URL(url) : url;
    const name = target.searchParams.get('name');
    const type = target.searchParams.get('type');
    const req = new EventEmitter();
    req.write = () => {};
    req.end = () => {
      process.nextTick(() => {
        let payload;
        try { payload = dnsResponses(name, type); } catch (e) { req.emit('error', e); return; }
        if (payload === null) { req.emit('error', new Error('mock: sin respuesta configurada')); return; }
        const resStream = new EventEmitter();
        callback(resStream);
        process.nextTick(() => {
          resStream.emit('data', JSON.stringify(payload));
          resStream.emit('end');
        });
      });
    };
    req.setTimeout = () => {};
    req.destroy = () => {};
    return req;
  };
}

// ─── Mock de net.createConnection (para probeStarttls) ──────────────────
// script: { onConnect: [líneas], onEhlo: [líneas], onStarttls: [líneas],
//           errorOnConnect: bool, neverRespond: bool }
function mockNetForStarttls(script) {
  net.createConnection = () => {
    const socket = new EventEmitter();
    socket.write = (dataStr) => {
      if (/^EHLO/.test(dataStr) && script.onEhlo) {
        process.nextTick(() => { for (const l of script.onEhlo) socket.emit('data', Buffer.from(l + '\r\n')); });
      } else if (/^STARTTLS/.test(dataStr) && script.onStarttls) {
        process.nextTick(() => { for (const l of script.onStarttls) socket.emit('data', Buffer.from(l + '\r\n')); });
      }
    };
    socket.end = () => {};
    socket.destroy = () => {};
    process.nextTick(() => {
      if (script.errorOnConnect) { socket.emit('error', new Error('ECONNREFUSED')); return; }
      if (script.neverRespond) return; // dispara el timeout real (mockeado a 50ms)
      if (script.onConnect) { for (const l of script.onConnect) socket.emit('data', Buffer.from(l + '\r\n')); }
    });
    return socket;
  };
}

// ─── Mock de tls.connect (para la negociación TLS real tras STARTTLS) ───
function mockTlsConnect(behavior) {
  // behavior: 'secure' | 'error'
  tls.connect = () => {
    const t = new EventEmitter();
    process.nextTick(() => {
      if (behavior === 'secure') t.emit('secureConnect');
      else t.emit('error', new Error('handshake TLS falló'));
    });
    return t;
  };
}

async function run() {
  // ═══════════════════════════ maildnssec ═══════════════════════════════
  // Nota: se usa el bit AD (Authenticated Data) de una consulta A/AAAA
  // normal contra dns.google — NO presencia de DS/DNSKEY en el hostname
  // exacto (ver server.js/checkAuthenticatedResolution() para la
  // justificación completa, con el caso real verificado de nic.ar).

  // PASS: MX bajo una zona con cadena DNSSEC validada (AD:true)
  {
    mockResolveMx(async () => [{ exchange: 'mx1.ejemplo-firmado.ar', priority: 10 }]);
    mockHttpsForAuthCheck(() => ({ Status: 0, Answer: [{ data: '203.0.113.10' }], AD: true }));
    const res = fakeRes();
    await handleMailDnssec('example.com', res);
    assert.strictEqual(res.body.results[0].state, 'secure');
    console.log('PASS maildnssec_mx_zona_firmada_ad_true');
  }

  // PASS (caso crítico: hostname MX que NO es un punto de delegación
  // propio — equivalente real: mx30.slyt.gob.ar, MX de nic.ar, verificado
  // en producción el 2026-09-16). Con el enfoque anterior (DS/DNSKEY
  // exactos en el hostname) esto habría dado FALSO NEGATIVO porque el
  // hostname MX no tiene su propio DS/DNSKEY aunque la cadena real (más
  // arriba) sí valide. El bit AD de una consulta A normal sí lo captura
  // correctamente porque refleja la cadena real, sin importar dónde esté
  // el punto de delegación efectivo.
  {
    mockResolveMx(async () => [{ exchange: 'mx30.slyt.gob.ar', priority: 10 }]);
    mockHttpsForAuthCheck((name, type) => {
      // Simula exactamente lo verificado en vivo: DS/DNSKEY directos en el
      // hostname no aplican aquí (este mock ni los simula porque el código
      // nuevo ya no los consulta) — solo la consulta A/AAAA con AD:true.
      return { Status: 0, Answer: [{ data: '200.108.150.92' }], AD: true };
    });
    const res = fakeRes();
    await handleMailDnssec('nic.ar', res);
    assert.strictEqual(res.body.results[0].state, 'secure');
    console.log('PASS maildnssec_mx_no_es_punto_delegacion_sigue_secure');
  }

  // FAIL: zona insegura (AD:false, pero resuelve bien)
  {
    mockResolveMx(async () => [{ exchange: 'mx1.sin-dnssec.com', priority: 10 }]);
    mockHttpsForAuthCheck(() => ({ Status: 0, Answer: [{ data: '203.0.113.20' }], AD: false }));
    const res = fakeRes();
    await handleMailDnssec('example.com', res);
    assert.strictEqual(res.body.results[0].state, 'insecure');
    console.log('PASS maildnssec_zona_insegura');
  }

  // FAIL-contributing: DNSSEC roto (SERVFAIL de validación real, Status:2)
  {
    mockResolveMx(async () => [{ exchange: 'mx1.dnssec-roto.com', priority: 10 }]);
    mockHttpsForAuthCheck(() => ({ Status: 2 }));
    const res = fakeRes();
    await handleMailDnssec('example.com', res);
    assert.strictEqual(res.body.results[0].state, 'broken');
    console.log('PASS maildnssec_dnssec_roto_servfail');
  }

  // INCONCLUSIVE-contributing: hostname MX que no resuelve en absoluto (ni A ni AAAA)
  {
    mockResolveMx(async () => [{ exchange: 'mx-fantasma.example.com', priority: 10 }]);
    mockHttpsForAuthCheck(() => ({ Status: 3 })); // NXDOMAIN en ambos tipos
    const res = fakeRes();
    await handleMailDnssec('example.com', res);
    assert.strictEqual(res.body.results[0].state, 'unresolved');
    console.log('PASS maildnssec_mx_no_resuelve');
  }

  // NOT_APPLICABLE: sin MX
  {
    mockResolveMx(async () => { throw enodata(); });
    const res = fakeRes();
    await handleMailDnssec('sin-mx.example.com', res);
    assert.strictEqual(res.body.error_code, 'NO_MX_RECORDS');
    console.log('PASS maildnssec_sin_mx');
  }

  // MEASUREMENT_ERROR real: fallo de DNS al resolver MX del propio dominio (no ENODATA)
  {
    mockResolveMx(async () => { throw servfail(); });
    const res = fakeRes();
    await handleMailDnssec('roto.example.com', res);
    assert.strictEqual(res.body.error_code, 'ESERVFAIL');
    console.log('PASS maildnssec_error_dns_dominio');
  }

  // INFO: adopción mixta entre 2 MX ya determinados (uno secure, otro no)
  {
    mockResolveMx(async () => [
      { exchange: 'mx1.mixto.com', priority: 10 },
      { exchange: 'mx2.mixto.com', priority: 20 }
    ]);
    mockHttpsForAuthCheck((name) => ({
      Status: 0,
      Answer: [{ data: '203.0.113.1' }],
      AD: name === 'mx1.mixto.com'
    }));
    const res = fakeRes();
    await handleMailDnssec('mixto.com', res);
    const states = res.body.results.map(r => r.state).sort();
    assert.deepStrictEqual(states, ['insecure', 'secure']);
    console.log('PASS maildnssec_mixto_backend_expone_ambos_estados');
  }

  // ═══════════════════════════ mailipv6 (sin cambios de esta revisión) ═══
  // PASS: todos los MX con AAAA
  {
    mockResolveMx(async () => [
      { exchange: 'mx1.example.com', priority: 10 },
      { exchange: 'mx2.example.com', priority: 20 }
    ]);
    mockResolve6(async () => ['2001:db8::1']);
    const res = fakeRes();
    await handleMailIpv6('example.com', res);
    assert.strictEqual(res.body.results.every(r => r.present === true), true);
    console.log('PASS mailipv6_todos');
  }

  // FAIL: ningún MX con AAAA
  {
    mockResolveMx(async () => [{ exchange: 'mx1.example.com', priority: 10 }]);
    mockResolve6(async () => { throw enodata(); });
    const res = fakeRes();
    await handleMailIpv6('example.com', res);
    assert.strictEqual(res.body.results[0].present, false);
    console.log('PASS mailipv6_ninguno');
  }

  // Mixto: un MX con AAAA, otro sin
  {
    mockResolveMx(async () => [
      { exchange: 'mx1.example.com', priority: 10 },
      { exchange: 'mx2.example.com', priority: 20 }
    ]);
    mockResolve6(async (host) => {
      if (host === 'mx1.example.com') return ['2001:db8::1'];
      throw enodata();
    });
    const res = fakeRes();
    await handleMailIpv6('example.com', res);
    const present = res.body.results.map(r => r.present);
    assert.deepStrictEqual(present.sort(), [false, true]);
    console.log('PASS mailipv6_mixto');
  }

  // NOT_APPLICABLE: sin MX
  {
    mockResolveMx(async () => { throw enodata(); });
    const res = fakeRes();
    await handleMailIpv6('sin-mx.example.com', res);
    assert.strictEqual(res.body.error_code, 'NO_MX_RECORDS');
    console.log('PASS mailipv6_sin_mx');
  }

  // MEASUREMENT_ERROR: no se pudo determinar (SERVFAIL, no ENODATA)
  {
    mockResolveMx(async () => [{ exchange: 'mx1.example.com', priority: 10 }]);
    mockResolve6(async () => { throw servfail(); });
    const res = fakeRes();
    await handleMailIpv6('example.com', res);
    assert.strictEqual(res.body.results[0].present, null);
    assert.strictEqual(res.body.results[0].error_code, 'ESERVFAIL');
    console.log('PASS mailipv6_no_determinable');
  }

  // ═══════════════════════════ starttls ═══════════════════════════════

  // PASS: anuncia STARTTLS Y el handshake TLS se completa de verdad
  {
    mockResolveMx(async () => [{ exchange: 'mx1.example.com', priority: 10 }]);
    safeWebFetchAdapter.resolvePublicAddresses = async () => [{ address: '203.0.113.10', family: 4 }];
    mockNetForStarttls({
      onConnect: ['220 mx1.example.com ESMTP'],
      onEhlo: ['250-mx1.example.com', '250-STARTTLS', '250 8BITMIME'],
      onStarttls: ['220 2.0.0 Ready to start TLS']
    });
    mockTlsConnect('secure');
    const res = fakeRes();
    await handleStarttls('example.com', res);
    assert.strictEqual(res.body.results[0].status, 'supports');
    console.log('PASS starttls_supports_handshake_real');
  }

  // announced_only: anuncia STARTTLS, acepta el comando, pero el handshake TLS falla
  {
    mockResolveMx(async () => [{ exchange: 'mx1.example.com', priority: 10 }]);
    safeWebFetchAdapter.resolvePublicAddresses = async () => [{ address: '203.0.113.10', family: 4 }];
    mockNetForStarttls({
      onConnect: ['220 mx1.example.com ESMTP'],
      onEhlo: ['250-mx1.example.com', '250-STARTTLS', '250 8BITMIME'],
      onStarttls: ['220 2.0.0 Ready to start TLS']
    });
    mockTlsConnect('error');
    const res = fakeRes();
    await handleStarttls('example.com', res);
    assert.strictEqual(res.body.results[0].status, 'announced_only');
    console.log('PASS starttls_anuncia_pero_handshake_falla');
  }

  // announced_only: anuncia STARTTLS pero el servidor rechaza el comando (4xx/5xx)
  {
    mockResolveMx(async () => [{ exchange: 'mx1.example.com', priority: 10 }]);
    safeWebFetchAdapter.resolvePublicAddresses = async () => [{ address: '203.0.113.10', family: 4 }];
    mockNetForStarttls({
      onConnect: ['220 mx1.example.com ESMTP'],
      onEhlo: ['250-mx1.example.com', '250-STARTTLS', '250 8BITMIME'],
      onStarttls: ['454 4.7.0 TLS not available due to temporary reason']
    });
    const res = fakeRes();
    await handleStarttls('example.com', res);
    assert.strictEqual(res.body.results[0].status, 'announced_only');
    console.log('PASS starttls_anuncia_pero_comando_rechazado');
  }

  // FAIL-contributing: responde pero sin STARTTLS en las capacidades
  {
    mockResolveMx(async () => [{ exchange: 'mx1.example.com', priority: 10 }]);
    safeWebFetchAdapter.resolvePublicAddresses = async () => [{ address: '203.0.113.10', family: 4 }];
    mockNetForStarttls({
      onConnect: ['220 mx1.example.com ESMTP'],
      onEhlo: ['250-mx1.example.com', '250 8BITMIME']
    });
    const res = fakeRes();
    await handleStarttls('example.com', res);
    assert.strictEqual(res.body.results[0].status, 'no');
    console.log('PASS starttls_no_soporta');
  }

  // INFO: mezcla conocida — 2 MX medidos con certeza, uno soporta y otro no
  {
    mockResolveMx(async () => [
      { exchange: 'mx1.mixto.com', priority: 10 },
      { exchange: 'mx2.mixto.com', priority: 20 }
    ]);
    safeWebFetchAdapter.resolvePublicAddresses = async () => [{ address: '203.0.113.10', family: 4 }];
    let call = 0;
    net.createConnection = () => {
      call += 1;
      const isFirst = call === 1;
      const socket = new EventEmitter();
      socket.write = (dataStr) => {
        if (/^EHLO/.test(dataStr)) {
          process.nextTick(() => {
            socket.emit('data', Buffer.from('250-mx ESMTP\r\n'));
            if (isFirst) socket.emit('data', Buffer.from('250-STARTTLS\r\n'));
            socket.emit('data', Buffer.from('250 8BITMIME\r\n'));
          });
        } else if (/^STARTTLS/.test(dataStr)) {
          process.nextTick(() => socket.emit('data', Buffer.from('220 Ready\r\n')));
        }
      };
      socket.end = () => {};
      socket.destroy = () => {};
      process.nextTick(() => socket.emit('data', Buffer.from('220 mx ESMTP\r\n')));
      return socket;
    };
    mockTlsConnect('secure'); // el único que llega a intentar TLS es el primero
    const res = fakeRes();
    await handleStarttls('mixto.com', res);
    const statuses = res.body.results.map(r => r.status).sort();
    assert.deepStrictEqual(statuses, ['no', 'supports']);
    console.log('PASS starttls_mezcla_conocida_backend_expone_ambos');
  }

  // NOT_APPLICABLE: sin MX
  {
    mockResolveMx(async () => { throw enodata(); });
    const res = fakeRes();
    await handleStarttls('sin-mx.example.com', res);
    assert.strictEqual(res.body.error_code, 'NO_MX_RECORDS');
    console.log('PASS starttls_sin_mx');
  }

  // timeout parcial: el socket nunca responde (STARTTLS_TIMEOUT_MS mockeado a 50ms)
  {
    mockResolveMx(async () => [{ exchange: 'mx-lento.example.com', priority: 10 }]);
    safeWebFetchAdapter.resolvePublicAddresses = async () => [{ address: '203.0.113.10', family: 4 }];
    mockNetForStarttls({ neverRespond: true });
    const res = fakeRes();
    await handleStarttls('example.com', res);
    assert.strictEqual(res.body.results[0].status, 'timeout');
    console.log('PASS starttls_timeout');
  }

  // todos timeout: 2 MX, ninguno responde
  {
    mockResolveMx(async () => [
      { exchange: 'mx1.lento.com', priority: 10 },
      { exchange: 'mx2.lento.com', priority: 20 }
    ]);
    safeWebFetchAdapter.resolvePublicAddresses = async () => [{ address: '203.0.113.10', family: 4 }];
    mockNetForStarttls({ neverRespond: true });
    const res = fakeRes();
    await handleStarttls('lento.com', res);
    assert.ok(res.body.results.every(r => r.status === 'timeout'));
    console.log('PASS starttls_todos_timeout');
  }

  // host privado bloqueado por la guarda SSRF (resolvePublicAddresses)
  {
    mockResolveMx(async () => [{ exchange: 'mx-interno.example.com', priority: 10 }]);
    safeWebFetchAdapter.resolvePublicAddresses = async () => {
      throw Object.assign(new Error('Destino interno bloqueado'), { code: 'WEBFETCH_BLOCKED_IP' });
    };
    const res = fakeRes();
    await handleStarttls('example.com', res);
    assert.strictEqual(res.body.results[0].status, 'blocked');
    assert.strictEqual(res.body.results[0].error_code, 'WEBFETCH_BLOCKED_IP');
    console.log('PASS starttls_host_privado_bloqueado');
  }

  // conexión rechazada
  {
    mockResolveMx(async () => [{ exchange: 'mx-caido.example.com', priority: 10 }]);
    safeWebFetchAdapter.resolvePublicAddresses = async () => [{ address: '203.0.113.10', family: 4 }];
    mockNetForStarttls({ errorOnConnect: true });
    const res = fakeRes();
    await handleStarttls('example.com', res);
    assert.strictEqual(res.body.results[0].status, 'connection-error');
    console.log('PASS starttls_conexion_rechazada');
  }

  // Límite de MX probados: 7 registros MX, solo se prueban MAX_MX_PROBED
  {
    assert.strictEqual(MAX_MX_PROBED, 5, 'MAX_MX_PROBED debe seguir siendo 5 (ver server.js)');
    const sevenMx = Array.from({ length: 7 }, (_, i) => ({ exchange: `mx${i}.example.com`, priority: i * 10 }));
    mockResolveMx(async () => sevenMx);
    safeWebFetchAdapter.resolvePublicAddresses = async () => [{ address: '203.0.113.10', family: 4 }];
    mockNetForStarttls({ onConnect: ['220 x ESMTP'], onEhlo: ['250 ok'] });
    const res = fakeRes();
    await handleStarttls('example.com', res);
    assert.strictEqual(res.body.results.length, 5);
    console.log('PASS starttls_limite_mx');
  }

  console.log('\nOK — maildnssec/mailipv6/starttls: todos los casos pasaron.');
}

run().catch((e) => {
  console.error('FALLÓ:', e);
  process.exitCode = 1;
});
