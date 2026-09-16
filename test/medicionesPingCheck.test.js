'use strict';

/**
 * Tests de los checks `ping`/`pingv6` de MEDICIONES — Fase 4 (2026-09-16).
 * Ver IMPLEMENTACION_MEDICIONES_FASE4_PING.md.
 *
 * A diferencia de Paraguay/upstream (que ejecuta `ping <dominio>` dejando
 * que el propio binario resuelva DNS, sin filtrar IPs privadas y tratando
 * 100% de pérdida como "fail" del dominio), Ecuador: resuelve primero,
 * filtra IPs privadas/reservadas (mismo guard que rpki en Fase 2), y solo
 * ejecuta `execFile` (nunca shell) contra IPs ya validadas por
 * `net.isIP()` — nunca contra el dominio ni una cadena de usuario.
 *
 * CI-safe: nada de esto ejecuta un binario `ping` real. dns.resolve4/
 * resolve6/resolveNs, childProcess.execFile y os.networkInterfaces se
 * reemplazan por mocks.
 *
 * Ejecutar: node test/medicionesPingCheck.test.js
 */

const assert = require('assert');
const dns = require('dns').promises;
const os = require('os');
const childProcess = require('child_process');

const { handlePing, handlePingV6, hasGlobalIPv6, MAX_PING_IPS } = require('../server');

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
function mockAddressesAllFail() {
  dns.resolve4 = async () => { throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }); };
  dns.resolve6 = async () => { throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }); };
  dns.resolveNs = async () => { throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }); };
}

// ─── Mock de os.networkInterfaces (capacidad IPv6 del propio nodo) ─────
function mockNodeWithGlobalIPv6() {
  os.networkInterfaces = () => ({
    eth0: [{ address: '2001:db8:abcd::1', family: 'IPv6', internal: false }]
  });
}
function mockNodeWithoutGlobalIPv6() {
  os.networkInterfaces = () => ({
    lo: [{ address: '::1', family: 'IPv6', internal: true }],
    eth0: [
      { address: 'fe80::1', family: 'IPv6', internal: false },
      { address: 'fd12:3456::1', family: 'IPv6', internal: false } // ULA, no pública
    ]
  });
}

// ─── Mock de childProcess.execFile (callback style, sin shell real) ────
// resolver(file, args) -> { stdout } | { enoent: true } | { error: {code, stdout, stderr, killed} }
function mockExecFile(resolver) {
  childProcess.execFile = (file, args, options, callback) => {
    let spec;
    try {
      spec = resolver(file, args, options);
    } catch (e) {
      callback(e, '', '');
      return;
    }
    if (!spec) { callback(new Error('mock: sin respuesta configurada'), '', ''); return; }
    if (spec.enoent) {
      const err = Object.assign(new Error(`spawn ${file} ENOENT`), { code: 'ENOENT' });
      callback(err, '', '');
      return;
    }
    if (spec.error) {
      const err = Object.assign(new Error(spec.error.message || 'exec failed'), spec.error);
      callback(err, spec.error.stdout || '', spec.error.stderr || '');
      return;
    }
    callback(null, spec.stdout || '', '');
  };
}

function execFileNeverCalled() {
  childProcess.execFile = () => { throw new Error('no debería llamarse — execFile invocado inesperadamente'); };
}

function pingOk(received, transmitted = 3, avg = '13.500') {
  return {
    stdout:
      `PING x (x) 56(84) bytes of data.\n` +
      `--- x ping statistics ---\n` +
      `${transmitted} packets transmitted, ${received} received, ${Math.round((1 - received / transmitted) * 100)}% packet loss, time ${transmitted * 1000}ms\n` +
      (received > 0 ? `rtt min/avg/max/mdev = 13.000/${avg}/14.000/0.100 ms\n` : '')
  };
}

async function run() {
  // ═══════════════════ IPv4 (ping) ═══════════════════

  // ── Responde ──
  {
    mockAddresses({ v4: ['203.0.113.10'] });
    mockExecFile((file, args) => {
      assert.strictEqual(file, 'ping');
      assert.deepStrictEqual(args, ['-c', '3', '-n', '-W', '2', '203.0.113.10']);
      return pingOk(3);
    });
    const res = fakeRes();
    await handlePing('sitio-a.example', res);
    assert.strictEqual(res.body.results[0].reachable, true);
    assert.strictEqual(res.body.results[0].received, 3);
    console.log('PASS ping_ipv4_responde');
  }

  // ── No responde (100% pérdida, pero medición completada) ──
  {
    mockAddresses({ v4: ['203.0.113.11'] });
    mockExecFile(() => pingOk(0));
    const res = fakeRes();
    await handlePing('sitio-b.example', res);
    assert.strictEqual(res.body.results[0].reachable, false);
    assert.strictEqual(res.body.results[0].lossPercent, 100);
    assert.strictEqual(res.body.error, undefined); // no es un error del check, es un dato real
    console.log('PASS ping_ipv4_no_responde');
  }

  // ── Múltiples IP, todas responden ──
  {
    mockAddresses({ v4: ['203.0.113.20', '203.0.113.21'] });
    mockExecFile(() => pingOk(3));
    const res = fakeRes();
    await handlePing('sitio-c.example', res);
    assert.strictEqual(res.body.results.length, 2);
    assert.ok(res.body.results.every(r => r.reachable));
    console.log('PASS ping_ipv4_multiples_todas_responden');
  }

  // ── Múltiples IP, mezcla ──
  {
    mockAddresses({ v4: ['203.0.113.30', '203.0.113.31'] });
    let call = 0;
    mockExecFile(() => { call += 1; return pingOk(call === 1 ? 3 : 0); });
    const res = fakeRes();
    await handlePing('sitio-d.example', res);
    assert.strictEqual(res.body.results[0].reachable, true);
    assert.strictEqual(res.body.results[1].reachable, false);
    console.log('PASS ping_ipv4_mezcla');
  }

  // ── Ninguna responde (múltiples IP, todas 100% pérdida) ──
  {
    mockAddresses({ v4: ['203.0.113.40', '203.0.113.41'] });
    mockExecFile(() => pingOk(0));
    const res = fakeRes();
    await handlePing('sitio-e.example', res);
    assert.ok(res.body.results.every(r => r.reachable === false));
    console.log('PASS ping_ipv4_ninguna_responde');
  }

  // ── Sin A (el dominio existe, resuelve v6, pero no v4) -> NOT_APPLICABLE ──
  {
    mockAddresses({ v6: ['2001:db8::1'] });
    const res = fakeRes();
    await handlePing('solo-ipv6.example', res);
    assert.strictEqual(res.body.error_code, 'PING_NO_A');
    console.log('PASS ping_ipv4_sin_a_not_applicable');
  }

  // ── Dominio totalmente inexistente (NXDOMAIN real, ninguna familia, sin NS) ──
  {
    mockAddressesAllFail();
    const res = fakeRes();
    await handlePing('inexistente.example', res);
    assert.notStrictEqual(res.body.error_code, 'PING_NO_A');
    console.log('PASS ping_ipv4_dominio_inexistente_no_es_not_applicable');
  }

  // ── IP privada bloqueada (no se ejecuta ping contra ella) ──
  {
    mockAddresses({ v4: ['203.0.113.50', '10.1.2.3'] });
    mockExecFile((file, args) => {
      assert.strictEqual(args[args.length - 1], '203.0.113.50', 'nunca debe pedirse ping contra la IP privada');
      return pingOk(3);
    });
    const res = fakeRes();
    await handlePing('mixto.example', res);
    const byIp = Object.fromEntries(res.body.results.map(r => [r.ip, r.state]));
    assert.strictEqual(byIp['10.1.2.3'], 'blocked');
    assert.strictEqual(byIp['203.0.113.50'], 'measured');
    console.log('PASS ping_ipv4_privada_bloqueada');
  }

  // ── "Timeout"/fallo de ejecución real (proceso matado, sin stdout útil) ──
  {
    mockAddresses({ v4: ['203.0.113.60'] });
    mockExecFile(() => ({ error: { code: null, killed: true, signal: 'SIGTERM', stdout: '' } }));
    const res = fakeRes();
    await handlePing('sitio-timeout.example', res);
    assert.strictEqual(res.body.results[0].state, 'error');
    assert.strictEqual(res.body.results[0].errorCode, 'PING_EXEC_ERROR');
    console.log('PASS ping_ipv4_timeout_exec_error');
  }

  // ── Binario ping ausente (ENOENT) -> MEASUREMENT_ERROR de todo el check ──
  {
    mockAddresses({ v4: ['203.0.113.70', '203.0.113.71', '203.0.113.72'] });
    let calls = 0;
    mockExecFile(() => { calls += 1; return { enoent: true }; });
    const res = fakeRes();
    await handlePing('sitio-sin-ping.example', res);
    assert.strictEqual(res.body.error_code, 'PING_BINARY_NOT_FOUND');
    assert.strictEqual(calls, 1, 'no debe reintentar contra las demás IP si el binario no existe');
    console.log('PASS ping_ipv4_binario_ausente_corta_el_lote');
  }

  // ── Respeta MAX_PING_IPS (muestra, no todas) ──
  {
    assert.strictEqual(MAX_PING_IPS, 3);
    mockAddresses({ v4: ['203.0.113.80', '203.0.113.81', '203.0.113.82', '203.0.113.83', '203.0.113.84'] });
    let calls = 0;
    mockExecFile(() => { calls += 1; return pingOk(3); });
    const res = fakeRes();
    await handlePing('muchas-ip.example', res);
    assert.strictEqual(calls, MAX_PING_IPS);
    assert.strictEqual(res.body.sampledCount, MAX_PING_IPS);
    assert.strictEqual(res.body.totalPublicIps, 5);
    console.log('PASS ping_ipv4_respeta_max_ips_muestra');
  }

  // ═══════════════════ IPv6 (pingv6) ═══════════════════

  // ── Responde (nodo con IPv6 global simulado) ──
  {
    mockNodeWithGlobalIPv6();
    mockAddresses({ v6: ['2001:db8::10'] });
    mockExecFile((file, args) => {
      assert.strictEqual(args[args.length - 1], '2001:db8::10');
      return pingOk(3);
    });
    const res = fakeRes();
    await handlePingV6('sitio-v6-a.example', res);
    assert.strictEqual(res.body.results[0].reachable, true);
    console.log('PASS pingv6_responde');
  }

  // ── No responde ──
  {
    mockNodeWithGlobalIPv6();
    mockAddresses({ v6: ['2001:db8::11'] });
    mockExecFile(() => pingOk(0));
    const res = fakeRes();
    await handlePingV6('sitio-v6-b.example', res);
    assert.strictEqual(res.body.results[0].reachable, false);
    console.log('PASS pingv6_no_responde');
  }

  // ── Sin AAAA (el dominio existe, resuelve v4, pero no v6) -> NOT_APPLICABLE ──
  {
    mockNodeWithGlobalIPv6();
    mockAddresses({ v4: ['203.0.113.90'] });
    const res = fakeRes();
    await handlePingV6('solo-ipv4.example', res);
    assert.strictEqual(res.body.error_code, 'PINGV6_NO_AAAA');
    console.log('PASS pingv6_sin_aaaa_not_applicable');
  }

  // ── Nodo sin IPv6 real -> INCONCLUSIVE-track, cero llamadas DNS/exec ──
  {
    mockNodeWithoutGlobalIPv6();
    dns.resolve4 = async () => { throw new Error('no debería llamarse — nodo sin IPv6'); };
    dns.resolve6 = async () => { throw new Error('no debería llamarse — nodo sin IPv6'); };
    execFileNeverCalled();
    const res = fakeRes();
    await handlePingV6('cualquier-dominio.example', res);
    assert.strictEqual(res.body.error_code, 'PINGV6_NODE_NO_IPV6');
    console.log('PASS pingv6_nodo_sin_ipv6_real');
  }
  assert.strictEqual(hasGlobalIPv6(), false, 'sanity check: mockNodeWithoutGlobalIPv6 sigue activo');

  // ── Múltiples AAAA ──
  {
    mockNodeWithGlobalIPv6();
    mockAddresses({ v6: ['2001:db8::20', '2001:db8::21'] });
    mockExecFile(() => pingOk(3));
    const res = fakeRes();
    await handlePingV6('sitio-v6-multi.example', res);
    assert.strictEqual(res.body.results.length, 2);
    console.log('PASS pingv6_multiples_aaaa');
  }

  // ── Dirección ULA bloqueada (no se le hace ping) ──
  {
    mockNodeWithGlobalIPv6();
    mockAddresses({ v6: ['2001:db8::30', 'fd12:3456::1'] });
    mockExecFile((file, args) => {
      assert.strictEqual(args[args.length - 1], '2001:db8::30', 'nunca debe pedirse ping contra la ULA');
      return pingOk(3);
    });
    const res = fakeRes();
    await handlePingV6('sitio-v6-ula.example', res);
    const byIp = Object.fromEntries(res.body.results.map(r => [r.ip, r.state]));
    assert.strictEqual(byIp['fd12:3456::1'], 'blocked');
    console.log('PASS pingv6_ula_bloqueada');
  }

  // ── Error (binario ausente para v6) ──
  {
    mockNodeWithGlobalIPv6();
    mockAddresses({ v6: ['2001:db8::40'] });
    mockExecFile(() => ({ enoent: true }));
    const res = fakeRes();
    await handlePingV6('sitio-v6-error.example', res);
    assert.strictEqual(res.body.error_code, 'PING_BINARY_NOT_FOUND');
    console.log('PASS pingv6_binario_ausente');
  }

  // ═══════════════════ Seguridad ═══════════════════
  //
  // Estos tres casos simulan una respuesta DNS "envenenada" (un valor que
  // no es una IP real) para probar defensa en profundidad extremo a
  // extremo: isBlockedIp() (logic/adapters/safeWebFetch.adapter.js) usa
  // net.isIP() para clasificar la dirección, y CUALQUIER valor que no sea
  // una IPv4/IPv6 válida cae por defecto a "bloqueado" (family===0 -> el
  // último `return true` de isBlockedIp) — nunca llega a pingOneAddress()
  // ni, por lo tanto, a execFile(). Verificado con execFileNeverCalled():
  // si el mock de execFile llegara a invocarse, el test fallaría de
  // inmediato en vez de silenciarlo.

  // ── DNS "envenenado" con un valor con metacaracteres de shell ──
  {
    mockAddresses({ v4: ['8.8.8.8; rm -rf /'] });
    execFileNeverCalled();
    const res = fakeRes();
    await handlePing('valor-malicioso.example', res);
    assert.strictEqual(res.body.results[0].state, 'blocked');
    console.log('PASS ping_seguridad_valor_no_ip_rechazado');
  }

  // ── Argumento que comienza con "-" (se trataría como flag si se pasara
  // tal cual a execFile) — nunca llega a ejecutarse ──
  {
    mockAddresses({ v4: ['-c 100'] });
    execFileNeverCalled();
    const res = fakeRes();
    await handlePing('flag-como-ip.example', res);
    assert.strictEqual(res.body.results[0].state, 'blocked');
    console.log('PASS ping_seguridad_argumento_con_guion_rechazado');
  }

  // ── Metacaracteres de shell en un valor supuestamente resuelto ──
  {
    mockAddresses({ v4: ['$(id)'] });
    execFileNeverCalled();
    const res = fakeRes();
    await handlePing('metacaracteres.example', res);
    assert.strictEqual(res.body.results[0].state, 'blocked');
    console.log('PASS ping_seguridad_metacaracteres_rechazados');
  }

  // ── Nunca se usa shell: execFile siempre recibe un array de argumentos,
  // nunca un string de comando concatenado ──
  {
    mockAddresses({ v4: ['203.0.113.99'] });
    mockExecFile((file, args) => {
      assert.ok(Array.isArray(args), 'los argumentos deben ir en un array, nunca concatenados en un string');
      assert.ok(args.every(a => typeof a === 'string'));
      return pingOk(3);
    });
    const res = fakeRes();
    await handlePing('sin-shell.example', res);
    assert.strictEqual(res.body.results[0].reachable, true);
    console.log('PASS ping_seguridad_nunca_usa_shell');
  }

  console.log('\nOK — ping/pingv6 (Fase 4): todos los casos pasaron.');
}

run().catch(e => {
  console.error('FALLÓ:', e);
  process.exitCode = 1;
});
