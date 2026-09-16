'use strict';

/**
 * Tests de orquestación del motor DNSSEC (services/dnssec.service.js) —
 * auditoría/fortalecimiento conservador, 2026-09-16. Ver
 * AUDITORIA_DNSSEC_ECUADOR_METODOLOGIA_MOTOR.md e
 * IMPLEMENTACION_DNSSEC_AUDITORIA_CORE.md.
 *
 * A diferencia de test/dnssecRules.test.js (que prueba la función pura de
 * clasificación con fixtures hechas a mano), este archivo prueba el flujo
 * REAL de extremo a extremo: getDnssecAnalysis() -> buildZoneChain ->
 * queryDnskey/queryDs/queryNameExistence (logic/adapters/dns/
 * realDns.adapter.js, que consulta Google Public DNS vía DoH JSON sobre
 * HTTPS) -> computeConfidence(). Se mockea https.get (nunca se toca la
 * red real) con fixtures que replican EXACTAMENTE el formato de respuesta
 * real de Google DoH, verificado en vivo durante la auditoría previa
 * (incluye Status, AD, Comment y extended_dns_errors reales observados
 * contra dns.google/resolve).
 *
 * Cada escenario usa nombres de dominio/zona ÚNICOS (nunca reutilizados
 * entre tests de este archivo) porque realDns.adapter.js cachea
 * respuestas por `nombre|tipo` durante 5 minutos y coalesce peticiones
 * concurrentes — reusar un nombre entre escenarios haría que un test
 * reutilizara silenciosamente el resultado cacheado de otro.
 *
 * Ejecutar: node test/dnssecService.test.js
 */

const assert = require('assert');
const https = require('https');
const { EventEmitter } = require('events');

const { getDnssecAnalysis } = require('../services/dnssec.service');
const { processDnssecAnalysis } = require('../logic/processors/dnssec.processor');
const { DNSSEC_DELEGATION_STATUS } = require('../config/dnssec.constants');

// ─── Mock de https.get (Google DoH) ─────────────────────────────────────
// responder(name, type) -> objeto de respuesta DoH real | { timeout: true }
function mockDoh(responder) {
  https.get = (url, options, callback) => {
    const target = typeof url === 'string' ? new URL(url) : url;
    const name = target.searchParams.get('name');
    const type = target.searchParams.get('type');
    const req = new EventEmitter();
    req.setTimeout = (ms, cb) => { req._onTimeout = cb; };
    req.destroy = (err) => { req.emit('error', err); };
    process.nextTick(() => {
      let spec;
      try {
        spec = responder(name, type);
      } catch (e) {
        req.emit('error', e);
        return;
      }
      if (!spec) { req.emit('error', new Error(`mock DoH: sin respuesta configurada para ${name} ${type}`)); return; }
      if (spec.timeout) { if (req._onTimeout) req._onTimeout(); return; }
      const res = new EventEmitter();
      callback(res);
      process.nextTick(() => {
        res.emit('data', JSON.stringify(spec));
        res.emit('end');
      });
    });
    return req;
  };
}

function ok(answers) { return { Status: 0, Answer: answers }; }
function noData() { return { Status: 0 }; }
function nxdomain() { return { Status: 3 }; }
function servfail(extra) { return { Status: 2, AD: false, ...extra }; }

function dnskeyAnswer(name) {
  return [{ name: `${name}.`, type: 48, TTL: 3600, data: '257 3 13 fakekeydata==' }];
}
function dsAnswer(name) {
  return [{ name: `${name}.`, type: 43, TTL: 3600, data: '12345 13 2 fakedigestdata' }];
}
function aAnswer(name) {
  return [{ name: `${name}.`, type: 1, TTL: 300, data: '203.0.113.10' }];
}

async function run() {
  // ── Escenario "ok" de extremo a extremo: cadena firmada y delegación segura ──
  {
    const domain = 'ok-e2e-test.example';
    mockDoh((name, type) => {
      if (name === 'example' && type === 'DNSKEY') return ok(dnskeyAnswer(name));
      if (name === domain && type === 'DNSKEY') return ok(dnskeyAnswer(name));
      if (name === domain && type === 'DS') return ok(dsAnswer(name));
      if (['A', 'AAAA', 'CNAME'].includes(type) && name === domain) return ok(aAnswer(name));
      return noData();
    });
    const result = await getDnssecAnalysis(domain);
    assert.strictEqual(result.raw_checks.zones.length, 2);
    assert.strictEqual(result.raw_checks.zones[1].status, 'signed');
    assert.strictEqual(result.raw_checks.delegations[0].status, 'secure');
    assert.strictEqual(result.assessment_meta.confidence, 'high');
    console.log('PASS service_e2e_ok');
  }

  // ── Escenario "non_existent" de extremo a extremo: NXDOMAIN total ──
  {
    const domain = 'nonexistent-e2e-test.example';
    mockDoh((name, type) => {
      if (name === 'example' && type === 'DNSKEY') return ok(dnskeyAnswer(name));
      if (name === domain) return nxdomain();
      return noData();
    });
    const result = await getDnssecAnalysis(domain);
    assert.strictEqual(result.raw_checks.name_existence.exists, false);
    assert.strictEqual(result.raw_checks.name_existence.query_status, 'nxdomain');
    console.log('PASS service_e2e_non_existent');
  }

  // ── Escenario "indeterminate" de extremo a extremo: timeout real en una
  // consulta -> confidence baja, sin forzar ninguna conclusión estructural ──
  {
    const domain = 'timeout-e2e-test.example';
    mockDoh((name, type) => {
      if (name === domain && type === 'DNSKEY') return { timeout: true };
      if (name === 'example' && type === 'DNSKEY') return ok(dnskeyAnswer(name));
      return noData();
    });
    const result = await getDnssecAnalysis(domain);
    assert.strictEqual(result.raw_checks.zones[1].query_status, 'timeout');
    assert.strictEqual(result.assessment_meta.confidence, 'low');
    console.log('PASS service_e2e_indeterminate_timeout');
  }

  // ── SERVFAIL con DS presente -> confidence "high" (evidencia consistente
  // de fallo DNSSEC, no un error genérico) — confirma que dnssec.service.js
  // etiqueta correctamente validation_problem antes de llegar a las reglas ──
  {
    const domain = 'servfail-e2e-test.example';
    mockDoh((name, type) => {
      if (name === 'example' && type === 'DNSKEY') return ok(dnskeyAnswer(name));
      if (name === domain && type === 'DNSKEY') return servfail({
        Comment: 'DNSSEC validation failure.',
        extended_dns_errors: [{ info_code: 9, extra_text: 'No DNSKEY matches DS RRs' }]
      });
      if (name === domain && type === 'DS') return ok(dsAnswer(name));
      if (['A', 'AAAA', 'CNAME'].includes(type) && name === domain) return servfail();
      return noData();
    });
    const result = await getDnssecAnalysis(domain);
    const domainZone = result.raw_checks.zones[1];
    assert.strictEqual(domainZone.validation_problem, 'dnssec_validation_failure');
    assert.strictEqual(result.assessment_meta.confidence, 'high');
    console.log('PASS service_e2e_servfail_con_ds_confidence_alta');
  }

  // ═══════════════════════════════════════════════════════════════════
  // Resolución del pendiente técnico BROKEN (2026-09-16) — ver
  // AUDITORIA_DNSSEC_BROKEN_DELEGATION.md e
  // IMPLEMENTACION_DNSSEC_AUDITORIA_CORE.md. DNSSEC_DELEGATION_STATUS.BROKEN
  // se eliminó por ser inalcanzable; estos tests confirman, contra el flujo
  // real (DoH mockeado), que el estado interno de cada delegación siempre
  // cae en uno de los 3 valores restantes, y que los escenarios que BROKEN
  // pretendía cubrir siguen resolviendo al mismo estado FINAL correcto por
  // otra vía (el estado de la zona), sin pérdida de exactitud.
  // ═══════════════════════════════════════════════════════════════════

  // ── delegation.status nunca es "broken" (ya no existe como valor posible;
  // se confirma que cae siempre en uno de los 3 valores restantes) a lo
  // largo de una matriz representativa de combinaciones DS/DNSKEY ──
  {
    const scenarios = [
      { label: 'ds_y_dnskey_presentes', domain: 'broken-check-a.example', dsFound: true, dnskeyFound: true },
      { label: 'ds_ausente_dnskey_presente', domain: 'broken-check-b.example', dsFound: false, dnskeyFound: true },
      { label: 'ds_presente_dnskey_ausente', domain: 'broken-check-c.example', dsFound: true, dnskeyFound: false },
      { label: 'ninguno_presente', domain: 'broken-check-d.example', dsFound: false, dnskeyFound: false }
    ];
    for (const s of scenarios) {
      mockDoh((name, type) => {
        if (name === 'example' && type === 'DNSKEY') return ok(dnskeyAnswer(name));
        if (name === s.domain && type === 'DNSKEY') return s.dnskeyFound ? ok(dnskeyAnswer(name)) : noData();
        if (name === s.domain && type === 'DS') return s.dsFound ? ok(dsAnswer(name)) : noData();
        if (['A', 'AAAA', 'CNAME'].includes(type) && name === s.domain) return ok(aAnswer(name));
        return noData();
      });
      const result = await getDnssecAnalysis(s.domain);
      const delegationStatus = result.raw_checks.delegations[0].status;
      assert.notStrictEqual(delegationStatus, 'broken', `${s.label}: "broken" ya no debe ser un valor posible`);
      assert.ok(
        Object.values(DNSSEC_DELEGATION_STATUS).includes(delegationStatus),
        `${s.label}: "${delegationStatus}" debe ser uno de los 3 valores restantes de DNSSEC_DELEGATION_STATUS`
      );
    }
    console.log('PASS service_broken_nunca_producido_matriz_ds_dnskey');
  }

  // ── DS presente + DNSKEY ausente en un nivel intermedio -> sigue dando
  // el mismo estado FINAL correcto (blocked_at_parent), detectado por el
  // estado de la ZONA (unsigned) — no por el de la delegación, que ahora
  // se etiqueta honestamente "secure" (no "broken", que ya no existe) ──
  {
    const domain = 'leaf.broken-check-mid.example';
    mockDoh((name, type) => {
      if (name === 'example' && type === 'DNSKEY') return ok(dnskeyAnswer(name));
      // "broken-check-mid.example": el TLD publica DS para ella, pero ELLA
      // no publica DNSKEY -- el caso que BROKEN pretendía representar.
      if (name === 'broken-check-mid.example' && type === 'DNSKEY') return noData();
      if (name === 'broken-check-mid.example' && type === 'DS') return ok(dsAnswer(name));
      if (name === domain && type === 'DNSKEY') return ok(dnskeyAnswer(name));
      if (name === domain && type === 'DS') return ok(dsAnswer(name));
      if (['A', 'AAAA', 'CNAME'].includes(type) && name === domain) return ok(aAnswer(name));
      return noData();
    });
    const result = await getDnssecAnalysis(domain);
    const midZone = result.raw_checks.zones.find(z => z.zone === 'broken-check-mid.example');
    const midDelegation = result.raw_checks.delegations.find(d => d.to === 'broken-check-mid.example');
    assert.strictEqual(midZone.status, 'unsigned');
    assert.strictEqual(midDelegation.status, 'secure', 'Etiquetado honesto: ds_present=true -> "secure" (nunca "broken", que ya no existe)');

    const processed = processDnssecAnalysis(result);
    assert.strictEqual(processed.dnssec.final_status, 'blocked_at_parent', 'El veredicto final sigue siendo correcto, vía el estado de zona');
    console.log('PASS service_ds_sin_dnskey_intermedio_sigue_blocked_at_parent');
  }

  // ── DS y DNSKEY AMBOS presentes -> el motor NUNCA afirma "validado
  // criptográficamente": solo observa presencia, nunca compara el DS con
  // el DNSKEY. Este test fija esa limitación de forma explícita y
  // ejecutable, no solo como nota de documentación. ──
  {
    const domain = 'crypto-not-checked.example';
    mockDoh((name, type) => {
      if (name === 'example' && type === 'DNSKEY') return ok(dnskeyAnswer(name));
      if (name === domain && type === 'DNSKEY') return ok(dnskeyAnswer(name));
      if (name === domain && type === 'DS') return ok(dsAnswer(name));
      if (['A', 'AAAA', 'CNAME'].includes(type) && name === domain) return ok(aAnswer(name));
      return noData();
    });
    const result = await getDnssecAnalysis(domain);
    const processed = processDnssecAnalysis(result);
    // El resultado es "ok" -- pero eso significa únicamente "DS y DNSKEY
    // están AMBOS presentes", nunca "el DS fue verificado criptográficamente
    // contra el DNSKEY". El motor no tiene ningún mecanismo para detectar un
    // DS que apunte a una clave equivocada o rotada -- limitación declarada,
    // no un bug de este hallazgo puntual (ver AUDITORIA_DNSSEC_BROKEN_DELEGATION.md §7).
    assert.strictEqual(processed.dnssec.final_status, 'ok');
    assert.ok(
      !JSON.stringify(processed).toLowerCase().includes('criptográficamente válid'),
      'Ningún texto debe afirmar que la cadena fue verificada criptográficamente -- el motor solo observa presencia'
    );
    console.log('PASS service_ds_dnskey_presentes_no_afirma_validacion_criptografica');
  }

  console.log('\nOK — orquestación DNSSEC (dnssec.service.js): todos los casos pasaron.');
}

run().catch(e => {
  console.error('FALLÓ:', e);
  process.exitCode = 1;
});
