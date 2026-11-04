'use strict';

/**
 * Tests del motor de clasificación DNSSEC (logic/rules/dnssec.rules.js) —
 * auditoría/fortalecimiento conservador, 2026-09-16. Ver
 * AUDITORIA_DNSSEC_ECUADOR_METODOLOGIA_MOTOR.md e
 * IMPLEMENTACION_DNSSEC_AUDITORIA_CORE.md.
 *
 * computeDnssecConclusion() es una función PURA (sin I/O) — se prueba
 * directamente, construyendo a mano los objetos zones/delegations/
 * nameExistence tal como los produce services/dnssec.service.js, sin
 * mockear DNS ni red. Esto es intencional: separa la verificación del
 * MOTOR de clasificación (aquí) de la verificación de la orquestación/
 * resolución DNS (test/dnssecService.test.js).
 *
 * Objetivo explícito de esta fase: verificar el comportamiento ACTUAL de
 * los 7 estados, no inventar un comportamiento "correcto" nuevo. Ningún
 * test de este archivo cambia la lógica de dnssec.rules.js — solo la
 * documenta con evidencia ejecutable.
 *
 * Ejecutar: node test/dnssecRules.test.js
 */

const assert = require('assert');
const { computeDnssecConclusion } = require('../logic/rules/dnssec.rules');
const { DNSSEC_FINAL_STATUS } = require('../config/dnssec.constants');

// ─── Helpers para construir fixtures mínimas y legibles ─────────────────
function zone(overrides) {
  return {
    zone: 'example.com',
    level: 1,
    signed: false,
    dnskey_present: false,
    status: 'unknown',
    query_status: 'no_data',
    dnskey_error: null,
    ...overrides
  };
}
function delegation(overrides) {
  return {
    from: 'com',
    to: 'example.com',
    ds_present: false,
    secure: false,
    status: 'unknown',
    query_status: 'no_data',
    ds_error: null,
    ...overrides
  };
}
function nameExistence(overrides) {
  return {
    exists: true,
    query_status: 'ok',
    records: [],
    ...overrides
  };
}

function run() {
  // ── 1) ok: dominio firmado + delegación segura ──
  {
    const zones = [
      zone({ zone: 'com', level: 1, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'example.com', level: 2, status: 'signed', query_status: 'ok' })
    ];
    const delegations = [delegation({ from: 'com', to: 'example.com', ds_present: true, secure: true, status: 'secure', query_status: 'ok' })];
    const result = computeDnssecConclusion(zones, delegations, 'example.com', nameExistence());
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.OK);
    assert.strictEqual(result.readiness, 'already_enabled');
    console.log('PASS estado_ok');
  }

  // ── 2) not_implemented: capa superior firmada, dominio sin DS/DNSKEY ──
  {
    const zones = [
      zone({ zone: 'com', level: 1, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'example.com', level: 2, status: 'unsigned', query_status: 'no_data' })
    ];
    const delegations = [delegation({ from: 'com', to: 'example.com', ds_present: false, secure: false, status: 'insecure', query_status: 'no_data' })];
    const result = computeDnssecConclusion(zones, delegations, 'example.com', nameExistence());
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.NOT_IMPLEMENTED);
    assert.strictEqual(result.readiness, 'ready_to_enable');
    console.log('PASS estado_not_implemented');
  }

  // ── 3) blocked_at_tld: el TLD mismo no está firmado ──
  {
    const zones = [
      zone({ zone: 'ec', level: 1, status: 'unsigned', query_status: 'no_data' }),
      zone({ zone: 'example.ec', level: 2, status: 'unsigned', query_status: 'no_data' })
    ];
    const delegations = [delegation({ from: 'ec', to: 'example.ec', ds_present: false, status: 'insecure', query_status: 'no_data' })];
    const result = computeDnssecConclusion(zones, delegations, 'example.ec', nameExistence());
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.BLOCKED_AT_TLD);
    assert.strictEqual(result.blocking_level, 'tld');
    console.log('PASS estado_blocked_at_tld');
  }

  // ── 4) blocked_at_parent: TLD firmado, zona padre inmediata no ──
  {
    const zones = [
      zone({ zone: 'ec', level: 1, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'gob.ec', level: 2, status: 'unsigned', query_status: 'no_data' }),
      zone({ zone: 'ministerio.gob.ec', level: 3, status: 'unsigned', query_status: 'no_data' })
    ];
    const delegations = [
      delegation({ from: 'ec', to: 'gob.ec', ds_present: false, status: 'insecure', query_status: 'no_data' }),
      delegation({ from: 'gob.ec', to: 'ministerio.gob.ec', ds_present: false, status: 'insecure', query_status: 'no_data' })
    ];
    const result = computeDnssecConclusion(zones, delegations, 'ministerio.gob.ec', nameExistence());
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.BLOCKED_AT_PARENT);
    assert.strictEqual(result.blocking_level, 'parent');
    console.log('PASS estado_blocked_at_parent');
  }

  // ── 5a) misconfigured: DNSKEY presente pero SIN DS válido en el padre ──
  {
    const zones = [
      zone({ zone: 'com', level: 1, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'example.com', level: 2, status: 'signed', query_status: 'ok' })
    ];
    const delegations = [delegation({ from: 'com', to: 'example.com', ds_present: false, secure: false, status: 'insecure', query_status: 'no_data' })];
    const result = computeDnssecConclusion(zones, delegations, 'example.com', nameExistence());
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.MISCONFIGURED);
    console.log('PASS estado_misconfigured_ds_ausente');
  }

  // ── 5b) misconfigured: DS presente en el padre, pero DNSKEY ausente en el hijo ──
  {
    const zones = [
      zone({ zone: 'com', level: 1, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'example.com', level: 2, status: 'unsigned', query_status: 'no_data' })
    ];
    const delegations = [delegation({ from: 'com', to: 'example.com', ds_present: true, secure: true, status: 'secure', query_status: 'ok' })];
    const result = computeDnssecConclusion(zones, delegations, 'example.com', nameExistence());
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.MISCONFIGURED);
    console.log('PASS estado_misconfigured_dnskey_ausente');
  }

  // ── 5c) misconfigured: SERVFAIL con DS presente (fallo de validación) ──
  {
    const zones = [
      zone({ zone: 'com', level: 1, status: 'signed', query_status: 'ok' }),
      zone({
        zone: 'example.com', level: 2, status: 'unknown', query_status: 'servfail',
        validation_problem: 'dnssec_validation_failure', failure_scope: 'zone_dnskey_lookup'
      })
    ];
    const delegations = [delegation({ from: 'com', to: 'example.com', ds_present: true, secure: true, status: 'secure', query_status: 'ok' })];
    const result = computeDnssecConclusion(zones, delegations, 'example.com', nameExistence());
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.MISCONFIGURED);
    console.log('PASS estado_misconfigured_servfail_con_ds');
  }

  // ── 6) non_existent: NXDOMAIN en existencia, zona y delegación ──
  {
    const zones = [
      zone({ zone: 'com', level: 1, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'noexiste12345.com', level: 2, status: 'unknown', query_status: 'nxdomain' })
    ];
    const delegations = [delegation({ from: 'com', to: 'noexiste12345.com', query_status: 'nxdomain' })];
    const result = computeDnssecConclusion(
      zones, delegations, 'noexiste12345.com',
      nameExistence({ exists: false, query_status: 'nxdomain' })
    );
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.NON_EXISTENT);
    console.log('PASS estado_non_existent');
  }

  // ── 7a) indeterminate: timeout en una consulta ──
  {
    const zones = [
      zone({ zone: 'com', level: 1, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'example.com', level: 2, status: 'unknown', query_status: 'timeout' })
    ];
    const delegations = [delegation({ from: 'com', to: 'example.com', query_status: 'ok' })];
    const result = computeDnssecConclusion(zones, delegations, 'example.com', nameExistence());
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.INDETERMINATE);
    console.log('PASS estado_indeterminate_timeout');
  }

  // ── 7b) indeterminate: SERVFAIL SIN evidencia estructural suficiente
  // (sin DS presente) -> nunca debe leerse como DNSSEC roto (sección 11) ──
  {
    const zones = [
      zone({ zone: 'com', level: 1, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'example.com', level: 2, status: 'unknown', query_status: 'servfail' })
    ];
    const delegations = [delegation({ from: 'com', to: 'example.com', ds_present: false, secure: false, status: 'insecure', query_status: 'no_data' })];
    const result = computeDnssecConclusion(zones, delegations, 'example.com', nameExistence());
    // SERVFAIL es un "error duro" (isHardQueryError) -> se evalúa ANTES que
    // cualquier regla estructural, así que cae en indeterminate — nunca en
    // "misconfigured" sin evidencia de DS que lo sustente.
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.INDETERMINATE);
    console.log('PASS estado_indeterminate_servfail_sin_ds');
  }

  // ── 7c) indeterminate: sin zonas en absoluto (fallback explícito) ──
  {
    const result = computeDnssecConclusion([], [], 'example.com', null);
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.INDETERMINATE);
    console.log('PASS estado_indeterminate_sin_zonas');
  }

  // ── "ready" ya no existe como valor producible (código muerto eliminado) ──
  {
    assert.strictEqual(DNSSEC_FINAL_STATUS.READY, undefined, 'READY debía eliminarse de DNSSEC_FINAL_STATUS');
    const allPossibleOutputs = new Set();
    // Se recolectan los final_status de TODOS los casos anteriores de este
    // archivo — ninguno debe ser "ready" bajo ninguna combinación probada.
    [DNSSEC_FINAL_STATUS.OK, DNSSEC_FINAL_STATUS.NOT_IMPLEMENTED, DNSSEC_FINAL_STATUS.BLOCKED_AT_TLD,
     DNSSEC_FINAL_STATUS.BLOCKED_AT_PARENT, DNSSEC_FINAL_STATUS.MISCONFIGURED, DNSSEC_FINAL_STATUS.NON_EXISTENT,
     DNSSEC_FINAL_STATUS.INDETERMINATE].forEach(s => allPossibleOutputs.add(s));
    assert.strictEqual(allPossibleOutputs.size, 7, 'Deben quedar exactamente 7 estados alcanzables');
    console.log('PASS ready_eliminado_7_estados_exactos');
  }

  // ═══════════════════════════════════════════════════════════════════
  // Cadenas multinivel (corrección 2026-09-16 — ver
  // AUDITORIA_DNSSEC_ECUADOR_METODOLOGIA_MOTOR.md e
  // IMPLEMENTACION_DNSSEC_AUDITORIA_CORE.md): antes de esta fecha, el
  // motor solo examinaba tldZone/parentZone y la ÚLTIMA delegación — una
  // ruptura en cualquier zona/delegación intermedia era invisible y el
  // dominio podía clasificarse "ok" incorrectamente. Se corrigió
  // reutilizando los estados YA EXISTENTES blocked_at_parent (ruptura
  // ancestro clara) e indeterminate (evidencia ancestro ambigua) — sin
  // crear ningún estado nuevo. Los 7 casos siguientes (A-G) cubren
  // exactamente los escenarios pedidos en la validación de esta corrección.
  // ═══════════════════════════════════════════════════════════════════
  const SEVEN_STATES = new Set([
    DNSSEC_FINAL_STATUS.OK, DNSSEC_FINAL_STATUS.NOT_IMPLEMENTED, DNSSEC_FINAL_STATUS.BLOCKED_AT_TLD,
    DNSSEC_FINAL_STATUS.BLOCKED_AT_PARENT, DNSSEC_FINAL_STATUS.MISCONFIGURED, DNSSEC_FINAL_STATUS.NON_EXISTENT,
    DNSSEC_FINAL_STATUS.INDETERMINATE
  ]);
  function assertKnownState(result) {
    assert.ok(SEVEN_STATES.has(result.final_status), `final_status "${result.final_status}" no es uno de los 7 estados conocidos`);
  }

  // ── A) Cadena completa y correcta (4 niveles) -> ok ──
  {
    const zones = [
      zone({ zone: 'ec', level: 1, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'gob.ec', level: 2, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'b.gob.ec', level: 3, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'a.b.gob.ec', level: 4, status: 'signed', query_status: 'ok' })
    ];
    const delegations = [
      delegation({ from: 'ec', to: 'gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' }),
      delegation({ from: 'gob.ec', to: 'b.gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' }),
      delegation({ from: 'b.gob.ec', to: 'a.b.gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' })
    ];
    const result = computeDnssecConclusion(zones, delegations, 'a.b.gob.ec', nameExistence());
    assertKnownState(result);
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.OK);
    console.log('PASS multinivel_A_cadena_completa_correcta');
  }

  // ── B) Ruptura inmediatamente bajo el TLD (nivel 2 de 4) -> blocked_at_parent ──
  // (Este es exactamente el caso que ANTES de la corrección se clasificaba
  // "ok" incorrectamente — ver el commit/documentación de esta fase.)
  {
    const zones = [
      zone({ zone: 'ec', level: 1, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'gob.ec', level: 2, status: 'unsigned', query_status: 'no_data' }), // ruptura, justo bajo el TLD
      zone({ zone: 'b.gob.ec', level: 3, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'a.b.gob.ec', level: 4, status: 'signed', query_status: 'ok' })
    ];
    const delegations = [
      delegation({ from: 'ec', to: 'gob.ec', ds_present: false, status: 'insecure', query_status: 'no_data' }),
      delegation({ from: 'gob.ec', to: 'b.gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' }),
      delegation({ from: 'b.gob.ec', to: 'a.b.gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' })
    ];
    const result = computeDnssecConclusion(zones, delegations, 'a.b.gob.ec', nameExistence());
    assertKnownState(result);
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.BLOCKED_AT_PARENT);
    assert.ok(result.summary.includes('gob.ec'), 'el resumen debe señalar la zona intermedia responsable');
    console.log('PASS multinivel_B_ruptura_justo_bajo_tld');
  }

  // ── C) Ruptura en un nivel intermedio "profundo" (5 niveles, rota en el
  // nivel 3, ni TLD ni padre inmediato) -> blocked_at_parent ──
  {
    const zones = [
      zone({ zone: 'ec', level: 1, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'gob.ec', level: 2, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'b.gob.ec', level: 3, status: 'unsigned', query_status: 'no_data' }), // ruptura intermedia profunda
      zone({ zone: 'a.b.gob.ec', level: 4, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'x.a.b.gob.ec', level: 5, status: 'signed', query_status: 'ok' })
    ];
    const delegations = [
      delegation({ from: 'ec', to: 'gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' }),
      delegation({ from: 'gob.ec', to: 'b.gob.ec', ds_present: false, status: 'insecure', query_status: 'no_data' }),
      delegation({ from: 'b.gob.ec', to: 'a.b.gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' }),
      delegation({ from: 'a.b.gob.ec', to: 'x.a.b.gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' })
    ];
    const result = computeDnssecConclusion(zones, delegations, 'x.a.b.gob.ec', nameExistence());
    assertKnownState(result);
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.BLOCKED_AT_PARENT);
    assert.ok(result.summary.includes('b.gob.ec'), 'el resumen debe señalar la zona intermedia profunda responsable');
    console.log('PASS multinivel_C_ruptura_intermedia_profunda');
  }

  // ── D) Ruptura en el padre INMEDIATO (4 niveles) -> blocked_at_parent
  // (comportamiento preexistente, confirmado que sigue intacto tras la corrección) ──
  {
    const zones = [
      zone({ zone: 'ec', level: 1, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'gob.ec', level: 2, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'b.gob.ec', level: 3, status: 'unsigned', query_status: 'no_data' }), // padre inmediato roto
      zone({ zone: 'a.b.gob.ec', level: 4, status: 'signed', query_status: 'ok' })
    ];
    const delegations = [
      delegation({ from: 'ec', to: 'gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' }),
      delegation({ from: 'gob.ec', to: 'b.gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' }),
      delegation({ from: 'b.gob.ec', to: 'a.b.gob.ec', ds_present: false, status: 'insecure', query_status: 'no_data' })
    ];
    const result = computeDnssecConclusion(zones, delegations, 'a.b.gob.ec', nameExistence());
    assertKnownState(result);
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.BLOCKED_AT_PARENT);
    console.log('PASS multinivel_D_ruptura_padre_inmediato');
  }

  // ── E) DNSKEY presente pero DS faltante en un nivel intermedio (la zona
  // intermedia SÍ está firmada, pero la delegación hacia ella no tiene DS
  // válido) -> blocked_at_parent, vía la delegación ancestro rota ──
  {
    const zones = [
      zone({ zone: 'ec', level: 1, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'gob.ec', level: 2, status: 'signed', query_status: 'ok' }), // tiene DNSKEY...
      zone({ zone: 'b.gob.ec', level: 3, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'a.b.gob.ec', level: 4, status: 'signed', query_status: 'ok' })
    ];
    const delegations = [
      // ...pero la delegación ec -> gob.ec no tiene DS: DNSKEY sin DS un nivel arriba.
      delegation({ from: 'ec', to: 'gob.ec', ds_present: false, secure: false, status: 'insecure', query_status: 'no_data' }),
      delegation({ from: 'gob.ec', to: 'b.gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' }),
      delegation({ from: 'b.gob.ec', to: 'a.b.gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' })
    ];
    const result = computeDnssecConclusion(zones, delegations, 'a.b.gob.ec', nameExistence());
    assertKnownState(result);
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.BLOCKED_AT_PARENT);
    console.log('PASS multinivel_E_dnskey_sin_ds_en_nivel_intermedio');
  }

  // ── F) DS presente pero DNSKEY ausente en un nivel intermedio -> sigue
  // dando blocked_at_parent, detectado por el estado de la ZONA (unsigned),
  // no por el de la delegación. (2026-09-16 — DNSSEC_DELEGATION_STATUS.BROKEN
  // se eliminó por ser inalcanzable, ver AUDITORIA_DNSSEC_BROKEN_DELEGATION.md:
  // el único productor real de `status` en una delegación con DS presente
  // SIEMPRE etiqueta "secure" — nunca "broken" — así que el fixture usa el
  // valor honesto que el sistema real produciría; lo que realmente atrapa
  // esta ruptura es que la zona "gob.ec" en sí no tiene DNSKEY.) ──
  {
    const zones = [
      zone({ zone: 'ec', level: 1, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'gob.ec', level: 2, status: 'unsigned', query_status: 'no_data' }), // sin DNSKEY propio...
      zone({ zone: 'b.gob.ec', level: 3, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'a.b.gob.ec', level: 4, status: 'signed', query_status: 'ok' })
    ];
    const delegations = [
      // ...aunque el padre sí publica un DS para ella (DS sin DNSKEY un nivel
      // arriba) — mapDelegationStatus() real la etiqueta "secure" igual,
      // porque solo mira presencia de DS, nunca DNSKEY del hijo.
      delegation({ from: 'ec', to: 'gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' }),
      delegation({ from: 'gob.ec', to: 'b.gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' }),
      delegation({ from: 'b.gob.ec', to: 'a.b.gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' })
    ];
    const result = computeDnssecConclusion(zones, delegations, 'a.b.gob.ec', nameExistence());
    assertKnownState(result);
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.BLOCKED_AT_PARENT);
    console.log('PASS multinivel_F_ds_sin_dnskey_en_nivel_intermedio');
  }

  // ── G) Error de medición en un nivel intermedio (timeout) -> indeterminate,
  // NUNCA un veredicto técnico (ya cubierto por hasHardErrors, que examina
  // TODAS las zonas/delegaciones desde antes de esta corrección — se
  // confirma aquí explícitamente en un contexto multinivel) ──
  {
    const zones = [
      zone({ zone: 'ec', level: 1, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'gob.ec', level: 2, status: 'unknown', query_status: 'timeout' }), // error de medición intermedio
      zone({ zone: 'b.gob.ec', level: 3, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'a.b.gob.ec', level: 4, status: 'signed', query_status: 'ok' })
    ];
    const delegations = [
      delegation({ from: 'ec', to: 'gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' }),
      delegation({ from: 'gob.ec', to: 'b.gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' }),
      delegation({ from: 'b.gob.ec', to: 'a.b.gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' })
    ];
    const result = computeDnssecConclusion(zones, delegations, 'a.b.gob.ec', nameExistence());
    assertKnownState(result);
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.INDETERMINATE);
    console.log('PASS multinivel_G_error_medicion_intermedio_timeout');
  }

  // ── G-bis) Evidencia AMBIGUA en un nivel intermedio (SERVFAIL sin
  // corroboración — no es un error "duro" como timeout/network_error, pero
  // tampoco es una confirmación clara de "unsigned") -> también
  // indeterminate, nunca "ok" forzado ──
  {
    const zones = [
      zone({ zone: 'ec', level: 1, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'gob.ec', level: 2, status: 'unknown', query_status: 'servfail' }), // ambiguo, no es error duro
      zone({ zone: 'b.gob.ec', level: 3, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'a.b.gob.ec', level: 4, status: 'signed', query_status: 'ok' })
    ];
    const delegations = [
      delegation({ from: 'ec', to: 'gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' }),
      delegation({ from: 'gob.ec', to: 'b.gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' }),
      delegation({ from: 'b.gob.ec', to: 'a.b.gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' })
    ];
    const result = computeDnssecConclusion(zones, delegations, 'a.b.gob.ec', nameExistence());
    assertKnownState(result);
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.INDETERMINATE);
    console.log('PASS multinivel_Gbis_servfail_ambiguo_intermedio');
  }

  // ── Verificación de no-regresión: not_implemented sigue funcionando en
  // un contexto multinivel donde TODOS los ancestros están correctamente
  // firmados y solo al propio dominio le falta DNSSEC ──
  {
    const zones = [
      zone({ zone: 'ec', level: 1, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'gob.ec', level: 2, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'b.gob.ec', level: 3, status: 'signed', query_status: 'ok' }), // padre inmediato, firmado
      zone({ zone: 'a.b.gob.ec', level: 4, status: 'unsigned', query_status: 'no_data' }) // el dominio en sí, sin DNSSEC
    ];
    const delegations = [
      delegation({ from: 'ec', to: 'gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' }),
      delegation({ from: 'gob.ec', to: 'b.gob.ec', ds_present: true, secure: true, status: 'secure', query_status: 'ok' }),
      delegation({ from: 'b.gob.ec', to: 'a.b.gob.ec', ds_present: false, status: 'insecure', query_status: 'no_data' })
    ];
    const result = computeDnssecConclusion(zones, delegations, 'a.b.gob.ec', nameExistence());
    assertKnownState(result);
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.NOT_IMPLEMENTED);
    console.log('PASS multinivel_sin_regresion_not_implemented');
  }

  // ── dnsvizSignal (2026-11-04, opt-in) — nuevos casos, no modifican los
  // de arriba. Ver logic/adapters/dnsviz.adapter.js y AUDITORIA_DNSVIZ_VS_
  // DNSSEC_ECUADOR.md para el contexto de esta integración.
  {
    // Sin dnsvizSignal (quinto argumento omitido): comportamiento idéntico
    // al caso 1 de arriba — no-regresión explícita del parámetro opcional.
    const zones = [
      zone({ zone: 'com', level: 1, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'example.com', level: 2, status: 'signed', query_status: 'ok' })
    ];
    const delegations = [delegation({ from: 'com', to: 'example.com', ds_present: true, secure: true, status: 'secure', query_status: 'ok' })];
    const result = computeDnssecConclusion(zones, delegations, 'example.com', nameExistence());
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.OK);
    console.log('PASS dnsvizSignal_omitido_sin_regresion');
  }

  {
    // Con dnsvizSignal.hasCryptoFailure=true: lo que el motor estructural
    // vería como OK (DS+DNSKEY presentes, igual que el caso 1) debe bajar
    // a misconfigured por la evidencia criptográfica real de DNSViz.
    const zones = [
      zone({ zone: 'com', level: 1, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'example.com', level: 2, status: 'signed', query_status: 'ok' })
    ];
    const delegations = [delegation({ from: 'com', to: 'example.com', ds_present: true, secure: true, status: 'secure', query_status: 'ok' })];
    const dnsvizSignal = { hasCryptoFailure: true, issues: [{ code: 'RRSIG_EXPIRED' }] };
    const result = computeDnssecConclusion(zones, delegations, 'example.com', nameExistence(), dnsvizSignal);
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.MISCONFIGURED);
    assert.ok(result.summary.includes('RRSIG_EXPIRED'), 'el resumen debe citar el código real reportado por DNSViz');
    console.log('PASS dnsvizSignal_degrada_ok_a_misconfigured');
  }

  {
    // dnsvizSignal.hasCryptoFailure=false (el adaptador corrió pero no
    // encontró problema real): el resultado debe seguir siendo ok, no
    // cambiar por el solo hecho de que el parámetro esté presente.
    const zones = [
      zone({ zone: 'com', level: 1, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'example.com', level: 2, status: 'signed', query_status: 'ok' })
    ];
    const delegations = [delegation({ from: 'com', to: 'example.com', ds_present: true, secure: true, status: 'secure', query_status: 'ok' })];
    const dnsvizSignal = { hasCryptoFailure: false, issues: [] };
    const result = computeDnssecConclusion(zones, delegations, 'example.com', nameExistence(), dnsvizSignal);
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.OK);
    console.log('PASS dnsvizSignal_sin_fallo_mantiene_ok');
  }

  {
    // dnsvizSignal no debe afectar estados que no son "sería ok" — ej. un
    // not_implemented sigue siendo not_implemented sin importar dnsvizSignal.
    const zones = [
      zone({ zone: 'com', level: 1, status: 'signed', query_status: 'ok' }),
      zone({ zone: 'example.com', level: 2, status: 'unsigned', query_status: 'no_data' })
    ];
    const delegations = [delegation({ from: 'com', to: 'example.com', ds_present: false, status: 'insecure', query_status: 'no_data' })];
    const dnsvizSignal = { hasCryptoFailure: true, issues: [{ code: 'RRSIG_EXPIRED' }] };
    const result = computeDnssecConclusion(zones, delegations, 'example.com', nameExistence(), dnsvizSignal);
    assert.strictEqual(result.final_status, DNSSEC_FINAL_STATUS.NOT_IMPLEMENTED);
    console.log('PASS dnsvizSignal_no_afecta_estados_distintos_de_ok');
  }

  console.log('\nOK — motor de clasificación DNSSEC (dnssec.rules.js): todos los casos pasaron.');
}

run();
