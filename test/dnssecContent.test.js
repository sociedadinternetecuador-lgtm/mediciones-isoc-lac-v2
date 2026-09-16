'use strict';

/**
 * Tests de logic/content/dnssecGuidance.content.js y
 * logic/content/dnssecGlossary.content.js — confirma que el estado muerto
 * "ready" fue eliminado limpiamente (ver AUDITORIA_DNSSEC_ECUADOR_
 * METODOLOGIA_MOTOR.md e IMPLEMENTACION_DNSSEC_AUDITORIA_CORE.md) y que
 * los 7 estados realmente alcanzables siguen teniendo guía/glosario
 * completos.
 *
 * Ejecutar: node test/dnssecContent.test.js
 */

const assert = require('assert');
const { getDnssecGuidance } = require('../logic/content/dnssecGuidance.content');
const { getGlossaryForStatus } = require('../logic/content/dnssecGlossary.content');
const { DNSSEC_FINAL_STATUS } = require('../config/dnssec.constants');

function run() {
  const reachableStates = Object.values(DNSSEC_FINAL_STATUS);
  assert.strictEqual(reachableStates.length, 7, 'DNSSEC_FINAL_STATUS debe tener exactamente 7 valores tras eliminar READY');
  assert.ok(!reachableStates.includes('ready'), '"ready" no debe seguir siendo un valor de DNSSEC_FINAL_STATUS');
  console.log('PASS constants_sin_ready_7_valores');

  // ── Cada uno de los 7 estados alcanzables tiene guía completa (no cae al default genérico) ──
  for (const status of reachableStates) {
    const guidance = getDnssecGuidance(status);
    assert.notStrictEqual(guidance.title, 'Análisis DNSSEC', `${status} no debería caer en la guía genérica de "default"`);
    assert.ok(Array.isArray(guidance.recommendations) && guidance.recommendations.length > 0, `${status} debe tener recomendaciones`);
  }
  console.log('PASS guidance_completa_para_los_7_estados');

  // ── "ready" ya no tiene guía propia — cae al default genérico ──
  {
    const guidance = getDnssecGuidance('ready');
    assert.strictEqual(guidance.title, 'Análisis DNSSEC');
    console.log('PASS guidance_ready_cae_a_default');
  }

  // ── Glosario: cada estado alcanzable devuelve al menos el término base "dnssec" ──
  for (const status of reachableStates) {
    const glossary = getGlossaryForStatus(status);
    assert.ok(Array.isArray(glossary) && glossary.length > 0, `${status} debe tener al menos un término de glosario`);
    assert.ok(glossary.some(g => g.term === 'DNSSEC'), `${status} debe incluir el término base DNSSEC`);
  }
  console.log('PASS glosario_completo_para_los_7_estados');

  console.log('\nOK — contenido de guía/glosario DNSSEC: todos los casos pasaron.');
}

run();
