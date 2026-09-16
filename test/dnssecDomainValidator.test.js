'use strict';

/**
 * Tests de logic/validators/domain.validator.js — auditoría/fortalecimiento
 * conservador del motor DNSSEC, 2026-09-16. Ver
 * AUDITORIA_DNSSEC_ECUADOR_METODOLOGIA_MOTOR.md e
 * IMPLEMENTACION_DNSSEC_AUDITORIA_CORE.md.
 *
 * Corrección objetiva de esta fase (no amplía el motor, corrige entrada
 * válida): un dominio internacionalizado en su forma Unicode natural (ej.
 * "café.com") se rechazaba como "Dominio inválido" porque
 * isLikelyValidDomain() exige [a-z0-9-] por etiqueta y no se aplicaba
 * conversión IDNA/punycode antes de validar. Se corrigió aplicando
 * url.domainToASCII() (mecanismo nativo de Node, mismo que ya usa
 * server.js para MEDICIONES) dentro de sanitizeDomain(), antes de la
 * validación de sintaxis — sin lógica IDNA artesanal.
 *
 * Ejecutar: node test/dnssecDomainValidator.test.js
 */

const assert = require('assert');
const { sanitizeDomain, isLikelyValidDomain, validateDomainInput } = require('../logic/validators/domain.validator');

function run() {
  // ── IDNA: dominio Unicode se acepta y se convierte a punycode ──
  {
    assert.strictEqual(validateDomainInput('café.com'), 'xn--caf-dma.com');
    assert.strictEqual(validateDomainInput('CAFÉ.COM'), 'xn--caf-dma.com');
    console.log('PASS idna_dominio_unicode_aceptado_y_convertido');
  }

  // ── IDNA: un dominio ya en punycode se acepta igual (idempotente) ──
  {
    assert.strictEqual(validateDomainInput('xn--caf-dma.com'), 'xn--caf-dma.com');
    console.log('PASS idna_punycode_ya_convertido_idempotente');
  }

  // ── Dominios ASCII normales: comportamiento sin cambios ──
  {
    assert.strictEqual(validateDomainInput('example.com'), 'example.com');
    assert.strictEqual(validateDomainInput('EXAMPLE.COM'), 'example.com');
    assert.strictEqual(validateDomainInput('https://example.com/ruta'), 'example.com');
    assert.strictEqual(validateDomainInput('  example.com  '), 'example.com');
    assert.strictEqual(validateDomainInput('example.com.'), 'example.com');
    console.log('PASS ascii_normal_sin_cambios');
  }

  // ── Entradas inválidas siguen siendo rechazadas ──
  {
    for (const bad of ['', null, undefined, 'no es un dominio !!', 'solo-una-etiqueta', '-empieza-con-guion.com']) {
      assert.throws(() => validateDomainInput(bad), { code: 'INVALID_DOMAIN' }, `debía rechazar: ${JSON.stringify(bad)}`);
    }
    console.log('PASS entradas_invalidas_siguen_rechazadas');
  }

  // ── sanitizeDomain/isLikelyValidDomain siguen exportadas y coherentes ──
  {
    assert.strictEqual(sanitizeDomain('café.com'), 'xn--caf-dma.com');
    assert.strictEqual(isLikelyValidDomain('xn--caf-dma.com'), true);
    assert.strictEqual(isLikelyValidDomain('café.com'), false, 'isLikelyValidDomain en sí no hace IDNA — sanitizeDomain es quien la aplica antes');
    console.log('PASS helpers_internos_coherentes');
  }

  console.log('\nOK — domain.validator.js (con corrección IDNA): todos los casos pasaron.');
}

run();
