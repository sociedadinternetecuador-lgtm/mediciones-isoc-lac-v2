'use strict';

/**
 * Prueba de equivalencia: logic/validators/dnsValidation.validator.js
 * (classifyAnswers / reviewSubtype) vs. classify_answers()/review_subtype()
 * del validador de referencia (validador/validar_dominios_isoc_lac.py).
 *
 * Son funciones puras (sin red) — se les da un conjunto sintético de
 * respuestas DNS ya resueltas y se compara la clasificación resultante.
 * Cubre en particular los casos donde el orden de evaluación de Python
 * importa (discrepancy se revisa ANTES que los subtipos REFUSED/MIXED, por
 * lo que esos subtipos solo aparecen cuando NO hay discrepancia).
 *
 * Los valores esperados se capturaron ejecutando classify_answers()/
 * review_subtype() REALES de Python (ver metodología en
 * datasetDomains.parity.test.js — mismo patrón de importlib).
 *
 * Ejecutar: node test/dnsValidation.classify.parity.test.js
 */

const assert = require('assert');
const { classifyAnswers, reviewSubtype } = require('../logic/validators/dnsValidation.validator');

function ans(resolver, server, rtype, rcode) {
  return { resolver, server, rtype, rcode, error: '', attempts: 1 };
}

const CASES = {
  both_noerror_ns: {
    answers: {
      'cloudflare:NS': ans('cloudflare', '1.1.1.1', 'NS', 'NOERROR'),
      'google:NS': ans('google', '8.8.8.8', 'NS', 'NOERROR'),
    },
    expected: { status: 'VALID', discrepancy: false, subtype: '' },
  },
  one_noerror_one_timeout_ns: {
    // VALID igual, aunque discrepancy=true (un NOERROR basta, sin importar
    // que el otro resolver no coincida).
    answers: {
      'cloudflare:NS': ans('cloudflare', '1.1.1.1', 'NS', 'NOERROR'),
      'google:NS': ans('google', '8.8.8.8', 'NS', 'TIMEOUT'),
    },
    expected: { status: 'VALID', discrepancy: true, subtype: '' },
  },
  both_nxdomain_ns: {
    answers: {
      'cloudflare:NS': ans('cloudflare', '1.1.1.1', 'NS', 'NXDOMAIN'),
      'google:NS': ans('google', '8.8.8.8', 'NS', 'NXDOMAIN'),
    },
    expected: { status: 'NXDOMAIN', discrepancy: false, subtype: '' },
  },
  nxdomain_and_servfail_ns: {
    // Un solo NXDOMAIN no basta (se requieren ambos) -> REVIEW, y como los
    // dos valores difieren, discrepancy=true -> REVIEW_CONFLICT (no
    // REVIEW_SERVFAIL, aunque SERVFAIL esté presente).
    answers: {
      'cloudflare:NS': ans('cloudflare', '1.1.1.1', 'NS', 'NXDOMAIN'),
      'google:NS': ans('google', '8.8.8.8', 'NS', 'SERVFAIL'),
    },
    expected: { status: 'REVIEW', discrepancy: true, subtype: 'REVIEW_CONFLICT' },
  },
  both_servfail_ns: {
    answers: {
      'cloudflare:NS': ans('cloudflare', '1.1.1.1', 'NS', 'SERVFAIL'),
      'google:NS': ans('google', '8.8.8.8', 'NS', 'SERVFAIL'),
    },
    expected: { status: 'REVIEW', discrepancy: false, subtype: 'REVIEW_SERVFAIL' },
  },
  noerror_and_nxdomain_ns: {
    answers: {
      'cloudflare:NS': ans('cloudflare', '1.1.1.1', 'NS', 'NOERROR'),
      'google:NS': ans('google', '8.8.8.8', 'NS', 'NXDOMAIN'),
    },
    expected: { status: 'VALID', discrepancy: true, subtype: '' },
  },
  ns_servfail_soa_noerror_nxdomain: {
    // NS inconcluso (SERVFAIL ambos) -> se consulta SOA de respaldo; SOA
    // trae un NOERROR -> VALID, aunque SOA discrepe entre sí.
    answers: {
      'cloudflare:NS': ans('cloudflare', '1.1.1.1', 'NS', 'SERVFAIL'),
      'google:NS': ans('google', '8.8.8.8', 'NS', 'SERVFAIL'),
      'cloudflare:SOA': ans('cloudflare', '1.1.1.1', 'SOA', 'NOERROR'),
      'google:SOA': ans('google', '8.8.8.8', 'SOA', 'NXDOMAIN'),
    },
    expected: { status: 'VALID', discrepancy: true, subtype: '' },
  },
  ns_servfail_soa_both_nxdomain: {
    answers: {
      'cloudflare:NS': ans('cloudflare', '1.1.1.1', 'NS', 'SERVFAIL'),
      'google:NS': ans('google', '8.8.8.8', 'NS', 'SERVFAIL'),
      'cloudflare:SOA': ans('cloudflare', '1.1.1.1', 'SOA', 'NXDOMAIN'),
      'google:SOA': ans('google', '8.8.8.8', 'SOA', 'NXDOMAIN'),
    },
    expected: { status: 'NXDOMAIN', discrepancy: false, subtype: '' },
  },
  fully_inconclusive_ns_soa_timeout: {
    answers: {
      'cloudflare:NS': ans('cloudflare', '1.1.1.1', 'NS', 'TIMEOUT'),
      'google:NS': ans('google', '8.8.8.8', 'NS', 'TIMEOUT'),
      'cloudflare:SOA': ans('cloudflare', '1.1.1.1', 'SOA', 'TIMEOUT'),
      'google:SOA': ans('google', '8.8.8.8', 'SOA', 'TIMEOUT'),
    },
    expected: { status: 'REVIEW', discrepancy: false, subtype: 'REVIEW_TIMEOUT' },
  },
  review_refused_present_but_discrepant: {
    // REFUSED está presente pero hay discrepancy -> gana REVIEW_CONFLICT.
    // review_subtype() revisa discrepancy ANTES que REFUSED/ERROR/etc.
    answers: {
      'cloudflare:NS': ans('cloudflare', '1.1.1.1', 'NS', 'REFUSED'),
      'google:NS': ans('google', '8.8.8.8', 'NS', 'SERVFAIL'),
    },
    expected: { status: 'REVIEW', discrepancy: true, subtype: 'REVIEW_CONFLICT' },
  },
  review_mixed_timeout_servfail_but_discrepant: {
    answers: {
      'cloudflare:NS': ans('cloudflare', '1.1.1.1', 'NS', 'TIMEOUT'),
      'google:NS': ans('google', '8.8.8.8', 'NS', 'SERVFAIL'),
    },
    expected: { status: 'REVIEW', discrepancy: true, subtype: 'REVIEW_CONFLICT' },
  },
  review_refused_no_discrepancy: {
    // Ambos resolvers REFUSED (mismo valor -> sin discrepancy) -> aquí sí
    // aparece REVIEW_REFUSED.
    answers: {
      'cloudflare:NS': ans('cloudflare', '1.1.1.1', 'NS', 'REFUSED'),
      'google:NS': ans('google', '8.8.8.8', 'NS', 'REFUSED'),
    },
    expected: { status: 'REVIEW', discrepancy: false, subtype: 'REVIEW_REFUSED' },
  },
  review_mixed_timeout_servfail_no_discrepancy: {
    // NS: ambos TIMEOUT (sin discrepancy en NS). SOA: ambos SERVFAIL (sin
    // discrepancy en SOA). La mezcla es ENTRE fases, no dentro de una —
    // por eso discrepancy=false pero el conjunto total mezcla TIMEOUT+SERVFAIL.
    answers: {
      'cloudflare:NS': ans('cloudflare', '1.1.1.1', 'NS', 'TIMEOUT'),
      'google:NS': ans('google', '8.8.8.8', 'NS', 'TIMEOUT'),
      'cloudflare:SOA': ans('cloudflare', '1.1.1.1', 'SOA', 'SERVFAIL'),
      'google:SOA': ans('google', '8.8.8.8', 'SOA', 'SERVFAIL'),
    },
    expected: { status: 'REVIEW', discrepancy: false, subtype: 'REVIEW_MIXED_TIMEOUT_SERVFAIL' },
  },
  review_error_present: {
    answers: {
      'cloudflare:NS': ans('cloudflare', '1.1.1.1', 'NS', 'ERROR'),
      'google:NS': ans('google', '8.8.8.8', 'NS', 'ERROR'),
    },
    expected: { status: 'REVIEW', discrepancy: false, subtype: 'REVIEW_ERROR' },
  },
};

let failures = 0;
for (const [name, { answers, expected }] of Object.entries(CASES)) {
  try {
    const c = classifyAnswers(answers, ['cloudflare', 'google']);
    const subtype = reviewSubtype({ status: c.status, discrepancy: c.discrepancy, answers });

    assert.strictEqual(c.status, expected.status, `${name}: status`);
    assert.strictEqual(c.discrepancy, expected.discrepancy, `${name}: discrepancy`);
    assert.strictEqual(subtype, expected.subtype, `${name}: review_subtype`);
    console.log(`PASS ${name}`);
  } catch (error) {
    failures += 1;
    console.error(`FAIL ${name}: ${error.message}`);
  }
}

if (failures > 0) {
  console.error(`\n${failures} caso(s) fallaron.`);
  process.exit(1);
}
console.log(`\nOK — ${Object.keys(CASES).length} casos coinciden exactamente con classify_answers()/review_subtype() de Python.`);
