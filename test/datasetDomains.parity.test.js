'use strict';

/**
 * Prueba de equivalencia: logic/validators/datasetDomains.validator.js
 * (parseDatasetText) vs. parse_input() del validador de referencia
 * (validador/validar_dominios_isoc_lac.py).
 *
 * Los valores esperados en EXPECTED_BY_CASE se capturaron ejecutando el
 * parse_input() REAL de Python (no reescrito) sobre estos mismos casos,
 * importando el módulo directamente (ver metodología abajo). Si el
 * validador Python cambia, hay que volver a capturar estos valores — no
 * ajustarlos por intuición.
 *
 * Cómo se capturaron (Python 3.11 + dnspython instalado):
 *   import importlib.util
 *   spec = importlib.util.spec_from_file_location(
 *     "validador_ref", "validador/validar_dominios_isoc_lac.py")
 *   mod = importlib.util.module_from_spec(spec)
 *   sys.modules["validador_ref"] = mod   # necesario por el uso de dataclasses
 *   spec.loader.exec_module(mod)
 *   normalized, rejected, stats = mod.parse_input(FakePath(text), "ec")
 *
 * Ejecutar: node test/datasetDomains.parity.test.js
 */

const assert = require('assert');
const { parseDatasetText } = require('../logic/validators/datasetDomains.validator');

const CASES = {
  csv_extra_columns: 'nic.ec,extra,column\n',
  csv_multiple_commas: 'isoc.org.ec,col2,col3,col4\n',
  csv_leading_comma: ',isoc.org.ec\n',
  csv_only_comma: ',\n',
  csv_quoted_with_embedded_comma: '"foo,bar.ec",baz\n',
  csv_trailing_comma: 'isoc.org.ec,\n',
  csv_no_comma_normal: 'isoc.org.ec\n',
  csv_spaces_around_first_col: '  isoc.org.ec  ,extra\n',
  csv_tab_not_comma: 'isoc.org.ec\textra\n',
  csv_semicolon_not_comma: 'isoc.org.ec;extra\n',
  // Caso real: espacios, mayúsculas, duplicado, fuera de ccTLD, no-dominio,
  // punto final — combinado en un solo archivo, como llegaría de verdad.
  mixed_realistic:
    'nic.ec,1,2\ncorpece.org.ec\nISOC.ORG.EC\ngoogle.com,x\nnot a domain,y\n gob.ec \n,\nisoc.org.ec.,z\n',
};

// Capturado del parse_input() real de Python (ver cabecera de este archivo).
const EXPECTED_BY_CASE = {
  csv_extra_columns: {
    normalized: ['nic.ec'],
    rejected: [],
    stats: { raw_lines: 1, empty: 0, normalized: 1, rejected: 0 },
  },
  csv_multiple_commas: {
    normalized: ['isoc.org.ec'],
    rejected: [],
    stats: { raw_lines: 1, empty: 0, normalized: 1, rejected: 0 },
  },
  csv_leading_comma: {
    normalized: [],
    rejected: [],
    stats: { raw_lines: 1, empty: 1, normalized: 0, rejected: 0 },
  },
  csv_only_comma: {
    normalized: [],
    rejected: [],
    stats: { raw_lines: 1, empty: 1, normalized: 0, rejected: 0 },
  },
  csv_quoted_with_embedded_comma: {
    // La primera "columna" naive incluye la comilla de apertura sin cierre;
    // normalize_domain() la retira (strip('"')), quedando "foo" — sin punto,
    // por lo que Python la rechaza por outside_tld (no por invalid_label).
    normalized: [],
    rejected: [['foo', 'outside_tld']],
    stats: { raw_lines: 1, empty: 0, normalized: 0, rejected: 1 },
  },
  csv_trailing_comma: {
    normalized: ['isoc.org.ec'],
    rejected: [],
    stats: { raw_lines: 1, empty: 0, normalized: 1, rejected: 0 },
  },
  csv_no_comma_normal: {
    normalized: ['isoc.org.ec'],
    rejected: [],
    stats: { raw_lines: 1, empty: 0, normalized: 1, rejected: 0 },
  },
  csv_spaces_around_first_col: {
    normalized: ['isoc.org.ec'],
    rejected: [],
    stats: { raw_lines: 1, empty: 0, normalized: 1, rejected: 0 },
  },
  csv_tab_not_comma: {
    // Sin coma, la "primera columna" es la línea completa (tab incluido);
    // no termina en ".ec" -> outside_tld. No se interpreta el tab como
    // separador — igual que Python, que solo separa por coma.
    normalized: [],
    rejected: [['isoc.org.ec\textra', 'outside_tld']],
    stats: { raw_lines: 1, empty: 0, normalized: 0, rejected: 1 },
  },
  csv_semicolon_not_comma: {
    normalized: [],
    rejected: [['isoc.org.ec;extra', 'outside_tld']],
    stats: { raw_lines: 1, empty: 0, normalized: 0, rejected: 1 },
  },
  mixed_realistic: {
    normalized: ['corpece.org.ec', 'gob.ec', 'isoc.org.ec', 'nic.ec'],
    // "not a domain" pasa el paso IDNA de Python sin error (fast-path ASCII
    // de encodings/idna.py no valida caracteres, solo longitud por etiqueta)
    // y se rechaza por outside_tld, NO por idna_error/invalid_label.
    rejected: [
      ['google.com', 'outside_tld'],
      ['not a domain', 'outside_tld'],
    ],
    stats: { raw_lines: 8, empty: 1, normalized: 4, rejected: 2 },
  },
};

function runCase(name, text) {
  const expected = EXPECTED_BY_CASE[name];
  const actual = parseDatasetText(text, 'ec');

  assert.deepStrictEqual(actual.normalized, expected.normalized, `${name}: normalized`);
  assert.deepStrictEqual(actual.rejected, expected.rejected, `${name}: rejected`);
  assert.strictEqual(actual.stats.raw_lines, expected.stats.raw_lines, `${name}: stats.raw_lines`);
  assert.strictEqual(actual.stats.empty, expected.stats.empty, `${name}: stats.empty`);
  assert.strictEqual(actual.stats.normalized, expected.stats.normalized, `${name}: stats.normalized`);
  assert.strictEqual(actual.stats.rejected, expected.stats.rejected, `${name}: stats.rejected`);
}

let failures = 0;
for (const [name, text] of Object.entries(CASES)) {
  try {
    runCase(name, text);
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
console.log(`\nOK — ${Object.keys(CASES).length} casos coinciden exactamente con parse_input() de Python.`);
