'use strict';

/**
 * parseGed2026BulkUpdateCsv() — a diferencia de parseGed2026Csv() (columnas
 * fijas, encabezado opcional), este parser es dirigido por encabezado
 * (obligatorio) y por nombre de columna, en cualquier orden.
 *
 * Ejecutar: node test/ged2026BulkUpdate.processor.test.js
 */

const assert = require('assert');
const { parseGed2026BulkUpdateCsv } = require('../logic/processors/ged2026BulkUpdate.processor');

function run() {
  // ─── Columnas en cualquier orden, mapeadas por nombre ────────────
  const basic = parseGed2026BulkUpdateCsv('notas,domain,estado_seleccion\nInstitución nacional,iess.gob.ec,shortlisted');
  assert.strictEqual(basic.rows.length, 1);
  assert.deepStrictEqual(basic.rows[0], { notas: 'Institución nacional', domain: 'iess.gob.ec', estado_seleccion: 'shortlisted' });

  // ─── Columna con comas entre comillas ────────────────────────────
  const quoted = parseGed2026BulkUpdateCsv('domain,notas\nbanco.com.ec,"Banco ""grande"", prioritario"');
  assert.strictEqual(quoted.rows[0].notas, 'Banco "grande", prioritario');

  // ─── Sin encabezado explícito: la primera fila SIEMPRE se toma como tal
  // (a diferencia del importador de altas) ──────────────────────────
  const noRealHeader = parseGed2026BulkUpdateCsv('domain,estado_seleccion\nsri.gob.ec,shortlisted\nmsp.gob.ec,shortlisted');
  assert.strictEqual(noRealHeader.rows.length, 2);
  assert.strictEqual(noRealHeader.rows[0].domain, 'sri.gob.ec');

  // ─── Líneas en blanco se cuentan, no generan fila ────────────────
  const withBlanks = parseGed2026BulkUpdateCsv('domain,estado_seleccion\nsri.gob.ec,shortlisted\n\n   \nmsp.gob.ec,shortlisted');
  assert.strictEqual(withBlanks.rows.length, 2);
  assert.strictEqual(withBlanks.skippedBlankLines, 2);

  // ─── Fila más corta que el encabezado: columnas faltantes quedan '' ──
  const shortRow = parseGed2026BulkUpdateCsv('domain,estado_seleccion,notas\nsolo-dominio.gob.ec');
  assert.deepStrictEqual(shortRow.rows[0], { domain: 'solo-dominio.gob.ec', estado_seleccion: '', notas: '' });

  console.log('✅ ged2026BulkUpdate.processor.test.js — todos los casos OK');
}

run();
