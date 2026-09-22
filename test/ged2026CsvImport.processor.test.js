'use strict';

/**
 * parseGed2026Csv() — parser puro, sin I/O. Cubre encabezado, campos con
 * comas entre comillas, comillas escapadas, líneas en blanco y filas con
 * columnas faltantes.
 *
 * Ejecutar: node test/ged2026CsvImport.processor.test.js
 */

const assert = require('assert');
const { parseGed2026Csv, splitCsvLine } = require('../logic/processors/ged2026CsvImport.processor');

function run() {
  // ─── splitCsvLine: campo entre comillas con coma interna + comilla escapada ──
  const fields = splitCsvLine('banco.ec,servicio_financiero,manual,"Banco ""Principal"", sede Quito"');
  assert.deepStrictEqual(fields, ['banco.ec', 'servicio_financiero', 'manual', 'Banco "Principal", sede Quito']);

  // ─── Encabezado se detecta y se salta ────────────────────────────
  const withHeader = parseGed2026Csv('domain,category,source,notes\nbanco.ec,financiero,manual,ok');
  assert.strictEqual(withHeader.rows.length, 1);
  assert.deepStrictEqual(withHeader.rows[0], { domain: 'banco.ec', category: 'financiero', source: 'manual', notes: 'ok' });

  // ─── Sin encabezado: la primera línea SÍ es un dato ──────────────
  const noHeader = parseGed2026Csv('banco.ec,financiero,manual,ok');
  assert.strictEqual(noHeader.rows.length, 1);
  assert.strictEqual(noHeader.rows[0].domain, 'banco.ec');

  // ─── Líneas en blanco se cuentan, no generan fila ────────────────
  const withBlanks = parseGed2026Csv('domain,category,source,notes\nbanco.ec,financiero,,\n\n   \nuniversidad.edu.ec,educacion,,');
  assert.strictEqual(withBlanks.rows.length, 2);
  assert.strictEqual(withBlanks.skippedBlankLines, 2);

  // ─── Columnas faltantes se completan como '' (no lanza, no descarta) ──
  const shortRow = parseGed2026Csv('domain,category,source,notes\nsolo-dominio.ec');
  assert.strictEqual(shortRow.rows.length, 1);
  assert.deepStrictEqual(shortRow.rows[0], { domain: 'solo-dominio.ec', category: '', source: '', notes: '' });

  // ─── Notas con coma sin comillas: se corta en la coma (comportamiento
  // esperado de CSV — el admin debe entrecomillar si su texto lleva comas) ──
  const unquotedComma = parseGed2026Csv('domain,category,source,notes\nx.ec,cat,src,uno, dos');
  assert.strictEqual(unquotedComma.rows[0].notes, 'uno'); // "dos" queda descartado (5ta columna, ignorada)

  console.log('✅ ged2026CsvImport.processor.test.js — todos los casos OK');
}

run();
