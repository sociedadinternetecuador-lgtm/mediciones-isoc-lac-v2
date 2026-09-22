'use strict';

/**
 * Parser CSV para la actualización masiva de dominios GED2026
 * (POST /admin/api/ged2026/domains/bulk-update) — a diferencia del
 * importador de altas (ged2026CsvImport.processor.js, columnas fijas
 * domain,category,source,notes), este formato es dirigido por
 * ENCABEZADO: la primera fila SIEMPRE se toma como nombres de columna
 * (no hay detección opcional), porque el propósito es dejar que el
 * curador incluya solo las columnas que quiere tocar en cada lote
 * (estado_seleccion, institutional_relevance, notas, tipo_institucion,
 * categoria, fuente), en cualquier orden.
 *
 * Reutiliza el mismo splitCsvLine (comillas dobles, escape "") que el
 * importador de altas — no se reimplementa el parseo de campos.
 */

const { splitCsvLine } = require('./ged2026CsvImport.processor');

function parseGed2026BulkUpdateCsv(text) {
  const lines = String(text || '').split(/\r?\n/);
  const rows = [];
  let skippedBlankLines = 0;
  let header = null;

  for (const line of lines) {
    if (!line.trim()) { skippedBlankLines += 1; continue; }
    const fields = splitCsvLine(line);
    if (!header) {
      header = fields.map((h) => h.trim().toLowerCase());
      continue;
    }
    const row = {};
    header.forEach((col, i) => { row[col] = (fields[i] || '').trim(); });
    rows.push(row);
  }

  return { rows, skippedBlankLines };
}

module.exports = { parseGed2026BulkUpdateCsv };
