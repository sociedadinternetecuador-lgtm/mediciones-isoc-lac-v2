'use strict';

/**
 * Parser CSV mínimo (RFC 4180 recortado) para la importación de dominios
 * GED2026 — columnas domain,category,source,notes (sección 30 del pedido).
 *
 * Sin dependencia externa (CLAUDE.md regla 3: sin frameworks/librerías
 * nuevas) — comillas dobles para campos con comas o comillas internas,
 * "" como escape de comilla, igual que cualquier CSV RFC 4180 estándar.
 * Deliberadamente más completo que datasetDomains.validator.js's
 * `line.split(',')[0]` porque aquí `notes` es texto libre y puede contener
 * comas con frecuencia.
 */

function splitCsvLine(line) {
  const fields = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (line[i + 1] === '"') { current += '"'; i += 1; }
        else inQuotes = false;
      } else {
        current += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      fields.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  fields.push(current);
  return fields.map((f) => f.trim());
}

const HEADER_RE = /^domain$/i;

// Devuelve { rows, skippedBlankLines }. No valida el dominio en sí (eso lo
// hace ged2026Domains.validator.js por fila, con acceso a la Public Suffix
// List) — este módulo es puro texto→estructura, sin I/O.
function parseGed2026Csv(text) {
  const lines = String(text || '').split(/\r\n|\r|\n/);
  const rows = [];
  let skippedBlankLines = 0;

  lines.forEach((line, i) => {
    if (!line.trim()) { skippedBlankLines += 1; return; }
    const fields = splitCsvLine(line);
    if (i === 0 && HEADER_RE.test(fields[0] || '')) return; // encabezado, se salta
    rows.push({
      domain: fields[0] || '',
      category: fields[1] || '',
      source: fields[2] || '',
      notes: fields[3] || '',
    });
  });

  return { rows, skippedBlankLines };
}

module.exports = { parseGed2026Csv, splitCsvLine };
