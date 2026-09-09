'use strict';

/**
 * Exportadores del reporte de "Análisis comparativo" (sub-tab de
 * Mediciones — index.html, medicionesBatchStart). El navegador ya corrió
 * la medición (checks + DNSSEC + validación DNS) y ensambló el payload
 * completo; este módulo solo formatea la salida:
 *
 *  - buildComparativeMarkdown: Markdown con frontmatter YAML para el
 *    servicio externo mdtopdf (server1:8600). Reporte EJECUTIVO
 *    CONDENSADO — por diseño, NO vuelca arrays largos de `details` crudos
 *    (eso satura el límite de 30s de mdtopdf con lotes de 20-25 dominios
 *    y ~40 checks). El detalle completo vive solo en el JSON.
 *  - buildJsonExport: el payload completo (detalle sin condensar) más
 *    metadata de exportación.
 *
 * Referencia de estilo: aggregate/exporters/exporters.js (HTML) y
 * logic/exporters/datasetResultsPackage.exporter.js (metadata/hashes) —
 * adaptado, no copiado: aquí no hay DNS crudo que hashear ni HTML que
 * generar, solo Markdown.
 */

const STATUS_ICON = { ok: '✓', fail: '✗', error: '⚠', info: 'ℹ' };

// Mismos 4 estados que devuelve cada check en el navegador (ver STATUS_SYMBOL
// en index.html) — la leyenda se repite en el PDF porque acá no hay tooltip
// posible como en la UI. Se renderiza como tabla (no como línea suelta antes
// de la tabla comparativa) y se ubica al inicio del documento — una línea
// itálica pegada a una tabla de 2+ páginas después se perdía de vista.
const STATUS_LEGEND_ROWS = [
  ['✓', 'OK — cumple / se detectó correctamente'],
  ['✗', 'No cumple / no se encontró'],
  ['⚠', 'Error al verificar — no se pudo comprobar (timeout, servicio externo caído, etc.). No es lo mismo que "no cumple".'],
  ['ℹ', 'Informativo — dato disponible, sin evaluación de "bien/mal" (ej. IPv6: tenerlo o no tenerlo no es en sí un fallo)'],
  ['—', 'Sin datos — este check no se ejecutó para este dominio'],
];

function buildStatusLegendTable() {
  const lines = ['| Símbolo | Significado |', '| --- | --- |'];
  for (const [icon, meaning] of STATUS_LEGEND_ROWS) {
    lines.push(`| **${icon}** | ${esc(meaning)} |`);
  }
  return lines.join('\n') + '\n';
}

// Mismo orden de categorías que `groupDefinitions` en index.html — solo para
// ordenar la tabla comparativa de forma legible (no es lógica de negocio).
// Un check con un `group` no reconocido cae en "Otros", al final.
const CHECK_GROUP_ORDER = [
  'IP y Red',
  'DNS y Seguridad',
  'Correo y Mensajería',
  'Identidad y Cumplimiento',
  'Contenido y Experiencia',
  'Seguridad Web y TLS',
];

// Máximo de columnas de check por tabla. Con encabezados de una sola palabra
// sin espacios (ej. claves crudas como "serverlocation") el renderizador no
// tiene dónde partir la línea y la tabla se sale de la página aunque esté en
// landscape — por eso además de usar la etiqueta legible (con espacios, sí
// se puede partir) se limita cuántas columnas entran por tabla.
const MAX_CHECKS_PER_TABLE = 6;

// A partir de `meta.selected_checks_glossary` (armado en el navegador por
// selectedGlossary(), misma fuente que los tooltips) arma key -> {label,
// group}. Si el payload no lo trae (compatibilidad hacia atrás), cae a la
// clave cruda como label y "Otros" como grupo — sigue funcionando, solo sin
// las mejoras de legibilidad.
function buildChecksMeta(glossaryEntries) {
  const meta = new Map();
  if (Array.isArray(glossaryEntries)) {
    for (const entry of glossaryEntries) {
      if (entry?.key) meta.set(entry.key, { label: entry.label || entry.key, group: entry.group || 'Otros' });
    }
  }
  return meta;
}

function checkLabel(key, checksMeta) {
  return checksMeta.get(key)?.label || key;
}

// Agrupa selectedChecks por categoría (orden de CHECK_GROUP_ORDER, luego
// "Otros") y parte cada grupo en tandas de MAX_CHECKS_PER_TABLE — devuelve
// [{ group, chunkIndex, chunkCount, keys }, ...] en el orden en que deben
// imprimirse las tablas.
function groupAndChunkChecks(selectedChecks, checksMeta) {
  const byGroup = new Map();
  for (const key of selectedChecks) {
    const group = checksMeta.get(key)?.group || 'Otros';
    if (!byGroup.has(group)) byGroup.set(group, []);
    byGroup.get(group).push(key);
  }
  const orderedGroups = [
    ...CHECK_GROUP_ORDER.filter((g) => byGroup.has(g)),
    ...[...byGroup.keys()].filter((g) => !CHECK_GROUP_ORDER.includes(g)),
  ];
  const result = [];
  for (const group of orderedGroups) {
    const keys = byGroup.get(group);
    const chunks = [];
    for (let i = 0; i < keys.length; i += MAX_CHECKS_PER_TABLE) chunks.push(keys.slice(i, i + MAX_CHECKS_PER_TABLE));
    chunks.forEach((chunkKeys, i) => {
      result.push({ group, chunkIndex: i + 1, chunkCount: chunks.length, keys: chunkKeys });
    });
  }
  return result;
}

const DNS_VALIDATION_LABELS = {
  VALID: 'VALID',
  NXDOMAIN: 'NXDOMAIN',
  REVIEW: 'REVIEW',
};

const SEMAPHORE_LABELS = {
  green: 'Verde — adopción sólida',
  yellow: 'Amarilla — adopción parcial',
  red: 'Roja — adopción crítica',
  insufficient: 'Muestra insuficiente',
};

function esc(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function truncate(value, maxLen) {
  const s = esc(value);
  if (s.length <= maxLen) return s;
  return s.slice(0, maxLen - 1) + '…';
}

function frontmatter({ title, subtitle, author }) {
  const escYaml = (v) => String(v || '').replace(/"/g, '\\"');
  return [
    '---',
    `title: "${escYaml(title)}"`,
    `subtitle: "${escYaml(subtitle)}"`,
    `author: "${escYaml(author)}"`,
    '---',
    '',
  ].join('\n');
}

function checkDetailOneLiner(check) {
  if (!check) return '';
  if (check.status === 'ok') return '';
  // Solo se resume el detalle cuando el check NO fue ok — mantiene el
  // reporte ejecutivo corto (ver nota de módulo sobre el límite de mdtopdf).
  const raw = Array.isArray(check.details) ? check.details.join('; ') : check.details;
  return truncate(raw, 90);
}

function buildDomainSection(domainEntry, selectedChecks, checksMeta) {
  const domain = domainEntry?.domain || '(dominio desconocido)';
  const dns = domainEntry?.dns_validation || null;
  const dnssecRaw = domainEntry?.dnssec?.dnssec || null;
  const checks = domainEntry?.checks || {};

  const lines = [];
  lines.push(`### ${domain}`);
  lines.push('');

  const dnsLine = dns
    ? `**DNS**: ${DNS_VALIDATION_LABELS[dns.final_status] || dns.final_status || 'N/D'}`
      + (dns.review_subtype ? ` (${esc(dns.review_subtype)})` : '')
      + (dns.discrepancy ? ' — discrepancia entre resolvers' : '')
    : '**DNS**: sin datos';
  lines.push(dnsLine);

  const dnssecLine = dnssecRaw
    ? `**DNSSEC**: ${dnssecRaw.final_status || 'N/D'}`
      + ` · riesgo: ${dnssecRaw.executive_summary?.risk_level || 'N/D'}`
      + ` · acción requerida: ${dnssecRaw.executive_summary?.action_required ? 'sí' : 'no'}`
    : (domainEntry?.dnssec?.error
      ? `**DNSSEC**: error — ${esc(domainEntry.dnssec.error)}`
      : '**DNSSEC**: sin datos');
  lines.push(dnssecLine);
  lines.push('');

  if (selectedChecks.length) {
    lines.push('| Check | Resultado | Detalle |');
    lines.push('| --- | --- | --- |');
    for (const key of selectedChecks) {
      const check = checks[key];
      const icon = check ? (STATUS_ICON[check.status] || '?') : '—';
      const label = check?.label || checkLabel(key, checksMeta);
      const detail = checkDetailOneLiner(check);
      lines.push(`| ${esc(label)} | ${icon} | ${detail} |`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

// Una tabla dominio × check con muchas columnas no cabe en una hoja, ni
// siquiera en horizontal, si se intenta meter todo en una sola tabla — la
// solución no es solo rotar la página, es también LIMITAR cuántas columnas
// entran por tabla (MAX_CHECKS_PER_TABLE) y partir en varias, agrupadas por
// categoría (mismos grupos que ve el usuario en la UI) para que cada tabla
// tenga contexto propio en vez de columnas sueltas sin agrupar.
function buildComparativeChunkTable(domains, chunk, checksMeta) {
  const header = ['Dominio', ...chunk.keys.map((k) => checkLabel(k, checksMeta))];
  const lines = [];
  lines.push(`| ${header.map(esc).join(' | ')} |`);
  lines.push(`| ${header.map(() => '---').join(' | ')} |`);
  for (const d of domains) {
    const row = [esc(d.domain)];
    for (const key of chunk.keys) {
      const check = d.checks?.[key];
      row.push(check ? (STATUS_ICON[check.status] || '?') : '—');
    }
    lines.push(`| ${row.join(' | ')} |`);
  }
  // Encabezado de nivel #### (h4 real, no texto en negrita suelto) — un
  // párrafo en negrita no tiene "break-after: avoid" en la plantilla de
  // mdtopdf, así que si cae cerca del borde de la página puede quedar
  // separado de su tabla (título en una página, tabla en la siguiente). Un
  // heading real sí lo evita, igual que ya pasa con los ### de esta sección.
  const heading = chunk.chunkCount > 1
    ? `#### ${esc(chunk.group)} (${chunk.chunkIndex}/${chunk.chunkCount})`
    : `#### ${esc(chunk.group)}`;
  const table = lines.join('\n') + '\n';
  return `${heading}\n\n${table}\n`;
}

function buildComparativeTable(domains, selectedChecks, checksMeta) {
  if (!domains.length || !selectedChecks.length) {
    return '_Sin datos suficientes para la tabla comparativa._\n';
  }
  const chunks = groupAndChunkChecks(selectedChecks, checksMeta);
  const allTables = chunks.map((chunk) => buildComparativeChunkTable(domains, chunk, checksMeta)).join('\n');
  // Un solo fenced div de pandoc (extensión fenced_divs, activa por defecto
  // en su lector "markdown") envolviendo TODAS las tablas partidas, no una
  // por tabla — así la plantilla de mdtopdf las acomoda juntas en la misma
  // página horizontal cuando caben, en vez de forzar un salto de página en
  // cada tabla (que pasaba cuando el encabezado "**Grupo**" quedaba afuera
  // del div: alternar portrait/landscape en cada bloque fuerza un @page
  // nuevo cada vez, aunque la tabla siguiente también fuera landscape).
  return `::: landscape\n${allTables}\n:::\n`;
}

function buildGlossarySection(glossaryEntries) {
  if (!Array.isArray(glossaryEntries) || !glossaryEntries.length) {
    return '_Sin checks seleccionados para documentar._\n';
  }
  const lines = [];
  lines.push('| Indicador | Qué mide |');
  lines.push('| --- | --- |');
  for (const entry of glossaryEntries) {
    lines.push(`| ${esc(entry.label)} | ${esc(entry.description)} |`);
  }
  return lines.join('\n') + '\n';
}

function buildDnsValidationSummary(summary) {
  const s = summary || {};
  const total = (s.VALID || 0) + (s.NXDOMAIN || 0) + (s.REVIEW || 0);
  return [
    '| Estado | Dominios |',
    '| --- | --- |',
    `| VALID | ${s.VALID || 0} |`,
    `| NXDOMAIN | ${s.NXDOMAIN || 0} |`,
    `| REVIEW | ${s.REVIEW || 0} |`,
    `| **Total** | **${total}** |`,
  ].join('\n') + '\n';
}

function buildDnssecAggregateSummary(agg) {
  if (!agg) return '_Sin datos DNSSEC agregados._\n';
  const semLabel = SEMAPHORE_LABELS[agg.semaphore] || agg.semaphore || 'N/D';
  const lines = [];
  lines.push(`**Etiqueta**: ${esc(agg.country || 'Lote analizado')}`);
  lines.push('');
  lines.push(`- Semáforo: ${semLabel}`);
  lines.push(`- Adopción DNSSEC: ${agg.adoptionRate !== null && agg.adoptionRate !== undefined ? agg.adoptionRate + '%' : 'N/D'}`);
  lines.push(`- Dominios analizados: ${agg.total || 0}`);
  lines.push(`- Con barrera estructural: ${agg.structural || 0}`);
  lines.push(`- Accionables: ${agg.actionable || 0}`);
  if (Array.isArray(agg.warnings) && agg.warnings.length) {
    lines.push('');
    lines.push('Advertencias:');
    for (const w of agg.warnings) lines.push(`- ${esc(w)}`);
  }
  return lines.join('\n') + '\n';
}

function buildChecksSummaryTable(checksSummary) {
  const entries = Object.entries(checksSummary || {});
  if (!entries.length) return '_Sin checks seleccionados._\n';
  const lines = [];
  lines.push('| Check | Sí | No |');
  lines.push('| --- | --- | --- |');
  for (const [, entry] of entries) {
    lines.push(`| ${esc(entry.label)} | ${entry.positive || 0} | ${entry.negative || 0} |`);
  }
  return lines.join('\n') + '\n';
}

function buildComparativeMarkdown(payload) {
  const meta = payload?.meta || {};
  const domains = Array.isArray(payload?.domains) ? payload.domains : [];
  const comparative = payload?.comparative || {};
  const selectedChecks = Array.isArray(meta.selected_checks) ? meta.selected_checks : [];
  const checksMeta = buildChecksMeta(meta.selected_checks_glossary);

  const generatedAt = meta.generated_at || new Date().toISOString();
  const title = 'Análisis comparativo de dominios — Mediciones ISOC LAC';
  const subtitle = `${meta.domain_count ?? domains.length} dominios · generado ${generatedAt}`;
  const author = 'Mediciones ISOC LAC — Internet Society';

  const parts = [];
  parts.push(frontmatter({ title, subtitle, author }));
  parts.push(`# ${title}`);
  parts.push('');
  parts.push(`Generado: ${generatedAt}  `);
  parts.push(`Dominios analizados: ${meta.domain_count ?? domains.length}  `);
  parts.push(`Checks seleccionados: ${selectedChecks.length}`);
  parts.push('');

  // Todo lo necesario para leer el resto del documento va primero — antes
  // se ponía la leyenda de símbolos pegada a la tabla comparativa y quedaba
  // perdida varias páginas después, sin que nadie la viera.
  parts.push('## Cómo leer este reporte');
  parts.push('');
  parts.push('### Símbolos de resultado');
  parts.push('');
  parts.push(buildStatusLegendTable());
  parts.push('### Glosario de indicadores');
  parts.push('');
  parts.push('Qué mide cada indicador incluido en este reporte.');
  parts.push('');
  parts.push(buildGlossarySection(meta.selected_checks_glossary));

  parts.push('## Resumen comparativo');
  parts.push('');
  parts.push('### Validación DNS');
  parts.push('');
  parts.push(buildDnsValidationSummary(comparative.dns_validation_summary));
  parts.push('### DNSSEC agregado');
  parts.push('');
  parts.push(buildDnssecAggregateSummary(comparative.dnssec_aggregate));
  parts.push('### Resumen acumulado por check');
  parts.push('');
  parts.push(buildChecksSummaryTable(comparative.checks_summary));

  parts.push('### Tabla comparativa dominio × check');
  parts.push('');
  parts.push('_Agrupada por categoría (símbolos explicados en "Cómo leer este reporte", al inicio). Si una categoría tiene muchos indicadores, se parte en varias tablas para que no se trunquen columnas._');
  parts.push('');
  parts.push(buildComparativeTable(domains, selectedChecks, checksMeta));

  parts.push('## Detalle por dominio');
  parts.push('');
  parts.push('_Columna "Resultado": mismos símbolos de la sección "Cómo leer este reporte"._');
  parts.push('');
  if (!domains.length) {
    parts.push('_No se analizó ningún dominio en este lote._');
    parts.push('');
  } else {
    for (const domainEntry of domains) {
      parts.push(buildDomainSection(domainEntry, selectedChecks, checksMeta));
    }
  }

  return parts.join('\n');
}

function buildJsonExport(payload) {
  return {
    ...payload,
    export_meta: {
      exported_at: new Date().toISOString(),
      generator: 'Mediciones ISOC LAC — Análisis comparativo',
    },
  };
}

module.exports = { buildComparativeMarkdown, buildJsonExport };
