'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Exportadores del reporte descargable de Mediciones (index.html,
 * medicionesBatchStart — flujo único desde 2026-09-11, antes había un
 * sub-tab "Un dominio" separado sin reporte propio; antes de eso este
 * módulo se llamaba "Análisis comparativo" — renombrado porque el reporte
 * no compara nada entre dominios, solo expone la medición cruda de cada
 * uno, sea 1 o varios). El navegador ya corrió la medición (checks +
 * DNSSEC + validación DNS) y ensambló el payload completo; este módulo solo
 * formatea la salida:
 *
 *  - buildComparativeMarkdown: Markdown con frontmatter YAML para el
 *    servicio externo mdtopdf (server1:8600). Reporte EJECUTIVO
 *    CONDENSADO — por diseño, NO vuelca arrays largos de `details` crudos
 *    (eso satura el límite de 30s de mdtopdf con lotes de 20-25 dominios
 *    y ~40 checks). El detalle completo vive solo en el JSON.
 *  - buildJsonExport: el payload completo (detalle sin condensar) más
 *    metadata de exportación.
 *
 * SIN análisis del dataset (2026-09-09, a pedido explícito): el reporte no
 * calcula ni compara nada sobre el lote analizado — ni agregados, ni
 * porcentajes, ni semáforos, ni siquiera en forma neutral. Solo hay dos
 * tipos de contenido: (a) "Cómo leer este reporte" — genérico, idéntico en
 * cualquier corrida (símbolos de resultado, glosario de indicadores,
 * limitaciones del sistema) — y (b) mediciones crudas por dominio (la
 * tabla del lote y, si se pide explícitamente, el detalle por dominio).
 * Antes existían aquí "Hallazgos por categoría" y "Resumen comparativo"
 * (Validación DNS, DNSSEC agregado, Resumen acumulado por check) — se
 * eliminaron por completo. Ver docs/arquitectura.md para el detalle de qué
 * se quitó y del historial de renombres (ese historial es solo para uso
 * interno — nunca aparece en el reporte ni en la guía).
 *
 * Alcance personalizable (2026-09-09, a pedido explícito): por defecto el
 * reporte trae únicamente la tabla del lote (dominio × indicador). El
 * detalle completo por dominio (`## Detalle por dominio`) es opcional —
 * solo se incluye si `payload.meta.include_domain_detail === true` (checkbox
 * en la UI, desmarcado por defecto). Esto NO aplica al reporte de "Un
 * dominio" (análisis individual), que siempre trae el detalle completo.
 *
 * Referencia de estilo: aggregate/exporters/exporters.js (HTML) y
 * logic/exporters/datasetResultsPackage.exporter.js (metadata/hashes) —
 * adaptado, no copiado: aquí no hay DNS crudo que hashear ni HTML que
 * generar, solo Markdown.
 */

// FASE 2 (2026-09-12): migrado de 4 a 6 estados explícitos — ver el mismo
// cambio y su justificación en index.html (STATUS_SYMBOL). Un fallo interno
// de MEDICIONES (MEASUREMENT_ERROR) no debe leerse como si fuera un hallazgo
// real sobre el dominio (FAIL), ni una prueba que no aplica o no es
// concluyente debe aparecer con el mismo símbolo que un "no cumple" real.
const STATUS_ICON = {
  PASS: '✓',
  FAIL: '✗',
  NOT_APPLICABLE: '⊘',
  INCONCLUSIVE: '?',
  MEASUREMENT_ERROR: '⚠',
  INFO: 'ℹ',
};

// Mismos 6 estados que devuelve cada check en el navegador (ver STATUS_SYMBOL
// en index.html) — la leyenda se repite en el PDF porque acá no hay tooltip
// posible como en la UI. Se renderiza como tabla (no como línea suelta antes
// de la tabla comparativa) y se ubica al inicio del documento — una línea
// itálica pegada a una tabla de 2+ páginas después se perdía de vista.
const STATUS_LEGEND_ROWS = [
  ['✓', 'PASS — se midió y cumple'],
  ['✗', 'FAIL — se midió y no cumple'],
  ['⊘', 'NO APLICA — esta prueba no aplica a este caso (ej. dato redactado por política de privacidad)'],
  ['?', 'NO CONCLUYENTE — el comportamiento del sitio impide concluir con certeza (ej. WAF, rate limit, respuesta ambigua como HTTP 401/403/405/429)'],
  ['⚠', 'ERROR DE MEDICIÓN — la herramienta no pudo ejecutar la prueba (timeout, servicio externo caído, etc.). No es un fallo del dominio.'],
  ['ℹ', 'INFORMATIVO — dato disponible, sin evaluación de "bien/mal" (ej. IPv6: tenerlo o no tenerlo no es en sí un fallo)'],
  ['—', 'Sin datos — este check no se ejecutó para este dominio'],
];

function buildStatusLegendTable() {
  const lines = ['| Símbolo | Significado |', '| --- | --- |'];
  for (const [icon, meaning] of STATUS_LEGEND_ROWS) {
    lines.push(`| **${icon}** | ${esc(meaning)} |`);
  }
  return lines.join('\n') + '\n';
}

// NOTA (2026-09-09): existió aquí un cómputo de "Hallazgos por categoría"
// (% de resultados "OK" por categoría núcleo, sin semáforo). Se eliminó a
// pedido explícito: el reporte no debe calcular NADA sobre el dataset
// analizado, ni siquiera en forma neutral/sin juicio de valor — solo puede
// haber contenido genérico e idéntico en cualquier corrida ("Cómo leer
// este reporte": símbolos, glosario, limitaciones) y las mediciones
// crudas por dominio (tabla comparativa + detalle por dominio). Por el
// mismo pedido se quitó también todo el bloque "Resumen comparativo"
// (Validación DNS, DNSSEC agregado, Resumen acumulado por check) — eran
// agregaciones/comparaciones sobre el lote, no mediciones crudas. Ver
// docs/arquitectura.md para el detalle.

// Mismo orden de categorías que `groupDefinitions` en index.html — solo para
// ordenar la tabla comparativa de forma legible (no es lógica de negocio).
// Un check con un `group` no reconocido cae en "Otros", al final.
const CHECK_GROUP_ORDER = [
  'Seguridad y confianza (DNS/TLS)',
  'Anti-suplantación de correo',
  'Cabeceras de seguridad web',
  'Transparencia y conectividad moderna',
  'Diagnóstico técnico',
  'Contenido y experiencia',
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

function esc(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function truncate(value, maxLen) {
  const s = esc(value);
  if (s.length <= maxLen) return s;
  return s.slice(0, maxLen - 1) + '…';
}

// Campos fijos de la carátula (mismo texto/imagen para todo reporte de
// Mediciones ISOC LAC generado por este exportador — no dependen del
// dataset analizado, igual criterio que SYSTEM_LIMITATIONS más abajo).
const REPORT_CONTACT = 'https://mediciones.isoc.org.ec  ·  info@isoc.org.ec';
// Sin "eyebrow": el logo (mediciones_grupo_trabajo.jpeg) ya trae el texto
// "Grupo de Trabajo de Mediciones de Internet" incrustado en la imagen —
// repetirlo como texto aparte duplicaría la misma frase dos veces en la
// carátula.
// Texto reutilizado de docs/GUIA_MEDICIONES_ISOC_LAC.md § "1. Introducción"
// (condensado para caber en la carátula) — no se redactó contenido nuevo.
const REPORT_DESCRIPTION = 'MEDICIONES ISOC LAC es una iniciativa de Internet Society en América Latina y el Caribe que genera información técnica abierta sobre el estado de la infraestructura de Internet en la región.';
const REPORT_COORDINATED_BY = 'Coordinado por: ISOC Argentina, ISOC Ecuador, ISOC Panamá, ISOC Paraguay, ISOC Uruguay';

// Logo institucional embebido como data URI: mdtopdf corre en un
// contenedor aparte (server1:8600) sin acceso al filesystem de MEDICIONES
// ni a su red — un <img src="/public/..."> no resolvería. Se lee una sola
// vez al cargar el módulo, no en cada reporte. Si el archivo no está
// disponible por algún motivo, se degrada a "sin logo" (el template lo
// omite con $if(logo)$) en vez de romper la generación del reporte.
const LOGO_PATH = path.join(__dirname, '..', '..', 'public', 'assets', 'mediciones_grupo_trabajo.jpeg');
let REPORT_LOGO_DATA_URI = '';
try {
  REPORT_LOGO_DATA_URI = `data:image/jpeg;base64,${fs.readFileSync(LOGO_PATH).toString('base64')}`;
} catch (e) {
  REPORT_LOGO_DATA_URI = '';
}

function frontmatter({ title, subtitle, author }) {
  const escYaml = (v) => String(v || '').replace(/"/g, '\\"');
  return [
    '---',
    `title: "${escYaml(title)}"`,
    `subtitle: "${escYaml(subtitle)}"`,
    `author: "${escYaml(author)}"`,
    `contact: "${escYaml(REPORT_CONTACT)}"`,
    `description: "${escYaml(REPORT_DESCRIPTION)}"`,
    `coordinated_by: "${escYaml(REPORT_COORDINATED_BY)}"`,
    ...(REPORT_LOGO_DATA_URI ? [`logo: "${REPORT_LOGO_DATA_URI}"`] : []),
    '---',
    '',
  ].join('\n');
}

function checkDetailOneLiner(check) {
  if (!check) return '';
  if (check.status === 'PASS') return '';
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

  // Solo el estado técnico crudo (final_status) — "riesgo"/"acción requerida"
  // (executive_summary.risk_level/action_required) son una categorización de
  // severidad y una recomendación, no una medición: el mismo criterio de "sin
  // análisis del dataset" que rige el resto de este módulo (ver nota de
  // cabecera) aplica también acá, aunque el mapeo sea fijo por estado.
  const dnssecLine = dnssecRaw
    ? `**DNSSEC**: ${dnssecRaw.final_status || 'N/D'}`
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

// Texto fijo — idéntico en cualquier reporte, no depende del dataset
// analizado (a pedido explícito). Mismo contenido que la sección
// "Limitaciones" de la guía del sistema (docs/GUIA_MEDICIONES_ISOC_LAC.md).
const SYSTEM_LIMITATIONS = [
  'No reemplaza auditorías técnicas especializadas.',
  'Depende de disponibilidad de servicios externos.',
  'Puede haber falsos positivos o negativos.',
  'No mide seguridad interna del servidor.',
];

function buildLimitationsSection() {
  return SYSTEM_LIMITATIONS.map((item) => `- ${item}`).join('\n') + '\n';
}

function buildComparativeMarkdown(payload) {
  const meta = payload?.meta || {};
  const domains = Array.isArray(payload?.domains) ? payload.domains : [];
  const selectedChecks = Array.isArray(meta.selected_checks) ? meta.selected_checks : [];
  const checksMeta = buildChecksMeta(meta.selected_checks_glossary);

  const generatedAt = meta.generated_at || new Date().toISOString();
  const includeDomainDetail = meta.include_domain_detail === true;
  const title = 'Reporte de dominios — Mediciones ISOC LAC';
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

  // "Cómo leer este reporte" — a pedido explícito, es la ÚNICA narrativa
  // del documento, y es genérica e idéntica en cualquier corrida (no
  // depende del dataset analizado): qué mide cada indicador, qué significa
  // cada símbolo de resultado, y las limitaciones del sistema. El resto del
  // documento son mediciones crudas (tabla comparativa + detalle por
  // dominio) — nada agregado ni comparado sobre el lote. Va todo al
  // principio — antes se ponía la leyenda de símbolos pegada a la tabla
  // comparativa y quedaba perdida varias páginas después, sin que nadie la
  // viera.
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
  parts.push('### Limitaciones del sistema');
  parts.push('');
  parts.push(buildLimitationsSection());

  parts.push('## Tabla de resultados — dominio × indicador');
  parts.push('');
  parts.push('_Agrupada por categoría (símbolos explicados en "Cómo leer este reporte", al inicio). Si una categoría tiene muchos indicadores, se parte en varias tablas para que no se trunquen columnas._');
  parts.push('');
  parts.push(buildComparativeTable(domains, selectedChecks, checksMeta));

  // Sección opcional (checkbox en la UI, desmarcado por defecto — a pedido
  // explícito: el reporte no trae por defecto el detalle completo de cada
  // dominio, solo la tabla comparativa), sea el análisis de 1 dominio o de
  // varios.
  if (includeDomainDetail) {
    parts.push('## Detalle por dominio');
    parts.push('');
    parts.push('_Columna "Resultado": mismos símbolos de la sección "Cómo leer este reporte"._');
    parts.push('');
    if (!domains.length) {
      parts.push('_No se analizó ningún dominio._');
      parts.push('');
    } else {
      for (const domainEntry of domains) {
        parts.push(buildDomainSection(domainEntry, selectedChecks, checksMeta));
      }
    }
  }

  return parts.join('\n');
}

function buildJsonExport(payload) {
  return {
    ...payload,
    export_meta: {
      exported_at: new Date().toISOString(),
      generator: 'Mediciones ISOC LAC',
    },
  };
}

module.exports = { buildComparativeMarkdown, buildJsonExport };
