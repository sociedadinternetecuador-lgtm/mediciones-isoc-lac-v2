'use strict';

/**
 * Pruebas de logic/exporters/medicionesBatchReport.exporter.js —
 * buildComparativeMarkdown / buildJsonExport, sin red.
 *
 * Ejecutar: node test/medicionesBatchReport.exporter.test.js
 */

const assert = require('assert');
const { buildComparativeMarkdown, buildJsonExport } = require('../logic/exporters/medicionesBatchReport.exporter');

function assertFrontmatter(markdown) {
  assert.ok(markdown.startsWith('---\n'), 'debe empezar con frontmatter YAML');
  const closeIdx = markdown.indexOf('\n---\n', 4);
  assert.ok(closeIdx > 0, 'el frontmatter debe cerrar con ---');
  const block = markdown.slice(4, closeIdx);
  assert.ok(/title:\s*"/.test(block), 'frontmatter debe incluir title');
  assert.ok(/subtitle:\s*"/.test(block), 'frontmatter debe incluir subtitle');
  assert.ok(/author:\s*"/.test(block), 'frontmatter debe incluir author');
  assert.ok(/contact:\s*".*mediciones\.isoc\.org\.ec.*info@isoc\.org\.ec/.test(block), 'la carátula debe incluir sitio web y correo de contacto');
  // Sin "eyebrow": el logo ya trae ese texto incrustado en la imagen (ver
  // exporter) — no debe duplicarse como campo de texto aparte.
  assert.ok(!/eyebrow:/.test(block), 'no debe incluir "eyebrow" — el logo ya trae ese texto incrustado en la imagen');
  assert.ok(/description:\s*".*Internet Society/.test(block), 'la carátula debe incluir la descripción institucional');
  assert.ok(/coordinated_by:\s*"Coordinado por:.*ISOC/.test(block), 'la carátula debe incluir los capítulos ISOC coordinadores');
  assert.ok(/logo:\s*"data:image\/jpeg;base64,/.test(block), 'la carátula debe incluir el logo embebido como data URI');
}

// El frontmatter YAML (título/subtítulo/autor/contacto/carátula, incluido
// el logo institucional embebido como base64) es metadata fija de la
// plantilla, no narrativa del reporte — y una cadena base64 es texto
// pseudoaleatorio que puede coincidir por azar con cualquier palabra corta
// (ej. "rojo" dentro de la codificación del logo). El escaneo de lenguaje
// evaluativo debe correr solo sobre el cuerpo del documento.
function stripFrontmatter(markdown) {
  const closeIdx = markdown.indexOf('\n---\n', 4);
  return closeIdx > 0 ? markdown.slice(closeIdx + 5) : markdown;
}

// A pedido explícito: el reporte NUNCA calcula ni compara nada sobre el
// dataset analizado — ni agregados, ni porcentajes, ni semáforos. Se
// verifica en cada caso que ninguna de las secciones/frases eliminadas
// reaparezca, sin importar qué traiga el payload.
function assertNoDatasetAnalysis(markdown) {
  assert.ok(!markdown.includes('## Hallazgos por categoría'), 'no debe existir la sección "Hallazgos por categoría" (se eliminó)');
  assert.ok(!markdown.includes('## Resumen comparativo'), 'no debe existir la sección "Resumen comparativo" (se eliminó)');
  assert.ok(!markdown.includes('Validación DNS'), 'no debe reportar un resumen de Validación DNS del lote');
  assert.ok(!markdown.includes('DNSSEC agregado'), 'no debe reportar un DNSSEC agregado del lote');
  assert.ok(!markdown.includes('Resumen acumulado por check'), 'no debe reportar conteos Sí/No por check del lote');
  const body = stripFrontmatter(markdown);
  assert.ok(
    !/verde|amarill|rojo|semáforo|adopción|brecha|débil|sólid|crític|indicativo|confiable|muestra insuficiente/i.test(body),
    'no debe usar lenguaje evaluativo/estadístico sobre el dataset en ninguna parte del cuerpo del reporte'
  );
  // La línea de DNSSEC por dominio debía reportar solo el estado técnico
  // crudo (final_status) — "riesgo"/"acción requerida" (executive_summary)
  // son una categorización de severidad y una recomendación, no una
  // medición, aunque el mapeo sea fijo por estado. Se quitaron (ver
  // AUDITORIA_MEDICIONES_TRACEROUTE.md § principios del reporte / pedido
  // explícito de "sin análisis ni narrativa").
  assert.ok(!/riesgo:/i.test(body), 'no debe reportar "riesgo" (executive_summary.risk_level) en el detalle por dominio');
  assert.ok(!/acción requerida/i.test(body), 'no debe reportar "acción requerida" (executive_summary.action_required) en el detalle por dominio');
}

// La sección "Cómo leer este reporte" es la ÚNICA narrativa permitida:
// genérica, idéntica en cualquier corrida — no depende del payload.
function assertGenericInstructions(markdown) {
  assert.ok(markdown.includes('## Cómo leer este reporte'));
  assert.ok(markdown.includes('### Símbolos de resultado'));
  assert.ok(markdown.includes('### Glosario de indicadores'));
  assert.ok(markdown.includes('### Limitaciones del sistema'));
  assert.ok(markdown.includes('No reemplaza auditorías técnicas especializadas.'));
  assert.ok(markdown.includes('Depende de disponibilidad de servicios externos.'));
  assert.ok(markdown.includes('Puede haber falsos positivos o negativos.'));
  assert.ok(markdown.includes('No mide seguridad interna del servidor.'));
}

function run() {
  // ── Caso 1: payload vacío de dominios ──────────────────────────────
  const emptyPayload = {
    meta: {
      generated_at: '2026-09-08T00:00:00.000Z',
      selected_checks: ['mx', 'dmarc'],
      domain_count: 0,
      source: { mode: 'paste', filename: null },
    },
    domains: [],
  };
  const emptyMd = buildComparativeMarkdown(emptyPayload);
  assert.strictEqual(typeof emptyMd, 'string');
  assertFrontmatter(emptyMd);
  assertGenericInstructions(emptyMd);
  assertNoDatasetAnalysis(emptyMd);
  // Alcance por defecto (checkbox desmarcado, meta.include_domain_detail
  // ausente): el reporte trae solo la tabla del lote, sin la sección de
  // detalle por dominio.
  assert.ok(!emptyMd.includes('## Detalle por dominio'), 'sin include_domain_detail, la sección de detalle por dominio no debe existir');

  // ── Caso 2: un dominio sin DNSSEC (null/error) — mediciones crudas ──
  const noDnssecPayload = {
    meta: {
      generated_at: '2026-09-08T00:00:00.000Z',
      selected_checks: ['mx', 'dmarc', 'spf'],
      domain_count: 1,
      source: { mode: 'upload', filename: 'dominios.csv' },
      include_domain_detail: true, // caso dedicado a probar el formato de la sección de detalle
    },
    domains: [
      {
        domain: 'sin-dnssec.example',
        dns_validation: { final_status: 'VALID', review_subtype: null, discrepancy: false },
        dnssec: { error: 'Timeout' },
        checks: {
          mx: { label: 'MX', status: 'PASS', details: 'mail.example' },
          dmarc: { label: 'DMARC', status: 'FAIL', details: 'No se encontró registro DMARC' },
          spf: { label: 'SPF', status: 'MEASUREMENT_ERROR', details: 'Timeout consultando SPF' },
        },
      },
      {
        domain: 'null-dnssec.example',
        dns_validation: null,
        dnssec: null,
        checks: {},
      },
    ],
  };
  const noDnssecMd = buildComparativeMarkdown(noDnssecPayload);
  assertFrontmatter(noDnssecMd);
  assertGenericInstructions(noDnssecMd);
  assertNoDatasetAnalysis(noDnssecMd);
  assert.ok(noDnssecMd.includes('sin-dnssec.example'));
  assert.ok(noDnssecMd.includes('null-dnssec.example'));
  assert.ok(!noDnssecMd.includes('undefined'), 'no debe filtrar "undefined" al texto por campos faltantes');
  assert.ok(noDnssecMd.includes('::: landscape'), 'la tabla del lote (por categoría) siempre se imprime en landscape');
  assert.ok(noDnssecMd.includes('INFORMATIVO — dato disponible'), 'debe incluir la leyenda de símbolos (✓/✗/⊘/?/⚠/ℹ/—)');
  const legendIdx = noDnssecMd.indexOf('Símbolos de resultado');
  const batchTableIdx = noDnssecMd.indexOf('## Tabla de resultados — dominio × indicador');
  assert.ok(legendIdx !== -1 && legendIdx < batchTableIdx, 'la leyenda de símbolos debe ir al inicio del documento, no pegada a la tabla');
  assert.ok(noDnssecMd.includes('## Detalle por dominio'), 'con include_domain_detail:true debe incluir la sección de detalle por dominio');
  assert.ok(batchTableIdx < noDnssecMd.indexOf('## Detalle por dominio'), 'la tabla del lote va antes del detalle por dominio');

  // ── Caso 3: un dominio con muchos checks fallidos ──────────────────
  const manyFailChecks = {};
  const selectedManyChecks = [];
  for (let i = 0; i < 40; i++) {
    const key = `check${i}`;
    selectedManyChecks.push(key);
    manyFailChecks[key] = { label: `Check ${i}`, status: i % 2 === 0 ? 'fail' : 'error', details: `Detalle largo repetido muchas veces para el check ${i} `.repeat(5) };
  }
  const manyFailPayload = {
    meta: {
      generated_at: '2026-09-08T00:00:00.000Z',
      selected_checks: selectedManyChecks,
      domain_count: 1,
      source: { mode: 'paste', filename: null },
      include_domain_detail: true, // necesario: este caso prueba el truncado de detalle, que vive en esa sección
    },
    domains: [
      {
        domain: 'muchos-fallos.example',
        dns_validation: { final_status: 'NXDOMAIN', review_subtype: null, discrepancy: false },
        dnssec: { domain: 'muchos-fallos.example', dnssec: { final_status: 'misconfigured', executive_summary: { risk_level: 'alto', action_required: true } } },
        checks: manyFailChecks,
      },
    ],
  };
  const manyFailMd = buildComparativeMarkdown(manyFailPayload);
  assertFrontmatter(manyFailMd);
  assertNoDatasetAnalysis(manyFailMd);
  assert.ok(manyFailMd.includes('muchos-fallos.example'));
  assert.ok(manyFailMd.includes('misconfigured'));
  // El detalle crudo largo no debe volcarse tal cual — cada línea de detalle
  // debe quedar acotada (truncada), no pasar de una fracción del original.
  const longDetailRepeated = 'Detalle largo repetido muchas veces para el check 0 '.repeat(5);
  assert.ok(!manyFailMd.includes(longDetailRepeated), 'el detalle crudo largo no debe volcarse completo (satura mdtopdf)');
  // Con 40 checks seleccionados, una sola tabla de 40 columnas se sale de la
  // página aunque esté en landscape (encabezados largos, o incluso claves
  // crudas sin espacios que no se pueden partir en varias líneas) — debe
  // partirse en varias tablas de a lo sumo MAX_CHECKS_PER_TABLE (6) columnas,
  // todas dentro de UN solo div landscape (no uno por tabla — envolver cada
  // tabla en su propio div fuerza un salto de página en cada una, aunque
  // todas sean landscape, porque el encabezado "**Grupo**" entre tablas
  // queda afuera del div y alterna portrait/landscape en cada bloque).
  const landscapeOpen = manyFailMd.indexOf('::: landscape');
  assert.ok(landscapeOpen !== -1, 'el div debe usar la clase "landscape"');
  const tableIdx = manyFailMd.indexOf('| Dominio |');
  assert.ok(tableIdx > landscapeOpen, 'la tabla comparativa debe quedar dentro del div landscape');
  const landscapeCount = (manyFailMd.match(/::: landscape/g) || []).length;
  assert.strictEqual(landscapeCount, 1, 'debe haber un solo div landscape envolviendo todas las tablas partidas, no uno por tabla');
  const domainHeaderCount = (manyFailMd.match(/\| Dominio \|/g) || []).length;
  assert.ok(domainHeaderCount >= 7, `40 checks / 6 por tabla deben producir al menos 7 tablas separadas (hubo ${domainHeaderCount})`);

  // ── Caso 4: glosario de términos de los checks seleccionados ───────
  const glossaryPayload = {
    meta: {
      generated_at: '2026-09-09T00:00:00.000Z',
      selected_checks: ['mx', 'dmarc'],
      selected_checks_glossary: [
        { key: 'mx', label: 'MX', description: 'Comprueba si el dominio tiene registros MX para recibir correo.' },
        { key: 'dmarc', label: 'DMARC', description: 'Comprueba si existe política DMARC en _dmarc del dominio.' },
      ],
      domain_count: 0,
      source: { mode: 'paste', filename: null },
    },
    domains: [],
  };
  const glossaryMd = buildComparativeMarkdown(glossaryPayload);
  assert.ok(glossaryMd.includes('### Glosario de indicadores'), 'debe incluir siempre la sección de glosario');
  assert.ok(glossaryMd.includes('Comprueba si el dominio tiene registros MX para recibir correo.'), 'debe listar la descripción de cada check seleccionado');
  assert.ok(glossaryMd.includes('Comprueba si existe política DMARC en _dmarc del dominio.'));

  const noGlossaryPayload = { ...emptyPayload, meta: { ...emptyPayload.meta, selected_checks_glossary: undefined } };
  const noGlossaryMd = buildComparativeMarkdown(noGlossaryPayload);
  assert.ok(noGlossaryMd.includes('### Glosario de indicadores'), 'la sección debe existir aunque el payload no traiga glosario (compatibilidad)');

  // ── Caso 5: tabla comparativa agrupada por categoría + etiquetas legibles ──
  // Antes, la tabla comparativa usaba la CLAVE cruda (ej. "serverlocation",
  // una sola palabra sin espacios) como encabezado — eso además de ilegible
  // impedía partir la línea, forzando columnas anchas que se salían de la
  // página. Ahora debe usar la etiqueta legible (con espacios) y agrupar por
  // categoría, partiendo en varias tablas cuando una categoría excede
  // MAX_CHECKS_PER_TABLE (6).
  const ipRedChecks = [
    { key: 'ipinfo', label: 'More IP Info', group: 'IP y Red' },
    { key: 'serverlocation', label: 'Server Location', group: 'IP y Red' },
  ];
  const tlsChecks = ['https', 'redirect', 'hsts', 'csp', 'xfo', 'xcto', 'referrer', 'permissions'].map((key, i) => ({
    key, label: `TLS Check ${i}`, group: 'Seguridad Web y TLS',
  }));
  const groupedSelectedChecks = [...ipRedChecks, ...tlsChecks].map((c) => c.key);
  const groupedChecksResult = {};
  for (const c of [...ipRedChecks, ...tlsChecks]) {
    groupedChecksResult[c.key] = { label: c.label, status: 'PASS', details: '' };
  }
  const groupedPayload = {
    meta: {
      generated_at: '2026-09-09T00:00:00.000Z',
      selected_checks: groupedSelectedChecks,
      selected_checks_glossary: [...ipRedChecks, ...tlsChecks].map((c) => ({ ...c, description: 'desc' })),
      domain_count: 1,
      source: { mode: 'paste', filename: null },
    },
    domains: [{
      domain: 'agrupado.example',
      dns_validation: { final_status: 'VALID', review_subtype: null, discrepancy: false },
      dnssec: null,
      checks: groupedChecksResult,
    }],
  };
  const groupedMd = buildComparativeMarkdown(groupedPayload);
  assert.ok(groupedMd.includes('Server Location'), 'el encabezado debe usar la etiqueta legible, no la clave cruda "serverlocation"');
  assert.ok(!groupedMd.includes('| serverlocation |') && !groupedMd.includes('serverlocation |'), 'la clave cruda no debe aparecer como encabezado de columna');
  assert.ok(groupedMd.includes('#### IP y Red'), 'debe agrupar por categoría con un encabezado real (h4), no texto en negrita suelto');
  assert.ok(!groupedMd.includes('**IP y Red**'), 'el encabezado de grupo no debe ser un párrafo en negrita (no tiene break-after:avoid, se puede separar de su tabla)');
  // 8 checks de "Seguridad Web y TLS" > MAX_CHECKS_PER_TABLE (6) → 2 tablas
  assert.ok(groupedMd.includes('#### Seguridad Web y TLS (1/2)'), 'un grupo con más de 6 checks debe partirse, indicando (1/2)');
  assert.ok(groupedMd.includes('#### Seguridad Web y TLS (2/2)'), 'y la segunda tanda (2/2)');
  // IP y Red (2 checks) no se parte, no debe llevar sufijo "(1/1)"
  assert.ok(!groupedMd.includes('#### IP y Red (1/1)'), 'un grupo que cabe en una sola tabla no debe llevar sufijo de tanda');

  // ── Caso 6: sin ningún análisis del dataset, aunque el payload TRAIGA
  // agregados a la vieja usanza (compatibilidad hacia atrás con un payload
  // de una versión anterior del cliente) — el exportador ya no los lee ni
  // los reproduce, los ignora por completo.
  const legacyPayload = {
    meta: {
      generated_at: '2026-09-09T00:00:00.000Z',
      selected_checks: ['https', 'hsts', 'spf', 'dmarc'],
      selected_checks_glossary: [
        { key: 'https', label: 'HTTPS', description: 'd', group: 'Seguridad y confianza (DNS/TLS)' },
      ],
      domain_count: 10,
      source: { mode: 'paste', filename: null },
    },
    domains: [],
    // Un cliente viejo podría seguir mandando esto — no debe aparecer.
    comparative: {
      checks_summary: { https: { label: 'HTTPS', positive: 9, negative: 1 } },
      dns_validation_summary: { VALID: 10, NXDOMAIN: 0, REVIEW: 0 },
      dnssec_aggregate: { country: 'Lote analizado', semaphore: 'green', adoptionRate: 85, total: 10, structural: 0, actionable: 1, warnings: [] },
      category_findings: {
        total: 10,
        categories: [{ key: 'dns_tls', title: 'Seguridad y confianza (DNS/TLS)', rate: 85, positive: 17, evaluated: 20, checks: [] }],
        lowestRates: [],
      },
    },
  };
  const legacyMd = buildComparativeMarkdown(legacyPayload);
  assertGenericInstructions(legacyMd);
  assertNoDatasetAnalysis(legacyMd);

  // ── Caso 7: alcance personalizable — "## Detalle por dominio" es opcional
  // (checkbox en la UI, desmarcado por defecto). Mismo payload con y sin
  // meta.include_domain_detail, para probar ambas ramas explícitamente.
  const scopeBasePayload = {
    meta: {
      generated_at: '2026-09-09T00:00:00.000Z',
      selected_checks: ['mx'],
      selected_checks_glossary: [{ key: 'mx', label: 'MX', description: 'd', group: 'Otros' }],
      domain_count: 1,
      source: { mode: 'paste', filename: null },
    },
    domains: [{
      domain: 'alcance.example',
      dns_validation: { final_status: 'VALID', review_subtype: null, discrepancy: false },
      dnssec: null,
      checks: { mx: { label: 'MX', status: 'PASS', details: '' } },
    }],
  };
  const scopeDefaultMd = buildComparativeMarkdown(scopeBasePayload);
  assert.ok(scopeDefaultMd.includes('## Tabla de resultados — dominio × indicador'), 'la tabla de resultados siempre debe estar, sea cual sea el alcance');
  assert.ok(scopeDefaultMd.includes('alcance.example'), 'el dominio debe aparecer en la tabla del lote aunque no se pida el detalle');
  assert.ok(!scopeDefaultMd.includes('## Detalle por dominio'), 'por defecto (sin include_domain_detail) no debe existir la sección de detalle por dominio');

  const scopeWithDetailMd = buildComparativeMarkdown({ ...scopeBasePayload, meta: { ...scopeBasePayload.meta, include_domain_detail: true } });
  assert.ok(scopeWithDetailMd.includes('## Detalle por dominio'), 'con include_domain_detail:true debe existir la sección de detalle por dominio');
  assert.ok(scopeWithDetailMd.includes('### alcance.example'), 'el detalle por dominio debe incluir un encabezado por dominio');

  const scopeExplicitFalseMd = buildComparativeMarkdown({ ...scopeBasePayload, meta: { ...scopeBasePayload.meta, include_domain_detail: false } });
  assert.ok(!scopeExplicitFalseMd.includes('## Detalle por dominio'), 'con include_domain_detail:false explícito tampoco debe existir la sección');

  // ── buildJsonExport ─────────────────────────────────────────────────
  const jsonExport = buildJsonExport(emptyPayload);
  assert.strictEqual(jsonExport.meta, emptyPayload.meta);
  assert.deepStrictEqual(jsonExport.domains, []);
  assert.ok(jsonExport.export_meta, 'debe incluir metadata de exportación');
  assert.ok(jsonExport.export_meta.exported_at, 'debe incluir timestamp de exportación');

  console.log('✅ medicionesBatchReport.exporter.test.js — todos los casos OK');
}

run();
