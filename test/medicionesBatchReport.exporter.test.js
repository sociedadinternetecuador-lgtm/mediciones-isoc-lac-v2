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
    comparative: {
      checks_summary: {},
      dns_validation_summary: { VALID: 0, NXDOMAIN: 0, REVIEW: 0 },
      dnssec_aggregate: null,
    },
  };
  const emptyMd = buildComparativeMarkdown(emptyPayload);
  assert.strictEqual(typeof emptyMd, 'string');
  assertFrontmatter(emptyMd);
  assert.ok(emptyMd.includes('No se analizó ningún dominio'), 'debe indicar que el lote está vacío');

  // ── Caso 2: un dominio sin DNSSEC (null/error) ─────────────────────
  const noDnssecPayload = {
    meta: {
      generated_at: '2026-09-08T00:00:00.000Z',
      selected_checks: ['mx', 'dmarc', 'spf'],
      domain_count: 1,
      source: { mode: 'upload', filename: 'dominios.csv' },
    },
    domains: [
      {
        domain: 'sin-dnssec.example',
        dns_validation: { final_status: 'VALID', review_subtype: null, discrepancy: false },
        dnssec: { error: 'Timeout' },
        checks: {
          mx: { label: 'MX', status: 'ok', details: 'mail.example' },
          dmarc: { label: 'DMARC', status: 'fail', details: 'No se encontró registro DMARC' },
          spf: { label: 'SPF', status: 'error', details: 'Timeout consultando SPF' },
        },
      },
      {
        domain: 'null-dnssec.example',
        dns_validation: null,
        dnssec: null,
        checks: {},
      },
    ],
    comparative: {
      checks_summary: {
        mx: { label: 'MX', positive: 1, negative: 0 },
        dmarc: { label: 'DMARC', positive: 0, negative: 1 },
        spf: { label: 'SPF', positive: 0, negative: 1 },
      },
      dns_validation_summary: { VALID: 1, NXDOMAIN: 0, REVIEW: 0 },
      dnssec_aggregate: {
        country: 'Lote analizado',
        semaphore: 'insufficient',
        adoptionRate: null,
        total: 2,
        structural: 0,
        actionable: 0,
        warnings: ['Muestra insuficiente (2 dominios).'],
      },
    },
  };
  const noDnssecMd = buildComparativeMarkdown(noDnssecPayload);
  assertFrontmatter(noDnssecMd);
  assert.ok(noDnssecMd.includes('sin-dnssec.example'));
  assert.ok(noDnssecMd.includes('null-dnssec.example'));
  assert.ok(noDnssecMd.includes('Lote analizado'), 'debe usar la etiqueta genérica, no un nombre de país');
  assert.ok(!noDnssecMd.includes('undefined'), 'no debe filtrar "undefined" al texto por campos faltantes');
  assert.ok(noDnssecMd.includes('::: landscape'), 'la tabla comparativa (por categoría) siempre se imprime en landscape');
  assert.ok(noDnssecMd.includes('Informativo — dato disponible'), 'debe incluir la leyenda de símbolos (✓/✗/⚠/ℹ/—)');
  const legendIdx = noDnssecMd.indexOf('Símbolos de resultado');
  const comparativeIdx = noDnssecMd.indexOf('## Resumen comparativo');
  assert.ok(legendIdx !== -1 && legendIdx < comparativeIdx, 'la leyenda de símbolos debe ir al inicio del documento, no pegada a la tabla');

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
    },
    domains: [
      {
        domain: 'muchos-fallos.example',
        dns_validation: { final_status: 'NXDOMAIN', review_subtype: null, discrepancy: false },
        dnssec: { domain: 'muchos-fallos.example', dnssec: { final_status: 'misconfigured', executive_summary: { risk_level: 'alto', action_required: true } } },
        checks: manyFailChecks,
      },
    ],
    comparative: {
      checks_summary: Object.fromEntries(selectedManyChecks.map((k) => [k, { label: k, positive: 0, negative: 1 }])),
      dns_validation_summary: { VALID: 0, NXDOMAIN: 1, REVIEW: 0 },
      dnssec_aggregate: { country: 'Lote analizado', semaphore: 'red', adoptionRate: 0, total: 1, structural: 0, actionable: 1, warnings: [] },
    },
  };
  const manyFailMd = buildComparativeMarkdown(manyFailPayload);
  assertFrontmatter(manyFailMd);
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
    comparative: { checks_summary: {}, dns_validation_summary: { VALID: 0, NXDOMAIN: 0, REVIEW: 0 }, dnssec_aggregate: null },
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
    groupedChecksResult[c.key] = { label: c.label, status: 'ok', details: '' };
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
    comparative: {
      checks_summary: {},
      dns_validation_summary: { VALID: 1, NXDOMAIN: 0, REVIEW: 0 },
      dnssec_aggregate: null,
    },
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

  // ── buildJsonExport ─────────────────────────────────────────────────
  const jsonExport = buildJsonExport(emptyPayload);
  assert.strictEqual(jsonExport.meta, emptyPayload.meta);
  assert.deepStrictEqual(jsonExport.domains, []);
  assert.ok(jsonExport.export_meta, 'debe incluir metadata de exportación');
  assert.ok(jsonExport.export_meta.exported_at, 'debe incluir timestamp de exportación');

  console.log('✅ medicionesBatchReport.exporter.test.js — todos los casos OK');
}

run();
