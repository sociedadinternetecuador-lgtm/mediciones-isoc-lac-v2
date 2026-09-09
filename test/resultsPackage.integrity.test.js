'use strict';

/**
 * Ejercita deliberadamente la salvaguarda de integridad de
 * logic/exporters/datasetResultsPackage.exporter.js (buildResultsPackage)
 * con datos inconsistentes, SIN modificar la lógica de producción de
 * Normalización/Validación DNS — se le entregan directamente `perDomain`/
 * `finalStatusCounts`/`context.normalize.normalized` fabricados a mano.
 *
 * Casos (según lo pedido):
 *   A. normalizados != VALID+NXDOMAIN+REVIEW
 *   B. perDomain.length != normalizados
 *   C. partición inconsistente (duplicado que reemplaza a un dominio
 *      faltante) — los conteos numéricos cuadran, pero el CONJUNTO real de
 *      dominios no coincide con el universo normalizado.
 *
 * Ejecutar: node test/resultsPackage.integrity.test.js
 */

const assert = require('assert');
const { buildResultsPackage } = require('../logic/exporters/datasetResultsPackage.exporter');
const {
  DEFAULT_RESOLVERS, DEFAULT_TIMEOUT_SECONDS, DEFAULT_RETRIES, DEFAULT_WORKERS, DEFAULT_REVIEW_WAIT_SECONDS,
} = require('../logic/validators/dnsValidation.validator');

function row(domain, status) {
  return {
    domain,
    first_pass_status: status,
    final_status: status,
    status_reason: 'test',
    review_subtype: status === 'REVIEW' ? 'REVIEW_OTHER' : '',
    retry_performed: false,
    discrepancy: false,
    cloudflare_ns: status === 'NOERROR' ? 'NOERROR' : status,
    google_ns: status,
    cloudflare_soa: 'NOT_QUERIED',
    google_soa: 'NOT_QUERIED',
    cloudflare_ns_error: '', google_ns_error: '', cloudflare_soa_error: '', google_soa_error: '',
    cloudflare_ns_attempts: 1, google_ns_attempts: 1, cloudflare_soa_attempts: '', google_soa_attempts: '',
    first_pass_observations: 'test', final_observations: 'test',
  };
}

function baseDnsParams() {
  const now = new Date().toISOString();
  return {
    resolvers: DEFAULT_RESOLVERS,
    timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
    retries: DEFAULT_RETRIES,
    workers: DEFAULT_WORKERS,
    review_wait_seconds: DEFAULT_REVIEW_WAIT_SECONDS,
    checking_disabled: true,
    preflight_ok: true,
    started_at: now,
    completed_at: now,
    duration_ms: 1,
  };
}

function baseContext(normalized) {
  return {
    source: { name: 'test.txt', size: 100, sha256: 'a'.repeat(64), date: null },
    tld: 'ec',
    normalize: { stats: {}, rejected: [], normalized, normalizedSha256: 'b'.repeat(64), psl: {} },
  };
}

async function runCases() {
  let failures = 0;

  // ── Caso de control: datos CONSISTENTES — debe pasar (confirma que la
  //    salvaguarda no da falsos positivos con datos correctos). ──
  {
    const normalized = ['a.ec', 'b.ec', 'c.ec'];
    const perDomain = [row('a.ec', 'VALID'), row('b.ec', 'NXDOMAIN'), row('c.ec', 'REVIEW')];
    const pkg = await buildResultsPackage({
      jobId: 'control', context: baseContext(normalized), perDomain,
      finalStatusCounts: { VALID: 1, NXDOMAIN: 1, REVIEW: 1 },
      reviewSubtypeCounts: { REVIEW_OTHER: 1 }, discrepancyCount: 0,
      dnsParams: baseDnsParams(), preflight: {}, reviewRetry: { retried: 0, became_VALID: 0, became_NXDOMAIN: 0, remained_REVIEW: 0 },
    });
    try {
      assert.strictEqual(pkg.integrity.passed, true, 'control: datos consistentes deben pasar integridad');
      console.log('PASS control (datos consistentes -> integrity.passed === true)');
    } catch (e) { failures++; console.error('FAIL control:', e.message); }
  }

  // ── A. Conteos inconsistentes: normalizados != VALID+NXDOMAIN+REVIEW ──
  {
    const normalized = ['a.ec', 'b.ec', 'c.ec']; // 3 normalizados
    const perDomain = [row('a.ec', 'VALID'), row('b.ec', 'NXDOMAIN'), row('c.ec', 'REVIEW')];
    const pkg = await buildResultsPackage({
      jobId: 'caso-A', context: baseContext(normalized), perDomain,
      finalStatusCounts: { VALID: 1, NXDOMAIN: 1, REVIEW: 0 }, // suma = 2, no 3 (REVIEW mal contado)
      reviewSubtypeCounts: {}, discrepancyCount: 0,
      dnsParams: baseDnsParams(), preflight: {}, reviewRetry: { retried: 0, became_VALID: 0, became_NXDOMAIN: 0, remained_REVIEW: 0 },
    });
    try {
      assert.strictEqual(pkg.integrity.passed, false, 'caso A: debe fallar integridad');
      assert.strictEqual(pkg.integrity.checks.status_sum_equals_normalized, false, 'caso A: debe identificar el check de suma de estados');
      assert.strictEqual(pkg.integrity.status_sum, 2);
      assert.strictEqual(pkg.integrity.normalized_count, 3);
      console.log('PASS caso A (conteos inconsistentes -> integrity.passed === false, status_sum_equals_normalized === false)');
    } catch (e) { failures++; console.error('FAIL caso A:', e.message); }
  }

  // ── B. perDomain.length != normalizados ──
  {
    const normalized = ['a.ec', 'b.ec', 'c.ec', 'd.ec']; // 4 normalizados
    const perDomain = [row('a.ec', 'VALID'), row('b.ec', 'NXDOMAIN'), row('c.ec', 'REVIEW')]; // solo 3 filas
    const pkg = await buildResultsPackage({
      jobId: 'caso-B', context: baseContext(normalized), perDomain,
      finalStatusCounts: { VALID: 1, NXDOMAIN: 1, REVIEW: 1 }, // suma=3, tampoco calza con 4
      reviewSubtypeCounts: {}, discrepancyCount: 0,
      dnsParams: baseDnsParams(), preflight: {}, reviewRetry: { retried: 0, became_VALID: 0, became_NXDOMAIN: 0, remained_REVIEW: 0 },
    });
    try {
      assert.strictEqual(pkg.integrity.passed, false, 'caso B: debe fallar integridad');
      assert.strictEqual(pkg.integrity.checks.csv_rows_equals_normalized, false, 'caso B: debe identificar el check de filas CSV');
      assert.strictEqual(pkg.integrity.csv_rows, 3);
      assert.strictEqual(pkg.integrity.normalized_count, 4);
      console.log('PASS caso B (perDomain.length != normalizados -> integrity.passed === false, csv_rows_equals_normalized === false)');
    } catch (e) { failures++; console.error('FAIL caso B:', e.message); }
  }

  // ── C. Partición inconsistente: duplicado que reemplaza a un faltante.
  //      Los conteos NUMÉRICOS cuadran (3 normalizados, 3 filas, suma=3),
  //      pero 'a.ec' aparece DOS veces y 'b.ec' no aparece — el conjunto de
  //      dominios de las filas NO es el universo normalizado. ──
  {
    const normalized = ['a.ec', 'b.ec', 'c.ec'];
    const perDomain = [row('a.ec', 'VALID'), row('a.ec', 'NXDOMAIN'), row('c.ec', 'REVIEW')]; // 'a.ec' duplicado, 'b.ec' ausente
    const pkg = await buildResultsPackage({
      jobId: 'caso-C', context: baseContext(normalized), perDomain,
      finalStatusCounts: { VALID: 1, NXDOMAIN: 1, REVIEW: 1 }, // suma=3=normalizados (coincide numéricamente)
      reviewSubtypeCounts: { REVIEW_OTHER: 1 }, discrepancyCount: 0,
      dnsParams: baseDnsParams(), preflight: {}, reviewRetry: { retried: 0, became_VALID: 0, became_NXDOMAIN: 0, remained_REVIEW: 0 },
    });
    try {
      assert.strictEqual(pkg.integrity.normalized_count, 3);
      assert.strictEqual(pkg.integrity.status_sum, 3);
      assert.strictEqual(pkg.integrity.csv_rows, 3);
      // Con solo los checks numéricos, este caso "cuadraría" por accidente.
      // La salvaguarda debe detectar la partición real igualmente.
      assert.strictEqual(pkg.integrity.passed, false, 'caso C: debe fallar integridad pese a que los conteos numéricos coincidan');
      console.log('PASS caso C (partición inconsistente detectada -> integrity.passed === false, pese a conteos numéricos coincidentes)');
      console.log('  checks:', JSON.stringify(pkg.integrity.checks));
    } catch (e) { failures++; console.error('FAIL caso C:', e.message, '\n  checks obtenidos:', JSON.stringify(pkg.integrity.checks)); }
  }

  return failures;
}

runCases().then((failures) => {
  if (failures > 0) {
    console.error(`\n${failures} caso(s) fallaron.`);
    process.exit(1);
  }
  console.log('\nOK — la salvaguarda de integridad detecta correctamente los 3 tipos de inconsistencia pedidos.');
}).catch((error) => {
  console.error('ERROR', error);
  process.exit(1);
});
