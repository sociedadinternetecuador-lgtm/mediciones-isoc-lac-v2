'use strict';

/**
 * Validación DNS — réplica fiel de validate_dns()/classify_answers()/
 * review_subtype()/preflight_resolvers() y la orquestación de main() en
 * validador/validar_dominios_isoc_lac.py.
 *
 * Principio replicado sin cambios: esta etapa SOLO determina si un nombre
 * existe en DNS (NOERROR en NS o SOA de al menos un resolver = VALID;
 * NXDOMAIN confirmado por AMBOS resolvers en el mismo tipo de consulta =
 * NXDOMAIN; cualquier otro caso = REVIEW, no se descarta automáticamente).
 * No exige A/AAAA/MX/DNSSEC/HTTPS/web como criterio de exclusión.
 *
 * Mismos valores por defecto que Python (no se cambian):
 *  - Resolvers: Cloudflare 1.1.1.1, Google 8.8.8.8.
 *  - timeout: 2.5s por intento, retries: 1 (máx. 2 intentos por consulta).
 *  - workers: 20 (concurrencia de dominios en paralelo).
 *  - review_wait: 2.0s de espera antes del reintento automático de REVIEW.
 */

const { dnsQuery } = require('../adapters/rawDns.adapter');

const DEFAULT_RESOLVERS = { cloudflare: '1.1.1.1', google: '8.8.8.8' };
const DEFAULT_TIMEOUT_SECONDS = 2.5;
const DEFAULT_RETRIES = 1;
const DEFAULT_WORKERS = 20;
const DEFAULT_REVIEW_WAIT_SECONDS = 2.0;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Réplica de classify_answers() del validador Python.
function classifyAnswers(answers, resolverNames) {
  const ns = resolverNames.map((name) => answers[`${name}:NS`]).filter(Boolean).map((a) => a.rcode);
  const soa = resolverNames.map((name) => answers[`${name}:SOA`]).filter(Boolean).map((a) => a.rcode);
  const allRcodes = ns.concat(soa);

  const discrepancy =
    (ns.length >= 2 && new Set(ns).size > 1) ||
    (soa.length >= 2 && new Set(soa).size > 1);

  if (allRcodes.includes('NOERROR')) {
    const where = ns.includes('NOERROR') ? 'NS' : 'SOA';
    return { status: 'VALID', reason: `NOERROR confirmado en ${where}`, discrepancy };
  }

  if (ns.length === resolverNames.length && ns.length >= 2 && ns.every((x) => x === 'NXDOMAIN')) {
    return { status: 'NXDOMAIN', reason: 'NXDOMAIN confirmado por ambos resolvers en NS', discrepancy };
  }

  if (soa.length === resolverNames.length && soa.length >= 2 && soa.every((x) => x === 'NXDOMAIN')) {
    return { status: 'NXDOMAIN', reason: 'NXDOMAIN confirmado por ambos resolvers en SOA', discrepancy };
  }

  return { status: 'REVIEW', reason: 'Resultado DNS no concluyente', discrepancy };
}

// Réplica de validate_dns() del validador Python: NS contra ambos
// resolvers; si es inconcluso, SOA de respaldo contra ambos. Las dos
// consultas de un mismo dominio se resuelven en paralelo aquí (no cambia
// el resultado, solo el tiempo de espera — Python las hace secuenciales
// dentro de cada dominio, pero cada dominio es independiente).
async function validateDomainDns(domain, timeoutSeconds, retries, resolvers) {
  const resolverNames = Object.keys(resolvers);
  const timeoutMs = timeoutSeconds * 1000;
  const answers = {};

  await Promise.all(resolverNames.map(async (name) => {
    answers[`${name}:NS`] = await dnsQuery(name, resolvers[name], domain, 'NS', timeoutMs, retries);
  }));

  let classification = classifyAnswers(answers, resolverNames);
  if (classification.status === 'VALID' || classification.status === 'NXDOMAIN') {
    return { domain, ...classification, answers };
  }

  await Promise.all(resolverNames.map(async (name) => {
    answers[`${name}:SOA`] = await dnsQuery(name, resolvers[name], domain, 'SOA', timeoutMs, retries);
  }));

  classification = classifyAnswers(answers, resolverNames);
  return { domain, ...classification, answers };
}

// Réplica de review_subtype() del validador Python.
function reviewSubtype(result) {
  if (result.status !== 'REVIEW') return '';

  const values = Object.values(result.answers).map((a) => a.rcode).filter(Boolean);
  if (!values.length) return 'REVIEW_ERROR';

  const unique = new Set(values);

  if (result.discrepancy) return 'REVIEW_CONFLICT';
  if (unique.size === 1 && unique.has('TIMEOUT')) return 'REVIEW_TIMEOUT';
  if (unique.size === 1 && unique.has('SERVFAIL')) return 'REVIEW_SERVFAIL';
  if (unique.has('REFUSED')) return 'REVIEW_REFUSED';
  if (unique.has('ERROR')) return 'REVIEW_ERROR';
  if (unique.has('TIMEOUT') && unique.has('SERVFAIL')) return 'REVIEW_MIXED_TIMEOUT_SERVFAIL';
  if (unique.has('TIMEOUT')) return 'REVIEW_TIMEOUT';
  if (unique.has('SERVFAIL')) return 'REVIEW_SERVFAIL';
  return 'REVIEW_OTHER';
}

// Réplica de preflight_resolvers()/preflight_ok() del validador Python.
async function preflightResolvers(resolvers, timeoutSeconds) {
  const results = {};
  await Promise.all(Object.entries(resolvers).map(async ([name, server]) => {
    results[name] = await dnsQuery(name, server, '.', 'NS', timeoutSeconds * 1000, 0);
  }));
  return results;
}

function preflightOk(results) {
  return Object.values(results).every((a) => a.rcode === 'NOERROR');
}

// Réplica de run_validation_batch(): ejecuta validateDomainDns para una
// lista de dominios con concurrencia limitada (equivalente al
// ThreadPoolExecutor(max_workers=workers) de Python — no altera resultados,
// solo el paralelismo).
async function runBatch(domains, concurrency, taskFn, onProgress) {
  const results = new Map();
  let index = 0;
  let completed = 0;

  async function worker() {
    while (index < domains.length) {
      const i = index++;
      const domain = domains[i];
      const result = await taskFn(domain);
      results.set(domain, result);
      completed += 1;
      if (onProgress) onProgress(completed, domains.length, domain, result);
    }
  }

  const poolSize = Math.max(1, Math.min(concurrency, domains.length));
  await Promise.all(Array.from({ length: poolSize }, () => worker()));
  return results;
}

// Réplica de la orquestación DNS de main(): preflight -> primera pasada ->
// reintento automático de REVIEW.
async function runDnsValidation({
  domains,
  timeoutSeconds = DEFAULT_TIMEOUT_SECONDS,
  retries = DEFAULT_RETRIES,
  workers = DEFAULT_WORKERS,
  reviewWaitSeconds = DEFAULT_REVIEW_WAIT_SECONDS,
  noReviewRetry = false,
  skipPreflight = false,
  resolvers = DEFAULT_RESOLVERS,
  onProgress,
}) {
  const preflight = await preflightResolvers(resolvers, timeoutSeconds);

  if (!preflightOk(preflight) && !skipPreflight) {
    const error = new Error(
      'Al menos un resolver no superó el preflight. No se inicia el lote para evitar producir REVIEW masivos.'
    );
    error.code = 'PREFLIGHT_FAILED';
    error.preflight = preflight;
    throw error;
  }

  const firstResults = await runBatch(
    domains,
    workers,
    (domain) => validateDomainDns(domain, timeoutSeconds, retries, resolvers),
    (done, total, domain, result) => onProgress && onProgress({ phase: 'first_pass', done, total, domain, result })
  );

  const firstReview = domains.filter((d) => firstResults.get(d).status === 'REVIEW');
  const finalResults = new Map(firstResults);
  let retriedCount = 0;
  let retryResults = new Map();

  if (firstReview.length > 0 && !noReviewRetry) {
    if (reviewWaitSeconds) await sleep(reviewWaitSeconds * 1000);

    retryResults = await runBatch(
      firstReview,
      workers,
      (domain) => validateDomainDns(domain, timeoutSeconds, retries, resolvers),
      (done, total, domain, result) => onProgress && onProgress({ phase: 'review_retry', done, total, domain, result })
    );
    retriedCount = firstReview.length;

    for (const [domain, result] of retryResults) {
      finalResults.set(domain, result);
    }
  }

  return { preflight, firstResults, finalResults, firstReview, retriedCount, retryResults };
}

module.exports = {
  DEFAULT_RESOLVERS,
  DEFAULT_TIMEOUT_SECONDS,
  DEFAULT_RETRIES,
  DEFAULT_WORKERS,
  DEFAULT_REVIEW_WAIT_SECONDS,
  classifyAnswers,
  validateDomainDns,
  reviewSubtype,
  preflightResolvers,
  preflightOk,
  runBatch,
  runDnsValidation,
};
