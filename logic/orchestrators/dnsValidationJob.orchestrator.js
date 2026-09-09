'use strict';

/**
 * Orquestador de jobs de Validación DNS — ejecuta runDnsValidation() en
 * segundo plano (un dataset completo puede tardar varios minutos) y expone
 * progreso vía SSE, siguiendo el mismo patrón que aggregate/orchestrator.js
 * usa para Observatorio (job en memoria + listeners SSE).
 *
 * Además de correr la validación, este módulo CAPTURA (no recalcula) todo
 * el detalle que ya produce runDnsValidation() — respuestas por resolver de
 * la primera pasada y de la pasada final, para que la etapa "Resultados y
 * descarga" pueda construir validacion_dns.csv, metadata.json y el resto
 * de archivos sin volver a tocar DNS ni la clasificación.
 */

const crypto = require('crypto');
const {
  runDnsValidation, reviewSubtype,
  DEFAULT_RESOLVERS, DEFAULT_TIMEOUT_SECONDS, DEFAULT_RETRIES,
  DEFAULT_WORKERS, DEFAULT_REVIEW_WAIT_SECONDS,
} = require('../validators/dnsValidation.validator');
const { buildResultsPackage } = require('../exporters/datasetResultsPackage.exporter');

const jobs = new Map(); // jobId -> job state
const listeners = new Map(); // jobId -> Set<writeFn>

function emit(jobId, event) {
  const set = listeners.get(jobId);
  if (!set) return;
  const payload = `data: ${JSON.stringify(event)}\n\n`;
  for (const write of set) {
    try {
      write(payload);
    } catch {
      set.delete(write);
    }
  }
}

function addListener(jobId, fn) {
  if (!listeners.has(jobId)) listeners.set(jobId, new Set());
  listeners.get(jobId).add(fn);
}

function removeListener(jobId, fn) {
  const set = listeners.get(jobId);
  if (set) set.delete(fn);
}

function getJob(jobId) {
  return jobs.get(jobId) || null;
}

// Réplica de answer_value()/answer_error()/answer_attempts() del validador
// Python, sobre la forma de `answers` usada en dnsValidation.validator.js.
function answerField(answers, resolver, rtype, field, fallback) {
  const a = answers[`${resolver}:${rtype}`];
  if (!a) return field === 'rcode' ? 'NOT_QUERIED' : fallback;
  return a[field] ?? fallback;
}

// Réplica de observation_text() del validador Python.
function observationText(answers) {
  const parts = [];
  for (const rtype of ['NS', 'SOA']) {
    for (const resolverName of Object.keys(DEFAULT_RESOLVERS)) {
      const a = answers[`${resolverName}:${rtype}`];
      if (!a) continue;
      let txt = `${resolverName}(${a.server}):${rtype}:${a.rcode}`;
      if (a.error) txt += `:${a.error}`;
      if (a.attempts > 1) txt += `:attempts=${a.attempts}`;
      parts.push(txt);
    }
  }
  return parts.join(' | ');
}

async function runJob(job, domains, context) {
  const dnsStartedAt = new Date().toISOString();
  const startMs = Date.now();

  try {
    const result = await runDnsValidation({
      domains,
      onProgress: ({ phase, done, total, domain, result: r }) => {
        job.progress = { phase, done, total };
        emit(job.jobId, { event: 'progress', phase, done, total, domain, status: r.status });
      },
    });

    const finalStatusCounts = { VALID: 0, NXDOMAIN: 0, REVIEW: 0 };
    const reviewSubtypeCounts = {};
    let discrepancyCount = 0;
    const perDomain = [];

    for (const domain of domains) {
      const first = result.firstResults.get(domain);
      const final = result.finalResults.get(domain);
      finalStatusCounts[final.status] = (finalStatusCounts[final.status] || 0) + 1;
      if (final.discrepancy) discrepancyCount += 1;
      const subtype = reviewSubtype(final);
      if (subtype) reviewSubtypeCounts[subtype] = (reviewSubtypeCounts[subtype] || 0) + 1;

      const retried = first.status === 'REVIEW';

      perDomain.push({
        domain,
        first_pass_status: first.status,
        final_status: final.status,
        status_reason: final.reason,
        review_subtype: subtype,
        retry_performed: retried,
        discrepancy: final.discrepancy,
        cloudflare_ns: answerField(final.answers, 'cloudflare', 'NS', 'rcode'),
        google_ns: answerField(final.answers, 'google', 'NS', 'rcode'),
        cloudflare_soa: answerField(final.answers, 'cloudflare', 'SOA', 'rcode'),
        google_soa: answerField(final.answers, 'google', 'SOA', 'rcode'),
        cloudflare_ns_error: answerField(final.answers, 'cloudflare', 'NS', 'error', ''),
        google_ns_error: answerField(final.answers, 'google', 'NS', 'error', ''),
        cloudflare_soa_error: answerField(final.answers, 'cloudflare', 'SOA', 'error', ''),
        google_soa_error: answerField(final.answers, 'google', 'SOA', 'error', ''),
        cloudflare_ns_attempts: answerField(final.answers, 'cloudflare', 'NS', 'attempts', ''),
        google_ns_attempts: answerField(final.answers, 'google', 'NS', 'attempts', ''),
        cloudflare_soa_attempts: answerField(final.answers, 'cloudflare', 'SOA', 'attempts', ''),
        google_soa_attempts: answerField(final.answers, 'google', 'SOA', 'attempts', ''),
        first_pass_observations: observationText(first.answers),
        final_observations: observationText(final.answers),
      });
    }

    const retryValues = Array.from(result.retryResults.values());
    const dnsCompletedAt = new Date().toISOString();
    const dnsDurationMs = Date.now() - startMs;

    job.status = 'completed';
    job.completedAt = dnsCompletedAt;
    job.summary = {
      preflight: result.preflight,
      total: domains.length,
      final_status: finalStatusCounts,
      review_subtypes: reviewSubtypeCounts,
      discrepancies: discrepancyCount,
      review_retry: {
        retried: result.retriedCount,
        became_VALID: retryValues.filter((r) => r.status === 'VALID').length,
        became_NXDOMAIN: retryValues.filter((r) => r.status === 'NXDOMAIN').length,
        remained_REVIEW: retryValues.filter((r) => r.status === 'REVIEW').length,
      },
      domains: perDomain,
    };

    job.dnsParams = {
      resolvers: DEFAULT_RESOLVERS,
      timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
      retries: DEFAULT_RETRIES,
      workers: DEFAULT_WORKERS,
      review_wait_seconds: DEFAULT_REVIEW_WAIT_SECONDS,
      checking_disabled: true,
      preflight_ok: Object.values(result.preflight).every((a) => a.rcode === 'NOERROR'),
      started_at: dnsStartedAt,
      completed_at: dnsCompletedAt,
      duration_ms: dnsDurationMs,
    };

    // Construye (UNA sola vez) los archivos descargables y sus hashes a
    // partir de lo ya calculado — no ejecuta DNS ni reclasifica nada.
    try {
      job.resultsPackage = await buildResultsPackage({
        jobId: job.jobId,
        context,
        perDomain,
        finalStatusCounts,
        reviewSubtypeCounts,
        discrepancyCount,
        dnsParams: job.dnsParams,
        preflight: result.preflight,
        reviewRetry: job.summary.review_retry,
      });
    } catch (packageError) {
      job.resultsPackageError = packageError.message;
    }

    emit(job.jobId, { event: 'done', status: 'completed' });
  } catch (error) {
    job.status = 'failed';
    job.error = error.message;
    job.completedAt = new Date().toISOString();
    if (error.code === 'PREFLIGHT_FAILED') {
      job.preflightFailed = true;
      job.preflight = error.preflight;
    }
    emit(job.jobId, { event: 'done', status: 'failed', error: error.message });
  }
}

function startDnsValidationJob(domains, context = {}) {
  const jobId = crypto.randomUUID();
  const job = {
    jobId,
    status: 'running',
    total: domains.length,
    progress: { phase: 'preflight', done: 0, total: domains.length },
    createdAt: new Date().toISOString(),
    completedAt: null,
    error: null,
    summary: null,
    context,
  };
  jobs.set(jobId, job);

  runJob(job, domains, context);

  return job;
}

module.exports = { startDnsValidationJob, getJob, addListener, removeListener };
