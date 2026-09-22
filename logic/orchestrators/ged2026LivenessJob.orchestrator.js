'use strict';

/**
 * Job en memoria para validar actividad de dominios GED2026 — mismo patrón
 * de logic/orchestrators/dnsValidationJob.orchestrator.js (Map en memoria,
 * sin persistencia, se pierde si el proceso reinicia — CLAUDE.md regla 5),
 * pero SIN SSE: ese módulo lo justifica para decenas de miles de dominios;
 * GED2026 opera sobre ~250-300, así que un polling simple del estado cada
 * pocos segundos desde el panel admin alcanza (ver docs/ged2026.md para el
 * razonamiento de costo/tiempo y la recomendación de correr primero sobre
 * una muestra reducida antes de validar el universo completo).
 */

const crypto = require('crypto');
const { checkDomainLiveness } = require('../adapters/ged2026Liveness.adapter');
const { updateDomain } = require('../adapters/ged2026Store.adapter');

const CONCURRENCY = 8;
const jobs = new Map();

async function runPool(items, worker, concurrency) {
  let next = 0;
  async function runWorker() {
    while (next < items.length) {
      const idx = next;
      next += 1;
      await worker(items[idx]);
    }
  }
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, runWorker);
  await Promise.all(workers);
}

function startLivenessJob(domainRecords, options = {}) {
  const jobId = crypto.randomUUID();
  const job = {
    jobId,
    status: 'running',
    total: domainRecords.length,
    done: 0,
    startedAt: new Date().toISOString(),
    finishedAt: null,
    results: [],
  };
  jobs.set(jobId, job);

  runPool(domainRecords, async (record) => {
    let outcome;
    try {
      outcome = await checkDomainLiveness(record.normalized_domain, options);
    } catch (error) {
      outcome = { estado_validacion: 'unknown', detail: { error: error.message } };
    }
    updateDomain(record.id, {
      estado_validacion: outcome.estado_validacion,
      fecha_ultima_validacion: new Date().toISOString(),
    });
    job.results.push({ id: record.id, domain: record.normalized_domain, estado_validacion: outcome.estado_validacion });
    job.done += 1;
  }, CONCURRENCY)
    .then(() => {
      job.status = 'completed';
      job.finishedAt = new Date().toISOString();
    })
    .catch((error) => {
      job.status = 'error';
      job.error = error.message;
      job.finishedAt = new Date().toISOString();
    });

  return job;
}

function getLivenessJob(jobId) {
  return jobs.get(jobId) || null;
}

module.exports = { startLivenessJob, getLivenessJob };
