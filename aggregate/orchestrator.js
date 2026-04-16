'use strict';

/**
 * Orchestrator — Mediciones ISOC LAC
 *
 * Motor unificado que:
 *  - Detecta listas duplicadas antes de analizar
 *  - Despacha al motor correcto (DoH rápido o Zonemaster completo)
 *  - Persiste resultados con histórico
 *  - Emite eventos de progreso via SSE
 *  - Produce métricas agregadas, semáforo y recomendaciones
 */

const { EventEmitter }     = require('events');
const { createAnalysis, updateAnalysis, readAnalysis,
        findByListHash, hashDomainList } = require('./history.store');
const { aggregateCountry } = require('./aggregators/country.aggregator');
const { getRecommendations } = require('./aggregators/policy.recommender');

// Motor DoH (existente)
const { getDnssecAnalysis }    = require('../services/dnssec.service');
const { processDnssecAnalysis }= require('../logic/processors/dnssec.processor');
const { validateDomainInput }  = require('../logic/validators/domain.validator');

// Motor Zonemaster
const { analyzeBatch: zmBatch, ping: zmPing } = require('./zonemaster/zonemaster.adapter');

const ENGINES = { DOH: 'doh', ZONEMASTER: 'zonemaster' };

// SSE clients activos: jobId → Set<writeFunction>
const sseClients = new Map();

function broadcast(jobId, data) {
  const clients = sseClients.get(jobId);
  if (!clients) return;
  const msg = `data: ${JSON.stringify(data)}\n\n`;
  for (const fn of clients) { try { fn(msg); } catch {} }
}

function addSseClient(jobId, writeFn) {
  if (!sseClients.has(jobId)) sseClients.set(jobId, new Set());
  sseClients.get(jobId).add(writeFn);
}

function removeSseClient(jobId, writeFn) {
  sseClients.get(jobId)?.delete(writeFn);
}

// ─── Inicio de análisis ───────────────────────────────────────────────────────

async function startAnalysis({ label, country, domains, engine = ENGINES.DOH, config = {} }) {
  const listHash = hashDomainList(domains);

  // Detectar duplicado
  const existing = findByListHash(listHash);
  if (existing.length > 0) {
    return {
      duplicate: true,
      previousAnalysis: existing[0],
      message: `Esta lista ya fue analizada el ${new Date(existing[0].createdAt).toLocaleDateString('es-EC')}.`,
    };
  }

  const analysis = createAnalysis({ label, country: country || label, domains, engine, meta: { config } });

  // Correr en background — no bloqueante
  setImmediate(() => runAnalysis(analysis.jobId, domains, engine, config));

  return {
    duplicate: false,
    jobId:    analysis.jobId,
    label:    analysis.label,
    engine,
    total:    domains.length,
    estimatedMinutes: engine === ENGINES.ZONEMASTER
      ? Math.ceil(domains.length * 60 / 3 / 60)  // ~60s/dominio, concurrencia 3
      : Math.ceil(domains.length * 3  / 10 / 60), // ~3s/dominio, concurrencia 10
  };
}

// ─── Ejecutar análisis ────────────────────────────────────────────────────────

async function runAnalysis(jobId, domains, engine, config) {
  updateAnalysis(jobId, { status: 'running' });
  broadcast(jobId, { event: 'started', jobId, engine, total: domains.length });

  try {
    let results = [], errors = [];

    if (engine === ENGINES.ZONEMASTER) {
      ({ results, errors } = await runZonemaster(jobId, domains, config));
    } else {
      ({ results, errors } = await runDoh(jobId, domains, config));
    }

    const aggregate      = aggregateCountry({
      country: readAnalysis(jobId)?.country || 'unknown',
      results, errors,
    });
    const recommendations = getRecommendations(aggregate);

    updateAnalysis(jobId, {
      status:       'completed',
      completedAt:  new Date().toISOString(),
      results,
      errors,
      aggregate,
      recommendations,
      errorCount:   errors.length,
      progress:     { processed: domains.length, total: domains.length, percent: 100 },
    });

    broadcast(jobId, { event: 'done', aggregate: aggregate.summary, errors: errors.length });
    sseClients.delete(jobId);

  } catch (err) {
    updateAnalysis(jobId, { status: 'failed', error: err.message });
    broadcast(jobId, { event: 'error', message: err.message });
    sseClients.delete(jobId);
  }
}

// ─── Motor DoH ────────────────────────────────────────────────────────────────

async function runDoh(jobId, domains, config) {
  const concurrency = config.concurrency || 10;
  const results = [], errors = [];
  const queue   = [...domains];
  let processed = 0;
  const total   = domains.length;

  const worker = async () => {
    while (queue.length > 0) {
      const rawDomain = queue.shift();
      let domain;
      try { domain = validateDomainInput(rawDomain); }
      catch { errors.push({ domain: rawDomain, error: 'invalid_domain' }); processed++; continue; }

      try {
        const raw    = await getDnssecAnalysis(domain);
        const result = processDnssecAnalysis(raw);
        results.push(result);
      } catch (err) {
        errors.push({ domain, error: err.message });
      }

      processed++;
      const progress = { processed, total, percent: Math.round(processed / total * 100), lastDomain: domain };
      updateAnalysis(jobId, { progress });
      broadcast(jobId, { event: 'progress', ...progress });
    }
  };

  await Promise.all(Array.from({ length: Math.min(concurrency, domains.length) }, () => worker()));
  return { results, errors };
}

// ─── Motor Zonemaster ─────────────────────────────────────────────────────────

async function runZonemaster(jobId, domains, config) {
  const zmConfig = {
    endpoint:    config.endpoint    || process.env.ZM_ENDPOINT || 'https://zonemaster.net/api',
    concurrency: config.concurrency || 3,
    username:    config.username    || process.env.ZM_USERNAME,
    apiKey:      config.apiKey      || process.env.ZM_API_KEY,
  };

  return zmBatch(domains, zmConfig, (progress) => {
    updateAnalysis(jobId, { progress });
    broadcast(jobId, { event: 'progress', ...progress });
  });
}

// ─── Verificar disponibilidad de Zonemaster ───────────────────────────────────

async function checkZonmasterAvailability(config = {}) {
  const endpoint = config.endpoint || process.env.ZM_ENDPOINT || 'https://zonemaster.net/api';
  return zmPing({ endpoint });
}

module.exports = {
  startAnalysis,
  addSseClient,
  removeSseClient,
  checkZonmasterAvailability,
  ENGINES,
};
