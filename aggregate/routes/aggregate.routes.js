'use strict';

/**
 * Aggregate Routes — Módulo Agregado DNSSEC ISOC LAC
 *
 * Endpoints:
 *
 *  POST /aggregate/batch
 *    Inicia un job batch para un país.
 *    Body: { country, domains: [...] }  o  { country, text: "dom1\ndom2\n..." }
 *    Responde: { jobId, status: 'started', totalDomains }
 *
 *  GET  /aggregate/job/:jobId
 *    Devuelve el estado actual y resultados del job.
 *
 *  GET  /aggregate/job/:jobId/progress
 *    Stream SSE con el progreso en tiempo real.
 *
 *  GET  /aggregate/job/:jobId/export?format=json|csv|html
 *    Exporta los resultados del job en el formato solicitado.
 *
 *  GET  /aggregate/jobs
 *    Lista todos los jobs registrados.
 *
 *  POST /aggregate/region
 *    Combina múltiples jobs completados en una vista regional.
 *    Body: { jobIds: [...] }  o  { countries: [...] }
 */

const { BatchQueue } = require('../batch/queue.manager');
const { createJob, updateJob, readJob, listJobs } = require('../batch/session.store');
const { aggregateCountry } = require('../aggregators/country.aggregator');
const { aggregateRegion } = require('../aggregators/region.aggregator');
const { getRecommendations } = require('../aggregators/policy.recommender');
const { toJson, resultsToCsv, buildHtmlReport } = require('../exporters/exporters');

// Mapa de streams SSE activos (jobId → Set de callbacks)
const sseClients = new Map();

function broadcastProgress(jobId, data) {
  const clients = sseClients.get(jobId);
  if (!clients) return;
  const msg = `data: ${JSON.stringify(data)}\n\n`;
  for (const write of clients) {
    try { write(msg); } catch { /* cliente desconectado */ }
  }
}

function parseDomainList(body) {
  if (Array.isArray(body.domains)) {
    return body.domains.map(d => String(d).trim()).filter(Boolean);
  }
  if (typeof body.text === 'string') {
    return body.text.split(/[\n,;]+/).map(d => d.trim()).filter(Boolean);
  }
  return [];
}

async function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => {
      try { resolve(JSON.parse(data || '{}')); }
      catch { resolve({}); }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data, null, 2));
}

function sendError(res, status, message) {
  sendJson(res, status, { error: message });
}

// ─── Manejadores ──────────────────────────────────────────────────────────────

async function handleStartBatch(req, res) {
  const body = await readBody(req);
  const country = String(body.country || '').trim().toLowerCase();
  const concurrency = Math.min(parseInt(body.concurrency) || 10, 20);

  if (!country) return sendError(res, 400, 'El campo "country" es requerido');

  const domains = parseDomainList(body);
  if (domains.length === 0) return sendError(res, 400, 'No se encontraron dominios en la solicitud');

  const job = createJob({
    country,
    domains,
    meta: { concurrency, source: body.source || 'api' }
  });

  updateJob(job.jobId, { status: 'running' });

  // Ejecutar batch en background (no bloqueante)
  setImmediate(() => runBatch(job.jobId, domains, country, concurrency));

  sendJson(res, 202, {
    jobId: job.jobId,
    status: 'started',
    country,
    totalDomains: domains.length,
    concurrency,
    progressUrl: `/aggregate/job/${job.jobId}/progress`,
    statusUrl: `/aggregate/job/${job.jobId}`
  });
}

async function runBatch(jobId, domains, country, concurrency) {
  const queue = new BatchQueue({ concurrency });

  queue.on('progress', (progress) => {
    updateJob(jobId, { progress });
    broadcastProgress(jobId, { event: 'progress', ...progress });
  });

  const { results, errors, summary } = await queue.run(domains);

  const aggregate = aggregateCountry({ country, results, errors });
  const recommendations = getRecommendations(aggregate);

  updateJob(jobId, {
    status: summary.status,
    results,
    errors,
    aggregate,
    recommendations,
    progress: { processed: summary.processed, total: summary.total, percent: 100 }
  });

  broadcastProgress(jobId, { event: 'done', summary, aggregate: aggregate.summary });

  // Cerrar streams SSE de este job
  sseClients.delete(jobId);
}

function handleGetJob(req, res, jobId) {
  const job = readJob(jobId);
  if (!job) return sendError(res, 404, 'Job no encontrado');
  // Omitimos results detallados del GET status (están en /export)
  const { results: _, ...summary } = job;
  sendJson(res, 200, summary);
}

function handleJobProgress(req, res, jobId) {
  const job = readJob(jobId);
  if (!job) return sendError(res, 404, 'Job no encontrado');

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no'
  });

  const write = (msg) => res.write(msg);

  if (!sseClients.has(jobId)) sseClients.set(jobId, new Set());
  sseClients.get(jobId).add(write);

  // Enviar estado actual inmediatamente
  res.write(`data: ${JSON.stringify({ event: 'current', ...job.progress, status: job.status })}\n\n`);

  if (job.status === 'completed' || job.status === 'cancelled') {
    res.write(`data: ${JSON.stringify({ event: 'done', status: job.status })}\n\n`);
    res.end();
    return;
  }

  // Heartbeat cada 15s
  const heartbeat = setInterval(() => {
    try { res.write(': ping\n\n'); } catch { clearInterval(heartbeat); }
  }, 15000);

  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.get(jobId)?.delete(write);
  });
}

function handleExport(req, res, jobId, searchParams) {
  const job = readJob(jobId);
  if (!job) return sendError(res, 404, 'Job no encontrado');
  if (job.status !== 'completed') return sendError(res, 409, 'El job aún no ha terminado');

  const format = searchParams.get('format') || 'json';
  const includeRegion = searchParams.get('region') === 'true';

  let regionData = null;
  if (includeRegion) {
    try {
      const jobs = listJobs().filter(j => j.status === 'completed' && j.jobId !== jobId);
      const aggregates = jobs.map(j => readJob(j.jobId)?.aggregate).filter(Boolean);
      if (aggregates.length > 0) {
        regionData = aggregateRegion([job.aggregate, ...aggregates]);
      }
    } catch { /* región opcional */ }
  }

  if (format === 'csv') {
    res.writeHead(200, {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': `attachment; filename="dnssec-${job.country}-${job.jobId.slice(0, 8)}.csv"`
    });
    res.end(resultsToCsv(job.results || []));
    return;
  }

  if (format === 'html') {
    const html = buildHtmlReport({
      country: job.country,
      aggregate: job.aggregate,
      recommendations: job.recommendations,
      results: job.results || [],
      regionData
    });
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
    return;
  }

  // JSON por defecto
  res.writeHead(200, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Disposition': `attachment; filename="dnssec-${job.country}-${job.jobId.slice(0, 8)}.json"`
  });
  res.end(toJson({ job: { ...job, results: job.results || [] }, regionData }));
}

function handleListJobs(req, res) {
  sendJson(res, 200, { jobs: listJobs() });
}

async function handleRegion(req, res) {
  const body = await readBody(req);
  const jobIds = Array.isArray(body.jobIds) ? body.jobIds : [];

  if (jobIds.length === 0) {
    // Si no se especifican jobIds, usar todos los completados
    const all = listJobs().filter(j => j.status === 'completed');
    const aggregates = all.map(j => readJob(j.jobId)?.aggregate).filter(Boolean);
    if (aggregates.length === 0) return sendError(res, 404, 'No hay jobs completados para agregar');
    return sendJson(res, 200, aggregateRegion(aggregates));
  }

  const aggregates = jobIds.map(id => readJob(id)?.aggregate).filter(Boolean);
  if (aggregates.length === 0) return sendError(res, 404, 'No se encontraron jobs válidos');

  sendJson(res, 200, aggregateRegion(aggregates));
}

// ─── Router ───────────────────────────────────────────────────────────────────

async function handleAggregateRequest(req, res, url) {
  const { pathname, searchParams } = url;
  const segments = pathname.split('/').filter(Boolean);

  // POST /aggregate/batch
  if (req.method === 'POST' && segments[1] === 'batch') {
    return handleStartBatch(req, res);
  }

  // GET /aggregate/jobs
  if (req.method === 'GET' && segments[1] === 'jobs') {
    return handleListJobs(req, res);
  }

  // POST /aggregate/region
  if (req.method === 'POST' && segments[1] === 'region') {
    return handleRegion(req, res);
  }

  // GET /aggregate/job/:jobId
  if (req.method === 'GET' && segments[1] === 'job' && segments[2]) {
    const jobId = segments[2];

    // GET /aggregate/job/:jobId/progress
    if (segments[3] === 'progress') {
      return handleJobProgress(req, res, jobId);
    }

    // GET /aggregate/job/:jobId/export
    if (segments[3] === 'export') {
      return handleExport(req, res, jobId, searchParams);
    }

    return handleGetJob(req, res, jobId);
  }

  sendError(res, 404, 'Ruta no encontrada');
}

module.exports = { handleAggregateRequest };
