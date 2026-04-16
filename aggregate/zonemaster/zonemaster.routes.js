'use strict';

/**
 * Zonemaster Batch Routes — Mediciones ISOC LAC
 *
 * Endpoints:
 *
 *  POST /zm/analyze
 *    Inicia análisis batch con Zonemaster.
 *    Body: { label, domains: [...], config?: {} }
 *    Devuelve: { jobId, status: 'started', total }
 *
 *  GET  /zm/job/:jobId
 *    Estado y resumen del job.
 *
 *  GET  /zm/job/:jobId/progress
 *    Stream SSE con progreso en tiempo real.
 *
 *  GET  /zm/job/:jobId/export?format=json|csv|html
 *    Exporta resultados.
 *
 *  GET  /zm/jobs
 *    Lista todos los jobs guardados.
 *
 *  GET  /zm/ping
 *    Verifica conectividad con el servidor Zonemaster.
 */

const { analyzeBatch, ping, DEFAULT_CONFIG } = require('./zonemaster.adapter');
const { aggregateCountry }    = require('../aggregators/country.aggregator');
const { getRecommendations }  = require('../aggregators/policy.recommender');
const { toJson, resultsToCsv, buildHtmlReport } = require('../exporters/exporters');
const { createJob, updateJob, readJob, listJobs } = require('../batch/session.store');

// SSE clients activos
const sseClients = new Map();

function broadcast(jobId, data) {
  const clients = sseClients.get(jobId);
  if (!clients) return;
  const msg = `data: ${JSON.stringify(data)}\n\n`;
  for (const write of clients) {
    try { write(msg); } catch {}
  }
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

function sendError(res, status, msg) {
  sendJson(res, status, { error: msg });
}

// ─── Iniciar batch ────────────────────────────────────────────────────────────

async function handleStartAnalysis(req, res) {
  const body    = await readBody(req);
  const domains = Array.isArray(body.domains)
    ? body.domains.map(d => String(d).trim()).filter(Boolean)
    : [];
  const label   = String(body.label || body.country || '').trim() || 'sin etiqueta';
  const config  = body.config || {};

  if (domains.length === 0) {
    return sendError(res, 400, 'Se requiere al menos un dominio en "domains"');
  }

  const job = createJob({ country: label, domains, meta: { engine: 'zonemaster', config } });
  updateJob(job.jobId, { status: 'running' });

  // Correr en background
  setImmediate(() => runZonemasterBatch(job.jobId, domains, label, config));

  sendJson(res, 202, {
    jobId: job.jobId,
    status: 'started',
    label,
    totalDomains: domains.length,
    engine: 'zonemaster',
    note: 'Análisis Zonemaster: 30–90 segundos por dominio. Use /progress para seguir el avance.',
    progressUrl: `/zm/job/${job.jobId}/progress`,
    statusUrl:   `/zm/job/${job.jobId}`,
  });
}

async function runZonemasterBatch(jobId, domains, label, config) {
  try {
    const zmConfig = { ...DEFAULT_CONFIG, ...config };

    const { results, errors } = await analyzeBatch(domains, zmConfig, (progress) => {
      updateJob(jobId, { progress });
      broadcast(jobId, { event: 'progress', ...progress });
    });

    const aggregate      = aggregateCountry({ country: label, results, errors });
    const recommendations = getRecommendations(aggregate);

    updateJob(jobId, {
      status: 'completed',
      results,
      errors,
      aggregate,
      recommendations,
      progress: { processed: domains.length, total: domains.length, percent: 100 },
    });

    broadcast(jobId, { event: 'done', aggregate: aggregate.summary });
    sseClients.delete(jobId);

  } catch (err) {
    updateJob(jobId, { status: 'failed', error: err.message });
    broadcast(jobId, { event: 'error', message: err.message });
    sseClients.delete(jobId);
  }
}

// ─── Estado del job ───────────────────────────────────────────────────────────

function handleGetJob(req, res, jobId) {
  const job = readJob(jobId);
  if (!job) return sendError(res, 404, 'Job no encontrado');
  const { results: _, ...summary } = job;
  sendJson(res, 200, summary);
}

// ─── SSE progreso ─────────────────────────────────────────────────────────────

function handleProgress(req, res, jobId) {
  const job = readJob(jobId);
  if (!job) return sendError(res, 404, 'Job no encontrado');

  res.writeHead(200, {
    'Content-Type':  'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection':    'keep-alive',
    'X-Accel-Buffering': 'no',
  });

  const write = msg => res.write(msg);
  if (!sseClients.has(jobId)) sseClients.set(jobId, new Set());
  sseClients.get(jobId).add(write);

  res.write(`data: ${JSON.stringify({ event: 'current', ...job.progress, status: job.status })}\n\n`);

  if (job.status === 'completed' || job.status === 'failed') {
    res.write(`data: ${JSON.stringify({ event: 'done', status: job.status })}\n\n`);
    res.end();
    return;
  }

  const hb = setInterval(() => {
    try { res.write(': ping\n\n'); } catch { clearInterval(hb); }
  }, 15000);

  req.on('close', () => {
    clearInterval(hb);
    sseClients.get(jobId)?.delete(write);
  });
}

// ─── Exportar ─────────────────────────────────────────────────────────────────

function handleExport(req, res, jobId, searchParams) {
  const job = readJob(jobId);
  if (!job) return sendError(res, 404, 'Job no encontrado');
  if (job.status !== 'completed') return sendError(res, 409, 'El job aún no terminó');

  const format = searchParams.get('format') || 'json';
  const slug   = `${job.country}-${job.jobId.slice(0, 8)}`;

  if (format === 'csv') {
    res.writeHead(200, {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': `attachment; filename="dnssec-zm-${slug}.csv"`,
    });
    // Adaptar resultados Zonemaster al formato CSV del sistema
    const adapted = (job.results || []).map(r => ({
      domain: r.domain,
      dnssec: r.dnssec,
    }));
    return res.end(resultsToCsv(adapted));
  }

  if (format === 'html') {
    const html = buildHtmlReport({
      country:         job.country,
      aggregate:       job.aggregate,
      recommendations: job.recommendations,
      results:         job.results || [],
    });
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(html);
  }

  // JSON
  res.writeHead(200, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Disposition': `attachment; filename="dnssec-zm-${slug}.json"`,
  });
  res.end(toJson({
    engine: 'zonemaster',
    job: { ...job, results: job.results || [] },
  }));
}

// ─── Lista de jobs ────────────────────────────────────────────────────────────

function handleListJobs(req, res) {
  sendJson(res, 200, { jobs: listJobs() });
}

// ─── Ping Zonemaster ──────────────────────────────────────────────────────────

async function handlePing(req, res) {
  const result = await ping();
  sendJson(res, result.ok ? 200 : 503, result);
}

// ─── Router ───────────────────────────────────────────────────────────────────

async function handleZonemasterRequest(req, res, url) {
  const { pathname, searchParams } = url;
  const segments = pathname.split('/').filter(Boolean);
  // segments[0] = 'zm'

  if (req.method === 'GET' && segments[1] === 'ping') {
    return handlePing(req, res);
  }

  if (req.method === 'POST' && segments[1] === 'analyze') {
    return handleStartAnalysis(req, res);
  }

  if (req.method === 'GET' && segments[1] === 'jobs') {
    return handleListJobs(req, res);
  }

  if (req.method === 'GET' && segments[1] === 'job' && segments[2]) {
    const jobId = segments[2];
    if (segments[3] === 'progress') return handleProgress(req, res, jobId);
    if (segments[3] === 'export')   return handleExport(req, res, jobId, searchParams);
    return handleGetJob(req, res, jobId);
  }

  sendError(res, 404, 'Ruta no encontrada');
}

module.exports = { handleZonemasterRequest };
