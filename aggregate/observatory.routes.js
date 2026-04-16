'use strict';

/**
 * Observatory Routes — Mediciones ISOC LAC
 *
 * Endpoints del observatorio DNSSEC:
 *
 *  POST /obs/analyze
 *    Inicia análisis. Detecta duplicados automáticamente.
 *    Body: { label, domains, engine: 'doh'|'zonemaster', config? }
 *
 *  GET  /obs/job/:jobId
 *    Estado y resumen del análisis.
 *
 *  GET  /obs/job/:jobId/progress
 *    SSE — progreso en tiempo real.
 *
 *  GET  /obs/job/:jobId/export?format=json|csv|html|pdf
 *    Exportar resultados.
 *
 *  GET  /obs/library
 *    Biblioteca pública de reportes disponibles.
 *
 *  GET  /obs/history?country=ec&engine=zonemaster
 *    Histórico de análisis (con filtros opcionales).
 *
 *  GET  /obs/evolution/:country
 *    Datos de evolución temporal para un país (para gráfica).
 *
 *  GET  /obs/zonemaster/status
 *    Verifica si Zonemaster está disponible.
 */

const {
  startAnalysis, addSseClient, removeSseClient,
  checkZonmasterAvailability, ENGINES,
} = require('./orchestrator');

const {
  readAnalysis, listAnalyses, getEvolutionData, getPublicLibrary,
} = require('./history.store');

const { toJson, resultsToCsv, buildHtmlReport } = require('./exporters/exporters');

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => { data += c; });
    req.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
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

function parseDomains(body) {
  if (Array.isArray(body.domains)) return body.domains.map(d => String(d).trim()).filter(Boolean);
  if (typeof body.text === 'string') return body.text.split(/[\n,;]+/).map(d => d.trim()).filter(Boolean);
  return [];
}

// ─── POST /obs/analyze ────────────────────────────────────────────────────────

async function handleAnalyze(req, res) {
  const body    = await readBody(req);
  const domains = parseDomains(body);
  const label   = String(body.label || body.country || '').trim() || 'sin etiqueta';
  const engine  = body.engine === 'zonemaster' ? ENGINES.ZONEMASTER : ENGINES.DOH;
  const config  = body.config || {};

  if (domains.length === 0) return sendError(res, 400, 'Se requiere al menos un dominio');
  if (domains.length > 1000) return sendError(res, 400, 'Máximo 1000 dominios por análisis');

  const result = await startAnalysis({ label, country: label, domains, engine, config });

  if (result.duplicate) {
    return sendJson(res, 200, {
      duplicate: true,
      message:   result.message,
      previous:  result.previousAnalysis,
      actions: {
        viewReport: `/obs/job/${result.previousAnalysis.jobId}`,
        exportHtml: `/obs/job/${result.previousAnalysis.jobId}/export?format=html`,
        exportCsv:  `/obs/job/${result.previousAnalysis.jobId}/export?format=csv`,
        runAgain:   'Envía force: true en el body para forzar un nuevo análisis',
      },
    });
  }

  sendJson(res, 202, {
    ...result,
    progressUrl: `/obs/job/${result.jobId}/progress`,
    statusUrl:   `/obs/job/${result.jobId}`,
    exportUrl:   `/obs/job/${result.jobId}/export?format=html`,
    note: engine === ENGINES.ZONEMASTER
      ? `Análisis Zonemaster iniciado. Estimado: ${result.estimatedMinutes} minutos. Puedes cerrar esta ventana y consultar el estado más tarde.`
      : `Análisis DoH iniciado. Estimado: ${result.estimatedMinutes} minutos.`,
  });
}

// ─── GET /obs/job/:jobId ──────────────────────────────────────────────────────

function handleGetJob(req, res, jobId) {
  const job = readAnalysis(jobId);
  if (!job) return sendError(res, 404, 'Análisis no encontrado');
  const { results: _, errors: __, domains: ___, ...summary } = job;
  sendJson(res, 200, {
    ...summary,
    exportUrls: job.status === 'completed' ? {
      html: `/obs/job/${jobId}/export?format=html`,
      csv:  `/obs/job/${jobId}/export?format=csv`,
      json: `/obs/job/${jobId}/export?format=json`,
    } : null,
  });
}

// ─── GET /obs/job/:jobId/progress (SSE) ──────────────────────────────────────

function handleProgress(req, res, jobId) {
  const job = readAnalysis(jobId);
  if (!job) return sendError(res, 404, 'Análisis no encontrado');

  res.writeHead(200, {
    'Content-Type':  'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection':    'keep-alive',
    'X-Accel-Buffering': 'no',
  });

  const write = msg => res.write(msg);
  addSseClient(jobId, write);

  res.write(`data: ${JSON.stringify({
    event: 'current', ...job.progress, status: job.status
  })}\n\n`);

  if (['completed', 'failed'].includes(job.status)) {
    res.write(`data: ${JSON.stringify({ event: 'done', status: job.status })}\n\n`);
    res.end(); return;
  }

  const hb = setInterval(() => {
    try { res.write(': ping\n\n'); } catch { clearInterval(hb); }
  }, 15000);

  req.on('close', () => {
    clearInterval(hb);
    removeSseClient(jobId, write);
  });
}

// ─── GET /obs/job/:jobId/export ───────────────────────────────────────────────

function handleExport(req, res, jobId, searchParams) {
  const job = readAnalysis(jobId);
  if (!job) return sendError(res, 404, 'Análisis no encontrado');
  if (job.status !== 'completed') return sendError(res, 409, 'El análisis aún no terminó');

  const format = searchParams.get('format') || 'html';
  const slug   = `${(job.country || 'analysis').replace(/[^a-z0-9]/gi, '-')}-${job.jobId.slice(0, 8)}`;

  if (format === 'csv') {
    res.writeHead(200, {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': `attachment; filename="dnssec-${slug}.csv"`,
    });
    return res.end(resultsToCsv(job.results || []));
  }

  if (format === 'json') {
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': `attachment; filename="dnssec-${slug}.json"`,
    });
    return res.end(toJson({
      engine: job.engine,
      label:  job.label,
      analyzedAt: job.completedAt,
      aggregate:  job.aggregate,
      recommendations: job.recommendations,
      results: job.results || [],
      errors:  job.errors  || [],
    }));
  }

  // HTML — reporte ejecutivo completo
  const html = buildHtmlReport({
    country:         job.label || job.country,
    aggregate:       job.aggregate,
    recommendations: job.recommendations,
    results:         job.results || [],
    engine:          job.engine,
    analyzedAt:      job.completedAt,
  });
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Disposition': `inline; filename="reporte-dnssec-${slug}.html"`,
  });
  res.end(html);
}

// ─── GET /obs/library ─────────────────────────────────────────────────────────

function handleLibrary(req, res) {
  sendJson(res, 200, getPublicLibrary());
}

// ─── GET /obs/history ─────────────────────────────────────────────────────────

function handleHistory(req, res, searchParams) {
  const country = searchParams.get('country') || null;
  const engine  = searchParams.get('engine')  || null;
  const limit   = parseInt(searchParams.get('limit')) || 50;
  sendJson(res, 200, { analyses: listAnalyses({ country, engine, limit }) });
}

// ─── GET /obs/evolution/:country ─────────────────────────────────────────────

function handleEvolution(req, res, country) {
  const data = getEvolutionData(country);
  sendJson(res, 200, { country, dataPoints: data });
}

// ─── GET /obs/zonemaster/status ───────────────────────────────────────────────

async function handleZonemasterStatus(req, res) {
  const result = await checkZonmasterAvailability();
  sendJson(res, result.ok ? 200 : 503, {
    available: result.ok,
    version:   result.version,
    error:     result.error,
    endpoint:  process.env.ZM_ENDPOINT || 'https://zonemaster.net/api',
    mode:      process.env.ZM_USERNAME ? 'authenticated (batch nativo)' : 'público (rate-limited)',
  });
}

// ─── Router ───────────────────────────────────────────────────────────────────

async function handleObservatoryRequest(req, res, url) {
  const { pathname, searchParams } = url;
  const segments = pathname.split('/').filter(Boolean);
  // segments[0] = 'obs'

  if (req.method === 'POST' && segments[1] === 'analyze') return handleAnalyze(req, res);
  if (req.method === 'GET'  && segments[1] === 'library')  return handleLibrary(req, res);
  if (req.method === 'GET'  && segments[1] === 'history')  return handleHistory(req, res, searchParams);

  if (req.method === 'GET' && segments[1] === 'zonemaster' && segments[2] === 'status') {
    return handleZonemasterStatus(req, res);
  }

  if (req.method === 'GET' && segments[1] === 'evolution' && segments[2]) {
    return handleEvolution(req, res, segments[2]);
  }

  if (req.method === 'GET' && segments[1] === 'job' && segments[2]) {
    const jobId = segments[2];
    if (segments[3] === 'progress') return handleProgress(req, res, jobId);
    if (segments[3] === 'export')   return handleExport(req, res, jobId, searchParams);
    return handleGetJob(req, res, jobId);
  }

  sendError(res, 404, 'Ruta no encontrada');
}

module.exports = { handleObservatoryRequest };
