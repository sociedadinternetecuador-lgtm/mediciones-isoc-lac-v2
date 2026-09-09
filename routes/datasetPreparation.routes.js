'use strict';

/**
 * Rutas de "Preparación de datasets de dominios" — Mediciones ISOC LAC.
 *
 * Etapas habilitadas: Fuente → Carga → Normalización → Validación DNS.
 * NO incluye generación de reporte final, ZIP ni PDF (sección "Resultados y
 * descarga") — corresponde a una iteración posterior.
 *
 *  POST /dataset/normalize
 *    Body: { text: string, tld: string }
 *    Normaliza el archivo (parse_input) y clasifica por sufijo usando la
 *    Public Suffix List, sección ICANN (misma metodología que
 *    validador/validar_dominios_isoc_lac.py). No ejecuta consultas DNS.
 *
 *  POST /dataset/validate-dns
 *    Body: { domains: string[] }
 *    Inicia un job de validación DNS (preflight -> primera pasada -> reintento
 *    REVIEW), réplica de la lógica DNS del validador de referencia. Responde
 *    de inmediato con { jobId, progressUrl, statusUrl } — el job corre en
 *    segundo plano (un dataset completo puede tardar varios minutos).
 *
 *  GET /dataset/validate-dns/:jobId/progress
 *    SSE — progreso en tiempo real (fase, dominios procesados, total).
 *
 *  GET /dataset/validate-dns/:jobId
 *    Estado y resumen (conteos VALID/NXDOMAIN/REVIEW, subtipos REVIEW,
 *    discrepancias, resultado por dominio) una vez completado.
 */

const crypto = require('crypto');
const { parseDatasetText } = require('../logic/validators/datasetDomains.validator');
const { getPublicSuffixList } = require('../logic/adapters/publicSuffixList.adapter');
const {
  startDnsValidationJob, getJob, addListener, removeListener,
} = require('../logic/orchestrators/dnsValidationJob.orchestrator');
const { buildZip } = require('../logic/exporters/zip.writer');

const MAX_DNS_DOMAINS = 50000;

const DOWNLOADABLE_CONTENT_TYPES = {
  '.txt': 'text/plain; charset=utf-8',
  '.csv': 'text/csv; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
};

const MAX_UPLOAD_CHARS = 20 * 1024 * 1024; // 20 MB de texto

function sha256OfLines(lines) {
  const payload = lines.length ? lines.join('\n') + '\n' : '';
  return crypto.createHash('sha256').update(payload, 'utf-8').digest('hex');
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => { data += c; });
    req.on('end', () => {
      try {
        resolve(JSON.parse(data || '{}'));
      } catch {
        resolve({});
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}

async function handleNormalize(req, res) {
  const body = await readBody(req);
  const text = typeof body.text === 'string' ? body.text : '';
  const tld = String(body.tld || '').trim().toLowerCase().replace(/^\./, '');

  if (!text) {
    return sendJson(res, 400, { error: 'empty_file', message: 'El archivo está vacío.' });
  }
  if (text.length > MAX_UPLOAD_CHARS) {
    return sendJson(res, 400, { error: 'file_too_large', message: 'El archivo excede el tamaño máximo admitido (20 MB de texto).' });
  }
  if (!/^[a-z]{2,24}$/.test(tld)) {
    return sendJson(res, 400, { error: 'invalid_tld', message: 'ccTLD inválido. Use solo letras, por ejemplo: ec' });
  }

  let pslResult;
  try {
    pslResult = await getPublicSuffixList();
  } catch (error) {
    return sendJson(res, 502, {
      error: 'psl_unavailable',
      message: 'No se pudo obtener la Public Suffix List (ICANN) y no hay copia en caché local.',
    });
  }

  const { normalized, rejected, rejectedCounts, stats } = parseDatasetText(text, tld);

  const suffixCounts = new Map();
  for (const domain of normalized) {
    const suffix = '.' + pslResult.psl.publicSuffix(domain);
    suffixCounts.set(suffix, (suffixCounts.get(suffix) || 0) + 1);
  }

  const suffixSummary = Array.from(suffixCounts.entries())
    .map(([suffix, count]) => ({ suffix, count }))
    .sort((a, b) => b.count - a.count || a.suffix.localeCompare(b.suffix));

  sendJson(res, 200, {
    tld: '.' + tld,
    stats: {
      raw_lines: stats.raw_lines,
      empty: stats.empty,
      duplicates: stats.duplicates,
      rejected: stats.rejected,
      normalized: stats.normalized,
      suffixes_detected: suffixSummary.length,
    },
    normalized,
    normalized_sha256: sha256OfLines(normalized),
    rejected,
    rejected_reason_counts: rejectedCounts,
    suffix_summary: suffixSummary,
    psl: {
      origin: pslResult.origin,
      sha256: pslResult.sha256,
      fetched_at: pslResult.fetchedAt,
      source_url: pslResult.sourceUrl,
    },
  });
}

async function handleValidateDnsStart(req, res) {
  const body = await readBody(req);
  const domains = Array.isArray(body.domains) ? body.domains.map((d) => String(d).trim()).filter(Boolean) : [];

  if (!domains.length) {
    return sendJson(res, 400, { error: 'empty_domains', message: 'Se requiere al menos un dominio.' });
  }
  if (domains.length > MAX_DNS_DOMAINS) {
    return sendJson(res, 400, {
      error: 'too_many_domains',
      message: `Máximo ${MAX_DNS_DOMAINS.toLocaleString('es-EC')} dominios por job.`,
    });
  }

  // Contexto de Fuente/Carga/Normalización — se guarda tal cual (sin
  // recalcular nada) para que "Resultados y descarga" pueda construir el
  // manifest/CSV/ZIP sin volver a tocar DNS ni la normalización.
  const context = {
    source: body.source && typeof body.source === 'object' ? {
      name: body.source.name || null,
      size: typeof body.source.size === 'number' ? body.source.size : null,
      sha256: body.source.sha256 || null,
      date: body.source.date || null,
    } : {},
    tld: String(body.tld || '').trim().toLowerCase().replace(/^\./, ''),
    normalize: body.normalize && typeof body.normalize === 'object' ? {
      stats: body.normalize.stats || {},
      rejected: Array.isArray(body.normalize.rejected) ? body.normalize.rejected : [],
      normalized: domains,
      normalizedSha256: body.normalize.normalized_sha256 || null,
      psl: body.normalize.psl || {},
    } : { normalized: domains },
  };

  const job = startDnsValidationJob(domains, context);

  sendJson(res, 202, {
    jobId: job.jobId,
    total: job.total,
    progressUrl: `/dataset/validate-dns/${job.jobId}/progress`,
    statusUrl: `/dataset/validate-dns/${job.jobId}`,
  });
}

function handleDownloadFile(req, res, jobId, filename) {
  const job = getJob(jobId);
  if (!job) return sendJson(res, 404, { error: 'job_not_found', message: 'Job no encontrado.' });
  if (job.status !== 'completed' || !job.resultsPackage) {
    return sendJson(res, 409, { error: 'not_ready', message: 'La corrida todavía no tiene resultados listos para descargar.' });
  }
  if (!job.resultsPackage.integrity.passed) {
    return sendJson(res, 422, {
      error: 'integrity_failed',
      message: 'Esta corrida quedó marcada como inconsistente (integrity.passed=false); no se sirven descargas de un paquete que no pasó el control de integridad.',
      checks: job.resultsPackage.integrity.checks,
    });
  }

  const decodedName = decodeURIComponent(filename);
  const content = job.resultsPackage.files[decodedName];
  if (content === undefined) {
    return sendJson(res, 404, { error: 'file_not_found', message: `"${decodedName}" no existe en esta corrida.` });
  }

  const ext = decodedName.slice(decodedName.lastIndexOf('.'));
  const contentType = DOWNLOADABLE_CONTENT_TYPES[ext] || 'application/octet-stream';
  const baseName = decodedName.includes('/') ? decodedName.split('/').pop() : decodedName;

  res.writeHead(200, {
    'Content-Type': contentType,
    'Content-Disposition': `attachment; filename="${baseName}"`,
  });
  res.end(content);
}

function handleDownloadZip(req, res, jobId) {
  const job = getJob(jobId);
  if (!job) return sendJson(res, 404, { error: 'job_not_found', message: 'Job no encontrado.' });
  if (job.status !== 'completed' || !job.resultsPackage) {
    return sendJson(res, 409, { error: 'not_ready', message: 'La corrida todavía no tiene resultados listos para descargar.' });
  }
  if (!job.resultsPackage.integrity.passed) {
    return sendJson(res, 422, {
      error: 'integrity_failed',
      message: 'Esta corrida quedó marcada como inconsistente (integrity.passed=false); no se genera el ZIP de un paquete que no pasó el control de integridad.',
      checks: job.resultsPackage.integrity.checks,
    });
  }

  // El ZIP se genera UNA vez (a partir de los mismos bytes ya congelados en
  // job.resultsPackage.files) y se cachea — no reconstruye ni reclasifica.
  if (!job.zipBuffer) {
    const entries = Object.entries(job.resultsPackage.files).map(([name, content]) => ({ name, content }));
    job.zipBuffer = buildZip(entries);
  }

  res.writeHead(200, {
    'Content-Type': 'application/zip',
    'Content-Disposition': `attachment; filename="mediciones-resultados-${jobId.slice(0, 8)}.zip"`,
    'Content-Length': job.zipBuffer.length,
  });
  res.end(job.zipBuffer);
}

function handleValidateDnsStatus(req, res, jobId) {
  const job = getJob(jobId);
  if (!job) return sendJson(res, 404, { error: 'job_not_found', message: 'Job no encontrado.' });

  // No se envía resultsPackage.files (contenido crudo, puede pesar varios MB
  // en datasets grandes) — solo metadata/integridad/hashes, que es lo que la
  // pantalla necesita. Los bytes reales se sirven por /download y /download-zip.
  let resultsPackage;
  if (job.resultsPackage) {
    const { files, ...rest } = job.resultsPackage;
    resultsPackage = { ...rest, file_list: Object.keys(files) };
  }

  const { zipBuffer, resultsPackage: _rawPackage, ...jobFields } = job;
  sendJson(res, 200, { ...jobFields, resultsPackage, resultsPackageError: job.resultsPackageError || null });
}

function handleValidateDnsProgress(req, res, jobId) {
  const job = getJob(jobId);
  if (!job) return sendJson(res, 404, { error: 'job_not_found', message: 'Job no encontrado.' });

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });

  const write = (msg) => res.write(msg);
  addListener(jobId, write);

  res.write(`data: ${JSON.stringify({ event: 'current', ...job.progress, status: job.status })}\n\n`);

  if (job.status === 'completed' || job.status === 'failed') {
    res.write(`data: ${JSON.stringify({ event: 'done', status: job.status })}\n\n`);
    res.end();
    return;
  }

  const heartbeat = setInterval(() => {
    try {
      res.write(': ping\n\n');
    } catch {
      clearInterval(heartbeat);
    }
  }, 15000);

  req.on('close', () => {
    clearInterval(heartbeat);
    removeListener(jobId, write);
  });
}

async function handleDatasetRequest(req, res, url) {
  const segments = url.pathname.split('/').filter(Boolean);
  // segments[0] = 'dataset'

  if (req.method === 'POST' && segments[1] === 'normalize') {
    return handleNormalize(req, res);
  }

  if (segments[1] === 'validate-dns') {
    if (req.method === 'POST' && !segments[2]) {
      return handleValidateDnsStart(req, res);
    }
    if (req.method === 'GET' && segments[2] && segments[3] === 'progress') {
      return handleValidateDnsProgress(req, res, segments[2]);
    }
    if (req.method === 'GET' && segments[2] && segments[3] === 'download-zip') {
      return handleDownloadZip(req, res, segments[2]);
    }
    if (req.method === 'GET' && segments[2] && segments[3] === 'download' && segments[4]) {
      return handleDownloadFile(req, res, segments[2], segments[4]);
    }
    if (req.method === 'GET' && segments[2]) {
      return handleValidateDnsStatus(req, res, segments[2]);
    }
  }

  sendJson(res, 404, { error: 'not_found', message: 'Ruta no encontrada.' });
}

module.exports = { handleDatasetRequest };
