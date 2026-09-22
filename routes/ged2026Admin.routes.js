'use strict';

/**
 * Rutas administrativas GED2026 — montadas desde routes/admin.routes.js
 * bajo /admin/api/ged2026/..., con sesión ya verificada por el llamador
 * (mismo nivel de acceso que Blog/Eventos/Materiales: cualquier admin con
 * sesión, no exige super_admin).
 *
 *  GET   /admin/api/ged2026/project
 *  PUT   /admin/api/ged2026/project                    { current_phase }
 *  GET   /admin/api/ged2026/dashboard
 *  GET   /admin/api/ged2026/domains
 *  POST  /admin/api/ged2026/domains                    alta manual de un dominio
 *  PUT   /admin/api/ged2026/domains/:id
 *  POST  /admin/api/ged2026/domains/import             { csv } (texto CSV en el body JSON)
 *  POST  /admin/api/ged2026/domains/bulk-update        { csv } (CSV con encabezado: domain + columnas a tocar)
 *  POST  /admin/api/ged2026/domains/validate-liveness  { ids?: string[] }
 *  GET   /admin/api/ged2026/domains/validate-liveness/:jobId
 */

const store = require('../logic/adapters/ged2026Store.adapter');
const { normalizeCandidateDomain } = require('../logic/validators/ged2026Domains.validator');
const { validateGed2026DomainCreate, validateGed2026DomainUpdate } = require('../logic/validators/ged2026DomainInput.validator');
const { parseGed2026Csv } = require('../logic/processors/ged2026CsvImport.processor');
const { parseGed2026BulkUpdateCsv } = require('../logic/processors/ged2026BulkUpdate.processor');
const { startLivenessJob, getLivenessJob } = require('../logic/orchestrators/ged2026LivenessJob.orchestrator');
const { getPublicSuffixList } = require('../logic/adapters/publicSuffixList.adapter');
const { ATRIBUTOS_RELEVANCIA_FIELDS } = require('../config/ged2026.constants');

// El CSV de importación puede pesar más que un post de blog — límite propio,
// no el de admin.routes.js (cada módulo de rutas define el suyo, mismo
// patrón que ya existe en el proyecto).
const MAX_BODY_BYTES = 2 * 1024 * 1024;

function sendJson(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    let tooLarge = false;
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > MAX_BODY_BYTES) { tooLarge = true; req.destroy(); }
    });
    req.on('end', () => {
      if (tooLarge) return reject(new Error('payload_too_large'));
      try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); }
    });
    req.on('error', reject);
  });
}

// ─── Proyecto ───────────────────────────────────────────────────────────────

async function handleProject(req, res) {
  if (req.method === 'GET') {
    return sendJson(res, 200, { project: store.getProject() });
  }
  if (req.method === 'PUT') {
    let body;
    try { body = await readJsonBody(req); } catch { return sendJson(res, 400, { error: 'invalid_body' }); }
    try {
      const project = store.setProjectPhase(body.current_phase);
      return sendJson(res, 200, { project });
    } catch (error) {
      return sendJson(res, 400, { error: 'invalid_phase', message: error.message });
    }
  }
  return sendJson(res, 405, { error: 'method_not_allowed' });
}

// ─── Dashboard interno ──────────────────────────────────────────────────────

async function handleDashboard(req, res) {
  if (req.method !== 'GET') return sendJson(res, 405, { error: 'method_not_allowed' });

  const domains = store.listDomains();
  const project = store.getProject();

  let psl = null;
  try {
    ({ psl } = await getPublicSuffixList());
  } catch {
    psl = null;
  }

  const by_estado_seleccion = {};
  const by_estado_validacion = {};
  const by_tld = {};
  const by_categoria = {};

  for (const d of domains) {
    by_estado_seleccion[d.estado_seleccion] = (by_estado_seleccion[d.estado_seleccion] || 0) + 1;
    by_estado_validacion[d.estado_validacion] = (by_estado_validacion[d.estado_validacion] || 0) + 1;
    const categoria = d.categoria || 'sin_categoria';
    by_categoria[categoria] = (by_categoria[categoria] || 0) + 1;
    const tld = psl && d.normalized_domain ? psl.publicSuffix(d.normalized_domain) : 'desconocido';
    by_tld[tld] = (by_tld[tld] || 0) + 1;
  }

  return sendJson(res, 200, {
    total_domains: domains.length,
    current_phase: project.current_phase,
    last_updated: project.last_updated,
    by_estado_seleccion,
    by_estado_validacion,
    by_tld,
    by_categoria,
  });
}

// ─── Dominios ───────────────────────────────────────────────────────────────

async function handleDomainsCollection(req, res) {
  if (req.method === 'GET') {
    return sendJson(res, 200, { items: store.listDomains() });
  }
  if (req.method === 'POST') {
    let body;
    try { body = await readJsonBody(req); } catch { return sendJson(res, 400, { error: 'invalid_body' }); }

    const normalization = await normalizeCandidateDomain(body.domain);
    if (!normalization.ok) {
      return sendJson(res, 400, { error: 'domain_invalid', reason: normalization.reason });
    }
    if (store.findByNormalizedDomain(normalization.normalized_domain)) {
      return sendJson(res, 409, { error: 'domain_duplicate' });
    }

    const { errors, data } = validateGed2026DomainCreate(body);
    if (errors.length) return sendJson(res, 400, { error: 'validation_failed', fields: errors });

    const item = store.createDomain({
      ...data,
      domain: String(body.domain).trim(),
      normalized_domain: normalization.normalized_domain,
    });
    return sendJson(res, 201, { item });
  }
  return sendJson(res, 405, { error: 'method_not_allowed' });
}

async function handleDomainItem(req, res, id) {
  if (req.method === 'PUT') {
    const existing = store.getDomain(id);
    if (!existing) return sendJson(res, 404, { error: 'not_found' });

    let body;
    try { body = await readJsonBody(req); } catch { return sendJson(res, 400, { error: 'invalid_body' }); }

    const { errors, data } = validateGed2026DomainUpdate(existing, body);
    if (errors.length) return sendJson(res, 400, { error: 'validation_failed', fields: errors });

    const item = store.updateDomain(id, data);
    return sendJson(res, 200, { item });
  }
  return sendJson(res, 405, { error: 'method_not_allowed' });
}

// ─── Importación CSV ────────────────────────────────────────────────────────

async function handleImport(req, res) {
  if (req.method !== 'POST') return sendJson(res, 405, { error: 'method_not_allowed' });

  let body;
  try { body = await readJsonBody(req); } catch { return sendJson(res, 400, { error: 'invalid_body' }); }

  const { rows, skippedBlankLines } = parseGed2026Csv(body.csv || '');
  const report = { importados: 0, duplicados: 0, invalidos: 0, omitidos: skippedBlankLines, details: [] };
  const seenInBatch = new Set();

  for (const row of rows) {
    if (!row.domain) { report.omitidos += 1; continue; }

    const normalization = await normalizeCandidateDomain(row.domain);
    if (!normalization.ok) {
      report.invalidos += 1;
      report.details.push({ domain: row.domain, status: 'invalido', reason: normalization.reason });
      continue;
    }

    if (seenInBatch.has(normalization.normalized_domain) || store.findByNormalizedDomain(normalization.normalized_domain)) {
      report.duplicados += 1;
      report.details.push({ domain: row.domain, status: 'duplicado' });
      continue;
    }
    seenInBatch.add(normalization.normalized_domain);

    store.createDomain({
      domain: row.domain,
      normalized_domain: normalization.normalized_domain,
      categoria: row.category || null,
      fuente: row.source || 'importacion_csv',
      notas: row.notes || null,
    });
    report.importados += 1;
  }

  return sendJson(res, 200, report);
}

// ─── Actualización masiva (upsert por lote) ────────────────────────────────
//
// Complementa a /import (que solo CREA y rechaza duplicados): aquí, si el
// dominio ya existe en el universo, se ACTUALIZA con las columnas
// presentes en el CSV; si no existe, se crea (con los mismos datos que
// vengan). Pensado para curación por lote — priorizar instituciones
// nacionales conocidas, marcar exclusiones, anotar fuente del criterio —
// sin tener que editar dominio por dominio en el panel.
//
// Encabezado obligatorio (a diferencia de /import): columnas reconocidas
// — domain (única obligatoria), estado_seleccion, exclusion_reason,
// tipo_institucion, categoria, notas, fuente (solo aplica al crear), y
// cualquiera de los 7 campos de atributos_relevancia (traffic_source,
// traffic_rank, traffic_score, transactionality_level,
// institutional_relevance, user_reach, critical_service) — cada uno se
// guarda como { value, method: 'clasificado_manual' }. Columnas no
// reconocidas o vacías se ignoran fila por fila.

function buildBulkUpdatePatch(row) {
  const patch = {};
  if (row.estado_seleccion) patch.estado_seleccion = row.estado_seleccion;
  if (row.exclusion_reason) patch.exclusion_reason = row.exclusion_reason;
  if (row.tipo_institucion) patch.tipo_institucion = row.tipo_institucion;
  if (row.categoria) patch.categoria = row.categoria;
  if (row.notas) patch.notas = row.notas;

  const atributos_relevancia = {};
  for (const field of ATRIBUTOS_RELEVANCIA_FIELDS) {
    if (row[field]) atributos_relevancia[field] = { value: row[field], method: 'clasificado_manual' };
  }
  if (Object.keys(atributos_relevancia).length) patch.atributos_relevancia = atributos_relevancia;

  return patch;
}

async function handleBulkUpdate(req, res) {
  if (req.method !== 'POST') return sendJson(res, 405, { error: 'method_not_allowed' });

  let body;
  try { body = await readJsonBody(req); } catch { return sendJson(res, 400, { error: 'invalid_body' }); }

  const { rows, skippedBlankLines } = parseGed2026BulkUpdateCsv(body.csv || '');
  const report = { actualizados: 0, creados: 0, invalidos: 0, omitidos: skippedBlankLines, details: [] };

  for (const row of rows) {
    if (!row.domain) { report.omitidos += 1; continue; }

    const normalization = await normalizeCandidateDomain(row.domain);
    if (!normalization.ok) {
      report.invalidos += 1;
      report.details.push({ domain: row.domain, status: 'invalido', reason: normalization.reason });
      continue;
    }

    const patch = buildBulkUpdatePatch(row);
    const existing = store.findByNormalizedDomain(normalization.normalized_domain);

    if (existing) {
      const { errors, data } = validateGed2026DomainUpdate(existing, patch);
      if (errors.length) {
        report.invalidos += 1;
        report.details.push({ domain: row.domain, status: 'invalido', fields: errors });
        continue;
      }
      store.updateDomain(existing.id, data);
      report.actualizados += 1;
    } else {
      const { errors, data } = validateGed2026DomainCreate(patch);
      if (errors.length) {
        report.invalidos += 1;
        report.details.push({ domain: row.domain, status: 'invalido', fields: errors });
        continue;
      }
      store.createDomain({
        ...data,
        domain: row.domain.trim(),
        normalized_domain: normalization.normalized_domain,
        categoria: data.categoria || normalization.suffix,
        fuente: row.fuente || 'actualizacion_masiva',
      });
      report.creados += 1;
    }
  }

  return sendJson(res, 200, report);
}

// ─── Validación de actividad (liveness) ────────────────────────────────────

async function handleValidateLiveness(req, res) {
  if (req.method !== 'POST') return sendJson(res, 405, { error: 'method_not_allowed' });

  let body;
  try { body = await readJsonBody(req); } catch { return sendJson(res, 400, { error: 'invalid_body' }); }

  const all = store.listDomains();
  const targets = Array.isArray(body.ids) && body.ids.length
    ? all.filter((d) => body.ids.includes(d.id))
    : all;

  if (!targets.length) return sendJson(res, 400, { error: 'no_domains_to_validate' });

  const job = startLivenessJob(targets);
  return sendJson(res, 202, {
    jobId: job.jobId,
    total: job.total,
    statusUrl: `/admin/api/ged2026/domains/validate-liveness/${job.jobId}`,
  });
}

function handleLivenessJobStatus(req, res, jobId) {
  if (req.method !== 'GET') return sendJson(res, 405, { error: 'method_not_allowed' });
  const job = getLivenessJob(jobId);
  if (!job) return sendJson(res, 404, { error: 'not_found' });
  return sendJson(res, 200, job);
}

// ─── Router ─────────────────────────────────────────────────────────────────

async function handleGed2026AdminRequest(req, res, parsed) {
  const segments = parsed.pathname.split('/').filter(Boolean); // ['admin','api','ged2026', ...]
  const rest = segments.slice(3);

  if (rest[0] === 'project') return handleProject(req, res);
  if (rest[0] === 'dashboard') return handleDashboard(req, res);

  if (rest[0] === 'domains') {
    if (rest[1] === 'import') return handleImport(req, res);
    if (rest[1] === 'bulk-update') return handleBulkUpdate(req, res);
    if (rest[1] === 'validate-liveness') {
      if (rest[2]) return handleLivenessJobStatus(req, res, rest[2]);
      return handleValidateLiveness(req, res);
    }
    if (rest[1]) return handleDomainItem(req, res, rest[1]);
    return handleDomainsCollection(req, res);
  }

  return sendJson(res, 404, { error: 'not_found' });
}

module.exports = { handleGed2026AdminRequest };
