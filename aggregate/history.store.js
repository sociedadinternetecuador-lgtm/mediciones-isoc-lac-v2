'use strict';

/**
 * Historia Store — Mediciones ISOC LAC
 *
 * Persiste análisis batch con histórico por país.
 * Diseño: JSON files por análisis + índice central.
 * Migrable a SQLite cambiando solo este módulo.
 *
 * Estructura en disco:
 *   data/history/
 *     index.json          ← índice de todos los análisis
 *     {jobId}.json        ← resultado completo de cada análisis
 */

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR, 'history')
  : path.resolve(__dirname, '../../data/history');

const INDEX_PATH = path.join(DATA_DIR, 'index.json');

function ensureDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

// ─── Índice ───────────────────────────────────────────────────────────────────

function readIndex() {
  ensureDir();
  try {
    return JSON.parse(fs.readFileSync(INDEX_PATH, 'utf8'));
  } catch {
    return { analyses: [] };
  }
}

function saveIndex(index) {
  fs.writeFileSync(INDEX_PATH, JSON.stringify(index, null, 2));
}

// ─── Hash de lista de dominios ────────────────────────────────────────────────

function hashDomainList(domains) {
  const normalized = [...domains]
    .map(d => d.trim().toLowerCase())
    .filter(Boolean)
    .sort()
    .join('\n');
  return crypto.createHash('sha256').update(normalized).digest('hex').slice(0, 16);
}

// ─── Crear análisis ───────────────────────────────────────────────────────────

function createAnalysis({ label, country, domains, engine, meta = {} }) {
  ensureDir();
  const jobId    = crypto.randomUUID();
  const listHash = hashDomainList(domains);

  const record = {
    jobId,
    listHash,
    label:        label || country || 'sin etiqueta',
    country:      country || label || 'unknown',
    engine:       engine || 'doh',
    totalDomains: domains.length,
    status:       'pending',
    createdAt:    new Date().toISOString(),
    updatedAt:    new Date().toISOString(),
    completedAt:  null,
    meta,
    progress:     { processed: 0, percent: 0 },
    aggregate:    null,
    errorCount:   0,
  };

  // Guardar en índice
  const index = readIndex();
  index.analyses.unshift({
    jobId,
    listHash,
    label:        record.label,
    country:      record.country,
    engine:       record.engine,
    totalDomains: record.totalDomains,
    status:       'pending',
    createdAt:    record.createdAt,
    completedAt:  null,
  });
  saveIndex(index);

  // Guardar dominio completo + dominios en archivo propio
  fs.writeFileSync(
    path.join(DATA_DIR, `${jobId}.json`),
    JSON.stringify({ ...record, domains, results: [], errors: [] }, null, 2)
  );

  return record;
}

// ─── Actualizar análisis ──────────────────────────────────────────────────────

function updateAnalysis(jobId, patch) {
  const filePath = path.join(DATA_DIR, `${jobId}.json`);
  try {
    const existing = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const updated  = { ...existing, ...patch, updatedAt: new Date().toISOString() };
    fs.writeFileSync(filePath, JSON.stringify(updated, null, 2));

    // Actualizar índice si cambió status o aggregate
    if (patch.status || patch.aggregate || patch.completedAt) {
      const index = readIndex();
      const entry = index.analyses.find(a => a.jobId === jobId);
      if (entry) {
        if (patch.status)      entry.status      = patch.status;
        if (patch.completedAt) entry.completedAt = patch.completedAt;
        if (patch.aggregate)   entry.semaphore   = patch.aggregate?.semaphore?.color;
        if (patch.aggregate)   entry.adoptionPct = patch.aggregate?.adoption?.rate;
        saveIndex(index);
      }
    }
    return updated;
  } catch {
    return null;
  }
}

// ─── Leer análisis ────────────────────────────────────────────────────────────

function readAnalysis(jobId) {
  try {
    return JSON.parse(fs.readFileSync(path.join(DATA_DIR, `${jobId}.json`), 'utf8'));
  } catch {
    return null;
  }
}

// ─── Detectar lista duplicada ─────────────────────────────────────────────────

function findByListHash(listHash) {
  const index = readIndex();
  return index.analyses
    .filter(a => a.listHash === listHash && a.status === 'completed')
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

// ─── Listar análisis ──────────────────────────────────────────────────────────

function listAnalyses({ country, engine, limit = 50 } = {}) {
  const index = readIndex();
  let list = index.analyses;
  if (country) list = list.filter(a => a.country?.toLowerCase().includes(country.toLowerCase()));
  if (engine)  list = list.filter(a => a.engine === engine);
  return list.slice(0, limit);
}

// ─── Datos para gráfica de evolución ─────────────────────────────────────────

function getEvolutionData(country) {
  const index = readIndex();
  return index.analyses
    .filter(a => a.country?.toLowerCase() === country.toLowerCase() && a.status === 'completed')
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
    .map(a => ({
      jobId:       a.jobId,
      date:        a.createdAt,
      engine:      a.engine,
      totalDomains:a.totalDomains,
      semaphore:   a.semaphore,
      adoptionPct: a.adoptionPct ?? null,
    }));
}

// ─── Biblioteca pública ───────────────────────────────────────────────────────

function getPublicLibrary() {
  const index = readIndex();
  const completed = index.analyses.filter(a => a.status === 'completed');

  // Agrupar por país — solo el más reciente por país
  const byCountry = {};
  for (const a of completed) {
    const key = a.country?.toLowerCase() || 'unknown';
    if (!byCountry[key] || new Date(a.createdAt) > new Date(byCountry[key].createdAt)) {
      byCountry[key] = a;
    }
  }

  return {
    total_analyses: completed.length,
    countries:      Object.values(byCountry).sort((a, b) =>
      (a.country || '').localeCompare(b.country || '')
    ),
    recent:         completed.slice(0, 10),
  };
}

module.exports = {
  createAnalysis,
  updateAnalysis,
  readAnalysis,
  findByListHash,
  listAnalyses,
  getEvolutionData,
  getPublicLibrary,
  hashDomainList,
};
