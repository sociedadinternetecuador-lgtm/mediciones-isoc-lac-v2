'use strict';

/**
 * Persistencia GED2026 — Global Encryption Day Ecuador 2026.
 *
 * Mismo patrón que logic/adapters/contentStore.adapter.js: JSON en disco,
 * sin base de datos (ver CLAUDE.md, regla 5 — esto es dato de negocio
 * persistente, no estado de job efímero, igual que Blog/Eventos/Materiales).
 *
 * Dos archivos, no uno:
 *   data/ged2026/domains.json  — array, el universo/muestra de dominios.
 *   data/ged2026/project.json  — objeto único, fase/estado del proyecto.
 * Forzar el registro de fase (un solo objeto) al mismo molde de array que
 * domains.json no aporta nada y complica "leer el único registro" en
 * "listar y tomar [0]".
 *
 * Convención de nombres de campo: snake_case en los campos de negocio del
 * dominio (domain, normalized_domain, estado_seleccion, created_at, ...) —
 * a propósito distinto de createdAt/updatedAt de contentStore.adapter.js.
 * Son exactamente los nombres pedidos para este módulo (incluido el
 * contrato público /ged2026/api/v1/summary), no una convención técnica
 * interna — ver docs/ged2026.md.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { ESTADOS_SELECCION, ESTADOS_VALIDACION, PROJECT_PHASES } = require('../../config/ged2026.constants');

const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR, 'ged2026')
  : path.resolve(__dirname, '../../data/ged2026');

const DOMAINS_PATH = path.join(DATA_DIR, 'domains.json');
const PROJECT_PATH = path.join(DATA_DIR, 'project.json');

function ensureDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function readJsonFile(filePath, fallback) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeJsonFile(filePath, data) {
  ensureDir();
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

// ─── Dominios ───────────────────────────────────────────────────────────────

function readDomains() {
  ensureDir();
  return readJsonFile(DOMAINS_PATH, []);
}

function writeDomains(domains) {
  writeJsonFile(DOMAINS_PATH, domains);
  touchLastUpdated();
}

function listDomains() {
  return readDomains();
}

function getDomain(id) {
  return readDomains().find((d) => d.id === id) || null;
}

function findByNormalizedDomain(normalized_domain) {
  return readDomains().find((d) => d.normalized_domain === normalized_domain) || null;
}

function defaultAtributosRelevancia() {
  return {
    traffic_source: null,
    traffic_rank: null,
    traffic_score: null,
    transactionality_level: null,
    institutional_relevance: null,
    user_reach: null,
    critical_service: null,
  };
}

function createDomain(data) {
  const domains = readDomains();
  const now = new Date().toISOString();
  const record = {
    id: crypto.randomUUID(),
    domain: '',
    normalized_domain: '',
    categoria: null,
    tipo_institucion: null,
    fuente: null,
    fecha_incorporacion: now,
    estado_validacion: 'unknown',
    activo: true,
    fecha_ultima_validacion: null,
    atributos_relevancia: defaultAtributosRelevancia(),
    estado_seleccion: 'candidate',
    exclusion_reason: null,
    notas: null,
    ...data,
    created_at: now,
    updated_at: now,
  };
  domains.push(record);
  writeDomains(domains);
  return record;
}

function updateDomain(id, patch) {
  const domains = readDomains();
  const idx = domains.findIndex((d) => d.id === id);
  if (idx === -1) return null;
  domains[idx] = {
    ...domains[idx],
    ...patch,
    atributos_relevancia: patch.atributos_relevancia
      ? { ...domains[idx].atributos_relevancia, ...patch.atributos_relevancia }
      : domains[idx].atributos_relevancia,
    id,
    updated_at: new Date().toISOString(),
  };
  writeDomains(domains);
  return domains[idx];
}

// ─── Proyecto (registro único) ──────────────────────────────────────────────

function defaultProject() {
  const now = new Date().toISOString();
  return { current_phase: 'planning', phase_started_at: now, last_updated: null };
}

function getProject() {
  ensureDir();
  const existing = readJsonFile(PROJECT_PATH, null);
  if (existing) return existing;
  const project = defaultProject();
  writeJsonFile(PROJECT_PATH, project);
  return project;
}

function setProjectPhase(newPhase) {
  if (!PROJECT_PHASES.includes(newPhase)) {
    throw new Error(`Fase de proyecto desconocida: ${newPhase}`);
  }
  const now = new Date().toISOString();
  const project = { current_phase: newPhase, phase_started_at: now, last_updated: now };
  writeJsonFile(PROJECT_PATH, project);
  return project;
}

// Se llama tras cualquier escritura en domains.json — el consumidor público
// (GET /ged2026/api/v1/summary) reporta updated_at como "última vez que
// cambió algo operativo", no solo "última vez que cambió la fase".
function touchLastUpdated() {
  const project = getProject();
  project.last_updated = new Date().toISOString();
  writeJsonFile(PROJECT_PATH, project);
}

module.exports = {
  listDomains,
  getDomain,
  findByNormalizedDomain,
  createDomain,
  updateDomain,
  getProject,
  setProjectPhase,
  ESTADOS_SELECCION,
  ESTADOS_VALIDACION,
};
