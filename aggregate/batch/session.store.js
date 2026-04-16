'use strict';

/**
 * Session Store — Módulo Agregado DNSSEC ISOC LAC
 *
 * Persiste el estado de cada job batch en disco (JSON).
 * Esto protege contra el auto-stop de Fly.io y permite
 * recuperar resultados de análisis largos.
 *
 * Directorio de datos: process.env.DATA_DIR || ./data/jobs
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR, 'jobs')
  : path.resolve(__dirname, '../../data/jobs');

function ensureDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function jobPath(jobId) {
  return path.join(DATA_DIR, `${jobId}.json`);
}

function createJob({ country, domains, meta = {} }) {
  const jobId = crypto.randomUUID();
  const job = {
    jobId,
    country,
    totalDomains: domains.length,
    status: 'pending',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    meta,
    progress: { processed: 0, percent: 0 },
    results: [],
    errors: [],
    aggregate: null
  };
  ensureDir();
  fs.writeFileSync(jobPath(jobId), JSON.stringify(job, null, 2));
  return job;
}

function updateJob(jobId, patch) {
  const existing = readJob(jobId);
  if (!existing) return null;
  const updated = { ...existing, ...patch, updatedAt: new Date().toISOString() };
  fs.writeFileSync(jobPath(jobId), JSON.stringify(updated, null, 2));
  return updated;
}

function readJob(jobId) {
  try {
    const raw = fs.readFileSync(jobPath(jobId), 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function listJobs() {
  ensureDir();
  return fs.readdirSync(DATA_DIR)
    .filter(f => f.endsWith('.json'))
    .map(f => {
      try {
        const raw = fs.readFileSync(path.join(DATA_DIR, f), 'utf8');
        const j = JSON.parse(raw);
        return {
          jobId: j.jobId,
          country: j.country,
          status: j.status,
          totalDomains: j.totalDomains,
          createdAt: j.createdAt,
          updatedAt: j.updatedAt,
          progress: j.progress
        };
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

function deleteJob(jobId) {
  try {
    fs.unlinkSync(jobPath(jobId));
    return true;
  } catch {
    return false;
  }
}

module.exports = { createJob, updateJob, readJob, listJobs, deleteJob };
