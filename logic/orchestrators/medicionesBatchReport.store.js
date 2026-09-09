'use strict';

/**
 * Almacén en memoria de reportes de "Análisis comparativo" (sub-tab de
 * Mediciones). Sin SSE ni progreso: el ensamblado del payload ya ocurrió
 * en el navegador (medición client-side, ver index.html) — aquí solo se
 * guarda el resultado final para servir /export?format=json|pdf y cachear
 * el PDF generado por el servicio externo mdtopdf (server1:8600).
 *
 * Mismo patrón de Map en memoria que dnsValidationJob.orchestrator.js —
 * sin base de datos, se pierde si el proceso reinicia (aceptado, ver
 * CLAUDE.md § "Sin base de datos ni persistencia de jobs").
 */

const crypto = require('crypto');

const reports = new Map();

function createReport(payload) {
  const reportId = crypto.randomUUID();
  reports.set(reportId, { reportId, createdAt: new Date().toISOString(), payload, pdfBuffer: null });
  return reportId;
}

function getReport(reportId) {
  return reports.get(reportId) || null;
}

function setPdfBuffer(reportId, buffer) {
  const r = reports.get(reportId);
  if (r) r.pdfBuffer = buffer;
}

module.exports = { createReport, getReport, setPdfBuffer };
