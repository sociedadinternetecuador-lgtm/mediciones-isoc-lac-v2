'use strict';

/**
 * Rutas del "Reporte por lote" — sub-tab de Mediciones (antes llamada
 * "Análisis comparativo").
 *
 * La medición (checks + DNSSEC + validación DNS) corre client-side en
 * index.html (medicionesBatchStart) reutilizando lógica/endpoints ya
 * existentes — este módulo solo recibe el payload ya ensamblado por el
 * navegador, lo guarda, y sirve las exportaciones JSON/PDF. El PDF se
 * genera delegando a mdtopdf (server1:8600, servicio externo ya
 * desplegado) — no se reimplementa conversión Markdown→PDF aquí.
 *
 *  POST /mediciones-batch/report
 *    Body: payload completo (ver logic/exporters/medicionesBatchReport.exporter.js
 *    para la forma esperada). Responde { reportId, jsonUrl, pdfUrl }.
 *
 *  GET /mediciones-batch/report/:id/export?format=json
 *    Descarga el payload (con metadata de exportación añadida).
 *
 *  GET /mediciones-batch/report/:id/export?format=pdf
 *    Genera (o sirve desde caché) el PDF vía mdtopdf.
 */

const {
  createReport, getReport, setPdfBuffer,
} = require('../logic/orchestrators/medicionesBatchReport.store');
const {
  buildComparativeMarkdown, buildJsonExport,
} = require('../logic/exporters/medicionesBatchReport.exporter');

// Mismo límite que routes/datasetPreparation.routes.js (MAX_UPLOAD_CHARS) —
// un payload de análisis comparativo (20-25 dominios, ~40 checks + DNSSEC
// crudo por dominio) es varios órdenes de magnitud más chico que eso, así
// que el mismo techo sirve de resguardo sin inventar un número nuevo.
const MAX_PAYLOAD_CHARS = 20 * 1024 * 1024; // 20 MB de JSON

// Límite funcional deliberado (no técnico): MEDICIONES es una herramienta
// de análisis técnico detallado, no de procesamiento masivo. Ver
// docs/arquitectura.md — misma constante replicada en index.html
// (mbGetDomainsList/medicionesBatchStart) porque no hay bundler ni módulo
// compartido entre navegador y servidor en este proyecto; esta es la
// verificación que impide el bypass del frontend.
const MAX_DOMAINS_PER_ANALYSIS = 20;

const MDTOPDF_URL = process.env.MDTOPDF_URL || 'http://server1:8600';

function readBody(req, maxChars) {
  return new Promise((resolve, reject) => {
    let data = '';
    let tooLarge = false;
    req.on('data', (chunk) => {
      if (tooLarge) return;
      data += chunk;
      if (data.length > maxChars) tooLarge = true;
    });
    req.on('end', () => {
      if (tooLarge) return resolve({ tooLarge: true });
      try {
        resolve({ body: JSON.parse(data || '{}') });
      } catch {
        resolve({ body: {} });
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}

async function handleCreateReport(req, res) {
  const { tooLarge, body } = await readBody(req, MAX_PAYLOAD_CHARS);
  if (tooLarge) {
    return sendJson(res, 400, {
      error: 'payload_too_large',
      message: 'El payload del reporte por lote excede el tamaño máximo admitido (20 MB).',
    });
  }

  if (!body || typeof body !== 'object' || !Array.isArray(body.domains)) {
    return sendJson(res, 400, {
      error: 'invalid_payload',
      message: 'El payload debe incluir al menos "domains" (arreglo).',
    });
  }

  if (body.domains.length > MAX_DOMAINS_PER_ANALYSIS) {
    return sendJson(res, 400, {
      error: 'DOMAIN_LIMIT_EXCEEDED',
      message: `Máximo ${MAX_DOMAINS_PER_ANALYSIS} dominios por análisis. Se recibieron ${body.domains.length}.`,
      received_count: body.domains.length,
      max_allowed: MAX_DOMAINS_PER_ANALYSIS,
    });
  }

  const reportId = createReport(body);
  sendJson(res, 201, {
    reportId,
    jsonUrl: `/mediciones-batch/report/${reportId}/export?format=json`,
    pdfUrl: `/mediciones-batch/report/${reportId}/export?format=pdf`,
  });
}

function handleExportJson(res, report) {
  const json = JSON.stringify(buildJsonExport(report.payload), null, 2);
  res.writeHead(200, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Disposition': `attachment; filename="reporte-mediciones-${report.reportId.slice(0, 8)}.json"`,
  });
  res.end(json);
}

async function handleExportPdf(res, report) {
  if (report.pdfBuffer) {
    res.writeHead(200, {
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="reporte-mediciones-${report.reportId.slice(0, 8)}.pdf"`,
      'Content-Length': report.pdfBuffer.length,
    });
    res.end(report.pdfBuffer);
    return;
  }

  let markdown;
  try {
    markdown = buildComparativeMarkdown(report.payload);
  } catch (error) {
    return sendJson(res, 500, {
      error: 'markdown_build_failed',
      message: 'No se pudo construir el reporte Markdown para exportar a PDF.',
      detail: error.message,
    });
  }

  try {
    const formData = new FormData();
    const blob = new Blob([markdown], { type: 'text/markdown' });
    formData.append('file', blob, 'reporte-mediciones.md');

    const response = await fetch(`${MDTOPDF_URL}/api/convert`, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      const detail = await response.text().catch(() => '');
      return sendJson(res, 502, {
        error: 'mdtopdf_failed',
        message: `El servicio de conversión a PDF respondió ${response.status}.`,
        detail: detail.slice(0, 2000),
      });
    }

    const arrayBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    setPdfBuffer(report.reportId, buffer);

    res.writeHead(200, {
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="reporte-mediciones-${report.reportId.slice(0, 8)}.pdf"`,
      'Content-Length': buffer.length,
    });
    res.end(buffer);
  } catch (error) {
    sendJson(res, 502, {
      error: 'mdtopdf_unreachable',
      message: 'No se pudo contactar al servicio de conversión a PDF (mdtopdf).',
      detail: error.message,
    });
  }
}

async function handleExport(req, res, reportId, format) {
  const report = getReport(reportId);
  if (!report) {
    return sendJson(res, 404, { error: 'report_not_found', message: 'Reporte no encontrado.' });
  }

  if (format === 'json') return handleExportJson(res, report);
  if (format === 'pdf') return handleExportPdf(res, report);

  return sendJson(res, 400, {
    error: 'invalid_format',
    message: 'format debe ser "json" o "pdf".',
  });
}

async function handleMedicionesBatchReportRequest(req, res, parsedUrl) {
  const segments = parsedUrl.pathname.split('/').filter(Boolean);
  // segments[0] = 'mediciones-batch', segments[1] = 'report'

  if (req.method === 'POST' && segments[1] === 'report' && !segments[2]) {
    return handleCreateReport(req, res);
  }

  if (req.method === 'GET' && segments[1] === 'report' && segments[2] && segments[3] === 'export') {
    const format = parsedUrl.searchParams.get('format');
    return handleExport(req, res, segments[2], format);
  }

  sendJson(res, 404, { error: 'not_found', message: 'Ruta no encontrada.' });
}

module.exports = { handleMedicionesBatchReportRequest };
