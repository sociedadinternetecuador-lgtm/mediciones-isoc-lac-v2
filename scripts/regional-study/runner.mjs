'use strict';

/**
 * Runner de investigación regional — cliente/orquestador EXTERNO de
 * MEDICIONES. NO es parte de la aplicación (vive fuera del código
 * funcional principal, en scripts/regional-study/) y no la modifica de
 * ninguna forma: carga el `index.html` REAL sin tocarlo en jsdom, llena el
 * formulario del sub-tab "Mediciones" tal como lo haría una persona, y deja
 * que el propio código del navegador (getCheckResult, medicionesBatchStart,
 * classifyDataError, etc.) corra sin cambios contra el backend real. El
 * runner no reimplementa ni un solo check — solo observa la corrida real y
 * descarga el JSON por el mismo endpoint que usa el botón "Descargar JSON"
 * de la UI (GET /mediciones-batch/report/:id/export?format=json).
 *
 * MAX_DOMAINS_PER_ANALYSIS (20) de MEDICIONES no se toca ni se evade: cada
 * lote que se envía tiene exactamente 20 dominios, tal como la app espera.
 * El estudio de 400 dominios se logra ejecutando 20 lotes SECUENCIALES
 * (nunca en paralelo — ver processCountriesSequentially), uno por país.
 *
 * Limitaciones encontradas al inspeccionar el código real (documentadas
 * también en README.md, no son bugs a corregir aquí):
 *  - El JSON exportado por MEDICIONES nunca incluye `error_code` por check
 *    (index.html solo lo usa para decidir el `status`, vía
 *    classifyDataError(), y lo descarta — la única traza que sobrevive es
 *    el `details` humano). Por eso `error_codes agrupados` se arma
 *    agrupando por el texto de `details`, no por un código real, y la
 *    columna `error_code` de regional_flat.csv queda vacía.
 *  - No hay timestamp por check, solo `meta.generated_at` por corrida
 *    completa de un país (`measurement_timestamp` en regional_flat.csv usa
 *    ese valor para las 20×54 filas del país).
 *
 * Requiere una instancia real de MEDICIONES ya corriendo (MEDICIONES_BASE_URL,
 * por defecto http://localhost:3500 — instancia local de desarrollo, ver
 * README.md). Ejecutar `npm install` en este directorio antes del primer uso
 * (jsdom es una dependencia propia de este runner, no de la app).
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';
import { JSDOM, VirtualConsole } from 'jsdom';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DIRS = {
  root: __dirname,
  input: path.join(__dirname, 'input'),
  results: path.join(__dirname, 'results'),
  logs: path.join(__dirname, 'logs'),
  consolidated: path.join(__dirname, 'consolidated'),
};

const BASE_URL = (process.env.MEDICIONES_BASE_URL || 'http://localhost:3500').replace(/\/+$/, '');
const EXPECTED_DOMAIN_COUNT = 20;
// Verificado en vivo contra la app real al construir el runner (54
// checkboxes renderizadas en #mb-checksContainer). Se reconfirma en cada
// corrida (ver runCountryBatch) — si la app real cambiara este número, el
// runner falla fuerte en vez de asumir 54 en silencio.
const EXPECTED_CHECK_COUNT = 54;
// 5 minutos por defecto (ver sección REINTENTO del pedido) — override solo
// para pruebas del propio runner (REGIONAL_STUDY_RETRY_WAIT_MS), nunca para
// uso normal.
const RETRY_WAIT_MS = Number(process.env.REGIONAL_STUDY_RETRY_WAIT_MS) || 5 * 60 * 1000;
const SETTLE_MS = 1000; // margen tras 'load' antes de tocar el DOM
const WARNING_ERROR_RATE = 0.10; // 10%, ver sección CONTROL DE CALIDAD

function nowIso() { return new Date().toISOString(); }

// ───────────────────────── logging ─────────────────────────
function ensureDirs() {
  for (const d of Object.values(DIRS)) fs.mkdirSync(d, { recursive: true });
}
function appendLine(file, line) { fs.appendFileSync(file, line + '\n'); }
function logInfo(msg) {
  const line = `[${nowIso()}] ${msg}`;
  appendLine(path.join(DIRS.logs, 'runner.log'), line);
  console.log(line);
}
function logError(msg) {
  const line = `[${nowIso()}] ${msg}`;
  appendLine(path.join(DIRS.logs, 'errors.log'), line);
  appendLine(path.join(DIRS.logs, 'runner.log'), `ERROR: ${line}`);
  console.error(line);
}

// ───────────────────────── CLI args ─────────────────────────
// --force[=CC,CC,...]      repite países aunque ya estén COMPLETED
// --only=CC,CC,...         limita la corrida a estos países
// --stop-on-failed-review  detiene el runner ante el primer FAILED_REVIEW
//                          (por defecto continúa con el resto de los países)
function parseArgs(argv) {
  const opts = { force: new Set(), only: null, stopOnFailedReview: false };
  for (const arg of argv) {
    if (arg === '--force') opts.force.add('*');
    else if (arg.startsWith('--force=')) {
      arg.slice('--force='.length).split(',').map((s) => s.trim().toUpperCase()).filter(Boolean).forEach((c) => opts.force.add(c));
    } else if (arg.startsWith('--only=')) {
      opts.only = new Set(arg.slice('--only='.length).split(',').map((s) => s.trim().toUpperCase()).filter(Boolean));
    } else if (arg === '--stop-on-failed-review') {
      opts.stopOnFailedReview = true;
    }
  }
  return opts;
}

// ───────────────────── CSV del runner (propio, 4 columnas fijas) ─────────────────────
// Esquema fijo: country,country_code,sector,domain. No reusa el parser
// interno de MEDICIONES (parseBatchDomains) porque ese resuelve un formato
// distinto (dominio por línea/coma, sin encabezados) para otro propósito
// (textarea de carga manual) — mezclar convenciones sería más confuso que
// un parser chico y propio para este esquema.
function parseCsvLine(line) {
  const fields = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQuotes) {
      if (c === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else { inQuotes = false; } }
      else cur += c;
    } else if (c === '"') inQuotes = true;
    else if (c === ',') { fields.push(cur); cur = ''; }
    else cur += c;
  }
  fields.push(cur);
  return fields.map((f) => f.trim());
}

function parseCsv(text) {
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (!lines.length) return { header: [], rows: [] };
  const header = parseCsvLine(lines[0]).map((h) => h.toLowerCase());
  const rows = lines.slice(1).map(parseCsvLine).map((fields) => {
    const row = {};
    header.forEach((h, i) => { row[h] = fields[i] !== undefined ? fields[i] : ''; });
    return row;
  });
  return { header, rows };
}

const REQUIRED_COLUMNS = ['country', 'country_code', 'sector', 'domain'];

function validateCountryInput(filePath) {
  const filename = path.basename(filePath);
  const errors = [];
  let text;
  try { text = fs.readFileSync(filePath, 'utf8'); }
  catch (e) { return { ok: false, filename, errors: [`No se pudo leer el archivo: ${e.message}`] }; }

  const { header, rows } = parseCsv(text);
  const missingCols = REQUIRED_COLUMNS.filter((c) => !header.includes(c));
  if (missingCols.length) {
    return { ok: false, filename, errors: [`Encabezado inválido — faltan columnas: ${missingCols.join(', ')} (encontradas: ${header.join(', ') || '(vacío)'})`] };
  }

  if (rows.length !== EXPECTED_DOMAIN_COUNT) {
    errors.push(`Se esperaban exactamente ${EXPECTED_DOMAIN_COUNT} filas, se encontraron ${rows.length}`);
  }

  const domains = rows.map((r) => (r.domain || '').trim());
  const emptyCount = domains.filter((d) => !d).length;
  if (emptyCount > 0) errors.push(`${emptyCount} fila(s) con dominio vacío`);

  const nonEmptyDomains = domains.filter(Boolean);
  const normalized = nonEmptyDomains.map((d) => d.toLowerCase());
  const seen = new Set();
  const dupes = new Set();
  normalized.forEach((d) => { if (seen.has(d)) dupes.add(d); seen.add(d); });
  if (dupes.size) errors.push(`Dominios duplicados dentro del archivo: ${[...dupes].join(', ')}`);

  const countryCodes = new Set(rows.map((r) => (r.country_code || '').trim().toUpperCase()).filter(Boolean));
  if (countryCodes.size === 0) errors.push('country_code vacío en todas las filas');
  else if (countryCodes.size > 1) errors.push(`country_code inconsistente dentro del archivo: ${[...countryCodes].join(', ')}`);

  const countryNames = new Set(rows.map((r) => (r.country || '').trim()).filter(Boolean));
  const countryCode = countryCodes.size === 1 ? [...countryCodes][0] : null;
  const countryName = countryNames.size >= 1 ? [...countryNames][0] : null;

  return { ok: errors.length === 0, filename, errors, countryCode, countryName, rows, domains: nonEmptyDomains };
}

// ───────── puente fetch jsdom -> fetch nativo de Node (preserva timeouts reales) ─────────
// jsdom expone su propio AbortController/AbortSignal, que el fetch nativo
// de Node (undici) rechaza por no ser instancia de su propio AbortSignal
// (comprobado antes de escribir este runner). Sin este puente,
// fetchWithTimeout() de index.html (20s por request, real, sin tocar)
// dejaría de poder abortar de verdad — una request colgada bloquearía el
// runner en vez de resolver como "Timeout", igual que le pasaría a un
// navegador real.
function createBridgedFetch(baseUrl, onExchange) {
  return async function bridgedFetch(input, init = {}) {
    const raw = typeof input === 'string' ? input : input.url;
    const url = new URL(raw, baseUrl + '/');
    const nodeInit = { ...init };
    if (init.signal) {
      const nodeController = new AbortController();
      if (init.signal.aborted) nodeController.abort();
      else init.signal.addEventListener('abort', () => nodeController.abort());
      nodeInit.signal = nodeController.signal;
    }
    let response;
    try {
      response = await fetch(url, nodeInit);
      return response;
    } finally {
      if (onExchange) {
        try { await onExchange({ url: url.toString(), method: (init.method || 'GET'), response }); }
        catch { /* nunca romper el flujo real por un fallo del observador */ }
      }
    }
  };
}

// ───────────────────── carga de la página real y ejecución del flujo real ─────────────────────
async function loadRealApp(baseUrl) {
  const virtualConsole = new VirtualConsole();
  const jsdomErrors = [];
  virtualConsole.on('jsdomError', (e) => jsdomErrors.push(e.message));
  const dom = await JSDOM.fromURL(baseUrl + '/', {
    runScripts: 'dangerously',
    resources: 'usable',
    pretendToBeVisual: true,
    virtualConsole,
  });
  const { window } = dom;
  await new Promise((resolve) => {
    if (window.document.readyState === 'complete') return resolve();
    window.addEventListener('load', resolve);
  });
  await sleep(SETTLE_MS);
  return { window, jsdomErrors };
}

// Corre UN lote de 20 dominios usando exactamente window.medicionesBatchStart()
// (función real de index.html, sin tocar) y descarga el JSON resultante por
// el mismo endpoint que usa el botón "Descargar JSON" de la UI real.
async function runCountryBatch(baseUrl, domains) {
  const exchanges = [];
  let reportCreateBody = null;

  const { window, jsdomErrors } = await loadRealApp(baseUrl);

  window.fetch = createBridgedFetch(baseUrl, async ({ url, method, response }) => {
    exchanges.push({ url, method, status: response ? response.status : null });
    if (method === 'POST' && url.endsWith('/mediciones-batch/report') && response) {
      try { reportCreateBody = await response.clone().json(); } catch { /* se valida por ausencia de reportId más abajo */ }
    }
  });

  const textarea = window.document.getElementById('mb-domains-input');
  if (!textarea) throw new Error('No se encontró #mb-domains-input — la página cargada no es el index.html real de MEDICIONES');
  textarea.value = domains.join('\n');

  const checkboxes = Array.from(window.document.querySelectorAll('#mb-checksContainer input[type="checkbox"][data-check]'));
  if (checkboxes.length !== EXPECTED_CHECK_COUNT) {
    throw new Error(`La app real renderizó ${checkboxes.length} checkboxes de checks, se esperaban ${EXPECTED_CHECK_COUNT}`);
  }
  checkboxes.forEach((cb) => { cb.checked = true; });

  if (typeof window.medicionesBatchStart !== 'function') {
    throw new Error('window.medicionesBatchStart no está disponible — no se puede invocar el flujo real');
  }

  await window.medicionesBatchStart();

  const errEl = window.document.getElementById('mb-report-error');
  if (errEl && !errEl.classList.contains('hidden')) {
    throw new Error(`La app real reportó un error al generar el reporte: ${errEl.textContent}`);
  }
  if (!reportCreateBody || !reportCreateBody.reportId || !reportCreateBody.jsonUrl) {
    throw new Error('No se pudo capturar reportId/jsonUrl del POST real a /mediciones-batch/report');
  }

  const jsonRes = await fetch(new URL(reportCreateBody.jsonUrl, baseUrl + '/'));
  if (!jsonRes.ok) throw new Error(`GET ${reportCreateBody.jsonUrl} devolvió HTTP ${jsonRes.status}`);
  const reportJson = await jsonRes.json();

  return { reportJson, reportId: reportCreateBody.reportId, jsdomErrors, exchanges };
}

// ───────────────────────── validación del JSON ─────────────────────────
function detailsToText(details) {
  if (details == null) return '';
  if (Array.isArray(details)) return details.join('; ');
  if (typeof details === 'object') { try { return JSON.stringify(details); } catch { return String(details); } }
  return String(details);
}

function validateReportJson(reportJson, expectedDomains) {
  const critical = [];
  const warnings = [];

  if (!reportJson || typeof reportJson !== 'object') {
    return { critical: ['JSON inválido o vacío'], warnings, metrics: null };
  }
  const domainsArr = Array.isArray(reportJson.domains) ? reportJson.domains : null;
  if (!domainsArr) {
    return { critical: ['El JSON no contiene un arreglo "domains"'], warnings, metrics: null };
  }
  if (domainsArr.length !== EXPECTED_DOMAIN_COUNT) {
    critical.push(`domain_count esperado ${EXPECTED_DOMAIN_COUNT}, encontrado ${domainsArr.length}`);
  }

  const expectedSet = new Set(expectedDomains.map((d) => d.toLowerCase()));
  const seenDomains = new Set();
  const dupDomains = new Set();
  const mismatchedDomains = [];

  const statusCounts = { PASS: 0, FAIL: 0, INFO: 0, INCONCLUSIVE: 0, NOT_APPLICABLE: 0, MEASUREMENT_ERROR: 0 };
  let timeoutCount = 0;
  let measurementErrorDomains = 0;
  let fullErrorDomains = 0;
  const errorCodesGrouped = {}; // agrupado por texto de `details` — ver limitación en README

  for (const entry of domainsArr) {
    const domain = entry && entry.domain;
    if (!domain) { critical.push('Se encontró un objeto domain sin campo "domain"'); continue; }
    const key = domain.toLowerCase();
    if (seenDomains.has(key)) dupDomains.add(domain); else seenDomains.add(key);
    if (!expectedSet.has(key)) mismatchedDomains.push(domain);

    if (!('dnssec' in entry)) critical.push(`Dominio ${domain}: sin campo "dnssec"`);

    if (!entry.checks || typeof entry.checks !== 'object') {
      critical.push(`Dominio ${domain}: sin objeto "checks"`);
      continue;
    }
    const checkEntries = Object.entries(entry.checks);
    if (checkEntries.length !== EXPECTED_CHECK_COUNT) {
      critical.push(`Dominio ${domain}: ${checkEntries.length} checks (esperados ${EXPECTED_CHECK_COUNT})`);
    }

    let domainErrorCount = 0;
    for (const [, check] of checkEntries) {
      const status = check && check.status;
      if (status && Object.prototype.hasOwnProperty.call(statusCounts, status)) statusCounts[status]++;
      const detailsText = detailsToText(check && check.details);
      // Coincidencia EXACTA, no substring: getCheckResult() en index.html
      // tiene un único catch a nivel de función (línea ~2970) que devuelve
      // `details: error.message` = literalmente "Timeout" para los 54
      // checks cuando fetchWithTimeout() aborta a los 20s. Un match por
      // substring (/timeout/i) genera falsos positivos reales — comprobado
      // en la corrida de prueba: el header HTTP "Keep-Alive: timeout=5"
      // quedó volcado tal cual en el `details` del check `headers` (PASS,
      // no es un timeout) y mensajes explicativos de `smtputf8`/`archive`
      // que solo mencionan la palabra sin ser el error real capturado.
      if (detailsText === 'Timeout') timeoutCount++;
      if (status === 'MEASUREMENT_ERROR') {
        domainErrorCount++;
        const groupKey = detailsText || '(sin detalle)';
        errorCodesGrouped[groupKey] = (errorCodesGrouped[groupKey] || 0) + 1;
      }
    }
    if (domainErrorCount > 0) measurementErrorDomains++;
    if (checkEntries.length > 0 && domainErrorCount === checkEntries.length) {
      fullErrorDomains++;
      critical.push(`Dominio ${domain}: ${checkEntries.length}/${checkEntries.length} MEASUREMENT_ERROR`);
    }
  }

  if (dupDomains.size) critical.push(`Dominios duplicados en el JSON: ${[...dupDomains].join(', ')}`);
  if (mismatchedDomains.length) critical.push(`Dominios en el JSON ausentes del CSV de entrada: ${mismatchedDomains.join(', ')}`);
  const missingFromJson = expectedDomains.filter((d) => !seenDomains.has(d.toLowerCase()));
  if (missingFromJson.length) critical.push(`Dominios del CSV ausentes en el JSON: ${missingFromJson.join(', ')}`);

  const totalChecks = domainsArr.length * EXPECTED_CHECK_COUNT;
  const errorRate = totalChecks > 0 ? statusCounts.MEASUREMENT_ERROR / totalChecks : 0;
  if (errorRate > WARNING_ERROR_RATE) warnings.push(`MEASUREMENT_ERROR ${(errorRate * 100).toFixed(1)}% del lote (umbral ${WARNING_ERROR_RATE * 100}%)`);
  if (measurementErrorDomains >= 3) warnings.push(`${measurementErrorDomains} dominios con algún MEASUREMENT_ERROR (múltiples dominios con errores)`);
  if (timeoutCount > EXPECTED_DOMAIN_COUNT) warnings.push(`Cantidad de Timeout anormalmente alta: ${timeoutCount}`);

  return {
    critical,
    warnings,
    metrics: {
      status_counts: statusCounts,
      measurement_error_domain_count: measurementErrorDomains,
      full_error_domain_count: fullErrorDomains,
      timeout_count: timeoutCount,
      error_codes: errorCodesGrouped,
      domain_count: domainsArr.length,
    },
  };
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

// ───────────────────────── orquestación por país ─────────────────────────
async function processCountry(input, opts) {
  const countryCode = input.countryCode;
  const resultDir = path.join(DIRS.results, countryCode);
  fs.mkdirSync(resultDir, { recursive: true });
  const runMetaPath = path.join(resultDir, 'run-meta.json');

  const forced = opts.force.has('*') || opts.force.has(countryCode);
  if (!forced && fs.existsSync(runMetaPath)) {
    try {
      const prevMeta = JSON.parse(fs.readFileSync(runMetaPath, 'utf8'));
      if (prevMeta.runner_status === 'COMPLETED' && prevMeta.validation_status === 'OK') {
        logInfo(`[${countryCode}] ya completado y validado — se omite (usar --force=${countryCode} para repetir)`);
        return { countryCode, skipped: true, meta: prevMeta };
      }
    } catch { /* run-meta corrupto: se re-ejecuta desde cero */ }
  }

  let lastEvidence = null;

  for (let attempt = 1; attempt <= 2; attempt++) {
    const startedAt = nowIso();
    const startedMs = Date.now();
    logInfo(`[${countryCode}] intento ${attempt} — iniciando (${input.domains.length} dominios, ${EXPECTED_CHECK_COUNT} checks)`);

    // Servidor caído ANTES de empezar el lote = CRITICAL inmediato, sin
    // gastar el intento en dejar correr una medición sobre un backend
    // inalcanzable.
    try {
      const health = await fetch(BASE_URL + '/', { signal: AbortSignal.timeout(10000) });
      if (health.status >= 500) throw new Error(`Health check devolvió HTTP ${health.status}`);
    } catch (e) {
      logError(`[${countryCode}] intento ${attempt}: servidor no disponible antes de iniciar — ${e.message}`);
      lastEvidence = { countryCode, attempt, phase: 'health_check', error: e.message, at: nowIso() };
      fs.writeFileSync(path.join(resultDir, `evidence-attempt${attempt}.json`), JSON.stringify(lastEvidence, null, 2));
      if (attempt === 1) { logInfo(`[${countryCode}] esperando 5 minutos antes de reintentar…`); await sleep(RETRY_WAIT_MS); continue; }
      break;
    }

    try {
      const { reportJson, reportId, jsdomErrors, exchanges } = await runCountryBatch(BASE_URL, input.domains);
      const validation = validateReportJson(reportJson, input.domains);

      const serverErrorExchange = exchanges.find((ex) => ex.status && ex.status >= 500);
      if (serverErrorExchange) validation.critical.push(`Respuesta HTTP 5xx real durante la corrida: ${serverErrorExchange.method} ${serverErrorExchange.url} -> ${serverErrorExchange.status}`);

      if (validation.critical.length > 0) {
        logError(`[${countryCode}] intento ${attempt}: CRITICAL — ${validation.critical.join(' | ')}`);
        lastEvidence = {
          countryCode, attempt, phase: 'validation', at: nowIso(),
          critical: validation.critical, warnings: validation.warnings,
          reportId, jsdomErrors, exchangeCount: exchanges.length,
        };
        fs.writeFileSync(path.join(resultDir, `evidence-attempt${attempt}.json`), JSON.stringify(lastEvidence, null, 2));
        fs.writeFileSync(path.join(resultDir, `report-attempt${attempt}.json`), JSON.stringify(reportJson, null, 2));
        if (attempt === 1) { logInfo(`[${countryCode}] esperando 5 minutos antes de reintentar…`); await sleep(RETRY_WAIT_MS); continue; }
        break;
      }

      for (const w of validation.warnings) logInfo(`[${countryCode}] WARNING: ${w}`);
      const reportPath = path.join(resultDir, 'report.json');
      fs.writeFileSync(reportPath, JSON.stringify(reportJson, null, 2));

      const runMeta = {
        country: input.countryName,
        country_code: countryCode,
        input_file: input.filename,
        input_file_sha256: sha256File(path.join(DIRS.input, input.filename)),
        report_sha256: sha256File(reportPath),
        started_at: startedAt,
        finished_at: nowIso(),
        duration_ms: Date.now() - startedMs,
        attempt,
        domain_count: validation.metrics.domain_count,
        check_count: EXPECTED_CHECK_COUNT,
        status_counts: validation.metrics.status_counts,
        measurement_error_count: validation.metrics.status_counts.MEASUREMENT_ERROR,
        measurement_error_domain_count: validation.metrics.measurement_error_domain_count,
        full_error_domain_count: validation.metrics.full_error_domain_count,
        timeout_count: validation.metrics.timeout_count,
        error_codes: validation.metrics.error_codes,
        warnings: validation.warnings,
        report_id: reportId,
        validation_status: 'OK',
        runner_status: 'COMPLETED',
      };
      fs.writeFileSync(runMetaPath, JSON.stringify(runMeta, null, 2));
      logInfo(`[${countryCode}] COMPLETED — ${JSON.stringify(validation.metrics.status_counts)}`);
      return { countryCode, skipped: false, meta: runMeta };
    } catch (e) {
      logError(`[${countryCode}] intento ${attempt}: excepción — ${e.stack || e.message}`);
      lastEvidence = { countryCode, attempt, phase: 'exception', at: nowIso(), error: e.message, stack: e.stack };
      fs.writeFileSync(path.join(resultDir, `evidence-attempt${attempt}.json`), JSON.stringify(lastEvidence, null, 2));
      if (attempt === 1) { logInfo(`[${countryCode}] esperando 5 minutos antes de reintentar…`); await sleep(RETRY_WAIT_MS); continue; }
      break;
    }
  }

  const runMeta = {
    country: input.countryName,
    country_code: countryCode,
    input_file: input.filename,
    started_at: nowIso(),
    finished_at: nowIso(),
    attempt: 2,
    domain_count: input.domains.length,
    check_count: EXPECTED_CHECK_COUNT,
    status_counts: null,
    measurement_error_count: null,
    timeout_count: null,
    error_codes: null,
    validation_status: 'FAILED',
    runner_status: 'FAILED_REVIEW',
    last_evidence: lastEvidence,
  };
  fs.writeFileSync(runMetaPath, JSON.stringify(runMeta, null, 2));
  logError(`[${countryCode}] FAILED_REVIEW tras 2 intentos (1 reintento automático, nunca más)`);
  return { countryCode, skipped: false, meta: runMeta };
}

// ───────────────────────── consolidados ─────────────────────────
function csvEscape(v) {
  const s = v === null || v === undefined ? '' : String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function buildConsolidated(processedCountryCodes) {
  const countries = [];
  for (const cc of processedCountryCodes) {
    const runMetaPath = path.join(DIRS.results, cc, 'run-meta.json');
    const reportPath = path.join(DIRS.results, cc, 'report.json');
    if (!fs.existsSync(runMetaPath) || !fs.existsSync(reportPath)) continue;
    const meta = JSON.parse(fs.readFileSync(runMetaPath, 'utf8'));
    if (meta.runner_status !== 'COMPLETED' || meta.validation_status !== 'OK') continue;
    const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    countries.push({ meta, report });
  }

  if (!countries.length) {
    logError('No hay corridas COMPLETED/OK — no se genera consolidado.');
    return;
  }

  const regional400 = {
    meta: {
      generated_at: nowIso(),
      source: 'scripts/regional-study/runner.mjs — cliente externo de MEDICIONES, sin modificar la app ni los 54 checks',
      countries_included: countries.length,
      expected_domains_per_country: EXPECTED_DOMAIN_COUNT,
      expected_total_domains: countries.length * EXPECTED_DOMAIN_COUNT,
    },
    countries: countries.map(({ meta, report }) => ({
      country: meta.country,
      country_code: meta.country_code,
      report_id: meta.report_id,
      generated_at: report.meta?.generated_at || null,
      domains: report.domains,
    })),
  };
  fs.writeFileSync(path.join(DIRS.consolidated, 'regional_400.json'), JSON.stringify(regional400, null, 2));

  const flatRows = ['country,country_code,sector,domain,check,status,details,error_code,measurement_timestamp,run_id'];
  for (const { meta, report } of countries) {
    const sectorByDomain = new Map();
    const inputPath = path.join(DIRS.input, meta.input_file);
    if (fs.existsSync(inputPath)) {
      const { rows } = parseCsv(fs.readFileSync(inputPath, 'utf8'));
      rows.forEach((r) => sectorByDomain.set((r.domain || '').trim().toLowerCase(), r.sector || ''));
    }
    for (const domainEntry of report.domains || []) {
      const sector = sectorByDomain.get((domainEntry.domain || '').toLowerCase()) || '';
      for (const [checkKey, check] of Object.entries(domainEntry.checks || {})) {
        flatRows.push([
          csvEscape(meta.country), csvEscape(meta.country_code), csvEscape(sector), csvEscape(domainEntry.domain),
          csvEscape(checkKey), csvEscape(check?.status), csvEscape(detailsToText(check?.details)),
          '', // error_code: no disponible en el JSON real exportado por MEDICIONES — ver README
          csvEscape(report.meta?.generated_at || ''), csvEscape(meta.report_id),
        ].join(','));
      }
    }
  }
  fs.writeFileSync(path.join(DIRS.consolidated, 'regional_flat.csv'), flatRows.join('\n') + '\n');

  const qualityRows = ['country,country_code,domain_count,check_count,PASS,FAIL,INFO,INCONCLUSIVE,NOT_APPLICABLE,MEASUREMENT_ERROR,measurement_error_domain_count,full_error_domain_count,timeout_count,attempt,duration_ms,validation_status,runner_status'];
  for (const { meta } of countries) {
    const sc = meta.status_counts || {};
    qualityRows.push([
      csvEscape(meta.country), csvEscape(meta.country_code), meta.domain_count, meta.check_count,
      sc.PASS || 0, sc.FAIL || 0, sc.INFO || 0, sc.INCONCLUSIVE || 0, sc.NOT_APPLICABLE || 0, sc.MEASUREMENT_ERROR || 0,
      meta.measurement_error_domain_count || 0, meta.full_error_domain_count || 0, meta.timeout_count || 0,
      meta.attempt, meta.duration_ms, meta.validation_status, meta.runner_status,
    ].join(','));
  }
  fs.writeFileSync(path.join(DIRS.consolidated, 'run_quality.csv'), qualityRows.join('\n') + '\n');

  const manifest = {
    generated_at: nowIso(),
    base_url: BASE_URL,
    countries_completed: countries.map((c) => c.meta.country_code),
    total_countries: countries.length,
    total_domains: countries.length * EXPECTED_DOMAIN_COUNT,
    total_checks: countries.length * EXPECTED_DOMAIN_COUNT * EXPECTED_CHECK_COUNT,
    files: {
      regional_json: 'consolidated/regional_400.json',
      regional_flat_csv: 'consolidated/regional_flat.csv',
      run_quality_csv: 'consolidated/run_quality.csv',
    },
  };
  fs.writeFileSync(path.join(DIRS.consolidated, 'manifest.json'), JSON.stringify(manifest, null, 2));

  logInfo(`Consolidado generado: ${countries.length} países, ${countries.length * EXPECTED_DOMAIN_COUNT} dominios, ${countries.length * EXPECTED_DOMAIN_COUNT * EXPECTED_CHECK_COUNT} resultados.`);
}

// ───────────────────────── main ─────────────────────────
async function main() {
  ensureDirs();
  const opts = parseArgs(process.argv.slice(2));
  logInfo(`=== Runner regional iniciado — BASE_URL=${BASE_URL} ===`);

  const files = fs.readdirSync(DIRS.input).filter((f) => f.toLowerCase().endsWith('.csv')).sort();
  if (!files.length) {
    logError(`No se encontraron archivos .csv en ${DIRS.input}`);
    process.exitCode = 1;
    return;
  }

  const validated = [];
  for (const f of files) {
    const result = validateCountryInput(path.join(DIRS.input, f));
    if (!result.ok) {
      logError(`[${f}] input inválido — NO se ejecuta este país: ${result.errors.join(' | ')}`);
      continue;
    }
    if (opts.only && !opts.only.has(result.countryCode)) continue;
    validated.push(result);
  }

  if (!validated.length) {
    logError('Ningún país con input válido para ejecutar.');
    process.exitCode = 1;
    return;
  }

  logInfo(`Países válidos a procesar (secuencial, nunca en paralelo): ${validated.map((v) => v.countryCode).join(', ')}`);

  // SECUENCIAL a propósito: cada país espera al anterior (await dentro del
  // for..of), nunca Promise.all — un solo lote de 20 dominios corriendo a
  // la vez contra la app real.
  const processedCodes = [];
  for (const input of validated) {
    const result = await processCountry(input, opts);
    processedCodes.push(result.countryCode);
    if (!result.skipped && result.meta.runner_status === 'FAILED_REVIEW' && opts.stopOnFailedReview) {
      logError(`Deteniendo el runner por --stop-on-failed-review tras fallo en ${result.countryCode}`);
      break;
    }
  }

  buildConsolidated(processedCodes);
  logInfo('=== Runner regional finalizado ===');
}

main().catch((e) => {
  logError(`Fallo no controlado del runner: ${e.stack || e.message}`);
  process.exitCode = 1;
});
