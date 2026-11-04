'use strict';

/**
 * Ejercicio comparativo de 24 dominios (6 países x 4 dominios) — cliente
 * EXTERNO puntual de MEDICIONES, análogo en técnica a
 * scripts/regional-study/runner.mjs (que no se toca ni se reutiliza como
 * módulo — este es un script propio, más simple, para una corrida única y
 * no recurrente). Carga el index.html REAL sin modificarlo en jsdom, llena
 * el formulario del sub-tab "Mediciones" y deja correr
 * window.medicionesBatchStart() sin cambios contra el backend real. No
 * reimplementa ni un solo check.
 *
 * MAX_DOMAINS_PER_ANALYSIS (20) no se toca ni se evade: los 24 dominios se
 * envían en DOS corridas ya decididas de antemano (ver BATCHES abajo,
 * fijado ANTES de ejecutar nada) — nunca los 24 juntos.
 *
 * Requiere una instancia real de MEDICIONES ya corriendo
 * (MEDICIONES_BASE_URL, por defecto http://localhost:3500).
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';
import { JSDOM, VirtualConsole } from 'jsdom';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT_DIR = path.resolve(__dirname, '../../data/exercises/2026-09-14_24dominios_6paises');
fs.mkdirSync(OUT_DIR, { recursive: true });

const BASE_URL = (process.env.MEDICIONES_BASE_URL || 'http://localhost:3500').replace(/\/+$/, '');
const EXPECTED_CHECK_COUNT = 54;
const SETTLE_MS = 1000;

// ─── Partición decidida ANTES de ejecutar nada (no depende de resultados) ───
// Criterio: los 5 países LAC van juntos en una sola corrida de 20; Estados
// Unidos (referencia/control, explícitamente NO-LAC) va aparte, en su
// propia corrida de 4 — separación por diseño, no por conveniencia técnica
// (justo da <=20 en ambos casos porque 5x4=20 y 1x4=4).
const BATCH_A_LAC_20 = {
  label: 'A — 20 dominios LAC (Argentina, Uruguay, Panamá, Ecuador, Paraguay)',
  domains: [
    // Argentina
    'mercadolibre.com.ar', 'uba.ar', 'argentina.gob.ar', 'nic.ar',
    // Uruguay
    'tiendainglesa.com.uy', 'udelar.edu.uy', 'gub.uy', 'nic.uy',
    // Panamá
    'copaair.com', 'utp.ac.pa', 'presidencia.gob.pa', 'nic.pa',
    // Ecuador
    'corporacionfavorita.com', 'epn.edu.ec', 'gob.ec', 'nic.ec',
    // Paraguay (nuevo en este ejercicio)
    'bancontinental.com.py', 'una.py', 'paraguay.gov.py', 'nic.py',
  ],
};
const BATCH_B_US_REF_4 = {
  label: 'B — 4 dominios de Estados Unidos (referencia/control, no-LAC)',
  domains: ['amazon.com', 'mit.edu', 'usa.gov', 'nic.us'],
};
const BATCHES = [BATCH_A_LAC_20, BATCH_B_US_REF_4];

function nowIso() { return new Date().toISOString(); }
function log(msg) { console.log(`[${nowIso()}] ${msg}`); }

// ─── puente fetch jsdom -> fetch nativo de Node (idéntico razonamiento que
// en scripts/regional-study/runner.mjs: preserva el timeout real de 20s de
// fetchWithTimeout() en index.html) ───
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

async function runBatch(baseUrl, domains) {
  let reportCreateBody = null;
  const { window, jsdomErrors } = await loadRealApp(baseUrl);

  window.fetch = createBridgedFetch(baseUrl, async ({ url, method, response }) => {
    if (method === 'POST' && url.endsWith('/mediciones-batch/report') && response) {
      try { reportCreateBody = await response.clone().json(); } catch { /* validado por ausencia de reportId abajo */ }
    }
  });

  const textarea = window.document.getElementById('mb-domains-input');
  if (!textarea) throw new Error('No se encontró #mb-domains-input — la página cargada no es el index.html real');
  textarea.value = domains.join('\n');

  const checkboxes = Array.from(window.document.querySelectorAll('#mb-checksContainer input[type="checkbox"][data-check]'));
  if (checkboxes.length !== EXPECTED_CHECK_COUNT) {
    throw new Error(`La app real renderizó ${checkboxes.length} checkboxes de checks, se esperaban ${EXPECTED_CHECK_COUNT}`);
  }
  checkboxes.forEach((cb) => { cb.checked = true; });

  if (typeof window.medicionesBatchStart !== 'function') {
    throw new Error('window.medicionesBatchStart no está disponible');
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

  return { reportJson, reportId: reportCreateBody.reportId, jsdomErrors };
}

async function main() {
  log(`=== Ejercicio 24 dominios — BASE_URL=${BASE_URL} ===`);
  const runMetas = [];

  for (const batch of BATCHES) {
    log(`Iniciando corrida ${batch.label} (${batch.domains.length} dominios)`);
    const startedAt = nowIso();
    const startedMs = Date.now();

    const { reportJson, reportId, jsdomErrors } = await runBatch(BASE_URL, batch.domains);

    const finishedAt = nowIso();
    if (jsdomErrors.length) log(`Advertencia jsdom (no fatal): ${jsdomErrors.join(' | ')}`);

    const gotDomains = (reportJson.domains || []).map((d) => d.domain);
    const missing = batch.domains.filter((d) => !gotDomains.includes(d));
    const extra = gotDomains.filter((d) => !batch.domains.includes(d));
    if (missing.length || extra.length) {
      throw new Error(`Discrepancia de dominios en ${batch.label}: faltantes=${missing.join(',')} sobrantes=${extra.join(',')}`);
    }

    const outFile = path.join(OUT_DIR, `report-${batch === BATCH_A_LAC_20 ? 'A-lac20' : 'B-usref4'}.json`);
    fs.writeFileSync(outFile, JSON.stringify(reportJson, null, 2));

    const meta = {
      batch: batch.label, report_id: reportId, started_at: startedAt, finished_at: finishedAt,
      duration_ms: Date.now() - startedMs, domain_count: gotDomains.length, domains: gotDomains,
      output_file: path.relative(path.resolve(__dirname, '../..'), outFile),
    };
    runMetas.push(meta);
    log(`Corrida ${batch.label} COMPLETED — reportId=${reportId} — ${meta.duration_ms}ms — guardado en ${outFile}`);
  }

  fs.writeFileSync(path.join(OUT_DIR, 'run-meta.json'), JSON.stringify({ generated_at: nowIso(), base_url: BASE_URL, batches: runMetas }, null, 2));
  log('=== Ejercicio 24 dominios finalizado — ambas corridas OK ===');
}

main().catch((e) => {
  console.error(`[${nowIso()}] FALLO: ${e.stack || e.message}`);
  process.exitCode = 1;
});
