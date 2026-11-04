'use strict';

const https = require('https');
const http = require('http');

// Cliente aislado hacia el Observatorio DNSSEC v2 (observatorio-dnssec-v2/,
// Flask/Python, ejecuta `dnsviz` real). Contrato de datos verificado leyendo
// backend/app.py de ese subproyecto (2026-11-04):
//
//   POST   /analyze              {domain} -> 202 {id, status:"queued", status_url}
//   GET    /analyze/<id>/status  -> {status: queued|running|done|error, progress, message}
//   GET    /analyze/<id>/result.json -> resultado estructurado final (API pública,
//          sin autenticación — ver _build_result_json en app.py)
//
// IMPORTANTE, corregido tras leer _build_result_json() completo (la primera
// versión de este comentario asumía un campo `errors[].is_crypto_dnssec_issue`
// que NO existe en la respuesta pública): el Observatorio clasifica
// SECURE/INSECURE/BOGUS internamente (`_calculate_dnssec_status`), pero ese
// veredicto es deliberadamente "legacy, no expuesto al frontend ni al PDF"
// (ver REPORTE-FINAL.md) — tampoco se expone en result.json. Lo único público
// es `structured_view.zones[]`, cada una con `classification.is_target`
// (true solo para la zona del dominio exacto, no sus ancestros) y
// `errors[]`/`warnings[]` con un `code` real de DNSViz (catálogo capa1A).
// Por eso este adaptador reimplementa, sobre datos públicos, el mismo criterio
// de "es un problema criptográfico real" que usa internamente app.py
// (CRYPTO_DNSSEC_HINTS: RRSIG/DNSKEY/DS/NSEC/NSEC3/SIGNATURE/DIGEST/
// ALGORITHM/SEP/KEY/CHAIN/BOGUS/VALIDATION) — no depende de ningún campo
// interno ni de autenticación de admin.
//
// Esta integración NO está conectada todavía a logic/rules/dnssec.rules.js —
// ese motor está protegido explícitamente en CLAUDE.md ("no tocar sin razón
// salvo error real y reproducible"). Este adaptador existe para que, cuando
// se decida formalmente sumar esta evidencia al veredicto, el punto de
// conexión ya esté probado y aislado.

const CRYPTO_DNSSEC_HINTS = [
  'RRSIG', 'DNSKEY', 'DS', 'NSEC', 'NSEC3', 'SIGNATURE', 'DIGEST',
  'ALGORITHM', 'SEP', 'KEY', 'CHAIN', 'BOGUS', 'VALIDATION'
];

const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_POLL_INTERVAL_MS = 2000;
const DEFAULT_MAX_WAIT_MS = 90000; // dnsviz real puede tardar ~60-90s por dominio

function getConfig() {
  return {
    baseUrl: String(process.env.DNSVIZ_OBSERVATORIO_URL || '').replace(/\/+$/, ''),
    timeoutMs: Number(process.env.DNSVIZ_OBSERVATORIO_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS,
    maxWaitMs: Number(process.env.DNSVIZ_OBSERVATORIO_MAX_WAIT_MS) || DEFAULT_MAX_WAIT_MS
  };
}

function isConfigured() {
  return getConfig().baseUrl.length > 0;
}

function defaultFetchImpl(url, options = {}) {
  return new Promise((resolve, reject) => {
    const lib = url.protocol === 'http:' ? http : https;
    const body = options.body ? Buffer.from(options.body) : null;
    const req = lib.request(
      url,
      {
        method: options.method || 'GET',
        headers: {
          Accept: 'application/json',
          'User-Agent': 'MedicionesISOCLAC/1.0 (+https://mediciones.isoc.org.ec)',
          ...(body ? { 'Content-Type': 'application/json', 'Content-Length': body.length } : {})
        }
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => resolve({ statusCode: res.statusCode, body: data }));
      }
    );
    req.on('error', reject);
    req.setTimeout(options.timeoutMs || DEFAULT_TIMEOUT_MS, () => {
      req.destroy(Object.assign(new Error('Timeout'), { code: 'DNSVIZ_OBS_TIMEOUT' }));
    });
    if (body) req.write(body);
    req.end();
  });
}

async function requestJson(path, { method = 'GET', body, fetchImpl = defaultFetchImpl, timeoutMs } = {}) {
  const config = getConfig();
  if (!config.baseUrl) {
    const err = new Error('DNSVIZ_OBSERVATORIO_URL no configurada');
    err.code = 'DNSVIZ_OBS_NOT_CONFIGURED';
    throw err;
  }
  const url = new URL(config.baseUrl + path);
  let response;
  try {
    response = await fetchImpl(url, {
      method,
      body: body ? JSON.stringify(body) : undefined,
      timeoutMs: timeoutMs || config.timeoutMs
    });
  } catch (e) {
    const err = new Error('Observatorio DNSSEC: error de red o timeout');
    err.code = e && e.code === 'DNSVIZ_OBS_TIMEOUT' ? 'DNSVIZ_OBS_TIMEOUT' : 'DNSVIZ_OBS_NETWORK_ERROR';
    err.cause = e;
    throw err;
  }
  if (response.statusCode >= 400 && response.statusCode !== 202) {
    const err = new Error(`Observatorio DNSSEC: respuesta HTTP ${response.statusCode}`);
    err.code = 'DNSVIZ_OBS_HTTP_ERROR';
    err.statusCode = response.statusCode;
    throw err;
  }
  try {
    return JSON.parse(response.body);
  } catch (e) {
    const err = new Error('Observatorio DNSSEC: respuesta no es JSON válido');
    err.code = 'DNSVIZ_OBS_BAD_RESPONSE';
    throw err;
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Corre un análisis dnsviz completo contra el Observatorio y espera el
// resultado. No lanza si el servicio está caído por facturación u otra
// causa externa: devuelve { available: false, reason } para que quien lo
// use pueda degradar sin romper nada (mismo patrón que pulse.adapter.js).
async function runFullAnalysis(domain, { fetchImpl, pollIntervalMs = DEFAULT_POLL_INTERVAL_MS } = {}) {
  const config = getConfig();
  if (!config.baseUrl) {
    return { available: false, reason: 'DNSVIZ_OBS_NOT_CONFIGURED' };
  }

  let queued;
  try {
    queued = await requestJson('/analyze', { method: 'POST', body: { domain }, fetchImpl });
  } catch (e) {
    return { available: false, reason: e.code || 'DNSVIZ_OBS_ERROR' };
  }

  const id = queued.id;
  if (!id) {
    return { available: false, reason: 'DNSVIZ_OBS_NO_ANALYSIS_ID' };
  }

  const deadline = Date.now() + config.maxWaitMs;
  while (Date.now() < deadline) {
    let status;
    try {
      status = await requestJson(`/analyze/${encodeURIComponent(id)}/status`, { fetchImpl });
    } catch (e) {
      return { available: false, reason: e.code || 'DNSVIZ_OBS_ERROR' };
    }
    if (status.status === 'done') {
      try {
        const result = await requestJson(`/analyze/${encodeURIComponent(id)}/result.json`, { fetchImpl });
        return { available: true, id, result };
      } catch (e) {
        return { available: false, reason: e.code || 'DNSVIZ_OBS_ERROR' };
      }
    }
    if (status.status === 'error') {
      return { available: false, reason: 'DNSVIZ_OBS_ANALYSIS_FAILED', detail: status.message };
    }
    await sleep(pollIntervalMs);
  }
  return { available: false, reason: 'DNSVIZ_OBS_TIMED_OUT_WAITING' };
}

function isCryptoDnssecCode(code) {
  const upper = String(code || '').toUpperCase();
  return CRYPTO_DNSSEC_HINTS.some((token) => upper.includes(token));
}

// Extrae, del result.json real (campo público structured_view.zones[]), solo
// lo que a MEDICIONES le haría falta para enriquecer su veredicto: si algún
// error reportado por dnsviz para la zona exacta del dominio (classification
// .is_target === true, no sus zonas ancestro) tiene un código de naturaleza
// criptográfica real (firma inválida, NSEC3 mal configurado, etc.), no solo
// ausencia estructural de DS/DNSKEY.
function extractCryptoValidationSignal(result) {
  const zones = result && result.structured_view && Array.isArray(result.structured_view.zones)
    ? result.structured_view.zones
    : [];
  const targetZone = zones.find((z) => z && z.classification && z.classification.is_target === true);
  if (!targetZone) {
    return { hasCryptoFailure: false, issues: [] };
  }
  const issues = (targetZone.errors || []).filter((e) => isCryptoDnssecCode(e && e.code));
  return { hasCryptoFailure: issues.length > 0, issues };
}

module.exports = {
  isConfigured,
  runFullAnalysis,
  extractCryptoValidationSignal,
  _internal: { getConfig, requestJson }
};
