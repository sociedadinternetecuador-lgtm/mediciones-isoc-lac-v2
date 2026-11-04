'use strict';

const https = require('https');
const http = require('http');

// Host real de la API (confirmado en vivo 2026-11-04): el esquema OpenAPI público en
// https://pulse.internetsociety.org/api/openapi.json declara `servers[0].url` como este host,
// distinto del sitio web (pulse.internetsociety.org). Autenticación: `Authorization: Bearer
// <token>` — sin esto, la API responde 401 (confirmado en pruebas reales, no asumido).
const DEFAULT_BASE_URL = 'https://pulse-api.internetsociety.org';
const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_CACHE_TTL_MS = 24 * 60 * 60 * 1000;

const cache = new Map();

function cacheGet(key, ttlMs) {
  const item = cache.get(key);
  if (!item) return null;
  if (Date.now() - item.timestamp > ttlMs) {
    cache.delete(key);
    return null;
  }
  return item.value;
}

function cacheSet(key, value) {
  cache.set(key, { timestamp: Date.now(), value });
}

function getConfig() {
  return {
    apiKey: String(process.env.PULSE_API_KEY || '').trim(),
    baseUrl: String(process.env.PULSE_API_BASE_URL || DEFAULT_BASE_URL).replace(/\/+$/, ''),
    timeoutMs: Number(process.env.PULSE_REQUEST_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS,
    cacheTtlMs: Number(process.env.PULSE_CACHE_TTL_MS) || DEFAULT_CACHE_TTL_MS
  };
}

function isConfigured() {
  return getConfig().apiKey.length > 0;
}

// Implementación de fetch propia e inyectable (igual patrón que safeWebFetch.adapter.js
// y rawDns.adapter.js): permite a los tests simular la respuesta de Pulse sin red real,
// sin depender de ningún mock de librerías globales.
function defaultFetchImpl(url, options = {}) {
  return new Promise((resolve, reject) => {
    const lib = url.protocol === 'http:' ? http : https;
    const req = lib.request(
      url,
      {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${options.apiKey}`,
          Accept: 'application/json',
          'User-Agent': 'MedicionesISOCLAC/1.0 (+https://mediciones.isoc.org.ec)'
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
      req.destroy(Object.assign(new Error('Timeout'), { code: 'PULSE_TIMEOUT' }));
    });
    req.end();
  });
}

function buildUrl(baseUrl, path, params = {}) {
  const url = new URL(baseUrl + path);
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      url.searchParams.set(key, value);
    }
  });
  return url;
}

async function callPulse(path, params, { fetchImpl = defaultFetchImpl, cacheKey, cacheTtlMsOverride } = {}) {
  const config = getConfig();
  if (!config.apiKey) {
    const err = new Error('PULSE_API_KEY no configurada');
    err.code = 'PULSE_NOT_CONFIGURED';
    throw err;
  }

  const ttlMs = cacheTtlMsOverride ?? config.cacheTtlMs;
  const key = cacheKey || `${path}?${JSON.stringify(params)}`;
  const cached = cacheGet(key, ttlMs);
  if (cached) return cached;

  const url = buildUrl(config.baseUrl, path, params);
  let response;
  try {
    response = await fetchImpl(url, { apiKey: config.apiKey, timeoutMs: config.timeoutMs });
  } catch (e) {
    const err = new Error('Pulse: error de red o timeout');
    err.code = e && e.code === 'PULSE_TIMEOUT' ? 'PULSE_TIMEOUT' : 'PULSE_NETWORK_ERROR';
    err.cause = e;
    throw err;
  }

  if (response.statusCode === 401 || response.statusCode === 403) {
    const err = new Error('Pulse: token inválido o sin permiso');
    err.code = 'PULSE_UNAUTHORIZED';
    throw err;
  }
  if (response.statusCode >= 400) {
    const err = new Error(`Pulse: respuesta HTTP ${response.statusCode}`);
    err.code = 'PULSE_HTTP_ERROR';
    err.statusCode = response.statusCode;
    throw err;
  }

  let parsed;
  try {
    parsed = JSON.parse(response.body);
  } catch (e) {
    const err = new Error('Pulse: respuesta no es JSON válido');
    err.code = 'PULSE_BAD_RESPONSE';
    throw err;
  }

  cacheSet(key, parsed);
  return parsed;
}

// Devuelve el estado diario de firma DNSSEC del ccTLD de un país — no de un dominio
// individual. Formato real confirmado: [{date, signed, ds_in_root, tld}, ...].
async function getDnssecAdoption(countryCode, { startDate, endDate, fetchImpl } = {}) {
  const cc = String(countryCode || '').trim().toLowerCase();
  return callPulse(`/dnssec/adoption/country/${encodeURIComponent(cc)}`, {
    start_date: startDate,
    end_date: endDate
  }, { fetchImpl, cacheKey: `dnssec:${cc}:${startDate}:${endDate}` });
}

// Devuelve el % diario de cobertura ROA (0-1) del espacio IP asignado al país.
async function getRoaCoverage(countryCode, { startDate, endDate, ipVersion, fetchImpl } = {}) {
  const cc = String(countryCode || '').trim().toLowerCase();
  return callPulse(`/roa/country/${encodeURIComponent(cc)}`, {
    start_date: startDate,
    end_date: endDate,
    ip_version: ipVersion
  }, { fetchImpl, cacheKey: `roa:${cc}:${startDate}:${endDate}:${ipVersion || ''}` });
}

// Devuelve el % diario de adopción de IPv6 del país.
async function getIpv6Adoption(countryCode, { startDate, endDate, fetchImpl } = {}) {
  const cc = String(countryCode || '').trim().toLowerCase();
  return callPulse(`/ipv6/country/${encodeURIComponent(cc)}`, {
    start_date: startDate,
    end_date: endDate
  }, { fetchImpl, cacheKey: `ipv6:${cc}:${startDate}:${endDate}` });
}

// El endpoint de resiliencia exige el país en MAYÚSCULAS (ISO 3166 alpha-2) —
// confirmado en pruebas reales (2026-11-04): "py" no devuelve datos, "PY" sí.
// Se normaliza acá para que quien use el adaptador nunca tenga que saber este detalle.
async function getResilience(countryCode, { year, quarter, fetchImpl } = {}) {
  const cc = String(countryCode || '').trim().toUpperCase();
  return callPulse('/resilience', {
    country: cc,
    year,
    quarter
  }, { fetchImpl, cacheKey: `resilience:${cc}:${year}:${quarter || ''}` });
}

function clearCache() {
  cache.clear();
}

module.exports = {
  isConfigured,
  getDnssecAdoption,
  getRoaCoverage,
  getIpv6Adoption,
  getResilience,
  clearCache,
  // expuestos para pruebas unitarias, no para uso en rutas reales
  _internal: { getConfig, callPulse, buildUrl }
};
