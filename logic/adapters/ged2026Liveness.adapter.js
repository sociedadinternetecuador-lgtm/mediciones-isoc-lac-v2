'use strict';

/**
 * Chequeo de actividad (liveness) de dominios GED2026 — sección 6 del
 * pedido: DNS + HTTP(S), usando SIEMPRE safeWebFetch.adapter.js (protección
 * SSRF ya existente en el proyecto) para cualquier acceso de red — nunca
 * http.request/https.request directo.
 *
 * Vocabulario de estado propio (dns_ok/http_ok/https_ok/redirect/timeout/
 * dns_error/tls_error/inactive/unknown), deliberadamente DISTINTO del
 * VALID/NXDOMAIN/REVIEW de la metodología cerrada de Preparación de
 * datasets (logic/validators/dnsValidation.validator.js) — son preguntas
 * distintas ("¿existe en el censo de dominios .ec?" vs. "¿responde ahora
 * mismo?"), así que este código es nuevo y no toca esa metodología.
 */

const { resolvePublicAddresses, resolveFinalWebTarget } = require('./safeWebFetch.adapter');

const TLS_ERROR_CODES = new Set([
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'CERT_HAS_EXPIRED',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'ERR_SSL_WRONG_VERSION_NUMBER',
  'EPROTO',
]);

const CONNECTION_FAILED_CODES = new Set(['ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH', 'ECONNRESET']);

function sameHost(finalUrl, originalHostname) {
  try {
    return new URL(finalUrl).hostname === originalHostname;
  } catch {
    return false;
  }
}

function classifyError(error) {
  const code = error && error.code;
  if (code === 'TIMEOUT' || code === 'WEBFETCH_TOTAL_TIMEOUT' || code === 'WEBFETCH_REDIRECT_LIMIT') return 'timeout';
  if (TLS_ERROR_CODES.has(code)) return 'tls_error';
  if (CONNECTION_FAILED_CODES.has(code)) return 'inactive';
  return null;
}

async function probe(domain, protocol, options) {
  const target = `${protocol}//${domain}/`;
  try {
    const resolved = await resolveFinalWebTarget(target, { method: 'HEAD', ...options });
    if (sameHost(resolved.finalUrl, domain)) {
      return { status: protocol === 'https:' ? 'https_ok' : 'http_ok' };
    }
    return { status: 'redirect', detail: { finalUrl: resolved.finalUrl } };
  } catch (error) {
    return { status: null, error };
  }
}

async function checkDomainLiveness(domain, options = {}) {
  try {
    await resolvePublicAddresses(domain, options.lookup);
  } catch (error) {
    if (error && (
      error.code === 'WEBFETCH_BLOCKED_IP'
      || error.code === 'WEBFETCH_NO_ADDRESS_RECORD'
      || error.code === 'WEBFETCH_NO_ADDRESS'
    )) {
      return { estado_validacion: 'inactive', detail: { code: error.code } };
    }
    return { estado_validacion: 'dns_error', detail: { code: error && (error.code || error.message) } };
  }

  const https = await probe(domain, 'https:', options);
  if (https.status) return { estado_validacion: https.status, detail: https.detail || null };
  const httpsReason = classifyError(https.error);

  const http = await probe(domain, 'http:', options);
  if (http.status) return { estado_validacion: http.status, detail: http.detail || null };
  const httpReason = classifyError(http.error);

  return {
    estado_validacion: httpsReason || httpReason || 'unknown',
    detail: { https_error: https.error && https.error.code, http_error: http.error && http.error.code },
  };
}

module.exports = { checkDomainLiveness };
