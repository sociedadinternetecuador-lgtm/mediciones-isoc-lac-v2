'use strict';

/**
 * Normalización de datasets de dominios — Preparación de datasets (Fuente →
 * Carga → Normalización).
 *
 * Réplica en JS de parse_input()/static_valid() de
 * validador/validar_dominios_isoc_lac.py, para que la normalización del
 * portal sea consistente con la metodología ya definida. NO ejecuta
 * validación DNS ni clasifica VALID/NXDOMAIN/REVIEW — eso corresponde a una
 * etapa posterior todavía no habilitada.
 */

const { domainToASCII } = require('url');

const LABEL_RE = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$/;
const ASCII_ONLY_RE = /^[\x00-\x7F]*$/;
const IDNA_DOT_SPLIT_RE = /[.。．｡]/; // los 4 puntos que reconoce el codec idna

// Réplica de str.splitlines() de Python: no genera un elemento vacío final
// cuando el texto termina en salto de línea.
function splitLines(text) {
  const lines = text.split(/\r\n|\r|\n/);
  if (lines.length && lines[lines.length - 1] === '' && /[\r\n]$/.test(text)) {
    lines.pop();
  }
  return lines;
}

// Réplica de str.strip(chars) de Python: quita TODAS las apariciones
// consecutivas de cualquiera de los caracteres en `chars`, en ambos extremos
// (a diferencia de un regex ancorado que solo quita una).
function stripBoth(s, chars) {
  const set = new Set(chars);
  let start = 0;
  let end = s.length;
  while (start < end && set.has(s[start])) start++;
  while (end > start && set.has(s[end - 1])) end--;
  return s.slice(start, end);
}

// Réplica de str.rstrip(chars) de Python: solo el extremo derecho.
function rstrip(s, chars) {
  const set = new Set(chars);
  let end = s.length;
  while (end > 0 && set.has(s[end - 1])) end--;
  return s.slice(0, end);
}

// Réplica exacta de normalize_domain() del validador Python:
//   raw.strip().strip('"').strip("'").rstrip(".").lower()
function normalizeDomainLine(raw) {
  let s = raw.trim();
  s = stripBoth(s, '"');
  s = stripBoth(s, "'");
  s = rstrip(s, '.');
  return s.toLowerCase();
}

// Réplica del codec 'idna' (RFC 3490) que usa Python vía str.encode('idna'),
// NO el algoritmo WHATWG/UTS46 de domainToASCII. Es clave: si el string
// COMPLETO ya es ASCII, Python toma un "fast path" (encodings/idna.py,
// Codec.encode) que NO valida caracteres en absoluto — solo longitud por
// etiqueta (0 < len < 64 para todas menos la última, que solo exige <64).
// Por eso "not a domain" (con espacios) es aceptado por Python como ASCII
// válido; solo domainToASCII lo rechazaría. Únicamente las etiquetas NO-ASCII
// pasan por nameprep + punycode (aquí delegado a domainToASCII por etiqueta).
function pythonIdnaEncode(domain) {
  if (domain === '') return '';

  if (ASCII_ONLY_RE.test(domain)) {
    const labels = domain.split('.');
    for (let i = 0; i < labels.length - 1; i++) {
      if (!(labels[i].length > 0 && labels[i].length < 64)) {
        throw new Error('label empty or too long');
      }
    }
    if (labels[labels.length - 1].length >= 64) {
      throw new Error('label too long');
    }
    return domain;
  }

  const labels = domain.split(IDNA_DOT_SPLIT_RE);
  let trailingDot = '';
  if (labels.length && labels[labels.length - 1] === '') {
    labels.pop();
    trailingDot = '.';
  }
  if (labels.length === 0) throw new Error('empty domain');

  const encoded = labels.map((label) => {
    if (ASCII_ONLY_RE.test(label)) {
      if (!(label.length > 0 && label.length < 64)) throw new Error('label empty or too long');
      return label;
    }
    const a = domainToASCII(label);
    if (!a) throw new Error('idna encoding failed');
    return a;
  });

  return encoded.join('.') + trailingDot;
}

// Réplica de static_valid() del validador Python.
function staticValid(domain, tld) {
  if (!domain) return { ok: false, reason: 'empty' };

  let ascii;
  try {
    ascii = pythonIdnaEncode(domain).toLowerCase();
  } catch {
    return { ok: false, reason: 'idna_error' };
  }
  if (!ascii) return { ok: false, reason: 'idna_error' };

  if (!ascii.endsWith('.' + tld)) return { ok: false, reason: 'outside_tld', ascii };
  if (ascii === tld) return { ok: false, reason: 'tld_itself', ascii };
  if (ascii.length > 253) return { ok: false, reason: 'too_long', ascii };

  const labels = ascii.split('.');
  if (labels.some((label) => !LABEL_RE.test(label))) {
    return { ok: false, reason: 'invalid_label', ascii };
  }

  return { ok: true, ascii };
}

// Réplica de parse_input() del validador Python.
function parseDatasetText(text, tld) {
  const rawLines = splitLines(text);
  const seen = new Set();
  const normalized = [];
  const rejected = [];
  const rejectedCounts = {};
  const stats = {
    raw_lines: rawLines.length,
    empty: 0,
    duplicates: 0,
    rejected: 0,
    normalized: 0,
  };

  for (const line of rawLines) {
    const first = line.split(',')[0];
    const d = normalizeDomainLine(first);

    if (!d) {
      stats.empty += 1;
      continue;
    }

    const result = staticValid(d, tld);
    if (!result.ok) {
      rejected.push([d, result.reason]);
      rejectedCounts[result.reason] = (rejectedCounts[result.reason] || 0) + 1;
      continue;
    }

    if (seen.has(result.ascii)) {
      stats.duplicates += 1;
      continue;
    }

    seen.add(result.ascii);
    normalized.push(result.ascii);
  }

  normalized.sort();
  stats.rejected = rejected.length;
  stats.normalized = normalized.length;

  return { normalized, rejected, rejectedCounts, stats };
}

module.exports = { parseDatasetText, normalizeDomainLine, staticValid };
