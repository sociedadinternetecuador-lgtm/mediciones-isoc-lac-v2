'use strict';

/**
 * Public Suffix List adapter — sección ICANN.
 *
 * Descarga y cachea localmente https://publicsuffix.org/list/public_suffix_list.dat
 * y expone publicSuffix(domain) replicando la lógica de
 * validador/validar_dominios_isoc_lac.py (clase ICANNPublicSuffixList):
 * reglas exactas, wildcard "*." y excepciones "!", usando SOLO la sección
 * ICANN (no PRIVATE). No se usa una lista manual de sufijos.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { domainToASCII } = require('url');

const PSL_URL = 'https://publicsuffix.org/list/public_suffix_list.dat';
const PSL_CACHE_DAYS = 7;
const MEMORY_CACHE_MS = 10 * 60 * 1000; // evita reparsear el archivo en cada request

const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR, 'psl_cache')
  : path.resolve(__dirname, '../../data/psl_cache');
const PSL_CACHE_PATH = path.join(DATA_DIR, 'public_suffix_list.dat');

function fetchText(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'Mediciones-ISOC-LAC/1.0' } }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error('Timeout descargando Public Suffix List'));
    });
  });
}

async function downloadPsl() {
  const data = await fetchText(PSL_URL, 20000);
  if (data.length < 10000) {
    throw new Error('La respuesta de Public Suffix List parece incompleta.');
  }
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(PSL_CACHE_PATH, data, 'utf-8');
  return data;
}

class IcannPublicSuffixList {
  constructor(text) {
    this.exact = new Set();
    this.wildcards = new Set();
    this.exceptions = new Set();
    this._parse(text);
  }

  _parse(text) {
    let inIcann = false;

    for (const rawLine of text.split(/\r\n|\r|\n/)) {
      const line = rawLine.trim();

      if (line === '// ===BEGIN ICANN DOMAINS===') { inIcann = true; continue; }
      if (line === '// ===END ICANN DOMAINS===') break;
      if (!inIcann || !line || line.startsWith('//')) continue;

      const rawRule = line.toLowerCase();
      let prefix = '';
      let body = rawRule;

      if (rawRule.startsWith('!')) {
        prefix = '!';
        body = rawRule.slice(1);
      } else if (rawRule.startsWith('*.')) {
        prefix = '*.';
        body = rawRule.slice(2);
      }

      let encoded;
      try {
        encoded = domainToASCII(body).toLowerCase();
      } catch {
        continue;
      }
      if (!encoded) continue;

      if (prefix === '!') this.exceptions.add(encoded);
      else if (prefix === '*.') this.wildcards.add(encoded);
      else this.exact.add(encoded);
    }

    if (this.exact.size === 0) {
      throw new Error('La Public Suffix List no contiene reglas ICANN utilizables.');
    }
  }

  // Réplica de ICANNPublicSuffixList.public_suffix() del validador Python.
  publicSuffix(domain) {
    const labels = domain.toLowerCase().replace(/\.$/, '').split('.');
    if (labels.length < 2) return labels[labels.length - 1];

    for (let i = 0; i < labels.length; i++) {
      const candidate = labels.slice(i).join('.');
      if (this.exceptions.has(candidate)) {
        const parts = candidate.split('.');
        return parts.length > 1 ? parts.slice(1).join('.') : candidate;
      }
    }

    const matches = [[1, labels[labels.length - 1]]];

    for (let i = 0; i < labels.length; i++) {
      const candidate = labels.slice(i).join('.');
      if (this.exact.has(candidate)) matches.push([labels.length - i, candidate]);
    }

    for (let i = 1; i < labels.length; i++) {
      const base = labels.slice(i).join('.');
      if (this.wildcards.has(base)) {
        const suffix = labels.slice(i - 1).join('.');
        matches.push([labels.length - (i - 1), suffix]);
      }
    }

    matches.sort((a, b) => b[0] - a[0]);
    return matches[0][1];
  }
}

let cachedInstance = null;
let cachedAt = 0;

async function getPublicSuffixList() {
  const now = Date.now();
  if (cachedInstance && (now - cachedAt) < MEMORY_CACHE_MS) {
    return cachedInstance;
  }

  const exists = fs.existsSync(PSL_CACHE_PATH);
  let stale = true;
  if (exists) {
    const ageMs = now - fs.statSync(PSL_CACHE_PATH).mtimeMs;
    stale = ageMs > PSL_CACHE_DAYS * 86400 * 1000;
  }

  let origin;
  let text;

  if (!exists || stale) {
    try {
      text = await downloadPsl();
      origin = 'downloaded';
    } catch (error) {
      if (!exists) throw error;
      text = fs.readFileSync(PSL_CACHE_PATH, 'utf-8');
      origin = 'cached_after_update_failure';
    }
  } else {
    text = fs.readFileSync(PSL_CACHE_PATH, 'utf-8');
    origin = 'cached';
  }

  const sha256 = crypto.createHash('sha256').update(text, 'utf-8').digest('hex');
  const fetchedAt = fs.statSync(PSL_CACHE_PATH).mtime.toISOString();

  cachedInstance = {
    psl: new IcannPublicSuffixList(text),
    origin,
    path: PSL_CACHE_PATH,
    sha256,
    fetchedAt,
    sourceUrl: PSL_URL,
  };
  cachedAt = now;
  return cachedInstance;
}

module.exports = { getPublicSuffixList };
