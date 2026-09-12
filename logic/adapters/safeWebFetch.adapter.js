'use strict';

const http = require('http');
const https = require('https');
const dns = require('dns').promises;
const net = require('net');
const { URL } = require('url');

const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_TOTAL_TIMEOUT_MS = 30000;
const DEFAULT_MAX_REDIRECTS = 5;
const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;

function isAllowedProtocol(protocol) {
  return protocol === 'http:' || protocol === 'https:';
}

function isAllowedPort(url) {
  if (!url.port) return true;
  return (url.protocol === 'http:' && url.port === '80') ||
    (url.protocol === 'https:' && url.port === '443');
}

function parseIpv4(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const nums = parts.map((part) => Number(part));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return nums;
}

function isBlockedIpv4(ip) {
  const p = parseIpv4(ip);
  if (!p) return true;
  const [a, b] = p;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    a >= 224
  );
}

function isBlockedIpv6(ip) {
  const lower = ip.toLowerCase();
  if (
    lower === '::' ||
    lower === '::1' ||
    lower.startsWith('fc') ||
    lower.startsWith('fd') ||
    lower.startsWith('fe8') ||
    lower.startsWith('fe9') ||
    lower.startsWith('fea') ||
    lower.startsWith('feb') ||
    lower.startsWith('ff')
  ) {
    return true;
  }

  const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isBlockedIpv4(mapped[1]);

  return false;
}

function isBlockedIp(ip) {
  const family = net.isIP(ip);
  if (family === 4) return isBlockedIpv4(ip);
  if (family === 6) return isBlockedIpv6(ip);
  return true;
}

function validateUrlPolicy(url) {
  if (!isAllowedProtocol(url.protocol)) {
    throw Object.assign(new Error('Protocolo no permitido'), { code: 'WEBFETCH_BAD_PROTOCOL' });
  }
  if (!isAllowedPort(url)) {
    throw Object.assign(new Error('Puerto no permitido'), { code: 'WEBFETCH_BAD_PORT' });
  }
  if (!url.hostname) {
    throw Object.assign(new Error('Host inválido'), { code: 'WEBFETCH_BAD_HOST' });
  }
}

// FASE 3 (2026-09-12): dns.lookup() (usado abajo, vía getaddrinfo) no
// distingue "el dominio no existe" de "el dominio existe (tiene zona
// delegada) pero no tiene A ni AAAA" — ambos casos dan ENOTFOUND por
// igual. Confirmado con gob.ec: NS resuelve (es una zona real, paraguas
// de subdominios como presidencia.gob.ec), pero dns.resolve4/resolve6
// dan ENODATA específicamente, no ENOTFOUND. Esta consulta adicional
// SOLO corre cuando el lookup principal ya falló (no agrega latencia al
// camino feliz) — si ambos tipos de registro dan ENODATA (no otro tipo
// de error), se re-etiqueta el error para que el resto del sistema lo
// pueda distinguir de un fallo real de medición.
async function hasNoAddressRecordAtAll(hostname) {
  const checks = await Promise.allSettled([dns.resolve4(hostname), dns.resolve6(hostname)]);
  return checks.every((r) => r.status === 'rejected' && r.reason && r.reason.code === 'ENODATA');
}

async function resolvePublicAddresses(hostname, lookup = dns.lookup) {
  if (net.isIP(hostname)) {
    if (isBlockedIp(hostname)) {
      throw Object.assign(new Error('Destino interno bloqueado'), { code: 'WEBFETCH_BLOCKED_IP' });
    }
    return [{ address: hostname, family: net.isIP(hostname) }];
  }

  let records;
  try {
    records = await lookup(hostname, { all: true, verbatim: true });
  } catch (lookupError) {
    if (lookupError && lookupError.code === 'ENOTFOUND' && (await hasNoAddressRecordAtAll(hostname).catch(() => false))) {
      throw Object.assign(new Error('Dominio sin registros A ni AAAA'), { code: 'WEBFETCH_NO_ADDRESS_RECORD' });
    }
    throw lookupError;
  }
  const addresses = Array.isArray(records) ? records : [records];
  if (!addresses.length) {
    throw Object.assign(new Error('Sin direcciones IP'), { code: 'WEBFETCH_NO_ADDRESS' });
  }
  const blocked = addresses.find((record) => isBlockedIp(record.address));
  if (blocked) {
    throw Object.assign(new Error('Destino interno bloqueado'), {
      code: 'WEBFETCH_BLOCKED_IP',
      address: blocked.address
    });
  }
  return addresses;
}

function requestPage(url, address, options = {}) {
  return new Promise((resolve, reject) => {
    const lib = url.protocol === 'http:' ? http : https;
    const headers = { ...(options.headers || {}), Host: url.host };
    const requestOptions = {
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port || (url.protocol === 'http:' ? 80 : 443),
      method: options.method || 'GET',
      path: `${url.pathname}${url.search}`,
      headers,
      timeout: options.timeoutMs || DEFAULT_TIMEOUT_MS,
      servername: url.hostname,
      // El callback se difiere un tick (setImmediate) en vez de llamarse en
      // el mismo stack síncrono. Node tiene un caso conocido: si un
      // `lookup` personalizado resuelve de forma síncrona y el intento de
      // connect() falla de inmediato a nivel de SO (ENETUNREACH — visto en
      // producción con direcciones IPv6 sin ruta desde el contenedor), el
      // error puede escapar como excepción no capturada en vez de emitirse
      // por el evento 'error' normal de la request, saltándose el
      // try/catch de fetchSafePage() y tirando abajo todo el proceso
      // (uncaughtException -> process.exit(1) en server.js). Diferir el
      // callback rompe esa cadena síncrona y deja que Node arme el manejo
      // de errores normal antes de intentar conectar.
      lookup: (hostname, lookupOptions, callback) => {
        setImmediate(() => {
          if (lookupOptions?.all) {
            callback(null, [{ address: address.address, family: address.family }]);
            return;
          }
          callback(null, address.address, address.family);
        });
      }
    };

    const req = lib.request(requestOptions, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size <= (options.maxBodyBytes || DEFAULT_MAX_BODY_BYTES)) chunks.push(chunk);
      });
      res.on('end', () => {
        resolve({
          url: url.toString(),
          statusCode: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString(options.encoding || 'utf8')
        });
      });
    });
    req.on('error', reject);
    req.setTimeout(options.timeoutMs || DEFAULT_TIMEOUT_MS, () => {
      req.destroy(Object.assign(new Error('Timeout'), { code: 'TIMEOUT' }));
    });
    if (options.body) req.write(options.body);
    req.end();
  });
}

async function fetchSafePage(target, options = {}) {
  const url = typeof target === 'string' ? new URL(target) : target;
  validateUrlPolicy(url);
  const addresses = await resolvePublicAddresses(url.hostname, options.lookup);
  let lastError = null;
  for (const address of addresses) {
    try {
      return await (options.requestImpl || requestPage)(url, address, options);
    } catch (e) {
      lastError = e;
    }
  }
  throw lastError || new Error('Servicio no disponible');
}

async function resolveFinalWebTarget(target, options = {}) {
  const started = Date.now();
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  const chain = [];
  let url = typeof target === 'string' ? new URL(target) : target;

  for (let redirects = 0; redirects <= maxRedirects; redirects++) {
    if (Date.now() - started > (options.totalTimeoutMs || DEFAULT_TOTAL_TIMEOUT_MS)) {
      throw Object.assign(new Error('Timeout total'), { code: 'WEBFETCH_TOTAL_TIMEOUT' });
    }

    const page = await fetchSafePage(url, options);
    chain.push({
      url: url.toString(),
      statusCode: page.statusCode,
      location: page.headers?.location || null
    });

    if (!(page.statusCode >= 300 && page.statusCode < 400 && page.headers?.location)) {
      return { finalUrl: url.toString(), chain, response: page };
    }

    url = new URL(page.headers.location, url);
    validateUrlPolicy(url);
  }

  throw Object.assign(new Error('Demasiadas redirecciones'), { code: 'WEBFETCH_REDIRECT_LIMIT', chain });
}

module.exports = {
  fetchSafePage,
  resolveFinalWebTarget,
  isBlockedIp,
  validateUrlPolicy
};
