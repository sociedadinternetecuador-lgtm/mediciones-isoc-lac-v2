const http = require('http');
const dns = require('dns').promises;
const DEFAULT_SERVERS = ['8.8.8.8', '8.8.4.4'];
dns.setServers(DEFAULT_SERVERS);
const net = require('net');
const https = require('https');
const tls = require('tls');
const { domainToASCII } = require('url');
const { URL } = require('url');
const fs = require('fs');
const path = require('path');
const { validateDomainInput } = require("./logic/validators/domain.validator");
const { getDnssecAnalysis } = require("./services/dnssec.service");
const { processDnssecAnalysis } = require("./logic/processors/dnssec.processor");
const { buildZoneChain } = require("./logic/builders/zoneChain.builder");
const { handleAggregateRequest } = require('./aggregate/routes/aggregate.routes');
const { handleZonemasterRequest } = require('./aggregate/zonemaster/zonemaster.routes');
const { handleObservatoryRequest } = require('./aggregate/observatory.routes');
const dnsPacket = require('dns-packet'); 
const htmlCache = new Map();
const headerCache = new Map();

async function resolveAddresses(domain) {
  const v4 = await dns.resolve4(domain).catch(() => []);
  const v6 = await dns.resolve6(domain).catch(() => []);
  return { v4, v6 };
}

async function resolveFirstIp(domain) {
  const { v4, v6 } = await resolveAddresses(domain);
  if (v4.length) return { ip: v4[0], family: 4 };
  if (v6.length) return { ip: v6[0], family: 6 };
  return { ip: null, family: null };
}

async function lookupIpMeta(ip) {
  if (!ip) throw new Error('Sin dirección IP');
  const data = await fetchJSON(`https://ipwho.is/${encodeURIComponent(ip)}`);
  if (!data || data.success === false) {
    const message =
      typeof data?.message === 'string' && data.message.trim()
        ? data.message.trim()
        : 'Servicio no disponible';
    throw new Error(message);
  }
  const connection = data.connection || {};
  return {
    ip,
    city: data.city || '',
    region: data.region || data.region_name || data.region_code || '',
    country: data.country || data.country_name || '',
    latitude: data.latitude ?? null,
    longitude: data.longitude ?? null,
    timezone:
      (data.timezone && data.timezone.id) ||
      data.timezone ||
      data.timezone_gmt ||
      '',
    asn: connection.asn || data.asn || null,
    org: connection.org || data.org || data.connection?.organization || '',
    isp: connection.isp || data.isp || '',
    network:
      connection.route ||
      connection.network ||
      connection.domain ||
      data.network ||
      ''
  };
}

const ALGO_MAP = {
  1: 'RSA/MD5',
  2: 'Diffie-Hellman',
  3: 'DSA/SHA1',
  5: 'RSA/SHA-1',
  6: 'DSA-NSEC3-SHA1',
  7: 'RSASHA1-NSEC3-SHA1',
  8: 'RSA/SHA-256',
  10: 'RSA/SHA-512',
  13: 'ECDSA/P256/SHA-256',
  14: 'ECDSA/P384/SHA-384',
  15: 'Ed25519',
  16: 'Ed448'
};

function normalizeDomain(domain) {
  try {
    return domainToASCII(domain.toLowerCase());
  } catch (e) {
    return domain;
  }
}

function errorMessage(e) {
  if (e && typeof e === 'object') {
    if (e.code === 'ENOTFOUND') return 'Dominio no encontrado';
    if (e.code === 'ETIMEOUT') return 'Timeout';
    if (e.code === 'ECONNREFUSED') return 'Conexión rechazada';
    if (e.code === 'EAI_AGAIN') return 'Problema de DNS';
  }
  return 'Servicio no disponible';
}

function sendJSON(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(JSON.stringify(data));
}

async function handleMx(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const records = await dns.resolveMx(domain);
    sendJSON(res, 200, { domain, records });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

function smtpQuery(server, port) {
  return new Promise(resolve => {
    const socket = net.createConnection(port, server);
    let buffer = '';
    let ehloSent = false;
    const timer = setTimeout(() => {
      socket.destroy();
      resolve({ status: 'timeout' });
    }, 15000);

    socket.on('data', data => {
      buffer += data.toString();
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop();
      for (const line of lines) {
        if (!ehloSent && /^220 /.test(line)) {
          socket.write('EHLO www.google.com\r\n');
          ehloSent = true;
        } else if (ehloSent && /^250[ -]/.test(line)) {
          if (/SMTPUTF8/i.test(line)) {
            clearTimeout(timer);
            socket.end();
            return resolve({ status: 'supports' });
          }
          if (line.startsWith('250 ')) {
            clearTimeout(timer);
            socket.end();
            return resolve({ status: 'no' });
          }
        }
      }
    });

    socket.on('error', () => {
      clearTimeout(timer);
      resolve({ status: 'connection-error' });
    });

    socket.on('end', () => {
      clearTimeout(timer);
      resolve({ status: 'no' });
    });
  });
}

async function checkSmtpUtf8(server) {
  // Try common SMTP ports for resilience
  const ports = [25, 587];
  let last = { status: 'connection-error' };
  for (const port of ports) {
    const res = await smtpQuery(server, port);
    if (res.status === 'supports') return res;
    if (res.status === 'no' && last.status !== 'supports') last = res;
    if (res.status === 'timeout' || res.status === 'connection-error') last = res;
  }
  return last;
}

async function handleSmtpUtf8(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const mx = await dns.resolveMx(domain);
    const results = [];
    for (const record of mx) {
      const { status } = await checkSmtpUtf8(record.exchange);
      results.push({ server: record.exchange, status });
    }
    sendJSON(res, 200, { domain, results });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function dnssecGoogle(domain) {
  domain = normalizeDomain(domain);
  const result = { parent: false, child: false, algorithms: [] };
  try {
    const ds = await fetchJSON(`https://dns.google/resolve?name=${domain}&type=DS`);
    if (Array.isArray(ds.Answer) && ds.Answer.length > 0) {
      result.parent = true;
      ds.Answer.forEach(a => {
        const parts = a.data.split(' ');
        const algo = Number(parts[1]);
        result.algorithms.push(ALGO_MAP[algo] || String(algo));
      });
    }
  } catch (e) {}
  try {
    const dnskey = await fetchJSON(`https://dns.google/resolve?name=${domain}&type=DNSKEY`);
    if (Array.isArray(dnskey.Answer) && dnskey.Answer.length > 0) {
      result.child = true;
      dnskey.Answer.forEach(a => {
        const parts = a.data.split(' ');
        const algo = Number(parts[2]);
        result.algorithms.push(ALGO_MAP[algo] || String(algo));
      });
    }
  } catch (e) {}
  return result;
}

async function handleDnssec(domain, res) {
  domain = normalizeDomain(domain);
  const google = await dnssecGoogle(domain);
  const algorithms = [...new Set(google.algorithms.filter(Boolean))];
  const valid = google.parent && google.child;
  sendJSON(res, 200, { domain, methods: { google }, algorithms, valid });
}

async function handleDkim(domain, selector, res) {
  domain = normalizeDomain(domain);
  try {
    const txt = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
    const flat = txt.flat().join('');
    const found = /v=DKIM1/i.test(flat);
    sendJSON(res, 200, { domain, selector, found });
  } catch (e) {
    sendJSON(res, 200, { domain, selector, found: false });
  }
}

function pickLib(target) {
  const url = typeof target === 'string' ? new URL(target) : target;
  return url.protocol === 'http:' ? http : https;
}

function fetchJSON(target, options = {}) {
  return new Promise((resolve, reject) => {
    const url = typeof target === 'string' ? new URL(target) : target;
    const lib = pickLib(url);
    const req = lib.request(
      url,
      { method: options.method || 'GET', headers: options.headers || {} },
      r => {
        let data = '';
        r.on('data', chunk => (data += chunk));
        r.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            reject(e);
          }
        });
      }
    );
    req.on('error', reject);
    req.setTimeout(options.timeout || 15000, () => {
      req.destroy(new Error('Timeout'));
    });
    if (options.body) req.write(options.body);
    req.end();
  });
}

function fetchText(target, options = {}) {
  return new Promise((resolve, reject) => {
    const url = typeof target === 'string' ? new URL(target) : target;
    const lib = pickLib(url);
    const req = lib.request(
      url,
      { method: options.method || 'GET', headers: options.headers || {} },
      r => {
        let data = '';
        r.on('data', chunk => (data += chunk));
        r.on('end', () => resolve(data));
      }
    );
    req.on('error', reject);
    req.setTimeout(options.timeout || 15000, () => {
      req.destroy(new Error('Timeout'));
    });
    if (options.body) req.write(options.body);
    req.end();
  });
}

function fetchHeaders(target, useHttp = false) {
  return fetchPage(target, { method: 'HEAD', useHttp }).then(({ headers, statusCode }) => ({
    headers,
    statusCode
  }));
}

function fetchPage(target, options = {}) {
  return new Promise((resolve, reject) => {
    try {
      const url = typeof target === 'string' ? new URL(target) : target;
      const lib = options.useHttp || url.protocol === 'http:' ? http : https;
      const req = lib.request(
        url,
        {
          method: options.method || 'GET',
          headers: options.headers || {},
          timeout: options.timeout || 15000
        },
        res => {
          const chunks = [];
          res.on('data', chunk => chunks.push(chunk));
          res.on('end', () => {
            resolve({
              statusCode: res.statusCode,
              headers: res.headers,
              body: Buffer.concat(chunks).toString(options.encoding || 'utf8')
            });
          });
        }
      );
      req.on('error', reject);
      req.setTimeout(options.timeout || 15000, () => {
        req.destroy(new Error('Timeout'));
      });
      if (options.body) req.write(options.body);
      req.end();
    } catch (e) {
      reject(e);
    }
  });
}

function cacheGet(cache, key, ttl = 60000) {
  const item = cache.get(key);
  if (!item) return null;
  if (Date.now() - item.timestamp > ttl) {
    cache.delete(key);
    return null;
  }
  return item.value;
}

function cacheSet(cache, key, value) {
  cache.set(key, { timestamp: Date.now(), value });
}

async function fetchWebsite(domain) {
  const cached = cacheGet(htmlCache, domain);
  if (cached) return cached;
  const targets = [`https://${domain}`, `http://${domain}`];
  for (const target of targets) {
    try {
      const page = await fetchPage(target);
      if (page.statusCode && page.statusCode >= 200 && page.statusCode < 400) {
        const value = { url: target, ...page };
        cacheSet(htmlCache, domain, value);
        cacheSet(headerCache, domain, { headers: page.headers, statusCode: page.statusCode });
        return value;
      }
    } catch (e) {}
  }
  throw new Error('Servicio no disponible');
}

async function rpkiValidity(ip) {
  try {
    const info = await fetchJSON(
      `https://stat.ripe.net/data/network-info/data.json?resource=${ip}`
    );
    const prefix =
      info?.data?.prefix || info?.data?.resources?.[0] || info?.data?.resource;
    const asnEntry = info?.data?.asns?.[0];
    const asn =
      typeof asnEntry === 'number'
        ? asnEntry
        : typeof asnEntry === 'object'
        ? asnEntry.asn || asnEntry.id
        : null;

    let state = 'unknown';

    if (asn) {
      try {
        const cf = await fetchJSON(
          `https://rpki.cloudflare.com/api/v1/validity?ip=${encodeURIComponent(
            ip
          )}&asn=${asn}`
        );
        const validity =
          cf?.state?.validity ||
          cf?.state ||
          cf?.validity ||
          cf?.result ||
          null;
        if (validity) state = String(validity).toLowerCase();
      } catch (e) {}
    }

    if (state === 'unknown') {
      try {
        const ripe = await fetchJSON(
          prefix
            ? `https://stat.ripe.net/data/rpki-validation/data.json?resource=${encodeURIComponent(
                prefix
              )}${asn ? `&origin_asn=${asn}` : ''}`
            : `https://stat.ripe.net/data/rpki-validation/data.json?resource=${encodeURIComponent(
                ip
              )}`
        );
        const validity =
          ripe?.data?.validity || ripe?.status || ripe?.state || ripe?.validity;
        if (validity) state = String(validity).toLowerCase();
      } catch (e) {}
    }

    if (!['valid', 'invalid'].includes(state)) state = 'unknown';
    return { state, asn: asn || null, prefix: prefix || null };
  } catch (e) {
    return { state: 'error', asn: null };
  }
}

async function handleRpki(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const { v4, v6 } = await resolveAddresses(domain);
    const ips = [...v4, ...v6];
    if (!ips.length) return sendJSON(res, 200, { domain, error: 'Sin direcciones IP' });
    const results = [];
    for (const ip of ips) {
      const { state, asn, prefix } = await rpkiValidity(ip);
      results.push({ ip, state, asn, prefix });
    }
    const overall = results.length && results.every(r => r.state === 'valid');
    sendJSON(res, 200, { domain, results, valid: Boolean(overall) });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleWhois(domain, res) {
  domain = normalizeDomain(domain);
  try {
    let name = '';
    let country = '';
    try {
      const html = await fetchText(`https://www.whois.com/whois/${domain}`);
      const orgMatch = html.match(
        /Registrant Organization:\s*<\/div>\s*<div class="df-value">([^<]*)/i
      );
      if (orgMatch) name = orgMatch[1].trim();
      const countryMatch = html.match(
        /Registrant Country:\s*<\/div>\s*<div class="df-value">([^<]*)/i
      );
      if (countryMatch) country = countryMatch[1].trim();
    } catch (e) {}

    if (!name && !country) {
      const data = await fetchJSON(`https://rdap.org/domain/${domain}`);
      const registrant = data.entities?.find(e => e.roles?.includes('registrant'));
      const vcard = registrant?.vcardArray?.[1] || [];
      for (const item of vcard) {
        if (item[0] === 'fn') name = item[3];
        if (item[0] === 'adr') {
          const label = item[1]?.label || '';
          country = label.split('\n').pop();
        }
        if (item[0] === 'country') country = item[3];
      }
      if (!name && data.name) name = data.name;
    }

    sendJSON(res, 200, { domain, name, country });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleW3C(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchJSON(
      `https://validator.w3.org/nu/?doc=https://${domain}&out=json`
    );
    const messages = Array.isArray(data.messages) ? data.messages : [];
    const errors = messages.filter(m => m.type === 'error').length;
    const warnings = messages.filter(m => m.type !== 'error').length;
    sendJSON(res, 200, { domain, errors, warnings });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleHeaders(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const httpsRes = await fetchHeaders(`https://${domain}`);
    const httpRes = await fetchHeaders(`http://${domain}`, true).catch(
      () => null
    );
    const result = {
      domain,
      https: httpsRes.statusCode === 200,
      redirect:
        httpRes &&
        httpRes.statusCode >= 300 &&
        httpRes.statusCode < 400 &&
        typeof httpRes.headers.location === 'string' &&
        httpRes.headers.location.startsWith('https://'),
      hsts: Boolean(httpsRes.headers['strict-transport-security']),
      csp: Boolean(httpsRes.headers['content-security-policy']),
      xfo: Boolean(httpsRes.headers['x-frame-options']),
      xcto: Boolean(httpsRes.headers['x-content-type-options']),
      referrer: Boolean(httpsRes.headers['referrer-policy']),
      permissions: Boolean(httpsRes.headers['permissions-policy']),
      xxss: Boolean(httpsRes.headers['x-xss-protection']),
      compression: Boolean(httpsRes.headers['content-encoding']),
      server: httpsRes.headers['server'] || '',
      headers: httpsRes.headers
    };
    sendJSON(res, 200, result);
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleCaa(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const records = await dns.resolve(domain, 'CAA');
    sendJSON(res, 200, { domain, records });
  } catch (e) {
    if (e.code === 'ENODATA' || e.code === 'ENOTFOUND')
      sendJSON(res, 200, { domain, records: [] });
    else sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleTlsa(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const records = await dns.resolve(`_443._tcp.${domain}`, 'TLSA');
    sendJSON(res, 200, { domain, records });
  } catch (e) {
    if (e.code === 'ENODATA' || e.code === 'ENOTFOUND')
      sendJSON(res, 200, { domain, records: [] });
    else sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleSecurityTxt(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchHeaders(`https://${domain}/.well-known/security.txt`);
    const found = data.statusCode && data.statusCode < 400;
    sendJSON(res, 200, { domain, found });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleTls(domain, res) {
  domain = normalizeDomain(domain);
  let settled = false;
  try {
    const socket = tls.connect(
      { host: domain, servername: domain, port: 443, rejectUnauthorized: false, requestOCSP: true },
      () => {
        if (settled) return;
        settled = true;
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        const key = socket.getEphemeralKeyInfo ? socket.getEphemeralKeyInfo() : null;
        const ocsp = Boolean(socket.ocspResponse);
        socket.end();
        sendJSON(res, 200, {
          domain,
          protocol,
          cipher: cipher && cipher.name,
          key,
          ocsp
        });
      }
    );
    socket.setTimeout(15000, () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      sendJSON(res, 200, { domain, error: 'Timeout' });
    });
    socket.on('error', e => {
      if (settled) return;
      settled = true;
      sendJSON(res, 200, { domain, error: errorMessage(e) });
    });
  } catch (e) {
    if (!settled) sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleIpInfo(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const { v4: ipv4, v6: ipv6 } = await resolveAddresses(domain);
    const geo = [];
    const ips = [...ipv4, ...ipv6].slice(0, 5);
    for (const ip of ips) {
      try {
        const info = await lookupIpMeta(ip);
        geo.push(info);
      } catch (e) {}
    }
    sendJSON(res, 200, { domain, ipv4, ipv6, geo });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleSslChain(domain, res) {
  domain = normalizeDomain(domain);
  let settled = false;
  try {
    const socket = tls.connect(
      { host: domain, servername: domain, port: 443, rejectUnauthorized: false },
      () => {
        if (settled) return;
        settled = true;
        const chain = [];
        const seen = new Set();
        let cert = socket.getPeerCertificate(true);
        while (cert && Object.keys(cert).length) {
          if (seen.has(cert.fingerprint256)) break;
          seen.add(cert.fingerprint256);
          chain.push({
            subject: cert.subject,
            issuer: cert.issuer,
            valid_from: cert.valid_from,
            valid_to: cert.valid_to,
            serialNumber: cert.serialNumber,
            fingerprint256: cert.fingerprint256,
            subjectaltname: cert.subjectaltname
          });
          if (!cert.issuerCertificate || cert.issuerCertificate === cert) break;
          cert = cert.issuerCertificate;
        }
        const protocol = socket.getProtocol();
        socket.end();
        sendJSON(res, 200, { domain, protocol, chain });
      }
    );
    socket.on('error', e => {
      if (settled) return;
      settled = true;
      sendJSON(res, 200, { domain, error: errorMessage(e) });
    });
    socket.setTimeout(15000, () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      sendJSON(res, 200, { domain, error: 'Timeout' });
    });
  } catch (e) {
    if (!settled) sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleDnsRecords(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const records = {};
    records.A = await dns.resolve4(domain).catch(() => []);
    records.AAAA = await dns.resolve6(domain).catch(() => []);
    records.MX = await dns.resolveMx(domain).catch(() => []);
    records.NS = await dns.resolveNs(domain).catch(() => []);
    records.TXT = await dns.resolveTxt(domain).catch(() => []);
    records.CNAME = await dns.resolveCname(domain).catch(() => []);
    sendJSON(res, 200, { domain, records });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleCookies(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const page = await fetchWebsite(domain);
    const cookies = page.headers['set-cookie'] || [];
    sendJSON(res, 200, { domain, cookies });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleCrawlRules(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const urls = [`https://${domain}/robots.txt`, `http://${domain}/robots.txt`];
    for (const url of urls) {
      try {
        const data = await fetchPage(url);
        if (data.statusCode && data.statusCode < 400) {
          return sendJSON(res, 200, {
            domain,
            found: true,
            content: data.body
          });
        }
      } catch (e) {}
    }
    sendJSON(res, 200, { domain, found: false, content: '' });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleQuality(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchJSON(
      `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=https://${domain}`
    );
    const lighthouse = data.lighthouseResult?.categories || {};
    sendJSON(res, 200, {
      domain,
      performance: lighthouse.performance?.score,
      accessibility: lighthouse.accessibility?.score,
      bestPractices: lighthouse['best-practices']?.score,
      seo: lighthouse.seo?.score,
      pwa: lighthouse.pwa?.score || null
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: 'Servicio no disponible' });
  }
}

async function handleServerLocation(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const { ip } = await resolveFirstIp(domain);
    if (!ip) return sendJSON(res, 200, { domain, error: 'Sin dirección IP' });
    const info = await lookupIpMeta(ip);
    sendJSON(res, 200, {
      domain,
      ip,
      city: info.city,
      region: info.region,
      country: info.country,
      latitude: info.latitude,
      longitude: info.longitude,
      timezone: info.timezone
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleAssociatedHosts(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const text = await fetchText(`https://api.hackertarget.com/hostsearch/?q=${domain}`);
    if (!text || /error/i.test(text))
      return sendJSON(res, 200, { domain, hosts: [], error: 'Sin datos' });
    const hosts = text
      .trim()
      .split('\n')
      .map(line => {
        const [host, ip] = line.split(',');
        return { host, ip };
      })
      .filter(h => h.host);
    sendJSON(res, 200, { domain, hosts });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function followRedirects(url, limit = 5, chain = []) {
  if (limit < 0) return chain;
  const { headers, statusCode } = await fetchPage(url, { method: 'HEAD' });
  const entry = { url, statusCode, location: headers.location || null };
  chain.push(entry);
  if (statusCode && statusCode >= 300 && statusCode < 400 && headers.location) {
    const next = headers.location.startsWith('http')
      ? headers.location
      : new URL(headers.location, url).toString();
    return followRedirects(next, limit - 1, chain);
  }
  return chain;
}

async function handleRedirectChain(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const chain = await followRedirects(`http://${domain}`);
    sendJSON(res, 200, { domain, chain });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleTxtRecords(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const records = await dns.resolveTxt(domain);
    sendJSON(res, 200, { domain, records });
  } catch (e) {
    if (e.code === 'ENODATA' || e.code === 'ENOTFOUND')
      sendJSON(res, 200, { domain, records: [] });
    else sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleServerStatus(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const page = await fetchPage(`https://${domain}`, { method: 'HEAD' });
    sendJSON(res, 200, {
      domain,
      statusCode: page.statusCode,
      location: page.headers?.location || null
    });
  } catch (e) {
    try {
      const page = await fetchPage(`http://${domain}`, {
        method: 'HEAD',
        useHttp: true
      });
      sendJSON(res, 200, {
        domain,
        statusCode: page.statusCode,
        location: page.headers?.location || null
      });
    } catch (err) {
      sendJSON(res, 200, { domain, error: errorMessage(err) });
    }
  }
}

async function handleOpenPorts(domain, res) {
  domain = normalizeDomain(domain);
  const ports = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 8080];
  const results = [];
  await Promise.all(
    ports.map(
      port =>
        new Promise(resolve => {
          const socket = net.createConnection({ host: domain, port, timeout: 4000 });
          socket.on('connect', () => {
            results.push({ port, open: true });
            socket.destroy();
            resolve();
          });
          socket.on('timeout', () => {
            socket.destroy();
            resolve();
          });
          socket.on('error', () => {
            resolve();
          });
        })
    )
  );
  sendJSON(res, 200, { domain, ports: results });
}

async function handleTraceroute(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const text = await fetchText(`https://api.hackertarget.com/mtr/?q=${domain}`);
    if (!text || /api count exceeded/i.test(text) || /error/i.test(text)) {
      return sendJSON(res, 200, {
        domain,
        error: 'Servicio no disponible (límite alcanzado)'
      });
    }
    const hops = text
      .split('\n')
      .slice(1)
      .filter(Boolean)
      .map(line => line.trim())
      .filter(line => /^\d+\./.test(line));
    sendJSON(res, 200, { domain, hops });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleCarbon(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchJSON(`https://api.websitecarbon.com/site?url=https://${domain}`);
    sendJSON(res, 200, { domain, data });
  } catch (e) {
    sendJSON(res, 200, { domain, error: 'Servicio no disponible' });
  }
}

async function handleServerInfo(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const { ip } = await resolveFirstIp(domain);
    if (!ip) return sendJSON(res, 200, { domain, error: 'Sin dirección IP' });
    const info = await lookupIpMeta(ip);
    sendJSON(res, 200, {
      domain,
      ip,
      asn: info.asn,
      org: info.org || info.isp,
      network: info.network,
      isp: info.isp,
      country: info.country,
      city: info.city
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleDomainInfo(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchJSON(`https://rdap.org/domain/${domain}`);
    const events = Array.isArray(data.events) ? data.events : [];
    const creation = events.find(e => e.eventAction === 'registration')?.eventDate || null;
    const expiration = events.find(e => e.eventAction === 'expiration')?.eventDate || null;
    sendJSON(res, 200, {
      domain,
      registry: data.registryName || null,
      status: data.status || [],
      creation,
      expiration
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleDnsSecurity(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const google = await dnssecGoogle(domain);
    let doh = false;
    try {
      const cf = await fetchJSON(
        `https://cloudflare-dns.com/dns-query?name=${domain}&type=DS`,
        {
          headers: { accept: 'application/dns-json' }
        }
      );
      doh = Array.isArray(cf.Answer) && cf.Answer.length > 0;
    } catch (e) {}
    const algorithms = [...new Set(google.algorithms.filter(Boolean))];
    sendJSON(res, 200, {
      domain,
      methods: { google },
      doh,
      valid: google.parent && google.child,
      algorithms
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

function analyzeSiteFeatures(html) {
  const lower = html.toLowerCase();
  return {
    hasForms: /<form/i.test(lower),
    hasLogin: /login|iniciar sesi[oó]n|sign in/.test(lower),
    hasSearch: /type="search"/.test(lower) || /search/.test(lower),
    hasVideo: /<video|youtube.com\/embed/.test(lower),
    hasAnalytics: /google-analytics|gtag\(|googletagmanager/.test(lower),
    hasEcommerce: /cart|checkout|woocommerce/.test(lower)
  };
}

function detectTechStack(html) {
  const lower = html.toLowerCase();
  const stack = [];
  if (/wp-content|wordpress/.test(lower)) stack.push('WordPress');
  if (/drupal/.test(lower)) stack.push('Drupal');
  if (/joomla/.test(lower)) stack.push('Joomla');
  if (/shopify/.test(lower)) stack.push('Shopify');
  if (/react/.test(lower)) stack.push('React');
  if (/vue/.test(lower)) stack.push('Vue.js');
  if (/angular/.test(lower)) stack.push('Angular');
  if (/bootstrap/.test(lower)) stack.push('Bootstrap');
  if (/jquery/.test(lower)) stack.push('jQuery');
  return [...new Set(stack)];
}

function extractLinks(html, domain) {
  const links = [];
  const regex = /<a\s+[^>]*href=["']([^"'#]+)["'][^>]*>/gi;
  let match;
  while ((match = regex.exec(html))) {
    const href = match[1];
    const internal = href.startsWith('/') || href.includes(domain);
    links.push({ href, internal });
  }
  return links;
}

function extractSocialTags(html) {
  const tags = {};
  const metaRegex = /<meta\s+([^>]+)>/gi;
  let match;
  while ((match = metaRegex.exec(html))) {
    const attrs = match[1];
    const propertyMatch = attrs.match(/property=["']([^"']+)["']/i);
    const nameMatch = attrs.match(/name=["']([^"']+)["']/i);
    const contentMatch = attrs.match(/content=["']([^"']*)["']/i);
    const key = propertyMatch?.[1] || nameMatch?.[1];
    if (key && contentMatch) tags[key] = contentMatch[1];
  }
  return tags;
}

async function handleSiteFeatures(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const page = await fetchWebsite(domain);
    const features = analyzeSiteFeatures(page.body);
    sendJSON(res, 200, { domain, features });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleDnsServer(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const servers = await dns.resolveNs(domain);
    sendJSON(res, 200, { domain, servers });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleTechStack(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const page = await fetchWebsite(domain);
    const stack = detectTechStack(page.body);
    sendJSON(res, 200, { domain, stack });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleListedPages(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const urls = [`https://${domain}/sitemap.xml`, `http://${domain}/sitemap.xml`];
    for (const url of urls) {
      try {
        const data = await fetchPage(url);
        if (data.statusCode && data.statusCode < 400) {
          const matches = [...data.body.matchAll(/<loc>([^<]+)<\/loc>/gi)].map(m => m[1]);
          return sendJSON(res, 200, { domain, pages: matches });
        }
      } catch (e) {}
    }
    sendJSON(res, 200, { domain, pages: [] });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleLinkedPages(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const page = await fetchWebsite(domain);
    const links = extractLinks(page.body, domain);
    sendJSON(res, 200, { domain, links });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleSocialTags(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const page = await fetchWebsite(domain);
    const tags = extractSocialTags(page.body);
    sendJSON(res, 200, { domain, tags });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleEmailConfig(domain, res) {
  domain = normalizeDomain(domain);

  try {
    // TXT del dominio, MX del dominio y TXT de _dmarc.dominio
    const [txt, mx, dmarcTxt] = await Promise.all([
      dns.resolveTxt(domain).catch(() => []),
      dns.resolveMx(domain).catch(() => []),
      dns.resolveTxt(`_dmarc.${domain}`).catch(() => [])
    ]);

    // SPF se define normalmente en el dominio raíz
    const flat = txt.map(row => row.join('')).join(' ');
    const spf = /v=spf1/i.test(flat);

    // DMARC se define en _dmarc.dominio
    const dmarcFlat = dmarcTxt.map(row => row.join('')).join(' ');
    const dmarc = /v=DMARC1/i.test(dmarcFlat);

    // DKIM: intentamos "default._domainkey.dominio" (muy usado, pero no único)
    let dkim = false;
    try {
      const def = await dns.resolveTxt(`default._domainkey.${domain}`);
      dkim = def.flat().some(v => /v=DKIM1/i.test(v));
    } catch (e) {
      // si falla, simplemente dejamos dkim = false
    }

    sendJSON(res, 200, {
      domain,
      spf,
      dmarc,
      dkim,
      mx: mx.map(r => ({ exchange: r.exchange, priority: r.priority }))
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleFirewall(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const page = await fetchWebsite(domain);
    const headers = page.headers;
    const server = (headers['server'] || '').toLowerCase();
    const wafHeaders = Object.values(headers)
      .join(' ')
      .toLowerCase();
    const detections = [];
    if (server.includes('cloudflare') || wafHeaders.includes('cloudflare')) detections.push('Cloudflare');
    if (server.includes('sucuri') || wafHeaders.includes('sucuri')) detections.push('Sucuri');
    if (server.includes('akamai') || wafHeaders.includes('akamai')) detections.push('Akamai');
    if (wafHeaders.includes('mod_security') || wafHeaders.includes('modsecurity')) detections.push('ModSecurity');
    sendJSON(res, 200, {
      domain,
      waf: detections,
      detected: detections.length > 0
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleHttpSecurity(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const cached = cacheGet(headerCache, domain);
    const headers = cached ? cached.headers : (await fetchWebsite(domain)).headers;
    const security = {
      hsts: Boolean(headers['strict-transport-security']),
      csp: Boolean(headers['content-security-policy']),
      xfo: Boolean(headers['x-frame-options']),
      xcto: Boolean(headers['x-content-type-options']),
      xxss: Boolean(headers['x-xss-protection']),
      referrer: Boolean(headers['referrer-policy'])
    };
    sendJSON(res, 200, { domain, security });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleArchive(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchJSON(
      `https://web.archive.org/cdx/search/cdx?url=${domain}&output=json&limit=5&fl=timestamp,original,statuscode`
    );
    const entries = Array.isArray(data)
      ? data.slice(1).map(item => ({ timestamp: item[0], original: item[1], status: item[2] }))
      : [];
    sendJSON(res, 200, { domain, entries });
  } catch (e) {
    sendJSON(res, 200, { domain, error: 'Servicio no disponible' });
  }
}

async function handleRanking(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchJSON(`https://tranco-list.eu/api/ranks/domain/${domain}`);
    sendJSON(res, 200, { domain, rank: data.rank || null, date: data.list_date || null });
  } catch (e) {
    sendJSON(res, 200, { domain, error: 'Sin información' });
  }
}

// --- Helpers para Quad9 (DNS-over-HTTPS con formato "dns=") ---

function base64UrlEncode(buf) {
  return buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}
//Version consulta Quad9 usando POST

function queryQuad9(domain) {
  return new Promise((resolve, reject) => {
    try {
      const query = dnsPacket.encode({
        type: 'query',
        id: 1,
        flags: 256, // RD (recursion desired)
        questions: [
          {
            type: 'A',
            name: domain
          }
        ]
      });

      const options = {
        hostname: 'dns.quad9.net',
        path: '/dns-query',
        method: 'POST',
        headers: {
          'content-type': 'application/dns-message',
          accept: 'application/dns-message',
          'content-length': query.length
        },
        timeout: 15000
      };

      const req = https.request(options, res => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => {
          try {
            const buf = Buffer.concat(chunks);
            const msg = dnsPacket.decode(buf);
            resolve(msg);
          } catch (e) {
            reject(e);
          }
        });
      });

      req.on('error', reject);
      req.setTimeout(15000, () => {
        req.destroy(new Error('Timeout'));
      });

      // Enviamos el mensaje DNS crudo
      req.write(query);
      req.end();
    } catch (e) {
      reject(e);
    }
  });
}


  



async function handleBlock(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const results = [];

    // Google DNS-over-HTTPS (JSON)
    try {
      const gData = await fetchJSON(
        `https://dns.google/resolve?name=${domain}&type=A`
      );
      const gAnswers = Array.isArray(gData.Answer)
        ? gData.Answer.filter(a => a.type === 1)
        : [];
      results.push({
        resolver: 'Google',
        blocked: gAnswers.length === 0
      });
    } catch (e) {
      results.push({
        resolver: 'Google',
        blocked: false,
        error: errorMessage(e)
      });
    }

    // Cloudflare DNS-over-HTTPS (JSON)
    try {
      const cfData = await fetchJSON(
        `https://cloudflare-dns.com/dns-query?name=${domain}&type=A`,
        { headers: { accept: 'application/dns-json' } }
      );
      const cfAnswers = Array.isArray(cfData.Answer)
        ? cfData.Answer.filter(a => a.type === 1)
        : [];
      results.push({
        resolver: 'Cloudflare',
        blocked: cfAnswers.length === 0
      });
    } catch (e) {
      results.push({
        resolver: 'Cloudflare',
        blocked: false,
        error: errorMessage(e)
      });
    }

       // Quad9 usando dns-packet sobre DNS-over-HTTPS (wire format)
    try {
      const qMsg = await queryQuad9(domain);

      let blocked = false;

      if (qMsg) {
        // rcode puede venir como número o como string según la versión de dns-packet
        const rcodeRaw = qMsg.rcode;
        let rcodeNum = null;
        let rcodeName = null;

        if (typeof rcodeRaw === 'number') {
          rcodeNum = rcodeRaw;
        } else if (typeof rcodeRaw === 'string') {
          rcodeName = rcodeRaw.toUpperCase();
        }

        const answers = Array.isArray(qMsg.answers) ? qMsg.answers : [];
        const aRecords = answers.filter(a => a.type === 'A' && a.data);

        // Regla de detección:
        // - Si NXDOMAIN (o código 3): consideramos bloqueado
        // - Si hay registros A: NO bloqueado
        // - Si no hay A pero tampoco NXDOMAIN: lo tratamos como "no bloqueado" (no asumimos bloqueo)
        const isNx =
          rcodeNum === 3 ||
          rcodeName === 'NXDOMAIN';

        if (isNx) {
          blocked = true;
        } else if (aRecords.length > 0) {
          blocked = false;
        } else {
          // Caso "indeterminado": no marcamos bloqueado para evitar falso positivo
          blocked = false;
        }
      }

      results.push({
        resolver: 'Quad9',
        blocked
      });
    } catch (e) {
      results.push({
        resolver: 'Quad9',
        blocked: false,
        error: errorMessage(e)
      });
    }

    sendJSON(res, 200, { domain, results });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleMalware(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const body = `host=${encodeURIComponent(domain)}`;
    const data = await fetchJSON('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body
    });
    const entries = Array.isArray(data?.urls) ? data.urls.slice(0, 10) : [];
    sendJSON(res, 200, { domain, entries, threat: data?.query_status });
  } catch (e) {
    sendJSON(res, 200, { domain, error: 'Servicio no disponible' });
  }
}

async function handleTlsCiphers(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const suites = [];
    const protocols = ['TLSv1.3', 'TLSv1.2'];
    for (const version of protocols) {
      await new Promise(resolve => {
        const socket = tls.connect(
          {
            host: domain,
            servername: domain,
            port: 443,
            rejectUnauthorized: false,
            minVersion: version,
            maxVersion: version
          },
          () => {
            const cipher = socket.getCipher();
            if (cipher) suites.push({ protocol: socket.getProtocol(), cipher: cipher.name });
            socket.end();
            resolve();
          }
        );
        socket.on('error', () => resolve());
        socket.setTimeout(7000, () => {
          socket.destroy();
          resolve();
        });
      });
    }
    sendJSON(res, 200, { domain, suites });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleTlsConfig(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchJSON(
      `https://tls-observatory.services.mozilla.com/api/v1/analyze?host=${domain}`
    );
    sendJSON(res, 200, { domain, data });
  } catch (e) {
    sendJSON(res, 200, { domain, error: 'Servicio no disponible' });
  }
}

async function handleTlsSimulation(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const scenarios = [];
    const clients = [
      { name: 'Modern Browser', minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' },
      { name: 'Legacy Browser', minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' }
    ];
    for (const client of clients) {
      await new Promise(resolve => {
        const socket = tls.connect(
          {
            host: domain,
            servername: domain,
            port: 443,
            rejectUnauthorized: false,
            minVersion: client.minVersion,
            maxVersion: client.maxVersion
          },
          () => {
            const cipher = socket.getCipher();
            scenarios.push({
              client: client.name,
              protocol: socket.getProtocol(),
              cipher: cipher ? cipher.name : null,
              success: true
            });
            socket.end();
            resolve();
          }
        );
        socket.on('error', () => {
          scenarios.push({ client: client.name, success: false });
          resolve();
        });
        socket.setTimeout(7000, () => {
          socket.destroy();
          scenarios.push({ client: client.name, success: false });
          resolve();
        });
      });
    }
    sendJSON(res, 200, { domain, scenarios });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e) });
  }
}

async function handleScreenshot(domain, res) {
  domain = normalizeDomain(domain);
  const encoded = encodeURIComponent(`https://${domain}`);
  const imageUrl = `https://image.thum.io/get/png/${encoded}`;
  sendJSON(res, 200, { domain, imageUrl });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function getStatusBadge(status) {
  switch (status) {
    case "ok":
      return {
        label: "DNSSEC correcto",
        color: "#166534",
        bg: "#dcfce7",
        border: "#86efac"
      };
    case "not_implemented":
      return {
        label: "DNSSEC no implementado",
        color: "#92400e",
        bg: "#fef3c7",
        border: "#fcd34d"
      };
    case "non_existent":
      return {
        label: "Nombre no existente o no verificable",
        color: "#7c2d12",
        bg: "#ffedd5",
        border: "#fdba74"
      };
    case "misconfigured":
      return {
        label: "DNSSEC mal configurado",
        color: "#991b1b",
        bg: "#fee2e2",
        border: "#fca5a5"
      };
    case "blocked_at_tld":
    case "blocked_at_parent":
      return {
        label: "Bloqueo estructural",
        color: "#991b1b",
        bg: "#fee2e2",
        border: "#fca5a5"
      };
    case "indeterminate":
    default:
      return {
        label: "Resultado no concluyente",
        color: "#1f2937",
        bg: "#e5e7eb",
        border: "#cbd5e1"
      };
  }
}

function mapConfidence(value) {
  if (value === "high") return "Alta";
  if (value === "medium") return "Media";
  if (value === "low") return "Baja";
  return "No determinada";
}

function mapConfidenceDescription(value) {
  if (value === "high") {
    return "Certeza alta: la evidencia disponible es consistente para sustentar la interpretación del resultado.";
  }
  if (value === "medium") {
    return "Certeza media: existen limitaciones estructurales del análisis y el resultado debe leerse con contexto.";
  }
  if (value === "low") {
    return "Certeza baja: una o más consultas devolvieron timeout, error de red o respuesta inválida. La evidencia es insuficiente para una interpretación confiable. Se recomienda repetir el análisis o verificar con herramientas externas.";
  }
  return "No fue posible determinar con claridad el nivel de certeza del análisis.";
}

function mapBlockingLevel(value) {
  if (value === "none") return "Sin restricciones estructurales";
  if (value === "tld") return "Bloqueo en TLD";
  if (value === "parent") return "Bloqueo en zona padre";
  if (value === "domain") return "Limitación en el dominio";
  return "No determinado";
}

function mapTechnicalStatus(value) {
  switch (value) {
    case "ok":
      return "Correcto";
    case "not_implemented":
      return "No implementado";
    case "non_existent":
      return "No existente o no verificable";
    case "misconfigured":
      return "Mal configurado";
    case "blocked_at_tld":
      return "Bloqueado en TLD";
    case "blocked_at_parent":
      return "Bloqueado en zona padre";
    case "indeterminate":
      return "No concluyente";
    default:
      return "No determinado";
  }
}

function mapDisplayTitle(finalStatus, execStatus) {
  switch (finalStatus) {
    case "ok":
      return "DNSSEC correctamente implementado";
    case "not_implemented":
      return "DNSSEC no implementado";
    case "non_existent":
      return "Nombre no existente o no verificable";
    case "misconfigured":
      return "DNSSEC presente pero mal configurado";
    case "blocked_at_tld":
      return "Bloqueo estructural en TLD";
    case "blocked_at_parent":
      return "Bloqueo estructural en zona padre";
    case "indeterminate":
      return "Resultado no concluyente";
    default:
      return execStatus || "Resultado del análisis";
  }
}


function getSpecialDnssecNote(finalStatus, currentNote) {
  if (currentNote && String(currentNote).trim()) {
    return currentNote;
  }

  if (finalStatus === "not_implemented") {
    return "La ausencia de registros DNSKEY o DS no permite inferir por sí sola la inexistencia del servicio. En algunos casos, el nombre analizado puede estar operativo sin estar delegado como zona DNS independiente o sin haber implementado DNSSEC.";
  }

  if (finalStatus === "misconfigured") {
    return "Una configuración DNSSEC incompleta o inconsistente puede generar fallos de validación silenciosos. Esto puede hacer que el dominio sea inaccessible para usuarios detrás de resolvers DNSSEC validadores. Se recomienda corrección prioritaria.";
  }

  if (finalStatus === "non_existent") {
    return "Este resultado combina evidencia de no existencia operativa del nombre consultado con ausencia de despliegue DNSSEC. Aun así, ante configuraciones no convencionales, conviene complementar con validaciones adicionales.";
  }

  if (finalStatus === "indeterminate") {
    return "Un resultado no concluyente puede deberse a condiciones transitorias de la red o del resolver. Se recomienda repetir el análisis o complementarlo con herramientas especializadas como DNSViz.";
  }

  return "Este análisis se basa en evidencia estructural observable en DNS y debe complementarse con validación técnica adicional cuando el caso lo requiera.";
}

function renderDnssecHtml(result) {
  const domain = result?.domain || "";
  const analyzed = result?.analyzed_object?.value || domain;
  const dnssec = result?.dnssec || {};
  const human = result?.human || {};
  const exec = dnssec?.executive_summary || {};
  const badge = getStatusBadge(dnssec?.final_status);

  const confidenceRaw = human.certainty || dnssec.assessment_meta?.confidence || "unknown";
  const confidenceLabel = mapConfidence(confidenceRaw);
  const confidenceDescription = mapConfidenceDescription(confidenceRaw);
  const blockingLabel = mapBlockingLevel(dnssec.blocking_level);
  const technicalStatusLabel = mapTechnicalStatus(dnssec.final_status);
  const displayTitle = mapDisplayTitle(dnssec.final_status, exec.status);
  const mainSummary = dnssec.summary || human.summary || "";
  const specialNote = getSpecialDnssecNote(dnssec.final_status, human.note_special);

  // Fuente única de recomendaciones: guidance.recommendations
  const nextSteps = Array.isArray(dnssec?.guidance?.recommendations) && dnssec.guidance.recommendations.length > 0
    ? dnssec.guidance.recommendations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")
    : "<li>No se registran acciones recomendadas para este caso.</li>";

  const zonesRows = Array.isArray(dnssec?.zones)
    ? dnssec.zones.map((z) => `
      <tr>
        <td>${escapeHtml(z.zone)}</td>
        <td>${escapeHtml(z.level)}</td>
        <td>${escapeHtml(z.status)}</td>
        <td>${escapeHtml(z.query_status)}</td>
      </tr>
    `).join("")
    : "";

  const delegationRows = Array.isArray(dnssec?.delegations)
    ? dnssec.delegations.map((d) => `
      <tr>
        <td>${escapeHtml(d.from)}</td>
        <td>${escapeHtml(d.to)}</td>
        <td>${escapeHtml(d.status)}</td>
        <td>${escapeHtml(d.query_status)}</td>
      </tr>
    `).join("")
    : "";

  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Análisis DNSSEC - ${escapeHtml(domain)}</title>
  <style>
    :root {
      --bg: #0b1220;
      --panel: #111827;
      --panel-2: #1f2937;
      --text: #e5e7eb;
      --muted: #9ca3af;
      --line: #374151;
      --accent: #60a5fa;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.45;
    }
    .wrap {
      max-width: 1100px;
      margin: 0 auto;
      padding: 24px;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 20px;
      margin-bottom: 18px;
    }
    .title {
      font-size: 28px;
      margin: 0 0 8px;
    }
    .sub {
      color: var(--muted);
      margin: 0 0 14px;
    }
    .badge {
      display: inline-block;
      padding: 8px 12px;
      border-radius: 999px;
      font-weight: bold;
      border: 1px solid;
      margin-bottom: 14px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 14px;
    }
    .mini {
      background: var(--panel-2);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 14px;
    }
    .mini h3 {
      margin: 0 0 8px;
      font-size: 14px;
      color: var(--muted);
      font-weight: normal;
      text-transform: uppercase;
      letter-spacing: .04em;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .mini p {
      margin: 0;
      font-size: 18px;
      font-weight: bold;
    }
    h2 {
      margin-top: 0;
      font-size: 20px;
    }
    h3 {
      margin-top: 18px;
      margin-bottom: 8px;
      font-size: 16px;
    }
    p {
      margin: 0 0 12px;
    }
    ul {
      margin: 8px 0 0 18px;
      padding: 0;
    }
    li {
      margin-bottom: 8px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
      font-size: 14px;
    }
    th, td {
      border-bottom: 1px solid var(--line);
      padding: 10px 8px;
      text-align: left;
      vertical-align: top;
    }
    th {
      color: var(--muted);
      font-weight: normal;
    }
    details {
      margin-top: 10px;
    }
    summary {
      cursor: pointer;
      color: var(--accent);
      margin-bottom: 8px;
    }
    pre {
      overflow: auto;
      background: #020617;
      padding: 14px;
      border-radius: 10px;
      border: 1px solid var(--line);
      color: #cbd5e1;
      font-size: 12px;
    }
    a {
      color: var(--accent);
      text-decoration: none;
    }
    .help-trigger {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 18px;
      height: 18px;
      border: 1px solid #6b7280;
      border-radius: 999px;
      background: transparent;
      color: #cbd5e1;
      font-size: 12px;
      font-weight: bold;
      cursor: pointer;
      padding: 0;
      line-height: 1;
    }
    .help-trigger:hover {
      background: #243041;
    }
    .help-box {
      display: none;
      margin-top: 8px;
      padding: 10px 12px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #0f172a;
      color: var(--muted);
      font-size: 13px;
      font-weight: normal;
      text-transform: none;
      letter-spacing: normal;
    }
    .help-box.open {
      display: block;
    }
  .hero-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
  flex-wrap: wrap;
}

.disclaimer-box {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  max-width: 360px;
  padding: 12px 14px;
  border: 1px solid #7c2d12;
  background: #1f1720;
  border-radius: 12px;
  color: #f3d2c1;
}

.disclaimer-icon {
  width: 18px;
  height: 18px;
  flex: 0 0 18px;
  margin-top: 2px;
}

.disclaimer-text {
  font-size: 13px;
  line-height: 1.4;
}

.disclaimer-text strong {
  display: block;
  color: #fde68a;
  margin-bottom: 2px;
}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
  <div class="hero-header">
    <div>
      <h1 class="title">Análisis DNSSEC</h1>
      <p class="sub">Dominio analizado: <strong>${escapeHtml(analyzed)}</strong></p>
    </div>

    <div class="disclaimer-box">
      <svg class="disclaimer-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path d="M12 3L22 21H2L12 3Z" fill="#f59e0b" stroke="#fbbf24" stroke-width="1.5"></path>
        <path d="M12 9V14" stroke="#1f2937" stroke-width="2" stroke-linecap="round"></path>
        <circle cx="12" cy="17.5" r="1.2" fill="#1f2937"></circle>
      </svg>
      <div class="disclaimer-text">
        <strong>Advertencia</strong>
        Sistema experimental del grupo de trabajo MEDICIONES ISOC LAC. Use con criterio técnico.
      </div>
    </div>
  </div>

  <div class="badge" style="color:${badge.color}; background:${badge.bg}; border-color:${badge.border};">
    ${escapeHtml(badge.label)}
  </div>
  <p><strong>${escapeHtml(displayTitle)}</strong></p>
  <p>${escapeHtml(mainSummary)}</p>
</div>

    <div class="grid">
      <div class="mini">
        <h3>
        Estado técnico
        <button type="button" class="help-trigger" data-target="help-tech">?</button>
        </h3>
      <div id="help-tech" class="help-box">
       Clasificación técnica del estado DNSSEC del dominio basada en la presencia de firmas, registros DNSKEY y DS, y la consistencia de la cadena de confianza.
      </div>
        <p>${escapeHtml(technicalStatusLabel)}</p>
      </div>

      <div class="mini">
        <h3>
        Nivel de certeza
        <button type="button" class="help-trigger" data-target="help-certainty">?</button>
        </h3>
        <div id="help-certainty" class="help-box">
        Indica el nivel de confianza del análisis estructural basado en la evidencia observable en DNS. No corresponde a una validación criptográfica completa mediante resolvers validadores.
      </div>

<p>${escapeHtml(confidenceLabel)}</p>
      </div>

      <div class="mini">
        <h3>
         Condición estructural
         <button type="button" class="help-trigger" data-target="help-blocking">?</button>
        </h3>

      <div id="help-blocking" class="help-box">
       Describe si existe alguna limitación en la cadena de delegación DNS que impida o condicione la implementación efectiva de DNSSEC en el dominio analizado.
      </div>
        <p>${escapeHtml(blockingLabel)}</p>
      </div>

      <div class="mini">
        <h3>Requiere acción</h3>
        <p>${exec.action_required ? "Sí" : "No"}</p>
      </div>
    </div>

    <div class="card">
      <h2>Interpretación del resultado</h2>
      <p>${escapeHtml(mainSummary)}</p>
      <p>${escapeHtml(confidenceDescription)}</p>
      <p>${escapeHtml(human.note_scope || "Este análisis evalúa evidencia estructural en DNS, no una validación criptográfica completa.")}</p>
      <p>${escapeHtml(specialNote)}</p>
    </div>

    <div class="card">
      <h2>Resumen ejecutivo</h2>
      <p><strong>Estado:</strong> ${escapeHtml(exec.status || "-")}</p>
      <p><strong>Riesgo:</strong> ${escapeHtml(exec.risk_level || "-")}</p>
      <p><strong>Nota de decisión:</strong> ${escapeHtml(exec.decision_note || "-")}</p>
    </div>

    <div class="card">
      <h2>Acciones recomendadas</h2>
      <ul>${nextSteps}</ul>
    </div>

    <div class="card">
      <h2>Lectura técnica resumida</h2>
      <p><strong>Resumen técnico:</strong> ${escapeHtml(dnssec.technical_summary || "-")}</p>

      <h3>Zonas analizadas</h3>
      <table>
        <thead>
          <tr>
            <th>Zona</th>
            <th>Nivel</th>
            <th>Estado</th>
            <th>Consulta</th>
          </tr>
        </thead>
        <tbody>${zonesRows}</tbody>
      </table>

      <h3>Delegaciones</h3>
      <table>
        <thead>
          <tr>
            <th>Desde</th>
            <th>Hacia</th>
            <th>Estado</th>
            <th>Consulta</th>
          </tr>
        </thead>
        <tbody>${delegationRows}</tbody>
      </table>
    </div>

    <div class="card">
      <details>
        <summary>Ver JSON técnico completo</summary>
        <pre>${escapeHtml(JSON.stringify(result, null, 2))}</pre>
      </details>
      <p style="margin-top:12px;">
        Vista JSON directa:
        <a href="/dnssec-analysis?domain=${encodeURIComponent(domain)}&format=json">abrir JSON</a>
      </p>
    </div>
  </div>

  <script>
  document.querySelectorAll(".help-trigger").forEach((button) => {
    button.addEventListener("click", (e) => {
      e.stopPropagation();

      const targetId = button.getAttribute("data-target");
      const box = document.getElementById(targetId);

      document.querySelectorAll(".help-box").forEach((b) => {
        if (b !== box) b.classList.remove("open");
      });

      if (box) {
        box.classList.toggle("open");
      }
    });
  });

  document.addEventListener("click", () => {
    document.querySelectorAll(".help-box").forEach((box) => {
      box.classList.remove("open");
    });
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      document.querySelectorAll(".help-box").forEach((box) => {
        box.classList.remove("open");
      });
    }
  });
</script>
</body>
</html>`;
}

function renderHomeHtml() {
  return `
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>MEDICIONES ISOC LAC | Análisis DNSSEC</title>
  <style>
    :root {
      --bg: #f4f7fb;
      --card: #ffffff;
      --text: #1f2937;
      --muted: #6b7280;
      --primary: #0f766e;
      --primary-hover: #0d5f59;
      --border: #dbe3ec;
      --shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
      --warning-bg: #fff8e1;
      --warning-border: #f0c36d;
      --warning-text: #7a5a00;
      --input-bg: #ffffff;
      --input-focus: #14b8a6;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: linear-gradient(180deg, #eef4f8 0%, #f7fafc 100%);
      color: var(--text);
    }

    .page {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 32px 16px;
    }

    .card {
      width: 100%;
      max-width: 760px;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 18px;
      box-shadow: var(--shadow);
      padding: 32px;
    }

    .eyebrow {
      display: inline-block;
      font-size: 12px;
      font-weight: bold;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--primary);
      margin-bottom: 12px;
    }

    h1 {
      margin: 0 0 14px 0;
      font-size: 32px;
      line-height: 1.2;
    }

    .lead {
      margin: 0 0 22px 0;
      color: var(--muted);
      font-size: 16px;
      line-height: 1.6;
    }

    .form-block {
      margin-top: 24px;
    }

    .label {
      display: block;
      margin-bottom: 10px;
      font-weight: bold;
      font-size: 15px;
    }

    .input-row {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
    }

    .domain-input {
      flex: 1 1 420px;
      min-width: 260px;
      padding: 14px 16px;
      border: 1px solid var(--border);
      border-radius: 12px;
      font-size: 16px;
      background: var(--input-bg);
      color: var(--text);
      outline: none;
      transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }

    .domain-input:focus {
      border-color: var(--input-focus);
      box-shadow: 0 0 0 4px rgba(20, 184, 166, 0.12);
    }

    .btn {
      border: none;
      background: var(--primary);
      color: white;
      font-size: 16px;
      font-weight: bold;
      padding: 14px 22px;
      border-radius: 12px;
      cursor: pointer;
      transition: background 0.2s ease, transform 0.05s ease;
      white-space: nowrap;
    }

    .btn:hover {
      background: var(--primary-hover);
    }

    .btn:active {
      transform: translateY(1px);
    }

    .helper-text {
      margin-top: 10px;
      font-size: 14px;
      color: var(--muted);
      line-height: 1.5;
    }

    .error-box {
      display: none;
      margin-top: 14px;
      padding: 12px 14px;
      border-radius: 10px;
      background: #fff1f2;
      border: 1px solid #fecdd3;
      color: #9f1239;
      font-size: 14px;
    }

    .info-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 14px;
      margin-top: 28px;
    }

    .info-item {
      background: #f8fbfd;
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 16px;
    }

    .info-item h3 {
      margin: 0 0 8px 0;
      font-size: 16px;
    }

    .info-item p {
      margin: 0;
      color: var(--muted);
      font-size: 14px;
      line-height: 1.5;
    }

    .warning {
      margin-top: 28px;
      padding: 14px 16px;
      border-radius: 12px;
      background: var(--warning-bg);
      border: 1px solid var(--warning-border);
      color: var(--warning-text);
      font-size: 14px;
      line-height: 1.5;
    }

    .footer-links {
      margin-top: 18px;
      display: flex;
      gap: 14px;
      flex-wrap: wrap;
    }

    .footer-links a {
      color: var(--primary);
      text-decoration: none;
      font-size: 14px;
      font-weight: bold;
    }

    .footer-links a:hover {
      text-decoration: underline;
    }

    @media (max-width: 640px) {
      .card {
        padding: 24px 18px;
      }

      h1 {
        font-size: 26px;
      }

      .btn {
        width: 100%;
      }

      .input-row {
        flex-direction: column;
      }

      .domain-input {
        width: 100%;
      }
    }
  </style>
</head>
<body>
  <main class="page">
    <section class="card">
      <div class="eyebrow">MEDICIONES ISOC LAC</div>
      <h1>Análisis estructural de DNSSEC</h1>
      <p class="lead">
        Ingrese un dominio para evaluar su estado DNSSEC desde una perspectiva estructural.
        El sistema revisa la cadena de zonas, delegaciones y señales observables de configuración.
      </p>

      <form id="dnssec-form" class="form-block" action="/dnssec-analysis" method="GET" novalidate>
        <label class="label" for="domain">Dominio a analizar</label>

        <div class="input-row">
          <input
            id="domain"
            name="domain"
            class="domain-input"
            type="text"
            inputmode="url"
            autocomplete="off"
            spellcheck="false"
            placeholder="Ejemplo: isoc.org"
            aria-describedby="domain-help domain-error"
            required
          />
          <button type="submit" class="btn">Analizar DNSSEC</button>
        </div>

        <div id="domain-help" class="helper-text">
          Escriba un dominio como <strong>example.com</strong>, <strong>isoc.org</strong> o <strong>gob.ec</strong>.
          No es necesario incluir <strong>http://</strong> ni rutas.
        </div>

        <div id="domain-error" class="error-box" role="alert"></div>
      </form>

      <div class="info-grid">
        <div class="info-item">
          <h3>Qué analiza</h3>
          <p>
            Señales estructurales relacionadas con DNSSEC, continuidad de zonas y consistencia observable de la delegación.
          </p>
        </div>
        <div class="info-item">
          <h3>Qué no analiza</h3>
          <p>
            No sustituye una validación criptográfica completa ni una auditoría exhaustiva del DNS autoritativo.
          </p>
        </div>
        <div class="info-item">
          <h3>Resultado esperado</h3>
          <p>
            Un reporte técnico con interpretación, acciones recomendadas y detalle de zonas y delegaciones observadas.
          </p>
        </div>
      </div>

      <div class="warning">
        <strong>Advertencia:</strong> Sistema experimental del grupo de trabajo MEDICIONES ISOC LAC.
        Use con criterio técnico.
      </div>

      <div class="footer-links">
        <a href="/docs/dnssec-guia.pdf" target="_blank" rel="noopener noreferrer">Guía metodológica PDF</a>
      </div>
    </section>
  </main>

  <script>
    (function () {
      const form = document.getElementById('dnssec-form');
      const input = document.getElementById('domain');
      const errorBox = document.getElementById('domain-error');

      function showError(message) {
        errorBox.textContent = message;
        errorBox.style.display = 'block';
      }

      function clearError() {
        errorBox.textContent = '';
        errorBox.style.display = 'none';
      }

      function normalizeDomain(value) {
        let domain = value.trim().toLowerCase();

        domain = domain.replace(/^https?:\\/\\//, '');
        domain = domain.replace(/^www\\./, '');
        domain = domain.split('/')[0];
        domain = domain.split('?')[0];
        domain = domain.split('#')[0];
        domain = domain.replace(/:\\d+$/, '');
        domain = domain.replace(/\\.$/, '');

        return domain;
      }

      function isValidDomain(domain) {
        if (!domain) return false;
        if (domain.length > 253) return false;
        if (domain.includes('..')) return false;

        const domainRegex = /^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\\.)+[a-z]{2,63}$/i;
        return domainRegex.test(domain);
      }

      form.addEventListener('submit', function (event) {
        clearError();

        const normalized = normalizeDomain(input.value);
        input.value = normalized;

        if (!normalized) {
          event.preventDefault();
          showError('Ingrese un dominio válido.');
          input.focus();
          return;
        }

        if (!isValidDomain(normalized)) {
          event.preventDefault();
          showError('El valor ingresado no parece un dominio válido. Use un formato como example.com');
          input.focus();
          return;
        }
      });

      input.addEventListener('input', function () {
        clearError();
      });
    })();
  </script>
</body>
</html>
  `;
}

function getBaseUrl(req) {
  const forwardedProto = req.headers["x-forwarded-proto"];
  const forwardedHost = req.headers["x-forwarded-host"];
  const host = forwardedHost || req.headers.host || "localhost:8080";
  const protocol = forwardedProto || (host.includes("localhost") ? "http" : "https");
  return `${protocol}://${host}`;
}

  const server = http.createServer(async (req, res) => {

  const publicPath = path.join(__dirname, 'public');
  let filePath = path.join(publicPath, req.url === '/' ? 'index.html' : req.url);

  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    const ext = path.extname(filePath);

    const contentType = {
      '.html': 'text/html',
      '.js': 'text/javascript',
      '.css': 'text/css',
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.svg': 'image/svg+xml',
      '.pdf': 'application/pdf'
    }[ext] || 'application/octet-stream';

    res.writeHead(200, { 'Content-Type': contentType });
    fs.createReadStream(filePath).pipe(res);
    return;
  }


  const parsed = new URL(req.url, 'http://localhost');
  if (parsed.pathname === "/debug-base-url") {
  const baseUrl = getBaseUrl(req);
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ baseUrl }, null, 2));
  return;
}
  // DNSSEC endpoint
  // TEST zone chain
if (parsed.pathname === "/test-zone-chain") {
  const domain = parsed.searchParams.get("domain");

  const zones = buildZoneChain(domain);

  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({
    input: domain,
    zones
  }, null, 2));

  return;
}
if (parsed.pathname === "/dnssec-analysis") {
  try {
    const domain = validateDomainInput(parsed.searchParams.get("domain"));
    const raw = await getDnssecAnalysis(domain);
    const result = processDnssecAnalysis(raw);

    const format = parsed.searchParams.get("format");

    if (format === "json") {
      res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify(result, null, 2));
      return;
    }

    const html = renderDnssecHtml(result);
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(html);
    return;
  } catch (error) {
    if (error.code === "INVALID_DOMAIN") {
      res.writeHead(400, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({
        error: "invalid_domain",
        message: "El dominio ingresado no es válido."
      }));
      return;
    }

    res.writeHead(500, { "Content-Type": "application/json; charset=utf-8" });
    res.end(JSON.stringify({
      error: "dnssec_analysis_failed",
      message: "No se pudo completar el análisis DNSSEC."
    }));
    return;
  }
}


  // 👉 Servir la interfaz web en la raíz
  if (parsed.pathname === '/' || parsed.pathname === '/index.html') {
    const filePath = path.join(__dirname, 'index.html');
    return fs.readFile(filePath, (err, data) => {
      if (err) {
        return sendJSON(res, 500, { error: 'Index file not found' });
      }
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Access-Control-Allow-Origin': '*'
      });
      res.end(data);
    });
  }

  const segments = parsed.pathname.split('/').filter(Boolean);

  if (segments[0] === 'mx' && segments[1]) return handleMx(segments[1], res);
  if (segments[0] === 'smtputf8' && segments[1]) return handleSmtpUtf8(segments[1], res);
  if (segments[0] === 'dnssec' && segments[1]) return handleDnssec(segments[1], res);
  if (segments[0] === 'dkim' && segments[1])
    return handleDkim(segments[1], parsed.searchParams.get('selector') || 'default', res);
  if (segments[0] === 'rpki' && segments[1]) return handleRpki(segments[1], res);
  if (segments[0] === 'whois' && segments[1]) return handleWhois(segments[1], res);
  if (segments[0] === 'w3c' && segments[1]) return handleW3C(segments[1], res);
  if (segments[0] === 'headers' && segments[1]) return handleHeaders(segments[1], res);
  if (segments[0] === 'caa' && segments[1]) return handleCaa(segments[1], res);
  if (segments[0] === 'tlsa' && segments[1]) return handleTlsa(segments[1], res);
  if (segments[0] === 'securitytxt' && segments[1])
    return handleSecurityTxt(segments[1], res);
  if (segments[0] === 'tlsinfo' && segments[1]) return handleTls(segments[1], res);
  if (segments[0] === 'ipinfo' && segments[1]) return handleIpInfo(segments[1], res);
  if (segments[0] === 'sslchain' && segments[1]) return handleSslChain(segments[1], res);
  if (segments[0] === 'dnsrecords' && segments[1]) return handleDnsRecords(segments[1], res);
  if (segments[0] === 'cookies' && segments[1]) return handleCookies(segments[1], res);
  if (segments[0] === 'crawlrules' && segments[1]) return handleCrawlRules(segments[1], res);
  if (segments[0] === 'quality' && segments[1]) return handleQuality(segments[1], res);
  if (segments[0] === 'serverlocation' && segments[1])
    return handleServerLocation(segments[1], res);
  if (segments[0] === 'associatedhosts' && segments[1])
    return handleAssociatedHosts(segments[1], res);
  if (segments[0] === 'redirectchain' && segments[1])
    return handleRedirectChain(segments[1], res);
  if (segments[0] === 'txtrecords' && segments[1]) return handleTxtRecords(segments[1], res);
  if (segments[0] === 'serverstatus' && segments[1])
    return handleServerStatus(segments[1], res);
  if (segments[0] === 'openports' && segments[1]) return handleOpenPorts(segments[1], res);
  if (segments[0] === 'traceroute' && segments[1]) return handleTraceroute(segments[1], res);
  if (segments[0] === 'carbon' && segments[1]) return handleCarbon(segments[1], res);
  if (segments[0] === 'serverinfo' && segments[1]) return handleServerInfo(segments[1], res);
  if (segments[0] === 'domaininfo' && segments[1]) return handleDomainInfo(segments[1], res);
  if (segments[0] === 'dnssecurity' && segments[1])
    return handleDnsSecurity(segments[1], res);
  if (segments[0] === 'sitefeatures' && segments[1])
    return handleSiteFeatures(segments[1], res);
  if (segments[0] === 'dnsserver' && segments[1]) return handleDnsServer(segments[1], res);
  if (segments[0] === 'techstack' && segments[1]) return handleTechStack(segments[1], res);
  if (segments[0] === 'listedpages' && segments[1]) return handleListedPages(segments[1], res);
  if (segments[0] === 'linkedpages' && segments[1]) return handleLinkedPages(segments[1], res);
  if (segments[0] === 'socialtags' && segments[1]) return handleSocialTags(segments[1], res);
  if (segments[0] === 'emailconfig' && segments[1])
    return handleEmailConfig(segments[1], res);
  if (segments[0] === 'firewall' && segments[1]) return handleFirewall(segments[1], res);
  if (segments[0] === 'httpsecurity' && segments[1])
    return handleHttpSecurity(segments[1], res);
  if (segments[0] === 'archive' && segments[1]) return handleArchive(segments[1], res);
  if (segments[0] === 'ranking' && segments[1]) return handleRanking(segments[1], res);
  if (segments[0] === 'block' && segments[1]) return handleBlock(segments[1], res);
  if (segments[0] === 'malware' && segments[1]) return handleMalware(segments[1], res);
  if (segments[0] === 'tlsciphers' && segments[1])
    return handleTlsCiphers(segments[1], res);
  if (segments[0] === 'tlsconfig' && segments[1])
    return handleTlsConfig(segments[1], res);
  if (segments[0] === 'tlssimulation' && segments[1])
    return handleTlsSimulation(segments[1], res);
  if (segments[0] === 'screenshot' && segments[1])
    return handleScreenshot(segments[1], res);

  // Ruta no encontrada



  // Observatorio DNSSEC — sistema completo con histórico
  if (parsed.pathname.startsWith('/obs')) {
    return handleObservatoryRequest(req, res, parsed);
  }

  // Módulo Zonemaster — análisis DNSSEC profundo
  if (parsed.pathname.startsWith('/zm')) {
    return handleZonemasterRequest(req, res, parsed);
  }

  // Módulo agregado DNSSEC
  if (parsed.pathname.startsWith('/aggregate')) {
    return handleAggregateRequest(req, res, parsed);
  }

    sendJSON(res, 404, { error: 'Not found' });
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));

