// Carga mínima de .env (sin dependencia nueva) — solo variables que no
// vengan ya definidas por el entorno (Docker/systemd tienen prioridad).
(function loadDotEnv() {
  const fs = require('fs');
  const path = require('path');
  const envPath = path.join(__dirname, '.env');
  if (!fs.existsSync(envPath)) return;
  const lines = fs.readFileSync(envPath, 'utf8').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = value;
  }
})();

// Logging de errores no manejados (2026-09-11) — antes NO había ningún log
// de solicitudes ni de errores: `docker logs` solo mostraba la línea de
// arranque, sin rastro de miles de solicitudes reales ya servidas.
// Encontrado al investigar un "HTTP 502" reportado por un usuario en el
// reporte por lote de Mediciones — no se pudo confirmar ni descartar una
// excepción no capturada como causa porque no había ninguna evidencia que
// revisar. Si una promesa dentro del handler de una request rechaza sin su
// propio try/catch, la respuesta HTTP nunca se envía (el callback de
// http.createServer no captura rechazos de promesas por su cuenta) — la
// conexión queda colgada hasta que algo en el camino (ej. el Cloudflare
// Tunnel) la corta, lo cual puede verse como un 502 del lado del cliente
// sin ningún indicio de qué pasó en el servidor. Con `restart:
// unless-stopped` en docker-compose.yml, es seguro terminar el proceso en
// una excepción síncrona no capturada (Docker lo reinicia solo) — no lo es
// necesariamente para cada unhandledRejection en un código base grande que
// no fue escrito asumiendo manejo estricto de rechazos, así que esos solo
// se registran, sin terminar el proceso.
process.on('uncaughtException', (err) => {
  console.error(`${new Date().toISOString()} uncaughtException:`, err && err.stack || err);
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  console.error(`${new Date().toISOString()} unhandledRejection:`, reason && reason.stack || reason);
});

const http = require('http');
const dns = require('dns').promises;
const DEFAULT_SERVERS = ['8.8.8.8', '8.8.4.4'];
dns.setServers(DEFAULT_SERVERS);
const net = require('net');
const https = require('https');
const http2 = require('http2');
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
const { handleDatasetRequest } = require('./routes/datasetPreparation.routes');
const { handleContentRequest } = require('./routes/content.routes');
const { handleAdminRequest } = require('./routes/admin.routes');
const { handleMedicionesBatchReportRequest } = require('./routes/medicionesBatchReport.routes');
// Se mantiene la referencia al módulo completo (no se desestructura
// resolvePublicAddresses) para que los tests puedan reemplazarla con un
// mock (safeWebFetchAdapter.resolvePublicAddresses = fn) — mismo patrón que
// ya usa test/content.publicVisibility.test.js con emailAdapter.sendMail.
const safeWebFetchAdapter = require('./logic/adapters/safeWebFetch.adapter');
const { fetchSafePage, resolveFinalWebTarget } = safeWebFetchAdapter;
const dnsPacket = require('dns-packet');
const htmlCache = new Map();
const headerCache = new Map();
const routeCache = new Map();

// FASE 2 (2026-09-12): la cuota de PageSpeed es compartida por TODO el
// proceso (una sola API key), no por dominio — si se agota en el primer
// dominio de un lote de 20, los otros 19 iban a repetir la misma llamada
// fallida uno por uno, perdiendo tiempo sin ningún beneficio. Corte de
// circuito simple en memoria: una vez confirmada la cuota agotada, se
// deja de llamar a la API real durante PAGESPEED_QUOTA_COOLDOWN_MS y se
// devuelve directo el mismo error explícito.
let pageSpeedQuotaExhaustedUntil = 0;
let pageSpeedQuotaMessage = '';
const PAGESPEED_QUOTA_COOLDOWN_MS = 10 * 60 * 1000; // 10 minutos

async function resolveAddresses(domain) {
  const v4 = await dns.resolve4(domain).catch(() => []);
  const v6 = await dns.resolve6(domain).catch(() => []);
  return { v4, v6 };
}

// (2026-09-12) — mismo propósito que hasNoAddressRecordAtAll() en
// safeWebFetch.adapter.js (distinguir "el dominio no existe" de "existe,
// con zona delegada real, pero sin A ni AAAA" — ej. gob.ec), replicada
// acá mínima porque estos handlers (rpki/serverlocation/serverinfo/tls/
// sslchain) no pasan por resolveFinalWebTarget/fetchSafePage y hoy
// reportan "Sin dirección IP"/ENOTFOUND genérico sin poder distinguir
// los dos casos.
async function domainHasNoAddressButIsRealZone(domain) {
  const [v4, v6, ns] = await Promise.all([
    dns.resolve4(domain).catch(() => null),
    dns.resolve6(domain).catch(() => null),
    dns.resolveNs(domain).catch(() => null)
  ]);
  return !v4 && !v6 && Array.isArray(ns) && ns.length > 0;
}

async function resolveFirstIp(domain) {
  const { v4, v6 } = await resolveAddresses(domain);
  if (v4.length) return { ip: v4[0], family: 4 };
  if (v6.length) return { ip: v6[0], family: 6 };
  return { ip: null, family: null };
}

// (2026-09-13) — mismo criterio que isPageSpeedQuotaError(): ninguno de
// los dos proveedores de metadata IP devuelve un HTTP status fiable que
// fetchJSON pueda leer (fetchJSON no revisa statusCode, solo parsea el
// body) — ambos señalan el motivo real DENTRO del cuerpo JSON. Verificado
// en vivo: ipwho.is -> {"success":false,"message":"Rate limit exceeded"};
// ip-api.com -> {"status":"fail","message":"private range"} /
// {"status":"fail","message":"invalid query"}. El timeout sí tiene su
// propio `.code` real (ver fetchJSON), no hace falta parsear texto para
// ese caso.
function classifyIpMetaFailure(e) {
  if (e && e.code === 'TIMEOUT') return 'TIMEOUT';
  const message = (e && e.message) || '';
  if (/rate limit/i.test(message)) return 'RATE_LIMITED';
  if (/(private range|invalid query|reserved range)/i.test(message)) return 'NOT_FOUND';
  return null;
}

async function lookupIpMetaPrimary(ip) {
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

// Fallback de geolocalización (2026-09-10): ipwho.is tiene rate limit y no
// tenía respaldo — verificado con una ráfaga de solicitudes ("Rate limit
// exceeded"). ip-api.com se eligió deliberadamente de una empresa/producto
// distinto (no la misma familia que ipwho.is/ipwhois.io/ipwhois.app, que
// comparten CDN de assets — cdn.ipwhois.io aparece en las tres — y muy
// probablemente comparten cuota por IP de origen, lo que habría hecho
// inútil usar cualquiera de esas como respaldo de las otras). Nota: el
// plan gratuito de ip-api.com es **solo HTTP, no HTTPS** — intencional,
// no un descuido; es una llamada servidor-a-servidor (sin navegador de
// por medio), así que no hay problema de contenido mixto.
async function lookupIpMetaFallback(ip) {
  const data = await fetchJSON(`http://ip-api.com/json/${encodeURIComponent(ip)}`);
  if (!data || data.status !== 'success') {
    throw new Error((data && data.message) || 'Servicio no disponible');
  }
  const asnMatch = typeof data.as === 'string' ? data.as.match(/^AS(\d+)/) : null;
  return {
    ip,
    city: data.city || '',
    region: data.regionName || data.region || '',
    country: data.country || '',
    latitude: data.lat ?? null,
    longitude: data.lon ?? null,
    timezone: data.timezone || '',
    asn: asnMatch ? Number(asnMatch[1]) : null,
    org: data.org || '',
    isp: data.isp || '',
    network: ''
  };
}

// (2026-09-13) — mismo bug de condición de carrera/duplicación que ya se
// corrigió en fetchWebsite(): asn/serverinfo/serverlocation/ipinfo/ipv4
// resuelven la IP del dominio cada uno por su cuenta y llamaban a
// lookupIpMeta() sin ninguna caché ni coalescing — hasta 5 consultas
// reales al mismo proveedor externo para la MISMA IP en una sola corrida
// (confirmado: asn y serverinfo son el mismo endpoint exacto,
// /serverinfo/:domain, llamado 2 veces). El proveedor primario
// (ipwho.is) tiene cuota diaria, no por-minuto — ipMetaCache guarda el
// resultado resuelto por IP (TTL abajo); ipMetaPending guarda la PROMESA
// en curso apenas se crea, igual que htmlPending en fetchWebsite() — una
// IP distinta siempre dispara su propia consulta nueva.
const IPMETA_CACHE_TTL_MS = 5 * 60 * 1000; // 5 min: geolocalización/ASN de una IP no cambia dentro de una corrida ni de un día
const ipMetaCache = new Map();
const ipMetaPending = new Map();

async function lookupIpMeta(ip) {
  if (!ip) throw new Error('Sin dirección IP');

  const cached = cacheGet(ipMetaCache, ip, IPMETA_CACHE_TTL_MS);
  if (cached) {
    recordCacheEvent('lookupIpMeta', ip, 'cache_hit');
    return cached;
  }
  if (ipMetaPending.has(ip)) {
    recordCacheEvent('lookupIpMeta', ip, 'pending_reused');
    return ipMetaPending.get(ip);
  }

  recordCacheEvent('lookupIpMeta', ip, 'new_fetch');
  const promise = (async () => {
    let primaryError;
    try {
      const info = await lookupIpMetaPrimary(ip);
      cacheSet(ipMetaCache, ip, info);
      return info;
    } catch (e) {
      primaryError = e;
    }

    // Un IP privada/reservada/inválida lo es para cualquier proveedor —
    // no tiene sentido gastar cupo del fallback preguntando lo mismo.
    if (classifyIpMetaFailure(primaryError) === 'NOT_FOUND') {
      throw Object.assign(new Error('Sin metadata disponible para esta IP'), { code: 'IPMETA_NOT_FOUND' });
    }

    try {
      const info = await lookupIpMetaFallback(ip);
      cacheSet(ipMetaCache, ip, info);
      return info;
    } catch (fallbackError) {
      if (classifyIpMetaFailure(fallbackError) === 'NOT_FOUND') {
        throw Object.assign(new Error('Sin metadata disponible para esta IP'), { code: 'IPMETA_NOT_FOUND' });
      }
      const rateLimited =
        classifyIpMetaFailure(primaryError) === 'RATE_LIMITED' ||
        classifyIpMetaFailure(fallbackError) === 'RATE_LIMITED';
      if (rateLimited) {
        throw Object.assign(new Error('El proveedor de metadata IP alcanzó su límite de consultas'), { code: 'IPMETA_RATE_LIMITED' });
      }
      throw Object.assign(new Error('Servicio de metadata IP no disponible'), { code: 'IPMETA_UNAVAILABLE' });
    }
  })();

  ipMetaPending.set(ip, promise);
  try {
    return await promise;
  } finally {
    ipMetaPending.delete(ip);
  }
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

// Casos de certificado agregados 2026-09-09: antes cualquier falla de TLS
// (ej. certificado que no cubre el hostname exacto) caía al genérico
// "Servicio no disponible" — indistinguible de "el servidor no responde".
// Para una herramienta que mide dominios, "el certificado no coincide" es
// en sí mismo un hallazgo de seguridad real, no solo un error técnico.
// Encontrado con presidencia.gob.ec: certificado compartido entre ~26
// sitios .gob.ec cuyo SAN no incluye la variante sin "www" del dominio
// (ERR_TLS_CERT_ALTNAME_INVALID, verificado con curl y con Node).
function errorMessage(e) {
  if (e && typeof e === 'object') {
    if (e.code === 'ENOTFOUND') return 'Dominio no encontrado';
    if (e.code === 'ETIMEOUT') return 'Timeout';
    // (2026-09-12) — 'TIMEOUT'/'WEBFETCH_TOTAL_TIMEOUT' son los códigos
    // reales que de verdad se lanzan cuando un timeout expira (fetchJSON/
    // fetchText/fetchPage/safeWebFetch.adapter.js/queryQuad9) — 'ETIMEOUT'
    // de arriba no corresponde a ningún código que este proyecto lance en
    // ningún lado (quedó de antes, no se toca). Antes, un `new
    // Error('Timeout')` sin `.code` cayera acá cayendo al genérico
    // "Servicio no disponible" — confirmado con evidencia real (duraciones
    // pegadas a los techos de 15s/30s con `error_code: null` en el log de
    // mediciones) que así perdíamos la distinción entre "no se pudo medir
    // a tiempo" y "no se pudo conectar en absoluto".
    if (e.code === 'TIMEOUT' || e.code === 'WEBFETCH_TOTAL_TIMEOUT') return 'Timeout';
    if (e.code === 'ECONNREFUSED') return 'Conexión rechazada';
    if (e.code === 'EAI_AGAIN') return 'Problema de DNS';
    if (e.code === 'ERR_TLS_CERT_ALTNAME_INVALID') return 'El certificado TLS no cubre este dominio exacto';
    if (e.code === 'CERT_HAS_EXPIRED') return 'El certificado TLS expiró';
    if (e.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' || e.code === 'SELF_SIGNED_CERT_IN_CHAIN') return 'Certificado TLS autofirmado o no confiable';
    if (e.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') return 'No se pudo verificar la cadena de certificados TLS';
    if (e.code === 'CERT_NOT_YET_VALID') return 'El certificado TLS aún no es válido';
    // FASE 3 (2026-09-12): agregado por safeWebFetch.adapter.js
    // (resolvePublicAddresses) cuando un dominio real (con zona delegada,
    // NS resuelve) no tiene registro A ni AAAA — ej. gob.ec, que existe
    // solo como paraguas DNS de subdominios (presidencia.gob.ec, etc.),
    // sin servicio web propio. dns.lookup() no distingue esto de un
    // dominio inexistente (ambos dan ENOTFOUND); esta consulta adicional
    // sí lo distingue.
    if (e.code === 'WEBFETCH_NO_ADDRESS_RECORD') return 'El dominio no tiene registros A ni AAAA (posible subdominio/zona sin servicio web propio)';
    // (2026-09-12) — fetchRdap() distingue explícitamente por qué falló la
    // consulta RDAP en vez de tragarse todo como "sin entrada RDAP": antes
    // un timeout o una caída de rdap.org se reportaba igual que un dominio
    // genuinamente sin RDAP, perdiendo la distinción entre "no tiene" y "no
    // se pudo consultar".
    if (e.code === 'RDAP_NOT_FOUND') return 'El dominio no tiene entrada RDAP';
    if (e.code === 'RDAP_TIMEOUT') return 'Timeout consultando el servicio RDAP';
    if (e.code === 'RDAP_UNAVAILABLE') return 'Servicio RDAP no disponible';
    if (e.code === 'RDAP_INVALID_RESPONSE') return 'El servicio RDAP devolvió una respuesta inválida';
    // (2026-09-12) — clasificación semántica de los MEASUREMENT_ERROR
    // residuales: Archive (web.archive.org) y PageSpeed son dependencias
    // externas que solo aportan contexto sobre el dominio, nunca al
    // dominio mismo — un fallo ahí no es un hallazgo del dominio medido.
    if (e.code === 'ARCHIVE_TIMEOUT') return 'Timeout consultando Wayback Machine';
    if (e.code === 'ARCHIVE_UNAVAILABLE') return 'Servicio de Wayback Machine no disponible';
    if (e.code === 'NO_MX_RECORDS') return 'El dominio no tiene registros MX';
    // (2026-09-13) — lookupIpMeta(): mismo criterio, dependencia externa
    // de geolocalización/ASN por IP, no un hallazgo sobre el dominio.
    if (e.code === 'IPMETA_RATE_LIMITED') return 'El proveedor de metadata IP alcanzó su límite de consultas';
    if (e.code === 'IPMETA_UNAVAILABLE') return 'Servicio de metadata IP no disponible';
    if (e.code === 'IPMETA_NOT_FOUND') return 'Sin metadata disponible para esta IP';
    // (2026-09-13) — handleMalware()/URLhaus: la fuente no pudo consultarse
    // de forma válida — nunca debe interpretarse como "sin reportes".
    if (e.code === 'MALWARE_AUTH_REQUIRED') return 'El servicio de detección de malware requiere autenticación no configurada';
    if (e.code === 'MALWARE_RATE_LIMITED') return 'El servicio de detección de malware alcanzó su límite de consultas';
    if (e.code === 'MALWARE_TIMEOUT') return 'Timeout consultando el servicio de detección de malware';
    if (e.code === 'MALWARE_SOURCE_UNAVAILABLE') return 'Servicio de detección de malware no disponible';
    if (e.code === 'MALWARE_INVALID_RESPONSE') return 'El servicio de detección de malware devolvió una respuesta inválida';
    // (2026-09-13) — ECONNREFUSED confirmado en vivo contra el servicio
    // objetivo (TCP directo + openssl s_client, no un timeout ni una
    // condición ambigua) — código propio por handler, ECONNREFUSED
    // genérico no se toca en ningún otro módulo.
    if (e.code === 'TLS_CONNECTION_REFUSED') return 'Conexión rechazada por el servicio TLS del dominio';
    if (e.code === 'SSLCHAIN_CONNECTION_REFUSED') return 'Conexión rechazada al consultar la cadena de certificados';
    if (e.code === 'SECURITYTXT_CONNECTION_REFUSED') return 'Conexión rechazada al consultar security.txt';
  }
  return 'Servicio no disponible';
}

// Log de mediciones (2026-09-12) — a pedido explícito, para poder hacer
// análisis internos de solidez/integridad del sistema (ej. detectar
// checks que se degradan con el tiempo, patrones de timeout) sin depender
// de scripts ad-hoc contra una corrida puntual. Un renglón JSON por cada
// respuesta de un check real (domain, check, duración, éxito/error,
// código de error). Reutiliza `res._startedAt` (ya seteado en el
// callback principal de `http.createServer`, mismo timestamp que ya usa
// el log de acceso) y `res._checkName`/`res._checkDomain` (seteados justo
// antes del despacho por `segments[0]`/`segments[1]`, ver más abajo) —
// server.js es la ÚNICA fuente de verdad de qué check corrió, así que se
// engancha acá, en el único punto por el que pasan casi todos los
// handlers (`sendJSON`), en vez de tocar cada uno de los ~50 handlers uno
// por uno. Un archivo por día (rota solo, por nombre) en el mismo volumen
// `data/` ya montado y persistente — sin dependencia nueva, sin base de
// datos (ver CLAUDE.md).
const MEASUREMENTS_DIR = path.join(__dirname, 'data', 'measurements');
function appendMeasurementLine(obj) {
  try {
    if (!fs.existsSync(MEASUREMENTS_DIR)) fs.mkdirSync(MEASUREMENTS_DIR, { recursive: true });
    const day = new Date().toISOString().slice(0, 10);
    fs.appendFile(path.join(MEASUREMENTS_DIR, `${day}.jsonl`), JSON.stringify(obj) + '\n', () => {});
  } catch (e) {
    // Nunca debe romper una respuesta real por un problema de logging.
  }
}

function recordMeasurement(res, data) {
  if (!res._checkName) return;
  appendMeasurementLine({
    ts: new Date().toISOString(),
    check: res._checkName,
    domain: (data && data.domain) || res._checkDomain || null,
    duration_ms: res._startedAt ? Date.now() - res._startedAt : null,
    success: !(data && data.error),
    error_code: (data && data.error_code) || null,
  });
}

// FIX (2026-09-12) — visibilidad del request coalescing de fetchWebsite()
// (más abajo): a diferencia de getSecurityHeaders()/getTlsInfo() en el
// cliente (cuya mejora ya es visible en el log de mediciones normal,
// porque las 12 llamadas duplicadas eran al MISMO endpoint /headers/),
// fetchWebsite() la comparten 5 checks con endpoints DISTINTOS
// (sitefeatures/cookies/linkedpages/socialtags/firewall) — cada uno ya
// registra su propia medición vía recordMeasurement(), pero eso no dice
// si, puertas adentro, fetchWebsite() reusó una promesa en curso o
// disparó una consulta real nueva. Se registra ese detalle acá, sin
// tocar el formato de las mediciones normales — mismo archivo, un campo
// `event` que las distingue.
function recordCacheEvent(fn, domain, event) {
  appendMeasurementLine({ ts: new Date().toISOString(), check: fn, domain, event });
}

function sendJSON(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(JSON.stringify(data));
  recordMeasurement(res, data);
}

async function handleMx(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const records = await dns.resolveMx(domain);
    sendJSON(res, 200, { domain, records });
  } catch (e) {
    // gob.mx (SPF "v=spf1 -all", declara explícitamente que no envía
    // correo) no tiene MX — dns.resolveMx() da ENODATA, un caso legítimo
    // de "sin registros", no una falla. handleCaa/handleTlsa ya
    // distinguen esto; handleMx no lo hacía y devolvía un error genérico
    // en vez de records: [].
    if (e.code === 'ENODATA' || e.code === 'ENOTFOUND')
      sendJSON(res, 200, { domain, records: [] });
    else sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

// FASE 1 (2026-09-12) — spf/dmarc/ipv4/ipv6 vivían SOLO en el cliente
// (index.html), llamando a https://dns.google/resolve y https://ipapi.co
// directo desde el navegador del usuario — el único caso de los ~54
// checks de Mediciones que no pasaba por este servidor. Causa raíz
// documentada del "Servicio no disponible" uniforme en los 20/20
// dominios: fetchWithTimeout() (index.html) colapsa cualquier fallo del
// fetch del navegador (CORS, red del cliente, rate limit de terceros) al
// mismo mensaje genérico, y como la llamada nunca llega a este proceso,
// no queda ningún rastro en `docker logs` para diagnosticarlo. Se
// resuelven aquí con dns.resolveTxt/resolve4/resolve6 nativos (mismo
// patrón y mismos resolvers que handleMx/handleCaa/handleTlsa) —
// consistente con el resto del sistema, con logging real, y sin depender
// de la red del navegador de quien esté usando la herramienta.
async function handleSpf(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const records = await dns.resolveTxt(domain);
    const flat = records.map((parts) => parts.join(''));
    // Mismo criterio que antes en el cliente: subcadena "v=spf1" en
    // cualquier TXT del apex (no solo como prefijo estricto), sin
    // distinguir mayúsculas/minúsculas de más — se preserva tal cual para
    // no cambiar semántica en esta fase.
    const found = flat.some((v) => v.includes('v=spf1'));
    sendJSON(res, 200, { domain, found });
  } catch (e) {
    if (e.code === 'ENODATA' || e.code === 'ENOTFOUND') {
      sendJSON(res, 200, { domain, found: false });
    } else {
      sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
    }
  }
}

async function handleDmarc(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const records = await dns.resolveTxt(`_dmarc.${domain}`);
    const flat = records.map((parts) => parts.join(''));
    const found = flat.some((v) => v.includes('v=DMARC1'));
    sendJSON(res, 200, { domain, found });
  } catch (e) {
    if (e.code === 'ENODATA' || e.code === 'ENOTFOUND') {
      sendJSON(res, 200, { domain, found: false });
    } else {
      sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
    }
  }
}

// Geolocalización por IP reutiliza lookupIpMeta() (primario + fallback,
// ya usada por handleIpInfo/handleServerLocation) en vez del ipapi.co
// directo que usaba el cliente — mismo dato (país/lat/lon/ASN por IP),
// ahora con la resiliencia que ya tenía el resto del sistema. Fallos de
// geolocalización por IP individual no rompen el check completo (mismo
// criterio que el código original: catch silencioso por IP).
async function handleIpv4(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const ips = await dns.resolve4(domain);
    const geos = [];
    const geoErrors = [];
    for (const ip of ips) {
      try {
        const info = await lookupIpMeta(ip);
        geos.push({ ip, country: info.country, lat: info.latitude, lon: info.longitude, asn: info.asn });
      } catch (e) {
        // (2026-09-13) — antes se descartaba en silencio: si lookupIpMeta()
        // fallaba para una IP, esa IP simplemente desaparecía del arreglo
        // `geos` sin dejar rastro. `geoErrors` es aditivo (no cambia
        // `ips`/`geos`, que el cliente ya consume tal cual) — deja visible
        // en la respuesta qué IP no se pudo medir y por qué.
        geoErrors.push({ ip, error: errorMessage(e), error_code: e && e.code });
      }
    }
    sendJSON(res, 200, { domain, ips, geos, geoErrors });
  } catch (e) {
    if (e.code === 'ENODATA' || e.code === 'ENOTFOUND') {
      sendJSON(res, 200, { domain, ips: [], geos: [] });
    } else {
      sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
    }
  }
}

async function handleIpv6(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const ips = await dns.resolve6(domain);
    sendJSON(res, 200, { domain, ips });
  } catch (e) {
    if (e.code === 'ENODATA' || e.code === 'ENOTFOUND') {
      sendJSON(res, 200, { domain, ips: [] });
    } else {
      sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
    }
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

// Puerto 25 saliente suele estar bloqueado por el hosting (verificado en
// server1 y en desarrollo: 25 no conecta, 587 sí) — probar los puertos en
// paralelo evita esperar el timeout completo de 25 (15s) antes de intentar
// 587 secuencialmente. Prioridad de resultado sin cambios: 'supports' >
// 'no' (respuesta definitiva) > 'timeout'/'connection-error'.
async function checkSmtpUtf8(server) {
  const ports = [25, 587];
  const results = await Promise.all(ports.map(port => smtpQuery(server, port)));
  return results.find(r => r.status === 'supports')
    || results.find(r => r.status === 'no')
    || results[results.length - 1];
}

async function handleSmtpUtf8(domain, res) {
  domain = normalizeDomain(domain);
  try {
    let mx;
    try {
      mx = await dns.resolveMx(domain);
    } catch (e) {
      // (2026-09-12) — antes un dominio sin registros MX (una condición
      // real y válida: no recibe correo) se reportaba con el mismo
      // error_code genérico ENODATA que usan otras consultas DNS con
      // significado distinto (ej. DKIM/TXT) — sin un código propio, el
      // cliente no puede distinguir "no tiene MX" de un fallo real de
      // medición. Solo se re-etiqueta ENODATA (dominio existe, sin MX);
      // ENOTFOUND (el dominio no resuelve en absoluto) sigue igual, es una
      // condición distinta y más grave que no se quiere ocultar acá.
      if (e && e.code === 'ENODATA') {
        throw Object.assign(new Error('El dominio no tiene registros MX'), { code: 'NO_MX_RECORDS' });
      }
      throw e;
    }
    // Antes recorría los registros MX en secuencia — cada uno puede tardar
    // hasta 15s (checkSmtpUtf8 ya prueba sus 2 puertos en paralelo, pero
    // un MX puede agotar igual el timeout completo si ambos puertos están
    // filtrados). Con 2+ registros MX el total se sumaba: verificado con
    // presidencia.gob.ec (2 MX, ambos con puertos filtrados) — 30.2s en
    // secuencia. isoc.org.ec solo tiene 1 MX, por eso este caso no había
    // aparecido en la ronda anterior. Ahora los registros MX también
    // corren en paralelo entre sí — mismo principio que ya se aplicó a
    // los puertos.
    const results = await Promise.all(
      mx.map(async (record) => {
        const { status } = await checkSmtpUtf8(record.exchange);
        return { server: record.exchange, status };
      })
    );
    sendJSON(res, 200, { domain, results });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
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

// ─── FASE 1 CORREO (2026-09-15, revisada 2026-09-16) — maildnssec /
// mailipv6 / starttls ────────────────────────────────────────────────────
// Los tres checks de correo que el fork de Paraguay agregó después de
// nuestra separación (ver AUDITORIA_CHECKS_FALTANTES_MEDICIONES.md, commit
// base 0d14f45). Paraguay/upstream es una REFERENCIA histórica y funcional,
// no una especificación — no se copió su código tal cual, y su semántica
// original de maildnssec/starttls se revisó y se corrigió tras encontrar
// problemas conceptuales reales (ver IMPLEMENTACION_MEDICIONES_FASE1_CORREO.md
// § "Revisión crítica frente al upstream Paraguay" para la evidencia
// completa, incluyendo un caso real verificado en producción: nic.ar).
//
// Límite deliberado (Paraguay no tenía ninguno): como máximo 5 MX por
// dominio, ordenados por prioridad ascendente — evita que un dominio con
// muchos MX dispare decenas de consultas/conexiones dentro de una sola
// corrida de hasta 20 dominios.
const MAX_MX_PROBED = 5;
// Corto y controlado — un solo puerto (25), no 15s x 2 puertos como
// smtputf8. Configurable por entorno solo para que los tests puedan
// simular un timeout real sin esperar 8s de verdad (nunca se toca en
// despliegue normal).
const STARTTLS_TIMEOUT_MS = Number(process.env.STARTTLS_TIMEOUT_MS) || 8000;

function sortAndCapMx(mxRecords) {
  return [...mxRecords]
    .sort((a, b) => (a.priority ?? 0) - (b.priority ?? 0))
    .slice(0, MAX_MX_PROBED);
}

// Mismo re-etiquetado que ya usa handleSmtpUtf8(): un dominio sin MX es una
// condición real y válida (no recibe correo), no un fallo de medición —
// NO_MX_RECORDS ya está en NOT_APPLICABLE_CODES del lado del cliente
// (index.html), así que no hace falta tocar esa clasificación.
async function resolveMxOrNotApplicable(domain) {
  try {
    return await dns.resolveMx(domain);
  } catch (e) {
    if (e && e.code === 'ENODATA') {
      throw Object.assign(new Error('El dominio no tiene registros MX'), { code: 'NO_MX_RECORDS' });
    }
    throw e;
  }
}

// ── maildnssec: revisado y corregido (2026-09-16) ──────────────────────
//
// Pregunta funcional real: ¿la resolución DNS relevante para la
// infraestructura de correo del dominio está protegida mediante DNSSEC?
//
// La primera versión de este check (y la de Paraguay, de la que partió)
// respondía esa pregunta consultando DS/DNSKEY directamente en el hostname
// MX (dnssecGoogle(exchange), heredada de dnssecGoogle() del check `dnssec`
// dormido). Eso es INCORRECTO en el caso general: DS/DNSKEY existen por
// ZONA (punto de delegación real, con NS propios), no por hostname. La
// inmensa mayoría de los hostnames MX (ej. mail.proveedor.net) NO son ellos
// mismos una zona delegada — son un registro A/AAAA normal dentro de la
// zona real (proveedor.net, o más arriba). Preguntar por DS/DNSKEY
// exactamente en ese nombre produce FALSO NEGATIVO sistemático aunque la
// cadena de confianza real (root → tld → dominio real → ese registro) esté
// perfectamente firmada y validada.
//
// Caso real verificado en producción (2026-09-16) que confirma el
// problema: nic.ar (DNSSEC: ok, confirmado en auditorías previas) tiene
// como MX mx30.slyt.gob.ar / mx20.slyt.gob.ar — un dominio de correo
// COMPLETAMENTE DISTINTO (slyt.gob.ar), que sí está firmado. Consultar
// DNSKEY exactamente en "mx30.slyt.gob.ar" no devuelve nada (no es un punto
// de delegación); consultar DS ahí devuelve SERVFAIL. Sin embargo, una
// consulta A normal a "mx30.slyt.gob.ar" contra un resolver validador
// (dns.google) devuelve AD:true — la cadena real SÍ está intacta y
// validada, el check anterior lo habría reportado como "sin DNSSEC" de
// forma incorrecta.
//
// Corrección: en vez de inferir seguridad por presencia de DS/DNSKEY en el
// nombre exacto, se usa el bit AD (Authenticated Data) que devuelve
// dns.google (resolver DNSSEC-validante) en una consulta A/AAAA normal —
// eso refleja si la cadena de confianza REAL (dondequiera que esté el
// punto de delegación efectivo) validó correctamente para ese nombre
// específico, sin necesidad de que MEDICIONES determine por sí mismo cuál
// es la zona autoritativa pertinente. No reutiliza dnssecGoogle() (esa
// función queda intacta, solo la usa el check `dnssec` dormido, sin
// relación con este) ni el módulo DNSSEC independiente de Ecuador — es un
// helper propio, local a este archivo.
//
// Clasificación del upstream: IMPRECISA (el enfoque DS/DNSKEY-por-hostname
// es razonable solo cuando el MX coincide con un punto de delegación real,
// pero produce falsos negativos en el caso general, que es mayoritario).
// Clasificación de esta versión: REIMPLEMENTADA PARA CORREGIR UPSTREAM.
//
// Limitación que SÍ se conserva conscientemente: esto refleja la validación
// de UN resolver público (Google), no una reconstrucción independiente de
// la cadena completa por MEDICIONES — es la misma limitación práctica que
// tiene cualquier chequeo basado en el bit AD de un tercero. Se documenta,
// no se oculta.
async function checkAuthenticatedResolution(hostname) {
  for (const type of ['A', 'AAAA']) {
    let data;
    try {
      data = await fetchJSON(`https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=${type}`);
    } catch (e) {
      continue; // probar el otro tipo antes de rendirse
    }
    if (data.Status === 0 && Array.isArray(data.Answer) && data.Answer.length > 0) {
      return { state: data.AD ? 'secure' : 'insecure', queriedType: type };
    }
    if (data.Status === 2) {
      // SERVFAIL — dns.google solo devuelve esto a un cliente que no pidió
      // CD=1 cuando la validación DNSSEC de la cadena falla realmente (no
      // es un timeout ni un problema de red): alguien intentó proteger
      // este nombre con DNSSEC y la cadena está rota. Distinto de
      // "insecure" (nunca se firmó) — se conserva la distinción en el
      // estado, aunque para PASS/FAIL ambos cuentan como "no protegido hoy".
      return { state: 'broken', queriedType: type };
    }
    // Status 3 (NXDOMAIN) u otro: probar el siguiente tipo de registro.
  }
  return { state: 'unresolved', queriedType: null };
}

async function handleMailDnssec(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const mx = sortAndCapMx(await resolveMxOrNotApplicable(domain));
    const domainAuth = await checkAuthenticatedResolution(domain);
    const results = await Promise.all(mx.map(async (record) => {
      const auth = await checkAuthenticatedResolution(record.exchange);
      return { server: record.exchange, state: auth.state };
    }));
    sendJSON(res, 200, { domain, domainState: domainAuth.state, results });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

// Semántica exacta de mailipv6 (documentada porque no es obvia): mide,
// para cada servidor MX, si publica un registro AAAA — solo resolución DNS,
// NO conectividad IPv6 real (mismo alcance/limitación que el check `ipv6`
// que ya existe en MEDICIONES para el dominio principal). No exige que
// TODOS los MX tengan AAAA para considerar el resultado positivo, ni
// convierte automáticamente la ausencia de AAAA en un error de medición
// (ver getCheckResult() en index.html para la política exacta: PASS si
// todos, FAIL si ninguno, INFO si es mixto — adopción parcial es un dato
// real, no un fallo binario).
async function handleMailIpv6(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const mx = sortAndCapMx(await resolveMxOrNotApplicable(domain));
    const results = await Promise.all(mx.map(async (record) => {
      const exchange = record.exchange;
      try {
        const ips = await dns.resolve6(exchange);
        return { server: exchange, present: ips.length > 0 };
      } catch (e) {
        if (e && (e.code === 'ENODATA' || e.code === 'ENOTFOUND')) {
          // Confirmado: no tiene AAAA. Resultado real, no un error.
          return { server: exchange, present: false };
        }
        // SERVFAIL/timeout/etc. — no se pudo determinar para este MX.
        return { server: exchange, present: null, error_code: e && e.code };
      }
    }));
    sendJSON(res, 200, { domain, results });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

// ── starttls: revisado (2026-09-16) ─────────────────────────────────────
//
// Pregunta funcional real: ¿los servidores MX que reciben correo para el
// dominio anuncian STARTTLS para SMTP entre servidores?
//
// Puerto: solo 25 (entrega SMTP real entre servidores — el puerto que
// STARTTLS protege). Se evaluó explícitamente el puerto 587 (que sí usa
// Paraguay) y se descartó a propósito: 587 es "message submission"
// (RFC 6409), un protocolo distinto pensado para clientes autenticados que
// envían correo, no para la recepción MX-a-MX que es lo que este check
// pregunta. Incluirlo "porque Paraguay lo hace" habría mezclado dos
// preguntas distintas bajo un mismo nombre.
//
// Anunciado vs. funcional: la primera versión de este check solo
// verificaba que el servidor ANUNCIE STARTTLS en la respuesta a EHLO — no
// que la negociación TLS realmente se complete. Un servidor puede anunciar
// STARTTLS y aun así fallar al negociarlo (certificado corrupto,
// configuración rota) — una distinción real y útil que el simple anuncio
// no captura. Esta versión intenta la negociación TLS real tras ver el
// anuncio (comando STARTTLS → banner 220 → tls.connect() envolviendo el
// mismo socket) — pero SIN enviar correo: la conexión se cierra en cuanto
// se confirma (o falla) el handshake, nunca se llega a MAIL FROM/RCPT
// TO/DATA. rejectUnauthorized:false porque este check mide si el cifrado
// oportunista está disponible, no si el certificado es válido (eso sería
// un check distinto).
//
// Salvaguardas SSRF (iguales o superiores a Paraguay, que no tenía
// ninguna):
//  (a) resuelve el hostname UNA vez vía resolvePublicAddresses() — ya
//      rechaza loopback/RFC1918/link-local/ULA IPv6/multicast/CGNAT — y
//      conecta DIRECTO a esa IP ya validada (nunca vuelve a resolver el
//      hostname al conectar), cerrando la ventana de DNS rebinding;
//  (b) puerto fijo (25), nunca proporcionado por quien usa la herramienta;
//  (c) timeout corto (STARTTLS_TIMEOUT_MS) que cubre TODA la sonda
//      (negociación SMTP + intento de TLS), y siempre destruye el socket
//      al finalizar — nunca queda una conexión abierta indefinidamente.
async function probeStarttls(exchange) {
  let addresses;
  try {
    addresses = await safeWebFetchAdapter.resolvePublicAddresses(exchange);
  } catch (e) {
    // Incluye WEBFETCH_BLOCKED_IP (IP privada/interna) y
    // WEBFETCH_NO_ADDRESS_RECORD — en ambos casos no se puede/debe conectar.
    return { server: exchange, status: 'blocked', error_code: e && e.code };
  }
  const target = addresses[0];
  return new Promise((resolve) => {
    let buffer = '';
    let ehloSent = false;
    let starttlsSent = false;
    let capabilities = [];
    let finished = false;
    const socket = net.createConnection({ host: target.address, port: 25 });
    const timer = setTimeout(() => {
      if (finished) return;
      finished = true;
      socket.destroy();
      resolve({ server: exchange, status: 'timeout' });
    }, STARTTLS_TIMEOUT_MS);
    const finish = (status) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      try { socket.end(); } catch (e) {}
      try { socket.destroy(); } catch (e) {}
      resolve({ server: exchange, status, capabilities });
    };
    // Intenta subir la MISMA conexión TCP a TLS — nunca abre un socket
    // nuevo, nunca envía ningún comando SMTP después de esto (ni siquiera
    // QUIT: alcanza con destruir el socket una vez confirmado el resultado).
    // IMPORTANTE: se quita el listener de texto plano (onPlainData) ANTES
    // de entregarle el socket a tls.connect() — si ambos siguieran activos,
    // los bytes del handshake TLS podrían leerse (parcialmente) como si
    // fueran texto SMTP, corrompiendo la negociación.
    const attemptTlsUpgrade = () => {
      socket.off('data', onPlainData);
      let tlsSocket;
      try {
        tlsSocket = tls.connect({ socket, servername: exchange, rejectUnauthorized: false });
      } catch (e) {
        return finish('announced_only');
      }
      tlsSocket.once('secureConnect', () => finish('supports'));
      tlsSocket.once('error', () => finish('announced_only'));
    };
    function onPlainData(data) {
      buffer += data.toString();
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop();
      for (const line of lines) {
        if (!ehloSent && /^220[ -]/.test(line)) {
          socket.write('EHLO mediciones.isoc-lac\r\n');
          ehloSent = true;
          continue;
        }
        if (ehloSent && !starttlsSent && /^250[ -]/.test(line)) {
          capabilities.push(line.replace(/^250[ -]/, '').trim());
          if (line.startsWith('250 ')) {
            const announced = capabilities.some((cap) => /^STARTTLS\b/i.test(cap));
            if (!announced) return finish('no');
            starttlsSent = true;
            socket.write('STARTTLS\r\n');
            return; // esperar la respuesta (220 / 4xx / 5xx) al comando
          }
          continue;
        }
        if (starttlsSent) {
          if (/^220/.test(line)) return attemptTlsUpgrade();
          if (/^[45]\d\d/.test(line)) {
            // El servidor anunció STARTTLS pero rechazó el comando —
            // anuncio sin soporte funcional real.
            return finish('announced_only');
          }
        }
      }
    }
    socket.on('data', onPlainData);
    socket.on('error', () => finish('connection-error'));
    socket.on('end', () => {
      if (!finished) finish(starttlsSent ? 'announced_only' : 'no');
    });
  });
}

// Nota de límite conocido (no resuelto en esta revisión): si el servidor
// envía la respuesta "220 ..." al comando STARTTLS y los primeros bytes
// del handshake TLS en el MISMO segmento TCP, la porción de handshake que
// llegue junto con esa línea se descarta (el parser de texto plano no la
// reenvía a tls.connect()) — el resultado sería 'timeout' en vez de
// 'supports' para ese caso puntual, nunca un falso PASS. No se intentó
// resolver con un buffer más sofisticado por ser una herramienta de
// diagnóstico, no un cliente SMTP de producción.

// La política de agregación de varios MX (todos soportan / mezcla conocida
// / ninguno / no se pudo medir) vive en getCheckResult() del lado del
// cliente (index.html, case 'starttls') — ver ese comentario para el
// detalle exacto y por qué "INCONCLUSIVE" se reserva solo para cuando la
// evidencia es insuficiente, no para adopción parcial ya determinada.
async function handleStarttls(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const mx = sortAndCapMx(await resolveMxOrNotApplicable(domain));
    const results = await Promise.all(mx.map((record) => probeStarttls(record.exchange)));
    sendJSON(res, 200, { domain, results });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

async function handleDnssec(domain, res) {
  domain = normalizeDomain(domain);
  const google = await dnssecGoogle(domain);
  const algorithms = [...new Set(google.algorithms.filter(Boolean))];
  const valid = google.parent && google.child;
  sendJSON(res, 200, { domain, methods: { google }, algorithms, valid });
}

// FASE 2 (2026-09-12): antes cualquier error de dns.resolveTxt (selector
// realmente inexistente, pero también timeout/SERVFAIL/red) se colapsaba
// por igual a found:false, y el cliente lo mostraba como "No permite
// DKIM" — una conclusión que solo probamos con UN selector no estándar
// ("default"), no una verificación exhaustiva. Se distingue ahora
// ENODATA/ENOTFOUND (ese selector específico no existe — found:false,
// sigue sin ser error) de cualquier otro fallo de la consulta DNS
// (error real de medición, no del dominio).
async function handleDkim(domain, selector, res) {
  domain = normalizeDomain(domain);
  try {
    const txt = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
    const flat = txt.flat().join('');
    const found = /v=DKIM1/i.test(flat);
    sendJSON(res, 200, { domain, selector, found });
  } catch (e) {
    if (e.code === 'ENODATA' || e.code === 'ENOTFOUND') {
      sendJSON(res, 200, { domain, selector, found: false });
    } else {
      sendJSON(res, 200, { domain, selector, error: errorMessage(e) });
    }
  }
}

function pickLib(target) {
  const url = typeof target === 'string' ? new URL(target) : target;
  return url.protocol === 'http:' ? http : https;
}

// User-Agent por defecto de todas las llamadas fetchJSON (2026-09-09):
// verificado que rdap.org (403) y web.archive.org (400) rechazan
// peticiones sin User-Agent — mismo patrón en dos servicios de terceros
// distintos, encontrado en dos rondas separadas de validación cruzada
// (ver docs/arquitectura.md). En vez de agregar el header caso por caso
// (como se hizo primero solo para RDAP), se puso acá para cubrir también
// llamadas nuevas a futuro. Verificado que no rompe ningún consumidor
// actual (dns.google, cloudflare-dns.com, ipwho.is, RIPEstat,
// tranco-list.eu, urlhaus-api.abuse.ch no son sensibles a este header).
// Un `options.headers['User-Agent']` explícito lo sobreescribe.
const DEFAULT_FETCH_USER_AGENT = 'MedicionesISOCLAC/1.0 (+https://mediciones.isoc.org.ec)';

function fetchJSON(target, options = {}) {
  return new Promise((resolve, reject) => {
    const url = typeof target === 'string' ? new URL(target) : target;
    const lib = pickLib(url);
    const req = lib.request(
      url,
      {
        method: options.method || 'GET',
        headers: { 'User-Agent': DEFAULT_FETCH_USER_AGENT, ...(options.headers || {}) }
      },
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
      req.destroy(Object.assign(new Error('Timeout'), { code: 'TIMEOUT' }));
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
      req.destroy(Object.assign(new Error('Timeout'), { code: 'TIMEOUT' }));
    });
    if (options.body) req.write(options.body);
    req.end();
  });
}

function fetchHeaders(target, useHttp = false) {
  return fetchSafePage(target, { method: 'HEAD' }).then(({ headers, statusCode }) => ({
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
        req.destroy(Object.assign(new Error('Timeout'), { code: 'TIMEOUT' }));
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

// FIX (2026-09-12) — mismo bug de condición de carrera que
// getSecurityHeaders()/getTlsInfo() (index.html), del lado servidor:
// sitefeatures/cookies/linkedpages/socialtags/firewall llegan como
// solicitudes HTTP simultáneas separadas (cada una su propio endpoint),
// y cada una llamaba a fetchWebsite(domain) de forma independiente —
// varias podían pasar el chequeo `cacheGet(htmlCache, domain)` antes de
// que cualquiera terminara de llenarlo, disparando hasta 5 consultas
// reales idénticas al mismo destino. htmlPending guarda la PROMESA en
// curso (no el resultado) apenas se crea — cualquier llamada concurrente
// posterior para el mismo `domain` se engancha a esa promesa en vez de
// arrancar una nueva. El TTL de 60s de htmlCache/cacheGet/cacheSet no
// cambia; el bucle de reintento HTTPS→HTTP tampoco.
const htmlPending = new Map();

async function fetchWebsite(domain) {
  const cached = cacheGet(htmlCache, domain);
  if (cached) {
    recordCacheEvent('fetchWebsite', domain, 'cache_hit');
    return cached;
  }
  if (htmlPending.has(domain)) {
    recordCacheEvent('fetchWebsite', domain, 'pending_reused');
    return htmlPending.get(domain);
  }
  recordCacheEvent('fetchWebsite', domain, 'new_fetch');
  const promise = (async () => {
    const targets = [`https://${domain}`, `http://${domain}`];
    let lastError = null;
    for (const target of targets) {
      try {
        const resolved = await resolveFinalWebTarget(target);
        const page = resolved.response;
        // FIX (2026-09-12): una respuesta HTTP real — 2xx, 3xx, 4xx o 5xx —
        // es una medición COMPLETADA, no un fallo de transporte. Antes se
        // exigía statusCode 2xx exacto para aceptar el resultado; cualquier
        // 401/403 (challenge de WAF, bloqueo de bot, auth-gate) se
        // descartaba en silencio y caía al genérico de abajo, aunque la
        // petición hubiera funcionado perfectamente — confirmado en vivo
        // contra tiendainglesa.com.uy (403 Cloudflare) y copaair.com (401
        // DataDome), ambos con respuesta real y útil (cookies, cabeceras de
        // WAF) que se perdía. fetchWebsite() ya no decide qué status code
        // es "éxito" — devuelve la respuesta tal cual y cada handler
        // (cookies/firewall/sitefeatures/linkedpages/socialtags) interpreta
        // status/headers/body/redirect según su propio criterio, igual que
        // ya hace handleHeaders con este mismo target. Solo un fallo real
        // de transporte (timeout, DNS, conexión rechazada, TLS) amerita
        // reintentar con el otro esquema (https->http) — antes también se
        // reintentaba ante cualquier 4xx/5xx, duplicando requests reales
        // sin necesidad.
        const value = { url: resolved.finalUrl, chain: resolved.chain, ...page };
        cacheSet(htmlCache, domain, value);
        cacheSet(headerCache, domain, { headers: page.headers, statusCode: page.statusCode });
        return value;
      } catch (e) {
        lastError = e; // fallo real de transporte — se conserva para propagar su .code si el otro esquema también falla
      }
    }
    throw lastError || new Error('Servicio no disponible');
  })();
  htmlPending.set(domain, promise);
  try {
    return await promise;
  } finally {
    htmlPending.delete(domain);
  }
}

// Team Cymru IP-to-ASN (origin.asn.cymru.com / origin6.asn.cymru.com):
// servicio DNS público construido sobre los feeds BGP propios de Cymru.
// Puede exponer MÚLTIPLES pares {asn, prefix} para una misma IP cuando más
// de un origen anuncia el mismo prefijo (señal de MOAS / posible secuestro
// de ruta) — visibilidad que RIPEstat network-info no da (entrega un solo
// ASN "elegido", sin indicar si hay otros orígenes observados). Formato de
// consulta replicado desde Paraguay/upstream (fase 2, ver auditoría) tras
// confirmar que es correcto para IPv4 e IPv6 (IPv6 se indexa por /48).
function ipToCymruQuery(ipIn) {
  const family = net.isIP(ipIn);
  if (family === 4) {
    const octets = String(ipIn).split('.').slice(0, 3).reverse();
    return `${octets.join('.')}.origin.asn.cymru.com`;
  }
  if (family === 6) {
    const [left, right = ''] = String(ipIn).toLowerCase().split('::');
    const leftParts = left ? left.split(':').filter(Boolean) : [];
    const rightParts = right ? right.split(':').filter(Boolean) : [];
    const fill = Math.max(0, 8 - leftParts.length - rightParts.length);
    const expanded = [...leftParts, ...Array(fill).fill('0'), ...rightParts]
      .map(part => part.padStart(4, '0'))
      .join('');
    const hex = expanded.padEnd(32, '0').slice(0, 12);
    return `${hex.split('').reverse().join('.')}.origin6.asn.cymru.com`;
  }
  return null;
}

async function resolveOriginRoutesViaCymru(ip) {
  const cached = cacheGet(routeCache, `cymru:${ip}`, 10 * 60 * 1000);
  if (cached) return cached;
  const query = ipToCymruQuery(ip);
  if (!query) return [];
  const txt = await dns.resolveTxt(query);
  const rows = txt.flat().map(String).filter(Boolean);
  const routes = [];
  for (const row of rows) {
    const [left, right] = row.split('|').map(part => part && part.trim());
    if (!left || !right) continue;
    for (const asnText of left.split(' ').map(part => part.trim()).filter(Boolean)) {
      const asn = parseInt(asnText, 10);
      if (asn) routes.push({ asn, prefix: right });
    }
  }
  cacheSet(routeCache, `cymru:${ip}`, routes);
  return routes;
}

async function rpkiValidity(ip) {
  // Nunca se envía una IP privada/interna a Cymru/RIPEstat: no existe BGP ni
  // ROA real para RFC1918/loopback/enlace-local/etc., así que consultarlas
  // solo desperdicia llamadas y filtra topología interna a un tercero. Se
  // reporta 'blocked' sin salir a red — distinto de 'error' o 'unknown' para
  // no esconder la razón de la ausencia de veredicto.
  if (safeWebFetchAdapter.isBlockedIp(ip)) {
    return { state: 'blocked', asn: null, prefix: null, routes: [] };
  }

  let routes = [];
  try {
    routes = await resolveOriginRoutesViaCymru(ip);
  } catch (e) {
    routes = [];
  }

  let asn = null;
  let prefix = null;
  let originLookupFailed = false;

  if (routes.length) {
    ({ asn, prefix } = routes[0]);
  } else {
    // La validación real requiere ASN de origen + prefijo; sin ruta vía Cymru
    // se recurre a RIPEstat network-info (la API de Cloudflare RPKI usada
    // antes aquí ya no existe — devuelve 404 en cualquier formato de URL).
    try {
      const info = await fetchJSON(
        `https://stat.ripe.net/data/network-info/data.json?resource=${ip}`
      );
      prefix = info?.data?.prefix || info?.data?.resources?.[0] || info?.data?.resource || null;
      // RIPEstat devuelve el ASN como string (ej. "13335"), no number ni object.
      const asnEntry = info?.data?.asns?.[0];
      asn =
        typeof asnEntry === 'number'
          ? asnEntry
          : typeof asnEntry === 'string'
          ? parseInt(asnEntry, 10) || null
          : typeof asnEntry === 'object' && asnEntry
          ? asnEntry.asn || asnEntry.id || null
          : null;
    } catch (e) {
      originLookupFailed = true;
    }
  }

  if (!asn || !prefix) {
    // Sin ASN/prefijo de origen no hay par que validar contra ROAs. Si ambas
    // fuentes (Cymru y RIPEstat network-info) fallaron por completo, es un
    // error de medición real — no lo mismo que "no se observó ninguna ruta".
    return { state: originLookupFailed ? 'error' : 'unknown', asn: null, prefix: null, routes };
  }

  try {
    const ripe = await fetchJSON(
      `https://stat.ripe.net/data/rpki-validation/data.json?resource=${asn}&prefix=${encodeURIComponent(prefix)}`
    );
    const rawStatus = String(ripe?.data?.status || '').toLowerCase();
    // Vocabulario real de RIPEstat/routinator (verificado en vivo contra la
    // API, 2026-09-15): 'valid' | 'invalid_asn' | 'invalid_length' | 'unknown'
    // — nunca el literal "invalid". El check anterior de Ecuador solo
    // reconocía 'invalid' exacto, así que un resultado realmente inválido
    // caía siempre a 'unknown' y jamás producía FAIL. Se preserva el estado
    // específico (invalid_asn / invalid_length) en vez de colapsarlo.
    const state = ['valid', 'invalid_asn', 'invalid_length', 'unknown'].includes(rawStatus)
      ? rawStatus
      : 'unknown';
    return { state, asn, prefix, routes };
  } catch (e) {
    // La validación ROA en sí falló (red/timeout/formato): se conoce el par
    // ASN/prefijo pero no su estado — error de medición, no "sin ROA".
    return { state: 'error', asn, prefix, routes };
  }
}

async function handleRpki(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const { v4, v6 } = await resolveAddresses(domain);
    const ips = [...v4, ...v6];
    if (!ips.length) {
      const noAddressRecord = await domainHasNoAddressButIsRealZone(domain);
      const code = noAddressRecord ? 'WEBFETCH_NO_ADDRESS_RECORD' : undefined;
      return sendJSON(res, 200, {
        domain,
        error: code ? errorMessage({ code }) : 'Sin direcciones IP',
        error_code: code
      });
    }
    const results = [];
    for (const ip of ips) {
      const { state, asn, prefix, routes } = await rpkiValidity(ip);
      results.push({ ip, family: v4.includes(ip) ? 4 : 6, state, asn, prefix, routes: routes || [] });
    }
    // 'blocked' (IP privada, nunca consultada a terceros) no cuenta ni a
    // favor ni en contra de la validez global — solo los IPs efectivamente
    // evaluados determinan `valid`.
    const evaluated = results.filter(r => r.state !== 'blocked');
    const overall = evaluated.length > 0 && evaluated.every(r => r.state === 'valid');
    sendJSON(res, 200, { domain, results, valid: Boolean(overall) });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

const WHOIS_DISCLAIMER =
  'Los datos WHOIS dependen de políticas de cada registrador/registro y pueden ' +
  'estar total o parcialmente redactados por privacidad, o el TLD puede no ' +
  'publicarlos en las fuentes consultadas. Su ausencia no implica ningún ' +
  'problema del dominio.';

// Extrae el bloque de una sección "df-heading" del HTML de whois.com (ej.
// "Registrant Contact") para no cruzar campos con otras secciones (Registrar,
// Technical Contact, etc.) que también puedan usar etiquetas genéricas.
function extractWhoisComSection(html, headingText) {
  const idx = html.indexOf(headingText);
  if (idx === -1) return '';
  const rest = html.slice(idx);
  const nextHeading = rest.indexOf('df-heading', headingText.length);
  return nextHeading === -1 ? rest : rest.slice(0, nextHeading);
}

async function handleWhois(domain, res) {
  domain = normalizeDomain(domain);
  let name = '';
  let country = '';
  let whoisComReached = false;
  let rdapReached = false;

  try {
    const html = await fetchText(`https://www.whois.com/whois/${domain}`);
    whoisComReached = true;
    const section = extractWhoisComSection(html, 'Registrant Contact');
    const orgMatch = section.match(
      /Organization:\s*<\/div>\s*<div class="df-value">([^<]*)/i
    );
    if (orgMatch) name = orgMatch[1].trim();
    const countryMatch = section.match(
      /Country:\s*<\/div>\s*<div class="df-value">([^<]*)/i
    );
    if (countryMatch) country = countryMatch[1].trim();
  } catch (e) {}

  if (!name && !country) {
    try {
      // Antes usaba fetchJSON directo (no sigue el 302 de rdap.org, sin
      // User-Agent) — mismo bug ya corregido en handleDomainInfo, nunca
      // aplicado acá hasta ahora. Ver fetchRdap() más arriba.
      const data = await fetchRdap(domain);
      rdapReached = true;
      const registrant = data.entities?.find(e => e.roles?.includes('registrant'));
      const vcard = registrant?.vcardArray?.[1] || [];
      for (const item of vcard) {
        if (item[0] === 'fn') name = item[3];
        if (item[0] === 'adr') {
          // Bug encontrado al verificar este fix (2026-09-09): buscaba
          // item[1]?.label, un parámetro que no existe en RDAP real — el
          // país viene como parámetro "cc" (ej. {"cc":"EC"}) o como último
          // elemento del array estructurado de dirección (item[3]).
          const addressParts = Array.isArray(item[3]) ? item[3] : [];
          country = item[1]?.cc || addressParts[addressParts.length - 1] || '';
        }
        if (item[0] === 'country') country = item[3];
      }
      if (!name && data.name) name = data.name;
    } catch (e) {}
  }

  let status;
  let message = null;
  if (name || country) {
    status = 'ok';
  } else if (whoisComReached || rdapReached) {
    status = 'redactado_o_no_disponible';
    message = 'Sin campos de registrante públicos en las fuentes consultadas.';
  } else {
    status = 'error_tecnico';
    message = 'No se pudo consultar ninguna fuente WHOIS/RDAP en este momento.';
  }

  sendJSON(res, 200, {
    domain,
    name,
    country,
    status,
    message,
    disclaimer: WHOIS_DISCLAIMER
  });
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
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

async function handleHeaders(domain, res) {
  domain = normalizeDomain(domain);
  try {
    // FASE 3 (2026-09-12): antes, si el primer intento HTTPS al apex
    // fallaba, handleHeaders se rendía ahí — a diferencia de
    // handleServerStatus, que ya reintentaba con HTTP. Confirmado con
    // evidencia real (llamadas secuenciales, sin concurrencia, mismo
    // resultado siempre — no es un problema de ráfagas): copaair.com no
    // escucha HTTPS en el apex (ECONNREFUSED puerto 443, solo puerto 80
    // que redirige a www), y gub.uy/nic.us sirven ahí un certificado que
    // no cubre el apex — en los tres casos el sitio real funciona
    // perfectamente vía HTTP → redirección. Sin este reintento, hasta 12
    // checks que dependen de este mismo endpoint (headers, https,
    // redirect, hsts, csp, xfo, xcto, referrer, permissions, xxss,
    // server, compression) fallaban juntos por la misma causa. Mismo
    // patrón que ya tenía handleServerStatus, copiado tal cual.
    let resolved;
    try {
      resolved = await resolveFinalWebTarget(`https://${domain}`, { method: 'HEAD' });
    } catch (httpsError) {
      resolved = await resolveFinalWebTarget(`http://${domain}`, { method: 'HEAD' });
    }
    const httpsRes = resolved.response;
    const httpRes = await fetchHeaders(`http://${domain}`, true).catch(
      () => null
    );
    const result = {
      domain,
      // FASE 2 (2026-09-12): `https` solo era true con statusCode === 200
      // exacto — un 401/403/405/429 (TLS funciona, la app responde, solo
      // rechaza el método/autorización) se reportaba igual que un dominio
      // sin HTTPS en absoluto. Se agrega `statusCode` crudo para que el
      // cliente pueda distinguir "no hubo conexión" de "hubo conexión con
      // este código" — `https` se conserva tal cual para no romper otros
      // consumidores del campo.
      https: httpsRes.statusCode === 200,
      statusCode: httpsRes.statusCode,
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
      finalUrl: resolved.finalUrl,
      chain: resolved.chain,
      headers: httpsRes.headers
    };
    sendJSON(res, 200, result);
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

// FASE 2 (2026-09-12): dns.resolve(domain,'CAA') devuelve un array de
// OBJETOS ({critical, issue}/{critical, issuewild}/{critical, iodef}), no
// strings — el cliente hacía `.join(', ')` sobre esos objetos, y
// String({...}) da literalmente "[object Object]" (bug confirmado,
// reproducible con cualquier dominio con registros CAA). Se agrega aquí
// `formatted` (strings legibles) sin quitar `records` (el objeto crudo
// original, por compatibilidad con quien ya lo consuma).
// dns.resolve(domain,'CAA') también incluye `type: 'CAA'` en cada objeto
// (además de `critical` y la propiedad-tag real) — verificado en vivo con
// argentina.gob.ar: sin excluirlo, Object.keys().find() lo tomaba como si
// fuera el tag, mostrando "type: CAA" repetido para todos los registros
// (peor que el bug original: ya no crashea a "[object Object]", pero
// sigue sin mostrar el valor real). Se busca explícitamente entre los
// tags CAA reales (issue/issuewild/iodef, los únicos que define el RFC
// 6844) en vez de "cualquier clave que no sea critical".
const CAA_TAGS = ['issue', 'issuewild', 'iodef'];
function formatCaaRecord(r) {
  const tag = CAA_TAGS.find((t) => r[t] !== undefined);
  const value = tag ? r[tag] : JSON.stringify(r);
  return `${tag || 'caa'}: ${value}${r.critical ? ' (critical)' : ''}`;
}

async function handleCaa(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const records = await dns.resolve(domain, 'CAA');
    sendJSON(res, 200, { domain, records, formatted: records.map(formatCaaRecord) });
  } catch (e) {
    if (e.code === 'ENODATA' || e.code === 'ENOTFOUND')
      sendJSON(res, 200, { domain, records: [], formatted: [] });
    else sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

async function handleTlsa(domain, res) {
  domain = normalizeDomain(domain);
  try {
    // dns.resolve()/dns.resolveTlsa() no reconocen el rrtype TLSA en la
    // versión de Node fijada en el Dockerfile (20.18.0) — lanzan
    // ERR_INVALID_ARG_VALUE antes de siquiera consultar la red, para
    // cualquier dominio (verificado con varios, incluyendo uno inventado).
    // Se usa DNS-over-HTTPS de Google (mismo patrón que dnssecGoogle() y
    // los checks de IPv4/IPv6/DMARC del cliente), así el check no depende
    // de qué tipos de registro soporte el binding nativo de DNS de Node.
    // Ver docs/arquitectura.md § "Validación cruzada con herramientas
    // independientes".
    const data = await fetchJSON(`https://dns.google/resolve?name=_443._tcp.${domain}&type=TLSA`);
    const records = Array.isArray(data.Answer) ? data.Answer.map(a => a.data) : [];
    sendJSON(res, 200, { domain, records });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

async function handleSecurityTxt(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await resolveFinalWebTarget(`https://${domain}/.well-known/security.txt`, { method: 'HEAD' });
    const found = data.response.statusCode && data.response.statusCode >= 200 && data.response.statusCode < 300;
    sendJSON(res, 200, { domain, found, finalUrl: data.finalUrl, chain: data.chain });
  } catch (e) {
    // (2026-09-13) — mismo criterio que handleTls()/handleSslChain(): un
    // ECONNREFUSED acá significa que la conexión necesaria para revisar
    // security.txt fue rechazada explícitamente por el destino — código
    // propio de este handler, no una regla global.
    if (e && e.code === 'ECONNREFUSED') {
      const code = 'SECURITYTXT_CONNECTION_REFUSED';
      return sendJSON(res, 200, { domain, error: errorMessage({ code }), error_code: code });
    }
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
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
      sendJSON(res, 200, { domain, error: 'Timeout', error_code: 'TIMEOUT' });
    });
    socket.on('error', e => {
      if (settled) return;
      settled = true;
      if (e && e.code === 'ENOTFOUND') {
        domainHasNoAddressButIsRealZone(domain).then((confirmed) => {
          const finalCode = confirmed ? 'WEBFETCH_NO_ADDRESS_RECORD' : e.code;
          sendJSON(res, 200, { domain, error: errorMessage({ code: finalCode }), error_code: finalCode });
        });
        return;
      }
      // (2026-09-13) — verificado en vivo (TCP directo + openssl s_client
      // desde server1) contra copaair.com: ECONNREFUSED acá es un rechazo
      // real y confirmado del propio servicio TLS objetivo (nada escucha
      // en el puerto 443 de esa IP exacta), no un timeout ni una condición
      // ambigua — código propio de este handler, no una regla global sobre
      // ECONNREFUSED (que en otros handlers tiene semántica distinta, ej.
      // handleOpenPorts lo usa como resultado normal de "puerto cerrado").
      // tls/key/ocsp (cliente) leen todos esta misma respuesta.
      if (e && e.code === 'ECONNREFUSED') {
        const code = 'TLS_CONNECTION_REFUSED';
        sendJSON(res, 200, { domain, error: errorMessage({ code }), error_code: code });
        return;
      }
      sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
    });
  } catch (e) {
    if (!settled) sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

async function handleIpInfo(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const { v4: ipv4, v6: ipv6 } = await resolveAddresses(domain);
    const geo = [];
    const geoErrors = [];
    const ips = [...ipv4, ...ipv6].slice(0, 5);
    for (const ip of ips) {
      try {
        const info = await lookupIpMeta(ip);
        geo.push(info);
      } catch (e) {
        // (2026-09-13) — ver mismo comentario en handleIpv4(): aditivo, no
        // cambia `geo` que el cliente ya consume tal cual.
        geoErrors.push({ ip, error: errorMessage(e), error_code: e && e.code });
      }
    }
    sendJSON(res, 200, { domain, ipv4, ipv6, geo, geoErrors });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
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
      if (e && e.code === 'ENOTFOUND') {
        domainHasNoAddressButIsRealZone(domain).then((confirmed) => {
          const finalCode = confirmed ? 'WEBFETCH_NO_ADDRESS_RECORD' : e.code;
          sendJSON(res, 200, { domain, error: errorMessage({ code: finalCode }), error_code: finalCode });
        });
        return;
      }
      // (2026-09-13) — mismo criterio que handleTls(): ECONNREFUSED acá es
      // un rechazo real y confirmado del servicio objetivo, código propio
      // de este handler.
      if (e && e.code === 'ECONNREFUSED') {
        const code = 'SSLCHAIN_CONNECTION_REFUSED';
        sendJSON(res, 200, { domain, error: errorMessage({ code }), error_code: code });
        return;
      }
      sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
    });
    socket.setTimeout(15000, () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      sendJSON(res, 200, { domain, error: 'Timeout', error_code: 'TIMEOUT' });
    });
  } catch (e) {
    if (!settled) sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
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
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

async function handleCookies(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const page = await fetchWebsite(domain);
    const cookies = page.headers['set-cookie'] || [];
    sendJSON(res, 200, { domain, cookies });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

async function handleCrawlRules(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const urls = [`https://${domain}/robots.txt`, `http://${domain}/robots.txt`];
    for (const url of urls) {
      try {
        const data = await resolveFinalWebTarget(url);
        if (data.response.statusCode && data.response.statusCode >= 200 && data.response.statusCode < 300) {
          return sendJSON(res, 200, {
            domain,
            found: true,
            finalUrl: data.finalUrl,
            chain: data.chain,
            content: data.response.body
          });
        }
      } catch (e) {}
    }
    sendJSON(res, 200, { domain, found: false, content: '' });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

function isPageSpeedQuotaError(errorObj) {
  if (!errorObj) return false;
  if (errorObj.status === 'RESOURCE_EXHAUSTED') return true;
  const message = errorObj.message || '';
  return /quota/i.test(message);
}

async function handleQuality(domain, res) {
  domain = normalizeDomain(domain);

  if (Date.now() < pageSpeedQuotaExhaustedUntil) {
    return sendJSON(res, 200, { domain, error: pageSpeedQuotaMessage, error_code: 'PAGESPEED_QUOTA_EXCEEDED' });
  }

  try {
    const data = await fetchJSON(
      `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=https://${domain}`
    );
    // PageSpeed responde HTTP 200 con un cuerpo {"error": {...}} cuando se
    // agota la cuota diaria (fetchJSON no revisa el status HTTP, solo
    // parsea el JSON) — antes esto caía directo a leer
    // data.lighthouseResult?.categories (undefined) y devolvía
    // silenciosamente `pwa: null` como si el sitio no tuviera PWA, en vez
    // de reportar que la consulta falló. Verificado: cuota agotada
    // (`RESOURCE_EXHAUSTED`) reproducible para cualquier dominio, no es
    // algo de este dominio en particular — se muestra el mensaje real de
    // Google (más útil que el genérico "Servicio no disponible" de
    // errorMessage()) para que quede claro que es un límite de cuota, no
    // un fallo de red.
    if (data.error) {
      const message = data.error.message || 'PageSpeed devolvió un error';
      const isQuota = isPageSpeedQuotaError(data.error);
      if (isQuota) {
        pageSpeedQuotaExhaustedUntil = Date.now() + PAGESPEED_QUOTA_COOLDOWN_MS;
        pageSpeedQuotaMessage = message;
      }
      // (2026-09-12) — la cuota agotada es un límite de NUESTRA cuenta de
      // Google, no un hallazgo sobre el dominio — se distingue con un
      // error_code propio para que el cliente pueda clasificarla aparte de
      // un fallo genérico de PageSpeed (otros errores de la API, sin
      // relación con cuota, se dejan tal cual, sin código específico).
      return sendJSON(res, 200, { domain, error: message, error_code: isQuota ? 'PAGESPEED_QUOTA_EXCEEDED' : undefined });
    }
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
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

async function handleServerLocation(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const { ip } = await resolveFirstIp(domain);
    if (!ip) {
      const noAddressRecord = await domainHasNoAddressButIsRealZone(domain);
      const code = noAddressRecord ? 'WEBFETCH_NO_ADDRESS_RECORD' : undefined;
      return sendJSON(res, 200, {
        domain,
        error: code ? errorMessage({ code }) : 'Sin dirección IP',
        error_code: code
      });
    }
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
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
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
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

async function followRedirects(url, limit = 5, chain = []) {
  const resolved = await resolveFinalWebTarget(url, { method: 'HEAD', maxRedirects: limit });
  chain.push(...resolved.chain);
  return chain;
}

async function handleRedirectChain(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const chain = await followRedirects(`http://${domain}`);
    sendJSON(res, 200, { domain, chain });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
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
    else sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

async function handleServerStatus(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await resolveFinalWebTarget(`https://${domain}`, { method: 'HEAD' });
    const page = data.response;
    sendJSON(res, 200, {
      domain,
      statusCode: page.statusCode,
      location: page.headers?.location || null,
      finalUrl: data.finalUrl,
      chain: data.chain
    });
  } catch (e) {
    try {
      const data = await resolveFinalWebTarget(`http://${domain}`, { method: 'HEAD' });
      const page = data.response;
      sendJSON(res, 200, {
        domain,
        statusCode: page.statusCode,
        location: page.headers?.location || null,
        finalUrl: data.finalUrl,
        chain: data.chain
      });
    } catch (err) {
      sendJSON(res, 200, { domain, error: errorMessage(err), error_code: err && err.code });
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

// Check "Traceroute" retirado de la UI (index.html, 2026-09-09): dependía
// de api.hackertarget.com/mtr/, que ahora exige API key ("error valid key
// required") de forma incondicional para cualquier dominio — confirmado
// repetido y desde dos redes distintas, no es un límite de cuota diario
// que se recupera solo. No hay alternativa gratuita equivalente (RIPEstat
// looking-glass necesita un prefijo IP, no un dominio, y mide anuncios
// BGP, no saltos de red reales; los demás endpoints de HackerTarget piden
// key también). Ruta dejada sin tocar (mismo patrón que /emailconfig,
// /httpsecurity, /dnssecurity, /tlsconfig), ahora inalcanzable desde la
// UI. Ver docs/arquitectura.md.
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
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
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
    if (!ip) {
      const noAddressRecord = await domainHasNoAddressButIsRealZone(domain);
      const code = noAddressRecord ? 'WEBFETCH_NO_ADDRESS_RECORD' : undefined;
      return sendJSON(res, 200, {
        domain,
        error: code ? errorMessage({ code }) : 'Sin dirección IP',
        error_code: code
      });
    }
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
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

// Extrae el nombre (campo "fn" del vCard) de la primera entidad RDAP con el
// rol dado (ej. "registrar") — RDAP no tiene un campo "registryName" plano;
// el nombre del registrador vive anidado en `entities[].vcardArray`.
// Fetch RDAP compartido (2026-09-09): originalmente vivía inline solo en
// handleDomainInfo; se consolidó acá porque handleWhois tenía su PROPIA
// copia de esta misma llamada rota (fallback RDAP, más abajo) que nunca
// se había corregido — dos lugares con el mismo bug en vez de uno.
// El bootstrap de rdap.org redirige (302) al servidor RDAP autoritativo
// del TLD (ej. .ec -> rdap.registry.ec) antes de entregar el JSON real —
// hay que seguir esa redirección (fetchJSON no lo hace, se queda con el
// cuerpo vacío del 302 y falla el JSON.parse). resolveFinalWebTarget ya
// sigue redirects con guardas SSRF, mismo utilitario que usan headers/
// security.txt/etc. También hace falta un User-Agent no vacío: rdap.org
// está detrás de Cloudflare y devuelve 403 (no 302) a peticiones sin
// User-Agent — verificado con curl -A "" vs -A "Mozilla/...". No se usa
// el User-Agent por defecto de fetchJSON (DEFAULT_FETCH_USER_AGENT)
// porque esta llamada no pasa por fetchJSON, sino por el adaptador SSRF
// (resolveFinalWebTarget) — mismo valor, dos mecanismos de fetch.
// FIX (2026-09-12): antes cualquier fallo acá (timeout de rdap.org,
// servicio caído, respuesta no-JSON) terminaba indistinguible de "el
// dominio no tiene entrada RDAP" — confirmado en vivo: rdap.org devuelve
// 404 (siguiendo redirect al servidor RDAP autoritativo del TLD) tanto
// para un dominio que genuinamente no existe como para un TLD sin
// bootstrap RDAP registrado (ej. .pa) — en ambos casos 404 es la señal
// correcta de "sin datos RDAP", así que sigue siendo RDAP_NOT_FOUND. Lo
// que se corrige es todo lo demás: un timeout de red o una caída del
// servicio ya no se disfrazan de "sin RDAP".
async function fetchRdap(domain) {
  let resolved;
  try {
    resolved = await resolveFinalWebTarget(`https://rdap.org/domain/${domain}`, {
      headers: {
        Accept: 'application/rdap+json',
        'User-Agent': DEFAULT_FETCH_USER_AGENT
      }
    });
  } catch (e) {
    if (e && (e.code === 'TIMEOUT' || e.code === 'WEBFETCH_TOTAL_TIMEOUT')) {
      throw Object.assign(new Error('Timeout consultando el servicio RDAP'), { code: 'RDAP_TIMEOUT' });
    }
    throw Object.assign(new Error('Servicio RDAP no disponible'), { code: 'RDAP_UNAVAILABLE' });
  }

  const status = resolved.response.statusCode;
  if (status === 404) {
    throw Object.assign(new Error('El dominio no tiene entrada RDAP'), { code: 'RDAP_NOT_FOUND' });
  }
  if (!status || status < 200 || status >= 300) {
    throw Object.assign(new Error('Servicio RDAP no disponible'), { code: 'RDAP_UNAVAILABLE' });
  }

  try {
    return JSON.parse(resolved.response.body);
  } catch (e) {
    throw Object.assign(new Error('El servicio RDAP devolvió una respuesta inválida'), { code: 'RDAP_INVALID_RESPONSE' });
  }
}

function rdapEntityName(entities, role) {
  const entity = (Array.isArray(entities) ? entities : [])
    .find(e => Array.isArray(e.roles) && e.roles.includes(role));
  const props = entity?.vcardArray?.[1];
  if (!Array.isArray(props)) return null;
  const fn = props.find(p => Array.isArray(p) && p[0] === 'fn');
  return fn?.[3] || null;
}

async function handleDomainInfo(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchRdap(domain);
    const events = Array.isArray(data.events) ? data.events : [];
    const creation = events.find(e => e.eventAction === 'registration')?.eventDate || null;
    const expiration = events.find(e => e.eventAction === 'expiration')?.eventDate || null;
    sendJSON(res, 200, {
      domain,
      registry: rdapEntityName(data.entities, 'registrar'),
      status: data.status || [],
      creation,
      expiration
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
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
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
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

// `baseUrl` debe ser la URL final real de la página (post-redirects,
// ej. "https://www.isoc.org.ec/") — antes se comparaba el href contra la
// clave cruda `domain` con `startsWith('/')`/`includes(domain)`, lo que
// clasificaba como "externo" cualquier enlace relativo sin "/" inicial
// (ej. "quienes-somos.html", un patrón HTML común) — bug verificado con
// el HTML real de isoc.org.ec. Resolver contra la URL base con el `URL`
// nativo de Node y comparar hostname es la forma correcta, sin depender
// de heurísticas de substring.
function extractLinks(html, baseUrl) {
  const links = [];
  const regex = /<a\s+[^>]*href=["']([^"'#]+)["'][^>]*>/gi;
  const base = new URL(baseUrl);
  let match;
  while ((match = regex.exec(html))) {
    const href = match[1];
    let internal = false;
    try {
      internal = new URL(href, base).hostname === base.hostname;
    } catch (e) {
      internal = false; // href no navegable como URL (ej. "javascript:...")
    }
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
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

async function handleDnsServer(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const servers = await dns.resolveNs(domain);
    sendJSON(res, 200, { domain, servers });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

async function handleTechStack(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const page = await fetchWebsite(domain);
    const stack = detectTechStack(page.body);
    sendJSON(res, 200, { domain, stack });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

async function handleListedPages(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const urls = [`https://${domain}/sitemap.xml`, `http://${domain}/sitemap.xml`];
    for (const url of urls) {
      try {
        const data = await resolveFinalWebTarget(url);
        if (data.response.statusCode && data.response.statusCode >= 200 && data.response.statusCode < 300) {
          const matches = [...data.response.body.matchAll(/<loc>([^<]+)<\/loc>/gi)].map(m => m[1]);
          return sendJSON(res, 200, { domain, pages: matches, finalUrl: data.finalUrl, chain: data.chain });
        }
      } catch (e) {}
    }
    sendJSON(res, 200, { domain, pages: [] });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

async function handleLinkedPages(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const page = await fetchWebsite(domain);
    const links = extractLinks(page.body, page.url);
    sendJSON(res, 200, { domain, links });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

async function handleSocialTags(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const page = await fetchWebsite(domain);
    const tags = extractSocialTags(page.body);
    sendJSON(res, 200, { domain, tags });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
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
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
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
    // FASE 2 (2026-09-12): faltaban Imperva y Vercara en el fingerprinting
    // (detectados solo por cabeceras propias del proveedor — mismo
    // criterio que los 4 de arriba, no hay verificación adicional).
    if (wafHeaders.includes('imperva') || wafHeaders.includes('incapsula')) detections.push('Imperva');
    if (wafHeaders.includes('vercara') || wafHeaders.includes('ultradns') || wafHeaders.includes('quantil')) detections.push('Vercara');
    sendJSON(res, 200, {
      domain,
      waf: detections,
      detected: detections.length > 0
    });
  } catch (e) {
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
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
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

async function handleArchive(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchJSON(
      `https://web.archive.org/cdx/search/cdx?url=${domain}&output=json&limit=5&fl=timestamp,original,statuscode`
    );
    // (2026-09-12) — verificado en vivo: cuando el dominio no tiene
    // snapshots, la API CDX de Wayback Machine responde 200 con "[]" (JSON
    // válido, se parsea sin error) — NO hace falta un código especial para
    // "sin historial", ya llega acá como éxito con entries:[] igual que
    // siempre. Lo único que amerita distinguirse es cuando la consulta a
    // web.archive.org en sí misma no se pudo completar.
    const entries = Array.isArray(data)
      ? data.slice(1).map(item => ({ timestamp: item[0], original: item[1], status: item[2] }))
      : [];
    sendJSON(res, 200, { domain, entries });
  } catch (e) {
    // (2026-09-12) — antes cualquier fallo acá (timeout de
    // web.archive.org, error de red, respuesta no-JSON) se perdía en el
    // genérico "Servicio no disponible" sin error_code — indistinguible de
    // un timeout real del DOMINIO medido, cuando en realidad
    // handleArchive() nunca contacta al dominio, solo a Wayback Machine.
    const code = e && e.code === 'TIMEOUT' ? 'ARCHIVE_TIMEOUT' : 'ARCHIVE_UNAVAILABLE';
    sendJSON(res, 200, { domain, error: errorMessage({ code }), error_code: code });
  }
}

async function handleRanking(domain, res) {
  domain = normalizeDomain(domain);
  try {
    const data = await fetchJSON(`https://tranco-list.eu/api/ranks/domain/${domain}`);
    // BUG encontrado (2026-09-12), verificado en vivo contra la API real:
    // Tranco NO devuelve {rank, list_date} en el nivel superior — devuelve
    // {domain, ranks: [{date, rank}, ...]} (histórico, más reciente
    // primero, o `ranks: []` si el dominio no está rankeado). El código
    // leía `data.rank`/`data.list_date` — siempre undefined — así que el
    // check nunca reportó un ranking real, ni para dominios que sí están
    // en el top de Tranco (confirmado con nic.uy: rank real ~17000, pero
    // el código devolvía null igual).
    const latest = Array.isArray(data.ranks) && data.ranks.length ? data.ranks[0] : null;
    sendJSON(res, 200, { domain, rank: latest ? latest.rank : null, date: latest ? latest.date : null });
  } catch (e) {
    // Verificado en vivo: Tranco aplica rate limit real (HTTP 429, cuerpo
    // HTML no-JSON) bajo ráfagas de varias consultas seguidas — un lote de
    // 20 dominios puede disparar esto. fetchJSON() no revisa el status
    // HTTP, así que cualquier causa (rate limit, timeout, red) cae acá por
    // igual — no se puede distinguir sin instrumentar fetchJSON para
    // exponer el status code (fuera de alcance de esta corrección
    // puntual). Se marca con error_code propio para que quede
    // identificable en el log de mediciones en vez de perderse como
    // "Sin información" sin más contexto.
    sendJSON(res, 200, { domain, error: 'Sin información', error_code: 'RANKING_UNAVAILABLE' });
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

// Quad9 exige HTTP/2 en su servidor DoH desde 2026 (RFC 8484 §5.2) — con
// HTTP/1.1 (lo que usa https.request) responde 505 siempre, para
// cualquier dominio, verificado también desde server1. No es un límite de
// tasa ni un problema de nuestra query — se confirmó reproduciendo la
// misma consulta con el módulo http2 nativo de Node (sin dependencia
// nueva), que sí obtiene 200 con la respuesta real. Ver
// docs/arquitectura.md § "Validación cruzada con herramientas
// independientes".
function queryQuad9(domain) {
  return new Promise((resolve, reject) => {
    let client;
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

      client = http2.connect('https://dns.quad9.net');
      client.on('error', reject);

      const req = client.request({
        ':method': 'POST',
        ':path': '/dns-query',
        'content-type': 'application/dns-message',
        accept: 'application/dns-message',
        'content-length': query.length
      });

      let status = null;
      req.on('response', headers => {
        status = Number(headers[':status']);
      });

      const chunks = [];
      req.on('data', c => chunks.push(c));
      req.on('end', () => {
        client.close();
        try {
          if (status !== 200) {
            reject(new Error(`Quad9 DoH respondió HTTP ${status}`));
            return;
          }
          const msg = dnsPacket.decode(Buffer.concat(chunks));
          resolve(msg);
        } catch (e) {
          reject(e);
        }
      });

      req.on('error', e => {
        client.close();
        reject(e);
      });

      req.setTimeout(15000, () => {
        req.close();
        client.close();
        reject(Object.assign(new Error('Timeout'), { code: 'TIMEOUT' }));
      });

      req.write(query);
      req.end();
    } catch (e) {
      if (client) client.close();
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
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

// (2026-09-13) — auditoría: urlhaus-api.abuse.ch exige autenticación
// (header `Auth-Key`) desde que abuse.ch unificó sus APIs — verificado en
// vivo, sin credencial la API devuelve 401 `{"error":"Unauthorized"}`, un
// cuerpo JSON válido. El código anterior usaba fetchJSON() (que no revisa
// el statusCode HTTP, solo parsea el body) y leía `data.urls`/
// `data.query_status` de esa respuesta de error — ambos `undefined` en un
// 401 — resultando SIEMPRE en `entries: []` y `threat: undefined`, que el
// cliente interpretaba como "Sin reportes" = PASS. Es decir: un fallo de
// autenticación se mostraba idéntico a "consultado, dominio limpio" — un
// falso negativo de seguridad, no un error visible. No hay
// URLHAUS_AUTH_KEY configurada en ningún .env (ni de ejemplo ni en
// producción) — nunca existió.
//
// Regla obligatoria de este fix: PASS solo si la fuente respondió de
// forma válida y confirma "sin reportes"; FAIL solo si confirma reportes
// reales; cualquier otra cosa (falta de credencial, 401/403, 429, 5xx,
// timeout, red, respuesta no interpretable) -> INCONCLUSIVE, nunca PASS.
function classifyUrlhausFailure(statusCode) {
  if (statusCode === 401 || statusCode === 403) return 'MALWARE_AUTH_REQUIRED';
  if (statusCode === 429) return 'MALWARE_RATE_LIMITED';
  return 'MALWARE_SOURCE_UNAVAILABLE'; // 5xx u otro status inesperado
}

async function handleMalware(domain, res) {
  domain = normalizeDomain(domain);
  const body = `host=${encodeURIComponent(domain)}`;
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
  // Soporte opcional para cuando exista una API key real (ver .env.example)
  // — sin ella, la consulta sigue intentándose (como antes) pero ahora el
  // 401 resultante se interpreta correctamente en vez de leerse como éxito.
  if (process.env.URLHAUS_AUTH_KEY) headers['Auth-Key'] = process.env.URLHAUS_AUTH_KEY;

  let page;
  try {
    page = await fetchPage('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers,
      body,
      timeout: 15000
    });
  } catch (e) {
    const code = e && e.code === 'TIMEOUT' ? 'MALWARE_TIMEOUT' : 'MALWARE_SOURCE_UNAVAILABLE';
    return sendJSON(res, 200, { domain, error: errorMessage({ code }), error_code: code });
  }

  if (page.statusCode !== 200) {
    const code = classifyUrlhausFailure(page.statusCode);
    return sendJSON(res, 200, { domain, error: errorMessage({ code }), error_code: code });
  }

  let data;
  try {
    data = JSON.parse(page.body);
  } catch (e) {
    return sendJSON(res, 200, { domain, error: errorMessage({ code: 'MALWARE_INVALID_RESPONSE' }), error_code: 'MALWARE_INVALID_RESPONSE' });
  }

  // Respuesta real de URLhaus autenticado: siempre trae `query_status`
  // ("ok" = hay entradas asociadas, "no_results" = consultado, sin
  // reportes). Cualquier otro valor (o su ausencia, como en el 401 que
  // motivó este fix) no es una respuesta real interpretable.
  if (data.query_status !== 'ok' && data.query_status !== 'no_results') {
    return sendJSON(res, 200, { domain, error: errorMessage({ code: 'MALWARE_INVALID_RESPONSE' }), error_code: 'MALWARE_INVALID_RESPONSE' });
  }

  const entries = Array.isArray(data.urls) ? data.urls.slice(0, 10) : [];
  sendJSON(res, 200, { domain, entries, hasReports: entries.length > 0 });
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
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
  }
}

// Check "TLS Security Config" retirado de la UI (index.html, 2026-09-09):
// dependía de tls-observatory.services.mozilla.com, que Mozilla dio de baja
// permanentemente (sunset oct-2024, repo archivado dic-2025 — verificado
// con curl, no responde en absoluto). No hay reemplazo gratuito equivalente
// con el mismo formato score/tests, y el check se solapaba con tlsinfo/
// sslchain/tlsciphers/tlssimulation, que sí funcionan. Ruta dejada sin
// tocar (mismo patrón que /emailconfig, /httpsecurity, /dnssecurity),
// ahora inalcanzable desde la UI. Ver docs/arquitectura.md.
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
    sendJSON(res, 200, { domain, error: errorMessage(e), error_code: e && e.code });
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
  // Log de acceso mínimo — método, ruta, status, duración. Sin datos
  // personales (no se loguea body ni query string completa, solo la ruta).
  // Ver nota más arriba sobre por qué se agregó.
  const _reqStartedAt = Date.now();
  const _reqMethod = req.method;
  const _reqPath = req.url.split('?')[0];
  res._startedAt = _reqStartedAt;
  res.on('finish', () => {
    console.log(`${new Date().toISOString()} ${_reqMethod} ${_reqPath} ${res.statusCode} ${Date.now() - _reqStartedAt}ms`);
  });
  res.on('close', () => {
    if (!res.writableEnded) {
      console.error(`${new Date().toISOString()} ${_reqMethod} ${_reqPath} CONEXIÓN CERRADA SIN RESPUESTA (${Date.now() - _reqStartedAt}ms)`);
    }
  });

  const publicPath = path.join(__dirname, 'public');
  const requestPath = req.url.split('?')[0];
  let filePath = path.join(publicPath, requestPath);

  if (requestPath !== '/' && requestPath !== '/index.html' && fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
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

    const headers = { 'Content-Type': contentType };
    // Defensa adicional (2026-09-11): Cloudflare cachea .js en su borde
    // con max-age=14400 por defecto aunque el origen no mande ningún
    // Cache-Control — encontrado porque public/i18n.js quedó sirviendo
    // una versión vieja del diccionario de traducción durante horas tras
    // un despliegue (claves crudas como "med.heading" en pantalla en vez
    // del texto). El ?v= en el <script src> de index.html/admin.html es
    // la defensa principal (URL nueva = cache miss garantizado); esto es
    // un respaldo para cualquier otro .js que se agregue sin ese cuidado.
    if (ext === '.js') headers['Cache-Control'] = 'no-cache';
    res.writeHead(200, headers);
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

  // Log de mediciones: se etiqueta acá (antes del despacho real) porque
  // este es el único lugar donde ya tenemos, listos y correctos,
  // "cuál check" (segments[0]) y "qué dominio" (segments[1]) para
  // cualquiera de las ~50 rutas de abajo — sendJSON() los lee de acá.
  if (segments[1]) {
    res._checkName = segments[0];
    res._checkDomain = segments[1];
  }

  if (segments[0] === 'mx' && segments[1]) return handleMx(segments[1], res);
  if (segments[0] === 'spf' && segments[1]) return handleSpf(segments[1], res);
  if (segments[0] === 'dmarc' && segments[1]) return handleDmarc(segments[1], res);
  if (segments[0] === 'ipv4' && segments[1]) return handleIpv4(segments[1], res);
  if (segments[0] === 'ipv6' && segments[1]) return handleIpv6(segments[1], res);
  if (segments[0] === 'smtputf8' && segments[1]) return handleSmtpUtf8(segments[1], res);
  if (segments[0] === 'maildnssec' && segments[1]) return handleMailDnssec(segments[1], res);
  if (segments[0] === 'mailipv6' && segments[1]) return handleMailIpv6(segments[1], res);
  if (segments[0] === 'starttls' && segments[1]) return handleStarttls(segments[1], res);
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

  // Preparación de datasets de dominios — Fuente → Carga → Normalización
  if (parsed.pathname.startsWith('/dataset')) {
    return handleDatasetRequest(req, res, parsed);
  }

  // Contenido editorial público — Blog, Eventos, Material de capacitación
  if (parsed.pathname.startsWith('/content')) {
    return handleContentRequest(req, res, parsed);
  }

  // Administración — login y CRUD de contenido editorial
  if (parsed.pathname.startsWith('/admin')) {
    return handleAdminRequest(req, res, parsed);
  }

  // Análisis comparativo — sub-tab de Mediciones (reporte final + export PDF/JSON)
  if (parsed.pathname.startsWith('/mediciones-batch')) {
    return handleMedicionesBatchReportRequest(req, res, parsed);
  }

    sendJSON(res, 404, { error: 'Not found' });
});

const PORT = process.env.PORT || 8080;
// Guarda añadida (2026-09-15) para permitir que los tests hagan
// require('../server.js') sin abrir un puerto real — server.js sigue
// arrancando exactamente igual que antes vía `node server.js`/`npm start`
// (ahí require.main === module es siempre true). Puramente aditivo: nada
// cambia en producción/despliegue.
if (require.main === module) {
  server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

// Exports mínimos para tests (2026-09-15) — los 3 checks de correo de la
// fase 1 más rpki/routing de la fase 2 (esta última reutiliza rpkiValidity,
// no crea un check nuevo — ver IMPLEMENTACION_MEDICIONES_FASE2_ROUTING_RPKI.md),
// para poder probarlos con dns/net/https mockeados sin levantar el servidor
// completo. No cambia ningún comportamiento existente.
module.exports = {
  handleMailDnssec,
  handleMailIpv6,
  handleStarttls,
  MAX_MX_PROBED,
  handleRpki,
  rpkiValidity,
  ipToCymruQuery,
  resolveOriginRoutesViaCymru
};
