const https = require("https");

const QUERY_TIMEOUT_MS = 5000;

// (2026-09-13) — corrección mínima: retry único + caché/coalescing por
// consulta, sin tocar timeout ni clasificación DNSSEC.
//
// Qué estados representan transporte fallido vs. respuesta DNS válida
// (confirmado leyendo el código, no supuesto): fetchJson() SOLO rechaza su
// promesa ante timeout, error de red o un cuerpo no parseable como JSON —
// una respuesta DNS real (NOERROR/NODATA, NXDOMAIN, SERVFAIL) SIEMPRE
// llega como HTTP 200 con un `Status` distinto dentro del cuerpo JSON
// (0/2/3), nunca como excepción — normalizeAnswer() la interpreta después.
// Por construcción, entonces, CUALQUIER excepción atrapada acá es un
// fallo de transporte y nunca una respuesta DNS — no hace falta filtrar
// por código de error para decidir si reintentar: alcanza con "hubo
// excepción". SERVFAIL/NXDOMAIN/ausencia de DS/DNSKEY nunca pasan por
// este `catch`, así que nunca disparan un reintento.
const DOH_CACHE_TTL_MS = 5 * 60 * 1000; // ventana razonable para una corrida — no es necesaria persistencia entre procesos
const RETRY_BACKOFF_MS = 200; // corto y acotado, un solo reintento — no duplica descontroladamente el tiempo total (peor caso por consulta: ~2x el timeout, acotado)

const dohCache = new Map(); // key `${name}|${type}` -> { timestamp, value: respuesta DoH cruda }
const dohPending = new Map(); // key -> Promise en curso

const dohStats = {
  totalCalls: 0,
  uniqueQueries: 0,
  cacheHits: 0,
  pendingReused: 0,
  retries: 0,
  retriesRecovered: 0,
  retriesFailed: 0
};

function getDohStats() {
  return { ...dohStats };
}

function resetDohStats() {
  Object.keys(dohStats).forEach((k) => {
    dohStats[k] = 0;
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function cacheGet(cache, key, ttlMs) {
  const item = cache.get(key);
  if (!item) return null;
  if (Date.now() - item.timestamp > ttlMs) {
    cache.delete(key);
    return null;
  }
  return item.value;
}

function cacheSet(cache, key, value) {
  cache.set(key, { timestamp: Date.now(), value });
}

function fetchJson(url, timeoutMs = QUERY_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const req = https.get(
      url,
      {
        headers: {
          Accept: "application/dns-json",
          "User-Agent": "isoc-lac-dnssec-checker"
        }
      },
      (res) => {
        let data = "";

        res.on("data", (chunk) => {
          data += chunk;
        });

        res.on("end", () => {
          try {
            const json = JSON.parse(data);
            resolve(json);
          } catch (error) {
            error.code = "INVALID_JSON";
            reject(error);
          }
        });
      }
    );

    req.on("error", (error) => {
      reject(error);
    });

    req.setTimeout(timeoutMs, () => {
      const error = new Error("DNS query timeout");
      error.code = "TIMEOUT";
      req.destroy(error);
    });
  });
}

function mapDohError(error, fallbackCode) {
  const code = error?.code || fallbackCode || "DOH_QUERY_ERROR";

  if (code === "ENOTFOUND" || code === "ECONNRESET" || code === "EAI_AGAIN") {
    return {
      found: null,
      records: [],
      query_status: "network_error",
      error_code: code
    };
  }

  if (code === "TIMEOUT" || error?.message === "DNS query timeout") {
    return {
      found: null,
      records: [],
      query_status: "timeout",
      error_code: "TIMEOUT"
    };
  }

  if (code === "INVALID_JSON") {
    return {
      found: null,
      records: [],
      query_status: "invalid_response",
      error_code: code
    };
  }

  return {
    found: null,
    records: [],
    query_status: "error",
    error_code: code
  };
}

async function fetchJsonWithRetry(url) {
  try {
    return await fetchJson(url);
  } catch (firstError) {
    dohStats.retries++;
    await sleep(RETRY_BACKOFF_MS);
    try {
      const result = await fetchJson(url);
      dohStats.retriesRecovered++;
      return result;
    } catch (secondError) {
      dohStats.retriesFailed++;
      throw secondError;
    }
  }
}

// (2026-09-13) — caché + request coalescing por consulta real (nombre +
// tipo de registro), mismo patrón ya validado en fetchWebsite()/
// lookupIpMeta(): la promesa se guarda ANTES de esperar la consulta, para
// que llamadas concurrentes por la misma clave la reutilicen en vez de
// disparar una consulta nueva; el resultado resuelto se cachea con TTL
// solo si la consulta tuvo éxito (un fallo, incluso tras el reintento,
// nunca queda cacheado — la siguiente llamada reintenta limpio). Evita
// que dominios que comparten TLD/zona intermedia repitan la misma
// consulta DNSKEY/DS.
async function queryGoogleDoh(name, type) {
  dohStats.totalCalls++;
  const key = `${name}|${type}`;

  const cached = cacheGet(dohCache, key, DOH_CACHE_TTL_MS);
  if (cached) {
    dohStats.cacheHits++;
    return cached;
  }
  if (dohPending.has(key)) {
    dohStats.pendingReused++;
    return dohPending.get(key);
  }

  dohStats.uniqueQueries++;
  const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  const promise = (async () => {
    const response = await fetchJsonWithRetry(url);
    cacheSet(dohCache, key, response);
    return response;
  })();

  dohPending.set(key, promise);
  try {
    return await promise;
  } finally {
    dohPending.delete(key);
  }
}

function normalizeAnswer(response) {
  if (!response || typeof response !== "object") {
    return {
      found: null,
      records: [],
      query_status: "invalid_response",
      error_code: "INVALID_RESPONSE"
    };
  }

  if (response.Status === 0) {
    const answers = Array.isArray(response.Answer) ? response.Answer : [];
    return {
      found: answers.length > 0,
      records: answers,
      query_status: answers.length > 0 ? "ok" : "no_data",
      error_code: null
    };
  }

  if (response.Status === 3) {
    return {
      found: false,
      records: [],
      query_status: "nxdomain",
      error_code: "NXDOMAIN"
    };
  }

  if (response.Status === 2) {
    return {
      found: null,
      records: [],
      query_status: "servfail",
      error_code: "SERVFAIL"
    };
  }

  return {
    found: null,
    records: [],
    query_status: "error",
    error_code: `DNS_STATUS_${response.Status}`
  };
}

async function queryDnskey(zone) {
  try {
    const response = await queryGoogleDoh(zone, "DNSKEY");
    return normalizeAnswer(response);
  } catch (error) {
    return mapDohError(error, "DNSKEY_QUERY_ERROR");
  }
}

async function queryDs(childZone) {
  try {
    const response = await queryGoogleDoh(childZone, "DS");
    return normalizeAnswer(response);
  } catch (error) {
    return mapDohError(error, "DS_QUERY_ERROR");
  }
}

async function queryNameExistence(name) {
  const recordTypes = ["A", "AAAA", "CNAME"];

  try {
    const results = await Promise.all(
      recordTypes.map(async (type) => {
        try {
          const response = await queryGoogleDoh(name, type);
          const normalized = normalizeAnswer(response);
          return { type, ...normalized };
        } catch (error) {
          return { type, ...mapDohError(error, "NAME_EXISTENCE_QUERY_ERROR") };
        }
      })
    );

    const anyFound = results.some((r) => r.found === true);
    const allNx = results.every((r) => r.query_status === "nxdomain");
    const anyError = results.some((r) =>
      ["timeout", "servfail", "error", "network_error", "invalid_response"].includes(r.query_status)
    );

    if (anyFound) {
      return {
        exists: true,
        query_status: "ok",
        records: results
      };
    }

    if (allNx) {
      return {
        exists: false,
        query_status: "nxdomain",
        records: results
      };
    }

    if (anyError) {
      return {
        exists: null,
        query_status: "error",
        records: results
      };
    }

    return {
      exists: false,
      query_status: "no_data",
      records: results
    };
  } catch (error) {
    return {
      exists: null,
      query_status: "error",
      records: [],
      error_code: error?.code || "NAME_EXISTENCE_QUERY_ERROR"
    };
  }
}

module.exports = {
  queryDnskey,
  queryDs,
  queryNameExistence,
  QUERY_TIMEOUT_MS,
  getDohStats,
  resetDohStats
};