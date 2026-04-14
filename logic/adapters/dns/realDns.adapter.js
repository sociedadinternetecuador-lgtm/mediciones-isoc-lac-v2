const https = require("https");

const QUERY_TIMEOUT_MS = 5000;

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

async function queryGoogleDoh(name, type) {
  const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  return fetchJson(url);
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
  QUERY_TIMEOUT_MS
};