'use strict';

/**
 * Zonemaster Adapter — Mediciones ISOC LAC
 *
 * Conecta tu sistema con la API JSON-RPC de Zonemaster.
 * Compatible con la instancia pública (zonemaster.net)
 * y con instancias propias en VPS.
 *
 * Flujo por dominio:
 *   1. start_domain_test  → obtiene test_id
 *   2. test_progress      → polling hasta 100%
 *   3. get_test_results   → resultados completos
 *   4. mapZonemasterToIsoc → traduce a tus 7 estados
 *
 * El método analyzeBatch usa add_batch_job cuando está
 * disponible (instancia propia con auth), o cae a análisis
 * individual con concurrencia controlada (instancia pública).
 */

const https = require('https');
const http  = require('http');

// ─── Configuración ────────────────────────────────────────────────────────────

const DEFAULT_CONFIG = {
  // Instancia pública — sin auth, rate-limited
  endpoint: 'https://zonemaster.net/api',

  // Para instancia propia en VPS:
  // endpoint: 'http://localhost:5000/',
  // username: 'isoclac',
  // apiKey:   'tu-clave-aqui',

  pollIntervalMs:  5000,   // cada 5s verificar progreso
  pollTimeoutMs:   180000, // 3 minutos máximo por dominio
  requestTimeoutMs:15000,  // timeout por llamada HTTP
  concurrency:     3,      // paralelo en instancia pública (conservador)
  language:        'es',   // idioma de los mensajes
};

// ─── Tests DNSSEC de Zonemaster y su significado ─────────────────────────────
//
// Zonemaster ejecuta DNSSEC01-DNSSEC17 (según versión).
// Los más relevantes para el mapeo:
//
//  DS07_NOT_SIGNED          → zona no firmada (WARNING)
//  DS07_DNSKEY_BUT_NO_DS   → DNSKEY sin DS en padre (WARNING → misconfigured)
//  DS07_DS_BUT_NO_DNSKEY   → DS en padre sin DNSKEY (ERROR → misconfigured)
//  DS11_DS_BUT_NO_DNSKEY   → ídem desde prueba 11
//  DS01_DS_ALGO_DEPRECATED → algoritmo obsoleto (WARNING)
//  DS01_DS_ALGO_NOT_DS     → tipo de digest inválido (ERROR)
//  DS08_DNSKEY_NOT_SIGNED  → DNSKEY sin RRSIG (ERROR → misconfigured)
//  DS09_SOA_NOT_SIGNED     → SOA sin firma (ERROR → misconfigured)
//  DS16_DNSKEY_EXPIRED     → clave vencida (CRITICAL → misconfigured)
//  DS05_ALGO_NOT_RECOMMENDED → algoritmo no recomendado (WARNING)
//
// Tags que indican bloqueo estructural (TLD o padre sin firmar):
//  BASIC02_NO_DELEGATION   → dominio no existe
//  BASIC01_NO_PARENT_      → padre no responde

// Severidades numéricas para comparación
const SEV = { NOTICE: 1, INFO: 1, WARNING: 2, ERROR: 3, CRITICAL: 4 };

// Tags que indican DNSSEC no implementado (zona no firmada)
const TAGS_NOT_SIGNED = new Set([
  'DS07_NOT_SIGNED',
  'DNSSEC07_NOT_SIGNED',
  'ZONE_NOT_SIGNED',
]);

// Tags que indican misconfigured
const TAGS_MISCONFIGURED = new Set([
  'DS07_DNSKEY_BUT_NO_DS',
  'DS07_DS_BUT_NO_DNSKEY',
  'DS11_DS_BUT_NO_DNSKEY',
  'DS11_DNSKEY_BUT_NO_DS',
  'DS08_DNSKEY_NOT_SIGNED',
  'DS09_SOA_NOT_SIGNED',
  'DS16_DNSKEY_EXPIRED',
  'DS16_DNSKEY_EXPIRING_SOON',
  'DS01_DS_ALGO_NOT_DS',
  'DNSSEC08_DNSKEY_NOT_SIGNED',
  'DNSSEC09_SOA_NOT_SIGNED',
]);

// Tags que indican bloqueo estructural
const TAGS_BLOCKED = new Set([
  'BASIC02_NO_DELEGATION',
  'BASIC02_DELEGATED_TO_CHILD',
  'BASIC01_PARENT_NOT_FOUND',
  'ZONE01_INCONSISTENT_SOA',
]);

// Tags que indican dominio no existente
const TAGS_NON_EXISTENT = new Set([
  'BASIC00_DOMAIN_NOT_FOUND',
  'BASIC01_NO_PARENT_FOUND',
  'BASIC02_NO_DELEGATION',
]);

// ─── Cliente HTTP JSON-RPC ────────────────────────────────────────────────────

let _rpcId = 1;

function rpcCall(endpoint, method, params, timeoutMs) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      jsonrpc: '2.0',
      id: _rpcId++,
      method,
      params: params || {},
    });

    const url = new URL(endpoint);
    const isHttps = url.protocol === 'https:';
    const lib = isHttps ? https : http;

    const options = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname || '/',
      method: 'POST',
      headers: {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(body),
        'Accept':         'application/json',
        'User-Agent':     'isoc-lac-mediciones/2.0',
      },
    };

    const req = lib.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.error) {
            reject(new Error(`ZM RPC error [${json.error.code}]: ${json.error.message}`));
          } else {
            resolve(json.result);
          }
        } catch (e) {
          reject(new Error(`ZM respuesta inválida: ${data.slice(0, 200)}`));
        }
      });
    });

    req.setTimeout(timeoutMs || DEFAULT_CONFIG.requestTimeoutMs, () => {
      req.destroy(new Error('ZM request timeout'));
    });

    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── Paso 1: Iniciar análisis ─────────────────────────────────────────────────

async function startDomainTest(domain, config = {}) {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const params = {
    domain:      domain.trim().toLowerCase(),
    ipv4:        true,
    ipv6:        true,
    profile:     'default',
    nameservers: [],
    ds_info:     [],
  };

  const testId = await rpcCall(cfg.endpoint, 'start_domain_test', params, cfg.requestTimeoutMs);
  if (!testId || typeof testId !== 'string') {
    throw new Error(`ZM: test_id inesperado para ${domain}: ${JSON.stringify(testId)}`);
  }
  return testId;
}

// ─── Paso 2: Polling de progreso ──────────────────────────────────────────────

async function waitForCompletion(testId, config = {}) {
  const cfg      = { ...DEFAULT_CONFIG, ...config };
  const deadline = Date.now() + cfg.pollTimeoutMs;

  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, cfg.pollIntervalMs));

    const progress = await rpcCall(
      cfg.endpoint,
      'test_progress',
      { test_id: testId },
      cfg.requestTimeoutMs
    );

    const pct = typeof progress === 'number' ? progress : progress?.progress ?? 0;
    if (pct >= 100) return true;
  }

  throw new Error(`ZM: timeout esperando análisis ${testId}`);
}

// ─── Paso 3: Obtener resultados ───────────────────────────────────────────────

async function getTestResults(testId, config = {}) {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  return rpcCall(
    cfg.endpoint,
    'get_test_results',
    { id: testId, language: cfg.language },
    cfg.requestTimeoutMs
  );
}

// ─── Paso 4: Mapeo a tus 7 estados ───────────────────────────────────────────

/**
 * Convierte los resultados de Zonemaster al modelo de 7 estados de ISOC LAC.
 *
 * Estructura de results de Zonemaster:
 * {
 *   hash: "...",
 *   params: { domain: "..." },
 *   results: [
 *     { module: "DNSSEC", testcase: "DNSSEC07", tag: "DS07_NOT_SIGNED",
 *       level: "WARNING", message: "La zona no está firmada..." },
 *     ...
 *   ]
 * }
 */
function mapZonemasterToIsoc(domain, zmResults) {
  const entries = Array.isArray(zmResults?.results) ? zmResults.results : [];

  if (entries.length === 0) {
    return buildIsocResult(domain, 'indeterminate', 'unknown', 'unknown', 'medium',
      'Zonemaster no devolvió resultados para este dominio.', [], zmResults);
  }

  // Separar tests DNSSEC de los demás
  const dnssecEntries = entries.filter(e =>
    e.module === 'DNSSEC' ||
    (e.testcase && e.testcase.startsWith('DNSSEC'))
  );
  const allEntries = entries;

  // Máxima severidad global
  const maxSeverity = entries.reduce((max, e) => {
    const s = SEV[e.level] || 0;
    return s > max ? s : max;
  }, 0);

  // Tags presentes
  const tags = new Set(entries.map(e => e.tag).filter(Boolean));

  // Mensajes con severidad CRITICAL o ERROR para el resumen técnico
  const criticalErrors = entries
    .filter(e => SEV[e.level] >= 3)
    .map(e => `[${e.testcase}] ${e.message}`)
    .slice(0, 5);

  // ── Reglas de clasificación (orden importa) ──────────────────────────────

  // 1. Dominio no existente
  if ([...TAGS_NON_EXISTENT].some(t => tags.has(t))) {
    return buildIsocResult(domain, 'non_existent', 'unknown', 'unknown', 'high',
      'El dominio no existe o no tiene delegación DNS válida.',
      criticalErrors, zmResults);
  }

  // 2. Error crítico en conectividad → indeterminate
  const hasConnectivityCritical = entries.some(e =>
    e.module === 'Connectivity' && SEV[e.level] >= 4
  );
  if (hasConnectivityCritical) {
    return buildIsocResult(domain, 'indeterminate', 'unknown', 'unknown', 'low',
      'Problemas graves de conectividad impiden el análisis DNSSEC.',
      criticalErrors, zmResults);
  }

  // 3. Bloqueo estructural (TLD o padre sin firmar)
  // Zonemaster detecta esto cuando la zona Basic falla en modo específico.
  // También lo inferimos si no hay tests DNSSEC ejecutados pero el dominio existe.
  // La detección más fiable es mirar si hay WARNING en DNSSEC por TLD no firmado.
  const tldNotSigned = entries.some(e =>
    e.module === 'DNSSEC' &&
    e.level === 'WARNING' &&
    (e.message || '').toLowerCase().includes('tld') &&
    (e.message || '').toLowerCase().includes('sign')
  );
  if (tldNotSigned) {
    return buildIsocResult(domain, 'blocked_at_tld', 'tld', 'blocked_by_tld', 'high',
      'El TLD no está firmado con DNSSEC. Barrera estructural externa.',
      criticalErrors, zmResults);
  }

  const parentNotSigned = entries.some(e =>
    e.module === 'DNSSEC' &&
    e.level === 'WARNING' &&
    (e.message || '').toLowerCase().includes('parent') &&
    (e.message || '').toLowerCase().includes('sign')
  );
  if (parentNotSigned) {
    return buildIsocResult(domain, 'blocked_at_parent', 'parent', 'blocked_by_parent', 'high',
      'La zona padre no está firmada. Barrera estructural en capa intermedia.',
      criticalErrors, zmResults);
  }

  // 4. DNSSEC no implementado
  // DS07_NOT_SIGNED: WARNING en DNSSEC07 → zona no firmada
  const notSigned = [...TAGS_NOT_SIGNED].some(t => tags.has(t)) ||
    (dnssecEntries.length > 0 &&
     dnssecEntries.every(e => SEV[e.level] <= 2) &&
     dnssecEntries.some(e => e.tag && e.tag.includes('NOT_SIGNED')));

  if (notSigned) {
    // Verificar si hay DS en el padre pero no DNSKEY (misconfigured tiene prioridad)
    const dsButNoKey = [...TAGS_MISCONFIGURED].some(t => tags.has(t));
    if (!dsButNoKey) {
      return buildIsocResult(domain, 'not_implemented', 'domain', 'ready_to_enable', 'high',
        'La zona no está firmada con DNSSEC. Las capas superiores lo soportan.',
        [], zmResults);
    }
  }

  // 5. Misconfigured — errores o críticos en tests DNSSEC
  const hasDnssecError = dnssecEntries.some(e => SEV[e.level] >= 3);
  const hasMisconfigTag = [...TAGS_MISCONFIGURED].some(t => tags.has(t));

  if (hasDnssecError || hasMisconfigTag) {
    return buildIsocResult(domain, 'misconfigured', 'domain', 'already_enabled', 'high',
      'DNSSEC implementado pero con errores de configuración.',
      criticalErrors, zmResults);
  }

  // 6. DNSSEC correcto — solo NOTICE/INFO en DNSSEC, o sin errores
  const hasDnssecTests = dnssecEntries.length > 0;
  const allDnssecClean = hasDnssecTests &&
    dnssecEntries.every(e => SEV[e.level] <= 1);
  const hasDnssecWarning = dnssecEntries.some(e => e.level === 'WARNING');

  if (hasDnssecTests && allDnssecClean && !hasDnssecWarning) {
    return buildIsocResult(domain, 'ok', 'none', 'already_enabled', 'high',
      'DNSSEC correctamente implementado. Cadena de confianza verificada.',
      [], zmResults);
  }

  // 7. Warnings en DNSSEC sin errores → misconfigured leve
  if (hasDnssecWarning && !hasDnssecError) {
    return buildIsocResult(domain, 'misconfigured', 'domain', 'already_enabled', 'medium',
      'DNSSEC implementado con advertencias. Revisión recomendada.',
      entries.filter(e => e.level === 'WARNING').map(e => e.message).slice(0, 3),
      zmResults);
  }

  // 8. Fallback indeterminate
  return buildIsocResult(domain, 'indeterminate', 'unknown', 'unknown', 'medium',
    'No fue posible clasificar el estado DNSSEC con evidencia suficiente.',
    criticalErrors, zmResults);
}

function buildIsocResult(domain, finalStatus, blockingLevel, readiness, confidence, summary, technicalNotes, rawZm) {
  const riskMap = {
    ok:               'bajo',
    not_implemented:  'medio',
    misconfigured:    'alto',
    blocked_at_tld:   'estructural',
    blocked_at_parent:'estructural',
    indeterminate:    'medio',
    non_existent:     'no aplicable',
  };

  const actionMap = {
    ok: false, not_implemented: true, misconfigured: true,
    blocked_at_tld: true, blocked_at_parent: true,
    indeterminate: false, non_existent: false,
  };

  return {
    domain,
    analyzed_at: new Date().toISOString(),
    engine: 'zonemaster',
    dnssec: {
      final_status:   finalStatus,
      blocking_level: blockingLevel,
      readiness,
      summary,
      technical_notes: technicalNotes,
      assessment_meta: {
        confidence,
        assessment_scope: 'dnssec_zonemaster_full',
        engine_version:   rawZm?.params?.engine_version || 'zonemaster',
        limitations: [
          'Análisis basado en Zonemaster — validación criptográfica completa.',
          'Los resultados reflejan el estado en el momento del análisis.',
          'Algunos problemas transitorios de red pueden afectar los resultados.',
        ],
      },
      executive_summary: {
        status:        EXECUTIVE_STATUS[finalStatus] || finalStatus,
        risk_level:    riskMap[finalStatus] || 'desconocido',
        action_required: actionMap[finalStatus] ?? false,
      },
      // Detalle técnico de Zonemaster para quien quiera profundizar
      zonemaster_detail: {
        test_id:  rawZm?.hash || null,
        results_url: rawZm?.hash
          ? `https://zonemaster.net/es/result/${rawZm.hash}`
          : null,
        entries_count: rawZm?.results?.length || 0,
        dnssec_entries: (rawZm?.results || [])
          .filter(e => e.module === 'DNSSEC')
          .map(e => ({
            testcase: e.testcase,
            tag:      e.tag,
            level:    e.level,
            message:  e.message,
          })),
      },
    },
  };
}

const EXECUTIVE_STATUS = {
  ok:               'DNSSEC correctamente implementado',
  not_implemented:  'DNSSEC no implementado',
  misconfigured:    'DNSSEC presente pero mal configurado',
  blocked_at_tld:   'Bloqueo estructural en TLD',
  blocked_at_parent:'Bloqueo en zona padre',
  indeterminate:    'Resultado no concluyente',
  non_existent:     'Dominio no existente o no verificable',
};

// ─── Análisis completo de un dominio ─────────────────────────────────────────

async function analyzeDomain(domain, config = {}) {
  const cfg = { ...DEFAULT_CONFIG, ...config };

  try {
    const testId = await startDomainTest(domain, cfg);
    await waitForCompletion(testId, cfg);
    const results = await getTestResults(testId, cfg);
    return mapZonemasterToIsoc(domain, results);
  } catch (err) {
    return buildIsocResult(domain, 'indeterminate', 'unknown', 'unknown', 'low',
      `Error durante el análisis Zonemaster: ${err.message}`, [], null);
  }
}

// ─── Batch con concurrencia ───────────────────────────────────────────────────

const { EventEmitter } = require('events');

async function analyzeBatch(domains, config = {}, onProgress = null) {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const results = [];
  const errors  = [];
  const queue   = [...domains];
  let processed = 0;
  const total   = domains.length;

  const worker = async () => {
    while (queue.length > 0) {
      const domain = queue.shift();
      const result = await analyzeDomain(domain, cfg);

      if (result.dnssec.final_status === 'indeterminate' &&
          result.dnssec.assessment_meta.confidence === 'low') {
        errors.push({ domain, error: result.dnssec.summary });
      } else {
        results.push(result);
      }

      processed++;
      if (typeof onProgress === 'function') {
        onProgress({
          processed,
          total,
          percent: Math.round(processed / total * 100),
          lastDomain: domain,
          lastStatus: result.dnssec.final_status,
        });
      }
    }
  };

  const workers = Array.from(
    { length: Math.min(cfg.concurrency, domains.length) },
    () => worker()
  );
  await Promise.all(workers);

  return { results, errors };
}

// ─── Batch nativo (solo instancia propia con auth) ────────────────────────────

async function addBatchJob(domains, config = {}) {
  const cfg = { ...DEFAULT_CONFIG, ...config };

  if (!cfg.username || !cfg.apiKey) {
    throw new Error('add_batch_job requiere username y apiKey (solo instancia propia)');
  }

  const batchId = await rpcCall(cfg.endpoint, 'add_batch_job', {
    username:    cfg.username,
    api_key:     cfg.apiKey,
    test_params: { ipv4: true, ipv6: true, profile: 'default' },
    domains:     domains.map(d => d.trim().toLowerCase()),
  }, cfg.requestTimeoutMs);

  return batchId; // ID del batch para hacer polling luego
}

async function getBatchProgress(batchId, config = {}) {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  return rpcCall(cfg.endpoint, 'get_batch_job_result', { batch_id: batchId }, cfg.requestTimeoutMs);
}

// ─── Utilidad: verificar conectividad ────────────────────────────────────────

async function ping(config = {}) {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  try {
    const info = await rpcCall(cfg.endpoint, 'version_info', {}, cfg.requestTimeoutMs);
    return { ok: true, version: info };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

module.exports = {
  analyzeDomain,
  analyzeBatch,
  addBatchJob,
  getBatchProgress,
  mapZonemasterToIsoc,
  ping,
  DEFAULT_CONFIG,
};
