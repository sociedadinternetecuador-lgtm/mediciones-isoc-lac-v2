'use strict';

/**
 * Construye el paquete de archivos descargables de "Resultados y descarga"
 * a partir de datos YA CALCULADOS por Normalización y Validación DNS —
 * ninguna función de este módulo ejecuta consultas DNS ni reclasifica
 * VALID/NXDOMAIN/REVIEW. Solo formatea/agrupa lo que ya existe en memoria,
 * siguiendo la misma nomenclatura y semántica que
 * validador/validar_dominios_isoc_lac.py (generate_outputs / write_master_csv
 * / write_discrepancies / make_suffix_summary).
 */

const crypto = require('crypto');
const { getPublicSuffixList } = require('../adapters/publicSuffixList.adapter');

function sha256(content) {
  return crypto.createHash('sha256').update(content, 'utf-8').digest('hex');
}

function csvEscape(value) {
  const s = value === null || value === undefined ? '' : String(value);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

function csvRow(values) {
  return values.map(csvEscape).join(',');
}

function linesFile(domains) {
  const sorted = [...domains].sort();
  return sorted.join('\n') + (sorted.length ? '\n' : '');
}

const MASTER_CSV_COLUMNS = [
  'domain', 'suffix', 'first_pass_status', 'final_status', 'status_reason',
  'review_subtype', 'retry_performed', 'discrepancy',
  'cloudflare_ns', 'google_ns', 'cloudflare_soa', 'google_soa',
  'cloudflare_ns_error', 'google_ns_error', 'cloudflare_soa_error', 'google_soa_error',
  'cloudflare_ns_attempts', 'google_ns_attempts', 'cloudflare_soa_attempts', 'google_soa_attempts',
  'first_pass_observations', 'final_observations',
];

function buildMasterCsv(rows) {
  const lines = [csvRow(MASTER_CSV_COLUMNS)];
  for (const r of rows) {
    lines.push(csvRow([
      r.domain, r.suffix, r.first_pass_status, r.final_status, r.status_reason,
      r.review_subtype, r.retry_performed ? 'YES' : 'NO', r.discrepancy ? 'YES' : 'NO',
      r.cloudflare_ns, r.google_ns, r.cloudflare_soa, r.google_soa,
      r.cloudflare_ns_error, r.google_ns_error, r.cloudflare_soa_error, r.google_soa_error,
      r.cloudflare_ns_attempts, r.google_ns_attempts, r.cloudflare_soa_attempts, r.google_soa_attempts,
      r.first_pass_observations, r.final_observations,
    ]));
  }
  return lines.join('\n') + '\n';
}

function buildDiscrepanciesCsv(rows) {
  const cols = ['domain', 'suffix', 'final_status', 'review_subtype', 'cloudflare_ns', 'google_ns', 'cloudflare_soa', 'google_soa', 'dns_observations'];
  const discrepant = rows.filter((r) => r.discrepancy).sort((a, b) => a.domain.localeCompare(b.domain));
  const lines = [csvRow(cols)];
  for (const r of discrepant) {
    lines.push(csvRow([r.domain, r.suffix, r.final_status, r.review_subtype, r.cloudflare_ns, r.google_ns, r.cloudflare_soa, r.google_soa, r.final_observations]));
  }
  return { csv: lines.join('\n') + '\n', count: discrepant.length };
}

function buildSuffixSummaryCsv(rows) {
  const bySuffix = new Map();
  for (const r of rows) {
    if (!bySuffix.has(r.suffix)) bySuffix.set(r.suffix, { total: 0, VALID: 0, NXDOMAIN: 0, REVIEW: 0 });
    const entry = bySuffix.get(r.suffix);
    entry.total += 1;
    entry[r.final_status] += 1;
  }

  const summaryRows = Array.from(bySuffix.entries())
    .map(([suffix, counts]) => {
      const pct = (n) => (counts.total ? Math.round((n / counts.total) * 10000) / 100 : 0);
      return {
        suffix, total: counts.total, valid: counts.VALID, nxdomain: counts.NXDOMAIN, review: counts.REVIEW,
        valid_pct: pct(counts.VALID), nxdomain_pct: pct(counts.NXDOMAIN), review_pct: pct(counts.REVIEW),
      };
    })
    .sort((a, b) => b.total - a.total || a.suffix.localeCompare(b.suffix));

  const cols = ['suffix', 'total', 'valid', 'nxdomain', 'review', 'valid_pct', 'nxdomain_pct', 'review_pct'];
  const lines = [csvRow(cols)];
  for (const row of summaryRows) {
    lines.push(csvRow([row.suffix, row.total, row.valid, row.nxdomain, row.review, row.valid_pct, row.nxdomain_pct, row.review_pct]));
  }
  return { csv: lines.join('\n') + '\n', rows: summaryRows };
}

function buildRejectedCsv(rejected) {
  const lines = [csvRow(['input_value', 'reason']), ...rejected.map((r) => csvRow(r))];
  return lines.join('\n') + '\n';
}

function buildReviewPorTipo(rows) {
  const groups = new Map();
  for (const r of rows) {
    if (!r.review_subtype) continue;
    if (!groups.has(r.review_subtype)) groups.set(r.review_subtype, []);
    groups.get(r.review_subtype).push(r.domain);
  }
  const files = {};
  for (const [subtype, domains] of groups.entries()) {
    files[`review_por_tipo/${subtype.toLowerCase()}.txt`] = linesFile(domains);
  }
  return files;
}

function buildListasPorSufijo(rows) {
  const groups = new Map();
  for (const r of rows) {
    if (r.final_status !== 'VALID') continue;
    if (!groups.has(r.suffix)) groups.set(r.suffix, []);
    groups.get(r.suffix).push(r.domain);
  }
  const files = {};
  for (const [suffix, domains] of groups.entries()) {
    const fname = suffix.replace(/^\./, '').replace(/\./g, '_') + '.txt';
    files[`listas_por_sufijo/${fname}`] = linesFile(domains);
  }
  return files;
}

async function buildResultsPackage({
  jobId, context, perDomain, finalStatusCounts, reviewSubtypeCounts, discrepancyCount, dnsParams, preflight, reviewRetry,
}) {
  const normalize = context?.normalize || {};
  const normalizedList = Array.isArray(normalize.normalized) ? normalize.normalized : perDomain.map((r) => r.domain);

  // Clasificación por sufijo — reutiliza el mismo adaptador PSL ya cargado
  // (sección ICANN); no repite ninguna consulta DNS ni cambia el criterio
  // de normalización, solo etiqueta cada dominio con su sufijo para poder
  // agrupar/exportar (resumen_sufijos.csv, listas_por_sufijo/).
  const { psl } = await getPublicSuffixList();
  const rows = perDomain.map((r) => ({ ...r, suffix: '.' + psl.publicSuffix(r.domain) }));

  // ── Control de integridad (obligatorio antes de permitir el paquete) ──
  // Nota: los checks de longitud/suma por sí solos no detectan una
  // partición inconsistente donde un dominio duplicado numéricamente
  // "reemplaza" a uno faltante (los conteos cuadran mientras el conjunto
  // real de dominios no es el universo normalizado) — de ahí los dos
  // checks basados en conjuntos (no_duplicate_domains /
  // domain_set_matches_normalized).
  const sumStatuses = finalStatusCounts.VALID + finalStatusCounts.NXDOMAIN + finalStatusCounts.REVIEW;
  const normalizedCount = normalizedList.length;
  const normalizedSet = new Set(normalizedList);
  const rowDomainSet = new Set(rows.map((r) => r.domain));
  const noDuplicateDomains = rowDomainSet.size === rows.length;
  const domainSetMatchesNormalized = normalizedSet.size === rowDomainSet.size
    && [...normalizedSet].every((d) => rowDomainSet.has(d));

  const integrity = {
    normalized_count: normalizedCount,
    status_sum: sumStatuses,
    csv_rows: rows.length,
    checks: {
      status_sum_equals_normalized: sumStatuses === normalizedCount,
      csv_rows_equals_normalized: rows.length === normalizedCount,
      all_domains_have_result: rows.length === perDomain.length,
      no_duplicate_domains: noDuplicateDomains,
      domain_set_matches_normalized: domainSetMatchesNormalized,
    },
  };
  integrity.passed = Object.values(integrity.checks).every(Boolean);

  const files = {}; // path -> string content
  files['dominios_normalizados.txt'] = linesFile(normalizedList);
  files['dominios_validos.txt'] = linesFile(rows.filter((r) => r.final_status === 'VALID').map((r) => r.domain));
  files['dominios_nxdomain.txt'] = linesFile(rows.filter((r) => r.final_status === 'NXDOMAIN').map((r) => r.domain));
  files['dominios_revisar.txt'] = linesFile(rows.filter((r) => r.final_status === 'REVIEW').map((r) => r.domain));

  const rejected = Array.isArray(normalize.rejected) ? normalize.rejected : [];
  if (rejected.length) {
    files['rechazados_estructura.csv'] = buildRejectedCsv(rejected);
  }

  files['validacion_dns.csv'] = buildMasterCsv(rows);

  const { csv: discrepanciesCsv } = buildDiscrepanciesCsv(rows);
  files['discrepancias_resolvers.csv'] = discrepanciesCsv;

  const { csv: suffixSummaryCsv, rows: suffixSummaryRows } = buildSuffixSummaryCsv(rows);
  files['resumen_sufijos.csv'] = suffixSummaryCsv;

  Object.assign(files, buildReviewPorTipo(rows));
  Object.assign(files, buildListasPorSufijo(rows));

  const now = new Date().toISOString();
  const metadata = {
    project: 'Mediciones LAC - Internet Society',
    platform: 'portal web (JS) — validador_dominios_isoc_lac.py como referencia metodológica',
    execution_id: jobId || null,
    generated_at: now,
    source: {
      filename: context?.source?.name || null,
      size_bytes: context?.source?.size ?? null,
      sha256: context?.source?.sha256 || null,
      source_date: context?.source?.date || null,
    },
    cctld: '.' + (context?.tld || ''),
    normalization: {
      raw_lines: normalize?.stats?.raw_lines ?? null,
      empty: normalize?.stats?.empty ?? null,
      duplicates: normalize?.stats?.duplicates ?? null,
      rejected: normalize?.stats?.rejected ?? null,
      normalized: normalize?.stats?.normalized ?? null,
      normalized_sha256: normalize?.normalizedSha256 || null,
    },
    public_suffix_list: {
      mode: 'ICANN section only',
      origin: normalize?.psl?.origin || null,
      sha256: normalize?.psl?.sha256 || null,
      fetched_at: normalize?.psl?.fetchedAt || null,
      source_url: normalize?.psl?.sourceUrl || null,
    },
    dns_validation: {
      resolvers: dnsParams.resolvers,
      timeout_seconds: dnsParams.timeout_seconds,
      retries: dnsParams.retries,
      workers: dnsParams.workers,
      review_wait_seconds: dnsParams.review_wait_seconds,
      checking_disabled: dnsParams.checking_disabled,
      preflight_ok: dnsParams.preflight_ok,
      preflight,
      started_at: dnsParams.started_at,
      completed_at: dnsParams.completed_at,
      duration_ms: dnsParams.duration_ms,
    },
    results: {
      total_validated: rows.length,
      final_status: finalStatusCounts,
      review_subtypes: reviewSubtypeCounts,
      discrepancies: discrepancyCount,
      review_retry_diagnostic: {
        note: 'Diagnóstico de la corrida — no comparar entre ejecuciones (condiciones de red transitorias).',
        ...reviewRetry,
      },
    },
    integrity,
    suffix_summary: suffixSummaryRows,
    files_sha256: {}, // se completa abajo, tras conocer el contenido final de cada archivo
  };

  const fileHashes = {};
  for (const [path, content] of Object.entries(files)) {
    fileHashes[path] = sha256(content);
  }
  metadata.files_sha256 = fileHashes;

  const metadataJson = JSON.stringify(metadata, null, 2);
  files['metadata.json'] = metadataJson;
  fileHashes['metadata.json'] = sha256(metadataJson);

  return {
    files,
    fileHashes,
    metadata,
    integrity,
    rows,
  };
}

module.exports = { buildResultsPackage };
