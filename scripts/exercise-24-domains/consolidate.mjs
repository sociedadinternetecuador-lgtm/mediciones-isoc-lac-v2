'use strict';

/**
 * Consolida las dos corridas reales (A: 20 LAC, B: 4 EE.UU. referencia) en
 * un único dataset de 24 dominios, valida 24x54=1296, y genera un resumen
 * compacto (mismo esquema que data/baseline/mediciones_resumen_20dominios_2026-09-13.json)
 * para alimentar el artículo/reporte. No reinterpreta estados: cada campo
 * del resumen es una copia literal del status que MEDICIONES ya asignó.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DIR = path.resolve(__dirname, '../../data/exercises/2026-09-14_24dominios_6paises');

const META = {
  'mercadolibre.com.ar': { country: 'Argentina', sector: 'Privado/comercial' },
  'uba.ar':               { country: 'Argentina', sector: 'Academia' },
  'argentina.gob.ar':     { country: 'Argentina', sector: 'Gobierno' },
  'nic.ar':               { country: 'Argentina', sector: 'Infraestructura/NIC' },
  'tiendainglesa.com.uy': { country: 'Uruguay', sector: 'Privado/comercial' },
  'udelar.edu.uy':        { country: 'Uruguay', sector: 'Academia' },
  'gub.uy':               { country: 'Uruguay', sector: 'Gobierno' },
  'nic.uy':               { country: 'Uruguay', sector: 'Infraestructura/NIC' },
  'copaair.com':          { country: 'Panamá', sector: 'Privado/comercial' },
  'utp.ac.pa':            { country: 'Panamá', sector: 'Academia' },
  'presidencia.gob.pa':   { country: 'Panamá', sector: 'Gobierno' },
  'nic.pa':               { country: 'Panamá', sector: 'Infraestructura/NIC' },
  'corporacionfavorita.com': { country: 'Ecuador', sector: 'Privado/comercial' },
  'epn.edu.ec':           { country: 'Ecuador', sector: 'Academia' },
  'gob.ec':               { country: 'Ecuador', sector: 'Gobierno' },
  'nic.ec':               { country: 'Ecuador', sector: 'Infraestructura/NIC' },
  'bancontinental.com.py':{ country: 'Paraguay', sector: 'Privado/comercial' },
  'una.py':               { country: 'Paraguay', sector: 'Academia' },
  'paraguay.gov.py':      { country: 'Paraguay', sector: 'Gobierno' },
  'nic.py':               { country: 'Paraguay', sector: 'Infraestructura/NIC' },
  'amazon.com':           { country: 'Estados Unidos (referencia/control)', sector: 'Privado/comercial' },
  'mit.edu':              { country: 'Estados Unidos (referencia/control)', sector: 'Academia' },
  'usa.gov':              { country: 'Estados Unidos (referencia/control)', sector: 'Gobierno' },
  'nic.us':               { country: 'Estados Unidos (referencia/control)', sector: 'Infraestructura/NIC' },
};
const EXPECTED_DOMAINS = Object.keys(META);
const EXPECTED_CHECK_COUNT = 54;

function load(file) { return JSON.parse(fs.readFileSync(path.join(DIR, file), 'utf8')); }

const a = load('report-A-lac20.json');
const b = load('report-B-usref4.json');
const allDomains = [...a.domains, ...b.domains];

// ─── Validación 24 x 54 = 1296 ───
const errors = [];
if (allDomains.length !== 24) errors.push(`Se esperaban 24 dominios, se encontraron ${allDomains.length}`);
const seen = new Set();
for (const d of allDomains) {
  const key = d.domain.toLowerCase();
  if (seen.has(key)) errors.push(`Dominio duplicado entre corridas: ${d.domain}`);
  seen.add(key);
  if (!EXPECTED_DOMAINS.map(x=>x.toLowerCase()).includes(key)) errors.push(`Dominio inesperado (no estaba en la muestra definida): ${d.domain}`);
  const checkCount = Object.keys(d.checks || {}).length;
  if (checkCount !== EXPECTED_CHECK_COUNT) errors.push(`${d.domain}: ${checkCount} checks (se esperaban ${EXPECTED_CHECK_COUNT})`);
}
for (const dom of EXPECTED_DOMAINS) {
  if (!seen.has(dom.toLowerCase())) errors.push(`Dominio de la muestra ausente en los resultados: ${dom}`);
}
const totalChecks = allDomains.reduce((sum, d) => sum + Object.keys(d.checks || {}).length, 0);
if (totalChecks !== 24 * 54) errors.push(`Total de resultados = ${totalChecks}, se esperaban 1296`);

if (errors.length) {
  console.error('VALIDACIÓN FALLIDA:');
  errors.forEach(e => console.error(' - ' + e));
  process.exit(1);
}
console.log(`Validación OK: ${allDomains.length} dominios únicos x 54 checks = ${totalChecks} resultados.`);

// ─── Distribución global de estados (verbatim, sin reinterpretar) ───
const STATUS_KEYS = ['PASS','FAIL','INFO','INCONCLUSIVE','NOT_APPLICABLE','MEASUREMENT_ERROR'];
const statusCounts = Object.fromEntries(STATUS_KEYS.map(s => [s, 0]));
const unexpectedStatuses = new Set();
for (const d of allDomains) {
  for (const check of Object.values(d.checks)) {
    const s = check?.status;
    if (statusCounts[s] !== undefined) statusCounts[s]++;
    else unexpectedStatuses.add(s);
  }
}

// ─── Distribución DNSSEC estructural (verbatim, 7 estados posibles) ───
const dnssecCounts = {};
for (const d of allDomains) {
  const s = d?.dnssec?.dnssec?.final_status || '(sin dato)';
  dnssecCounts[s] = (dnssecCounts[s] || 0) + 1;
}

// ─── Consolidado completo (24 x 54, con país/sector adjuntado) ───
const consolidated = {
  meta: {
    generated_at: new Date().toISOString(),
    exercise: 'Ejercicio comparativo de 24 dominios (6 países x 4 dominios) — actualización del ejercicio de 20 dominios (2026-09-13), incorpora Paraguay',
    countries: ['Argentina', 'Uruguay', 'Panamá', 'Ecuador', 'Paraguay'],
    reference_country: 'Estados Unidos (referencia/control, no forma parte de LAC)',
    domain_count: 24,
    check_count: 54,
    total_results: 1296,
    batches: [
      { label: a.meta?.label || 'A — 20 dominios LAC', report_id: null, domain_count: a.domains.length },
      { label: b.meta?.label || 'B — 4 dominios EE.UU. referencia', report_id: null, domain_count: b.domains.length },
    ],
    source_note: 'Nueva medición íntegra (2026-09-14). No reutiliza ni mezcla resultados del ejercicio de 20 dominios (2026-09-13) ni del estudio regional de 400 dominios.',
  },
  domains: allDomains.map(d => ({ country: META[d.domain]?.country, sector: META[d.domain]?.sector, ...d })),
};
fs.writeFileSync(path.join(DIR, 'consolidated-24dominios.json'), JSON.stringify(consolidated, null, 2));

// ─── Resumen compacto (mismo esquema que el ejercicio anterior) ───
function st(d, key) { return d.checks[key]?.status ?? null; }
const resumen = allDomains.map(d => ({
  country: META[d.domain].country,
  sector: META[d.domain].sector,
  domain: d.domain,
  dns: {
    A: st(d,'ipv4'), AAAA_publica: st(d,'ipv6'),
    DNSSEC: d?.dnssec?.dnssec?.final_status ?? null,
    NS: st(d,'dnsserver'), CAA: st(d,'caa'),
  },
  routing: { ASN: st(d,'asn'), RPKI: st(d,'rpki') },
  correo: { MX: st(d,'mx'), SPF: st(d,'spf'), DMARC: st(d,'dmarc'), DKIM: st(d,'dkim'), SMTPUTF8: st(d,'smtputf8') },
  web_tls: {
    HTTPS: st(d,'https'), TLS: st(d,'tls'), certificado_OCSP: st(d,'ocsp'), cadena_SSL: st(d,'sslchain'),
    redirecciones: st(d,'redirect'), HSTS: st(d,'hsts'), CSP: st(d,'csp'),
    security_headers: {
      xfo: st(d,'xfo'), xcto: st(d,'xcto'), xxss: st(d,'xxss'),
      referrer: st(d,'referrer'), permissions: st(d,'permissions'), compression: st(d,'compression'),
    },
  },
  otros: {
    RDAP_domaininfo: st(d,'domaininfo'), malware: st(d,'malware'), archive: st(d,'archive'),
    ranking: st(d,'ranking'), quality: st(d,'quality'), security_txt: st(d,'securitytxt'),
  },
}));
fs.writeFileSync(path.join(DIR, 'resumen-24dominios.json'), JSON.stringify(resumen, null, 2));

// ─── Stats para redactar el artículo/reporte ───
function thematicCounts(key) {
  const counts = {};
  for (const d of allDomains) {
    const s = st(d, key) ?? '(sin dato)';
    counts[s] = (counts[s] || 0) + 1;
  }
  return counts;
}
const THEMATIC_KEYS = ['ipv6','ipv4','rpki','spf','dmarc','dkim','caa','https','tls','hsts','csp','securitytxt','mx','xfo','xcto','referrer','permissions','compression','xxss','malware','ranking','quality','domaininfo'];
const thematic = Object.fromEntries(THEMATIC_KEYS.map(k => [k, thematicCounts(k)]));

const stats = {
  generated_at: new Date().toISOString(),
  total_domains: 24, total_checks_per_domain: 54, total_results: totalChecks,
  status_counts: statusCounts,
  unexpected_statuses: [...unexpectedStatuses],
  dnssec_structural_counts: dnssecCounts,
  thematic_counts: thematic,
};
fs.writeFileSync(path.join(DIR, 'stats-24dominios.json'), JSON.stringify(stats, null, 2));

console.log('\n=== Distribución global de estados (1296 resultados) ===');
console.log(statusCounts);
console.log('\n=== DNSSEC estructural (24 dominios) ===');
console.log(dnssecCounts);
console.log('\nArchivos escritos en', DIR);
