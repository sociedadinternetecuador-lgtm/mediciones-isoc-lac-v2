'use strict';

/**
 * Comparación de equivalencia EN VIVO: corre la validación DNS en JS
 * (logic/validators/dnsValidation.validator.js) sobre una lista real de
 * dominios y la compara, dominio por dominio, contra el CSV maestro
 * (validacion_dns.csv) que produce el validador de referencia
 * (validador/validar_dominios_isoc_lac.py) sobre ESA MISMA lista.
 *
 * Requiere red real y no es determinista por naturaleza (dos ejecuciones
 * en momentos distintos pueden ver transitoriamente un SERVFAIL/TIMEOUT
 * distinto en algún resolver) — por eso no es parte de "npm test". Sirve
 * para reproducir la verificación de equivalencia cuando se quiera repetir
 * a mayor escala o sobre otro dataset.
 *
 * Procedimiento:
 *   1. python validador/validar_dominios_isoc_lac.py <domains.txt> --tld ec --out <outdir>
 *   2. node test/dnsValidation.live.pythonCompare.js <domains.txt> <outdir>/validacion_dns.csv
 *
 * Métricas reportadas:
 *   - Acuerdo de final_status por dominio (debe ser ~100%; es la métrica
 *     que realmente importa — first_pass_status y discrepancy pueden
 *     variar entre ejecuciones por ruido de red transitorio sin afectar
 *     la clasificación final gracias al reintento automático de REVIEW).
 *   - Acuerdo de review_subtype para los dominios que terminan en REVIEW.
 */

const fs = require('fs');
const path = require('path');
const { runDnsValidation, reviewSubtype } = require('../logic/validators/dnsValidation.validator');

function parseCsv(text) {
  const lines = text.split(/\r?\n/).filter(Boolean);
  const header = lines[0].split(',');
  return lines.slice(1).map((line) => {
    const cols = line.split(',');
    const row = {};
    header.forEach((h, i) => { row[h] = cols[i]; });
    return row;
  });
}

async function main() {
  const [, , domainsPath, pythonCsvPath] = process.argv;
  if (!domainsPath || !pythonCsvPath) {
    console.error('Uso: node test/dnsValidation.live.pythonCompare.js <domains.txt> <validacion_dns.csv de Python>');
    process.exit(2);
  }

  const domains = fs.readFileSync(path.resolve(domainsPath), 'utf-8')
    .split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const pyRows = parseCsv(fs.readFileSync(path.resolve(pythonCsvPath), 'utf-8'));
  const pyByDomain = {};
  for (const row of pyRows) pyByDomain[row.domain] = row;

  console.log(`Corriendo validación DNS en JS sobre ${domains.length} dominios reales...`);
  const start = Date.now();
  const result = await runDnsValidation({
    domains,
    onProgress: ({ phase, done, total }) => {
      if (done % 500 === 0 || done === total) console.log(`[${phase}] ${done}/${total}`);
    },
  });
  console.log(`JS completado en ${((Date.now() - start) / 1000).toFixed(1)}s\n`);

  let agree = 0;
  let disagree = 0;
  const disagreements = [];
  let subtypeAgree = 0;
  let subtypeDisagree = 0;

  for (const domain of domains) {
    const final = result.finalResults.get(domain);
    const py = pyByDomain[domain];
    if (!py) {
      console.log('Dominio ausente en el CSV de Python (no comparable):', domain);
      continue;
    }

    if (final.status === py.final_status) {
      agree += 1;
    } else {
      disagree += 1;
      disagreements.push({
        domain,
        js_status: final.status,
        python_status: py.final_status,
        python_first_pass: py.first_pass_status,
        python_reason: py.status_reason,
      });
    }

    if (final.status === 'REVIEW') {
      const subtype = reviewSubtype(final);
      if (subtype === py.review_subtype) subtypeAgree += 1;
      else subtypeDisagree += 1;
    }
  }

  console.log('=== Resultado de equivalencia ===');
  console.log(`Dominios comparados: ${agree + disagree}`);
  console.log(`final_status — acuerdo: ${agree} | desacuerdo: ${disagree} (${((agree / (agree + disagree)) * 100).toFixed(3)}%)`);
  console.log(`review_subtype — acuerdo: ${subtypeAgree} | desacuerdo: ${subtypeDisagree}`);

  if (disagreements.length) {
    console.log('\n=== Desacuerdos (revisar causa exacta antes de tocar código) ===');
    console.log(JSON.stringify(disagreements, null, 2));
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error('ERROR', error);
  process.exit(1);
});
