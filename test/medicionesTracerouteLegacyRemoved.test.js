'use strict';

/**
 * Verifica el cierre del backend residual de "Traceroute" (ver
 * AUDITORIA_MEDICIONES_TRACEROUTE.md): el frontend se había retirado en el
 * commit e1ed8bd (2026-09-12), pero `handleTraceroute` y la ruta
 * `/traceroute/:dominio` seguían presentes y alcanzables en server.js,
 * dependiendo de api.hackertarget.com/mtr/ (roto permanentemente, exige
 * API key). Esta fase elimina ese backend residual.
 *
 * No depende de un servidor real ni de red — solo lee server.js/index.html
 * como texto.
 *
 * Ejecutar: node test/medicionesTracerouteLegacyRemoved.test.js
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const INDEX_PATH = path.join(__dirname, '..', 'index.html');
const SERVER_PATH = path.join(__dirname, '..', 'server.js');

function run() {
  const html = fs.readFileSync(INDEX_PATH, 'utf8');
  const serverJs = fs.readFileSync(SERVER_PATH, 'utf8');

  // ── No existe la ruta de despacho /traceroute/:dominio ──
  assert.ok(
    !/segments\[0\]\s*===\s*'traceroute'/.test(serverJs),
    'La ruta backend "traceroute" (segments[0] === \'traceroute\') sigue presente en server.js'
  );
  console.log('PASS sin_ruta_backend_traceroute');

  // ── No existe la función handleTraceroute ──
  assert.ok(
    !/function\s+handleTraceroute\s*\(/.test(serverJs),
    'handleTraceroute() sigue definida en server.js'
  );
  console.log('PASS sin_handleTraceroute');

  // ── No queda una llamada productiva a HackerTarget para traceroute (mtr) ──
  assert.ok(
    !/api\.hackertarget\.com\/mtr/i.test(serverJs),
    'Sigue existiendo una referencia a api.hackertarget.com/mtr/ en server.js'
  );
  console.log('PASS sin_hackertarget_mtr_residual');

  // ── El otro uso legítimo de HackerTarget (hostsearch, check distinto:
  // handleAssociatedHosts) no debe haberse tocado por esta limpieza ──
  assert.ok(
    /api\.hackertarget\.com\/hostsearch/i.test(serverJs),
    'La llamada a api.hackertarget.com/hostsearch/ (handleAssociatedHosts, check distinto a traceroute) desapareció — no debía tocarse'
  );
  console.log('PASS hostsearch_no_tocado');

  // ── index.html no tiene ningún rastro de "traceroute" (ya se había
  // retirado del frontend antes de esta fase; se reconfirma que sigue así) ──
  assert.ok(!/traceroute/i.test(html), 'index.html todavía contiene referencias a "traceroute"');
  console.log('PASS index_html_sin_traceroute');

  // ── El registro de checks sigue en 60 (esta limpieza no debía tocar
  // groupDefinitions: traceroute ya no era un check activo) ──
  const start = html.indexOf('const groupDefinitions = [');
  assert.ok(start !== -1, 'No se encontró "const groupDefinitions = [" en index.html');
  const arrayStart = html.indexOf('[', start);
  let depth = 0;
  let end = -1;
  for (let i = arrayStart; i < html.length; i += 1) {
    if (html[i] === '[') depth += 1;
    else if (html[i] === ']') {
      depth -= 1;
      if (depth === 0) { end = i; break; }
    }
  }
  assert.ok(end !== -1, 'No se pudo balancear el arreglo groupDefinitions');
  const literal = html.slice(arrayStart, end + 1);
  // eslint-disable-next-line no-new-func
  const groupDefinitions = new Function(`'use strict'; return (${literal});`)();
  const allKeys = [];
  for (const group of groupDefinitions) {
    for (const check of group.checks) allKeys.push(check.key);
  }
  assert.strictEqual(allKeys.length, 60, `Se esperaban 60 checks, se encontraron ${allKeys.length}`);
  console.log('PASS conteo_60_checks_sin_cambios');

  console.log('\nOK — backend residual de traceroute eliminado; hostsearch y el registro de 60 checks intactos.');
}

run();
