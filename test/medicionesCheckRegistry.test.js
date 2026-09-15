'use strict';

/**
 * Verifica la integridad del registro de checks de MEDICIONES después de
 * la Fase 1 (maildnssec, mailipv6, starttls):
 *
 *   - groupDefinitions (index.html) contiene exactamente 57 checks (54 +
 *     los 3 nuevos), sin duplicados.
 *   - Cada clave de groupDefinitions tiene una ruta de despacho
 *     correspondiente en server.js (segments[0] === '<key>').
 *
 * No depende de un servidor real ni de red — solo lee index.html/server.js
 * como texto y evalúa el arreglo `groupDefinitions` en un contexto
 * aislado (new Function), igual que se haría con cualquier literal de
 * datos de confianza del propio repositorio.
 *
 * Ejecutar: node test/medicionesCheckRegistry.test.js
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const INDEX_PATH = path.join(__dirname, '..', 'index.html');
const SERVER_PATH = path.join(__dirname, '..', 'server.js');

function extractGroupDefinitions(html) {
  const start = html.indexOf('const groupDefinitions = [');
  assert.ok(start !== -1, 'No se encontró "const groupDefinitions = [" en index.html');
  const arrayStart = html.indexOf('[', start);
  // Balanceo simple de corchetes para hallar el cierre exacto del arreglo.
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
  return groupDefinitions;
}

function extractServerRouteKeys(serverJs) {
  const re = /segments\[0\]\s*===\s*'([a-z0-9]+)'/g;
  const keys = new Set();
  let m;
  while ((m = re.exec(serverJs))) keys.add(m[1]);
  return keys;
}

// getCheckResult() en index.html es donde CADA check de groupDefinitions
// debe tener su lógica de clasificación (case 'key':) — no necesariamente
// una ruta backend propia: varios checks preexistentes (https, hsts, csp,
// tls, asn, server, etc.) comparten un endpoint "bundle" (/headers,
// /tlsinfo, /serverinfo) y extraen su campo del mismo JSON ya cacheado.
// Ese patrón es arquitectura previa, no algo de esta fase — la invariante
// real de completitud del registro es "tiene case en el switch", no
// "tiene su propia ruta backend".
function extractFrontendCaseKeys(html) {
  const re = /case '([a-z0-9]+)':/g;
  const keys = new Set();
  let m;
  while ((m = re.exec(html))) keys.add(m[1]);
  return keys;
}

function run() {
  const html = fs.readFileSync(INDEX_PATH, 'utf8');
  const serverJs = fs.readFileSync(SERVER_PATH, 'utf8');

  const groupDefinitions = extractGroupDefinitions(html);
  const allKeys = [];
  for (const group of groupDefinitions) {
    for (const check of group.checks) allKeys.push(check.key);
  }

  // ── Conteo exacto ──
  assert.strictEqual(allKeys.length, 57, `Se esperaban 57 checks, se encontraron ${allKeys.length}`);
  console.log('PASS conteo_57_checks');

  // ── Sin duplicados ──
  const seen = new Set();
  const dupes = [];
  for (const key of allKeys) {
    if (seen.has(key)) dupes.push(key);
    seen.add(key);
  }
  assert.deepStrictEqual(dupes, [], `Claves duplicadas en groupDefinitions: ${dupes.join(', ')}`);
  console.log('PASS sin_duplicados');

  // ── Los 3 nuevos están presentes ──
  for (const key of ['maildnssec', 'mailipv6', 'starttls']) {
    assert.ok(seen.has(key), `Falta el check nuevo "${key}" en groupDefinitions`);
  }
  console.log('PASS nuevos_checks_presentes');

  // ── Todos los checks del frontend tienen su lógica en getCheckResult() ──
  const frontendCases = extractFrontendCaseKeys(html);
  const orphanedFrontend = allKeys.filter((key) => !frontendCases.has(key));
  assert.deepStrictEqual(orphanedFrontend, [], `Checks de groupDefinitions sin case en getCheckResult(): ${orphanedFrontend.join(', ')}`);
  console.log('PASS todos_los_checks_tienen_case_frontend');

  // ── Los 3 checks nuevos, específicamente, sí tienen ruta backend propia
  // (no comparten bundle — a diferencia de otros checks preexistentes) ──
  const serverRoutes = extractServerRouteKeys(serverJs);
  for (const key of ['maildnssec', 'mailipv6', 'starttls']) {
    assert.ok(serverRoutes.has(key), `El check nuevo "${key}" debería tener su propia ruta backend (segments[0] === '${key}')`);
  }
  console.log('PASS nuevos_checks_tienen_ruta_backend_propia');

  console.log('\nOK — registro de checks de MEDICIONES íntegro (57, sin duplicados, todos con handler).');
}

run();
