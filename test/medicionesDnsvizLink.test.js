'use strict';

/**
 * Verifica que DNSViz se incorporó ÚNICAMENTE como enlace externo estático
 * en el frontend (Fase 5, 2026-09-16) — ver
 * AUDITORIA_DNSVIZ_VS_DNSSEC_ECUADOR.md. No es un check de MEDICIONES: no
 * hay endpoint backend, no hay llamada de servidor a dnsviz.net, no cuenta
 * en groupDefinitions ni en el conteo de 60 checks.
 *
 * Igual que medicionesCheckRegistry.test.js, esto es análisis estático de
 * texto sobre index.html/server.js (sin DOM/navegador real, ya que
 * buildDnsvizLink() usa document.createElement, no disponible en Node
 * plano) — suficiente para verificar las invariantes de esta fase sin
 * añadir un framework de testing de DOM nuevo al proyecto.
 *
 * Ejecutar: node test/medicionesDnsvizLink.test.js
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const INDEX_PATH = path.join(__dirname, '..', 'index.html');
const SERVER_PATH = path.join(__dirname, '..', 'server.js');

function run() {
  const html = fs.readFileSync(INDEX_PATH, 'utf8');
  const serverJs = fs.readFileSync(SERVER_PATH, 'utf8');

  // ── DNSViz no aparece como check en groupDefinitions ──
  const groupDefsStart = html.indexOf('const groupDefinitions = [');
  const groupDefsEnd = html.indexOf('const checkGlossary', groupDefsStart);
  const groupDefsSlice = html.slice(groupDefsStart, groupDefsEnd);
  assert.ok(!/key:\s*'dnsviz'/.test(groupDefsSlice), 'dnsviz no debe existir como key en groupDefinitions');
  console.log('PASS dnsviz_no_esta_en_groupDefinitions');

  // ── No existe ruta backend /dnsviz ──
  assert.ok(!/segments\[0\]\s*===\s*'dnsviz'/.test(serverJs), 'No debe existir una ruta backend para dnsviz');
  console.log('PASS sin_ruta_backend_dnsviz');

  // ── No existe ninguna llamada de servidor a dnsviz.net ──
  assert.ok(!/dnsviz\.net/i.test(serverJs), 'server.js no debe contener ninguna referencia a dnsviz.net (cero llamadas backend)');
  console.log('PASS sin_llamada_backend_a_dnsviz_net');

  // ── El enlace existe en el frontend y usa el dominio ya normalizado ──
  assert.ok(/function buildDnsvizLink\(domain\)/.test(html), 'Debe existir buildDnsvizLink(domain) en el frontend');
  const fnMatch = html.match(/function buildDnsvizLink\(domain\)\s*\{[\s\S]*?\n    \}/);
  assert.ok(fnMatch, 'No se pudo extraer el cuerpo de buildDnsvizLink');
  const fnBody = fnMatch[0];
  assert.ok(/const host = toASCII\(domain\)/.test(fnBody), 'Debe normalizar el dominio con toASCII() antes de construir la URL, igual que getCheckResult()');
  console.log('PASS enlace_usa_dominio_normalizado');

  // ── La URL apunta únicamente al host oficial esperado, sobre HTTPS ──
  assert.ok(
    /a\.href\s*=\s*`https:\/\/dnsviz\.net\/d\/\$\{encodeURIComponent\(host\)\}\/dnssec\/`/.test(fnBody),
    'El href debe ser exactamente https://dnsviz.net/d/<host codificado>/dnssec/ — ningún otro host ni esquema'
  );
  console.log('PASS url_apunta_solo_al_host_oficial_https');

  // ── target="_blank" siempre acompañado de noopener noreferrer ──
  assert.ok(/a\.target\s*=\s*'_blank'/.test(fnBody), 'Debe abrir en una pestaña nueva (target=_blank)');
  assert.ok(/a\.rel\s*=\s*'noopener noreferrer'/.test(fnBody), 'target=_blank debe ir acompañado de rel="noopener noreferrer"');
  console.log('PASS target_blank_con_noopener_noreferrer');

  // ── El texto visible no debe presentarlo como una medición propia ──
  const forbidden = ['Medición DNSViz', 'Resultado DNSViz', 'Validado por DNSViz', 'Check DNSViz'];
  for (const phrase of forbidden) {
    assert.ok(!html.includes(phrase), `El frontend no debe usar la frase "${phrase}" (DNSViz no es una medición de MEDICIONES)`);
  }
  console.log('PASS texto_no_lo_presenta_como_medicion_propia');

  console.log('\nOK — DNSViz incorporado únicamente como enlace externo, sin backend ni check nuevo.');
}

run();
