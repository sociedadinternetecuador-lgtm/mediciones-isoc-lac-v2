'use strict';

/**
 * Verifica la separación estructural de la Base de Conocimiento DNSSEC tras
 * extraer su lógica de index.html a public/dnssecKb.js (+ dnssecKb.css).
 * Es un módulo de navegador (DOM real) sin jsdom en el proyecto, así que
 * aquí solo se comprueban invariantes estáticos: forma del archivo, API
 * expuesta, y que index.html quedó realmente libre de la lógica extraída
 * (sin duplicarla) y referencia los assets en el orden correcto. El
 * comportamiento en navegador (búsqueda, filtros, TOC, deep-links,
 * IntersectionObserver, enlaces contextuales) se verifica con Playwright
 * de forma manual, igual que el resto de la regresión de frontend del
 * proyecto (ver CLAUDE.md).
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const jsPath = path.join(__dirname, '..', 'public', 'dnssecKb.js');
const cssPath = path.join(__dirname, '..', 'public', 'dnssecKb.css');
const indexPath = path.join(__dirname, '..', 'index.html');

assert.ok(fs.existsSync(jsPath), 'public/dnssecKb.js debe existir');
assert.ok(fs.existsSync(cssPath), 'public/dnssecKb.css debe existir');

const js = fs.readFileSync(jsPath, 'utf8');
const css = fs.readFileSync(cssPath, 'utf8');
const html = fs.readFileSync(indexPath, 'utf8');

// dnssecKb.js: script de navegador plano, sin CommonJS.
assert.ok(!/require\(|module\.exports/.test(js), 'dnssecKb.js debe ser un script de navegador plano, sin CommonJS');

// Envuelto en una única IIFE (no contamina el scope global salvo por su
// única interfaz pública). El archivo puede empezar con un comentario de
// cabecera, así que se busca la IIFE, no el inicio literal del archivo.
assert.ok(/\(function \(\) \{/.test(js), 'dnssecKb.js debe estar envuelto en una IIFE');
assert.ok(/\}\)\(\);\s*$/.test(js.trim()), 'dnssecKb.js debe cerrar la IIFE al final del archivo');

// Única superficie global expuesta: window.DnssecKb.
const windowAssignments = js.match(/window\.[A-Za-z_$][A-Za-z0-9_$]*\s*=/g) || [];
const uniqueGlobals = new Set(windowAssignments.map((s) => s.replace(/\s*=$/, '')));
assert.deepStrictEqual(
  Array.from(uniqueGlobals),
  ['window.DnssecKb'],
  `dnssecKb.js debe exponer un único global (window.DnssecKb), encontrados: ${Array.from(uniqueGlobals).join(', ')}`
);

// API pública mínima esperada (Fase 4 del pedido de optimización).
const expectedApi = ['init', 'switchTopTab', 'setLevel', 'openGuide', 'backToGrid', 'handleRoute', 'infoLink'];
for (const method of expectedApi) {
  assert.ok(
    new RegExp(`\\b${method}\\s*:\\s*${method}\\b`).test(js),
    `window.DnssecKb debe exponer "${method}"`
  );
}

// dnssecKb.css: contiene la corrección del TOC de escritorio validada en
// la revisión visual (no debe volver a depender de "hidden md:block").
assert.ok(css.includes('.dnssec-kb-toc-desktop-wrap'), 'dnssecKb.css debe definir .dnssec-kb-toc-desktop-wrap');
assert.ok(/min-width:\s*768px/.test(css), 'dnssecKb.css debe mostrar el TOC de escritorio a partir de 768px');

// index.html: debe cargar los 3 assets de la KB, contenido ANTES que
// lógica, y sin haber quedado una copia duplicada de las funciones que ya
// viven en dnssecKb.js.
const contentTagIndex = html.indexOf('<script src="/dnssecKb.content.js">');
const jsTagIndex = html.indexOf('<script src="/dnssecKb.js">');
const cssTagIndex = html.indexOf('href="/dnssecKb.css"');
assert.ok(contentTagIndex !== -1, 'index.html debe cargar /dnssecKb.content.js');
assert.ok(jsTagIndex !== -1, 'index.html debe cargar /dnssecKb.js');
assert.ok(cssTagIndex !== -1, 'index.html debe enlazar /dnssecKb.css');
assert.ok(contentTagIndex < jsTagIndex, 'dnssecKb.content.js debe cargar ANTES que dnssecKb.js (orden de carga)');

const extractedFunctionNames = [
  'function dnssecKbInit', 'function dnssecSwitchTopTab', 'function dnssecKbSetLevel',
  'function dnssecKbOpenGuide', 'function dnssecKbBackToGrid', 'function dnssecKbHandleHashRoute',
  'function dnssecKbRenderGrid', 'function renderDnssecKbGuide', 'function dnssecKbInfoLink'
];
for (const fn of extractedFunctionNames) {
  assert.ok(!html.includes(fn), `index.html no debe seguir definiendo "${fn}" — debe vivir solo en dnssecKb.js`);
}

// Los onclick inline y el wireup de hashchange deben llamar a la nueva
// interfaz, no a las funciones sueltas anteriores.
assert.ok(html.includes("DnssecKb.switchTopTab("), 'index.html debe invocar DnssecKb.switchTopTab desde los botones del sub-tab superior');
assert.ok(html.includes("DnssecKb.setLevel("), 'index.html debe invocar DnssecKb.setLevel desde los filtros de nivel');
assert.ok(html.includes("DnssecKb.backToGrid("), 'index.html debe invocar DnssecKb.backToGrid desde los botones "Volver"');
assert.ok(html.includes("DnssecKb.infoLink("), 'index.html (analizador) debe invocar DnssecKb.infoLink para los enlaces contextuales');
assert.ok(!/[^.]dnssecKbInfoLink\(/.test(html), 'no debe quedar ninguna llamada a la función suelta dnssecKbInfoLink');

// El wireup de hashchange no debe romper el resto del sitio si dnssecKb.js
// no llegó a cargar (aislamiento de fallos, Fase 15).
assert.ok(
  /if\s*\(\s*window\.DnssecKb\s*\)/.test(html),
  'el wireup de hashchange debe comprobar que window.DnssecKb existe antes de usarlo (aislamiento de fallos)'
);

// Búsqueda tolerante a acentos (Fase 11): sin librería, vía NFD + remoción
// de diacríticos, aplicada tanto al término buscado como al contenido.
assert.ok(
  /normalize\(\s*['"]NFD['"]\s*\)\.replace\(/.test(js),
  'dnssecKb.js debe normalizar con NFD y remover marcas diacríticas para que la búsqueda sea tolerante a acentos'
);
// Verificación funcional directa (no solo textual): "validacion" (sin
// tilde) debe normalizar igual que "validación".
const stripDiacriticsMatch = js.match(/function stripDiacritics\(text\) \{\s*return ([\s\S]*?);\s*\}/);
assert.ok(stripDiacriticsMatch, 'no se encontró la función stripDiacritics en dnssecKb.js');
const stripDiacritics = new Function('text', 'return ' + stripDiacriticsMatch[1] + ';');
assert.strictEqual(
  stripDiacritics('validación').toLowerCase(),
  stripDiacritics('validacion').toLowerCase(),
  'la búsqueda debe ser tolerante a acentos: "validación" y "validacion" deben normalizar igual'
);

console.log('dnssecKb.module.test.js OK');
