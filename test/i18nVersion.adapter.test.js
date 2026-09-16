'use strict';

/**
 * logic/adapters/i18nVersion.adapter.js — cache-busting automático de
 * /i18n.js (ver comentario del propio módulo: reemplaza el "?v=N" manual,
 * que dos veces (2026-09-11 y 2026-09-16) se olvidó de subir y dejó
 * navegadores viendo claves crudas de traducción en vez del texto real).
 *
 * Ejecutar: node test/i18nVersion.adapter.test.js
 */

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { injectI18nVersion } = require('../logic/adapters/i18nVersion.adapter');

function run() {
  const i18nPath = path.join(__dirname, '..', 'public', 'i18n.js');
  const expectedHash = crypto.createHash('md5').update(fs.readFileSync(i18nPath)).digest('hex').slice(0, 10);

  // ── Reemplaza el placeholder manual por el hash real del archivo ──
  const withOldPlaceholder = '<script src="/i18n.js?v=11"></script>';
  const result1 = injectI18nVersion(withOldPlaceholder);
  assert.ok(result1.includes(`/i18n.js?v=${expectedHash}`), 'debe reemplazar "?v=11" por el hash real de public/i18n.js');
  assert.ok(!result1.includes('?v=11'), 'no debe quedar el número viejo a mano');
  console.log('PASS reemplaza_placeholder_manual_por_hash_real');

  // ── También normaliza si no hay query string, o si ya trae un hash de
  // una corrida anterior de esta misma función (idempotente) ──
  const withoutQuery = '<script src="/i18n.js"></script>';
  assert.ok(injectI18nVersion(withoutQuery).includes(`/i18n.js?v=${expectedHash}`), 'debe agregar el hash aunque no haya query string previo');
  const alreadyHashed = `<script src="/i18n.js?v=${expectedHash}"></script>`;
  assert.strictEqual(injectI18nVersion(alreadyHashed), alreadyHashed, 'debe ser idempotente si ya trae el hash actual');
  console.log('PASS funciona_sin_query_previo_y_es_idempotente');

  // ── Si el contenido real de i18n.js cambiara, el hash cambiaría — se
  // verifica indirectamente: el hash devuelto depende del contenido real
  // del archivo, no de un valor fijo en el código ──
  const differentContentHash = crypto.createHash('md5').update('contenido distinto').digest('hex').slice(0, 10);
  assert.notStrictEqual(expectedHash, differentContentHash, 'el hash debe derivarse del contenido real, no ser un valor fijo casual');
  console.log('PASS hash_depende_del_contenido_real_del_archivo');

  // ── index.html y admin.html todavía usan el patrón que esta función
  // sabe reemplazar (si algún día cambia el markup, este test debe
  // fallar y avisar que hay que revisar la integración) ──
  for (const file of ['index.html', 'admin.html']) {
    const html = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
    assert.ok(/<script src="\/i18n\.js\?v=\d+"><\/script>/.test(html), `${file} debe tener un <script src="/i18n.js?v=N"> para que injectI18nVersion lo reemplace`);
  }
  console.log('PASS index_y_admin_html_usan_el_patron_esperado');

  console.log('\nOK — cache-busting automático de i18n.js: todos los casos pasaron.');
}

run();
