'use strict';

/**
 * Cache-busting automático para /i18n.js.
 *
 * Historia (2026-09-11, repetido 2026-09-16): index.html/admin.html traían
 * un query string a mano, `<script src="/i18n.js?v=11">` — y dependía de
 * que quien editara public/i18n.js se acordara de subir ese número. Dos
 * veces se olvidó, y los navegadores (sobre todo celulares, que retienen
 * caché más agresivamente) siguieron sirviendo una copia vieja del
 * diccionario de traducción durante horas/días tras el deploy —
 * observable como claves crudas en pantalla ("inicio.hero.lead") en vez
 * del texto real, aunque el archivo en el servidor ya estuviera correcto.
 *
 * Fix: el número deja de existir. La versión es un hash del contenido
 * real de public/i18n.js en este momento — si el archivo cambia, la URL
 * cambia sola (cache miss garantizado), sin que nadie tenga que acordarse
 * de nada. Se calcula una sola vez al cargar el módulo (el archivo no
 * cambia mientras el proceso corre; un deploy siempre reconstruye el
 * contenedor).
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PUBLIC_DIR = path.join(__dirname, '..', '..', 'public');
const I18N_PATH = path.join(PUBLIC_DIR, 'i18n.js');

// 2026-09-27: mismo riesgo de caché vieja tras deploy que ya mordió a
// i18n.js aplica igual a los assets de la Base de Conocimiento DNSSEC
// (public/dnssecKb.js, dnssecKb.content.js, dnssecKb.css) — se reutiliza
// el mismo mecanismo de hash-por-contenido en vez de inventar uno nuevo.
const VERSIONED_ASSETS = [
  { file: 'i18n.js', path: I18N_PATH },
  { file: 'dnssecKb.content.js', path: path.join(PUBLIC_DIR, 'dnssecKb.content.js') },
  { file: 'dnssecKb.js', path: path.join(PUBLIC_DIR, 'dnssecKb.js') },
  { file: 'dnssecKb.css', path: path.join(PUBLIC_DIR, 'dnssecKb.css') }
];

function hashFile(filePath) {
  try {
    return crypto.createHash('md5').update(fs.readFileSync(filePath)).digest('hex').slice(0, 10);
  } catch (e) {
    // Si el archivo no está disponible por algún motivo, se degrada a un
    // valor fijo — sigue funcionando (misma URL siempre), solo pierde el
    // cache-busting automático hasta el próximo reinicio del proceso.
    return 'unversioned';
  }
}

let cachedVersion; // compatibilidad: versión de i18n.js, mismo nombre que antes.
const versions = {};
for (const asset of VERSIONED_ASSETS) {
  versions[asset.file] = hashFile(asset.path);
}
cachedVersion = versions['i18n.js'];

// Reemplaza cualquier `<archivo>.js?v=<lo que sea>` (el número viejo a
// mano, o una corrida anterior de esta misma función) por el hash actual
// de ese archivo — mismo patrón para los 4 assets versionados.
function injectI18nVersion(html) {
  let result = String(html);
  for (const asset of VERSIONED_ASSETS) {
    const escaped = asset.file.replace(/\./g, '\\.');
    const pattern = new RegExp(`${escaped}(\\?v=[^"'\\s]*)?`, 'g');
    result = result.replace(pattern, `${asset.file}?v=${versions[asset.file]}`);
  }
  return result;
}

module.exports = { injectI18nVersion };
