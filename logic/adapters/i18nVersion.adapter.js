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

const I18N_PATH = path.join(__dirname, '..', '..', 'public', 'i18n.js');

let cachedVersion = 'unversioned';
try {
  cachedVersion = crypto.createHash('md5').update(fs.readFileSync(I18N_PATH)).digest('hex').slice(0, 10);
} catch (e) {
  // Si el archivo no está disponible por algún motivo, se degrada a un
  // valor fijo — sigue funcionando (misma URL siempre), solo pierde el
  // cache-busting automático hasta el próximo reinicio del proceso.
}

// Reemplaza cualquier `i18n.js?v=<lo que sea>` (el número viejo a mano, o
// una corrida anterior de esta misma función) por el hash actual.
function injectI18nVersion(html) {
  return String(html).replace(/i18n\.js(\?v=[^"'\s]*)?/g, `i18n.js?v=${cachedVersion}`);
}

module.exports = { injectI18nVersion };
