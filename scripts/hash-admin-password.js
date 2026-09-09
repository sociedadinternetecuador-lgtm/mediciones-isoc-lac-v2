'use strict';

/**
 * Utilidad de un solo uso: genera el hash scrypt para ADMIN_PASSWORD_HASH.
 *
 * Uso:
 *   node scripts/hash-admin-password.js "mi-clave-elegida"
 *
 * Copiar la salida completa (incluye el salt) en .env como
 * ADMIN_PASSWORD_HASH. La contraseña en texto plano no se guarda en
 * ningún lado — solo existe en la terminal al ejecutar este comando.
 */

const { hashPassword } = require('../logic/auth/adminAuth.adapter');

const password = process.argv[2];
if (!password) {
  console.error('Uso: node scripts/hash-admin-password.js "mi-clave-elegida"');
  process.exit(1);
}
if (password.length < 8) {
  console.error('La contraseña debe tener al menos 8 caracteres.');
  process.exit(1);
}

console.log(hashPassword(password));
