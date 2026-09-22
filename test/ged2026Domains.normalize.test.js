'use strict';

/**
 * normalizeCandidateDomain() — confirma que reutiliza tal cual
 * normalizeDomainLine()/staticValid() del validador cerrado (sin
 * reimplementarlos) y que el paso propio de GED2026 (extraer hostname de
 * una URL completa) funciona antes de entrar a ese pipeline.
 *
 * Ejecutar: node test/ged2026Domains.normalize.test.js
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

// Este test ejercita normalizeCandidateDomain(), que necesita la Public
// Suffix List (logic/adapters/publicSuffixList.adapter.js). Para mantener
// el test CI-safe (sin red — ver CLAUDE.md § convención de testing) se
// aísla DATA_DIR en un temporal y se precarga con la copia YA descargada
// en data/psl_cache/ del propio proyecto, en vez de dejar que el adaptador
// intente bajarla de publicsuffix.org.
const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'mediciones-ged2026-normalize-'));
process.env.DATA_DIR = TMP_DIR;
fs.mkdirSync(path.join(TMP_DIR, 'psl_cache'), { recursive: true });
fs.copyFileSync(
  path.resolve(__dirname, '../data/psl_cache/public_suffix_list.dat'),
  path.join(TMP_DIR, 'psl_cache', 'public_suffix_list.dat'),
);

const { normalizeCandidateDomain } = require('../logic/validators/ged2026Domains.validator');

async function run() {
  // ─── Caso normal, multi-TLD (no fijo a .ec como en Preparación de datasets) ──
  const ok1 = await normalizeCandidateDomain('Ejemplo.COM.EC');
  assert.strictEqual(ok1.ok, true);
  assert.strictEqual(ok1.normalized_domain, 'ejemplo.com.ec');
  assert.strictEqual(ok1.suffix, 'com.ec');

  // ─── URL completa: protocolo, mayúsculas, ruta y barra final se descartan ──
  const ok2 = await normalizeCandidateDomain('HTTPS://WWW.EJEMPLO.COM.EC/alguna/ruta?x=1');
  assert.strictEqual(ok2.ok, true);
  assert.strictEqual(ok2.normalized_domain, 'www.ejemplo.com.ec', 'www. se preserva, no se recorta');

  // ─── Puerto explícito se descarta ────────────────────────────────
  const ok3 = await normalizeCandidateDomain('ejemplo.com.ec:8443');
  assert.strictEqual(ok3.ok, true);
  assert.strictEqual(ok3.normalized_domain, 'ejemplo.com.ec');

  // ─── Vacío / solo espacios ───────────────────────────────────────
  const empty = await normalizeCandidateDomain('   ');
  assert.strictEqual(empty.ok, false);
  assert.strictEqual(empty.reason, 'empty');

  // ─── Dominio sin sufijo válido (una sola etiqueta, es su propio sufijo) ──
  // staticValid() comprueba primero `!ascii.endsWith('.' + tld)` — con
  // ascii === tld eso siempre es cierto (outside_tld), así que la rama
  // 'tld_itself' del validador cerrado nunca se alcanza por esta vía; se
  // documenta así en vez de asumir el motivo sin correrlo de verdad.
  const bare = await normalizeCandidateDomain('localhost');
  assert.strictEqual(bare.ok, false);
  assert.strictEqual(bare.reason, 'outside_tld');

  // ─── Etiqueta inválida (guion al inicio) → invalid_label, vía staticValid real ──
  const badLabel = await normalizeCandidateDomain('-invalido.com.ec');
  assert.strictEqual(badLabel.ok, false);
  assert.strictEqual(badLabel.reason, 'invalid_label');

  // ─── Comillas envolventes y punto final se limpian (normalizeDomainLine real) ──
  const quoted = await normalizeCandidateDomain('"ejemplo.org.ec"');
  assert.strictEqual(quoted.ok, true);
  assert.strictEqual(quoted.normalized_domain, 'ejemplo.org.ec');

  const trailingDot = await normalizeCandidateDomain('ejemplo.org.ec.');
  assert.strictEqual(trailingDot.ok, true);
  assert.strictEqual(trailingDot.normalized_domain, 'ejemplo.org.ec');

  console.log('✅ ged2026Domains.normalize.test.js — todos los casos OK');
}

run()
  .catch((err) => {
    console.error('❌ ged2026Domains.normalize.test.js FALLÓ:', err);
    process.exitCode = 1;
  })
  .finally(() => {
    fs.rmSync(TMP_DIR, { recursive: true, force: true });
  });
