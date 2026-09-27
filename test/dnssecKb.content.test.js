'use strict';

/**
 * Integridad de datos de la Base de Conocimiento DNSSEC (public/dnssecKb.content.js).
 * Es un script plano cargado en el navegador vía <script src>, sin module.exports —
 * se carga aquí con vm para no depender de un runtime de browser.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const filePath = path.join(__dirname, '..', 'public', 'dnssecKb.content.js');
const source = fs.readFileSync(filePath, 'utf8');

assert.ok(
  !/require\(|module\.exports/.test(source),
  'dnssecKb.content.js debe ser un script de navegador plano, sin CommonJS'
);

const sandbox = { window: {} };
vm.createContext(sandbox);
vm.runInContext(source, sandbox);

const kb = sandbox.window.DNSSEC_KB;
assert.ok(kb, 'window.DNSSEC_KB debe existir tras cargar el script');

// 20 guías del currículo (básico/intermedio/avanzado) + Glosario + Referencias.
assert.strictEqual(kb.guides.length, 22, 'deben existir exactamente 22 guías (20 currículo + Glosario + Referencias)');

const ids = kb.guides.map((g) => g.id);
assert.strictEqual(new Set(ids).size, ids.length, 'no debe haber ids de guía duplicados');

const slugs = kb.guides.map((g) => g.slug);
assert.strictEqual(new Set(slugs).size, slugs.length, 'no debe haber slugs duplicados');

const categoryIds = new Set(kb.categories.map((c) => c.id));
const validLevels = new Set(['basico', 'intermedio', 'avanzado', 'referencia']);

for (const guide of kb.guides) {
  assert.ok(validLevels.has(guide.level), `nivel inválido en guía ${guide.id}`);
  assert.ok(categoryIds.has(guide.category), `categoría inexistente en guía ${guide.id}: ${guide.category}`);
  assert.ok(Array.isArray(guide.sections) && guide.sections.length > 0, `guía ${guide.id} sin secciones`);
  if (guide.prevId !== null) {
    assert.ok(ids.includes(guide.prevId), `prevId roto en guía ${guide.id}: ${guide.prevId}`);
  }
  if (guide.nextId !== null) {
    assert.ok(ids.includes(guide.nextId), `nextId roto en guía ${guide.id}: ${guide.nextId}`);
  }
}

// Glosario y Referencias deben existir, con slug estable, categoría propia,
// y fuera de la cadena prev/next del currículo (no participan de ella).
const glosario = kb.guides.find((g) => g.id === 'glosario-dnssec');
assert.ok(glosario, 'debe existir la guía de Glosario DNSSEC');
assert.strictEqual(glosario.slug, 'glosario', 'el slug del Glosario debe ser "glosario" (deep-link #/dnssec/aprender/glosario)');
assert.strictEqual(glosario.category, 'glosario', 'el Glosario debe pertenecer a la categoría "glosario"');
assert.strictEqual(glosario.prevId, null, 'el Glosario no debe participar de la cadena prev/next del currículo');
assert.strictEqual(glosario.nextId, null, 'el Glosario no debe participar de la cadena prev/next del currículo');

const referencias = kb.guides.find((g) => g.id === 'referencias-estandares');
assert.ok(referencias, 'debe existir la guía de Referencias y estándares');
assert.strictEqual(referencias.slug, 'referencias', 'el slug de Referencias debe ser "referencias" (deep-link #/dnssec/aprender/referencias)');
assert.strictEqual(referencias.category, 'referencias', 'Referencias debe pertenecer a la categoría "referencias"');
assert.strictEqual(referencias.prevId, null, 'Referencias no debe participar de la cadena prev/next del currículo');
assert.strictEqual(referencias.nextId, null, 'Referencias no debe participar de la cadena prev/next del currículo');

// Las categorías GLOSARIO y REFERENCIAS ya no deben estar vacías.
for (const catId of ['glosario', 'referencias']) {
  const count = kb.guides.filter((g) => g.category === catId).length;
  assert.ok(count > 0, `la categoría "${catId}" debe tener al menos una guía`);
}

// La cadena prev/next debe formar una única secuencia lineal de exactamente
// las 20 guías del currículo (básico/intermedio/avanzado), sin incluir a
// Glosario/Referencias y sin ciclos.
const curriculumGuides = kb.guides.filter((g) => g.level !== 'referencia');
assert.strictEqual(curriculumGuides.length, 20, 'deben existir exactamente 20 guías de currículo (básico/intermedio/avanzado)');

const startGuides = curriculumGuides.filter((g) => g.prevId === null);
assert.strictEqual(startGuides.length, 1, 'debe existir exactamente una guía inicial de currículo (prevId null)');

let current = startGuides[0];
const visited = new Set();
while (current) {
  assert.ok(!visited.has(current.id), `ciclo detectado en la cadena prev/next en ${current.id}`);
  visited.add(current.id);
  current = current.nextId ? kb.guides.find((g) => g.id === current.nextId) : null;
}
assert.strictEqual(visited.size, 20, 'la cadena next debe recorrer las 20 guías de currículo exactamente una vez');

// Todos los enlaces internos "#/dnssec/aprender/<slug>" dentro del HTML de
// cualquier sección (glosario, referencias relacionadas, etc.) deben apuntar
// a un slug de guía que realmente exista.
const linkPattern = /#\/dnssec\/aprender\/([a-z0-9-]+)/g;
for (const guide of kb.guides) {
  for (const section of guide.sections) {
    let match;
    while ((match = linkPattern.exec(section.html)) !== null) {
      const targetSlug = match[1];
      assert.ok(
        slugs.includes(targetSlug),
        `enlace interno roto en guía "${guide.id}" sección "${section.id}": apunta a slug inexistente "${targetSlug}"`
      );
    }
  }
}

// Referencias obligatorias (sección 2 del pedido) presentes en la guía de
// Referencias y estándares: RFC/BCP exactos + registros IANA.
const referenciasHtml = referencias.sections.map((s) => s.html).join(' ');
const requiredRfcCodes = [
  'RFC 4033', 'RFC 4034', 'RFC 4035', 'RFC 5011', 'RFC 5155', 'RFC 6781',
  'RFC 7344', 'RFC 8078', 'RFC 9276', 'RFC 9364', 'RFC 9499', 'RFC 9904'
];
for (const code of requiredRfcCodes) {
  assert.ok(referenciasHtml.includes(code), `falta la referencia obligatoria "${code}" en la guía de Referencias`);
}
for (const term of ['DNSSEC Algorithm Numbers', 'DS Digest Algorithms', 'DNS Root Trust Anchors']) {
  assert.ok(referenciasHtml.includes(term), `falta el registro IANA obligatorio "${term}" en la guía de Referencias`);
}
assert.ok(/rfc-editor\.org/.test(referenciasHtml), 'la guía de Referencias debe enlazar a rfc-editor.org');
assert.ok(/iana\.org/.test(referenciasHtml), 'la guía de Referencias debe enlazar a iana.org');

// Glosario: los términos obligatorios del pedido deben estar presentes.
const glosarioHtml = glosario.sections.map((s) => s.html).join(' ');
const requiredTerms = [
  'AD', 'Bogus', 'CD', 'CDNSKEY', 'CDS', 'CSK', 'Delegación segura', 'Digest',
  'DNS', 'DNSKEY', 'DNSSEC', 'DS', 'Indeterminate', 'Insecure', 'Key Tag', 'KSK',
  'NSEC3PARAM', 'NSEC3', 'NSEC', 'Resolver validador', 'Resolver', 'Rollover',
  'RRset', 'RRSIG', 'Secure', 'Trust Anchor', 'ZSK', 'Zona hija', 'Zona padre', 'Zona'
];
for (const term of requiredTerms) {
  assert.ok(
    glosarioHtml.includes('>' + term + '<'),
    `falta el término obligatorio "${term}" en el Glosario`
  );
}

// Reducción de repetición: el bloque final "Referencias relacionadas" de
// cada guía de currículo debe ser un resumen breve (no el catálogo completo
// de ~12 RFC) y debe enlazar a la página central de Referencias.
for (const guide of curriculumGuides) {
  const refsBlock = guide.sections.find((s) => s.id === 'referencias-relacionadas');
  assert.ok(refsBlock, `la guía "${guide.id}" debe tener un bloque final "referencias-relacionadas"`);
  const rfcMentions = (refsBlock.html.match(/RFC \d{4}/g) || []).length;
  assert.ok(
    rfcMentions >= 1 && rfcMentions <= 3,
    `la guía "${guide.id}" debe listar entre 1 y 3 códigos RFC relacionados, no el catálogo completo (encontrados: ${rfcMentions})`
  );
  assert.ok(
    refsBlock.html.includes('#/dnssec/aprender/referencias'),
    `la guía "${guide.id}" debe enlazar a la página central de Referencias en vez de repetir el catálogo completo`
  );
}

console.log('dnssecKb.content.test.js OK');
