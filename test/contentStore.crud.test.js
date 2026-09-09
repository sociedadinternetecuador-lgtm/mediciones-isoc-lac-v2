'use strict';

/**
 * CRUD de logic/adapters/contentStore.adapter.js contra un DATA_DIR temporal
 * y aislado (nunca toca data/content real). Cubre las 3 colecciones
 * (blog/events/materials) y, en particular, que listPublished() nunca
 * exponga un item con published:false — es la garantía central detrás del
 * split público (/content/*) vs. administrativo (/admin/api/content/*).
 *
 * Ejecutar: node test/contentStore.crud.test.js
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'mediciones-content-'));
process.env.DATA_DIR = TMP_DIR;

const store = require('../logic/adapters/contentStore.adapter');

function cleanup() {
  fs.rmSync(TMP_DIR, { recursive: true, force: true });
}

function run() {
  try {
    // ─── Crear ───────────────────────────────────────────────────────
    const blog = store.createItem('blog', { title: 'A', summary: 'a', url: 'https://x.test/a' });
    assert.ok(blog.id, 'createItem debe asignar un id');
    assert.strictEqual(blog.published, false, 'un item nuevo nace como borrador (published:false)');

    const event = store.createItem('events', { title: 'Webinar', date: '2026-09-01' });
    const material = store.createItem('materials', { title: 'Guía', description: 'd', url: 'https://x.test/g.pdf' });

    // ─── Aislamiento entre colecciones ──────────────────────────────
    assert.strictEqual(store.listAll('blog').length, 1);
    assert.strictEqual(store.listAll('events').length, 1);
    assert.strictEqual(store.listAll('materials').length, 1);

    // ─── published:false NUNCA aparece en listPublished ─────────────
    assert.deepStrictEqual(store.listPublished('blog'), [], 'borrador no debe aparecer en listPublished');

    // ─── Publicar y confirmar visibilidad ───────────────────────────
    store.updateItem('blog', blog.id, { published: true });
    const publishedBlog = store.listPublished('blog');
    assert.strictEqual(publishedBlog.length, 1);
    assert.strictEqual(publishedBlog[0].id, blog.id);

    // ─── Update no pisa el id ni el createdAt ────────────────────────
    const before = store.getItem('blog', blog.id);
    const updated = store.updateItem('blog', blog.id, { title: 'A editado' });
    assert.strictEqual(updated.id, blog.id);
    assert.strictEqual(updated.createdAt, before.createdAt);
    assert.strictEqual(updated.title, 'A editado');
    assert.ok(new Date(updated.updatedAt) >= new Date(before.updatedAt), 'updatedAt no debe retroceder tras un update');

    // ─── Volver a borrador oculta de nuevo ───────────────────────────
    store.updateItem('blog', blog.id, { published: false });
    assert.deepStrictEqual(store.listPublished('blog'), [], 'al despublicar debe desaparecer de listPublished');

    // ─── updateItem sobre id inexistente devuelve null, no lanza ────
    assert.strictEqual(store.updateItem('blog', 'no-existe', { title: 'x' }), null);

    // ─── Borrar ──────────────────────────────────────────────────────
    assert.strictEqual(store.deleteItem('events', event.id), true);
    assert.strictEqual(store.listAll('events').length, 0);
    assert.strictEqual(store.deleteItem('events', event.id), false, 'borrar dos veces el mismo id debe devolver false');

    // ─── Colección desconocida lanza, no falla en silencio ──────────
    assert.throws(() => store.createItem('no-es-un-tipo', {}), /Colección de contenido desconocida/);

    // material sigue intacto (no afectado por operaciones sobre blog/events)
    assert.strictEqual(store.listAll('materials').length, 1);
    assert.strictEqual(store.listAll('materials')[0].id, material.id);

    console.log('✅ contentStore.crud.test.js — todos los casos OK');
  } finally {
    cleanup();
  }
}

run();
