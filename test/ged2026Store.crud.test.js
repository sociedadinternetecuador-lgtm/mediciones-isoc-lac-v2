'use strict';

/**
 * CRUD de logic/adapters/ged2026Store.adapter.js contra un DATA_DIR temporal
 * y aislado (nunca toca data/ged2026 real). Mismo patrón que
 * test/contentStore.crud.test.js.
 *
 * Ejecutar: node test/ged2026Store.crud.test.js
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'mediciones-ged2026-'));
process.env.DATA_DIR = TMP_DIR;

const store = require('../logic/adapters/ged2026Store.adapter');

function cleanup() {
  fs.rmSync(TMP_DIR, { recursive: true, force: true });
}

function run() {
  try {
    // ─── Proyecto se autoinicializa sin archivo previo ──────────────
    const project = store.getProject();
    assert.strictEqual(project.current_phase, 'planning');
    assert.strictEqual(project.last_updated, null);

    assert.throws(() => store.setProjectPhase('fase_inventada'), /Fase de proyecto desconocida/);

    // ─── Crear dominio con defaults completos ───────────────────────
    const d1 = store.createDomain({ domain: 'Ejemplo.COM.EC', normalized_domain: 'ejemplo.com.ec' });
    assert.ok(d1.id, 'createDomain debe asignar un id');
    assert.strictEqual(d1.estado_seleccion, 'candidate');
    assert.strictEqual(d1.estado_validacion, 'unknown');
    assert.strictEqual(d1.activo, true);
    assert.strictEqual(d1.exclusion_reason, null);
    assert.deepStrictEqual(d1.atributos_relevancia, {
      traffic_source: null, traffic_rank: null, traffic_score: null,
      transactionality_level: null, institutional_relevance: null,
      user_reach: null, critical_service: null,
    });
    assert.ok(d1.created_at && d1.updated_at, 'debe traer created_at/updated_at');

    // ─── setProjectPhase / cambios de dominio actualizan last_updated ──
    const projectAfterCreate = store.getProject();
    assert.ok(projectAfterCreate.last_updated, 'crear un dominio debe actualizar last_updated del proyecto');

    // ─── listDomains / getDomain / findByNormalizedDomain ───────────
    assert.strictEqual(store.listDomains().length, 1);
    assert.strictEqual(store.getDomain(d1.id).id, d1.id);
    assert.strictEqual(store.getDomain('no-existe'), null);
    assert.strictEqual(store.findByNormalizedDomain('ejemplo.com.ec').id, d1.id);
    assert.strictEqual(store.findByNormalizedDomain('otro.ec'), null);

    // ─── updateDomain no pisa id/created_at, sí actualiza updated_at ───
    const before = store.getDomain(d1.id);
    const updated = store.updateDomain(d1.id, { categoria: 'gob.ec', estado_seleccion: 'validated' });
    assert.strictEqual(updated.id, d1.id);
    assert.strictEqual(updated.created_at, before.created_at);
    assert.strictEqual(updated.categoria, 'gob.ec');
    assert.strictEqual(updated.estado_seleccion, 'validated');
    assert.ok(new Date(updated.updated_at) >= new Date(before.updated_at));

    // ─── update parcial de atributos_relevancia hace merge, no reemplaza ──
    store.updateDomain(d1.id, { atributos_relevancia: { traffic_rank: { value: 10, method: 'medido' } } });
    const withAttr = store.getDomain(d1.id);
    assert.deepStrictEqual(withAttr.atributos_relevancia.traffic_rank, { value: 10, method: 'medido' });
    assert.strictEqual(withAttr.atributos_relevancia.traffic_source, null, 'un merge parcial no debe borrar otros atributos');

    // ─── updateDomain sobre id inexistente devuelve null ────────────
    assert.strictEqual(store.updateDomain('no-existe', { categoria: 'x' }), null);

    console.log('✅ ged2026Store.crud.test.js — todos los casos OK');
  } finally {
    cleanup();
  }
}

run();
