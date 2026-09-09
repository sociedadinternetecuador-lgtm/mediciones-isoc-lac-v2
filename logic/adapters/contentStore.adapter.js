'use strict';

/**
 * Content Store — Mediciones ISOC LAC
 *
 * Persistencia de contenido editorial (Blog, Eventos, Material de
 * capacitación) administrado desde el panel /admin. Mismo patrón que
 * aggregate/history.store.js: JSON por colección, sin base de datos.
 *
 * Estructura en disco:
 *   data/content/
 *     blog.json
 *     events.json
 *     materials.json
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR, 'content')
  : path.resolve(__dirname, '../../data/content');

const COLLECTIONS = new Set(['blog', 'events', 'materials']);

function ensureDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function assertCollection(type) {
  if (!COLLECTIONS.has(type)) throw new Error(`Colección de contenido desconocida: ${type}`);
}

function filePath(type) {
  return path.join(DATA_DIR, `${type}.json`);
}

function readAll(type) {
  assertCollection(type);
  ensureDir();
  try {
    return JSON.parse(fs.readFileSync(filePath(type), 'utf8'));
  } catch {
    return [];
  }
}

function writeAll(type, items) {
  assertCollection(type);
  ensureDir();
  fs.writeFileSync(filePath(type), JSON.stringify(items, null, 2));
}

// ─── Lectura pública (solo publicados) ─────────────────────────────────────

function listPublished(type) {
  return readAll(type)
    .filter((item) => item.published === true)
    .sort((a, b) => new Date(b.date || b.createdAt) - new Date(a.date || a.createdAt));
}

// ─── CRUD administrativo (todo, incluyendo borradores) ─────────────────────

function listAll(type) {
  return readAll(type).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

function getItem(type, id) {
  return readAll(type).find((item) => item.id === id) || null;
}

function createItem(type, data) {
  const items = readAll(type);
  const now = new Date().toISOString();
  const item = {
    id: crypto.randomUUID(),
    createdAt: now,
    updatedAt: now,
    published: false,
    ...data,
  };
  items.push(item);
  writeAll(type, items);
  return item;
}

function updateItem(type, id, patch) {
  const items = readAll(type);
  const idx = items.findIndex((item) => item.id === id);
  if (idx === -1) return null;
  items[idx] = { ...items[idx], ...patch, id, updatedAt: new Date().toISOString() };
  writeAll(type, items);
  return items[idx];
}

function deleteItem(type, id) {
  const items = readAll(type);
  const next = items.filter((item) => item.id !== id);
  if (next.length === items.length) return false;
  writeAll(type, next);
  return true;
}

module.exports = {
  listPublished,
  listAll,
  getItem,
  createItem,
  updateItem,
  deleteItem,
};
