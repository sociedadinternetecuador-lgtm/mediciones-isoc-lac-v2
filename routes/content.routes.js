'use strict';

/**
 * Rutas públicas de contenido editorial — Mediciones ISOC LAC.
 *
 *  GET /content/blog
 *  GET /content/events
 *  GET /content/materials
 *    Devuelven solo los items con published:true, más recientes primero.
 *    Sin autenticación — el contenido en borrador nunca se expone aquí
 *    (eso vive exclusivamente bajo /admin/api/*).
 */

const { listPublished } = require('../logic/adapters/contentStore.adapter');

const TYPES = new Set(['blog', 'events', 'materials']);

function sendJson(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}

function handleContentRequest(req, res, parsed) {
  const segments = parsed.pathname.split('/').filter(Boolean); // ['content', type]
  const type = segments[1];

  if (req.method !== 'GET') {
    return sendJson(res, 405, { error: 'method_not_allowed' });
  }
  if (!TYPES.has(type)) {
    return sendJson(res, 404, { error: 'not_found' });
  }

  const items = listPublished(type).map(({ published, ...rest }) => rest);
  return sendJson(res, 200, { items });
}

module.exports = { handleContentRequest };
