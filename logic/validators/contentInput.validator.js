'use strict';

/**
 * Validación de payloads de contenido editorial (Blog, Eventos, Materiales)
 * antes de persistir con contentStore.adapter. Longitudes máximas explícitas
 * en todo campo de texto — regla de seguridad del proyecto.
 */

const MAX_TITLE = 200;
const MAX_SHORT_TEXT = 500;
const MAX_LONG_TEXT = 2000;
const MAX_URL = 2000;
const MAX_CATEGORY = 60;

function isValidHttpUrl(value) {
  try {
    const u = new URL(value);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

function str(value, max) {
  const s = typeof value === 'string' ? value.trim() : '';
  return s.slice(0, max);
}

const SCHEMAS = {
  blog: (body) => {
    const errors = [];
    const title = str(body.title, MAX_TITLE);
    const summary = str(body.summary, MAX_SHORT_TEXT);
    const url = str(body.url, MAX_URL);
    const date = str(body.date, 40);
    const category = str(body.category, MAX_CATEGORY);

    if (!title) errors.push('title_required');
    if (!summary) errors.push('summary_required');
    if (!url) errors.push('url_required');
    else if (!isValidHttpUrl(url)) errors.push('url_invalid');

    return { errors, data: { title, summary, url, date: date || new Date().toISOString(), category } };
  },

  events: (body) => {
    const errors = [];
    const title = str(body.title, MAX_TITLE);
    const date = str(body.date, 40);
    const type = str(body.type, MAX_CATEGORY);
    const description = str(body.description, MAX_LONG_TEXT);
    const url = str(body.url, MAX_URL);

    if (!title) errors.push('title_required');
    if (url && !isValidHttpUrl(url)) errors.push('url_invalid');

    return { errors, data: { title, date, type, description, url } };
  },

  materials: (body) => {
    const errors = [];
    const title = str(body.title, MAX_TITLE);
    const description = str(body.description, MAX_LONG_TEXT);
    const url = str(body.url, MAX_URL);
    const category = str(body.category, MAX_CATEGORY);

    if (!title) errors.push('title_required');
    if (!description) errors.push('description_required');
    if (!url) errors.push('url_required');
    else if (!isValidHttpUrl(url)) errors.push('url_invalid');

    return { errors, data: { title, description, url, category } };
  },
};

function validateContentInput(type, body) {
  const schema = SCHEMAS[type];
  if (!schema) return { errors: ['unknown_type'], data: null };
  const { errors, data } = schema(body || {});
  return { errors, data: errors.length ? null : data };
}

module.exports = { validateContentInput };
