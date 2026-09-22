'use strict';

/**
 * Validación de forma de los campos de un dominio GED2026 (no de red, no de
 * normalización — eso es logic/validators/ged2026Domains.validator.js).
 * Mismo estilo que logic/validators/contentInput.validator.js: {errors, data}.
 *
 * No valida `domain`/`normalized_domain` — esos los calcula la ruta llamando
 * a normalizeCandidateDomain() antes de invocar este validador.
 */

const {
  ESTADOS_SELECCION, ESTADOS_VALIDACION, EXCLUSION_REASONS,
  ATRIBUTO_METODOS, ATRIBUTOS_RELEVANCIA_FIELDS,
} = require('../../config/ged2026.constants');

const MAX_SHORT = 120;
const MAX_NOTES = 2000;

function str(value, max) {
  const s = typeof value === 'string' ? value.trim() : '';
  return s.slice(0, max);
}

function validateAtributosRelevancia(input, errors) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    errors.push('atributos_relevancia_invalid');
    return undefined;
  }
  const out = {};
  for (const key of Object.keys(input)) {
    if (!ATRIBUTOS_RELEVANCIA_FIELDS.includes(key)) {
      errors.push(`atributos_relevancia_unknown_field:${key}`);
      continue;
    }
    const entry = input[key];
    if (entry === null) { out[key] = null; continue; }
    if (typeof entry !== 'object' || Array.isArray(entry)) {
      errors.push(`atributos_relevancia_shape:${key}`);
      continue;
    }
    const method = entry.method;
    if (method !== undefined && method !== null && !ATRIBUTO_METODOS.includes(method)) {
      errors.push(`atributos_relevancia_method_invalid:${key}`);
      continue;
    }
    out[key] = { value: entry.value ?? null, method: method || 'no_disponible' };
  }
  return out;
}

// Campos presentes en `body` se validan/normalizan; campos ausentes se
// omiten de `data` (así un PUT parcial no pisa lo que no vino en el patch).
function validateBaseFields(body, errors) {
  const data = {};

  if (body.categoria !== undefined) data.categoria = str(body.categoria, MAX_SHORT) || null;
  if (body.tipo_institucion !== undefined) data.tipo_institucion = str(body.tipo_institucion, MAX_SHORT) || null;
  if (body.fuente !== undefined) data.fuente = str(body.fuente, MAX_SHORT) || null;
  if (body.notas !== undefined) data.notas = str(body.notas, MAX_NOTES) || null;
  if (body.activo !== undefined) data.activo = body.activo === true || body.activo === 'true';

  if (body.estado_seleccion !== undefined) {
    if (!ESTADOS_SELECCION.includes(body.estado_seleccion)) errors.push('estado_seleccion_invalid');
    else data.estado_seleccion = body.estado_seleccion;
  }

  if (body.estado_validacion !== undefined) {
    if (!ESTADOS_VALIDACION.includes(body.estado_validacion)) errors.push('estado_validacion_invalid');
    else data.estado_validacion = body.estado_validacion;
  }

  if (body.exclusion_reason !== undefined) {
    if (body.exclusion_reason !== null && !EXCLUSION_REASONS.includes(body.exclusion_reason)) {
      errors.push('exclusion_reason_invalid');
    } else {
      data.exclusion_reason = body.exclusion_reason;
    }
  }

  if (body.atributos_relevancia !== undefined) {
    const before = errors.length;
    const value = validateAtributosRelevancia(body.atributos_relevancia, errors);
    if (errors.length === before) data.atributos_relevancia = value;
  }

  return data;
}

// Alta manual (POST /admin/api/ged2026/domains). El dominio en sí ya fue
// normalizado/validado por separado — este validador solo cubre el resto
// de los campos del cuerpo.
function validateGed2026DomainCreate(body) {
  const errors = [];
  const data = validateBaseFields(body || {}, errors);
  const estadoSeleccion = data.estado_seleccion || 'candidate';
  if (estadoSeleccion === 'excluded' && !data.exclusion_reason) {
    errors.push('exclusion_reason_required');
  }
  return { errors, data: errors.length ? null : data };
}

// Edición (PUT /admin/api/ged2026/domains/:id) — la regla "excluded exige
// exclusion_reason" se evalúa contra el estado FINAL (patch fusionado sobre
// lo existente), no solo contra lo que vino en este PUT puntual.
function validateGed2026DomainUpdate(existing, patch) {
  const errors = [];
  const data = validateBaseFields(patch || {}, errors);
  const finalEstadoSeleccion = data.estado_seleccion || existing.estado_seleccion;
  const finalExclusionReason = 'exclusion_reason' in data ? data.exclusion_reason : existing.exclusion_reason;
  if (finalEstadoSeleccion === 'excluded' && !finalExclusionReason) {
    errors.push('exclusion_reason_required');
  }
  return { errors, data: errors.length ? null : data };
}

module.exports = { validateGed2026DomainCreate, validateGed2026DomainUpdate };
