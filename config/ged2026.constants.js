'use strict';

/**
 * Constantes GED2026 — Global Encryption Day Ecuador 2026.
 *
 * Mismo rol que config/dnssec.constants.js: enumeraciones compartidas entre
 * el store, los validadores y las rutas. Ver docs/ged2026.md.
 */

// Estados del ciclo de vida de un dominio dentro de la muestra GED2026.
const ESTADOS_SELECCION = ['candidate', 'validated', 'eligible', 'shortlisted', 'selected', 'excluded'];

// Resultado del chequeo de actividad (DNS + HTTP/HTTPS) — logic/adapters/ged2026Liveness.adapter.js.
const ESTADOS_VALIDACION = [
  'dns_ok', 'http_ok', 'https_ok', 'redirect', 'timeout',
  'dns_error', 'tls_error', 'inactive', 'unknown',
];

// Fase general del proyecto (data/ged2026/project.json).
const PROJECT_PHASES = [
  'planning', 'dataset_collection', 'dataset_validation', 'dataset_analysis',
  'sample_selection', 'pilot', 'measurement', 'analysis', 'published',
];

// Motivo obligatorio cuando estado_seleccion pasa a 'excluded'.
const EXCLUSION_REASONS = [
  'inactive', 'duplicate', 'not_relevant', 'insufficient_information',
  'sampling_balance', 'technical_issue', 'other',
];

// Procedencia de cada atributo de relevancia — sección 8 del pedido.
const ATRIBUTO_METODOS = ['medido', 'estimado', 'clasificado_manual', 'no_disponible'];

// Clasificación simple de transaccionalidad — sección 9 del pedido.
const TRANSACTIONALITY_LEVELS = ['informativo', 'interactivo', 'transaccional', 'critico'];

// Catálogo SUGERIDO para tipo_institucion — a propósito NO es una
// enumeración rígida (sección 7 del pedido): el validador no rechaza un
// valor fuera de esta lista, es solo la referencia para el <select> del
// panel admin.
const TIPO_INSTITUCION_CATALOG = [
  'gobierno', 'empresa', 'universidad', 'organizacion_sociedad_civil',
  'servicio_financiero', 'telecomunicaciones', 'comercio', 'medios',
  'servicios_publicos', 'otros',
];

// Claves admitidas dentro de atributos_relevancia (sección 8 del pedido).
const ATRIBUTOS_RELEVANCIA_FIELDS = [
  'traffic_source', 'traffic_rank', 'traffic_score', 'transactionality_level',
  'institutional_relevance', 'user_reach', 'critical_service',
];

module.exports = {
  ESTADOS_SELECCION,
  ESTADOS_VALIDACION,
  PROJECT_PHASES,
  EXCLUSION_REASONS,
  ATRIBUTO_METODOS,
  TRANSACTIONALITY_LEVELS,
  TIPO_INSTITUCION_CATALOG,
  ATRIBUTOS_RELEVANCIA_FIELDS,
};
