'use strict';

/**
 * Ruta pública GED2026 — Global Encryption Day Ecuador 2026.
 *
 *  GET /ged2026/api/v1/summary
 *    Único endpoint público de este módulo. Devuelve SOLO indicadores
 *    agregados (nunca dominios individuales, notas ni motivos de
 *    exclusión) — contrato completo en docs/ged2026-api.md.
 *
 * El futuro portal informativo (repositorio ISOC-EC-WEB, fuera de este
 * proyecto) deberá consumir EXCLUSIVAMENTE esta ruta — nunca leer
 * data/ged2026/*.json directamente ni duplicar el cálculo de estos
 * indicadores. Ver sección 22-23 del pedido: portal = solicitar/recibir/
 * mostrar, nunca recalcular.
 *
 * Prefijo /api/v1 (en vez de /ged2026/summary a secas, que sería más
 * consistente con /content/:type) elegido deliberadamente porque este
 * endpoint SÍ tiene un consumidor externo real (un repositorio distinto),
 * a diferencia de /content/:type que solo consume el propio frontend de
 * este servidor — un consumidor externo necesita la garantía de
 * estabilidad que da versionar la ruta. Ver docs/ged2026-api.md.
 *
 * CORS: este es el único módulo del proyecto pensado para ser consumido
 * por un origen DISTINTO (isoc.org.ec) desde el navegador — verificado
 * empíricamente (curl con `Origin: https://isoc.org.ec`) que, sin esta
 * cabecera, la respuesta no traía ningún `Access-Control-Allow-Origin` y
 * el navegador habría bloqueado el fetch() del portal. Origen fijo
 * configurable por variable de entorno, nunca wildcard `*` en producción
 * (regla de seguridad del proyecto) — mismo patrón que
 * `SUPER_ADMIN_RECOVERY_EMAIL` en admin.routes.js.
 */

const { listDomains, getProject } = require('../logic/adapters/ged2026Store.adapter');
const { ESTADOS_SELECCION } = require('../config/ged2026.constants');

const PORTAL_ORIGIN = process.env.GED2026_PORTAL_ORIGIN || 'https://isoc.org.ec';

function sendJson(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': PORTAL_ORIGIN,
  });
  res.end(JSON.stringify(data));
}

function computePublicSummary() {
  const domains = listDomains();
  const project = getProject();

  const counts_by_estado_seleccion = Object.fromEntries(ESTADOS_SELECCION.map((s) => [s, 0]));
  let active_domains = 0;
  for (const d of domains) {
    counts_by_estado_seleccion[d.estado_seleccion] = (counts_by_estado_seleccion[d.estado_seleccion] || 0) + 1;
    if (d.activo) active_domains += 1;
  }

  return {
    project: 'GED Ecuador 2026',
    project_phase: project.current_phase,
    updated_at: project.last_updated,
    total_domains: domains.length,
    active_domains,
    counts_by_estado_seleccion,
  };
}

function handleGed2026Request(req, res, parsed) {
  const segments = parsed.pathname.split('/').filter(Boolean); // ['ged2026','api','v1','summary']

  if (req.method !== 'GET') {
    return sendJson(res, 405, { error: 'method_not_allowed' });
  }
  if (segments[1] === 'api' && segments[2] === 'v1' && segments[3] === 'summary') {
    return sendJson(res, 200, computePublicSummary());
  }
  return sendJson(res, 404, { error: 'not_found' });
}

module.exports = { handleGed2026Request };
