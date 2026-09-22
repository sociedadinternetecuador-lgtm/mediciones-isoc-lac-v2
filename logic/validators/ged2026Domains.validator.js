'use strict';

/**
 * Normalización de un dominio individual para GED2026.
 *
 * Reutiliza la metodología CERRADA de logic/validators/datasetDomains.validator.js
 * (ver CLAUDE.md, reglas 1-2) — no reimplementa normalización, IDNA ni
 * clasificación de sufijo. La única razón de que exista este archivo es que
 * datasetDomains.validator.js fue diseñado para un dataset de un solo ccTLD
 * a la vez (`staticValid(domain, tld)` con un único `tld` fijo), mientras
 * que el universo GED2026 mezcla .gob.ec/.com.ec/.edu.ec/.org.ec/etc. Para
 * no bifurcar la metodología, se deriva primero el sufijo propio de CADA
 * dominio con logic/adapters/publicSuffixList.adapter.js (el mismo adaptador
 * que ya usa la Preparación de datasets) y ese sufijo se pasa tal cual a
 * staticValid() — el algoritmo que corre es exactamente el mismo, solo que
 * aplicado dominio por dominio en vez de sobre un texto de un único ccTLD.
 *
 * Además, a diferencia de la Preparación de datasets (que asume un dominio
 * "pelado" por línea), la importación de GED2026 admite que el admin pegue
 * URLs completas (sección 5 del pedido: quitar protocolo, ruta, barra
 * final). Eso NO es parte de la normalización cerrada — es un paso previo,
 * propio de este módulo, que reduce una URL a su hostname ANTES de entrar
 * al pipeline frozen. `www.` se preserva tal cual venga (no se recorta):
 * decidir si www.x.ec y x.ec son "el mismo" dominio es una decisión de
 * curación editorial, no algo que este normalizador deba asumir en
 * silencio — ver docs/ged2026.md.
 */

const { normalizeDomainLine, staticValid } = require('./datasetDomains.validator');
const { getPublicSuffixList } = require('../adapters/publicSuffixList.adapter');

function extractHostname(rawField) {
  let s = String(rawField || '').trim();
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, ''); // protocolo (http://, https://, ...)
  s = s.split(/[/?#]/)[0]; // ruta/query/fragment
  s = s.replace(/^[^@]*@/, ''); // credenciales tipo user:pass@
  s = s.replace(/:\d+$/, ''); // puerto explícito
  return s;
}

async function normalizeCandidateDomain(rawField) {
  const raw = extractHostname(rawField);
  const normalized = normalizeDomainLine(raw);
  if (!normalized) return { ok: false, reason: 'empty' };

  const { psl } = await getPublicSuffixList();
  const suffix = psl.publicSuffix(normalized);
  const result = staticValid(normalized, suffix);
  if (!result.ok) return { ok: false, reason: result.reason };

  return { ok: true, normalized_domain: result.ascii, suffix };
}

module.exports = { normalizeCandidateDomain };
