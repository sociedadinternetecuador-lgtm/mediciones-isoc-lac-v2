'use strict';

/**
 * Country Aggregator — Módulo Agregado DNSSEC ISOC LAC
 *
 * Toma los resultados individuales del análisis batch
 * y produce métricas agregadas por país:
 *
 *  - Distribución de estados DNSSEC (7 estados del modelo)
 *  - Tasa de adopción real (ok / universo elegible)
 *  - Clasificación de barreras (estructurales vs accionables)
 *  - Semáforo de madurez (verde / amarillo / rojo) con criterios explícitos
 *  - Resumen para política pública
 */

const STATUS = {
  OK:               'ok',
  NOT_IMPLEMENTED:  'not_implemented',
  MISCONFIGURED:    'misconfigured',
  BLOCKED_AT_TLD:   'blocked_at_tld',
  BLOCKED_AT_PARENT:'blocked_at_parent',
  INDETERMINATE:    'indeterminate',
  NON_EXISTENT:     'non_existent'
};

// Qué tipo de barrera representa cada estado
const BARRIER_TYPE = {
  [STATUS.OK]:                'none',
  [STATUS.NOT_IMPLEMENTED]:   'actionable',   // el operador puede actuar
  [STATUS.MISCONFIGURED]:     'actionable',   // requiere corrección técnica
  [STATUS.BLOCKED_AT_TLD]:    'structural',   // requiere acción de registry/TLD
  [STATUS.BLOCKED_AT_PARENT]: 'structural',   // requiere acción en capa intermedia
  [STATUS.INDETERMINATE]:     'unknown',
  [STATUS.NON_EXISTENT]:      'non_applicable'
};

// Criterios del semáforo de madurez DNSSEC LAC
// Calibrados para el contexto regional (adopción promedio LAC < 15%)
const SEMAPHORE_CRITERIA = {
  green: {
    label: 'verde',
    description: 'Adopción sólida, sin barreras estructurales dominantes',
    conditions: 'adopción ≥ 40% y barreras estructurales < 20%'
  },
  yellow: {
    label: 'amarillo',
    description: 'Adopción parcial o barreras mixtas que requieren atención',
    conditions: 'adopción 10–39% o barreras estructurales 20–60%'
  },
  red: {
    label: 'rojo',
    description: 'Adopción crítica o bloqueo estructural dominante',
    conditions: 'adopción < 10% o barreras estructurales > 60%'
  }
};

function countByStatus(results) {
  const counts = Object.fromEntries(Object.values(STATUS).map(s => [s, 0]));
  for (const r of results) {
    const status = r?.dnssec?.final_status;
    if (status && counts[status] !== undefined) counts[status]++;
    else counts[STATUS.INDETERMINATE]++;
  }
  return counts;
}

function computeAdoptionRate(counts) {
  // Universo elegible: excluimos non_existent e indeterminate del denominador
  // porque no son dominios que puedan adoptar DNSSEC en este momento
  const eligible = counts[STATUS.OK]
    + counts[STATUS.NOT_IMPLEMENTED]
    + counts[STATUS.MISCONFIGURED]
    + counts[STATUS.BLOCKED_AT_TLD]
    + counts[STATUS.BLOCKED_AT_PARENT];

  if (eligible === 0) return { rate: null, eligible: 0, adopted: 0 };

  const adopted = counts[STATUS.OK];
  return {
    rate: Math.round((adopted / eligible) * 100 * 10) / 10,
    eligible,
    adopted
  };
}

function classifyBarriers(counts) {
  const structural = counts[STATUS.BLOCKED_AT_TLD] + counts[STATUS.BLOCKED_AT_PARENT];
  const actionable = counts[STATUS.NOT_IMPLEMENTED] + counts[STATUS.MISCONFIGURED];
  const none = counts[STATUS.OK];
  const unknown = counts[STATUS.INDETERMINATE];
  const non_applicable = counts[STATUS.NON_EXISTENT];
  const total = structural + actionable + none + unknown + non_applicable;

  return {
    structural,
    actionable,
    none,
    unknown,
    non_applicable,
    structural_pct: total > 0 ? Math.round((structural / total) * 100 * 10) / 10 : 0,
    actionable_pct: total > 0 ? Math.round((actionable / total) * 100 * 10) / 10 : 0,
    // Detalle de barreras estructurales
    tld_blocked: counts[STATUS.BLOCKED_AT_TLD],
    parent_blocked: counts[STATUS.BLOCKED_AT_PARENT],
    // Detalle de barreras accionables
    not_implemented: counts[STATUS.NOT_IMPLEMENTED],
    misconfigured: counts[STATUS.MISCONFIGURED]
  };
}

function computeSemaphore(adoptionRate, barriers) {
  const rate = adoptionRate.rate ?? 0;
  const structuralPct = barriers.structural_pct;

  if (rate >= 40 && structuralPct < 20) {
    return { color: 'green', ...SEMAPHORE_CRITERIA.green };
  }

  if (rate >= 10 && structuralPct <= 60) {
    return { color: 'yellow', ...SEMAPHORE_CRITERIA.yellow };
  }

  return { color: 'red', ...SEMAPHORE_CRITERIA.red };
}

function inferCountryProfile(semaphore, barriers, adoptionRate) {
  // Perfiles para recomendaciones diferenciadas de política pública
  if (barriers.tld_blocked > (barriers.actionable + barriers.structural * 0.5)) {
    return 'tld_blocked';
  }
  if (semaphore.color === 'green') {
    return 'leader';
  }
  if (adoptionRate.rate !== null && adoptionRate.rate < 5 && barriers.actionable > barriers.structural) {
    return 'low_capacity';
  }
  if (barriers.actionable >= barriers.structural && semaphore.color !== 'green') {
    return 'ready_to_adopt';
  }
  return 'mixed';
}

function buildConfidenceSummary(results, errors) {
  const high   = results.filter(r => r?.dnssec?.assessment_meta?.confidence === 'high').length;
  const medium = results.filter(r => r?.dnssec?.assessment_meta?.confidence === 'medium').length;
  const low    = results.filter(r => r?.dnssec?.assessment_meta?.confidence === 'low').length;
  const total  = results.length;

  return {
    high,
    medium,
    low,
    error_count: errors.length,
    total_analyzed: total,
    reliability: total > 0
      ? (high >= total * 0.7 ? 'alta' : high + medium >= total * 0.7 ? 'media' : 'baja')
      : 'sin_datos'
  };
}

function aggregateCountry({ country, results, errors = [], meta = {} }) {
  const counts = countByStatus(results);
  const adoptionRate = computeAdoptionRate(counts);
  const barriers = classifyBarriers(counts);
  const semaphore = computeSemaphore(adoptionRate, barriers);
  const profile = inferCountryProfile(semaphore, barriers, adoptionRate);
  const confidence = buildConfidenceSummary(results, errors);

  return {
    country,
    analyzed_at: new Date().toISOString(),
    meta,
    total_domains: results.length + errors.length,
    status_distribution: counts,
    adoption: adoptionRate,
    barriers,
    semaphore,
    country_profile: profile,
    confidence,
    // Vista rápida para dashboards y comparaciones regionales
    summary: {
      adoption_pct: adoptionRate.rate,
      semaphore_color: semaphore.color,
      dominant_barrier: barriers.structural > barriers.actionable ? 'structural' : 'actionable',
      profile
    }
  };
}

module.exports = { aggregateCountry, STATUS, BARRIER_TYPE, SEMAPHORE_CRITERIA };
