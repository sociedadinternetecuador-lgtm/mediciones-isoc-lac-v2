'use strict';

/**
 * Region Aggregator — Módulo Agregado DNSSEC ISOC LAC
 *
 * Compara resultados agregados de múltiples países de LAC
 * y produce:
 *  - Ranking regional por adopción DNSSEC
 *  - Distribución de semáforos (verde/amarillo/rojo) en la región
 *  - Clasificación de perfiles de país dominantes
 *  - Métricas regionales consolidadas
 *  - Panorama de barreras a nivel regional
 */

function aggregateRegion(countryAggregates) {
  if (!Array.isArray(countryAggregates) || countryAggregates.length === 0) {
    return null;
  }

  const valid = countryAggregates.filter(c => c && c.country && c.adoption);

  // Ranking por tasa de adopción (de mayor a menor)
  const ranking = [...valid]
    .filter(c => c.adoption.rate !== null)
    .sort((a, b) => b.adoption.rate - a.adoption.rate)
    .map((c, i) => ({
      rank: i + 1,
      country: c.country,
      adoption_pct: c.adoption.rate,
      semaphore: c.semaphore.color,
      profile: c.country_profile,
      dominant_barrier: c.summary.dominant_barrier
    }));

  // Distribución de semáforos en la región
  const semaphoreDistribution = { green: 0, yellow: 0, red: 0, unknown: 0 };
  for (const c of valid) {
    const color = c.semaphore?.color;
    if (color && semaphoreDistribution[color] !== undefined) {
      semaphoreDistribution[color]++;
    } else {
      semaphoreDistribution.unknown++;
    }
  }

  // Distribución de perfiles
  const profileDistribution = {};
  for (const c of valid) {
    const p = c.country_profile || 'unknown';
    profileDistribution[p] = (profileDistribution[p] || 0) + 1;
  }

  // Métricas regionales
  const ratesAvailable = valid.filter(c => c.adoption.rate !== null);
  const regionalAdoption = ratesAvailable.length > 0
    ? Math.round(
        ratesAvailable.reduce((sum, c) => sum + c.adoption.rate, 0) / ratesAvailable.length * 10
      ) / 10
    : null;

  const totalDomains = valid.reduce((sum, c) => sum + (c.total_domains || 0), 0);
  const totalAdopted = valid.reduce((sum, c) => sum + (c.adoption.adopted || 0), 0);
  const totalEligible = valid.reduce((sum, c) => sum + (c.adoption.eligible || 0), 0);

  // Barreras a nivel regional
  const regionalBarriers = {
    structural: valid.reduce((sum, c) => sum + (c.barriers.structural || 0), 0),
    actionable: valid.reduce((sum, c) => sum + (c.barriers.actionable || 0), 0),
    tld_blocked_countries: valid.filter(c => c.barriers.tld_blocked > 0).map(c => c.country),
    misconfigured_total: valid.reduce((sum, c) => sum + (c.barriers.misconfigured || 0), 0)
  };

  // Semáforo regional: basado en el promedio de adopción regional
  let regionalSemaphore;
  if (regionalAdoption === null) {
    regionalSemaphore = { color: 'unknown', label: 'sin datos suficientes' };
  } else if (regionalAdoption >= 40) {
    regionalSemaphore = { color: 'green', label: 'adopción regional sólida' };
  } else if (regionalAdoption >= 10) {
    regionalSemaphore = { color: 'yellow', label: 'adopción regional parcial' };
  } else {
    regionalSemaphore = { color: 'red', label: 'adopción regional crítica' };
  }

  return {
    region: 'LAC',
    analyzed_at: new Date().toISOString(),
    countries_analyzed: valid.length,
    total_domains_analyzed: totalDomains,
    regional_adoption: {
      average_pct: regionalAdoption,
      total_adopted: totalAdopted,
      total_eligible: totalEligible,
      aggregate_rate: totalEligible > 0
        ? Math.round((totalAdopted / totalEligible) * 100 * 10) / 10
        : null
    },
    semaphore: regionalSemaphore,
    semaphore_distribution: semaphoreDistribution,
    profile_distribution: profileDistribution,
    barriers: regionalBarriers,
    ranking,
    // Líderes y rezagados
    leaders: ranking.slice(0, 3),
    laggards: ranking.slice(-3).reverse()
  };
}

module.exports = { aggregateRegion };
