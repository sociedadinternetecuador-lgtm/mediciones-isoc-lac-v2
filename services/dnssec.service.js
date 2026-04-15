const { buildZoneChain } = require("../logic/builders/zoneChain.builder");
const { buildDelegationsFromZones } = require("../logic/builders/delegation.builder");
const {
  DNSSEC_ZONE_STATUS,
  DNSSEC_DELEGATION_STATUS
} = require("../config/dnssec.constants");
const {
  queryDnskey,
  queryDs,
  queryNameExistence,
  QUERY_TIMEOUT_MS
} = require("../logic/adapters/dns/realDns.adapter");

function mapZoneStatus(found, queryStatus) {
  if (found === true) return DNSSEC_ZONE_STATUS.SIGNED;
  if (found === false && queryStatus === "no_data") return DNSSEC_ZONE_STATUS.UNSIGNED;

  // SERVFAIL en una zona hija no debe mezclarse con no existencia.
  // Lo dejamos como UNKNOWN a nivel de constantes actuales,
  // pero agregamos metadata adicional para que reglas posteriores
  // puedan interpretarlo como fallo DNSSEC.
  if (queryStatus === "servfail") return DNSSEC_ZONE_STATUS.UNKNOWN;

  return DNSSEC_ZONE_STATUS.UNKNOWN;
}

function mapDelegationStatus(secure, dsPresent, queryStatus) {
  if (secure === true) return DNSSEC_DELEGATION_STATUS.SECURE;
  if (dsPresent === false && queryStatus === "no_data") return DNSSEC_DELEGATION_STATUS.INSECURE;
  if (dsPresent === true && secure === false) return DNSSEC_DELEGATION_STATUS.BROKEN;
  return DNSSEC_DELEGATION_STATUS.UNKNOWN;
}

/**
 * ISOC LAC DNSSEC Measurement Model
 *
 * Indicador: Nivel de certeza del resultado
 *
 * Este indicador mide qué tan confiable es la interpretación generada por el sistema
 * a partir de la evidencia estructural observable en DNS.
 *
 * NO mide el estado del dominio directamente ni reemplaza una validación criptográfica
 * completa con resolvers validadores.
 *
 * Reglas:
 *
 * - Alta:
 *   Evidencia consistente o patrón técnico claro.
 *   Incluye detección de fallo DNSSEC (SERVFAIL + DS presente + validation_problem).
 *
 * - Media:
 *   Evidencia parcial o con limitaciones, pero interpretable.
 *
 * - Baja:
 *   Evidencia insuficiente o afectada por problemas operativos
 *   (timeout, network_error, invalid_response).
 *
 * Nota: network_error e invalid_response se tratan igual que timeout
 * porque implican ausencia total de datos confiables.
 *
 * Regla crítica DNSSEC:
 * SERVFAIL en presencia de DS NO se interpreta como error genérico,
 * sino como evidencia fuerte de fallo de validación DNSSEC.
 *
 * Este criterio forma parte del modelo de medición DNSSEC ISOC LAC.
 */
function computeConfidence(zones, delegations, nameExistence) {
  const zoneStatuses = zones.map((z) => z.query_status);
  const delegationStatuses = delegations.map((d) => d.query_status);
  const allStatuses = [...zoneStatuses, ...delegationStatuses, nameExistence?.query_status].filter(Boolean);

  const timeoutCount = allStatuses.filter((s) => s === "timeout").length;

  const dnssecFailureDetected =
    zones.some((z) => z.validation_problem === "dnssec_validation_failure") ||
    nameExistence?.error_cause === "dnssec_validation_failure";

  // Timeout real o degradación operativa fuerte (sin datos fiables)
  const hardDegradationCount = allStatuses.filter((s) =>
    ["timeout", "invalid_response", "network_error"].includes(s)
  ).length;

  if (hardDegradationCount > 0) {
    return "low";
  }

  // Fallo DNSSEC detectado de forma consistente
  if (dnssecFailureDetected) {
    return "high";
  }

  // Errores de consulta moderados (SERVFAIL sin contexto DNSSEC claro)
  const errorCount = allStatuses.filter((s) =>
    ["error"].includes(s)
  ).length;

  if (errorCount > 0) {
    return "medium";
  }

  const unknownCount =
    zones.filter((z) => z.status === "unknown").length +
    delegations.filter((d) => d.status === "unknown").length;

  if (unknownCount > 0) {
    return "medium";
  }

  return "high";
}

function buildAssessmentMeta(confidence) {
  return {
    assessment_scope: "dnssec_structural_real",
    confidence,
    query_timeout_ms: QUERY_TIMEOUT_MS,
    limitations: [
      "Este análisis verifica evidencia estructural observable en DNS, no una validación criptográfica completa.",
      "La cadena de confianza se verifica desde el TLD, sin incluir la zona raíz ('.'). Se asume implícitamente que el TLD es confiable.",
      "La ausencia de DNSKEY o DS no siempre equivale por sí sola a una falla definitiva; puede requerir análisis más profundo.",
      "Timeouts, SERVFAIL u otros errores de resolución pueden impedir conclusiones definitivas."
    ]
  };
}

function hasSecureDelegation(delegations = [], zoneName) {
  return delegations.some((d) =>
    d.to === zoneName &&
    (d.ds_present === true || d.secure === true || d.status === DNSSEC_DELEGATION_STATUS.SECURE)
  );
}

function normalizeZone(zoneItem, dnskey, secureDelegation) {
  const base = {
    zone: zoneItem.zone,
    level: zoneItem.level,
    signed: dnskey.found,
    dnskey_present: dnskey.found,
    status: mapZoneStatus(dnskey.found, dnskey.query_status),
    query_status: dnskey.query_status,
    dnskey_error: dnskey.error_code || null
  };

  if (secureDelegation && dnskey.query_status === "servfail") {
    return {
      ...base,
      validation_problem: "dnssec_validation_failure",
      failure_scope: "zone_dnskey_lookup"
    };
  }

  if (dnskey.query_status === "nxdomain") {
    return {
      ...base,
      existence_problem: "zone_not_found"
    };
  }

  return base;
}

function normalizeNameExistence(nameExistence, secureDelegation) {
  const records = Array.isArray(nameExistence?.records) ? nameExistence.records : [];

  const anyFound = records.some((r) => r?.found === true);
  const allNxdomain = records.length > 0 && records.every((r) =>
    r?.query_status === "nxdomain" || r?.error_code === "NXDOMAIN"
  );
  const anyServfail = records.some((r) =>
    r?.query_status === "servfail" || r?.error_code === "SERVFAIL"
  );

  if (anyFound) {
    return {
      ...nameExistence,
      exists: true,
      query_status: "ok"
    };
  }

  if (allNxdomain) {
    return {
      ...nameExistence,
      exists: false,
      query_status: "nxdomain"
    };
  }

  if (secureDelegation && anyServfail) {
    return {
      ...nameExistence,
      exists: true,
      query_status: "servfail",
      error_cause: "dnssec_validation_failure"
    };
  }

  return nameExistence;
}

async function getDnssecAnalysis(domain) {
  const baseZones = buildZoneChain(domain);

  const rawZoneResults = await Promise.all(
    baseZones.map(async (zoneItem) => {
      const dnskey = await queryDnskey(zoneItem.zone);
      return { zoneItem, dnskey };
    })
  );

  const preliminaryZones = rawZoneResults.map(({ zoneItem, dnskey }) => ({
    zone: zoneItem.zone,
    level: zoneItem.level,
    signed: dnskey.found,
    dnskey_present: dnskey.found,
    status: mapZoneStatus(dnskey.found, dnskey.query_status),
    query_status: dnskey.query_status,
    dnskey_error: dnskey.error_code || null
  }));

  const baseDelegations = buildDelegationsFromZones(preliminaryZones);

  const delegations = await Promise.all(
    baseDelegations.map(async (delegation) => {
      const ds = await queryDs(delegation.to);
      const secure = ds.found === true;

      return {
        from: delegation.from,
        to: delegation.to,
        ds_present: ds.found,
        secure,
        status: mapDelegationStatus(secure, ds.found, ds.query_status),
        query_status: ds.query_status,
        ds_error: ds.error_code || null
      };
    })
  );

  const zones = rawZoneResults.map(({ zoneItem, dnskey }) => {
    const secureDelegation = hasSecureDelegation(delegations, zoneItem.zone);
    return normalizeZone(zoneItem, dnskey, secureDelegation);
  });

  const rawNameExistence = await queryNameExistence(domain);
  const secureDelegationToDomain = hasSecureDelegation(delegations, domain);
  const name_existence = normalizeNameExistence(rawNameExistence, secureDelegationToDomain);

  const confidence = computeConfidence(zones, delegations, name_existence);
  const assessment_meta = buildAssessmentMeta(confidence);

  return {
    domain,
    raw_checks: {
      zones,
      delegations,
      name_existence
    },
    assessment_meta
  };
}

module.exports = { getDnssecAnalysis };