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
  return DNSSEC_ZONE_STATUS.UNKNOWN;
}

function mapDelegationStatus(secure, dsPresent, queryStatus) {
  if (secure === true) return DNSSEC_DELEGATION_STATUS.SECURE;
  if (dsPresent === false && queryStatus === "no_data") return DNSSEC_DELEGATION_STATUS.INSECURE;
  if (dsPresent === true && secure === false) return DNSSEC_DELEGATION_STATUS.BROKEN;
  return DNSSEC_DELEGATION_STATUS.UNKNOWN;
}

function computeConfidence(zones, delegations, nameExistence) {
  const zoneStatuses = zones.map((z) => z.query_status);
  const delegationStatuses = delegations.map((d) => d.query_status);
  const allStatuses = [...zoneStatuses, ...delegationStatuses, nameExistence?.query_status].filter(Boolean);

  const timeoutCount = allStatuses.filter((s) => s === "timeout").length;
  const errorCount = allStatuses.filter((s) =>
    ["error", "servfail", "network_error", "invalid_response"].includes(s)
  ).length;
  const unknownCount =
    zones.filter((z) => z.status === "unknown").length +
    delegations.filter((d) => d.status === "unknown").length;

  if (timeoutCount > 0 || errorCount > 0) {
    return "low";
  }

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
      "La ausencia de DNSKEY o DS no siempre equivale por sí sola a una falla definitiva; puede requerir análisis más profundo.",
      "Timeouts, SERVFAIL u otros errores de resolución pueden impedir conclusiones definitivas."
    ]
  };
}

async function getDnssecAnalysis(domain) {
  const baseZones = buildZoneChain(domain);

  const zonePromises = baseZones.map(async (zoneItem) => {
    const dnskey = await queryDnskey(zoneItem.zone);

    return {
      zone: zoneItem.zone,
      level: zoneItem.level,
      signed: dnskey.found,
      dnskey_present: dnskey.found,
      status: mapZoneStatus(dnskey.found, dnskey.query_status),
      query_status: dnskey.query_status,
      dnskey_error: dnskey.error_code || null
    };
  });

  const zones = await Promise.all(zonePromises);

  const baseDelegations = buildDelegationsFromZones(zones);

  const delegationPromises = baseDelegations.map(async (delegation) => {
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
  });

  const delegations = await Promise.all(delegationPromises);

  const name_existence = await queryNameExistence(domain);

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