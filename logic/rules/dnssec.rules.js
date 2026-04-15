const {
  DNSSEC_FINAL_STATUS,
  DNSSEC_READINESS
} = require("../../config/dnssec.constants");

function normalizeStatus(value) {
  return String(value || "").trim().toLowerCase();
}

function isHardQueryError(status) {
  return [
    "timeout",
    "error",
    "network_error",
    "invalid_response"
  ].includes(normalizeStatus(status));
}

function hasStatus(value, allowed) {
  return allowed.includes(normalizeStatus(value));
}

function computeDnssecConclusion(zones, delegations, domain, nameExistence) {
  const zoneList = Array.isArray(zones) ? zones : [];
  const delegationList = Array.isArray(delegations) ? delegations : [];

  if (zoneList.length === 0) {
    const final_status = DNSSEC_FINAL_STATUS.INDETERMINATE;
    return {
      final_status,
      readiness: DNSSEC_READINESS.UNKNOWN,
      blocking_level: "unknown",
      summary: "No hay datos suficientes para analizar DNSSEC.",
      technical_summary: "No se obtuvo información sobre la cadena de zonas.",
    };
  }

  const tldZone = zoneList[0];
  const domainZone = zoneList[zoneList.length - 1];
  const parentZone = zoneList.length > 1 ? zoneList[zoneList.length - 2] : null;
  const lastDelegation =
    delegationList.length > 0
      ? delegationList[delegationList.length - 1]
      : null;

  const recommendationContext = {
    domainZone,
    lastDelegation,
    tldZone,
    parentZone
  };

  const allQueryStatuses = [
    ...zoneList.map((z) => z?.query_status),
    ...delegationList.map((d) => d?.query_status),
    nameExistence?.query_status
  ].filter(Boolean);

  const hasHardErrors = allQueryStatuses.some(isHardQueryError);

  const hasSignedTld = hasStatus(tldZone?.status, ["signed"]);
  const hasSignedParent = hasStatus(parentZone?.status, ["signed"]);
  const hasSignedUpperLayer = hasSignedTld || hasSignedParent;

  const domainSigned = hasStatus(domainZone?.status, ["signed"]);
  const domainUnsigned = hasStatus(domainZone?.status, ["unsigned"]);
  const secureDelegation = hasStatus(lastDelegation?.status, ["secure"]);

  const domainQueryNx = hasStatus(domainZone?.query_status, ["nxdomain"]);
  const delegationQueryNx = hasStatus(lastDelegation?.query_status, ["nxdomain"]);
  const existenceQueryNx = hasStatus(nameExistence?.query_status, ["nxdomain"]);

  const delegationQueryNoData = hasStatus(lastDelegation?.query_status, ["no_data"]);

  const nameExists = nameExistence?.exists === true;
  const nameDoesNotExist = nameExistence?.exists === false;

  const dsMissing = lastDelegation?.ds_present === false;

  const hasDnssecValidationFailure =
    domainZone?.validation_problem === "dnssec_validation_failure" ||
    nameExistence?.error_cause === "dnssec_validation_failure";

  // Evidencia de existencia restringida al dominio analizado y su delegación directa.
  // Las capas superiores (TLD, parent) responden aunque el dominio no exista —
  // incluirlas causaría falsos negativos en la detección de non_existent.
  const hasDomainLevelEvidenceOfExistence =
    nameExists ||
    hasStatus(domainZone?.query_status, ["noerror", "no_data"]) ||
    hasStatus(domainZone?.status, ["signed", "unsigned"]) ||
    hasStatus(lastDelegation?.query_status, ["noerror", "no_data"]) ||
    hasStatus(lastDelegation?.status, ["secure", "insecure"]);

  // 1) Errores duros
  if (hasHardErrors) {
    const final_status = DNSSEC_FINAL_STATUS.INDETERMINATE;
    return {
      final_status,
      readiness: DNSSEC_READINESS.UNKNOWN,
      blocking_level: "unknown",
      summary: "No fue posible clasificar el estado DNSSEC de forma concluyente.",
      technical_summary: "Una o más consultas DNS devolvieron error, timeout o respuesta no confiable.",
    };
  }

  // 2) NON EXISTENT — se evalúa antes que cualquier otra regla estructural.
  // La existencia del dominio es prerequisito de toda clasificación DNSSEC.
  // Se basa exclusivamente en query_status reales (datos del DNS), no en campos
  // derivados como status o ds_present que se calculan asumiendo existencia.
  const allDomainQueriesNx =
    nameDoesNotExist &&
    existenceQueryNx &&
    domainQueryNx &&
    delegationQueryNx;

  if (allDomainQueriesNx) {
    const final_status = DNSSEC_FINAL_STATUS.NON_EXISTENT;
    return {
      final_status,
      readiness: DNSSEC_READINESS.UNKNOWN,
      blocking_level: "unknown",
      summary: "El dominio no existe o no está delegado como zona DNS independiente.",
      technical_summary: "Todas las consultas DNS devolvieron NXDOMAIN. No hay evidencia estructural ni operativa del dominio.",
    };
  }

  // 3) Bloqueo en TLD
  if (hasStatus(tldZone?.status, ["unsigned"])) {
    const final_status = DNSSEC_FINAL_STATUS.BLOCKED_AT_TLD;
    return {
      final_status,
      readiness: DNSSEC_READINESS.BLOCKED_BY_TLD,
      blocking_level: "tld",
      summary: `La zona superior ${tldZone.zone} no está firmada con DNSSEC, impidiendo la cadena de confianza para este dominio.`,
      technical_summary: `La zona ${tldZone.zone} no está firmada. La limitación es estructural y externa al dominio analizado.`,
    };
  }

  // 4) Bloqueo en parent
  if (
    parentZone &&
    parentZone.zone !== domain &&
    hasStatus(parentZone?.status, ["unsigned"])
  ) {
    const final_status = DNSSEC_FINAL_STATUS.BLOCKED_AT_PARENT;
    return {
      final_status,
      readiness: DNSSEC_READINESS.BLOCKED_BY_PARENT,
      blocking_level: "parent",
      summary: `La zona padre ${parentZone.zone} no está firmada, bloqueando la cadena de confianza hacia este dominio.`,
      technical_summary: `La zona padre ${parentZone.zone} no está firmada. El dominio no puede completar la cadena DNSSEC sin acción de esa capa.`,
    };
  }

  // 5) OK
  if (domainSigned && secureDelegation) {
    const final_status = DNSSEC_FINAL_STATUS.OK;
    return {
      final_status,
      readiness: DNSSEC_READINESS.ALREADY_ENABLED,
      blocking_level: "none",
      summary: `${domainZone.zone} está firmado y cuenta con delegación segura desde la zona padre. La cadena de confianza DNSSEC es válida.`,
      technical_summary: `DNSSEC activo en ${domainZone.zone} con delegación segura.`,
    };
  }

  // 6) MISCONFIGURED (zona firmada pero sin DS en el padre)
  if (domainSigned && lastDelegation && !secureDelegation) {
    const final_status = DNSSEC_FINAL_STATUS.MISCONFIGURED;
    return {
      final_status,
      readiness: DNSSEC_READINESS.ALREADY_ENABLED,
      blocking_level: "domain",
      summary: `${domainZone.zone} tiene DNSKEY, pero la zona padre no publica un DS válido. La cadena de confianza está rota.`,
      technical_summary: `DNSSEC activo en ${domainZone.zone}, pero sin DS en ${lastDelegation?.from || "la zona padre"}. La delegación no es segura.`,
    };
  }

  // 7) MISCONFIGURED (fallo de validación explícito — SERVFAIL con DS presente)
  if (hasSignedUpperLayer && hasDnssecValidationFailure) {
    const final_status = DNSSEC_FINAL_STATUS.MISCONFIGURED;
    return {
      final_status,
      readiness: DNSSEC_READINESS.ALREADY_ENABLED,
      blocking_level: "domain",
      summary: `Se detectó evidencia de fallo de validación DNSSEC en ${domainZone.zone}. El resolver rechaza la respuesta por inconsistencia criptográfica.`,
      technical_summary: "SERVFAIL con DS presente detectado. Indica fallo de validación DNSSEC activo.",
    };
  }

  // 8) MISCONFIGURED (DS en padre pero DNSKEY ausente en zona hija)
  if (
    lastDelegation &&
    lastDelegation.ds_present === true &&
    secureDelegation &&
    domainUnsigned
  ) {
    const final_status = DNSSEC_FINAL_STATUS.MISCONFIGURED;
    return {
      final_status,
      readiness: DNSSEC_READINESS.ALREADY_ENABLED,
      blocking_level: "domain",
      summary: `La zona padre publica un DS para ${domainZone.zone}, pero la zona no responde con DNSKEY. La cadena de confianza está rota desde el lado del dominio.`,
      technical_summary: `DS presente en ${lastDelegation.from}, pero ${domainZone.zone} no devuelve DNSKEY. El dominio fue configurado para DNSSEC pero no lo sirve.`,
    };
  }

  // 9) NOT IMPLEMENTED
  if (
    hasSignedParent &&
    lastDelegation &&
    dsMissing &&
    domainUnsigned &&
    ["nxdomain", "no_data"].includes(normalizeStatus(lastDelegation?.query_status))
  ) {
    const final_status = DNSSEC_FINAL_STATUS.NOT_IMPLEMENTED;
    return {
      final_status,
      readiness: DNSSEC_READINESS.READY_TO_ENABLE,
      blocking_level: "domain",
      summary: `${domainZone.zone} no tiene DNSSEC implementado. Las capas superiores ya lo soportan, por lo que la acción está en manos del operador del dominio.`,
      technical_summary: `${domainZone.zone} no tiene DS ni DNSKEY. La zona padre ${lastDelegation?.from || ""} está firmada y lista para publicar el DS.`,
    };
  }

  // 10) fallback
  const final_status = DNSSEC_FINAL_STATUS.INDETERMINATE;
  return {
    final_status,
    readiness: DNSSEC_READINESS.UNKNOWN,
    blocking_level: "unknown",
    summary: "No fue posible clasificar el estado DNSSEC con la evidencia disponible.",
    technical_summary: "La evidencia no es suficiente para una conclusión clara. Verifique manualmente la cadena de zonas.",
  };
}

module.exports = { computeDnssecConclusion };