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

function isServfail(status) {
  return normalizeStatus(status) === "servfail";
}

function hasStatus(value, allowed) {
  return allowed.includes(normalizeStatus(value));
}

function computeDnssecConclusion(zones, delegations, domain, nameExistence) {
  const zoneList = Array.isArray(zones) ? zones : [];
  const delegationList = Array.isArray(delegations) ? delegations : [];

  if (zoneList.length === 0) {
    return {
      final_status: DNSSEC_FINAL_STATUS.INDETERMINATE,
      readiness: DNSSEC_READINESS.UNKNOWN,
      blocking_level: "unknown",
      summary: "No hay datos suficientes para analizar DNSSEC.",
      technical_summary: "No se obtuvo información sobre la cadena de zonas."
    };
  }

  const tldZone = zoneList[0];
  const domainZone = zoneList[zoneList.length - 1];
  const parentZone = zoneList.length > 1 ? zoneList[zoneList.length - 2] : null;
  const lastDelegation =
    delegationList.length > 0
      ? delegationList[delegationList.length - 1]
      : null;

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

  const domainQueryNoData = hasStatus(domainZone?.query_status, ["no_data"]);
  const delegationQueryNoData = hasStatus(lastDelegation?.query_status, ["no_data"]);

  const nameExists = nameExistence?.exists === true;
  const nameDoesNotExist = nameExistence?.exists === false;

  const dsMissing = lastDelegation?.ds_present === false;

  // 🔥 NUEVO: evidencia explícita de fallo DNSSEC
  const hasDnssecValidationFailure =
    domainZone?.validation_problem === "dnssec_validation_failure" ||
    nameExistence?.error_cause === "dnssec_validation_failure";

  const hasStructuralEvidenceOfExistence =
    nameExists ||
    zoneList.some((z) =>
      hasStatus(z?.query_status, ["noerror", "no_data"])
    ) ||
    delegationList.some((d) =>
      hasStatus(d?.query_status, ["noerror", "no_data"])
    ) ||
    zoneList.some((z) => hasStatus(z?.status, ["signed", "unsigned"])) ||
    delegationList.some((d) => hasStatus(d?.status, ["secure", "insecure"]));

  // 1) Errores duros
  if (hasHardErrors) {
    return {
      final_status: DNSSEC_FINAL_STATUS.INDETERMINATE,
      readiness: DNSSEC_READINESS.UNKNOWN,
      blocking_level: "unknown",
      summary: "No fue posible clasificar el estado DNSSEC de forma concluyente.",
      technical_summary: "Una o más consultas DNS devolvieron error, timeout o respuesta no confiable."
    };
  }

  // 2) Bloqueo en TLD
  if (hasStatus(tldZone?.status, ["unsigned"])) {
    return {
      final_status: DNSSEC_FINAL_STATUS.BLOCKED_AT_TLD,
      readiness: DNSSEC_READINESS.BLOCKED_BY_TLD,
      blocking_level: "tld",
      summary: "El dominio no puede implementar DNSSEC porque la capa superior no está firmada.",
      technical_summary: `La zona ${tldZone.zone} no está firmada.`
    };
  }

  // 3) Bloqueo en parent
  if (
    parentZone &&
    parentZone.zone !== domain &&
    hasStatus(parentZone?.status, ["unsigned"])
  ) {
    return {
      final_status: DNSSEC_FINAL_STATUS.BLOCKED_AT_PARENT,
      readiness: DNSSEC_READINESS.BLOCKED_BY_PARENT,
      blocking_level: "parent",
      summary: "El dominio no puede implementar DNSSEC porque su zona padre no está firmada.",
      technical_summary: `La zona padre ${parentZone.zone} no está firmada.`
    };
  }

  // 4) OK
  if (domainSigned && secureDelegation) {
    return {
      final_status: DNSSEC_FINAL_STATUS.OK,
      readiness: DNSSEC_READINESS.ALREADY_ENABLED,
      blocking_level: "none",
      summary: "El dominio cuenta con una cadena válida de confianza DNSSEC.",
      technical_summary: `DNSSEC activo en ${domainZone.zone} con delegación segura.`
    };
  }

  // 5) MISCONFIGURED (delegación rota)
  if (domainSigned && lastDelegation && !secureDelegation) {
    return {
      final_status: DNSSEC_FINAL_STATUS.MISCONFIGURED,
      readiness: DNSSEC_READINESS.ALREADY_ENABLED,
      blocking_level: "domain",
      summary: "El dominio presenta DNSSEC, pero la delegación no es segura.",
      technical_summary: `DNSSEC detectado pero la delegación no es segura.`
    };
  }

  // 6) MISCONFIGURED (🔥 CORREGIDO: evidencia real)
  if (hasSignedUpperLayer && hasDnssecValidationFailure) {
    return {
      final_status: DNSSEC_FINAL_STATUS.MISCONFIGURED,
      readiness: DNSSEC_READINESS.ALREADY_ENABLED,
      blocking_level: "domain",
      summary: "El dominio muestra señales de validación DNSSEC inconsistente o fallida.",
      technical_summary: "Se detectó evidencia explícita de fallo de validación DNSSEC."
    };
  }

  // 7) NOT IMPLEMENTED (🔥 unificado)
  if (
    hasSignedParent &&
    lastDelegation &&
    dsMissing &&
    domainUnsigned &&
    (
      delegationQueryNoData ||
      ["nxdomain", "no_data"].includes(normalizeStatus(lastDelegation?.query_status))
    )
  ) {
    return {
      final_status: DNSSEC_FINAL_STATUS.NOT_IMPLEMENTED,
      readiness: DNSSEC_READINESS.READY_TO_ENABLE,
      blocking_level: "domain",
      summary: "El dominio no ha implementado DNSSEC.",
      technical_summary: `Las capas superiores permiten DNSSEC, pero ${domainZone.zone} no tiene DS ni firma.`
    };
  }

  // 8) NON EXISTENT
  if (
    zoneList.length === 2 &&
    domainQueryNx &&
    delegationQueryNx &&
    dsMissing &&
    domainUnsigned &&
    nameDoesNotExist &&
    existenceQueryNx &&
    !hasStructuralEvidenceOfExistence &&
    !hasSignedUpperLayer
  ) {
    return {
      final_status: DNSSEC_FINAL_STATUS.NON_EXISTENT,
      readiness: DNSSEC_READINESS.UNKNOWN,
      blocking_level: "unknown",
      summary: "El dominio no existe.",
      technical_summary: "No hay evidencia estructural ni operativa del dominio."
    };
  }

  // 9) fallback
  return {
    final_status: DNSSEC_FINAL_STATUS.INDETERMINATE,
    readiness: DNSSEC_READINESS.UNKNOWN,
    blocking_level: "unknown",
    summary: "No fue posible clasificar el estado DNSSEC.",
    technical_summary: "La evidencia no permite una conclusión clara."
  };
}

module.exports = { computeDnssecConclusion };