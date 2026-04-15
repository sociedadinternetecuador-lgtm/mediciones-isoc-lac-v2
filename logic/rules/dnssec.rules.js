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
  const hasServfailAnywhere = allQueryStatuses.some(isServfail);

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

  // 1) Errores duros de red o respuestas no confiables
  // Ojo: servfail NO se trata aquí porque puede significar DNSSEC roto.
  if (hasHardErrors) {
    return {
      final_status: DNSSEC_FINAL_STATUS.INDETERMINATE,
      readiness: DNSSEC_READINESS.UNKNOWN,
      blocking_level: "unknown",
      summary: "No fue posible clasificar el estado DNSSEC de forma concluyente.",
      technical_summary: "Una o más consultas DNS devolvieron error, timeout o respuesta no confiable."
    };
  }

  // 2) Bloqueo estructural en TLD
  if (hasStatus(tldZone?.status, ["unsigned"])) {
    return {
      final_status: DNSSEC_FINAL_STATUS.BLOCKED_AT_TLD,
      readiness: DNSSEC_READINESS.BLOCKED_BY_TLD,
      blocking_level: "tld",
      summary: "El dominio no puede implementar DNSSEC porque la capa superior no está firmada.",
      technical_summary: `La zona ${tldZone.zone} no está firmada, lo que impide la continuidad de la cadena de confianza.`
    };
  }

  // 3) Bloqueo estructural en la zona padre inmediata
  if (
    parentZone &&
    parentZone.zone !== domain &&
    hasStatus(parentZone?.status, ["unsigned"])
  ) {
    return {
      final_status: DNSSEC_FINAL_STATUS.BLOCKED_AT_PARENT,
      readiness: DNSSEC_READINESS.BLOCKED_BY_PARENT,
      blocking_level: "parent",
      summary: "El dominio no puede implementar DNSSEC porque su zona padre inmediata no está firmada.",
      technical_summary: `La zona padre inmediata ${parentZone.zone} no está firmada.`
    };
  }

  // 4) Caso OK: DNSKEY en zona final + delegación segura
  if (domainSigned && secureDelegation) {
    return {
      final_status: DNSSEC_FINAL_STATUS.OK,
      readiness: DNSSEC_READINESS.ALREADY_ENABLED,
      blocking_level: "none",
      summary: "El dominio cuenta con una cadena válida o potencialmente válida de confianza DNSSEC.",
      technical_summary: `Se detecta firma DNSSEC en ${domainZone.zone} y una delegación segura desde ${lastDelegation.from} hacia ${lastDelegation.to}.`
    };
  }

  // 5) Caso MISCONFIGURED:
  // La zona final muestra firma, pero la delegación no es segura
  if (domainSigned && lastDelegation && !secureDelegation) {
    return {
      final_status: DNSSEC_FINAL_STATUS.MISCONFIGURED,
      readiness: DNSSEC_READINESS.ALREADY_ENABLED,
      blocking_level: "domain",
      summary: "El dominio presenta señales de DNSSEC, pero la delegación segura no está completa.",
      technical_summary: `Se detectó DNSSEC en ${domainZone.zone}, pero la delegación desde ${lastDelegation.from} hacia ${lastDelegation.to} no aparece como segura.`
    };
  }

  // 6) Caso MISCONFIGURED por fallo de validación:
  // Si la capa superior está firmada y aparece SERVFAIL, no debe tratarse como inexistencia.
  if (hasSignedUpperLayer && hasServfailAnywhere) {
    return {
      final_status: DNSSEC_FINAL_STATUS.MISCONFIGURED,
      readiness: DNSSEC_READINESS.ALREADY_ENABLED,
      blocking_level: "domain",
      summary: "El dominio muestra señales de validación DNSSEC inconsistente o fallida.",
      technical_summary: "La jerarquía superior permite DNSSEC, pero una o más consultas devolvieron SERVFAIL, lo que sugiere una cadena DNSSEC inconsistente o rota."
    };
  }

  // 7) Caso NOT_IMPLEMENTED:
  // La capa superior permite DNSSEC, pero el nombre analizado no muestra despliegue propio.
  if (
    hasSignedParent &&
    lastDelegation &&
    ["no_data", "nxdomain"].includes(normalizeStatus(lastDelegation?.query_status)) &&
    dsMissing &&
    domainUnsigned &&
    zoneList.length > 2
  ) {
    return {
      final_status: DNSSEC_FINAL_STATUS.NOT_IMPLEMENTED,
      readiness: DNSSEC_READINESS.READY_TO_ENABLE,
      blocking_level: "domain",
      summary: "Las capas superiores permiten DNSSEC, pero el dominio no lo ha implementado.",
      technical_summary: `Las capas superiores (${parentZone.zone} y superiores) soportan DNSSEC, pero ${domainZone.zone} no muestra evidencia estructural de despliegue DNSSEC ni DS en la delegación inmediata.`
    };
  }

  // 8) Caso READY legado: ausencia limpia de DNSSEC en la capa final sin errores ambiguos
  if (
    domainUnsigned &&
    domainQueryNoData &&
    hasSignedParent &&
    lastDelegation &&
    delegationQueryNoData &&
    dsMissing
  ) {
    return {
      final_status: DNSSEC_FINAL_STATUS.READY,
      readiness: DNSSEC_READINESS.READY_TO_ENABLE,
      blocking_level: "domain",
      summary: "La infraestructura superior permite DNSSEC, pero el dominio aún no lo ha activado.",
      technical_summary: `Las zonas superiores permiten DNSSEC, pero ${domainZone.zone} no publica evidencia estructural de DNSSEC y su delegación no muestra DS.`
    };
  }

  // 9) Caso NON_EXISTENT:
  // Solo cuando no exista evidencia operativa ni estructural de existencia
  // y además no estemos en un contexto que sugiera validación DNSSEC fallida.
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
      summary: "El nombre consultado no presenta evidencia suficiente de existencia como zona DNS delegada independiente.",
      technical_summary: `La consulta estructural para ${domainZone.zone} devolvió NXDOMAIN y tampoco se observó existencia operativa del nombre mediante A, AAAA o CNAME.`
    };
  }

  // 10) Si la capa superior está firmada y el resultado parece inexistente,
  // pero no podemos confirmar inexistencia real, es más seguro clasificar como inconcluso.
  if (
    zoneList.length === 2 &&
    domainQueryNx &&
    delegationQueryNx &&
    hasSignedUpperLayer
  ) {
    return {
      final_status: DNSSEC_FINAL_STATUS.INDETERMINATE,
      readiness: DNSSEC_READINESS.UNKNOWN,
      blocking_level: "domain",
      summary: "El dominio no pudo clasificarse con certeza entre inexistencia y fallo de validación DNSSEC.",
      technical_summary: "La jerarquía superior está firmada, pero el nombre analizado devolvió respuestas compatibles tanto con inexistencia como con una posible validación DNSSEC fallida."
    };
  }

  // 11) Caso residual: inconcluso
  return {
    final_status: DNSSEC_FINAL_STATUS.INDETERMINATE,
    readiness: DNSSEC_READINESS.UNKNOWN,
    blocking_level: "unknown",
    summary: "No fue posible clasificar el estado DNSSEC de forma concluyente.",
    technical_summary: "Los datos estructurales obtenidos no permiten distinguir con suficiente certeza entre ausencia de DNSSEC, configuración inconsistente o condición no aplicable."
  };
}

module.exports = { computeDnssecConclusion };