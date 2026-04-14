const {
  DNSSEC_FINAL_STATUS,
  DNSSEC_READINESS
} = require("../../config/dnssec.constants");

function isQueryError(status) {
  return [
    "timeout",
    "servfail",
    "error",
    "network_error",
    "invalid_response"
  ].includes(status);
}

function computeDnssecConclusion(zones, delegations, domain, nameExistence) {
  if (!Array.isArray(zones) || zones.length === 0) {
    return {
      final_status: DNSSEC_FINAL_STATUS.INDETERMINATE,
      readiness: DNSSEC_READINESS.UNKNOWN,
      blocking_level: "unknown",
      summary: "No hay datos suficientes para analizar DNSSEC.",
      technical_summary: "No se obtuvo información sobre la cadena de zonas."
    };
  }

  const tldZone = zones[0];
  const domainZone = zones[zones.length - 1];
  const parentZone = zones.length > 1 ? zones[zones.length - 2] : null;
  const lastDelegation =
    Array.isArray(delegations) && delegations.length > 0
      ? delegations[delegations.length - 1]
      : null;

  const allQueryStatuses = [
    ...zones.map((z) => z.query_status),
    ...delegations.map((d) => d.query_status),
    nameExistence?.query_status
  ].filter(Boolean);

  // 1) Errores de red o respuestas no confiables
  if (allQueryStatuses.some(isQueryError)) {
    return {
      final_status: DNSSEC_FINAL_STATUS.INDETERMINATE,
      readiness: DNSSEC_READINESS.UNKNOWN,
      blocking_level: "unknown",
      summary: "No fue posible clasificar el estado DNSSEC de forma concluyente.",
      technical_summary: "Una o más consultas DNS devolvieron error, timeout o respuesta no confiable."
    };
  }

  // 2) Bloqueo estructural en TLD
  if (tldZone?.status === "unsigned") {
    return {
      final_status: DNSSEC_FINAL_STATUS.BLOCKED_AT_TLD,
      readiness: DNSSEC_READINESS.BLOCKED_BY_TLD,
      blocking_level: "tld",
      summary: "El dominio no puede implementar DNSSEC porque la capa superior no está firmada.",
      technical_summary: `La zona ${tldZone.zone} no está firmada, lo que impide la continuidad de la cadena de confianza.`
    };
  }

  // 3) Bloqueo estructural en la zona padre inmediata
  if (parentZone && parentZone.zone !== domain && parentZone.status === "unsigned") {
    return {
      final_status: DNSSEC_FINAL_STATUS.BLOCKED_AT_PARENT,
      readiness: DNSSEC_READINESS.BLOCKED_BY_PARENT,
      blocking_level: "parent",
      summary: "El dominio no puede implementar DNSSEC porque su zona padre inmediata no está firmada.",
      technical_summary: `La zona padre inmediata ${parentZone.zone} no está firmada.`
    };
  }

  // 4) Caso OK: DNSKEY en zona final + delegación segura
  if (domainZone?.status === "signed" && lastDelegation?.status === "secure") {
    return {
      final_status: DNSSEC_FINAL_STATUS.OK,
      readiness: DNSSEC_READINESS.ALREADY_ENABLED,
      blocking_level: "none",
      summary: "El dominio cuenta con una cadena válida o potencialmente válida de confianza DNSSEC.",
      technical_summary: `Se detecta firma DNSSEC en ${domainZone.zone} y una delegación segura desde ${lastDelegation.from} hacia ${lastDelegation.to}.`
    };
  }

  // 5) Caso MISCONFIGURED: la zona final muestra firma, pero la delegación no es segura
  if (domainZone?.status === "signed" && lastDelegation && lastDelegation.status !== "secure") {
    return {
      final_status: DNSSEC_FINAL_STATUS.MISCONFIGURED,
      readiness: DNSSEC_READINESS.ALREADY_ENABLED,
      blocking_level: "domain",
      summary: "El dominio presenta señales de DNSSEC, pero la delegación segura no está completa.",
      technical_summary: `Se detectó DNSKEY en ${domainZone.zone}, pero la delegación desde ${lastDelegation.from} hacia ${lastDelegation.to} no aparece como segura.`
    };
  }

  // 6) Caso NOT_IMPLEMENTED:
  // La capa superior permite DNSSEC, pero el nombre analizado no muestra despliegue propio.
  // Esto debe cubrir tanto dominios/subdominios existentes operativamente como nombres bajo una jerarquía firmada
  // que no tengan DS ni DNSKEY propios en la capa analizada.
  if (
    parentZone?.status === "signed" &&
    lastDelegation &&
    ["no_data", "nxdomain"].includes(lastDelegation.query_status) &&
    lastDelegation.ds_present === false &&
    domainZone?.signed === false &&
    zones.length > 2
  ) {
    return {
      final_status: DNSSEC_FINAL_STATUS.NOT_IMPLEMENTED,
      readiness: DNSSEC_READINESS.READY_TO_ENABLE,
      blocking_level: "domain",
      summary: "Las capas superiores permiten DNSSEC, pero el dominio no lo ha implementado.",
      technical_summary: `Las capas superiores (${parentZone.zone} y superiores) soportan DNSSEC, pero ${domainZone.zone} no muestra evidencia estructural de despliegue DNSSEC ni DS en la delegación inmediata.`
    };
  }

  // 7) Caso NON_EXISTENT:
  // Solo aplicar a dominios de 2 niveles cuando además no exista evidencia operativa del nombre.
  if (
    zones.length === 2 &&
    domainZone?.query_status === "nxdomain" &&
    lastDelegation?.query_status === "nxdomain" &&
    lastDelegation?.ds_present === false &&
    domainZone?.signed === false &&
    nameExistence?.exists === false &&
    nameExistence?.query_status === "nxdomain"
  ) {
    return {
      final_status: DNSSEC_FINAL_STATUS.NON_EXISTENT,
      readiness: DNSSEC_READINESS.UNKNOWN,
      blocking_level: "unknown",
      summary: "El nombre consultado no presenta evidencia suficiente de existencia como zona DNS delegada independiente.",
      technical_summary: `La consulta estructural para ${domainZone.zone} devolvió NXDOMAIN y tampoco se observó existencia operativa del nombre mediante A, AAAA o CNAME.`
    };
  }

  // 8) Caso READY legado: ausencia limpia de DNSSEC en la capa final sin errores ambiguos
  if (
    domainZone?.status === "unsigned" &&
    domainZone?.query_status === "no_data" &&
    parentZone?.status === "signed" &&
    lastDelegation &&
    lastDelegation.query_status === "no_data" &&
    lastDelegation.ds_present === false
  ) {
    return {
      final_status: DNSSEC_FINAL_STATUS.READY,
      readiness: DNSSEC_READINESS.READY_TO_ENABLE,
      blocking_level: "domain",
      summary: "La infraestructura superior permite DNSSEC, pero el dominio aún no lo ha activado.",
      technical_summary: `Las zonas superiores permiten DNSSEC, pero ${domainZone.zone} no publica evidencia estructural de DNSSEC y su delegación no muestra DS.`
    };
  }

  // 9) Caso residual: inconcluso
  return {
    final_status: DNSSEC_FINAL_STATUS.INDETERMINATE,
    readiness: DNSSEC_READINESS.UNKNOWN,
    blocking_level: "unknown",
    summary: "No fue posible clasificar el estado DNSSEC de forma concluyente.",
    technical_summary: "Los datos estructurales obtenidos no permiten distinguir con suficiente certeza entre ausencia de DNSSEC, configuración inconsistente o condición no aplicable."
  };
}

module.exports = { computeDnssecConclusion };