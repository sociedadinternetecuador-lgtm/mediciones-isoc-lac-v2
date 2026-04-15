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

function buildRecommendations(finalStatus, context = {}) {
  const {
    domainZone,
    lastDelegation,
    tldZone,
    parentZone
  } = context;

  switch (finalStatus) {
    case DNSSEC_FINAL_STATUS.OK:
      return [
        "Mantener monitoreo periódico.",
        "Revisar rotación de claves y vigencia de firmas.",
        "Documentar la configuración como buena práctica replicable."
      ];

    case DNSSEC_FINAL_STATUS.MISCONFIGURED:
      return [
        `Revisar la cadena de confianza DNSSEC de ${domainZone?.zone || "la zona"}.`,
        `Verificar que el registro DS publicado en ${lastDelegation?.from || "la zona padre"} corresponda al DNSKEY vigente del dominio.`,
        "Revisar firmas, claves y tiempos de vigencia.",
        "Validar nuevamente la cadena completa con herramientas especializadas."
      ];

    case DNSSEC_FINAL_STATUS.NOT_IMPLEMENTED:
      return [
        `Evaluar la implementación de DNSSEC en ${domainZone?.zone || "el dominio"}.`,
        "Firmar la zona con claves DNSSEC.",
        `Publicar el registro DS en ${lastDelegation?.from || "la zona padre"}.`,
        "Establecer monitoreo y procedimientos de rotación de claves."
      ];

    case DNSSEC_FINAL_STATUS.BLOCKED_AT_TLD:
      return [
        `La limitación estructural se encuentra en ${tldZone?.zone || "el TLD"}.`,
        "Escalar el hallazgo al operador del TLD o registrador correspondiente.",
        "Registrar el caso como barrera estructural externa al dominio analizado."
      ];

    case DNSSEC_FINAL_STATUS.BLOCKED_AT_PARENT:
      return [
        `La limitación estructural se encuentra en la zona padre ${parentZone?.zone || ""}.`.trim(),
        "Revisar la capacidad DNSSEC de la capa intermedia.",
        "Escalar el hallazgo al operador responsable de la zona padre."
      ];

    case DNSSEC_FINAL_STATUS.NON_EXISTENT:
      return [
        "Confirmar que el nombre de dominio exista y esté correctamente delegado.",
        "Verificar registros A, AAAA o CNAME.",
        "Revisar si se trata realmente de una zona DNS independiente."
      ];

    case DNSSEC_FINAL_STATUS.INDETERMINATE:
    default:
      return [
        "Verificar con herramientas DNSSEC especializadas.",
        "Consultar resolutores validadores.",
        "Revisar nuevamente la delegación, DNSKEY y DS."
      ];
  }
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
      recommendations: buildRecommendations(final_status)
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
    const final_status = DNSSEC_FINAL_STATUS.INDETERMINATE;
    return {
      final_status,
      readiness: DNSSEC_READINESS.UNKNOWN,
      blocking_level: "unknown",
      summary: "No fue posible clasificar el estado DNSSEC de forma concluyente.",
      technical_summary: "Una o más consultas DNS devolvieron error, timeout o respuesta no confiable.",
      recommendations: buildRecommendations(final_status, recommendationContext)
    };
  }

  // 2) Bloqueo en TLD
  if (hasStatus(tldZone?.status, ["unsigned"])) {
    const final_status = DNSSEC_FINAL_STATUS.BLOCKED_AT_TLD;
    return {
      final_status,
      readiness: DNSSEC_READINESS.BLOCKED_BY_TLD,
      blocking_level: "tld",
      summary: "El dominio no puede implementar DNSSEC porque la capa superior no está firmada.",
      technical_summary: `La zona ${tldZone.zone} no está firmada.`,
      recommendations: buildRecommendations(final_status, recommendationContext)
    };
  }

  // 3) Bloqueo en parent
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
      summary: "El dominio no puede implementar DNSSEC porque su zona padre no está firmada.",
      technical_summary: `La zona padre ${parentZone.zone} no está firmada.`,
      recommendations: buildRecommendations(final_status, recommendationContext)
    };
  }

  // 4) OK
  if (domainSigned && secureDelegation) {
    const final_status = DNSSEC_FINAL_STATUS.OK;
    return {
      final_status,
      readiness: DNSSEC_READINESS.ALREADY_ENABLED,
      blocking_level: "none",
      summary: "El dominio cuenta con una cadena válida de confianza DNSSEC.",
      technical_summary: `DNSSEC activo en ${domainZone.zone} con delegación segura.`,
      recommendations: buildRecommendations(final_status, recommendationContext)
    };
  }

  // 5) MISCONFIGURED (delegación rota)
  if (domainSigned && lastDelegation && !secureDelegation) {
    const final_status = DNSSEC_FINAL_STATUS.MISCONFIGURED;
    return {
      final_status,
      readiness: DNSSEC_READINESS.ALREADY_ENABLED,
      blocking_level: "domain",
      summary: "El dominio presenta DNSSEC, pero la delegación no es segura.",
      technical_summary: "DNSSEC detectado pero la delegación no es segura.",
      recommendations: buildRecommendations(final_status, recommendationContext)
    };
  }

  // 6) MISCONFIGURED (evidencia real)
  if (hasSignedUpperLayer && hasDnssecValidationFailure) {
    const final_status = DNSSEC_FINAL_STATUS.MISCONFIGURED;
    return {
      final_status,
      readiness: DNSSEC_READINESS.ALREADY_ENABLED,
      blocking_level: "domain",
      summary: "El dominio muestra señales de validación DNSSEC inconsistente o fallida.",
      technical_summary: "Se detectó evidencia explícita de fallo de validación DNSSEC.",
      recommendations: buildRecommendations(final_status, recommendationContext)
    };
  }

  // 7) NOT IMPLEMENTED
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
    const final_status = DNSSEC_FINAL_STATUS.NOT_IMPLEMENTED;
    return {
      final_status,
      readiness: DNSSEC_READINESS.READY_TO_ENABLE,
      blocking_level: "domain",
      summary: "El dominio no ha implementado DNSSEC.",
      technical_summary: `Las capas superiores permiten DNSSEC, pero ${domainZone.zone} no tiene DS ni firma.`,
      recommendations: buildRecommendations(final_status, recommendationContext)
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
    const final_status = DNSSEC_FINAL_STATUS.NON_EXISTENT;
    return {
      final_status,
      readiness: DNSSEC_READINESS.UNKNOWN,
      blocking_level: "unknown",
      summary: "El dominio no existe.",
      technical_summary: "No hay evidencia estructural ni operativa del dominio.",
      recommendations: buildRecommendations(final_status, recommendationContext)
    };
  }

  // 9) fallback
  const final_status = DNSSEC_FINAL_STATUS.INDETERMINATE;
  return {
    final_status,
    readiness: DNSSEC_READINESS.UNKNOWN,
    blocking_level: "unknown",
    summary: "No fue posible clasificar el estado DNSSEC.",
    technical_summary: "La evidencia no permite una conclusión clara.",
    recommendations: buildRecommendations(final_status, recommendationContext)
  };
}

module.exports = { computeDnssecConclusion };