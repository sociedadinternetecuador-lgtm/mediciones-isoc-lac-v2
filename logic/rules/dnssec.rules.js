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

// dnsvizSignal (2026-11-04, opt-in, ver logic/adapters/dnsviz.adapter.js):
// evidencia real de verificación criptográfica (RRSIG/NSEC/etc.) del
// Observatorio DNSSEC v2, vía `dnsviz` real — algo que este motor nunca
// verifica por sí mismo (solo infiere por presencia de DS/DNSKEY, ver
// limitations en services/dnssec.service.js). Parámetro opcional: si se
// omite (caso por defecto, análisis individual normal), el comportamiento
// es IDÉNTICO al de antes de este cambio — no se agrega latencia ni riesgo
// a la ruta rápida. Solo se usa cuando quien llama decidió explícitamente
// pedir esta validación de firma DNSSEC (ver server.js, parámetro `?dnsviz=1`).
function computeDnssecConclusion(zones, delegations, domain, nameExistence, dnsvizSignal) {
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

  // Zonas/delegaciones "ancestro": todo lo que está ESTRICTAMENTE entre el
  // TLD y el padre inmediato del dominio (ambos excluidos), más la
  // delegación entre el TLD y el padre inmediato (que antes tampoco se
  // examinaba — solo se miraba la ÚLTIMA delegación, padre->dominio).
  // Antes de esta corrección (2026-09-16), el motor solo examinaba
  // tldZone y parentZone: una ruptura en cualquier zona/delegación
  // intermedia de una cadena de 4+ niveles (ej. a.b.gob.ec, donde
  // "gob.ec" está sin firmar pero "b.gob.ec" luce firmado) era
  // completamente invisible — el dominio podía clasificarse "ok" aunque
  // la cadena real, vista desde el TLD, nunca pudiera validar. Ver
  // AUDITORIA_DNSSEC_ECUADOR_METODOLOGIA_MOTOR.md e
  // IMPLEMENTACION_DNSSEC_AUDITORIA_CORE.md para el hallazgo original.
  const ancestorZones = zoneList.slice(1, Math.max(1, zoneList.length - 2));
  const ancestorDelegations = delegationList.slice(0, Math.max(0, delegationList.length - 1));
  // .find() recorre en el mismo orden que zoneList/delegationList (TLD ->
  // dominio), así que devuelve la zona/delegación más cercana al TLD — la
  // causa raíz más útil de comunicar (arreglarla primero desbloquea todo
  // lo que depende de ella).
  const brokenAncestorZone = ancestorZones.find((z) => hasStatus(z?.status, ["unsigned"]));
  // (2026-09-16) — "broken" se quitó de esta búsqueda: DNSSEC_DELEGATION_STATUS.BROKEN
  // se eliminó por ser inalcanzable (ver AUDITORIA_DNSSEC_BROKEN_DELEGATION.md);
  // "insecure" sigue siendo una señal real y necesaria (delegación ancestro sin
  // DS publicado, ej. zona intermedia firmada cuya propia delegación desde SU
  // padre no tiene DS — no se pierde ninguna detección al quitar "broken",
  // porque esa rama nunca se producía con datos reales.
  const insecureAncestorDelegation = ancestorDelegations.find((d) => hasStatus(d?.status, ["insecure"]));
  // "Ambiguo" = ni claramente firmado/seguro ni claramente roto (status
  // "unknown") por un motivo que YA no cayó en hasHardErrors (evitar
  // duplicar esa clasificación) — nunca se debe forzar un veredicto "ok"
  // ignorando esta incertidumbre.
  const ambiguousAncestorZone = ancestorZones.find(
    (z) => hasStatus(z?.status, ["unknown"]) && !isHardQueryError(z?.query_status)
  );
  const ambiguousAncestorDelegation = ancestorDelegations.find(
    (d) => hasStatus(d?.status, ["unknown"]) && !isHardQueryError(d?.query_status)
  );

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

  // 3.5) NUEVO (2026-09-16) — Bloqueo en una zona ancestro intermedia (ni
  // el TLD ni el padre inmediato, sino algo entre ambos). Mismo
  // significado estructural que "bloqueo en la zona padre": un enlace
  // externo al propio dominio, fuera del control de su operador, impide
  // completar la cadena — por eso se reutiliza el MISMO estado existente
  // blocked_at_parent en vez de crear uno nuevo. Se reporta la zona más
  // cercana al TLD (la causa raíz más útil de comunicar: arreglarla
  // primero desbloquea todo lo que depende de ella).
  if (brokenAncestorZone) {
    const final_status = DNSSEC_FINAL_STATUS.BLOCKED_AT_PARENT;
    return {
      final_status,
      readiness: DNSSEC_READINESS.BLOCKED_BY_PARENT,
      blocking_level: "parent",
      summary: `La zona ${brokenAncestorZone.zone}, en un nivel intermedio de la cadena hacia ${domainZone.zone}, no está firmada, bloqueando la cadena de confianza.`,
      technical_summary: `La zona intermedia ${brokenAncestorZone.zone} no está firmada. El dominio no puede completar la cadena DNSSEC sin acción de esa capa.`,
    };
  }

  // 3.6) NUEVO (2026-09-16) — Misma idea que 3.5, pero la ruptura está en
  // la DELEGACIÓN entre dos zonas ancestro: el padre de esa zona intermedia
  // no publica un DS para ella (delegación "insecure" en ese punto) — un
  // patrón estructuralmente análogo a "DNSKEY sin DS" a nivel del propio
  // dominio (regla 6 más abajo), pero ocurriendo un nivel arriba. También
  // se reporta como blocked_at_parent: desde la perspectiva del dominio
  // analizado, es un problema externo, no de su propia configuración.
  if (insecureAncestorDelegation) {
    const final_status = DNSSEC_FINAL_STATUS.BLOCKED_AT_PARENT;
    return {
      final_status,
      readiness: DNSSEC_READINESS.BLOCKED_BY_PARENT,
      blocking_level: "parent",
      summary: `La delegación de ${insecureAncestorDelegation.from} hacia ${insecureAncestorDelegation.to}, en un nivel intermedio de la cadena hacia ${domainZone.zone}, no es segura, bloqueando la cadena de confianza.`,
      technical_summary: `Delegación intermedia ${insecureAncestorDelegation.from} -> ${insecureAncestorDelegation.to} sin DS válido. El dominio no puede completar la cadena DNSSEC sin acción de esa capa.`,
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

  // 4.5) NUEVO (2026-09-16) — Evidencia ambigua en una zona/delegación
  // ancestro intermedia (status "unknown" no explicado por un error duro
  // ya capturado arriba): nunca se fuerza un veredicto "ok" ignorando
  // esta incertidumbre — cae en indeterminate, igual que cualquier otra
  // evidencia insuficiente del motor (sección 6 del alcance de esta
  // fase: "error de medición intermedio nunca debe transformarse
  // falsamente en un veredicto técnico").
  if (ambiguousAncestorZone || ambiguousAncestorDelegation) {
    const final_status = DNSSEC_FINAL_STATUS.INDETERMINATE;
    return {
      final_status,
      readiness: DNSSEC_READINESS.UNKNOWN,
      blocking_level: "unknown",
      summary: "No fue posible clasificar el estado DNSSEC de forma concluyente: hay evidencia insuficiente en un nivel intermedio de la cadena.",
      technical_summary: ambiguousAncestorZone
        ? `Estado no determinante en la zona intermedia ${ambiguousAncestorZone.zone} — no se puede confirmar si está firmada.`
        : `Estado no determinante en la delegación intermedia ${ambiguousAncestorDelegation.from} -> ${ambiguousAncestorDelegation.to} — no se puede confirmar si es segura.`,
    };
  }

  // 5) OK
  if (domainSigned && secureDelegation) {
    // 5.1) NUEVO (2026-11-04, opt-in) — evidencia criptográfica real del
    // Observatorio DNSSEC v2 contradice lo que este motor concluye por
    // presencia de DS/DNSKEY. Solo se evalúa si dnsvizSignal fue provisto
    // explícitamente (ver comentario en la firma de la función) — nunca
    // cambia el resultado de un análisis individual normal sin ese dato.
    if (dnsvizSignal && dnsvizSignal.hasCryptoFailure) {
      const codes = (dnsvizSignal.issues || []).map((i) => i.code).filter(Boolean).join(", ") || "sin código";
      const final_status = DNSSEC_FINAL_STATUS.MISCONFIGURED;
      return {
        final_status,
        readiness: DNSSEC_READINESS.ALREADY_ENABLED,
        blocking_level: "domain",
        summary: `${domainZone.zone} tiene DS y DNSKEY presentes, pero una verificación criptográfica real (DNSViz) detectó un problema de validación (${codes}). La cadena de confianza no es válida pese a la evidencia estructural.`,
        technical_summary: `Evidencia estructural (DS/DNSKEY) sugería OK, pero DNSViz reportó fallo(s) criptográfico(s) real(es) en ${domainZone.zone}: ${codes}.`,
      };
    }

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