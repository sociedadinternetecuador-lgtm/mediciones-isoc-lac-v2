const { computeDnssecConclusion } = require("../rules/dnssec.rules");
const { buildStandardResponse } = require("../core/result.formatter");
const { getDnssecGuidance } = require("../content/dnssecGuidance.content");
const { getGlossaryForStatus } = require("../content/dnssecGlossary.content");

function buildExecutiveSummary(finalStatus, readiness, confidence) {
  switch (finalStatus) {
    case "ok":
      return {
        status: "DNSSEC correctamente implementado",
        risk_level: "bajo",
        action_required: false,
        decision_note: "El dominio muestra evidencia estructural consistente de implementación DNSSEC."
      };

    case "ready":
    case "not_implemented":
      return {
        status: "DNSSEC no implementado",
        risk_level: "medio",
        action_required: true,
        decision_note: "Las capas superiores permiten DNSSEC, pero el nombre analizado no muestra evidencia de despliegue propio."
      };

    case "blocked_at_tld":
      return {
        status: "Bloqueo estructural en capa superior",
        risk_level: "alto",
        action_required: true,
        decision_note: "La barrera no está en el nombre final, sino en la infraestructura superior."
      };

    case "blocked_at_parent":
      return {
        status: "Bloqueo en la zona padre inmediata",
        risk_level: "alto",
        action_required: true,
        decision_note: "La implementación depende de una capa intermedia que actualmente no soporta la cadena de confianza."
      };

    case "misconfigured":
      return {
        status: "DNSSEC presente pero inconsistente",
        risk_level: "alto",
        action_required: true,
        decision_note: "El nombre muestra despliegue parcial o inconsistente que requiere corrección técnica."
      };

    case "non_existent":
      return {
        status: "Nombre no existente o no verificable como zona independiente",
        risk_level: "medio",
        action_required: false,
        decision_note: "La evidencia disponible no confirma existencia operativa ni despliegue DNSSEC del nombre analizado."
      };

    case "indeterminate":
    default:
      return {
        status: "Resultado no concluyente",
        risk_level: confidence === "low" ? "indeterminado" : "medio",
        action_required: false,
        decision_note: "La evidencia disponible no permite una conclusión final confiable."
      };
  }
}

function buildHumanReadable(result, context = {}) {
  const { domain } = context;

  const dnssec = result?.dnssec || result || {};
  const finalStatus = dnssec?.final_status || "indeterminate";
  const certainty = dnssec?.assessment_meta?.confidence || result?.assessment_meta?.confidence || "medium";

  let title = "";
  let summary = "";
  let certainty_text = "";
  let next_steps = [];

  if (certainty === "high") {
    certainty_text = "Certeza alta: la evidencia es consistente.";
  } else if (certainty === "medium") {
    certainty_text = "Certeza media: existen limitaciones estructurales del análisis.";
  } else {
    certainty_text = "Certeza baja: el resultado debe interpretarse con cautela.";
  }

  switch (finalStatus) {
    case "ok":
      title = "DNSSEC correctamente implementado";
      summary = `El dominio ${domain} muestra evidencia consistente de implementación DNSSEC, incluyendo firma y delegación segura.`;
      next_steps = ["Mantener monitoreo periódico", "Verificar continuidad de firmas y delegación segura"];
      break;

    case "ready":
    case "not_implemented":
      title = "DNSSEC no implementado";
      summary = `Las capas superiores permiten DNSSEC, pero ${domain} no muestra evidencia de despliegue propio.`;
      next_steps = ["Evaluar implementación de DNSSEC", "Revisar firma de zona y publicación de DS"];
      break;

    case "non_existent":
      title = "Nombre no existente o no verificable";
      summary = `No se encontró evidencia de existencia operativa ni de despliegue DNSSEC para ${domain}.`;
      next_steps = ["Confirmar que el nombre exista", "Verificar registros A, AAAA o CNAME", "Comprobar si se trata de una zona independiente"];
      break;

    case "misconfigured":
      title = "DNSSEC presente pero inconsistente";
      summary = `El dominio ${domain} muestra señales de DNSSEC, pero con evidencia estructural inconsistente o incompleta.`;
      next_steps = [
        "Revisar si el DS en la zona padre corresponde al DNSKEY del dominio",
        "Revisar firmas, claves y tiempos de vigencia",
        "Validar nuevamente la cadena completa"
      ];
      break;

    case "blocked_at_tld":
      title = "Bloqueo estructural en capa superior";
      summary = `El dominio ${domain} no puede implementar DNSSEC porque la capa superior no está firmada.`;
      next_steps = ["Verificar estado DNSSEC del TLD", "Escalar el hallazgo como limitación estructural"];
      break;

    case "blocked_at_parent":
      title = "Bloqueo en la zona padre inmediata";
      summary = `El dominio ${domain} depende de una zona padre inmediata que no soporta adecuadamente la cadena de confianza.`;
      next_steps = ["Revisar la zona padre inmediata", "Confirmar firma y publicación de DS en la capa intermedia"];
      break;

    case "indeterminate":
    default:
      title = "Resultado no concluyente";
      summary = `No es posible determinar con certeza el estado DNSSEC de ${domain}.`;
      next_steps = [
        "Verificar con herramientas DNSSEC especializadas",
        "Consultar resolutores validadores",
        "Confirmar existencia con registros A, AAAA o CNAME"
      ];
      break;
  }

  return {
    title,
    summary,
    certainty,
    certainty_text,
    note_scope:
      "Este análisis evalúa evidencia estructural en DNS, no validación criptográfica completa.",
    note_special:
      "En nombres de dominio que no están delegados como zonas DNS independientes, la ausencia de registros DNSKEY o DS no implica necesariamente la inexistencia del servicio, sino que puede responder a la forma en que está estructurada la delegación o a la ausencia de implementación de DNSSEC. Esto puede ocurrir, por ejemplo, en subdominios utilizados para portales o aplicaciones dentro de dominios mayores.",
    next_steps
  };
}

function processDnssecAnalysis(raw) {
  const domain = raw?.domain || null;
  const zones = raw?.raw_checks?.zones || [];
  const delegations = raw?.raw_checks?.delegations || [];
  const nameExistence = raw?.raw_checks?.name_existence || null;
  const assessmentMeta = raw?.assessment_meta || {};

  const conclusion = computeDnssecConclusion(
    zones,
    delegations,
    domain,
    nameExistence
  );

  const guidance = getDnssecGuidance(conclusion.final_status);
  const glossary = getGlossaryForStatus(conclusion.final_status);

  const executiveSummary = buildExecutiveSummary(
    conclusion.final_status,
    conclusion.readiness,
    assessmentMeta.confidence || "unknown"
  );

  const final_result = buildStandardResponse({
    domain,
    indicator: "dnssec",
    payload: {
      zones,
      delegations,
      name_existence: nameExistence,
      final_status: conclusion.final_status,
      readiness: conclusion.readiness,
      blocking_level: conclusion.blocking_level,
      summary: conclusion.summary,
      technical_summary: conclusion.technical_summary,
      executive_summary: executiveSummary,
      assessment_meta: assessmentMeta,
      guidance,
      glossary
    }
  });

  final_result.human = buildHumanReadable(final_result, { domain });

  return final_result;
}

module.exports = { processDnssecAnalysis };