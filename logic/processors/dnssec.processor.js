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
        risk_level: "estructural",
        action_required: true,
        decision_note: "La barrera no está en el dominio analizado sino en la infraestructura superior. El operador debe escalar al registry o TLD correspondiente."
      };

    case "blocked_at_parent":
      return {
        status: "Bloqueo en la zona padre inmediata",
        risk_level: "estructural",
        action_required: true,
        decision_note: "La implementación depende de una capa intermedia que no soporta DNSSEC. Debe coordinarse con el operador de esa zona."
      };

    case "misconfigured":
      return {
        status: "DNSSEC presente pero mal configurado",
        risk_level: "alto",
        action_required: true,
        decision_note: "El nombre muestra despliegue parcial o inconsistente que requiere corrección técnica."
      };

    case "non_existent":
      return {
        status: "Nombre no existente o no verificable",
        risk_level: "no aplicable",
        action_required: false,
        decision_note: "El dominio no existe como zona DNS operativa. El análisis DNSSEC no es aplicable hasta confirmar existencia y delegación."
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

  // Fuente única de recomendaciones: guidance.recommendations
  // next_steps se deriva de ella para mantener una sola fuente de verdad
  const next_steps = Array.isArray(dnssec?.guidance?.recommendations)
    ? dnssec.guidance.recommendations
    : [];

  // human.summary toma el summary de rules (ya específico por caso) para evitar doble redacción
  const summary = dnssec?.summary || "";

  const certainty_text =
    certainty === "high" ? "Certeza alta: la evidencia es consistente." :
    certainty === "medium" ? "Certeza media: existen limitaciones estructurales del análisis." :
    "Certeza baja: el resultado debe interpretarse con cautela.";

  let title = "";

  switch (finalStatus) {
    case "ok":              title = "DNSSEC correctamente implementado"; break;
    case "not_implemented": title = "DNSSEC no implementado"; break;
    case "non_existent":    title = "Nombre no existente o no verificable"; break;
    case "misconfigured":   title = "DNSSEC presente pero mal configurado"; break;
    case "blocked_at_tld":  title = "Bloqueo estructural en capa superior"; break;
    case "blocked_at_parent": title = "Bloqueo en la zona padre inmediata"; break;
    case "indeterminate":
    default:                title = "Resultado no concluyente"; break;
  }

  const noteSpecialMap = {
    ok: "La cadena de confianza verificada es estructural, no criptográfica completa. Se recomienda complementar con herramientas validadoras como DNSViz para confirmar la firma activa.",
    not_implemented: "La ausencia de DNSKEY o DS no implica inexistencia del servicio. El dominio puede estar operativo sin haber implementado DNSSEC. Esta es una oportunidad de mejora directamente accionable.",
    misconfigured: "Una configuración DNSSEC incompleta puede provocar fallos de resolución silenciosos para usuarios detrás de resolvers validadores. Es recomendable corregir antes de que afecte la disponibilidad.",
    blocked_at_tld: "Esta limitación no es atribuible al operador del dominio analizado. La acción correctiva debe realizarse en la capa superior (TLD o registry), lo que puede requerir coordinación institucional.",
    blocked_at_parent: "La barrera está en una zona intermedia, no en el dominio final. La corrección requiere coordinación con el operador de esa zona padre, lo que puede estar fuera del control directo del titular del dominio.",
    non_existent: "Si el nombre es un subdominio de uso interno o una zona delegada de forma no convencional, es posible que no aparezca como zona independiente en el DNS público. Verificar con el administrador del dominio padre.",
    indeterminate: "Los errores de consulta pueden ser transitorios. Se recomienda repetir el análisis en un momento distinto antes de tomar decisiones basadas en este resultado."
  };

  const note_special = noteSpecialMap[finalStatus] || "Este análisis evalúa evidencia estructural en DNS y debe complementarse con validación técnica adicional cuando el caso lo requiera.";

  return {
    title,
    summary,
    certainty,
    certainty_text,
    note_scope: "Este análisis evalúa evidencia estructural en DNS, no validación criptográfica completa.",
    note_special,
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