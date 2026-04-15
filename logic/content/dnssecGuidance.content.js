function getDnssecGuidance(status) {
  switch (status) {
    case "blocked_at_tld":
      return {
        title: "Bloqueo estructural en la capa superior del DNS",
        diagnosis: "La zona superior del dominio no está firmada con DNSSEC, por lo que la cadena de confianza no puede completarse.",
        why_it_matters: "Esto limita la autenticidad verificable de las respuestas DNS y reduce la confianza técnica en el dominio y en otros dominios bajo la misma estructura.",
        impact: "El problema no afecta solo a este dominio, sino potencialmente a múltiples dominios dependientes de la misma capa superior.",
        policy_angle: "Este hallazgo sugiere la necesidad de acciones coordinadas de infraestructura, gobernanza y política pública para fortalecer la confianza digital.",
        standards: [
          "NIST SP 800-81r3",
          "RFC 9364",
          "RFC 4033",
          "RFC 4034",
          "RFC 4035"
        ],
        recommendations: [
          "Evaluar la implementación de DNSSEC en la zona superior.",
          "Coordinar con el operador del registry o de la capa superior.",
          "Preparar los dominios críticos para activación una vez habilitada la infraestructura superior."
        ],
        call_to_action: "ISOC LAC recomienda tratar este tipo de hallazgo como una oportunidad de mejora estructural y no solo como un problema aislado de un dominio individual."
      };

    case "blocked_at_parent":
      return {
        title: "Bloqueo en la zona padre inmediata",
        diagnosis: "La zona padre inmediata no está firmada, por lo que el dominio no puede completar una cadena válida de confianza DNSSEC.",
        why_it_matters: "Aunque el dominio quiera implementar DNSSEC, la validación queda interrumpida en la capa superior inmediata.",
        impact: "El dominio no depende únicamente de su propia configuración, sino también de la capacidad de la zona padre para soportar delegación segura.",
        policy_angle: "Este resultado muestra un cuello de botella operativo o institucional en la capa intermedia de la delegación DNS.",
        standards: [
          "NIST SP 800-81r3",
          "RFC 9364",
          "RFC 4033",
          "RFC 4034",
          "RFC 4035"
        ],
        recommendations: [
          "Coordinar con el operador de la zona padre inmediata.",
          "Verificar si la zona intermedia tiene un plan de despliegue DNSSEC.",
          "Preparar el dominio para activación cuando la zona padre quede habilitada."
        ],
        call_to_action: "ISOC LAC recomienda identificar claramente a la capa responsable para orientar mejor la acción correctiva."
      };

    case "ready":
      return {
        title: "Dominio listo para implementar DNSSEC",
        diagnosis: "Las capas superiores permiten el despliegue de DNSSEC, pero el dominio aún no lo ha activado.",
        why_it_matters: "El dominio puede mejorar su nivel de seguridad y confianza con una acción directa bajo control del operador.",
        impact: "La ausencia de DNSSEC en este caso no se debe a bloqueo estructural, sino a una oportunidad pendiente de implementación.",
        policy_angle: "Este tipo de hallazgo refleja una brecha de adopción y puede abordarse con lineamientos técnicos, incentivos o requisitos institucionales.",
        standards: [
          "NIST SP 800-81r3",
          "RFC 9364",
          "RFC 4033",
          "RFC 4034",
          "RFC 4035"
        ],
        recommendations: [
          "Firmar la zona DNS del dominio.",
          "Publicar DNSKEY y firmas correspondientes.",
          "Registrar el DS en la zona padre.",
          "Verificar la cadena completa de confianza."
        ],
        call_to_action: "ISOC LAC recomienda activar DNSSEC como medida prioritaria de fortalecimiento de confianza digital."
      };

    case "misconfigured":
      return {
        title: "DNSSEC presente pero mal configurado",
        diagnosis: "El dominio muestra señales de implementación DNSSEC, pero la delegación o validación no está completa correctamente.",
        why_it_matters: "Una configuración incompleta o inconsistente puede generar fallos de validación y pérdida de confianza técnica.",
        impact: "El problema afecta directamente la confiabilidad operativa del dominio y puede dificultar diagnósticos posteriores.",
        policy_angle: "Este tipo de hallazgo sugiere necesidad de capacidades técnicas, validación periódica y mejores prácticas operativas.",
        standards: [
          "NIST SP 800-81r3",
          "RFC 9364",
          "RFC 4033",
          "RFC 4034",
          "RFC 4035"
        ],
        recommendations: [
          "Revisar si el DS en la zona padre corresponde al DNSKEY del dominio.",
          "Revisar firmas, claves y tiempos de vigencia.",
          "Validar nuevamente la cadena completa."
        ],
        call_to_action: "ISOC LAC recomienda corregir la configuración antes de considerar el despliegue como satisfactorio."
      };

    case "ok":
      return {
        title: "DNSSEC correctamente desplegado",
        diagnosis: "El dominio presenta una cadena válida o consistente de confianza DNSSEC.",
        why_it_matters: "Esto fortalece la autenticidad de las respuestas DNS y mejora la confianza técnica en el servicio.",
        impact: "El dominio se encuentra en una mejor posición de seguridad y madurez operativa frente a la integridad de resolución DNS.",
        policy_angle: "Estos casos pueden servir como referencia de buenas prácticas para otros operadores y autoridades.",
        standards: [
          "NIST SP 800-81r3",
          "RFC 9364",
          "RFC 4033",
          "RFC 4034",
          "RFC 4035"
        ],
        recommendations: [
          "Mantener monitoreo periódico.",
          "Revisar rotación de claves y vigencia de firmas.",
          "Documentar la configuración como buena práctica replicable."
        ],
        call_to_action: "ISOC LAC recomienda usar estos casos como referencia de adopción efectiva y confianza digital."
      };

    case "not_implemented":
      return {
        title: "DNSSEC no implementado — acción disponible",
        diagnosis: "Las capas superiores del DNS permiten DNSSEC, pero el dominio aún no ha firmado su zona ni publicado un registro DS en la zona padre.",
        why_it_matters: "El dominio puede ser víctima de ataques de envenenamiento de caché DNS o redirección maliciosa sin que el usuario pueda detectarlo.",
        impact: "La ausencia de DNSSEC en este caso no depende de terceros: es una brecha directamente corregible por el operador del dominio.",
        policy_angle: "Este tipo de hallazgo refleja una brecha de adopción técnica. Puede abordarse con lineamientos institucionales, incentivos o requisitos de política pública.",
        standards: [
          "NIST SP 800-81r3",
          "RFC 9364",
          "RFC 4033",
          "RFC 4034",
          "RFC 4035"
        ],
        recommendations: [
          "Firmar la zona DNS del dominio con claves DNSSEC (ZSK y KSK).",
          "Publicar el registro DNSKEY en la zona.",
          "Registrar el DS correspondiente en la zona padre a través del registrador.",
          "Verificar la cadena completa de confianza con herramientas como DNSViz o Verisign DNSSEC Debugger.",
          "Establecer procedimientos de rotación de claves y monitoreo periódico."
        ],
        call_to_action: "ISOC LAC recomienda activar DNSSEC como medida prioritaria. Las capas superiores ya lo soportan: la acción correctiva está dentro del alcance directo del operador."
      };

    case "non_existent":
      return {
        title: "Dominio no existente o no verificable",
        diagnosis: "No se encontró evidencia de que el nombre de dominio exista como zona DNS operativa.",
        why_it_matters: "Sin existencia confirmada, no es posible evaluar ni implementar DNSSEC.",
        impact: "El análisis DNSSEC no es aplicable hasta que el dominio esté correctamente registrado y delegado.",
        policy_angle: "Este caso puede indicar un dominio dado de baja, mal configurado o aún no registrado.",
        standards: [
          "RFC 1034",
          "RFC 1035"
        ],
        recommendations: [
          "Confirmar que el nombre de dominio esté correctamente registrado.",
          "Verificar la existencia de registros A, AAAA o CNAME.",
          "Revisar si el dominio está delegado correctamente por el registrador.",
          "Comprobar si se trata de un subdominio dentro de una zona mayor."
        ],
        call_to_action: "ISOC LAC recomienda confirmar la existencia y delegación del dominio antes de realizar cualquier evaluación DNSSEC."
      };

    case "indeterminate":
      return {
        title: "Resultado no concluyente",
        diagnosis: "La evidencia disponible no permite determinar el estado DNSSEC del dominio con certeza suficiente.",
        why_it_matters: "Un resultado indeterminado puede ocultar problemas reales de configuración o de infraestructura.",
        impact: "Sin una clasificación clara, no es posible emitir recomendaciones específicas de acción.",
        policy_angle: "La indeterminación recurrente puede indicar limitaciones de infraestructura DNS o problemas operativos que requieren atención.",
        standards: [
          "RFC 4033",
          "RFC 4034",
          "RFC 4035"
        ],
        recommendations: [
          "Verificar el estado DNS con herramientas especializadas como DNSViz.",
          "Consultar resolutores validadores para confirmar el comportamiento real.",
          "Revisar manualmente la delegación, DNSKEY y DS del dominio.",
          "Repetir el análisis en un momento posterior para descartar problemas transitorios."
        ],
        call_to_action: "ISOC LAC recomienda complementar este resultado con herramientas de validación externa antes de tomar decisiones basadas en él."
      };

    default:
      return {
        title: "Análisis DNSSEC",
        diagnosis: "No fue posible emitir una guía concluyente.",
        why_it_matters: "",
        impact: "",
        policy_angle: "",
        standards: [],
        recommendations: [],
        call_to_action: ""
      };
  }
}

module.exports = { getDnssecGuidance };