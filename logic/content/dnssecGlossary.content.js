const glossary = {
  dnssec: {
    term: "DNSSEC",
    short: "Extensión de seguridad del DNS que permite verificar la autenticidad de las respuestas.",
    detailed: "DNSSEC agrega firmas criptográficas a los registros DNS para que los resolvers puedan verificar que la respuesta no ha sido alterada.",
    why_it_matters: "Ayuda a evitar manipulación de respuestas DNS y mejora la confianza técnica en los servicios digitales.",
    example: "Sin DNSSEC, un usuario podría recibir una respuesta DNS falsa sin que el sistema lo detecte."
  },
  chain_of_trust: {
    term: "Cadena de confianza",
    short: "Secuencia de validación desde la capa superior hasta el dominio.",
    detailed: "La cadena de confianza DNSSEC conecta criptográficamente una zona con su zona hija mediante DS y DNSKEY.",
    why_it_matters: "Si un eslabón falla, la validación completa se rompe.",
    example: "Aunque el dominio esté firmado, si la zona padre no lo está, la cadena no valida."
  },
  zone: {
    term: "Zona DNS",
    short: "Porción del espacio de nombres DNS administrada separadamente.",
    detailed: "Cada zona puede estar firmada o no con DNSSEC. El análisis revisa cada una en la cadena del dominio.",
    why_it_matters: "DNSSEC se implementa por zonas, no como una sola configuración global.",
    example: "ec, gob.ec y ministerio.gob.ec pueden comportarse como capas distintas del análisis."
  },
  delegation: {
    term: "Delegación DNS",
    short: "Relación entre una zona padre y una zona hija.",
    detailed: "La delegación indica cómo la zona padre referencia la zona hija. En DNSSEC, esta relación debe ser segura.",
    why_it_matters: "Una delegación insegura puede impedir una validación completa.",
    example: "gob.ec delega el control de ministerio.gob.ec."
  },
  ds: {
    term: "Registro DS",
    short: "Registro que enlaza criptográficamente la zona padre con la zona hija.",
    detailed: "El DS publicado en la zona padre contiene un hash del DNSKEY de la zona hija.",
    why_it_matters: "Sin DS, la cadena de confianza no puede continuar hacia la zona hija.",
    example: "Un dominio puede estar firmado, pero sin DS en su padre no se valida plenamente."
  },
  readiness: {
    term: "Readiness",
    short: "Indica si el dominio ya está en condiciones de activar DNSSEC.",
    detailed: "Readiness no dice solo si DNSSEC está activo, sino si las capas superiores ya permiten activarlo correctamente.",
    why_it_matters: "Distingue entre falta de acción y bloqueo por dependencia externa.",
    example: "Un dominio puede no tener DNSSEC, pero estar listo para implementarlo."
  },
  blocking: {
    term: "Bloqueo estructural",
    short: "Imposibilidad de implementar DNSSEC por dependencia de una capa superior.",
    detailed: "Ocurre cuando una zona superior no está firmada o no permite una cadena segura de delegación.",
    why_it_matters: "En estos casos el operador del dominio no puede resolver por sí solo el problema.",
    example: "Si el TLD no está firmado, muchos dominios inferiores quedan limitados."
  }
};

function getGlossaryForStatus(status) {
  switch (status) {
    case "blocked_at_tld":
      return [
        glossary.dnssec,
        glossary.chain_of_trust,
        glossary.zone,
        glossary.blocking
      ];
    case "blocked_at_parent":
      return [
        glossary.dnssec,
        glossary.chain_of_trust,
        glossary.delegation,
        glossary.blocking
      ];
    case "not_implemented":
      return [
        glossary.dnssec,
        glossary.readiness,
        glossary.delegation,
        glossary.ds
      ];
    case "non_existent":
      return [
        glossary.dnssec,
        glossary.zone,
        glossary.delegation
      ];
    case "indeterminate":
      return [
        glossary.dnssec,
        glossary.chain_of_trust
      ];
    case "misconfigured":
      return [
        glossary.dnssec,
        glossary.ds,
        glossary.chain_of_trust,
        glossary.delegation
      ];
    case "ok":
      return [
        glossary.dnssec,
        glossary.chain_of_trust,
        glossary.ds
      ];
    default:
      return [glossary.dnssec];
  }
}

module.exports = { getGlossaryForStatus };