const { domainToASCII } = require("url");

function sanitizeDomain(input) {
  if (!input || typeof input !== "string") {
    return null;
  }

  let domain = input.trim().toLowerCase();

  // elimina http:// o https://
  domain = domain.replace(/^https?:\/\//, "");

  // elimina rutas después del dominio
  domain = domain.replace(/\/.*$/, "");

  // elimina punto final
  domain = domain.replace(/\.$/, "");

  // IDNA/punycode (2026-09-16, corrección objetiva — no amplía el motor,
  // corrige entrada válida): un dominio internacionalizado en su forma
  // Unicode natural (ej. "café.com") se convertía en "Dominio inválido"
  // porque isLikelyValidDomain() exige [a-z0-9-] por etiqueta. Node ya
  // expone esta conversión de forma nativa y estándar (mismo mecanismo que
  // ya usa server.js para MEDICIONES) — no se implementa IDNA a mano.
  // domainToASCII() devuelve "" ante una entrada que ni siquiera es un
  // hostname parseable; ese caso ya lo rechaza el "|| null" de abajo, igual
  // que antes de este cambio.
  domain = domainToASCII(domain);

  return domain || null;
}

function isLikelyValidDomain(domain) {
  if (!domain || typeof domain !== "string") {
    return false;
  }

  if (domain.length > 253) {
    return false;
  }

  const labels = domain.split(".");

  if (labels.length < 2) {
    return false;
  }

  return labels.every((label) => {
    if (!label || label.length > 63) {
      return false;
    }

    return /^[a-z0-9-]+$/i.test(label) &&
      !label.startsWith("-") &&
      !label.endsWith("-");
  });
}

function validateDomainInput(input) {
  const domain = sanitizeDomain(input);

  if (!domain || !isLikelyValidDomain(domain)) {
    const error = new Error("Dominio inválido");
    error.code = "INVALID_DOMAIN";
    throw error;
  }

  return domain;
}

module.exports = {
  sanitizeDomain,
  isLikelyValidDomain,
  validateDomainInput
};