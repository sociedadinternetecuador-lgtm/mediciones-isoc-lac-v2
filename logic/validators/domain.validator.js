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