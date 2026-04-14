const express = require("express");
const router = express.Router();

const { validateDomainInput } = require("../logic/validators/domain.validator");
const { getDnssecAnalysis } = require("../services/dnssec.service");
const { processDnssecAnalysis } = require("../logic/processors/dnssec.processor");

router.get("/dnssec-analysis", async (req, res) => {
  try {
    const domain = validateDomainInput(req.query.domain);

    const raw = await getDnssecAnalysis(domain);
    const result = processDnssecAnalysis(raw);

    res.json(result);
  } catch (error) {
    if (error.code === "INVALID_DOMAIN") {
      return res.status(400).json({
        error: "invalid_domain",
        message: "El dominio ingresado no es válido."
      });
    }

    return res.status(500).json({
      error: "dnssec_analysis_failed",
      message: "No se pudo completar el análisis DNSSEC."
    });
  }
});

module.exports = router;