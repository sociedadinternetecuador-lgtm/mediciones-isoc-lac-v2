// (2026-09-16) — "READY" se eliminó: computeDnssecConclusion() (logic/rules/
// dnssec.rules.js) nunca lo producía (los 7 estados realmente alcanzables
// son los que quedan abajo) — confirmado por grep antes de borrar, no
// asumido. Ver AUDITORIA_DNSSEC_ECUADOR_METODOLOGIA_MOTOR.md e
// IMPLEMENTACION_DNSSEC_AUDITORIA_CORE.md.
const DNSSEC_FINAL_STATUS = {
  OK: "ok",
  NOT_IMPLEMENTED: "not_implemented",
  BLOCKED_AT_TLD: "blocked_at_tld",
  BLOCKED_AT_PARENT: "blocked_at_parent",
  MISCONFIGURED: "misconfigured",
  INDETERMINATE: "indeterminate",
  NON_EXISTENT: "non_existent"
};

const DNSSEC_READINESS = {
  READY_TO_ENABLE: "ready_to_enable",
  ALREADY_ENABLED: "already_enabled",
  BLOCKED_BY_TLD: "blocked_by_tld",
  BLOCKED_BY_PARENT: "blocked_by_parent",
  UNKNOWN: "unknown"
};

const DNSSEC_ZONE_STATUS = {
  SIGNED: "signed",
  UNSIGNED: "unsigned",
  UNKNOWN: "unknown"
};

const DNSSEC_DELEGATION_STATUS = {
  SECURE: "secure",
  INSECURE: "insecure",
  BROKEN: "broken",
  UNKNOWN: "unknown"
};

module.exports = {
  DNSSEC_FINAL_STATUS,
  DNSSEC_READINESS,
  DNSSEC_ZONE_STATUS,
  DNSSEC_DELEGATION_STATUS
};