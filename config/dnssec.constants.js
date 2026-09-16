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

// (2026-09-16) — "BROKEN" se eliminó: mapDelegationStatus()
// (services/dnssec.service.js) nunca podía producirlo — su único invocador
// calcula `secure = ds.found === true` y pasa `dsPresent = ds.found` (el
// mismo valor fuente), así que la condición `dsPresent === true && secure
// === false` era algebraicamente imposible. Demostrado con 24
// combinaciones representativas del flujo DoH real, ninguna lo producía.
// Ver AUDITORIA_DNSSEC_BROKEN_DELEGATION.md e
// IMPLEMENTACION_DNSSEC_AUDITORIA_CORE.md. El caso que pretendía cubrir
// (DS presente, DNSKEY del hijo ausente) ya se detecta correctamente por
// el estado de la zona (UNSIGNED) — no se pierde ninguna capacidad de
// diagnóstico al eliminarlo.
const DNSSEC_DELEGATION_STATUS = {
  SECURE: "secure",
  INSECURE: "insecure",
  UNKNOWN: "unknown"
};

module.exports = {
  DNSSEC_FINAL_STATUS,
  DNSSEC_READINESS,
  DNSSEC_ZONE_STATUS,
  DNSSEC_DELEGATION_STATUS
};