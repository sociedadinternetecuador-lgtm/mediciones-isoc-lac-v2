'use strict';

/**
 * Rate limiter genérico por IP — ventana deslizante simple, en memoria.
 * Sin dependencia nueva. Pensado para proteger /admin/api/login.
 */

function createRateLimiter({ maxAttempts, windowMs }) {
  const attemptsByIp = new Map();

  function check(ip) {
    const now = Date.now();
    const entry = attemptsByIp.get(ip);
    if (!entry || now - entry.windowStart > windowMs) {
      attemptsByIp.set(ip, { windowStart: now, count: 1 });
      return { allowed: true, remaining: maxAttempts - 1 };
    }
    if (entry.count >= maxAttempts) {
      return { allowed: false, retryAfterMs: windowMs - (now - entry.windowStart) };
    }
    entry.count += 1;
    return { allowed: true, remaining: maxAttempts - entry.count };
  }

  function reset(ip) {
    attemptsByIp.delete(ip);
  }

  return { check, reset };
}

module.exports = { createRateLimiter };
