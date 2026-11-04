#!/usr/bin/env node
'use strict';

/**
 * Verificación periódica ("canario") del sistema en producción.
 *
 * Corre contra la API REAL en producción (no contra funciones internas) —
 * igual principio que los *.live.smoke.test.js: es un observador externo,
 * no una prueba unitaria. Un puñado fijo de casos con resultado esperado
 * conocido de antemano; si alguno se desvía, es una señal real de que algo
 * cambió en el entorno (un WAF empezó a bloquearnos, una API externa dejó
 * de responder, facturación de un servicio externo se cerró, etc.) — el
 * mismo tipo de problema real que motivó este script (ver commit
 * "fix(safeWebFetch): send a real User-Agent on every outbound request").
 *
 * No reemplaza `npm test` (eso valida LÓGICA con datos simulados, sin red).
 * Esto valida que el SISTEMA REAL EN VIVO sigue respondiendo como se
 * espera — separar validación de ejecución, por diseño.
 *
 * Uso manual: node scripts/canary-check.js
 * Uso programado: ver scripts/canary-check.service / .timer (systemd --user en server1).
 *
 * Variables de entorno:
 *   MEDICIONES_BASE_URL     (default: https://mediciones.isoc.org.ec)
 *   CANARY_ALERT_EMAIL      (a quién avisar si algo falla; si no está,
 *                            usa SUPER_ADMIN_RECOVERY_EMAIL)
 *   SMTP_HOST/PORT/USER/PASSWORD/FROM (ya existentes, para el aviso)
 */

const path = require('path');
const emailAdapter = require(path.join(__dirname, '..', 'logic', 'adapters', 'email.adapter'));

const BASE_URL = (process.env.MEDICIONES_BASE_URL || 'https://mediciones.isoc.org.ec').replace(/\/+$/, '');
const TIMEOUT_MS = 20000;

function fetchJson(url, { timeoutMs = TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https:') ? require('https') : require('http');
    const req = lib.get(url, { headers: { 'User-Agent': 'MedicionesISOCLAC-Canary/1.0' } }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        try {
          resolve({ statusCode: res.statusCode, body: JSON.parse(data) });
        } catch (e) {
          resolve({ statusCode: res.statusCode, body: null, parseError: true, raw: data.slice(0, 300) });
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(timeoutMs, () => req.destroy(new Error('Timeout')));
  });
}

// Dominios/casos canario — resultado esperado documentado explícitamente,
// no inferido. Revisar y actualizar si el dominio de referencia cambia de
// estado real (ej. si isoc.org alguna vez desactiva DNSSEC a propósito).
const CHECKS = [
  {
    name: 'HTTPS de isoc.org.ec (vía WAF Cloudflare)',
    url: () => `${BASE_URL}/headers/isoc.org.ec`,
    validate: (body) => body && body.statusCode === 200 && body.https === true,
    context: 'Si esto falla con 429/403, es muy probable que falte un User-Agent en alguna llamada saliente (ver fix de 2026-11-04) o que el WAF cambió de criterio.'
  },
  {
    name: 'WHOIS de isoc.org.ec',
    url: () => `${BASE_URL}/whois/isoc.org.ec`,
    validate: (body) => body && !body.error,
    context: 'Si falla, revisar si whois.com cambió de formato o empezó a bloquear sin User-Agent.'
  },
  {
    name: 'Hosts asociados (hackertarget) de isoc.org.ec',
    url: () => `${BASE_URL}/associatedhosts/isoc.org.ec`,
    validate: (body) => body && Array.isArray(body.hosts),
    context: 'Si falla, revisar api.hackertarget.com (cuota gratuita del servicio, o bloqueo sin User-Agent).'
  },
  {
    name: 'DNSSEC de isoc.org (dominio con DNSSEC real y válido conocido)',
    url: () => `${BASE_URL}/dnssec-analysis?domain=isoc.org&format=json`,
    validate: (body) => body && body.dnssec && body.dnssec.final_status === 'ok',
    context: 'isoc.org tiene DNSSEC correctamente configurado — si esto deja de dar "ok", es señal de un bug real en el motor (dnssec.rules.js) o en la resolución DoH, no del dominio.'
  },
  {
    name: 'Contexto ISOC Pulse (API key / billing)',
    url: () => `${BASE_URL}/pulse-context?domain=isoc.org.ec`,
    validate: (body) => body && body.available === true,
    context: 'Si "available" es false, revisar PULSE_API_KEY en server1:.env y si la API key sigue vigente.'
  },
  {
    name: 'Observatorio DNSSEC v2 (dnsviz real) — salud del servicio',
    url: () => 'https://dnssec.corpece.org.ec/health',
    validate: (body) => body && body.status === 'ok',
    context: 'Si falla, revisar facturación de GCP (proyecto observatorio-dnssec) — ya pasó una vez, 2026-11-04, por tarjeta vencida.'
  }
];

async function runCanary() {
  const results = [];
  for (const check of CHECKS) {
    const url = check.url();
    try {
      const { statusCode, body, parseError, raw } = await fetchJson(url);
      const ok = !parseError && check.validate(body);
      results.push({ name: check.name, url, ok, statusCode, body: parseError ? raw : body, context: check.context });
    } catch (e) {
      results.push({ name: check.name, url, ok: false, error: e.message, context: check.context });
    }
  }
  return results;
}

async function sendAlert(failures) {
  const to = process.env.CANARY_ALERT_EMAIL || process.env.SUPER_ADMIN_RECOVERY_EMAIL;
  if (!to) {
    console.error('No hay CANARY_ALERT_EMAIL ni SUPER_ADMIN_RECOVERY_EMAIL configurado — no se pudo avisar por correo.');
    return;
  }
  if (!emailAdapter.isConfigured()) {
    console.error('SMTP no configurado — no se pudo enviar la alerta por correo.');
    return;
  }
  const lines = failures.map((f) =>
    `- ${f.name}\n  URL: ${f.url}\n  ${f.error ? 'Error: ' + f.error : 'HTTP ' + f.statusCode + ' / ' + JSON.stringify(f.body)}\n  Contexto: ${f.context}\n`
  );
  const text = `El chequeo periódico (canario) de MEDICIONES detectó ${failures.length} caso(s) fallando:\n\n${lines.join('\n')}\n\nEjecutado: ${new Date().toISOString()}\nBase: ${BASE_URL}`;
  await emailAdapter.sendMail({
    to,
    subject: `[MEDICIONES] Alerta canario — ${failures.length} chequeo(s) fallando`,
    text
  });
}

async function main() {
  const results = await runCanary();
  const failures = results.filter((r) => !r.ok);

  for (const r of results) {
    console.log(`${r.ok ? 'OK  ' : 'FAIL'} ${r.name} (${r.url})`);
    if (!r.ok) console.log(`     -> ${r.error || 'HTTP ' + r.statusCode + ' ' + JSON.stringify(r.body)}`);
  }

  if (failures.length > 0) {
    console.error(`\n${failures.length} de ${results.length} chequeos fallaron.`);
    try {
      await sendAlert(failures);
    } catch (e) {
      console.error('No se pudo enviar la alerta por correo:', e.message);
    }
    process.exit(1);
  }

  console.log(`\nTodos los chequeos (${results.length}) pasaron.`);
  process.exit(0);
}

main().catch((e) => {
  console.error('Fallo inesperado del script canario:', e);
  process.exit(2);
});
