'use strict';

/**
 * Prueba de humo EN VIVO (requiere red real) de los fixes aplicados a
 * server.js el 2026-09-09, encontrados durante cuatro rondas de
 * validación cruzada del módulo Mediciones contra herramientas
 * independientes (ver docs/arquitectura.md § "Validación cruzada con
 * herramientas independientes"). No está en el script "test" de
 * package.json — mismo criterio que rawDns.live.smoke.test.js: depende
 * del estado real de Internet, no solo de nuestro código.
 *
 * Ejecutar manualmente (con el servidor local corriendo):
 *   PORT=3500 node server.js &
 *   node test/domainChecks.live.smoke.test.js
 */

const assert = require('assert');

const BASE = process.env.MEDICIONES_TEST_BASE || 'http://localhost:3500';

async function getJSON(path) {
  const res = await fetch(`${BASE}${path}`);
  return res.json();
}

async function run() {
  // ── handleDomainInfo (RDAP): antes fallaba siempre con "Servicio no
  // disponible" porque fetchJSON() no seguía el 302 con el que rdap.org
  // redirige al servidor RDAP autoritativo del TLD, y además rdap.org
  // bloquea con 403 las peticiones sin User-Agent. Se probó contra un
  // ccTLD que sí redirige (isoc.org.ec -> rdap.registry.ec) y dos gTLD.
  const isoc = await getJSON('/domaininfo/isoc.org.ec');
  assert.ok(!isoc.error, `domaininfo/isoc.org.ec no debe fallar: ${isoc.error}`);
  assert.strictEqual(isoc.registry, '.ec DOMINIOS ECUADOR');
  assert.ok(isoc.creation, 'debe traer fecha de registro');
  assert.ok(isoc.expiration, 'debe traer fecha de expiración');
  assert.ok(Array.isArray(isoc.status) && isoc.status.length > 0);

  const google = await getJSON('/domaininfo/google.com');
  assert.ok(!google.error, `domaininfo/google.com no debe fallar: ${google.error}`);
  assert.ok(google.registry, 'gTLD también debe traer registrador');

  // Dominio inexistente: no debe tirar error genérico, solo campos vacíos
  // (RDAP responde 404 con JSON parseable, sin los campos esperados).
  const inexistente = await getJSON('/domaininfo/dominio-que-no-existe-xyz123abc.ec');
  assert.strictEqual(inexistente.error, undefined);

  // ── checkSmtpUtf8: antes probaba 25 y 587 en secuencia (hasta 15s de
  // timeout en 25, bloqueado en el hosting, antes de intentar 587).
  // Ahora corren en paralelo. Se verifica que el resultado siga siendo
  // correcto (confirmado a mano con un EHLO crudo: mail.isoc.org.ec NO
  // anuncia SMTPUTF8) y que ya no tome más de ~16s (antes ~15s + ronda
  // completa de 587 en secuencia).
  const startedAt = Date.now();
  const smtp = await getJSON('/smtputf8/isoc.org.ec');
  const elapsedMs = Date.now() - startedAt;
  assert.ok(Array.isArray(smtp.results) && smtp.results.length === 1);
  assert.strictEqual(smtp.results[0].server, 'mail.isoc.org.ec');
  assert.strictEqual(smtp.results[0].status, 'no');
  assert.ok(elapsedMs < 16000, `no debería tardar más de ~16s (tardó ${elapsedMs}ms)`);

  // ── handleTlsa: antes fallaba siempre porque dns.resolve()/resolveTlsa()
  // no reconocen el rrtype TLSA en Node 20.18.0 (el Dockerfile del
  // proyecto) — ERR_INVALID_ARG_VALUE antes de tocar la red, para
  // cualquier dominio. Ahora usa DNS-over-HTTPS de Google. Se prueba un
  // dominio sin TLSA (debe dar records:[], no error) y uno que sí tiene
  // TLSA real (torproject.org) para confirmar el parseo del formato
  // "usage selector matchingtype hex".
  const tlsaVacio = await getJSON('/tlsa/isoc.org.ec');
  assert.strictEqual(tlsaVacio.error, undefined);
  assert.deepStrictEqual(tlsaVacio.records, []);

  const tlsaReal = await getJSON('/tlsa/torproject.org');
  assert.strictEqual(tlsaReal.error, undefined);
  assert.ok(Array.isArray(tlsaReal.records) && tlsaReal.records.length > 0, 'torproject.org sí tiene TLSA');
  assert.ok(/^\d+ \d+ \d+ [0-9a-f]+$/.test(tlsaReal.records[0]), 'formato "usage selector matchingtype hex"');

  // ── handleBlock (Quad9, dentro de queryQuad9): antes fallaba siempre con
  // HTTP 505 porque Quad9 exige HTTP/2 (RFC 8484 §5.2) y el código usaba
  // https.request (HTTP/1.1). Ahora usa el módulo http2 nativo. Se prueba
  // un dominio normal (no bloqueado) y el dominio oficial de test de Quad9
  // (blocked.test.on.quad9.net) para confirmar que la detección de
  // bloqueo, no solo la ausencia de error, sigue funcionando.
  const blockNormal = await getJSON('/block/isoc.org.ec');
  const quad9Normal = blockNormal.results.find((r) => r.resolver === 'Quad9');
  assert.strictEqual(quad9Normal.error, undefined);
  assert.strictEqual(quad9Normal.blocked, false);

  const blockTest = await getJSON('/block/blocked.test.on.quad9.net');
  const quad9Test = blockTest.results.find((r) => r.resolver === 'Quad9');
  assert.strictEqual(quad9Test.error, undefined);
  assert.strictEqual(quad9Test.blocked, true, 'Quad9 debe reportar bloqueado su propio dominio de test oficial');

  // ── extractLinks (dentro de handleLinkedPages): antes marcaba como
  // "externo" cualquier link relativo sin "/" inicial (ej. "index.html"),
  // un patrón HTML común — bug determinista de la función, no depende de
  // red. Se prueba con el HTML real de isoc.org.ec, que tiene ambos casos.
  const linked = await getJSON('/linkedpages/isoc.org.ec');
  assert.ok(!linked.error, `linkedpages no debe fallar: ${linked.error}`);
  const relativo = linked.links.find((l) => l.href === 'index.html');
  assert.ok(relativo, 'debe existir el link relativo "index.html" en la página real');
  assert.strictEqual(relativo.internal, true, 'un link relativo sin "/" debe marcarse interno');
  const externo = linked.links.find((l) => l.href.includes('internetsociety.org'));
  assert.ok(externo, 'debe existir al menos un link externo real en la página');
  assert.strictEqual(externo.internal, false);

  // ── fetchRdap (usado por handleDomainInfo Y por el fallback RDAP de
  // handleWhois): antes handleWhois tenía su PROPIA llamada rota a RDAP
  // (sin seguir redirect, sin User-Agent) que nunca se había corregido
  // junto con handleDomainInfo. isoc.org.ec no tiene datos en whois.com
  // (sección "Registrant Contact" ausente), así que este resultado viene
  // exclusivamente del fallback RDAP — si fallara, "status" sería
  // "redactado_o_no_disponible" en vez de "ok".
  const whois = await getJSON('/whois/isoc.org.ec');
  assert.strictEqual(whois.status, 'ok', `esperaba datos RDAP reales, llegó: ${JSON.stringify(whois)}`);
  assert.strictEqual(whois.name, 'Francis Tigreros');
  assert.strictEqual(whois.country, 'EC');

  // ── handleArchive (Wayback Machine): antes fallaba siempre porque
  // fetchJSON() no mandaba User-Agent y web.archive.org (nginx) responde
  // 400 Bad Request sin uno. Ahora fetchJSON manda un User-Agent por
  // defecto. isoc.org.ec tiene snapshots reales desde 2004.
  const archive = await getJSON('/archive/isoc.org.ec');
  assert.ok(!archive.error, `archive no debe fallar: ${archive.error}`);
  assert.ok(Array.isArray(archive.entries) && archive.entries.length > 0, 'isoc.org.ec tiene snapshots reales en Wayback Machine');

  // ── handleQuality (PageSpeed Insights): antes, si la API respondía un
  // objeto {"error": {...}} (ej. cuota diaria agotada), el código leía
  // igual lighthouseResult (undefined) y devolvía silenciosamente
  // `pwa: null` como si hubiera evaluado el sitio. Ahora detecta
  // data.error explícitamente. No se puede afirmar en este test si la
  // cuota está agotada en el momento en que corre (cambia día a día) —
  // se verifica solo que la respuesta sea consistente: o trae scores
  // reales, o trae un error explícito, nunca un pwa:null silencioso sin
  // haber recibido lighthouseResult.
  const quality = await getJSON('/quality/isoc.org.ec');
  const tieneScores = quality.performance !== undefined || quality.accessibility !== undefined;
  assert.ok(quality.error || tieneScores, 'debe traer error explícito o scores reales, no un resultado ambiguo');

  // ── errorMessage(): antes cualquier falla de TLS (ej. certificado que no
  // cubre el hostname exacto) caía al genérico "Servicio no disponible".
  // presidencia.gob.ec sirve un certificado compartido entre ~26 sitios
  // .gob.ec cuyo SAN no incluye la variante sin "www" del dominio —
  // dominio de prueba real y estable para este caso (no depende de que
  // nosotros lo mantengamos, es una configuración del sitio del
  // gobierno). Ahora debe traer un mensaje específico de certificado.
  const headersCertMismatch = await getJSON('/headers/presidencia.gob.ec');
  assert.strictEqual(headersCertMismatch.error, 'El certificado TLS no cubre este dominio exacto');

  // ── handleSmtpUtf8 con 2+ registros MX: antes los recorría en secuencia
  // (hasta 15s cada uno) — con presidencia.gob.ec (2 MX, ambos con
  // puertos filtrados) tardaba ~30s. Ahora corren en paralelo entre sí,
  // igual que ya corrían los puertos dentro de un mismo MX.
  const startedAtMx = Date.now();
  const smtpMultiMx = await getJSON('/smtputf8/presidencia.gob.ec');
  const elapsedMsMx = Date.now() - startedAtMx;
  assert.strictEqual(smtpMultiMx.results.length, 2, 'presidencia.gob.ec tiene 2 registros MX');
  assert.ok(elapsedMsMx < 20000, `2 MX en paralelo no deberían tardar más de ~20s (tardó ${elapsedMsMx}ms)`);

  // ── handleMx: antes devolvía un error genérico cuando el dominio no
  // tiene MX (ENODATA) — le faltaba el mismo manejo que ya tenían
  // handleCaa/handleTlsa. gob.mx declara "v=spf1 -all" (no envía correo)
  // y genuinamente no tiene MX — dominio de prueba real y estable.
  const mxSinRegistros = await getJSON('/mx/gob.mx');
  assert.strictEqual(mxSinRegistros.error, undefined);
  assert.deepStrictEqual(mxSinRegistros.records, []);

  // ── errorMessage(): validación adicional de los 3 casos de certificado
  // agregados en la ronda 4, usando los dominios de prueba oficiales de
  // badssl.com (construidos exactamente para esto, estables por diseño).
  const expired = await getJSON('/headers/expired.badssl.com');
  assert.strictEqual(expired.error, 'El certificado TLS expiró');

  const selfSigned = await getJSON('/headers/self-signed.badssl.com');
  assert.strictEqual(selfSigned.error, 'Certificado TLS autofirmado o no confiable');

  const wrongHost = await getJSON('/headers/wrong.host.badssl.com');
  assert.strictEqual(wrongHost.error, 'El certificado TLS no cubre este dominio exacto');

  // ── lookupIpMeta con fallback (ip-api.com si ipwho.is falla, ej. por
  // rate limit): no se puede forzar de forma determinista que el
  // proveedor primario falle en un test automatizado, así que esto solo
  // confirma que /serverlocation sigue devolviendo la forma esperada —
  // no importa cuál de los dos proveedores haya respondido.
  const location = await getJSON('/serverlocation/isoc.org.ec');
  assert.ok(!location.error, `serverlocation no debe fallar: ${location.error}`);
  assert.ok(location.country, 'debe traer país (de ipwho.is o del fallback ip-api.com)');

  console.log('✅ domainChecks.live.smoke.test.js — todos los casos OK');
}

run().catch((e) => {
  console.error('❌ domainChecks.live.smoke.test.js falló:', e.message);
  process.exit(1);
});
