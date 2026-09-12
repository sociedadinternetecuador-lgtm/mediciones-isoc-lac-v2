# Guía de pruebas — validación cruzada de Mediciones ISOC LAC

> Documento interno. No es el manual de uso (`docs/GUIA_MEDICIONES_ISOC_LAC.md`)
> ni la arquitectura técnica (`docs/arquitectura.md`) — es el **registro
> histórico de qué dominios se probaron, cuándo, y qué se encontró**, para
> evidenciar el trabajo de validación aunque un dominio no arroje ningún
> hallazgo. Los fixes de código con su detalle técnico completo (causa,
> solución, verificación) viven en `docs/arquitectura.md` § "Validación
> cruzada con herramientas independientes" — este documento referencia esa
> sección en vez de repetirla, y se enfoca en **el dominio**: por qué se
> eligió, qué se verificó de forma independiente, y el resultado.

## Metodología (resumen — detalle completo en `docs/arquitectura.md`)

1. Verificación **independiente** del dominio antes de correr nuestro
   sistema: `dig`/`curl`/`openssl s_client` a mano, DNS-over-HTTPS de
   Google/Cloudflare, y — cuando aplica — el comportamiento documentado
   públicamente del dominio (ej. los subdominios de badssl.com están
   construidos a propósito para fallar de una forma específica).
2. Batería de checks contra **producción real**
   (`https://mediciones.isoc.org.ec`), no un servidor local — un hallazgo
   de la primera ronda fue que probar solo en local puede ocultar bugs
   dependientes del entorno (ej. la versión de Node del `Dockerfile`).
3. Todo hallazgo se **repite antes de reportarlo como bug real** — mínimo
   un reintento inmediato. Si no se repite, se descarta como intermitencia
   (de nuestra red, de la red del dominio probado, o del servicio externo
   del que depende un check) y se anota igual, para no repetir la
   investigación en el futuro si vuelve a aparecer.
4. "Sin novedades" es un resultado válido y se registra igual — el
   objetivo es tener evidencia de qué se cubrió, no solo de qué falló.

## Resumen (por fecha, más reciente primero)

| Dominio | Fecha | Por qué se eligió | Resultado |
|---|---|---|---|
| `expired.badssl.com` | 2026-09-10 | Certificado TLS expirado a propósito | ✅ Sin novedades — valida el fix de la ronda 4 |
| `self-signed.badssl.com` | 2026-09-10 | Certificado autofirmado a propósito | ✅ Sin novedades — valida el fix de la ronda 4 |
| `wrong.host.badssl.com` | 2026-09-10 | Certificado que no cubre el hostname, a propósito | ✅ Sin novedades — valida el fix de la ronda 4 |
| `dnssec-failed.org` | 2026-09-10 | DNSSEC roto a propósito (dominio de prueba público conocido) | ✅ Sin novedades — motor DNSSEC detecta la falla correctamente |
| `neverssl.com` | 2026-09-10 | Diseñado para no ofrecer HTTPS funcional | ⚠️ Anomalía de infraestructura (no de código) — ver detalle |
| `cloudflare.com` | 2026-09-10 | Contraste global, muy bien configurado | ✅ Sin novedades |
| `gob.mx` | 2026-09-10 | Gobierno LAC fuera de Ecuador | 🔧 2 hallazgos — 1 bug corregido, 1 hallazgo real del sitio (no nuestro) |
| `lacnic.net` | 2026-09-10 | Organismo regional LAC, relevante a la misión del proyecto | ✅ Sin novedades |
| `presidencia.gob.ec` | 2026-09-09 | Dominio "difícil" pedido explícitamente | 🔧 2 bugs corregidos |
| `dominiosecuador.ec` | 2026-09-09 | Registrador de `.ec`, dominio "difícil" pedido explícitamente | ✅ Sin novedades |
| `isoc.org.ec` | 2026-09-09 | Dominio piloto original, muy bien configurado | 🔧 7 bugs corregidos a lo largo de 3 rondas |

---

## `isoc.org.ec` — 2026-09-09

**Por qué se eligió**: dominio propio del proyecto (ISOC Ecuador), candidato natural a piloto — verificado primero de forma independiente y confirmado como muy bien configurado (DNSSEC, DMARC estricto, CAA, CSP, HSTS, TLS 1.3).

**Resultado**: 7 bugs reales encontrados y corregidos a lo largo de 3 rondas de prueba (RDAP sin seguir redirect/sin User-Agent, "TLS Security Config" con dependencia externa dada de baja, SMTPUTF8 lento por puertos en secuencia, "Linked Pages" con enlaces relativos mal clasificados, "Archive" y el fallback RDAP de "Whois" con el mismo bug de User-Agent que RDAP, "Quality" silenciando errores de cuota). Un hallazgo inicial (SMTPUTF8 como posible falso negativo) se investigó y se descartó — el resultado ya era correcto. Detalle técnico completo, con evidencia de verificación de cada punto: `docs/arquitectura.md` §§ "Validación cruzada con herramientas independientes — primera ronda / segunda ronda / tercera ronda" (puntos 1 a 10) y "Fixes reales de checks individuales".

---

## `dominiosecuador.ec` — 2026-09-09

**Por qué se eligió**: pedido explícito como dominio "más complicado" — es el registrador oficial de `.ec` (`.EC DOMINIOS ECUADOR S.A.S.`), con infraestructura propia (WHMCS, Apache) distinta a la de `isoc.org.ec` (Cloudflare).

**Verificación independiente**: DNS básico (sin DNSSEC — sin DS en `.ec`), HTTPS con certificado Sectigo válido, cadena de redirección limpia.

**Resultado**: ✅ **Sin novedades.** Todos los checks probados (`headers`, `caa`, `rpki`, `whois`, `domaininfo`, `tlsa`, `mx`, `securitytxt`, `tlsinfo`, `sslchain`, `dnsrecords`, `firewall`, `ipinfo`, `malware`, `dkim`, `dnssec-analysis`) respondieron correctamente, sin errores ni discrepancias. Dato curioso (no es un bug, es información real sobre el dominio): el propio registrador de `.ec` no tiene ninguna cabecera de seguridad web (HSTS/CSP/X-Frame-Options/etc. todas ausentes) — el sistema lo reportó correctamente.

---

## `presidencia.gob.ec` — 2026-09-09

**Por qué se eligió**: pedido explícito como dominio "más complicado" — sitio del gobierno de Ecuador, infraestructura distinta a Cloudflare.

**Verificación independiente**: certificado TLS compartido entre ~26 sitios `.gob.ec`, cuyo SAN no incluye la variante sin `www` del dominio (confirmado con `curl` y con Node: `ERR_TLS_CERT_ALTNAME_INVALID`); puerto 80 no responde en absoluto (timeout, no rechazo); DNSSEC no habilitado (aunque `.ec`/`.gob.ec` sí lo soportan).

**Resultado**: 🔧 **2 bugs corregidos**:
1. Mensajes de error genéricos ("Servicio no disponible") ocultaban el hallazgo real de certificado — se agregaron mensajes específicos a `errorMessage()` para los casos de TLS más comunes.
2. `SMTPUTF8` con los 2 registros MX del dominio tardaba 30.2s (los recorría en secuencia) — se paralelizaron, bajó a ~15.1s.

Detalle técnico completo: `docs/arquitectura.md` § "Validación cruzada con herramientas independientes — cuarta ronda" (puntos 11 y 12).

---

## `lacnic.net` — 2026-09-10

**Por qué se eligió**: organismo regional de LAC (Registro de Direcciones de Internet para América Latina y Caribe) — directamente relevante a la misión de ISOC LAC, y fuera de Ecuador.

**Verificación independiente**: DNSSEC firmado (DS + `AD:true`), NS distribuidos entre LACNIC/ARIN/APNIC/RIPE/registro.br/LACTLD (infraestructura de un RIR real).

**Resultado**: ✅ **Sin novedades.** `headers`, `caa`, `rpki`, `domaininfo`, `tlsa`, `mx`, `sslchain`, `firewall`, `dnsrecords`, `ipinfo`, `malware`, `dnssec-analysis` — todos correctos. Igual que con `dominiosecuador.ec`: sin cabeceras de seguridad web (dato real del sitio, no un bug).

---

## `gob.mx` — 2026-09-10

**Por qué se eligió**: gobierno de un país LAC grande, fuera de Ecuador, para contraste regional.

**Verificación independiente**: `openssl s_client -verify_return_error` → `verify error:num=20: unable to get local issuer certificate` (el servidor no envía el certificado intermedio completo en el handshake TLS); DNS-over-HTTPS confirma NODATA en MX (no `Answer`, solo `Authority`/SOA) consistente con su TXT `"v=spf1 -all"` (declara explícitamente que no envía correo); RDAP directo confirma `404 — "No RDAP service is available for this resource"` (`.mx` no tiene RDAP).

**Resultado**: 🔧 **1 bug corregido, 1 hallazgo real del sitio (no nuestro), 1 comportamiento confirmado correcto**:
1. **Bug corregido**: `/mx` devolvía un error genérico en vez de `records: []` cuando el dominio no tiene MX — `handleMx` no distinguía "sin registros" (ENODATA) de una falla real, a diferencia de `handleCaa`/`handleTlsa` que ya lo hacían. Corregido con el mismo patrón.
2. **Hallazgo real del sitio, no un bug nuestro**: `/headers` reporta `"No se pudo verificar la cadena de certificados TLS"` — verificado de forma independiente que es correcto: `gob.mx` no envía el certificado intermedio en el handshake (Node, sin *AIA chasing* como hacen los navegadores, no puede completar la cadena). Es una configuración TLS real y mejorable del sitio del gobierno mexicano — el sistema la detecta correctamente, no es una falla nuestra.
3. `domaininfo` devuelve todo vacío sin error — correcto, `.mx` no tiene RDAP (confirmado directo), comportamiento ya esperado desde la primera ronda con `isoc.org.ec`/`nic.uy`.

Detalle técnico del fix: `docs/arquitectura.md` § "Validación cruzada con herramientas independientes — quinta ronda".

---

## `cloudflare.com` — 2026-09-10

**Por qué se eligió**: contraste global — sitio de gran escala, muy bien configurado, para confirmar que el sistema no tiene sesgos hacia dominios pequeños/LAC.

**Resultado**: ✅ **Sin novedades.** `headers` (todas las cabeceras presentes), `caa`, `rpki`, `domaininfo`, `tlsa`, `mx`, `sslchain`, `firewall` (detecta Cloudflare correctamente), `malware`, `dnssec-analysis` — todos correctos.

---

## `expired.badssl.com` / `self-signed.badssl.com` / `wrong.host.badssl.com` — 2026-09-10

**Por qué se eligieron**: dominios de prueba públicos, mantenidos específicamente para verificar el manejo de cada tipo de falla de certificado TLS — la validación más directa posible del fix de mensajes de error de la cuarta ronda (`docs/arquitectura.md` § punto 11).

**Resultado**: ✅ **Sin novedades — los 3 confirmaron el fix exactamente como se esperaba**:

| Dominio | Mensaje devuelto por `/headers` |
|---|---|
| `expired.badssl.com` | `"El certificado TLS expiró"` |
| `self-signed.badssl.com` | `"Certificado TLS autofirmado o no confiable"` |
| `wrong.host.badssl.com` | `"El certificado TLS no cubre este dominio exacto"` |

`/tlsinfo` (que deliberadamente no valida el certificado, para poder inspeccionar qué protocolo/cifrado ofrece un servidor sin importar si el certificado es válido) siguió funcionando correctamente en los tres casos, mostrando el protocolo TLS negociado.

---

## `dnssec-failed.org` — 2026-09-10

**Por qué se eligió**: dominio de prueba público conocido, con DNSSEC deliberadamente mal configurado (DS presente en el padre, pero la zona propia falla la validación) — ya usado en `test/rawDns.live.smoke.test.js` para el motor de validación DNS; aquí se probó el motor de análisis DNSSEC completo (`/dnssec-analysis`).

**Resultado**: ✅ **Sin novedades.** El motor detectó correctamente: `final_status: "misconfigured"`, zona `dnssec-failed.org` con `query_status: "servfail"` y `validation_problem: "dnssec_validation_failure"`, mientras la delegación desde `org.` (DS presente) se reporta como `secure`. El resumen en español explica correctamente la causa ("El resolver rechaza la respuesta por inconsistencia criptográfica"). Confirma que el sistema no solo detecta DNSSEC bien configurado — también detecta DNSSEC mal configurado con precisión.

---

## `neverssl.com` — 2026-09-10

**Por qué se eligió**: diseñado específicamente para que su HTTPS no funcione como el de un sitio normal (su propósito es probar portales cautivos, que dependen de HTTP sin cifrar) — buen caso límite para "sitio con HTTPS deliberadamente no funcional en el path esperado".

**Verificación independiente**: el dominio sí acepta conexiones TLS en el puerto 443 (confirmado con `openssl s_client` y con `tls.connect` de Node — protocolo TLS 1.3 válido, certificado de Amazon vigente), pero la respuesta HTTPS de la aplicación es `403 Forbidden` a propósito (su diseño exige HTTP plano). Confirmado igual corriendo el servidor local (fuera de producción): `headers` → `https:false` (correcto, 403≠200), `serverstatus` → `403` (correcto), `tlsinfo` → protocolo TLS real (correcto).

**Resultado**: ⚠️ **Sin bugs de código — sí se detectó una anomalía de infraestructura, no relacionada con `server.js`.** Contra producción pública (`https://mediciones.isoc.org.ec`), `/serverstatus/neverssl.com` y `/headers/neverssl.com` devolvían `502 Bad Gateway` servido por **Cloudflare** (el Tunnel de acceso público, no nuestro servidor) — reproducible en reintentos. Se aisló la causa: accediendo **directo** a `server1:8700` (vía Tailscale, sin pasar por el Cloudflare Tunnel) el mismo endpoint respondió `200 OK` correctamente y de inmediato. Conclusión: es una particularidad del Cloudflare Tunnel con este dominio externo específico, no un bug de la aplicación — no se tocó código. Queda anotado por si se repite con otros dominios en el futuro, para no re-investigarlo desde cero.

---

## Plantilla para agregar un nuevo dominio

```markdown
## `dominio.tld` — YYYY-MM-DD

**Por qué se eligió**: ...

**Verificación independiente**: (dig/curl/openssl u otra fuente externa, antes de correr nuestro sistema)

**Resultado**: ✅ Sin novedades. / 🔧 N hallazgos — ...

(si hay hallazgos, detalle breve acá + referencia a docs/arquitectura.md
si implicó cambios de código)
```
