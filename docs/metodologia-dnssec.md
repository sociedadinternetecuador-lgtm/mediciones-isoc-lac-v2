# Metodología del módulo DNSSEC Ecuador

> Documento consolidado (2026-09-16) que reúne la metodología del motor
> DNSSEC independiente de Ecuador — hasta ahora dispersa en comentarios de
> código y textos de interfaz. Complementa, sin reemplazar,
> `AUDITORIA_DNSSEC_ECUADOR_METODOLOGIA_MOTOR.md` (auditoría técnica
> completa) e `IMPLEMENTACION_DNSSEC_AUDITORIA_CORE.md` (registro de los
> cambios de esta fase).

## Definición del core (congelada para esta fase y siguientes, salvo
## decisión explícita en contrario)

> El módulo DNSSEC Ecuador realiza un diagnóstico estructural de la cadena
> DNSSEC de un dominio mediante evidencia DS/DNSKEY y respuestas de un
> resolver validante, y presenta ese diagnóstico de forma explicable al
> usuario.
>
> **No pretende ser una implementación completa del motor criptográfico
> de DNSViz.**

## Objetivo

Ofrecer un diagnóstico DNSSEC amigable, comprensible y accionable para
usuarios que no son necesariamente especialistas en DNS — en la línea
conceptual de lo que herramientas como DNSViz permiten analizar, pero con
una presentación explicada, no un grafo técnico.

## Alcance

- Evalúa **presencia estructural** de DNSKEY (por zona) y DS (por
  delegación), desde el TLD hasta el propio dominio.
- **No incluye la zona raíz** (`.`) en la cadena verificada — se asume
  implícitamente que el TLD es un ancla de confianza fiable. Esta es una
  decisión de alcance declarada, no un descuido.
- Interpreta **SERVFAIL** como señal de fallo de validación DNSSEC
  únicamente cuando coincide con un DS presente en la delegación
  (evidencia estructural que sustenta la inferencia) — nunca de forma
  aislada.
- Produce un **indicador de confianza** en la propia interpretación (no
  en la seguridad del dominio), basado en la calidad de la evidencia
  obtenida.

## Fuente de datos: Google Public DNS (fuente única)

El motor consulta **exclusivamente** `https://dns.google/resolve`
(DNS-over-HTTPS, formato JSON) — confirmado por lectura completa de
`logic/adapters/dns/realDns.adapter.js`, el único punto del motor que
hace peticiones de red.

- **No existe consenso multi-resolver.** No se consulta Cloudflare,
  Quad9 ni ningún otro resolver. Cada resultado representa **la visión de
  Google Public DNS en el momento de la consulta**, no un consenso ni una
  verificación independiente.
- Esto es una decisión de alcance explícita de esta fase (no se agregó
  un segundo resolver) — ver `AUDITORIA_DNSSEC_ECUADOR_METODOLOGIA_MOTOR.md`
  §5/§8 para el análisis completo de por qué no se incorpora en el core.
- La respuesta de Google DoH incluye, además del código de estado
  (`Status`), un campo `AD` (Authenticated Data) y, en casos de fallo,
  `Comment`/`extended_dns_errors` (RFC 8914) — el motor **no usa
  actualmente** estos campos para clasificar (ver §"Fuera de alcance del
  core" y `IMPLEMENTACION_DNSSEC_AUDITORIA_CORE.md`).

## Flujo

```
GET /dnssec-analysis?domain=X[&format=json]
  -> validateDomainInput(X)        [sanitiza + IDNA/punycode + valida sintaxis]
  -> getDnssecAnalysis(domain)
       -> buildZoneChain(domain)                    [TLD -> dominio completo]
       -> queryDnskey(zona) por cada zona            [Google DoH, paralelo]
       -> buildDelegationsFromZones(zonas)           [pares padre->hijo consecutivos]
       -> queryDs(zona_hija) por cada delegación     [Google DoH, paralelo]
       -> normalizeZone() / normalizeNameExistence() [detecta SERVFAIL+DS como señal]
       -> queryNameExistence(domain)                 [A+AAAA+CNAME, Google DoH]
       -> computeConfidence(...)                      [high/medium/low]
  -> processDnssecAnalysis(raw)
       -> computeDnssecConclusion(...)                [motor de 7 estados]
       -> getDnssecGuidance(final_status)             [remediación]
       -> getGlossaryForStatus(final_status)          [glosario contextual]
       -> resumen ejecutivo + bloque "human"
  -> HTML (renderDnssecHtml) o JSON crudo (?format=json)
```

## Los 7 estados

| Estado | Significado | Regla resumida |
|---|---|---|
| `ok` | DNSSEC correctamente implementado | Dominio firmado + delegación segura |
| `not_implemented` | DNSSEC no implementado, acción disponible | Capas superiores firmadas, dominio sin DS/DNSKEY |
| `blocked_at_tld` | Bloqueo estructural en el TLD | El propio TLD no está firmado |
| `blocked_at_parent` | Bloqueo en la zona padre inmediata | La zona padre inmediata no está firmada |
| `misconfigured` | DNSSEC presente pero mal configurado | DNSKEY sin DS válido, o DS sin DNSKEY, o SERVFAIL con DS presente |
| `non_existent` | Dominio no existente o no verificable | NXDOMAIN en existencia, zona y delegación |
| `indeterminate` | Resultado no concluyente | Timeout/error/red/respuesta inválida en cualquier consulta — evaluado primero, antes de cualquier regla estructural |

Detalle completo de cada regla, precedencia exacta y riesgos de falso
positivo/negativo: ver `AUDITORIA_DNSSEC_ECUADOR_METODOLOGIA_MOTOR.md` §4.

## Indicador de confianza

Mide **qué tan confiable es la interpretación del motor dado lo que pudo
observar**, no el nivel de seguridad del dominio. Tres niveles:

- **Alta**: evidencia consistente, incluida la detección explícita de un
  fallo DNSSEC real (SERVFAIL + DS presente).
- **Media**: evidencia parcial o con limitaciones estructurales, pero
  interpretable.
- **Baja**: una o más consultas devolvieron timeout, error de red o
  respuesta inválida — evidencia insuficiente para una lectura confiable.

Este indicador es heurístico (no un cálculo estadístico riguroso) pero
técnicamente sustentado: cada regla de asignación tiene una justificación
directa y verificable en `services/dnssec.service.js`. No debe leerse
como "qué tan seguro es el dominio", sino "cuánto puede confiarse en esta
lectura en particular".

## Limitaciones declaradas

- No incluye la zona raíz en la verificación de la cadena.
- No valida firmas RRSIG (vigencia, algoritmo) — solo observa presencia
  estructural de DNSKEY/DS.
- **No verifica que un DS corresponda criptográficamente a un DNSKEY
  concreto** — solo observa que ambos existan (presencia), nunca que el
  DS publicado en la zona padre realmente describa (por hash/digest) una
  de las claves que la zona hija publica. Un DS "huérfano" (apunta a una
  clave rotada o inexistente) mientras la zona hija sí publica *alguna*
  DNSKEY se reportaría como `ok`/`secure` — una limitación estructural
  real, documentada explícitamente (ver `AUDITORIA_DNSSEC_BROKEN_
  DELEGATION.md`), no corregida por requerir verificación criptográfica
  fuera del alcance del core.
- No consulta NSEC/NSEC3.
- No contacta servidores autoritativos directamente (usa un resolver
  recursivo) — no detecta inconsistencias entre autoritativos ni
  delegaciones "lame".
- Un único resolver (Google Public DNS) — sin comparación multi-resolver.
- **(Corregido 2026-09-16)** El motor examina el TLD, la zona padre
  inmediata, **y también cualquier zona/delegación ancestro intermedia**
  entre ambos — una ruptura en cualquier nivel de la cadena (no solo TLD o
  padre inmediato) se detecta y se reporta como `blocked_at_parent`
  (evidencia clara de ruptura ancestro) o `indeterminate` (evidencia
  ancestro ambigua, ej. SERVFAIL sin corroborar) — nunca se sigue
  clasificando "ok" con una ruptura ancestro sin resolver. Cubierto por 8
  tests dedicados en `test/dnssecRules.test.js` (casos `multinivel_A` a
  `multinivel_Gbis`, más un test de no-regresión para `not_implemented`).
  No se creó ningún estado nuevo — se reutilizan `blocked_at_parent` e
  `indeterminate` exactamente con su semántica ya existente.

## Qué no mide

- Si el sitio web, el correo o cualquier otro servicio del dominio está
  operativo — DNSSEC es independiente de esa disponibilidad.
- Si el dominio "es seguro" en un sentido amplio — solo si su cadena
  DNSSEC estructural es consistente.
- Nada relacionado con TLS/HTTPS, SPF/DKIM/DMARC u otros mecanismos de
  seguridad de correo o web (esos viven en MEDICIONES, un módulo aparte).

## Fuera de alcance del core (por diseño, no por descuido)

- Validación criptográfica completa de RRSIG.
- Verificación de correspondencia criptográfica DS↔DNSKEY (comparar el
  hash publicado en el DS contra las claves realmente publicadas por la
  zona hija) — más simple que validar RRSIG, pero igualmente fuera del
  alcance estructural actual.
- Análisis avanzado de NSEC/NSEC3.
- Comparación multi-resolver (Google/Cloudflare/otros).
- Análisis de consistencia multi-autoritativo / detección de lame
  delegation.
- Visualización tipo grafo (estilo DNSViz).
- Cualquier automatización o scraping de DNSViz u otras herramientas
  externas.
- Otras herramientas avanzadas de diagnóstico profundo.

Estas capacidades, si se desarrollan, deben vivir en un módulo o
herramienta separada — nunca dentro de `services/dnssec.service.js` ni
`logic/rules/dnssec.rules.js` (ver siguiente sección).

## Posibles funciones adicionales futuras (NO implementadas, NO forman parte del core)

Identificadas durante la auditoría de 2026-09-16, listadas aquí
únicamente como referencia para una eventual fase futura e independiente
— no se incorporan hoy:

- Leer y aprovechar el campo `AD` de la respuesta Google DoH como
  corroboración adicional (sin reemplazar la heurística SERVFAIL+DS ya
  existente).
- Leer y exponer `extended_dns_errors`/`Comment` (RFC 8914) para explicar
  la causa raíz específica de un SERVFAIL en el texto mostrado al
  usuario, solo como texto explicativo/evidencia de soporte — nunca para
  crear un nuevo estado ni cambiar la clasificación principal.
- Parsear y exponer algoritmo y tipo de digest de los registros DS/DNSKEY
  ya obtenidos (hoy solo se cuenta su presencia).
- Señalar algoritmos DNSSEC legados/débiles (SHA-1, DSA) como hallazgo de
  higiene de seguridad.
- Verificar la correspondencia criptográfica DS↔DNSKEY (comparar el hash
  del DS contra las claves realmente publicadas por la zona hija) — el
  dato de DNSKEY por zona ya se calcula en `getDnssecAnalysis()`
  (`preliminaryZones`) pero nunca se cruza con el resultado de la
  consulta DS; cruzarlos permitiría detectar un DS "huérfano" (ver
  `AUDITORIA_DNSSEC_BROKEN_DELEGATION.md`), pero implica decidir a qué
  estado final alimentaría y no se persigue en esta fase.
- Análisis RRSIG completo (vigencia, expiración, algoritmo real).
- Consulta y análisis de NSEC/NSEC3 (parámetros, pruebas de no
  existencia).
- Comparación multi-resolver.
- Análisis de consistencia autoritativa / lame delegation.
- Visualización tipo grafo de la cadena de confianza.

Cada una de estas, de perseguirse, debe evaluarse como módulo
complementario o herramienta avanzada separada, con su propia decisión de
producto — nunca como una ampliación silenciosa del core actual.
