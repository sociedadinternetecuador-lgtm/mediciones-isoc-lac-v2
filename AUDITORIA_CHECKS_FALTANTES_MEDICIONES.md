> **Esta auditoría se refiere exclusivamente al módulo MEDICIONES — el único módulo de MEDICIONES Ecuador originado en el fork de Paraguay (`nicocamarao/mediciones-isoc-lac`, commit base `0d14f45`).** DNSSEC, Observatorio, Zonemaster, Preparación de datasets/OpenINTEL, panel de administración, Blog/Eventos, el runner regional y el ejercicio de 24 dominios son desarrollos propios de Ecuador con historia y arquitectura independientes, y quedan **fuera de alcance** de este documento. No se usan para aumentar el conteo de checks de Ecuador, ni para considerar cubierta ninguna capacidad de Paraguay/upstream.

---

# Auditoría de checks faltantes — módulo MEDICIONES

**Fecha:** 2026-09-15 · **Continuación de:** `AUDITORIA_FORK_MEDICIONES.md`

---

## 1. Límites exactos del módulo MEDICIONES Ecuador

### 1.1 IN SCOPE

| Archivo/bloque | Qué contiene | Por qué es MEDICIONES |
|---|---|---|
| `index.html` — `const groupDefinitions = [...]` (línea 1829) | Los 54 checks: clave, etiqueta ES/EN, grupo, `default` | Es el registro central de checks del módulo |
| `index.html` — `const checkGlossary = {...}` (línea 1931) | Descripción de cada check | Metadata de MEDICIONES |
| `index.html` — `getCheckResult()` / `case 'xxx':` (switch por cada check) | Lógica cliente que arma cada resultado | Parte del flujo de un check individual |
| `index.html` — `#mb-checksContainer`, `#tabPanelMediciones`, `renderMbCheckOptions()`, `medicionesBatchStart()` y funciones `mb*` | Formulario, tabla de resultados, disparo de la corrida por lote | Frontend del módulo |
| `index.html` — `STATUS_SYMBOL`, `STATUS_SYMBOL_I18N_KEY` (los 6 estados) | Vocabulario de estados PASS/FAIL/INFO/INCONCLUSIVE/NOT_APPLICABLE/MEASUREMENT_ERROR | Contrato de salida de cada check |
| `server.js` — bloques `if (segments[0] === '<key>' ...) return handleXxx(...)` para cada una de las 54 claves, y las funciones `handleXxx()` correspondientes | Backend de cada check | Implementación real de la medición |
| `routes/medicionesBatchReport.routes.js` | `POST /mediciones-batch/report`, límite de 20 dominios, export JSON/PDF | Es el "Reporte por lote" del mismo módulo |
| `logic/exporters/medicionesBatchReport.exporter.js` | Arma el Markdown/JSON del reporte de los 54 checks | Exportación del módulo |
| `logic/orchestrators/medicionesBatchReport.store.js` | Persistencia en memoria de los reportes generados | Backend del módulo |
| `test/medicionesBatchReport.*.test.js` | Tests del límite de 20 dominios y del exportador | Tests del módulo |

**Dependencias compartidas** (usadas por MEDICIONES pero también por otros módulos — se consultan como utilidades, no se auditan como "parte" del módulo): `logic/adapters/rawDns.adapter.js`, `logic/adapters/email.adapter.js`, `logic/adapters/safeWebFetch.adapter.js`, `logic/adapters/publicSuffixList.adapter.js`, `logic/validators/domain.validator.js`.

### 1.2 OUT OF SCOPE (explícitamente excluido de esta auditoría)

| Archivo/carpeta | Módulo real |
|---|---|
| `logic/processors/dnssec.processor.js`, `logic/rules/dnssec.rules.js`, `logic/content/dnssecGuidance.content.js`, `logic/content/dnssecGlossary.content.js` | DNSSEC (pestaña propia) |
| `aggregate/**` completo | Observatorio + Zonemaster |
| `routes/datasetPreparation.routes.js`, `logic/orchestrators/dnsValidationJob.orchestrator.js`, `logic/validators/datasetDomains.validator.js` | Preparación de datasets / OpenINTEL |
| `admin.html`, `routes/admin.routes.js`, `routes/content.routes.js`, `logic/adapters/contentStore.adapter.js` | Administración / Blog / Eventos / Materiales |
| `scripts/regional-study/**`, `scripts/exercise-24-domains/**`, `data/exercises/**`, `data/baseline/**` | Herramientas de investigación externas al producto |
| `data/measurements/*.jsonl` | Log transversal (registra también DNSSEC; no es exclusivo de MEDICIONES) |
| `index.html` — secciones `tabPanelDnssec`, `tabPanelObservatorio*`, `tabPanelPreparacion`, `tabPanelInicio`, `tabPanelBlog`, `tabPanelEventos`, `tabPanelInformacion` | Otras pestañas |

Todo lo que sigue en este documento se limita estrictamente a la columna "IN SCOPE".

---

## 2. Reconteo de checks, solo dentro de MEDICIONES

```
$ grep -oE "\{ key: '[a-z0-9]+'" index.html | wc -l
54
```

Confirmado por suma manual de los 6 grupos de `groupDefinitions`:

| Grupo | # checks |
|---|---|
| Seguridad y confianza (DNS/TLS) | 7 |
| Anti-suplantación de correo | 3 |
| Cabeceras de seguridad web | 5 |
| Transparencia y conectividad moderna | 2 |
| Diagnóstico técnico | 27 |
| Contenido y experiencia | 10 |
| **Total** | **54** |

- **Checks definidos:** 54.
- **Checks activos:** 54 (ninguno está comentado ni deshabilitado — no existe un equivalente a `checkSoon()` en Ecuador; todo lo que está en `groupDefinitions` corre).
- **Checks visibles en frontend:** 54 (los 54 aparecen como checkbox en `#mb-checksContainer`; 18 vienen premarcados `default: true`, los otros 36 se activan manualmente, pero los 54 están disponibles y visibles).
- **Endpoints backend:** 54 rutas `segments[0] === '<key>'` correspondientes en `server.js` (una por check; no hay checks que compartan endpoint dentro de MEDICIONES, a diferencia de Paraguay que sí tenía bundles).
- **De dónde sale el 54, exactamente:** de la longitud del arreglo combinado de `checks` dentro de los 6 objetos de `groupDefinitions` en `index.html:1829-1929`. No incluye DNSSEC (que no tiene entrada en `groupDefinitions`, vive en su propia pestaña), ni ningún check de Observatorio/datasets.

---

## 3. Reconstrucción del módulo MEDICIONES de Paraguay/upstream

Fuente: `nicocamarao/mediciones-isoc-lac` (HEAD `b88aff3`, 2026-06-15) — `isoclac/mediciones-isoc-lac` tiene el mismo historial exacto (0 commits propios), así que es redundante auditarlo por separado.

Estructura equivalente a `groupDefinitions`: `const groups = [...]` en `index.html`, con una función `check(id, labelEs, labelPt, descEs, descPt)` y `checkSoon(...)` para los "próximamente" (no activos).

| Grupo upstream | Checks activos |
|---|---|
| HTTPS / Web | https, redirect, hsts, serverbanner, compression |
| Cabeceras defensivas / AppSecPriv | csp, xfo, xcto, referrer, permissions, securitytxt |
| TLS / Criptografia | tls, sslchain, ocsp, tlsa, caa |
| IP / Endereços | ipv4, ipv6 |
| DNSSEC / DNS | dnssec, dnsviz, internetnlweb, dnsrecords, txtrecords |
| DKIM, SPF y DMARC | maildnssec, spf, dmarc, dkim |
| MX y transporte | mx, mailipv6, starttls, internetnlmail |
| Universal Acceptance | smtputf8 |
| Ruta y confianza | rpki, routing, serverinfo |
| Accesibilidad | w3c, quality |
| Laboratorio | serverstatus, redirectchain, openports, ping, pingv6, traceroute, sitefeatures, cookies, listedpages, linkedpages, socialtags, archive, ranking |
| *Próximamente (no activo)* | ofds, aspa, quantum |

**Total activos: 50.** Herramientas explícitamente fuera de este conteo por no ser "checks del módulo MEDICIONES" de Paraguay: el rediseño visual "Massively" (assets/CSS/SASS), los 3 locales de idioma (`locales/{en,es,pt}.properties`), y la integración con **ISOC Pulse** (`data/pulse-*.json`, `scripts/pulse_snapshot*`) — ver análisis específico en §10.

---

## 4. Checks añadidos después de `0d14f45` (evidencia commit por commit)

Se descargaron los parches (`git diff`) de los 9 commits de `nicocamarao/mediciones-isoc-lac` posteriores a `0d14f45` y se ubicó la primera aparición de cada clave nueva:

| Clave | Commit | Fecha | Archivos tocados | Endpoint | Función backend |
|---|---|---|---|---|---|
| `dnssec` (como card individual propia) | `ca5271d` | 2026-04-15 | `index.html`, `server.js` | `GET /dnssec/:domain` | `handleDnssec` → `dnssecGoogle()` |
| `dnsviz` | `ca5271d` | 2026-04-15 | `index.html`, `server.js` | `GET /dnsviz/:domain?format=&resolver=` | `handleDnsviz` |
| `maildnssec` | `ca5271d` | 2026-04-15 | `index.html`, `server.js` | `GET /maildnssec/:domain` | `handleMailDnssec` |
| `mailipv6` | `ca5271d` | 2026-04-15 | `index.html`, `server.js` | `GET /mailipv6/:domain` | `handleMailIpv6` |
| `routing` | `ca5271d` | 2026-04-15 | `index.html`, `server.js` | `GET /routing/:domain` | `handleRouting` |
| `starttls` | `ca5271d` | 2026-04-15 | `index.html`, `server.js` | `GET /starttls/:domain` | `handleStarttls` |
| `w3c` | `ca5271d` | 2026-04-15 | `index.html`, `server.js` | `GET /w3c/:domain` | `handleW3C` |
| `serverbanner`* | `ca5271d` | 2026-04-15 | `index.html` | (deriva de `headers`/`https`, sin endpoint propio) | — |
| `ofds` (planeado, no activo) | `ca5271d` | 2026-04-15 | `index.html` | — | — |
| `ping` | `1bfc702` | 2026-04-17 | `index.html`, `server.js` | `GET /ping/:domain` | `handlePing` → `runLocalPing(host, 4)` |
| `pingv6` | `1bfc702` | 2026-04-17 | `index.html`, `server.js` | `GET /pingv6/:domain` | `handlePingV6` → `runLocalPing(host, 6)` |
| `aspa`, `quantum` (planeados, no activos) | `1bfc702` | 2026-04-17 | `index.html` | — | — |
| `internetnlweb` | `de6474c` | 2026-06-10 | `index.html`, `server.js` | `GET /internetnl/:domain?type=web` | `handleInternetNl(..., 'web')` |
| `internetnlmail` | `de6474c` | 2026-06-10 | `index.html`, `server.js` | `GET /internetnl/:domain?type=mail` | `handleInternetNl(..., 'mail')` |

`*` `serverbanner` **no es una capacidad nueva real** — extrae el header `Server:` de la misma respuesta HTTP que ya usan `https`/`headers`. Ecuador ya tiene esta capacidad bajo el nombre `server` (grupo "Diagnóstico técnico") desde el fork. Se documenta aquí por transparencia (es una clave nueva en el registro de Paraguay) pero **no se cuenta como brecha** — ver footnote de §12.

**Corrección importante a la auditoría anterior:** el análisis previo (`AUDITORIA_FORK_MEDICIONES.md`) reportó "12 checks añadidos post-fork" contando en ese número una comparación menos fina. El recuento exacto y verificado por commit es: **12 claves activas nuevas** (`dnssec, dnsviz, maildnssec, mailipv6, routing, starttls, w3c, serverbanner, ping, pingv6, internetnlweb, internetnlmail`) + 3 planeadas no activas (`ofds, aspa, quantum`, que no cuentan como brecha real porque tampoco están activas en Paraguay). De esas 12, **una (`serverbanner`) no es una brecha real** — ver arriba. Quedan **11 capacidades genuinamente nuevas y ausentes en Ecuador MEDICIONES**.

**Hallazgo adicional que corrige la auditoría anterior:** `traceroute` **sí existía en el commit base `0d14f45`** (confirmado: aparece en el registro de checks del fork-point) y **Paraguay lo conserva hoy** — pero **Ecuador ya no lo tiene**. Esto **no es una omisión de sincronización** (Paraguay no lo agregó después) sino una **eliminación propia de Ecuador** en algún punto de su propio historial (probablemente durante la reorganización de checks de septiembre 2026 — `traceroute` normalmente depende de un binario del sistema no siempre disponible en el contenedor de despliegue, lo que sería una razón técnica plausible, aunque **no se encontró el commit exacto de Ecuador que lo eliminó** — NO DETERMINADO). Se trata como un caso aparte, no como "post-fork".

---

## 5. Matriz central de comparación (módulo MEDICIONES únicamente)

| Check/capacidad | Paraguay en `0d14f45` | Paraguay actual | Ecuador MEDICIONES actual | Fecha añadido upstream | Estado | Observación |
|---|---|---|---|---|---|---|
| https, redirect, hsts, csp, tls, sslchain, ocsp, tlsa, caa, ipv4, ipv6, spf, dmarc, dkim, mx, smtputf8, rpki, xfo, xcto, referrer, permissions, securitytxt, compression, dnsrecords, txtrecords, openports, redirectchain, serverstatus, sitefeatures, cookies, listedpages, linkedpages, socialtags, archive, ranking, quality, serverinfo | Sí | Sí | Sí | — | **HEREDADO** | 37 checks, evolucionados en paralelo en ambos lados |
| asn, block, crawlrules, dnsserver, domaininfo, firewall, headers, ipinfo, key, malware, screenshot, server, serverlocation, tlsciphers, tlssimulation, whois, xxss | Sí | **No** (abandonados por upstream) | Sí | — | **ELIMINADO POR UPSTREAM, CONSERVADO EN ECUADOR** | 17 checks |
| traceroute | Sí | Sí | **No** | — | **EXISTÍA EN EL FORK, ELIMINADO POR ECUADOR** | Caso aparte — ver §4 |
| serverbanner | No (bundle sin nombre propio) | Sí | No con ese nombre (existe como `server`) | 2026-04-15 | **HEREDADO Y MODIFICADO** (renombrado en upstream) | No es brecha real |
| dnssec (card individual) | No (endpoint sí, sin card) | Sí | **No** dentro de MEDICIONES (existe en módulo aparte, fuera de alcance) | 2026-04-15 | **NO INCORPORADO EN ECUADOR MEDICIONES** | Ver §7.1 |
| dnsviz | No | Sí | No | 2026-04-15 | **NO INCORPORADO** | Ver §7.2 |
| maildnssec | No | Sí | No | 2026-04-15 | **NO INCORPORADO** | Ver §7.3 |
| mailipv6 | No | Sí | No | 2026-04-15 | **NO INCORPORADO** | Ver §7.4 |
| routing | No | Sí | Parcial (Ecuador tiene `rpki`, un solo veredicto; falta el detalle por IP/ASN/prefijo) | 2026-04-15 | **PARCIAL / NO INCORPORADO** | Ver §7.5 |
| starttls | No | Sí | No | 2026-04-15 | **NO INCORPORADO** | Ver §7.6 |
| w3c | No | Sí | No | 2026-04-15 | **NO INCORPORADO** | Ver §7.7 |
| ping (IPv4) | No | Sí | No | 2026-04-17 | **NO INCORPORADO** | Ver §7.8 |
| pingv6 | No | Sí | No | 2026-04-17 | **NO INCORPORADO** | Ver §7.9 |
| internetnlweb | No | Sí | No | 2026-06-10 | **NO INCORPORADO** (es agregación, no medición nueva) | Ver §9 |
| internetnlmail | No | Sí | No | 2026-06-10 | **NO INCORPORADO** (ídem) | Ver §9 |
| ofds, aspa, quantum | No | No (solo "próximamente", inactivos) | No | 2026-04 | **NO APLICA** | Ni upstream los tiene activos |

---

## 6. Regla de no-redundancia (aplicada)

Se verificó explícitamente para cada uno de los 11 checks faltantes que **no existe una entrada equivalente dentro de `groupDefinitions`**, sin considerar el módulo DNSSEC independiente, Observatorio, ni datasets. En particular:

- `dnssec`: el módulo DNSSEC independiente de Ecuador (7 estados estructurales) es más sofisticado que el simple check `dnssec` de Paraguay — **pero eso no cuenta aquí**. Dentro de `groupDefinitions` no existe ninguna clave `dnssec`. Se marca **NO INCORPORADO EN MEDICIONES**, sin excepción.
- `routing`/`rpki`: Ecuador sí tiene `rpki` dentro de MEDICIONES (un veredicto agregado), por lo que se marca **PARCIAL**, no "NO INCORPORADO" — esta es la única capacidad de las 11 con solapamiento real dentro del propio módulo.
- El resto (dnsviz, maildnssec, mailipv6, starttls, w3c, ping, pingv6, internetnlweb, internetnlmail) no tiene ningún equivalente en ningún check de `groupDefinitions`.

---

## 7. Auditoría técnica de cada check faltante

### 7.1 `dnssec` (card individual dentro de MEDICIONES)

- **Qué mide:** presencia de DS en el padre y DNSKEY en el hijo, más el bit AD devuelto por un resolvedor validador (Google DNS) — una señal binaria simple, no un árbol de estados.
- **Implementación upstream:** función `dnssecGoogle(domain, mode)` en `server.js`, endpoint `GET /dnssec/:domain`. Llama a la API de Google DNS-over-HTTPS.
- **Input:** dominio. **Output:** `{parent, child, algorithms[], digests[], dsRecords[], dnskeyRecords[], nsec3{...}}`.
- **Subresultados:** ~7 campos por dominio.
- **Dependencias externas:** `https://dns.google/resolve` (Google Public DNS).
- **Dependencias locales:** ninguna adicional.
- **Riesgos:** bajo — es una consulta DNS-over-HTTPS estándar, sin ejecución de comandos ni acceso a red interna.
- **Frontend asociado:** card individual en grupo "DNSSEC / DNS".
- **Mapeo a los 6 estados de Ecuador:** `PASS` si `parent && child` con AD=true; `FAIL` si hay DS pero no valida; `NOT_APPLICABLE` si el dominio no tiene NS/no existe; `MEASUREMENT_ERROR` si Google DoH no responde.

### 7.2 `dnsviz`

- **Qué mide:** no mide nada por sí mismo — **es una integración externa**. Compone metadatos y, si se pide `format=svg`, descarga el gráfico SVG pre-renderizado de `dnsviz.net` para el dominio.
- **Implementación upstream:** `handleDnsviz(domain, res, format, mode)`, endpoint `GET /dnsviz/:domain?format=svg&resolver=remote`. Llama a `resolveDnsvizMeta()` + `dnssecChain()` (cadena reconstruida localmente) y opcionalmente `fetchCachedDnsvizSvg()` contra `dnsviz.net`.
- **Input:** dominio. **Output:** metadatos + cadena de confianza DNSSEC nivel por nivel, o un SVG.
- **Subresultados:** variable, un nodo por zona en la cadena (puede ser 3-6).
- **Dependencias externas:** `dnsviz.net` (no oficial, sitio de terceros, sin SLA).
- **Riesgos:** **SSRF de bajo riesgo** — el servidor hace un `fetch` a una URL construida con el nombre de dominio ingresado por el usuario (`https://dnsviz.net/d/${domain}/...`) hacia un host fijo (`dnsviz.net`), no hacia una URL arbitraria — el vector real de riesgo sería que `domain` no esté saneado y permita inyectar una ruta que escape a otro host (path traversal en la URL), lo cual debe verificarse en la implementación real antes de portar. Timeout/rate-limit: depende enteramente de `dnsviz.net`, que es públicamente conocido por ser lento.
- **Clasificación (§9):** **INTEGRACIÓN EXTERNA**, no medición local.
- **Mapeo a 6 estados:** difícil de mapear como PASS/FAIL binario — más natural como `INFO` (muestra la cadena) con `INCONCLUSIVE` si el servicio externo no responde, nunca `FAIL` (no es una prueba de cumplimiento).

### 7.3 `maildnssec`

- **Qué mide:** si los servidores MX del dominio (no el dominio mismo) tienen DNSSEC válido.
- **Implementación:** `handleMailDnssec(domain, res)` — resuelve MX (`resolveMxRecords`), y para cada exchange llama a `dnssecGoogle()`.
- **Input:** dominio. **Output:** `{domainDnssec:{secure,algorithms}, mx:[{exchange,secure,algorithms}]}`.
- **Subresultados:** 2 + (1 por servidor MX).
- **Dependencias externas:** Google DoH (mismo que 7.1), resolución MX local.
- **Riesgos:** bajo — incluso el número de servidores MX a consultar es acotado por el propio DNS del dominio (no hay input arbitrario del usuario que dispare N consultas ilimitadas más allá de los MX reales).
- **Mapeo:** `PASS` si domainDnssec.secure y todos los MX seguros; `FAIL` si alguno no; `NOT_APPLICABLE` si no hay MX.

### 7.4 `mailipv6`

- **Qué mide:** si los servidores MX publican AAAA.
- **Implementación:** `handleMailIpv6` — resuelve MX, y para cada exchange resuelve AAAA.
- **Riesgos:** bajo, mismo patrón que 7.3.
- **Mapeo:** `PASS` si todos los MX tienen AAAA; `FAIL` si ninguno; `INFO`/parcial si algunos sí y otros no; `NOT_APPLICABLE` si no hay MX.

### 7.5 `routing` (relacionado con el `rpki` que Ecuador ya tiene)

- **Qué mide:** para cada IP (v4 y v6) del dominio, ASN, prefijo y estado de validación RPKI (`valid`/`invalid`/`not-found`) — un detalle por IP, no un veredicto único.
- **Implementación:** `handleRouting` — resuelve direcciones, llama a `rpkiValidity(ip)` por cada una (misma familia de fuente que usa Ecuador para su propio `rpki`: RIPEstat).
- **Riesgos:** bajo — mismas dependencias que el `rpki` que Ecuador ya opera hoy.
- **Mapeo:** Ecuador podría **extender** su propio check `rpki` para exponer el detalle por IP en vez de crear un check nuevo — decisión de diseño en §13.

### 7.6 `starttls`

- **Qué mide:** si los servidores MX anuncian `STARTTLS` en el saludo SMTP.
- **Implementación:** `handleStarttls` — resuelve MX, para cada uno llama a `checkSmtpUtf8(exchange)` (conexión SMTP real, EHLO) y busca la capacidad `STARTTLS` en la respuesta.
- **Input:** dominio → MX → conexión TCP saliente al puerto 25/587 de terceros.
- **Riesgos:** **medio** — esto abre una conexión TCP saliente arbitraria a un host y puerto determinados por DNS (los MX del dominio consultado). Riesgos a verificar antes de portar: (1) **SSRF/escaneo de puertos internos** si el MX resuelto apunta a una IP privada/`localhost` (debe validarse que la IP resuelta no sea RFC1918/loopback antes de conectar — Ecuador ya tiene este mismo patrón de riesgo en su propio check `smtputf8` actual, así que la mitigación probablemente ya existe y es reutilizable); (2) **timeout** — necesita uno explícito, igual que el resto de checks de Ecuador (`fetchWithTimeout`, 20s); (3) **rate limiting** — conectar repetidamente a servidores de correo de terceros puede ser visto como abuso por el proveedor de correo si se corre en lote (20 dominios × varios MX c/u).
- **Mapeo:** `PASS` si todos los MX soportan STARTTLS; `FAIL` si alguno no; `MEASUREMENT_ERROR` si la conexión SMTP falla/timeout.

### 7.7 `w3c`

- **Qué mide:** validación HTML (vía el validador oficial W3C) + heurísticas propias de accesibilidad (idioma declarado, `alt` en imágenes, estructura de encabezados, `aria-label`, `tabindex` positivo, etc.) sobre el HTML de la portada.
- **Implementación:** `handleW3C` — llama a `https://validator.w3.org/nu/?doc=...&out=json` (API pública oficial del W3C) y en paralelo hace `fetchWebsite(domain)` para las heurísticas locales con regex sobre el HTML.
- **Riesgos:** bajo-medio — el fetch a `validator.w3.org` envía la URL del dominio auditado como parámetro (no hay ejecución de código ni acceso a recursos internos); el `fetchWebsite()` interno reutiliza la misma lógica que ya usa Ecuador para otros checks (`sitefeatures`, `socialtags`), por lo que no introduce una superficie nueva de SSRF más allá de la que ya existe.
- **Clasificación (§9):** **medición real híbrida** (parte integración externa oficial + parte heurística local).
- **Mapeo:** `PASS` si 0 errores; `FAIL` si hay errores del validador; `INFO` para las heurísticas de accesibilidad (no son pruebas de cumplimiento binario); `MEASUREMENT_ERROR` si el validador W3C no responde.

### 7.8 y 7.9 `ping` (IPv4) / `pingv6`

- **Qué miden:** latencia/pérdida ICMP real, ejecutando el binario del sistema operativo.
- **Implementación:** `runLocalPing(host, family)` → `execFileAsync('/sbin/ping'|'ping'|'/sbin/ping6', ['-c','3','-n', host], {timeout: REQUEST_TIMEOUT_MS})`.
- **Riesgos — el más serio de todo este documento:**
  - **Command injection: bajo**, porque usa `execFile` (no `exec`/`spawn` con shell), pasando `host` como elemento de un arreglo de argumentos — Node **no** invoca un shell intermedio, así que caracteres como `;`, `` ` ``, `$()` no se interpretan. Esto es el patrón correcto.
  - **Inyección de argumentos / abuso de flags: riesgo real a verificar.** `normalizeDomain()` aplica `domainToASCII` + una función `cleanDomain()` no auditada en este documento (fuera del snapshot descargado) — si esa limpieza no rechaza estrictamente cualquier cosa que no sea un hostname válido, un input como `-i 0.01` o `-f` podría interpretarse como una **opción** del binario `ping` en vez de un host, permitiendo ping flood local o denegación de servicio del propio contenedor. **Antes de portar, Ecuador debe validar el dominio contra un patrón estricto de hostname (ya lo hace `logic/validators/domain.validator.js` para sus propios checks) y rechazar cualquier valor que comience con `-`.**
  - **DoS/recursos:** cada ping son 3 paquetes con timeout — acotado, pero en un lote de 20 dominios son hasta 40 procesos `ping`/`ping6` reales lanzados desde el contenedor de producción; **requiere un límite de concurrencia** (Ecuador ya usa este patrón de límite de concurrencia en otros checks batch).
  - **Disponibilidad del binario:** en contenedores Docker mínimos (como el que usa MEDICIONES en producción, ver `docs/arquitectura.md`), el binario `ping` y el permiso `CAP_NET_RAW` para sockets ICMP **no siempre están disponibles** — esto podría explicar por qué `traceroute` (que tiene el mismo requisito) fue removido de Ecuador en algún momento (ver §4, hallazgo NO DETERMINADO con certeza pero plausible).
- **Mapeo:** `PASS` si hay respuesta con 0% pérdida; `FAIL` si 100% pérdida; `INCONCLUSIVE` si pérdida parcial; `MEASUREMENT_ERROR` si el comando no pudo ejecutarse (binario ausente, timeout del proceso).

---

## 8. Compatibilidad con el modelo de 6 estados de MEDICIONES Ecuador

| Check | PASS | FAIL | NOT_APPLICABLE | INCONCLUSIVE | MEASUREMENT_ERROR | INFO |
|---|---|---|---|---|---|---|
| dnssec | DS+DNSKEY+AD válidos | DS presente, no valida | Dominio sin NS | — | Google DoH no responde | — |
| dnsviz | — | — | — | Cadena parcial | Servicio externo no responde | Cadena completa mostrada |
| maildnssec | Dominio y todos los MX seguros | Alguno inseguro | Sin MX | — | Falla de resolución | — |
| mailipv6 | Todos los MX con AAAA | Ninguno | Sin MX | Algunos sí, otros no | — | — |
| routing (extensión de rpki) | Todas las IP con RPKI válido | Alguna inválida | Sin IP | — | RIPEstat no responde | Detalle por IP |
| starttls | Todos los MX soportan STARTTLS | Alguno no | Sin MX | — | Conexión SMTP falla/timeout | — |
| w3c | 0 errores del validador | ≥1 error | — | — | Validador no responde | Hallazgos de accesibilidad (no binarios) |
| ping / pingv6 | 0% pérdida | 100% pérdida | — | Pérdida parcial | Binario ausente/timeout del proceso | — |

---

## 9. Clasificación: medición real vs. enriquecimiento vs. integración vs. UI

| Ítem | Clasificación |
|---|---|
| dnssec, maildnssec, mailipv6, routing, starttls, ping, pingv6 | **MEDICIÓN REAL** — produce un resultado técnico verificable sobre el dominio |
| w3c | **MEDICIÓN REAL HÍBRIDA** — combina un validador externo oficial con heurísticas propias |
| dnsviz | **INTEGRACIÓN EXTERNA** — no calcula nada por sí mismo salvo componer/enlazar el servicio de terceros dnsviz.net |
| internetnlweb, internetnlmail | **ENRIQUECIMIENTO / COMPOSICIÓN** — no consulta nada nuevo; agrega y pondera resultados que Paraguay ya calculó por separado (spf+dmarc+dkim+starttls+mailipv6+tls+...) en un score único al estilo Internet.nl |
| serverbanner | **No es medición nueva** — ya existe en Ecuador como `server` |
| traceroute | **MEDICIÓN REAL** que Ecuador tenía y perdió (no es "faltante post-fork") |
| Rediseño "Massively", locales en 3 idiomas | **UI / TRADUCCIÓN** — no constituyen medición |
| ISOC Pulse | ver §10 |

---

## 10. ISOC Pulse — determinación específica

Se revisó `data/pulse-manifest.json`, `data/pulse-hardcoded.json` y `scripts/pulse_snapshot*.{py,mjs}` del repositorio de Paraguay. Pulse:

- **No forma parte de ningún check** de `groupDefinitions`/`groups` — no hay ninguna clave `pulse` dentro del arreglo de checks activos.
- **Es un scraping periódico** (fuera de la corrida por dominio) de las páginas de reporte público de `pulse.internetsociety.org` por país (`ar`, `bo`, `br`, etc.), guardado como snapshot estático (`pulse-manifest.json`) para mostrarse en una sección separada del sitio ("situación LAC"/"ccTLD flags").
- El manifiesto revisado registra **51 intentos, 0 éxitos** (todos fallaron con HTTP 403) al momento de la última generación — es decir, ni siquiera está funcionando de forma confiable en el propio upstream.
- **Conclusión: Pulse es enriquecimiento/contexto de página, no una medición del módulo MEDICIONES.** No se cuenta como check faltante, y no se recomienda incorporarlo como tal — si se quiere en el futuro, sería contenido editorial (más cercano al módulo Blog de Ecuador) que a MEDICIONES.

---

## 11. Cifra "202+" — reconfirmación dentro del alcance estricto de MEDICIONES

```
$ grep -n "202" index.html
119:  <span class="section-pill">Más de 202 mediciones integradas</span>
```

- **Archivo:** `index.html` (línea 119).
- **Texto exacto:** `Más de 202 mediciones integradas`.
- **Contexto:** encabezado de la sección "Mapa general" (que organiza todo en 3 ejes: seguridad, universalidad, accesibilidad) — **fuera del propio `groups[]`/registro de checks**, es un elemento decorativo de portada.
- **¿Existe alguna función que la justifique?** No. Es texto estático en el HTML, sin interpolación de JavaScript (`${...}`) ni referencia a `groups.length`, `allIds.length` ni ninguna variable calculada.
- **¿Representa checks, resultados o subresultados?** Ninguna de las tres de forma verificable: el registro real de checks del módulo MEDICIONES de Paraguay es 50 (activos). No hay 202 checks, ni 202 endpoints (son 64 documentados), ni una función que sume subresultados a 202. **Dentro del alcance estricto de MEDICIONES, "202" no tiene un origen verificable en el código — es una cifra de portada, no una métrica del módulo.**

---

## 12. Brecha real — conciliación matemática

| Métrica | Valor |
|---|---|
| Checks Ecuador MEDICIONES actuales | **54** |
| Checks Paraguay MEDICIONES actuales (activos) | **50** |
| Checks compartidos (mismo id, ambos lados) | **37** |
| Checks exclusivos de Ecuador MEDICIONES (heredados del fork, abandonados por Paraguay) | **17** |
| Checks post-fork reales y ausentes en Ecuador | **11** |
| Checks post-fork sin brecha real (`serverbanner`, equivalente a `server`) | 1 |
| Checks que existían en el fork, Paraguay conserva, Ecuador perdió (`traceroute`) | 1 |

**Conciliación:**
```
Ecuador (54)        = compartidos (37) + exclusivos de Ecuador (17)
Paraguay-actual (50) = compartidos (37) + nuevos post-fork reales (11)
                      + serverbanner-equivalente (1) + traceroute-heredado (1)
                      = 37 + 11 + 1 + 1 = 50   ✓ cuadra exactamente
```

---

## 13. Propuesta de incorporación (sin implementar)

| Check | Decisión | Justificación |
|---|---|---|
| maildnssec | **PORTAR CASI DIRECTAMENTE** | Reutiliza exactamente el mismo patrón que el `dnssec` que se decida agregar (7.1) + resolución MX que Ecuador ya tiene (`mx`, `smtputf8`) |
| mailipv6 | **PORTAR CASI DIRECTAMENTE** | Resolución MX + AAAA, ambas ya usadas por Ecuador en otros checks |
| starttls | **PORTAR CON ADAPTACIÓN** | Misma lógica que el `smtputf8` que Ecuador ya opera (conexión SMTP/EHLO) — adaptar para extraer la capacidad STARTTLS en vez de SMTPUTF8, reforzando la validación de IP privada/loopback antes de conectar |
| ping, pingv6 | **PORTAR CON ADAPTACIÓN** | Viable, pero requiere: validar el dominio contra un patrón estricto de hostname antes de pasarlo a `execFile`, confirmar disponibilidad del binario `ping`/`ping6` y de `CAP_NET_RAW` en el contenedor de despliegue de Ecuador, y límite de concurrencia explícito |
| routing | **REIMPLEMENTAR PARA ARQUITECTURA ECUADOR** | No como check nuevo — extender el `rpki` existente de Ecuador para exponer detalle por IP, evitando duplicar lógica de RIPEstat |
| w3c | **PORTAR CASI DIRECTAMENTE** | La API del validador W3C es pública y estable; las heurísticas de accesibilidad son JS puro, portable sin cambios de fondo |
| dnsviz | **PORTAR CON ADAPTACIÓN** | Verificar primero el comportamiento real de `dnsviz.net` (disponibilidad, límites de uso) antes de depender de él en producción; considerar exponerlo solo como enlace/INFO, no como PASS/FAIL |
| dnssec (dentro de MEDICIONES) | **REIMPLEMENTAR PARA ARQUITECTURA ECUADOR** | No copiar la lógica simple de Paraguay — envolver el motor DNSSEC propio de Ecuador (mucho más robusto, fuera de este módulo) detrás de un checkbox `dnssec` dentro de `groupDefinitions`, mapeando sus 7 estados a los 6 de MEDICIONES. Esto es una integración de arquitectura (llamar al módulo existente), no una comparación de módulos — coherente con la regla de §6 porque el veredicto de "falta" se mantiene igual, solo cambia cómo se resuelve la implementación |
| internetnlweb, internetnlmail | **NO PORTAR** | Es agregación de datos que Ecuador ya tendría en sus propios checks tras incorporar los anteriores — se puede reconsiderar como una vista de resumen, no como un check nuevo |
| traceroute | **decisión aparte, no "incorporar nuevo"** — es una **restauración**, evaluar si el entorno de despliegue de Ecuador soporta el binario antes de decidir | Ver riesgo de disponibilidad en §7.8/7.9 |
| serverbanner | **NO PORTAR** — ya existe como `server` | — |

---

## 14. Orden de implementación propuesto

**FASE 1 — Correo (menor riesgo, mayor reutilización de código existente):**
`maildnssec`, `mailipv6`, `starttls` — los tres reutilizan resolución MX y patrones que Ecuador ya opera hoy (`mx`, `smtputf8`).

**FASE 2 — Ruteo:**
`routing` como extensión del `rpki` existente (no como check nuevo).

**FASE 3 — Validador de accesibilidad:**
`w3c` — depende de una API pública oficial y estable, riesgo bajo.

**FASE 4 — Conectividad ICMP (mayor riesgo operativo):**
`ping`, `pingv6` — requieren primero confirmar viabilidad en el entorno de despliegue real (binario disponible, permisos ICMP) antes de escribir código; podría no ser viable sin cambios de infraestructura (Docker/Fly.io).

**FASE 5 — Integraciones externas de terceros (evaluar valor primero):**
`dnsviz` — depende de un servicio no oficial de terceros sin SLA; evaluar estabilidad real antes de comprometerse a mantenerlo.

**FASE 6 — DNSSEC dentro de MEDICIONES:**
Envolver el motor DNSSEC propio de Ecuador como checkbox — depende de una decisión de producto (¿vale la pena duplicar la señal si ya existe una pestaña DNSSEC completa?), no solo de una decisión técnica.

Este orden se basa en: menor riesgo técnico primero, mayor reutilización de código ya probado en Ecuador primero, y dependencias externas frágiles al final.

---

## 15. Casos de prueba por check faltante (para cuando se implemente — no ejecutados)

| Caso | Descripción aplicable a los 8 checks (7.1-7.9) |
|---|---|
| Positivo | Dominio conocido que cumple (ej. un MX con STARTTLS activo, un dominio con w3c sin errores) |
| Negativo | Dominio que no cumple (MX sin STARTTLS, HTML con errores W3C) |
| NOT_APPLICABLE | Dominio sin MX (para maildnssec/mailipv6/starttls), dominio sin AAAA propio (mailipv6 parcial) |
| INCONCLUSIVE | Pérdida ICMP parcial, cadena DNSViz parcialmente resuelta |
| MEASUREMENT_ERROR | Servicio externo caído (validator.w3.org, dnsviz.net, RIPEstat), timeout de conexión SMTP |
| Timeout | Ping a un host que no responde (dropea silenciosamente, no rechaza) — debe distinguirse de host inexistente |
| Dominio inexistente (NXDOMAIN) | Todos — debe devolver NOT_APPLICABLE o MEASUREMENT_ERROR según el check, nunca FAIL |
| Entrada inválida | Un `domain` con espacios, guiones al inicio (`-c`), o caracteres no ASCII sin normalizar — crítico para `ping`/`pingv6` por el riesgo de inyección de argumentos (§7.8) |
| Localhost / IP privada | Un MX que resuelva a `127.0.0.1` o `10.0.0.0/8` — debe rechazarse antes de conectar (starttls, ping) |
| Fallo del proveedor externo | Simular 500/timeout de Google DoH, RIPEstat, validator.w3.org, dnsviz.net |
| IPv4-only / IPv6-only | mailipv6/pingv6 contra un dominio sin AAAA en absoluto |

---

## 16. Resumen ejecutivo (para referencia rápida)

- El módulo MEDICIONES Ecuador tiene **54 checks**, todos activos y expuestos.
- El módulo MEDICIONES Paraguay/upstream tiene **50 checks activos** (+3 planeados no activos).
- **37 se comparten**, **17 son exclusivos de Ecuador** (heredados del fork, que Paraguay abandonó), **11 son capacidades reales de Paraguay ausentes en Ecuador**, **1 (`traceroute`) existía en el fork y Ecuador lo perdió**, **1 (`serverbanner`) no es brecha real**.
- "202+" sigue sin tener un origen verificable en el código — es texto de portada, confirmado dentro del alcance estricto de este módulo.
- Nada de esto se implementó en esta auditoría.
