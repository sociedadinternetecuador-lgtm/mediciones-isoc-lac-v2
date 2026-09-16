# Auditoría: DNSViz (Paraguay/upstream) vs. módulo DNSSEC independiente (Ecuador)

Fecha: 2026-09-16. Auditoría exclusivamente técnica, **sin cambios de
código**. No se implementó nada, no se creó ningún commit. Objetivo:
decidir si conviene incorporar DNSViz al módulo MEDICIONES Ecuador, y de
qué forma.

Alcance de la comparación: el módulo DNSSEC de Ecuador (`services/
dnssec.service.js`, `logic/processors/dnssec.processor.js`,
`logic/builders/*`, `logic/adapters/dns/realDns.adapter.js`,
`logic/content/dnssecGuidance.content.js`) es, como aclaró el usuario, un
desarrollo **independiente** del fork de Paraguay — no proviene de él. Se
revisó únicamente con fines de comparación funcional, sin modificarlo.

## 1. Qué hace realmente `dnsviz` en Paraguay/upstream

Leído el código real (`server.js` de `nicocamarao/mediciones-isoc-lac`,
funciones `resolveDnsvizMeta` L2555, `fetchCachedDnsvizSvg` L3225,
`extractDnsvizNoticeSections`/`parseDnsvizNoticeEntry` L3237-3327,
`handleDnsviz` L5032, `dnssecChain` L1270, ruta `segments[0]==='dnsviz'`
L5216).

### Endpoint y función

`GET /dnsviz/:domain?format=svg&resolver=local|remote` → `handleDnsviz()`.

Internamente combina **dos fuentes completamente distintas**:

1. **`dnssecChain(domain, mode)`** — una comprobación **local** propia de
   Paraguay: para cada etiqueta del dominio (de más específica a TLD),
   consulta DNSSEC vía Google DoH (`dnssecGoogle`) y arma una cadena
   `target → ancestor → tld → raíz` con un booleano `valid` por nivel
   (`parent && child`, es decir, "¿la zona padre publica DS y la zona hija
   publica DNSKEY?"). Nivel de la raíz siempre `valid: true` con nota
   "ancla de confianza" (no se verifica realmente, se asume).
2. **`resolveDnsvizMeta(domain)`** — la integración con el sitio público
   **dnsviz.net**, un servicio de terceros. Esto es lo que el nombre del
   check ("DNSViz") realmente identifica y lo que interesa auditar aquí.

### Qué hace `resolveDnsvizMeta` exactamente (paso a paso)

1. `GET https://dnsviz.net/d/<domain>/dnssec/` con `fetchPage` (no la ruta
   segura de fetch del proyecto — sin guard de IP privada, ver §9),
   siguiendo hasta 4 redirecciones manualmente, timeout 20s.
2. Regex crudo sobre el HTML devuelto en busca de palabras clave:
   `nsec3`, `fallback`+`tcp`, `delegation`, `insecure` → produce
   "observaciones" de texto libre, sin estructura (ej. "NSEC3 mencionado
   en el reporte").
3. Extrae, con otra regex, la URL de un archivo JavaScript
   (`auth_graph.js`) que el propio frontend de dnsviz.net usa para pintar
   su grafo.
4. Descarga ese `.js` y, con **otra regex sobre el texto del script**,
   localiza una asignación `var notices = {...};` y hace `JSON.parse()`
   de ese fragmento — es decir, **extrae una estructura de datos interna
   del frontend de un tercero, nunca documentada ni versionada como API**,
   confiando en que el nombre de la variable y el formato no cambien.
5. De ese objeto `notices`, separa:
   - `notices.notices.warnings` / `.errors` — arrays de texto libre.
   - Secciones por título (`"DNSKEY/DS/NSEC status"`, `"delegation
     status"`, `"RRset status"`) con sub-grupos por
     SECURE/INSECURE/BOGUS/WARNING/ERROR, cada uno con entradas de texto
     que a veces incluyen `(alg=X, id=Y)` (algoritmo e id de clave).
6. Además descarga y cachea el grafo SVG/PNG (`auth_graph.svg?download=1`)
   para mostrarlo como imagen.
7. Todo se cachea 30 minutos en memoria (`dnsvizMetaCache`/`dnsvizSvgCache`).

### Respuestas expresas del punto 1 de la tarea

- **¿Ejecuta un análisis nuevo o consulta uno existente?** Consulta el
  análisis **ya publicado** por dnsviz.net para ese dominio — no dispara
  ni controla cuándo dnsviz.net vuelve a analizar la zona. Si dnsviz.net
  no tiene un análisis reciente, la página que se scrapea puede estar
  desactualizada o dnsviz.net puede tardar en generarlo (no observable
  desde el código de Paraguay).
- **¿API oficial o no oficial?** **No oficial.** No existe una API pública
  documentada de dnsviz.net que Paraguay consuma; lo que hace es *web
  scraping* de una página HTML pensada para humanos y de un archivo
  JavaScript interno de esa misma página — ninguno de los dos es un
  contrato estable.
- **¿Depende de dnsviz.net?** Sí, por completo, para toda la porción
  "DNSViz" del check (grafo, avisos, errores, secciones). La porción
  `dnssecChain` es local y no depende de terceros (aunque sí de Google
  DoH).
- **¿Devuelve imagen/grafo?** Sí — SVG y PNG del grafo de autenticación,
  obtenidos por URL fija y cacheados.
- **¿Devuelve datos estructurados o solo un enlace?** Ambas cosas a la
  vez, mezcladas: hay datos estructurados reales (el objeto `notices`,
  extraído por scraping frágil) y también enlaces directos a las páginas
  de dnsviz.net (`pageUrl`, `svgUrl`, `pngUrl`) que el frontend usa.

### Clasificación (paso 1 de la tarea)

**Combinación de: integración externa (scraping no oficial) +
visualizador (grafo SVG/PNG) + agregador** (combina su propio
`dnssecChain` local con las notas de un tercero en un solo payload). No
es un "simple enlace" (hace scraping real, no solo enlaza) ni un
"validador DNSSEC" propio (no valida nada criptográficamente por su
cuenta — repite literalmente lo que dnsviz.net ya concluyó).

## 2. Qué mide DNSViz técnicamente — plataforma vs. lo que Paraguay consume

### Capacidades reales de DNSViz como plataforma (conocimiento público de
la herramienta, no inventado)

DNSViz es una herramienta de análisis y visualización DNS/DNSSEC de uso
académico/operativo (originada en el trabajo de Casey Deccio), que
realiza consultas en vivo contra los servidores autoritativos reales de
toda la cadena de delegación y produce:

- Cadena de confianza completa, incluyendo la zona raíz.
- Presencia y coincidencia de DS/DNSKEY en cada nivel de delegación.
- **Validación real de firmas RRSIG** (vigencia, expiración, algoritmo).
- Pruebas de no-existencia autenticada (NSEC/NSEC3), incluyendo
  parámetros de NSEC3 (iteraciones, salt).
- Detección de inconsistencias entre distintos servidores autoritativos
  de la misma zona (delegaciones "lame", respuestas discordantes).
- Advertencias operativas (algoritmos débiles/deprecados, tamaños de
  clave, fallback TCP, etc.).
- Un grafo visual completo de la cadena de autenticación.

### Lo que Paraguay REALMENTE consume de todo eso

Únicamente:

- Los textos de `warnings`/`errors` ya redactados por DNSViz (sin acceso
  a los datos crudos que los originan: no hay fechas de expiración de
  RRSIG explícitas, no hay parámetros NSEC3 estructurados, no hay
  detalle de qué servidor autoritativo específico respondió distinto).
- Un conteo de elementos SECURE/INSECURE bajo dos secciones puntuales
  (`DNSKEY/DS/NSEC status`, `delegation status`), sin desglosar por qué.
- El grafo como imagen (opaco: no se puede consultar su contenido
  programáticamente, solo mostrarlo).
- Unas pocas "observaciones" por palabra clave regex (§1), de calidad muy
  baja comparadas con la profundidad real de la plataforma.

**Conclusión del punto 2**: Paraguay usa una fracción mínima y superficial
de lo que DNSViz es capaz de hacer. No se le puede atribuir a Paraguay
(ni, por extensión, a incorporar "lo que hace Paraguay") la profundidad
real de la plataforma DNSViz — la mayoría de esa profundidad (RRSIG,
NSEC3 estructurado, consistencia multi-servidor) queda **enterrada dentro
del grafo SVG**, no expuesta como dato.

## 3. Auditoría del módulo DNSSEC independiente de Ecuador

Archivos: `services/dnssec.service.js` (262 líneas), `logic/processors/
dnssec.processor.js` (170 líneas), `logic/builders/zoneChain.builder.js`,
`logic/builders/delegation.builder.js`, `logic/adapters/dns/
realDns.adapter.js`, `logic/rules/dnssec.rules.js`, `logic/content/
dnssecGuidance.content.js`, `logic/content/dnssecGlossary.content.js`.

### Motor y fuentes

- Construye la cadena de zonas desde el dominio hasta el TLD
  (`buildZoneChain`) — **sin incluir la zona raíz**, decisión explícita y
  documentada ("se asume implícitamente que el TLD es confiable").
- Consultas DNS **directas y propias** (`realDns.adapter.js`): únicamente
  `DNSKEY`, `DS` y existencia de nombre (A/AAAA vía `queryNameExistence`).
  **No consulta RRSIG ni NSEC/NSEC3** — confirmado por grep, no aparece
  ningún query de esos tipos en el adaptador.
- No usa Google/Cloudflare DoH ni depende de Zonemaster — resolución
  propia, con timeout configurable (`QUERY_TIMEOUT_MS`).

### Qué mide

- **Por zona**: `signed`/`dnskey_present` (¿hay DNSKEY?), estado
  (`SIGNED`/`UNSIGNED`/`UNKNOWN`), `query_status` (`ok`/`no_data`/
  `servfail`/`nxdomain`/`timeout`/`network_error`/`invalid_response`).
- **Por delegación** (entre zona padre e hija): `ds_present`, `secure`,
  estado (`SECURE`/`INSECURE`/`BROKEN`/`UNKNOWN`) — distingue
  explícitamente "sin DS, sin firmar" (INSECURE) de "con DS, pero algo
  está roto" (BROKEN).
- **Regla propia y sofisticada**: SERVFAIL en una zona con delegación
  seguridad (DS presente) se interpreta como evidencia fuerte de **fallo
  real de validación DNSSEC** (`dnssec_validation_failure`) — no como un
  error genérico. Es la firma clásica de un resolver validador rechazando
  una cadena de firmas rota.
- **Meta-indicador de confianza** (`high`/`medium`/`low`): qué tan
  confiable es la propia interpretación, degradado explícitamente por
  timeouts/errores de red, elevado quando el patrón de evidencia es
  consistente. No existe nada equivalente en el DNSViz que consume
  Paraguay.
- **Capa de interpretación de negocio** (`dnssec.processor.js` +
  `dnssec.rules.js`, no auditado en detalle por no ser el foco de esta
  fase): estado final (`ok`/`not_implemented`/`misconfigured`/
  `blocked_at_tld`/`blocked_at_parent`/`non_existent`/`indeterminate`),
  con guía de remediación por caso, nivel de riesgo y texto en español
  orientado a un operador no experto — no solo el dato crudo.
- **Reconoce explícitamente su propio límite, en el código**: "Este
  análisis evalúa evidencia estructural en DNS, no validación
  criptográfica completa" — repetido en varios textos de guía. Y, de
  forma directamente relevante para esta auditoría, **ya recomienda
  DNSViz por nombre** como la herramienta a usar quando se necesita esa
  profundidad adicional:
  > "La cadena de confianza verificada es estructural, no criptográfica
  > completa. Se recomienda complementar con herramientas validadoras
  > como DNSViz para confirmar la firma activa." (`dnssec.processor.js`)
  >
  > "Verificar la cadena completa de confianza con herramientas como
  > DNSViz o Verisign DNSSEC Debugger." (`dnssecGuidance.content.js`)
  >
  > "...complementarlo con herramientas especializadas como DNSViz."
  > (`server.js`, ruta `/dnssec-analysis`)

Esto no es una opinión de esta auditoría: es una decisión de diseño **ya
tomada por el propio módulo DNSSEC de Ecuador**, de forma independiente,
antes de esta fase.

### Lo que NO hace (y por qué eso importa)

No verifica firmas RRSIG (vigencia/expiración/algoritmo real), no procesa
NSEC/NSEC3 en detalle, no compara consistencia entre múltiples servidores
autoritativos, no produce una visualización gráfica. Estas son
exactamente las capacidades que sí tiene DNSViz como plataforma (§2).

## 4. Matriz de intersección

| Capacidad | DNSViz (lo que Paraguay consume) | DNSSEC Ecuador | Relación |
|---|---|---|---|
| Presencia de DS | Sí (dentro de "delegation status", vía texto) | Sí, explícito y estructurado (`ds_present`, por delegación) | Parcial — Ecuador es más explícito/estructurado |
| Presencia de DNSKEY | Sí (dentro de "DNSKEY/DS/NSEC status", vía texto) | Sí, explícito y estructurado (`dnskey_present`, por zona) | Parcial — igual razón |
| Cadena de confianza | Sí, completa, **incluye la raíz**, con grafo visual | Sí, hasta el TLD, **sin raíz** (asumida) | Complementario — DNSViz cubre un tramo que Ecuador omite a propósito |
| Validación criptográfica de RRSIG (vigencia/expiración) | Sí, en la plataforma DNSViz — pero Paraguay no expone estos datos, solo el veredicto textual | No — explícitamente fuera de alcance | **Solo DNSViz** — capacidad real no cubierta por Ecuador |
| AD flag / resolver validante | No aplica directamente (DNSViz no usa el flag AD; hace su propia validación) | No aplica tampoco (Ecuador tampoco consulta el flag AD; usa SERVFAIL-como-señal) | Ninguno lo usa — no es una brecha real |
| Algoritmos de firma | Parcial (aparecen en texto de notices, ej. "alg=8") | Parcial (Paraguay's `dnssecChain` sí extrae algoritmos vía Google DoH; el motor Ecuador no los expone en este análisis) | Complementario |
| Delegación (padre→hijo) | Sí, con grafo completo | Sí, explícito por nivel | Igual en concepto, distinto en detalle |
| Consistencia entre servidores NS (lame delegation) | Sí, capacidad real de la plataforma DNSViz | No | **Solo DNSViz** |
| Errores DNSSEC | Sí (texto libre, sección "errors") | Sí, con causa estructurada (`validation_problem`, `dnssec_validation_failure`) y confianza asociada | Complementario — Ecuador es más preciso sobre el PORQUÉ |
| NSEC/NSEC3 | Sí, mención regex superficial ("NSEC3 mencionado") | No consultado | **Solo DNSViz** (aunque lo que Paraguay expone de esto es muy pobre) |
| Visualización gráfica | Sí (SVG/PNG) | No | **Solo DNSViz** |
| Diagnóstico humano/explicativo | Mínimo (texto ya redactado por DNSViz, sin traducir contexto de negocio) | Extenso (resumen ejecutivo, riesgo, próximos pasos, glosario, en español, por caso) | Ecuador ya cubre esto mejor |
| Múltiples resolvers | No (una sola fuente: el análisis publicado de DNSViz) | No directamente (usa su propio resolver; no compara Google vs Cloudflare) | Ninguno — no es una brecha real de esta comparación |
| Zonemaster | No relacionado | No integrado en este módulo (Zonemaster es un módulo aparte de MEDICIONES, fuera de alcance) | N/A |
| Dependencia externa | Total (dnsviz.net, scraping no oficial) | Ninguna (consultas DNS directas propias) | Diferencia arquitectónica central |

## 5. Redundancia real, capacidad por capacidad

| Capacidad | Clasificación |
|---|---|
| Presencia DS/DNSKEY | YA CUBIERTA EQUIVALENTEMENTE (Ecuador, de forma más estructurada) |
| Diagnóstico humano/guía de remediación | YA CUBIERTA MEJOR EN ECUADOR |
| Causa de fallo DNSSEC (SERVFAIL+DS como señal) | YA CUBIERTA MEJOR EN ECUADOR |
| Cadena de confianza hasta el TLD | YA CUBIERTA EQUIVALENTEMENTE (con menor alcance que DNSViz, ver siguiente fila) |
| Cadena de confianza incluyendo la raíz | COMPLEMENTARIA (DNSViz cubre un tramo que Ecuador omite a propósito) |
| Validación real de RRSIG (expiración/algoritmo) | NUEVA (no cubierta por Ecuador en absoluto) |
| NSEC/NSEC3 | NUEVA, pero SOLO VISUALIZACIÓN/textual en lo que Paraguay expone — el dato estructurado real no se consume |
| Consistencia entre servidores NS (lame delegation) | NUEVA |
| Grafo visual | SOLO VISUALIZACIÓN |
| Dependencia de dnsviz.net en sí (dominio de terceros como fuente) | DEPENDENCIA EXTERNA SIN VALOR ADICIONAL PROPIO — el valor está en los datos que trae, no en el hecho de depender de un tercero |

No se asume redundancia total ni valor automático por ser externo: la
tabla muestra explícitamente que hay capacidades reales y no triviales
(RRSIG, NSEC3, consistencia multi-servidor) que Ecuador no cubre, y
capacidades donde Ecuador ya es superior (interpretación, guía,
confianza).

## 6. Dependencia externa (DNSViz)

- **Disponibilidad**: sin SLA público conocido; es un servicio de
  investigación/comunidad, no un producto comercial con garantías.
- **Robots.txt (verificado en vivo, 2026-09-16)**:
  ```
  User-agent: *
  Allow: /$
  Disallow: /
  ```
  **El operador de dnsviz.net prohíbe explícitamente el acceso automatizado
  a cualquier ruta salvo la raíz exacta del sitio** — lo que incluye las
  páginas `/d/<dominio>/dnssec/` que Paraguay scrapea programáticamente en
  cada invocación del check. Esto no es una opinión: es la política
  publicada por el propio operador.
- **Términos de uso / API**: no existe una API pública documentada.
  Todo lo que Paraguay consume depende de la estructura interna del HTML
  y de un archivo JS de frontend no versionado — puede romperse sin aviso
  ante cualquier cambio de diseño del sitio.
- **CORS**: la página de análisis no envía cabeceras
  `Access-Control-Allow-Origin` (verificado en vivo) — no está pensada
  para consumo programático desde un navegador de terceros.
- **Cache-Control**: la página de análisis se sirve con
  `no-cache, no-store, must-revalidate` (verificado en vivo) — el propio
  servicio no quiere que sus páginas se cacheen aguas abajo, lo cual va
  en la dirección opuesta a "guardar en caché y reutilizar" que
  necesitaría cualquier integración respetuosa de tráfico.
- **Privacidad**: consultar `dnsviz.net/d/<dominio>/...` **revela a un
  tercero exactamente qué dominio está siendo auditado** por un usuario
  de MEDICIONES — sin que el usuario lo sepa necesariamente, si la
  consulta ocurre en el backend de forma automática y no como un enlace
  que el propio usuario decide abrir.
- **Costo por consulta**: un análisis DNSSEC completo (cadena completa,
  múltiples servidores autoritativos, verificación criptográfica) es
  trabajo real no trivial del lado de dnsviz.net — no se pudo confirmar
  con certeza si cada solicitud dispara un análisis nuevo o reutiliza una
  caché interna del propio dnsviz.net, pero el robots.txt deja claro que
  el operador no desea tráfico automatizado repetido, sea cual sea el
  caso real.
- **Riesgo de abuso/sobrecarga si se integrara en MEDICIONES**: dado que
  MEDICIONES ya soporta lotes de hasta 20 dominios por corrida (ver fases
  previas), una integración automática tipo Paraguay dispararía hasta 20
  scrapes por lote contra un servicio que explícitamente pide no ser
  scrapeado — un riesgo real de generar carga no deseada sobre un tercero
  que no lo consintió para este uso.

## 7. Seguridad

- **SSRF**: el propio código de Paraguay construye la URL directamente
  con el dominio del usuario (`https://dnsviz.net/d/${domain}/dnssec/`)
  y usa `fetchPage` — la ruta de fetch **sin** el guard de IP privada
  (`resolvePublicAddresses`) que el resto del proyecto sí exige. En este
  caso específico el riesgo de SSRF clásico es bajo porque el host
  (`dnsviz.net`) está fijo — el dominio del usuario solo viaja como
  segmento de *path*, no como host — pero el patrón en sí (no usar la
  ruta de fetch segura del proyecto) es una inconsistencia frente al
  resto de checks ya endurecidos en Ecuador (Fases 1-4).
- **Redirects**: Paraguay sigue hasta 4 redirecciones manualmente, sin
  validar que el destino siga siendo `dnsviz.net` ni aplicar ningún guard
  de IP privada en cada salto — si `dnsviz.net` alguna vez redirigiera a
  una URL controlada por un atacante (poco probable, pero no verificado
  por el código), no habría ninguna barrera.
- **Payload/tamaño de respuesta**: sin límite explícito de tamaño en la
  descarga del HTML/JS/SVG.
- **Parsing inseguro**: el uso de `JSON.parse()` sobre un fragmento
  extraído por regex de un archivo JS ajeno es fràgil pero no
  intrínsecamente inseguro (no hay `eval()` ni ejecución de código de
  terceros) — el riesgo es de **fragilidad/rotura silenciosa**, no de
  seguridad en sentido estricto.
- **Imágenes/HTML externos**: el SVG se sirve tal cual al navegador del
  usuario final de MEDICIONES bajo el propio dominio de MEDICIONES
  (`format=svg`) — un SVG puede contener JavaScript embebido si el
  proveedor de origen decidiera incluirlo; no se observó sanitización del
  contenido SVG antes de servirlo. No se pudo confirmar si dnsviz.net
  incluye scripts en sus SVG (no observado en la muestra revisada), pero
  Paraguay no aplica ninguna sanitización defensiva por su cuenta.

## 8. Experiencia de usuario

Lo que DNSViz aportaría a un usuario de MEDICIONES que no tiene ya:

- Un grafo visual de la cadena de autenticación (Ecuador no ofrece
  ningún gráfico, solo texto/estados estructurados).
- Confirmación de que las firmas activas son criptográficamente válidas
  y no han expirado — un dato real que Ecuador no calcula.

Lo que Ecuador YA ofrece y DNSViz (tal como lo consume Paraguay) no:

- Resumen ejecutivo en español, nivel de riesgo, próximos pasos
  accionables, específicos por tipo de falla (bloqueo en TLD vs. zona
  padre vs. el propio dominio) — diseñado para un operador no experto en
  DNSSEC.
- Un indicador propio de "confianza en el resultado" que le dice al
  usuario cuánto puede fiarse de lo que está viendo.

Una integración que sencillamente repita "grafo + texto de avisos" sin
traducirlo al mismo nivel de utilidad ejecutiva que ya tiene el módulo
DNSSEC de Ecuador sería, en la práctica, una interfaz de menor calidad
que la que MEDICIONES/DNSSEC Ecuador ya construyó — no una mejora.

## 9. Decisión final

**INCORPORAR SOLO COMO ENLACE/CONTRASTE** (Opción B de la tarea) — no
como check de MEDICIONES, no como scraping automatizado, no como
reimplementación local.

Justificación técnica, en orden de las prioridades típicas de este
proyecto (corrección técnica, seguridad, reproducibilidad):

1. El propio módulo DNSSEC de Ecuador **ya identificó, de forma
   independiente y antes de esta auditoría, que DNSViz es la herramienta
   correcta para la brecha real que tiene** (validación criptográfica de
   RRSIG) — y ya lo recomienda por nombre en su guía. Esta auditoría
   simplemente confirma, con evidencia técnica propia, que esa
   recomendación es correcta.
2. Automatizar el scraping (como hace Paraguay) **viola el robots.txt
   explícito de dnsviz.net** — un servicio comunitario, sin API oficial,
   cuyo operador ha declarado que no quiere tráfico de bots en esas
   rutas. Repetir el patrón de Paraguay en un módulo que además soporta
   lotes de hasta 20 dominios agravaría ese problema, no lo mantendría al
   mismo nivel.
3. Lo que Paraguay realmente extrae de DNSViz (texto de avisos + un
   grafo opaco) es una fracción mínima de la profundidad real de la
   plataforma — no justifica el costo de mantenimiento de un scraper
   frágil (depende de la estructura interna de un frontend ajeno) ni el
   riesgo de reputación de generar tráfico automatizado no deseado contra
   un tercero.
4. Reimplementar localmente la validación criptográfica de RRSIG
   completa (Opción "reimplementar función equivalente") sería un
   proyecto de envergadura propia (parsing de firmas, verificación
   criptográfica real, manejo de todos los algoritmos DNSSEC vigentes) —
   desproporcionado frente al valor incremental para MEDICIONES, y fuera
   del rol que el propio módulo DNSSEC de Ecuador ya se asignó a sí mismo
   (evidencia estructural, no criptografía completa).
5. Un enlace directo, humano, abierto por el propio usuario (no
   automatizado por el backend) **no está gobernado por el robots.txt**
   (que regula bots/crawlers, no clics individuales de personas) y no
   representa carga repetida ni sistemática sobre el tercero — es el uso
   exactamente previsto por dnsviz.net para su página pública.

## 10. Qué hacer en su lugar (sin implementar todavía)

- Añadir, donde ya se muestran resultados DNSSEC en MEDICIONES (y,
  idealmente, también en el módulo DNSSEC independiente si su propio
  equipo lo decide — fuera del alcance de MEDICIONES), un enlace simple:
  `https://dnsviz.net/d/<dominio>/dnssec/`, abierto en una pestaña nueva,
  con un texto que dijo claramente que es una herramienta externa
  independiente para verificación criptográfica adicional.
- No contarlo como check de MEDICIONES (no suma al conteo de 60).
- No cachear nada del lado de MEDICIONES relacionado con DNSViz — el
  enlace simplemente compone la URL con el dominio ya validado/normalizado
  que MEDICIONES ya usa, sin ninguna llamada de red del backend hacia
  dnsviz.net.
- Mantener el texto explicativo ya existente en el módulo DNSSEC de
  Ecuador ("se recomienda complementar con herramientas como DNSViz")
  como la referencia canónica — MEDICIONES solo necesita un enlace
  clicable equivalente, no una nueva narrativa.

## 11. Sobre no acoplar MEDICIONES al módulo DNSSEC

Esta auditoría no encontró ninguna necesidad de integración fuerte entre
ambos módulos. La única "reutilización" recomendada es conceptual (el
mismo criterio de "DNSViz es un complemento externo, no un sustituto")
manifestada de forma independiente en cada módulo, cada uno con su propio
enlace hacia dnsviz.net si lo desea — sin acceso directo a los internals
del módulo DNSSEC desde MEDICIONES, ni viceversa. Ambos módulos siguen
operando de forma completamente independiente, como ya lo hacían.

## 12. Confirmación de alcance (auditoría, fase previa)

No se modificó ningún archivo de código durante la auditoría en sí. No se
creó ningún commit en esa fase. Esa parte fue exclusivamente de lectura y
análisis.

## 13. Decisión de implementación (cierre, 2026-09-16)

Con base en la recomendación de la §9 (INCORPORAR SOLO COMO
ENLACE/CONTRASTE), se implementó exactamente eso — nada más.

### Qué se implementó

- **No check**: DNSViz no aparece en `groupDefinitions`, no tiene
  `checkGlossary`, no tiene `case` en `getCheckResult()`.
- **No scraping**: no se descarga ni analiza HTML, JS ni imágenes de
  dnsviz.net desde ningún punto del código.
- **No backend**: no existe endpoint `/dnsviz`, ninguna ruta en
  `server.js` lo referencia, y `server.js` no contiene la cadena
  `dnsviz.net` en ningún lugar — cero llamadas de servidor hacia ese
  tercero.
- **No incremento de conteo**: MEDICIONES permanece en 60 checks.
- **Enlace externo únicamente**: se agregó `buildDnsvizLink(domain)` en
  el frontend (`index.html`), que construye
  `https://dnsviz.net/d/<dominio ya normalizado con toASCII()>/dnssec/` y
  lo agrega, como un pequeño enlace "DNSViz ↗", junto al nombre de cada
  dominio en la primera columna de la tabla comparativa de resultados
  (`mbRenderPreview()`) — nunca dentro de las columnas de checks, para no
  parecer un control número 61.
- Se agregó, una sola vez (no repetido por fila), una nota explicativa
  breve justo encima de la tabla, junto a la leyenda de símbolos ya
  existente, aclarando que DNSViz es un servicio externo e independiente,
  que solo se contacta si el usuario decide abrir el enlace, y que
  MEDICIONES no realiza esa consulta ni incorpora su resultado a ninguna
  medición propia.

### Razón técnica

La misma que ya estableció la auditoría (§9): automatizar la consulta
violaría el `robots.txt` explícito de dnsviz.net (`Disallow: /`), no
existe una API oficial estable que consumir, y lo que Paraguay extrae por
scraping es una fracción mínima del valor real de la plataforma. Un
enlace abierto por el propio usuario no está gobernado por ese
`robots.txt` (que regula bots automatizados, no clics individuales de
personas) y es exactamente el uso previsto por dnsviz.net para su página
pública.

### Privacidad

Declarado explícitamente en la nota visible junto a la tabla: DNSViz
conocerá el dominio consultado únicamente en el momento en que el usuario
decide abrir el enlace — MEDICIONES no envía ningún dato a dnsviz.net por
su cuenta, ni antes ni después de ese clic, y no se agregó ningún
mecanismo de tracking adicional.

### Independencia del resultado MEDICIONES

El enlace no lee ni escribe ningún estado de ningún check. No participa
en absoluto en el cálculo de PASS/FAIL/INFO/INCONCLUSIVE/
NOT_APPLICABLE/MEASUREMENT_ERROR de ningún check existente — es una pieza
de UI completamente aislada del pipeline `groupDefinitions` →
`getCheckResult()` → `checkConfig`.

### DNSSEC Ecuador y otros módulos

No se modificó el módulo DNSSEC independiente, el Observatorio DNSSEC,
Zonemaster, la lógica de 7 estados, los resolvers ni los datasets. Las
capacidades de DNSViz identificadas en la auditoría (validación real de
RRSIG, NSEC/NSEC3, consistencia multi-servidor) que podrían inspirar
mejoras futuras al módulo DNSSEC de Ecuador quedan fuera de esta
implementación, para una fase independiente si el equipo de ese módulo lo
decide.

### Tests

`test/medicionesDnsvizLink.test.js` (7 casos, análisis estático de texto
sobre `index.html`/`server.js`, sin DOM real): confirma que `dnsviz` no
está en `groupDefinitions`, que no existe ruta backend ni referencia a
`dnsviz.net` en `server.js`, que el enlace normaliza el dominio con
`toASCII()` antes de construir la URL, que la URL apunta exactamente al
host oficial sobre HTTPS, que `target="_blank"` va siempre acompañado de
`rel="noopener noreferrer"`, y que el texto visible nunca usa frases que
sugieran que MEDICIONES realiza esa medición.
