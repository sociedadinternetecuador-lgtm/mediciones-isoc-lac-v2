# Arquitectura — Mediciones ISOC LAC

> Última actualización: 2026-09-09. Agrega la sub-pestaña "Reporte por
> lote" de Mediciones (varios dominios a la vez, reporte PDF/JSON; nombre
> original "Análisis comparativo", renombrada por no comparar nada — ver
> § "Renombre a 'Reporte por lote'"), un glosario de indicadores conectado
> a la UI, varios fixes reales en el módulo de checks individuales (WHOIS,
> RPKI, fetch seguro), una ronda de QA sobre ese reporte en producción
> (símbolos de resultado sin explicar, tabla truncada — ver § tablas
> anchas más abajo), y una reorganización de la taxonomía de checks por
> propósito (tier core/diagnostic/content, 3 duplicados eliminados), un
> deslizador visible para la tabla del lote en pantalla, ajustes de
> tipografía/carátula en la plantilla PDF compartida (mdtopdf), un bug
> real (`escapeAttr is not defined`) que dejaba vacíos el glosario y el
> árbol de checks de "Un dominio", y — al final del día, tras tres rondas
> de ajuste — la **eliminación completa** de todo análisis/agregado sobre
> el dataset en el reporte (semáforo, %, Resumen comparativo con
> Validación DNS/DNSSEC agregado/Resumen por check): a pedido explícito,
> el reporte solo expone contenido genérico fijo (símbolos, glosario,
> limitaciones) y mediciones crudas por dominio — ver § "Sin ningún
> análisis del dataset" más abajo. Por el mismo pedido, la sección de
> detalle por dominio pasó a ser opcional (desmarcada por defecto, checkbox
> en la UI) en vez de estar siempre presente — ver § "Renombre a 'Reporte
> por lote' + alcance personalizable". La sección "Preparación de datasets
> de dominios" (2026-08-14) sigue sin cambios. Este encabezado y todo el
> historial de cambios de este archivo son **de uso interno**: nunca se
> reproducen en el reporte generado ni en la guía de usuario — ambos
> documentos describen solo el estado actual del sistema, sin lenguaje de
> versión ni changelog. Además, tras una validación cruzada de
> `isoc.org.ec` contra herramientas independientes (dig/curl/openssl,
> RIPEstat, handshake SMTP crudo — ver § "Validación cruzada con
> herramientas independientes — primera ronda"): se corrigió
> `handleDomainInfo` (RDAP) que
> siempre fallaba por no seguir redirects y por un `User-Agent` ausente
> (bloqueado por Cloudflare) — de paso se corrigió también la extracción
> del registrador, que leía un campo que no existe en RDAP; se retiró de
> la UI el check "TLS Security Config" porque su dependencia (Mozilla TLS
> Observatory) fue dada de baja permanentemente en 2024 (55 checks en vez
> de 56); y se paralelizaron los dos puertos que prueba "SMTPUTF8" para no
> perder ~15s por dominio en un puerto bloqueado por el hosting. Un cuarto
> hallazgo inicial (SMTPUTF8 como posible falso negativo) se investigó y
> se descartó — el resultado ya era correcto. Una segunda ronda de esa
> misma validación, esta vez contra producción real y recorriendo todas
> las rutas de `server.js` (no una lista armada de memoria — ver § "Validación
> cruzada con herramientas independientes — segunda ronda"), encontró 3 problemas más, verificados como
> genéricos (no intermitentes, no específicos de un dominio) antes de
> tocar código: **TLSA** fallaba siempre porque Node 20.18.0 (versión
> fijada en el `Dockerfile`) no soporta ese rrtype — se cambió a DNS-over-
> HTTPS de Google; **Quad9** (dentro de "Block Detection") fallaba siempre
> porque ahora exige HTTP/2 (RFC 8484) y el código usaba HTTP/1.1 — se
> cambió al módulo `http2` nativo de Node; **Traceroute** dependía de un
> endpoint de HackerTarget que ahora exige API key sin excepción, sin
> alternativa gratuita equivalente — se retiró de la UI, mismo criterio
> que "TLS Security Config" (54 checks en vez de 55). Una tercera ronda,
> con la lista de endpoints generada por `grep` sobre `server.js` (no de
> memoria — ver § "Validación cruzada con herramientas independientes —
> tercera ronda"), encontró 4 problemas más: **"Linked Pages"** clasificaba
> mal enlaces relativos sin `/` inicial (bug propio, corregido resolviendo
> contra la URL real con `URL` nativo); **"Archive"** y el **fallback RDAP
> de "Whois"** fallaban por el mismo patrón que "Domain Info" en la
> primera ronda (`fetchJSON()` sin `User-Agent`) pero en dos lugares de
> código que ese primer fix no había tocado — se agregó un `User-Agent`
> por defecto dentro de `fetchJSON()` (no caso por caso) y se consolidó la
> llamada a RDAP en un helper compartido (`fetchRdap`) usado por ambos
> checks, más un bug adicional de extracción de país encontrado al
> verificar; **"Quality"** silenciaba el error de cuota de PageSpeed
> Insights y devolvía `pwa: null` como si hubiera evaluado el sitio — ahora
> muestra el error real. Se confirmó que "Ranking" (Tranco) no es un bug:
> isoc.org.ec genuinamente no está en ese ranking. Una cuarta ronda probó
> dos dominios más difíciles (`dominiosecuador.ec`, limpio;
> `presidencia.gob.ec`, sí reveló problemas — ver § "cuarta ronda"):
> `errorMessage()` no distinguía fallas de certificado TLS (ej. un
> certificado compartido entre ~26 sitios `.gob.ec` que no cubre la
> variante sin `www` de `presidencia.gob.ec`) del genérico "Servicio no
> disponible", perdiendo una señal de seguridad real — ahora reconoce los
> códigos de error de certificado más comunes; y "SMTPUTF8" con 2+
> registros MX seguía recorriéndolos en secuencia (el fix de la primera
> ronda solo paralelizó los puertos dentro de un mismo MX) — bajó de
> 30.2s a ~15.1s al paralelizar también los registros MX entre sí. Una
> quinta ronda amplió el set de dominios probados más allá de Ecuador
> (`lacnic.net`, `gob.mx`, `cloudflare.com`, el trío de badssl.com,
> `dnssec-failed.org`, `neverssl.com`) — 1 bug de código nuevo ("MX" no
> distinguía "sin registros" de una falla real) y varias confirmaciones
> positivas de los fixes anteriores. El registro completo, dominio por
> dominio (por qué se eligió cada uno, qué se verificó, resultado —
> incluyendo los "sin novedades"), vive en el nuevo
> **`docs/GUIA_PRUEBAS_VALIDACION.md`**, separado de este archivo.

## Qué es este proyecto

Portal web (Node.js + HTML/JS plano) de Internet Society LAC para:

1. **Mediciones de dominios** — más de 30 verificaciones técnicas por dominio
   (MX, DKIM, RPKI, WHOIS, CAA, TLSA, cabeceras de seguridad, cadena TLS, etc.).
2. **DNSSEC** — validación de cadena de firma, individual y por lote.
3. **Observatorio** — histórico de análisis por lote con reportes descargables.
4. **Preparación de datasets de dominios** — el módulo más nuevo y extenso:
   prepara y valida un dataset de dominios ccTLD (típicamente de OpenINTEL)
   **antes** de que se use en las mediciones anteriores.

## Arquitectura general

- **Backend**: `server.js` — un único `http.createServer` (Node puro, sin
  Express/Fastify/etc.). El routing es manual: bloques `if (parsed.pathname
  === '/x')` y prefijos (`startsWith('/obs')`, `startsWith('/dataset')`, ...)
  que delegan a módulos de rutas.
- **Frontend**: `index.html` — un solo archivo, Tailwind vía CDN, sin build
  step ni framework de UI. Sistema de pestañas genérico basado en
  `data-tab`/`data-panel` + clase `.tab-btn.active`/`.tab-panel`.
- **Sin base de datos.** Todo el estado de jobs (Observatorio, Validación DNS)
  vive en memoria (`Map`) dentro del proceso Node — se pierde si el proceso
  se reinicia. Aceptado como decisión de arquitectura para esta fase; no hay
  persistencia en disco salvo cachés (PSL) y archivos históricos de
  Observatorio en `data/`.
- **Despliegue**: Docker, servido en `server1` (home-lab, Tailscale) puerto
  `8700`, sin exposición pública todavía. Ver `docs/server1.md` en el repo de
  infraestructura (`srv/INFRAESTRUCTURA`) para el resto del home-lab.

## Convenciones de módulos (`logic/`)

| Carpeta | Contenido | Ejemplo |
|---|---|---|
| `logic/adapters/` | Integración con fuentes externas (DNS crudo, PSL, DoH) | `rawDns.adapter.js`, `publicSuffixList.adapter.js` |
| `logic/validators/` | Lógica de negocio pura (sin I/O), clasifica/valida | `datasetDomains.validator.js`, `dnsValidation.validator.js` |
| `logic/orchestrators/` | Coordina validators+adapters en jobs de larga duración | `dnsValidationJob.orchestrator.js` |
| `logic/exporters/` | Formatea resultados ya calculados a archivos descargables | `datasetResultsPackage.exporter.js`, `zip.writer.js` |
| `logic/builders/`, `logic/rules/`, `logic/content/`, `logic/processors/` | Preexistentes, del módulo DNSSEC | — |
| `routes/` | Handlers HTTP que llaman a `logic/` | `datasetPreparation.routes.js` |
| `aggregate/` | Módulo Observatorio (preexistente, patrón job+SSE que se reutilizó) | `orchestrator.js`, `observatory.routes.js` |
| `test/` | Scripts de prueba planos con `assert` de Node — sin framework de test nuevo | ver sección Testing |

**Nota de arquitectura real (no ideal):** existe `routes/dnssec.routes.js` que
usa Express y **no está conectado a nada** — `server.js` reimplementa esa
misma lógica inline. Es código muerto, detectado durante este trabajo. No se
eliminó (no se pidió), pero cualquier cambio al endpoint `/dnssec-analysis`
debe hacerse en `server.js`, no en ese archivo.

## Preparación de datasets de dominios — las 5 etapas

Implementado como réplica metodológica fiel de
`validador/validar_dominios_isoc_lac.py` (script Python de referencia,
**no modificado**). El principio rector en todo el módulo: **no introducir
una metodología nueva** — cuando JS y Python difieren, se investiga la causa
exacta en el código fuente de Python y se replica, nunca se "mejora" por
intuición.

```
Fuente → Carga → Normalización → Validación DNS → Resultados y descarga
```

### 1. Fuente
Solo contenido informativo (tarjeta OpenINTEL: qué es, por qué no es un censo
oficial, enlace a openintel.nl). Sin scraping ni descarga automática.

### 2. Carga
100% cliente (JS del navegador): lee el archivo, calcula SHA-256
(`crypto.subtle` — requiere HTTPS o `localhost`, degrada con un mensaje claro
si no está disponible), detecta fecha/ccTLD del nombre de archivo
(heurística, siempre editable por el usuario).

### 3. Normalización
`POST /dataset/normalize` → `logic/validators/datasetDomains.validator.js`.

Réplica de `parse_input()`/`static_valid()` de Python, con dos hallazgos
importantes documentados en el código:

- **`normalizeDomainLine()`** replica `str.strip().strip('"').strip("'")
  .rstrip(".")` de Python exactamente (quitando *todas* las apariciones
  consecutivas del carácter, no solo una — un regex ancorado simple no basta).
- **`pythonIdnaEncode()`** replica el "fast path" del codec `idna` legado de
  Python (`encodings/idna.py`): si el string completo ya es ASCII, Python
  **no valida caracteres en absoluto**, solo longitud por etiqueta. Por eso
  `"not a domain"` (con espacios) es aceptado por Python como ASCII válido y
  rechazado después por `outside_tld` — mientras que `domainToASCII()` de
  Node lo rechazaría antes, con un motivo distinto (`idna_error`). Usar
  `domainToASCII()` a secas habría sido **más estricto que Python**, no
  equivalente.

Clasificación de sufijo: `logic/adapters/publicSuffixList.adapter.js`
descarga/cachea la Public Suffix List (sección ICANN únicamente) en
`data/psl_cache/`, con SHA-256 y fecha de obtención expuestos para
reproducibilidad.

### 4. Validación DNS
`POST /dataset/validate-dns` (+ `/progress` SSE, + `/:jobId` estado) →
`logic/orchestrators/dnsValidationJob.orchestrator.js` →
`logic/validators/dnsValidation.validator.js` → `logic/adapters/rawDns.adapter.js`.

- **`rawDns.adapter.js`**: construye paquetes DNS crudos con `dns-packet`
  (ya dependencia del proyecto) sobre `dgram`/`net` (núcleo de Node) — UDP
  primero, TCP si la respuesta viene truncada. Replica el flag **CD=1**
  (Checking Disabled) que usa `dnspython` en Python, verificado
  empíricamente contra `dnssec-failed.org` (dominio de prueba con DNSSEC
  roto a propósito): sin CD=1 da SERVFAIL, con CD=1 da NOERROR — confirma
  que el flag es efectivo.
- **`dnsValidation.validator.js`**: `classifyAnswers()`/`reviewSubtype()`
  replican exactamente `classify_answers()`/`review_subtype()` de Python,
  incluyendo el orden de evaluación (discrepancy se revisa *antes* que
  REFUSED/MIXED en `review_subtype`, por lo que esos subtipos solo aparecen
  cuando *no* hay discrepancia entre resolvers).
- Parámetros — **no configurables, no cambiar sin razón demostrada**:
  resolvers Cloudflare `1.1.1.1` / Google `8.8.8.8`, timeout 2.5s, retries 1,
  workers 20 (concurrencia), review_wait 2.0s, CD=1 siempre activo.
- El job corre en segundo plano (`Map` en memoria, sin persistencia),
  progreso vía SSE — mismo patrón que usa Observatorio
  (`aggregate/orchestrator.js`).
- **Equivalencia verificada contra Python real**: sobre una muestra
  estratificada real de 1,587 dominios (`validador/ec_openintel_normalizado.txt`,
  todos los 32 sufijos), tres corridas independientes en momentos distintos
  dieron **100.000% de acuerdo** en `final_status` y `review_subtype` entre
  Python y JS. Las cuentas de "reintentados"/"discrepancias" SÍ variaron
  entre corridas (ruido transitorio real de red) — por diseño, no se tratan
  como comparables entre ejecuciones.

### 5. Resultados y descarga
`logic/exporters/datasetResultsPackage.exporter.js` construye, **una sola
vez** al terminar el job (nunca en cada descarga), todos los archivos +
`metadata.json` + hashes SHA-256, a partir exclusivamente de los datos ya
calculados. Se cachean en `job.resultsPackage` (memoria).

Archivos generados (nomenclatura idéntica al validador Python):
`dominios_normalizados.txt`, `dominios_validos.txt`, `dominios_nxdomain.txt`,
`dominios_revisar.txt`, `rechazados_estructura.csv` (si aplica),
`validacion_dns.csv`, `discrepancias_resolvers.csv`, `resumen_sufijos.csv`,
`review_por_tipo/*.txt`, `listas_por_sufijo/*.txt`, `metadata.json`.

**Control de integridad** (`buildResultsPackage` → `integrity`):

```
status_sum_equals_normalized   VALID+NXDOMAIN+REVIEW === dominios normalizados
csv_rows_equals_normalized     filas del CSV === dominios normalizados
all_domains_have_result        (tautológico por construcción — siempre true)
no_duplicate_domains           el conjunto de dominios en las filas no tiene duplicados
domain_set_matches_normalized  el conjunto de dominios coincide EXACTAMENTE con el universo normalizado
```

Los dos últimos checks se agregaron tras una ronda de QA que encontró que los
checks puramente numéricos (suma/longitud) no detectan una partición donde un
dominio duplicado "reemplaza" numéricamente a uno faltante — ver
`test/resultsPackage.integrity.test.js` caso C.

`integrity.passed === false` **bloquea las descargas a nivel de API**
(`handleDownloadFile`/`handleDownloadZip` devuelven HTTP 422), no solo a
nivel de UI — este enforcement también se agregó tras QA (antes las rutas
servían el archivo igual, con HTTP 200, aunque la integridad hubiera
fallado).

**ZIP**: escritor propio en `logic/exporters/zip.writer.js` usando solo
`zlib` (DEFLATE) + CRC-32 implementado a mano — **sin dependencia nueva**
(no se usó `archiver`/`jszip`/etc.). Verificado con `unzip` real.

**Invalidación de estado**: seleccionar un archivo nuevo invalida
Normalización+DNS+Resultados; re-ejecutar Normalización invalida
DNS+Resultados. Navegar entre pestañas del portal (Inicio/Preparación/...)
sin cambiar datos preserva todo. Implementado en `index.html`
(`prepInvalidateFromNormalize`/`prepInvalidateDnsAndResultados`).

**Pendiente explícito** (decisión del usuario, no un olvido): generación de
PDF no implementada.

## Mediciones — reporte de dominios (antes "Análisis comparativo", luego "Reporte por lote")

Flujo único de Mediciones (hasta 2026-09-11 convivía con una sub-pestaña
"Un dominio" separada, eliminada — ver § "Eliminación de la sub-pestaña
'Un dominio'" más abajo), para correr los mismos checks + DNSSEC +
validación DNS sobre 1 o varios dominios y descargar un reporte final
(`index.html`, panel `mediciones-panel-batch` / `medicionesBatchStart`).

- **Todo el cálculo corre en el navegador** (reutiliza `getCheckResult`,
  `/dnssec-analysis?format=json` y `/dataset/validate-dns` tal cual, sin
  duplicar lógica) — el backend solo recibe el payload ya ensamblado.
- `routes/medicionesBatchReport.routes.js` + `logic/orchestrators/
  medicionesBatchReport.store.js` (Map en memoria, mismo patrón que
  `dnsValidationJob.orchestrator.js`) + `logic/exporters/
  medicionesBatchReport.exporter.js` (Markdown ejecutivo condensado para
  mdtopdf + JSON con el detalle completo).
- **PDF**: se delega a mdtopdf (servicio externo ya desplegado en
  `server1:8600`, ver `c:\PROJECTS\mdtopdf\contexto.md`) — no se reimplementa
  conversión Markdown→PDF aquí. `MDTOPDF_URL` en `.env` (en producción,
  `http://192.168.16.1:8600` — no `http://server1:8600`, porque desde dentro
  del contenedor `mediciones` el hostname Tailscale `server1` no resuelve;
  sí resuelve la IP LAN del host Docker).
- **Tablas anchas → agrupadas, partidas y en hoja horizontal** (2026-09-09,
  revisión tras QA en producción — ver `git log` del exporter): la primera
  versión solo activaba landscape a partir de 6 checks, pero con lotes
  reales (20+ checks de varios grupos) la tabla se seguía truncando. Causa
  real, no solo de ancho de página: los encabezados usaban la **clave
  cruda** del check (`serverlocation`, sin espacios) en vez de la etiqueta
  legible — un token sin espacios no se puede partir en varias líneas, así
  que cada columna forzaba un ancho mínimo que multiplicado por 20-40
  columnas se salía de la página aunque estuviera en horizontal. Fix en
  `buildComparativeTable`/`buildChecksMeta` (`medicionesBatchReport.exporter.js`):
  - Usa la **etiqueta legible** (`meta.selected_checks_glossary[].label`,
    con espacios — si el payload no la trae, cae a la clave cruda como
    antes, sin las mejoras).
  - **Agrupa por categoría** (mismos 6 grupos de `groupDefinitions`,
    `CHECK_GROUP_ORDER` en el exporter — duplica solo el orden de display,
    no lógica) y **parte cada grupo en tablas de máximo `MAX_CHECKS_PER_TABLE`
    (6) columnas** — garantiza que ninguna tabla, sin importar cuántos
    checks se seleccionen, tenga más columnas de las que caben.
  - Todas las tablas partidas van dentro de **un solo** `::: landscape :::`
    (no uno por tabla) — envolver cada tabla en su propio div forzaba un
    salto de página en cada una (el encabezado `**Grupo**` entre tablas
    quedaba fuera del div, alternando portrait/landscape en cada bloque).
    Con un solo div, mdtopdf/WeasyPrint acomoda varias tablas en la misma
    página landscape cuando caben.
  - Verificado con un PDF real de extremo a extremo (7 dominios × 24 checks
    de 3 categorías, generado contra el servicio real) antes de desplegar.
- **Símbolos de resultado explicados** (mismo QA): los iconos ✓/✗/⚠/ℹ no
  tenían leyenda en ningún lado. Se agregó `STATUS_SYMBOL` en `index.html`
  (con tooltip nativo en la tabla de vista previa del lote, antes
  colapsaba error+info en un solo `?` indistinguible) y `STATUS_LEGEND_ROWS`
  en el exporter — mismos 4 estados (`ok`/`fail`/`error`/`info`) + "sin
  datos". En el PDF, la leyenda vive en una sección **"## Cómo leer este
  reporte"** al principio del documento (no pegada a la tabla comparativa,
  que quedaba fuera de vista varias páginas después).
- **Glosario siempre incluido**: el navegador arma `meta.selected_checks_glossary`
  (función `selectedGlossary()`, misma fuente de verdad que los tooltips de
  la UI — `checkGlossary`/`checkConfig` en `index.html`) y lo manda en el
  payload; el exportador construye con eso la sección "### Glosario de
  indicadores" (dentro de "## Cómo leer este reporte"). No hay una segunda
  copia del glosario en el backend — si el payload no lo trae (compatibilidad
  hacia atrás), la sección igual se genera, vacía.

### Taxonomía de checks: tier + categoría (2026-09-09, reorganización)

`groupDefinitions` en `index.html` pasó de agrupar por "tipo de consulta
técnica" (IP y Red, DNS y Seguridad, etc.) a agrupar por **propósito**, tras
revisar con el usuario qué de los 59 checks era realmente relevante para el
objetivo del proyecto (evidencia técnica de seguridad/infraestructura, no
marketing/UX). Cada grupo lleva un campo `tier`:

- **`tier: 'core'`** (17 checks, 4 grupos: "Seguridad y confianza (DNS/TLS)",
  "Anti-suplantación de correo", "Cabeceras de seguridad web",
  "Transparencia y conectividad moderna") — adopción de buenas prácticas,
  binario, con un "debería tenerlo" claro (alineado con lo que miden
  Internet.nl/Mozilla Observatory) — a diferencia de `diagnostic`, aquí el
  resultado sí tiene un sentido "correcto"/"incorrecto". Cada grupo `core`
  lleva además `category`/`categoryTitle`, campos que quedaron **sin
  consumidor** tras eliminar "Hallazgos por categoría" (ver más abajo) —
  se dejaron (metadata inerte, bajo riesgo) en vez de tocar 4 definiciones
  de grupo por pura prolijidad.
- **`tier: 'diagnostic'`** (29 checks, un solo grupo "Diagnóstico técnico")
  — dan contexto/depuración, sin un valor "correcto" universal (ej. "TLS
  Version" muestra la versión, no dice si es aceptable).
- **`tier: 'content'`** (10 checks, grupo "Contenido y experiencia") — miden
  marketing/UX (SEO, redes sociales, ranking, capturas), no seguridad ni
  infraestructura. **No se eliminaron** (pueden servir a otro tipo de
  análisis) pero: (a) el grupo lleva un campo `note` con la explicación,
  renderizado como aviso ámbar tanto en el árbol de selección
  (`groupNoteHtml()`) como en el glosario
  (`renderGlossaryBlock()`); (b) el `<details>` de ese grupo arranca
  colapsado (`details.open = group.tier !== 'content'`); (c) todos sus
  checks ya tenían `default: false` (no se tocó, solo se confirmó).

**Duplicados eliminados** (eran resúmenes de checks que ya estaban sueltos
en la misma lista — se quitaron de `groupDefinitions`/`checkGlossary` y de
los `case` del switch `getCheckResult`; las rutas backend correspondientes
en `server.js` — `/emailconfig`, `/httpsecurity`, `/dnssecurity` — se
dejaron sin tocar, ahora inalcanzables desde la UI, mismo patrón ya
documentado para `routes/dnssec.routes.js`):

- `emailconfig` ("Email Configuration") — duplicaba `mx`+`spf`+`dmarc`+`dkim`.
- `httpsecurity` ("HTTP Security Features") — duplicaba `csp`/`xfo`/`xcto`/
  `referrer`/`permissions`.
- `dnssecurity` ("DNS Security Extensions") — señal DS/DNSKEY básica que
  duplicaba (con menos detalle) el motor DNSSEC completo que el reporte
  batch YA corre siempre por dominio vía `/dnssec-analysis`, independiente
  de qué checks se seleccionen.

### Sin ningún análisis del dataset — el reporte solo expone mediciones crudas

**Historia de esta sección (2026-09-09), útil si se retoma el tema**: el
reporte comparativo pasó por tres versiones sucesivas de la misma idea,
cada una a pedido explícito del usuario tras revisarla:

1. **v1 — "Conclusiones y hallazgos"**: semáforo (verde/amarillo/rojo) por
   categoría núcleo + narrativa con "adopción", "el indicador más débil",
   "brechas más extendidas del lote".
2. **v2 — "Hallazgos por categoría"**: se pidió que fuera objetivo, sin
   concluir ni inferir nada. Se quitó el semáforo (el color mismo ya es un
   juicio de "bien/mal", no solo la etiqueta de texto) y se reescribió la
   narrativa a lenguaje puramente descriptivo: solo `%` y conteo
   (`N/M resultados "OK"`) por categoría, con el cálculo explicado en el
   propio texto.
3. **v3 — eliminada por completo**: el usuario aclaró que ni siquiera v2
   es aceptable — "no debe existir de ningún modo análisis de los
   resultados para una medición (...) el dataset que nunca se analiza ni
   compara (...) solo las mediciones crudas". Cualquier cómputo SOBRE el
   lote específico (incluso neutral, incluso sin semáforo) cuenta como
   "análisis". Se confirmó con el usuario (pregunta explícita) que esto
   también aplicaba a las otras tres agregaciones preexistentes del
   reporte — no solo a lo construido en la conversación — y la respuesta
   fue eliminar las cuatro.

**Qué se eliminó, completo, de `index.html` y
`logic/exporters/medicionesBatchReport.exporter.js`**:

- `computeCategoryFindings()` / `buildCategoryNarrative()` /
  `mbRenderConclusions()` (index.html) y `buildCategoryNarrative()` /
  `buildConclusionsSection()` (exporter) — la sección "Hallazgos por
  categoría" completa, pantalla y PDF.
- Sección "## Resumen comparativo" del PDF — **preexistente**, no
  construida en esta conversación: "Validación DNS" (conteo
  VALID/NXDOMAIN/REVIEW del lote, `buildDnsValidationSummary`), "DNSSEC
  agregado" (adopción/semáforo/perfil vía `computeAggregate` — el mismo
  motor que sigue usando la pestaña separada "DNSSEC por lote", no
  tocada), "Resumen acumulado por check" (conteo Sí/No por check,
  `buildChecksSummaryTable`).
- En pantalla: las tarjetas "Adopción DNSSEC del lote" y "Dominios VALID"
  (`#mb-summary-dnssec-adoption`/`#mb-summary-dns-valid`) — queda solo
  "Dominios analizados" (un conteo del propio reporte, no un análisis del
  resultado).
- Del payload que arma `medicionesBatchStart()`: ya no se calcula ni se
  manda `comparative.checks_summary` / `dns_validation_summary` /
  `dnssec_aggregate` / `category_findings` — ni siquiera para el JSON. El
  exportador ya no lee `payload.comparative` en absoluto (queda ignorado
  si un cliente viejo lo sigue mandando — probado en el caso 6 del test).

**Qué queda, y por qué SÍ está permitido**:

- `## Cómo leer este reporte` — símbolos de resultado + glosario de
  indicadores + **"### Limitaciones del sistema"** (nueva, texto fijo
  idéntico al de la sección 10 de la guía: `SYSTEM_LIMITATIONS` en el
  exporter). Es contenido **genérico**: el mismo texto exacto en cualquier
  corrida, no depende de qué se haya medido ni de qué haya dado cada
  resultado — coincide exactamente con lo pedido ("una indicación general
  que siempre se incluye... esto siempre es general e idéntico
  independientemente del análisis realizado o del dataset").
- `## Tabla comparativa dominio × check` (antes `### `, anidada bajo
  "Resumen comparativo" — ahora es una sección de primer nivel) y
  `## Detalle por dominio` — mediciones crudas, dominio por dominio. El
  `**DNSSEC**: ... riesgo: ... acción requerida: ...` que trae cada
  dominio en el detalle es una propiedad de LA CONFIGURACIÓN DE ESE
  dominio (viene tal cual del motor `/dnssec-analysis`), no una
  comparación contra otros dominios del lote — se mantuvo por eso.
- Test reescrito completo en `medicionesBatchReport.exporter.test.js`:
  `assertNoDatasetAnalysis()` verifica con una regex negativa
  (`!/verde|amarill|rojo|semáforo|adopción|brecha|débil|sólid|crític|
  indicativo|confiable|muestra insuficiente/i`) más las cuatro secciones
  eliminadas por nombre, sobre CADA markdown generado en el archivo —
  cualquier reintroducción accidental de análisis o de las secciones
  viejas rompe el test. `assertGenericInstructions()` verifica que
  símbolos/glosario/limitaciones estén siempre, con el mismo texto fijo.
- Verificado con `jsdom` (ejecutando el JS real — ver el bug de
  `escapeAttr` más abajo, encontrado con la misma técnica) contra el HTML
  servido real: `mbRenderPreview()` con un payload sin `comparative`
  corre sin excepciones, `#mb-conclusions-wrap` ya no existe en el DOM,
  `computeCategoryFindings`/`mbRenderConclusions` ya no son funciones
  definidas.

### Renombre a "Reporte por lote" + alcance personalizable (2026-09-09)

Dos cambios más, mismo pedido explícito, después de que se eliminó el
análisis del dataset (sección anterior):

1. **Renombre**: "Análisis comparativo" → **"Reporte por lote"**, en todo
   lo user-facing — pestaña (`#mediciones-tab-batch` en `index.html`),
   encabezado de la tabla en pantalla, título del PDF (`title` en
   `buildComparativeMarkdown`), encabezado `## Tabla comparativa dominio ×
   check` → `## Tabla del lote — dominio × indicador`, y sección 9 de
   `docs/GUIA_MEDICIONES_ISOC_LAC.md`. Motivo: el sistema no compara
   dominios entre sí (eso ya había quedado establecido al eliminar el
   análisis del dataset) — "comparativo" describía mal lo que el reporte
   hace. Este historial de renombre es **solo para uso interno** (este
   archivo, comentarios de código, commits) — nunca debe aparecer como
   changelog/versión en el reporte ni en la guía, ambos documentos
   describen únicamente el estado actual del sistema.
2. **Alcance personalizable**: la sección `## Detalle por dominio` pasó de
   estar siempre presente a ser **opcional**, desmarcada por defecto —
   checkbox `#mb-include-domain-detail` en `index.html`, leído en
   `medicionesBatchStart()` y mandado como `meta.include_domain_detail`
   (boolean) en el payload. `buildComparativeMarkdown()`
   (`medicionesBatchReport.exporter.js`) solo agrega la sección si
   `meta.include_domain_detail === true`; por defecto (flag ausente o
   `false`) el PDF trae únicamente carátula + "Cómo leer este reporte" +
   la tabla del lote. El **JSON** no se ve afectado por este flag — sigue
   trayendo siempre el payload completo sin condensar (`buildJsonExport`
   no lee `include_domain_detail`, solo el Markdown/PDF lo respeta). Esto
   (aplica igual sea 1 dominio o varios — no hay un exportador ni un flujo
   de reporte separado para el caso de un solo dominio).
   `test/medicionesBatchReport.exporter.test.js` (caso 7) prueba
   explícitamente las tres variantes: flag ausente, `true` y `false`.

### Glosario de indicadores y tooltips

`groupDefinitions` + `checkGlossary` + `checkConfig` en `index.html` son la
única fuente de verdad de qué hace cada uno de los 54 checks (59 antes de
quitar los 3 duplicados de la reorganización de taxonomía; 56 antes de
retirar `tlsconfig`; 55 antes de retirar también `traceroute` — ver
§ "Validación cruzada con herramientas independientes"). De ahí salen:

- `checkHelpButton(key)` — el ícono "?" con tooltip (CSS `.term-help`) junto
  a cada checkbox.
- `renderGlossaryBlock()` — bloque colapsable "📖 Glosario de términos",
  montado una sola vez, con un `<details>` por grupo (incluye el aviso
  ámbar de `group.note` para el grupo `content`).
- `selectedGlossary(selectedChecks)` — lo que arma el payload del reporte
  batch (arriba); cada entrada trae `key`/`label`/`description`/`group`.

### Toggle de idioma de los nombres de los checks (2026-09-11)

A pedido explícito ("botón de traducción"). Investigación previa a
escribir código: el resto de la interfaz (Inicio, Preparación de
datasets, DNSSEC, Observatorio, Blog, Eventos, `admin.html`,
descripciones, glosario, guía de uso) ya está en español — el **único**
texto en inglés de todo el portal son los ~54 nombres (`label`) de los
checks de Mediciones en `groupDefinitions` (ej. "Whois Lookup", "Server
Location", "TLS Cipher Suites"), términos técnicos de la industria de
seguridad. Esos mismos nombres son los que aparecen como encabezado de
columna en la tabla del reporte PDF/JSON (vía
`meta.selected_checks_glossary[].label`). Se confirmó con el usuario que
el botón debía ser un **interruptor reversible** (no una traducción de
una sola vía), recordando la preferencia entre sesiones.

**Diseño**: cada check en `groupDefinitions` ahora tiene `labelEs` además
de `label` (que pasa a ser implícitamente el inglés). `checkConfig[key]`
(construido a partir de `groupDefinitions`) guarda `labelEn`/`labelEs`
más un campo **`label` mutable** — ese es el que leen todos los puntos de
la UI que ya existían (`checkHelpButton`, `renderGlossaryBlock`,
`selectedGlossary`, `getCheckResult`, `initializeSummary`, los
encabezados de la tabla en pantalla del lote) — así que **no hizo falta
tocar ninguno de esos puntos de consumo**, solo mutar
`checkConfig[key].label` centralizadamente:

- `setCheckLabelLanguage(lang)`: guarda la preferencia en `localStorage`
  (`mediciones-check-label-lang`), reescribe `label` en cada entrada de
  `checkConfig`, y vuelve a renderizar checkboxes (ambas sub-pestañas) +
  glosario + el propio botón.
- Botón `#mediciones-lang-toggle`, ubicado sobre el glosario compartido
  (visible en ambas sub-pestañas, consistente con dónde ya vivía el
  glosario).
- `renderCheckOptions()`/`renderMbCheckOptions()` (los que dibujan los
  árboles de checkboxes) se modificaron para (a) leer
  `checkConfig[check.key].label` en vez de `check.label` crudo, y (b)
  **preservar qué checks estaban marcados** al volver a renderizar —
  antes de este cambio, cualquier re-render reseteaba todo a los valores
  `default` de `groupDefinitions`, lo que habría borrado la selección del
  usuario cada vez que tocara el botón. Se detecta "es un re-render, no
  la primera carga" con `container.dataset.rendered`.

**Por qué no hizo falta tocar el exportador de reportes**: el payload
que arma `medicionesBatchStart()` construye
`meta.selected_checks_glossary` llamando a `selectedGlossary()`, que lee
`checkConfig[key].label` **en el momento de generar el reporte** — como
ese valor ya refleja el idioma elegido (mutado por
`setCheckLabelLanguage`), el PDF/JSON hereda el idioma automáticamente.
`medicionesBatchReport.exporter.js` no sabe ni le importa qué idioma
tiene cada `label` — solo lo imprime tal cual llega.

**Verificación**: con `jsdom` (mismo patrón que el resto de la sesión) se
confirmó: (a) sin errores en consola; (b) el botón muestra el texto
correcto según el idioma guardado al cargar la página; (c) togglear
cambia los labels visibles en ambas sub-pestañas (`whois`: "Whois
Lookup" → "Consulta Whois"; `sslchain`: "SSL Chain Info" → "Cadena de
certificados SSL") y en el glosario; (d) la selección de checks marcados
se preserva exacta (mismo conjunto de 19 claves) antes y después de
togglear, en ambos sentidos (EN→ES→EN); (e) `localStorage` guarda la
preferencia; (f) `selectedGlossary()` devuelve los `label` en español una
vez togleado. Se generó además un reporte PDF real de extremo a extremo
(vía el servicio mdtopdf) con `meta.selected_checks_glossary` en español
y se revisó página por página — la tabla de glosario del PDF muestra
"Consulta Whois", "Cadena de certificados SSL", "Información del
dominio" correctamente.

**No se agregó test automatizado permanente para este feature**: la
verificación con `jsdom` requiere esa dependencia, que solo vive en el
scratchpad de la sesión (nunca en `package.json` del proyecto — ver
"Sin frameworks nuevos" en `CLAUDE.md`); el proyecto tampoco tiene
ningún test de JS de cliente hasta ahora (todos los `test/*.js`
existentes prueban `server.js`/`logic/`, no `index.html`). Mantener esa
frontera es consistente con el resto del proyecto — no se introdujo una
excepción nueva para este feature puntual.

### Deslizador visible en la tabla comparativa (pantalla)

El contenedor de la tabla ya tenía `overflow-x-auto` (scroll horizontal
nativo), pero con muchas columnas seleccionadas el scrollbar del sistema
puede ser fino o estar oculto (Windows con "ocultar barras de
desplazamiento" activado, trackpads, distintos temas de navegador) — el
usuario no se daba cuenta de que había más columnas para ver. Fix en
`index.html`:

- CSS `.table-scroll` fuerza un scrollbar horizontal siempre visible y
  grueso (`scrollbar-width`/`scrollbar-color` para Firefox,
  `::-webkit-scrollbar-*` para Chrome/Edge).
- Además, un `<input type="range">` explícito (`#mb-comparative-slider`,
  clase `.table-scroll-slider`) debajo de la tabla, sincronizado en ambos
  sentidos con el scroll real por `mbWireComparativeSlider()`: mover el
  control desplaza la tabla, y desplazar la tabla (mouse/trackpad/scrollbar)
  actualiza el control. Solo se muestra (`.is-active`) si la tabla
  realmente no cabe completa — con pocas columnas no hay nada que
  desplazar. Se llama después de poblar `thead`/`tbody` en
  `mbRenderPreview()`, dentro de un `requestAnimationFrame` (el ancho real
  solo se conoce después de que el navegador maquetó la tabla).

### Tipografía y carátula de la plantilla PDF compartida (mdtopdf, 2026-09-09)

A pedido explícito: los textos del PDF deben ser Arial, tamaño 12pt como
techo (nunca mayor), para guardar proporción con material impreso
institucional — y la carátula debe mostrar sitio web y correo de contacto.
Cambio en `c:\PROJECTS\mdtopdf\templates\clasico.html` (plantilla única,
compartida por cualquier documento que pase por mdtopdf, no solo
MEDICIONES — ver `contexto.md` de ese proyecto):

- Se quitó el `@import` de Google Fonts (Lora/PT Sans) — ya no depende de
  red para tipografía. Fuente única: `'Liberation Sans', Arial, 'DejaVu
  Sans', sans-serif`. Arial no existe en Linux; **Liberation Sans** es la
  sustituta libre métricamente compatible (mismas medidas carácter por
  carácter) — se instala en el contenedor vía el paquete apt
  `fonts-liberation` (`Dockerfile` de mdtopdf).
- Cuerpo y carátula a 12pt (antes: cuerpo 11.5pt, título de carátula
  25pt). Los encabezados `h1`-`h4` (antes 20pt/15.5pt/12.5pt/11.5pt en
  Lora) también quedan en 12pt — la jerarquía visual ahora es por
  peso/mayúsculas/cursiva (h1: negrita+mayúsculas+línea inferior, h2:
  negrita, h3: negrita cursiva, h4: cursiva), no por tamaño. Tablas a
  10.5pt (por debajo del techo, para que las tablas anchas del reporte
  comparativo no se apreten más de lo necesario).
- Nuevo campo de frontmatter opcional `contact`, renderizado en la
  carátula debajo del autor (`.cover .contact`, 10pt). MEDICIONES lo llena
  siempre con `https://mediciones.isoc.org.ec  ·  info@isoc.org.ec` — ver
  `REPORT_CONTACT` en `medicionesBatchReport.exporter.js` (reporte batch)
  y el frontmatter de `docs/GUIA_MEDICIONES_ISOC_LAC.md` (guía).
- Verificado con un contenedor Docker local aislado antes de desplegar a
  `server1:8600` (mismo procedimiento que los fixes anteriores de esta
  plantilla): guía completa y un reporte comparativo con tabla landscape,
  ambos con la carátula y tipografía nuevas, sin truncamientos.
- **Regresión post-tipografía**: el cambio de tamaños arriba compactó la
  maquetación lo suficiente para reexponer el bug de "título suelto" (el
  mismo problema conceptual de la sección "Tablas anchas" más abajo, pero
  esta vez con un título quedando solo al final de una página y su tabla
  arrancando en la siguiente). Causa exacta: `break-after: avoid` en el
  título solo cubre un lado de la unión título↔tabla — hacía falta también
  `break-before: avoid` en `<table>` para que el renderizador trate
  título+tabla como una sola unidad (ver gotcha 10 en `contexto.md` de
  mdtopdf). Reverificado con el mismo reporte de prueba de 56 checks × 7
  dominios (28 páginas), revisando cada página: cero títulos sueltos.

### Bug real: `escapeAttr is not defined` rompía "Un dominio" y el glosario

Encontrado al fin recibiendo el reporte "el glosario sigue vacío" — ninguna
revisión de sintaxis (`node --check` sobre el JS extraído) lo detectaba
porque **es un error de orden de ejecución entre `<script>`, no de
sintaxis**. Diagnosticado con `jsdom` (ejecutando el HTML/JS real fuera del
navegador, capturando errores no atrapados — no había forma de verlo con
Playwright esta sesión, sin acceso a red para bajar un Chromium
compatible).

`checkHelpButton()` (primer `<script>` de la página, define
`groupDefinitions`/`checkConfig`/`renderCheckOptions`/`renderGlossaryBlock`)
llama a `escapeAttr()` — pero esa función solo estaba definida en un
`<script>` **posterior** (sección Inicio/Blog/Eventos). Los `<script>` de
una página corren en el orden en que aparecen; una `function` declarada en
un bloque posterior no existe todavía cuando corre uno anterior, aunque
después queden en el mismo scope global. Resultado real: apenas
`renderCheckOptions()` llamaba a `checkHelpButton()` para el primer check
del primer grupo, lanzaba `ReferenceError: escapeAttr is not defined` — sin
ningún mensaje visible en pantalla — que abortaba el resto de ese
`<script>`, dejando **tanto `#checksContainer` ("Un dominio") como
`#mediciones-glossary-body` (el glosario) completamente vacíos**, aunque el
`<details>` se abriera/cerrara bien (eso es CSS/HTML nativo, no necesita
JS). `#mb-checksContainer` (pestaña "Análisis comparativo") sí funcionaba,
porque su `renderMbCheckOptions()` vive en un `<script>` posterior, después
de que `escapeAttr` ya existía.

Fix: se movió `escapeAttr()` al primer `<script>`, justo después de
`escapeHtml()` (de la que depende) — una sola definición, ya no dos. Se
verificó con `jsdom` contra el HTML servido real, local y en producción:
cero errores, `#checksContainer` y `#mediciones-glossary-body` con
contenido real (~25 KB cada uno).

**Lección para retomar esta sesión**: para cambios en `index.html` que
toquen la interacción entre `<script>` tags o el orden de definición de
funciones, `node --check` sobre el JS extraído (usado varias veces antes
en esta sesión) solo detecta errores de sintaxis — no detecta
`ReferenceError`/`TypeError` en tiempo de ejecución ni problemas de orden
entre bloques `<script>`. Para eso hace falta ejecutar el JS de verdad
(`jsdom`, instalado como dependencia de desarrollo temporal y aislada en
el scratchpad de la sesión — no se agregó a `package.json` de
MEDICIONES — o un navegador real si hay acceso de red para Playwright).

## Log de mediciones persistente y fix de request coalescing — 2026-09-12

Seguimiento directo de la auditoría de 3 fases (§ siguiente): el usuario
seguía viendo un % de timeout preocupante en `redirect`/`hsts`/`csp`/
`xfo`/`xcto`/`referrer`/`permissions`/`headers`/`server`/`compression`/
`xxss`/`key` en los 20 dominios de una corrida real. Se pidió (a)
implementar un log persistente de mediciones para poder hacer este tipo
de análisis sin scripts ad-hoc, y (b) investigar la causa raíz exacta
antes de tocar código.

**Log de mediciones** (`server.js`): `data/measurements/YYYY-MM-DD.jsonl`,
un renglón JSON por respuesta de check real (`domain`, `check`,
`duration_ms`, `success`, `error_code`). Se engancha en `sendJSON()`
(único punto de paso de casi todos los handlers) leyendo
`res._checkName`/`res._checkDomain` (etiquetados justo antes del
despacho por segmento de ruta) y `res._startedAt` (mismo timestamp que
ya usa el log de acceso). Un archivo por día, en el volumen `data/` ya
persistente; agregado a `.gitignore`.

**Causa raíz confirmada con el log real**: los checks de la lista
comparten `getSecurityHeaders()`/`getTlsInfo()` (index.html) — ambas
funciones tenían el patrón clásico `if (cache[key]) return cache[key];
const data = await fetch(...); cache[key] = data;`. Como hasta 12 checks
de un mismo dominio se disparan con `Promise.all` casi en el mismo tick,
todos pasan el chequeo de caché **antes** de que el primero termine de
llenarlo — confirmado contando llamadas reales en el log:
`/headers/:domain` se llamaba **12 veces por dominio** (no 1), y
`/tlsinfo/:domain` **3 veces**, sin excepción en los 20 dominios. Mismo
bug exacto, del lado servidor, en `fetchWebsite()` (compartida por
`sitefeatures`/`cookies`/`linkedpages`/`socialtags`/`firewall`). El
techo de `safeWebFetch.adapter.js` (30s total) es más largo que el del
cliente (`fetchWithTimeout`, 20s) — el cliente se rinde antes de que el
servidor termine de resolver las 12 llamadas duplicadas compitiendo por
el mismo destino, de ahí el "Timeout" repetido en ese grupo específico
de checks, en todos los dominios a la vez.

**Fix — request coalescing / promise caching**: la primera llamada
guarda la *promesa en curso* de inmediato (antes de esperarla) en un
mapa separado del caché de resultados ya resueltos
(`headerPending`/`tlsPending` en index.html; `htmlPending` Map en
server.js) — llamadas concurrentes posteriores se enganchan a esa misma
promesa en vez de disparar un fetch nuevo. Si falla, se limpia en un
`finally` (nunca queda una promesa rechazada cacheada para siempre).
Sin cambios de timeouts, semántica de estados, frontend visible,
endpoints, ni concurrencia/número de workers — exclusivamente el bug de
caché, a pedido explícito.

**Verificación** (5 tests, servidor local real, `jsdom`): 12 llamadas
concurrentes a `getSecurityHeaders()` para un mismo dominio → 1 fetch
real (antes 12); 2 dominios simultáneos → 1 fetch real cada uno, sin
interferencia cruzada; fetch simulado fallido → las 5 llamadas
concurrentes reciben el mismo error, un reintento posterior sí funciona
(no queda cacheado el rechazo); `fetchWebsite()` con sus 5 checks reales
simultáneos → 1 consulta real + 4 reutilizaciones; corrida real de 3
dominios × 54 checks con el fix aplicado → `headers`/`tlsinfo` en 1x por
dominio en los 3 (antes 12x/3x), 7.3% `MEASUREMENT_ERROR` (vs. 12.8-19.6%
en corridas previas con el bug), 0 timeouts explícitos, duración máxima
19.1s (bajo el techo de 20s del cliente). `npm test` OK.

## Auditoría técnica de Mediciones y corrección en 3 fases — 2026-09-12

Pedido explícito: auditoría completa de por qué un lote real de 20 dominios
(los mismos del "experimento" de comparación con RIPE Atlas — ver más abajo)
dio ~60% de checks en error (`ok: 275, fail: 109, info: 53, error: 643` sobre
1080 mediciones). La auditoría (solo lectura, sin cambios) identificó
causas concretas con evidencia de código; se implementaron en 3 fases,
cada una mostrada y autorizada por separado antes de avanzar a la
siguiente. **DNSSEC y la validación/normalización DNS (módulo
"Preparación de datasets") no se tocaron en ninguna fase** — fuera de
alcance por diseño (CLAUDE.md).

Checkpoints de git creados antes de cada fase para poder revertir:
`c45582a` (antes de esta sesión) → `e1ed8bd` (antes de Fase 1) → `a86c4e4`
(Fase 1) → `9f6c879` (Fase 2) → (Fase 3, este commit).

### Fase 1 — spf/dmarc/ipv4/ipv6 devolvían "Servicio no disponible" en el 100% de los dominios

**Causa**: de los ~54 checks, estos 4 eran los ÚNICOS que llamaban
directo desde el **navegador** a `https://dns.google/resolve` (y `ipv4`
además a `https://ipapi.co`) — nunca pasaban por `server.js`. Como
`fetchWithTimeout()` (index.html) colapsa cualquier fallo del `fetch()`
del navegador al mismo mensaje genérico, y la llamada nunca tocaba este
proceso, no quedaba ningún rastro en `docker logs` para diagnosticarlo.

**Solución**: 4 handlers nuevos en `server.js` (`handleSpf`, `handleDmarc`,
`handleIpv4`, `handleIpv6`) con `dns.resolveTxt`/`resolve4`/`resolve6`
nativos — mismo patrón que `handleMx`/`handleCaa`. La geolocalización de
IPv4 reutiliza `lookupIpMeta()` (primario+fallback ya existente) en vez
de `ipapi.co` suelto. Los 4 `case` de `index.html` pasaron a llamar
`${API_BASE}/spf|dmarc|ipv4|ipv6/...` como el resto de los checks.

**Verificación**: corrida real de 1/5/20 dominios — de 80/80 en error
(20 dominios × 4 checks) a 0/80. Confirmado con `docker logs`: las
llamadas ahora quedan registradas (antes, nada).

### Fase 2 — HTTPS/DKIM/CAA/WAF/PageSpeed + migración de semántica de estados

**Bugs funcionales**, todos con causa confirmada por código y verificados en vivo:

- **HTTPS**: `handleHeaders()` marcaba `https:false` con cualquier código
  distinto de 200 exacto — un 401/403/405/429 (TLS funciona, la app
  responde, solo rechaza el método/autorización) se leía igual que "no
  responde HTTPS". Se expone `statusCode` real; el cliente lo clasifica
  con `httpStatusToCheckStatus()` (nueva función compartida).
- **DKIM**: solo se prueba el selector `"default"` (no estándar);
  `found:false` pasó de "No permite DKIM" a `INCONCLUSIVE` con mensaje
  honesto — no es una verificación exhaustiva.
- **CAA**: `dns.resolve(...,'CAA')` devuelve objetos, `.join(', ')` daba
  `[object Object]`. `formatCaaRecord()` en `server.js` arma el texto
  legible — **se encontró y corrigió un segundo bug durante la propia
  verificación**: los registros CAA de Node también traen `type:'CAA'`,
  que el primer intento de `formatCaaRecord` tomaba por error en vez del
  tag real (`issue`/`issuewild`/`iodef`) — corregido buscando
  explícitamente esos 3 tags del RFC 6844.
- **WAF**: agregado fingerprinting de Imperva y Vercara (faltaban).
  "WAF detectado" pasó de `ok` a `INFO` — no es un juicio bien/mal.
- **PageSpeed**: corte de circuito en memoria
  (`pageSpeedQuotaExhaustedUntil`, 10 min de cooldown) tras detectar
  cuota agotada — confirmado con logs reales: la primera llamada agotada
  tarda normal, las siguientes responden en 0-1ms sin repetir la llamada
  externa.

**Migración de semántica de estados**: `ok/fail/error/info` →
`PASS/FAIL/NOT_APPLICABLE/INCONCLUSIVE/MEASUREMENT_ERROR/INFO` en los
~54 `case` de `getCheckResult()` (index.html), `STATUS_ICON`
(`medicionesBatchReport.exporter.js`) y `status.*` (`public/i18n.js`).
Un fallo interno de la herramienta ya no puede leerse como un hallazgo
real del dominio. **Bug adicional encontrado durante la migración**: el
check genérico `case 'dnssec':` (distinto del análisis DNSSEC completo)
devolvía un estado `'warn'` que **nunca existió** en `STATUS_SYMBOL` —
`not_implemented`/`blocked_at_tld`/`blocked_at_parent` (ej. nic.pa,
bloqueo porque `.pa` no está firmado) se mostraban silenciosamente como
"—" (sin datos) en vez de la información real. Corregido a
`INCONCLUSIVE`. (Nota: ese `case` no tiene checkbox en `groupDefinitions`
— código no alcanzable desde la UI actual, preexistente, no introducido
en esta sesión; se corrigió igual por si se reconecta).

**Verificación**: `npm test` + smoke tests en vivo + corrida real de
1/5/20 dominios con subconjunto de 17 checks representativos → 0
errores de página, reporte generado sin problema.

### Fase 3 — de "quizás es concurrencia" a 3 causas reales verificadas

Antes de tocar código se corrió el lote **completo real** (20 dominios ×
54 checks = 1080 mediciones) contra el código ya con Fases 1-2, para ver
si hacía falta limitar concurrencia (hipótesis original de la auditoría:
threadpool de libuv, tamaño 4 por defecto, compartido por `dns.lookup()`
en todos los checks HTTP). Resultado: **19.6% de error (212/1080)**, ya
muy por debajo del 60% original, pero concentrado de forma no uniforme
en unos pocos dominios (`gob.ec` 31/54, `usa.gov` 27/54, `copaair.com`
25/54, `nic.us` 22/54, `nic.pa` 22/54, `gub.uy` 18/54) — la pregunta era
si esa concentración era un síntoma de concurrencia o de otra cosa.

**Se probó la hipótesis de concurrencia directamente, antes de asumirla**:
5 llamadas a `headers/copaair.com`, secuenciales, separadas por 1s, sin
ninguna concurrencia — falló las 5 veces, idéntico. **Eso descarta
concurrencia como causa** para este patrón: es un fallo constante, no
intermitente. Conexión TCP directa confirmó la causa real:

```
HTTPS directo a copaair.com (apex, sin www): ECONNREFUSED puerto 443
HTTP directo a copaair.com (apex): 302 → http://www.copaair.com/...
```

El dominio raíz de `copaair.com` **nunca** escucha HTTPS — solo HTTP,
que redirige a `www` (donde HTTPS sí funciona). Mismo patrón, otra
variante, confirmado también en `gub.uy` y `nic.us`: el certificado del
apex no cubre el hostname exacto, pero el sitio real funciona perfecto
vía `www`. La diferencia real: `handleServerStatus` ya tenía reintento
HTTPS→HTTP si el primero fallaba; `handleHeaders` no — y de
`handleHeaders` dependen **12 de los 54 checks**
(`headers`/`https`/`redirect`/`hsts`/`csp`/`xfo`/`xcto`/`referrer`/
`permissions`/`xxss`/`server`/`compression`), así que fallaban los 12
juntos por la misma causa cada vez que el apex no aceptaba HTTPS directo.

Investigando `gob.ec` (el caso con más errores) apareció una causa
distinta: `dnsrecords/gob.ec` muestra `A:[]`, `AAAA:[]`, pero SÍ tiene
`NS` reales (`n2.nic.ec`, etc.) — es un dominio real, delegado, que
existe únicamente como paraguas DNS de subdominios
(`presidencia.gob.ec`, etc.), sin servicio web propio en el apex. No es
que la herramienta no pudo medir — genuinamente no hay nada que medir
ahí vía HTTP.

**Tres correcciones, todas de bajo riesgo por estar acotadas a causas ya confirmadas**:

1. **`handleHeaders` (server.js) gana el mismo reintento HTTPS→HTTP que
   ya tenía `handleServerStatus`** — copiado tal cual, sin cambiar la
   lógica de interpretación de cabeceras/estado que ya sigue.
2. **`error_code` agregado junto a `error`** en las respuestas de error
   de `server.js` (bulk en las 41 apariciones idénticas del patrón
   `sendJSON(res, 200, { domain, error: errorMessage(e) })`, más 2
   variantes puntuales en `handleDkim`/`handleServerStatus`) — el `e.code`
   original de Node, para que el cliente pueda clasificar sin depender
   de matching de texto traducido.
3. **`resolvePublicAddresses()` (`safeWebFetch.adapter.js`) distingue "no
   existe" de "existe pero sin A/AAAA"**: `dns.lookup()` da `ENOTFOUND`
   para ambos casos por igual; se agregó una consulta adicional
   (`dns.resolve4`/`resolve6` explícitos) **solo cuando el lookup
   principal ya falló** (sin latencia en el camino feliz) — si ambos dan
   `ENODATA` específicamente, se re-etiqueta como
   `WEBFETCH_NO_ADDRESS_RECORD`.
4. **`classifyDataError(data)` (index.html)**, nueva función central:
   códigos de certificado (`ERR_TLS_CERT_ALTNAME_INVALID`,
   `CERT_HAS_EXPIRED`, `DEPTH_ZERO_SELF_SIGNED_CERT`,
   `SELF_SIGNED_CERT_IN_CHAIN`, `UNABLE_TO_VERIFY_LEAF_SIGNATURE`,
   `CERT_NOT_YET_VALID`) → `FAIL` (ya eran hallazgos reales bien
   detectados por `errorMessage()`, solo mal clasificados);
   `WEBFETCH_NO_ADDRESS_RECORD` → `NOT_APPLICABLE`; cualquier otro
   código (timeout, conexión rechazada, DNS caído) sigue en
   `MEASUREMENT_ERROR` sin cambios — ahí sí no se puede afirmar con
   certeza de quién es la causa. Reemplaza, vía bulk edit, las 53
   apariciones idénticas de `status: 'MEASUREMENT_ERROR', details:
   data.error` en `getCheckResult()`.

**Alcance explícitamente NO cubierto** (documentado para no repetir la
investigación después): la detección de `WEBFETCH_NO_ADDRESS_RECORD`
solo alcanza a los checks que pasan por `resolveFinalWebTarget`/
`fetchSafePage` (la mayoría de los basados en HTTP) — los que hacen
conexión TLS/socket cruda por su cuenta (`handleTls`, `handleSslChain`,
`handleOpenPorts`) no se tocaron, quedan con su comportamiento previo
ante un dominio sin A/AAAA.

**Verificación**: `npm test` OK. Verificado en vivo, uno por uno, contra
los 3 dominios reales que motivaron el fix (`copaair.com`, `gub.uy`,
`nic.us` — los 3 ahora devuelven datos reales en vez de error) y contra
`gob.ec` (ahora `error_code: 'WEBFETCH_NO_ADDRESS_RECORD'`). Los 6
códigos de certificado verificados con los dominios de prueba oficiales
de `badssl.com`. `classifyDataError()` probado con los 10 casos
relevantes vía `jsdom`. Corrida real de 1080 mediciones repetida
después del fix, mismos 20 dominios, mismo subconjunto de checks —
resultado antes/después:

| Estado | Antes de Fase 3 | Después de Fase 3 |
|---|---|---|
| PASS | 531 (49.2%) | 555 (51.4%) |
| FAIL | 214 (19.8%) | 250 (23.1%) |
| INCONCLUSIVE | 27 (2.5%) | 29 (2.7%) |
| INFO | 86 (8.0%) | 82 (7.6%) |
| NOT_APPLICABLE | 10 (0.9%) | 26 (2.4%) |
| MEASUREMENT_ERROR | 212 (19.6%) | **138 (12.8%)** |

Por dominio, la mejora es más marcada donde estaba la causa confirmada:
`gub.uy` 18→5 errores, `nic.us` 22→7, `copaair.com` 25→12, `gob.ec`
31→17 (parcial — el resto son checks de socket/TLS crudo, fuera del
alcance de esta fase, ver arriba). `usa.gov` se mantuvo en 27 — como se
documentó, es un problema real de alcanzabilidad externa, no algo que
esta fase pretendiera resolver.

## Eliminación de la sub-pestaña "Un dominio" — flujo único de Mediciones — 2026-09-11

Pedido explícito, en el mismo hilo que el bug de arriba (§ siguiente): *"debe
eliminarse la opción de un dominio pues no tiene sentido.. se puede dejar
solamente la opción de análisis y se puede pegar uno o varios dominios o
subir un txt o csv con uno o varios dominios y el sistema los debe ordenar,
depurar y proceder a analizar"*.

Antes de tocar código se lanzó un agente de planificación (regla propia del
usuario: refactor que afecta más de un módulo) para leer el estado real de
`index.html` y separar qué era exclusivo de "Un dominio" (seguro de borrar)
de qué era infraestructura compartida (`getCheckResult`, `groupDefinitions`,
`checkConfig`, `initializeSummary`/`updateSummary`, `parseBatchDomains`/
`normalizeBatchDomain` — estos dos últimos también los usa, sin relación,
la herramienta de lote de DNSSEC, que no debía tocarse). El plan encontró 4
decisiones de producto genuinas (no técnicas) que "Un dominio" resolvía y
"Reporte por lote" no: Historial (localStorage), Mapa de geolocalización,
selector rápido de país, y el hecho de que el "Resumen acumulado" en
pantalla ya estaba conectado al flujo de lote pero vivía en el HTML del
panel eliminado. Se confirmaron con el usuario antes de borrar nada:

- **Historial**: eliminado (sin equivalente en el flujo único).
- **Mapa**: eliminado (geocodificar muchos dominios contra
  `restcountries.com` no escala bien a lotes grandes; solo funcionaba
  porque "Un dominio" se usaba con pocos).
- **Selector rápido de país**: eliminado (comodidad menor).
- **"Resumen acumulado"**: **conservado y reconvertido en vista de progreso
  en vivo** — `initializeSummary()`/`updateSummary()` ya estaban invocadas
  desde `medicionesBatchStart()`/`runMedicionesBatchDomain()` (llamadas
  preexistentes, nunca se habían tocado), pero el `<div id="summary">` al
  que escriben vivía dentro del panel de "Un dominio" (oculto durante el
  modo lote) — bastó con reubicar ese bloque de HTML dentro del panel
  único, entre la barra de progreso y la tabla final, para que "solo
  funcionara" como resumen en vivo del análisis único o por lotes.

**Cambios**:

- `index.html`: eliminado el panel `#mediciones-panel-single` completo
  (país, textarea de dominios, historial, mapa, tarjetas de resultado por
  dominio) y el selector de sub-pestañas; `#mediciones-panel-batch` pasa a
  ser el único panel (sin `class="hidden"`). Eliminadas las funciones
  exclusivas: `medicionesSwitchTab`, `renderCheckOptions` (queda solo
  `renderMbCheckOptions`), `createResultCard`, `getStatusHtml`,
  `analyzeDomain`, `handleAnalysis`, `loadHistory`, `saveHistory`,
  `initMap`/`clearMap`/`updateMap`, el objeto `countryTlds` y su wiring.
  Se quitó también el `<link>`/`<script>` de Leaflet (unpkg) — sin más
  usos de `L.` en el archivo. `initializeSummary`/`updateSummary`,
  `getCheckResult`, `groupDefinitions`, `checkConfig` y demás
  infraestructura compartida quedaron intactas.
- `mbGetDomainsList()` ahora depura duplicados (case-insensitive, vía
  `normalizeBatchDomain`) y ordena la lista alfabéticamente antes de
  analizar: `[...new Set(domains)].sort()`. `parseBatchDomains()`/
  `normalizeBatchDomain()` en sí **no** se tocaron (siguen sin dedupe/sort
  propios) porque también los usa la herramienta de lote de DNSSEC — el
  dedupe/sort se agregó solo en el punto de ensamblado propio de
  Mediciones para no cambiarle el comportamiento a esa otra herramienta.
- `public/i18n.js`: retiradas las claves `med.subtab.*`/`med.single.*`
  (sin uso ya); reescritas `med.summary.*` ("Resumen acumulado" →
  "Resumen en vivo"), `med.batch.domainsHint`/`maxHint`/`tableHeading`/
  `includeDetailHint` para dejar de asumir "20-25 dominios"/"lote" como
  único caso de uso. Versión `?v=9` → `?v=10`.
- `logic/exporters/medicionesBatchReport.exporter.js`: título del PDF
  ("Reporte por lote de dominios" → "Reporte de dominios"), encabezado de
  la tabla comparativa ("Tabla del lote" → "Tabla de resultados") y el
  campo `export_meta.generator` del JSON, para no seguir asumiendo "lote"
  como marco por defecto — sin cambios de lógica ni de esquema del
  payload. `test/medicionesBatchReport.exporter.test.js` actualizado para
  las dos aserciones que comprobaban el texto exacto del encabezado.
- `docs/GUIA_MEDICIONES_ISOC_LAC.md`: reescritas las secciones 7 y 9 para
  describir un solo flujo (antes: "dos formas de uso... según la
  sub-pestaña"). `public/docs/GUIA_MEDICIONES_ISOC_LAC.pdf` queda
  pendiente de regenerar manualmente (no hay pipeline automático en este
  repo para ese PDF — ver `git status`, ya aparecía modificado antes de
  esta sesión).

**Verificación**: `jsdom` contra servidor local real (no un archivo
estático) — confirmado que los 14 IDs/funciones exclusivos de "Un dominio"
ya no existen en el DOM/`window`; que `#mediciones-panel-batch` quedó sin
`class="hidden"`; que `#summary`/`#summaryBody` quedaron reubicados dentro
del panel único; que `mbGetDomainsList()` sobre una lista con dominios
repetidos (incluida una variante en mayúsculas) y líneas `# comentario`
devuelve exactamente los dominios únicos, ordenados, sin las líneas de
comentario; y una corrida real de extremo a extremo con **1 solo dominio**
(`medicionesBatchStart()` para N=1: histórico gap del período "Un dominio"
vs "lote" — antes N=1 nunca pasaba por el exportador de reportes) que
confirmó: el resumen en vivo se llena durante la corrida, la tabla
comparativa se puebla al terminar, y el POST a
`/mediciones-batch/report` devuelve las URLs de PDF/JSON sin error.
`npm test` OK (incluye el exporter con las aserciones de texto
actualizadas). Desplegado y confirmado: `npm test` OK dentro del
contenedor de `server1` tras el rebuild.

## "Un dominio" perdía la lista completa al pegar dominios uno por línea — 2026-09-11

- **Problema**: el usuario pegó una lista de 20 dominios en la pestaña "Un
  dominio" (no "Reporte por lote"), organizada un dominio por línea con
  encabezados de comentario (`# ARGENTINA`, `# URUGUAY`, etc.), seleccionó
  todos los checks y ejecutó el análisis. El resultado salió "todo
  desorganizado": la tabla resumen no mostraba nada útil, cada
  verificación aparecía como "Servicio no disponible", el bloque de texto
  pegado (con los `#` incluidos) aparecía literalmente en la salida, y el
  mapa de geolocalización quedaba en un estado roto/por defecto.
- **Causa**: 🐛 **bug real de nuestro código**, no relacionado con el
  trabajo de la casilla "Todos/Ninguno" del mismo día (coincidencia: fue
  la primera vez que alguien seleccionó literalmente todos los checks a
  la vez, lo que hizo más visible el problema). `handleAnalysis()` en la
  pestaña "Un dominio" (`index.html`, dentro del primer `<script>`)
  parseaba la lista de dominios con
  `domainsInput.value.trim().split(',')` — **solo** separaba por coma. La
  pestaña "Reporte por lote" ya tenía, desde antes, un parser tolerante
  (`parseBatchDomains()`, separa por salto de línea, coma o `;`, y
  descarta líneas sin un `.` — por lo que las líneas `# PAÍS` se ignoran
  solas). Como la lista pegada no tenía ninguna coma, el `split(',')`
  devolvía **un solo "dominio"** de 292 caracteres con todos los saltos de
  línea y comentarios incluidos — ese string basura se pasaba tal cual a
  cada `getCheckResult()`, que fallaba en todos los checks (de ahí "Servicio
  no disponible" repetido) y el intento de geolocalizar esa cadena rompía
  el mapa.
- **Solución**: `handleAnalysis()` ahora reutiliza el mismo
  `parseBatchDomains()` que ya usaba "Reporte por lote" — ambas pestañas
  comparten exactamente el mismo parser tolerante (salto de línea, coma,
  `;`, líneas sin punto descartadas). Se actualizó también la etiqueta del
  campo (`med.single.domainsLabel`, ambos idiomas en `public/i18n.js`) de
  "Dominios (separados por coma)" a "Dominios (uno por línea o separados
  por coma)" para que quede explícito que ambos formatos funcionan.
- **Verificación**: `jsdom` — reproducido primero el bug aislado
  (`split(',')` sobre el texto pegado real del usuario → 1 sola entrada de
  292 caracteres); confirmado que `parseBatchDomains()` sobre el mismo
  texto produce los 20 dominios limpios, en orden, sin ninguna línea `#`.
  Luego una corrida real de extremo a extremo contra el servidor local
  (pegando una lista reducida de 4 dominios con encabezados de comentario
  en la pestaña "Un dominio", 1 check activo) confirmó 4 tarjetas de
  resultado correctas — una por dominio real — y cero texto de comentario
  filtrado en la salida. `npm test` OK local y en el contenedor de
  `server1`. `public/i18n.js` subido de `?v=8` a `?v=9`.

## Casilla "seleccionar todo/nada" por grupo de checks — 2026-09-12

A pedido explícito: en cada grupo de checks de Mediciones (ambas
sub-pestañas), una casilla en la cabecera del grupo (junto al contador
"N checks") que marca o desmarca todos los checks de ese grupo — sin
afectar los `default` de `groupDefinitions` que se usan al cargar la
página de cero (ver más abajo).

- **Diseño**: `buildGroupMasterCheckbox()` / `syncGroupMasterCheckbox()` /
  `wireGroupMasterCheckbox()` (nuevas, compartidas por
  `renderCheckOptions()` y `renderMbCheckOptions()`, mismo patrón que
  `groupNoteHtml`/`checkHelpButton`). `stopPropagation()` en el evento
  `click` de la casilla evita que marcarla también abra/cierre el
  `<details>` del grupo (todo el `<summary>` es clickeable para eso por
  diseño previo).
- **Binaria, no de tres estados** (corregido el mismo día, a pedido
  explícito de seguimiento): la primera versión usaba el estado nativo
  `indeterminate` de `<input type="checkbox">` cuando algunos checks del
  grupo estaban marcados y otros no. Se pidió que fuera estrictamente
  "TODOS o NINGUNO, mutuamente excluyentes" — sin ese tercer estado
  visual. `syncGroupMasterCheckbox()` ahora fuerza
  `indeterminate = false` siempre; `checked` es `true` únicamente cuando
  el 100% de los checks del grupo están marcados, `false` en cualquier
  otro caso (ninguno o parcial). Un clic entonces siempre lleva a uno de
  los dos extremos puros: si no muestra los 7 marcados (0 o algunos),
  clickear selecciona TODOS; si ya los muestra todos marcados, clickear
  selecciona NINGUNO.
- **Los valores por defecto al recargar la página no cambian**: el nuevo
  mecanismo solo lee/escribe el estado de checkboxes ya existentes en el
  DOM — no toca `check.default` en `groupDefinitions` ni la lógica ya
  existente de `renderCheckOptions()`/`renderMbCheckOptions()` que decide
  el estado inicial (`isRerender ? checkedKeys.has(...) : Boolean(check.default)`).
  Confirmado explícitamente con el pedido del usuario de que esto se
  mantuviera así.
- **Verificación**: `jsdom` — estado inicial mixto del primer grupo (3 de
  7 checks marcados por default) produce `checked: false, indeterminate:
  false` en la casilla maestra (binario, nunca un tercer estado); un clic
  la marca → los 7 quedan marcados, `indeterminate` sigue en `false`; un
  clic más la desmarca → los
  7 quedan desmarcados; marcar 1 a mano deja la maestra en
  `checked: false, indeterminate: false` (no un tercer estado); el
  `<details>` del grupo no se abre/cierra al clickear la casilla (se
  comparó `details.open` antes/después). Repetido en
  `#mb-checksContainer` ("Reporte por lote") con el mismo resultado.

### Seguimiento — casilla sin etiqueta visible + botón "Seleccionar todos" global — 2026-09-11

- **Problema**: captura de pantalla del usuario mostró la casilla maestra
  de grupo (recién agregada arriba) sin ningún texto junto a ella — solo
  `title`/`aria-label` como tooltip, invisibles hasta hacer hover — y por
  separado, arriba del árbol de checks, seguía existiendo el botón de
  texto `"Seleccionar todos"` (`#selectAll` / `#mb-selectAll`) con
  comportamiento **de un solo sentido** (solo marcaba, nunca desmarcaba) y
  sin relación con las casillas de grupo. Pedido explícito: eliminar ese
  botón y poner en su lugar una casilla con nombre visible "Todos/Ninguno".
- **Solución**:
  - `buildGroupMasterCheckbox()` ahora devuelve `{ wrapper, input }`: la
    casilla queda envuelta en un `<label>` con un `<span>` de texto visible
    (clave `med.selectAllGlobal` = "Todos/Ninguno" / "All/None"), no solo
    tooltip. `stopPropagation()` se movió al `<label>` completo para que
    clickear el texto también cuente como clic sobre la casilla sin abrir
    el `<details>` del grupo.
  - `#selectAll` y `#mb-selectAll` dejaron de ser `<button>` con handler de
    un solo sentido — ahora son `<input type="checkbox">` dentro de un
    `<label>` con el mismo texto visible "Todos/Ninguno", en el mismo lugar
    del DOM donde estaba el botón (junto a "Verificaciones a realizar").
  - Nueva función compartida `wireGlobalMasterCheckbox()` (misma lógica
    binaria que `wireGroupMasterCheckbox()`/`syncMasterCheckbox()`, pero
    marca/desmarca **todos** los checks del panel, no solo los de un
    grupo). A diferencia de la maestra de cada grupo (que se recrea en cada
    `renderCheckOptions()`), `#selectAll`/`#mb-selectAll` son elementos
    fijos del DOM que persisten entre renders — por eso usan `onchange =`
    (se sobrescribe) en vez de `addEventListener` (que se acumularía en
    cada cambio de idioma).
  - Clave `med.selectAll` (texto del botón viejo) se retiró de
    `public/i18n.js`; se agregó `med.selectAllGlobal`.
- **Verificación**: `jsdom` contra servidor local real — `#selectAll` y
  `#mb-selectAll` son `type: checkbox`; el texto visible "Todos/Ninguno"
  se confirma tanto en el `<label>` del control global como en el de cada
  grupo; clic en el control global marca/desmarca los 54 checks del panel
  (ambos sentidos, sin tercer estado); marcar 1 casilla a mano dentro de
  un grupo dejó el control global en `checked: false` (no se activa con
  selección parcial); marcar las 54 manualmente activó el control global
  automáticamente; el `<details>` del primer grupo no cambió de estado al
  clickear su maestra; toggle de idioma a inglés tradujo ambos textos
  visibles ("All/None"). Repetido en `#mb-checksContainer`. Confirmado
  también contra producción (`https://mediciones.isoc.org.ec/`) tras el
  despliegue: mismo resultado. `npm test` OK local y en el contenedor de
  `server1`. Versión de `public/i18n.js` en `index.html`/`admin.html`
  subida de `?v=7` a `?v=8`.

## Caché de borde de Cloudflare sirviendo `i18n.js` desactualizado — 2026-09-11

- **Problema**: el usuario reportó (con captura de pantalla) el módulo
  Mediciones mostrando claves crudas sin traducir (`med.heading`,
  `med.subtitle`, `med.batch.domainsLabel`, etc.) en vez del texto real,
  después de varios despliegues sucesivos de `public/i18n.js` durante la
  construcción del toggle de idioma.
- **Causa**: 🌐 **cambio externo (comportamiento de infraestructura, no
  un bug de nuestro código en sentido estricto)** — verificado con
  `curl -D -` directo a `https://mediciones.isoc.org.ec/i18n.js`:
  `cf-cache-status: HIT` con `Cache-Control: max-age=14400` (4 horas),
  sirviendo una versión de `i18n.js` **sin** las claves agregadas en fases
  posteriores. `server.js` nunca mandó ningún `Cache-Control` para
  archivos estáticos — ese header lo agrega **Cloudflare en su borde**,
  por defecto, para archivos `.js` sin importar lo que mande el origen.
  Cada despliegue sobreescribía el archivo en el servidor, pero
  Cloudflare seguía sirviendo su copia cacheada desde antes del cambio —
  afectaba a **todos** los visitantes, no solo al navegador del usuario
  que lo reportó.
- **Solución**: dos capas, la de arriba es la que realmente resuelve el
  problema de raíz — (a) **principal**: `<script src="/i18n.js?v=N">` en
  `index.html` y `admin.html` — una URL con query string nueva es, para
  Cloudflare, un recurso distinto nunca cacheado, así que cada vez que se
  edite `public/i18n.js` hay que subir `N` para forzar que todos los
  visitantes obtengan la versión nueva sin depender de que Cloudflare
  respete ningún header; (b) **respaldo**: `server.js` ahora manda
  `Cache-Control: no-cache` explícito para cualquier `.js` servido desde
  `public/` (no elimina el problema por sí solo — Cloudflare puede
  igual no respetarlo, como se vio — pero es la práctica correcta y cubre
  cualquier otro `.js` que se agregue a futuro sin acordarse de
  versionarlo).
- **Verificación**: `curl -D -` a la URL nueva (`?v=6`) mostró
  `cf-cache-status: EXPIRED` (miss real, trajo la versión actual del
  origen) en vez de `HIT`; el contenido de la respuesta ya incluye las
  claves de fases posteriores; y con `jsdom` contra la producción real
  (no un HTML local) se confirmó que el texto renderizado en pantalla es
  el real ("MEDICIONES", "Lista de dominios", "Subir archivo .txt o
  .csv") y no las claves crudas.

## Logging de acceso y errores no manejados — 2026-09-11

- **Problema**: un usuario reportó `"No se pudo generar el reporte
  descargable: HTTP 502"` al correr un lote de 20 dominios en Mediciones
  y descargar el reporte. Preguntó si había algún log para ver qué pasó —
  **no había ninguno**: `docker logs mediciones` solo mostraba la línea de
  arranque del proceso, sin rastro de ninguna de las miles de solicitudes
  ya servidas en producción.
- **Causa**: 🔴 **bug propio (ausencia de instrumentación, no un bug
  funcional confirmado)** — `server.js` nunca tuvo logging de solicitudes
  ni un manejador de `uncaughtException`/`unhandledRejection`. Esto
  importa especialmente porque el callback pasado a `http.createServer`
  es `async` — si una promesa dentro rechaza sin su propio try/catch
  local, Node **no** la captura automáticamente: la respuesta HTTP nunca
  se envía y la conexión queda colgada hasta que algo en el camino (ej.
  el Cloudflare Tunnel) la corta — visto desde el cliente, eso puede
  aparecer exactamente como un `502` sin ningún indicio del lado del
  servidor de qué pasó. **No se pudo confirmar que esta fuera la causa
  real del 502 reportado**: se reprodujo el flujo completo (payload
  realista de 20 dominios × 20 checks, ~171KB, construido con datos reales
  de `/dnssec-analysis` y `/sslchain`) contra producción 5 veces seguidas,
  y también bajo carga concurrente simulando el fan-out real de un lote
  (10 dominios × 2 checks pesados en paralelo + el POST del reporte al
  mismo tiempo) — el endpoint `/mediciones-batch/report` respondió `201`
  en <200ms en todos los casos, sin reproducir el 502. La hipótesis
  principal que queda, sin poder confirmarla, es la misma que ya se
  documentó con `neverssl.com` (ver § "Validación cruzada... quinta
  ronda"): una falla intermitente puntual del Cloudflare Tunnel, no de
  `server.js`.
- **Solución**: se agregó (a) un log de acceso mínimo por solicitud
  (método, ruta, status, duración — sin body ni query string, sin datos
  personales) impreso a stdout (capturado por `docker logs`, sin
  dependencia nueva); (b) un log específico para conexiones cerradas
  **sin** respuesta completa (`res.on('close')` con `!res.writableEnded`)
  — exactamente la señal que confirmaría o descartaría la hipótesis de
  arriba si vuelve a pasar; (c) `process.on('uncaughtException')` que
  registra el stack y termina el proceso (seguro porque
  `docker-compose.yml` ya tiene `restart: unless-stopped` — Docker lo
  reinicia solo) y `process.on('unhandledRejection')` que solo registra,
  sin terminar el proceso (más conservador, dado el tamaño del código base
  y que no fue escrito asumiendo manejo estricto de rechazos en todas
  partes).
- **Verificación**: probado en local (`GET /` y una ruta inexistente,
  ambos logueados con status/duración correctos) y confirmado en
  producción real (`docker logs` después del despliegue muestra las
  solicitudes de verificación con timestamp, método, ruta, status y
  duración). Si el 502 se repite, ahora hay evidencia real que revisar en
  vez de tener que reproducirlo a ciegas.

### Seguimiento — causa raíz del 502 confirmada y corregida — 2026-09-12

El logging agregado arriba cumplió exactamente su propósito: el usuario
repitió el mismo lote de 20 dominios (con todos los checks activos) y
`docker logs mediciones` mostró la causa real de inmediato.

- **Problema**: `docker logs` mostró
  `uncaughtException: Error: connect ENETUNREACH 2801:140:5::10:443 -
  Local (:::0)` con el stack apuntando a
  `logic/adapters/safeWebFetch.adapter.js:127` (dentro del `lookup`
  personalizado de `requestPage()`), seguido de un reinicio completo del
  proceso (`restart: unless-stopped` de Docker lo trajo de vuelta, pero
  **todas** las solicitudes en curso en ese momento — incluido el POST de
  generación del reporte — quedaron cortadas a medio camino, lo cual el
  cliente ve como `502`). Esto explica también "todo desorganizado" y los
  "no disponible" en cascada del reporte del usuario: el servidor entero
  murió mientras decenas de checks estaban en vuelo.
- **Causa**: 🔴 **bug real de nuestro código**, ahora sí confirmado y
  reproducido de forma aislada — `2801:140:5::10` es la dirección IPv6 de
  `nic.ar` (LACNIC), pero el contenedor de `server1` **no tiene ruta
  IPv6** (confirmado: el mismo `ENETUNREACH` se repite también con otra
  IPv6 real distinta, `2600:1f18:...` de otro dominio, en el mismo log).
  `resolvePublicAddresses()` resuelve tanto A como AAAA
  (`dns.lookup(hostname, { all: true })`) y `fetchSafePage()` intenta cada
  dirección en orden dentro de un `try/catch`, pensado para pasar a la
  siguiente si una falla — pero `requestPage()` le pasa a
  `https.request()`/`http.request()` un `lookup` **personalizado y
  síncrono** que fuerza esa dirección específica. Es un caso conocido de
  Node.js: cuando ese `lookup` síncrono resuelve a una dirección
  inalcanzable a nivel de sistema operativo (`ENETUNREACH` inmediato, no
  un timeout), el error puede escapar como excepción **no capturada** en
  vez de emitirse por el evento `'error'` normal de la request —
  saltándose por completo el `try/catch` de `fetchSafePage()` y llegando
  directo al `process.on('uncaughtException')` agregado en la entrada de
  arriba, que mata el proceso.
  - Reproducido de forma aislada y determinística en `server1` (dentro del
    contenedor real, usando el volumen `./data:/app/data` para inyectar un
    script de prueba sin depender de `docker cp`, que falla en este host):
    un `https.request()` mínimo con exactamente el mismo patrón de
    `lookup` síncrono contra `2801:140:5::10` reproduce el **mismo stack
    trace exacto** visto en producción (`uncaughtException` en
    `internalConnect`/`emitLookup`/`lookupAndConnect`).
- **Solución**: se difiere el callback del `lookup` personalizado con
  `setImmediate()` en vez de invocarlo de forma síncrona
  (`safeWebFetch.adapter.js`, `requestPage()`). Diferir un tick rompe la
  cadena síncrona que causaba el escape: Node arma el manejo de errores
  normal de la request antes de intentar conectar, así que el mismo
  `ENETUNREACH` ahora se emite correctamente por `req.on('error', ...)`,
  cae dentro del `try/catch` de `fetchSafePage()`, y el bucle pasa a la
  siguiente dirección disponible (la IPv4, que sí funciona) — sin tumbar
  el proceso.
- **Verificación**: el mismo script de reproducción aislado, con la
  corrección aplicada (`setImmediate`), produce ahora
  `"normal error event fired"` en vez de `uncaughtException` para la
  **misma** dirección IPv6 inalcanzable. `npm test` OK local y en el
  contenedor de `server1`. Verificado en vivo contra producción tras el
  despliegue: `GET /headers/nic.ar` responde `200` (~5.6s — consistente
  con intentar primero la IPv6, fallar de forma segura, y caer a IPv4),
  `docker logs` sin ningún `uncaughtException`/`ENETUNREACH` posterior al
  despliegue, y el contenedor sigue arriba sin reinicios.

## Toggle de idioma de sitio completo (EN⇄ES) — 2026-09-11

A pedido explícito: un interruptor reversible, visible desde la primera
página, que traduce toda la interfaz estática del portal (no solo los
~54 nombres de checks de Mediciones — ver más abajo cómo ese mecanismo
anterior se absorbe en este). Antes de escribir código se usó un Plan
agent para inventariar el alcance real (leyendo `index.html` de 5,362
líneas y `admin.html`) — estimación: **~450-550 strings distintos**
repartidos en 8 fases, ejecutadas incrementalmente (cada una revisable
por separado). Este documento se actualiza a medida que avanza cada fase
— ver la tabla de estado más abajo.

### Qué NO se traduce (decisión explícita, confirmada con el usuario)

1. **La narrativa que genera el motor DNSSEC del lado del servidor**
   (`logic/content/dnssecGuidance.content.js`, `dnssecGlossary.content.js`,
   `logic/rules/dnssec.rules.js`, `logic/processors/dnssec.processor.js`)
   — campos `summary`, `technical_summary`, `guidance.*`, `glossary[].*`
   que llegan ya armados desde `/dnssec-analysis`. Es prosa ligada a
   lógica de clasificación DNSSEC, metodológicamente cerrada según
   `CLAUDE.md`. Queda **siempre en español**, sin importar el idioma
   elegido — esta es una decisión de alcance para esta ronda, no una
   imposibilidad técnica; si se quiere revisar a futuro, es un plan
   aparte, no una extensión mecánica de este.
2. **Los reportes PDF/JSON del módulo Mediciones**
   (`logic/exporters/medicionesBatchReport.exporter.js`) — tiene su
   propio texto fijo en español (categorías, "Cómo leer este reporte",
   limitaciones), independiente de este diccionario. No se toca en esta
   ronda.
3. **Contenido editorial de Blog/Eventos/Materiales** — lo escriben los
   administradores vía el panel (`data/content/*.json`), se muestra tal
   cual lo escribieron. Solo la interfaz alrededor (títulos de sección,
   estados de carga/vacío) entra en el alcance.
4. **`tabPanelObservatorioLegacy`** (sección vieja de Observatorio,
   desconectada de cualquier botón de pestaña alcanzable — código muerto
   preexistente, no confundir con la pestaña "Observatorio" activa, que sí
   se traduce). No vale la pena traducir algo que ningún usuario puede
   ver.

### Diseño técnico

- **`public/i18n.js`** (nuevo, servido como estático desde `/i18n.js` —
  `server.js` ya sirve cualquier archivo bajo `public/` en la raíz, mismo
  mecanismo que `/assets/...` y `/docs/...`; no es una dependencia nueva,
  es un archivo propio) — diccionario único `TRANSLATIONS.es`/`.en`,
  cargado por igual en `index.html` y `admin.html` con
  `<script src="/i18n.js">` **en `<head>`, antes de los `<script>` inline
  del body** (para que `t()`/`currentLang` existan cuando esos bloques
  arman HTML en su primer render — mismo cuidado de orden entre
  `<script>` tags que ya causó el bug real de `escapeAttr` documentado
  más arriba en este archivo).
- Dos convenciones de uso, según el tipo de contenido:
  - `data-i18n="clave"` (+ `data-i18n-placeholder`/`-title`/`-aria-label`)
    en HTML **estático** — `applyLanguage(lang)` barre el DOM una vez con
    `querySelectorAll` y actualiza `textContent`/atributos.
  - `t('clave')` dentro de JS que arma HTML **dinámicamente** (tablas,
    alertas, mensajes) — se evalúa en el momento del render, mismo patrón
    que ya usaba `checkConfig[key].label` para los nombres de los checks,
    ahora generalizado.
- `setLanguage(lang)` guarda la preferencia en `localStorage`
  (`isoc-lac-lang`, clave única de sitio — reemplaza a la anterior
  `mediciones-check-label-lang`, específica de Mediciones, que se absorbe
  en la fase 5) y llama a `applyLanguage()`.
- Idioma por defecto: **español** (`<html lang="es">`, idioma principal
  de todo el contenido actual) — deliberadamente distinto del default
  `'en'` que tenía el mecanismo anterior solo para nombres de checks; con
  alcance de sitio completo, arrancar en español es lo correcto. No se
  migra la preferencia de la clave anterior (ver razón en el código de
  `public/i18n.js`).
- Hook `window.onLanguageApplied(lang)` (opcional, cada página lo define
  si lo necesita) — `i18n.js` no conoce las funciones de render
  específicas de `index.html` (ej. re-renderizar tablas ya construidas
  por JS que no pasan por `data-i18n`); esto evita acoplar el archivo
  compartido a una sola página.

### Estado por fase

| Fase | Contenido | Estado |
|---|---|---|
| 0 | Infraestructura (`public/i18n.js`, carga en ambas páginas) | ✅ hecho |
| 1 | Cabecera global + 8 botones de pestaña + `<title>` | ✅ hecho |
| 2 | Inicio + Observatorio | ✅ hecho |
| 3 | Blog + Eventos + Información (solo interfaz) | ✅ hecho |
| 4 | Preparación de datasets — contenido estático (encabezados, pasos, etapas) | ✅ hecho — **resultados de normalización/validación DNS armados por JS (`prep-normalize-results`, `prep-dns-results`, `prep-resultado-content`) quedan sin traducir, alcance grande aparte** |
| 5 | Mediciones — cabecera, sub-pestañas, formularios, glosario, leyenda de símbolos, alertas, historial, absorbe el toggle de nombres de checks | ✅ hecho — **el texto de detalle/resultado de cada uno de los ~50 `case` de `getCheckResult()` (ej. "Sin datos de Lighthouse", líneas armadas por cada check individual) queda sin traducir, alcance grande aparte, ver nota más abajo** |
| 6 | DNSSEC (solo interfaz, nunca la narrativa) | pendiente |
| 7 | Panel admin (`admin.html`) | infraestructura lista (botón + script), contenido pendiente |

**Verificación fases 0-1**: `jsdom` contra el servidor local real (no un
HTML estático aislado, para que `/i18n.js` se sirva de verdad) — sin
errores; `<title>`, subtítulo, los 8 botones de pestaña, y el atributo
`title`/`aria-label` del link de Admin cambian correctamente en ambos
sentidos (ES→EN→ES); `<html lang>` se actualiza; `localStorage` persiste;
el mecanismo de checkboxes de Mediciones (`checkLabelLang`) sigue intacto
sin interferencia (se absorbe recién en la fase 5, no antes). El botón y
el `<script src="/i18n.js">` se confirmaron presentes en el HTML servido
de `/admin`.

**Verificación fase 2**: `jsdom` — encabezado, párrafo con `<strong>`/
`<code>`/`<a>` embebidos (`data-i18n-html`), y las 3 tarjetas de
Observatorio cambian correctamente en ambos sentidos.

**Verificación fase 3**: `jsdom` — encabezados y estados vacíos de Blog/
Eventos/Información cambian correctamente, incluyendo el re-render vía
`window.onLanguageApplied` cuando el toggle se usa **después** de que la
tarjeta ya se pintó (fetch real contra `/content/blog` etc., con el
servidor local corriendo). Confirmado que el contenido editorial en sí
(`item.title`/`description`, `post.title`/`summary`, `ev.title`/
`description`) nunca pasa por `t()` — sigue tal cual lo escribió el
administrador, como se pidió.

**Verificación fase 4** (contenido estático): `jsdom` — encabezado, lista
con marcado embebido (`data-i18n-html="prep.source.list"`), y el texto de
la etapa de Validación DNS (con `<strong>VALID</strong>` etc.) cambian
correctamente.

**Verificación fase 5**: `jsdom` — encabezado del módulo, sub-pestañas,
leyenda de símbolos (`STATUS_SYMBOL`, ahora sin `label` fijo — se calcula
con `t()` en el momento de renderizar, tanto en la leyenda como en el
`title` de cada celda de la tabla del lote), encabezado de la tabla del
lote, y el selector de velocidad cambian correctamente. Se confirmó
específicamente que **absorber el toggle de nombres de checks no rompió
nada**: el checkbox de "whois" se marcó a mano, se togleó el idioma
global, y siguió marcado — y su nombre pasó de "Consulta Whois" (español,
default nuevo) a "Whois Lookup" (inglés) usando el mismo mecanismo
`checkConfig[key].label` que ya existía, ahora disparado por
`window.onLanguageApplied` en lugar de su propio setter. El botón viejo
`#mediciones-lang-toggle` (específico de Mediciones) se eliminó — queda
solo el del header global.

**Nota de alcance importante, encontrada al ejecutar la fase 5**: la
estimación original del Plan agent (~120-150 strings para Mediciones)
contaba el texto fijo de la interfaz (formularios, botones, tabla), pero
**no** el texto de *resultado* que arma cada uno de los ~50 `case` dentro
de `getCheckResult()` — cada check individual (ej. `archive`, `quality`,
`sslchain`, etc.) construye sus propias líneas de detalle en español
(`'Sin datos de Lighthouse'`, `'Sin historial'`, mensajes por cada campo
del resultado). Traducir esto es un sub-alcance grande y separado, del
mismo orden de magnitud que la fase 5 ya hecha — no se abordó en esta
pasada. Mismo problema aplica, casi seguro, a las funciones de render de
resultados de la fase 4 (`prep-normalize-results`/`prep-dns-results`/
`prep-resultado-content`) y aplicará también a la fase 6 (DNSSEC). Queda
como alcance pendiente explícito, no un olvido — se decidió no ocultarlo
en la tabla de arriba.

## Fixes reales de checks individuales (módulo Mediciones)

No relacionados al feature de lote — bugs y regresiones externas
encontrados probando en producción. Cada entrada sigue la misma tríada:
**Problema** (síntoma observado) → **Causa** (clasificada — de dónde viene
realmente) → **Solución** (qué se cambió) → **Verificación** (cómo se
confirmó que es real, general y que el fix funciona). La clasificación de
causa usada en todo este archivo:

- 🔴 **Bug propio** — código nuestro incorrecto, sin relación con terceros.
- 🌐 **Cambio externo — protocolo/política** — un tercero cambió cómo
  responde (ej. ahora exige HTTP/2, ahora exige key); nuestro código
  quedó desactualizado respecto a esa nueva regla.
- ⚰️ **Cambio externo — servicio dado de baja** — el tercero del que
  dependíamos dejó de existir, sin reemplazo directo.
- 🧱 **Limitación de plataforma** — no es un bug de nuestra lógica ni un
  cambio de terceros: una pieza de la plataforma (versión de Node fijada
  en el Dockerfile, en este proyecto) no soporta algo que el check
  necesita.
- ⏱️ **Ineficiencia propia (no rompe el resultado)** — el resultado ya era
  correcto, pero el diseño desperdicia tiempo/recursos innecesariamente.

### `logic/adapters/safeWebFetch.adapter.js` — 2026-09-09

- **Problema**: `fetchPage` (el helper viejo, usado en whois/headers/
  security.txt/robots/sitemap/status) no seguía cadenas de redirección con
  ninguna protección contra SSRF (podía terminar apuntando a una IP
  privada si un dominio redirigía ahí).
- **Causa**: 🔴 bug propio — `fetchPage` nunca implementó esa protección.
- **Solución**: nuevo adaptador `safeWebFetch.adapter.js`
  (`fetchSafePage`/`resolveFinalWebTarget`) que sigue redirects con
  guardas SSRF (bloquea IPs privadas, límite de saltos) y reemplaza a
  `fetchPage` en todos los checks que lo usaban.
- **Verificación**: `test/safeWebFetch.adapter.test.js` (en `npm test`).

### RPKI (`server.js`, `rpkiValidity`) — 2026-09-09

- **Problema**: el check de RPKI siempre devolvía `state: 'unknown'`, para
  cualquier IP.
- **Causa**: dos causas combinadas — ⚰️ **cambio externo (servicio dado de
  baja)**: la API de Cloudflare RPKI que se usaba
  (`rpki.cloudflare.com/api/v1/validity`) ya no existe (404 siempre); y
  🔴 **bug propio**: el ASN que devuelve RIPEstat viene como **string**
  (`"13335"`), no `number` ni objeto, y el código lo comparaba mal —
  aunque la llamada a Cloudflare hubiera funcionado, este segundo bug
  también habría forzado `state: 'unknown'`.
- **Solución**: se quitó la llamada a Cloudflare; ahora usa solo RIPEstat,
  parseando el `asn` correctamente antes de compararlo.
- **Verificación**: verificado end-to-end en la ronda de validación cruzada
  de más abajo (`/rpki/isoc.org.ec` → `state: valid`, ASN 13335 correcto).

### WHOIS (`server.js`, `handleWhois`) — 2026-09-09

- **Problema**: el campo de organización/país podía traer el dato del
  *Registrar* en vez del *Registrant* si el HTML de la fuente cambiaba de
  orden. Además, "sin datos porque están redactados por privacidad" y
  "error técnico consultando la fuente" se veían idénticos (ambos como
  campos vacíos), sin forma de distinguirlos.
- **Causa**: 🔴 bug propio — el regex de extracción leía el HTML de
  whois.com sin acotar primero a la sección correcta.
- **Solución**: se acota primero al bloque `"Registrant Contact"`
  (`extractWhoisComSection`) antes de aplicar los regex; se agregó
  `status`/`message`/`disclaimer` en la respuesta para distinguir los dos
  escenarios.
- **Verificación**: probado contra dominios reales con y sin redacción de
  privacidad, confirmando que cada caso ahora trae el `status` correcto.

### Carga de `.env` al boot de `server.js` — 2026-09-09

- **Problema**: no había forma de que `server.js` leyera credenciales
  desde `.env` al arrancar.
- **Causa**: no aplica una de las categorías de arriba — es una
  **necesidad nueva**, no un bug: se agregó `nodemailer` (envío de
  contraseñas del panel admin) y con eso credenciales SMTP que debían
  cargarse desde `.env`.
- **Solución**: parser mínimo de `.env` al inicio de `server.js`, sin
  dependencia nueva (solo variables no definidas ya por el entorno —
  Docker/systemd tienen prioridad).
- **Verificación**: `npm test` (`adminAuth.session.test.js`) ejercita el
  flujo que depende de estas credenciales.

### Validación cruzada con herramientas independientes — primera ronda (2026-09-09)

A pedido explícito del usuario: antes de confiar en los resultados de
Mediciones para publicar hallazgos, se contrastó `isoc.org.ec` (dominio
piloto, elegido por estar muy bien configurado — DNSSEC, DMARC estricto,
CAA, CSP, HSTS, TLS 1.3, todo presente) contra herramientas externas
reconocidas: `dig`/`curl`/`openssl s_client` a mano, DNS-over-HTTPS de
Google, Verisign DNSSEC Debugger/DNSViz (conceptualmente — el propio motor
`/dnssec-analysis` ya recomienda contrastar con DNSViz en su salida),
RIPEstat (RPKI), y un handshake SMTP crudo por socket. En los checks que
se pudieron contrastar (DNS, DNSSEC, TLS, CAA, cabeceras, RPKI, MX/TXT) el
sistema coincidió sin discrepancias.

#### 1. "Domain Info" (RDAP) — 2026-09-09

- **Problema**: siempre devolvía `{"error":"Servicio no disponible"}`,
  para cualquier dominio.
- **Causa**: 🔴 **bug propio, doble** — (a) `fetchJSON()` (la llamada
  original en `handleDomainInfo`) usa `http/https.request()` crudo sin
  seguir redirecciones, y `rdap.org` responde con **302** hacia el
  servidor RDAP autoritativo del TLD (ej. `.ec` → `rdap.registry.ec`)
  antes de entregar el JSON real — `JSON.parse()` fallaba sobre el cuerpo
  del 302. Confirmado con `curl -D -` sin seguir redirects (302) vs con
  `-L` (200, JSON completo). (b) Al corregir (a) reutilizando
  `resolveFinalWebTarget`, seguía fallando por una segunda causa propia:
  `rdap.org` está detrás de Cloudflare y devuelve **403** a peticiones sin
  `User-Agent` (`curl -A ""` → 403; `curl -A "Mozilla/..."` → 302), y
  ninguna llamada de este proyecto mandaba `User-Agent` hasta ahora. (No
  se tocó el adaptador compartido para agregar un `User-Agent` por
  defecto — cambio de mayor alcance, fuera de lo pedido; es probable que
  otros checks que usan el mismo adaptador, como headers/security.txt/
  redirect-chain/server-status/associated-hosts, tengan el mismo problema
  contra sitios con filtrado similar — **pendiente, no investigado**.)
  (c) Bug propio adicional, encontrado al implementar el fix, no
  reportado originalmente: aunque el redirect se siguiera, el campo
  `registry` iba a seguir saliendo `null` porque el código leía
  `data.registryName`, un campo que **no existe** en el esquema RDAP — el
  nombre del registrador vive anidado en `entities[].vcardArray`.
- **Solución**: `handleDomainInfo` (`server.js`) ahora usa
  `resolveFinalWebTarget` con `User-Agent:
  MedicionesISOCLAC/1.0 (+https://mediciones.isoc.org.ec)` y `Accept:
  application/rdap+json`, parsea `resolved.response.body`, y usa la nueva
  función `rdapEntityName(entities, role)` para extraer `registry`.
- **Verificación**: 5 dominios reales (no solo isoc.org.ec, para no
  sobreajustar el fix a un caso): `isoc.org.ec` (ccTLD con redirect),
  `nic.uy` (ccTLD sin datos — responde vacío, no error, comportamiento
  correcto), `google.com` y `lacnic.net` (gTLD), y un dominio inventado
  (`dominio-que-no-existe-xyz123abc.ec`, también vacío sin error).
  Cubierto por `test/domainChecks.live.smoke.test.js` (red real, no en
  `npm test`).

#### 2. "TLS Security Config" — 2026-09-09

- **Problema**: siempre devolvía `{"error":"Servicio no disponible"}`,
  para cualquier dominio.
- **Causa**: ⚰️ **cambio externo (servicio dado de baja permanentemente)**
  — el check llama a `tls-observatory.services.mozilla.com` (Mozilla TLS
  Observatory). Mozilla dio de baja ese servicio en **octubre de 2024** y
  archivó el repositorio en **diciembre de 2025** — confirmado tanto por
  búsqueda (GitHub, changelog de Mozilla) como por `curl` directo al
  endpoint, que no responde en absoluto (timeout de conexión, no un
  404/500 — el host ya no atiende). No es un problema temporal ni de este
  entorno, y no hay swap simple: no existe un servicio hosteado gratuito
  equivalente que devuelva el mismo formato `{score, tests}`. Además el
  check se solapaba con 4 checks que sí funcionan (`tlsinfo`, `sslchain`,
  `tlsciphers`, `tlssimulation`).
- **Solución**: se **retiró de la UI** (`index.html`): entrada en
  `groupDefinitions` (grupo "Diagnóstico técnico"), `checkGlossary`, y el
  `case 'tlsconfig'` del switch en `getCheckResult`. La ruta `/tlsconfig`
  y `handleTlsConfig` en `server.js` se dejaron sin tocar (mismo patrón
  que `/emailconfig`, `/httpsecurity`, `/dnssecurity` — ver § Taxonomía de
  checks), ahora inalcanzable desde la UI, con un comentario explicando
  por qué.
- **Verificación**: confirmado que el endpoint de Mozilla no responde
  (timeout) y que `tlsconfig` ya no aparece en el HTML servido
  (`grep -c "TLS Security Config"` → 0) ni en `groupDefinitions`.

#### 3. "SMTPUTF8" — 2026-09-09

- **Problema (hallazgo inicial, descartado)**: se sospechó que el
  resultado `"no"` para `isoc.org.ec` era un falso negativo por bloqueo
  del puerto 25 saliente.
- **Causa**: ❌ **no era un bug** — se verificó con un **handshake SMTP
  crudo por socket TCP** (Node, sin pasar por nuestro código) contra
  `mail.isoc.org.ec:587`: el EHLO real devuelve `SIZE`, `8BITMIME`,
  `PIPELINING`, `AUTH`, `STARTTLS` — **sin `SMTPUTF8`**. El resultado del
  sistema era correcto; se descartó el hallazgo.
- **Problema real, más chico**: `checkSmtpUtf8` probaba los puertos 25 y
  587 **en secuencia**, perdiendo ~15s por dominio.
- **Causa**: ⏱️ **ineficiencia propia (no rompía el resultado)** — el
  puerto 25 está bloqueado saliente tanto en `server1` (producción,
  verificado con `/dev/tcp` por SSH) como en este entorno de desarrollo,
  así que cada consulta perdía el timeout completo de 15s en el puerto 25
  antes de intentar el 587 (que sí conecta), en secuencia.
- **Solución**: `checkSmtpUtf8` ahora prueba ambos puertos **en paralelo**
  (`Promise.all`), misma prioridad de antes (`supports` > `no` definitivo
  > `timeout`/`connection-error`).
- **Verificación**: mismo resultado correcto (`"no"`) para `isoc.org.ec`,
  ahora en ~15s en vez de ~15s + ronda adicional de 587 en secuencia.
  Cubierto por `test/domainChecks.live.smoke.test.js`.

### Validación cruzada con herramientas independientes — segunda ronda (2026-09-09)

Tras desplegar los 3 fixes de arriba, se pidió repetir la batería completa
contra **producción real** (`https://mediciones.isoc.org.ec`, no un
servidor local) recorriendo **todas** las rutas de `server.js` — la
primera ronda se había hecho contra un servidor local en el entorno de
desarrollo y con una lista de endpoints incompleta (le faltaban
`tlssimulation`, `openports`, `traceroute`, `redirectchain`, `block`; ver
"por qué no se detectaron antes" al final de esta sección). Los 3
problemas encontrados se verificaron como **genéricos y no
intermitentes** antes de tocar código: repetidos varias veces, contra
varios dominios distintos, y desde dos redes distintas (este entorno de
desarrollo y `server1`).

#### 4. "TLSA" — 2026-09-09

- **Problema**: siempre devolvía `{"error":"Servicio no disponible"}`,
  para cualquier dominio.
- **Causa**: 🧱 **limitación de plataforma** — `dns.resolve()` y
  `dns.resolveTlsa()` no reconocen el rrtype TLSA en Node v20.18.0 (la
  versión fijada en `ARG NODE_VERSION` del `Dockerfile`); lanzan
  `TypeError ERR_INVALID_ARG_VALUE` **antes de siquiera consultar la
  red** — confirmado dentro del contenedor con 3 dominios distintos,
  incluyendo uno inventado que no existe, mismo error idéntico en los
  tres. No es un problema de ningún dominio en particular ni del código
  de consulta DNS del proyecto: es que esa versión de Node no implementa
  ese tipo de registro. (La primera ronda no lo detectó porque se probó
  contra un servidor local en este entorno de desarrollo, Node v24.11.1,
  que sí soporta TLSA — nunca se había ejercitado este endpoint contra el
  Node real de producción hasta esta segunda ronda.)
- **Solución**: `handleTlsa` (`server.js`) ya no usa `dns.resolve()` —
  consulta DNS-over-HTTPS de Google (`dns.google/resolve?...&type=TLSA`),
  mismo patrón que `dnssecGoogle()` y los checks de IPv4/IPv6/DMARC del
  cliente. No depende de qué rrtypes soporte el binding nativo de Node.
- **Verificación**: 6 dominios en el primer barrido
  (`isoc.org.ec`, `google.com`, `cloudflare.com`, `nic.uy`, `lacnic.net`,
  `github.com`), más un dominio sin TLSA (`records: []`, sin error) y uno
  con TLSA real (`torproject.org`, formato `"usage selector matchingtype
  hex"` correcto). Cubierto por `test/domainChecks.live.smoke.test.js`.

#### 5. "Block Detection" (resolver Quad9) — 2026-09-09

- **Problema**: el resolver Quad9 (dentro de `/block`) siempre devolvía
  `blocked:false` **junto con** un `error: "Servicio no disponible"`
  contradictorio, para cualquier dominio. Google y Cloudflare (los otros
  dos resolvers del mismo check) funcionaban bien.
- **Causa**: 🌐 **cambio externo (protocolo)** — Quad9 exige HTTP/2 en su
  servidor DoH (`dns.quad9.net`) desde 2026, citando RFC 8484 §5.2; el
  código usaba `https.request()`, que negocia HTTP/1.1 por defecto →
  `HTTP 505` en 3 intentos seguidos y para 3 dominios distintos. No se
  confió solo en el mensaje de error de Quad9: se reprodujo la misma
  consulta con el módulo `http2` nativo de Node (sin dependencia nueva)
  contra el mismo endpoint y se obtuvo `200 OK` con la respuesta DNS
  real — confirma que el único problema es el protocolo, no autenticación
  ni límite de tasa.
- **Solución**: `queryQuad9` (`server.js`) usa `http2.connect()` +
  `client.request()` en vez de `https.request()`.
- **Verificación**: ya no da error; y la **lógica de detección de
  bloqueo** (no solo la ausencia de error) se confirmó probando contra
  `blocked.test.on.quad9.net` (dominio oficial de test de Quad9,
  documentado en su sitio) — el check reporta `blocked: true`
  correctamente para Quad9 mientras Google/Cloudflare dan `false`.
  Cubierto por `test/domainChecks.live.smoke.test.js`.

#### 6. "Traceroute" — 2026-09-09

- **Problema**: siempre devolvía `{"error":"Servicio no disponible (límite
  alcanzado)"}`, para cualquier dominio.
- **Causa**: 🌐 **cambio externo (política del proveedor)** — el check
  depende de `api.hackertarget.com/mtr/`, que ahora responde `"error valid
  key required"` de forma incondicional (verificado: mismo mensaje exacto
  en 3 repeticiones seguidas, para 4 dominios distintos, y desde dos redes
  distintas — este entorno y `server1`; un límite de cuota diaria
  variaría o eventualmente se recuperaría, esto es constante y textual).
  El mensaje de error que teníamos en el código ("límite alcanzado") ya no
  reflejaba la causa real. No hay alternativa gratuita equivalente: se
  investigó RIPEstat looking-glass (necesita un **prefijo IP**, no un
  dominio, y mide anuncios BGP — dato distinto al que el check prometía) y
  otros endpoints de HackerTarget (`/traceroute/`: 404; `/nping/`: también
  exige key). Construir un traceroute real (ICMP/UDP crudo) queda fuera de
  alcance — requiere privilegios elevados y es una herramienta de red
  completa, no un ajuste de un check existente.
- **Solución**: mismo criterio que "TLS Security Config" (#2 arriba) — se
  **retiró de la UI** en vez de simular una funcionalidad que ya no existe
  gratis. Quitado de `groupDefinitions`, `checkGlossary` y el switch en
  `index.html`; `/traceroute` y `handleTraceroute` en `server.js`
  quedaron sin tocar (mismo patrón que los checks retirados
  anteriormente), ahora inalcanzables desde la UI.
- **Verificación**: confirmado que `api.hackertarget.com/mtr/` exige key
  desde dos redes distintas, y que `traceroute` ya no aparece en
  `groupDefinitions`/`checkGlossary`/el switch de `index.html`.

**Por qué la primera ronda no encontró el #5 y el #6**: no fue un fallo
del check enmascarado — simplemente no se habían probado esas rutas. La
primera batería de `curl` cubrió `rpki whois domaininfo tlsa mx smtputf8
securitytxt tlsinfo sslchain tlsciphers tlsconfig firewall dnsrecords
txtrecords dnsserver ipinfo serverinfo serverlocation serverstatus
malware` — una lista armada de memoria, no derivada de recorrer
`server.js`. `tlssimulation`, `openports`, `traceroute`, `redirectchain`
y `block` quedaron fuera por simple omisión. `test/domainChecks.live.smoke.test.js`
ahora cubre los fixes de ambas rondas (RDAP, SMTPUTF8, TLSA, Block/Quad9);
sigue sin cubrir cada endpoint de `server.js` de forma exhaustiva y
sistemática — si se quiere esa garantía a futuro, haría falta generar la
lista de rutas a probar directamente desde el código (ej. parseando los
`if (segments[0] === 'x')` de `server.js`) en vez de mantenerla a mano en
el test.

### Validación cruzada con herramientas independientes — tercera ronda (2026-09-09)

Aplicando la recomendación del cierre de la segunda ronda: la lista de
endpoints a probar se generó **con `grep` directo sobre `server.js`**
(`segments[0] === '...'`), no de memoria — 34 rutas alcanzables desde la
UI recorridas contra producción real. Aparecieron 4 problemas reales
(más uno adicional encontrado al verificar el fix de uno de ellos) y se
confirmó que "Ranking" (Tranco) **no** es un bug: `isoc.org.ec` no está en
el ranking de Tranco (`{"ranks": [], ...}`, confirmado con `curl` directo
al mismo endpoint) — es un sitio pequeño, esperado, no un fallo.

#### 7. "Linked Pages" — 2026-09-09

- **Problema**: enlaces relativos comunes en el HTML real de isoc.org.ec
  (`index.html`, `quienes-somos.html`, `proyectos.html`, `cursos_2026/`)
  se marcaban como `internal: false`, siendo claramente internos.
- **Causa**: 🔴 **bug propio** — `extractLinks()` clasificaba con
  `href.startsWith('/') || href.includes(domain)`. No contempla enlaces
  relativos **sin** `/` inicial, un patrón HTML muy común. Es un bug
  determinista de la función (una entrada de texto fija siempre da la
  misma salida incorrecta) — no depende de qué dominio se consulte ni de
  la red, por construcción.
- **Solución**: `extractLinks(html, baseUrl)` ahora recibe la URL final
  real de la página (`page.url`, post-redirects, ya disponible desde
  `fetchWebsite`) y resuelve cada `href` contra ella con el `URL` nativo
  de Node (`new URL(href, base).hostname === base.hostname`), en vez de
  comparación de substring. Sin dependencia nueva.
- **Verificación**: con el HTML real de isoc.org.ec, los 9 enlaces
  relativos de navegación (`index.html`, etc.) pasaron a `internal: true`;
  los enlaces externos reales (`internetsociety.org`, `corpece.org.ec`)
  siguen en `internal: false`. Cubierto por
  `test/domainChecks.live.smoke.test.js`.

#### 8. "Archive" (Wayback Machine) — 2026-09-09

- **Problema**: siempre devolvía `{"error":"Servicio no disponible"}`,
  aunque isoc.org.ec sí tiene historial en Wayback Machine (snapshots
  desde 2004, confirmado con `curl` directo al mismo endpoint).
- **Causa**: 🔴 **bug propio** — mismo patrón que el bug #1 de RDAP (ver
  arriba), pero en un servicio y una llamada distintos: `fetchJSON()`
  nunca mandaba `User-Agent`, y `web.archive.org` (nginx) responde
  `400 Bad Request` sin uno. Reproducido exacto dentro del contenedor de
  producción: `curl -A ""` → 400; `curl -A "Mozilla/..."` → 200 con datos
  reales. El fix de RDAP (punto 1) solo tocó la llamada puntual de
  `handleDomainInfo`, sin revisar si otras llamadas de `fetchJSON`
  tenían el mismo problema — acá se confirmó que sí, en un segundo
  servicio real.
- **Solución**: en vez de agregar el header caso por caso otra vez, se
  agregó un `User-Agent` **por defecto dentro de `fetchJSON()`** mismo
  (`DEFAULT_FETCH_USER_AGENT`, sobreescribible por el caller) — cubre esta
  llamada y cualquier futura sin tener que recordar agregarlo cada vez.
  Verificado antes de aplicarlo que ninguno de los ~14 consumidores
  actuales de `fetchJSON` (dns.google, cloudflare-dns.com, ipwho.is,
  RIPEstat, tranco-list.eu, urlhaus-api.abuse.ch, entre otros) es sensible
  a este header — no rompe nada existente.
- **Verificación**: `/archive/isoc.org.ec` trae los 5 snapshots reales de
  2004. Cubierto por `test/domainChecks.live.smoke.test.js`.

#### 9. "Whois" — el fallback a RDAP tenía el mismo bug del punto 1, sin corregir — 2026-09-09

- **Problema**: para isoc.org.ec, el check reportaba
  `status: "redactado_o_no_disponible"` — un mensaje que sugiere "los
  datos podrían estar protegidos por privacidad, no es un problema del
  dominio". Verificado que eso es **engañoso**: el RDAP de `.ec` no
  redacta nada (nombre, email, organización del contacto, todo público,
  ya confirmado en el punto 1) — el dato SÍ existe y es público, el
  sistema simplemente no podía alcanzarlo.
- **Causa**: 🔴 **bug propio** — `handleWhois` tiene su **propio** fallback
  interno a RDAP (si el scraping de whois.com no encuentra nombre/país),
  con una llamada a `fetchJSON('https://rdap.org/domain/...')` **separada
  e independiente** de la que ya se había corregido en `handleDomainInfo`
  (punto 1) — nunca se tocó al hacer ese fix, porque no se sabía que
  existía una segunda copia de la misma lógica rota. Reproducido exacto
  dentro del contenedor: `403 Forbidden` (mismo bloqueo por falta de
  `User-Agent`). Para isoc.org.ec específicamente, el scraping de
  whois.com tampoco encuentra la sección "Registrant Contact" en su HTML
  (verificado con `grep` — fuente externa sin ese dato para este dominio,
  no es algo nuestro), así que el resultado dependía **enteramente** de
  que el fallback RDAP funcionara.
- **Bug adicional encontrado al verificar el fix** (no reportado
  originalmente): incluso con el fetch corregido, el campo `country`
  seguía saliendo vacío — el código leía `item[1]?.label`, un parámetro
  vCard que **no existe** en la respuesta real de RDAP; el país viene
  como parámetro `cc` (ej. `{"cc":"EC"}`) o como último elemento del
  array estructurado de dirección (`item[3]`).
- **Solución**: se extrajo un helper compartido `fetchRdap(domain)`
  (`resolveFinalWebTarget` + `User-Agent` + `JSON.parse`, mismo mecanismo
  del punto 1) y `handleWhois` ahora lo usa en vez de su copia de
  `fetchJSON` directo — consolida la lógica de fetch de RDAP en un solo
  lugar, así un futuro bug de este tipo no puede volver a quedar
  duplicado sin corregir. La extracción de `country` ahora lee
  `item[1]?.cc` primero, con el último elemento de `item[3]` como
  respaldo.
- **Verificación**: `isoc.org.ec` → `{"name":"Francis Tigreros",
  "country":"EC","status":"ok"}` (antes: nombre y país vacíos,
  `"redactado_o_no_disponible"`). Probado también con `google.com`
  (`{"name":"Google LLC","country":"US","status":"ok"}`, vía el scraping
  de whois.com — no necesitó el fallback RDAP, pero confirma que el flujo
  completo sigue intacto). Cubierto por
  `test/domainChecks.live.smoke.test.js`.

#### 10. "Quality" (PageSpeed Insights) — 2026-09-09

- **Problema**: devolvía `{"pwa": null}` sin ningún error, pareciendo un
  resultado válido ("el sitio no tiene PWA"), para cualquier dominio.
- **Causa**: dos causas combinadas — 🌐 **límite de cuota de un tercero**:
  la API de Google PageSpeed responde `HTTP 200` con un cuerpo
  `{"error": {...}}` (`429 RESOURCE_EXHAUSTED`, cuota diaria de consultas
  agotada — este proyecto la llama sin API key propia, con la cuota
  anónima compartida); y 🔴 **bug propio**: el código nunca revisaba si
  la respuesta traía `data.error` antes de leer
  `data.lighthouseResult?.categories` (`undefined` en ese caso), así que
  el resultado vacío se interpretaba silenciosamente como "sin PWA" en
  vez de "no se pudo evaluar". Confirmado que la cuota agotada afecta a
  cualquier dominio (probado también con `google.com`, mismo `429`), no
  es algo específico de isoc.org.ec.
- **Solución**: `handleQuality` ahora revisa `data.error` explícitamente
  y devuelve el mensaje real de Google (`error: data.error.message`) en
  vez de seguir leyendo campos inexistentes. No se resolvió la causa de
  cuota en sí (eso requeriría gestionar una API key propia de Google
  Cloud — una decisión de infraestructura/costo que no se tomó
  unilateralmente); el fix asegura que, agotada o no la cuota, el check
  **nunca vuelve a mentir** sobre el resultado.
- **Verificación**: `/quality/isoc.org.ec` ahora muestra el mensaje real
  de cuota de Google en vez de `pwa: null`. Cubierto por
  `test/domainChecks.live.smoke.test.js` (verifica que la respuesta
  siempre traiga o un error explícito o scores reales, nunca un
  resultado ambiguo).

**Nota sobre alcance no cubierto**: `dnssec`, `w3c`, `associatedhosts`,
`carbon`, `techstack` son rutas de `server.js` que existen pero **no
están conectadas a la UI** (no aparecen en `groupDefinitions` de
`index.html`) — inventario de código muerto preexistente, no tocado en
esta ronda por no ser alcanzable por ningún usuario. `serverlocation`/
`serverinfo` siguen con el rate-limit de `ipwho.is` ya documentado en la
segunda ronda (sin cambios nuevos acá).

### Validación cruzada con herramientas independientes — cuarta ronda (2026-09-09)

A pedido explícito: se probaron dos dominios más "difíciles" que
`isoc.org.ec` para forzar casos borde — `dominiosecuador.ec` (el
registrador de `.ec`, resultó limpio, sin hallazgos nuevos sobre el
sistema) y `presidencia.gob.ec` (sí reveló 2 problemas reales). Verificado
con `curl`/`openssl`/Node directo antes de tocar código, igual que en las
rondas anteriores.

#### 11. Mensajes de error genéricos ocultaban fallas de certificado TLS (hallazgo real, no exclusivo de un check) — 2026-09-09

- **Problema**: `/headers`, `/securitytxt` y `/firewall` para
  `presidencia.gob.ec` devolvían todos el mismo
  `{"error":"Servicio no disponible"}` — indistinguible de "el servidor
  no responde".
- **Causa**: 🔴 **bug propio (pérdida de señal diagnóstica)** —
  `presidencia.gob.ec` (sin `www`) sirve un certificado compartido entre
  ~26 sitios `.gob.ec` (agricultura, salud, defensa, etc.) cuyo SAN
  **no incluye** la variante sin `www` del dominio — confirmado con
  `curl` (falla con "target principal name is incorrect") y con Node
  (`ERR_TLS_CERT_ALTNAME_INVALID`). Esto es un hallazgo real sobre el
  sitio del gobierno, no un bug nuestro — pero `errorMessage()` (el
  normalizador de errores de `server.js`) no tenía ningún caso para
  errores de certificado, así que ese hallazgo (en sí mismo valioso para
  una herramienta que mide seguridad de dominios) se perdía detrás de un
  mensaje genérico indistinguible de un fallo de red cualquiera. Los
  checks de TLS (`tlsinfo`, `sslchain`, `tlsciphers`) no se ven afectados
  porque deliberadamente no verifican el hostname del certificado (diseño
  correcto para poder inspeccionar qué certificado sirve un servidor,
  coincida o no con el dominio).
- **Solución**: `errorMessage()` ahora reconoce
  `ERR_TLS_CERT_ALTNAME_INVALID`, `CERT_HAS_EXPIRED`,
  `DEPTH_ZERO_SELF_SIGNED_CERT`/`SELF_SIGNED_CERT_IN_CHAIN`,
  `UNABLE_TO_VERIFY_LEAF_SIGNATURE` y `CERT_NOT_YET_VALID`, devolviendo un
  mensaje específico para cada uno en vez del genérico — cambio aditivo,
  no afecta ningún caso que ya funcionaba.
- **Verificación**: `/headers/presidencia.gob.ec` ahora devuelve
  `{"error":"El certificado TLS no cubre este dominio exacto"}`. Cubierto
  por `test/domainChecks.live.smoke.test.js`.

#### 12. "SMTPUTF8" con 2+ registros MX — mismo problema de fondo del fix anterior, en un caso no cubierto — 2026-09-09

- **Problema**: `/smtputf8/presidencia.gob.ec` tardaba **30.2 segundos**.
- **Causa**: ⏱️ **ineficiencia propia (no rompía el resultado)** —
  `presidencia.gob.ec` tiene 2 registros MX (una pasarela de Trend Micro +
  `webmail.presidencia.gob.ec`), y `handleSmtpUtf8` los recorría **en
  secuencia** con un `for...of`. El fix de la primera ronda (punto 3)
  paralelizó los 2 *puertos* (25/587) dentro de la consulta a un mismo
  servidor, pero no tocó el bucle que recorre *registros MX distintos* —
  `isoc.org.ec` solo tiene 1 MX, así que ese caso nunca se había
  ejercitado hasta probar un dominio con más de uno.
- **Solución**: `handleSmtpUtf8` ahora recorre los registros MX también
  **en paralelo** (`Promise.all` sobre `mx.map(...)`), mismo principio ya
  aplicado a los puertos.
- **Verificación**: `presidencia.gob.ec` bajó de 30.2s a ~15.1s (2 MX en
  paralelo, cada uno con ambos puertos también en paralelo). Regresión
  confirmada: `isoc.org.ec` (1 MX) sigue en ~15s con el mismo resultado
  correcto (`"no"`) de antes. Cubierto por
  `test/domainChecks.live.smoke.test.js`.

**Descartado — no reproducible**: `tlsciphers` devolvió `suites:[]`
(vacío) una vez contra `presidencia.gob.ec`, pero 2 reintentos inmediatos
después funcionaron perfecto — probablemente interferencia de una ráfaga
de ~20 solicitudes seguidas contra un servidor modesto (no detrás de un
CDN grande). Mismo patrón se repitió con `archive/isoc.org.ec` al correr
`test/domainChecks.live.smoke.test.js` completo (falló una vez, pasó al
repetir en aislado y al re-correr el script completo) — Wayback Machine
es conocida por ser ocasionalmente lenta/inestable en su capa gratuita.
Ninguno de los dos se trató como bug: no reproducible tras repetición
inmediata es la señal de descarte usada en toda esta sección.

### Validación cruzada con herramientas independientes — quinta ronda (2026-09-10)

A pedido explícito: se amplió el set de dominios de prueba más allá de
Ecuador, con un criterio deliberado (no aleatorio) por dominio — el
detalle completo de por qué se eligió cada uno, qué se verificó de forma
independiente, y el resultado (incluyendo los "sin novedades") vive en
**`docs/GUIA_PRUEBAS_VALIDACION.md`**, un registro nuevo separado de este
archivo — este archivo (`arquitectura.md`) sigue documentando el detalle
técnico de los fixes de código; `GUIA_PRUEBAS_VALIDACION.md` documenta el
registro histórico por dominio probado. 8 dominios: `lacnic.net`,
`gob.mx`, `cloudflare.com` (contraste normal), `expired.badssl.com`,
`self-signed.badssl.com`, `wrong.host.badssl.com` (validación directa del
fix de certificados de la ronda 4), `dnssec-failed.org` (validación del
motor DNSSEC detectando fallas), `neverssl.com` (caso límite de HTTPS no
funcional a propósito). Solo 1 bug de código nuevo.

#### 13. "MX" no distinguía "sin registros" de una falla real — 2026-09-10

- **Problema**: `/mx/gob.mx` devolvía `{"error":"Servicio no disponible"}`,
  aunque `gob.mx` genuinamente no tiene registros MX (declara
  `"v=spf1 -all"` — no envía correo — y DNS-over-HTTPS confirma NODATA,
  sin `Answer`, solo `Authority`/SOA).
- **Causa**: 🔴 **bug propio** — `handleMx` no tenía el manejo de
  `ENODATA`/`ENOTFOUND` que `handleCaa` y `handleTlsa` ya tenían para
  distinguir "el dominio no tiene registros de este tipo" (caso legítimo,
  no un error) de una falla real de red/DNS. Simple inconsistencia entre
  handlers del mismo archivo, no una falla nueva de ningún servicio
  externo.
- **Solución**: `handleMx` ahora captura `e.code === 'ENODATA' ||
  e.code === 'ENOTFOUND'` y devuelve `records: []`, mismo patrón que los
  otros dos handlers.
- **Verificación**: `/mx/gob.mx` → `{"records":[]}` (antes: error).
  Regresión confirmada: `/mx/isoc.org.ec` sigue trayendo su registro MX
  real sin cambios. Cubierto por `test/domainChecks.live.smoke.test.js`.

**Hallazgo real del sitio, no un bug nuestro (documentado para contexto,
sin acción de código)**: `/headers/gob.mx` devuelve
`"No se pudo verificar la cadena de certificados TLS"` — verificado de
forma independiente con `openssl s_client -verify_return_error`:
`verify error:num=20: unable to get local issuer certificate`. El
servidor de `gob.mx` no envía el certificado intermedio completo en el
handshake TLS — un cliente que no haga *AIA chasing* (como Node, y como
la mayoría de clientes no-navegador) no puede completar la cadena de
confianza, aunque un navegador (que sí hace AIA chasing) probablemente no
lo note. Es una configuración TLS real y mejorable del sitio, correctamente
detectada por el sistema — no algo que corregir en `server.js`. Sirve
además como confirmación positiva del mensaje `UNABLE_TO_VERIFY_LEAF_SIGNATURE`
agregado en la ronda 4 (punto 11), funcionando en un caso real encontrado
sin buscarlo a propósito (a diferencia de los dominios badssl.com, que
están construidos deliberadamente para fallar).

**Anomalía de infraestructura, no de código**: `/serverstatus/neverssl.com`
y `/headers/neverssl.com` devolvían `502 Bad Gateway` — pero **servido por
Cloudflare** (el Tunnel de acceso público a `mediciones.isoc.org.ec`, ver
`CLAUDE.md` § despliegue), no por nuestro servidor. Aislado accediendo
directo a `server1:8700` vía Tailscale (sin pasar por el Tunnel): mismo
endpoint respondió `200 OK` correctamente. No se tocó código — queda
anotado en `docs/GUIA_PRUEBAS_VALIDACION.md` por si se repite con otros
dominios, para no re-investigar desde cero.

### Pendientes revisados el 2026-09-10 (tras la quinta ronda)

Al cierre de la quinta ronda quedaron 5 pendientes anotados (ver
`docs/GUIA_PRUEBAS_VALIDACION.md` y el resumen de esa conversación). Se
revisaron con criterio de "qué aporta más valor técnico con el menor
riesgo" — 2 resueltos, 1 cerrado sin cambios (investigado, sin hallazgo),
2 quedan explícitamente abiertos.

#### 14. `safeWebFetch.adapter.js` — sospecha cerrada sin hallazgo — 2026-09-10

- **Sospecha**: desde el fix de RDAP (punto 1), quedó anotado que
  `resolveFinalWebTarget`/`fetchSafePage` (el adaptador HTML, usado por
  `headers`, `security.txt`, `redirect-chain`, `server-status`,
  `linkedpages`, `crawlrules`, etc.) podía tener el mismo problema de
  `User-Agent` ausente que se encontró y corrigió en `fetchJSON()`
  (usado por RDAP y Wayback Machine) — nunca se había verificado.
- **Investigación**: se probó `/headers/archive.org` (el sitio principal,
  no la API CDX que ya sabíamos sensible a este header) — mismo
  proveedor cuya API sí bloqueaba sin `User-Agent`, para maximizar la
  chance de encontrar el mismo patrón. Funcionó igual con y sin
  `User-Agent` (`curl -A ""` y `curl -A "Mozilla/..."`, ambos `200`).
  Sumado a que ninguno de los ~11 dominios probados en las 5 rondas
  anteriores (incluyendo sitios con WAF/CDN agresivos como Cloudflare)
  mostró nunca una falla atribuible a esto en los checks que usan este
  adaptador.
- **Conclusión**: sin evidencia de un problema real — se cierra la
  sospecha sin tocar código. No se descarta que aparezca con algún sitio
  específico en el futuro, pero no hay base hoy para un cambio preventivo
  sin caso real que lo justifique.

#### 15. Geolocalización de IP — fallback agregado — 2026-09-10

- **Problema**: `lookupIpMeta()` (usado por `serverlocation`, `serverinfo`,
  y el campo `geo` de `ipinfo`) dependía únicamente de `ipwho.is`, sin
  respaldo — verificado con una ráfaga de solicitudes que sí lo agota
  ("Rate limit exceeded").
- **Causa**: 🔴 **bug propio (punto único de falla, no una dependencia
  externa rota)** — la función nunca tuvo un segundo proveedor.
- **Solución**: se agregó `lookupIpMetaFallback()` usando **ip-api.com**,
  elegido deliberadamente por ser de una empresa/producto **distinto** al
  de `ipwho.is` — se descartó `ipwhois.app` (que se había investigado como
  candidato en la ronda de investigación previa) porque su respuesta
  referencia `cdn.ipwhois.io`, el mismo dominio que aparece en
  `ipwho.is` — indicio fuerte de que son el mismo backend/familia de
  producto y probablemente comparten cuota por IP de origen, lo que
  habría vuelto inútil el respaldo (el mismo rate limit tumbaría a
  ambos a la vez). `ip-api.com` es explícitamente de otro proveedor. Nota:
  su plan gratuito es solo HTTP (no HTTPS) — intencional, no un
  descuido: es una llamada servidor-a-servidor, sin navegador de por
  medio, así que no hay problema de contenido mixto.
- **Verificación**: `lookupIpMeta()` sigue funcionando igual cuando el
  primario responde (regresión confirmada: `/serverlocation/isoc.org.ec`,
  `/serverinfo/lacnic.net`); la normalización del formato de ip-api.com
  se probó por separado con datos reales, incluyendo el parseo del ASN
  (`"AS13335 Cloudflare, Inc."` → `13335` numérico). No se pudo forzar de
  forma determinista que el primario falle para probar el camino de
  fallback en un test automatizado — sigue como limitación conocida del
  test (ver `test/domainChecks.live.smoke.test.js`, que solo confirma la
  forma de la respuesta, no cuál proveedor contestó).

**Quedan explícitamente abiertos, sin cambios de código**:
- **"Quality" (PageSpeed) con cuota agotada**: requeriría gestionar una
  API key propia de Google Cloud — decisión de infraestructura/costo, no
  se toma unilateralmente.
- **`test/domainChecks.live.smoke.test.js` con lista de endpoints armada
  a mano**: seguiría beneficiándose de generarse automáticamente desde
  `server.js`, pendiente desde la segunda ronda.

## Testing

Dos categorías, separadas deliberadamente:

### CI-safe (`npm test`, sin red, deterministas)
- `test/datasetDomains.parity.test.js` — 11 casos de normalización/CSV vs
  valores capturados de una ejecución real de `parse_input()` de Python.
- `test/dnsValidation.classify.parity.test.js` — 14 casos de
  `classifyAnswers`/`reviewSubtype` vs Python real.
- `test/resultsPackage.integrity.test.js` — 4 casos (control + A/B/C) que
  ejercitan deliberadamente la salvaguarda de integridad con datos
  fabricados a mano (sin tocar Normalización/DNS reales).
- `test/contentStore.crud.test.js`, `test/adminAuth.session.test.js`,
  `test/content.publicVisibility.test.js` — CRUD de contenido editorial,
  sesión/rate-limit del panel admin, visibilidad público/admin extremo a
  extremo.
- `test/medicionesBatchReport.exporter.test.js` — Markdown/JSON del reporte
  de "Análisis comparativo": frontmatter, envoltura `::: landscape :::` con
  >6 checks seleccionados, sección "Cómo leer este reporte" (símbolos +
  glosario + limitaciones) siempre presente con texto fijo, truncado de
  detalle largo, y — el caso más importante — que **ninguna** sección ni
  frase de análisis del dataset (Resumen comparativo, Hallazgos por
  categoría, lenguaje evaluativo) reaparezca en ningún escenario, ni
  siquiera si el payload la trae (compatibilidad hacia atrás: se ignora).
- `test/medicionesBatchReport.routes.test.js` — rutas `POST /mediciones-batch/report`
  y `GET .../export`.
- `test/safeWebFetch.adapter.test.js` — resolución de redirecciones +
  protección SSRF de `safeWebFetch.adapter.js`.

### Con red real (manuales, no en `npm test`)
- `test/rawDns.live.smoke.test.js` — preflight, VALID/NXDOMAIN reales, CD=1
  contra `dnssec-failed.org`, timeout real.
- `test/dnsValidation.live.pythonCompare.js` — script reutilizable:
  `node test/dnsValidation.live.pythonCompare.js <domains.txt> <validacion_dns.csv de Python>`.
- `test/dnsDownloads.noDnsCalls.test.js` — instrumenta `dnsQuery` (spy sobre
  la función real, no mide tiempos) para demostrar que las descargas no
  generan ninguna consulta DNS nueva.
- `test/downloads.integrityGuard.test.js` — corre un job real, muta
  `integrity.passed` a `false` directamente en memoria (sin tocar
  producción) y confirma que las descargas quedan bloqueadas.
- `test/domainChecks.live.smoke.test.js` — RDAP (`/domaininfo`, 5 dominios
  reales incluyendo ccTLD con redirect y gTLD), SMTPUTF8 (`/smtputf8`,
  resultado + tiempo de respuesta), TLSA (`/tlsa`, dominio sin registros +
  `torproject.org` con TLSA real), Block Detection/Quad9 (`/block`,
  dominio normal + `blocked.test.on.quad9.net`, dominio oficial de test de
  Quad9), Linked Pages (`/linkedpages`, enlace relativo + enlace externo
  real), Whois vía fallback RDAP (`/whois/isoc.org.ec`, nombre + país
  reales), Archive (`/archive`, snapshots reales de Wayback Machine) y
  Quality (`/quality`, respuesta siempre con error explícito o scores
  reales, nunca ambigua), mensajes de error de certificado TLS
  (`/headers/presidencia.gob.ec`, certificado que no cubre el dominio
  exacto; más los 3 casos de badssl.com — expirado, autofirmado, hostname
  incorrecto), SMTPUTF8 con múltiples registros MX (`/smtputf8/
  presidencia.gob.ec`, 2 MX en paralelo, bajo ~20s) y MX sin registros
  (`/mx/gob.mx`, `records: []` sin error) contra `isoc.org.ec`,
  `presidencia.gob.ec`, `gob.mx`, el trío de badssl.com y otros dominios
  reales. Requiere el servidor local corriendo (`PORT=3500 node server.js`).

Para volver a capturar valores "verdad" de Python si el validador de
referencia cambia: `importlib.util.spec_from_file_location` + registrar en
`sys.modules` antes de `exec_module` (necesario por el uso de
`@dataclass` con `from __future__ import annotations`).

## Cómo desplegar

```bash
tar -cf - -C "/c/PROJECTS/MEDICIONES" index.html admin.html server.js logic routes test package.json package-lock.json scripts .env.example \
  | ssh server1 "tar -xf - -C ~/projects/MEDICIONES"
ssh server1 "cd ~/projects/MEDICIONES && docker compose up -d --build"
```

`docker-compose.yml` en `server1:~/projects/MEDICIONES/` — build local desde
`Dockerfile`, puerto `8700:8700`, `environment: PORT=8700`, volumen
`./data:/app/data` (persiste PSL cache + histórico Observatorio).

Verificar tras desplegar: `docker exec mediciones npm test`, y repetir los
tests de red real dentro del contenedor si se tocó algo del módulo DNS.

## Decisiones clave y por qué

- **Sin frameworks nuevos, nunca.** Ni Express, ni librería de ZIP, ni
  librería de test. Todo con módulos core de Node + lo que ya era
  dependencia (`dns-packet`).
- **Sin persistencia de jobs.** Aceptado explícitamente para esta fase; si en
  el futuro se necesita sobrevivir a un reinicio del proceso, habría que
  añadir persistencia a `dnsValidationJob.orchestrator.js` (hoy es un `Map`
  en memoria) — no implementado, no pedido todavía.
- **Concurrencia de dominios en paralelo (JS) vs. hilos (Python).** No
  cambia resultados (cada dominio es independiente), solo velocidad — se
  mantuvo intencionalmente para no alterar el modelo de concurrencia
  explícito de Python (`workers=20`) mientras se preserva el paralelismo real.
- **Archivos de descarga se generan una sola vez, no por request.** Garantiza
  que lo que el usuario ve en pantalla y lo que descarga sean *exactamente*
  los mismos bytes (verificado con hashes en tests).

## Análisis de los 144 `MEASUREMENT_ERROR` residuales y 3 correcciones — 2026-09-12

Tras el fix de coalescing (§ arriba) y la corrida completa de verificación,
quedaban 144 `MEASUREMENT_ERROR` sobre 1080 mediciones (20 dominios × 54
checks). Se analizó cada uno contra el log persistente de mediciones,
clasificando causa real (error del instrumento / condición válida del
dominio / dependencia externa fallida / resultado inconcluso / caso no
aplicable / timeout real), **sin corregir nada hasta tener el análisis
completo**. De esa clasificación se priorizaron 3 correcciones de bajo
riesgo por estar acotadas a causas ya confirmadas:

**1. `errorMessage()` no reconocía timeouts reales.** Los `Error('Timeout')`
lanzados por los timers de `fetchJSON`/`fetchText`/`fetchPage` (server.js),
`requestPage()` (`safeWebFetch.adapter.js`) y `queryQuad9` no llevaban
`.code`, así que caían al genérico "Servicio no disponible" — un timeout
real quedaba indistinguible de cualquier otro fallo. Se les agregó
`code: 'TIMEOUT'` en el punto donde se lanzan (5 sitios), y `errorMessage()`
gana una rama explícita para `'TIMEOUT'`/`'WEBFETCH_TOTAL_TIMEOUT'` →
`'Timeout'`. Además, `handleTls`/`handleSslChain` (conexión TLS cruda, no
pasan por `errorMessage()` en su timeout) tenían el timeout hardcodeado sin
`error_code` — se les agregó `error_code: 'TIMEOUT'` directamente.

**2. `handleRanking()` tenía un bug de nombre de campo, nunca detectado.**
Leía `data.rank`/`data.list_date`, pero la API real de Tranco devuelve
`{domain, ranks: [{date, rank}, ...]}` — confirmado con `curl` directo a
`https://tranco-list.eu/api/ranks/domain/nic.uy` (rank real ≈17000). El
check de ranking **nunca** devolvió un rank real para ningún dominio,
aunque estuviera efectivamente rankeado — el caso `isoc.org.ec` (§
"tercera ronda", arriba) era simultáneamente cierto (no está rankeado) y
enmascaraba este bug de raíz (tampoco lo hubiera mostrado si lo estuviera).
Se corrigió a leer `data.ranks[0]`. De paso se confirmó, también con
`curl`, que Tranco aplica rate limiting real (HTTP 429 observado en vivo
contra `mercadolibre.com.ar` durante las pruebas) — probable causa de
buena parte de los "Sin información" en corridas de lote. El `catch` ahora
setea `error_code: 'RANKING_UNAVAILABLE'` para distinguir "Tranco no
respondió" de "dominio no rankeado" (este último sigue sin error, `rank:
null` con 200 OK, sin tocar). **Fuera de alcance de esta corrección**:
retry/backoff ante 429 — no se implementó, no se pidió.

**3. Extensión de `WEBFETCH_NO_ADDRESS_RECORD` a handlers que no pasan por
`resolveFinalWebTarget`.** La Fase 3 (§ arriba) dejó explícitamente fuera
`handleTls`, `handleSslChain` y los handlers basados en `resolveFirstIp`/
`resolveAddresses` directo (`handleRpki`, `handleServerLocation`,
`handleServerInfo`) — todos con su propia resolución DNS, no comparten
`resolvePublicAddresses()`. Nueva función `domainHasNoAddressButIsRealZone(domain)`
(server.js, junto a `resolveAddresses`): equivalente server-side de la
lógica ya usada en `safeWebFetch.adapter.js`, vía
`Promise.all([dns.resolve4, dns.resolve6, dns.resolveNs])` — confirma zona
real delegada (NS resuelve) sin registros A/AAAA. Aplicada en los 5
handlers listados arriba: `handleRpki`/`handleServerLocation`/
`handleServerInfo` en su rama `if (!ip)`/`if (!ips.length)`, y
`handleTls`/`handleSslChain` en su `socket.on('error', ...)` cuando
`e.code === 'ENOTFOUND'`.

**Verificación**: `node --check` en ambos archivos tocados, `npm test` OK
completo. Contra servidor local: `ranking/nic.uy` → rank real (17261,
antes `null`); `ranking/mercadolibre.com.ar` → `error_code:
'RANKING_UNAVAILABLE'` (antes indistinguible de cualquier otro fallo);
`rpki`/`serverlocation`/`serverinfo`/`tlsinfo`/`sslchain` contra `gob.ec` →
los 5 devuelven `error_code: 'WEBFETCH_NO_ADDRESS_RECORD'` (antes "Sin
dirección IP"/"Sin direcciones IP" genérico, sin `error_code`).

**Explícitamente no tocado en esta corrección** (identificado en el
análisis pero no priorizado): `handleArchive` (Wayback Machine) sigue sin
`error_code` en su timeout; `classifyDataError()` (index.html) no gana
casos nuevos para `TIMEOUT`/`RANKING_UNAVAILABLE` — ambos deben seguir
clasificando como `MEASUREMENT_ERROR`, que es correcto (no son hallazgos
del dominio, son fallos del instrumento o de un tercero).

## `fetchWebsite()` exigía 2xx exacto y descartaba el error real por intento — 2026-09-12

Del análisis de los 42 `MEASUREMENT_ERROR` "sin causa clara" (mismo lote
de 20×54) surgió una causa raíz única para 35 de los 42: `firewall`,
`cookies`, `socialtags`, `sitefeatures` y `linkedpages` comparten una sola
llamada real a `fetchWebsite()` (gracias al coalescing) — los 5 heredaban
el mismo resultado, siempre "Servicio no disponible" sin `error_code`,
para 7 dominios distintos, cada uno por una razón real diferente.

**Causa**: `fetchWebsite()` (server.js) es una implementación de fetch
independiente de `handleHeaders`/`resolveFinalWebTarget`, con dos
defectos propios:

1. Exigía `statusCode` 2xx exacto para aceptar el resultado — un 401/403
   (challenge de WAF, bloqueo de bot, auth-gate) se descartaba aunque la
   petición hubiera funcionado perfectamente. Confirmado en vivo:
   `tiendainglesa.com.uy` (403 Cloudflare, challenge) y `copaair.com` (401
   DataDome) tenían respuesta real y útil que se perdía.
2. `catch (e) {}` silencioso por cada intento (https/http) — descartaba el
   error real (`TIMEOUT`, `WEBFETCH_NO_ADDRESS_RECORD`,
   `UNABLE_TO_VERIFY_LEAF_SIGNATURE`) y, si ambos intentos fallaban,
   lanzaba `new Error('Servicio no disponible')` sin `.code`.

**Corrección**: `fetchWebsite()` ya no decide qué status code es
"éxito" — acepta cualquier respuesta HTTP real (2xx/3xx/4xx/5xx) como
medición completada y devuelve `statusCode`/`headers`/`body` tal cual;
cada handler interpreta el significado (igual que ya hacía
`handleHeaders`). Solo un fallo real de transporte (timeout, DNS,
conexión rechazada, TLS) amerita reintentar con el otro esquema
(https→http); si ambos fallan de verdad, se propaga el `.code` del
**último** error real en vez de un genérico sin código. Aceptar un 4xx/5xx
como "medición completada" **no** implica marcarlo como PASS — eso sigue
siendo criterio de cada handler/del cliente, sin cambios.

**Handlers afectados** (sin cambios propios, ya consumían `headers`/`body`
sin asumir 2xx): `handleCookies`, `handleSiteFeatures`, `handleTechStack`,
`handleLinkedPages`, `handleSocialTags`, `handleFirewall`,
`handleHttpSecurity`.

## `handleArchive()` sin `error_code` — 2026-09-12

Único handler de este bloque que aún no propagaba `e.code` en su `catch`.
Mismo patrón de una línea que el resto del código (`error_code: e &&
e.code`), sin tocar retry/backoff ni la lógica de consulta a
`web.archive.org/cdx`.

## RDAP: `fetchRdap()`/`handleDomainInfo()` confundían "sin RDAP" con "no se pudo consultar RDAP" — 2026-09-12

**Causa**: `fetchRdap()` hacía `JSON.parse(resolved.response.body)` sin
revisar el `statusCode` de la respuesta. Verificado en vivo:
`rdap.org/domain/{dominio}` responde con un cuerpo JSON válido **incluso
en sus propios 404** (`{"errorCode":404,"title":"No RDAP service is
available..."}`) — el `JSON.parse` nunca fallaba, así que el código viejo
leía `data.events`/`data.entities`/`data.status` como `undefined` y
devolvía silenciosamente un resultado "vacío pero exitoso"
(`registry:null, status:[], creation:null, expiration:null`), sin
distinguir eso de un timeout real o de `rdap.org` caído.

**Corrección**: `fetchRdap()` ahora revisa el resultado en 3 pasos y
lanza un código explícito en cada uno:

| Código | Cuándo |
|---|---|
| `RDAP_TIMEOUT` | la consulta a `rdap.org` lanza `TIMEOUT`/`WEBFETCH_TOTAL_TIMEOUT` |
| `RDAP_UNAVAILABLE` | la consulta lanza cualquier otro error de transporte, o responde con un status fuera de 2xx (y no es 404) |
| `RDAP_NOT_FOUND` | responde 404 — confirmado en vivo que `rdap.org` usa 404 tanto para un dominio inexistente como para un TLD sin bootstrap RDAP registrado (ej. `.uy`, `.pa`, `.edu` — probado con `nic.uy`, `nic.pa`, `mit.edu`: los 3 dan 404 de forma **consistente y determinista**, no es un fallo transitorio) |
| `RDAP_INVALID_RESPONSE` | responde 2xx pero el cuerpo no es JSON parseable |

`handleWhois` (que comparte `fetchRdap()`) no se tocó — su `catch(e){}`
ya ignoraba el error por completo, así que el cambio no le afecta.

**Tests** (mockeados, mismo patrón que `test/safeWebFetch.adapter.test.js`
— `resolveFinalWebTarget` con `lookup`/`requestImpl` inyectados, sin red
real): HTTP 200/301→200/403/404/405 aceptados como medición completada
por el mecanismo que usa `fetchWebsite()`; `ECONNREFUSED`/`TIMEOUT` sí
propagan con su `.code` real; RDAP 404→`RDAP_NOT_FOUND`, RDAP
500→`RDAP_UNAVAILABLE`, timeout de red→`RDAP_TIMEOUT` (no
`RDAP_NOT_FOUND`), RDAP 200 con cuerpo no-JSON→`RDAP_INVALID_RESPONSE`.
11/11 casos correctos.

**Verificación end-to-end** (servidor local + corrida real de 20×54):

| Estado | Antes de esta corrección (tras timeouts/ranking/webfetch) | Ahora |
|---|---|---|
| MEASUREMENT_ERROR | 120 | **101** |

De los 39 casos con causa ya identificada (35 de `fetchWebsite()` + 4 de
`archive`): **25/35 resueltos por el fix de `fetchWebsite()`** (pasaron a
PASS/INFO/FAIL/NOT_APPLICABLE reales), **4/4 resueltos por el fix de
`archive`**. Los 10 restantes de `fetchWebsite()` (`nic.pa` × 5,
`usa.gov` × 5) siguen en `MEASUREMENT_ERROR` — correctamente, ahora con
`error_code: TIMEOUT` visible: son timeouts reales de esos dos dominios,
no un problema del código.

`domaininfo` pasó de 0-3 errores (variable, enmascarado) a exponer
consistentemente `RDAP_NOT_FOUND` para dominios `.uy`/`.pa`/`.edu` (7
casos, confirmado determinista contra 10 dominios reprobados en
aislado) y `RDAP_UNAVAILABLE` para 2-3 casos de flakiness real y
transitoria de `rdap.org` bajo ráfaga de peticiones (confirmado: los
mismos dominios que fallaron en el lote completo, al reprobarse aislados
segundos después, respondieron con datos reales). **Efecto secundario
esperado, no un bug**: como `classifyDataError()` (cliente) no tiene un
caso especial para `RDAP_NOT_FOUND`, estos 7 casos caen en
`MEASUREMENT_ERROR` en vez de algo más preciso como `NOT_APPLICABLE` —
antes esos mismos 7 casos ni siquiera aparecían como error (se leían como
`INFO "Sin datos"`, un falso positivo silencioso). Corregir esa
clasificación queda fuera del alcance de esta corrección, no se tocó
`classifyDataError()` según lo indicado.

**Sin regresiones de código**: se revisó cada caso que cambió de
"no-error" a `MEASUREMENT_ERROR` entre el estado previo a ambas rondas de
fixes y ahora. Los únicos cambios de ese tipo son (a) los 7 `domaininfo`
`RDAP_NOT_FOUND` explicados arriba (comportamiento nuevo intencional), (b)
2-3 `domaininfo` `RDAP_UNAVAILABLE` por flakiness real de `rdap.org` (no
causado por este cambio), y (c) `archive/amazon.com` con timeout real
contra `web.archive.org` en esta corrida puntual (el código de
`handleArchive` solo ganó `error_code`, no se tocó su timeout ni su
lógica — variación normal de un servicio externo entre dos corridas en
momentos distintos, no atribuible al fix).

## Clasificación semántica de MEASUREMENT_ERROR: dependencia externa vs. dominio — 2026-09-12

**Principio**: un fallo contra un TERCERO que solo aporta contexto sobre
el dominio (Tranco, rdap.org, `web.archive.org`, PageSpeed) no es un
hallazgo sobre el dominio medido — mezclarlo con "no pudimos medir el
dominio" (timeout/refuse contra el dominio mismo) infla
`MEASUREMENT_ERROR` de forma engañosa. Del análisis de los 101
`MEASUREMENT_ERROR` residuales se separaron ambos casos y se aplicaron
los cambios mínimos correspondientes.

**`classifyDataError()` (index.html)**, 3 códigos ya existentes más 5
nuevos, agrupados en dos sets:
```js
const EXTERNAL_UNAVAILABLE_CODES = new Set([
  'RDAP_UNAVAILABLE', 'RANKING_UNAVAILABLE', 'PAGESPEED_QUOTA_EXCEEDED',
  'ARCHIVE_TIMEOUT', 'ARCHIVE_UNAVAILABLE'
]); // -> INCONCLUSIVE
const NOT_APPLICABLE_CODES = new Set([
  'WEBFETCH_NO_ADDRESS_RECORD', 'RDAP_NOT_FOUND', 'NO_MX_RECORDS'
]); // -> NOT_APPLICABLE
```

**`handleQuality()`**: `error_code: 'PAGESPEED_QUOTA_EXCEEDED'` en las dos
ramas de cuota agotada (el cooldown de 10 min y el `RESOURCE_EXHAUSTED`
recién detectado) — otros errores de PageSpeed no relacionados con cuota
quedan sin código específico, sin cambios.

**`handleArchive()`**: `ARCHIVE_TIMEOUT` (timeout) / `ARCHIVE_UNAVAILABLE`
(cualquier otro fallo de transporte o respuesta no-JSON) — **se descartó
`ARCHIVE_NO_DATA`**: verificado en vivo que la API CDX de Wayback Machine
responde 200 con `[]` (JSON válido) cuando el dominio no tiene snapshots,
que el código YA trata como éxito (`entries: []`) sin lanzar excepción —
no existe una ruta de fallo real que ese código capturaría.

**`handleSmtpUtf8()`**: `NO_MX_RECORDS` cuando `dns.resolveMx()` da
`ENODATA` (dominio real, sin MX) — se distingue explícitamente de
`ENOTFOUND` (dominio que no resuelve en absoluto, condición más grave,
sin cambios). Además, **bug real corregido en `index.html`**: el case
`'smtputf8'` marcaba `FAIL` ante CUALQUIER resultado que no fuera
`'supports'` en todos los MX, incluyendo `'timeout'`/`'connection-error'`
— un timeout no confirma que el servidor no soporte SMTPUTF8, solo que no
se pudo comprobar. Ahora: `FAIL` solo si todos los MX respondieron de
forma definitiva (`'supports'`/`'no'`); `INCONCLUSIVE` si alguno no se
pudo medir.

**Tests**: 7 casos de `classifyDataError()` + 5 de la lógica de
`smtputf8` (incl. mezcla supports+no, mezcla no+timeout, solo
connection-error), todos vía mocks/jsdom sin depender de que los
servicios externos fallen en el momento exacto de la prueba. 11/11 OK.

**Verificación end-to-end** (corrida real 20×54):

| Estado | Antes | Ahora |
|---|---|---|
| PASS | 573 | 537 |
| FAIL | 254 | 240 |
| INFO | 83 | 83 |
| INCONCLUSIVE | 29 | 99 |
| NOT_APPLICABLE | 40 | 51 |
| MEASUREMENT_ERROR | 101 | 70 |

De los 101 `MEASUREMENT_ERROR` originales: **51 reclasificados** (20
`PAGESPEED_QUOTA_EXCEEDED`→INCONCLUSIVE, 10 `RANKING_UNAVAILABLE`→INCONCLUSIVE,
7 `RDAP_NOT_FOUND`→NOT_APPLICABLE, 4 `NO_MX_RECORDS`→NOT_APPLICABLE, 3
`ARCHIVE_TIMEOUT`→INCONCLUSIVE, 3 `RDAP_UNAVAILABLE`→INCONCLUSIVE, 2
`ARCHIVE_UNAVAILABLE`→INCONCLUSIVE, 2 `ranking` con datos reales esta vez
→PASS), **50 se mantienen `MEASUREMENT_ERROR`** correctamente (44
`TIMEOUT` + 4 `ETIMEDOUT` + 1 `ECONNREFUSED` + 1 `HPE_CLOSED_CONNECTION`,
todos contra el dominio medido directamente, no contra un tercero).
Además, 14 `smtputf8` que antes eran `FAIL` (mezclando timeouts con "no
soporta") ahora son `INCONCLUSIVE` correctamente.

**Verificación de que ningún fallo real del dominio quedó oculto**: se
revisaron los 45 casos con `error_code` `TIMEOUT`/`ECONNREFUSED`/
`ETIMEDOUT` contra el dominio mismo (excluyendo `quality`/`ranking`/
`domaininfo`/`archive`, que son deliberadamente dependencias externas) —
los 45 siguen visibles como `MEASUREMENT_ERROR` o `FAIL`, ninguno se
"blanqueó".

**Hallazgo nuevo, NO corregido en esta ronda** (fuera del alcance de los
4 cambios autorizados, código no tocado): 20 casos nuevos de
`MEASUREMENT_ERROR` en `asn`/`serverlocation`/`serverinfo` (7+7+6, en
`nic.uy`/`nic.us`/`uba.ar`/`presidencia.gob.pa`/`udelar.edu.uy`/
`usa.gov`/`utp.ac.pa`) que antes pasaban. Investigado con el log de
mediciones: es `lookupIpMeta()` (proveedor de geolocalización de IP,
primario + fallback, sin relación con RDAP/Tranco/Archive/PageSpeed)
golpeando su propio rate limit — el propio código ya documenta este
riesgo ("Rate limit exceeded" en su comentario). No se disparó en la
corrida anterior porque menos checks completaban trabajo real en la
misma ventana de tiempo; al corregir los otros 4 puntos, más checks
llegan a ejecutar la consulta de geolocalización dentro de la misma
ventana y superan el límite del proveedor. Mismo patrón que Tranco/RDAP/
Archive/PageSpeed — candidato claro para una futura ronda con un código
propio (ej. `IPMETA_UNAVAILABLE`), no implementado ahora.

## `lookupIpMeta()`: sin caché ni coalescing, duplicación confirmada asn/serverinfo — 2026-09-13

**Causa raíz** (análisis previo, confirmado con evidencia en vivo): `lookupIpMeta()`
no tenía ninguna caché ni deduplicación — 4 handlers independientes
(`handleServerInfo`, `handleServerLocation`, `handleIpInfo`, `handleIpv4`)
resuelven la IP del dominio cada uno por su cuenta y llaman al proveedor
externo por separado, incluso cuando terminan consultando la MISMA IP.
Además, **`asn` y `serverinfo` (dos checks distintos del cliente) llaman
literalmente al mismo endpoint** (`/serverinfo/:domain`) — confirmado en
código (`fetchWithTimeout(`${API_BASE}/serverinfo/${ascii}`)` en ambos
`case`). Hasta 5 llamadas reales por dominio para la misma IP. Verificado
en vivo: `ipwho.is` (primario) devuelve 429 "Rate limit exceeded" con
`Retry-After: 80784` (~22h, cuota larga ya agotada); `ip-api.com`
(fallback) sano pero con límite real de 45 req/min (confirmado vía
cabeceras `X-Rl`/`X-Ttl`) — la duplicación multiplicaba la carga sobre
ese fallback lo suficiente como para superar su ventana dentro de una
sola corrida.

**Corrección — caché + request coalescing, mismo patrón que `fetchWebsite()`**
(`server.js`, `lookupIpMeta()`):
```js
const IPMETA_CACHE_TTL_MS = 5 * 60 * 1000; // 5 min
const ipMetaCache = new Map();   // resultado resuelto por IP
const ipMetaPending = new Map(); // promesa en curso por IP
```
Primera llamada para una IP: cache miss → se crea la promesa, se guarda
en `ipMetaPending` **antes** de esperar la consulta externa, se ejecuta
la consulta, se guarda el resultado en `ipMetaCache` solo si tuvo éxito
(un fallo nunca queda cacheado — la siguiente llamada reintenta limpio),
y se borra de `ipMetaPending` en `finally`. Llamadas concurrentes
posteriores para la misma IP reutilizan exactamente la misma promesa
(`pending_reused`); una llamada posterior dentro del TTL reutiliza el
resultado resuelto (`cache_hit`); una IP distinta siempre dispara su
propia consulta. TTL de 5 minutos — la geolocalización/ASN de una IP no
cambia dentro de una corrida ni de un día; el TTL es una constante única
(`IPMETA_CACHE_TTL_MS`) fácil de ajustar si hiciera falta. Sin
infraestructura nueva — reutiliza `cacheGet`/`cacheSet` (ya usadas por
`htmlCache`/`headerCache`/`tlsCache`) y `recordCacheEvent` (ya usada por
`fetchWebsite()`, mismo campo `domain` del log ahora contiene la IP en
vez de un dominio — mismo esquema, distinta clave).

**Clasificación del motivo real de fallo** — nueva
`classifyIpMetaFailure(e)`: ninguno de los dos proveedores da un HTTP
status fiable (`fetchJSON` no revisa `statusCode`), así que se lee el
mensaje del cuerpo (mismo criterio que `isPageSpeedQuotaError()`):
`/rate limit/i` → `RATE_LIMITED`; `/private range|invalid query|reserved
range/i` → `NOT_FOUND` (verificado en vivo con `ip-api.com` contra una IP
privada real); `e.code === 'TIMEOUT'` → `TIMEOUT` (ya viene confiable, sin
parseo de texto). Si el primario falla por `NOT_FOUND`, **no se llama al
fallback** — una IP privada/inválida lo es para cualquier proveedor, no
tiene sentido gastar su cupo. Tres códigos nuevos:

| Código | Cuándo | `classifyDataError()` |
|---|---|---|
| `IPMETA_RATE_LIMITED` | 429/"rate limit" en primario y/o fallback | `INCONCLUSIVE` |
| `IPMETA_UNAVAILABLE` | cualquier otro fallo de transporte en ambos proveedores | `INCONCLUSIVE` |
| `IPMETA_NOT_FOUND` | el proveedor respondió con certeza que no tiene datos para esa IP | `INFO` — a diferencia de `NOT_APPLICABLE` (reservado para "este check no aplica a este dominio"), acá el check SÍ aplica, solo esta IP puntual no tiene metadata; el proveedor respondió de forma definitiva, no es una medición fallida |

**Handlers**: `handleServerInfo`/`handleServerLocation` ya propagaban
`error_code: e && e.code` en su `catch` de siempre — no necesitaron
cambios, heredan los 3 códigos nuevos automáticamente. `handleIpInfo`/
`handleIpv4` tragaban el error por IP en silencio (`catch (e) {}`) — se
agregó un campo **aditivo** `geoErrors: [{ip, error, error_code}]` junto
a los campos existentes (`geo`/`geos`, sin tocar), visible en la
respuesta sin cambiar el contrato que el frontend ya consume.

**Duplicación `asn`/`serverinfo`**: no se tocó el frontend — la caché del
lado servidor ya garantiza que la segunda llamada idéntica (venga de
`asn` o de `serverinfo`, mismo endpoint) golpea `pending_reused`/
`cache_hit` y no genera una segunda consulta externa. Verificado en vivo:
en los 20 dominios de la corrida real, `asn` y `serverinfo` **coinciden
al 100%** (antes podían discrepar — ver hallazgo de la ronda anterior con
`nic.uy`/`nic.us`/`tiendainglesa.com.uy`).

**Tests**: A (4 llamadas concurrentes, misma IP) → 1 `new_fetch` + resto
`cache_hit`/`pending_reused`, 0 llamadas externas duplicadas. B (llamada
posterior dentro del TTL) → `cache_hit`, 0 llamadas nuevas. C (2 IPs
distintas simultáneas) → 1 `new_fetch` cada una, sin cruce. D (primario
en 429 real ahora mismo) → fallback cubre, datos reales sin error. E/E2/F/F2
(mockeados, mismo patrón que rondas anteriores para condiciones no
reproducibles en vivo de forma determinista): ambos proveedores caídos →
`IPMETA_UNAVAILABLE`; ambos rate-limited → `IPMETA_RATE_LIMITED` (no
`UNAVAILABLE`); IP privada → `IPMETA_NOT_FOUND` sin llamar al fallback.
G (asn+serverlocation+serverinfo+ipinfo repetidos, mismo dominio) → 1
`new_fetch`, resto `pending_reused`. **11/11 OK**. `npm test` completo OK.

**Verificación end-to-end** (corrida real 20×54):

| Check | MEASUREMENT_ERROR antes | después |
|---|---|---|
| `asn` | 7 | **0** |
| `serverlocation` | 7 | **0** |
| `serverinfo` | 6 | **0** |
| `ipinfo` | 0 | 0 (sin cambio, ya no fallaba a nivel de check) |
| `ipv4` | 0 | 0 (sin cambio) |

Eventos `lookupIpMeta()` en la corrida: 133 totales — **38 `new_fetch`**
(consulta real disparada), **57 `pending_reused`**, **38 `cache_hit`** —
para **44 IPs únicas** (6 de ellas ya estaban tibias en caché por la
batería de tests A-G corrida minutos antes en el mismo proceso, dentro
del TTL de 5 min — confirma el TTL funcionando correctamente incluso
entre corridas separadas, no es un error). De un techo estimado de ~100
llamadas potenciales (análisis de la ronda anterior) a 38 intentos reales
— muy cerca del número de IPs únicas, tal como se buscaba. `MEASUREMENT_ERROR`
total de la corrida: 70 → 50 (los 20 que este fix corrige, ninguna otra
categoría cambió en cantidad — las diferencias en `INCONCLUSIVE`/`PASS`
del resto de checks son variación normal de Tranco/RDAP/PageSpeed/Archive
entre corridas, ya documentada, no atribuible a este cambio).

## Motor DNSSEC (`realDns.adapter.js`): retry único + caché/coalescing por consulta — 2026-09-13

**Contexto**: análisis previo (solo lectura, sin cambios) no logró
reproducir los timeouts DNSKEY reportados en ninguna de 3 condiciones
(dominio individual, 20 dominios concurrentes vía `/dnssec-analysis`,
corrida real completa de 20×54) — la red DNS real, verificada con `dig`
UDP/TCP desde `server1`, resuelve rápido y limpio en todos los niveles de
la cadena para los dominios probados. Se encontró sí una fragilidad
arquitectónica real: cero reintentos + "cualquier fallo aislado en
cualquiera de las 6-9 consultas por dominio invalida el dominio entero a
`indeterminate`" + duplicación de consultas TLD/zona intermedia entre
dominios del mismo lote sin ningún caché. Esta corrección ataca
exclusivamente esos dos últimos puntos (retry + caché), sin tocar
timeout, clasificación DNSSEC, ni agregar un segundo proveedor DoH.

**Confirmación previa a implementar — qué es transporte fallido vs.
respuesta DNS válida**: `fetchJson()` (la función que hace el
`https.get()` a `dns.google`) **solo** rechaza su promesa ante timeout,
error de red o un cuerpo no parseable como JSON. Una respuesta DNS real
— NOERROR/NODATA, NXDOMAIN, SERVFAIL — llega **siempre** como HTTP 200
con un campo `Status` distinto (0/2/3) dentro del cuerpo JSON, nunca como
excepción; `normalizeAnswer()` la interpreta después, ya fuera del
`catch`. Por construcción, entonces, cualquier excepción capturada en
`queryGoogleDoh()` es un fallo de transporte y nunca una respuesta DNS —
no hizo falta una lista de códigos a excluir: SERVFAIL/NXDOMAIN/ausencia
de DS/DNSKEY nunca llegan a ese `catch`, así que nunca disparan retry.

**`logic/adapters/dns/realDns.adapter.js`** — único archivo modificado:

1. **Retry único** (`fetchJsonWithRetry`): si `fetchJson()` lanza una
   excepción, se espera un backoff corto y fijo (`RETRY_BACKOFF_MS =
   200`) y se reintenta exactamente una vez más. Si el segundo intento
   también falla, se propaga tal cual (mismo comportamiento de
   `mapDohError()`/clasificación de ahí en adelante, sin cambios — un
   dominio con ambos intentos fallidos en cualquiera de sus consultas
   sigue cayendo en `indeterminate`, sin ocultar el fallo). Peor caso por
   consulta: ~2× `QUERY_TIMEOUT_MS` (5000ms sin tocar) + 200ms de
   backoff — acotado, no descontrolado, y como las consultas de un mismo
   dominio corren en paralelo (`Promise.all`, sin cambios en
   `dnssec.service.js`), el peor caso por DOMINIO sigue siendo ese mismo
   techo, no la suma de sus 6-9 consultas.
2. **Caché + request coalescing** (`queryGoogleDoh`): mismo patrón ya
   validado en `fetchWebsite()`/`lookupIpMeta()` — clave
   `` `${name}|${type}` `` (ej. `com|DNSKEY`, `amazon.com|DNSKEY`,
   `com|DS`), promesa guardada en `dohPending` **antes** de esperar la
   consulta (coalescing real para llamadas concurrentes), resultado
   cacheado en `dohCache` con TTL de 5 min (`DOH_CACHE_TTL_MS`) **solo si
   la consulta tuvo éxito** — un fallo, incluso tras el reintento, nunca
   queda cacheado. `queryDnskey`/`queryDs`/`queryNameExistence` no
   cambiaron ni una línea — siguen llamando a `queryGoogleDoh(name,
   type)` igual que antes, el cambio es enteramente interno a esa
   función.
3. **Instrumentación mínima** (`getDohStats()`/`resetDohStats()`,
   exportadas): contadores en memoria (`totalCalls`, `uniqueQueries`,
   `cacheHits`, `pendingReused`, `retries`, `retriesRecovered`,
   `retriesFailed`) — solo para verificación, no se expone ningún
   endpoint HTTP nuevo ni se tocó `server.js`/`dnssec.service.js`/
   `dnssec.rules.js`/`dnssec.processor.js`.

**Tests** (contra el módulo real, interceptando `https.get` con el mismo
flujo de eventos que usa Node — no una réplica de lógica): A (éxito al
primer intento, 1 request) — B (timeout luego éxito, recupera) — C
(ambos timeout, `query_status: 'timeout'`, sigue siendo el camino a
`indeterminate`) — D (2 llamadas concurrentes idénticas, 1 request real +
1 `pending_reused`) — E (misma consulta después de resuelta, `cache_hit`,
0 requests nuevos) — F (`com|DNSKEY` vs `amazon.com|DNSKEY`,
independientes, sin cruce) — G1/G2/G3 (NODATA/NXDOMAIN/SERVFAIL — sin
retry, confirmado) — extra (JSON inválido sí es transporte fallido, sí
reintenta). **10/10 OK**. `npm test` completo OK.

**Corrida real** (20 dominios, llamando a `getDnssecAnalysis()` +
`processDnssecAnalysis()` directamente en el mismo proceso para leer
`getDohStats()` — funcionalmente equivalente a 20 llamadas concurrentes a
`/dnssec-analysis`, mismo código exacto que usa `server.js`):

| Métrica | Valor |
|---|---|
| Llamadas totales a `queryGoogleDoh()` | 134 |
| Consultas reales únicas (`uniqueQueries`) | **122** |
| `pendingReused` (ahorradas por coalescing) | **12** |
| `cacheHits` | 0 (esperado: las 20 corren simultáneas, sin ventana de tiempo entre ellas para que aplique TTL en vez de coalescing) |
| `retries` | 0 (red sana en el momento de la prueba — consistente con el análisis previo) |
| Tiempo total del lote | 1.4s |

**Clasificación final — idéntica a la corrida previa a este fix** (mismos
20 dominios, mismo código de reglas sin tocar): `not_implemented`: 11,
`ok`: 5, `blocked_at_tld`: 3, `blocked_at_parent`: 1, `indeterminate`: 0
— **confirmado bit a bit igual**, como exigía el alcance ("no cambies la
lógica de clasificación").

**¿Hay evidencia real que justifique un segundo proveedor DoH?** No, con
esta corrida. La red hacia `dns.google` estuvo sana (`retries: 0`) y el
único problema demostrable — la duplicación de consultas TLD entre
dominios del mismo lote — ya lo resuelve el caché/coalescing (12/134,
9%, evitadas). El retry solo se ejercitó en los tests mockeados, nunca
en la corrida real, porque no hubo ningún fallo de transporte que
disparara. Sin una reproducción real de una falla de `dns.google` no hay
base empírica para justificar la complejidad y el riesgo adicional de un
segundo proveedor — queda como mejora identificada pero no priorizada,
consistente con el análisis anterior.

## `malware`/URLhaus: falso negativo de seguridad — PASS sin haber consultado la fuente — 2026-09-13

**Hallazgo crítico** (auditoría de los `MEASUREMENT_ERROR` residuales):
`urlhaus-api.abuse.ch/v1/host/` exige autenticación (header `Auth-Key`,
esquema unificado de abuse.ch) — verificado en vivo:
```
curl -X POST -d "host=nic.ar" https://urlhaus-api.abuse.ch/v1/host/
→ HTTP 401 {"error": "Unauthorized"}
```
No existe ninguna variable `URLHAUS_AUTH_KEY` (ni en `.env.example` ni en
`server1:~/projects/MEDICIONES/.env`, confirmado) — **nunca estuvo
autenticado**. El código anterior usaba `fetchJSON()` (no revisa el
`statusCode` HTTP, solo parsea el body) y ese 401 es JSON válido
(`{"error":"Unauthorized"}`) — `data.urls` y `data.query_status` quedaban
`undefined`, y el cliente interpretaba eso como "Sin reportes" = **PASS**.
Confirmado en los 20 dominios de prueba: **19/20 mostraban PASS sin haber
consultado nada de verdad** (el 20º, `nic.ar`, mostraba error porque esa
vez la conexión se cortó en vez de llegar el 401 limpio — mismo problema
de fondo, solo que visible por casualidad de red).

**Segundo bug encontrado en la misma auditoría** (mismo mecanismo, no un
módulo aparte): aun con una respuesta real y autenticada, el cliente
interpretaba `query_status` al revés — `threat = data.threat &&
data.threat !== 'ok'`, cuando en la API real de URLhaus `query_status:
"ok"` significa "SÍ hay URLs asociadas" (amenaza) y `"no_results"`
significa limpio. Nunca se había ejercitado contra una respuesta real
porque el fetch jamás estuvo autenticado — quedaba latente. Corregido
como parte de este mismo fix, no un cambio aparte.

**Regla implementada, sin excepciones**: PASS solo si la fuente respondió
de forma válida y confirma "sin reportes"; FAIL solo si confirma reportes
reales; cualquier otra cosa — falta de credencial, 401/403, 429, 5xx,
timeout, red, JSON inválido, `query_status` no reconocible — **INCONCLUSIVE,
nunca PASS**.

**`server.js` — `handleMalware()` reescrito** (nueva `classifyUrlhausFailure(statusCode)`):
usa `fetchPage()` (ya existente, expone `statusCode`) en vez de `fetchJSON()`
(que lo descarta) — permite distinguir status HTTP antes de interpretar el
body. Soporte opcional para `URLHAUS_AUTH_KEY` (env var, documentada en
`.env.example`): si existe, se envía como header `Auth-Key`; si no, la
consulta se sigue intentando (como antes) pero el 401 resultante ahora se
clasifica correctamente en vez de leerse como éxito.

| Código | Cuándo |
|---|---|
| `MALWARE_AUTH_REQUIRED` | HTTP 401 o 403 |
| `MALWARE_RATE_LIMITED` | HTTP 429 |
| `MALWARE_TIMEOUT` | timeout de la consulta |
| `MALWARE_SOURCE_UNAVAILABLE` | 5xx, error de red, u otro status inesperado |
| `MALWARE_INVALID_RESPONSE` | JSON no parseable, o `query_status` fuera de `{"ok","no_results"}` |

**`index.html`**: los 5 códigos agregados a `EXTERNAL_UNAVAILABLE_CODES`
→ `INCONCLUSIVE` (mismo set que RDAP/Tranco/Archive/PageSpeed/IPMeta). El
`case 'malware'` ya no interpreta `query_status` — el servidor manda
`hasReports` (booleano, ya calculado a partir de `entries.length > 0`),
eliminando la ambigüedad del segundo bug.

**Tests**: A (sin reportes → PASS), B (reportado → FAIL), C/D (401/403 →
INCONCLUSIVE), E (429 → INCONCLUSIVE), F (timeout → INCONCLUSIVE), G (500
→ INCONCLUSIVE), H (JSON inválido → INCONCLUSIVE), I (sin API key,
comportamiento real actual → INCONCLUSIVE, confirmado que no se envía el
header `Auth-Key` si no hay variable configurada), + 2 extra (con key sí
se envía el header; `query_status` no reconocible → INCONCLUSIVE, no PASS
silencioso). **11/11 OK** (réplica literal de la lógica de `server.js` con
`fetchPage` inyectable — mismo patrón ya usado para RDAP/IPMeta, `server.js`
no es requerible como módulo). `npm test` completo OK.

**Corrida real** (20 dominios, servidor local, sin `URLHAUS_AUTH_KEY`
configurada — condición real de producción hoy): **20/20 → INCONCLUSIVE
(`MALWARE_AUTH_REQUIRED`)**, **0 PASS generados por ausencia de
respuesta**. Es el resultado correcto y esperado dado que no hay
credencial real disponible — antes de este fix, 19/20 mostraban un PASS
falso.

**Pendiente, fuera del alcance de este fix** (según lo indicado — "no
inventes otro proveedor"): registrar una cuenta gratuita en
`https://auth.abuse.ch/` y configurar `URLHAUS_AUTH_KEY` en
`server1:~/projects/MEDICIONES/.env` es lo único que falta para que el
check vuelva a producir PASS/FAIL reales — es una acción manual fuera del
alcance de este cambio de código, ya documentada en `.env.example`.

## ECONNREFUSED confirmado vs. HPE_CLOSED_CONNECTION ambiguo — códigos por handler, sin regla global — 2026-09-13

**Contexto**: de los `MEASUREMENT_ERROR` residuales, 5 `ECONNREFUSED`
(`copaair.com`, checks `tls`/`key`/`ocsp`/`sslchain`/`securitytxt`) y 1
`HPE_CLOSED_CONNECTION` (`corporacionfavorita.com`/`redirectchain`).
Verificado en vivo antes de tocar código: DNS de `copaair.com` correcto
(`204.74.99.103`), TCP a puerto 80 conecta, TCP a puerto 443 da
`Connection refused` (`errno=111`) confirmado con `bash /dev/tcp` **y**
`openssl s_client` (rechazo a nivel de socket, ni siquiera arranca el
handshake TLS) — `www.copaair.com` resuelve a una IP totalmente distinta
donde 443 sí funciona. Conclusión: rechazo real y determinista del
servicio objetivo, no un timeout, no un problema de conectividad local
(confirmado: la misma máquina conecta sin problema a `www.copaair.com:443`
segundos después).

**Decisión explícita: sin regla global `ECONNREFUSED → FAIL`.** `ECONNREFUSED`
se usa en otros módulos con semántica distinta (`handleOpenPorts` lo trata
como resultado normal — puerto cerrado es un dato, no un error; handlers
con fallback https→http, terceros como RDAP/Tranco, etc.). Se agregaron
**3 códigos propios**, uno por handler, asignados solo en la rama
`e.code === 'ECONNREFUSED'` de cada uno:

| Código | Handler | Checks del cliente que lo consumen |
|---|---|---|
| `TLS_CONNECTION_REFUSED` | `handleTls()` | `tls`, `key`, `ocsp` (mismo endpoint `/tlsinfo`, sin duplicar lógica) |
| `SSLCHAIN_CONNECTION_REFUSED` | `handleSslChain()` | `sslchain` |
| `SECURITYTXT_CONNECTION_REFUSED` | `handleSecurityTxt()` | `securitytxt` |

Los 3 → `FAIL` en `classifyDataError()` (nuevo set `CONNECTION_REFUSED_CODES`,
separado de `CERTIFICATE_ERROR_CODES` para no mezclar significados). El
`ECONNREFUSED` crudo (sin pasar por estos 3 handlers) sigue sin mapeo
propio — comportamiento sin cambios en cualquier otro lugar del código.

**`HPE_CLOSED_CONNECTION`**: reproducido con `curl -I -L` (mismo método
`HEAD`, mismos redirects que usa `redirectchain`) — **no se reprodujo**
con `curl` (la cadena completa de `corporacionfavorita.com`, sitio en
Vercel, con una mezcla de HTTP/1.0→HTTP/2 entre saltos de la
redirección, resolvió sin problema). Al reintentar contra el propio
adaptador HTTP del proyecto (3 veces seguidas) el error **sí reapareció
las 3 veces** — indica una incompatibilidad puntual entre el parser HTTP
nativo de Node y ese patrón de redirección mixto, distinta del
comportamiento de `curl`, pero sin evidencia de que sea un rechazo
explícito del servidor ni tampoco un bug claro del instrumento. Se
mapeó a `INCONCLUSIVE` (nuevo set `AMBIGUOUS_TRANSPORT_CODES` en
`classifyDataError()`) — **sin tocar la lógica de red ni intentar
"arreglar" el comportamiento**, tal como se pidió explícitamente.

**Archivos modificados**: `server.js` (`handleTls`, `handleSslChain`,
`handleSecurityTxt`, `errorMessage()`), `index.html`
(`classifyDataError()`). Nada más — `ECONNREFUSED` genérico, `TIMEOUT`,
`ETIMEDOUT`, `fetchJSON`, `resolveFinalWebTarget`, el fallback
HTTPS→HTTP, `malware`/URLhaus, DNSSEC, RDAP, Archive, Ranking, PageSpeed
y SMTPUTF8 no se tocaron.

**Tests**: A/B/C (los 3 códigos nuevos → FAIL, contra `copaair.com` real),
D (`handleOpenPorts`/`redirectchain` con `ECONNREFUSED` — comportamiento
sin cambios, verificado en vivo), E (`HPE_CLOSED_CONNECTION` →
INCONCLUSIVE, vía `classifyDataError()` directo y vía mock del `case
'redirectchain'`), F (TLS normal contra `nic.uy` — éxito sin cambios),
G (timeout TLS contra `usa.gov` real — sigue siendo `TIMEOUT`, no se
transformó en `CONNECTION_REFUSED`). **Todos verificados en vivo o vía
jsdom contra el cliente real, sin mocks de lógica replicada** (a
diferencia de rondas anteriores, acá sí fue reproducible con dominios
reales). `npm test` completo OK.

**Corrida real** (`copaair.com`, `corporacionfavorita.com`):

| Check | Antes | Después |
|---|---|---|
| `tls`/`key`/`ocsp` (copaair.com) | MEASUREMENT_ERROR (`ECONNREFUSED`) | **FAIL** (`TLS_CONNECTION_REFUSED`) |
| `sslchain` (copaair.com) | MEASUREMENT_ERROR (`ECONNREFUSED`) | **FAIL** (`SSLCHAIN_CONNECTION_REFUSED`) |
| `securitytxt` (copaair.com) | MEASUREMENT_ERROR (`ECONNREFUSED`) | **FAIL** (`SECURITYTXT_CONNECTION_REFUSED`) |
| `redirectchain` (corporacionfavorita.com) | MEASUREMENT_ERROR (`HPE_CLOSED_CONNECTION`) | **INCONCLUSIVE** |

**Sin regresiones detectadas**: `openports`/`redirectchain` contra
`copaair.com` mantienen su comportamiento previo (puerto 443 simplemente
ausente de la lista de abiertos, sin error; la cadena de redirección
real vía puerto 80→www sigue funcionando igual). Dominios con TLS/SSL
normales (`nic.uy`) y con timeout real (`usa.gov`) no se vieron
afectados.

## Límite funcional de 20 dominios por análisis — 2026-09-13

Decisión deliberada (no técnica): MEDICIONES es una herramienta de
análisis técnico detallado, no un sistema de procesamiento masivo. Una
prueba con 400 dominios confirmó que el sistema los acepta, pero eso
implica tiempos de ejecución excesivos, más probabilidad de timeouts,
PDFs desproporcionados y menor control metodológico por corrida. Se fija
`MAX_DOMAINS_PER_ANALYSIS = 20` como techo duro del sub-tab "Reporte por
lote" de Mediciones (`medicionesBatchStart()`/`POST
/mediciones-batch/report`) — no de "Preparación de datasets de
dominios" (validación DNS) ni de "DNSSEC batch"/"Observatorio", que son
herramientas distintas con su propio alcance y no se tocaron.

La constante está declarada dos veces — una en `index.html` (contexto
navegador) y otra en `routes/medicionesBatchReport.routes.js` (contexto
Node) — porque el proyecto no usa bundler ni módulo compartido entre
cliente y servidor (regla del proyecto: sin frameworks nuevos). Es la
duplicación mínima inevitable dada esa restricción, no un número mágico
disperso: cada validación real del código (frontend y backend) lee de
su única constante local.

**Comportamiento**: si se supera el límite, no se inicia ninguna
medición, no se trunca ni se divide la lista silenciosamente — se
muestra un mensaje explícito (`alert()` con el texto acordado) y, para
carga por archivo, una advertencia inline con el conteo real
("El archivo contiene X dominios..."). La validación del servidor
(`POST /mediciones-batch/report` → 400 `DOMAIN_LIMIT_EXCEEDED` con
`received_count`/`max_allowed`) es la que realmente impide el bypass del
frontend, ya que es el único endpoint del flujo de Mediciones que recibe
la lista completa de dominios de una sola vez.

**Archivos modificados**: `index.html` (`MAX_DOMAINS_PER_ANALYSIS`,
`mbUpdateDomainCountUI()`, `medicionesBatchLoadFile()`, listener de
`mb-domains-input`, guard en `medicionesBatchStart()`),
`routes/medicionesBatchReport.routes.js` (`MAX_DOMAINS_PER_ANALYSIS`,
validación en `handleCreateReport()`), `public/i18n.js` (claves
`med.alert.domainLimitExceeded`, `med.batch.csvLimitWarning`, ES/EN),
`test/medicionesBatchReport.routes.test.js` (casos 20/21/400). No se
tocó ningún handler de los 54 checks, `classifyDataError()`, DNSSEC,
RPKI, ni `/dataset/validate-dns`.

**Tests**: backend vía `test/medicionesBatchReport.routes.test.js`
(`npm test` completo OK) — 20 dominios → 201, 21 → 400
`DOMAIN_LIMIT_EXCEEDED` (`received_count:21`), 400 → 400 (`received_count:400`).
Frontend vía jsdom contra servidor real (puerto local temporal): 1/19/20
dominios avanzan al análisis (sentinel en `initializeSummary()` antes de
disparar red real), 21/50/400 quedan bloqueados por el `alert()` con el
texto exacto pedido. Carga de CSV de 20 → mensaje verde normal; CSV de
21 → advertencia roja "El archivo contiene 21 dominios. El máximo
permitido es 20.". Llamada directa por `curl` al backend con 21/400
dominios (sin pasar por el frontend) confirmada rechazada con el mismo
código `DOMAIN_LIMIT_EXCEEDED`.

## Runner de investigación regional (400 dominios) — cliente externo, 2026-09-13

`scripts/regional-study/` — herramienta de investigación **fuera** de la
aplicación (no se importa desde `server.js`/`index.html`, no forma parte
del build/deploy de MEDICIONES). Automatiza 20 países × 20 dominios × 54
checks corriendo 20 lotes **secuenciales** (nunca en paralelo) contra una
instancia real de MEDICIONES ya en marcha, reusando exactamente
`window.medicionesBatchStart()` vía `index.html` cargado sin modificar en
`jsdom` — no reimplementa ningún check, y no toca `MAX_DOMAINS_PER_ANALYSIS`
(sigue en 20, cada lote respeta ese límite tal cual). Descarga el JSON por
el mismo endpoint que usa el botón "Descargar JSON" de la UI real
(`GET /mediciones-batch/report/:id/export?format=json`).

Detalle técnico no obvio: el `AbortSignal` de `jsdom` no es compatible con
el `fetch` nativo de Node — sin puentearlo a un `AbortController` real de
Node, el timeout real de 20s de `fetchWithTimeout()` (index.html) dejaría
de abortar de verdad. Ver `scripts/regional-study/README.md` para el
detalle completo, incluidas dos limitaciones reales del JSON exportado por
MEDICIONES descubiertas al inspeccionar el código (no reimplementables sin
tocar `index.html`, fuera de alcance de este pedido): `error_code` no
viaja en el JSON por check (solo el `details` humano), y no hay timestamp
por check, solo por corrida completa de un país.

## Rediseño de la pantalla de Inicio — 2026-09-13

El panel `tabPanelInicio` (`data-panel="inicio"`) se reescribió para
comunicar en pocos segundos qué es MEDICIONES, qué evalúa, para qué sirve,
cómo interpretar los resultados y quién coordina el proyecto — reemplaza
el bloque anterior ("¿Qué es Mediciones ISOC LAC?" + grid de 3 tarjetas de
módulos). Estructura: hero (texto + botón "Iniciar medición" + nota del
límite de 20 dominios) → ámbitos evaluados (8 etiquetas: DNS, IPv4/IPv6,
DNSSEC, RPKI, correo, TLS, seguridad web, configuración técnica — sin
listar los 54 checks) → para qué sirve/audiencias → alcance y
limitaciones (no es auditoría ni certificación; estados INCONCLUSIVE/
NOT_APPLICABLE/MEASUREMENT_ERROR no son fallas) → institucional (proyecto
coordinado por los capítulos de Internet Society de Uruguay, Paraguay,
Argentina, Panamá y Ecuador — **no** se afirma participación formal de
todos los capítulos LAC, solo de estos cinco como coordinadores).

El botón "Iniciar medición" (`#inicio-cta-medicion`) no duplica el
formulario ni la lógica de Mediciones: dispara el mismo mecanismo de
navegación existente (`document.getElementById('tabBtnMediciones').click()`,
igual que ya hacían los antiguos links "Ir al módulo →") y además hace
`scrollIntoView` sobre `#mb-domains-input` (guardado tras comprobar que
existe la función, para no romper en entornos sin esa API — encontrado al
probar con `jsdom`, que no la implementa).

`site.subtitle` (cabecera global, visible en todas las pestañas, no solo
Inicio) se actualizó de "Herramienta experimental para apoyar las
mediciones y la implementación del DNSSEC..." (enfocado solo en DNSSEC) a
"Diagnóstico técnico de dominios de Internet." — más preciso dado que la
herramienta ya cubre 54 checks más allá de DNSSEC.

Los textos nuevos entran al diccionario de `public/i18n.js` (ES/EN) bajo
las claves `inicio.hero.*`, `inicio.scope.*`, `inicio.purpose.*`,
`inicio.limits.*` y `inicio.about.*` (esta última reemplaza el contenido
anterior de `inicio.about.heading`/`.body`, que solo se usaba en este
panel). Se eliminaron del diccionario `inicio.modules.*`,
`inicio.module.*` e `inicio.goLink` — quedaban huérfanos tras el
reemplazo (verificado que no los usaba ningún otro archivo antes de
borrarlos).

**Pestaña Observatorio oculta de la navegación pública** (no eliminada):
`tabBtnObservatorio` recibió `style="display:none"`, `aria-hidden="true"`
y `tabindex="-1"` — el botón, ambos paneles (`tabPanelObservatorio` y
`tabPanelObservatorio Legacy`) y las rutas backend (`aggregate/`, `/obs`,
`/zm`, `/aggregate` en `server.js`) siguen intactos en el código, solo
inalcanzables desde la UI mientras se redefine el alcance de producto del
Observatorio (ver auditoría de sesión previa). Comentario explícito en
`index.html` junto al botón y junto a la sección: "Observatorio permanece
deshabilitado en navegación mientras se redefine su alcance de producto."
La tarjeta de Observatorio que existía en el grid de módulos de Inicio
desapareció como parte del reemplazo de esa sección, no por un cambio
aparte.

**Verificación**: `npm test` completo sin cambios de resultado (el
rediseño no tocó `routes/medicionesBatchReport.routes.js`, `aggregate/`
ni `scripts/regional-study/`). Smoke `jsdom` contra el servidor real
(`PORT=3501 node server.js`): `tabBtnObservatorio` presente en el DOM con
`display:none`; texto del hero e institucional presentes en ES y en EN
tras `setLanguage('en')`/`('es')`; click en el CTA activa
`tabPanelMediciones` (`display:block`, botón con clase `active`) y
`#mb-domains-input` queda presente/visible; cero errores de consola.
Playwright (desktop 1280px/tablet 768px/mobile 375px) no pudo ejecutarse
en este entorno por falta de red para descargar el binario de Chromium —
la responsividad se verificó por revisión manual de las clases usadas
(grid con breakpoints `sm:`, sin anchos fijos ni `min-width`, mismo
patrón que otras secciones ya shippeadas de `index.html`), no por
captura real de viewport.
