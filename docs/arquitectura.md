# Arquitectura — Mediciones ISOC LAC

> Última actualización: 2026-09-09. Agrega la sub-pestaña "Análisis
> comparativo" de Mediciones (lote de dominios, reporte PDF/JSON), un
> glosario de indicadores conectado a la UI, varios fixes reales en el
> módulo de checks individuales (WHOIS, RPKI, fetch seguro), y una ronda de
> QA sobre el reporte comparativo en producción (símbolos de resultado sin
> explicar, tabla comparativa truncada — ver § tablas anchas más abajo). La
> sección "Preparación de datasets de dominios" (2026-08-14) sigue sin
> cambios.

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

## Mediciones — "Análisis comparativo" (sub-pestaña de lote)

Sub-pestaña de Mediciones (junto a "Un dominio"), para correr los mismos
checks + DNSSEC + validación DNS sobre un lote de 20-25 dominios y descargar
un reporte final (`index.html`, panel `mediciones-panel-batch` /
`medicionesBatchStart`).

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

### Glosario de indicadores y tooltips (compartido "Un dominio" / lote)

`groupDefinitions` + `checkGlossary` + `checkConfig` en `index.html` son la
única fuente de verdad de qué hace cada uno de los ~70 checks. De ahí salen:

- `checkHelpButton(key)` — el ícono "?" con tooltip (CSS `.term-help`) junto
  a cada checkbox, en **ambas** sub-pestañas de Mediciones.
- `renderGlossaryBlock()` — bloque colapsable "📖 Glosario de términos",
  montado una sola vez (compartido por "Un dominio" y "Análisis comparativo")
  justo debajo de las sub-pestañas, con un `<details>` por grupo.
- `selectedGlossary(selectedChecks)` — lo que arma el payload del reporte
  batch (arriba).

## Fixes reales de checks individuales (módulo Mediciones, 2026-09-09)

No relacionados al feature de lote — bugs encontrados probando en producción:

- **`logic/adapters/safeWebFetch.adapter.js`** (nuevo): reemplaza el viejo
  `fetchPage` en whois/headers/security.txt/robots/sitemap/status. Resuelve
  la cadena de redirecciones con protección SSRF (no sigue a IPs privadas),
  algo que `fetchPage` no hacía.
- **RPKI** (`server.js`, `rpkiValidity`): la API de Cloudflare RPKI que se
  usaba (`rpki.cloudflare.com/api/v1/validity`) ya no existe (404 siempre,
  se retiró) — se quitó esa llamada. Además el ASN que devuelve RIPEstat
  viene como **string** (`"13335"`), no `number` ni objeto — el código viejo
  lo comparaba mal y siempre caía a `state: 'unknown'`. Ahora usa solo
  RIPEstat con `asn` (parseado) + `prefix`.
- **WHOIS** (`server.js`, `handleWhois`): el regex de organización/país leía
  el HTML de whois.com sin acotar sección — podía capturar el campo de
  *Registrar* en vez de *Registrant* si el orden del HTML cambiaba. Se
  corrigió acotando primero al bloque `"Registrant Contact"`
  (`extractWhoisComSection`) antes de aplicar los regex. También se agregó
  `status`/`message`/`disclaimer` en la respuesta para distinguir "sin datos
  porque están redactados por privacidad" de "error técnico consultando la
  fuente" — antes ambos casos se veían igual (campos vacíos).
- **`.env` se carga al boot de `server.js`** (parser mínimo, sin dependencia
  nueva) — necesario porque se agregó `nodemailer` (envío de contraseñas del
  panel admin) y credenciales SMTP.

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
  >6 checks seleccionados (y ausencia con pocos), sección de glosario
  siempre presente, truncado de detalle largo.
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
