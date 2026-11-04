# Auditoría técnica: origen, fork y divergencia de MEDICIONES Ecuador

**Fecha de la auditoría:** 2026-09-15
**Alcance:** solo lectura — sin modificar, comitear, mergear, ni instalar nada en el repositorio local. Se consultaron repositorios públicos de GitHub vía `gh api` (lectura).

---

## 0. Resumen ejecutivo

MEDICIONES Ecuador **no es un fork Git** de ningún repositorio de Paraguay ni de ISOC LAC — no existe ninguna relación de historial Git (ni como fork nativo de GitHub, ni como remoto agregado y luego fetch/merge). Sin embargo, sí existe una relación real y verificable a nivel de **contenido de archivos**: el primer commit de Ecuador (`6c9c68c`, 2025-12-08) es una **copia byte-por-byte** — confirmada con `diff` de 0 líneas en los 5 archivos — del commit `0d14f45` del repositorio **`nicocamarao/mediciones-isoc-lac`** (2025-10-06T18:28:46Z, "Improve network insights reliability and messaging"). Esa persona (`nicocamarao`, GitHub individual) es el origen real del proyecto; el repositorio **`isoclac/mediciones-isoc-lac`** es simplemente un fork nativo de GitHub de ese mismo repositorio, creado el 2026-05-06, **sin ningún commit propio** — es un espejo pasivo, no una evolución independiente.

Tras esa copia (que no fue un `git clone`/fork sino una subida manual de archivos — hay evidencia de un intento previo del mismo tipo en un repositorio ahora abandonado, `mediciones-isoc-lac` sin sufijo, con 19 commits "Add files via upload" desde la interfaz web de GitHub), **Ecuador nunca volvió a sincronizar con el proyecto de origen**. No hay ni un solo commit, remoto, comentario ni referencia en todo el historial de Ecuador (58 commits, todas las ramas) que mencione Paraguay, `nicocamarao` o `isoclac`.

La cifra "202+" **no es un conteo de endpoints ni de tipos de medición distintos** en ninguno de los dos proyectos — es un texto estático (`<span class="section-pill">Más de 202 mediciones integradas</span>`) incrustado literalmente en el HTML de `nicocamarao/mediciones-isoc-lac`, sin ningún cálculo de JavaScript detrás. El registro real de "checks" de ese proyecto hoy tiene **~50-53 entradas activas**, prácticamente el mismo orden de magnitud que las **54 de Ecuador** — no 202. La cifra "~30" atribuida a Ecuador tampoco corresponde a ningún artefacto encontrado en el código actual (Ecuador tiene 54 checks activos, de los cuales 18 vienen premarcados por defecto — ver §11 para el detalle de por qué ninguna cifra exacta de "30" pudo verificarse).

El hallazgo más importante y menos intuitivo: **Ecuador no perdió funcionalidad heredada del fork** — de los 21 nombres de check/bundle que existían en Paraguay al momento del fork y que hoy YA NO aparecen en el registro activo de Paraguay/upstream, Ecuador conserva 17 vivos hoy. La verdadera brecha es que Ecuador **nunca recibió las ~12 mediciones genuinamente nuevas** que Paraguay agregó después del fork (DNSViz, W3C, routing, ping/traceroute IPv6, STARTTLS, IPv6 en MX, DNSSEC de correo, y el rediseño visual "Massively" con soporte de portugués e integración con ISOC Pulse).

---

## 1. Identidad del repositorio local

```
$ pwd
C:\PROJECTS\MEDICIONES

$ git status
On branch main
Your branch is ahead of 'origin/main' by 20 commits.
(untracked: data/exercises/, scripts/exercise-24-domains/, 2 PDFs nuevos,
 1 zip redundante ya documentado en sesiones previas — nada de esto es
 relevante para esta auditoría)

$ git log -1 --format="%H%n%an <%ae>%n%ad%n%s"
d3cc5a7905191d7edbbac986a18c9b998443585c
Carlos Vera <sociedadinternetecuador@gmail.com>
Sun Sep 13 14:35:41 2026 -0500
tooling: add regional study runner

$ git tag -l
(vacío — no hay tags)

$ git remote -v
origin  https://github.com/sociedadinternetecuador-lgtm/mediciones-isoc-lac-v2 (fetch)
origin  https://github.com/sociedadinternetecuador-lgtm/mediciones-isoc-lac-v2 (push)

$ git branch -a
* main
  remotes/origin/HEAD -> origin/main
  remotes/origin/flyio-new-files
  remotes/origin/main
  remotes/origin/v2-interface

$ git log --max-parents=0 --all --format="%H %ai %an %s"
6c9c68cb7708fa0ba7d738c72e9a0fa316acdbd4 2025-12-08 12:23:30 -0500 sociedadinternetecuador-lgtm Initial commit

$ git log --oneline --all | wc -l
58

$ git reflog show --all | tail -1
f71e227 refs/heads/main@{36}: clone: from https://github.com/sociedadinternetecuador-lgtm/mediciones-isoc-lac-v2
```

**Conclusiones directas:**
- **Un solo remoto** (`origin`), nunca hubo otro configurado (confirmado también por `git config --get-regexp "^remote\."` y por el reflog completo).
- **Un solo commit raíz**, sin padres, sin merge de historial externo — el único merge en toda la historia (`a028742`) es un PR de "Fly.io Launch" (scaffolding de despliegue), no relacionado con Paraguay.
- **Sin tags.**
- El reflog confirma que este working copy es simplemente un `git clone` del propio `origin` (`sociedadinternetecuador-lgtm/mediciones-isoc-lac-v2`) — no hay indicio de que alguna vez haya tenido un remoto adicional que luego se haya eliminado.
- **No existe relación Git directa ni indirecta con ningún repositorio paraguayo u original.** Cualquier relación es a nivel de contenido de archivos copiados manualmente, no de historial de versiones.

---

## 2. Reconstrucción del fork Paraguay → Ecuador

### 2.1 Identidad de los tres repositorios en juego

| Repositorio | Dueño | Tipo GitHub | Creado | Último push | Commits propios |
|---|---|---|---|---|---|
| `nicocamarao/mediciones-isoc-lac` | Usuario individual `nicocamarao` | Original (`fork: false`) | 2025-08-29 | 2026-06-15 | 30 |
| `isoclac/mediciones-isoc-lac` | Organización `isoclac` | Fork nativo de GitHub del anterior (`fork: true`, `parent: nicocamarao/...`) | 2026-05-06 | 2026-06-15 (heredado) | **0 propios** — historial idéntico a nicocamarao |
| `sociedadinternetecuador-lgtm/mediciones-isoc-lac` (sin sufijo) | Cuenta de Ecuador | Independiente (`fork: false`) | 2025-11-15 | 2025-11-16 | 19 ("Add files via upload") — **abandonado, no es el repo en uso** |
| `sociedadinternetecuador-lgtm/mediciones-isoc-lac-v2` | Cuenta de Ecuador | Independiente (`fork: false`) | 2025-12-08 | 2026-04-16 (vía push); local sigue trabajando encima | 58 — **este es el repositorio auditado** |

Nota: la cuenta `isoclac` es casi con certeza el "capítulo regional ISOC LAC" — su nombre coincide exactamente con un `username` que aparece **comentado** en el código de Ecuador (`aggregate/zonemaster/zonemaster.adapter.js:32: // username: 'isoclac',`), evidencia indirecta de que Ecuador conocía/configuró en algún momento una cuenta compartida de ese nombre para el servicio Zonemaster — consistente con que "isoclac" es la identidad regional del proyecto, no una coincidencia.

### 2.2 El commit exacto del fork

Se descargó el contenido de `nicocamarao/mediciones-isoc-lac@0d14f45` (el último commit de ese repositorio antes de la fecha del primer commit de Ecuador) y se comparó archivo por archivo contra `6c9c68c` (Initial commit de Ecuador):

```
$ wc -l nico_0d14f45/* ecuador_initial/*
    22 README.md      22 README.md
  1154 index.html   1154 index.html
    14 package.json   14 package.json
  1409 server.js     1409 server.js

$ diff nico_0d14f45/server.js ecuador_initial/server.js | wc -l
0
$ diff nico_0d14f45/index.html ecuador_initial/index.html | wc -l
0
$ diff nico_0d14f45/README.md ecuador_initial/README.md
(sin diferencias)
$ diff nico_0d14f45/package.json ecuador_initial/package.json
(sin diferencias)
$ diff nico_0d14f45/.gitignore ecuador_initial/.gitignore
(sin diferencias)
```

**HECHO COMPROBADO:** los 5 archivos son idénticos byte a byte. El commit `0d14f45` es el siguiente commit de `nicocamarao` después de eso no hubo ningún otro commit en ese repositorio hasta el 2026-04-15 (6 meses después) — es decir, `0d14f45` era literalmente el HEAD de `nicocamarao/mediciones-isoc-lac` en el momento en que Ecuador tomó su copia.

- **Fecha del fork/copia:** entre 2025-10-06 (commit `0d14f45`) y 2025-12-08 (primer commit de Ecuador) — el commit del lado Ecuador está fechado el 2025-12-08, que es la fecha más precisa disponible.
- **Autor del commit base en Paraguay:** `nicocamarao`.
- **Primer commit propio de Ecuador después de la copia:** `be571b0` ("Serve index.html for root path requests", 2025-12-08, mismo día).
- **Mecanismo:** **no** fue un fork Git nativo, **no** fue un `git clone` + `remote add` + `push` a un repo nuevo. La evidencia (README/package.json/server.js/index.html idénticos pero sin ningún objeto Git compartido, más el precedente del repositorio abandonado `mediciones-isoc-lac` con 19 commits "Add files via upload" desde la interfaz web) apunta a una **copia manual de archivos** (descarga del ZIP o copiar-pegar contenido) seguida de un `git init` nuevo — perdiendo deliberada o accidentalmente todo el historial de autoría original.

### 2.3 Árbol genealógico (con evidencia real)

```
nicocamarao/mediciones-isoc-lac  (creado 2025-08-29, "Nico" / "nicocamarao")
  │
  ├── commit 0d14f45 (2025-10-06) ── copiado manualmente (sin fork Git) ──┐
  │                                                                        │
  ├── [2026-04-15 → 2026-04-17] Nico: DNSViz, ccTLD, Pulse, DNSSEC        │
  ├── [2026-05-06] fork nativo de GitHub → isoclac/mediciones-isoc-lac    │
  │                (0 commits propios — espejo pasivo)                    │
  ├── [2026-06-10 → 2026-06-15] rediseño "Massively", Pulse, README EN    │
  │   (HEAD actual, b88aff3, sin push desde entonces)                     │
  │                                                                        │
  └── (no hay más ramas activas)                                         │
                                                                           ▼
                                          sociedadinternetecuador-lgtm/mediciones-isoc-lac
                                          (sin sufijo, creado 2025-11-15, ABANDONADO
                                           tras 19 "Add files via upload" — no es
                                           el repo en producción)
                                                          │
                                                          │ (no hay continuidad Git
                                                          │  documentada entre ambos)
                                                          ▼
                              sociedadinternetecuador-lgtm/mediciones-isoc-lac-v2
                              (creado 2025-12-08, ESTE es el repo local auditado)
                                │
                                ├── [dic 2025] Fly.io launch, Quad9 DoH
                                ├── (gap 4 meses)
                                ├── [abr 2026] DNSSEC propio, Zonemaster, Observatorio
                                ├── (gap 5 meses)
                                └── [sep 2026] reorganización de checks, 6 estados,
                                    límite de 20 dominios, runner regional,
                                    portada nueva, Observatorio oculto,
                                    ejercicio de 24 dominios (HEAD actual)
```

---

## 3. Tres momentos comparados

| Momento | Repositorio/commit | Fecha | Nº de "checks" (registro frontend) | Nº de endpoints backend (crudo) |
|---|---|---|---|---|
| **A. Paraguay al momento del fork** | `nicocamarao@0d14f45` | 2025-10-06 | **59** claves `key:` en el switch-case cliente | **46** rutas `segments[0] === '...'` en server.js |
| **B. Paraguay/upstream actual** | `nicocamarao@b88aff3` (HEAD, = `isoclac` HEAD) | 2026-06-15 | **50 activas + 3 "próximamente"** (`check()`/`checkSoon()`) | **64** endpoints `GET` documentados en README |
| **C. Ecuador actual** | HEAD local `d3cc5a7` | 2026-09-13 | **54** (`groupDefinitions`, verificado por suma exacta de los 6 grupos) | ver §4 |

Con esto se puede responder directamente a la pregunta motivadora de la auditoría, sección por sección, en 4 y en adelante.

---

## 4. Inventario real de Ecuador hoy (54 checks)

El frontend (`index.html`, `const groupDefinitions = [...]`, línea 1829) organiza los 54 checks en 6 grupos. Cada uno corresponde a un `case` en `getCheckResult()` (index.html) que llama a un endpoint real de `server.js` o resuelve datos vía DoH cliente-side. Todos están **activos y expuestos en el frontend** (ninguno está deshabilitado/comentado) — Ecuador no tiene "checks fantasma" en backend sin exponer.

| Grupo (UI) | # | Checks (clave) |
|---|---|---|
| Seguridad y confianza (DNS/TLS) | 7 | https, redirect, hsts, caa, rpki, tlsa, malware |
| Anti-suplantación de correo | 3 | spf, dmarc, dkim |
| Cabeceras de seguridad web | 5 | csp, xfo, xcto, referrer, permissions |
| Transparencia y conectividad moderna | 2 | securitytxt, ipv6 |
| Diagnóstico técnico | 27 | ipinfo, serverlocation, serverinfo, ipv4, asn, serverstatus, openports, redirectchain, block, dnsrecords, txtrecords, dnsserver, mx, smtputf8, whois, domaininfo, headers, server, compression, ocsp, tls, key, sslchain, tlsciphers, tlssimulation, firewall, xxss |
| Contenido y experiencia | 10 | sitefeatures, cookies, crawlrules, linkedpages, listedpages, socialtags, quality, archive, ranking, screenshot |
| **Total** | **54** | — |

Fuera de estos 54 (no cuentan como "checks de Mediciones" pero SÍ existen y funcionan en Ecuador, como módulos aparte):
- **DNSSEC completo** (`/dnssec-analysis`, `logic/processors/dnssec.processor.js`) — 7 estados estructurales (`ok`, `not_implemented`, `blocked_at_tld`, `blocked_at_parent`, `misconfigured`, `indeterminate`, `non_existent`). Vive como **pestaña propia**, no como uno de los 54 checkboxes.
- **Motor Zonemaster** (`aggregate/zonemaster/`) — análisis DNSSEC profundo vía API externa, batch.
- **Preparación de datasets de dominios** — validación DNS multi-resolver (Cloudflare/Google DoH), sin equivalente en Paraguay.
- **Observatorio** (`aggregate/`) — actualmente oculto de navegación, pero el backend sigue montado.

**No se encontró ningún artefacto en el código que produzca literalmente "~30"** como conteo de mediciones. El candidato más cercano encontrado: **18 checks vienen marcados `default: true`** (preseleccionados al abrir la pestaña Mediciones) — posible origen de una impresión visual de "unas 30" si se cuenta a ojo lo que aparece premarcado más algún margen, pero esto es **NO DETERMINADO** con certeza — no hay una cifra "30" codificada en ningún lugar.

---

## 5. Inventario de Paraguay al momento del fork (2025-10-06)

Extraído del switch-case client-side de `nicocamarao@0d14f45/index.html` (arquitectura: cliente resuelve casos, llama a endpoints de `server.js`; varios endpoints eran "bundle" que agrupaban varios campos — `dnssecurity`, `httpsecurity`, `emailconfig`, `tlsconfig`):

| Clave | ¿Existía en Paraguay al fork? | ¿Existe hoy en Ecuador? | ¿Existe hoy en upstream? | Observación |
|---|---|---|---|---|
| ipv4, ipv6 | Sí | Sí | Sí | Sin cambios de fondo |
| spf, dmarc, dkim | Sí | Sí | Sí | Ecuador migró spf/dmarc/ipv4/ipv6 de cliente→backend en 2026-09 (Fase 1), igual que upstream ya lo tenía server-side desde antes |
| https, redirect, hsts, csp | Sí | Sí | Sí | — |
| tls, sslchain, ocsp, tlsa, caa | Sí | Sí | Sí | — |
| xfo, xcto, referrer, permissions, xxss | Sí | Sí (xxss también) | xxss no aparece en upstream actual | Posible renombre/fusión en upstream |
| securitytxt | Sí | Sí | Sí | — |
| mx, smtputf8 | Sí | Sí | Sí | — |
| rpki | Sí | Sí | Sí | — |
| dnssec | Sí (endpoint backend, sin card propia en UI) | **Sí, pero como módulo separado mucho más rico** (7 estados), no como uno de los 54 | Sí, como card individual simple | Ver nota en §4 — no es una pérdida, es una reubicación con mejora |
| whois, domaininfo | Sí | Sí | **No** (ausentes del registro activo actual) | Ecuador conserva algo que Paraguay abandonó |
| asn, ipinfo, serverinfo, serverlocation | Sí | Sí | serverinfo sí, los otros 3 no | — |
| block | Sí | Sí | No | Ecuador conserva algo que Paraguay abandonó |
| firewall, headers, server, key | Sí | Sí | No | Ecuador conserva algo que Paraguay abandonó |
| tlsciphers, tlssimulation | Sí | Sí | No | Ecuador conserva algo que Paraguay abandonó |
| crawlrules, screenshot | Sí | Sí | No | Ecuador conserva algo que Paraguay abandonó |
| dnsserver | Sí | Sí | No | Ecuador conserva algo que Paraguay abandonó |
| dnssecurity, httpsecurity, emailconfig, tlsconfig (bundles) | Sí | No como bundle (se dividieron en checks individuales) | No como bundle (ídem) | Ambos proyectos independientemente abandonaron el patrón "bundle" a favor de checks atómicos |

**Conclusión de esta tabla:** de las funciones que Paraguay tenía al momento del fork, **ninguna se perdió en Ecuador** en el sentido estricto — Ecuador retiene 17 de los 21 nombres que Paraguay mismo dejó de exponer después. Lo que sí falta en Ecuador son las funciones que Paraguay **agregó después** del fork (ver §7).

---

## 6. Inventario del upstream actual (`nicocamarao`/`isoclac`, HEAD `b88aff3`)

Registro completo extraído de `const groups = [...]` en `index.html` (HEAD):

| Grupo | Checks activos |
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
| Laboratorio | serverstatus, redirectchain, openports, ping, pingv6, traceroute, sitefeatures, cookies, listedpages, linkedpages, socialtags, quality*, archive, ranking |
| *Próximamente* (no activo) | ofds, aspa, quantum |

**Total: 50 activos únicos + 3 planeados = 53.** El README (reescrito en inglés) documenta **64 rutas `GET`** distintas — más que los 53 porque incluye endpoints compuestos/utilitarios (`/api`, `/mini`, `/pulse`, `/compat`, `/carbon`, `/techstack`, `/associatedhosts`, etc.) que no son "checks" con tarjeta propia en la UI.

### 6.1 De dónde sale "202+"

```
$ grep -n "202" index.html
119:  <span class="section-pill">Más de 202 mediciones integradas</span>
```

Es **texto estático en el HTML**, dentro de la sección "Mapa general" (que organiza todo en tres ejes: seguridad, universalidad, accesibilidad). No hay ninguna variable, plantilla ni cálculo de JavaScript detrás de ese número — no es `${count}` ni el resultado de sumar un array en tiempo real.

**Determinación exacta de qué tipo de cifra es** (respondiendo a las 5 opciones planteadas):

- **(a) 202 endpoints independientes:** NO — hay 64 documentados, 53 activos como check.
- **(b) ~202 subpruebas/resultados agregados:** **INFERENCIA RAZONABLE, no confirmada.** Varios checks devuelven arreglos/objetos con múltiples campos (suites de cifrado en `tlsciphers`, nodos de cadena en `dnsviz`, enlaces en `linkedpages`, hops en `traceroute`, métricas de Lighthouse en `quality`) — sumando esos sub-resultados de una corrida completa contra un dominio real es plausible que el total ronde varios cientos. No se pudo verificar ejecutando la app real porque no se encontró una URL de despliegue en vivo del proyecto de Paraguay/upstream en el repositorio, y no corresponde desplegarla para esta auditoría de solo lectura.
- **(c) combinación de verificaciones internas y servicios externos:** posible, pero no es la explicación primaria — el texto no distingue esa combinación explícitamente en ningún comentario del código.
- **(d) calculada dinámicamente en el código:** **NO** — confirmado, es texto plano.
- **(e) hardcodeada en frontend:** **SÍ, confirmado.** Es la respuesta con más evidencia directa.

**No determinado con certeza matemática** es qué compone exactamente el "202" — solo que no es un conteo de checks ni de endpoints, y que está escrito a mano en el HTML.

---

## 7. Cronología de crecimiento después del fork

| Fecha | Commit | Función añadida en Paraguay/upstream | ¿Ecuador ya se había separado? | ¿Llegó alguna vez a Ecuador? |
|---|---|---|---|---|
| 2026-04-15 | `ca5271d` | "Nico nuevos cambios" (cambios generales) | Sí (4 meses antes) | No |
| 2026-04-17 | `1bfc702` | **DNSViz**, ccTLD, reporte Pulse | Sí | No |
| 2026-04-17 | `e0de845` | Renderizado de estado DNSSEC más estricto | Sí | No (Ecuador desarrolló su propio modelo DNSSEC de 7 estados en paralelo, mismos días de abril 2026, sin relación) |
| 2026-05-06 | (fork GitHub) | Creación de `isoclac/mediciones-isoc-lac` | Sí | N/A (0 commits propios) |
| 2026-06-10 | `de6474c`, `0697b8b`, `abe1f00` | Rediseño visual completo "Massively" (HTML5UP), nuevo layout de mediciones | Sí | No |
| 2026-06-12 | `47194fc`, `4cb4d3c` | Refinamiento "situación LAC", **restauración de datos de ISOC Pulse**, banderas ccTLD | Sí | No |
| 2026-06-15 | `11da02b`, `b88aff3` | Pulido de vista "Mini", README reescrito en inglés | Sí | No |

**Funciones añadidas después del fork que Ecuador nunca recibió** (12, excluyendo los 3 "próximamente" que ni siquiera están activos en upstream): `dnsviz`, `internetnlweb`, `internetnlmail`, `maildnssec`, `mailipv6`, `ping`, `pingv6`, `routing`, `serverbanner`, `starttls`, `w3c`, y `dnssec` como card individual propia (en Ecuador el equivalente vive en un módulo aparte, más completo).

También post-fork y nunca recibido: la arquitectura de **3 idiomas** (`locales/{en,es,pt}.properties`), la **integración con ISOC Pulse** (`data/pulse-*.json`, `scripts/pulse_snapshot*`), y el rediseño visual "Massively".

---

## 8. Matriz comparativa Ecuador vs. Paraguay/upstream

| Medición/módulo | Paraguay en el fork | Upstream actual | Ecuador actual | Estado |
|---|---|---|---|---|
| https, redirect, hsts, csp, tls, sslchain, ocsp, tlsa, caa, ipv4, ipv6, spf, dmarc, dkim, mx, smtputf8, rpki, xfo, xcto, referrer, permissions, securitytxt | Sí | Sí | Sí | **HEREDADO DEL FORK**, evolucionado en paralelo en ambos lados |
| dnssec (card individual simple) | Backend sí, card no | Sí, card propia | No como card; sí como módulo aparte mucho más rico | **HEREDADO Y MODIFICADO EN ECUADOR** (mejorado, reubicado) |
| whois, domaininfo, asn, ipinfo, block, firewall, headers, server, key, tlsciphers, tlssimulation, crawlrules, screenshot, dnsserver | Sí | **No** | Sí | **EXISTÍA EN PARAGUAY, upstream lo abandonó — Ecuador NO lo perdió** |
| dnsviz, internetnlweb, internetnlmail, maildnssec, mailipv6, routing, w3c, ping, pingv6, starttls, serverbanner | No | Sí | No | **AÑADIDO A PARAGUAY DESPUÉS DEL FORK** — Ecuador no lo tiene |
| Motor Zonemaster, Observatorio DNSSEC, Preparación de datasets, Admin/Blog/Eventos, log persistente de mediciones, runner regional/24-dominios | No | No | Sí | **SOLO ECUADOR** |
| Rediseño "Massively", i18n en 3 idiomas, integración ISOC Pulse | No | Sí | No | **SOLO PARAGUAY/UPSTREAM** |
| Pestaña Observatorio (nav pública) | N/A | N/A | Backend existe, tab oculta | **DESHABILITADO EN ECUADOR** (decisión propia de producto, no relacionado al fork) |

---

## 9. Desarrollos propios de Ecuador que deben conservarse

| Funcionalidad | Origen (commit/fecha) | Archivo(s) | Diferencia con Paraguay | Importancia | Riesgo si se sincroniza mal |
|---|---|---|---|---|---|
| Motor DNSSEC de 7 estados estructurales | `663c53f`…`046c8fa` (abr 2026) | `logic/processors/dnssec.processor.js`, `logic/rules/dnssec.rules.js` | Paraguay solo tiene un booleano simple | Alta — es la pieza más sofisticada del proyecto | **Alto** — un merge naíf podría reemplazarlo por el modelo simple de upstream |
| Modelo de 6 estados (PASS/FAIL/INFO/INCONCLUSIVE/NOT_APPLICABLE/MEASUREMENT_ERROR) | Fase 2, `9f6c879` (sep 2026) | todo `index.html`/`routes/` | Paraguay no distingue "no aplica" de "error de medición" | Alta — evita falsos negativos de seguridad | **Alto** |
| Motor Zonemaster + Observatorio | `83c4f57`, `3480309`, `fca2a1c` (abr 2026) | `aggregate/` | Sin equivalente en Paraguay | Media (actualmente oculto de nav) | Medio |
| Preparación de datasets de dominios (multi-resolver DoH) | (documentado en `docs/arquitectura.md`) | `logic/orchestrators/dnsValidationJob.orchestrator.js` | Sin equivalente en Paraguay | Alta — módulo más nuevo y extenso | Bajo (aislado) |
| Panel de administración, Blog/Eventos/Materiales | (ver `docs/arquitectura.md`) | `admin.html`, `routes/admin.routes.js`, `routes/content.routes.js` | Sin equivalente en Paraguay | Media | Bajo (aislado) |
| Log persistente de mediciones | `a6b2c87` (sep 2026) | `data/measurements/*.jsonl` | Sin equivalente en Paraguay | Baja-media | Bajo |
| Límite de 20 dominios + runner regional + ejercicio 24 dominios | sep 2026 | `routes/medicionesBatchReport.routes.js`, `scripts/regional-study/`, `scripts/exercise-24-domains/` | Sin equivalente en Paraguay | Media (metodológico) | Bajo (aislado, fuera de la app) |

---

## 10. Por qué Ecuador quedó divergente (no "en ~30")

**HECHO COMPROBADO:**
- No hay sincronización Git en ningún momento del historial de Ecuador con `nicocamarao` ni `isoclac`.
- Ecuador copió manualmente el HEAD de `nicocamarao` en 2025-10-06/12-08 y nunca repitió el proceso.
- Paraguay/upstream siguió evolucionando después (abril y junio 2026) con funciones que Ecuador no recibió.
- Ecuador desarrolló extensamente sus propios módulos (DNSSEC, Zonemaster, Observatorio, datasets, admin) de forma completamente independiente, en las mismas fechas (abril 2026) en que Paraguay hacía sus propios cambios — desarrollo paralelo, no coordinado.
- Ecuador hoy tiene 54 checks activos, no ~30 — cifra verificada por conteo directo del código, no estimada.
- Paraguay/upstream hoy tiene ~50-53 checks activos, no 202+ — la cifra "202" es un texto de marketing hardcodeado, no un conteo de checks.

**INFERENCIA RAZONABLE:**
- El "~30" que motivó esta auditoría probablemente refleja una impresión visual (quizás contando lo premarcado por defecto —18— más algún margen, o un recuerdo de una versión más antigua del código antes de la reorganización de checks de septiembre 2026) más que una cifra derivada de una lectura literal del código actual.
- El "202+" probablemente cuenta sub-resultados/datos agregados de una corrida completa (arrays de cifrados TLS, nodos de cadena DNSViz, enlaces, hops de traceroute, métricas de Lighthouse), no "mediciones" en el sentido de categorías distintas — pero esto no pudo confirmarse ejecutando la aplicación real de Paraguay, porque no se encontró (ni se buscó activamente) una URL de despliegue en vivo.

**NO DETERMINADO:**
- Si el copiado manual del código de Paraguay fue una decisión deliberada de no preservar el historial Git, o simplemente el resultado de cómo se hizo la transferencia de archivos en su momento (vía descarga/upload en vez de clone).
- La composición exacta y verificada del número "202".
- El origen exacto del número "~30" (no se encontró en el código).

---

## 11. Cuantificación 30 vs 202+

| Métrica | Ecuador | Paraguay al fork | Paraguay/upstream actual |
|---|---|---|---|
| Checks activos en registro frontend | **54** | 59 (arquitectura distinta, con bundles) | **50** activos + 3 planeados |
| Endpoints backend crudos | no contado exhaustivamente en esta auditoría (fuera de alcance re-enumerar los ~54+ handlers de `server.js`; ya documentado en sesiones previas de este mismo proyecto) | 46 | 64 (documentados en README) |
| Cifra "202+" | N/A | N/A | **No verificable como conteo — es texto estático** |
| Checks agregados a Paraguay después del fork | — | — | **12** activos nuevos (+3 planeados) |
| Checks que Ecuador nunca recibió de esos 12 | **12 de 12** | — | — |
| Checks del fork que Ecuador conserva y Paraguay ya no tiene | **17** | (base) | 0 (los abandonó) |
| Desarrollos exclusivos de Ecuador (módulos, no checks individuales) | 6 módulos mayores (§9) | 0 | 0 |

**Por qué no se puede dar una cifra exacta de "cuánto se perdió":** en sentido estricto, comparando registros de checks nombre-por-nombre, **Ecuador no perdió nada del fork** — todo lo que Paraguay tenía en 2025-10-06 sigue vivo en Ecuador hoy (54 checks cubren y superan esos nombres). Lo que existe es una **brecha de no-incorporación**: 12 checks que Paraguay construyó después y que nunca llegaron a Ecuador porque nunca hubo un segundo intento de sincronización.

---

## 12. Estrategia futura recomendada (no ejecutada)

Dado que:
- no existe ninguna relación Git aprovechable (un `merge`/`rebase` no tiene una base común real que Git pueda usar automáticamente — los historiales son completamente independientes desde el commit raíz);
- las arquitecturas de UI divergieron radicalmente (Ecuador: Tailwind + estructura de pestañas propia; Paraguay: plantilla "Massively" HTML5UP con SASS compilado, 3 idiomas, Pulse);
- el modelo de estados de Ecuador (6 estados) es más preciso que el de Paraguay y **no debería revertirse**;

la recomendación es una **combinación (E)** de:

- **(D) Conservar la arquitectura ecuatoriana** — no tocar `logic/`, `routes/`, el modelo de 6 estados, el motor DNSSEC propio, ni el Observatorio/datasets.
- **(C) Portar manualmente** cada uno de los 12 checks nuevos de Paraguay (dnsviz, w3c, routing, ping/pingv6, starttls, mailipv6, maildnssec, serverbanner, internetnlweb/mail) como nuevos handlers en `logic/adapters/` + entradas nuevas en `groupDefinitions`, reimplementados contra el modelo de 6 estados de Ecuador — **no copiar el código de Paraguay tal cual**, ya que su semántica de estados es distinta y más simple.

**Explícitamente NO recomendado:** (A) merge Git completo (no hay base común real que lo haga seguro) ni (B) cherry-pick de commits (los commits de Paraguay tocan un árbol de archivos completamente distinto — plantilla "Massively" con cientos de archivos de assets — no aplican de forma limpia sobre la estructura de Ecuador).

No se ejecutó ninguna de estas acciones en esta auditoría.

---

*Fin del informe. Todas las cifras de este documento fueron obtenidas por inspección directa de código y `git`/`gh api` — ver los comandos citados en cada sección para reproducir cualquier hallazgo.*
