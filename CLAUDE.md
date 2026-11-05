# Contexto del proyecto — Mediciones ISOC LAC

> Portal web de Internet Society LAC. Este archivo da contexto rápido para
> retomar trabajo en este directorio. Arquitectura completa en
> `docs/arquitectura.md` — léelo antes de tocar código si no conoces el
> proyecto.

## Qué hay que saber antes de tocar nada

1. **`validador/validar_dominios_isoc_lac.py` es la referencia metodológica
   y NO se modifica.** Todo el módulo "Preparación de datasets de dominios"
   existe para replicar su comportamiento exacto en JS, no para mejorarlo.
   Si Python y JS difieren, se investiga la causa en el código Python real
   (no se adivina) y se replica — nunca se corrige "porque parece mejor".

2. **Normalización y Validación DNS están cerradas metodológicamente.** No
   cambiar: algoritmo de normalización, IDNA, clasificación PSL, criterios
   VALID/NXDOMAIN/REVIEW, orden de evaluación de `review_subtype`,
   resolvers, timeout, retries, workers, review_wait, CD. Solo tocar si se
   demuestra un bug real y reproducible respecto al validador Python.

3. **Sin frameworks nuevos.** Ni Express, ni librerías de ZIP/test/etc.
   Núcleo de Node + `dns-packet` + `nodemailer` (únicas dos dependencias
   externas — `nodemailer` es una excepción deliberada: envío de
   contraseñas es sensible a bugs sutiles de STARTTLS/codificación como
   para implementarlo a mano). Esta regla es para el código de MEDICIONES
   propiamente — `observatorio-dnssec-v2/` (ver punto 13) es un
   subproyecto aparte, stack Python/Flask, con sus propias reglas en su
   propio `CLAUDE.md` interno; no aplica acá.

4. **Despliegue**: `server1:8700` (Tailscale, home-lab), Docker, y también
   público en `https://mediciones.isoc.org.ec` vía Cloudflare Tunnel. Ver
   comando exacto en `docs/arquitectura.md` § "Cómo desplegar".

5. **Sin base de datos ni persistencia de jobs.** Los jobs de Validación DNS
   y Observatorio viven en memoria (`Map`) — se pierden si el proceso
   reinicia. Decisión aceptada, no un bug. (Blog/Eventos/Materiales SÍ
   persisten en disco — `data/content/*.json` — no son jobs efímeros.)

6. **`.env` nunca se sube por el mismo canal que el código** (tar+scp del
   deploy). Vive solo en `server1:~/projects/MEDICIONES/.env`, fuera de
   `.dockerignore`/`.gitignore`. Contiene credenciales del super_admin y del
   relay SMTP (Brevo) — ver `.env.example` para el esquema completo.

7. **Brevo/Sendinblue: usar `smtp-relay.sendinblue.com`, NO
   `smtp-relay.brevo.com`.** Este último falla con error de certificado TLS
   (verificado contra el relay real) — mismo hallazgo que en otros
   proyectos CORPECE que usan la misma cuenta.

8. **Logos institucionales — ya están en el proyecto, no pedirlos ni
   buscarlos en Descargas.**
   - `public/assets/ISOC_Logo_Dark-RGB.png` — isotipo + wordmark oscuro de
     Internet Society (horizontal, fondo transparente).
   - `public/assets/mediciones_grupo_trabajo.jpeg` — logo del Grupo de
     Trabajo de Mediciones de Internet Society (cuadrado 1024×1024, fondo
     azul, con el ícono ISOC + texto "Grupo de Trabajo de Mediciones de
     Internet" + ícono de barras, todo incrustado en la imagen). Es el
     archivo que el usuario compartió por chat (originalmente en
     `~/Downloads/mediciones_logo.jpeg`, 2026-09-16) — ya copiado acá,
     usar esta ruta siempre que se necesite este logo (portada del PDF de
     reportes, cabecera de `index.html`, etc.), no volver a pedirlo.

## Estado actual (2026-08-14)

Flujo de Preparación de datasets implementado y cerrado:

```
Fuente → Carga → Normalización → Validación DNS → Resultados y descarga
   ✓         ✓          ✓               ✓                  ✓
```

Pendiente explícito (no implementar sin que se pida): **generación de PDF**.

Portal ampliado con Blog, Eventos y Administración:
- Pestañas públicas **BLOG** y **EVENTOS** (antes vivían embebidas en
  Inicio como listas hardcodeadas vacías — ahora son pestañas propias que
  leen de `GET /content/blog` y `/content/events`, solo items publicados).
  La sección "Información" de Inicio (material de capacitación) también
  pasó de un array hardcodeado a `GET /content/materials`.
- Se eliminó la sección "Listas de ccTLD" de Inicio (redundante: reemplazada
  íntegramente por "Preparación de datasets de dominios").
- **`/admin`**: panel de administración con dos roles — `super_admin` (una
  sola cuenta, credenciales en `.env`, puede crear/borrar cuentas `admin`)
  y `admin` (creadas por el super_admin, gestionan Blog/Eventos/Materiales
  pero no usuarios). Contraseñas siempre generadas por el sistema (scrypt)
  y enviadas por correo — nunca se escriben a mano en el panel. Recuperación
  de contraseña vía `/admin/api/forgot-password` (respuesta genérica
  siempre, para no permitir enumerar usuarios).
- Ícono de candado discreto junto a "Acerca de" en Inicio enlaza a `/admin`.

## Comandos esenciales

```bash
# Tests rápidos (CI-safe, sin red — incluye contentStore, adminAuth/sesión/rate-limit, y visibilidad público/admin de extremo a extremo)
npm test

# Generar el hash de una contraseña nueva para ADMIN_PASSWORD_HASH
node scripts/hash-admin-password.js "clave-elegida"

# Tests con red real (manuales, no están en npm test)
node test/rawDns.live.smoke.test.js
node test/dnsDownloads.noDnsCalls.test.js
node test/downloads.integrityGuard.test.js
node test/dnsValidation.live.pythonCompare.js <domains.txt> <validacion_dns.csv de Python>
PULSE_API_KEY=xxxx node test/pulseAdapter.live.smoke.test.js
DNSVIZ_OBSERVATORIO_URL=https://dnssec.corpece.org.ec node test/dnsvizAdapter.live.smoke.test.js

# Chequeo periódico (canario) contra producción real — manual, además de
# correr solo via systemd en server1 (ver punto 17)
node scripts/canary-check.js
ssh server1 "docker exec mediciones node scripts/canary-check.js"

# Levantar local
PORT=3500 node server.js

# Desplegar a server1 (.env NUNCA va en este tar — vive solo en server1)
# 2026-09-16: la lista de directorios a mano (index.html admin.html
# server.js logic routes test ...) llevaba tiempo incompleta — faltaban
# aggregate/, config/, services/ (los tres son dependencias reales de
# server.js vía require(), no opcionales) y, por separado, public/ entero
# (incluye public/i18n.js). Cada gap se coló en silencio: config/services
# quedaron con código DNSSEC ya eliminado localmente (sin fallar ningún
# test — el código muerto no cambia comportamiento observable), y
# public/i18n.js quedó sin las claves del rediseño de Inicio del
# 2026-09-13 — eso sí rompió la UI en vivo (claves crudas en pantalla,
# ej. "inicio.hero.lead"), detectado por el usuario en producción, no por
# ningún test. Cambiado a `git ls-files`: despliega exactamente los
# archivos trackeados en git, así que agregar un directorio nuevo nunca
# vuelve a exigir acordarse de tocar este comando. Requiere que TODO
# archivo de producción esté con `git add` (si algo nuevo no aparece tras
# desplegar, lo primero a revisar es si quedó sin trackear).
git ls-files -z | tar --null -T - -cf - | ssh server1 "tar -xf - -C ~/projects/MEDICIONES"
ssh server1 "cd ~/projects/MEDICIONES && docker compose up -d --build"
ssh server1 "docker exec mediciones npm test"
```

## Convención de testing en este proyecto

- Sin framework de test (no jest/mocha). Scripts planos con `assert` de Node,
  ejecutables directo con `node test/archivo.js`.
- Para verificar equivalencia con Python: capturar valores reales
  ejecutando el validador (`importlib.util.spec_from_file_location` +
  registrar en `sys.modules` antes de `exec_module`, necesario por
  `@dataclass` + `from __future__ import annotations`), nunca asumir el
  comportamiento por lectura del código.
- Para probar "no hay nuevas consultas DNS": instrumentar (spy/contador)
  la función real (`dnsQuery` en `rawDns.adapter.js`), no medir tiempos de
  respuesta como evidencia principal.
- Para probar salvaguardas (integridad, etc.): ejercitarlas con datos
  fabricados a mano llamando directo a la función, no solo confiar en que
  "nunca debería pasar".

## Regresión obligatoria tras cualquier cambio de frontend

Playwright headless, desktop (1280px), tablet (768px) y mobile (375px),
sobre las 7 pestañas del portal (Inicio, Preparación, Mediciones, DNSSEC,
Observatorio, Blog, Eventos) y sobre `/admin`: cero overflow horizontal,
cero errores de consola. Los scripts de prueba usados durante el
desarrollo quedaron en el scratchpad de sesión, no en el repo — si hace
falta reproducir el patrón, ver `docs/arquitectura.md`.

9. **GED2026 ya no vive acá.** El módulo del Global Encryption Day
   Ecuador 2026 (universo de dominios candidatos, liveness, panel admin,
   API pública) se separó a su propio proyecto/repo el 2026-09-23 —
   `C:\PROJECTS\MEDICIONES-ged2026`, desplegado en `server1:8601`, con su
   propia autenticación (no comparte sesión con MEDICIONES). Los 354
   dominios reales se migraron ahí (verificado conteo por conteo contra
   `GET /ged2026/api/v1/summary` antes/después). No queda código ni ruta
   de GED2026 en este repositorio — si algo lo referencia, es una
   mención histórica de una fase anterior, no algo para editar acá.
   **Su avance es trabajo propio, no de un tercero.** El 2026-09-23 se
   hicieron allá la muestra (100 selected / 23 excluded sobre 366), los
   Snapshots WEB (`GED2026-WEB-RUN-002`) y MAIL (`GED2026-MAIL-RUN-001`,
   STARTTLS "No medido"), la fase `analysis` y el portal isoc.org.ec.
   `mediciones.isoc.org.ec` solo expone sus 4 rutas de API
   (`/ged2026/api/v1/{summary,results,results/web,results/mail}`), por una
   regla exacta del túnel que va ANTES de la regla general. No tocarla desde acá.

10. **Base de Conocimiento DNSSEC ("Aprender DNSSEC") — implementada y en
    producción desde 2026-09-27** (commit `299ffc4`, desplegado y validado
    en `https://mediciones.isoc.org.ec`). Vive dentro del tab DNSSEC como
    sub-navegación "Analizar dominio | Aprender DNSSEC", sin tocar el
    analizador existente. Arquitectura:
    - `public/dnssecKb.content.js` — contenido editorial (20 guías +
      Glosario + Referencias y estándares = 22 páginas), categorías,
      diagramas HTML/CSS. Fuente única de verdad del contenido.
    - `public/dnssecKb.js` — toda la lógica (landing, buscador tolerante a
      acentos sin librería, filtros de nivel, render de guía, TOC con
      `IntersectionObserver` para active-state, prev/next, hash-routing
      propio `#/dnssec/aprender/<slug>`). Expone un único global,
      `window.DnssecKb`, para no ensuciar `window`.
    - `public/dnssecKb.css` — única regla propia: `.dnssec-kb-toc-desktop-wrap`
      (el TOC de escritorio necesita esta clase dedicada porque
      `.hidden{display:none!important}` del sitio le gana en cascada a
      `hidden md:block` de Tailwind — no volver a usar esa combinación ahí).
    - Enlaces contextuales "ⓘ" desde `renderDnssecInlineResult` (el
      renderer del analizador, en `index.html`) hacia guías concretas —
      vía `DnssecKb.infoLink(slug, label)`, sin tocar la lógica de datos
      del analizador.
    - Aislamiento de fallos: el wireup de `hashchange` al final de
      `index.html` comprueba `if (window.DnssecKb)` antes de invocarlo —
      si este módulo no carga, el analizador (individual y batch) sigue
      funcionando igual.
    - Cache-busting: los 3 assets (`dnssecKb.js`, `.content.js`, `.css`)
      se versionan con el mismo mecanismo de `i18n.js`
      (`logic/adapters/i18nVersion.adapter.js`, ahora generalizado a una
      lista `VERSIONED_ASSETS` en vez de un solo archivo hardcodeado).
    - Tests: `test/dnssecKb.content.test.js` (integridad del contenido:
      22 guías, sin slugs duplicados, enlaces internos válidos, RFC/IANA
      obligatorios presentes) y `test/dnssecKb.module.test.js`
      (estructura del módulo: IIFE única, un solo global, API esperada,
      `index.html` libre de la lógica extraída).
    - No tocar sin razón: la taxonomía de 7 estados
      (`config/dnssec.constants.js`), el motor (`dnssec.rules.js`/
      `dnssec.service.js`), ni el contenido editorial de las 22 guías
      salvo error real y reproducible.

## Archivos que NO están conectados (código muerto conocido)

`routes/dnssec.routes.js` usa Express y no lo requiere nadie — `server.js`
reimplementa esa lógica inline. No confundir al buscar dónde editar
`/dnssec-analysis`.

## Deploy — nota operativa 2026-09-27

El comando de deploy en `docs/arquitectura.md` § "Cómo desplegar" quedó
desactualizado (lista archivos a mano) — el comando **vigente** es el de
este archivo, arriba, con `git ls-files` (más robusto, ver comentario
2026-09-16 junto al comando).

(2026-09-27 → ya no aplica desde 2026-11-04) Durante un tiempo el deploy
reportaba errores no bloqueantes de `tar` sobre
`DNSLab/local/lab/zones/keys/**` (permisos restrictivos de fixtures de un
laboratorio DNSSEC de pruebas). **DNSLab se eliminó por completo el
2026-11-04** (ver punto 11 más abajo) — ese módulo, y por lo tanto ese
error de deploy, ya no existen. Si alguna vez vuelve a aparecer un error
similar de `tar` sobre otro directorio, el principio general sigue
valiendo: GNU tar sigue extrayendo el resto del stream tras un error por
archivo y recién falla (`exit 2`) al final, así que no corta la
transferencia de los demás archivos — confirmar por `md5sum` los archivos
que sí importan antes de asumir que el deploy falló completo.

11. **DNSLab se eliminó por completo el 2026-11-04** — a pedido explícito
    del usuario, tras confirmar que todas sus fases estaban técnicamente
    cerradas y sin trabajo activo desde 2026-09-25. Se borró del repo
    local, del directorio en `server1` (`~/projects/MEDICIONES/DNSLab/`,
    incluyendo volúmenes Docker y los 7 timers `systemd --user` que
    corrían su observabilidad/backups/reportes), y **del historial
    completo de git** (reescrito con `git filter-repo` antes del primer
    `git push` de este repo a GitHub — nunca llegó a existir públicamente).
    Si algo en el código o en commits viejos lo menciona, es una mención
    histórica de una fase ya cerrada, no algo para editar o recuperar acá.
    Backup completo (con datos de runtime) fuera de este repo, por si
    hiciera falta en el futuro: `C:\PROJECTS\OBSERVA\observatorio-dnssec-v2_backup_20261104T193536Z.zip`
    (ese nombre es por un backup distinto, ver punto 13 — el backup real de
    DNSLab vive en los backups de `server1:~/backups/dnslab*` que no se
    tocaron).

12. **Integración con ISOC Pulse (API oficial) — en producción desde
    2026-11-04.** `logic/adapters/pulse.adapter.js` consulta
    `pulse-api.internetsociety.org` (Bearer token en `PULSE_API_KEY`,
    nunca scraping) y expone una ruta `/pulse-context?domain=` que
    MEDICIONES usa para mostrar, junto al análisis DNSSEC, cobertura ROA
    real del país y si el ccTLD está firmado a nivel nacional. Aislado por
    diseño: sin `PULSE_API_KEY` configurada, o ante cualquier fallo del
    servicio, la tarjeta simplemente no se muestra — nunca afecta el
    análisis del dominio. Caché de 24h (los datos de Pulse tienen varios
    días de rezago real, confirmado en vivo). Tests:
    `test/pulseAdapter.test.js` (simulado) y
    `test/pulseAdapter.live.smoke.test.js` (manual, red real).

13. **Observatorio DNSSEC v2 — importado como subproyecto aislado el
    2026-11-04**, en `observatorio-dnssec-v2/` (stack Python/Flask, NO
    Node — propio `CLAUDE.md` interno con sus reglas de aislamiento).
    Desarrollado por ISOC Ecuador/CORPECE, originalmente solo en
    `C:\PROJECTS\OBSERVA\observatorio-dnssec-v2` (sin control de
    versiones) y desplegado en `https://dnssec.corpece.org.ec` (Google
    Cloud Run, proyecto `observatorio-dnssec` — **no `server1`**, porque
    `server1` no tiene IPv6 pública real y esta herramienta la necesita
    para que `dnsviz` evalúe correctamente). Se importó tal cual (commit
    de línea base, sin modificar su contenido) para: (a) darle control de
    versiones real por primera vez, y (b) poder integrarlo con el motor
    DNSSEC de MEDICIONES — ver punto 14. Backup completo pre-importación
    (incluye datos de runtime excluidos del repo por `.gitignore`):
    `C:\PROJECTS\OBSERVA\observatorio-dnssec-v2_backup_20261104T193536Z.zip`.
    Tag de git `pre-import-observatorio-dnssec-v2` marca el commit justo
    antes de esta importación, por si hiciera falta revertir.
    **Pendiente real, no resuelto todavía:** la producción en Cloud Run
    sigue en el despliegue de mayo 2026; el rediseño completo (6 fases,
    `observatorio-dnssec-v2/REPORTE-FINAL.md`) que se importó acá nunca se
    publicó ahí — son versiones distintas del mismo subproyecto. También
    pendiente: la cuenta de facturación de ese proyecto GCP se había
    cerrado por tarjeta vencida (reabierta el mismo día) — los créditos de
    Google for Nonprofits para Cloud se empezaron a tramitar pero no se
    completaron.

14. **Validación real de firma DNSSEC (DNSViz) — conectada como
    verificación OPCIONAL, nunca por defecto.** `dnsviz` real tarda 60-90s
    por dominio (medido: 74s para isoc.org) — conectarlo al camino rápido
    del analizador habría sido una regresión de UX, no una mejora. Se
    expone vía `?dnsviz=1` en `/dnssec-analysis` (ver `server.js`,
    `logic/adapters/dnsviz.adapter.js`), que llama al Observatorio DNSSEC
    v2 (punto 13) y extrae, de su respuesta PÚBLICA (`structured_view`,
    no el veredicto SECURE/INSECURE/BOGUS interno, que esa API no
    expone), si hay un fallo criptográfico real en la zona exacta del
    dominio — replicando fielmente (incluida la exclusión de códigos
    operativos como `UNABLE_TO_RETRIEVE_DNSSEC_RECORDS`, que si no se
    excluye da un falso positivo por matchear la subcadena "DS") la
    clasificación `CRYPTO_DNSSEC_HINTS` del propio Observatorio. Si esa
    evidencia contradice un veredicto que de otro modo sería `ok`, baja a
    `misconfigured`. **`logic/rules/dnssec.rules.js` recibió un 5º
    parámetro opcional (`dnsvizSignal`) para esto — sigue siendo una
    función pura, sin I/O, con no-regresión explícita probada en
    `test/dnssecRules.test.js` cuando el parámetro se omite.** En la UI
    (`index.html`, tab DNSSEC → "Un dominio"): elección obligatoria Sí/No
    antes de habilitar "Analizar DNSSEC", y un modal de progreso
    bloqueante con botón Cancelar real (`AbortController`) — ver punto 15.

15. **Modal de progreso genérico, por tiempo transcurrido, no por tipo de
    análisis.** `showModalIfSlow(modalId, delayMs=30000)` en `index.html`:
    muestra un modal centrado y bloqueante SOLO si la operación no
    terminó a los 30s (por defecto), en vez de decidir de antemano "este
    tipo de análisis es lento, mostrar siempre". Usado tanto por el
    análisis DNSSEC individual (punto 14) como por el batch de Mediciones
    — un análisis rápido nunca lo ve; cualquiera que se demore (por el
    motivo que sea) lo dispara solo.

16. **Bug real corregido (2026-11-04): falta de `User-Agent` en llamadas
    salientes causaba bloqueos 429 de WAFs (Cloudflare) de terceros,
    reportados incorrectamente como falla del dominio medido.**
    Descubierto con `isoc.org.ec` (HTTPS daba "fail" — en realidad era
    `INCONCLUSIVE` por un 429, pero igual era un bug real: nuestro propio
    cliente HTTP, sin User-Agent, era tratado como bot). Corregido en
    `logic/adapters/safeWebFetch.adapter.js` (`requestPage`, afecta a los
    ~12 checks de `handleHeaders`) y en `server.js`
    (`fetchText`/`fetchPage`, por consistencia con `fetchJSON`, que ya
    tenía el default). Auditado el resto del sistema (DoH/DNS crudo,
    RIPEstat/Cymru, RDAP, Pulse/DNSViz, PSL, URLhaus, servicio interno
    MDTOPDF) — no quedan más puntos de este mismo defecto. Test de
    regresión en `test/safeWebFetch.adapter.test.js` que intercepta la
    llamada real a `http.request()` (no el mock inyectado) para confirmar
    que siempre se envía un User-Agent no vacío.

17. **Chequeo periódico ("canario") del sistema real en producción —
    `scripts/canary-check.js`, desde 2026-11-04.** No reemplaza `npm test`
    (que valida lógica con datos simulados, sin red) — este corre contra
    la API real en vivo, el único tipo de prueba capaz de haber detectado
    el bug del punto 16 antes de que un usuario lo reportara. 6 casos con
    resultado esperado documentado (HTTPS de isoc.org.ec, WHOIS, hosts
    asociados, DNSSEC de isoc.org, contexto Pulse, salud del Observatorio
    DNSSEC v2). Corre vía `systemd --user timer` en `server1`
    (`mediciones-canary.timer`/`.service`), una vez al día a las 22:00
    hora Ecuador (`03:00 UTC` — `server1` corre en UTC), con `flock` para
    evitar solaparse consigo mismo. Si algo falla, envía un correo real
    (reusa el SMTP de Brevo ya configurado) a `CANARY_ALERT_EMAIL`
    (fallback: `SUPER_ADMIN_RECOVERY_EMAIL`), asunto `ALERTA MEDICIONES`.
    Se corre `docker exec mediciones node scripts/canary-check.js` —
    requiere que el contenedor esté construido con esta versión del
    código (rebuild, no solo copiar archivos).
