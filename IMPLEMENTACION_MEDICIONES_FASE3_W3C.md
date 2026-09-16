# Fase 3 — MEDICIONES: check `w3c` (validación HTML W3C/Nu)

Fecha: 2026-09-16. Continúa la Fase 2 (routing/RPKI), cerrada en el
commit `cb4dbad6a38afb9f834f2047adc8f6d3d7c12c1b`. Alcance: exclusivamente
el módulo MEDICIONES (`server.js`, `index.html`, `test/`, `package.json`).
No se tocó DNSSEC independiente, Observatorio, Zonemaster, datasets,
OpenINTEL, administración, blog, eventos ni el runner regional.

Principio aplicado, igual que en Fases 1 y 2: **Paraguay/upstream es
referencia histórica y funcional, nunca especificación normativa.** El
código real de `nicocamarao/mediciones-isoc-lac` se leyó directamente (vía
`gh api`, no el README), y el servicio externo (Nu Html Checker) se probó
en vivo con llamadas reales de solo lectura para confirmar su forma de
respuesta antes de diseñar nada.

## 0. Baseline

```
rama:   main
HEAD:   cb4dbad6a38afb9f834f2047adc8f6d3d7c12c1b
status: sin cambios pendientes de Fase 2; solo los mismos untracked
        pre-existentes y ajenos a esta fase (AUDITORIA_FORK_MEDICIONES.md,
        data/exercises/, PDFs de public/docs/, scripts/exercise-24-domains/,
        scripts/regional-study/input/*.zip)
npm test (antes de tocar nada): 11/11 suites OK, 57 checks, 0 duplicados
```

Ecuador ya tenía un `handleW3C()` en `server.js`, con ruta backend
registrada (`segments[0] === 'w3c'`) pero **sin** entrada en
`groupDefinitions` ni `checkGlossary` ni `case` en `getCheckResult()` —
es decir, existía y respondía, pero era invisible para el usuario final.
Su implementación era mínima: enviaba `doc=https://${domain}` al
validador (sin fallback HTTP, sin manejo de redirecciones, sin guard de
destinos privados) y contaba `warnings = messages.filter(m => m.type !==
'error').length` — cualquier mensaje que no fuera `'error'` se contaba
como aviso, sin distinguir avisos reales de mensajes puramente
informativos.

## 1. Qué mide realmente `w3c` en Paraguay/upstream

Leído el código real (`server.js` línea 4015, `index.html` línea 4879 de
`nicocamarao/mediciones-isoc-lac`).

`handleW3C()` de Paraguay hace **dos cosas distintas y las mezcla**:

1. Llama al validador Nu (`validator.w3.org/nu/?doc=<url>&out=json`) y
   cuenta `errors`/`warnings` de sus mensajes — esto sí es validación real
   de conformidad HTML5.
2. Descarga el HTML por su cuenta (`fetchWebsite`, sin guard de
   destinos privados) y le aplica **17 heurísticas propias basadas en
   expresiones regulares** sobre el HTML crudo: atributo `lang`, `<title>`,
   `alt` en imágenes, etiquetas de formulario, nombre accesible de
   botones/enlaces, jerarquía de encabezados, región `<main>`, `tabindex`
   positivo, `onclick` en elementos no semánticos, `title` en `<iframe>`,
   encabezados de tabla, referencias ARIA rotas, contenido interactivo
   oculto con `aria-hidden`, autoplay con audio, SVG-botón sin nombre.

Y las combina en un solo número:

```js
sendJSON(res, 200, {
  domain,
  errors: errors + scanIssues.length,   // <- suma validación HTML + heurísticas de accesibilidad
  warnings: warnings,
  issues: scanIssues,
  htmlChecked: Boolean(html)
});
```

El frontend de Paraguay (`case 'w3c'`, `index.html:4879`) solo muestra
`Errores: N` / `Avisos: N` — **nunca desglosa `issues`**, así que ese
número mezclado es, para el usuario final, indistinguible: no hay forma
de saber, sin ir directo a la API cruda, cuántos de esos "errores" son
del validador real y cuántos son heurísticas propias no estandarizadas.

**Respuesta directa a la pregunta del paso 2 de la tarea: ¿qué pretende
medir `w3c` en Paraguay?** Pretende medir dos cosas (conformidad HTML +
accesibilidad), pero termina midiendo una sola cosa confusa: un conteo
combinado que no es ni una validación de conformidad limpia ni una
auditoría de accesibilidad real (las heurísticas regex no siguen WCAG, no
usan un motor estándar como axe-core, y pueden dar falsos positivos/
negativos triviales — p. ej. el chequeo de "tablas sin encabezados"
usa un lookahead negativo sobre todo el documento, no por tabla).

## 2. Fuente exacta: Nu Html Checker (validator.w3.org/nu)

Confirmado en vivo (2026-09-16), llamadas reales de solo lectura:

```
GET https://validator.w3.org/nu/?doc=https%3A%2F%2Fexample.com%2F&out=json
-> {"url":"...","version":"26.9.9","messages":[
     {"type":"error","url":"...","message":"The character encoding was not declared..."}
   ]}

GET https://validator.w3.org/nu/?doc=http%3A%2F%2Finfo.cern.ch%2F&out=json
-> messages incluye:
     {"type":"error", ...}                          x4
     {"type":"info","subType":"warning","message":"Consider adding a “lang” attribute..."}

POST https://validator.w3.org/nu/?out=json
Content-Type: text/html; charset=utf-8
<cuerpo HTML directo, sin parámetro doc>
-> funciona igual, devolviendo los mismos mensajes para el HTML enviado.
```

- **No es** el validador clásico "W3C Markup Validator" (`validator.w3.org/check`,
  basado en SGML/DTD) — es el **Nu Html Checker** (`validator.w3.org/nu`),
  el verificador HTML5 mantenido por el WHATWG/Mike Smith y alojado por el
  W3C. Es la herramienta técnicamente correcta hoy para validar HTML5 (el
  validador clásico está deprecado para ese propósito).
- Vocabulario real de `messages[].type`: `'error'` (error de conformidad),
  `'info'` (mensaje informativo; si además trae `subType:'warning'`, es un
  aviso real de conformidad, no un `type` separado), y
  `'non-document-error'` (el validador no pudo procesar el envío por
  completo). **Ni Paraguay ni la versión anterior de Ecuador comprobaban
  `subType`** — ambos contaban cualquier `type !== 'error'` como
  "warning", lo que incluye mensajes puramente informativos sin relación
  con un aviso de conformidad real.
- Acepta tanto `?doc=<url>` (el validador descarga la URL él mismo) como
  envío directo del HTML por `POST` con `Content-Type: text/html` —
  confirmado en vivo, ambos modos devuelven la misma estructura de
  mensajes.
- Sin autenticación, `Access-Control-Allow-Origin: *`, servido detrás de
  Cloudflare. Sin límite de tasa documentado públicamente, pero es un
  servicio comunitario compartido — no apto para volumen alto sin
  cautela (no se le debe pedir más de una validación por check/dominio).
- Sin política de privacidad especial declarada para el contenido
  enviado — es preferible, cuando sea posible, no depender de que el
  validador re-descargue el sitio (ver §6).

## 3. Separación validación HTML vs. accesibilidad (obligatorio, paso 4)

**El servicio Nu solo detecta errores/avisos de marcado (HTML5), no
accesibilidad.** No se afirma en ningún lugar de esta implementación que
pasar la validación HTML equivalga a que el sitio sea accesible. Algunos
mensajes del validador (ej. avisos sobre atributos `alt` faltantes o uso
incorrecto de landmarks) **ayudan indirectamente** a la accesibilidad,
pero eso se documenta como tal en el glossary, nunca como "el sitio es
accesible".

Dato relevante que refuerza esta decisión: **Ecuador ya tiene una señal de
accesibilidad real** en el check `quality` (`handleQuality`, PageSpeed
Insights/Lighthouse — `lighthouse.accessibility?.score`, que internamente
usa axe-core, un motor de accesibilidad estandarizado con reglas basadas
en WCAG). Reimplementar "accesibilidad" con heurísticas regex propias en
`w3c` no solo mezclaría dos preguntas técnicas distintas — sería además
una versión **inferior** de algo que MEDICIONES ya mide mejor en otro
check. Por lo tanto: **`w3c` en Ecuador es exclusivamente validación de
conformidad de marcado HTML5. No contiene ninguna heurística de
accesibilidad propia.**

## 4. Pregunta técnica definida para Ecuador (paso 5)

> ¿El documento HTML principal del sitio (obtenido de forma segura, con
> HTTPS preferido y redirecciones resueltas) presenta errores o avisos de
> conformidad detectables por el validador HTML5 Nu del W3C/WHATWG?

No se usa "¿el sitio cumple con W3C?" — sería impreciso: el check no mide
CSS, no mide ARIA de forma estandarizada, no mide ningún otro estándar
W3C más allá de conformidad de marcado HTML5.

## 5. Arquitectura elegida: obtener el HTML de forma segura y enviarlo al validador (Opción B)

De las opciones planteadas (A: consultar el validador en vivo con
`doc=url`; B: obtener el HTML de forma segura y enviarlo al validador; C:
validador local; D: otra):

- **Opción D (instalar un validador local) descartada**: el propio
  CLAUDE.md del proyecto prohíbe frameworks/dependencias nuevas salvo
  excepción justificada (`dns-packet`/`nodemailer` son las únicas, ambas
  ya evaluadas en fases previas). Empaquetar un motor de validación HTML5
  completo (java + validator.jar, o una librería npm equivalente) sería
  una dependencia pesada e innecesaria cuando existe un servicio público
  ya usado por el propio upstream.
- **Opción A (dejar que el validador descargue la URL) descartada**: el
  validador terminaría decidiendo qué esquema (http/https) usar, cómo
  seguir redirecciones y qué pasa si el destino resuelve a una dirección
  privada — fuera del control y de las políticas de seguridad ya
  existentes en MEDICIONES. Además, enviar `doc=https://dominio.ec` le
  informa al validador (un tercero) exactamente qué dominio se está
  auditando.
- **Opción B — elegida**: se reutiliza `fetchWebsite(domain)`, ya
  existente y usado por `headers`/`sitefeatures`/`socialtags`/etc., que
  internamente aplica `resolveFinalWebTarget` → `fetchSafePage` →
  `resolvePublicAddresses` (bloqueo de IP privada/loopback/link-local/ULA
  en cada salto de redirección, tope de 5 redirecciones, timeout total,
  preferencia HTTPS con fallback HTTP). El HTML resultante se envía como
  **cuerpo `POST`** al validador (`Content-Type: text/html`), nunca por
  parámetro `doc=`. Ventajas verificadas:
  - Reproducible: se valida exactamente el mismo HTML que MEDICIONES
    obtuvo (y cachea) para los demás checks del sitio — no hay una
    segunda descarga independiente con resultado potencialmente distinto.
  - El validador nunca recibe el nombre de dominio ni decide a qué
    destino conectarse — no hay forma de usarlo como vector de SSRF ni de
    filtrarle qué dominio se está midiendo.
  - Reutiliza guardas de seguridad ya probadas, en vez de duplicar lógica
    de red nueva.

## 6. Semántica de resultados

| Estado | Condición | Ejemplo |
|---|---|---|
| PASS | `errors === 0 && warnings === 0` | Documento sin errores ni avisos de conformidad |
| FAIL | `errors > 0` | Al menos un error real de conformidad HTML5 |
| INFO | `errors === 0 && warnings > 0` | Solo avisos, sin errores |
| INCONCLUSIVE | El validador marcó `non-document-error` (no pudo procesar el envío por completo) | El conteo de errores/avisos ya no es fiable |
| NOT_APPLICABLE | El dominio no tiene ningún registro A/AAAA (zona real sin sitio web) | Vía `WEBFETCH_NO_ADDRESS_RECORD`, ya presente en `NOT_APPLICABLE_CODES` |
| MEASUREMENT_ERROR | Sitio inalcanzable, timeout, validador caído, respuesta malformada, cuerpo HTML vacío | Nunca se convierte en FAIL del dominio |

Un fallo del **servicio W3C/Nu** (timeout, 5xx, JSON inválido) nunca se
traduce en FAIL — se distingue con sus propios `error_code`
(`W3C_VALIDATOR_UNAVAILABLE`, `W3C_INVALID_RESPONSE`) que no coinciden
con ningún código de los conjuntos compartidos de
`index.html`/`classifyDataError` (`CERTIFICATE_ERROR_CODES`,
`CONNECTION_REFUSED_CODES`, `EXTERNAL_UNAVAILABLE_CODES`,
`AMBIGUOUS_TRANSPORT_CODES`), así que caen por defecto en
MEASUREMENT_ERROR sin tocar esos conjuntos compartidos (usados por otros
checks) ni su comportamiento.

## 7. Errors vs. warnings vs. info (política final)

Verificado contra la estructura real de respuesta (§2):

```js
const errors = messages.filter(m => m.type === 'error').length;
const warnings = messages.filter(m => m.type === 'info' && m.subType === 'warning').length;
const incomplete = messages.some(m => m.type === 'non-document-error');
```

- `errors > 0` → FAIL.
- `errors === 0 && warnings > 0` → INFO.
- `errors === 0 && warnings === 0` → PASS.
- Mensajes `type:'info'` **sin** `subType:'warning'` (puramente
  informativos) no se cuentan como error ni como aviso — no participan en
  la clasificación, pero sí se listan en el detalle para transparencia.
- Cualquier `non-document-error` fuerza INCONCLUSIVE, sin importar el
  conteo de errores/avisos ya acumulado (ese conteo puede estar
  incompleto si el validador no terminó de procesar el documento).

Esto corrige el comportamiento tanto de Paraguay como de la versión
anterior de Ecuador, donde `warnings = todo lo que no sea 'error'`
contaba también los mensajes puramente informativos.

## 8. URL validada

Se usa el HTML obtenido por `fetchWebsite(domain)`: intenta
`https://dominio` primero, cae a `http://dominio` solo si el intento
HTTPS falla por un error real de transporte (DNS, TLS, conexión
rechazada, timeout — no por un status HTTP de error, que sí se acepta
como medición válida), y sigue redirecciones (máx. 5) reportando la URL
final. La respuesta del check incluye `url` (URL final realmente
validada) y `statusCode` (el status HTTP de esa URL), para que quede claro
qué se validó exactamente — nunca se valida una URL interna aportada por
el usuario: solo el dominio normalizado del propio check, igual que el
resto de MEDICIONES.

## 9. Seguridad / SSRF

- El fetch del HTML reutiliza `fetchWebsite`, que ya aplica
  `resolvePublicAddresses` (bloquea IP privada, loopback, link-local, ULA
  IPv6, CGNAT, multicast) en cada salto de redirección, y `validateUrlPolicy`
  (solo `http`/`https`, solo puertos 80/443). No se agregó código de red
  nuevo para esto — se reutilizó exactamente lo mismo que ya usan
  `headers`/`sitefeatures`/`socialtags`.
- El validador externo nunca recibe una URL ni un nombre de dominio — solo
  bytes de HTML por `POST`. Esto **traslada y elimina** el riesgo de que el
  tercero intente conectarse a algo por cuenta propia: no hay nada a lo
  que pueda conectarse, porque no se le da ninguna URL.
- Verificado con test dedicado (`w3c_destino_privado_bloqueado`): si el
  dominio resuelve a una IP privada, `fetchWebsite` lanza
  `WEBFETCH_BLOCKED_IP` antes de cualquier intento de red hacia el
  validador — el mock de `https.request`/`http.request` para el validador
  lanza si llegara a invocarse, y el test pasa (nunca se invoca).
- Tamaño de respuesta: `fetchSafePage` ya limita el cuerpo descargado a 1MB
  (`DEFAULT_MAX_BODY_BYTES`, preexistente) — ese es el HTML máximo que se
  reenvía al validador, sin cambios.
- Timeout: 15s por defecto en `fetchJSON` para la llamada al validador
  (mismo valor que el resto de servicios externos del proyecto); el fetch
  del sitio hereda el timeout total ya existente de `resolveFinalWebTarget`
  (`DEFAULT_TOTAL_TIMEOUT_MS`, 30s).
- Ninguna entrada de usuario llega a un shell — todo el flujo es HTTP/DNS
  puro (`fetchJSON`/`fetchSafePage`, sin `child_process` en ningún punto
  de esta implementación).

## 10. Frontend

Nombre visible elegido: **"Validación HTML (W3C/Nu)"** (`labelEs`) /
"HTML Validation (W3C/Nu)" (`label`) — se evita deliberadamente cualquier
formulación tipo "Accesibilidad W3C" o "Cumplimiento W3C" genérico, ya que
el check no mide accesibilidad ni todos los estándares W3C.

Glossary (`checkGlossary.w3c`):

> "Obtiene el HTML de la página principal (con el mismo mecanismo seguro
> que otros checks del sitio: HTTPS primero, redirecciones acotadas,
> bloqueo de destinos privados) y lo envía al validador Nu
> (validator.w3.org), el verificador de conformidad HTML5 del W3C/WHATWG.
> Reporta errores y avisos de marcado (etiquetas, atributos, anidamiento).
> No es una auditoría de accesibilidad — para eso, ver el puntaje de
> accesibilidad (Lighthouse) del check "Métricas de calidad"."

Ubicado en el grupo "Contenido y experiencia" (junto a `quality`), por ser
el que mejor encaja de los 6 grupos existentes (no es seguridad/infra
como "Diagnóstico técnico" ni DNS/TLS/correo/cabeceras) — no se creó un
grupo nuevo para un solo check.

## 11. Tests

`test/medicionesW3cCheck.test.js` — 13 casos, sin red real (mocks de
`dns.lookup`, `https.request`/`http.request`, discriminando por forma de
invocación entre el fetch del sitio — `requestPage`, 2 argumentos — y la
llamada al validador — `fetchJSON`, 3 argumentos):

0 errores/0 warnings · 0 errores con warnings reales · con errores ·
mensajes puramente informativos (no cuentan como warning) ·
`non-document-error` (marca `incomplete`) · timeout del validador ·
5xx/respuesta no-JSON del validador · JSON válido sin campo `messages` ·
sitio inexistente (DNS falla) · redirección (se valida la URL final) ·
destino privado bloqueado (verificado que nunca se llama a servicios
externos) · cuerpo HTML vacío · cap de mensajes (55 mensajes reales,
`messagesTotal` correcto, `messages` recortado a 40).

Registrado en `package.json` (`npm test`).

## 12. Comparativo Paraguay vs. Ecuador

| Aspecto | Paraguay | Ecuador (Fase 3) | Razón |
|---|---|---|---|
| Semántica | errors/warnings mezclan validación HTML + heurísticas de accesibilidad propias en un solo número | 6 estados (PASS/FAIL/INFO/INCONCLUSIVE/NOT_APPLICABLE/MEASUREMENT_ERROR), separación estricta | Modelo de estados ya establecido en MEDICIONES Ecuador; evita ocultar la naturaleza mixta del resultado |
| Fuente | `doc=https://dominio` (el validador descarga la URL) | HTML obtenido por Ecuador (`fetchWebsite`, seguro) enviado por `POST` | Reproducibilidad y control total sobre qué bytes se validan |
| Warnings | Cualquier `type !== 'error'` (incluye mensajes puramente informativos) | Solo `type:'info'` + `subType:'warning'` | Verificado en vivo contra la API real; evita sobreconteo |
| Errors | Suma validación HTML + heurísticas de accesibilidad regex | Solo `type:'error'` del validador Nu | Separación estricta pedida (paso 4) |
| Accesibilidad | 17 heurísticas regex propias, no estandarizadas, sumadas a `errors` | Ninguna — se remite al check `quality` (Lighthouse/axe-core, ya real y estandarizado) | Evita duplicar peor una señal que MEDICIONES ya tiene mejor |
| Timeout / proveedor caído | No hay distinción explícita — `unavailable:true` en `index.html` upstream se muestra como INFO | MEASUREMENT_ERROR explícito, nunca FAIL ni INFO silencioso | El modelo de 6 estados de Ecuador exige distinguir "no se pudo medir" de "se midió y no hay hallazgos" |
| Seguridad | `fetchWebsite` propio sin guard de IP privada | Reutiliza `fetchSafePage`/`resolvePublicAddresses` ya existentes | El dominio nunca se envía al validador; destinos privados bloqueados antes de cualquier llamada externa |
| Redirecciones | No documentado/gestionado explícitamente | Seguidas de forma seguro (máx. 5), se reporta la URL final validada | Transparencia sobre qué se validó realmente |
| Mensajes al usuario | Solo el conteo combinado, sin desglose de `issues` | Detalle línea por línea (tipo, línea, mensaje), con cap explícito y conteo total real | Evita opacidad — el usuario ve qué encontró el validador, no solo un número |

## 13. Riesgos y limitaciones restantes

- El HTML se decodifica como UTF-8 en la capa de fetch existente
  (`fetchSafePage`), igual que el resto de checks basados en HTML de
  MEDICIONES — si un sitio real usa una codificación distinta (ej.
  windows-1252, como el propio `example.com` reportó en la prueba en
  vivo), el HTML reenviado al validador podría no coincidir byte a byte
  con el original. Limitación preexistente y compartida por todos los
  checks de contenido HTML del proyecto, no introducida ni corregida en
  esta fase.
- El Nu Html Checker es un servicio comunitario sin SLA formal ni límite
  de tasa documentado — se trata como cualquier otro proveedor externo ya
  usado en MEDICIONES (PageSpeed, Tranco, Wayback, RIPEstat, Cymru): sin
  reintentos agresivos, con timeout de 15s y sin caché propia (una
  llamada por invocación del check).
- No se agregó una caché dedicada para la respuesta del validador (a
  diferencia de `routeCache` en Fase 2): cada invocación de `w3c` hace
  exactamente una llamada al validador, no N llamadas por IP como en
  `rpki`, así que no había el mismo caso de uso para cachear.

## 14. Conclusión

Conteo de checks: **57 → 58** (único check nuevo de esta fase). Suite
completa verde, sin duplicados, `w3c` con ruta backend propia y `case` en
`getCheckResult()`. Ningún módulo fuera de MEDICIONES fue tocado.

## 15. Decisiones consolidadas de Fase 3 (cierre, 2026-09-16)

Validación final realizada antes del commit de cierre. Resume, sin
repetir el detalle ya expuesto arriba, las decisiones que quedan fijadas
para el check `w3c` a partir de este punto.

### Qué hacía Paraguay

`handleW3C()` de upstream combinaba dos mediciones de naturaleza distinta
en un solo número: los `errors`/`warnings` reales del validador Nu **más**
el resultado de 17 heurísticas propias basadas en expresiones regulares
sobre el HTML crudo (atributo `lang`, `alt` en imágenes, jerarquía de
encabezados, landmarks ARIA, `tabindex` positivo, autoplay, etc.):

```js
errors: errors + scanIssues.length   // conformidad HTML + heurísticas de accesibilidad, sumadas
```

El frontend de Paraguay solo mostraba el total combinado, sin desglosar
`issues` — el usuario final no podía distinguir un error real de marcado
de una heurística de accesibilidad no estandarizada.

### Por qué se separó accesibilidad de conformidad

1. Son preguntas técnicas distintas: "¿el HTML es válido según la
   especificación HTML5?" no es lo mismo que "¿el sitio es accesible?".
   Sumarlas en un número oculta cuál de las dos está fallando.
2. Las heurísticas regex de Paraguay no son un estándar reconocido (no
   siguen WCAG, no usan un motor validado como axe-core) — dan una falsa
   sensación de rigor técnico.
3. Ecuador **ya mide accesibilidad real** en el check `quality`
   (PageSpeed Insights/Lighthouse, cuya categoría de accesibilidad usa
   axe-core internamente). Reintentar cubrir accesibilidad en `w3c` con
   heurísticas propias habría sido, además de una mezcla conceptual
   incorrecta, una versión **inferior** de algo que MEDICIONES ya hace
   mejor en otro lugar.

Verificado en el código final (`grep` sobre `server.js`): no existe
ninguna heurística de accesibilidad, `scanIssues`, ni lógica derivada de
las 17 reglas regex de Paraguay — el único resultado de `handleW3C()` es
el conteo de mensajes reales devueltos por el validador Nu.

### Qué hace Ecuador

`w3c` responde exactamente una pregunta: *¿el documento HTML principal
del sitio presenta errores o avisos de conformidad detectables por el
validador HTML5 Nu?* El HTML se obtiene con el mismo mecanismo seguro que
ya usan otros checks del sitio (`fetchWebsite`) y se envía como cuerpo
`POST` al validador — nunca como URL (`doc=`) para que el validador la
descargue por su cuenta.

### Fuente: Nu Html Checker

`validator.w3.org/nu` (WHATWG/W3C), no el validador clásico basado en
DTD/SGML. Confirmado en vivo que acepta tanto `?doc=<url>` como envío
directo por `POST` con `Content-Type: text/html`, devolviendo la misma
estructura de `messages[]` en ambos modos. Sin autenticación, sin límite
de tasa documentado — se trata como cualquier otro proveedor externo ya
integrado en MEDICIONES (mismo nivel de confianza que PageSpeed, Tranco,
RIPEstat, Cymru).

### Clasificación final errors/warnings/info

| `type` | `subType` | Clasificación |
|---|---|---|
| `error` | — | Error de conformidad (cuenta en `errors`) |
| `info` | `warning` | Aviso real de conformidad (cuenta en `warnings`) |
| `info` | (ninguno) | Información no penalizante — se muestra en el detalle, no cuenta ni como error ni como aviso |
| `non-document-error` | — | El validador no pudo procesar el envío por completo — fuerza `incomplete: true`, el conteo de arriba deja de ser confiable |

Confirmado con test dedicado (`w3c_info_puro_no_cuenta_como_warning`) que
un mensaje `type:'info'` sin `subType:'warning'` no incrementa `warnings`
— corrige el comportamiento de Paraguay y de la versión anterior de
Ecuador, donde `warnings = todo lo que no sea 'error'` sí lo contaba.

### Semántica final (6 estados)

PASS (`errors=0, warnings=0`) / INFO (`errors=0, warnings>0`) / FAIL
(`errors>0`) / INCONCLUSIVE (`incomplete=true`, revisado con prioridad
sobre errors/warnings) / NOT_APPLICABLE (zona real delegada sin ningún
registro A/AAAA — `WEBFETCH_NO_ADDRESS_RECORD`) / MEASUREMENT_ERROR
(cualquier otro fallo: sitio inalcanzable, timeout, validador caído,
respuesta malformada, HTML vacío).

**Regla NOT_APPLICABLE, revisada explícitamente en el cierre**: se
apoya en `hasNoAddressRecordAtAll()` (`safeWebFetch.adapter.js`), que
exige `ENODATA` en **ambas** consultas (`dns.resolve4` y `dns.resolve6`)
para reclasificar un `ENOTFOUND` de `dns.lookup` como
`WEBFETCH_NO_ADDRESS_RECORD`. Esto ya distingue correctamente, por código
de resolución DNS y no por heurística:

- **Zona real delegada, sin A/AAAA** (ej. un dominio-paraguas que solo
  aloja subdominios) → `ENODATA` en ambas consultas → `WEBFETCH_NO_ADDRESS_RECORD`
  → **NOT_APPLICABLE**. Correcto: no hay sitio web que validar.
- **Dominio inexistente (NXDOMAIN)** → `dns.resolve4`/`resolve6` fallan
  con `ENOTFOUND`, no `ENODATA` → **no** se reclasifica → queda como
  error genérico → **MEASUREMENT_ERROR**, nunca NOT_APPLICABLE.
- **Fallo temporal de DNS** (SERVFAIL, timeout del resolver) → tampoco es
  `ENODATA` en ambas → **no** se reclasifica → **MEASUREMENT_ERROR**.

La regla ya era correctamente estrecha (reutiliza infraestructura
compartida por muchos otros checks del proyecto, no algo inventado para
`w3c`) — **no requirió corrección**. Sí se detectó y corrigió un hueco de
cobertura de pruebas: el test de "sitio inexistente" solo mockeaba
`dns.lookup`, dejando `dns.resolve4`/`resolve6` sin mockear (dependencia
oculta de red real en un test que debía ser CI-safe). Se agregó
`mockResolve4And6()` y dos tests explícitos — uno para NXDOMAIN real
(`w3c_sitio_inexistente_nxdomain`, confirma que NO se reclasifica) y uno
para zona real sin web (`w3c_zona_real_sin_web_not_applicable`, confirma
que SÍ se reclasifica) — antes de cerrar la fase.

### Seguridad

- Solo `http`/`https` (`validateUrlPolicy`, preexistente).
- Resolución a IP pública obligatoria en cada salto de redirección
  (`resolvePublicAddresses`); privadas/loopback/link-local/ULA IPv6/CGNAT
  bloqueadas — confirmado con test que cubre tanto el destino directo
  como una redirección hacia un destino privado
  (`w3c_redirect_a_privado_bloqueado`, agregado en el cierre): se bloquea
  al resolver el nuevo host, sin llegar nunca a solicitarlo.
- Tope de 5 redirecciones y timeout total de 30s (`resolveFinalWebTarget`,
  preexistente).
- **Límite de tamaño del HTML enviado al validador**: 1 MB
  (`DEFAULT_MAX_BODY_BYTES` en `safeWebFetch.adapter.js`), ya aplicado
  automáticamente por `fetchSafePage`/`requestPage` a cualquier descarga,
  sin código nuevo — el HTML que se reenvía al validador nunca supera ese
  tamaño porque nunca se descargó más que eso en primer lugar. No se
  agregó un límite adicional propio del check: habría sido redundante.
- El validador Nu recibe el HTML por `POST` (`Content-Type: text/html`) —
  nunca la URL/dominio original. No hay forma de que el tercero decida a
  qué destino conectarse.
- Ninguna entrada llega a un shell (confirmado: cero referencias a
  `child_process`/`exec`/`spawn` en el flujo completo de `w3c`).

### Dependencia externa y manejo de fallos

Nu Html Checker es una dependencia externa explícita. Su caída (timeout,
5xx, JSON inválido, `messages` ausente) se traduce en `error_code` propios
(`W3C_VALIDATOR_UNAVAILABLE`, `W3C_INVALID_RESPONSE`) que no coinciden
con ningún código de los conjuntos compartidos de clasificación en
`index.html` — caen por defecto en **MEASUREMENT_ERROR**, nunca en FAIL.
Un 4xx/5xx del validador no produce una respuesta JSON válida con
`messages`, así que `fetchJSON` falla al parsear el cuerpo (o el status
code se ignora y el cuerpo no es JSON) y ese fallo se captura igual como
`W3C_VALIDATOR_UNAVAILABLE`.

### Limitaciones que permanecen

Las mismas documentadas en §13: decodificación asumida UTF-8 (compartida
con el resto de checks HTML del proyecto, no introducida aquí); sin SLA
del proveedor externo; sin caché dedicada para la respuesta del
validador (no hacía falta: una sola llamada por invocación).
