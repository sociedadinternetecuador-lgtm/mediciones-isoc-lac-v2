# Auditoría y fortalecimiento conservador del core DNSSEC Ecuador

Fecha: 2026-09-16. Continúa la auditoría previa
(`AUDITORIA_DNSSEC_ECUADOR_METODOLOGIA_MOTOR.md`). Alcance:
exclusivamente el core DNSSEC independiente de Ecuador (ver lista de
archivos en §1). No se tocó MEDICIONES, Observatorio, Zonemaster,
datasets ni ningún otro módulo.

Principio rector de esta fase (explícito del usuario): el módulo debe
**conservar su identidad y alcance funcional actuales**. Solo se
corrigen errores objetivos, se elimina código muerto confirmado, se crea
cobertura de tests, y se mejora documentación — **sin rediseño
funcional, sin nuevas métricas, sin nuevos estados, sin ampliar el
alcance del motor**.

## 0. Baseline

```
rama:   main
HEAD:   da7f95439e9b091a3dbbbcba22c8a710a3ee9599
status: sin cambios pendientes de fases anteriores; solo los mismos
        untracked pre-existentes y ajenos (AUDITORIA_FORK_MEDICIONES.md,
        data/exercises/, PDFs de public/docs/, scripts/exercise-24-domains/,
        scripts/regional-study/input/*.zip) más
        AUDITORIA_DNSSEC_ECUADOR_METODOLOGIA_MOTOR.md (auditoría previa,
        sin código)
npm test (antes de tocar nada): 15/15 suites OK, 60 checks MEDICIONES,
        0 tests DNSSEC (no existían)
```

## 1. Archivos exactos del core DNSSEC (confirmados, sin cambio respecto
## a la auditoría previa)

- `services/dnssec.service.js`
- `logic/rules/dnssec.rules.js`
- `logic/processors/dnssec.processor.js`
- `logic/builders/zoneChain.builder.js`
- `logic/builders/delegation.builder.js`
- `logic/adapters/dns/realDns.adapter.js`
- `config/dnssec.constants.js`
- `logic/content/dnssecGuidance.content.js`
- `logic/content/dnssecGlossary.content.js`
- `logic/validators/domain.validator.js`
- `server.js` — únicamente el bloque `/dnssec-analysis` y
  `renderDnssecHtml()`/funciones de mapeo asociadas (no el resto del
  archivo, que pertenece a MEDICIONES)

Fuera de scope (confirmado, sin tocar): `dnssecGoogle()`/`handleDnssec()`
(código heredado del fork de Paraguay, huérfano), `routes/dnssec.routes.js`
(Express sin usar), MEDICIONES (60 checks), Observatorio/`aggregate/`,
Zonemaster, datasets.

## 2. Definición del core (congelada)

> El módulo DNSSEC Ecuador realiza un diagnóstico estructural de la
> cadena DNSSEC de un dominio mediante evidencia DS/DNSKEY y respuestas
> de un resolver validante, y presenta ese diagnóstico de forma
> explicable al usuario. No pretende ser una implementación completa del
> motor criptográfico de DNSViz.

Esta definición no se modificó durante la fase — se documenta ahora
formalmente en `docs/metodologia-dnssec.md`.

## 3. Los 7 estados — permanecen exactamente iguales

Revisados uno por uno (regla, precedencia, inputs, alcanzabilidad,
solapamiento, riesgos) en `AUDITORIA_DNSSEC_ECUADOR_METODOLOGIA_MOTOR.md`
§4 y verificados ahora con tests ejecutables
(`test/dnssecRules.test.js`). **No se modificó ninguna regla, ningún
nombre, ningún orden de precedencia.** Los 7 estados y sus condiciones
son idénticos a los documentados en la auditoría previa:

`ok` · `not_implemented` · `blocked_at_tld` · `blocked_at_parent` ·
`misconfigured` · `non_existent` · `indeterminate`.

Confirmado por test que son mutuamente excluyentes (cada fixture produce
exactamente el estado esperado) y que cubren el espacio de entradas (el
`fallback` a `indeterminate` garantiza una salida ante cualquier
combinación no anticipada).

## 4. `ready` — código muerto confirmado y eliminado

Confirmado, antes de tocar nada, que `DNSSEC_FINAL_STATUS.READY` ("ready")
**nunca era producido** por `computeDnssecConclusion()`:

```
$ grep -rn "DNSSEC_FINAL_STATUS.READY|\"ready\"" services/ logic/ config/ server.js index.html
logic/content/dnssecGuidance.content.js:47:    case "ready":
config/dnssec.constants.js:3:  READY: "ready",
```

Solo 2 referencias en todo el repositorio, ninguna en la lógica de
clasificación real. Se eliminó limpiamente:

- `config/dnssec.constants.js`: se quitó `READY: "ready"` de
  `DNSSEC_FINAL_STATUS` (queda con exactamente 7 valores).
- `logic/content/dnssecGuidance.content.js`: se eliminó el bloque
  `case "ready": { ... }` completo (25 líneas).
- `logic/content/dnssecGlossary.content.js`: no tenía ningún caso
  `"ready"` — nada que eliminar ahí.
- `server.js` (`mapDisplayTitle`/`mapTechnicalStatus`/`getStatusBadge`):
  tampoco tenían caso `"ready"` — nada que eliminar ahí tampoco.

No se sustituyó por ningún estado nuevo (explícitamente prohibido por el
alcance de esta fase). Verificado con test
(`test/dnssecContent.test.js`, `test/dnssecRules.test.js`) que:
- `DNSSEC_FINAL_STATUS` tiene exactamente 7 valores.
- `getDnssecGuidance('ready')` ahora cae al bloque `default` genérico
  (comportamiento correcto: nunca se le pedirá guía para "ready" en
  producción porque el motor nunca lo produce; el fallback es solo una
  red de seguridad para un valor inesperado).

## 5. AD / extended_dns_errors / Comment — solo documentados, no incorporados

Confirmado en vivo (auditoría previa) que Google DoH expone estos campos
en cada respuesta. **No se modificó `realDns.adapter.js` para leerlos.**
Por decisión explícita de esta fase conservadora, quedan únicamente
documentados como posible mejora futura en `docs/metodologia-dnssec.md`
(sección "Posibles funciones adicionales futuras") — su incorporación
podría, en el futuro, enriquecer únicamente el texto explicativo
(`technical_summary`) sin cambiar ningún `final_status`, pero eso queda
fuera de esta fase.

## 6. Nuevas métricas — ninguna incorporada

No se agregó algoritmo, digest, key tag, expiración, RRSIG ni NSEC/NSEC3
como evaluaciones del motor. Se identificaron como posibles mejoras
futuras (inspiradas en, pero no copiadas de, la implementación de
Paraguay) y quedan listadas en `docs/metodologia-dnssec.md`, sin ningún
cambio de código asociado.

## 7. IDNA — corrección objetiva aplicada

**Bug confirmado antes de corregir** (no se asumió, se reprodujo):

```js
validateDomainInput('café.com')
// -> Error: Dominio inválido (INVALID_DOMAIN)
// mientras que validateDomainInput('xn--caf-dma.com') (mismo dominio, ya
// en punycode) sí se aceptaba.
```

Causa: `sanitizeDomain()` no aplicaba ninguna conversión IDNA antes de
que `isLikelyValidDomain()` exigiera `[a-z0-9-]` por etiqueta — un
dominio internacionalizado legítimo, en su forma Unicode natural, se
rechazaba.

**Corrección aplicada** (`logic/validators/domain.validator.js`): se
agregó `const { domainToASCII } = require("url");` y se aplica
`domain = domainToASCII(domain);` al final de `sanitizeDomain()`, después
de quitar esquema/ruta/punto final y antes de retornar — mecanismo nativo
de Node (mismo que ya usa `server.js` para MEDICIONES), sin lógica IDNA
artesanal. Un dominio ya en ASCII queda idéntico (`domainToASCII` es
identidad para ASCII); una entrada que ni siquiera es un hostname
parseable sigue rechazándose igual que antes (`domainToASCII` devuelve
`""`, que el `|| null` ya existente convierte en rechazo).

Verificado con test (`test/dnssecDomainValidator.test.js`, 5 casos):
dominio Unicode aceptado y convertido, punycode ya convertido aceptado
igual (idempotente), dominios ASCII normales sin cambio de comportamiento,
entradas inválidas siguen rechazadas.

Esto **no amplía el alcance del motor** — corrige la aceptación de una
entrada de dominio válida, exactamente como pidió el alcance de esta
fase.

## 8. Google Public DNS como fuente única — confirmado, documentado

Confirmado (otra vez, por lectura completa de `realDns.adapter.js`, sin
cambios): el motor usa exclusivamente `https://dns.google/resolve`. No se
agregó Cloudflare ni ningún otro resolver. Esto se documenta ahora
explícitamente en `docs/metodologia-dnssec.md` (antes solo se sabía por
lectura de código, no estaba declarado en ningún documento ni en la UI).

## 9-11. Tests — objetivo principal de esta fase

**34 tests en total, en 4 archivos** (26 de la auditoría conservadora +
8 nuevos de la corrección de niveles intermedios, ver §18), ninguno
depende de DNS real (mocks de
`https.get` con fixtures que replican el formato real de Google DoH,
verificado en vivo en la auditoría previa):

- `test/dnssecRules.test.js` (13 casos) — motor de clasificación puro
  (`computeDnssecConclusion`), sin I/O: los 7 estados aislados + casos
  límite (DS sin DNSKEY, DNSKEY sin DS, SERVFAIL con DS presente,
  SERVFAIL sin DS suficiente → indeterminate, sin zonas, cadena de 4
  niveles con zona intermedia rota — comportamiento actual documentado,
  no corregido) + confirmación de que `ready` ya no es producible.
- `test/dnssecService.test.js` (4 casos) — orquestación de extremo a
  extremo (`getDnssecAnalysis`) con Google DoH mockeado: escenario `ok`,
  `non_existent`, `indeterminate` por timeout real, y SERVFAIL con DS
  presente confirmando `confidence: "high"`.
- `test/dnssecDomainValidator.test.js` (5 casos) — corrección IDNA +
  comportamiento existente sin cambios.
- `test/dnssecContent.test.js` (4 casos) — confirma que los 7 estados
  alcanzables tienen guía/glosario completos y que `"ready"` cae
  correctamente al `default` genérico.

Registrados en `package.json` (`npm test`). Suite completa del proyecto:
**18 archivos de test, 60 checks MEDICIONES (sin cambio), 0 duplicados,
34/34 casos DNSSEC en verde**.

## 12. SERVFAIL — comportamiento verificado, sin cambios

Confirmado con tests dedicados que la regla actual es correcta y no se
modificó:
- SERVFAIL **con** DS presente (evidencia estructural de fallo) →
  `misconfigured` (`estado_misconfigured_servfail_con_ds`).
- SERVFAIL **sin** DS presente (sin evidencia suficiente) →
  `indeterminate`, nunca se fuerza una lectura DNSSEC
  (`estado_indeterminate_servfail_sin_ds`). SERVFAIL es un "error duro"
  evaluado antes que cualquier regla estructural — por diseño, ya
  correcto, no requirió corrección.

## 13. Indicador de confianza — verificado, sin cambios

Confirmado con tests (`service_e2e_ok` → `high`,
`service_e2e_indeterminate_timeout` → `low`,
`service_e2e_servfail_con_ds_confidence_alta` → `high`) que:
- Mide confianza en el diagnóstico, no seguridad del dominio.
- Su cálculo corresponde a evidencia real ya calculada por el propio
  motor (no introduce una fuente nueva).
- El texto que lo acompaña (`mapConfidenceDescription` en `server.js`) ya
  aclara correctamente la distinción — no se encontró contradicción
  textual que corregir.

**No se modificó** `computeConfidence()` ni su texto.

## 14. Metodología

Creado `docs/metodologia-dnssec.md` — documento consolidado con
objetivo, alcance, fuente (Google Public DNS, resolver único), flujo, los
7 estados, indicador de confianza, limitaciones declaradas, qué no mide,
sección explícita "Fuera de alcance del core", y sección "Posibles
funciones adicionales futuras" (AD/EDE, algoritmo/digest, RRSIG,
NSEC/NSEC3, multi-resolver, multi-autoritativo, visualización) —
ninguna implementada, todas explícitamente fuera del core actual.

## 15. Comparación con DNSViz y con Paraguay

Sin cambios respecto a `AUDITORIA_DNSSEC_ECUADOR_METODOLOGIA_MOTOR.md`
§6-§7 — se referencian aquí, no se repiten. Ninguna capacidad de DNSViz
ni de Paraguay se incorporó al core en esta fase; todas quedan en la
sección "funciones adicionales futuras" de `docs/metodologia-dnssec.md`.

## 16. Validación final

```
npm test
-> 18/18 archivos de test OK
-> 60 checks MEDICIONES, 0 duplicados (sin cambio)
-> 34/34 tests DNSSEC en verde (26 de la auditoría conservadora + 8 de
   la corrección de niveles intermedios, §18)
-> smoke test manual: GET /dnssec-analysis?domain=example.com
   JSON: final_status=ok, confidence=high  (sin cambio)
-> smoke test manual: GET /dnssec-analysis?domain=dnssec-failed.org
   JSON: final_status=misconfigured, confidence=high  (sin cambio)
   HTML: HTTP 200, <title>Análisis DNSSEC - example.com</title>
```

Comportamiento funcional equivalente al anterior, con las dos
correcciones objetivas documentadas (eliminación de `ready` muerto,
corrección IDNA) — ningún cambio de alcance.

## 17. Riesgos/limitaciones que permanecen (no corregidas, por diseño de esta fase)

- El motor sigue sin usar `AD`/`extended_dns_errors` (documentado como
  mejora futura, no corregido).
- El motor sigue usando un único resolver (decisión de alcance, no un
  defecto).
- **Hallazgo nuevo, menor, detectado al construir el test del escenario F
  (§18) — no corregido, fuera de alcance de esta microfase**: en
  `services/dnssec.service.js`, `secure` se calcula como `ds.found ===
  true` y se pasa como ambos argumentos (`secure` y `dsPresent`) a
  `mapDelegationStatus(secure, dsPresent, queryStatus)` (función definida
  en `services/dnssec.service.js`) — como ambos valores son literalmente
  el mismo booleano en la
  orquestación real, la rama `BROKEN` de `mapDelegationStatus` (`dsPresent
  === true && secure === false`) nunca se produce hoy a través del flujo
  real basado en DoH; solo se ejercitó aquí construyendo el fixture a mano
  para probar que `dnssec.rules.js` maneja correctamente ese estado si
  llegara a recibirlo. No se modificó `dnssec.service.js` — es un hallazgo
  distinto al de zonas intermedias, y corregirlo (verificar
  correspondencia real DS↔DNSKEY) ampliaría el alcance del motor
  (cripto-validación), algo explícitamente fuera de esta fase.

  **Pendiente técnico registrado, sin resolver**:
  `mapDelegationStatus -> BROKEN parece no alcanzable mediante el flujo
  DoH actual.` No se ha demostrado que esto produzca ninguna
  clasificación incorrecta hoy (la rama simplemente nunca se ejercita en
  producción) — no es, por sí solo, evidencia de un bug. Requiere una
  auditoría separada, independiente de esta fase, antes de decidir si se
  elimina (si de verdad es inalcanzable por diseño) o se activa (si
  debería poder producirse y hoy no lo hace por otro motivo). No se
  modifica en esta fase.

## 18. Corrección aplicada: rupturas en niveles intermedios de la cadena

**Causa exacta confirmada** (antes de corregir, no asumida):
`computeDnssecConclusion()` solo derivaba `tldZone` (`zoneList[0]`),
`parentZone` (`zoneList[length-2]`, el padre INMEDIATO) y `lastDelegation`
(`delegationList[length-1]`, la delegación padre→dominio) — cualquier
zona en `zoneList[1..length-3]` o delegación en
`delegationList[0..length-3]` (es decir, todo lo que está estrictamente
entre el TLD y el padre inmediato) nunca se leía en ninguna regla de
clasificación. La única excepción era el chequeo de errores duros
(`hasHardErrors`), que sí recorre `zoneList`/`delegationList` completos —
por eso un timeout/error de red en un nivel intermedio SÍ se detectaba
correctamente incluso antes de esta corrección; lo que no se detectaba
era una ruptura *estructural* (zona sin firmar, delegación insegura/rota)
en un nivel intermedio.

**¿Bug real o solo limitación documental?** Bug real, confirmado con
evidencia: una cadena de 4 niveles con una zona intermedia sin firmar
(pero con el propio dominio y su padre inmediato luciendo correctos)
se clasificaba `ok` — una falsa confirmación de que la cadena de
confianza es válida, cuando en realidad un resolver validador real
nunca podría completarla (verificado antes de corregir, con el test que
existía en la fase anterior, que documentaba exactamente ese resultado
incorrecto).

**Corrección aplicada** (`logic/rules/dnssec.rules.js`, cambio mínimo):
se agregaron `ancestorZones` (zonas estrictamente entre TLD y padre
inmediato) y `ancestorDelegations` (delegaciones excluyendo solo la
última) y dos nuevas reglas, insertadas en la secuencia existente sin
tocar ninguna regla previa:

- Si alguna zona/delegación ancestro está claramente rota (zona
  `unsigned`, delegación `insecure`/`broken`) → **`blocked_at_parent`**
  (mismo estado ya existente, reutilizado con su misma semántica: "un
  enlace externo al propio dominio, fuera de su control, bloquea la
  cadena" — generalizado de "solo el padre inmediato" a "cualquier
  ancestro"). Se reporta la zona/delegación más cercana al TLD (causa
  raíz más útil).
- Si alguna zona/delegación ancestro tiene evidencia ambigua (`unknown`,
  sin ser ya un error duro) → **`indeterminate`** (mismo estado
  existente) — nunca se fuerza "ok" con una incertidumbre ancestro sin
  resolver.

**No se creó ningún estado nuevo.** Los 7 estados y todas las reglas
preexistentes quedan exactamente iguales; solo se agregaron dos
condiciones nuevas evaluadas antes de la regla "ok", usando los mismos
dos estados que el motor ya usaba para casos estructuralmente análogos.

**Estado usado por escenario** (§18, ver tests A-G en
`test/dnssecRules.test.js`):

| Escenario | Estado |
|---|---|
| A. Cadena completa y correcta | `ok` (sin cambio) |
| B. Ruptura justo bajo el TLD | `blocked_at_parent` (antes: `ok`, incorrecto) |
| C. Ruptura en nivel intermedio profundo (5 niveles) | `blocked_at_parent` (antes: `ok`, incorrecto) |
| D. Ruptura en el padre inmediato | `blocked_at_parent` (comportamiento preexistente, sin cambio) |
| E. DNSKEY presente, DS faltante en nivel intermedio | `blocked_at_parent` (antes: `ok`, incorrecto) |
| F. DS presente, DNSKEY ausente en nivel intermedio | `blocked_at_parent` (antes: `ok`, incorrecto) |
| G. Error de medición (timeout) en nivel intermedio | `indeterminate` (sin cambio — ya lo cubría `hasHardErrors`) |
| G-bis. SERVFAIL ambiguo en nivel intermedio | `indeterminate` (antes: `ok`, incorrecto) |

**Compatibilidad verificada**: los 12 tests preexistentes de
`test/dnssecRules.test.js` (7 estados + casos límite originales) siguen
pasando sin modificación. Se agregó un test explícito de no-regresión
(`multinivel_sin_regresion_not_implemented`) confirmando que una cadena
multinivel con todos los ancestros correctos y solo el dominio propio sin
DNSSEC sigue clasificando `not_implemented` correctamente. Verificado
también en vivo contra DNS real (`example.com` sigue `ok`/`high`;
`dnssec-failed.org` sigue `misconfigured`/`high`, sin cambios).

**Limitación residual**: ninguna conocida específica a niveles
intermedios. La única limitación residual nueva identificada durante esta
microfase es la de §17 (rama `BROKEN` de `mapDelegationStatus` no
alcanzable hoy vía el flujo real) — menor, no relacionada con la
detección de rupturas intermedias en sí, y explícitamente no corregida
por estar fuera del alcance aprobado de esta microfase.
