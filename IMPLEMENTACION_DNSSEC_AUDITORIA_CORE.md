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

  **Pendiente técnico — RESUELTO el 2026-09-16 (ver §19).** Se registró
  como `mapDelegationStatus -> BROKEN parece no alcanzable mediante el
  flujo DoH actual`, se auditó por separado en
  `AUDITORIA_DNSSEC_BROKEN_DELEGATION.md` (confirmando, con evidencia
  ejecutable, que era 100% inalcanzable y que su ausencia no afectaba
  ningún veredicto final), y se eliminó de
  `DNSSEC_DELEGATION_STATUS`/`mapDelegationStatus()`. Ya no es un
  pendiente abierto.

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
microfase (rama `BROKEN` de `mapDelegationStatus` no alcanzable hoy vía
el flujo real) quedó resuelta en la microfase siguiente — ver §19.

## 19. Resolución del pendiente técnico BROKEN (2026-09-16)

Ver auditoría completa en `AUDITORIA_DNSSEC_BROKEN_DELEGATION.md`.
Resume aquí solo el cambio aplicado y su alcance.

### Qué se eliminó

- `config/dnssec.constants.js`: `DNSSEC_DELEGATION_STATUS.BROKEN` — el
  enum queda con exactamente 3 valores (`SECURE`, `INSECURE`, `UNKNOWN`).
- `services/dnssec.service.js`: la rama `if (dsPresent === true && secure
  === false) return DNSSEC_DELEGATION_STATUS.BROKEN;` dentro de
  `mapDelegationStatus()` — la función ahora solo puede devolver los 3
  valores restantes.
- `logic/rules/dnssec.rules.js`: se quitó `"broken"` del arreglo de
  búsqueda `hasStatus(d?.status, ["insecure", "broken"])` (quedó solo
  `["insecure"]`) y se renombró la variable `brokenAncestorDelegation` →
  `insecureAncestorDelegation` (ya nunca podía coincidir con `"broken"`,
  el nombre anterior habría sido engañoso). **La regla que la consume
  (bloqueo por delegación ancestro insegura → `blocked_at_parent`) no se
  eliminó ni se modificó en su lógica — sigue siendo necesaria y real**
  para el caso "delegación ancestro sin DS publicado", que es distinto e
  independiente del caso que `BROKEN` intentaba cubrir.

### No se sustituyó por una etiqueta artificial

Tal como exigía el alcance de esta fase: al quitar la rama de `BROKEN`,
la función simplemente cae en su `return UNKNOWN` ya existente — el mismo
resultado que ya producía en la práctica (la rama nunca se ejecutaba con
datos reales, así que remover el código muerto no cambia ningún
comportamiento observable).

### Consumidores revisados, no modificados donde no era necesario

- Regla 8 de `computeDnssecConclusion()` (nivel del propio dominio, "DS
  presente + DNSKEY ausente" → `misconfigured`): usa `ds_present`
  directamente, nunca leyó `status === "broken"` — sin cambios.
- `brokenAncestorZone`/ahora `insecureAncestorDelegation` (nivel
  ancestro): la detección real de "DS presente + DNSKEY ausente" en un
  ancestro sigue funcionando exactamente igual, porque siempre dependió
  del **estado de la zona** (`unsigned`, vía `mapZoneStatus`), nunca del
  estado de la delegación — confirmado con test dedicado
  (`service_ds_sin_dnskey_intermedio_sigue_blocked_at_parent`).

### Correspondencia criptográfica DS↔DNSKEY: permanece fuera de alcance

Documentado expresamente (`docs/metodologia-dnssec.md`, sección
"Limitaciones declaradas" y "Fuera de alcance del core"): el motor NUNCA
compara el contenido del DS con el DNSKEY real de la zona hija — "DS
presente + DNSKEY presente" no equivale a "cadena criptográficamente
válida", solo a "ambos registros existen". Un DS que apunte a una clave
rotada o inexistente, mientras la zona hija publica *alguna* otra
DNSKEY, se seguiría reportando `ok`. Esta limitación **no se resuelve en
esta fase** (requeriría verificar el hash del DS contra el DNSKEY, fuera
del alcance estructural del core) y queda fijada con un test explícito
(`service_ds_dnskey_presentes_no_afirma_validacion_criptografica`) que
confirma que ningún texto del resultado afirma una validación
criptográfica que nunca se realizó.

### JSON crudo (`/dnssec-analysis?format=json`)

Verificado en vivo, sin cambios de comportamiento: `example.com` sigue
`final_status: "ok"`, delegación `"secure"`; `dnssec-failed.org` sigue
`final_status: "misconfigured"`. El campo `delegation.status` ya no
puede mostrar `"broken"` (no existe); para el caso "DS presente + DNSKEY
ausente" sigue mostrando `"secure"` (la etiqueta más precisa que el
modelo actual puede producir sin cruzar datos de DNSKEY en el cálculo de
`secure` — ver siguiente párrafo) — el **veredicto final** de 7 estados
sigue siendo correcto porque lo determina el estado de la zona, no el de
la delegación.

**Sobre corregir la etiqueta `"secure"` misma**: los datos de DNSKEY por
zona (`preliminaryZones`) técnicamente ya están calculados en el mismo
alcance de `getDnssecAnalysis()` antes de construirse las delegaciones,
así que sería *posible* cruzarlos para que `secure` deje de ser un alias
de `ds.found`. **Se decidió explícitamente no hacerlo en esta fase**:
cambiar cómo se calcula `secure` afectaría también a
`hasSecureDelegation()` y a las reglas 5/6/8 de `computeDnssecConclusion()`
que leen `secureDelegation` — es decir, dejaría de ser "eliminar un
estado muerto" para convertirse en "cambiar cómo se determina la
seguridad de una delegación", exactamente el tipo de ampliación de
alcance que esta fase (y la decisión que la originó) excluye
explícitamente ("NO intentar hacerlo alcanzable"). Queda documentado como
posible mejora futura en `docs/metodologia-dnssec.md`, no implementada.

### Tests añadidos (7)

`test/dnssecContent.test.js`: 1 test nuevo
(`constants_sin_broken_3_valores_delegacion`). `test/dnssecService.test.js`:
3 tests nuevos (`service_broken_nunca_producido_matriz_ds_dnskey` — 4
combinaciones DS/DNSKEY confirmando que `"broken"` nunca aparece;
`service_ds_sin_dnskey_intermedio_sigue_blocked_at_parent` — extremo a
extremo, confirma que el veredicto final no cambió;
`service_ds_dnskey_presentes_no_afirma_validacion_criptografica` — fija
la limitación de forma ejecutable). `test/dnssecRules.test.js`: el
fixture del escenario F se corrigió para usar `status: 'secure'` (el
valor que el sistema real produce) en vez del artificial `'broken'`
usado antes de esta resolución — mismo resultado final, sin cambios en la
lógica de `dnssec.rules.js`.

Además, `test/dnssecBrokenDelegationAudit.test.js` (archivo de auditoría
de la fase de investigación previa, no registrado en `package.json`, no
parte de la suite de producción) se conserva sin modificar como registro
histórico de la evidencia que sustentó esta decisión.

### Validación final

```
npm test
-> 18/18 archivos de test OK
-> 60 checks MEDICIONES, 0 duplicados (sin cambio)
-> 38 tests DNSSEC en verde (34 previos + 1 en dnssecContent + 3 en
   dnssecService; el fixture de multinivel_F se corrigió sin cambiar el
   conteo de dnssecRules)
-> smoke test manual: example.com -> ok/secure (sin cambio);
   dnssec-failed.org -> misconfigured (sin cambio); "broken" no aparece
   en ningún JSON de salida
```

**Confirmado**: los 7 estados finales no cambiaron, MEDICIONES no fue
tocado, ningún módulo externo al core DNSSEC fue modificado, no se
incorporó RRSIG/NSEC3/multi-resolver/AD-EDE-decisorio/DNSViz.
