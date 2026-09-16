# Auditoría del pendiente técnico: `mapDelegationStatus -> BROKEN`

Fecha: 2026-09-16. Auditoría exclusiva y de solo lectura sobre el
pendiente técnico registrado en `IMPLEMENTACION_DNSSEC_AUDITORIA_CORE.md`
(commit `c8d348c9856e68a609fc67ebcfe237bdf95525c2`): *"mapDelegationStatus
-> BROKEN parece no alcanzable mediante el flujo DoH actual."*

**No se modificó ningún archivo de producción.** El core DNSSEC mantiene
exactamente sus 7 estados finales, sin cambios. La evidencia empírica de
este documento proviene de `test/dnssecBrokenDelegationAudit.test.js`, un
archivo de auditoría **no registrado en `package.json`, no incluido en la
suite de producción, y no destinado a commit**.

## 1. Localización de `BROKEN`

| Elemento | Ubicación |
|---|---|
| Enum/constante | `config/dnssec.constants.js` — `DNSSEC_DELEGATION_STATUS.BROKEN = "broken"` (junto a `SECURE`, `INSECURE`, `UNKNOWN`) |
| Función que lo produce | `mapDelegationStatus(secure, dsPresent, queryStatus)` — `services/dnssec.service.js` (única definición, sin comentario explicativo, a diferencia de su función hermana `mapZoneStatus`) |
| Único invocador | `services/dnssec.service.js`, dentro de `getDnssecAnalysis()`, en el `.map()` que construye `delegations` |
| Consumidores potenciales de `status === "broken"` | `logic/rules/dnssec.rules.js` — `ancestorDelegations.find(d => hasStatus(d?.status, ["insecure","broken"]))` (agregado en la fase anterior, commit `c8d348c`); ningún otro archivo lo lee explícitamente por su nombre literal |

### Árbol de llamadas real

```
queryDs(delegation.to)                              [realDns.adapter.js — Google DoH]
  -> { found, records, query_status, error_code }    (found: true | false | null)
  -> en getDnssecAnalysis() [dnssec.service.js:225-236]:
       const secure = ds.found === true;              <- ①
       mapDelegationStatus(secure, ds.found, ds.query_status)  <- ② dsPresent = ds.found (SIN transformar)
       -> delegation.status  ("secure" | "insecure" | "broken" | "unknown")
  -> delegations[] pasa a:
       - hasSecureDelegation() [service.js:126-131] — usado por normalizeZone()
         para la señal SERVFAIL+DS ("dnssec_validation_failure")
       - computeDnssecConclusion() [dnssec.rules.js] — reglas 5/6/8 (nivel del
         propio dominio, vía ds_present/secureDelegation) y reglas 3.5/3.6
         (ancestorZones/ancestorDelegations, fase anterior)
  -> final_status (uno de los 7 estados)
```

El punto crítico está marcado ① ② arriba: `secure` y el segundo argumento
de `mapDelegationStatus` (`dsPresent`) se derivan **del mismo valor
fuente** (`ds.found`), en el único lugar donde la función se invoca en
todo el repositorio.

## 2. Significado original reconstruido (sin asumir)

`mapDelegationStatus` no tiene comentario explicativo, así que su
intención se reconstruye a partir de su firma y de sus tres condiciones:

```js
function mapDelegationStatus(secure, dsPresent, queryStatus) {
  if (secure === true) return SECURE;
  if (dsPresent === false && queryStatus === "no_data") return INSECURE;
  if (dsPresent === true && secure === false) return BROKEN;
  return UNKNOWN;
}
```

La función recibe **dos parámetros que, en un diseño coherente, deberían
ser señales independientes**: `dsPresent` (¿existe un registro DS en la
zona padre?) y `secure` (¿esa delegación está realmente asegurada, en un
sentido más estricto que la mera presencia del DS?). Si fueran
independientes, la condición de `BROKEN` (`dsPresent === true && secure
=== false`) tiene un significado preciso y correcto: **"hay un DS
publicado, pero la delegación no logra considerarse segura por algún
motivo adicional"** — el patrón clásico de una delegación DNSSEC
declarada pero no funcional: DS presente que no corresponde a ningún
DNSKEY realmente publicado por la zona hija (DS "huérfano" o "colgante").

Esto distingue a `BROKEN` de:
- `INSECURE`: la zona padre **deliberadamente** no tiene DS (no hay
  intención de asegurar esa delegación) — un estado neutral, no un error.
- `BROKEN` (según su diseño original reconstruido): la zona padre **sí**
  publica un DS, pero la delegación no se sostiene — un error real.

**Conclusión de esta sección: `BROKEN` fue diseñado para representar "DS
presente pero delegación no funcional" — muy probablemente por ausencia
o no-correspondencia del DNSKEY del hijo con ese DS —, no SERVFAIL, no
Bogus en el sentido de validación criptográfica activa (eso se maneja en
otro mecanismo completamente distinto, ver §5-E), y no un error de
resolver.**

## 3. Alcanzabilidad — demostrada empíricamente

### Parte 1 — `mapDelegationStatus` en aislamiento

Probada con una matriz de 10 combinaciones (`secure`, `dsPresent`,
`queryStatus` como parámetros verdaderamente independientes):

```
secure=false dsPresent=true queryStatus=ok        -> broken   ✓
secure=false dsPresent=true queryStatus=servfail  -> broken   ✓
```

**La función en sí misma SÍ puede producir `BROKEN`** cuando se le pasan
valores independientes. No hay ningún error en la condición ni en la
lógica de la función — el bug no está aquí.

### Parte 2 — Replicando el único call site real

Se replicó exactamente la fórmula real (`secure = ds.found === true`;
`mapDelegationStatus(secure, ds.found, ds.query_status)`) para las **3**
valores posibles de `ds.found` (`true`/`false`/`null`, contrato de
`realDns.adapter.js`) cruzados con los **8** `query_status` reales que el
adaptador puede producir (`ok`, `no_data`, `nxdomain`, `servfail`,
`timeout`, `network_error`, `invalid_response`, `error`) — **24
combinaciones en total, ninguna produce `BROKEN`.**

**Causa exacta**: `dsPresent` recibe literalmente `ds.found`, el mismo
valor con el que se calculó `secure` (`ds.found === true`). Son
algebraicamente idénticos en todo momento:
- `ds.found === true` → `secure = true` y `dsPresent = true` → cae en la
  primera condición (`SECURE`), nunca llega a evaluar la de `BROKEN`.
- `ds.found === false` → `secure = false` y `dsPresent = false` → la
  condición de `BROKEN` exige `dsPresent === true`, que aquí es falso.
- `ds.found === null` → `secure = false` y `dsPresent = null` → la
  condición de `BROKEN` exige `dsPresent === true` (estrictamente), y
  `null !== true`.

**No es un bug en la condición de `mapDelegationStatus` (esa condición es
correcta si recibe entradas independientes). No es un problema del
parser DoH (`realDns.adapter.js` ya entrega `found` con tres valores
útiles y distintos). Es que el único invocador nunca calcula `secure`
como una señal realmente distinta de `dsPresent` — los pasa como el
mismo dato con dos nombres.**

## 4. Relación con el flujo DoH real

**¿El flujo actual pierde información antes de llegar a
`mapDelegationStatus`?** Sí, pero no en el sentido de que el dato no
exista — sino en que la función **nunca recibe el dato que necesitaría**
para expresar `BROKEN` correctamente: la presencia de DNSKEY en la zona
**hija** (`delegation.to`). Esa información **sí existe** en
`getDnssecAnalysis()` — se calcula unas líneas antes, para cada zona, en
`preliminaryZones` (a partir de `queryDnskey()`) — pero nunca se cruza
con el resultado de `queryDs()` al construir cada delegación. Las dos
piezas de evidencia (DS en el padre, DNSKEY en el hijo) existen ambas en
memoria en el mismo momento, en el mismo archivo, pero no se combinan.

**¿`BROKEN` es inalcanzable porque el parser nunca produce el patrón
esperado?** No — el parser (`normalizeAnswer()`) produce correctamente
`found: true|false|null` según corresponda; el patrón de entrada que
`BROKEN` necesitaría (`dsPresent=true` junto a una señal independiente de
"no asegurado") simplemente nunca se construye en el código que llama a
`mapDelegationStatus`.

**¿O porque la condición está mal escrita?** No — demostrado en la Parte
1: la condición es correcta y alcanzable cuando se le dan entradas
independientes.

## 5. Casos conceptuales (A-G)

| Caso | Qué observaría el motor hoy | `mapDelegationStatus` | Estado final actual | ¿`BROKEN` sería apropiado? |
|---|---|---|---|---|
| A. DS en padre, DNSKEY ausente en hijo | DNSKEY del hijo: `no_data` (zona → `unsigned`). DS del padre: `found=true` | `secure` (mal etiquetado — **demostrado empíricamente en Parte 3**) | Correcto igual: `blocked_at_parent` (nivel ancestro, vía `brokenAncestorZone`) o `misconfigured` (nivel del propio dominio, vía regla 8) — **por una vía independiente de `status`** | Sí, semánticamente sería el caso más apropiado para `BROKEN` — pero es 100% redundante: el veredicto final ya es correcto sin él |
| B. DS no coincide con DNSKEY (ambos presentes, pero no corresponden) | DNSKEY del hijo: `found=true` (zona → `signed`). DS del padre: `found=true` | `secure` (no hay forma de detectar la NO correspondencia — el motor nunca compara contenido/digest) | Probablemente `ok` (falso positivo real) | No — ni siquiera si `BROKEN` fuera alcanzable, porque ningún punto del motor calcula la correspondencia DS↔DNSKEY. Corregir esto requeriría criptografía real, fuera de alcance |
| C. Firma RRSIG expirada | Nada — el motor no consulta RRSIG en absoluto | No aplica | No detectable con el motor actual (fuera de su alcance declarado) | No — sin relación con `BROKEN` |
| D. Algoritmo DNSSEC no soportado | Nada — el motor no analiza algoritmos | No aplica | No detectable con el motor actual (fuera de su alcance declarado) | No — sin relación con `BROKEN` |
| E. SERVFAIL de resolver validante por cadena rota | DNSKEY del hijo: `servfail`, con `hasSignedUpperLayer` verdadero | No aplica — se maneja por `hasDnssecValidationFailure`/`validation_problem` en `normalizeZone()`, un mecanismo **completamente distinto**, no pasa por `mapDelegationStatus` | `misconfigured` (ya correcto, probado en la fase anterior) | No — mecanismo separado, ya funcional |
| F. DNSKEY presente pero sin DS | DNSKEY del hijo: `found=true`. DS del padre: `no_data` | `insecure` (correcto — esto es exactamente lo que `INSECURE` representa) | `not_implemented` o `misconfigured` según el nivel, ya correcto | No — este es el caso de `INSECURE`, un concepto distinto de `BROKEN` (delegación deliberadamente sin DS, no un DS roto) |
| G. Respuesta parcial/error temporal en un nivel intermedio | `query_status` en `{timeout, network_error, invalid_response}` (o `error`) | `unknown` | `indeterminate` (ya correcto, cubierto por `hasHardErrors` desde antes de la fase anterior) | No — mecanismo separado, ya funcional |

## 6. Relación con los 7 estados finales

`BROKEN` es un estado **interno** (de la delegación), nunca un estado
final. Si se hiciera alcanzable, no necesitaría ninguna regla nueva de
consumo — **las reglas consumidoras ya existen y ya lo manejan
correctamente**, aunque nunca lo reciben:

- A nivel del **propio dominio**: la regla 8 de `computeDnssecConclusion()`
  (`lastDelegation.ds_present === true && secureDelegation &&
  domainUnsigned`) ya produce `misconfigured` para este patrón —
  funciona hoy vía `ds_present`, sin necesitar leer `status === "broken"`.
- A nivel **ancestro**: `ancestorDelegations.find(d => hasStatus(d?.status,
  ["insecure","broken"]))` (agregado en la fase anterior) ya está
  preparado para tratar `"broken"` como `blocked_at_parent`, exactamente
  igual que `"insecure"` — simplemente nunca recibe ese valor.

**No hace falta crear ni modificar ninguna regla de `dnssec.rules.js`
para "activar" `BROKEN`** — el único cambio necesario, si se decidiera
perseguir esto, estaría en el productor (`dnssec.service.js`), nunca en
el consumidor.

## 7. Evaluación: ¿`BROKEN` aporta algo?

**CONCEPTO ÚTIL PERO IMPLEMENTACIÓN INALCANZABLE — con una matización
importante**, y es la conclusión central de esta auditoría:

- Para su interpretación **más simple y verificable** (caso A: DS
  presente, DNSKEY del hijo totalmente ausente), `BROKEN` sería
  redundante — esa situación **ya se clasifica correctamente hoy** por
  la vía del estado de la zona (`unsigned`), tanto a nivel del propio
  dominio como a nivel de cualquier ancestro. Hacerlo alcanzable para
  este caso específico no agregaría ninguna capacidad de diagnóstico
  nueva al veredicto final — solo corregiría una etiqueta interna
  (`delegation.status`) que hoy es engañosa en el JSON crudo.
- Para su interpretación **más completa y valiosa** (caso B: DS y DNSKEY
  ambos presentes pero sin corresponder entre sí — un DS "huérfano" o
  apuntando a una clave rotada), `BROKEN` seguiría siendo inalcanzable
  incluso corrigiendo el call site actual, porque ningún punto del motor
  calcula esa correspondencia — se necesitaría verificación criptográfica
  real (comparar el hash publicado en el DS contra el DNSKEY), que el
  core declara explícitamente fuera de su alcance.

## 8. Recomendación (sin implementar en esta fase)

**A. ELIMINAR.**

Justificación:

1. Está demostrado, con evidencia ejecutable, que es 100% inalcanzable
   con el código actual — no por un caso límite raro, sino por
   construcción algebraica del único call site.
2. Hacerlo alcanzable para su forma más simple (caso A) sería, también
   demostrado, puramente redundante con el mecanismo de estado de zona
   ya existente — cero valor de diagnóstico nuevo.
3. Hacerlo alcanzable para su forma más valiosa (caso B) exigiría
   verificación criptográfica real DS↔DNSKEY — una ampliación de alcance
   explícitamente descartada para este core en la fase anterior, y que
   debería ser, si alguna vez se persigue, una decisión de producto
   deliberada y propia, no una corrección incidental de este hallazgo.
4. Mantener una rama de código permanentemente muerta es un riesgo de
   mantenimiento menor pero real (mismo criterio ya aplicado al estado
   `ready` en la fase anterior): alguien podría asumir que `BROKEN` es
   una señal viva y diseñar lógica downstream contando con ella.

Nota práctica: como la condición de `BROKEN` nunca se cumple hoy,
eliminarla no cambia ningún comportamiento observable — la ejecución ya
cae siempre en el `return UNKNOWN` final para cualquier entrada real. Es
decir, eliminar `BROKEN` (opción A) produce, en la práctica, el mismo
resultado que "eliminar y mapear directamente a otro estado interno"
(opción C) — `UNKNOWN` ya es ese destino natural, sin necesidad de
ninguna acción adicional.

**No se implementa esta eliminación en la presente fase**, tal como se
indicó explícitamente en el alcance.

## 9. Impacto real

- **¿Falso `ok`?** No causado por la inalcanzabilidad de `BROKEN` en sí
  — el caso donde `BROKEN` habría sido relevante (caso A) ya se clasifica
  correctamente por otra vía. El único falso `ok` real posible (caso B,
  DS/DNSKEY presentes pero sin corresponder) existiría **con o sin**
  `BROKEN` alcanzable, porque ningún mecanismo del motor calcula esa
  correspondencia — no es atribuible a este hallazgo puntual.
- **¿Falso `not_implemented`?** No se encontró ningún camino donde la
  inalcanzabilidad de `BROKEN` produzca esto.
- **¿Falso `indeterminate`?** No.
- **¿Pérdida de diagnóstico?** Sí, pero acotada y menor: el campo crudo
  `delegation.status` (expuesto directamente en `/dnssec-analysis?
  format=json`) puede mostrar `"secure"` para una delegación que, en
  sentido estricto, no lo es (DS presente pero DNSKEY del hijo ausente)
  — confirmado empíricamente en la Parte 3. Esto **no afecta el
  veredicto final de 7 estados** (que sigue siendo correcto por la vía
  del estado de zona), solo el detalle técnico crudo que un consumidor
  avanzado del JSON podría leer directamente.
- **Conclusión de impacto: ningún impacto observable en el veredicto
  final (7 estados). Impacto menor, real pero acotado, en la precisión
  del campo interno `delegation.status` expuesto en el JSON crudo.**

## 10. Confirmación de alcance (auditoría, fase previa)

No se modificó ningún archivo de producción durante la auditoría en sí
(`services/dnssec.service.js`, `logic/rules/dnssec.rules.js`,
`config/dnssec.constants.js` permanecían exactamente iguales al commit
`c8d348c9856e68a609fc67ebcfe237bdf95525c2` al cerrar esta auditoría). El
único archivo nuevo de esa fase fue este documento y
`test/dnssecBrokenDelegationAudit.test.js` (auditoría, no registrado en
`package.json`, no incluido en la suite de producción). No se creó ningún
commit en esa fase.

## 11. Resolución (2026-09-16, microfase siguiente)

Con base en la recomendación única de la §8 (**ELIMINAR**), se aplicó
exactamente eso — nada más:

- `DNSSEC_DELEGATION_STATUS.BROKEN` eliminado de
  `config/dnssec.constants.js` (quedan 3 valores: `SECURE`, `INSECURE`,
  `UNKNOWN`).
- La rama que lo producía, eliminada de `mapDelegationStatus()`
  (`services/dnssec.service.js`) — la función ahora solo devuelve estados
  realmente alcanzables. No se sustituyó por ninguna etiqueta nueva: cae
  en `UNKNOWN`, el mismo resultado que ya producía en la práctica.
- En `logic/rules/dnssec.rules.js`, se quitó `"broken"` del único lugar
  que lo referenciaba (`brokenAncestorDelegation`, renombrada
  `insecureAncestorDelegation`) — la regla en sí (bloqueo por delegación
  ancestro insegura) se conservó intacta, porque sigue siendo necesaria
  para el caso `"insecure"`, genuinamente distinto e independiente del
  caso que `BROKEN` intentaba cubrir.
- **No se intentó hacer alcanzable `BROKEN`** ni se agregó verificación
  criptográfica DS↔DNSKEY — la limitación del caso B (§5) permanece
  documentada y fuera de alcance, tal como recomendaba esta auditoría.
- Se agregaron 7 tests nuevos (4 en `test/dnssecService.test.js`, 1 en
  `test/dnssecContent.test.js`, más la corrección del fixture del
  escenario F en `test/dnssecRules.test.js`) confirmando: que `"broken"`
  ya no es producible en ningún escenario real; que el caso A (§5) sigue
  resolviendo al mismo veredicto final correcto por la vía del estado de
  zona; y que el caso B nunca se presenta como "validado
  criptográficamente".

Detalle completo de la resolución: `IMPLEMENTACION_DNSSEC_AUDITORIA_
CORE.md` §19.

## 12. Confirmación de alcance (cierre)

Los 7 estados finales no cambiaron. MEDICIONES (60 checks) no fue
tocado. DNSViz (enlace externo) no fue tocado. No se incorporó
RRSIG, NSEC/NSEC3, multi-resolver, AD/EDE decisorio, ni ninguna otra
funcionalidad fuera del alcance ya establecido para el core DNSSEC.
