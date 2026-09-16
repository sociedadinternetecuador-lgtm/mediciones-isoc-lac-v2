# Auditoría integral: motor DNSSEC independiente de Ecuador

Fecha: 2026-09-16. Auditoría exclusivamente técnica y de solo lectura.
**No se modificó ningún código, no se creó ningún commit.**

Aclaración que gobierna toda esta auditoría: el módulo DNSSEC aquí
analizado **no proviene del fork de Paraguay** — es un desarrollo
independiente de Ecuador. Su propósito conceptual declarado es ofrecer un
diagnóstico DNSSEC **amigable, comprensible y accionable** para usuarios
no necesariamente especializados, en la misma línea de lo que herramientas
como DNSViz permiten analizar, pero con una presentación distinta.
Cualquier hallazgo de esta auditoría se clasifica en una de tres
categorías — corrección del motor, mejora del mismo diagnóstico, o
funcionalidad adicional separada — nunca mezcladas.

## 1. Arquitectura — inventario IN SCOPE

Componentes que pertenecen directamente al motor DNSSEC independiente:

| Capa | Archivo | Rol |
|---|---|---|
| Orquestación | `services/dnssec.service.js` (262 líneas) | `getDnssecAnalysis(domain)` — arma la cadena de zonas/delegaciones, dispara las consultas DNS, calcula el índice de confianza |
| Clasificación | `logic/rules/dnssec.rules.js` (237 líneas) | `computeDnssecConclusion()` — el motor de decisión de los 7 estados finales |
| Presentación de negocio | `logic/processors/dnssec.processor.js` (170 líneas) | `processDnssecAnalysis()` — arma el resumen ejecutivo, adjunta guía y glosario, produce el bloque `human` |
| Construcción de zonas | `logic/builders/zoneChain.builder.js` (14 líneas) | `buildZoneChain(domain)` — descompone el dominio en zonas candidatas, de TLD a dominio completo |
| Construcción de delegaciones | `logic/builders/delegation.builder.js` (13 líneas) | `buildDelegationsFromZones(zones)` — arma pares padre→hijo consecutivos |
| Fuente de datos DNS | `logic/adapters/dns/realDns.adapter.js` (330 líneas) | `queryDnskey`/`queryDs`/`queryNameExistence` — consultas DoH reales, con caché/coalescing/reintento |
| Constantes | `config/dnssec.constants.js` | Enumeraciones de estado (zona, delegación, estado final, readiness) |
| Contenido — remediación | `logic/content/dnssecGuidance.content.js` (193 líneas) | Texto de diagnóstico/impacto/recomendaciones por estado final |
| Contenido — glosario | `logic/content/dnssecGlossary.content.js` (105 líneas) | Términos explicativos mostrados según el estado |
| Entrada HTTP | `server.js` — bloque `if (parsed.pathname === "/dnssec-analysis")` (~línea 4142) | Único punto de entrada real: valida input, invoca el motor, sirve HTML o JSON |
| Validación de input | `logic/validators/domain.validator.js` | `validateDomainInput()` — sanitiza y valida sintaxis de dominio antes de tocar el motor |
| Presentación HTML | `server.js` — `renderDnssecHtml()` (~línea 3271) y funciones auxiliares `getStatusBadge`/`mapConfidence`/`mapConfidenceDescription`/`mapBlockingLevel`/`mapTechnicalStatus`/`mapDisplayTitle`/`getSpecialDnssecNote` (~líneas 3127-3313) | Página HTML independiente (tema oscuro propio, no comparte diseño con el portal principal ni con MEDICIONES) |
| Formulario de entrada | `index.html` — `#dnssec-form` (acción `GET /dnssec-analysis`) | Punto de entrada del usuario |

**Consumidores del motor** (reutilizan `getDnssecAnalysis`/`processDnssecAnalysis` tal cual, sin duplicar lógica):
- `/dnssec-analysis` (uso individual, descrito arriba).
- `aggregate/batch/queue.manager.js` y `aggregate/orchestrator.js` — el **Observatorio DNSSEC**, que corre este mismo motor en lote. Su UI/orquestación de colas queda **fuera de esta auditoría** (no se revisó en profundidad), pero es relevante saber que cualquier hallazgo de exactitud del motor (§8-A) se propaga automáticamente a Observatorio.

### Explícitamente FUERA DE SCOPE (para evitar confusión de nombres)

- **`dnssecGoogle()` / `handleDnssec()` / ruta `segments[0] === 'dnssec'`** dentro de `server.js` (~líneas 658, 1000, 4215) — **esto NO es el motor independiente**. Es código heredado del fork de Paraguay (misma familia que `handleW3C`/`handlePing` antes de sus respectivas fases de MEDICIONES), que además está **huérfano**: no aparece en `groupDefinitions` de MEDICIONES, no tiene `case` en `getCheckResult()`, por lo que ningún usuario llega a él desde la interfaz — solo es alcanzable llamando la ruta HTTP directamente. No se modifica ni se analiza en profundidad aquí; se menciona únicamente para que nadie lo confunda con el motor DNSSEC real al buscar por el nombre "dnssec" en el código.
- `routes/dnssec.routes.js` — archivo Express sin usar, no requerido por nada (ya documentado en `CLAUDE.md`).
- MEDICIONES (los 60 checks, Fases 1-5) — módulo aparte.
- Observatorio DNSSEC (orquestación de lotes, colas, UI de resultados agregados) — reutiliza el motor pero su lógica propia no se audita aquí.
- Zonemaster, datasets, administración, blog, eventos — sin relación.
- El directorio vacío `filesdnssec/` en la raíz — sin contenido, sin referencias en el código, irrelevante.

### Tests

**No existe ningún test automatizado para el motor DNSSEC independiente.**
Verificado: `grep` de `dnssec.service|dnssec.processor|dnssec.rules|zoneChain.builder|delegation.builder|realDns.adapter` contra todo archivo `*.test.js` del repositorio no arroja resultados. Ni `services/`, ni `logic/rules/`, ni `logic/builders/`, ni `logic/adapters/dns/` tienen contraparte de prueba. Este es el hallazgo de mayor riesgo estructural de toda la auditoría (ver §13).

## 2. Qué pretende medir hoy (reconstruido del código, no de intención)

Pregunta técnica real que responde el motor:

> Para un dominio dado, ¿existe una cadena estructural de DNSKEY/DS
> consistente desde el TLD hasta el propio dominio (sin incluir la
> raíz), y qué tan confiable es esa interpretación dada la evidencia
> disponible?

Confirmado por el código, explícitamente:

- **Sí analiza presencia de registros**: DNSKEY por zona, DS por
  delegación (booleano `found`, no contenido).
- **Sí interpreta SERVFAIL** como señal de fallo de validación cuando
  coincide con DS presente en la delegación (`hasDnssecValidationFailure`).
- **No realiza resolución autenticada en el sentido de leer el bit `AD`
  de una respuesta DoH** — no se lee `response.AD` en ningún punto de
  `realDns.adapter.js` (confirmado por lectura completa del archivo).
  Infiere el equivalente por su cuenta, combinando `Status` (SERVFAIL) +
  presencia de DS.
- **No valida la cadena de confianza criptográficamente** — no verifica
  firmas RRSIG, no calcula si un DNSKEY corresponde matemáticamente a un
  DS (no compara hashes). Solo observa presencia/ausencia con `Status`
  del DoH.
- **No consulta múltiples resolvers.** Solo usa Google Public DNS
  (`dns.google/resolve`, DoH JSON) — no hay ninguna llamada a Cloudflare,
  Quad9 ni ningún otro resolver en este motor. No hay comparación
  multi-resolver de ningún tipo (contradice cualquier suposición previa
  de que existiera tal comparación — verificado por lectura completa del
  adaptador, único archivo que hace peticiones de red).
- **No analiza DS/DNSKEY/algoritmos en detalle**: obtiene los registros
  crudos (`response.Answer`) pero solo cuenta `answers.length > 0` — no
  extrae número de algoritmo, tipo de digest, flags de clave, ni tamaño.
- **No consulta RRSIG en absoluto** — ningún query type `RRSIG` en el
  adaptador. No hay expiración, no hay verificación de vigencia.
- **No consulta NSEC/NSEC3** — ningún query type de esos en el adaptador.
- **Sí evalúa delegación** (padre→hijo) y **sí distingue tres condiciones
  de error de configuración** (ver §4: DS sin DNSKEY, DNSKEY sin DS,
  SERVFAIL con DS presente).
- **Sí produce un meta-indicador de confianza** (`high`/`medium`/`low`,
  ver §12).

## 3. Flujo real del motor (diagrama textual)

```
Usuario -> GET /dnssec-analysis?domain=X
  -> validateDomainInput(X)              [sintaxis, no DNS todavía]
  -> getDnssecAnalysis(domain)
       -> buildZoneChain(domain)          [ej. midominio.com -> [com, midominio.com]]
       -> por cada zona: queryDnskey(zona)          [DoH Google, paralelo]
       -> buildDelegationsFromZones(zonas)          [pares padre->hijo consecutivos]
       -> por cada delegación: queryDs(zona_hija)   [DoH Google, paralelo]
       -> normalizeZone() por zona                  [signed/unsigned/unknown
                                                       + detecta SERVFAIL con
                                                       delegación segura]
       -> queryNameExistence(domain)                 [A+AAAA+CNAME, DoH Google]
       -> normalizeNameExistence()                   [exists true/false/servfail-como-señal]
       -> computeConfidence(...)                      [high/medium/low]
       => { domain, raw_checks: {zones, delegations, name_existence}, assessment_meta }
  -> processDnssecAnalysis(raw)
       -> computeDnssecConclusion(zones, delegations, domain, nameExistence)
            [el motor de 10 reglas secuenciales -> 1 de 7 estados finales]
       -> getDnssecGuidance(final_status)             [texto de remediación]
       -> getGlossaryForStatus(final_status)          [glosario contextual]
       -> buildExecutiveSummary(...)                  [riesgo/acción requerida]
       -> buildHumanReadable(...)                     [título/certeza/nota especial]
       => resultado final consolidado
  -> renderDnssecHtml(resultado)  ó  JSON crudo si ?format=json
```

## 4. Los 7 estados actuales

Confirmado en `config/dnssec.constants.js` + `logic/rules/dnssec.rules.js`
(el único lugar donde `final_status` se asigna realmente). El enum
`DNSSEC_FINAL_STATUS` define **8** valores, pero **`READY` ("ready") nunca
es producido por `computeDnssecConclusion()`** — es un estado muerto (ver
hallazgo en §8-C/§14). Los 7 estados realmente alcanzables son:

| # | Estado | Condición técnica exacta (del código) | Evidencia usada | Riesgo de falso positivo | Riesgo de falso negativo | Texto mostrado |
|---|---|---|---|---|---|---|
| 1 | `ok` | `domainSigned && secureDelegation` (DNSKEY en el dominio Y DS válido en la delegación inmediata) | Presencia DNSKEY + presencia DS | Bajo — requiere ambas piezas presentes, pero no valida que el DNSKEY corresponda matemáticamente al DS (ver §5) | Bajo | "DNSSEC correctamente implementado" |
| 2 | `not_implemented` | Zona padre firmada, DS ausente (`no_data`/`nxdomain`), dominio sin DNSKEY | DS `no_data`, DNSKEY ausente | Bajo | Medio — un dominio recién firmado, con propagación de DS pendiente, podría clasificarse aquí en vez de "misconfigured" o "en transición" (no existe ese estado) | "DNSSEC no implementado" |
| 3 | `blocked_at_tld` | La zona TLD tiene `status: unsigned` | Ausencia de DNSKEY en el TLD | Bajo | Bajo | "Bloqueo estructural en capa superior" |
| 4 | `blocked_at_parent` | La zona padre inmediata (≠ el propio dominio) tiene `status: unsigned` | Ausencia de DNSKEY en la zona padre | Bajo | Bajo | "Bloqueo en la zona padre inmediata" |
| 5 | `misconfigured` | Tres sub-casos: (a) DNSKEY presente pero DS ausente/inválido; (b) SERVFAIL con capa superior firmada; (c) DS presente pero DNSKEY ausente | Combinaciones de DS/DNSKEY/SERVFAIL | Medio — ver §5 (SERVFAIL) | Medio — colapsa tres causas raíz distintas en un solo estado (ver §8-B) | "DNSSEC presente pero mal configurado" |
| 6 | `non_existent` | **Todas** las consultas de existencia y delegación devuelven NXDOMAIN | `query_status: nxdomain` en existencia, zona del dominio y delegación | Bajo | Bajo | "Nombre no existente o no verificable" |
| 7 | `indeterminate` | Cualquier `query_status` en `{timeout, error, network_error, invalid_response}` en cualquier zona/delegación/existencia, evaluado primero (antes que cualquier regla estructural) | Errores de transporte/consulta | Bajo (es intencionalmente el estado "no sé") | Bajo | "Resultado no concluyente" |

### ¿Son mutuamente excluyentes? ¿Cubren todos los escenarios?

Sí son mutuamente excluyentes en el código: `computeDnssecConclusion` es
una cadena de `if/return` evaluada en un orden fijo (errores duros →
no-existencia → bloqueo TLD → bloqueo padre → ok → 3 variantes de
misconfigured → not_implemented → fallback indeterminate) — nunca se
evalúa más de una condición a la vez. El orden importa y está bien
razonado: los errores duros y la no-existencia se evalúan primero
porque son prerrequisito de cualquier otra clasificación (documentado
explícitamente en comentarios del propio archivo).

Cobertura: el `fallback` final (`indeterminate`) garantiza que **siempre**
se devuelve alguno de los 7 estados — no hay combinación de entradas que
deje al motor sin poder responder. Eso es una fortaleza real.

### ¿Mezclan estado DNSSEC con error de medición?

**No, están bien separados.** `indeterminate` existe precisamente para
aislar los errores de medición (timeout/red/respuesta inválida) del resto
— es la PRIMERA regla evaluada, antes de cualquier inferencia estructural,
así que un error de transporte nunca se disfraza de "not_implemented" ni
de "misconfigured". Esto es correcto y coincide con el principio general
de MEDICIONES (ya aplicado en Fases 1-5) de nunca convertir un fallo de
medición en un veredicto sobre el dominio.

## 5. Validación técnica del método

### DS — presencia, ausencia, punto de delegación

Correcto conceptualmente: `queryDs(childZone)` consulta el DS **en el
nombre de la zona hija** (comportamiento estándar: el registro DS vive
técnicamente en la zona padre pero se publica bajo el nombre del hijo,
que es exactamente cómo funciona el protocolo real) — no hay confusión
de punto de delegación.

### DNSKEY — existencia, correspondencia con la zona

Se verifica solo **existencia** (`answers.length > 0`) en el nombre
exacto de la zona. **No se verifica correspondencia matemática entre el
DNSKEY y el DS** (i.e., nunca se calcula el hash del DNSKEY y se compara
con el `digest` publicado en el DS) — el motor asume que si ambos existen,
"probablemente" corresponden. Esto es una limitación real y ya
reconocida por el propio módulo en su documentación interna
("no reemplaza una validación criptográfica completa").

### RRSIG — ¿se valida o solo se observa presencia?

**Ni siquiera se observa presencia.** No hay ninguna consulta de tipo
`RRSIG` en el adaptador. El motor no tiene ninguna noción de vigencia,
expiración ni algoritmo de firma. Esto es, con diferencia, la brecha más
grande frente a lo que DNSViz sí hace (ver §6).

### AD — cómo se usa, qué resolver lo entrega

**No se usa.** Confirmado por lectura completa de `realDns.adapter.js`:
`normalizeAnswer()` solo lee `response.Status` (0/2/3/otro), nunca
`response.AD`. Sin embargo, **Google DoH sí expone el campo `AD` en cada
respuesta** — verificado en vivo:

```
GET https://dns.google/resolve?name=example.com&type=DNSKEY
-> {"Status":0,...,"AD":true,...}   (dominio con DNSSEC válido)
```

Esto es una oportunidad concreta de mejora (ver §8-B), no un error — el
motor ya llega a la conclusión correcta por otra vía (presencia
estructural + SERVFAIL), pero **desperdicia una señal de corroboración
directa que ya viene gratis en cada respuesta que el motor ya solicita**.

### SERVFAIL — cuándo indica cadena rota y cuándo no

El motor asume: `SERVFAIL en una zona con delegación segura (DS presente)`
⇒ fallo de validación DNSSEC. Esta es una heurística **técnicamente
razonable y ampliamente aceptada** en la comunidad operativa (un
resolver validador que rechaza una respuesta con SERVFAIL, cuando existe
un DS que activa la validación, es la firma clásica de "Bogus"). Pero
tiene un límite real: **SERVFAIL también puede deberse a causas no
relacionadas con DNSSEC** — sobrecarga del servidor autoritativo, fallos
de red transitorios, configuración rota del propio servidor sin relación
a DNSSEC. El motor **ya mitiga parcialmente** este riesgo exigiendo que
exista un DS (`secureDelegation`) antes de interpretar SERVFAIL como
fallo DNSSEC — sin DS, un SERVFAIL cae en la categoría genérica de
"error duro" → `indeterminate`, no se fuerza una conclusión DNSSEC. Esto
es correcto.

**Verificación en vivo, con evidencia adicional no explotada por el
motor**: Google DoH devuelve, para el dominio de prueba público
`dnssec-failed.org` (diseñado para fallar validación DNSSEC
permanentemente):

```
GET https://dns.google/resolve?name=dnssec-failed.org&type=A
-> {"Status":2,"AD":false,
    "Comment":"DNSSEC validation failure. Check http://dnsviz.net/d/dnssec-failed.org/...",
    "extended_dns_errors":[{"info_code":9,"extra_text":"No DNSKEY matches DS RRs of dnssec-failed.org"}]}
```

**Google DoH ya entrega, en el mismo request que el motor hace hoy, un
código de error extendido (RFC 8914, "Extended DNS Errors") y un texto
explicando la causa raíz exacta** ("No DNSKEY matches DS RRs..."). El
motor actual descarta por completo este campo — solo guarda
`query_status: "servfail"`, perdiendo la explicación específica. Esta es
la oportunidad de mejora más valiosa de toda la auditoría (§8-B):
disponible hoy mismo, sin nueva dependencia, sin nuevo resolver, sin
tocar la arquitectura.

### Multi-resolver

No aplica — **no existe tal funcionalidad en el motor actual**. No hay
diferencia que evaluar entre Google/Cloudflare/otros porque solo se
consulta uno. Si en algún momento se considerara agregar un segundo
resolver, eso sería una **funcionalidad adicional** (§8-C), no una
corrección — el motor actual nunca prometió comparación multi-resolver
y no hay evidencia de que su ausencia cause una clasificación incorrecta
hoy.

## 6. Comparación conceptual con DNSViz (referencia, sin integrar)

| Capacidad | DNSSEC Ecuador | DNSViz | Diferencia | ¿Debe Ecuador incorporarla? |
|---|---|---|---|---|
| Cadena de confianza | Hasta el TLD, sin raíz (asumida confiable) | Completa, incluye la raíz | DNSViz cubre un tramo adicional | No — el propio motor ya documenta y acepta esta limitación como parte de su alcance declarado |
| Validación criptográfica de RRSIG | No — no se consulta RRSIG | Sí, valida firmas reales (vigencia, algoritmo) | Brecha real y significativa | No incorporar dentro del motor actual — es una funcionalidad adicional separada (§8-C), no una corrección |
| DS | Presencia únicamente | Presencia + validación de coincidencia con DNSKEY | Ecuador no verifica la correspondencia matemática | Parcialmente — exponer algoritmo/tipo de digest sí es una mejora de bajo riesgo (§8-B); verificar la coincidencia criptográfica completa NO (funcionalidad adicional) |
| DNSKEY | Presencia únicamente | Presencia + validación | Igual que DS | Igual que DS |
| Expiración de firmas | No aplica (no hay RRSIG) | Sí | Brecha real | No — requiere el motor de RRSIG completo, funcionalidad adicional separada |
| Algoritmos | No expuestos al usuario (aunque los datos crudos sí llegan del DoH) | Sí, con evaluación de fortaleza | Ecuador desperdicia datos ya disponibles | Sí — mejora de bajo riesgo, no cambia la naturaleza del motor (§8-B) |
| NSEC/NSEC3 | No consultado | Sí, con parámetros completos | Brecha real | No — funcionalidad adicional (requiere nuevas consultas y lógica de prueba de no-existencia autenticada) |
| Servidores autoritativos / consistencia | No consultado (el motor usa DoH recursivo, nunca contacta autoritativos directamente) | Sí, contacta cada autoritativo de la zona | Brecha arquitectónica real | No — cambiaría la naturaleza del motor (de "análisis vía resolver recursivo" a "análisis autoritativo directo"); calificaría como módulo adicional, no como ajuste |
| Lame delegation | No detectado | Sí | Brecha real | No — mismo motivo que el punto anterior |
| Visualización de cadena (grafo) | No — solo tablas/tarjetas de texto | Sí, grafo visual completo | Diferencia de UX, no de exactitud | No — fuera de la misión "diagnóstico amigable basado en texto explicado"; si se quisiera, sería módulo/UI adicional, no un ajuste del motor |
| Diagnóstico explicado en lenguaje humano | Sí, extenso (resumen ejecutivo, guía, glosario, en español) | Mínimo — texto técnico breve | Ecuador ya cumple mejor su propia misión aquí | No aplica — ya es una fortaleza |
| Remediación accionable | Sí, específica por estado, distingue capas responsables | No — DNSViz no da recomendaciones de negocio | Ecuador ya cumple mejor su propia misión | No aplica — ya es una fortaleza |

**Conclusión de esta sección**: el motor Ecuador NO necesita convertirse
en un clon de DNSViz. Su metodología (evidencia estructural + veredicto
explicado) es coherente con su propósito declarado. La única brecha que
vale la pena cerrar sin cambiar su naturaleza es aprovechar mejor los
datos que YA recibe de Google DoH (algoritmos, extended DNS errors) — el
resto de las capacidades de DNSViz son, legítimamente, un producto
distinto con una misión distinta.

## 7. Comparación con Paraguay (solo funcionalidades DNSSEC-relacionadas)

Paraguay tiene su propio motor DNSSEC local (`dnssecGoogle()` +
`buildDnssecAssessment()`, usado en su dashboard de ccTLD y en su check
`dnsviz` combinado — ver `AUDITORIA_DNSVIZ_VS_DNSSEC_ECUADOR.md`), también
basado en Google DoH. No se asume que sea mejor por existir primero; se
evaluó cada capacidad de forma independiente:

| Capacidad Paraguay | Qué hace | Cómo lo hace | ¿Aporta algo útil? | ¿Técnicamente correcto? | ¿Ecuador ya lo cubre? | Clasificación |
|---|---|---|---|---|---|---|
| Extracción de algoritmo/digest de DS/DNSKEY | Parsea el campo `data` crudo de cada registro DS/DNSKEY para obtener número de algoritmo y tipo de digest, mapeados a nombre legible (ej. "RSASHA256", "SHA-256") | Regex/parsing sobre el string de datos DoH | Sí — es información real ya disponible que hoy Ecuador descarta | Sí, es un parsing directo de campos estándar del protocolo | No — Ecuador solo cuenta `answers.length`, nunca parsea el contenido | **Mejora del mismo diagnóstico (B)** — mismo nivel de análisis (estructural), más rico |
| Detección de algoritmos "legacy"/débiles (SHA-1, DSA) | Clasifica DS/DNSKEY por fortaleza criptográfica (ECDSA/RSASHA256 = fuerte; SHA-1/DSA = legado) | Tabla de mapeo de números de algoritmo | Sí — es una señal de higiene de seguridad real y accionable | Sí, es una clasificación pública y estable (los números de algoritmo DNSSEC están estandarizados por IANA) | No | **Mejora del mismo diagnóstico (B)** |
| Parámetros NSEC3 (iteraciones, salt, algoritmo de hash) | Extrae y expone parámetros NSEC3 cuando existen | Consulta NSEC3PARAM y parsea la respuesta | Interesante para un diagnóstico más profundo, pero implica una consulta nueva que el motor actual no hace | Sí, es correcto si se implementa | No — el motor Ecuador no consulta NSEC3 en absoluto | **Funcionalidad adicional (C)** — no es una corrección de un error existente, es una capacidad nueva; no se recomienda incorporar al motor actual sin una decisión de producto explícita |
| `dnssecChain` (cadena target→ancestor→tld→raíz, con la raíz incluida y marcada `valid:true` sin verificarla) | Construye una cadena similar a `buildZoneChain` de Ecuador, pero incluye un nivel "raíz" que se marca válido por definición, sin ninguna consulta real | Hardcodeo de `valid:true` para la raíz | **No** — es una simplificación engañosa: presenta una "validación" de la raíz que en realidad nunca se hizo | No — es técnicamente incorrecto presentar un dato no verificado como si lo fuera | Ecuador ya es más honesto en este punto: documenta explícitamente que no incluye la raíz, en vez de fingir que la validó | **Descartado** — Ecuador NO debe adoptar este patrón; su propia omisión honesta de la raíz es preferible a la simulación de Paraguay |
| Mezcla de scraping de DNSViz con el resultado local (`handleDnssec`) | Combina su análisis local con notas de terceros en un solo payload | Ver auditoría previa de DNSViz | No aporta nada que Ecuador deba imitar — ya se determinó que la integración automática con DNSViz es inapropiada | No — depende de scraping no oficial | No aplica | **Descartado** (ya resuelto en la auditoría/fase de DNSViz) |

**Ninguna funcionalidad de Paraguay corrige un error objetivo del motor
Ecuador** — por lo tanto, ninguna se incorpora automáticamente. Las dos
del bucket B (algoritmo/digest, detección de legado) son candidatas
razonables de mejora futura, no correcciones urgentes.

## 8. Tres tipos de hallazgos

### A. Corrección del motor DNSSEC actual (afectan exactitud)

Ninguno de los hallazgos de esta auditoría constituye un **error objetivo
de clasificación** verificado (es decir, no se encontró un caso donde el
motor asigne demostrablemente el estado incorrecto según su propia
metodología declarada). Sí se identificaron dos puntos que rozan esta
categoría y merecen mención explícita, aunque no se clasifican como
"error" sino como riesgo estructural:

1. **Ausencia total de tests automatizados** (§13/§1) — no es un error de
   clasificación en sí, pero es la razón por la que ningún error futuro
   se detectaría antes de llegar a producción. Se recomienda tratar esto
   con prioridad de corrección aunque no sea, técnicamente, un "bug" hoy.
2. **Enum `DNSSEC_FINAL_STATUS.READY` muerto** (§4/§14): existe en
   `config/dnssec.constants.js` y tiene contenido completo en
   `dnssecGuidance.content.js` (caso `"ready"`), pero `computeDnssecConclusion()`
   nunca lo produce. No causa una clasificación incorrecta (simplemente
   nunca se usa), pero es código que puede inducir a error a quien
   mantenga el módulo asumiendo que ese estado es alcanzable.

### B. Mejora del mismo diagnóstico (sin cambiar su naturaleza)

1. **Leer el campo `AD` de la respuesta DoH de Google** (ya se consulta,
   dato gratis) como corroboración adicional del estado de validación,
   sin reemplazar la heurística SERVFAIL+DS ya existente.
2. **Leer `extended_dns_errors`/`Comment` de la respuesta DoH** (RFC 8914,
   verificado en vivo que Google los entrega) para enriquecer
   `technical_summary` con la causa raíz específica de un SERVFAIL
   (ej. "No DNSKEY matches DS RRs") en vez de solo decir "SERVFAIL con DS
   presente detectado". Esta es la mejora de mayor valor por menor
   esfuerzo de toda la auditoría — no requiere ninguna consulta nueva.
3. **Parsear algoritmo y tipo de digest de los registros DS/DNSKEY ya
   obtenidos** (dato ya presente en `response.Answer[].data`, hoy
   descartado) y exponerlo en la interfaz — mismo nivel de análisis
   (estructural, no criptográfico), mayor riqueza informativa. Inspirado
   en, pero no copiado de, la implementación de Paraguay (§7).
4. **Detectar y señalar algoritmos DNSSEC legados/débiles** (SHA-1, DSA)
   usando la misma tabla de mapeo que ya demostró Paraguay — un hallazgo
   de higiene de seguridad genuino y accionable, coherente con la misión
   de "diagnóstico amigable y accionable".
5. **Aclarar en la interfaz que el motor usa un único resolver (Google
   Public DNS)** — hoy no se declara explícitamente en ningún texto
   visible al usuario que la fuente sea un único resolver; dado que el
   propio motor recomienda "verificar con herramientas externas", sería
   coherente que también aclare cuál es su propia fuente única.
6. **IDNA/punycode antes de validar sintaxis** (`domain.validator.js`):
   `isLikelyValidDomain()` rechaza cualquier dominio con caracteres no
   ASCII (`/^[a-z0-9-]+$/i` por etiqueta) — un dominio internacionalizado
   legítimo (con tilde, eñe, etc.) sería rechazado como "Dominio inválido"
   en vez de convertirse primero a su forma ASCII/punycode. No se
   verificó si esto ocurre en la práctica con un dominio `.ec` real, pero
   es una limitación real del validador tal como está escrito hoy.

### C. Funcionalidad adicional (NO debe incorporarse al motor actual)

1. Validación criptográfica completa de RRSIG (vigencia, algoritmo,
   verificación real de firma).
2. Consulta y parsing de NSEC/NSEC3 completo (más allá de exponer
   parámetros ya calculados si se decidiera agregar la consulta).
3. Consistencia entre múltiples servidores autoritativos / detección de
   lame delegation.
4. Comparación multi-resolver (Google vs. Cloudflare vs. otros).
5. Visualización gráfica tipo grafo de cadena de confianza.
6. Cualquier forma de integración automática con DNSViz (ya resuelto:
   solo enlace externo, ver `AUDITORIA_DNSVIZ_VS_DNSSEC_ECUADOR.md`).

Todas estas, si se decide perseguirlas, deberían proponerse como **módulo
adicional independiente** o **herramienta avanzada separada** — nunca
mezcladas dentro de `services/dnssec.service.js`/`logic/rules/dnssec.rules.js`,
que deben seguir respondiendo exactamente la pregunta que hoy responden
bien: evidencia estructural interpretada de forma honesta y explicada.

## 9. Metodología documentada — vacíos

Existe documentación metodológica real y de buena calidad, **embebida en
el propio código** (comentarios extensos en `dnssec.service.js`,
`dnssec.rules.js`, y los textos de `human.note_scope`/`note_special` que
el usuario final ve). Esto es infrecuente y meritorio. Sin embargo:

- **No existe un documento metodológico externo/formal** (tipo
  `docs/arquitectura.md` pero específico de DNSSEC) que alguien sin leer
  el código pueda consultar — toda la metodología vive dispersa en
  comentarios de código y en textos de UI, nunca consolidada en un solo
  lugar navegable.
- **No se documenta en ningún lugar visible que la fuente es un único
  resolver** (Google) — vacío ya señalado en §8-B.
- Las limitaciones SÍ están bien declaradas (`assessment_meta.limitations`
  en `dnssec.service.js`) y SÍ llegan al usuario final vía `note_scope`.
- No hay documentación de qué significa exactamente un resultado
  `indeterminate` recurrente ni con qué frecuencia debería reintentarse
  (el texto solo dice "repetir el análisis en un momento posterior", sin
  más guía operativa).

## 10. Experiencia de usuario

El motor cumple razonablemente su misión de "diagnóstico amigable":
título claro por estado, insignia con color semántico, resumen ejecutivo
con nivel de riesgo y si requiere acción, nota especial contextual,
glosario de términos bajo demanda (`help-trigger`), y una etiqueta de
certeza explícita. Un usuario no experto puede razonablemente entender
**qué pasa** y, en la mayoría de los casos, **qué debería revisar**.

Comparado conceptualmente con DNSViz (diagnóstico técnico
profundo/visual) vs. Ecuador (diagnóstico amigable/explicable): el motor
sí cumple el rol que se propuso — no intenta ser DNSViz, y su lenguaje
está más cerca de un operador de sitio web que de un ingeniero DNS. Un
punto de mejora de UX real: **el usuario no ve, salvo que abra las
tablas técnicas, ningún dato crudo (DS, DNSKEY, algoritmo)** — todo el
diagnóstico amigable está bien resuelto, pero para quien sí quiere
profundizar sin salir de la página, faltan los datos de algoritmo/digest
que §8-B recomienda exponer.

## 11. Remediación

Revisadas las recomendaciones (`dnssecGuidance.content.js`) para los 7
estados alcanzables (más el caso muerto `"ready"`):

- **No prometen soluciones incorrectas** — cada bloque de
  `recommendations` es coherente con el estado (ej. "not_implemented"
  pide firmar+publicar DNSKEY+registrar DS; "blocked_at_tld"/
  "blocked_at_parent" correctamente redirigen la acción a un tercero, no
  al operador del dominio).
- **Sí diferencian capas de responsabilidad** (dominio vs. zona padre vs.
  TLD/registry) — explícito en `blocking_level`, `policy_angle`, y en el
  texto mismo ("La acción correctiva debe realizarse en la capa
  superior... puede requerir coordinación institucional").
- **No recomiendan crear un DS donde no corresponde** — el flujo de
  "not_implemented" pide firmar la zona y publicar DNSKEY *antes* de
  mencionar el registro del DS, en el orden técnico correcto.
- **No interpretan la ausencia de DNSSEC como fallo técnico obligatorio**
  — el propio texto de "not_implemented" y el glosario de "readiness"
  distinguen explícitamente "no tiene DNSSEC" de "está bloqueado
  estructuralmente", y el estado `ok`/`misconfigured` nunca se confunde
  con "no implementado".

No se encontraron recomendaciones técnicamente incorrectas o engañosas.

## 12. El indicador de "confianza"

`computeConfidence()` (`dnssec.service.js`) — evaluado con detalle:

- **Cómo se calcula**: prioriza, en este orden, (1) degradación dura
  (timeout/error de red/respuesta inválida en cualquier consulta) → 
  `low`; (2) evidencia consistente de fallo DNSSEC (SERVFAIL+DS) →
  `high`; (3) errores de consulta moderados (SERVFAIL sin contexto
  DNSSEC claro) o zonas/delegaciones con estado `unknown` → `medium`;
  (4) en cualquier otro caso → `high`.
- **Evidencia que utiliza**: exclusivamente los `query_status` ya
  calculados por el propio motor — no introduce una fuente nueva.
- **¿Tiene fundamento técnico?** Sí, es coherente: básicamente mide
  "¿tuve suficientes respuestas limpias del DNS para confiar en mi propia
  interpretación?", no "¿el dominio es seguro?" — la separación conceptual
  entre "confianza en el diagnóstico" y "estado del dominio" es correcta
  y está bien mantenida en el código (el propio comentario del archivo lo
  aclara explícitamente).
- **¿El nombre "confianza" puede inducir a error?** Levemente — un
  usuario podría leer "certeza alta" y asumir que eso significa "el
  dominio es más seguro", cuando en realidad significa "estoy más seguro
  de mi propia lectura de la evidencia". El texto (`mapConfidenceDescription`)
  sí aclara esto correctamente ("la evidencia disponible es consistente
  para sustentar la interpretación del resultado"), por lo que el riesgo
  de confusión existe solo si el usuario no lee el texto acompañante, no
  por un defecto del indicador en sí.
- **Clasificación**: **heurístico pero técnicamente sustentado** — no es
  un cálculo estadístico riguroso, pero tampoco es arbitrario: cada regla
  tiene una justificación directa y verificable en el propio código, y su
  propósito (separar "no sé" de "sé con matices" de "sé bien") es
  correcto y útil. No necesita renombrarse ni ajustarse en esta fase.

## 13. Casos de prueba

### Inventario de tests existentes

**Ninguno.** (Confirmado, ver §1.) Este es, en términos de riesgo
operativo, el hallazgo más importante de la auditoría, aunque no sea un
error de clasificación en sí mismo.

### Matriz de escenarios propuesta (para una futura fase de tests — no implementada aquí)

| Escenario | Estado esperado | Cubierto hoy por algún test |
|---|---|---|
| Dominio sin DNSSEC, capas superiores firmadas | `not_implemented` | No |
| DNSSEC correctamente configurado | `ok` | No |
| DS huérfano (DS en el padre, sin DNSKEY en la zona) | `misconfigured` (regla 8) | No |
| DNSKEY sin DS en el padre | `misconfigured` (regla 6) | No |
| SERVFAIL con DS presente (cadena rota) | `misconfigured` (regla 7) | No |
| Firma expirada | No detectable — el motor no consulta RRSIG (fuera de su alcance actual, ver §6/§8-C) | No aplica |
| Algoritmo no soportado por el resolver | Indistinguible de otros SERVFAIL hoy — se beneficiaría de `extended_dns_errors` (§8-B) | No |
| Cadena rota en un nivel intermedio (zona ancestro, no el dominio ni el TLD) | Depende del nivel — cubierto conceptualmente por las reglas de zona padre, pero no hay test que confirme el comportamiento exacto para 3+ niveles | No |
| Resolver A valida / resolver B no | No aplicable — el motor es de un solo resolver (§5); si se agregara un segundo, sería funcionalidad nueva, no un caso de test del motor actual | No aplica |
| SERVFAIL temporal (transitorio) | `indeterminate` (cae en errores duros antes que cualquier regla estructural) | No |
| NXDOMAIN real | `non_existent` | No |
| Dominio no delegado (subdominio sin zona propia) | Ambiguo — depende de si el nivel intermedio responde `no_data` (tratado como zona sin firmar, razonable) o `nxdomain` en niveles internos (no está claro que el motor lo distinga limpiamente sin un test que lo confirme) | No |
| Errores autoritativos (SERVFAIL sin DS, no relacionado a DNSSEC) | `indeterminate` (correcto: no se fuerza una lectura DNSSEC sin DS) | No |
| IPv6 irrelevante para DNSSEC en sí | El motor consulta A/AAAA/CNAME juntos solo para existencia del nombre, no distingue familia — comportamiento correcto, no es una brecha | No |

No se implementaron tests nuevos en esta fase (auditoría de solo lectura,
según alcance explícito). Se deja esta matriz como insumo directo para
una fase de corrección/mejora futura si se decide abordar el hallazgo de
§8-A.1.

## 14. Funciones que deben mantenerse fuera del motor DNSSEC

| Función | Por qué queda fuera | Dónde tendría más sentido |
|---|---|---|
| Validación criptográfica real de RRSIG | Cambia la naturaleza del motor de "análisis estructural explicado" a "validador criptográfico completo" — proyecto de envergadura propia | Módulo/herramienta avanzada separada, opcional, para usuarios que ya pasaron por el diagnóstico amigable y quieren profundizar |
| Consulta y prueba de NSEC/NSEC3 | Requiere nuevas consultas y lógica de interpretación no trivial (parámetros de hash, iteraciones) | Mismo módulo avanzado que RRSIG, o enriquecimiento futuro bien acotado si se decide (ver §8-B como el límite razonable: solo exponer NSEC3PARAM si ya se consultara, no is implementar pruebas de denegación) |
| Consistencia multi-autoritativo / lame delegation | Cambia el modelo de resolución de "vía resolver recursivo" a "contacto directo con autoritativos" — arquitectura distinta | Módulo adicional, posiblemente compartiendo el mismo motor de consulta que Observatorio si se diseñara para eso |
| Comparación multi-resolver (Google/Cloudflare/otros) | El motor nunca prometió esto; agregar un segundo resolver es una decisión de producto, no una corrección | Enriquecimiento externo/módulo adicional, con su propia semántica de "coincidencia/discrepancia" bien definida antes de implementar |
| Visualización tipo grafo | Fuera de la misión declarada ("diagnóstico amigable" ya se resuelve con tarjetas/texto explicado, no con un grafo) | Si se quisiera, una vista adicional opcional, nunca reemplazando las tarjetas actuales |
| Integración automatizada con DNSViz (scraping) | Ya resuelto en fase previa: viola el robots.txt del proveedor, sin API oficial | Enlace externo únicamente (ya implementado en MEDICIONES; el módulo DNSSEC independiente podría añadir el mismo tipo de enlace si su propio equipo lo decide, fuera de esta auditoría) |

## 15. Recomendaciones finales

### Correcciones necesarias

Ninguna de exactitud de clasificación verificada. Se recomienda, como
única "corrección" real:
- Eliminar o implementar de verdad el estado muerto `DNSSEC_FINAL_STATUS.READY`
  (hoy definido y con contenido de guía, pero inalcanzable) — decisión de
  limpieza, no de exactitud.
- Priorizar dotar al motor de una suite de tests automatizados (matriz
  de §13) antes de cualquier otro cambio, para poder verificar con
  confianza cualquier futura corrección o mejora sin depender solo de
  lectura manual de código.

### Mejoras recomendadas (no cambian la naturaleza del motor)

1. Leer y aprovechar el campo `AD` de Google DoH (ya disponible, sin
   costo adicional).
2. Leer y exponer `extended_dns_errors`/`Comment` de Google DoH para
   enriquecer la explicación de causas de SERVFAIL (mayor valor por menor
   esfuerzo de toda la auditoría).
3. Parsear y exponer algoritmo/tipo de digest de DS/DNSKEY ya obtenidos.
4. Señalar algoritmos DNSSEC legados/débiles (SHA-1, DSA) como hallazgo
   de higiene de seguridad.
5. Declarar explícitamente en la UI que la fuente es un único resolver
   (Google Public DNS).
6. Aplicar IDNA/punycode antes de validar sintaxis de dominio, para no
   rechazar dominios internacionalizados legítimos.
7. Consolidar la metodología dispersa en comentarios de código en un
   documento único navegable (no solo en la UI ni en comentarios).

### Funciones adicionales separadas (no incorporar al motor actual)

Validación criptográfica RRSIG completa; NSEC/NSEC3 completo;
consistencia multi-autoritativo/lame delegation; comparación
multi-resolver; visualización tipo grafo — todas como módulo(s)
independiente(s) futuro(s), fuera de `services/dnssec.service.js` y
`logic/rules/dnssec.rules.js`.

### No recomendado

- Adoptar el patrón de Paraguay de marcar la zona raíz como `valid:true`
  sin verificarla — es menos honesto que la omisión explícita actual de
  Ecuador.
- Cualquier integración automatizada con DNSViz dentro de este motor
  (scraping o API no oficial) — ya resuelto como enlace externo únicamente.
- Renombrar o eliminar el indicador de "confianza" — es heurístico pero
  técnicamente sustentado y útil tal como está.

## 16. Conclusión

**MOTOR CORRECTO CON AJUSTES.** El motor DNSSEC independiente de Ecuador
cumple honestamente la misión que se propuso: interpreta evidencia
estructural real (DNSKEY/DS/existencia) con un modelo de 7 estados
mutuamente excluyentes, bien ordenado, que nunca confunde error de
medición con veredicto sobre el dominio, con un indicador de confianza
técnicamente razonable y remediación correctamente diferenciada por capa
de responsabilidad. No se encontró ningún error objetivo de
clasificación. Las brechas reales frente a DNSViz (RRSIG, NSEC3,
multi-autoritativo, multi-resolver) son coherentes con una decisión de
alcance ya declarada por el propio módulo, no con negligencia técnica.

Los ajustes recomendados —especialmente aprovechar el campo `AD` y los
`extended_dns_errors` que Google DoH ya entrega gratis en cada consulta
que el motor ya hace, y construir por fin una suite de tests— mejorarían
significativamente tanto la precisión explicativa como la seguridad de
mantenimiento del motor, sin alterar su naturaleza ni su arquitectura.
