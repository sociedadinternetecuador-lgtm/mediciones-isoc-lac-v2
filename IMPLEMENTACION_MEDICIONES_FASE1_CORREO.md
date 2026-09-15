# Implementación MEDICIONES — Fase 1: correo (maildnssec, mailipv6, starttls)

**Fecha:** 2026-09-15 · **Revisión crítica:** 2026-09-16 · **Alcance:** exclusivamente el módulo MEDICIONES (ver `AUDITORIA_CHECKS_FALTANTES_MEDICIONES.md` para los límites exactos). DNSSEC independiente, Observatorio, Zonemaster, datasets, administración, blog, eventos y el runner regional **no se tocaron**.

**Principio de la revisión del 2026-09-16**: el código de Paraguay/upstream se trató como referencia histórica y funcional, no como especificación normativa. Se auditó cada check preguntando primero "¿qué debería medir esto?" y solo después "¿lo mide bien la implementación actual?" — sin asumir que la versión de la Fase 1 (2026-09-15), inspirada en upstream, era correcta por el solo hecho de existir. Esa revisión encontró un problema conceptual real en `maildnssec` (confusión hostname/zona de delegación, ver §11) y una simplificación evitable en `starttls` (solo verificaba el anuncio, no la negociación TLS real) — ambos se corrigieron. Donde la corrección técnica entró en conflicto con la compatibilidad literal con Paraguay, se priorizó la corrección técnica.

---

## 1. Baseline

```
Rama:   main
HEAD:   d3cc5a7905191d7edbbac986a18c9b998443585c
        "tooling: add regional study runner" (Carlos Vera, 2026-09-13)

git status (antes de cualquier cambio): sin cambios en archivos rastreados,
solo untracked ya conocidos de sesiones anteriores (AUDITORIA_*.md,
data/exercises/, scripts/exercise-24-domains/, 2 PDFs, 1 zip redundante).
No se descartó ni se tocó nada de eso.

npm test (baseline): 8 suites, OK — exit code 0.
```

## 2. Implementación upstream analizada (referencia funcional, no copiada)

| Check | Endpoint Paraguay | Dependencias | Timeout | Guardas SSRF |
|---|---|---|---|---|
| `maildnssec` | `GET /maildnssec/:domain` | `dig` vía `execFile` (mode local) o `dns.google` (mode remote); resolución MX propia | `REQUEST_TIMEOUT_MS` genérico | Ninguna (no aplica, es solo DNS) |
| `mailipv6` | `GET /mailipv6/:domain` | `dns.resolve6` nativo | ídem | N/A |
| `starttls` | `GET /starttls/:domain` | `net.createConnection(port, server)` **directo al hostname**, sin resolver ni validar IP antes | 15s | **Ninguna** — sin bloqueo de IP privada/loopback/link-local |

Decisión: no copiar el código de Paraguay. Dos motivos concretos:
1. Su modo "local" depende del binario `dig` (`execFile('dig', ...)`) — una dependencia de sistema que Ecuador no necesita agregar (Ecuador ya resuelve DNS con `dns.promises` nativo en todos sus checks existentes).
2. Su `starttls` conecta por TCP directo al hostname del MX **sin validar la IP resuelta** — un MX controlado por un atacante podría apuntar a `127.0.0.1` o a una IP interna del contenedor. Esto es una SSRF real en el código de referencia.

## 3. Semántica exacta de cada check (documentada, no asumida)

> **Nota:** esta sección refleja la versión ya corregida (2026-09-16). Ver §11 para qué cambió respecto a la versión original de la Fase 1 y por qué.

### `maildnssec`
**Mide si la resolución de los servidores de correo (hostnames MX) está protegida por una cadena DNSSEC validada** — usando el bit **AD (Authenticated Data)** que devuelve `dns.google` (resolver DNSSEC-validante) en una consulta A/AAAA normal, no presencia de DS/DNSKEY en el hostname exacto. **No** vuelve a medir el DNSSEC del dominio que envía/recibe (eso lo cubre — fuera de esta fase — el check `dnssec` y el módulo DNSSEC independiente de Ecuador). El campo `domainState` viaja solo como contexto adicional, no determina el resultado del check.

Por qué el bit AD y no DS/DNSKEY directos: DS/DNSKEY existen por **zona** (punto de delegación real), no por hostname — la mayoría de los hostnames MX no son ellos mismos una zona delegada. El bit AD refleja si la cadena de confianza real (dondequiera que esté el punto de delegación efectivo) validó para ese nombre específico, sin que MEDICIONES tenga que determinar cuál es esa zona. Ver §11 para el caso real que expuso el problema (nic.ar).

**Límite conocido y documentado, no oculto**: esto refleja la validación de UN resolver público (Google), no una reconstrucción independiente de la cadena completa por MEDICIONES — es la limitación práctica inherente a cualquier chequeo basado en el bit AD de un tercero.

Estados por MX: `secure` (AD:true), `insecure` (resuelve, AD:false), `broken` (SERVFAIL de validación DNSSEC real — la cadena se intentó y está rota, distinto de "nunca se firmó"), `unresolved` (ni A ni AAAA en absoluto).

Casos agregados:
- **PASS**: todos los MX probados (máx. 5) y determinados son `secure`.
- **FAIL**: todos los MX determinados son `insecure`/`broken` (ninguno `secure`).
- **INFO**: adopción mixta entre MX ya determinados (algunos `secure`, otros no) — dato real, no se fuerza a PASS/FAIL.
- **NOT_APPLICABLE**: el dominio no tiene registros MX.
- **INCONCLUSIVE**: algún MX quedó `unresolved` (no se pudo determinar en absoluto) — no se puede certificar el conjunto completo.
- **MEASUREMENT_ERROR**: ningún MX se pudo determinar, o falló la resolución de MX del propio dominio por una causa distinta de "no tiene MX".

### `mailipv6`
**Mide únicamente si cada servidor MX publica un registro AAAA** — resolución DNS, no conectividad real (mismo alcance que el check `ipv6` ya existente para el dominio principal). Sin cambios respecto a la Fase 1 original — la revisión crítica confirmó que ya distinguía correctamente publicación de conectividad, y ya usaba INFO para adopción mixta.

Casos:
- **PASS**: todos los MX probados tienen AAAA.
- **FAIL**: ningún MX tiene AAAA (confirmado por ENODATA/ENOTFOUND, no por error).
- **INFO**: adopción mixta (algunos sí, algunos no) — deliberadamente **no** es PASS ni FAIL, es un dato real no binario.
- **NOT_APPLICABLE**: sin registros MX.
- **INCONCLUSIVE/MEASUREMENT_ERROR**: no se pudo determinar para alguno/todos los MX (SERVFAIL, timeout — nunca por ausencia confirmada de AAAA).

### `starttls`
**Mide si el servidor SMTP (puerto 25) anuncia STARTTLS Y si la negociación TLS realmente se completa** tras enviar el comando `STARTTLS` — no solo si aparece en la respuesta a `EHLO`. Nunca se envía correo (ni `MAIL FROM`/`RCPT TO`/`DATA`, ni siquiera `QUIT`): la conexión se cierra apenas se confirma o falla el handshake.

Puerto: solo **25** (entrega SMTP real entre servidores). Se evaluó explícitamente el puerto 587 (message submission, RFC 6409 — protocolo para clientes autenticados, no para recepción MX-a-MX) y se descartó a propósito, aunque Paraguay lo usa — ver §11.

Estados por MX: `supports` (anuncia Y el handshake TLS se completa), `announced_only` (anuncia pero la negociación falla o el servidor rechaza el comando STARTTLS), `no` (no anuncia), `timeout`, `connection-error`, `blocked` (SSRF).

Política con varios MX (máx. 5, ordenados por prioridad) — misma lógica de 3 vías que `maildnssec`/`mailipv6`:
- **PASS**: todos los MX determinados (`supports`/`announced_only`/`no`) son `supports`.
- **FAIL**: todos los MX determinados no son `supports` (`no` y/o `announced_only`).
- **INFO**: mezcla conocida entre MX ya determinados (algunos `supports`, otros no) — **corrección respecto a la Fase 1 original**, que colapsaba este caso a FAIL perdiendo la información de adopción parcial (ver §11).
- **NOT_APPLICABLE**: sin registros MX.
- **INCONCLUSIVE**: algún MX no se pudo medir en absoluto (timeout/conexión rechazada/bloqueado).
- **MEASUREMENT_ERROR**: si el propio `resolveMx` del dominio falla por una causa distinta de "sin MX", o ningún MX pudo determinarse.

## 4. Seguridad — medidas SSRF aplicadas

**No se escribió una segunda implementación de validación de IP.** Se reutilizó tal cual `resolvePublicAddresses()` de `logic/adapters/safeWebFetch.adapter.js` (la guarda que ya usa `fetchSafePage()` para todos los checks HTTP existentes), que ya bloquea:

- loopback IPv4/IPv6 (`127.0.0.0/8`, `::1`)
- RFC1918 (`10/8`, `172.16/12`, `192.168/16`)
- link-local IPv4/IPv6 (`169.254/16`, `fe80::/10`)
- ULA IPv6 (`fc00::/7`)
- CGNAT (`100.64/10`), multicast y reservados

`probeStarttls()` resuelve el hostname MX **una sola vez** vía esa función y conecta directo a la IP numérica ya validada (`net.createConnection({host: ip, port: 25})`) — nunca vuelve a resolver el hostname al conectar, cerrando la ventana de **DNS rebinding** entre validar y conectar.

Medidas adicionales, específicas de esta fase:
- **Puerto fijo (25)**, nunca proporcionado por quien usa la herramienta, nunca 587 (protocolo/semántica distinta, no es lo que STARTTLS de entrega protege).
- **Timeout corto y controlado** (`STARTTLS_TIMEOUT_MS`, 8s por defecto — configurable solo por variable de entorno para que los tests puedan simular un timeout real sin esperarlo) que cubre toda la sonda, incluida la fase de negociación TLS.
- **Máximo 5 MX probados por dominio** (`MAX_MX_PROBED`) — Paraguay no tenía ningún límite; en una corrida de hasta 20 dominios esto evita que un dominio con muchos MX dispare decenas de conexiones DNS/SMTP.
- El socket (y el socket TLS, si se llega a intentar el handshake) siempre se destruye/cierra al finalizar (éxito, error o timeout) — nunca queda una conexión abierta indefinidamente, y **nunca se envía ningún comando SMTP posterior al handshake** (sin `MAIL FROM`/`RCPT TO`/`DATA`).
- El listener de datos en texto plano se retira explícitamente (`socket.off('data', onPlainData)`) **antes** de entregarle el socket a `tls.connect()`, para que ningún byte del handshake se interprete por error como texto SMTP.

**Cambio necesario para que la guarda fuera mockeable en tests** (documentado como desviación menor): `server.js` desestructuraba `resolvePublicAddresses` directamente de `safeWebFetch.adapter.js`; se cambió a mantener una referencia al módulo completo (`safeWebFetchAdapter.resolvePublicAddresses(...)`) — mismo patrón que ya usa `test/content.publicVisibility.test.js` con `emailAdapter.sendMail`. No cambia ningún comportamiento; `fetchSafePage`/`resolveFinalWebTarget` siguen desestructurados igual que antes.

## 5. Archivos modificados

| Archivo | Cambio |
|---|---|
| `server.js` | 3 handlers nuevos (`handleMailDnssec`, `handleMailIpv6`, `handleStarttls`) + helpers (`sortAndCapMx`, `resolveMxOrNotApplicable`, `probeStarttls`) + 3 rutas nuevas + guarda `require.main === module` alrededor de `server.listen()` (permite testear sin abrir puerto real) + `module.exports` mínimo para tests + cambio de `resolvePublicAddresses` a referencia de módulo completo |
| `logic/adapters/safeWebFetch.adapter.js` | Se agrega `resolvePublicAddresses` a `module.exports` (ya existía, no se tocó su lógica) |
| `index.html` | 3 entradas nuevas en `groupDefinitions` (grupo "Anti-suplantación de correo"), 3 entradas en `checkGlossary`, 3 `case` nuevos en `getCheckResult()` |
| `package.json` | 2 tests nuevos agregados al script `test` |

**No se tocó**: `groupDefinitions` de ningún otro grupo, `medicionesBatchStart()`, `routes/medicionesBatchReport.routes.js`, `logic/exporters/medicionesBatchReport.exporter.js`, `logic/orchestrators/medicionesBatchReport.store.js` — **verificado que no hacía falta**: el flujo de batch/reporte ya es completamente genérico sobre `selectedChecks`/`groupDefinitions` (ningún archivo tiene una lista hardcodeada de 54 checks ni el número "54" en ningún literal) — los 3 checks nuevos entran automáticamente en cualquier corrida/reporte por lote sin cambios adicionales.

## 6. Hallazgo colateral (no accionado en esta fase)

Al revisar el router de `server.js` se descubrió que **ya existen, desde el propio fork, un `handleDnssec` y un `handleW3C` completos y funcionales** (rutas `/dnssec/:domain` y `/w3c/:domain`), heredados de Paraguay en 2025-12-08 pero **nunca conectados a ningún checkbox de `groupDefinitions`** — dormidos desde entonces. Esto es relevante para una futura Fase 3/6 (ver `AUDITORIA_CHECKS_FALTANTES_MEDICIONES.md`): el backend de `w3c` ya existe y probablemente no requeriría escribirse desde cero. **No se tocó ni se expuso en esta fase** (fuera del alcance explícito: "NO implementar todavía... w3c").

## 7. Tests

**`test/medicionesMailChecks.test.js`** (23 casos, todo mockeado — `dns.resolveMx/resolve6`, `https.request`, `net.createConnection`, `tls.connect`, `safeWebFetchAdapter.resolvePublicAddresses` — cero red real):

- maildnssec: MX bajo zona con cadena validada (AD:true), **el caso real de MX que no es punto de delegación propio (equivalente a nic.ar) y aun así da `secure`**, zona insegura (AD:false), DNSSEC roto (SERVFAIL real), MX que no resuelve en absoluto, sin MX, error DNS del dominio, adopción mixta entre 2 MX (→ INFO).
- mailipv6: todos con AAAA, ninguno, mixto, sin MX, no determinable (sin cambios respecto a la Fase 1 original).
- starttls: soporta con **handshake TLS real completado**, anuncia pero el handshake falla, anuncia pero el servidor rechaza el comando STARTTLS, no soporta, **mezcla conocida entre 2 MX (→ INFO)**, sin MX, timeout parcial, todos timeout, host privado bloqueado por la guarda SSRF, conexión rechazada, límite de 5 MX con 7 registros de entrada.

**`test/medicionesCheckRegistry.test.js`** (5 casos, lee `index.html`/`server.js` como texto, sin red ni servidor):

- `groupDefinitions` tiene exactamente 57 checks.
- Sin claves duplicadas.
- Los 3 nuevos están presentes.
- Los 57 tienen su `case` correspondiente en `getCheckResult()` (invariante real de completitud — no "tiene ruta backend propia", porque varios checks preexistentes comparten un endpoint "bundle").
- Los 3 nuevos, específicamente, sí tienen ruta backend propia dedicada.

## 8. Resultado de la validación final

```
npm test                         → 10 suites, OK, exit code 0
node --check server.js           → sin errores de sintaxis
node -e "require('./server.js')" → no abre ningún puerto (guarda require.main)
node server.js (PORT=3599)       → arranca, responde 200 en /
```

**Smoke test contra red real** (fuera de los tests automatizados, verificación manual puntual, 2026-09-16, ya con la versión corregida):
```
GET /maildnssec/nic.ar      → domainState:"secure", mx30.slyt.gob.ar:"secure",
                               mx20.slyt.gob.ar:"secure"
                               (caso real que expuso el bug de la v. anterior —
                               ver §11: con DS/DNSKEY directos ambos MX daban
                               "insecure" pese a que la cadena real SÍ valida)
GET /starttls/isoc.org.ec   → mail.isoc.org.ec: timeout (puerto 25 bloqueado
                               en server1, ver §9 — confirmado, no es un bug)
```

## 9. Comprobación de TCP/25 en producción (server1) — CONFIRMADO: BLOQUEADO

Se verificó conectividad TCP saliente pura (sin enviar datos SMTP, sin autenticar, sin relay, sin escaneo) desde `server1` vía SSH:

```bash
# Ejecutado el 2026-09-16 contra dos MX públicos distintos, más un control:
time timeout 8 bash -c 'echo > /dev/tcp/gmail-smtp-in.l.google.com/25'   # timeout a los 8s
time timeout 8 bash -c 'echo > /dev/tcp/alt1.gmail-smtp-in.l.google.com/25' # timeout a los 8s
time timeout 5 bash -c 'echo > /dev/tcp/www.google.com/443'              # conecta en 0.2s (control: la red general funciona)
```

**Resultado: BLOQUEADO.** Dos MX públicos independientes y confiables (Gmail) dan timeout silencioso completo (nunca "connection refused" inmediato, que sería un rechazo activo) en el puerto 25, mientras que el mismo host conecta instantáneamente por 443 — descarta un problema de DNS/ruteo general y apunta a un bloqueo/descarte específico del puerto 25 saliente (política común de datacenters/ISP contra spam).

**Consecuencia práctica**: `starttls`, tal como está desplegado hoy en `server1`, **siempre devolverá `MEASUREMENT_ERROR`/`INCONCLUSIVE` por timeout** — nunca PASS/FAIL/INFO reales — hasta que se revise esa restricción de red a nivel de infraestructura (fuera del alcance de MEDICIONES y de esta fase; es una decisión de red/firewall del home-lab, no de código). El comportamiento del check ante ese bloqueo ya es correcto y seguro (no se cuelga, no miente, clasifica honestamente como indeterminado).

## 10. Pendientes explícitos (no implementados, fuera de esta fase)

- `dnssec` (como check propio dentro de MEDICIONES), `dnsviz`, `routing`, `w3c`, `ping`, `pingv6`, `internetnlweb`, `internetnlmail`, `traceroute`, Pulse — según lo acordado, ninguno se tocó.
- **TCP/25 saliente bloqueado en `server1`** (ver §9, ahora confirmado, ya no es una pregunta abierta) — condiciona la utilidad práctica de `starttls` hasta que se decida si se ajusta la red del home-lab; no bloquea el commit de este trabajo.
- El límite de "máximo 5 MX" y el timeout de 8s de STARTTLS son decisiones de diseño de esta fase, no vienen de ningún acuerdo previo — quedan documentados aquí por si se quieren ajustar.
- La limitación conocida de `probeStarttls()` cuando el banner "220 Ready" y los primeros bytes del handshake TLS llegan en el mismo segmento TCP (ver comentario en `server.js`) — nunca produce un falso PASS, en el peor caso produce `timeout` en vez de `supports` para ese caso puntual.

## 11. Revisión crítica frente al upstream Paraguay (2026-09-16)

Principio aplicado: Paraguay/upstream es una referencia histórica y funcional, nunca una especificación normativa. Se evaluó cada check con la pregunta funcional que debería responder, no con la pregunta "¿hace esto lo mismo que Paraguay?".

### `maildnssec`

**Qué hace Paraguay**: consulta DS y DNSKEY directamente en el hostname MX exacto (`dig`/`dns.google` según el modo), y considera "seguro" si ambos registros existen ahí.

**Problema encontrado**: DS y DNSKEY existen por **zona** (un punto de delegación real, con NS propios) — no por hostname. La inmensa mayoría de los hostnames MX (`mail.proveedor.net`, `aspmx.l.google.com`, etc.) **no son ellos mismos una zona delegada**: son un registro A/AAAA normal dentro de la zona real, que puede estar varios niveles más arriba. Preguntar DS/DNSKEY exactamente en ese nombre produce **falso negativo sistemático** aunque la cadena de confianza real (root → tld → dominio real → ese registro) esté perfectamente firmada y validada por cualquier resolver DNSSEC-consciente.

**Caso real verificado en producción (2026-09-16)**, sin modificar nada, solo consultando DNS real:

```
nic.ar tiene DNSSEC: ok (confirmado en auditorías previas de este mismo proyecto)
Sus MX: mx30.slyt.gob.ar, mx20.slyt.gob.ar — un dominio de correo DISTINTO (slyt.gob.ar)

$ curl -s "https://dns.google/resolve?name=mx30.slyt.gob.ar&type=DNSKEY"
→ sin Answer (solo SOA en Authority) — el enfoque de Paraguay concluiría "sin DNSSEC"

$ curl -s "https://dns.google/resolve?name=mx30.slyt.gob.ar&type=DS"
→ Status:2 (SERVFAIL) — el enfoque de Paraguay lo trataría como fallo silencioso

$ curl -s "https://dns.google/resolve?name=mx30.slyt.gob.ar&type=A"
→ AD:true — la cadena real (slyt.gob.ar y gob.ar están firmados, confirmado
  por separado) SÍ valida correctamente para este nombre específico
```

Es decir: el enfoque de Paraguay habría reportado el correo de `nic.ar` como "sin DNSSEC" — exactamente lo opuesto a la realidad.

**Clasificación de la implementación upstream: IMPRECISA.** No es descabellada como heurística (funciona cuando el MX coincide con un punto de delegación real), pero falla en el caso general, que es el mayoritario en la práctica.

**Qué hace Ecuador (corregido)**: en vez de inferir seguridad por presencia de DS/DNSKEY en el nombre exacto, usa el bit **AD (Authenticated Data)** que devuelve `dns.google` (un resolver que sí valida DNSSEC) en una consulta A/AAAA normal — eso refleja si la cadena de confianza real validó para ese nombre específico, sin que MEDICIONES necesite determinar por sí mismo cuál es la zona autoritativa pertinente. No se acopla al módulo DNSSEC independiente de Ecuador (más sofisticado, pero fuera de alcance) — es un helper propio y local (`checkAuthenticatedResolution()`), separado también de `dnssecGoogle()` (que sigue intacta, sin relación con este check).

**Resultado final: REIMPLEMENTADA PARA CORREGIR UPSTREAM.**

### `mailipv6`

**Qué hace Paraguay**: resuelve AAAA en cada MX, sin más.

**Evaluación**: la pregunta funcional ("¿la infraestructura MX está publicada para IPv6?") queda correctamente respondida por una simple resolución AAAA — publicación DNS y conectividad real son cosas distintas, y este check nunca afirmó ser lo segundo (el texto y el glosario dicen explícitamente "solo resolución DNS, no conectividad real"). La política de Paraguay de exigir unanimidad para PASS/FAIL también es razonable como umbral binario, pero pierde la información de adopción parcial.

**Clasificación de la implementación upstream: SIMPLIFICADA PERO VÁLIDA.**

**Qué hace Ecuador**: exactamente lo mismo a nivel de medición (resolución AAAA), pero con una política de 3 vías que Paraguay no tiene: adopción mixta → `INFO`, no forzada a PASS/FAIL. Esta distinción ya estaba correctamente implementada desde la Fase 1 original — la revisión crítica no encontró nada que corregir en el propio chequeo, solo confirmó que la semántica ya era honesta.

**Resultado final: CORRECTA PERO LIMITADA** (limitada porque, como el propio check ya aclara, resolución ≠ conectividad — una limitación reconocida, no oculta).

### `starttls`

**Qué hace Paraguay**: conecta a los puertos 25 y 587 sin resolver/validar la IP antes (SSRF real), y considera "soporta" con solo ver `STARTTLS` en la respuesta a `EHLO` — nunca intenta la negociación TLS.

**Problemas encontrados**:
1. **Puerto**: 587 es *message submission* (RFC 6409) — un protocolo para clientes autenticados que envían correo, no para la recepción SMTP servidor-a-servidor que es la pregunta real de este check ("¿los MX que reciben correo anuncian STARTTLS?"). Incluir 587 solo porque Paraguay lo hace habría mezclado dos preguntas distintas bajo un mismo check.
2. **Anunciado vs. funcional**: un servidor puede anunciar STARTTLS y aun así fallar al negociarlo (certificado corrupto, configuración rota) — un servidor "roto" así se reportaría como "soporta STARTTLS" con el criterio de Paraguay, un **falso positivo** real.
3. **SSRF**: ya identificado y corregido desde la Fase 1 original (§4) — Paraguay conecta al hostname sin validar la IP.

**Clasificación de la implementación upstream: IMPRECISA** (el puerto 587 mezcla protocolos distintos; "anunciado" no es lo mismo que "funcional"; sin guardas SSRF).

**Qué hace Ecuador (corregido)**: solo puerto 25; tras ver el anuncio de STARTTLS, envía el comando real y **intenta completar la negociación TLS** sobre el mismo socket (`tls.connect({socket, ...})`), sin enviar correo — la conexión se cierra apenas se confirma el resultado. Introduce el estado `announced_only` (anuncia pero no funciona) en vez de colapsarlo a "soporta". Además corrige la política de varios MX: una mezcla conocida (2 de 3 MX soportan) ahora es `INFO`, no `FAIL` como habría sido con la política binaria de la Fase 1 original — `INCONCLUSIVE` queda reservado exclusivamente para cuando de verdad falta evidencia (timeout/conexión rechazada/bloqueo SSRF).

**Resultado final: REIMPLEMENTADA PARA CORREGIR UPSTREAM** (puerto, nivel de verificación, y política multi-MX).

### Tabla comparativa

**`maildnssec`**

| Aspecto | Paraguay | Ecuador final | Motivo de la diferencia |
|---|---|---|---|
| Semántica | DS/DNSKEY presentes en el hostname MX exacto | Bit AD de una consulta A/AAAA normal (resolver validante) | El hostname MX casi nunca es un punto de delegación — DS/DNSKEY ahí da falso negativo sistemático (caso real: nic.ar) |
| Resolver | `dig` local o `dns.google` según modo | Solo `dns.google` | Sin dependencia de binarios del sistema |
| Validación | Presencia de registros | Bit AD de un resolver validante | Refleja la cadena real sin necesitar ubicar la zona autoritativa |
| Política multi-MX | Implícita, no documentada | 3 vías: PASS/FAIL/INFO + INCONCLUSIVE | Adopción mixta ya determinada no debe perderse en un binario |
| Manejo de errores | Silencioso (try/catch vacío) | Estados explícitos: `secure`/`insecure`/`broken`/`unresolved` | Distingue "no firmado" de "DNSSEC roto" de "no se pudo medir" |

**`mailipv6`**

| Aspecto | Paraguay | Ecuador final | Motivo de la diferencia |
|---|---|---|---|
| Semántica | Resolución AAAA por MX | Igual | Ya era técnicamente correcto y honesto |
| Política multi-MX | No documentada explícitamente | PASS/FAIL/INFO ya desde la Fase 1 | Adopción parcial es un dato real, no un fallo |
| Cambios de esta revisión | — | Ninguno | No se encontró nada que corregir |

**`starttls`**

| Aspecto | Paraguay | Ecuador final | Motivo de la diferencia |
|---|---|---|---|
| Puertos | 25 y 587 | Solo 25 | 587 es message submission (RFC 6409), protocolo distinto a la recepción MX-a-MX |
| Nivel de verificación | Solo anuncio en EHLO | Anuncio + intento real de negociación TLS | "Anuncia" y "funciona" son afirmaciones distintas; un servidor puede anunciar y fallar |
| Seguridad (SSRF) | Ninguna — conecta al hostname sin validar IP | `resolvePublicAddresses()` + conexión a IP ya validada, sin re-resolver | Paraguay es vulnerable a que un MX controlado apunte a una IP interna |
| Timeout | 15s x 2 puertos | 8s, 1 puerto, cubre negociación SMTP + TLS | Puerto único, alcance más acotado |
| Límite de MX | Ninguno | 5, ordenados por prioridad | Evita decenas de conexiones por corrida de 20 dominios |
| Política multi-MX | Binaria (implícita) | PASS/FAIL/INFO + INCONCLUSIVE | Mezcla conocida (2 de 3 soportan) es informativa, no un fallo del check |
| Manejo de correo | No enviaba correo (correcto) | Igual — nunca se envía correo | Sin cambios, ya era correcto |

## 12. Cierre de Fase 1 (2026-09-17) — STARTTLS deshabilitado por defecto, no por deficiencia del check

`starttls` está **técnicamente implementado, correcto y validado** (handshake TLS real, puerto 25, guardas SSRF, política de 3 vías — ver §2-3 y §11). El diagnóstico de infraestructura (`DIAGNOSTICO_TCP25_MEDICIONES.md`, 2026-09-16/17) confirmó que **`server1` no dispone hoy de salida TCP saliente al puerto 25** — el bloqueo se observa idéntico desde el host y desde el contenedor, TCP/443 funciona con normalidad, no pudo demostrarse un bloqueo local (falta de acceso root al firewall), y la causa más probable es filtrado del proveedor de conectividad (CNT, ver el diagnóstico para el detalle completo — no se repite ni se referencia el nombre del proveedor en la interfaz pública de MEDICIONES).

**Esto es una limitación del nodo de medición, no del check.** El código de `starttls` ya se comporta correctamente ante esa condición: nunca cuelga, nunca produce un falso `FAIL` — reporta `MEASUREMENT_ERROR`/`INCONCLUSIVE` por timeout, exactamente el resultado honesto esperado cuando la medición no puede completarse (ver el modelo de estados en §3).

**Decisión de esta fase**: mantener `starttls` disponible como uno de los 57 checks de MEDICIONES, con `default: false` (ya era así desde su implementación — no fue necesario ningún cambio de código para esta decisión). No se activa por defecto mientras el nodo de medición no tenga conectividad TCP/25 saliente real. No se intentó ni se recomendó el puerto 587 como sustituto (ver §11 — resuelve una pregunta funcional distinta). No se introdujo un worker/nodo externo ni se modificó arquitectura, firewall, router ni configuración del proveedor en esta fase — evaluado y descartado como primer recurso en `DIAGNOSTICO_TCP25_MEDICIONES.md` §8-9.

**Texto visible actualizado** (`checkGlossary.starttls`, `index.html`) para dejar explícito, sin mencionar al proveedor ni presentar el bloqueo como una deficiencia del dominio medido:

> "Comprueba si los servidores MX (hasta 5) anuncian STARTTLS y permiten establecer una negociación TLS real por SMTP en el puerto 25 (sin enviar correo) — distingue 'anuncia' de 'funciona'. La medición requiere conectividad TCP saliente al puerto 25 desde el nodo de medición."

### Pendiente operativo (registrado, sin resolver en esta fase)

> STARTTLS requiere TCP/25 saliente desde el nodo de medición. El nodo actual (`server1`) no dispone de esa conectividad. Evaluar en el futuro habilitación por el proveedor o ejecución desde otro nodo si STARTTLS debe activarse por defecto.

No se creó ninguna infraestructura nueva para atender este pendiente.
