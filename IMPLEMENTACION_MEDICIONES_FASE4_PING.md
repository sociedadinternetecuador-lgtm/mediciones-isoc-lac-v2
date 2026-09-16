# Fase 4 — MEDICIONES: checks `ping` / `pingv6` (ICMP)

Fecha: 2026-09-16. Continúa la Fase 3 (validación HTML W3C/Nu), cerrada en
el commit `87c7018eb97ce844f2ea307a258f9f33933bd923`. Alcance:
exclusivamente el módulo MEDICIONES (`server.js`, `index.html`, `test/`,
`package.json`). No se tocó DNSSEC independiente, Observatorio,
Zonemaster, datasets, OpenINTEL, administración, blog, eventos, el runner
regional, ni Docker/docker-compose (explícitamente fuera de alcance de
esta fase).

Principio aplicado, igual que en fases previas: **Paraguay/upstream es
referencia histórica y funcional, nunca especificación normativa.** El
código real de `nicocamarao/mediciones-isoc-lac` se leyó directamente (vía
`gh api`), y la viabilidad operativa se verificó con diagnóstico real
contra `server1` (host y contenedor Docker), no se asumió nada.

## 0. Baseline

```
rama:   main
HEAD:   87c7018eb97ce844f2ea307a258f9f33933bd923
status: sin cambios pendientes de Fase 3; solo los mismos untracked
        pre-existentes y ajenos a esta fase (AUDITORIA_FORK_MEDICIONES.md,
        data/exercises/, PDFs de public/docs/, scripts/exercise-24-domains/,
        scripts/regional-study/input/*.zip)
npm test (antes de tocar nada): 12/12 suites OK, 58 checks, 0 duplicados
```

## 1. Auditoría de `ping`/`pingv6` en Paraguay/upstream

Leído el código real (`server.js` líneas 2073-2094 y 4534-4562,
`index.html` líneas 5377-5412 de `nicocamarao/mediciones-isoc-lac`).

```js
async function runLocalPing(host, family = 4) {
  const candidates = family === 6
    ? [['/sbin/ping6', ['-c', '3', '-n', host]], ['ping', ['-6', '-c', '3', '-n', host]]]
    : [['/sbin/ping', ['-c', '3', '-n', host]], ['ping', ['-c', '3', '-n', host]]];
  ...
  const { stdout } = await execFileAsync(cmd, args, { timeout: REQUEST_TIMEOUT_MS });
  ...
}

async function handlePing(domain, res) {
  domain = normalizeDomain(domain);
  const data = await runLocalPing(domain, 4);   // <- el DOMINIO, no una IP
  ...
}
```

- **Ejecución**: `execFile` (vía `util.promisify`), nunca `exec`/shell —
  correcto en ese aspecto puntual, sin riesgo de inyección de comandos
  clásica (metacaracteres de shell no se interpretan).
- **Sin embargo, `runLocalPing(domain, family)` recibe el DOMINIO
  directamente y lo pasa tal cual como argumento de `ping`** — nunca
  resuelve DNS ni filtra direcciones por su cuenta. Es el propio binario
  `ping` quien hace `getaddrinfo()` internamente y decide a qué IP
  conectarse. **No hay ningún guard de IP privada/reservada**: si un
  dominio resuelve a `127.0.0.1`, `169.254.169.254` (metadata de nube),
  un rango RFC1918, etc., Paraguay le haría ping igual, sin bloquearlo.
  Esto es un problema real de seguridad (no de inyección de comandos,
  sino de **ausencia total de la guarda de destinos privados** que el
  resto del proyecto sí exige) y crea, además, un riesgo de "reflector"
  débil: un atacante podría usar el propio endpoint para confirmar si una
  IP interna arbitraria responde a ICMP desde la red de Paraguay (un
  probe de reconocimiento de red interna, aunque de bajo impacto por sí
  solo).
- **Ni siquiera hay resolución explícita de IPv4 vs IPv6**: para
  `pingv6`, se pasa el mismo `domain` (no una IP) a `ping6`/`ping -6` —
  si el dominio tiene múltiples AAAA, cuál se prueba depende enteramente
  del resolver del sistema, sin visibilidad ni control.
- **Un solo intento por dominio, sin muestreo de múltiples IP** — no hay
  forma de ver "IP A responde, IP B no", solo un resultado agregado del
  primer/único destino que el propio `ping` decida resolver.
- **Conflación crítica de estados** (verificada leyendo el código, no
  supuesta): `execFile`/`execFileAsync` **rechaza la promesa cuando el
  proceso `ping` sale con código distinto de 0** — y `ping` estándar
  (iputils) sale con código 1 cuando hay 100% de pérdida de paquetes,
  aunque haya funcionado perfectamente y el destino simplemente no
  responda ICMP. El código de Paraguay:
  - Descarta por completo `stdout` en ese caso (no lo usa para nada).
  - Para IPv4: relanza el error genérico tal cual — el frontend
    (`data.error` truthy) muestra `status: 'error'` con el texto crudo del
    fallo de `execFile` (algo como "Command failed: ping -c 3 -n
    dominio\n...") — indistinguible de un fallo real de ejecución.
  - Para IPv6, específicamente: si **ambos** candidatos (`ping6` y
    `ping -6`) fallan por CUALQUIER motivo, lanza siempre el mismo mensaje
    fijo `'Sin conectividad IPv6 local en este entorno'` — **sin
    distinguir si el binario no existe (ENOENT) de si el destino
    simplemente no respondió** (100% de pérdida, exit code 1 con `ping`
    funcionando perfectamente). Un dominio real, con IPv6 pública y
    perfectamente operativo, que solo bloquea ICMPv6 en su firewall,
    produciría el mismo mensaje que "este nodo no tiene IPv6" — una
    conflación exactamente del tipo que esta fase debía evitar.
- **Frontend** (`case 'ping'`/`case 'pingv6'`, `index.html`):
  ```js
  status: typeof summary.loss === 'number' && summary.loss < 100 ? 'ok' : 'fail'
  ```
  En la práctica, dado que `execFileAsync` ya rechaza ante 100% de
  pérdida (ver arriba), esta rama `'fail'` basada en `summary.loss` es
  código casi inalcanzable — el camino real para "no responde" pasa por
  `data.error` → `status: 'error'`, no por esta comparación. Aun así, la
  intención expresada en el código (100% pérdida = fail) confirma el
  problema conceptual central que esta fase debía corregir: **tratar la
  ausencia de respuesta ICMP como una falla del dominio**, cuando puede
  ser simplemente una decisión de seguridad legítima del operador del
  sitio (bloquear ICMP es una práctica común y razonable).

## 2. Diagnóstico operativo real (server1, 2026-09-16)

Verificado con acceso SSH directo a `server1` — nunca inferido.

### Host (server1, fuera del contenedor)

```
$ which ping && getcap $(which ping)
/usr/bin/ping
/usr/bin/ping cap_net_raw=ep

$ id
uid=1000(cvq) ... (usuario normal, sin root)

$ ping -c 2 -n -W 2 1.1.1.1
2 packets transmitted, 2 received, 0% packet loss   -> FUNCIONA SIN CAMBIOS (IPv4)
```

`/usr/bin/ping` tiene la file capability `cap_net_raw=ep` ya asignada —
funciona para cualquier usuario sin necesitar root ni un binario setuid.
**Clasificación IPv4 en el host: FUNCIONA SIN CAMBIOS.**

```
$ ip -6 addr show dev enp2s0
    inet6 fe80::.../64 scope link          <- solo link-local, ninguna global

$ ip -6 addr show scope global
    (tailscale0) inet6 fd7a:115c:a1e0::.../128   <- ULA (fc00::/7) de Tailscale, no pública

$ ping -6 -c 2 -n -W 2 2606:4700:4700::1111   (Cloudflare)
2 packets transmitted, 0 received, 100% packet loss

$ ping -6 -c 2 -n -W 2 2001:4860:4860::8888   (Google)
2 packets transmitted, 0 received, 100% packet loss
```

**El host NO tiene conectividad IPv6 real hacia Internet** — confirmado
con pings reales a dos anclas públicas conocidas (Cloudflare y Google),
ambos con 100% de pérdida. La única dirección "global" visible es la ULA
interna de Tailscale, que no es Internet pública. Esto se determinó por
prueba directa, no por inferencia de la existencia de una ruta por
defecto IPv6 (que sí existe, mal — apunta a un next-hop link-local sin
salida real) ni por la simple presencia de registros AAAA de terceros.

### Contenedor Docker (`mediciones`, donde corre `server.js` en producción)

```
$ docker exec mediciones which ping
OCI runtime exec failed: exec: "ping": executable file not found in $PATH

$ docker exec mediciones id
uid=0(root) gid=0(root)   <- corre como root, pero irrelevante: el binario no existe

$ docker exec mediciones ip -6 addr show
sh: ip: not found
```

**El contenedor de MEDICIONES no tiene el binario `ping` instalado en
absoluto** (imagen Node mínima, sin `iputils-ping` ni herramientas de red).
No es un problema de privilegios/capabilities — el ejecutable ni siquiera
existe en la imagen. **Clasificación: REQUIERE CAMBIO DE CONTENEDOR.**

### Clasificación final (paso 9 de la tarea)

| Entorno | IPv4 | IPv6 |
|---|---|---|
| Host (server1) | FUNCIONA SIN CAMBIOS (`cap_net_raw` de archivo, sin root) | NO DETERMINADO por privilegios — **inviable**: sin salida IPv6 real |
| Contenedor `mediciones` (donde corre el código real) | **REQUIERE CAMBIO DE CONTENEDOR** (binario ausente) | **REQUIERE CAMBIO DE CONTENEDOR** + el host tampoco tiene IPv6 real |

**Decisión, siguiendo el principio "seguridad debe prevalecer" y "no
modificar Docker todavía"**: no se toca ningún Dockerfile ni
docker-compose en esta fase. `ping`/`pingv6` se implementan completos y
correctos en el código, pero **quedan deshabilitados por defecto**
(`default: false`) — mismo patrón exacto que STARTTLS en Fase 1 (TCP/25
bloqueado en el nodo, ver `DIAGNOSTICO_TCP25_MEDICIONES.md`): la
capacidad existe y es correcta, la habilitación real queda pendiente de
una decisión de infraestructura explícitamente fuera de esta fase. Hasta
que se actualice la imagen del contenedor, **ambos checks se
autorreportarán como `MEASUREMENT_ERROR` (`PING_BINARY_NOT_FOUND`) de
forma honesta** — no se simula ni se oculta la limitación.

## 3. Pregunta técnica definida

- **ping (IPv4)**: ¿Alguna dirección IPv4 pública del dominio (de hasta 3
  muestreadas) responde a ICMP Echo Request desde este nodo de medición?
- **pingv6 (IPv6)**: ¿Alguna dirección IPv6 pública del dominio (de hasta
  3 muestreadas) responde a ICMPv6 Echo Request desde este nodo de
  medición, asumiendo que el propio nodo tiene conectividad IPv6 real?

No se usa "¿el dominio funciona?" — ping no lo demuestra: un sitio puede
estar perfectamente operativo (HTTP/HTTPS/correo funcionando) y bloquear
ICMP por completo.

## 4. Arquitectura elegida: dos checks separados (Opción A/C)

Se mantiene la separación IPv4/IPv6 de Paraguay, pero por una razón
propia y verificada, no por copiarla: **`ping` y `pingv6` ejercitan
capacidades genuinamente distintas del nodo y del dominio**, exactamente
como ya lo hacen los checks preexistentes `ipv4`/`ipv6` en MEDICIONES
Ecuador (separados desde antes de esta fase). Sus modos de fallo son,
además, estructuralmente diferentes: un fallo de `ping` es casi siempre
una propiedad del DOMINIO (bloquea ICMP o no); un fallo de `pingv6` en
este momento es casi siempre una propiedad del NODO (sin IPv6 real) —
mezclar ambos en un solo check `reachability` habría forzado un único
veredicto que ocultaría cuál de las dos cosas está realmente en juego.
No se persiguió el conteo de Paraguay — la decisión se tomó evaluando la
arquitectura ya existente en Ecuador (ver Fase 2/3, donde en cambio se
evitó crear un check nuevo cuando no representaba una pregunta técnica
distinta).

Conteo final: **58 → 60** (dos checks nuevos).

## 5. Implementación

### `server.js`

- `execFileAsync(file, args, options)` — envoltorio propio sobre
  `childProcess.execFile` (callback nativo, nunca `exec`/shell), que
  adjunta `stdout`/`stderr` al error en caso de rechazo — necesario para
  poder distinguir "el proceso corrió pero salió con código != 0"
  (típicamente 100% de pérdida, un resultado real) de "el proceso no pudo
  ni arrancar" (`ENOENT`, binario ausente). Verificado en vivo (Node
  v24.11.1, prueba cruzada Windows/Linux) que `error.stdout` contiene el
  texto real cuando el proceso sí llegó a ejecutarse y escribir salida.
- `hasGlobalIPv6()` — usa `os.networkInterfaces()` para verificar si el
  propio proceso Node tiene alguna interfaz no interna con una dirección
  IPv6 que no sea link-local/ULA/loopback (reutiliza
  `safeWebFetchAdapter.isBlockedIp` para esa clasificación). Nunca se
  infiere de la existencia de registros AAAA de ningún dominio — se
  verifica la configuración de red real del nodo, sin generar tráfico
  adicional.
- `parsePingSummary(stdout)` — parsea `transmitted`/`received`/`loss`/
  `rttAvgMs` de la salida real de `ping` (formato verificado en vivo
  contra `server1`, tanto para el caso de éxito como para 100% de
  pérdida).
- `pingOneAddress(ip, family)` — antes de nada, `net.isIP(ip) !== family`
  aborta con `PING_EXEC_ERROR`: defensa en profundidad — nunca se llega a
  `execFile` con algo que no sea una IP ya validada de la familia
  correcta. Prueba, en orden, los mismos pares de candidatos que Paraguay
  (`ping6` primero, luego `ping -6`, por portabilidad BusyBox/iputils),
  pero **siempre contra la IP, nunca contra el dominio**. Si el proceso
  sale con código != 0 pero con `stdout` real, se interpreta como una
  medición válida (posible 100% de pérdida), no como un fallo.
- `runIcmpCheck(domain, family, res)` — flujo común a `handlePing`/
  `handlePingV6`:
  1. Para family=6, si `hasGlobalIPv6()` es falso, responde de inmediato
     `PINGV6_NODE_NO_IPV6` sin resolver DNS ni ejecutar nada.
  2. Resuelve `{v4, v6}` con `resolveAddresses(domain)` (ya existente,
     reutilizado de Fase 2).
  3. Si la familia pedida no tiene direcciones: distingue "el dominio no
     existe en absoluto" (ninguna familia resolvió y tampoco hay NS —
     mismo criterio que `domainHasNoAddressButIsRealZone`, ya usado por
     `rpki`/`w3c`) de "el dominio es real pero no tiene esta familia"
     (`PING_NO_A`/`PINGV6_NO_AAAA`).
  4. Filtra las IPs resueltas con `safeWebFetchAdapter.isBlockedIp` —
     las privadas/reservadas se reportan como `state:'blocked'`, nunca se
     les hace ping.
  5. Muestrea hasta `MAX_PING_IPS` (3) de las IPs públicas restantes, en
     el orden en que las devolvió el DNS — política simple y documentada,
     no una selección arbitraria oculta.
  6. Si el binario de ping no existe (`PING_BINARY_NOT_FOUND`) en el
     primer intento, corta el lote de inmediato (todas las IPs
     fallarían igual) y reporta el fallo a nivel de todo el check — no
     tiene sentido reintentar N veces un binario que no existe.
- `handlePing`/`handlePingV6` — delegan en `runIcmpCheck` con
  `family = 4`/`6`.

### `index.html`

- `groupDefinitions`: `ping`/`pingv6` añadidos al grupo "Diagnóstico
  técnico" (junto a `openports`, con el mismo espíritu: conectividad
  básica, no una prueba de seguridad ni de disponibilidad formal), ambos
  `default: false`.
- `checkGlossary`: texto explícito indicando que es ICMP, que se mide
  desde el nodo, que la ausencia de respuesta no implica caída, y — para
  `pingv6` — que depende de que el propio nodo tenga IPv6 real.
- `NOT_APPLICABLE_CODES` ampliado con `PING_NO_A`/`PINGV6_NO_AAAA`
  (mismo patrón que `WEBFETCH_NO_ADDRESS_RECORD`).
- `case 'ping'`/`case 'pingv6'`: **siempre `INFO`** cuando la medición se
  completa (responda o no cada IP) — nunca PASS/FAIL. `pingv6` además
  reconoce `PINGV6_NODE_NO_IPV6` como **INCONCLUSIVE** explícito (no pasa
  por `classifyDataError`, es un caso bespoke: la ausencia de IPv6 del
  propio nodo no es un hallazgo sobre el dominio).
- `buildPingDetails()` — helper compartido que arma el detalle por IP
  (responde/no responde, paquetes, RTT, o el motivo si está bloqueada o
  en error), más una nota de muestreo si se recortaron IPs.

## 6. Semántica de resultados

| Estado | Condición |
|---|---|
| INFO | Medición completada — al menos un resultado `measured`, responda o no cada IP. **Nunca PASS/FAIL**: bloquear ICMP es una decisión de seguridad legítima, no una falla. |
| NOT_APPLICABLE | El dominio no tiene registros de la familia evaluada (`PING_NO_A`/`PINGV6_NO_AAAA`) |
| INCONCLUSIVE | (solo `pingv6`) Este nodo no tiene conectividad IPv6 real (`PINGV6_NODE_NO_IPV6`) |
| MEASUREMENT_ERROR | Dominio inexistente, binario de ping ausente, fallo real de ejecución, respuesta no parseable |

**Decisión explícita, revisada en el cierre**: no se usa PASS/FAIL en
ningún caso para `ping`/`pingv6`, ni siquiera "PASS si alguna IP
responde" (una de las opciones que planteaba la tarea). Razón: convertir
"responde" en PASS crea una asimetría engañosa — implicaría que bloquear
ICMP (una práctica de endurecimiento perfectamente razonable y común) es
"peor" que responder, cuando no lo es. Ambos son resultados igualmente
válidos de un check puramente descriptivo; se muestran como hechos
(`detalle por IP`), nunca como un veredicto normativo.

## 7. Política de múltiples IP

- Se resuelven todas las direcciones de la familia solicitada.
- Se filtran las privadas/reservadas (`state: 'blocked'`, nunca
  contactadas).
- De las públicas restantes, se muestrean **como máximo 3** (`MAX_PING_IPS`),
  en el orden devuelto por el DNS — una política simple, documentada, no
  "aleatoria" ni oculta.
- Cada IP se reporta de forma independiente en `results[]` — nunca se
  colapsa una situación mixta ("IP A responde, IP B no") en un solo
  booleano. El detalle del frontend lista cada IP explícitamente.
- Si se recortaron IPs por el muestreo, se informa cuántas del total se
  evaluaron (`sampledCount`/`totalPublicIps`).

## 8. Seguridad

- **Nunca se ejecuta ping contra el dominio ni una cadena de usuario** —
  se resuelve primero (`resolveAddresses`, DNS estándar de Node) y solo
  se pasa a `execFile` una IP ya confirmada por `net.isIP()`.
- **Filtrado de IP privada/reservada**: reutiliza
  `safeWebFetchAdapter.isBlockedIp` (mismo guard ya usado por `rpki` en
  Fase 2) — bloquea loopback, RFC1918, link-local, ULA IPv6, CGNAT,
  multicast, y — como efecto colateral seguro y verificado con test — 
  cualquier valor que ni siquiera sea una IP válida (el `family===0` de
  `net.isIP()` cae al `return true` final de `isBlockedIp`, es decir,
  "bloqueado por defecto" ante cualquier entrada no reconocida).
- **Nunca se usa shell**: `childProcess.execFile` (nunca `exec`), con los
  argumentos siempre en un array — verificado con test dedicado.
- **Defensa en profundidad adicional**: `pingOneAddress()` valida
  `net.isIP(ip) === family` inmediatamente antes de construir los
  argumentos, aunque en la práctica `isBlockedIp` ya habría descartado
  cualquier valor no válido antes de llegar ahí — dos capas
  independientes, no una sola.
- **Sin riesgo de "reflector"/escaneo**: a diferencia de Paraguay (que
  permite pingear cualquier IP a la que el dominio del usuario resuelva,
  incluidas privadas), Ecuador nunca contacta una IP privada, y el número
  de paquetes/IPs por invocación está topado (ver rate limiting abajo) —
  no es utilizable como herramienta de escaneo de red interna ni de
  amplificación.
- Ninguna entrada llega a un shell interpretativo en ningún punto del
  flujo.

## 9. Rate limiting / límites operativos

- `MAX_PING_IPS = 3` por familia, por invocación.
- `PING_PACKET_COUNT = 3` paquetes ICMP por IP (máximo 9 paquetes ICMP
  totales por invocación de `ping` o `pingv6`).
- `-W 2` (timeout de 2s por paquete) + `PING_TIMEOUT_MS = 8000` como tope
  duro a nivel de Node (`execFile`'s `timeout`), independiente de si
  `ping` respeta su propio flag.
- Ejecución secuencial (no paralela) por IP — sin ráfagas, sin barridos,
  sin flood, sin probar redes completas.
- No se agregó un limitador de tasa nuevo a nivel de endpoint HTTP — 
  mismo patrón ya aceptado en todo el proyecto (checks on-demand por
  dominio, sin límite propio de solicitudes; ver auditoría de Fase 2).

## 10. Tests

`test/medicionesPingCheck.test.js` — 22 casos, sin red real ni binarios
reales (mocks de `dns.resolve4/resolve6/resolveNs`,
`childProcess.execFile` y `os.networkInterfaces`):

IPv4: responde · no responde (100% pérdida con medición válida) ·
múltiples IP todas responden · múltiples IP mezcla · ninguna responde ·
sin A (NOT_APPLICABLE, distinguido de NXDOMAIN real) · IP privada
bloqueada · fallo de ejecución tipo timeout (proceso matado, sin stdout
útil) · binario ausente (corta el lote sin reintentar) · respeta el
muestreo máximo de IPs.

IPv6: responde · no responde · sin AAAA (NOT_APPLICABLE) · nodo sin IPv6
real (INCONCLUSIVE, cero llamadas DNS/exec) · múltiples AAAA · dirección
ULA bloqueada · binario ausente.

Seguridad: valor DNS no-IP con metacaracteres de shell, argumento que
empieza con "-", y otro con metacaracteres — los tres verificados como
bloqueados antes de cualquier `execFile` (con un mock que lanza si se
invoca) · confirmación de que los argumentos siempre viajan en un array,
nunca concatenados.

Registrado en `package.json` (`npm test`).

## 11. Comparativo Paraguay vs. Ecuador

| Aspecto | Paraguay | Ecuador (Fase 4) | Motivo |
|---|---|---|---|
| Método de ejecución | `execFile`, contra el **dominio** directamente | `execFile`, contra una **IP ya resuelta y validada** | Nunca delegar la resolución/decisión de destino al binario externo |
| IPv4/IPv6 | Un solo intento, el que el resolver del sistema elija | Hasta 3 IP por familia, cada una reportada por separado | Visibilidad real ante múltiples IP/CDN/anycast |
| Privilegios | No diagnosticado en el código; sin guard | Diagnosticado en vivo: host OK (cap_net_raw), contenedor sin binario — documentado, sin modificar Docker | Cumple "primero diagnosticar, seguridad prevalece" |
| Seguridad | Sin filtro de IP privada — riesgo real de pinguear destinos internos | `isBlockedIp` obligatorio antes de cualquier ping | Elimina el riesgo de "reflector"/probe interno |
| Interpretación de ausencia de respuesta | 100% pérdida tiende a tratarse como fallo (`fail`/`error` genérico) | Siempre INFO — descriptivo, nunca normativo | Bloquear ICMP es una práctica de seguridad legítima, no un defecto |
| IPv6 sin conectividad del nodo | Conflada con "destino no respondió" (mismo mensaje genérico) | Detectada por separado (`os.networkInterfaces()`) antes de intentar nada, estado INCONCLUSIVE propio | Nunca presentar una limitación del nodo como un hallazgo del dominio |
| Límites | Sin límite explícito documentado | 3 IP × 3 paquetes máx., timeout corto, ejecución secuencial | Evita convertir el check en herramienta de barrido/flood |
| Estados | ok/fail/error (tres, ambiguos) | 6 estados del modelo Ecuador, con INCONCLUSIVE/NOT_APPLICABLE propios | Consistencia con el resto de MEDICIONES Ecuador |

## 12. Limitaciones operativas

- **`ping`/`pingv6` no son funcionales en el despliegue actual**: el
  contenedor `mediciones` no tiene el binario `ping` instalado — ambos
  checks reportarán `MEASUREMENT_ERROR` (`PING_BINARY_NOT_FOUND`) hasta
  que se actualice la imagen (fuera de alcance de esta fase, requiere una
  decisión explícita posterior).
- **`pingv6` adicionalmente no es viable a nivel de red** en `server1`:
  ni el host ni, por lo tanto, el contenedor tienen conectividad IPv6
  real hacia Internet (verificado con pings reales a anclas públicas).
  Aunque se instale `iputils-ping` en el contenedor, `pingv6` seguirá
  reportando `PINGV6_NODE_NO_IPV6` (INCONCLUSIVE) en este nodo específico
  hasta que exista salida IPv6 real — una limitación de infraestructura,
  no del código.
- Ambos checks quedan con `default: false`, exactamente como STARTTLS en
  Fase 1 — implementados y correctos, disponibles para cuando la
  infraestructura lo permita, sin fingir una capacidad que hoy no existe.
- El muestreo de IPs (máx. 3) es una política simple documentada, no una
  selección "representativa" sofisticada — para dominios con más de 3 IPs
  por familia, las restantes no se evalúan en esa invocación.

## 13. Decisiones consolidadas de Fase 4 (cierre, 2026-09-16)

Validación final realizada antes del commit de cierre. Resume, sin
repetir el detalle ya expuesto arriba, las decisiones que quedan fijadas
para `ping`/`pingv6` a partir de este punto.

### Finalidad exacta

- **ping (IPv4)**: ¿alguna dirección IPv4 pública del dominio, hasta un
  máximo de 3, responde a ICMP Echo desde el nodo MEDICIONES?
- **pingv6 (IPv6)**: ¿alguna dirección IPv6 pública del dominio, hasta un
  máximo de 3, responde a ICMPv6 Echo desde el nodo MEDICIONES, siempre
  que el propio nodo tenga conectividad IPv6 real?

Confirmado expresamente: **ninguno de los dos mide disponibilidad HTTP,
ni si el dominio "funciona"**. Ausencia de respuesta ICMP no equivale a
fallo del servicio — un firewall puede bloquear ICMP legítimamente sin
que eso diga nada sobre si el sitio, el correo o cualquier otro servicio
del dominio están operativos.

### Por qué no se usa PASS/FAIL

ICMP es una señal puramente descriptiva: un servidor perfectamente
operativo puede bloquear ICMP deliberadamente por endurecimiento de
seguridad, y eso no es un defecto de configuración. Usar PASS cuando
responde y "algo distinto" cuando no, crearía una asimetría engañosa —
daría a entender que bloquear ICMP es peor que permitirlo, cuando ambas
son decisiones igualmente válidas del operador del sitio. Por eso el
estado es **siempre INFO** cuando la medición se ejecuta correctamente,
con el detalle real (responde/no responde, paquetes, RTT) por cada IP —
nunca un veredicto normativo.

### Semántica final (confirmada)

| Estado | Condición |
|---|---|
| INFO | Medición ICMP ejecutada correctamente — responda o no cada IP, con detalle individual (responde/no responde, paquetes, RTT si se obtuvo) |
| NOT_APPLICABLE | `ping`: el dominio no tiene registros A. `pingv6`: el dominio no tiene registros AAAA |
| INCONCLUSIVE | Existe la familia de dirección, pero el nodo de medición no tiene la capacidad de red necesaria — hoy, siempre `pingv6` por falta de conectividad IPv6 real del nodo |
| MEASUREMENT_ERROR | Binario ausente, fallo de ejecución, error inesperado, o el dominio no resuelve en ninguna familia (DNS defectuoso/inexistente) |

Confirmado con test dedicado (`ping_ipv4_binario_ausente_corta_el_lote`,
`pingv6_binario_ausente`) que la ausencia del binario `ping` en el
contenedor **nunca** se traduce en una evaluación negativa del
dominio — se reporta `MEASUREMENT_ERROR` (`PING_BINARY_NOT_FOUND`), un
hecho sobre el nodo de medición, no sobre el dominio evaluado.

### Política multi-IP (confirmada)

Máximo 3 IPs públicas por familia, muestreadas en el orden que devuelve
el DNS; cada IP con su propio resultado individual (nunca colapsado en un
booleano); ejecución secuencial (nunca en paralelo, nunca en ráfaga);
máximo 3 paquetes ICMP por IP; timeout de 2s por paquete más 8s duros a
nivel de proceso Node. Resultados mixtos (algunas IP responden, otras no)
se muestran tal cual, sin ocultar la diversidad.

### Seguridad (confirmada)

El dominio nunca se pasa al binario de ping — se resuelve primero
(`resolveAddresses`), se filtran las IPs privadas/reservadas/no válidas
con `isBlockedIp()` (RFC1918, loopback, link-local, ULA IPv6, CGNAT,
multicast, y cualquier valor que ni siquiera sea una IP reconocible por
`net.isIP()`), y solo se ejecuta `childProcess.execFile` — nunca un
shell — contra una IP ya validada, con los argumentos siempre en un
array. Verificado con tests que un valor DNS con metacaracteres de shell,
un valor que empieza con "-", y otro con sintaxis de sustitución de
comando, quedan bloqueados antes de que `execFile` se invoque siquiera
(mock configurado para fallar el test si llegara a llamarse). No existe
ninguna ruta por la que la entrada del usuario controle flags del
binario ni resulte en inyección de comandos.

### Rate limiting / abuso

Límites ya vigentes: 3 IP por familia × 3 paquetes = máx. 9 ICMP por
invocación, timeout corto, ejecución secuencial sin concurrencia. El
proyecto MEDICIONES **no tiene, en general, un limitador de tasa a nivel
de endpoint HTTP para ningún check** (patrón ya documentado en la
auditoría de Fase 2: checks on-demand por dominio, sin límite propio de
solicitudes) — no se introdujo uno nuevo específico para `ping`/`pingv6`
en esta fase. Si en el futuro se detecta abuso real del endpoint (no
observado hasta ahora), se registra aquí como **riesgo pendiente de
evaluación**, no como algo que deba resolverse hoy sin evidencia de
necesidad.

### Situación del contenedor y de la red IPv6 de server1 (sin cambios en esta fase)

- El contenedor `mediciones` no tiene el binario `ping` instalado —
  confirmado con `docker exec`, no modificado.
- El host `server1` sí puede hacer ping ICMPv4 (`cap_net_raw` de archivo,
  sin necesitar root) pero no tiene conectividad IPv6 real hacia Internet
  — confirmado con pings reales a anclas públicas (Cloudflare, Google),
  ambos con 100% de pérdida; no se modificó ninguna configuración de red.
- Ninguna capability, paquete, imagen Docker ni ruta de red fue tocada en
  esta fase — solo diagnóstico de solo lectura.

### Por qué ambos quedan `default: false`

Mismo criterio que STARTTLS en Fase 1: la capacidad está implementada
completa y correctamente, pero no puede ejecutarse de forma fiable en el
despliegue actual (`ping` ausente en el contenedor; `pingv6` además sin
salida IPv6 real en el nodo). Activarlos por defecto expondría al usuario
final a un check que siempre falla por una razón de infraestructura, no
por nada del dominio medido — indistinguible en la práctica de un check
roto. Quedan disponibles para habilitarse manualmente y listos para
funcionar en cuanto la infraestructura lo permita, sin necesitar cambios
de código.

### Pendiente infraestructura IPv4 ICMP

Si en el futuro se quiere activar `ping`, incorporar el binario `ping`
(paquete `iputils-ping` o equivalente según la base de la imagen) de
forma controlada en el Dockerfile/imagen del contenedor `mediciones`, y
volver a validar con el mismo procedimiento de diagnóstico usado en esta
fase (host + contenedor, prueba mínima con un ancla pública conocida)
antes de cambiar `default` a `true`.

### Pendiente IPv6

No activar `pingv6` hasta que `server1` disponga de conectividad IPv6
global funcional real hacia Internet (verificable con un ping real a un
ancla pública IPv6 conocida, no por la sola presencia de una ruta por
defecto ni de una dirección ULA/link-local). Es una decisión de
infraestructura de red, explícitamente fuera del alcance de MEDICIONES
como módulo de software.
