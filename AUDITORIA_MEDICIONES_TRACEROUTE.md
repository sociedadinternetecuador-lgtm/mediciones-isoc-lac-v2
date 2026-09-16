# Auditoría — Check "Traceroute" en MEDICIONES Ecuador

**Fecha de la auditoría original**: 2026-09-16
**Fecha de cierre del backend residual**: 2026-09-16
**Alcance**: exclusivamente `traceroute`. DNSSEC independiente, fuera de alcance.
**Restricciones de la fase de auditoría (§0-§15 originales)**: no se restauró
código, no se modificó producción, no se hizo commit, no se hizo push, no se
desplegó. Solo lectura de código, git log/show de dos repositorios, y
diagnóstico de entorno de solo lectura por SSH (sin instalar nada).

## Addendum — cierre del backend residual (2026-09-16)

Tras esta auditoría se decidió **no recuperar traceroute en `server1`** y
evaluar una futura implementación **únicamente sobre un nodo de medición
dedicado** (§13 de este documento). Como consecuencia, el backend heredado
que esta auditoría había documentado como "presente pero inalcanzable desde
la UI" (§3.4, clasificación B+D) se consideró código muerto sin valor de
mantenerlo, y se eliminó en una fase de limpieza separada:

- **Frontend**: ya estaba eliminado desde el commit `e1ed8bd` (2026-09-12) —
  sin cambios en esta fase.
- **Backend residual eliminado ahora**: `handleTraceroute(domain, res)`, la
  ruta de despacho `segments[0] === 'traceroute'` y el comentario
  explicativo que las acompañaba, todos en `server.js`. La llamada a
  `api.hackertarget.com/mtr/?q=<dominio>` (exclusiva de esta función)
  desapareció con ella.
- **No se tocó** `handleAssociatedHosts` ni su llamada a
  `api.hackertarget.com/hostsearch/?q=<dominio>` — es un check distinto, no
  relacionado con traceroute, fuera del alcance de esta limpieza.
- **`groupDefinitions` no se modificó** — traceroute ya no era un check
  activo (no contaba entre los 60), así que esta limpieza no cambia el
  conteo: 60 antes, 60 después.
- **Test de regresión agregado**:
  `test/medicionesTracerouteLegacyRemoved.test.js` — confirma que no existe
  ruta backend `/traceroute`, que `handleTraceroute` no existe, que no hay
  referencia productiva a `api.hackertarget.com/mtr`, que
  `handleAssociatedHosts`/`hostsearch` sigue intacto, y que el registro de
  checks se mantiene en 60 sin duplicados.
- **Estado resultante**: `traceroute` queda oficialmente **fuera de
  MEDICIONES operativo actual** — sin frontend, sin backend, sin
  dependencia de HackerTarget. Una futura implementación (si se retoma) se
  evaluará exclusivamente sobre un nodo de medición dedicado, siguiendo la
  arquitectura de seguridad/privacidad propuesta en §8-§10 de este
  documento (resolución→filtrado de IP privada/SSRF→ejecución, sin exponer
  topología de red del nodo, semántica INFO/NOT_APPLICABLE/INCONCLUSIVE/
  MEASUREMENT_ERROR en vez de PASS/FAIL).

El resto de este documento (§1-§15 más abajo) es el registro original de la
auditoría y se conserva sin alterar como referencia histórica.

## 0. Baseline

- Rama: `main`. HEAD: `104075f` ("refactor(dnssec): remove unreachable
  delegation broken state").
- `git status --short`: solo los 7 archivos/directorios ya conocidos de fases
  anteriores (`AUDITORIA_FORK_MEDICIONES.md`, `data/exercises/`, dos PDF de
  `public/docs/`, `scripts/exercise-24-domains/`,
  `scripts/regional-study/input/mediciones_20_paises_csv.zip`,
  `test/dnssecBrokenDelegationAudit.test.js`) — ninguno tocado en esta fase.
- `npm test`: verde, incluye `conteo_60_checks` → **60 checks confirmados**,
  sin duplicados, todos con `case` de frontend y ruta de backend propia.
- No se modificó ningún archivo de producción durante esta auditoría.

---

## 1. Implementación original (commit ancestral `0d14f45`, Paraguay, base del fork)

Reconstruida desde el código real de `nicocamarao/mediciones-isoc-lac` en ese
commit exacto (`gh api .../contents/server.js?ref=0d14f45...`), no desde
README.

- **Backend**: `handleTraceroute(domain, res)` — sin binario local, sin
  resolución DNS propia. Hace un único `fetch` HTTP a un servicio de
  terceros:
  ```
  https://api.hackertarget.com/mtr/?q=${domain}
  ```
  (dominio normalizado interpolado sin `encodeURIComponent`).
- **Detección de fallo**: si la respuesta es vacía o contiene
  `"api count exceeded"` o `/error/i`, se devuelve
  `{ domain, error: 'Servicio no disponible (límite alcanzado)' }`.
- **Parsing**: `text.split('\n').slice(1)` (descarta cabecera), filtra líneas
  no vacías, y se queda solo con las que matchean `/^\d+\./` (líneas de hop
  numeradas del formato MTR de HackerTarget). Sin estructura adicional —
  cada hop es la línea de texto cruda.
- **Endpoint expuesto**: `GET /traceroute/:domain`.
- **Frontend** (`index.html` en el mismo commit):
  - `groupDefinitions`: `{ key: 'traceroute', label: 'Traceroute', default: false }`,
    dentro del grupo "IP y Red".
  - `case 'traceroute':` — pide `${API_BASE}/traceroute/${ascii}`, si
    `data.error` → `status: 'error'`; si no, toma `hops = data.hops?.slice(0, 10)`
    (**cap visual de 10 saltos**, aunque el backend ya devolvía como máximo lo
    que HackerTarget reportara) y `status: hops.length ? 'ok' : 'info'`.
- **IPv4/IPv6**: no diferenciado — una sola ruta, una sola familia implícita
  (la que HackerTarget decida resolver). No hay `traceroute6`.
- **Timeout**: no hay timeout propio explícito en `handleTraceroute`; depende
  del timeout genérico de `fetch` del proyecto en ese commit.
- **Resultado esperado**: lista de líneas de texto tipo `1.  192.168.1.1  2.3 ms`,
  máximo 10 mostradas en UI, o `status: 'info'` si no hay hops (nunca `'error'`
  solo por tener menos saltos).

**Conclusión clave**: la implementación original **nunca ejecutó un binario
de red** ni hizo su propia resolución/filtrado de IP — dependía enteramente
de la disponibilidad gratuita de un API de terceros.

---

## 2. Implementación actual en Paraguay (upstream real, hoy)

Re-obtenida en esta sesión directamente desde el repo (no cacheada de fases
previas) y diffeada contra una copia anterior — idéntica, sin drift.

Paraguay **reescribió por completo** el mecanismo: pasó de "API HTTP de
terceros" a "binario local vía `execFile`" — el mismo patrón arquitectónico
que ya tenían (y que Ecuador corrigió) para `ping`.

```js
function parseTracerouteOutput(output) {
  // separa por líneas, matchea /^(\d+)\s+(.*)$/ por hop,
  // detecta "unresolved" si la línea empieza con *,
  // extrae host (dominio o IP) y todos los "N ms" como rtts[]
}

async function runLocalTraceroute(host) {
  const candidates = [
    ['/usr/sbin/traceroute', ['-n', '-m', '5', '-q', '1', '-w', '1', host]],
    ['traceroute', ['-n', '-m', '5', '-q', '1', '-w', '1', host]],
  ];
  // prueba cada candidato con execFileAsync hasta que uno funcione
}

async function handleTraceroute(domain, res) {
  domain = normalizeDomain(domain);       // solo IDNA, sin resolución/filtrado
  const data = await runLocalTraceroute(domain); // dominio CRUDO al binario
  sendJSON(res, 200, { domain, command: 'traceroute', hops: data.hops, lines: data.lines });
}
```

- **Flags**: `-n` (sin resolución inversa), `-m 5` (**máximo 5 saltos**,
  muy bajo — descriptivo, no un trace completo), `-q 1` (1 sonda por salto),
  `-w 1` (1s de espera por sonda).
- **Input**: el dominio normalizado (solo IDNA) se pasa **directo** como
  argumento al binario — sin resolución DNS propia, sin filtrado de IP
  privada/reservada.
- **Ejecución**: `execFileAsync` (child_process.execFile promisificado) —
  **sin shell**, argumentos como array. Esto descarta inyección de comandos
  por metacaracteres de shell (`;`, `&&`, backticks), pero **no** valida que
  el destino resuelto sea una IP pública.
- **IPv4/IPv6**: sigue sin haber `traceroute6` — una sola familia.
- **Timeout**: `REQUEST_TIMEOUT_MS` (25000ms por defecto vía env var),
  aplicado a `execFileAsync`.
- **Salida**: hops estructurados (`hop`, `line`, `unresolved`, `host`, `rtts[]`),
  más las líneas crudas. Mucho más rico que el texto plano del original.
- **Manejo de errores**: si ningún candidato de binario funciona, se
  propaga el último error como `{ domain, error, command: 'traceroute' }` —
  no distingue "binario ausente" de "sin permisos" de "timeout de red".

### Tabla comparativa — Base `0d14f45` vs. Paraguay actual

| Aspecto | Base `0d14f45` | Paraguay actual |
|---|---|---|
| Comando | Ninguno (HTTP a API externa) | `traceroute` local vía `execFile` |
| Flags | N/A (decide HackerTarget) | `-n -m 5 -q 1 -w 1` |
| Input al comando | N/A | Dominio normalizado (IDNA), **sin resolver a IP** |
| Seguridad | Depende de un tercero; sin control propio | Sin shell (execFile ok), pero sin filtrado de IP privada/SSRF |
| IPv6 | No | No |
| Núm. de saltos | Lo que reporte HackerTarget (UI capa a 10) | Máx. 5 (`-m 5`) |
| Timeout | Implícito (fetch genérico) | Explícito, `REQUEST_TIMEOUT_MS` (25s) |
| Salida | Texto crudo por línea | Objetos estructurados (`hop`, `host`, `rtts`, `unresolved`) |
| Parsing | Regex simple `/^\d+\./` | Regex más rico, separa host/rtts/unresolved |
| Frontend | `case 'traceroute'`, cap visual a 10 hops | **No existe** (ver §4) |
| Manejo de errores | Un solo mensaje genérico de "límite alcanzado" | Un solo mensaje genérico, sin distinguir causa |
| Dependencia externa | Total (HackerTarget) | Ninguna, pero depende de que el binario exista en el host/contenedor |

**Lectura**: Paraguay resolvió su dependencia de un API de terceros que dejó
de ser gratuito migrando a un binario local — pero heredó (y nunca corrigió)
el mismo patrón de riesgo que tenía `ping`: pasar el dominio crudo al
proceso hijo sin resolver ni filtrar la IP.

---

## 3. Historia en Ecuador: cómo y cuándo desapareció

### 3.1 Presencia continua desde el inicio

El repositorio local de Ecuador **no es un fork real** de Paraguay (es una
copia manual) — el commit ancestral `0d14f45` no existe en este historial.
Se recorrió el historial completo de Ecuador (`6c9c68c`, commit inicial,
2025-12-08, hasta HEAD `104075f`, 2026-09-16) contando ocurrencias de
`"traceroute"` en `server.js`/`index.html` en cada commit relevante.

- `traceroute` está presente **desde el primer commit** ("Initial commit",
  `6c9c68c`) — descarta la hipótesis A ("nunca se copió correctamente").
- El backend de Ecuador **nunca adoptó la reescritura de Paraguay** (binario
  local `execFile`). Ecuador se quedó con la **implementación original**
  (API de HackerTarget) durante toda su historia, incluso hoy.
- El conteo de referencias sube de 2 a 3 entre `c45582a` (2026-09-09) y
  `e1ed8bd` (2026-09-12) — ese incremento es la adición del comentario
  explicativo (ver 3.2), no una nueva funcionalidad.

### 3.2 Commit exacto de eliminación (frontend)

```
commit e1ed8bd1ce17398e273645beb7d0c2a3f6842380
fecha:  2026-09-12 05:55:49 -0500
mensaje: "checkpoint: respaldo previo a Fase 1 (fix SPF/DMARC/IPv4/IPv6)"
padre:  c45582a427274eb43b2eadabb194f35613643c42 (2026-09-09)
```

Diff real de ese commit (confirmado con `git diff e1ed8bd^ e1ed8bd`):

- `index.html`:
  - Elimina `{ key: 'traceroute', label: 'Traceroute', default: false }` de
    `groupDefinitions`.
  - Elimina la entrada de `checkGlossary`:
    `traceroute: 'Obtiene una ruta aproximada de red usando un servicio externo de diagnóstico.'`.
  - Elimina el bloque `case 'traceroute': { ... }` del switch de ejecución
    de checks.
- `server.js`:
  - **No borra** `handleTraceroute` ni la ruta `/traceroute/:domain` —
    las deja intactas.
  - Agrega un comentario explicativo inmediatamente antes de la función
    (texto real, íntegro):

    > `// Check "Traceroute" retirado de la UI (index.html, 2026-09-09): dependía`
    > `// de api.hackertarget.com/mtr/, que ahora exige API key ("error valid key`
    > `// required") de forma incondicional para cualquier dominio — confirmado`
    > `// repetido y desde dos redes distintas, no es un límite de cuota diario`
    > `// que se recupera solo. No hay alternativa gratuita equivalente (RIPEstat`
    > `// looking-glass necesita un prefijo IP, no un dominio, y mide anuncios`
    > `// BGP, no saltos de red reales; los demás endpoints de HackerTarget piden`
    > `// key también). Ruta dejada sin tocar (mismo patrón que /emailconfig,`
    > `// /httpsecurity, /dnssecurity, /tlsconfig), ahora inalcanzable desde la`
    > `// UI. Ver docs/arquitectura.md.`

### 3.3 Contexto documentado (no inventado — cita directa)

`docs/arquitectura.md`, sección **"Validación cruzada con herramientas
independientes — tercera ronda (2026-09-09)"**, punto **"6. Traceroute —
2026-09-09"**, contiene el registro completo de la investigación que llevó
a la decisión:

- **Problema observado**: el check devolvía siempre
  `{"error":"Servicio no disponible (límite alcanzado)"}` para cualquier
  dominio.
- **Causa diagnosticada**: `api.hackertarget.com/mtr/` responde
  `"error valid key required"` de forma incondicional — verificado con el
  mismo mensaje exacto en 3 repeticiones seguidas, para 4 dominios
  distintos, desde dos redes distintas (entorno de desarrollo y `server1`).
  Se descartó explícitamente que fuera un límite de cuota diaria (esos
  varían o se recuperan; este es constante y textual).
- **Alternativas evaluadas y descartadas**:
  - RIPEstat looking-glass: requiere un **prefijo IP**, no un dominio, y
    mide anuncios BGP, no saltos de red reales — dato distinto al prometido.
  - Otros endpoints de HackerTarget: `/traceroute/` → 404; `/nping/` →
    también exige key.
  - Construir un traceroute real (ICMP/UDP crudo): marcado explícitamente
    como **fuera de alcance en ese momento** — "requiere privilegios
    elevados y es una herramienta de red completa, no un ajuste de un check
    existente".
- **Decisión tomada**: retirar de la UI (mismo criterio aplicado a "TLS
  Security Config"), en vez de simular una funcionalidad que ya no existe
  gratis. Ruta de backend dejada sin tocar deliberadamente, siguiendo el
  mismo patrón que otros checks retirados antes (`/emailconfig`,
  `/httpsecurity`, `/dnssecurity`, `/tlsconfig`).

### 3.4 Clasificación

**No es el caso "no documentado"**: la causa y la decisión están registradas
con evidencia verificable, tanto en el comentario de código como en
`docs/arquitectura.md`. No hace falta inventar intención — está escrita.

Clasificación según las opciones del enunciado:

- **No es A** (nunca se copió correctamente) — presente desde el commit
  inicial.
- **Es una combinación de B y D**:
  - **B** (estuvo presente y luego se eliminó) — el frontend sí se eliminó,
    de forma intencional y documentada, no accidental ni por refactor
    colateral.
  - **D** (existe todavía backend/frontend parcial) — el **backend sigue
    existiendo y sigue siendo alcanzable hoy**: `handleTraceroute` y la
    ruta `if (segments[0] === 'traceroute' && segments[1])` (línea 4245 de
    `server.js` actual) responden a `GET /traceroute/<dominio>` en
    producción ahora mismo, aunque la UI no lo exponga. Funcionalmente está
    roto (HackerTarget exige key), pero el endpoint responde con un JSON de
    error, no con un 404.
  - **No es C**: no fue una consecuencia colateral de una reorganización —
    la reorganización de taxonomía de checks ocurrió en un commit distinto
    (`c45582a`, "antes de reorganizar taxonomía"), y `traceroute` ya no
    estaba en la lista de checks para cuando esa reorganización tocó los
    demás.
  - **No es E**: sí pudo localizarse con precisión (commit, fecha, causa,
    verificación, alternativas descartadas).

---

## 4. Qué mide técnicamente traceroute (no "conectividad")

Definición operativa propuesta:

> *¿Qué ruta IP observable sigue el tráfico desde el nodo de medición de
> MEDICIONES hasta una dirección pública del dominio evaluado, hasta el
> límite de saltos permitido, en el momento de la medición?*

Precisiones importantes:

- Mide la **ruta observada desde ese nodo en ese instante** — no la
  alcanzabilidad del dominio en general, ni su disponibilidad de servicio.
- Un salto que no responde (`*` o `no reply`) **no implica** que el dominio
  esté caído, ni que el salto en sí esté caído — muchos routers descartan o
  limitan la tasa de paquetes ICMP TTL-exceeded por política, sin afectar
  el tráfico real que sí sigue esa ruta. Esto se confirmó empíricamente en
  esta sesión: un `tracepath` real desde `server1` llegó a 8.8.8.8
  reportando 6 saltos con respuesta y luego 20 saltos consecutivos de
  "no reply" — sin que eso signifique que la ruta esté rota.
- No mide el destino final necesariamente: con CDN/anycast (muy común en
  dominios modernos), la "IP pública del dominio" puede ser un borde de
  CDN geográficamente cercano al nodo de medición, no el origen real del
  sitio — el traceroute describe la ruta a ese borde, no al backend.
- Es **temporalmente variable**: rutas BGP cambian, hay balanceo de carga
  por flujo/paquete en algunos proveedores — dos ejecuciones consecutivas
  pueden diferir en saltos intermedios sin que eso sea un error.
- Un `*` (o `no reply`) en cualquier salto, incluido el último, **nunca
  debe interpretarse como fallo del dominio**.

---

## 5. Política ante múltiples IPs

Un dominio puede resolver a varias A/AAAA (round-robin DNS, CDN, anycast).
Recomendación: **una IP por familia, selección determinística** — ej. la
primera IP devuelta por la resolución (mismo criterio que ya usa
`resolveFirstIp()` en el proyecto para otros checks), nunca todas las IPs.
Trazar todas las IPs de un dominio con muchos registros A multiplicaría el
tráfico y el tiempo de respuesta sin aportar valor proporcional — la ruta a
las distintas IPs de un mismo anycast/CDN suele ser redundante en
información.

---

## 6. Arquitectura IPv4/IPv6

Dado que:

- `server1` (el nodo de medición real) **no tiene IPv6 pública real** — solo
  tiene una dirección ULA de Tailscale (`fd7a:115c:a1e0::.../128`), confirmado
  en esta sesión con `ip -6 addr show scope global`. No es una IPv6 de
  Internet enrutable.
- El contenedor **no tiene el binario** en ninguna variante (`traceroute`,
  `tracepath`, `mtr` — los tres ausentes, confirmado con `which` dentro del
  contenedor).

La arquitectura recomendada para una futura implementación es: **un solo
check** (`traceroute`) que reporte lo que encuentre para cada familia
disponible, no dos checks separados (`traceroute4`/`traceroute6`). Si no hay
AAAA, o si el nodo no tiene IPv6 utilizable, el check debe declarar esa
familia como `NOT_APPLICABLE`/`INCONCLUSIVE` (ver §9), nunca como fallo del
dominio. Esto sigue el mismo patrón ya usado en `ping`/`pingv6` de Fase 4,
que si son checks separados fue una decisión ya tomada y no hace falta
repetir la discusión aquí — pero para traceroute, dado que es una sola
"ruta" con dos variantes posibles, un solo check con secciones IPv4/IPv6 en
el resultado es más coherente con lo que el usuario espera ver.

---

## 7. Diagnóstico de entorno (sin modificar nada)

### Host (`server1`)

| Ítem | Resultado |
|---|---|
| `traceroute` | **Ausente** (`which traceroute` → sin salida) |
| `tracepath` | **Presente** (`/usr/bin/tracepath`) |
| Requiere root/capability | `tracepath` **no** — corrió como usuario normal sin `sudo`, sin `CAP_NET_RAW` explícito |
| IPv4 | **Viable** — `tracepath -n 8.8.8.8` devolvió ruta real: `192.168.100.1` (gateway local) → `10.48.0.1` → `10.85.2.150` → `190.152.253.153` (IP pública del ISP) → `10.9.14.2` → `72.14.211.196` (red de Google) → 20 saltos siguientes sin respuesta hasta el límite |
| IPv6 | **No viable** — sin dirección IPv6 pública, solo ULA de Tailscale |

### Contenedor (`mediciones`, Docker, Debian 12 bookworm)

| Ítem | Resultado |
|---|---|
| `traceroute` | Ausente |
| `tracepath` | Ausente |
| `mtr` | Ausente |
| Conclusión | **Ningún binario de traceo de ruta disponible** — requiere modificar el `Dockerfile` (fuera de alcance de esta auditoría) |

### Clasificación

**NO VIABLE ACTUALMENTE** en producción (contenedor) — **REQUIERE BINARIO**
(ninguna de las tres herramientas está instalada en la imagen). En el host,
fuera del contenedor, `tracepath` sería **OPERATIVO** para IPv4 sin
privilegios especiales, pero **NO VIABLE** para IPv6 (sin conectividad IPv6
pública real). El host no es donde corre el servicio (corre en el
contenedor Docker), así que esta distinción es relevante solo si se
considerara ejecutar el binario en el host y proxear el resultado — una
opción que introduce su propia complejidad y no se recomienda sin más
análisis.

---

## 8. Auditoría de seguridad

### 8.1 Ejecución del comando

- Paraguay actual usa `execFileAsync` (sin shell) — **correcto**, descarta
  inyección de comandos vía metacaracteres de shell. Cualquier futura
  implementación en Ecuador debe seguir el mismo patrón (`execFile`/`spawn`
  sin `shell: true`), consistente con cómo se implementó `ping`/`pingv6` en
  Fase 4.
- El riesgo real no es inyección de shell, sino que **el dominio crudo del
  usuario se pasa directo al binario**, sin resolver a IP ni validar que
  esa IP sea pública. `normalizeDomain()` solo hace IDNA
  (`domainToASCII(domain.toLowerCase())`) — no valida formato, no resuelve,
  no filtra rangos.

### 8.2 SSRF / red interna

Riesgo concreto: un atacante puede registrar o controlar un dominio cuyo
registro A/AAAA apunte a una IP privada, loopback, link-local, ULA, CGNAT
(`100.64.0.0/10`) o multicast, y pedir `GET /traceroute/ese-dominio` para
que el contenedor de MEDICIONES ejecute un traceo de ruta contra su propia
red interna — exponiendo en la respuesta JSON la topología interna del nodo
(exactamente lo que se observó empíricamente en esta sesión contra un
destino legítimo: gateway, hops de ISP, IP pública real).

**Flujo recomendado para una futura implementación** (mismo patrón ya
aplicado a `ping` en Fase 4):

```
dominio normalizado → resolución DNS propia → filtrar con
safeWebFetchAdapter.isBlockedIp() → ejecutar el binario SOLO contra la IP
pública ya validada (nunca contra el dominio crudo)
```

Esto también resuelve el problema de qué IP usar cuando hay varias (§5): la
resolución ya la hace el propio código, no el binario.

### 8.3 URL sin escapar (implementación original, ya muerta)

La implementación original interpola el dominio sin `encodeURIComponent()`
en la URL de HackerTarget. Es código ya inalcanzable desde la UI y de baja
severidad (no hay reflejo en HTML, es una llamada saliente a un tercero),
pero se documenta para que no se arrastre el mismo patrón si en algún
momento se reintrodujera una llamada a un API externo.

---

## 9. Abuso / DoS

Traceroute genera más tráfico que ping (múltiples paquetes por salto, hasta
el límite de TTL configurado, más lento por los timeouts de espera por
salto). Valores conservadores propuestos para una futura implementación,
en línea con lo que ya usa Paraguay (`-m 5 -q 1 -w 1`) pero explicitados:

- **Máximo de saltos**: 5–8 (no 30, el valor por defecto de `traceroute`) —
  suficiente para ver el primer tramo de la ruta sin generar un trace
  completo innecesario.
- **Sondas por salto**: 1 (no el default de 3) — reduce el tráfico a un
  tercio.
- **Timeout por sonda**: 1–2s.
- **Timeout total**: acotado por `REQUEST_TIMEOUT_MS` del proyecto.
- **Concurrencia**: igual que el resto de checks batch del proyecto — sin
  paralelismo adicional específico para traceroute; no se debe permitir que
  un batch de N dominios dispare N traceroutes simultáneos sin límite.
- **Máximo de IPs por consulta**: 1 por familia (§5) — nunca todas las IPs
  de un dominio.
- **Rate limiting**: aplicar el mismo rate limiting que ya protege los
  endpoints públicos del proyecto (regla de seguridad ya establecida en
  `CLAUDE.md` del proyecto: "Rate limiting en todo endpoint público").

No se recomienda traceroute masivo (todos los dominios de un batch en
paralelo) — es la herramienta con mayor costo de tráfico y tiempo de todo
el catálogo de checks.

---

## 10. Privacidad / exposición

Este es el hallazgo más delicado de la auditoría, con evidencia empírica
directa de esta sesión.

`server1` es un nodo **residencial / home-lab**, no un servidor de
datacenter. Un `tracepath` real ejecutado en esta sesión (solo lectura,
contra `8.8.8.8`) reveló:

```
1  192.168.100.1        (gateway doméstico — rango privado RFC1918)
2  10.48.0.1             (infraestructura del ISP — CGNAT/backbone)
3  10.85.2.150           (infraestructura del ISP)
4  190.152.253.153       (IP pública real, atribuible a la conexión del ISP)
5  10.9.14.2              (infraestructura del ISP)
6  72.14.211.196          (borde de red de Google)
7–26  sin respuesta
```

Si un endpoint de traceroute público (como el de Paraguay hoy, o el
original de Ecuador si volviera a funcionar) expusiera esta ruta sin
filtrar, **cualquier visitante externo del sitio** podría:

- Confirmar que el nodo de medición corre en una red residencial, no en un
  datacenter.
- Ver la IP pública real de esa conexión residencial (`190.152.253.153` en
  este ejemplo).
- Inferir el ISP y aproximar la ubicación geográfica del nodo por esa IP.

**Recomendación**: si se implementa, **no publicar los primeros saltos
privados tal cual** (rangos RFC1918, CGNAT `100.64.0.0/10`, ULA). Opciones,
de más a menos conservadora:

- Mostrar solo el conteo de saltos privados iniciales ("N saltos internos
  omitidos") sin sus IPs, y empezar a mostrar detalle desde el primer salto
  público.
- Mostrar todo pero con los primeros saltos redactados (`***`) si son
  rangos privados/CGNAT.
- No mostrar la IP pública real del nodo emisor bajo ningún escenario —
  ese dato en particular (`190.152.253.153` en este ejemplo) es el más
  sensible porque identifica la conexión específica del hogar donde corre
  `server1`.

No se debe asumir que "mostrar toda la ruta" es aceptable solo porque
`traceroute` es una herramienta de diagnóstico estándar — en un datacenter
esto es rutinario y de bajo riesgo; en un nodo residencial, no.

---

## 11. Semántica de interpretación propuesta

Traceroute es fundamentalmente **descriptivo**, no una prueba binaria de
éxito/fallo. Se propone:

- **INFO**: se obtuvo una ruta, completa o parcial (algunos saltos
  intermedios sin respuesta no invalidan el resultado).
- **NOT_APPLICABLE**: el dominio no tiene registro de la familia consultada
  (sin AAAA para la variante IPv6, por ejemplo).
- **INCONCLUSIVE**: el nodo no tiene capacidad para esa familia en ese
  momento (sin IPv6 pública real, como es el caso actual de `server1`).
- **MEASUREMENT_ERROR**: el binario no está disponible, falla al
  ejecutarse, o hay un error de ejecución no relacionado con la red del
  dominio evaluado (ej. el contenedor actual, donde ningún binario existe).

**Nunca PASS/FAIL** salvo que exista una condición clara y objetiva que lo
justifique — y no se identificó ninguna para este check: un destino que no
responde en el último salto (`*`/"no reply") es información esperable, no
un fallo del dominio (ver §4).

---

## 12. Valor real para MEDICIONES

Preguntas para evaluar si aporta algo distinto a lo que el proyecto ya mide:

- **¿Distinto de ping?** Sí — ping mide latencia/pérdida punto a punto;
  traceroute describe la ruta intermedia. Son complementarios, no
  redundantes.
- **¿Distinto de RPKI/ASN/prefijo (Fase 2)?** Parcialmente — RPKI/ASN
  describen la **anunciada** vía BGP (a qué AS pertenece un prefijo, si
  está cubierto por ROA), no la ruta **real observada** paquete por
  paquete. Traceroute es empírico; RPKI es declarativo. Hay complementariedad
  real, pero requiere que el usuario entienda la diferencia (riesgo de
  confusión si no se explica bien en el glosario).
- **¿Reproducible?** Baja-media — la ruta puede cambiar entre ejecuciones
  (balanceo BGP, ECMP), lo cual es normal pero reduce el valor de
  comparaciones históricas simples.
- **¿Valor regional/comparativo?** Sí, en teoría — comparar cuántos saltos y
  por qué ASNs pasa el tráfico hacia distintos ccTLD .ec o dominios
  gubernamentales podría ser interesante para el objetivo de MEDICIONES
  (visibilizar infraestructura de Internet en la región). Pero ese valor
  depende de la variabilidad temporal y del origen del nodo de medición —
  medido siempre desde una única conexión residencial en Ecuador, no
  generaliza a "cómo se ve la ruta desde la región".
- **¿Ruido?** Alto en el tramo final (saltos que no responden, típico y
  documentado en esta misma sesión) — requiere una UI que no lo presente
  como error.

**Clasificación: VALOR MODERADO.** Aporta una dimensión distinta
(ruta observada vs. latencia vs. anuncio BGP), pero con reproducibilidad
limitada y con el riesgo de privacidad de §10 pesando en contra si se corre
desde un nodo residencial.

---

## 13. Comparación de opciones

| Opción | Viabilidad hoy | Comentario |
|---|---|---|
| **A. Recuperar como check normal** | No | Requiere binario ausente del contenedor y filtrado SSRF nuevo; sin eso, sería repetir el mismo patrón de riesgo que Paraguay nunca corrigió |
| **B. Recuperar como herramienta avanzada, `default:false`** | Parcial | Mismo problema de binario ausente en el contenedor — el `default:false` no resuelve la falta de binario, solo evita que corra por defecto |
| **C. No recuperarlo** | Sí, viable de inmediato | Estado actual de facto; ya documentado y decidido una vez con criterio técnico (§3.3) |
| **D. Reemplazar por `tracepath`** | Parcial | `tracepath` es más seguro (no requiere privilegios) y **está presente en el host**, pero **ausente del contenedor** — igual requiere tocar el `Dockerfile` |
| **E. Posponer a un nodo de medición dedicado futuro** | Sí, como plan a futuro | Resuelve tanto el problema de binario (se instalaría a propósito) como el de privacidad (§10) — un nodo dedicado de medición, no residencial, no expone la misma información sensible si es alcanzado desde afuera |

---

## 14. Casos de prueba propuestos para una futura implementación

1. Dominio con IPv4 pública única — ruta obtenida con al menos 1 salto.
2. Dominio con múltiples registros A — confirmar que solo se traza 1 IP
   (política de §5), no todas.
3. Dominio sin registro A (`NXDOMAIN` o sin A) — `NOT_APPLICABLE`, no error.
4. Dominio cuyo A resuelve a IP privada/loopback/link-local/ULA/CGNAT/
   multicast/reservada — **bloqueado antes de ejecutar el binario**, nunca
   se traza.
5. Ruta parcial (algunos saltos intermedios responden, otros no) —
   `INFO`, no `FAIL`.
6. Destino final que no responde en el último salto — `INFO`, nunca `FAIL`
   por eso solo.
7. Binario ausente en el entorno de ejecución — `MEASUREMENT_ERROR`
   explícito, no genérico.
8. Timeout de ejecución del binario — `MEASUREMENT_ERROR` distinto del
   caso "binario ausente".
9. Salida del binario malformada / inesperada — el parser no debe lanzar
   una excepción no controlada.
10. Input malicioso en el nombre de dominio (intento de inyección,
    caracteres de shell, longitud excesiva) — normalizado o rechazado antes
    de llegar al `execFile`; confirmar que `execFile` sin shell ya lo
    neutraliza aunque pase de largo la validación.
11. Ruta con saltos internos del propio nodo (simulando lo observado en
    §10) — confirmar que la UI no expone las IP privadas/CGNAT/pública real
    del nodo tal cual.
12. Límite máximo de saltos alcanzado sin llegar al destino — resultado
    `INFO` (ruta parcial), no error.
13. Dominio con AAAA pero sin A — comportamiento para IPv6 (ver ítems 14-15).
14. Dominio sin AAAA — `NOT_APPLICABLE` para la variante IPv6.
15. Nodo sin conectividad IPv6 utilizable (como `server1` hoy — solo ULA de
    Tailscale) — `INCONCLUSIVE` para IPv6, nunca `FAIL`.
16. IPv6 ULA como destino resuelto — bloqueado igual que IPv4 privada
    (ítem 4), mismo criterio de filtrado.

---

## 15. Qué NO se hizo en esta fase (confirmación explícita)

- No se restauró código de traceroute (ni backend ni frontend).
- No se modificó `server.js`, `index.html`, `Dockerfile`, ni ninguna otra
  parte de producción.
- No se instaló ningún binario ni paquete en el host ni en el contenedor.
- No se modificó ninguna capability de Docker ni configuración de red/firewall.
- No se hizo commit ni push.
- No se desplegó nada.
- Todo el diagnóstico de entorno fue de solo lectura (`which`, `ip addr
  show`, `tracepath` de prueba contra un destino público externo — el mismo
  tipo de comando de diagnóstico no destructivo ya usado en la auditoría de
  Fase 4 para `ping`).
- `git status` al cierre de esta fase permanece igual que al inicio (§0) —
  el único cambio es este archivo nuevo, `AUDITORIA_MEDICIONES_TRACEROUTE.md`.

---

## Resumen — recomendación única

**POSPONER A NODO DE MEDICIÓN DEDICADO** (opción E). Razones concentradas:

1. El binario no existe en el contenedor actual (ninguna variante:
   `traceroute`, `tracepath`, `mtr`).
2. El nodo actual (`server1`) es residencial — ejecutar traceroute desde ahí
   y exponerlo públicamente revela topología de red doméstica e IP pública
   real de una conexión particular (§10), algo que un nodo dedicado de
   medición no tendría como problema.
3. IPv6 no es viable de todas formas en el nodo actual (sin IPv6 pública
   real).
4. La implementación original (API externa) está confirmada y documentada
   como permanentemente rota (exige API key). La implementación local de
   Paraguay funciona pero arrastra el mismo patrón de riesgo SSRF que ya se
   corrigió en `ping` — replicarla sin ese fix repetiría un problema ya
   conocido.
5. El valor es moderado, no alto — no justifica asumir el riesgo de
   privacidad de un nodo residencial para recuperarlo ahora mismo.

Si en el futuro existe un nodo de medición dedicado (no residencial), con
el binario instalado a propósito, con el flujo de resolución→filtrado→
ejecución (§8.2) implementado desde el inicio, y con la política de
saltos/timeouts de §9, la opción **RECUPERAR (default:false)** sería
razonable como punto de partida.
