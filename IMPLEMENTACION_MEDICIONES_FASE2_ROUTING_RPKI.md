# Fase 2 — MEDICIONES: `routing` (Paraguay) vs `rpki` (Ecuador)

Fecha: 2026-09-15. Continúa la Fase 1 (correo), cerrada en el commit
`24c56fe8ea03d47b5c77413a6078a6a01c6d7def`. Alcance: exclusivamente el
módulo MEDICIONES (`server.js`, `index.html`, `test/`). No se tocó DNSSEC
independiente, Observatorio, Zonemaster, datasets, OpenINTEL,
administración, blog, eventos ni el runner regional.

Principio aplicado, igual que en Fase 1: **Paraguay/upstream es
referencia histórica y funcional, nunca especificación normativa.** Todo
lo que se incorpora de su código se verificó primero (leyendo el
`server.js`/`index.html` reales de `nicocamarao/mediciones-isoc-lac`, no
el README) y, en un caso, contrastando además contra la API real de
RIPEstat en vivo.

## 0. Baseline

```
rama:   main
HEAD:   24c56fe8ea03d47b5c77413a6078a6a01c6d7def
status: sin cambios inesperados (solo los mismos untracked
        pre-existentes y ajenos a esta fase: AUDITORIA_FORK_MEDICIONES.md,
        data/exercises/, PDFs de public/docs/, scripts/exercise-24-domains/,
        scripts/regional-study/input/*.zip)
npm test: 10/10 suites OK, 57 checks confirmados, 0 duplicados
```

## 1. Qué hace hoy `rpki` en Ecuador (antes de esta fase)

Endpoint: `GET /rpki/:domain` → `handleRpki()` (`server.js`).

Flujo (código real, no interpretación):

1. Resuelve A + AAAA del dominio con `dns.resolve4`/`resolve6` (plano, sin
   pasar por el guard SSRF `resolvePublicAddresses` — ver §7).
2. Sin direcciones → distingue "no existe" de "zona real sin A/AAAA" (mismo
   patrón que `domainHasNoAddressButIsRealZone`, ya usado en Fase 1).
3. Para cada IP (v4 y v6 mezcladas, sin límite ni deduplicación), llama a
   `rpkiValidity(ip)`:
   - `stat.ripe.net/data/network-info/data.json?resource=<ip>` → un único
     ASN + prefijo "elegido" para esa IP.
   - Si hay ASN y prefijo: `stat.ripe.net/data/rpki-validation/data.json?
     resource=<asn>&prefix=<prefix>` → estado de validación RPKI.
4. Devuelve `{ domain, results: [{ip, state, asn, prefix}], valid }`, con
   `valid = true` solo si TODOS los resultados son `state === 'valid'`.
5. Frontend (`case 'rpki'` en `index.html`): FAIL si algún IP es
   `'invalid'`; PASS si todos son `'valid'`; si no, INFO.

**Fuente de datos real**: únicamente **RIPEstat** (`stat.ripe.net`), la API
pública de datos de RIPE NCC — no es RIPE RIS ni RIPE Atlas ni un RPKI
Validator propio; es una capa de agregación oficial que internamente
consulta RIS (para `network-info`) y su propio validador RPKI (`routinator`,
confirmado en la respuesta real — ver §4) para `rpki-validation`.

### Bug crítico encontrado (verificado en vivo contra la API real)

```
$ curl -s "https://stat.ripe.net/data/rpki-validation/data.json?resource=1&prefix=1.1.1.0/24"
...  "data":{"resource":"1","prefix":"1.1.1.0/24",
      "validating_roas":[{"origin":"13335","prefix":"1.1.1.0/24","validity":"invalid_asn","max_length":24}],
      "status":"invalid_asn","validator":"routinator"}
```

RIPEstat **nunca** devuelve el literal `"invalid"` en `data.status` — los
valores reales son `valid` / `invalid_asn` / `invalid_length` / `unknown`
(confirmado también con casos `valid` y `unknown` reales, ver más abajo).
El código anterior de Ecuador hacía:

```js
if (!['valid', 'invalid'].includes(state)) state = 'unknown';
```

Como `'invalid_asn'`/`'invalid_length'` no están en esa lista, **todo
resultado realmente inválido caía silenciosamente a `'unknown'`**, y la
rama `FAIL` del frontend (`data.results.some(r => r.state === 'invalid')`)
era código muerto: nunca se activaba con datos reales de RIPEstat. Este
era el problema de corrección técnica más grave detectado (prioridad 1 del
usuario) — un dominio con un anuncio RPKI-inválido real se reportaba como
"desconocido" (INFO), nunca como FAIL.

Lo que **sí** hacía bien el código anterior: no confundía "sin ROA"
(`status: "unknown"`, `validating_roas: []` — verificado en vivo con
`resource=64512&prefix=203.0.113.0/24`) con "inválido". Esa distinción
específica era correcta; el problema era el string-matching contra
`invalid_asn`/`invalid_length`.

## 2. Qué hace realmente `routing` en Paraguay/upstream

Leído el código real de `nicocamarao/mediciones-isoc-lac` (`server.js` +
`index.html`, vía `gh api`, no el README).

`handleRouting()`:

```js
async function handleRouting(domain, res) {
  const { v4, v6 } = await resolveAddresses(domain);
  const ips = [...v4, ...v6];
  const results = [];
  for (const ip of ips) {
    const details = await rpkiValidity(ip);           // <- MISMA función
    results.push({ ip, asn: details.asn, prefix: details.prefix,
                   state: details.state, reason: details.reason || null,
                   routes: details.routes || [] });
  }
  sendJSON(res, 200, { domain, results });
}
```

`routing` **llama a la misma `rpkiValidity()` que usa `handleRpki()`** —
no hay una segunda fuente de datos, ni una pregunta técnica distinta
(no consulta BGP looking-glass, no cuenta peers, no mide múltiples rutas
por prefijo más allá de lo que ya trae `rpkiValidity`). Lo único que
`routing` expone y `handleRpki()` (en su versión upstream) ignora en su
propio `case`, es el campo `routes`.

Ese campo sí es real y viene de una fuente adicional legítima que Ecuador
no tenía: **Team Cymru IP-to-ASN** (`origin.asn.cymru.com` /
`origin6.asn.cymru.com`), un servicio DNS público construido sobre los
feeds BGP propios de Cymru. `rpkiValidity()` de Paraguay:

```js
const routes = await resolveOriginRoutesViaCymru(ip).catch(() => []);
let chosen = routes[0] || null;
if (!chosen) { /* fallback a RIPEstat network-info */ }
// ... valida chosen.asn/chosen.prefix contra RIPEstat rpki-validation ...
return { state, reason, asn, prefix, routes };
```

Es decir: usa Cymru **primero** (con RIPEstat network-info como
respaldo), y solo la **primera** ruta de Cymru se usa para la validación
ROA — pero **todas** las rutas observadas se devuelven en `routes`. Cuando
Cymru reporta más de un origen para el mismo prefijo, eso es una señal de
visibilidad real (posible MOAS / anuncio múltiple) que RIPEstat
`network-info` no expone (esa API solo entrega un ASN "elegido").

En el frontend de Paraguay (`case 'routing'`, `index.html`), el estado
global del check es casi siempre `'info'` (`rows.length ? 'info' :
'warning'`) — **no** agrega a ok/fail a nivel de check completo, solo a
nivel de cada IP dentro de `sections[].items[]`. Es decir: Paraguay mismo
trata `routing` como fundamentalmente descriptivo, no como un
PASS/FAIL — coincide con lo que pedía el usuario para cualquier check de
esta naturaleza (§5, paso 8 de la tarea).

### Problema detectado en el propio Paraguay

El whitelist de estados en su `rpkiValidity()` es
`['valid', 'invalid_asn', 'invalid_length', 'unknown']` — a diferencia de
Ecuador, este SÍ incluye los valores reales de RIPEstat, y su frontend usa
`String(item.state).startsWith('invalid')`, así que su `rpki` (el propio,
no `routing`) sí detecta FAIL correctamente. El código de Paraguay está
bien en ese aspecto — el bug de "invalid nunca coincide" era específico
de la implementación de Ecuador, no heredado de upstream.

## 3. Tabla comparativa

| Capacidad | `rpki` Ecuador (antes) | `routing` Paraguay | Solapamiento | Faltaba en Ecuador |
|---|---|---|---|---|
| IP destino (v4/v6) | Sí | Sí (misma función) | Total | — |
| ASN de origen | Sí (RIPEstat network-info) | Sí (Cymru con respaldo RIPEstat) | Parcial | Fuente adicional (Cymru) |
| Prefijo anunciado | Sí | Sí | Total | — |
| Estado RPKI (ROA) | Sí, pero con bug (§1) | Sí, correcto | Total (tras el fix) | El fix mismo |
| Múltiples orígenes por prefijo (MOAS) | No | Sí (`routes[]` de Cymru) | Ninguno | **Sí — único dato realmente nuevo** |
| Visibilidad en tabla de ruteo global / peers | No | No (tampoco Paraguay) | — | No aplica a ninguno |
| IPv4 | Sí | Sí | Total | — |
| IPv6 | Sí | Sí | Total | — |
| Fuente de datos | RIPEstat únicamente | Cymru + RIPEstat | Parcial | Cymru como fuente adicional |
| Timestamp/frescura expuesta al cliente | No | No | — | No aplica a ninguno |
| Múltiples IP por dominio | Sí (sin dedup ni cap) | Sí (idéntico) | Total | — |

**Clasificación de `routing` (paso 4 de la tarea):** ni "check nuevo real"
ni "duplicación pura" — es **ENRIQUECIMIENTO**: reempaqueta exactamente el
mismo cómputo de `rpkiValidity()` y solo añade un campo (`routes`, MOAS)
que la propia Paraguay no explota en `rpki`, solo en `routing`. No hay una
pregunta técnica distinta detrás de `routing` que no esté ya cubierta por
`rpkiValidity()`.

## 4. Validación de fuentes de datos

- **RIPEstat** (`stat.ripe.net`) — servicio oficial de RIPE NCC, de acceso
  público sin autenticación. Confirmado en vivo (2026-09-15): responde
  `"validator":"routinator"` — es decir, el estado RPKI que RIPEstat
  entrega proviene de un validador RPKI real (Routinator, de NLnet Labs),
  no de una heurística propia de RIPEstat. Estable, ampliamente usado en
  la comunidad de operadores; sin SLA formal público pero con alta
  disponibilidad histórica. Cachea internamente (`"cached":true/false`
  visible en la respuesta). No es RIPE RIS directo ni RIPE Atlas ni
  RPKI Validator (auto-hospedado) — es la API de datos agregados de RIPE
  NCC, que a su vez consume RIS (para BGP) y Routinator (para RPKI).
- **Team Cymru IP-to-ASN** (`origin.asn.cymru.com` / `origin6.asn.cymru.com`)
  — servicio DNS público y gratuito, sin autenticación ni SLA formal,
  operado por Team Cymru desde hace más de una década, ampliamente citado
  en documentación de operadores de red. Indexa IPv6 por bloques /48 (una
  limitación real del servicio, no de esta implementación: dos IPs
  distintas dentro del mismo /48 obtienen la misma respuesta Cymru).
  Sin rate limit publicado, pero es una consulta DNS TXT estándar — se
  cachea 10 minutos por IP (`routeCache`, mismo patrón que `htmlCache`/
  `headerCache`/`ipMetaCache` ya existentes en el proyecto) para no
  repetirla en checks sucesivos del mismo dominio.
- Ninguna de las dos fuentes requiere ni expone credenciales; ambas se
  consultan por GET/DNS simple, con el mismo timeout de 15s ya usado en
  el resto de `fetchJSON` del proyecto.

## 5. Arquitectura elegida

**Opción B: enriquecer el `rpki` existente. No se crea un check
`routing` separado.**

Justificación (evidencia, no preferencia estética):

1. `routing` de Paraguay no responde una pregunta técnica distinta de
   `rpki` — usa la misma función, el mismo dominio, las mismas IPs. Crear
   un segundo check en Ecuador solo para repetir el 95% del mismo cómputo
   sería duplicar lógica y confundir al usuario final con dos checks casi
   idénticos (viola "no perseguir un número" y el principio de
   reproducibilidad: dos checks que casi siempre coinciden invitan a
   preguntarse por qué difieren cuando no deberían).
2. El único dato genuinamente nuevo (`routes` / visibilidad de múltiples
   orígenes) es un enriquecimiento natural del mismo resultado por IP que
   ya devuelve `rpki` — no amerita un endpoint ni un `case` de frontend
   propio.
3. Mantiene la separación conceptual pedida (paso 6 de la tarea) sin
   necesidad de un segundo check: dentro de cada resultado por IP,
   `state`/`asn`/`prefix` siguen siendo la evaluación criptográfica RPKI
   (B), y el nuevo campo `routes` es dato descriptivo de enrutamiento (A)
   — ambos conviven en el mismo resultado sin mezclarse en un único
   veredicto, porque el veredicto (`state`) nunca depende de `routes`.

Conteo final de checks: **57 (sin cambio)** — se enriqueció `rpki`, no se
agregó un check nuevo. No se persiguió llegar a 58 para "igualar" a
Paraguay.

## 6. Implementación

### `server.js`

- `ipToCymruQuery(ip)` — construye la consulta DNS Cymru para IPv4
  (`origin.asn.cymru.com`) e IPv6 (`origin6.asn.cymru.com`, indexado por
  /48). Formato replicado de Paraguay tras confirmar que es correcto para
  ambas familias (no se copió sin verificar: se probó contra
  `2001:4860:4860::8888` y se confirmó el formato de consulta esperado).
- `resolveOriginRoutesViaCymru(ip)` — resuelve el TXT, cachea 10 min en
  `routeCache` (reutilizando `cacheGet`/`cacheSet`, ya existentes),
  devuelve `[{asn, prefix}, ...]` (puede haber más de uno — MOAS).
- `rpkiValidity(ip)` (reescrita):
  1. Si `safeWebFetchAdapter.isBlockedIp(ip)` → `state: 'blocked'`, cero
     llamadas externas (§7, seguridad).
  2. Intenta Cymru primero; si no hay rutas, cae a RIPEstat
     `network-info` (igual que Paraguay).
  3. Si no se determina ASN+prefijo por ninguna vía: `state: 'unknown'`
     si simplemente no se observó ninguna ruta, o `state: 'error'` si
     ambas fuentes fallaron por completo (distinción exigida en el paso 8
     de la tarea — nunca confundir "no hay dato" con "no se pudo medir").
  4. Si se determina el par, valida contra RIPEstat `rpki-validation` y
     preserva el estado real (`valid` / `invalid_asn` / `invalid_length` /
     `unknown`) — ya no colapsa `invalid_asn`/`invalid_length` a
     `unknown` (el fix del bug de §1).
  5. Si la llamada de validación ROA en sí falla (red/timeout): `state:
     'error'` (se conoce el ASN/prefijo pero no su veredicto — distinto
     de "sin ROA").
- `handleRpki()` — sin cambios de flujo; cada resultado ahora incluye
  `family` (4 o 6, explícito) y `routes` (siempre presente, `[]` si no
  aplica). `valid` (booleano global) ahora excluye los IPs `'blocked'`
  del cómputo (ni suman ni restan a la validez).
- `module.exports` ampliado con `handleRpki`, `rpkiValidity`,
  `ipToCymruQuery`, `resolveOriginRoutesViaCymru` (mismo patrón aditivo de
  Fase 1, no cambia el arranque real del servidor).

### `index.html`

- `case 'rpki'`: reconoce los 6 estados posibles por IP (`valid`,
  `invalid_asn`, `invalid_length`, `unknown`, `error`, `blocked`) con
  etiquetas explícitas en español; muestra `routes` cuando hay más de un
  origen observado ("orígenes observados: AS... ..., AS... ...").
  Agregación global:
  - Cualquier `invalid_asn`/`invalid_length` → **FAIL** (ahora sí
    alcanzable con datos reales — antes era código muerto).
  - Si todos los IPs evaluados (excluyendo `blocked`) son `error` →
    **MEASUREMENT_ERROR**.
  - Si no queda ningún IP evaluado (todos `blocked`, dominio solo resuelve
    a IP privada) → **NOT_APPLICABLE**.
  - Si todos los evaluados son `valid` → **PASS**.
  - Cualquier otra mezcla determinada (válido+desconocido, válido+error
    parcial, etc.) → **INFO**, nunca forzado a PASS/FAIL.
- `checkGlossary.rpki` actualizado para describir el flujo real (Cymru +
  RIPEstat, ROA, visibilidad de múltiples orígenes).

## 7. Semántica de los 6 estados aplicada a `rpki`

| Estado por IP | Estado del check (agregado) | Significado |
|---|---|---|
| `valid` (todos) | PASS | Todas las IPs tienen un origen autorizado por ROA |
| `invalid_asn` / `invalid_length` (alguno) | FAIL | Al menos un anuncio real viola un ROA vigente |
| `unknown` (mezclado con válidos, sin inválidos) | INFO | Cobertura parcial — no forzar PASS ni FAIL |
| `error` (todos los evaluados) | MEASUREMENT_ERROR | Falló la medición en sí, no "sin ROA" |
| `blocked` (todos) | NOT_APPLICABLE | El dominio solo resuelve a IP privada/interna — no aplica RPKI público |
| `error`/`unknown` sueltos entre otros determinados | INFO | Se representa la mezcla honestamente, sin ocultar la diversidad |

## 8. IPv4 / IPv6

Cubiertos ambos desde antes de esta fase (`resolveAddresses` ya combinaba
v4+v6) y ahora también en la fuente nueva: `ipToCymruQuery` maneja
`origin.asn.cymru.com` (v4) y `origin6.asn.cymru.com` (v6, /48) —
verificado con pruebas dedicadas para cada familia (`rpki_ipv6_valid`,
`rpki_ipv6_invalid_length`) y con el resultado incluyendo `family: 4|6`
explícito por IP.

## 9. Múltiples IPs / múltiples ASN / CDN-anycast

- Cada IP se evalúa y reporta de forma independiente (`results[]`); nunca
  se colapsa a un solo veredicto oculto.
- Mismo ASN en varias IPs (ancla/anycast simple): se refleja
  correctamente como N resultados idénticos.
- ASNs distintos con estados distintos (ej. una IP válida, otra inválida):
  el agregado es FAIL (una sola IP realmente inválida es una condición de
  seguridad real, no una curiosidad a promediar) — cubierto en
  `rpki_mix_valid_invalid_multi_asn`.
- Múltiples orígenes para el **mismo** prefijo (MOAS, vía Cymru) se
  exponen en `routes[]` sin forzar ningún veredicto adicional — es
  información descriptiva, no un fallo per se.

## 10. Seguridad (paso 11)

- **SSRF**: no aplica en el sentido clásico — el servidor nunca abre una
  conexión directa a la IP resuelta del dominio; solo la incrusta como
  parámetro numérico (`net.isIP`-validado, nunca texto libre) en una URL
  fija (`stat.ripe.net`) o en una consulta DNS a un sufijo fijo
  (`*.cymru.com`). No hay redirección seguida ni URL construida a partir
  de un host arbitrario.
- **IPs privadas/internas**: antes no se filtraban (se enviaban tal cual
  a RIPEstat). Ahora, `safeWebFetchAdapter.isBlockedIp(ip)` corta el flujo
  ANTES de cualquier llamada externa — verificado en el test
  `rpki_ip_privada_bloqueada`, donde los mocks de `dns.resolveTxt` y
  `https.request` están configurados para lanzar si se invocan, y el test
  pasa (es decir: nunca se llaman).
- **Timeouts**: se reutiliza el timeout de 15s ya existente en
  `fetchJSON`; la consulta DNS a Cymru hereda el comportamiento estándar
  del resolver del sistema (mismo patrón que el resto de llamadas
  `dns.resolve*` del proyecto, sin regresión ni mejora nueva aquí).
- **Caching**: `routeCache` (10 min) evita repetir la consulta Cymru en
  checks sucesivos del mismo dominio.
- **Tamaño de respuesta / rate limiting propio**: sin cambios respecto al
  resto del proyecto — no se introduce ni corrige nada nuevo aquí (mismo
  patrón preexistente en todos los checks basados en `fetchJSON`, fuera
  del alcance de esta fase).

## 11. Tests

`test/medicionesRpkiCheck.test.js` — 18 casos, sin red real (mocks de
`dns.resolve4/resolve6/resolveNs/resolveTxt` y `https.request`):

IPv4 valid/invalid/not-found · IPv6 valid/invalid · múltiples IPs mismo
ASN · múltiples IPs distinto ASN con mezcla valid/invalid · dominio sin
direcciones (dos variantes: inexistente vs. zona real sin A/AAAA) · error
de medición en la validación ROA · timeout en la validación ROA · IP
privada bloqueada (con verificación de que no se llama a servicios
externos) · respuesta externa malformada · fallo total de ambas fuentes
de origen · fallback Cymru→RIPEstat · visibilidad MOAS (múltiples
orígenes) · propagación de errores DNS de `resolveOriginRoutesViaCymru`.

Registrado en `package.json` (`npm test`). Suite completa: **10/10
archivos, 57 checks, 0 duplicados** (ver §0 vs. resultado final idéntico
— el conteo no cambió, como se esperaba de la Opción B).

## 12. Riesgos y limitaciones restantes

- Cymru indexa IPv6 por /48: dos IPs del mismo /48 obtienen la misma
  respuesta de origen — limitación real del servicio, no de esta
  implementación; documentada, no hay mitigación disponible del lado de
  MEDICIONES.
- El par ASN/prefijo validado refleja lo observado en el momento de la
  consulta (BGP en vivo); si el propio anuncio BGP está secuestrado, el
  ROA se valida contra ese estado ya comprometido — limitación inherente
  de cualquier validación RPKI basada en "qué se ve anunciado ahora mismo
  desde una IP", no un defecto específico de Ecuador ni de Paraguay.
- No se expone timestamp/frescura de los datos de RIPEstat/Cymru al
  cliente — ninguna de las dos implementaciones (Ecuador ni Paraguay) lo
  hacía antes; no se agregó en esta fase por no ser parte del objetivo
  (routing vs. rpki), queda como mejora futura opcional.
- Sin límite de IPs procesadas por dominio (a diferencia de
  `MAX_MX_PROBED` en correo) — un dominio con muchas IPs anycast haría
  igual número de resoluciones Cymru+RIPEstat en serie; no se tocó porque
  el comportamiento es idéntico al preexistente (no es una regresión de
  esta fase) y no fue señalado como problema en el objetivo planteado.

## 13. Decisiones consolidadas de Fase 2 (cierre, 2026-09-15)

Validación final realizada antes del commit de cierre. Resume, sin
repetir el detalle ya expuesto arriba, las decisiones que quedan fijadas
para el módulo MEDICIONES a partir de este punto.

### Bug original

`rpkiValidity()` normalizaba el estado de RIPEstat así:

```js
if (!['valid', 'invalid'].includes(state)) state = 'unknown';
```

RIPEstat/routinator nunca devuelve el literal `"invalid"` — devuelve
`invalid_asn` o `invalid_length` (confirmado en vivo, §1). Como ninguno de
los dos está en esa lista, cualquier resultado realmente inválido se
reescribía a `"unknown"` antes de llegar al frontend.

### Impacto potencial

La rama `FAIL` del `case 'rpki'` (`data.results.some(r => r.state ===
'invalid')`) dependía de un valor que la API real nunca produce: **era
código inalcanzable**. Cualquier dominio con un anuncio RPKI-inválido real
(ASN no autorizado, o longitud de prefijo fuera de lo permitido por el
ROA) se reportaba como INFO ("desconocido"), nunca como FAIL. El check
`rpki` de Ecuador, desde que existe, no podía detectar RPKI inválido real
— solo podía confirmar `valid` o quedarse en `unknown`. Esto afecta
directamente al valor de la medición (prioridad 5 del usuario) pero, más
grave aún, a la corrección técnica (prioridad 1): el check reportaba una
garantía de seguridad que no estaba realmente verificando.

### Corrección aplicada

Se preserva el estado específico devuelto por RIPEstat
(`valid` / `invalid_asn` / `invalid_length` / `unknown`) en vez de
colapsarlo a un booleano `invalid`/`no invalid`. El frontend ahora
reconoce ambas variantes de inválido explícitamente
(`r.state === 'invalid_asn' || r.state === 'invalid_length'`) para decidir
FAIL. Verificado con tests dedicados (`rpki_ipv4_invalid_asn`,
`rpki_ipv6_invalid_length`) que antes habrían fallado (o habrían tenido
que testear un valor — `'invalid'` — que la API real jamás entrega).

### Semántica final (6 estados por IP)

| Estado | Significa | Nunca se confunde con |
|---|---|---|
| `valid` | Existe un ROA que autoriza el par prefijo/ASN de origen observado | — |
| `invalid_asn` | Hay ROA(s) para el prefijo, pero ninguno autoriza al ASN observado como origen | `unknown` (sí hay info RPKI, solo que no autoriza a este origen) |
| `invalid_length` | El anuncio usa una longitud de prefijo mayor a la máxima permitida por el ROA | `invalid_asn` (el origen es correcto; el problema es la longitud) |
| `unknown` | No hay ROA aplicable / información RPKI insuficiente para ese prefijo | `invalid_asn`/`invalid_length` (ausencia de ROA no es lo mismo que un ROA que lo contradiga) — **nunca se trata como FAIL** |
| `error` | La medición en sí no pudo completarse (RIPEstat/Cymru no respondieron o fallaron) | `unknown` (aquí sí se intentó medir y no se logró; en `unknown` la medición sí se completó y no encontró ROA) |
| `blocked` | La IP es privada/reservada — nunca se consultó a servicios externos | `error` (no es un fallo de medición, es una decisión deliberada de no medir) |

Confirmado en código y tests que backend, frontend y glossary usan
exactamente este vocabulario (ver §6 y `RPKI_STATE_LABEL` en `index.html`).

### Manejo multi-IP (política agregada, confirmada)

1. Cualquier IP en `invalid_asn` o `invalid_length` → **FAIL** global,
   sin excepción (una sola IP con un anuncio realmente inválido es una
   condición de seguridad real).
2. Si todas las IPs evaluadas (excluyendo `blocked`) son `valid` →
   **PASS**.
3. Mezcla `valid` + `unknown` (sin ningún inválido) → **INFO** — nunca se
   fuerza a PASS ni a FAIL (verificado en `rpki_mix_valid_unknown`).
4. Cualquier otra mezcla de resultados determinados y distintos (p. ej.
   `valid` + `error` parcial) → **INFO**, representando la diversidad tal
   cual, nunca colapsada ni ocultada.
5. Si todas las IPs evaluadas fallan por error de medición → **
   MEASUREMENT_ERROR** (no INCONCLUSIVE): es el mismo criterio que ya usa
   este `case` para "Sin datos" cuando `results` viene vacío — INCONCLUSIVE
   en este proyecto se reserva para fallos a nivel de todo el dominio
   (`classifyDataError`, códigos de servicio externo no disponible), no
   para el detalle por IP dentro de una respuesta que sí se completó.
6. Si todas las IPs son `blocked` (el dominio solo resuelve a direcciones
   privadas) → **NOT_APPLICABLE**: el check no aplica de verdad, no es un
   error ni una ausencia de datos.

### MOAS / routing (Team Cymru)

- `routes` es puramente descriptivo: nunca participa en el cálculo de
  `status`/`valid`. Solo se usa `routes[0]` para elegir qué par
  ASN/prefijo se valida contra ROAs; el resto de `routes` se expone tal
  cual, sin evaluarse.
- Múltiples orígenes para el mismo prefijo (longitud de `routes` > 1) se
  muestran en el detalle ("orígenes observados: AS... ..., AS... ...")
  pero **no** se traducen automáticamente en FAIL ni en ningún estado
  distinto — no existe ninguna regla que interprete MOAS como problema por
  sí solo, sería necesaria una regla técnica independiente y explícita
  (comparar contra ROAs cada origen alternativo) que no forma parte del
  alcance de esta fase.
- IPv4 usa `origin.asn.cymru.com` (últimos 3 octetos, orden inverso);
  IPv6 usa `origin6.asn.cymru.com` (primeros 48 bits, en nibbles
  invertidos) — ambos verificados con tests dedicados
  (`rpki_cymru_query_ipv4_ipv6`, `rpki_ipv6_valid`,
  `rpki_ipv6_invalid_length`, `rpki_moas_multiples_origenes_visibles`).

### Fuentes (sin genéricos)

- **RIPEstat** (`stat.ripe.net`): `network-info` (prefijo + ASN observado,
  como respaldo si Cymru no responde) y `rpki-validation` (estado ROA
  real, resuelto internamente por `routinator`). Nunca se usa RIPE RIS,
  RIPE Atlas ni un RPKI Validator propio — es la API de datos agregados
  de RIPE NCC.
- **Team Cymru DNS** (`origin.asn.cymru.com` / `origin6.asn.cymru.com`):
  fuente primaria de ASN/prefijo de origen (antes de RIPEstat) y única
  fuente de visibilidad de múltiples orígenes (`routes`).

### Diferencias con Paraguay (resumen de cierre)

- Paraguay mantiene `rpki` y `routing` como dos checks que llaman a la
  misma función; Ecuador consolida ambos en uno solo (`rpki` enriquecido).
- El propio whitelist de estados de Paraguay ya incluía
  `invalid_asn`/`invalid_length` — el bug de "invalid nunca coincide" era
  exclusivo de la implementación anterior de Ecuador, no heredado de
  upstream.
- Ecuador añade un bloqueo explícito de IPs privadas antes de consultar
  Cymru/RIPEstat (`isBlockedIp`); Paraguay no lo tiene.

### Por qué no se creó un check `routing` separado

`routing` de Paraguay no responde una pregunta técnica distinta de
`rpki` — reutiliza literalmente la misma `rpkiValidity()`, sobre el mismo
dominio y las mismas IPs. El único dato no cubierto por el `rpki` original
de Ecuador (`routes`/MOAS vía Cymru) es un enriquecimiento del mismo
resultado por IP, no una medición independiente. Crear un segundo check
solo para exponer ese campo habría duplicado ~95% de la lógica y el
tráfico de red por cada verificación, sin ninguna pregunta técnica nueva
que lo justificara — se optó por enriquecer `rpki` en su lugar. El
conteo de checks de MEDICIONES permanece en **57**, sin cambio.
