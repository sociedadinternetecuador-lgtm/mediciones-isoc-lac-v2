# Runner de investigación regional (400 dominios)

Cliente/orquestador **externo** de MEDICIONES. No es parte de la
aplicación, no la modifica, no toca `MAX_DOMAINS_PER_ANALYSIS` (20) ni
reimplementa ningún check. Automatiza el estudio de:

```
20 países × 20 dominios × 54 checks = 400 dominios, 21 600 resultados
```

ejecutando **20 lotes secuenciales de 20 dominios** — nunca en paralelo —
contra una instancia real de MEDICIONES ya en marcha.

## Cómo funciona (sin reimplementar checks)

Para cada país, el runner:

1. Carga el `index.html` **real** (sin tocarlo) en `jsdom` — el mismo
   HTML/JS que usa cualquier persona en el navegador.
2. Llena el formulario real del sub-tab "Mediciones" (`#mb-domains-input`
   con los 20 dominios, las 54 checkboxes de checks marcadas) tal como lo
   haría un usuario.
3. Invoca `window.medicionesBatchStart()` — la función real de
   `index.html`, sin modificar — y espera a que su promesa se resuelva.
   Internamente esa función ya corre los 54 checks × 20 dominios contra el
   backend real (`GET /<check>/<dominio>`), la validación DNS del lote
   (`POST /dataset/validate-dns`) y crea el reporte
   (`POST /mediciones-batch/report`).
4. Descarga el JSON por el **mismo endpoint que usa el botón "Descargar
   JSON"** de la UI real: `GET /mediciones-batch/report/:id/export?format=json`.

El runner nunca decide si un check pasa o falla — solo observa lo que la
aplicación real ya decidió y lo persiste/valida/cuenta.

### Detalle técnico: por qué hace falta un puente de `fetch`

`fetchWithTimeout()` en `index.html` usa `AbortController` con un timeout
real de 20s por request. El `AbortSignal` de `jsdom` no es compatible con
el `fetch` nativo de Node (Node lo rechaza con `TypeError`) — sin un
puente, los timeouts dejarían de abortar de verdad y una request colgada
bloquearía el runner en vez de resolver como `"Timeout"`, igual que le
pasaría a un navegador real. El runner crea un `AbortController` nativo de
Node y lo conecta al signal de `jsdom` (`createBridgedFetch` en
`runner.mjs`) — comprobado que aborta correctamente antes de implementar
el resto.

## Instalación

```bash
cd scripts/regional-study
npm install     # instala jsdom, dependencia propia de ESTE runner —
                 # no se agrega a package.json de la aplicación principal
```

## Uso

1. Levantar una instancia real de MEDICIONES (recomendado: instancia local
   de desarrollo, para no competir por cuota de los servicios externos
   compartidos — URLhaus, PageSpeed, Tranco, RDAP, Wayback — con el uso
   normal de `server1`):

   ```bash
   cd ../..
   PORT=3500 node server.js
   ```

2. Colocar un CSV por país en `input/`, con **exactamente** estas 4
   columnas y 20 filas:

   ```csv
   country,country_code,sector,domain
   Argentina,AR,Gobierno,argentina.gob.ar
   Argentina,AR,Registro,nic.ar
   ...
   ```

   El nombre del archivo es libre (se recomienda `<CC>.csv`) — el país se
   identifica por la columna `country_code`, no por el nombre del archivo.

3. Correr el runner:

   ```bash
   MEDICIONES_BASE_URL=http://localhost:3500 node runner.mjs
   ```

   `MEDICIONES_BASE_URL` por defecto es `http://localhost:3500` (mismo
   puerto del comando de desarrollo documentado en el `CLAUDE.md` de la
   aplicación).

### Ejemplo de ejecución real (corrida de prueba, 2 países × 20 dominios)

```
$ MEDICIONES_BASE_URL=http://localhost:3500 node runner.mjs
[...] === Runner regional iniciado — BASE_URL=http://localhost:3500 ===
[...] Países válidos a procesar (secuencial, nunca en paralelo): AR, BO
[...] [AR] intento 1 — iniciando (20 dominios, 54 checks)
[...] [AR] COMPLETED — {"PASS":662,"FAIL":166,"INFO":101,"INCONCLUSIVE":121,"NOT_APPLICABLE":10,"MEASUREMENT_ERROR":20}
[...] [BO] intento 1 — iniciando (20 dominios, 54 checks)
[...] [BO] COMPLETED — {"PASS":640,"FAIL":193,"INFO":95,"INCONCLUSIVE":137,"NOT_APPLICABLE":14,"MEASUREMENT_ERROR":1}
[...] Consolidado generado: 2 países, 40 dominios, 2160 resultados.
[...] === Runner regional finalizado ===
```

### Opciones de línea de comandos

| Flag | Efecto |
|---|---|
| (ninguno) | Procesa todos los `.csv` válidos en `input/` que no estén ya `COMPLETED` |
| `--only=AR,BO` | Limita la corrida a estos `country_code` |
| `--force=AR,BO` | Repite estos países aunque ya estén `COMPLETED` |
| `--force` | Repite **todos** los países, aunque ya estén `COMPLETED` |
| `--stop-on-failed-review` | Detiene el runner ante el primer país que caiga en `FAILED_REVIEW` (por defecto, continúa con el resto) |

## Validación de input (antes de ejecutar cada país)

Por cada CSV, antes de enviar nada a MEDICIONES, se verifica:

- exactamente 20 filas;
- 20 dominios no vacíos;
- dominios únicos dentro del archivo (comparación insensible a
  mayúsculas);
- `country_code` consistente (un único valor en todas las filas del
  archivo).

Si algo falla, **ese país no se ejecuta** — queda registrado en
`logs/errors.log` con el detalle exacto y el runner sigue con el resto.

## Validación del JSON descargado (por país)

Después de descargar `report.json`, antes de aceptarlo como válido:

- JSON parseable;
- `domains.length === 20`;
- los 20 dominios del JSON coinciden exactamente con los del CSV (sin
  faltantes ni sobrantes);
- ningún dominio duplicado en el JSON;
- cada dominio tiene exactamente 54 checks;
- cada dominio tiene el campo `dnssec` presente;
- cada dominio tiene el campo `checks` presente.

Cualquier falla de estas es **CRITICAL** (ver abajo).

## Alertas

**CRITICAL** (dispara reintento):
- servidor no disponible (health check antes de iniciar, o HTTP 5xx real
  durante la corrida);
- JSON inválido;
- menos/más de 20 dominios en el JSON;
- menos/más de 54 checks en algún dominio;
- un dominio con 54/54 `MEASUREMENT_ERROR`;
- excepción no controlada durante la corrida (incluye que el servidor
  desaparezca a mitad de camino: la mayoría de esas caídas ya se
  manifiestan como una excepción real al crear el reporte o como un
  patrón de errores masivos detectado por las reglas de arriba — el
  runner no tiene un evento dedicado de "el proceso se reinició", lo
  infiere de sus síntomas observables, igual que lo haría cualquier
  cliente externo).

**WARNING** (no detiene nada, solo se registra):
- `MEASUREMENT_ERROR` > 10% del lote;
- cantidad de `Timeout` anormalmente alta (> 20, uno por dominio);
- 3 o más dominios con algún `MEASUREMENT_ERROR`.

**Nunca se marca CRITICAL/WARNING automáticamente** por: DKIM
`INCONCLUSIVE` por selector único, falta de credencial de URLhaus,
cuota de PageSpeed, Ranking no disponible, Archive no disponible, RDAP
`NOT_APPLICABLE` — son estados esperados y documentados de MEDICIONES, no
fallas del runner ni del instrumento.

## Reintento

Ante un CRITICAL: se guarda evidencia (`results/<CC>/evidence-attempt*.json`,
y si ya se había descargado un JSON con problemas, también
`results/<CC>/report-attempt*.json`), se espera 5 minutos
(`REGIONAL_STUDY_RETRY_WAIT_MS`, solo para pruebas del propio runner — en
uso normal son siempre 5 minutos reales) y se reintenta el país **una sola
vez**. Si vuelve a fallar, el país queda en `runner_status: "FAILED_REVIEW"`
y el runner sigue con el siguiente país (o se detiene, con
`--stop-on-failed-review`). Nunca hay un segundo reintento automático.

## Resume

Cada país completado y validado (`runner_status: "COMPLETED"` +
`validation_status: "OK"`) queda registrado en
`results/<CC>/run-meta.json`. Si el runner se interrumpe (Ctrl+C, corte de
luz, lo que sea) y se lo vuelve a correr, detecta esos países ya hechos y
los salta — solo procesa los que faltan. Para forzar la repetición de un
país concreto (por ejemplo, si se corrigió su CSV de entrada), usar
`--force=<CC>`.

## Salida

```
results/<CC>/report.json        JSON real descargado de MEDICIONES para ese país
results/<CC>/run-meta.json      metadata de la corrida (ver campos abajo)
results/<CC>/evidence-*.json    solo si hubo CRITICAL — diagnóstico del fallo
consolidated/regional_400.json  las 20 corridas válidas concatenadas
consolidated/regional_flat.csv  una fila por país×dominio×check
consolidated/run_quality.csv    una fila por país con sus métricas de calidad
consolidated/manifest.json      resumen + trazabilidad (hashes, BASE_URL, totales)
logs/runner.log                 log completo de toda la ejecución
logs/errors.log                 solo errores (inputs inválidos, CRITICAL, excepciones)
```

`run-meta.json` incluye: `country`, `country_code`, `input_file`,
`input_file_sha256`, `report_sha256`, `started_at`, `finished_at`,
`duration_ms`, `attempt`, `domain_count`, `check_count`, `status_counts`,
`measurement_error_count`, `measurement_error_domain_count`,
`full_error_domain_count`, `timeout_count`, `error_codes`, `warnings`,
`report_id`, `validation_status`, `runner_status`.

`regional_flat.csv` no calcula scores ni rankings ni interpreta nada — es
una proyección fila por fila de lo que MEDICIONES ya produjo.

## Dos limitaciones reales encontradas al inspeccionar el código (no son
## bugs de este runner — son del formato del JSON exportado por la app)

1. **`error_code` no viaja en el JSON exportado.** `index.html` usa
   `data.error_code` solo internamente (dentro de `getCheckResult()`,
   vía `classifyDataError()`) para decidir el `status` de cada check, y lo
   descarta — el objeto que termina en `checks[key]` es
   `{label, status, details}`, sin `error_code`. Por eso la columna
   `error_code` de `regional_flat.csv` queda **vacía** para todas las
   filas, y `error_codes` en `run-meta.json`/`run_quality.csv` agrupa por
   el **texto** de `details` (el mensaje humano), no por un código real.
   Esto no se puede corregir sin modificar `index.html` — fuera de
   alcance de este pedido.

2. **No hay timestamp por check**, solo `meta.generated_at` de la corrida
   completa del país. `measurement_timestamp` en `regional_flat.csv` usa
   ese único valor para las 1080 filas del país.

3. **`timeout_count` es coincidencia exacta de texto**, no una
   reclasificación: cuenta los checks cuyo `details` es **literalmente**
   `"Timeout"` (la única forma en que fetchWithTimeout()/getCheckResult()
   lo producen en el código real, confirmado leyendo el catch de
   `getCheckResult()` en `index.html`). Se probó y se descartó una
   variante con `/timeout/i` por substring: generaba falsos positivos
   reales (p. ej. el header HTTP de respuesta `Keep-Alive: timeout=5`
   volcado tal cual en el `details` de un check `headers` en `PASS`, o
   menciones explicativas de la palabra "timeout" en checks
   `INCONCLUSIVE` como `smtputf8`/`archive` que no son el error real
   capturado).

## Antes de correr las 20 corridas completas (400 dominios)

Se recomienda correr primero con `--only=<un-país>` para medir la
duración real de un lote de 20 dominios (queda en `duration_ms` de
`run-meta.json`) y proyectar el tiempo total de las 20 corridas antes de
dejarlo desatendido — en la corrida de prueba de este runner, un lote de
20 dominios con las 54 checks tardó entre 35 y 40 segundos contra una
instancia local sin otra carga; con dominios reales de producción y
servicios externos más lentos (RDAP, PageSpeed, Wayback) puede ser
sensiblemente mayor.
