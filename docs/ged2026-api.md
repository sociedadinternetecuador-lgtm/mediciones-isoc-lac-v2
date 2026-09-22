# GED2026 — contrato de la API pública

> Único endpoint destinado a ser consumido por un sistema externo (el
> futuro portal informativo GED Ecuador 2026, fuera de este repositorio).
> Todo lo demás bajo `/admin/api/ged2026/...` es administrativo, requiere
> sesión y **no** forma parte de este contrato — no debe consumirse desde
> fuera de este proceso.

## `GET /ged2026/api/v1/summary`

Sin autenticación. Solo lectura. Devuelve indicadores agregados
calculados en el momento de la petición a partir del estado interno del
proyecto — nunca dominios individuales, notas ni motivos de exclusión.

### Ejemplo real (estado actual del proyecto en este entorno, recién
inicializado — no son datos de ejemplo inventados, es la respuesta real
del endpoint contra `data/ged2026/` vacío)

```json
{
  "project": "GED Ecuador 2026",
  "project_phase": "planning",
  "updated_at": null,
  "total_domains": 0,
  "active_domains": 0,
  "counts_by_estado_seleccion": {
    "candidate": 0,
    "validated": 0,
    "eligible": 0,
    "shortlisted": 0,
    "selected": 0,
    "excluded": 0
  }
}
```

### Campos

| Campo | Tipo | Significado |
|---|---|---|
| `project` | string | Nombre fijo del proyecto, `"GED Ecuador 2026"`. |
| `project_phase` | string (enum) | Fase actual: `planning \| dataset_collection \| dataset_validation \| dataset_analysis \| sample_selection \| pilot \| measurement \| analysis \| published`. |
| `updated_at` | string (ISO-8601) o `null` | Última vez que cambió algo operativo (un dominio o la fase del proyecto). `null` solo antes de la primera escritura — nunca se omite el campo. |
| `total_domains` | integer | Cantidad total de dominios en el universo/muestra, en cualquier estado. |
| `active_domains` | integer | Cantidad de dominios marcados `activo: true` (no necesariamente validados — es el flag administrativo, no el resultado del chequeo de liveness). |
| `counts_by_estado_seleccion` | object | Las 6 claves fijas `candidate, validated, eligible, shortlisted, selected, excluded`, siempre presentes con valor entero (`0` si no hay ninguno en ese estado — nunca se omite una clave). |

### Versionado

La ruta incluye `/api/v1/` explícitamente — a diferencia de otras rutas
públicas de este proyecto (`/content/:type`), que no versionan porque solo
las consume el propio frontend servido por este mismo proceso. Este
endpoint sí tiene un consumidor externo real (el portal informativo, otro
repositorio), así que necesita la garantía de estabilidad que da versionar
la ruta: un cambio incompatible de forma se publicaría como `/api/v2/...`,
dejando `/api/v1/...` intacto mientras el portal no migre.

### Campos que aún no existen

Todavía no hay endpoints para progreso detallado, dataset descargable,
resultados ni indicadores de medición (`progress`, `dataset`, `results`,
`indicators` de la sección 20 del pedido original) — se agregarán como
rutas adicionales bajo el mismo prefijo `/ged2026/api/v1/...` cuando esas
fases del proyecto existan. Mientras no existan, **no** deben inventarse
ni devolverse con valores vacíos desde este endpoint — simplemente no
existen todavía como rutas.

### CORS

Este es el único endpoint del proyecto pensado para ser consumido desde un
origen distinto (el portal informativo en `isoc.org.ec`). La respuesta
incluye `Access-Control-Allow-Origin: https://isoc.org.ec` (configurable
vía `GED2026_PORTAL_ORIGIN`, nunca wildcard `*` en producción). Sin esta
cabecera el navegador bloquea el `fetch()` del portal aunque el servidor
responda 200 — verificado empíricamente con `curl -H "Origin:
https://isoc.org.ec"` antes de agregarla.

### Errores

Mismo formato que el resto del proyecto: `{ "error": "<código>" }`, sin
stack traces ni detalles internos.

| Caso | Status | `error` |
|---|---|---|
| Método distinto de GET | 405 | `method_not_allowed` |
| Ruta bajo `/ged2026` no reconocida | 404 | `not_found` |

No hay caso de "no autorizado" — este endpoint nunca requiere sesión.

### Qué NO expone (y por qué)

- Dominios individuales, su `domain`/`normalized_domain`, `notas`,
  `exclusion_reason` ni ningún atributo de relevancia — son datos de
  curación interna, no un indicador agregado.
- Cualquier cosa que dependa de sesión administrativa.
- Nada de `data/ged2026/*.json` "tal cual" — la respuesta siempre pasa por
  el cálculo de `routes/ged2026.routes.js`, nunca es un volcado directo del
  archivo en disco.

### Nota para quien construya el portal consumidor

No recalcular ningún porcentaje ni derivar un indicador distinto a partir
de estos campos si ese mismo indicador puede pedirse ya calculado aquí —
el principio rector de este proyecto es que los indicadores se calculan en
un solo sitio (GED2026) para evitar que portal y plataforma queden
inconsistentes entre sí (sección 23 del pedido original). Si el portal
necesita un indicador que este endpoint no expone todavía, la solución es
agregarlo aquí, no derivarlo del lado del portal.
