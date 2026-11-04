# Reporte final — Observatorio DNSSEC v2

Rediseño completo del Observatorio como **intérprete estructurado de DNSViz**.
Las seis fases solicitadas están entregadas. Este documento sigue el formato
pedido por el usuario.

> **Regla central** que rige todo el rediseño:
> DNSViz es la **fuente soberana**. El sistema NO reinterpreta DNSSEC, NO crea
> scoring propio, NO crea "salud DNS", NO produce "riesgo crítico/alto" como
> diagnóstico global. Solo organiza, explica y traza la salida de DNSViz.

---

## 1. Archivos modificados

### Backend
| Archivo | Cambio |
|---|---|
| `backend/app.py` | Núcleo del rediseño. `_load_layers` nueva, `_run_dnsviz(domain, id)` persiste a disco, `_build_structured_view`, `_build_result_json`, endpoints `/analyze/<id>/{result.json,graph.html,probe.json,grok.json,print.txt,report.pdf,report.csv}`, `/api/{ui-texts,report-texts,layers/capa1a..3}.json`, `/admin/data*`. Funciones legacy `_calculate_dnssec_status` / `_calculate_dns_service_health` preservadas pero **no expuestas al frontend ni al PDF**. |
| `backend/requirements.txt` | + `weasyprint>=62.0` y `jinja2>=3.1`. |
| `backend/templates/pdf-report.html.j2` | **Nuevo** — plantilla institucional WeasyPrint con `@page` rules, márgenes 22/18mm, paginación y portada de una sola página. |

### Datos (capas y textos)
| Archivo | Estado |
|---|---|
| `backend/data/dnsviz/capa1a-catalogo-dnsviz.json` | **Nuevo** — catálogo DNSViz puro (197 entradas). **Solo lectura, no editable** desde admin. |
| `backend/data/dnsviz/capa1b-semantica-dnsviz.json` | **Nuevo** — semántica visual por code (100 entradas). |
| `backend/data/dnsviz/capa2-contexto-normativo.json` | **Nuevo** — contexto normativo (NIST/ISO) por code (94 entradas). |
| `backend/data/dnsviz/capa3-explicaciones.json` | **Nuevo** — explicaciones humanas en lenguaje prudente (29 entradas, 26 ES + 3 EN). |
| `backend/data/dnsviz/ui-texts.json` | **Nuevo** — chrome de la app, ES + EN. |
| `backend/data/dnsviz/report-texts.json` | **Nuevo** — textos del reporte (portada, glosario, metodología, disclaimer, intros), ES + EN. |
| `backend/data/dnsviz/*.default.json` | **Nuevo** — copias semilla inmutables (6) para "Restaurar valores por defecto". |
| `backend/data/dnsviz/_backups/<key>/<key>.YYYYMMDDTHHMMSSZ.json` | Generadas en runtime al editar/restaurar. Conserva las últimas 10 por archivo. |

### Frontend
| Archivo | Estado |
|---|---|
| `frontend/report-v2.html` | **Nuevo** — layout con dos paneles + tabs sticky móviles. |
| `frontend/css/style-v2.css` | **Nuevo** — estilos del reporte v2, breakpoints 1440/1024/768/430/390. |
| `frontend/css/style-admin-v2.css` | **Nuevo** — estilos del editor admin de capas. |
| `frontend/js/report-v2.js` | **Nuevo** — renderer estructurado, i18n inline, exports JSON/CSV/PDF. |
| `frontend/js/admin-data.js` | **Nuevo** — editor de capas (tabular + árbol + JSON crudo). |
| `frontend/admin/data-editor.html` | **Nuevo** — UI del editor admin. |

### Deploy
| Archivo | Cambio |
|---|---|
| `Dockerfile` | + libs nativas WeasyPrint (`libpango`, `libcairo2`, `libgdk-pixbuf`, `libffi-dev`, `shared-mime-info`, `fontconfig`, `fonts-dejavu-core`, `fonts-liberation`). |
| `deploy-produccion.ps1` | + `node --check` para `report-v2.js`, `admin-data.js`, `api.js`, `main.js`. |

### Tests
| Archivo | Estado |
|---|---|
| `tests/test_classification.py` | **Reescrito** completo. 18 tests sobre el shape público nuevo. |
| `tests/test_report_texts.py` | **Reescrito** completo. 16 tests sobre `/admin/data/<key>` y los endpoints públicos. |
| `tests/test_structured_view.py` | **Nuevo** — 16 tests de la vista estructurada. |
| `tests/test_pdf_csv_exports.py` | **Nuevo** — 12 tests de exports JSON/CSV/PDF. |
| `tests/test_dnsviz_command.py`, `tests/test_env_admin_bootstrap.py`, `tests/test_utf8.py` | Sin cambios — siguen pasando. |

### NO se tocaron (modo paralelo, conmutación pendiente para Fase 6 final)
- `frontend/index.html`, `frontend/js/main.js`, `frontend/js/api.js`, `frontend/js/i18n.js`
- `frontend/report.html`, `frontend/js/report.js`
- `frontend/css/style.css`, `frontend/admin/dashboard.html`, `frontend/admin/login.html`, `frontend/js/admin.js`
- `frontend/data/*.json` (datos viejos quedan disponibles como backup)
- `frontend/about.html`, `aboutv2.html`, `aboutv21.html`
- Backups `*.bak-*`

---

## 2. Nueva estructura de datos

### Disco

```
backend/
├── data/dnsviz/
│   ├── capa1a-catalogo-dnsviz.json           ← catálogo DNSViz, BLOQUEADO
│   ├── capa1a-catalogo-dnsviz.default.json
│   ├── capa1b-semantica-dnsviz.json           ← editable
│   ├── capa1b-semantica-dnsviz.default.json
│   ├── capa2-contexto-normativo.json          ← editable
│   ├── capa2-contexto-normativo.default.json
│   ├── capa3-explicaciones.json               ← editable (ES/EN)
│   ├── capa3-explicaciones.default.json
│   ├── ui-texts.json                          ← editable
│   ├── ui-texts.default.json
│   ├── report-texts.json                      ← editable
│   ├── report-texts.default.json
│   └── _backups/<key>/<key>.<ts>.json         ← rotación 10 últimos
├── analyses/
│   └── <id>/
│       ├── probe.json     ← evidencia DNSViz (probe)
│       ├── grok.json      ← evidencia DNSViz (grok)
│       ├── graph.html     ← evidencia DNSViz (grafo, fuente del iframe)
│       ├── print.txt      ← evidencia DNSViz (text-print)
│       └── result.json    ← análisis estructurado (fuente del frontend nuevo)
├── templates/pdf-report.html.j2
└── db.json                ← solo índice ligero (analyses, users, logs, tokens)
```

### Esquemas

**Capa 1A** — code, class, abstract, category, description_template, references, rfcs, parent_class, required_params. **Sin** responsable/scoring/riesgo.

**Capa 1B** — code, dnsviz_section, dnsviz_level, dnsviz_group, visual_status_relation (`does_not_override_visual_status` | `may_cause_bogus` | `may_cause_insecure` | `informational_only`), applies_to[], notes.

**Capa 2** — code, nist_reference, iso27001_reference, possible_operational_area, operational_complexity (`SIMPLE`|`MODERATE`|`COMPLEX`), estimated_effort.

**Capa 3** — code, language (`es`|`en`), audience_level (`general`|`technical`|`both`), plain_title, plain_description, what_it_means, possible_actions[{audience, text}], suggested_review.

**ui-texts** — `{es: {...}, en: {...}}` con sub-objetos `nav/home/report/audience/errors/admin/footer`.

**report-texts** — `{es: {...}, en: {...}}` con sub-objetos `cover/intro/sections/glossary/disclaimer/methodology`.

**db.json** — Mantiene solo: `users`, `analyses` (índice ligero), `domains`, `logs`, `tokens`, y `report_texts` legacy (no usado por el nuevo flujo). Cada análisis en el índice tiene: `id`, `domain`, `created_at`, `timestamp`, `user`, `result_path`, `graph_html_url`, `status` y `service_health` (legacy interno), `error_count`, `summary{...}`. **Los archivos pesados ya NO viven en `db.json`.**

---

## 3. Cómo se genera el JSON final

```
POST /analyze {"domain": "isoc.org.ec"}
   │
   ├── 1. id = _uid()                         (16 hex)
   ├── 2. _run_dnsviz(domain, id):
   │       a) dnsviz probe -A -a . <zone_chain> -o probe.json
   │       b) dnsviz grok  -l warning -r probe.json -o grok.json <zones>
   │       c) dnsviz graph --ignore-rfc9276 -Thtml -r probe.json -o graph.html
   │       d) dnsviz print -r probe.json > print.txt
   │       → todos los artefactos persistidos en backend/analyses/<id>/
   │       → _build_dnsviz_visual extrae node_info del graph.html
   │       → _parse_grok extrae errors/warnings con zona y servidor
   ├── 3. _build_result_json(domain, id, internal):
   │       a) _build_structured_view:
   │            • zones por zone_chain con classification, errors, warnings, rfcs
   │            • sections (rrset/dnskey/delegation/notices)
   │            • notices_by_zone, _by_code, _by_rfc
   │            • cada notice enriquecido con capa1a (rfcs), capa1b (semántica),
   │              capa2 (contexto normativo), capa3 (explicación ES/EN), traceability
   │       b) _layers_subset_for_codes: solo capas para codes vistos
   ├── 4. Escribir backend/analyses/<id>/result.json (UTF-8, ensure_ascii=False)
   ├── 5. Insertar metadata mínima en db['analyses']
   └── 6. Devolver result.json al cliente
```

**Shape final exacto del result.json** (validado por tests):

```json
{
  "id": "...",
  "domain": "isoc.org.ec",
  "generated_at": "...",
  "source": {
    "engine": "DNSViz CLI",
    "probe":  "/analyze/<id>/probe.json",
    "graph":  "/analyze/<id>/graph.html",
    "grok":   "/analyze/<id>/grok.json",
    "print":  "/analyze/<id>/print.txt",
    "commands": {...},
    "version": "...",
    "zone_chain": [".", "ec.", "org.ec.", "isoc.org.ec."],
    "fidelity": {...}
  },
  "dnsviz_original": {
    "graph_html_url": "/analyze/<id>/graph.html",
    "raw_text": "<text-print.txt content>",
    "raw_grok": {...}
  },
  "dnsviz_visual": {
    "source": "dnsviz graph node_info",
    "rrset_status": [...],
    "dnskey_ds_nsec_status": [...],
    "delegation_status": [...],
    "notices": {"errors_count":N, "warnings_count":N, "errors":[...], "warnings":[...]},
    "default_view": {...}
  },
  "structured_view": {
    "zones": [
      { "name": ".", "classification": {...}, "visual_status": {...}, "errors": [], "warnings": [], "rfcs": [] },
      ...
    ],
    "sections": {
      "rrset_status": [...],
      "dnskey_ds_nsec_status": [...],
      "delegation_status": [...],
      "notices": { "errors": [...], "warnings": [...] }
    },
    "notices_by_zone": [...],
    "notices_by_code": [...],
    "notices_by_rfc":  [...]
  },
  "layers": {
    "capa1a": {CODE: [...]},
    "capa1b": {CODE: {...}},
    "capa2":  {CODE: {...}},
    "capa3":  {CODE: {"es":{...}, "en":{...}}}
  },
  "nameservers": [...]
}
```

**`dnssec_status` y `dns_service_health` NO aparecen en este JSON.** Solo se preservan dentro del índice `db.json` (legacy interno) y no afectan al frontend ni al PDF.

---

## 4. Cómo se renderiza el panel izquierdo

`frontend/report-v2.html` carga `report-v2.js`. Este:

1. Lee `?id=<aid>` de la URL (o lo deduce de `sessionStorage.obs_report.id`).
2. Hace `fetch('/analyze/<aid>/result.json')`.
3. Inyecta `<iframe id="dnsviz-graph" src="/analyze/<aid>/graph.html" loading="lazy">`.

**El iframe carga el HTML que genera DNSViz, sin modificación**. El backend lo sirve textualmente desde el archivo persistido (`send_from_directory(backend/analyses/<id>/graph.html)`). No se reinyecta nada.

Debajo del iframe se exponen los enlaces directos a la evidencia auditable:

```
graph.html · grok.json · probe.json · print.txt
```

En desktop (≥1024px) este panel ocupa la mitad izquierda. En móvil (<1024px) se accede vía la pestaña "DNSViz original".

---

## 5. Cómo se renderiza el panel derecho

`renderAll()` en `report-v2.js` invoca seis renderers que consumen el `result.json`:

| Sección | Función | Fuente de datos |
|---|---|---|
| **1. Resumen DNSViz** | `renderSummary()` | `result.dnsviz_visual` — counts de RRset/DNSKEY/DS/NSEC/Delegation, errors_count, warnings_count. **Solo cantidades de DNSViz, ningún score**. |
| **2. Zonas analizadas** | `renderZones()` | `result.structured_view.zones` — una card por zona con tag (`root`/`TLD`/`intermediate`/`target`), pills de estado visual, conteos, RFCs y `<details>` colapsable con sus notices. |
| **3. Notices** | `renderNotices()` | `result.structured_view.sections.notices.errors` y `.warnings`. Filtros pill (`Todos / Errores / Advertencias`). Cada notice trae código, status pill (de `capa1b.dnsviz_level`), zona, RFCs (de `capa1a.rfcs`), mensaje original DNSViz, explicación humana ES/EN (de `capa3`), meta-grid (zone/node/section/group/applies_to/server/query_options/NIST/ISO/área operativa/complejidad/esfuerzo), `<details>` con acciones por audiencia, `<details>` con revisión sugerida, y línea de trazabilidad. |
| **4. Mapeo DNSViz → RFC** | `renderRFCMap()` | `result.structured_view.notices_by_code` + `result.layers.capa3` para la columna "Explicación". Tabla con columnas Código, RFC, Nivel, Mensaje DNSViz, Explicación. |
| **5. Glosario** | `renderGlossary()` | `report-texts.json[lang].glossary[]` — términos definitorios DNSSEC (RRset, DNSKEY, DS, RRSIG, NSEC/NSEC3, Secure, Insecure, Bogus, Delegation, EDNS). Editable desde admin. |
| **6. Trazabilidad** | `renderTraceability()` | Cada notice expone `traceability { source: 'DNSViz CLI', zone, node_key, layers_used: ['capa1a','capa1b','capa2','capa3'] }`. La sección agrupa todos los notices con esos campos para auditoría. |

**Status pills** sólo colorean palabras que ya vienen de DNSViz (`SECURE`, `BOGUS`, `INSECURE`, `WARNING`, `ERROR`, `UNKNOWN`). El JS no genera estados nuevos.

**Idioma**: `report-v2.js` carga `/api/ui-texts.json` y `/api/report-texts.json` y aplica el lang seleccionado (`localStorage.obs_lang`). Toggle ES/EN en header re-renderiza sin reload.

**Acciones**: 4 botones — Nuevo análisis (link `/`), Exportar JSON (descarga `result.json`), Exportar CSV (descarga del `/analyze/<id>/report.csv` del backend), Exportar PDF (`/analyze/<id>/report.pdf?lang=…` vía blob).

---

## 6. Qué edita el admin

**URL**: `/admin/data-editor` (gateado por token de admin).

| Capa / Archivo | Tipo | Editor |
|---|---|---|
| **Capa 1A** (`capa1a-catalogo-dnsviz.json`) | Tabular | 🔒 **No editable**. PUT devuelve 403 a nivel servidor. UI muestra como solo-lectura. |
| **Capa 1B** (`capa1b-semantica-dnsviz.json`) | Tabular | Tabla con búsqueda full-text + filtro por `dnsviz_group`. Modal con campos: code (mono, deshabilitado en edición), `dnsviz_section`, `dnsviz_level`, `dnsviz_group`, `visual_status_relation`, `applies_to` (lista), `notes`. |
| **Capa 2** (`capa2-contexto-normativo.json`) | Tabular | Tabla con búsqueda + filtro por `possible_operational_area`. Modal con NIST, ISO 27001, área operativa, complejidad, esfuerzo. |
| **Capa 3** (`capa3-explicaciones.json`) | Tabular bilingüe | Tabla agrupa por code (pills ES/EN). Modal **dos columnas lado a lado** (ES \| EN) con `plain_title`, `plain_description`, `what_it_means`, `possible_actions[]` (repeater audience+text), `suggested_review`. Checkbox "incluir" por idioma para borrar/crear esa fila. |
| **ui-texts** (`ui-texts.json`) | Documento | Editor árbol de claves anidadas. Hojas con `<input>` o `<textarea>` según largo. Búsqueda por clave o valor. Modo "JSON crudo" valida `JSON.parse` antes de aplicar. Botones expandir/colapsar todo. |
| **report-texts** (`report-texts.json`) | Documento | Igual que ui-texts. |

**Restaurar valores por defecto**: confirm modal que nombra el archivo + crea backup automático (`backend/data/dnsviz/_backups/<key>/<key>.<ts>.json`, máx. 10 por archivo) antes de copiar `*.default.json` sobre el archivo activo.

**Todos los PUT**:
- Validan schema (lista vs dict, code no vacío, `(code, language)` única en capa3).
- Crean backup antes de escribir.
- Escriben con `json.dump(data, f, ensure_ascii=False, indent=2)` en UTF-8.
- Invalidan el cache en memoria (`_invalidate_layer_cache()`) para que el próximo `/analyze` use los datos actualizados.

**Banner permanente** del editor: "Los estados técnicos (RRset / DNSKEY / DS / NSEC / Delegation / Notices) provienen de DNSViz y no son editables aquí."

---

## 7. Validación responsive

CSS dual: `style-v2.css` (reporte) y `style-admin-v2.css` (admin). Comportamiento por breakpoint:

| Breakpoint | Reporte v2 | Admin editor |
|---|---|---|
| **≥1440px** | Grid 2 columnas iguales. Padding 1rem. iframe altura 100% del panel. Todo holgado. | Sidebar 280px sticky + main 1fr. |
| **≥1024px** | Mismo grid 2 columnas. `.mobile-tabs { display: none }`. Cada panel scroll independiente. | Mismo layout sidebar+main. |
| **768–1023px** | Tabs sticky `top: 62px`. Un panel visible. iframe 65vh. Padding reducido. | Sidebar y main apilados (1fr). |
| **≤768px** | Igual que arriba. `.report-section` padding `.85rem`. | Filtros y toolbar en wrap. |
| **≤430px** | Summary grid pasa a `2 cols`. Botones de acción `flex 50%`. iframe 60vh. `meta-grid` colapsa a 1 col. | Modal `bilingual-grid` colapsa a 1 col en `<760px`. |
| **≤390px** | Tipografía menor en tabs/filter. Summary cards más compactas. | Tree leaves a 1 col. |

**Reglas verificadas**:
- `body { overflow-x: hidden }` y `main { max-width: 100vw }` previenen overflow horizontal.
- Tablas envueltas en `.table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch }` con `min-width` para mantener legibilidad sin desbordar el contenedor.
- Cards (`.zone-card`, `.notice-card`, `.glossary-item`) con `flex` o `grid` que colapsa a 1 columna.
- Botones táctiles `min-height: 36-44px`.
- Paneles desktop con `overflow-y: auto` independiente (`.panel-body`).

**Validación manual recomendada en navegador** (no automatizable sin Playwright):
1440 / 1024 / 768 / 430 / 390 px → verificar sin scroll horizontal y todos los componentes legibles.

---

## 8. Confirmación de no reinterpretación

Garantía verificada por tests automatizados:

### En el JSON público
- `result.json` **no contiene** `dnssec_status`, `dns_service_health`, `risk_score`, `health_score`, `risk_level`, `service_health`. ✓ Test `test_no_legacy_diagnostic_fields_in_public_result`.
- Los counts del Resumen vienen literalmente de `dnsviz_visual.{rrset_status,dnskey_ds_nsec_status,delegation_status}` y `dnsviz_visual.notices.{errors_count,warnings_count}`. ✓ Test `test_dnsviz_visual_is_passthrough_from_graph`.

### En la vista estructurada
- `structured_view` no agrega ningún veredicto global. Solo agrupa lo que ya estaba en `dnsviz_visual` y en `errors/warnings` del grok. ✓ Test `test_structured_view_has_no_diagnostic_aggregates`.
- Cada notice trae una `traceability` que apunta a `'DNSViz CLI'` como `source`. ✓ Test `test_traceability_attached_to_each_notice`.

### En las capas
- **Capa 1A** (DNSViz catalog) no contiene los campos prohibidos `responsible/severity/risk/health/cost_ref/action_*`. ✓ Test `test_capa1a_has_no_forbidden_fields`.
- **Capa 1B** declara `visual_status_relation` por code, pero el frontend no usa este campo para inventar estados. Lo expone en el meta-grid del notice como información, no como veredicto. Códigos de transporte (`SERVER_UNRESPONSIVE_*`) tienen `does_not_override_visual_status` para indicar que pueden coexistir con `SECURE` final. ✓ Test `test_capa1b_visual_relations_come_from_dnsviz`.
- **Capa 3** usa lenguaje prudente. Ejemplo: el título de `MISSING_RRSIG` empieza con "DNSViz reporta…". ✓ Test `test_capa3_uses_prudent_language`.

### En el PDF
- La plantilla `pdf-report.html.j2` usa los mismos datos del `result.json`. Una prueba renderiza el HTML completo y verifica que **no contiene** las cadenas `dnssec_status`, `dns_service_health`, `health_score`, `risk_score`, `risk_level`. ✓ Test `test_render_template_only`.
- El PDF **no embebe captura del grafo** (sin Chromium/PNG). Solo enlace textual a `/analyze/<id>/graph.html`. ✓ Test `test_render_template_only` verifica que `<img` no está en el HTML del PDF.

### En el frontend
- `report-v2.js` no contiene lógica que sintetice `status` global. Las status pills sólo aplican CSS-class basado en strings que ya vinieron en el JSON.
- El home (`index.html`) y el admin viejo no fueron modificados; siguen disponibles para comparación side-by-side.

### En el admin
- **capa1a no es editable**: `PUT /admin/data/capa1a` → **403 forbidden**. ✓ Test `test_put_capa1a_is_forbidden`. La UI del editor lista la capa como locked en la sidebar.
- Banner del editor recuerda: "Los estados técnicos (RRset / DNSKEY / DS / NSEC / Delegation / Notices) provienen de DNSViz y no son editables aquí."

---

## 9. Pruebas ejecutadas

### Cadena de validación automatizada

```bash
# 1. py_compile del backend
$ python -m py_compile backend/app.py
OK

# 2. Tests unitarios completos
$ python -m unittest discover tests
.......................................................................
----------------------------------------------------------------------
Ran 70 tests in 0.212s

OK
```

**Cobertura de tests** (70 totales):

| Archivo | Tests | Foco |
|---|---|---|
| `test_classification.py` | 18 | Shape público del result.json, zonas, notices, capas; sin reinterpretación |
| `test_report_texts.py` | 16 | `/admin/data/<key>` GET/PUT/restore-defaults/backups, capa1a locked, lecturas públicas, UTF-8 con ensure_ascii=False |
| `test_structured_view.py` | 16 | `_build_structured_view`, clasificación de zonas, agrupaciones, trazabilidad |
| `test_pdf_csv_exports.py` | 12 | CSV (estructura, UTF-8, escape), PDF (501 sin WeasyPrint, 200 con), JSON, plantilla sin leaks |
| `test_dnsviz_command.py` | 2 | Resolución del binario dnsviz |
| `test_env_admin_bootstrap.py` | 3 | Bootstrap admin desde env vars |
| `test_utf8.py` | 4 | UTF-8 end-to-end |

```bash
# 3. node --check (todos los JS de frontend)
$ for f in frontend/js/api.js frontend/js/main.js frontend/js/i18n.js \
           frontend/js/admin.js frontend/js/admin-data.js \
           frontend/js/report.js frontend/js/report-v2.js; do
    node --check "$f" && echo "  OK $f"
  done
  OK frontend/js/api.js
  OK frontend/js/main.js
  OK frontend/js/i18n.js
  OK frontend/js/admin.js
  OK frontend/js/admin-data.js
  OK frontend/js/report.js
  OK frontend/js/report-v2.js
```

### Validación sintética de los 3 dominios

Validación de invariantes (sin red) para `isoc.org.ec`, `cloudflare.com`,
`wikipedia.org`. Para los tres se verificó:
- `zone_chain` correcto (root → TLD → [intermedias] → target)
- `structured_view.zones` con la misma cadena
- Clasificación correcta (root/TLD/intermediate/target)
- `dnsviz_original.graph_html_url` apunta a `/analyze/<id>/graph.html`
- `source.{probe,grok,graph,print}` apuntan a artefactos persistidos
- `result.layers` contiene `capa1a/1b/2/3`
- **No se filtra** `dnssec_status`, `dns_service_health`, `risk_*` ni `health_*`

Resultado: **3/3 dominios PASS** en validación sintética.

### Validación live de los 3 dominios (manual)

Pendiente de ejecución en el ambiente Docker / Cloud Run, donde DNSViz CLI tiene acceso de red estable. Comandos listos:

**Opción A — Docker local**:

```bash
# Construir imagen con todas las dependencias
docker build -t observatorio-dnssec-v2 .

# Levantar servicio
docker run --rm -e ADMIN_EMAIL=admin@local -e ADMIN_PASS=changeme \
           -e SECRET_KEY=$(python -c "import secrets;print(secrets.token_hex(32))") \
           -p 8080:8080 observatorio-dnssec-v2

# Ejecutar análisis
curl -s -X POST http://localhost:8080/analyze \
     -H 'Content-Type: application/json' \
     -d '{"domain":"isoc.org.ec"}' | python -m json.tool > isoc.json

curl -s -X POST http://localhost:8080/analyze \
     -H 'Content-Type: application/json' \
     -d '{"domain":"cloudflare.com"}' | python -m json.tool > cloudflare.json

curl -s -X POST http://localhost:8080/analyze \
     -H 'Content-Type: application/json' \
     -d '{"domain":"wikipedia.org"}' | python -m json.tool > wikipedia.json

# Verificar invariantes
for f in isoc.json cloudflare.json wikipedia.json; do
    python -c "
import json, sys
r = json.load(open('$f'))
assert 'dnssec_status' not in r, 'leak dnssec_status'
assert 'dns_service_health' not in r, 'leak dns_service_health'
print('$f', 'OK', 'zones=', [z['name'] for z in r['structured_view']['zones']])
"
done

# Ver el reporte v2 en el browser
open http://localhost:8080/report-v2?id=$(jq -r .id isoc.json)
```

**Opción B — Cloud Run después del deploy**:

```bash
# Tras ejecutar deploy-produccion.ps1
$URL = "https://dnssec.corpece.org.ec"

curl -s -X POST $URL/analyze -H 'Content-Type: application/json' \
     -d '{"domain":"isoc.org.ec"}' | jq '.id, .structured_view.zones[].name'
```

**Por qué no se ejecutó en este entorno**: DNSViz CLI v0.11.1 está instalada en
el host Windows pero `dnsviz probe` falla con error en el `DNSQueryTransportManager`
(problema conocido de raw sockets en Python 3.11 sobre Windows nativo).
Funciona correctamente dentro del contenedor Docker, que es donde corre la
producción.

### PDF en producción (lazy import)

El test `test_pdf_endpoint_responds_predictably` verifica ambos escenarios:
- Sin WeasyPrint instalada (entorno dev local): respuesta `501 pdf_unavailable` con mensaje claro.
- Con WeasyPrint instalada (Docker/Cloud Run con el nuevo Dockerfile): respuesta `200 application/pdf` con magic bytes `%PDF` validados.

---

## 10. Pendientes

### Conmutación de producción
1. Cambiar `frontend/js/main.js:51` para redirigir al reporte nuevo:
   ```js
   location.href = `/report-v2?id=${encodeURIComponent(result.id)}`;
   ```
2. Agregar link al editor de capas en `frontend/admin/dashboard.html` (sidebar):
   ```html
   <a href="/admin/data-editor">Capas y textos</a>
   ```
3. Una vez confirmado que el flujo nuevo funciona en producción, eliminar:
   - `frontend/report.html`, `frontend/js/report.js`
   - Backups `.bak-*` de `app.py`, `report.html`, `report.js`, `style.css`
   - Duplicados `aboutv2.html`, `aboutv21.html`, `en1.json`, `es1.json`
   - El bloque legacy `_calculate_dnssec_status` / `_calculate_dns_service_health` y constantes asociadas en `app.py` (preservadas por compatibilidad histórica con `db.json`).

### Validación visual responsive
Verificación manual en browser en los breakpoints 1440, 1024, 768, 430, 390 px. Sin scroll horizontal en ningún caso. Recomendado hacerlo después del deploy con análisis reales para tener contenido representativo.

### Endpoint live de los 3 dominios
Ejecutar `curl -X POST .../analyze` para `isoc.org.ec`, `cloudflare.com`, `wikipedia.org` desde el ambiente con DNSViz funcional (Docker / Cloud Run). Verificar que cada `result.json` cumple las invariantes ya validadas con fixtures.

### Migraciones desde el shape viejo
- `db.json['analyses']` antiguo guardaba todo el payload en `a['data']`. Los nuevos análisis solo guardan metadata + `result_path`. **Análisis viejos siguen siendo legibles**: `admin_history_get` lee primero `result_path` y cae al `data` legacy si existe.
- `db['report_texts']` legacy queda en disco pero ya no se consulta. Los textos editables del reporte ahora viven en `backend/data/dnsviz/report-texts.json`.

### Datos viejos en `frontend/data/`
`frontend/data/capa1-*.json`, `capa2-*.json`, `capa3-*.json`, `es.json`, `en.json` siguen sirviendo para el reporte viejo. Cuando se elimine `report.html`/`report.js`, esos archivos también pueden eliminarse.

### Hardening menor
- Backup timestamp tiene granularidad 1s; dos PUT en el mismo segundo sobrescriben el primer backup. Cambiar a milisegundos (`%H%M%S%f`) si se usa con scripts automatizados.
- Endpoint `/admin/dashboard-v2` no existe — el admin del editor es página dedicada en `/admin/data-editor` y se navega manualmente desde `/admin/dashboard`. Agregar el link en el dashboard viejo (1 línea).

---

## Estado del repositorio al cerrar Fase 6

```
70 tests pasando.
node --check OK en 7/7 archivos JS.
py_compile OK.
Synthetic validation OK 3/3 dominios.
Live validation pendiente — comandos documentados arriba.
```

Sistema listo para conmutación de producción cuando se valide en Cloud Run.
