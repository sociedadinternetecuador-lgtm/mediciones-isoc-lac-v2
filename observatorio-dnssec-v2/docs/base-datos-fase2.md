# Base de datos FASE 2

Este documento describe el primer esquema PostgreSQL para el Laboratorio DNSSEC.

La migracion inicial esta en:

`backend/migrations/001_phase2_lab_schema.sql`

## Decision

FASE 2 debe usar PostgreSQL, preferiblemente Cloud SQL PostgreSQL en Google Cloud.

Motivo:

- El laboratorio necesita historial.
- Los analisis bulk generan multiples dominios por job.
- Los artefactos DNSViz deben relacionarse con snapshots.
- Los reportes deben poder agrupar por dominio, zona, proveedor, nameserver, ASN, TLD, error y fecha.
- `db.json` no es suficiente para concurrencia, auditoria, reportes ni consultas historicas.

## Responsabilidades

PostgreSQL guarda:

- usuarios y roles;
- jobs;
- dominios normalizados;
- snapshots;
- hallazgos DNSSEC estructurados;
- relaciones con infraestructura;
- reportes;
- publicaciones;
- auditoria;
- limites de uso.

Cloud Storage debe guardar:

- `probe.json`;
- `grok.json`;
- `print.txt`;
- `graph.html`;
- `graph.png`;
- `graph.svg`;
- PDFs y otros reportes generados.

La base de datos solo guarda metadatos, rutas, hashes y relaciones.

## Tablas principales

### Acceso

- `app_users`
- `roles`
- `user_roles`

El acceso recomendado es Google Workspace/IAP o login Google. La base conserva el correo y los roles internos.

### Configuracion

- `system_settings`

Aqui viven limites del laboratorio como maximo de dominios por lote, concurrencia y cache.

### Muestras e inventario

Antes de crear jobs de analisis debe existir el concepto de muestra o inventario:

- archivo o texto cargado por el usuario;
- entradas originales;
- dominios normalizados;
- invalidos;
- duplicados;
- subdominios pendientes de revision;
- clasificacion tecnica (`gTLD`, `ccTLD`, `org.ec`, `com.ec`, etc.);
- selecciones o vistas activas;
- lotes sugeridos de 100 dominios unicos de analisis.

La muestra puede contener mas de 100 entradas. El limite de 100 aplica al lote
operacional de analisis, no al inventario.

Seleccionar un grupo no debe destruir la muestra. Grupos y lotes son vistas sobre
la misma lista hasta que el usuario limpie o cargue una nueva muestra.

Los subdominios se marcan para revision. La verificacion de delegacion se hara
solo sobre la seleccion depurada que entrara a analisis.

### Jobs

- `analysis_jobs`
- `analysis_job_items`
- `domain_inputs`

Un `analysis_job` puede ser `single` o `bulk`.

Cada dominio cargado pasa por `domain_inputs`, donde se guarda:

- valor original;
- dominio normalizado;
- TLD;
- tipo de TLD;
- reglas de normalizacion aplicadas;
- advertencias si hubo ambiguedad.

### Resultados DNSViz

- `domain_snapshots`
- `dnsviz_artifacts`
- `dnssec_status_groups`
- `dnssec_findings`

Un snapshot representa el resultado tecnico de un dominio en un momento y desde un vantage point.

Los artefactos DNSViz se guardan como referencias a Cloud Storage.

FASE 1 permite acceso publico al grafico interactivo `graph_html` para reproducir el mouse-over de DNSViz.net, y a las descargas `graph_png` y `graph_svg`.

Los demas artefactos (`probe_json`, `grok_json`, `print_txt`, `result_json`, PDF, CSV, etc.) pertenecen a FASE 2 y requieren autenticacion.

### Infraestructura

- `infrastructure_entities`
- `domain_entity_links`

Estas tablas permiten agrupar resultados por:

- nameserver;
- IP;
- ASN;
- proveedor DNS;
- hosting;
- registrar;
- registry;
- TLD;
- zona.

### Reportes

- `reports`
- `report_sections`
- `report_publications`

Los reportes se generan en el laboratorio.

Solo se publican al sitio publico cuando un admin o superadmin los aprueba.

### Control

- `audit_log`
- `rate_limits`

Estas tablas ayudan a evitar abuso y a mantener trazabilidad.

## Aplicar migracion en PostgreSQL local

Ejemplo:

```powershell
psql "postgresql://usuario:clave@localhost:5432/observatorio_dnssec" -f backend/migrations/001_phase2_lab_schema.sql
```

## Aplicar migracion en Cloud SQL

Ejemplo con Cloud SQL Auth Proxy o conexion autorizada:

```powershell
psql "postgresql://usuario:clave@127.0.0.1:5432/observatorio_dnssec" -f backend/migrations/001_phase2_lab_schema.sql
```

## Siguiente paso tecnico

La primera capa de acceso a datos esta en:

`backend/phase2_db.py`

Esta capa:

- lee `DATABASE_URL`;
- no rompe FASE 1 si PostgreSQL no esta configurado;
- verifica conexion y tablas requeridas;
- permite exponer estado desde rutas administrativas.

Rutas relacionadas:

- `/health`: indica si FASE 2 tiene base configurada o no.
- `/admin/phase2/db/health`: requiere admin y verifica el esquema PostgreSQL.

El siguiente paso es ampliar esta capa:

- repositorios para usuarios, jobs y snapshots;
- adaptador temporal para seguir usando `db.json` solo en FASE 1/prototipo mientras se migra el laboratorio.
