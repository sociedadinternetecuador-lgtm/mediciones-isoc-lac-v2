# Arquitectura FASE 1 / FASE 2

Este documento fija la separacion funcional del Observatorio DNSSEC para evitar mezclar el analisis publico tipo DNSViz con las capacidades avanzadas del laboratorio.

## Principio rector

La FASE 1 reproduce el resultado publico equivalente a DNSViz.net para un dominio individual.

La FASE 2 es el sistema privado de laboratorio, administracion, exportacion, procesamiento, analisis masivo, reportes e investigacion tecnica.

Todo lo que sea extra a DNSViz.net pertenece a FASE 2, aunque internamente se use para construir la FASE 1.

## FASE 1: analisis publico uno a uno

La FASE 1 es publica y no requiere usuario.

Objetivo:

- Permitir que cualquier visitante analice un dominio.
- Mostrar un reporte visual equivalente al que se obtiene en DNSViz.net.
- Mantener la vista base sin interpretaciones propias ni procesamiento adicional visible al publico.

Incluye:

- Interfaz publica en espanol e ingles.
- Toggle unico de idioma.
- Formulario para analizar un dominio individual.
- Vista del reporte en formato similar a DNSViz.net:
  - columna izquierda con estados, notices, errores y warnings;
  - grafico central interactivo de cadena de autenticacion DNSSEC;
  - mouse-over y clic sobre elementos del grafico mediante `graph.html`;
  - leyenda visual;
  - mensajes y textos en el idioma activo.
- Descarga publica del grafico:
  - PNG;
  - SVG.

No incluye:

- Descarga publica de `probe.json`.
- Descarga publica de `grok.json`.
- Descarga publica de `print.txt`.
- Descarga publica de `result.json`.
- Descarga publica de PDF.
- Bulk de dominios.
- Historial publico avanzado.
- Interpretacion adicional del resultado.
- Clasificacion por proveedor, ccTLD, hosting, nameserver, ASN o patrones.

Los artefactos internos pueden existir y usarse para generar la vista, pero su exposicion publica pertenece a FASE 2.

## FASE 2: laboratorio DNSSEC privado

La FASE 2 requiere autenticacion y autorizacion.

Objetivo:

- Convertir los resultados DNSViz en una base de datos tecnica consultable.
- Permitir analisis masivo controlado.
- Generar reportes avanzados.
- Proteger el sistema contra abuso, spam, uso excesivo o interpretaciones de escaneo agresivo.

Incluye:

- Admin.
- Gestion manual de usuarios.
- Roles y privilegios.
- Laboratorio DNSSEC.
- Carga de hasta 100 dominios por lote.
- Normalizacion de dominios.
- Clasificacion por tipo de dominio y zona.
- Cola de analisis.
- Almacenamiento estructurado de resultados.
- Exportacion de artefactos y datos.
- Reportes HTML, PDF, CSV y JSON.
- Publicacion selectiva de informes en el sitio publico.

## Superficies del sistema

### Sitio publico

Dominio sugerido:

- `dnssec.corpece.org.ec`

Funciones:

- Analisis publico uno a uno.
- Reporte DNSViz-like.
- Descarga de grafico PNG/SVG.
- Seccion publica de reportes aprobados.
- Informacion institucional.

### Laboratorio privado

Dominio sugerido:

- `lab.dnssec.corpece.org.ec`

Funciones:

- Admin.
- Laboratorio DNSSEC.
- Analisis bulk.
- Reportes avanzados.
- Exportaciones.
- Gestion de usuarios y permisos.

Separar estas superficies reduce el riesgo operativo: la FASE 1 queda simple y publica; la FASE 2 queda protegida y controlada.

## Identidad y acceso

Como se cuenta con Google Workspace, la decision tecnica recomendada es usar identidad Google/Workspace para el laboratorio.

Modelo recomendado:

- Proteger `lab.dnssec.corpece.org.ec` con Google Identity-Aware Proxy o autenticacion Google.
- Permitir acceso solo a usuarios autorizados manualmente.
- Mantener roles internos dentro de la aplicacion.

Roles iniciales:

- `superadmin`: acceso total, configuracion, usuarios, reportes, laboratorio.
- `admin`: usuarios, reportes, revision operativa.
- `researcher`: ejecutar jobs, revisar resultados, generar reportes.
- `viewer`: solo lectura de resultados internos autorizados.

No se recomienda registro publico para FASE 2.

## Base de datos

La FASE 2 debe usar una base de datos relacional.

Decision recomendada:

- Produccion: Cloud SQL PostgreSQL.
- Desarrollo inicial: PostgreSQL local o Cloud SQL de pruebas.
- Evitar `db.json` para el laboratorio y reportes avanzados.

`db.json` puede mantenerse solo como compatibilidad temporal del prototipo actual.

## Almacenamiento de artefactos

Los artefactos pesados no deben vivir en la base de datos.

Decision recomendada:

- Cloud Storage para:
  - `probe.json`;
  - `grok.json`;
  - `print.txt`;
  - `graph.html`;
  - `graph.png`;
  - `graph.svg`;
  - reportes PDF generados.

La base de datos almacena metadatos, rutas, estados, hashes y relaciones.

## Worker DNSViz

La ejecucion real de DNSViz debe mantenerse en Ubuntu/GCP dual-stack.

Principios:

- Windows es solo terminal/cliente.
- El worker Ubuntu/GCP es el vantage point serio.
- El worker genera los artefactos DNSViz.
- El backend conserva trazabilidad de comandos y resultados.

Artefactos internos base:

- `probe.json`
- `grok.json`
- `print.txt`
- `graph.html`
- `graph.png`
- `graph.svg`

En FASE 1 solo se publican PNG/SVG del grafico.

## Modelo de datos propuesto

Tablas iniciales:

- `users`
- `roles`
- `user_roles`
- `analysis_jobs`
- `analysis_job_items`
- `domain_inputs`
- `domain_normalizations`
- `domain_snapshots`
- `dnsviz_artifacts`
- `dnssec_findings`
- `dnssec_status_groups`
- `dnssec_notices`
- `infrastructure_entities`
- `domain_entity_links`
- `reports`
- `report_sections`
- `report_publications`
- `audit_log`
- `rate_limits`
- `system_settings`

## Flujo de inventario y bulk

La FASE 2 separa la carga grande de la ejecucion de analisis.

### Inventario de muestra

El usuario autorizado puede cargar una lista grande desde TXT, CSV o texto pegado.
Esta carga no ejecuta DNSViz.

Objetivo:

- conservar la lista original completa mientras dure el trabajo;
- normalizar entradas;
- detectar invalidos y duplicados;
- identificar subdominios;
- clasificar genericos y ccTLD;
- agrupar ccTLD por pais y subzona (`ec`, `org.ec`, `com.ec`, `gob.ec`, `edu.ec`, etc.);
- mostrar estadisticas del universo cargado.

La lista grande no se destruye cuando el usuario selecciona un grupo. Los grupos y
lotes son vistas sobre el inventario hasta que el usuario limpie o cargue una
nueva lista.

La interfaz del laboratorio no debe mezclar todos los modulos en una sola pagina.
Debe existir navegacion interna superior:

- tablero del laboratorio (`/lab`);
- preparacion de dominios (`/lab/prepare`);
- campanas;
- reportes.

La preparacion de dominios vive en su propia pagina para que el usuario cargue,
organice, filtre y revise listas antes de crear una campana.

### Selecciones y lotes de trabajo

Sobre el inventario, el usuario puede seleccionar:

- todos los validos;
- genericos por TLD (`com`, `org`, `net`, etc.);
- ccTLD por raiz (`ec`, `co`, `pe`, etc.);
- ccTLD por subzona (`org.ec`, `com.ec`, `gob.ec`, `edu.ec`, etc.);
- recomendaciones;
- lotes sugeridos de 100 dominios de analisis.

La seleccion activa puede descargarse como TXT o CSV. El TXT contiene dominios
unicos candidatos a analisis. El CSV conserva columnas de auditoria y
clasificacion.

Antes de enviar a analisis, el sistema debe mostrar una revision explicita:

- mensaje de advertencia con el tipo de seleccion;
- maximo 100 dominios;
- lista visible;
- lista editable;
- acciones: procesar, aplicar edicion, cancelar.

Si el usuario cancela, vuelve al inventario sin perder la lista original.

### Subdominios

En el inventario grande no se hacen consultas DNS para verificar si un subdominio
esta delegado. Basta marcarlo como subdominio que requiere revision antes de
entrar al lote de analisis.

Ejemplo:

- `observatorios.corpece.org.ec` queda como subdominio pendiente de revision.
- Su dominio base sugerido es `corpece.org.ec`.
- La verificacion real de delegacion se hara solo si el subdominio entra a una
  lista depurada de hasta 100 dominios.

### Campana de analisis

Cuando el usuario confirma una seleccion, se crea una campana o lote de analisis.
Cada lote operacional debe tener maximo 100 dominios candidatos.

Antes de analizar hijos, el sistema debe construir el mapa de zonas comunes:

- `.`;
- `ec`;
- `org.ec`;
- `com.ec`;
- etc.

Para un lote con `isoc.org.ec`, `corpece.org.ec` y otros `*.org.ec`, el sistema
analiza primero las zonas padre de la campana:

- `.`;
- `ec`;
- `org.ec`.

El resultado de esas zonas padre se considera cache de campana, no cache global.
Si hay un hallazgo padre, se puede repetir un numero pequeno de veces para
confirmar consistencia y evitar interpretar una falla temporal como hallazgo
estructural.

Luego se analizan los dominios hijos. En el reporte se separa:

- hallazgo padre;
- hallazgo heredado;
- hallazgo propio del dominio;
- hallazgo repetido;
- hallazgo inconsistente.

Esto evita reportar 100 veces la misma falla de `org.ec` como si fuera una falla
independiente de cada dominio hijo.

### Ejecucion controlada

Una vez confirmada la campana:

1. Se aplican protecciones:
   - maximo por lote;
   - cola;
   - limite por usuario;
   - limite global;
   - reintentos controlados.
2. Se crea un `analysis_job`.
3. Cada dominio se agrega como `analysis_job_item`.
4. La cola procesa dominios con concurrencia controlada.
5. El worker ejecuta DNSViz.
6. Se guardan artefactos en Cloud Storage.
7. Se extraen hallazgos estructurados.
8. Se actualiza la base de datos.
9. El usuario revisa dashboard del lote.
10. Se generan reportes segun filtros y agrupaciones.

## Normalizacion de dominios

El laboratorio debe separar el valor ingresado del dominio analizado.

Ejemplos:

- `https://www.corpece.org.ec/path` -> `corpece.org.ec`
- `www.corpece.org.ec` -> `corpece.org.ec`
- `CORPECE.ORG.EC` -> `corpece.org.ec`

La normalizacion debe ser trazable:

- valor original;
- valor normalizado;
- regla aplicada;
- advertencia si hay ambiguedad;
- usuario que confirma.

## Agrupaciones utiles

El sistema de reportes debe poder agrupar por:

- dominio;
- TLD;
- ccTLD;
- gTLD;
- zona delegada;
- nameserver;
- proveedor DNS;
- IP;
- ASN;
- hosting;
- estado DNSSEC;
- tipo de error;
- severidad;
- fecha de analisis;
- campana o lote.

## Reportes de FASE 2

Tipos iniciales:

- Reporte tecnico completo.
- Reporte ejecutivo.
- Reporte por dominio.
- Reporte por lote.
- Reporte por TLD o ccTLD.
- Reporte por proveedor DNS.
- Reporte por patron de falla.
- Reporte comparativo historico.

Formatos:

- HTML interno.
- PDF.
- CSV.
- JSON.

Publicacion:

- Solo el admin o superadmin puede publicar un reporte en la seccion publica.
- La publicacion debe tener estado: borrador, aprobado, publicado, archivado.

## Proteccion contra abuso

Aunque el sistema no consulte DNSViz.net para ejecutar analisis, si consulta servidores autoritativos reales. Un uso masivo puede ser interpretado como trafico abusivo por operadores DNS, ccTLDs, proveedores cloud o sistemas antiabuso.

Controles recomendados:

- FASE 2 solo con usuarios autenticados.
- Usuarios creados manualmente.
- Limite de dominios por lote.
- Limite diario por usuario.
- Limite de concurrencia global.
- Cache de resultados recientes.
- Backoff ante fallas repetidas.
- Pausa administrativa del worker.
- Auditoria completa.
- Terminos de uso del laboratorio.
- Identificacion clara del proposito tecnico/academico.

## Decision tecnica actual

La decision tecnica recomendada para evolucionar el sistema es:

- Mantener FASE 1 como servicio publico simple.
- Crear FASE 2 como laboratorio privado separado.
- Usar Google Workspace/IAP o login Google para acceso al laboratorio.
- Usar Cloud SQL PostgreSQL para datos estructurados.
- Usar Cloud Storage para artefactos.
- Mantener la VM Ubuntu/GCP dual-stack como worker DNSViz.
- Usar Cloud Run para los servicios web.

## Orden de implementacion recomendado

1. Congelar contrato publico de FASE 1.
2. Crear esquema PostgreSQL inicial.
3. Migrar usuarios/roles de `db.json` a base relacional.
4. Separar rutas publicas y rutas de laboratorio.
5. Integrar identidad Google/Workspace.
6. Crear modulo Admin v2.
7. Crear modulo Laboratorio DNSSEC.
8. Implementar bulk con cola controlada.
9. Persistir artefactos en Cloud Storage.
10. Extraer hallazgos estructurados a PostgreSQL.
11. Crear generador de reportes.
12. Crear publicacion controlada de reportes.
