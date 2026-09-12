'use strict';

/**
 * Diccionario de traducción de la interfaz estática del portal Mediciones
 * ISOC LAC (2026-09-11) — a pedido explícito: un único idioma global
 * (español/inglés), reversible, visible desde la primera página, cargado
 * por igual en index.html y admin.html (por eso vive en /public, servido
 * como archivo estático — ver server.js, no es una dependencia nueva).
 *
 * Deliberadamente NO traduce (ver docs/arquitectura.md § "Toggle de
 * idioma de sitio completo" para el detalle y el porqué de cada uno):
 *   - La narrativa que genera el motor DNSSEC del lado del servidor
 *     (logic/content/dnssecGuidance.content.js, dnssecGlossary.content.js,
 *     logic/rules/dnssec.rules.js, logic/processors/dnssec.processor.js)
 *     — prosa ligada a lógica de clasificación cerrada metodológicamente.
 *     Siempre en español, sin importar el idioma elegido.
 *   - Los reportes PDF/JSON del módulo Mediciones
 *     (logic/exporters/medicionesBatchReport.exporter.js) — texto fijo
 *     propio, independiente de este diccionario.
 *   - El contenido editorial de Blog/Eventos/Materiales — lo escriben los
 *     administradores vía el panel, se muestra tal cual lo escribieron.
 *
 * Convención de uso:
 *   - `data-i18n="clave"` en HTML estático → aplica a `textContent`.
 *   - `data-i18n-html="clave"` → igual, pero aplica a `innerHTML` — SOLO
 *     para bloques con marcado embebido de confianza (`<strong>`, `<code>`,
 *     `<a>`, etc.) que el propio equipo escribe en el diccionario; nunca
 *     para contenido con datos de usuario/CMS de por medio.
 *   - `data-i18n-placeholder` / `data-i18n-title` / `data-i18n-aria-label`
 *     → mismo mecanismo, para esos atributos.
 *   - `t('clave')` dentro de JS que arma HTML dinámicamente (tablas,
 *     alertas, mensajes) — mismo patrón que ya usaba `checkConfig[key].label`
 *     para los nombres de los checks (ver index.html, módulo Mediciones),
 *     ahora generalizado a todo el sitio.
 *
 * Español es el idioma de respaldo (fallback) si falta una clave en inglés
 * — nunca debe verse una clave cruda sin traducir en pantalla.
 */

const TRANSLATIONS = {
  es: {
    // ── Fase 1: cabecera global y pestañas (visible en toda página) ──
    'site.title': 'Suite de Análisis de Dominios',
    'site.subtitle': 'Herramienta experimental para apoyar las mediciones y la implementación del DNSSEC en la región LAC.',
    'site.aboutBtn': 'Acerca de',
    'site.adminAccess': 'Acceso administración',
    'site.adminLink': 'Admin',
    'site.aboutText': 'Varios capítulos de ISOC en región LAC desarrollaron esta herramienta abierta para medir la adopción de tecnologías y buenas prácticas en Internet en América Latina y el Caribe.',
    'tab.inicio': 'INICIO',
    'tab.preparacion': 'DataSet',
    'tab.mediciones': 'MEDICIONES',
    'tab.dnssec': 'DNSSEC',
    'tab.observatorio': 'OBSERVATORIO',
    'tab.blog': 'BLOG',
    'tab.informacion': 'INFORMACIÓN',
    'tab.eventos': 'EVENTOS',

    // ── Fase 2: Inicio + Observatorio ──
    'inicio.about.heading': '¿Qué es Mediciones ISOC LAC?',
    'inicio.about.body': 'Esta plataforma es una iniciativa abierta impulsada por capítulos de <strong>Internet Society (ISOC)</strong> en América Latina y el Caribe para generar evidencia técnica sobre la salud de la infraestructura de Internet en la región: adopción de DNSSEC, seguridad de enrutamiento (RPKI) y buenas prácticas en dominios ccTLD (<code>.ec</code>, <code>.co</code>, <code>.ar</code>, <code>.mx</code>, ...). Los datos generados alimentan reportes que respaldan política pública regional y se integran con <a href="https://pulse.internetsociety.org" target="_blank" class="text-blue-600 underline">ISOC Pulse</a>, la plataforma global de métricas de Internet Society.',
    'inicio.modules.heading': 'Módulos de la plataforma',
    'inicio.module.mediciones.title': 'Mediciones',
    'inicio.module.mediciones.body': 'Análisis individual o por lote de un dominio: MX, DKIM, RPKI, WHOIS, CAA, TLSA, cabeceras de seguridad, cadena TLS y más de 30 verificaciones técnicas por dominio.',
    'inicio.module.dnssec.title': 'DNSSEC',
    'inicio.module.dnssec.body': 'Valida la cadena de firma DNSSEC completa (TLD → dominio) y las delegaciones seguras (DS/DNSKEY), en modo individual o por lote sobre listas de dominios.',
    'inicio.module.observatorio.title': 'Observatorio <span class="text-amber-600 normal-case font-semibold">(en construcción)</span>',
    'inicio.module.observatorio.body': 'Panel de comparación de la evolución de DNSSEC por país, entre países de la región y frente a otras regiones del mundo — pendiente de definir las fuentes de datos.',
    'inicio.goLink': 'Ir al módulo →',
    'obs.heading': 'Observatorio DNSSEC — LAC',
    'obs.badge': 'En construcción',
    'obs.intro': 'El Observatorio será un panel de comparación, no una herramienta de análisis por lote. En vez de correr verificaciones sobre listas propias, mostrará la <strong>evolución de la adopción de DNSSEC</strong> ya medida a partir de fuentes de datos regionales:',
    'obs.byCountry.title': 'Por país',
    'obs.byCountry.body': 'Evolución en el tiempo de la adopción de DNSSEC dentro de un mismo país — ¿el porcentaje de dominios firmados sube, baja o se estanca?',
    'obs.betweenCountries.title': 'Entre países',
    'obs.betweenCountries.body': 'Comparación lado a lado entre países de la región LAC — qué ccTLD lidera la adopción y cuáles van rezagados.',
    'obs.vsRegions.title': 'LAC vs. otras regiones',
    'obs.vsRegions.body': 'Ubicar a América Latina y el Caribe frente a otras regiones del mundo, para dimensionar la brecha o el avance relativo.',
    'obs.pending.title': 'Pendiente de definir',
    'obs.pending.body': 'Todavía no se ha definido de dónde vendrán los datos de esta comparación (fuente propia, agregador internacional existente, o una combinación). El dashboard no se activa hasta resolver esa fuente — así se evita construir sobre una base de datos que luego cambie de origen o de formato.',

    // ── Fase 3: Blog + Eventos + Información (solo interfaz — el
    // contenido editorial en sí, escrito por administradores, nunca se
    // traduce) ──
    'info.heading': 'Información',
    'info.intro': 'Guías, presentaciones y material de capacitación sobre DNSSEC y sobre la metodología de mediciones: qué se mide, por qué es válido hacerlo y para qué sirve.',
    'info.empty': 'Aún no hay material de capacitación publicado.',
    'info.viewMaterial': 'Ver material →',
    'blog.heading': 'Blog',
    'blog.intro': 'Artículos técnicos y de opinión sobre DNSSEC, RPKI y la infraestructura de Internet en la región.',
    'blog.empty': 'Aún no hay artículos publicados. Próximamente contenido técnico y de opinión sobre DNSSEC, RPKI y medición de infraestructura regional.',
    'eventos.heading': 'Eventos',
    'eventos.intro': 'Cursos, seminarios y capacitaciones organizados por los capítulos ISOC de la región.',
    'eventos.empty': 'No hay eventos programados por el momento. Aquí se publicarán cursos, seminarios y capacitaciones sobre DNSSEC y mediciones ISOC LAC.',
    'eventos.moreInfo': 'Más información →',

    // ── Fase 4: Preparación de datasets (contenido estático) ──
    'prep.heading': 'Preparación de datasets de dominios',
    'prep.intro': 'Esta sección prepara el universo de dominios que posteriormente utilizarán las mediciones del portal (Mediciones, DNSSEC y Observatorio). A partir de una fuente de dominios (por ejemplo, listas ccTLD de OpenINTEL basadas en Certificate Transparency), el flujo de preparación normaliza, clasifica y valida técnicamente cada nombre antes de que forme parte del dataset operativo — sin exigir todavía A/AAAA, MX, DNSSEC ni disponibilidad web como criterio de exclusión.',
    'prep.step.fuente.title': 'Fuente',
    'prep.step.fuente.body': 'Archivo de origen de dominios (ej. listas ccTLD de OpenINTEL vía Certificate Transparency). Es una fuente amplia de descubrimiento, no un censo oficial del ccTLD.',
    'prep.step.carga.title': 'Carga',
    'prep.step.carga.body': 'Subida del archivo al portal (.txt/.csv, un dominio por línea o primera columna).',
    'prep.step.normalizacion.title': 'Normalización',
    'prep.step.normalizacion.body': 'Limpieza y deduplicación: minúsculas, IDNA/Punycode, validación de sintaxis y ccTLD, y clasificación por sufijo con la Public Suffix List (sección ICANN).',
    'prep.step.validacion.title': 'Validación DNS',
    'prep.step.validacion.body': 'Confirmación de existencia DNS contra dos resolvers independientes (Cloudflare y Google): NS y, si es inconcluso, SOA. Clasifica cada dominio como VALID, NXDOMAIN o REVIEW.',
    'prep.step.resultado.title': 'Resultados y descarga',
    'prep.step.resultado.body': 'Dataset operativo (dominios VALID) listo para las mediciones del portal, junto con las listas de exclusión, discrepancias y el reporte de metodología.',
    'prep.source.badge': 'Fuente recomendada',
    'prep.source.list': '<li>La lista ccTLD se descarga <strong>manualmente</strong> desde el sitio de OpenINTEL — este portal no realiza scraping ni descargas automáticas.</li><li>Las listas se derivan principalmente de nombres observados en <strong>Certificate Transparency (CT)</strong>.</li><li>Ofrecen una cobertura amplia, pero <strong>no son un archivo oficial de zona ni un censo completo</strong> del ccTLD.</li><li>Que un dominio aparezca en la lista <strong>no garantiza que siga existiendo actualmente en DNS</strong> — por eso Mediciones realiza después una validación DNS independiente.</li><li>Antes de descargar, revisa y acepta directamente los <strong>términos y licencia</strong> aplicables de OpenINTEL en su propio sitio; este portal no los gestiona ni los reemplaza.</li>',
    'prep.source.link': 'Ir al sitio oficial de OpenINTEL →',
    'prep.source.continueBtn': 'Ya tengo el archivo — continuar a Carga →',
    'prep.upload.heading': 'Carga del archivo',
    'prep.upload.body': 'Selecciona el archivo .txt o .csv descargado desde la fuente (un dominio por línea, o primera columna si es CSV). El archivo se procesa en este portal; no se sube a ningún tercero.',
    'prep.upload.selectFile': 'Seleccionar archivo…',
    'prep.upload.meta.name': 'Nombre:',
    'prep.upload.meta.size': 'Tamaño:',
    'prep.upload.meta.lines': 'Líneas:',
    'prep.upload.meta.date': 'Fecha (del nombre):',
    'prep.upload.meta.sha256': 'SHA-256:',
    'prep.upload.tldLabel': 'ccTLD detectado (editable):',
    'prep.upload.tldWarning': '⚠ Cambiar el ccTLD no es solo una etiqueta: modifica el criterio de filtrado — decide qué dominios se aceptan o se rechazan como "outside_tld" durante la normalización. Corrígelo solo si el detectado es incorrecto.',
    'prep.upload.continueBtn': 'Continuar a Normalización →',
    'prep.norm.heading': 'Normalización',
    'prep.norm.body': 'Aplica la misma metodología del validador de referencia: trim, minúsculas, eliminación de punto final, IDNA/Punycode, eliminación de vacíos y duplicados, validación de longitud/sintaxis, pertenencia al ccTLD, y clasificación por sufijo con la Public Suffix List (sección ICANN). Todavía no se ejecutan consultas DNS ni se clasifica como VALID/NXDOMAIN/REVIEW.',
    'prep.norm.runBtn': 'Normalizar dominios',
    'prep.norm.loading': 'Normalizando y clasificando por sufijo (PSL, sección ICANN)…',
    'prep.dns.heading': 'Validación DNS',
    'prep.dns.body': 'Réplica fiel del validador de referencia: confirma existencia DNS contra dos resolvers independientes — Cloudflare (1.1.1.1) y Google (8.8.8.8) — consultando NS y, si es inconcluso, SOA, con CD=1 para no depender de la validación DNSSEC del resolver. <strong>VALID</strong> = NOERROR en al menos un resolver. <strong>NXDOMAIN</strong> = ambos resolvers confirman NXDOMAIN para el mismo tipo de consulta. <strong>REVIEW</strong> = resultado no concluyente, no se descarta automáticamente. Los REVIEW de la primera pasada se reintentan una vez de forma automática.',
    'prep.dns.startBtn': 'Iniciar validación DNS',
    'prep.dns.preflight': 'Preflight de resolvers…',

    // ── Fase 5: Mediciones (cabecera + flujo único de análisis) ──
    // Hasta 2026-09-11 existían dos flujos ("Un dominio" y "Reporte por
    // lote", claves med.subtab.*/med.single.*) — se unificaron a pedido
    // explícito del usuario. Ver docs/arquitectura.md.
    'med.heading': 'MEDICIONES',
    'med.subtitle': 'Análisis de dominios por país y evaluación de infraestructura de red.',
    'med.guideBadge': 'Guía institucional de apoyo',
    'med.downloadGuide': 'Descargar guía MEDICIONES',
    'med.mainModuleBadge': 'Módulo principal',
    'med.glossary.title': '📖 Glosario de términos — qué mide cada indicador',
    'med.glossary.hint': 'Ver todos los grupos',
    'med.symbolsMeaning': 'Significado de los símbolos:',
    'med.checksLabel': 'Verificaciones a realizar',
    'med.selectAllGlobal': 'Todos/Ninguno',
    'med.group.selectAllTitle': 'Marcar o desmarcar todo este grupo',
    'med.analyzing': 'Analizando...',
    'med.summary.heading': 'Resumen en vivo',
    'med.summary.subtitle': 'Totales por verificación, actualizándose a medida que avanza el análisis',
    'med.summary.colCheck': 'Verificación',
    'med.summary.colYes': 'Sí',
    'med.summary.colNo': 'No',
    'med.batch.domainsLabel': 'Lista de dominios',
    'med.batch.domainsHint': 'Uno o varios, pegados o subidos como archivo',
    'med.batch.uploadFile': 'Subir archivo .txt o .csv',
    'med.batch.uploadHint': 'Un dominio por línea, o separados por coma. Sin encabezados.',
    'med.batch.maxHint': 'Se depuran duplicados y se ordenan automáticamente antes de analizar',
    'med.batch.speedLabel': 'Velocidad:',
    'med.batch.speed.slow': 'Conservadora — 5 simultáneos',
    'med.batch.speed.recommended': 'Recomendada — 10 simultáneos',
    'med.batch.speed.fast': 'Rápida — 15 simultáneos',
    'med.batch.includeDetail': 'Incluir detalle completo por dominio en el reporte',
    'med.batch.includeDetailHint': 'Por defecto el reporte trae solo la tabla comparativa (dominio × indicador). Si marcas esto, se agrega además una sección con el detalle de cada dominio.',
    'med.batch.analyzeBtn': 'Analizar',
    'med.batch.cancelBtn': 'Cancelar',
    'med.batch.processing': 'Procesando…',
    'med.batch.dnsQueue': 'Validación DNS: en cola…',
    'med.batch.domainsAnalyzed': 'Dominios analizados',
    'med.batch.tableHeading': 'Tabla de resultados — dominio × verificación',
    'med.batch.sliderAriaLabel': 'Desplazar tabla horizontalmente para ver más columnas',
    'med.batch.downloadPdf': 'Descargar PDF',
    'med.batch.downloadJson': 'Descargar JSON',
    'status.ok': 'OK — cumple / se detectó correctamente',
    'status.fail': 'No cumple / no se encontró',
    'status.error': 'Error al verificar — no se pudo comprobar (timeout, servicio externo caído, etc.)',
    'status.info': 'Informativo — dato disponible, sin evaluación de "bien/mal"',
    'status.empty': 'Sin datos — este check no se ejecutó para este dominio',
    'med.alert.noDomains': 'Ingresa al menos un dominio.',
    'med.alert.noChecks': 'Selecciona al menos una verificación.',
  },
  en: {
    'site.title': 'Domain Analysis Suite',
    'site.subtitle': 'Experimental tool to support Internet measurements and DNSSEC deployment in the LAC region.',
    'site.aboutBtn': 'About',
    'site.adminAccess': 'Admin access',
    'site.adminLink': 'Admin',
    'site.aboutText': 'Several ISOC chapters in the LAC region developed this open tool to measure the adoption of Internet technologies and best practices in Latin America and the Caribbean.',
    'tab.inicio': 'HOME',
    'tab.preparacion': 'DataSet',
    'tab.mediciones': 'MEASUREMENTS',
    'tab.dnssec': 'DNSSEC',
    'tab.observatorio': 'OBSERVATORY',
    'tab.blog': 'BLOG',
    'tab.informacion': 'INFORMATION',
    'tab.eventos': 'EVENTS',

    // ── Fase 2: Inicio + Observatorio ──
    'inicio.about.heading': 'What is Mediciones ISOC LAC?',
    'inicio.about.body': 'This platform is an open initiative driven by <strong>Internet Society (ISOC)</strong> chapters in Latin America and the Caribbean to generate technical evidence about the health of Internet infrastructure in the region: DNSSEC adoption, routing security (RPKI), and best practices across ccTLD domains (<code>.ec</code>, <code>.co</code>, <code>.ar</code>, <code>.mx</code>, ...). The generated data feeds reports that support regional public policy and integrates with <a href="https://pulse.internetsociety.org" target="_blank" class="text-blue-600 underline">ISOC Pulse</a>, Internet Society\'s global Internet metrics platform.',
    'inicio.modules.heading': 'Platform modules',
    'inicio.module.mediciones.title': 'Measurements',
    'inicio.module.mediciones.body': 'Individual or batch analysis of a domain: MX, DKIM, RPKI, WHOIS, CAA, TLSA, security headers, TLS chain, and over 30 technical checks per domain.',
    'inicio.module.dnssec.title': 'DNSSEC',
    'inicio.module.dnssec.body': 'Validates the full DNSSEC signature chain (TLD → domain) and secure delegations (DS/DNSKEY), in individual or batch mode over domain lists.',
    'inicio.module.observatorio.title': 'Observatory <span class="text-amber-600 normal-case font-semibold">(under construction)</span>',
    'inicio.module.observatorio.body': 'Comparison panel for the evolution of DNSSEC by country, between countries in the region, and against other regions of the world — data sources still to be defined.',
    'inicio.goLink': 'Go to module →',
    'obs.heading': 'DNSSEC Observatory — LAC',
    'obs.badge': 'Under construction',
    'obs.intro': 'The Observatory will be a comparison panel, not a batch analysis tool. Instead of running checks on your own lists, it will show the <strong>evolution of DNSSEC adoption</strong> already measured from regional data sources:',
    'obs.byCountry.title': 'By country',
    'obs.byCountry.body': 'Evolution over time of DNSSEC adoption within a single country — is the percentage of signed domains rising, falling, or stagnant?',
    'obs.betweenCountries.title': 'Between countries',
    'obs.betweenCountries.body': 'Side-by-side comparison between countries in the LAC region — which ccTLD leads adoption and which lag behind.',
    'obs.vsRegions.title': 'LAC vs. other regions',
    'obs.vsRegions.body': 'Position Latin America and the Caribbean against other regions of the world, to gauge the relative gap or progress.',
    'obs.pending.title': 'Still to be defined',
    'obs.pending.body': 'It has not yet been decided where the data for this comparison will come from (an own source, an existing international aggregator, or a combination). The dashboard won\'t activate until that source is resolved — this avoids building on a data source that later changes origin or format.',

    // ── Fase 3: Blog + Eventos + Información ──
    'info.heading': 'Information',
    'info.intro': 'Guides, presentations, and training material on DNSSEC and on the measurement methodology: what is measured, why it is valid to do so, and what it is for.',
    'info.empty': 'No training material has been published yet.',
    'info.viewMaterial': 'View material →',
    'blog.heading': 'Blog',
    'blog.intro': 'Technical articles and opinion pieces on DNSSEC, RPKI, and Internet infrastructure in the region.',
    'blog.empty': 'No articles published yet. Technical and opinion content on DNSSEC, RPKI, and regional infrastructure measurement is coming soon.',
    'eventos.heading': 'Events',
    'eventos.intro': 'Courses, seminars, and training sessions organized by ISOC chapters in the region.',
    'eventos.empty': 'No events scheduled at the moment. Courses, seminars, and training on DNSSEC and Mediciones ISOC LAC will be published here.',
    'eventos.moreInfo': 'More information →',

    // ── Fase 4: Preparación de datasets ──
    'prep.heading': 'Domain Dataset Preparation',
    'prep.intro': 'This section prepares the universe of domains that the portal\'s measurements (Measurements, DNSSEC, and Observatory) will use afterward. Starting from a domain source (for example, OpenINTEL ccTLD lists based on Certificate Transparency), the preparation flow normalizes, classifies, and technically validates each name before it becomes part of the operational dataset — without yet requiring A/AAAA, MX, DNSSEC, or web availability as exclusion criteria.',
    'prep.step.fuente.title': 'Source',
    'prep.step.fuente.body': 'Source file of domains (e.g. OpenINTEL ccTLD lists via Certificate Transparency). It is a broad discovery source, not an official ccTLD census.',
    'prep.step.carga.title': 'Upload',
    'prep.step.carga.body': 'Upload the file to the portal (.txt/.csv, one domain per line or first column).',
    'prep.step.normalizacion.title': 'Normalization',
    'prep.step.normalizacion.body': 'Cleanup and deduplication: lowercase, IDNA/Punycode, syntax and ccTLD validation, and suffix classification with the Public Suffix List (ICANN section).',
    'prep.step.validacion.title': 'DNS Validation',
    'prep.step.validacion.body': 'Confirms DNS existence against two independent resolvers (Cloudflare and Google): NS and, if inconclusive, SOA. Classifies each domain as VALID, NXDOMAIN, or REVIEW.',
    'prep.step.resultado.title': 'Results and download',
    'prep.step.resultado.body': 'Operational dataset (VALID domains) ready for the portal\'s measurements, along with the exclusion lists, discrepancies, and the methodology report.',
    'prep.source.badge': 'Recommended source',
    'prep.source.list': '<li>The ccTLD list is downloaded <strong>manually</strong> from the OpenINTEL site — this portal does not scrape or auto-download it.</li><li>The lists are derived mainly from names observed in <strong>Certificate Transparency (CT)</strong>.</li><li>They offer broad coverage, but <strong>are not an official zone file or a complete census</strong> of the ccTLD.</li><li>A domain appearing on the list <strong>does not guarantee it currently exists in DNS</strong> — that\'s why Mediciones later performs an independent DNS validation.</li><li>Before downloading, review and accept OpenINTEL\'s applicable <strong>terms and license</strong> directly on their own site; this portal does not manage or replace them.</li>',
    'prep.source.link': 'Go to the official OpenINTEL site →',
    'prep.source.continueBtn': 'I already have the file — continue to Upload →',
    'prep.upload.heading': 'File upload',
    'prep.upload.body': 'Select the .txt or .csv file downloaded from the source (one domain per line, or first column if CSV). The file is processed on this portal; it is not uploaded to any third party.',
    'prep.upload.selectFile': 'Select file…',
    'prep.upload.meta.name': 'Name:',
    'prep.upload.meta.size': 'Size:',
    'prep.upload.meta.lines': 'Lines:',
    'prep.upload.meta.date': 'Date (from filename):',
    'prep.upload.meta.sha256': 'SHA-256:',
    'prep.upload.tldLabel': 'Detected ccTLD (editable):',
    'prep.upload.tldWarning': '⚠ Changing the ccTLD is not just a label: it changes the filtering criteria — it decides which domains are accepted or rejected as "outside_tld" during normalization. Only correct it if the detected value is wrong.',
    'prep.upload.continueBtn': 'Continue to Normalization →',
    'prep.norm.heading': 'Normalization',
    'prep.norm.body': 'Applies the same methodology as the reference validator: trim, lowercase, trailing-dot removal, IDNA/Punycode, removal of empty entries and duplicates, length/syntax validation, ccTLD membership, and suffix classification with the Public Suffix List (ICANN section). DNS queries are not run yet, nor is anything classified as VALID/NXDOMAIN/REVIEW.',
    'prep.norm.runBtn': 'Normalize domains',
    'prep.norm.loading': 'Normalizing and classifying by suffix (PSL, ICANN section)…',
    'prep.dns.heading': 'DNS Validation',
    'prep.dns.body': 'A faithful replica of the reference validator: confirms DNS existence against two independent resolvers — Cloudflare (1.1.1.1) and Google (8.8.8.8) — querying NS and, if inconclusive, SOA, with CD=1 so it doesn\'t depend on the resolver\'s own DNSSEC validation. <strong>VALID</strong> = NOERROR on at least one resolver. <strong>NXDOMAIN</strong> = both resolvers confirm NXDOMAIN for the same query type. <strong>REVIEW</strong> = inconclusive result, not automatically discarded. REVIEW results from the first pass are automatically retried once.',
    'prep.dns.startBtn': 'Start DNS validation',
    'prep.dns.preflight': 'Resolver preflight…',

    // ── Fase 5: Mediciones ──
    'med.heading': 'MEASUREMENTS',
    'med.subtitle': 'Domain analysis by country and network infrastructure assessment.',
    'med.guideBadge': 'Institutional support guide',
    'med.downloadGuide': 'Download MEDICIONES guide',
    'med.mainModuleBadge': 'Main module',
    'med.glossary.title': '📖 Glossary of terms — what each indicator measures',
    'med.glossary.hint': 'View all groups',
    'med.symbolsMeaning': 'What the symbols mean:',
    'med.checksLabel': 'Checks to run',
    'med.selectAllGlobal': 'All/None',
    'med.group.selectAllTitle': 'Check or uncheck this entire group',
    'med.analyzing': 'Analyzing...',
    'med.summary.heading': 'Live summary',
    'med.summary.subtitle': 'Per-check totals, updating as the analysis runs',
    'med.summary.colCheck': 'Check',
    'med.summary.colYes': 'Yes',
    'med.summary.colNo': 'No',
    'med.batch.domainsLabel': 'Domain list',
    'med.batch.domainsHint': 'One or several, pasted or uploaded as a file',
    'med.batch.uploadFile': 'Upload .txt or .csv file',
    'med.batch.uploadHint': 'One domain per line, or comma-separated. No headers.',
    'med.batch.maxHint': 'Duplicates are removed and the list is sorted automatically before analysis',
    'med.batch.speedLabel': 'Speed:',
    'med.batch.speed.slow': 'Conservative — 5 concurrent',
    'med.batch.speed.recommended': 'Recommended — 10 concurrent',
    'med.batch.speed.fast': 'Fast — 15 concurrent',
    'med.batch.includeDetail': 'Include full per-domain detail in the report',
    'med.batch.includeDetailHint': 'By default the report only includes the comparative table (domain × indicator). If you check this, a section with each domain\'s detail is added.',
    'med.batch.analyzeBtn': 'Analyze',
    'med.batch.cancelBtn': 'Cancel',
    'med.batch.processing': 'Processing…',
    'med.batch.dnsQueue': 'DNS validation: queued…',
    'med.batch.domainsAnalyzed': 'Domains analyzed',
    'med.batch.tableHeading': 'Results table — domain × check',
    'med.batch.sliderAriaLabel': 'Scroll table horizontally to see more columns',
    'med.batch.downloadPdf': 'Download PDF',
    'med.batch.downloadJson': 'Download JSON',
    'status.ok': 'OK — passes / detected correctly',
    'status.fail': 'Fails / not found',
    'status.error': 'Error checking — could not verify (timeout, external service down, etc.)',
    'status.info': 'Informational — data available, no "good/bad" evaluation',
    'status.empty': 'No data — this check did not run for this domain',
    'med.alert.noDomains': 'Enter at least one domain.',
    'med.alert.noChecks': 'Select at least one check.',
  }
};

function t(key) {
  return (TRANSLATIONS[currentLang] && TRANSLATIONS[currentLang][key])
    || TRANSLATIONS.es[key]
    || key;
}

// Idioma por defecto: español (idioma principal del sitio, <html lang="es">,
// todo el contenido actual). No se migra la preferencia del mecanismo
// anterior específico de Mediciones (mediciones-check-label-lang) — ese
// solo afectaba ~54 nombres de checks, no "todo el sitio en inglés"; con
// el alcance ahora global, arrancar en español para todos es el default
// correcto, y cambiar de idioma es un clic.
let currentLang = localStorage.getItem('isoc-lac-lang') === 'en' ? 'en' : 'es';

function applyLanguage(lang) {
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    el.textContent = t(el.getAttribute('data-i18n'));
  });
  document.querySelectorAll('[data-i18n-html]').forEach((el) => {
    el.innerHTML = t(el.getAttribute('data-i18n-html'));
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
    el.setAttribute('placeholder', t(el.getAttribute('data-i18n-placeholder')));
  });
  document.querySelectorAll('[data-i18n-title]').forEach((el) => {
    el.setAttribute('title', t(el.getAttribute('data-i18n-title')));
  });
  document.querySelectorAll('[data-i18n-aria-label]').forEach((el) => {
    el.setAttribute('aria-label', t(el.getAttribute('data-i18n-aria-label')));
  });
  document.documentElement.setAttribute('lang', lang);
  updateLangToggleButtons();
  // Hook opcional: cada página (index.html/admin.html) puede definir
  // window.onLanguageApplied para re-renderizar sus propios bloques
  // armados por JS (tablas, listas) que no pasan por data-i18n. i18n.js
  // no conoce esas funciones — evita acoplar este archivo compartido a
  // una página en particular.
  if (typeof window.onLanguageApplied === 'function') window.onLanguageApplied(lang);
}

function setLanguage(lang) {
  currentLang = lang === 'en' ? 'en' : 'es';
  localStorage.setItem('isoc-lac-lang', currentLang);
  applyLanguage(currentLang);
}

function updateLangToggleButtons() {
  document.querySelectorAll('.lang-toggle-btn').forEach((btn) => {
    btn.textContent = currentLang === 'es' ? '🌐 English' : '🌐 Español';
    btn.setAttribute('aria-pressed', currentLang === 'en' ? 'true' : 'false');
  });
}

document.addEventListener('DOMContentLoaded', () => applyLanguage(currentLang));
