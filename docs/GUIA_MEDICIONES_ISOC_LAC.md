---
title: "MEDICIONES ISOC LAC"
subtitle: "Guía técnica del módulo de medición"
author: "Internet Society LatinoAmérica y el Caribe (LAC)"
contact: "https://mediciones.isoc.org.ec  ·  info@isoc.org.ec"
---

## 1. Introducción

El módulo **MEDICIONES** forma parte del proyecto *Mediciones ISOC LAC*, una
iniciativa colaborativa impulsada por capítulos de Internet Society en
América Latina y el Caribe.

Su propósito es generar **información técnica abierta, comparable y útil**
sobre el estado de la infraestructura de Internet en la región, con énfasis
en buenas prácticas, resiliencia y seguridad.

Esta herramienta tiene carácter **experimental** y está diseñada como un
apoyo para análisis preliminar, investigación y fortalecimiento de
capacidades técnicas.

El sistema es dinámico, en constante evolución y cambio para mejora.

## 2. ¿Qué es el módulo MEDICIONES?

El módulo **MEDICIONES** permite analizar uno o varios dominios asociados a
un país, evaluando distintos componentes de su infraestructura técnica.

A través de un conjunto de verificaciones automatizadas, la herramienta
construye una visión general del estado de:

- Resolución DNS
- Infraestructura de red
- Configuración de servicios
- Elementos básicos de seguridad

El objetivo no es emitir certificaciones, sino **proveer evidencia técnica
inicial** para análisis posteriores.

## 3. ¿Qué se intenta medir?

El módulo busca medir el nivel de adopción de **buenas prácticas técnicas en
Internet**, incluyendo:

### 3.1 Infraestructura de red

- Disponibilidad del dominio
- Resolución IP (IPv4 / IPv6)
- Información de ASN
- Ubicación de servidores
- Redirecciones y comportamiento HTTP

### 3.2 DNS y seguridad

- Existencia de registros DNS
- Configuración de servidores DNS
- Registros TXT
- Políticas CAA
- Preparación para DNSSEC (cuando aplique)

### 3.3 Servicios asociados

- Configuración de correo (MX)
- Puertos abiertos (cuando se evalúa)
- Comportamiento de red (traceroute)

## 4. Enfoque en dominios de 3er y 4to nivel

Uno de los elementos más relevantes del proyecto es el análisis de dominios
estructurados en niveles como:

- **Tercer nivel**
- **Cuarto nivel**

Esto es especialmente importante en países como Ecuador, donde gran parte
de la infraestructura institucional se organiza bajo subdominios.

### ¿Por qué es importante?

- Permite evaluar la **capilaridad real de la adopción tecnológica**
- Identifica brechas entre nivel país y nivel institucional
- Evidencia dependencias estructurales (ej. TLD no firmado → impacto en
  subdominios)
- Permite análisis comparativo entre sectores (gobierno, academia, privado)

## 5. ¿Quiénes están detrás del proyecto?

El proyecto es impulsado por:

- Capítulos regionales de Internet Society
- Comunidad técnica de América Latina y el Caribe
- Colaboradores independientes y académicos

Se alinea con iniciativas globales como:

- Medición de resiliencia de Internet
- Promoción de estándares abiertos
- Fortalecimiento del ecosistema técnico regional

## 6. Importancia para la región LAC

La región de América Latina y el Caribe presenta desafíos específicos:

- Heterogeneidad en la adopción tecnológica
- Dependencia de infraestructura externa
- Brechas en seguridad (especialmente DNSSEC, RPKI, etc.)
- Falta de datos comparables a nivel regional

Este módulo contribuye a:

- Generar evidencia técnica regional
- Apoyar políticas públicas digitales
- Fortalecer capacidades técnicas locales
- Promover estándares de seguridad

## 7. Funcionamiento general

**Mediciones** tiene un único flujo de análisis (hasta el 11-09-2026 existían
dos: "Un dominio" y "Reporte por lote" por separado — se unificaron porque
la distinción no aportaba nada: el mismo formulario sirve para 1 dominio o
para muchos):

1. El usuario pega uno o varios dominios, o sube un archivo `.txt`/`.csv`
   (uno por línea, o separados por coma — sin encabezados)
2. El sistema depura duplicados y ordena la lista automáticamente antes de
   analizar
3. Selecciona las verificaciones a realizar — con una casilla **"Todos/
   Ninguno"** junto al título de cada grupo y otra general arriba del árbol
   de checks, para marcar o desmarcar de un clic
4. El sistema ejecuta las consultas técnicas automatizadas (con una cola de
   concurrencia configurable si son muchos dominios) y muestra un resumen
   en vivo que se va llenando a medida que terminan las verificaciones
5. Al terminar, genera la tabla comparativa (dominio × verificación) en
   pantalla y un reporte descargable en PDF y JSON — ver sección 9

Cada verificación tiene un ícono de ayuda ("?") junto a su nombre con una
descripción de qué mide, y un bloque colapsable **"Glosario de términos"**
con la lista completa. La sección 8 de esta guía reproduce ese mismo
glosario.

Los nombres de los indicadores (ej. "Whois Lookup", "TLS Cipher Suites")
son términos técnicos en inglés, de uso estándar en la industria de
seguridad. El botón **🌐 English / 🌐 Español**, en la cabecera del sitio,
traduce todo el portal —incluidos estos nombres— entre ambos idiomas. La
elección se recuerda en el navegador y se aplica también a los reportes
PDF/JSON que se generen después de usarlo (los nombres de columna de la
tabla reflejan el idioma elegido). Cambiar el idioma no borra las
verificaciones ya marcadas.

### Símbolos de resultado

Cada verificación devuelve uno de estos cuatro estados, mostrados siempre
con el mismo símbolo y color (en pantalla y en el PDF del reporte, sección
9):

- **✓ verde — OK**: cumple / se detectó correctamente.
- **✗ rojo — No cumple**: no se encontró lo que el check busca.
- **⚠ gris — Error al verificar**: no se pudo comprobar (timeout, servicio
  externo caído, etc.) — no es lo mismo que "no cumple".
- **ℹ azul — Informativo**: hay un dato disponible, pero el check no evalúa
  "bien/mal" (por ejemplo, IPv6: tenerlo o no tenerlo no es en sí mismo un
  fallo).
- **— gris claro — Sin datos**: ese check no se ejecutó para ese dominio.

En pantalla, esta leyenda aparece siempre arriba de los resultados. En el
PDF del reporte aparece en la sección **"Cómo leer este reporte"**, al
inicio del documento — ver sección 9.

## 8. Indicadores evaluados

Los indicadores se agrupan en tres niveles según su propósito — no por
tipo de consulta técnica. Esta es la misma fuente de verdad que usa la
interfaz (tooltips y glosario en pantalla, con el mismo aviso para el
grupo de contenido) — si un indicador nuevo se agrega al sistema, esta
lista debe actualizarse desde ahí.

### Núcleo — seguridad y buenas prácticas

**Indicadores núcleo — buenas prácticas de seguridad.** Un resultado "OK" indica que el dominio cumple la práctica descrita; cualquier otro resultado, que no la cumple (o no se pudo verificar) — a diferencia de los indicadores de diagnóstico, aquí el resultado sí tiene un sentido "correcto"/"incorrecto" claro. Se agrupan en 4 categorías. El sistema no calcula ningún resumen ni porcentaje sobre estos indicadores — cada resultado se reporta tal cual, dominio por dominio (ver sección 9).

#### Seguridad y confianza (DNS/TLS)

- **HTTPS** — Comprueba si el sitio final responde por HTTPS correctamente.
- **HTTPS Redirect** — Comprueba si HTTP redirige hacia HTTPS.
- **HTTP Strict Transport Security** — Detecta Strict-Transport-Security, que fuerza uso futuro de HTTPS en navegadores compatibles.
- **CAA** — Busca registros CAA, que indican qué autoridades certificadoras pueden emitir certificados para el dominio.
- **RPKI** — Valida si la IP observada tiene cobertura RPKI válida para el prefijo y ASN de origen.
- **TLSA** — Busca registros TLSA/DANE para vincular certificados TLS con DNSSEC.
- **Malware & Phishing Detection** — Consulta URLHaus para señales públicas de malware o phishing asociadas al dominio.

#### Anti-suplantación de correo

- **SPF** — Comprueba si el dominio publica una política SPF en registros TXT.
- **DMARC** — Comprueba si existe política DMARC en _dmarc del dominio.
- **DKIM** — Busca una clave DKIM con el selector configurado o por defecto.

#### Cabeceras de seguridad web

- **Content Security Policy** — Detecta Content-Security-Policy, política que limita fuentes de scripts, estilos, imágenes y conexiones.
- **X-Frame-Options** — Detecta X-Frame-Options, protección clásica contra clickjacking.
- **X-Content-Type-Options** — Detecta X-Content-Type-Options, que evita interpretación MIME insegura.
- **Referrer-Policy** — Detecta Referrer-Policy, que controla cuánta información de origen se envía al navegar.
- **Permissions-Policy** — Detecta Permissions-Policy, que restringe APIs del navegador como cámara, micrófono o geolocalización.

#### Transparencia y conectividad moderna

- **Security.txt** — Comprueba si existe /.well-known/security.txt para reportar vulnerabilidades.
- **IPv6** — Comprueba si el dominio publica registros AAAA para conectividad IPv6.

### Diagnóstico técnico

**Indicadores de diagnóstico.** Dan contexto técnico, pero no tienen un valor "correcto" único — por ejemplo, ver la versión de TLS no dice por sí sola si es aceptable.

- **More IP Info** — Lista las direcciones IPv4/IPv6 del dominio y datos básicos de geolocalización/ASN cuando están disponibles.
- **Server Location** — Ubica geográficamente la primera IP resuelta del dominio. Es una aproximación basada en bases públicas de IP.
- **Server Info** — Resume IP, ASN, organización, red e ISP asociados al servidor observado.
- **IPv4** — Comprueba si el dominio publica registros A para conectividad IPv4.
- **ASN** — Identifica el Sistema Autónomo que anuncia la IP principal del dominio.
- **Server Status** — Consulta el estado HTTP final del sitio después de redirecciones válidas.
- **Open Ports** — Prueba conectividad básica a puertos comunes. No sustituye un escaneo de seguridad formal.
- **Redirect Chain** — Muestra la cadena HTTP/HTTPS desde el dominio inicial hasta el destino final.
- **Block Detection** — Compara respuestas de resolvers públicos para detectar posibles bloqueos o diferencias de resolución.
- **DNS Records** — Consulta registros DNS principales: A, AAAA, MX, NS, TXT y CNAME.
- **TXT Records** — Lista registros TXT publicados en el dominio, usados para políticas y verificaciones.
- **DNS Server** — Lista los servidores NS autoritativos declarados para el dominio.
- **MX** — Comprueba si el dominio tiene registros MX para recibir correo.
- **SMTPUTF8** — Detecta si los servidores MX anuncian soporte SMTPUTF8 para direcciones internacionalizadas.
- **Whois Lookup** — Consulta fuentes WHOIS/RDAP para datos públicos del registrante, sujetos a redacción por privacidad.
- **Domain Info** — Consulta RDAP para registrar, estado y fechas relevantes del dominio.
- **Headers** — Muestra las cabeceras HTTP observadas en la respuesta final.
- **Server Header** — Muestra el valor de Server, que puede revelar tecnología o estar oculto por el proveedor.
- **HTTP Compression** — Detecta si la respuesta usa compresión HTTP como gzip, br o deflate.
- **OCSP Stapling** — Detecta OCSP Stapling en la conexión TLS, usado para estado de revocación del certificado.
- **TLS Version** — Muestra la versión TLS negociada con el servidor.
- **Key Exchange** — Muestra información de intercambio de claves de la sesión TLS.
- **SSL Chain Info** — Lista la cadena de certificados presentada por el servidor.
- **TLS Cipher Suites** — Prueba suites de cifrado disponibles en TLS 1.2/1.3.
- **TLS Handshake Simulation** — Simula handshakes TLS con distintos perfiles para observar compatibilidad.
- **Firewall Detection** — Detecta señales de WAF/CDN como Cloudflare, Akamai, Sucuri o ModSecurity.
- **X-XSS-Protection** — Detecta X-XSS-Protection. Es una cabecera antigua y hoy menos relevante en navegadores modernos.

### Contenido y experiencia

**Indicadores de contenido y experiencia — fuera del alcance de seguridad/infraestructura de Mediciones ISOC LAC.** Miden aspectos de marketing/UX del sitio (SEO, redes sociales, ranking, capturas). Se mantienen disponibles por si sirven a otro tipo de análisis, pero no se seleccionan por defecto.

- **Site Features** — Detecta señales simples de formularios, búsqueda, video, analítica o comercio en el HTML final.
- **Cookies** — Lista cookies Set-Cookie observadas en la respuesta final del sitio.
- **Crawl Rules** — Lee robots.txt para reglas de rastreo y señales de uso automatizado.
- **Linked Pages** — Extrae enlaces encontrados en la página principal final.
- **Listed Pages** — Lee sitemap.xml y extrae URLs declaradas.
- **Social Tags** — Extrae metadatos sociales como Open Graph, Twitter cards, descripción y viewport.
- **Quality Metrics** — Consulta métricas de PageSpeed/Lighthouse cuando el servicio externo responde.
- **Archive History** — Consulta historial básico de capturas en Internet Archive.
- **Global Ranking** — Consulta ranking global aproximado del dominio en Tranco.
- **Screenshot** — Genera o consulta una captura visual del sitio, si el servicio está disponible.

## 9. Reporte de dominios

El flujo de análisis de **Mediciones** (sección 7) sirve para 1 dominio o
para muchos a la vez — por ejemplo, todos los dominios de instituciones
públicas de un país, o todos los capítulos de un mismo sector — y siempre
termina en un reporte final descargable. No se llama "comparativo" porque
el sistema no compara dominios entre sí: cada uno se mide de forma
independiente, sin importar cuántos se hayan analizado juntos.

### Cómo usarlo

1. Ingresar la lista de dominios: pegando texto (uno o varios, uno por
   línea o separados por coma) o subiendo un archivo `.txt`/`.csv`. El
   sistema depura duplicados y ordena la lista automáticamente.
2. Seleccionar las verificaciones a realizar (árbol de indicadores de la
   sección 8, con el mismo botón de ayuda en cada uno, y una casilla
   "Todos/Ninguno" por grupo y general para marcar/desmarcar rápido).
3. Elegir la velocidad de análisis (conservadora, recomendada o rápida —
   controla cuántos dominios se procesan en simultáneo; irrelevante si es
   un solo dominio).
4. Opcional: marcar "Incluir detalle completo por dominio" si el reporte
   descargable debe traer, además de la tabla comparativa, una sección con
   el detalle de cada dominio (estado DNS, DNSSEC y resultado de cada
   check). Desmarcado por defecto.
5. Presionar **Analizar**. El sistema corre, en paralelo, los checks
   seleccionados de cada dominio, el análisis DNSSEC, y una validación DNS
   del conjunto completo (misma metodología que "Preparación de datasets
   de dominios") — con una barra de progreso y un resumen en vivo que se
   va llenando en tiempo real.
6. Al terminar, se muestra el conteo de dominios analizados y la tabla de
   resultados (dominio × check), y quedan disponibles dos descargas:
   **JSON** (payload completo, con el detalle de cada check por dominio,
   siempre) y **PDF** (con el alcance elegido en el paso 4).

### Qué trae siempre el reporte PDF, qué es opcional, y qué NO trae

El reporte **no calcula ni compara nada sobre los dominios analizados** —
ni un total, ni un porcentaje, ni un semáforo. Siempre trae:

- **"Cómo leer este reporte"**, siempre al inicio del documento (no al
  final ni pegada a una tabla, para que no se pierda de vista) — y es
  **genérica**: el mismo contenido exacto sale siempre, sin importar qué
  dominios se hayan analizado ni qué haya dado cada resultado:
  - La leyenda de símbolos de resultado (misma tabla de la sección 7).
  - El **glosario** con la descripción de cada indicador seleccionado —
    nunca hay que adivinar qué mide una columna.
  - Las **limitaciones del sistema** (sección 10 de esta guía).
- La **tabla de resultados — dominio × indicador**, agrupada por categoría
  (los mismos grupos de la sección 8) y con las etiquetas legibles de cada
  indicador (no la clave interna). Si una categoría tiene más de 6
  indicadores seleccionados, se parte en varias tablas — así ninguna tabla
  se sale de la página ni se truncan columnas, sin importar cuántos checks
  se hayan elegido, ni cuántos dominios. Todo el bloque se imprime en hoja
  horizontal; el resto del documento sigue en hoja vertical.

Es **opcional** (checkbox del paso 4, desmarcado por defecto), sea el
análisis de 1 dominio o de varios:

- El **detalle por dominio** (estado DNS, DNSSEC, y resultado de cada check
  — para ese dominio en particular, no comparado con los demás). El JSON
  descargable siempre trae este detalle completo sin condensar,
  independientemente del checkbox; el PDF solo lo incluye si se marcó la
  opción, y en ese caso resume el detalle de los checks que no salieron
  "OK" para mantenerlo corto y legible.

Analizar, comparar o sacar conclusiones sobre el conjunto de dominios —
causas, tendencias, qué tan bien o mal está un sector — queda **fuera del
alcance del sistema**: es trabajo de quien usa el reporte, no del sistema.

## 10. Limitaciones

- No reemplaza auditorías técnicas especializadas
- Depende de disponibilidad de servicios externos
- Puede haber falsos positivos o negativos
- No mide seguridad interna del servidor

## 11. Uso recomendado

Se recomienda utilizar esta herramienta como:

- Diagnóstico inicial
- Insumo para análisis técnico más profundo
- Apoyo en investigación
- Base para decisiones de mejora

## 12. Invitación

Se invita a la comunidad técnica, instituciones y usuarios a:

- Probar la herramienta
- Analizar sus propios dominios
- Compartir resultados
- Contribuir con retroalimentación

## 13. Nota final

El módulo **MEDICIONES** es una herramienta en evolución.
Su valor radica no solo en los resultados individuales, sino en su
capacidad de construir una **visión regional de Internet en LAC**.
