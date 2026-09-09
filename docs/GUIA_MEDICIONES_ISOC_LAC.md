---
title: "MEDICIONES ISOC LAC"
subtitle: "Guía técnica del módulo de medición"
author: "Internet Society LatinoAmérica y el Caribe (LAC)"
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

El módulo tiene dos formas de uso, según la sub-pestaña que se elija dentro
de **Mediciones**: **Un dominio** (análisis individual, con historial y
mapa) y **Análisis comparativo** (lote de dominios, con reporte final
descargable — ver sección 9).

En ambos casos, el flujo es el mismo:

1. El usuario ingresa uno o varios dominios (o sube un archivo, en el caso
   del lote)
2. Selecciona las verificaciones a realizar
3. El sistema ejecuta consultas técnicas automatizadas
4. Se generan resultados estructurados

Cada verificación tiene un ícono de ayuda ("?") junto a su nombre con una
descripción de qué mide, y un bloque colapsable **"Glosario de términos"**
—visible en ambas sub-pestañas— con la lista completa. La sección 8 de esta
guía reproduce ese mismo glosario.

### Símbolos de resultado

Cada verificación devuelve uno de estos cuatro estados, mostrados siempre
con el mismo símbolo y color (en pantalla y en el PDF del reporte
comparativo, sección 9):

- **✓ verde — OK**: cumple / se detectó correctamente.
- **✗ rojo — No cumple**: no se encontró lo que el check busca.
- **⚠ gris — Error al verificar**: no se pudo comprobar (timeout, servicio
  externo caído, etc.) — no es lo mismo que "no cumple".
- **ℹ azul — Informativo**: hay un dato disponible, pero el check no evalúa
  "bien/mal" (por ejemplo, IPv6: tenerlo o no tenerlo no es en sí mismo un
  fallo).
- **— gris claro — Sin datos**: ese check no se ejecutó para ese dominio.

En pantalla, esta leyenda aparece siempre arriba de los resultados (en
ambas sub-pestañas). En el PDF del reporte comparativo aparece en la
sección **"Cómo leer este reporte"**, al inicio del documento — ver
sección 9.

## 8. Indicadores evaluados

Los indicadores se agrupan en seis categorías. Esta es la misma fuente de
verdad que usa la interfaz (tooltips y glosario en pantalla) — si un
indicador nuevo se agrega al sistema, esta lista debe actualizarse desde ahí.

### IP y Red

- **More IP Info** — Lista las direcciones IPv4/IPv6 del dominio y datos básicos de geolocalización/ASN cuando están disponibles.
- **Server Location** — Ubica geográficamente la primera IP resuelta del dominio. Es una aproximación basada en bases públicas de IP.
- **Server Info** — Resume IP, ASN, organización, red e ISP asociados al servidor observado.
- **IPv4** — Comprueba si el dominio publica registros A para conectividad IPv4.
- **IPv6** — Comprueba si el dominio publica registros AAAA para conectividad IPv6.
- **ASN** — Identifica el Sistema Autónomo que anuncia la IP principal del dominio.
- **Server Status** — Consulta el estado HTTP final del sitio después de redirecciones válidas.
- **Open Ports** — Prueba conectividad básica a puertos comunes. No sustituye un escaneo de seguridad formal.
- **Traceroute** — Obtiene una ruta aproximada de red usando un servicio externo de diagnóstico.
- **Redirect Chain** — Muestra la cadena HTTP/HTTPS desde el dominio inicial hasta el destino final.
- **Block Detection** — Compara respuestas de resolvers públicos para detectar posibles bloqueos o diferencias de resolución.

### DNS y Seguridad

- **DNS Records** — Consulta registros DNS principales: A, AAAA, MX, NS, TXT y CNAME.
- **TXT Records** — Lista registros TXT publicados en el dominio, usados para políticas y verificaciones.
- **DNS Server** — Lista los servidores NS autoritativos declarados para el dominio.
- **DNS Security Extensions** — Detecta señales básicas de DNSSEC mediante DS/DNSKEY y DoH.
- **RPKI** — Valida si la IP observada tiene cobertura RPKI válida para el prefijo y ASN de origen.
- **CAA** — Busca registros CAA, que indican qué autoridades certificadoras pueden emitir certificados para el dominio.
- **TLSA** — Busca registros TLSA/DANE para vincular certificados TLS con DNSSEC.

### Correo y Mensajería

- **Email Configuration** — Resume MX, SPF, DMARC y DKIM observado con selectores comunes.
- **MX** — Comprueba si el dominio tiene registros MX para recibir correo.
- **SMTPUTF8** — Detecta si los servidores MX anuncian soporte SMTPUTF8 para direcciones internacionalizadas.
- **DMARC** — Comprueba si existe política DMARC en _dmarc del dominio.
- **SPF** — Comprueba si el dominio publica una política SPF en registros TXT.
- **DKIM** — Busca una clave DKIM con el selector configurado o por defecto.

### Identidad y Cumplimiento

- **Whois Lookup** — Consulta fuentes WHOIS/RDAP para datos públicos del registrante, sujetos a redacción por privacidad.
- **Domain Info** — Consulta RDAP para registrar, estado y fechas relevantes del dominio.
- **Security.txt** — Comprueba si existe /.well-known/security.txt para reportar vulnerabilidades.

### Contenido y Experiencia

- **Site Features** — Detecta señales simples de formularios, búsqueda, video, analítica o comercio en el HTML final.
- **Cookies** — Lista cookies Set-Cookie observadas en la respuesta final del sitio.
- **Crawl Rules** — Lee robots.txt para reglas de rastreo y señales de uso automatizado.
- **Linked Pages** — Extrae enlaces encontrados en la página principal final.
- **Listed Pages** — Lee sitemap.xml y extrae URLs declaradas.
- **Social Tags** — Extrae metadatos sociales como Open Graph, Twitter cards, descripción y viewport.
- **Quality Metrics** — Consulta métricas de PageSpeed/Lighthouse cuando el servicio externo responde.
- **Archive History** — Consulta historial básico de capturas en Internet Archive.
- **Global Ranking** — Consulta ranking global aproximado del dominio en Tranco.
- **Malware & Phishing Detection** — Consulta URLHaus para señales públicas de malware o phishing asociadas al dominio.
- **Screenshot** — Genera o consulta una captura visual del sitio, si el servicio está disponible.

### Seguridad Web y TLS

- **HTTPS** — Comprueba si el sitio final responde por HTTPS correctamente.
- **HTTPS Redirect** — Comprueba si HTTP redirige hacia HTTPS.
- **HTTP Strict Transport Security** — Detecta Strict-Transport-Security, que fuerza uso futuro de HTTPS en navegadores compatibles.
- **Content Security Policy** — Detecta Content-Security-Policy, política que limita fuentes de scripts, estilos, imágenes y conexiones.
- **X-Frame-Options** — Detecta X-Frame-Options, protección clásica contra clickjacking.
- **X-Content-Type-Options** — Detecta X-Content-Type-Options, que evita interpretación MIME insegura.
- **Referrer-Policy** — Detecta Referrer-Policy, que controla cuánta información de origen se envía al navegar.
- **Permissions-Policy** — Detecta Permissions-Policy, que restringe APIs del navegador como cámara, micrófono o geolocalización.
- **X-XSS-Protection** — Detecta X-XSS-Protection. Es una cabecera antigua y hoy menos relevante en navegadores modernos.
- **Headers** — Muestra las cabeceras HTTP observadas en la respuesta final.
- **Server Header** — Muestra el valor de Server, que puede revelar tecnología o estar oculto por el proveedor.
- **HTTP Compression** — Detecta si la respuesta usa compresión HTTP como gzip, br o deflate.
- **OCSP Stapling** — Detecta OCSP Stapling en la conexión TLS, usado para estado de revocación del certificado.
- **TLS Version** — Muestra la versión TLS negociada con el servidor.
- **Key Exchange** — Muestra información de intercambio de claves de la sesión TLS.
- **SSL Chain Info** — Lista la cadena de certificados presentada por el servidor.
- **TLS Cipher Suites** — Prueba suites de cifrado disponibles en TLS 1.2/1.3.
- **TLS Security Config** — Resume configuración TLS observable y posibles debilidades.
- **TLS Handshake Simulation** — Simula handshakes TLS con distintos perfiles para observar compatibilidad.
- **HTTP Security Features** — Agrupa cabeceras de seguridad HTTP principales.
- **Firewall Detection** — Detecta señales de WAF/CDN como Cloudflare, Akamai, Sucuri o ModSecurity.

## 9. Análisis comparativo (lote de dominios)

Sub-pestaña de **Mediciones**, pensada para analizar entre 20 y 25 dominios
de una sola vez y obtener un reporte final descargable — por ejemplo, todos
los dominios de instituciones públicas de un país, o todos los capítulos de
un mismo sector.

### Cómo usarla

1. Ingresar la lista de dominios: pegando texto (uno por línea o separados
   por coma) o subiendo un archivo `.txt`/`.csv`.
2. Seleccionar las verificaciones a realizar (mismo árbol de indicadores de
   la sección 8, con el mismo botón de ayuda en cada uno).
3. Elegir la velocidad de análisis (conservadora, recomendada o rápida —
   controla cuántos dominios se procesan en simultáneo).
4. Presionar **Analizar**. El sistema corre, en paralelo, los checks
   seleccionados de cada dominio, el análisis DNSSEC, y una validación DNS
   del lote completo (misma metodología que "Preparación de datasets de
   dominios") — con una barra de progreso en tiempo real.
5. Al terminar, se muestra un resumen (dominios analizados, adopción DNSSEC
   del lote, dominios con DNS válido) y una tabla comparativa dominio ×
   check, y quedan disponibles dos descargas: **JSON** (payload completo,
   con el detalle de cada check por dominio) y **PDF** (reporte ejecutivo).

### Qué trae siempre el reporte PDF

- Una sección **"Cómo leer este reporte"**, siempre al inicio del
  documento (no al final ni pegada a una tabla, para que no se pierda de
  vista): la leyenda de símbolos de resultado (misma tabla de la sección 7)
  y el **glosario** con la descripción de cada indicador seleccionado —
  nunca hay que adivinar qué mide una columna.
- Un resumen de validación DNS, adopción DNSSEC agregada del lote, y el
  resumen acumulado por check.
- La **tabla comparativa dominio × check**, agrupada por categoría (los
  mismos seis grupos de la sección 8) y con las etiquetas legibles de cada
  indicador (no la clave interna). Si una categoría tiene más de 6
  indicadores seleccionados, se parte en varias tablas — así ninguna tabla
  se sale de la página ni se truncan columnas, sin importar cuántos checks
  se hayan elegido. Todo el bloque se imprime en hoja horizontal; el resto
  del documento sigue en hoja vertical.
- El detalle por dominio (estado DNS, DNSSEC, y resultado de cada check).

El JSON siempre trae el detalle completo sin condensar; el PDF resume el
detalle de los checks que no salieron "OK" para mantenerlo corto y legible.

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
