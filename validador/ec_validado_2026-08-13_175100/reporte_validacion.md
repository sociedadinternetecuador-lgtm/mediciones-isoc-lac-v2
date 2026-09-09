# Reporte de validación DNS — .ec

## Identificación

- Proyecto: **Mediciones LAC - Internet Society**
- Fuente declarada: **OpenINTEL**
- Archivo de entrada: `ec_openintel_normalizado.txt`
- Fecha de la fuente: **no indicada**
- ccTLD: **.ec**
- Fecha de procesamiento: **2026-08-13 18:06:36 -0500**
- SHA-256 archivo fuente: `932ab032f513ffaddf6595cab1b9413ed0c88d3ca246b0850c1e53b594b79e5c`
- SHA-256 lista normalizada: `932ab032f513ffaddf6595cab1b9413ed0c88d3ca246b0850c1e53b594b79e5c`

## Normalización

- Líneas originales: **34,785**
- Líneas vacías: **0**
- Duplicados eliminados: **0**
- Rechazados por estructura/ccTLD: **0**
- Dominios normalizados: **34,785**

## Resultado de validación

| Estado | Dominios | Porcentaje | Significado |
|---|---:|---:|---|
| VALID | 33,888 | 97.42% | Existencia DNS confirmada. Pasa al dataset de Mediciones LAC. |
| NXDOMAIN | 414 | 1.19% | Inexistencia confirmada por ambos resolvers. Se excluye del dataset operativo. |
| REVIEW | 483 | 1.39% | Resultado no concluyente. Debe reintentarse o revisarse; no se descarta automáticamente. |
| **TOTAL** | **34,785** | **100.00%** | |

### Qué significa VALID

`VALID` significa únicamente que el nombre existe en DNS según el criterio del validador. 
No implica que tenga sitio web, IPv6, DNSSEC, MX, HTTPS u otro servicio. Esas características deben medirse posteriormente.

### Qué significa NXDOMAIN

`NXDOMAIN` se asigna únicamente cuando **Cloudflare y Google** confirman NXDOMAIN para una misma consulta (NS o SOA).

### Qué significa REVIEW

`REVIEW` agrupa casos no concluyentes como SERVFAIL, TIMEOUT, REFUSED, ERROR o combinaciones que no permiten confirmar existencia ni inexistencia.
Estos nombres no deben tratarse como inexistentes.

## Resolvers y política aplicada

- Cloudflare: `1.1.1.1`
- Google: `8.8.8.8`
- Timeout: **2.5 s**
- Reintentos por consulta fallida: **1**
- Concurrencia: **20 workers**
- Se consulta **NS a ambos resolvers para todos los dominios**.
- SOA se consulta a ambos resolvers solo cuando NS no permite clasificar el dominio.
- Las consultas usan `CD=1` (Checking Disabled) para reducir falsos negativos causados por DNSSEC roto.
- Si UDP llega truncado, se usa TCP automáticamente.

## Discrepancias entre resolvers

Se detectaron **202** dominios con respuestas diferentes entre Cloudflare y Google en al menos una consulta realizada.
El CSV maestro conserva ambas respuestas para auditoría.

## Resultado por sufijo

| Sufijo | Total | VALID | NXDOMAIN | REVIEW | VALID % |
|---|---:|---:|---:|---:|---:|
| .com.ec | 15,660 | 15,265 | 176 | 219 | 97.48% |
| .ec | 14,392 | 13,969 | 201 | 222 | 97.06% |
| .gob.ec | 1,961 | 1,939 | 13 | 9 | 98.88% |
| .edu.ec | 1,595 | 1,555 | 13 | 27 | 97.49% |
| .org.ec | 395 | 388 | 3 | 4 | 98.23% |
| .fin.ec | 359 | 357 | 2 | 0 | 99.44% |
| .net.ec | 185 | 182 | 2 | 1 | 98.38% |
| .med.ec | 101 | 101 | 0 | 0 | 100.00% |
| .info.ec | 27 | 27 | 0 | 0 | 100.00% |
| .mil.ec | 23 | 22 | 1 | 0 | 95.65% |
| .uio.ec | 15 | 15 | 0 | 0 | 100.00% |
| .pro.ec | 12 | 11 | 0 | 1 | 91.67% |
| .tech.ec | 12 | 12 | 0 | 0 | 100.00% |
| .k12.ec | 11 | 8 | 3 | 0 | 72.73% |
| .cue.ec | 6 | 6 | 0 | 0 | 100.00% |
| .adm.ec | 4 | 4 | 0 | 0 | 100.00% |
| .gye.ec | 4 | 4 | 0 | 0 | 100.00% |
| .abg.ec | 3 | 3 | 0 | 0 | 100.00% |
| .gal.ec | 3 | 3 | 0 | 0 | 100.00% |
| .pub.ec | 3 | 3 | 0 | 0 | 100.00% |
| .doc.ec | 2 | 2 | 0 | 0 | 100.00% |
| .vet.ec | 2 | 2 | 0 | 0 | 100.00% |
| .art.ec | 1 | 1 | 0 | 0 | 100.00% |
| .bar.ec | 1 | 1 | 0 | 0 | 100.00% |
| .cpa.ec | 1 | 1 | 0 | 0 | 100.00% |
| .disco.ec | 1 | 1 | 0 | 0 | 100.00% |
| .fot.ec | 1 | 1 | 0 | 0 | 100.00% |
| .gov.ec | 1 | 1 | 0 | 0 | 100.00% |
| .prof.ec | 1 | 1 | 0 | 0 | 100.00% |
| .rio.ec | 1 | 1 | 0 | 0 | 100.00% |
| .rrpp.ec | 1 | 1 | 0 | 0 | 100.00% |
| .tur.ec | 1 | 1 | 0 | 0 | 100.00% |

## Principales patrones de REVIEW

- **353** — `NS[cloudflare=SERVFAIL, google=SERVFAIL] ; SOA[cloudflare=SERVFAIL, google=SERVFAIL]`
- **101** — `NS[cloudflare=TIMEOUT, google=SERVFAIL] ; SOA[cloudflare=SERVFAIL, google=SERVFAIL]`
- **12** — `NS[cloudflare=TIMEOUT, google=TIMEOUT] ; SOA[cloudflare=SERVFAIL, google=TIMEOUT]`
- **5** — `NS[cloudflare=TIMEOUT, google=TIMEOUT] ; SOA[cloudflare=TIMEOUT, google=TIMEOUT]`
- **5** — `NS[cloudflare=SERVFAIL, google=TIMEOUT] ; SOA[cloudflare=SERVFAIL, google=SERVFAIL]`
- **3** — `NS[cloudflare=SERVFAIL, google=SERVFAIL] ; SOA[cloudflare=TIMEOUT, google=SERVFAIL]`
- **2** — `NS[cloudflare=TIMEOUT, google=TIMEOUT] ; SOA[cloudflare=SERVFAIL, google=SERVFAIL]`
- **1** — `NS[cloudflare=SERVFAIL, google=TIMEOUT] ; SOA[cloudflare=SERVFAIL, google=TIMEOUT]`
- **1** — `NS[cloudflare=TIMEOUT, google=SERVFAIL] ; SOA[cloudflare=TIMEOUT, google=SERVFAIL]`

## Archivos generados

- `validacion_dns.csv`: archivo maestro; una fila por dominio y respuestas separadas de ambos resolvers.
- `dominios_normalizados.txt`: lista después de limpieza, deduplicación y validación estructural.
- `dominios_validos.txt`: dominios que pasan al universo operativo de Mediciones LAC.
- `dominios_nxdomain.txt`: nombres cuya inexistencia DNS fue confirmada.
- `dominios_revisar.txt`: casos no concluyentes que requieren reintento o revisión.
- `resumen_sufijos.csv`: conteos y porcentajes por sufijo.
- `listas_por_sufijo/`: listas completas de dominios VALID separadas por sufijo.
- `metadata.json`: parámetros, hashes y metadatos reproducibles de la ejecución.

## Uso en Mediciones LAC

El dataset operativo inicial está formado por `dominios_validos.txt` o por los archivos VALID de `listas_por_sufijo/`.
Los dominios `REVIEW` deben reintentarse antes de decidir su inclusión o exclusión definitiva.
