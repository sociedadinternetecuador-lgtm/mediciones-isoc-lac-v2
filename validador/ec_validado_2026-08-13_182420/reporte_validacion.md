# Reporte de validación DNS — .ec

## Identificación

- Proyecto: **Mediciones LAC - Internet Society**
- Validador: **v6.1**
- Estado de ejecución: **COMPLETED_WITH_REVIEW**
- Fuente declarada: **OpenINTEL**
- Archivo de entrada: `ec_openintel_normalizado.txt`
- Fecha de la fuente: **no indicada**
- ccTLD: **.ec**
- Fecha de procesamiento: **2026-08-13 18:42:18 -0500**
- SHA-256 archivo fuente: `932ab032f513ffaddf6595cab1b9413ed0c88d3ca246b0850c1e53b594b79e5c`
- SHA-256 lista normalizada: `932ab032f513ffaddf6595cab1b9413ed0c88d3ca246b0850c1e53b594b79e5c`

## Public Suffix List

- Clasificación de sufijos: **Public Suffix List, sección ICANN**.
- Origen en esta ejecución: **downloaded**.
- Archivo utilizado: `C:\Users\cvera\.cache\mediciones_lac\public_suffix_list.dat`
- SHA-256 PSL: `084a5674d77c1d14900b16da5fc8afee9765af2f00a638552a8c7aa18f44ae81`

## Nota sobre la fuente OpenINTEL

Las listas ccTLD de OpenINTEL se construyen a partir de nombres observados en Certificate Transparency (CT), procesados para extraer dominios registrables. Constituyen una fuente de descubrimiento amplia, pero no un archivo oficial de zona ni un censo completo del ccTLD. La validación DNS de esta herramienta existe precisamente para comprobar qué nombres de la lista pueden utilizarse en la ejecución de Mediciones LAC.

## Normalización

- Líneas originales: **34,785**
- Líneas vacías: **0**
- Duplicados eliminados: **0**
- Rechazados por estructura/ccTLD: **0**
- Dominios normalizados: **34,785**

## Preflight de resolvers

- Cloudflare `1.1.1.1`: **NOERROR**
- Google `8.8.8.8`: **NOERROR**

El lote DNS solo se inicia cuando ambos resolvers superan el preflight, salvo que el usuario use explícitamente `--skip-preflight`.

## Resultado final

| Estado | Dominios | Porcentaje | Significado |
|---|---:|---:|---|
| VALID | 33,892 | 97.43% | Existencia DNS confirmada. Pasa al dataset de Mediciones LAC. |
| NXDOMAIN | 414 | 1.19% | Inexistencia confirmada por ambos resolvers. Se excluye del dataset operativo. |
| REVIEW | 479 | 1.38% | Resultado no concluyente. No se descarta automáticamente. |
| **TOTAL** | **34,785** | **100.00%** | |

## Reintento automático de REVIEW

- REVIEW después de la primera pasada: **480**
- Se resolvieron como VALID: **1**
- Se resolvieron como NXDOMAIN: **0**
- Permanecieron REVIEW: **479**

El segundo intento se aplica solamente a los dominios REVIEW para reducir falsos pendientes causados por timeouts o fallos transitorios.

## Tipos de REVIEW final

- **REVIEW_SERVFAIL**: 369
- **REVIEW_CONFLICT**: 104
- **REVIEW_TIMEOUT**: 5
- **REVIEW_MIXED_TIMEOUT_SERVFAIL**: 1

## Metodología de validación

1. **Normalización.** Se limpian las entradas, se convierten a minúsculas, se elimina el punto final, se aplica IDNA/Punycode cuando corresponde, se eliminan duplicados y se valida sintaxis y pertenencia al ccTLD.
2. **Clasificación PSL.** Cada nombre se clasifica usando la Public Suffix List, sección ICANN, evitando reglas manuales por país.
3. **Preflight.** Antes del lote se comprueba que Cloudflare (`1.1.1.1`) y Google (`8.8.8.8`) puedan responder una consulta `. NS`.
4. **Consulta NS.** Todos los dominios se consultan por NS contra ambos resolvers.
5. **Consulta SOA de respaldo.** Si NS es inconcluso, se consulta SOA contra ambos resolvers.
6. **VALID.** Se asigna cuando al menos un resolver devuelve NOERROR en NS o SOA.
7. **NXDOMAIN.** Se excluye automáticamente solo cuando ambos resolvers confirman NXDOMAIN para el mismo tipo de consulta.
8. **REVIEW.** SERVFAIL, TIMEOUT, REFUSED, ERROR o respuestas no concluyentes no se interpretan como inexistencia.
9. **Segundo intento.** Los REVIEW de la primera pasada se vuelven a consultar automáticamente salvo que se desactive esta opción.
10. **DNSSEC.** Las consultas usan CD=1 para reducir falsos negativos causados por validación DNSSEC defectuosa.
11. **Transporte.** Se usa UDP inicialmente y TCP cuando la respuesta está truncada (TC=1).
12. **Sin sesgo por mediciones posteriores.** A, AAAA, IPv6, MX, DNSSEC, HTTPS o disponibilidad web no se utilizan como criterios de exclusión.

> El principio es conservador: solo se excluye automáticamente un nombre cuya inexistencia DNS ha sido confirmada por ambos resolvers.

## Discrepancias entre resolvers

Se detectaron **391** dominios con respuestas diferentes entre Cloudflare y Google en al menos una consulta final.
El detalle está en `discrepancias_resolvers.csv`.

## Resultado por sufijo

| Sufijo | Total | VALID | NXDOMAIN | REVIEW | VALID % |
|---|---:|---:|---:|---:|---:|
| .com.ec | 15,660 | 15,266 | 176 | 218 | 97.48% |
| .ec | 14,392 | 13,972 | 201 | 219 | 97.08% |
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

## Control de integridad

- Resultado global: **PASSED**
- `normalized_equals_result_count`: **OK**
- `status_partition_equals_result_count`: **OK**
- `all_normalized_domains_have_result`: **OK**
- `result_domains_are_unique`: **OK**
- `suffix_totals_equal_result_count`: **OK**

## Tiempos de ejecución

- Normalización + PSL: **0.90 s**
- Preflight: **0.12 s**
- Primera pasada DNS: **15 min 12.7 s**
- Reintento REVIEW: **2 min 42.2 s**
- Validación DNS total: **17 min 56.9 s**
- Generación de archivos/reporte: **0.30 s**
- Tiempo total: **17 min 58.2 s**

## Archivos generados

- `validacion_dns.csv`: CSV maestro con primera pasada, estado final y respuestas DNS.
- `dominios_normalizados.txt`: universo después de normalización.
- `dominios_validos.txt`: dataset operativo que pasa a Mediciones LAC.
- `dominios_nxdomain.txt`: nombres excluidos por inexistencia confirmada.
- `dominios_revisar.txt`: casos finales no concluyentes.
- `review_por_tipo/`: REVIEW separados por causa.
- `discrepancias_resolvers.csv`: respuestas distintas entre Cloudflare y Google.
- `resumen_sufijos.csv`: resultados por sufijo.
- `listas_por_sufijo/`: todos los dominios VALID separados por sufijo.
- `metadata.json`: parámetros, hashes, metodología, tiempos e integridad.

## Uso en Mediciones LAC

El dataset operativo está formado por `dominios_validos.txt` o por las listas VALID de `listas_por_sufijo/`.
Los dominios REVIEW permanecen separados y no deben tratarse como inexistentes sin revisión adicional.
