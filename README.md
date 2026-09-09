# Proyecto Mediciones ISOC LAC

Portal web de Internet Society LAC. Interfaz web (`index.html`) + servidor
Node.js (`server.js`, `http` puro, sin frameworks) para medir y validar
dominios ccTLD de la región.

Arquitectura completa, decisiones y convenciones: **`docs/arquitectura.md`**.
Contexto rápido para trabajar en el repo: **`CLAUDE.md`**.

## Uso del servidor

No requiere paquetes externos salvo `dns-packet` (ya en `package.json`):

```
npm install
npm start
```

## Módulos del portal

- **Mediciones** — más de 30 verificaciones técnicas por dominio (MX, DKIM,
  RPKI, WHOIS, CAA, TLSA, cabeceras de seguridad, cadena TLS, etc.).
- **DNSSEC** — validación de cadena de firma, individual y por lote.
- **Observatorio** — histórico de análisis por lote con reportes
  descargables (HTML/CSV/JSON).
- **Preparación de datasets de dominios** — prepara y valida un dataset
  ccTLD (típicamente de OpenINTEL) antes de usarlo en los módulos
  anteriores. Flujo completo:

  ```
  Fuente → Carga → Normalización → Validación DNS → Resultados y descarga
  ```

  Réplica metodológica fiel de `validador/validar_dominios_isoc_lac.py`
  (script Python de referencia, no modificado — ver `docs/arquitectura.md`
  para el detalle de equivalencia verificada).

### Endpoints de análisis individual (módulo Mediciones)

- `GET /mx/:dominio` — registros MX del dominio.
- `GET /smtputf8/:dominio` — conecta vía Telnet/EHLO a los servidores MX
  (puertos 25 y 587) para detectar el anuncio de `SMTPUTF8`.
- `GET /dnssec-analysis?domain=:dominio` — análisis DNSSEC completo (cadena
  de firma, delegaciones).
- `GET /dkim/:dominio?selector=default` — busca un registro DKIM.
- `GET /rpki/:dominio` — valida las IPs del dominio contra RIPEstat.
- `GET /whois/:dominio` — datos de whois.com, con fallback a RDAP.

### Endpoints de Preparación de datasets

- `POST /dataset/normalize` — normaliza un archivo de dominios y clasifica
  por sufijo (Public Suffix List, sección ICANN).
- `POST /dataset/validate-dns` — inicia un job de validación DNS en segundo
  plano (preflight → primera pasada → reintento REVIEW).
- `GET /dataset/validate-dns/:jobId` / `/progress` (SSE) — estado y progreso.
- `GET /dataset/validate-dns/:jobId/download/:archivo` /
  `/download-zip` — descarga individual o paquete completo de la corrida
  terminada.

## Pruebas

```
npm test
```

Corre las suites rápidas (sin red, deterministas) de equivalencia con el
validador Python. Ver `docs/arquitectura.md` § Testing para las suites que
requieren red real (no están en `npm test`).
