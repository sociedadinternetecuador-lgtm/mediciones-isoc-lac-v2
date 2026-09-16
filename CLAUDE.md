# Contexto del proyecto — Mediciones ISOC LAC

> Portal web de Internet Society LAC. Este archivo da contexto rápido para
> retomar trabajo en este directorio. Arquitectura completa en
> `docs/arquitectura.md` — léelo antes de tocar código si no conoces el
> proyecto.

## Qué hay que saber antes de tocar nada

1. **`validador/validar_dominios_isoc_lac.py` es la referencia metodológica
   y NO se modifica.** Todo el módulo "Preparación de datasets de dominios"
   existe para replicar su comportamiento exacto en JS, no para mejorarlo.
   Si Python y JS difieren, se investiga la causa en el código Python real
   (no se adivina) y se replica — nunca se corrige "porque parece mejor".

2. **Normalización y Validación DNS están cerradas metodológicamente.** No
   cambiar: algoritmo de normalización, IDNA, clasificación PSL, criterios
   VALID/NXDOMAIN/REVIEW, orden de evaluación de `review_subtype`,
   resolvers, timeout, retries, workers, review_wait, CD. Solo tocar si se
   demuestra un bug real y reproducible respecto al validador Python.

3. **Sin frameworks nuevos.** Ni Express, ni librerías de ZIP/test/etc.
   Núcleo de Node + `dns-packet` + `nodemailer` (únicas dos dependencias
   externas — `nodemailer` es una excepción deliberada: envío de
   contraseñas es sensible a bugs sutiles de STARTTLS/codificación como
   para implementarlo a mano).

4. **Despliegue**: `server1:8700` (Tailscale, home-lab), Docker, y también
   público en `https://mediciones.isoc.org.ec` vía Cloudflare Tunnel. Ver
   comando exacto en `docs/arquitectura.md` § "Cómo desplegar".

5. **Sin base de datos ni persistencia de jobs.** Los jobs de Validación DNS
   y Observatorio viven en memoria (`Map`) — se pierden si el proceso
   reinicia. Decisión aceptada, no un bug. (Blog/Eventos/Materiales SÍ
   persisten en disco — `data/content/*.json` — no son jobs efímeros.)

6. **`.env` nunca se sube por el mismo canal que el código** (tar+scp del
   deploy). Vive solo en `server1:~/projects/MEDICIONES/.env`, fuera de
   `.dockerignore`/`.gitignore`. Contiene credenciales del super_admin y del
   relay SMTP (Brevo) — ver `.env.example` para el esquema completo.

7. **Brevo/Sendinblue: usar `smtp-relay.sendinblue.com`, NO
   `smtp-relay.brevo.com`.** Este último falla con error de certificado TLS
   (verificado contra el relay real) — mismo hallazgo que en otros
   proyectos CORPECE que usan la misma cuenta.

8. **Logos institucionales — ya están en el proyecto, no pedirlos ni
   buscarlos en Descargas.**
   - `public/assets/ISOC_Logo_Dark-RGB.png` — isotipo + wordmark oscuro de
     Internet Society (horizontal, fondo transparente).
   - `public/assets/mediciones_grupo_trabajo.jpeg` — logo del Grupo de
     Trabajo de Mediciones de Internet Society (cuadrado 1024×1024, fondo
     azul, con el ícono ISOC + texto "Grupo de Trabajo de Mediciones de
     Internet" + ícono de barras, todo incrustado en la imagen). Es el
     archivo que el usuario compartió por chat (originalmente en
     `~/Downloads/mediciones_logo.jpeg`, 2026-09-16) — ya copiado acá,
     usar esta ruta siempre que se necesite este logo (portada del PDF de
     reportes, cabecera de `index.html`, etc.), no volver a pedirlo.

## Estado actual (2026-08-14)

Flujo de Preparación de datasets implementado y cerrado:

```
Fuente → Carga → Normalización → Validación DNS → Resultados y descarga
   ✓         ✓          ✓               ✓                  ✓
```

Pendiente explícito (no implementar sin que se pida): **generación de PDF**.

Portal ampliado con Blog, Eventos y Administración:
- Pestañas públicas **BLOG** y **EVENTOS** (antes vivían embebidas en
  Inicio como listas hardcodeadas vacías — ahora son pestañas propias que
  leen de `GET /content/blog` y `/content/events`, solo items publicados).
  La sección "Información" de Inicio (material de capacitación) también
  pasó de un array hardcodeado a `GET /content/materials`.
- Se eliminó la sección "Listas de ccTLD" de Inicio (redundante: reemplazada
  íntegramente por "Preparación de datasets de dominios").
- **`/admin`**: panel de administración con dos roles — `super_admin` (una
  sola cuenta, credenciales en `.env`, puede crear/borrar cuentas `admin`)
  y `admin` (creadas por el super_admin, gestionan Blog/Eventos/Materiales
  pero no usuarios). Contraseñas siempre generadas por el sistema (scrypt)
  y enviadas por correo — nunca se escriben a mano en el panel. Recuperación
  de contraseña vía `/admin/api/forgot-password` (respuesta genérica
  siempre, para no permitir enumerar usuarios).
- Ícono de candado discreto junto a "Acerca de" en Inicio enlaza a `/admin`.

## Comandos esenciales

```bash
# Tests rápidos (CI-safe, sin red — incluye contentStore, adminAuth/sesión/rate-limit, y visibilidad público/admin de extremo a extremo)
npm test

# Generar el hash de una contraseña nueva para ADMIN_PASSWORD_HASH
node scripts/hash-admin-password.js "clave-elegida"

# Tests con red real (manuales, no están en npm test)
node test/rawDns.live.smoke.test.js
node test/dnsDownloads.noDnsCalls.test.js
node test/downloads.integrityGuard.test.js
node test/dnsValidation.live.pythonCompare.js <domains.txt> <validacion_dns.csv de Python>

# Levantar local
PORT=3500 node server.js

# Desplegar a server1 (.env NUNCA va en este tar — vive solo en server1)
# 2026-09-16: la lista de directorios a mano (index.html admin.html
# server.js logic routes test ...) llevaba tiempo incompleta — faltaban
# aggregate/, config/, services/ (los tres son dependencias reales de
# server.js vía require(), no opcionales) y, por separado, public/ entero
# (incluye public/i18n.js). Cada gap se coló en silencio: config/services
# quedaron con código DNSSEC ya eliminado localmente (sin fallar ningún
# test — el código muerto no cambia comportamiento observable), y
# public/i18n.js quedó sin las claves del rediseño de Inicio del
# 2026-09-13 — eso sí rompió la UI en vivo (claves crudas en pantalla,
# ej. "inicio.hero.lead"), detectado por el usuario en producción, no por
# ningún test. Cambiado a `git ls-files`: despliega exactamente los
# archivos trackeados en git, así que agregar un directorio nuevo nunca
# vuelve a exigir acordarse de tocar este comando. Requiere que TODO
# archivo de producción esté con `git add` (si algo nuevo no aparece tras
# desplegar, lo primero a revisar es si quedó sin trackear).
git ls-files -z | tar --null -T - -cf - | ssh server1 "tar -xf - -C ~/projects/MEDICIONES"
ssh server1 "cd ~/projects/MEDICIONES && docker compose up -d --build"
ssh server1 "docker exec mediciones npm test"
```

## Convención de testing en este proyecto

- Sin framework de test (no jest/mocha). Scripts planos con `assert` de Node,
  ejecutables directo con `node test/archivo.js`.
- Para verificar equivalencia con Python: capturar valores reales
  ejecutando el validador (`importlib.util.spec_from_file_location` +
  registrar en `sys.modules` antes de `exec_module`, necesario por
  `@dataclass` + `from __future__ import annotations`), nunca asumir el
  comportamiento por lectura del código.
- Para probar "no hay nuevas consultas DNS": instrumentar (spy/contador)
  la función real (`dnsQuery` en `rawDns.adapter.js`), no medir tiempos de
  respuesta como evidencia principal.
- Para probar salvaguardas (integridad, etc.): ejercitarlas con datos
  fabricados a mano llamando directo a la función, no solo confiar en que
  "nunca debería pasar".

## Regresión obligatoria tras cualquier cambio de frontend

Playwright headless, desktop (1280px), tablet (768px) y mobile (375px),
sobre las 7 pestañas del portal (Inicio, Preparación, Mediciones, DNSSEC,
Observatorio, Blog, Eventos) y sobre `/admin`: cero overflow horizontal,
cero errores de consola. Los scripts de prueba usados durante el
desarrollo quedaron en el scratchpad de sesión, no en el repo — si hace
falta reproducir el patrón, ver `docs/arquitectura.md`.

## Archivos que NO están conectados (código muerto conocido)

`routes/dnssec.routes.js` usa Express y no lo requiere nadie — `server.js`
reimplementa esa lógica inline. No confundir al buscar dónde editar
`/dnssec-analysis`.
