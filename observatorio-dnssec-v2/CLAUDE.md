# Observatorio DNSSEC v2 — reglas para trabajar en este subproyecto

Importado el 2026-11-04 desde `C:\PROJECTS\OBSERVA\observatorio-dnssec-v2` (proyecto
original, con historial y backup propio fuera de este repo — ver
`C:\PROJECTS\OBSERVA\observatorio-dnssec-v2_backup_20261104T193536Z.zip`). Desarrollado
por ISOC Ecuador, con apoyo de CORPECE. Hoy en producción en
`https://dnssec.corpece.org.ec` (infraestructura de Google Cloud, no `server1`).

Es un subproyecto completamente aislado, stack propio (Python/Flask), no Node. Se trajo
a este repo para darle control de versiones real (no lo tenía) y para evaluar, con el
código a la vista, si conviene fusionarlo con el motor DNSSEC de MEDICIONES — ver
`ANALISIS_PREVIO_Y_CONDICIONES_EJERCICIO_MULTISITIO.md` y los documentos de
`data/exercises/2026-10-28_dataset_6paises_cctld/` para el contexto de esa discusión.

## No negociable

- Nunca modificar nada fuera de `observatorio-dnssec-v2/` para trabajar en este
  subproyecto.
- No es parte del servicio productivo de MEDICIONES — no se despliega junto con
  `server.js`/`index.html`, no comparte proceso ni contenedor.
- A diferencia del resto de MEDICIONES, este subproyecto ejecuta el comando real
  `dnsviz` (CLI) — requiere `dnsviz`, `graphviz`, `python3-pygraphviz` instalados en el
  entorno donde corra, y puede necesitar IPv6 real (de ahí el nodo GCP dedicado
  `dnsviz-lab` que usa hoy — ver `setup-gcp-dnsviz-node.sh`).
- `backend/analyses/` y `backend/db.json` son datos de runtime, excluidos de git por
  `.gitignore` (mismo criterio que `data/` en el resto de MEDICIONES) — el backup
  completo con esos datos vive en el `.zip` mencionado arriba, no en este repo.
- No se integró todavía con el motor DNSSEC de MEDICIONES — eso es una decisión y un
  trabajo aparte, pendiente de evaluación.
