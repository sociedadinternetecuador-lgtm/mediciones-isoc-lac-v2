# Observatorio DNSSEC v2
Desarrollado por ISOC Ecuador · Con apoyo de CORPECE

## Inicio rápido

```bash
# 1. Activar venv (ya debe tener dnsviz instalado)
source ~/dnsviz-v2/venv/bin/activate

# 2. Instalar dependencias Flask
pip install -r backend/requirements.txt

# 3. Iniciar
python3 backend/app.py
```

Abrir: http://localhost:8080
Admin: http://localhost:8080/admin/login

Credenciales por defecto:
  Email:  admin@corpece.org.ec
  Clave:  changeme123

## Variables de entorno (opcional)
Copiar backend/.env.example → backend/.env y editar.

## Estructura
```
frontend/data/   ← JSONs de capas y configuración
backend/db.json  ← Base de datos (se crea automáticamente)
```
