# run.ps1 — Levanta Observatorio DNSSEC v2
# Ejecutar: powershell -ExecutionPolicy Bypass -File run.ps1
# Desde:    C:\PROJECTS\OBSERVATORIOS\observatorio-dnssec-v2\

$PROJECT_WSL = "/mnt/c/PROJECTS/OBSERVATORIOS/observatorio-dnssec-v2"
$VENV_WSL    = "~/dnsviz-v2/venv"

Write-Host ""
Write-Host "  Observatorio DNSSEC v2 -- ISOC Ecuador - CORPECE" -ForegroundColor Cyan
Write-Host ""

# Paso 1: Crear venv si no existe
Write-Host "  [1/3] Preparando venv..." -ForegroundColor Gray
wsl -e bash -c "if [ ! -f ~/dnsviz-v2/venv/bin/activate ]; then python3 -m venv ~/dnsviz-v2/venv && echo 'Venv creado'; fi"
Write-Host "  [1/3] Venv OK" -ForegroundColor Green

# Paso 2: Instalar Flask en el venv
Write-Host "  [2/3] Instalando Flask..." -ForegroundColor Gray
wsl -e bash -c "source ~/dnsviz-v2/venv/bin/activate && pip install -q flask"
Write-Host "  [2/3] Flask OK" -ForegroundColor Green

# Paso 3: Levantar Flask
Write-Host "  [3/3] Iniciando servidor..." -ForegroundColor Green
Write-Host ""
Write-Host "    http://localhost:8080              <- publico" -ForegroundColor White
Write-Host "    http://localhost:8080/admin/login  <- admin" -ForegroundColor White
Write-Host "    Credenciales: admin@corpece.org.ec / changeme123" -ForegroundColor Gray
Write-Host ""
Write-Host "  Ctrl+C para detener" -ForegroundColor Gray
Write-Host ""

wsl -e bash -c "source ~/dnsviz-v2/venv/bin/activate && cd /mnt/c/PROJECTS/OBSERVATORIOS/observatorio-dnssec-v2 && python3 backend/app.py"