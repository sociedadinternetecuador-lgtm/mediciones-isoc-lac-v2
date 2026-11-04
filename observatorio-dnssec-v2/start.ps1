# start.ps1 — Inicia el Observatorio DNSSEC v2
# Ejecutar desde C:\PROJECTS\OBSERVATORIOS\observatorio-dnssec-v2\

$VENV   = "$HOME\dnsviz-v2\venv"
$PYTHON = "$VENV\bin\python3"
$APP    = "backend\app.py"

Write-Host ""
Write-Host "  Observatorio DNSSEC v2" -ForegroundColor Cyan
Write-Host "  ISOC Ecuador · CORPECE" -ForegroundColor Gray
Write-Host ""

# Verificar venv
if (-not (Test-Path $PYTHON)) {
    Write-Host "  ERROR: venv no encontrado en $VENV" -ForegroundColor Red
    Write-Host "  Crea el venv con: python3 -m venv ~/dnsviz-v2/venv" -ForegroundColor Yellow
    exit 1
}

# Activar venv e instalar dependencias si hace falta
& "$VENV\bin\pip" install -q -r backend\requirements.txt

Write-Host "  Iniciando en http://localhost:8080 ..." -ForegroundColor Green
Write-Host "  Ctrl+C para detener" -ForegroundColor Gray
Write-Host ""

# Arrancar Flask
& $PYTHON $APP
