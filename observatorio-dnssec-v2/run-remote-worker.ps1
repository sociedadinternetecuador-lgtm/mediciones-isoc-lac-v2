# Levanta la web local usando la VM dual-stack de Google Cloud como worker DNSViz.
# Ejecutar desde: C:\PROJECTS\OBSERVA\observatorio-dnssec-v2

$ErrorActionPreference = "Stop"

$env:DNSVIZ_REMOTE = "1"
$env:DNSVIZ_GCP_PROJECT = if ($env:DNSVIZ_GCP_PROJECT) { $env:DNSVIZ_GCP_PROJECT } else { "observatorio-dnssec" }
$env:DNSVIZ_GCP_ZONE = if ($env:DNSVIZ_GCP_ZONE) { $env:DNSVIZ_GCP_ZONE } else { "us-central1-a" }
$env:DNSVIZ_GCP_VM = if ($env:DNSVIZ_GCP_VM) { $env:DNSVIZ_GCP_VM } else { "dnsviz-lab" }

Write-Host ""
Write-Host "  Observatorio DNSSEC v2" -ForegroundColor Cyan
Write-Host "  Worker DNSViz remoto: $env:DNSVIZ_GCP_VM ($env:DNSVIZ_GCP_PROJECT / $env:DNSVIZ_GCP_ZONE)" -ForegroundColor Gray
Write-Host ""
Write-Host "  Web:    http://localhost:8080" -ForegroundColor White
Write-Host "  Health: http://localhost:8080/health" -ForegroundColor White
Write-Host ""
Write-Host "  Ctrl+C para detener" -ForegroundColor Gray
Write-Host ""

python backend\app.py
