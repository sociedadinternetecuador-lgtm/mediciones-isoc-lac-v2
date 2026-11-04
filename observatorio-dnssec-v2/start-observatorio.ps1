param(
    [switch]$Foreground,
    [switch]$ForceAuth,
    [switch]$Restart
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

$Project = if ($env:DNSVIZ_GCP_PROJECT) { $env:DNSVIZ_GCP_PROJECT } else { "observatorio-dnssec" }
$Zone    = if ($env:DNSVIZ_GCP_ZONE)    { $env:DNSVIZ_GCP_ZONE }    else { "us-central1-a" }
$VM      = if ($env:DNSVIZ_GCP_VM)      { $env:DNSVIZ_GCP_VM }      else { "dnsviz-lab" }
$Port    = if ($env:PORT)               { $env:PORT }               else { "8080" }
$CloudSdkConfig = if ($env:CLOUDSDK_CONFIG) {
    $env:CLOUDSDK_CONFIG
} else {
    Join-Path $env:USERPROFILE ".gcloud-observatorio-dnssec"
}
$env:CLOUDSDK_CONFIG = $CloudSdkConfig

function Step($Message) {
    Write-Host ""
    Write-Host $Message -ForegroundColor Cyan
}

function Warn($Message) {
    Write-Host $Message -ForegroundColor Yellow
}

function Ensure-Gcloud {
    if (-not (Get-Command gcloud -ErrorAction SilentlyContinue)) {
        throw "gcloud no esta instalado o no esta en PATH."
    }
    if (-not (Test-Path $CloudSdkConfig)) {
        New-Item -ItemType Directory -Force -Path $CloudSdkConfig | Out-Null
    }
    Write-Host "Config gcloud: $CloudSdkConfig" -ForegroundColor Gray
}

function Test-GcloudAuth {
    if ($ForceAuth) { return $false }
    gcloud auth print-access-token --quiet *> $null
    return $LASTEXITCODE -eq 0
}

function Ensure-GcloudAuth {
    Step "Verificando autenticacion de Google Cloud"
    if (Test-GcloudAuth) {
        Write-Host "Google Cloud autenticado." -ForegroundColor Green
        return
    }

    Warn "Google Cloud requiere reautenticacion. Se abrira el navegador."
    gcloud auth login
    if ($LASTEXITCODE -ne 0) {
        throw "No se completo gcloud auth login."
    }
}

function Ensure-GcloudProject {
    Step "Configurando proyecto $Project"
    gcloud config set project $Project | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "No se pudo configurar el proyecto $Project."
    }
}

function Test-WorkerSsh {
    Step "Probando SSH con worker DNSViz $VM"
    gcloud compute ssh $VM --zone $Zone --project $Project --command "echo dnsviz-worker-ok" --quiet
    if ($LASTEXITCODE -ne 0) {
        throw "No se pudo conectar por SSH a $VM en $Zone."
    }
}

function Get-Health {
    try {
        return Invoke-RestMethod "http://localhost:$Port/health" -TimeoutSec 5
    } catch {
        return $null
    }
}

function Start-Server {
    Step "Verificando servidor local"
    if ($Restart) {
        $listeners = Get-NetTCPConnection -LocalPort ([int]$Port) -State Listen -ErrorAction SilentlyContinue
        foreach ($listener in $listeners) {
            try {
                $proc = Get-Process -Id $listener.OwningProcess -ErrorAction Stop
                Warn "Deteniendo servidor anterior en puerto $Port (PID $($proc.Id))"
                Stop-Process -Id $proc.Id -Force
            } catch {
                Warn "No se pudo detener PID $($listener.OwningProcess): $($_.Exception.Message)"
            }
        }
        Start-Sleep -Seconds 1
    }

    $health = Get-Health
    if ($health -and $health.status -eq "ok") {
        Write-Host "Servidor ya activo: http://localhost:$Port" -ForegroundColor Green
        Write-Host "Worker: $($health.dnsviz_runner)" -ForegroundColor Gray
        return
    }

    Step "Iniciando servidor local en http://localhost:$Port"
    $env:DNSVIZ_REMOTE = "1"
    $env:DNSVIZ_GCP_PROJECT = $Project
    $env:DNSVIZ_GCP_ZONE = $Zone
    $env:DNSVIZ_GCP_VM = $VM
    $env:PORT = $Port

    if ($Foreground) {
        Write-Host "Servidor en primer plano. Ctrl+C para detener." -ForegroundColor Gray
        python backend\app.py
        return
    }

    $outLog = Join-Path (Get-Location) "local-server.log"
    $errLog = Join-Path (Get-Location) "local-server.err.log"
    $cmd = @"
`$env:DNSVIZ_REMOTE='1'
`$env:DNSVIZ_GCP_PROJECT='$Project'
`$env:DNSVIZ_GCP_ZONE='$Zone'
`$env:DNSVIZ_GCP_VM='$VM'
`$env:PORT='$Port'
python backend\app.py
"@

    $process = Start-Process powershell `
        -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $cmd `
        -WorkingDirectory (Get-Location) `
        -RedirectStandardOutput $outLog `
        -RedirectStandardError $errLog `
        -WindowStyle Hidden `
        -PassThru

    Start-Sleep -Seconds 3
    $health = Get-Health
    if ($health -and $health.status -eq "ok") {
        Write-Host "Servidor iniciado. PID: $($process.Id)" -ForegroundColor Green
        Write-Host "Web:    http://localhost:$Port" -ForegroundColor White
        Write-Host "Health: http://localhost:$Port/health" -ForegroundColor White
        Write-Host "Logs:   $outLog" -ForegroundColor Gray
        Write-Host "Errores:$errLog" -ForegroundColor Gray
        return
    }

    Warn "No se pudo confirmar /health aun. Revisa:"
    Warn $outLog
    Warn $errLog
}

Ensure-Gcloud
Ensure-GcloudAuth
Ensure-GcloudProject
Test-WorkerSsh
Start-Server
