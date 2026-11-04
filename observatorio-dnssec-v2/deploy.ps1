$ErrorActionPreference = "Stop"

$PROJECT_ID = "observatorio-dnssec"
$REGION     = "us-central1"
$SERVICE    = "observatorio-dnssec"

$IMAGE_BASE = "gcr.io/$PROJECT_ID/$SERVICE"
$TAG        = Get-Date -Format "yyyyMMdd-HHmmss"
$IMAGE      = "$IMAGE_BASE`:$TAG"

$APP_BASE_URL = "https://observatorio-dnssec-548575814841.us-central1.run.app"

# Variables críticas de producción.
# Mantén estos valores ESTABLES entre deploys para no invalidar sesiones ni perder acceso admin.
# Recomendado: define estos valores como variables de entorno de Windows o edítalos aquí antes de desplegar.
$SECRET_KEY  = if ($env:DNSSEC_SECRET_KEY)  { $env:DNSSEC_SECRET_KEY }  else { "CAMBIA_ESTA_CLAVE_LARGA_Y_FIJA" }
$ADMIN_EMAIL = if ($env:DNSSEC_ADMIN_EMAIL) { $env:DNSSEC_ADMIN_EMAIL } else { "admin@corpece.org.ec" }
$ADMIN_PASS  = if ($env:DNSSEC_ADMIN_PASS)  { $env:DNSSEC_ADMIN_PASS }  else { "CAMBIA_ESTA_CONTRASENA_ADMIN" }

function Step($Message) {
    Write-Host ""
    Write-Host $Message -ForegroundColor Cyan
}

function Ok($Message) {
    Write-Host $Message -ForegroundColor Green
}

function Warn($Message) {
    Write-Host $Message -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Deploy Observatorio DNSSEC a Google Cloud Run" -ForegroundColor Cyan
Write-Host "Proyecto: $PROJECT_ID"
Write-Host "Region:   $REGION"
Write-Host "Servicio: $SERVICE"
Write-Host "Imagen:   $IMAGE"
Write-Host ""

try {
    if ($SECRET_KEY -eq "CAMBIA_ESTA_CLAVE_LARGA_Y_FIJA" -or $ADMIN_PASS -eq "CAMBIA_ESTA_CONTRASENA_ADMIN") {
        throw "Debes configurar SECRET_KEY y ADMIN_PASS antes de desplegar. Edita deploy.ps1 o define DNSSEC_SECRET_KEY y DNSSEC_ADMIN_PASS en variables de entorno."
    }

    Step "[1/6] Configurando proyecto..."
    gcloud config set project $PROJECT_ID

    Step "[2/6] Verificando Docker..."
    docker version | Out-Null

    Step "[3/6] Habilitando APIs necesarias..."
    gcloud services enable run.googleapis.com
    gcloud services enable containerregistry.googleapis.com

    Step "[4/6] Autenticando Docker con Google..."
    gcloud auth configure-docker gcr.io --quiet

    Step "[5/6] Construyendo y subiendo imagen Docker..."
    docker build -t $IMAGE .
    docker push $IMAGE

    Step "[6/6] Desplegando nueva revision en Cloud Run..."
    gcloud run deploy $SERVICE `
      --image $IMAGE `
      --platform managed `
      --region $REGION `
      --allow-unauthenticated `
      --port 8080 `
      --memory 1Gi `
      --cpu 1 `
      --no-cpu-throttling `
      --timeout 600 `
      --min-instances 0 `
      --max-instances 3 `
      --update-env-vars APP_BASE_URL=$APP_BASE_URL,SECRET_KEY=$SECRET_KEY,ADMIN_EMAIL=$ADMIN_EMAIL,ADMIN_PASS=$ADMIN_PASS

    Write-Host ""
    $URL = gcloud run services describe $SERVICE --region $REGION --format "value(status.url)"
    $REVISION = gcloud run services describe $SERVICE --region $REGION --format "value(status.latestReadyRevisionName)"

    Ok "LISTO."
    Ok "URL publica: $URL"
    Ok "Revision activa: $REVISION"
    Ok "Imagen desplegada: $IMAGE"

    Write-Host ""
    Ok "Variables de entorno enviadas: APP_BASE_URL, SECRET_KEY, ADMIN_EMAIL, ADMIN_PASS"
    Warn "No se imprime ADMIN_PASS por seguridad. Mantén SECRET_KEY estable entre deploys."
    Warn "Cuando dnssec.corpece.org.ec funcione, cambia APP_BASE_URL a ese dominio."
}
catch {
    Write-Host ""
    Write-Host "ERROR EN EL DESPLIEGUE" -ForegroundColor Red
    Write-Host "$($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
