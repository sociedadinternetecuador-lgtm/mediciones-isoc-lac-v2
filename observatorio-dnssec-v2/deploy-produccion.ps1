$PROJECT_ID = "observatorio-dnssec"
$SERVICE_NAME = "observatorio-dnssec"
$REGION = "us-central1"
$IMAGE = "gcr.io/$PROJECT_ID/$SERVICE_NAME"

$SECRET_KEY = "598af8533eb845938f4b51fbc70bbb3e1e07cd00ef3d4d64ab2e331d44adbc51CAMBIA_ESTA_CLAVE_LARGA"
$ADMIN_EMAIL = "cveraq@corpece.org.ec"
$ADMIN_PASS = "KRJ.wzyi-_ty74"

Write-Host "1. Configurando proyecto..."
gcloud config set project $PROJECT_ID

Write-Host "2. Verificando archivos..."
python -m py_compile backend\app.py
python -m unittest discover tests
node --check frontend\js\report.js
node --check frontend\js\report-v2.js
node --check frontend\js\admin.js
node --check frontend\js\admin-data.js
node --check frontend\js\api.js
node --check frontend\js\main.js

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Las pruebas fallaron. No se despliega."
    exit 1
}

Write-Host "3. Construyendo imagen en Google Cloud Build..."
gcloud builds submit --tag $IMAGE

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Falló la construcción de imagen."
    exit 1
}

Write-Host "4. Desplegando nueva revisión en Cloud Run..."
gcloud run deploy $SERVICE_NAME `
  --image $IMAGE `
  --platform managed `
  --region $REGION `
  --allow-unauthenticated `
  --no-cpu-throttling `
  --set-env-vars SECRET_KEY=$SECRET_KEY,ADMIN_EMAIL=$ADMIN_EMAIL,ADMIN_PASS=$ADMIN_PASS

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Falló el despliegue."
    exit 1
}

Write-Host "5. Despliegue terminado."
Write-Host "Prueba:"
Write-Host "https://dnssec.corpece.org.ec/health"
Write-Host "https://dnssec.corpece.org.ec"
