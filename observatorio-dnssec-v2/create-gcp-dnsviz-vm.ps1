$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

# Creates a Google Cloud dual-stack VM to use as a DNSViz vantage point.
# Run from PowerShell after `gcloud auth login`.

$PROJECT_ID = if ($env:GCP_PROJECT_ID) { $env:GCP_PROJECT_ID } else { "observatorio-dnssec" }
$REGION     = if ($env:GCP_REGION)     { $env:GCP_REGION }     else { "us-central1" }
$ZONE       = if ($env:GCP_ZONE)       { $env:GCP_ZONE }       else { "us-central1-a" }

$NETWORK = if ($env:DNSVIZ_NETWORK) { $env:DNSVIZ_NETWORK } else { "dnsviz-vpc" }
$SUBNET  = if ($env:DNSVIZ_SUBNET)  { $env:DNSVIZ_SUBNET }  else { "dnsviz-subnet" }
$VM      = if ($env:DNSVIZ_VM)      { $env:DNSVIZ_VM }      else { "dnsviz-lab" }
$CIDR    = if ($env:DNSVIZ_CIDR)    { $env:DNSVIZ_CIDR }    else { "10.10.0.0/24" }

$MACHINE_TYPE = if ($env:DNSVIZ_MACHINE_TYPE) { $env:DNSVIZ_MACHINE_TYPE } else { "e2-micro" }
$IMAGE_FAMILY = if ($env:DNSVIZ_IMAGE_FAMILY) { $env:DNSVIZ_IMAGE_FAMILY } else { "ubuntu-2404-lts-amd64" }
$IMAGE_PROJECT = if ($env:DNSVIZ_IMAGE_PROJECT) { $env:DNSVIZ_IMAGE_PROJECT } else { "ubuntu-os-cloud" }

function Step($Message) {
    Write-Host ""
    Write-Host $Message -ForegroundColor Cyan
}

function Exists($Command) {
    Invoke-Expression "$Command *> `$null"
    return $LASTEXITCODE -eq 0
}

function Ensure-Gcloud {
    if (-not (Get-Command gcloud -ErrorAction SilentlyContinue)) {
        throw "gcloud no esta instalado o no esta en PATH."
    }
}

function Gcloud-ResourceExists($ListCommand) {
    $result = Invoke-Expression "$ListCommand 2>`$null"
    if ($LASTEXITCODE -ne 0) {
        return $false
    }
    return -not [string]::IsNullOrWhiteSpace(($result | Out-String).Trim())
}

function Ensure-Project {
    Step "Configurando proyecto $PROJECT_ID"
    gcloud config set project $PROJECT_ID | Out-Null
    gcloud services enable compute.googleapis.com --project $PROJECT_ID | Out-Null
}

function Ensure-Network {
    Step "Creando/verificando VPC $NETWORK"
    $networkExists = Gcloud-ResourceExists "gcloud compute networks list --project $PROJECT_ID --format='value(name)' | Select-String -SimpleMatch '$NETWORK'"
    if (-not $networkExists) {
        gcloud compute networks create $NETWORK `
            --project $PROJECT_ID `
            --subnet-mode=custom `
            --bgp-routing-mode=regional
    }

    Step "Creando/verificando subnet dual-stack $SUBNET"
    $subnetExists = Gcloud-ResourceExists "gcloud compute networks subnets list --project $PROJECT_ID --regions $REGION --format='value(name)' | Select-String -SimpleMatch '$SUBNET'"
    if (-not $subnetExists) {
        gcloud compute networks subnets create $SUBNET `
            --project $PROJECT_ID `
            --network $NETWORK `
            --region $REGION `
            --range $CIDR `
            --stack-type IPV4_IPV6 `
            --ipv6-access-type EXTERNAL
    }
}

function Ensure-Firewall {
    Step "Creando/verificando firewall SSH"
    $sshRule = "dnsviz-allow-ssh"
    $sshExists = Gcloud-ResourceExists "gcloud compute firewall-rules list --project $PROJECT_ID --format='value(name)' | Select-String -SimpleMatch '$sshRule'"
    if (-not $sshExists) {
        gcloud compute firewall-rules create $sshRule `
            --project $PROJECT_ID `
            --network $NETWORK `
            --direction INGRESS `
            --allow tcp:22 `
            --source-ranges 0.0.0.0/0 `
            --target-tags dnsviz-lab
    }

    Step "Creando/verificando firewall ICMP IPv4"
    $icmpRule = "dnsviz-allow-icmp"
    $icmpExists = Gcloud-ResourceExists "gcloud compute firewall-rules list --project $PROJECT_ID --format='value(name)' | Select-String -SimpleMatch '$icmpRule'"
    if (-not $icmpExists) {
        gcloud compute firewall-rules create $icmpRule `
            --project $PROJECT_ID `
            --network $NETWORK `
            --direction INGRESS `
            --allow icmp `
            --source-ranges 0.0.0.0/0 `
            --target-tags dnsviz-lab
    }

    Step "Creando/verificando firewall ICMPv6"
    $icmpv6Rule = "dnsviz-allow-icmpv6"
    $icmpv6Exists = Gcloud-ResourceExists "gcloud compute firewall-rules list --project $PROJECT_ID --format='value(name)' | Select-String -SimpleMatch '$icmpv6Rule'"
    if (-not $icmpv6Exists) {
        gcloud compute firewall-rules create $icmpv6Rule `
            --project $PROJECT_ID `
            --network $NETWORK `
            --direction INGRESS `
            --allow 58 `
            --source-ranges "::/0" `
            --target-tags dnsviz-lab
    }
}

function New-StartupScript {
@'
#!/usr/bin/env bash
set -euxo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
  dnsviz graphviz python3-pygraphviz dnsutils bind9-utils curl ca-certificates

install -d -m 0755 /opt/dnsviz-lab
cat >/opt/dnsviz-lab/run-check.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
DOMAIN="${1:-example.com}"
WORKDIR="${2:-/opt/dnsviz-lab/checks/${DOMAIN}-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

IFS='.' read -ra PARTS <<< "${DOMAIN%.}"
ZONES=(".")
for ((i=${#PARTS[@]}-1; i>0; i--)); do
  zone=""
  for ((j=i; j<${#PARTS[@]}; j++)); do
    if [[ -z "$zone" ]]; then zone="${PARTS[$j]}"; else zone="$zone.${PARTS[$j]}"; fi
  done
  ZONES+=("${zone}.")
done
ZONES+=("${DOMAIN%.}.")

dnsviz probe -A -a . -o probe.json "${ZONES[@]}"
dnsviz grok -l warning -r probe.json -o grok.json "${ZONES[@]}"
GRAPH_ARGS=()
if dnsviz help graph 2>/dev/null | grep -q -- '--ignore-rfc9276'; then
  GRAPH_ARGS+=(--ignore-rfc9276)
fi
dnsviz graph "${GRAPH_ARGS[@]}" -Thtml -r probe.json -o graph.html "${ZONES[@]}"
dnsviz graph "${GRAPH_ARGS[@]}" -Tpng -r probe.json -o graph.png "${ZONES[@]}"
dnsviz graph "${GRAPH_ARGS[@]}" -Tsvg -r probe.json -o graph.svg "${ZONES[@]}"
dnsviz print -r probe.json "${ZONES[@]}" > print.txt

ls -lh probe.json grok.json graph.html graph.png graph.svg print.txt
echo "$WORKDIR"
EOF
chmod +x /opt/dnsviz-lab/run-check.sh

cat >/opt/dnsviz-lab/verify-ipv6.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ip -6 addr
ip -6 route
ping -6 -c 3 2606:4700:4700::1111
curl -6 --max-time 10 https://ifconfig.co
EOF
chmod +x /opt/dnsviz-lab/verify-ipv6.sh

/opt/dnsviz-lab/verify-ipv6.sh >/opt/dnsviz-lab/ipv6-verify.log 2>&1 || true
/opt/dnsviz-lab/run-check.sh example.com >/opt/dnsviz-lab/example-check.log 2>&1 || true
'@
}

function Ensure-VM {
    Step "Creando/verificando VM $VM"
    $vmExists = Gcloud-ResourceExists "gcloud compute instances list --project $PROJECT_ID --zones $ZONE --format='value(name)' | Select-String -SimpleMatch '$VM'"
    if (-not $vmExists) {
        $startupPath = Join-Path $env:TEMP "dnsviz-startup-$VM.sh"
        New-StartupScript | Set-Content -Path $startupPath -Encoding utf8

        gcloud compute instances create $VM `
            --project $PROJECT_ID `
            --zone $ZONE `
            --machine-type $MACHINE_TYPE `
            --image-family $IMAGE_FAMILY `
            --image-project $IMAGE_PROJECT `
            --tags dnsviz-lab `
            --network-interface "network=$NETWORK,subnet=$SUBNET,stack-type=IPV4_IPV6,ipv6-network-tier=PREMIUM" `
            --metadata-from-file "startup-script=$startupPath"
    }
}

function Show-Result {
    Step "Resumen"
    gcloud compute instances describe $VM `
        --project $PROJECT_ID `
        --zone $ZONE `
        --format "table(name,zone.basename(),machineType.basename(),networkInterfaces[0].accessConfigs[0].natIP,networkInterfaces[0].ipv6AccessConfigs[0].externalIpv6)"

    Write-Host ""
    Write-Host "Conectar por SSH:" -ForegroundColor Green
    Write-Host "  gcloud compute ssh $VM --zone $ZONE --project $PROJECT_ID"
    Write-Host ""
    Write-Host "Dentro de la VM, verificar IPv6 y DNSViz:" -ForegroundColor Green
    Write-Host "  sudo /opt/dnsviz-lab/verify-ipv6.sh"
    Write-Host "  sudo /opt/dnsviz-lab/run-check.sh example.com"
    Write-Host ""
    Write-Host "Ver logs de instalacion/prueba:" -ForegroundColor Green
    Write-Host "  sudo cat /opt/dnsviz-lab/ipv6-verify.log"
    Write-Host "  sudo cat /opt/dnsviz-lab/example-check.log"
}

Ensure-Gcloud
Ensure-Project
Ensure-Network
Ensure-Firewall
Ensure-VM
Show-Result
