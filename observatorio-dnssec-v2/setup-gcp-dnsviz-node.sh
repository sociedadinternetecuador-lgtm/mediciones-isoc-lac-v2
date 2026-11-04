#!/usr/bin/env bash
set -euo pipefail

echo "[host]"
hostname
whoami

echo
echo "[wait apt locks]"
for i in $(seq 1 120); do
  if sudo fuser /var/lib/apt/lists/lock /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock >/dev/null 2>&1; then
    echo "waiting apt lock $i"
    sleep 5
  else
    break
  fi
done

echo
echo "[install]"
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  dnsviz graphviz python3-pygraphviz dnsutils bind9-utils curl ca-certificates

echo
echo "[ipv6]"
ip -6 addr show scope global
ip -6 route
ping -6 -c 3 2606:4700:4700::1111
curl -6 --max-time 10 https://ifconfig.co

echo
echo "[dnsviz]"
command -v dnsviz
dnsviz help | head -n 12 || true

sudo install -d -m 0775 /opt/dnsviz-lab
sudo chown -R "$USER:$USER" /opt/dnsviz-lab
rm -f /opt/dnsviz-lab/run-check.sh /opt/dnsviz-lab/verify-ipv6.sh
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

echo
echo "[example.com check]"
/opt/dnsviz-lab/run-check.sh example.com /opt/dnsviz-lab/checks/manual-example
head -n 15 /opt/dnsviz-lab/checks/manual-example/print.txt
