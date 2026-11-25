#!/usr/bin/env bash
# SecureTunnel proof-of-concept setup for one Ubuntu host (22.04 or 24.04).
#
#   sudo ./setup.sh <public-host> [--no-nat]
#
# <public-host> is the IP or DNS name test devices use to reach this machine.
# Safe to re-run: existing secrets, keys and accounts are kept.
set -euo pipefail

cd "$(dirname "$0")"

PUBLIC_HOST="${1:-}"
NAT=1
[[ "${2:-}" == "--no-nat" ]] && NAT=0

if [[ -z "$PUBLIC_HOST" ]]; then
  echo "usage: sudo ./setup.sh <public-ip-or-dns> [--no-nat]" >&2
  exit 2
fi
if [[ $EUID -ne 0 ]]; then
  echo "run with sudo (needs to set IP forwarding and file ownership)" >&2
  exit 1
fi
for cmd in docker openssl; do
  command -v "$cmd" >/dev/null || { echo "missing: $cmd (install Docker Engine and openssl first)" >&2; exit 1; }
done
docker compose version >/dev/null 2>&1 || { echo "missing: docker compose plugin" >&2; exit 1; }

echo "==> Checking WireGuard kernel support"
modprobe wireguard 2>/dev/null || true
if ! lsmod | grep -q '^wireguard'; then
  echo "WireGuard kernel module not loaded. On Ubuntu it ships with the kernel; try: sudo apt install wireguard" >&2
  exit 1
fi

rand_hex() { openssl rand -hex "$1"; }
rand_pw()  { openssl rand -base64 24 | tr -d '/+=' | cut -c1-20; }

echo "==> Secrets (.env)"
if [[ ! -f .env ]]; then
  NAT_IFACE=""
  if [[ $NAT -eq 1 ]]; then
    NAT_IFACE="$(ip route show default | awk '{print $5; exit}')"
  fi
  cat > .env <<EOF
PUBLIC_HOST=${PUBLIC_HOST}
HOST_LABEL=$(hostname)
PG_PASSWORD=$(rand_hex 16)
ST_SECRET_KEY=$(rand_hex 32)
ADMIN_PASSWORD=$(rand_pw)
TESTUSER_PASSWORD=$(rand_pw)
LAB_NAT_IFACE=${NAT_IFACE}
LOCAL_REQUIRE_TOTP=false
TUNNEL_DNS=1.1.1.1,9.9.9.9
TUNNEL_ALLOWED_IPS=0.0.0.0/0,::/0
ENTRA_TENANT_ID=
ENTRA_API_AUDIENCE=
EOF
  chmod 600 .env
  echo "    created .env"
else
  echo "    keeping existing .env"
fi
# shellcheck disable=SC1091
set -a; source .env; set +a

mkdir -p data/tls data/gateway data/clients

echo "==> TLS certificate (self-signed, for the POC)"
if [[ ! -f data/tls/tls.crt ]]; then
  if [[ "$PUBLIC_HOST" =~ ^[0-9.]+$ ]]; then SAN="IP:${PUBLIC_HOST}"; else SAN="DNS:${PUBLIC_HOST}"; fi
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout data/tls/tls.key -out data/tls/tls.crt \
    -subj "/CN=${PUBLIC_HOST}" \
    -addext "subjectAltName=${SAN},IP:127.0.0.1,DNS:localhost" >/dev/null 2>&1
  echo "    created data/tls/tls.crt"
fi
chown 65532:65532 data/tls/tls.key
chmod 600 data/tls/tls.key
chmod 644 data/tls/tls.crt

echo "==> Building the image (compiles and tests the Go code; first run takes a few minutes)"
docker compose build

echo "==> Gateway WireGuard key and API token"
if [[ ! -f data/gateway/private.key ]]; then
  KEYS="$(docker run --rm securetunnel:latest gatewayagent genkey)"
  echo "$KEYS" | sed -n 's/^private_key=//p' > data/gateway/private.key
  echo "$KEYS" | sed -n 's/^public_key=//p'  > data/gateway/public.key
  TOK="$(docker run --rm securetunnel:latest controlserver gateway-token)"
  echo "$TOK" | sed -n 's/^token=//p' > data/gateway/token
  echo "$TOK" | sed -n 's/^hash=//p'  > data/gateway/token.sha256
  chmod 600 data/gateway/private.key data/gateway/token
fi

echo "==> data/gateways.json"
cat > data/gateways.json <<EOF
[
  {
    "id": "lab-gw",
    "site": "lab",
    "endpoint": "${PUBLIC_HOST}:51820",
    "public_key": "$(cat data/gateway/public.key)",
    "pool": "10.200.0.0/21",
    "capacity": 1500,
    "token_hash": "$(cat data/gateway/token.sha256)",
    "enabled": true
  }
]
EOF
chmod 644 data/gateways.json

echo "==> IP forwarding"
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-securetunnel.conf
sysctl -q -p /etc/sysctl.d/99-securetunnel.conf

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  echo "==> Opening firewall ports (ufw)"
  ufw allow 8443/tcp >/dev/null
  ufw allow 51820/udp >/dev/null
  ufw route allow in on wg0 >/dev/null
fi

echo "==> Starting the stack"
docker compose up -d

echo -n "==> Waiting for the control server"
for _ in $(seq 1 60); do
  if curl -fsk https://127.0.0.1:8443/healthz >/dev/null 2>&1; then echo " ok"; break; fi
  echo -n "."; sleep 2
done

echo "==> Test VPN account"
if docker compose exec -T -e ST_NEW_PASSWORD="$TESTUSER_PASSWORD" control controlserver useradd testuser user >/dev/null 2>&1; then
  echo "    created testuser"
else
  echo "    testuser already exists (or creation failed; check: docker compose logs control)"
fi

echo "==> Copying test clients to data/clients/"
CID="$(docker create securetunnel:latest)"
docker cp "$CID:/opt/securetunnel/clients/." data/clients/ >/dev/null
docker rm "$CID" >/dev/null
cp data/tls/tls.crt data/clients/securetunnel-ca.crt

cat <<EOF

SecureTunnel POC is running.

  Admin site:   https://${PUBLIC_HOST}:8443/admin/
                (self-signed certificate: your browser will warn once)
  Admin login:  admin / ${ADMIN_PASSWORD}
  Test VPN:     testuser / ${TESTUSER_PASSWORD}
  NAT (lab):    ${LAB_NAT_IFACE:-off}

These passwords are also in deploy/.env. Change them on the Users page.

Test from a Windows PC:
  1. Copy data/clients/stclient.exe and data/clients/securetunnel-ca.crt to the PC.
  2. stclient.exe -server https://${PUBLIC_HOST}:8443 -ca securetunnel-ca.crt -user testuser
  3. Import the securetunnel.conf it writes into the WireGuard app and activate it.
  4. Watch the session appear on the admin site.

Logs:  docker compose logs -f control gateway
EOF
