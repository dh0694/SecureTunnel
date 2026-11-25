#!/usr/bin/env bash
# HA lab on one host.
#   ./ha.sh up       second control server + HAProxy + second gateway
#   ./ha.sh status   what's running and which control server is active
#   ./ha.sh down     back to the single-server stack
#
# Try it:  docker compose stop control     (control-b takes over in ~4 s)
#          docker compose start control    (control-a takes back over)
#          docker compose stop gateway     (clients fail over to lab-gw-b)
set -euo pipefail
cd "$(dirname "$0")"

PUBLIC_HOST="$(sed -n 's/^PUBLIC_HOST=//p' .env)"

set_compose_file() {
  sed -i '/^COMPOSE_FILE=/d' .env
  [[ -n "$1" ]] && echo "COMPOSE_FILE=$1" >> .env
  return 0
}

write_gateways() {
  local b_entry=""
  if [[ -f data/gateway-b/public.key ]]; then
    b_entry=$(cat <<EOF
,
  {
    "id": "lab-gw-b",
    "site": "lab-b",
    "endpoint": "${PUBLIC_HOST}:51821",
    "public_key": "$(cat data/gateway-b/public.key)",
    "pool": "10.200.8.0/21",
    "capacity": 1500,
    "token_hash": "$(cat data/gateway-b/token.sha256)",
    "enabled": true
  }
EOF
)
  fi
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
  }${b_entry}
]
EOF
  chmod 644 data/gateways.json
}

case "${1:-}" in
  up)
    if [[ ! -f data/gateway-b/private.key ]]; then
      echo "==> Second gateway key and token"
      mkdir -p data/gateway-b
      KEYS="$(docker run --rm securetunnel:latest gatewayagent genkey)"
      echo "$KEYS" | sed -n 's/^private_key=//p' > data/gateway-b/private.key
      echo "$KEYS" | sed -n 's/^public_key=//p'  > data/gateway-b/public.key
      TOK="$(docker run --rm securetunnel:latest controlserver gateway-token)"
      echo "$TOK" | sed -n 's/^token=//p' > data/gateway-b/token
      echo "$TOK" | sed -n 's/^hash=//p'  > data/gateway-b/token.sha256
      chmod 600 data/gateway-b/private.key data/gateway-b/token
      chown --reference=data/gateway/private.key data/gateway-b/* 2>/dev/null || true
    fi
    write_gateways
    set_compose_file "docker-compose.yml:docker-compose.ha.yml"
    docker compose up -d --remove-orphans
    echo
    echo "HA lab is up. Admin site → System shows control-a, control-b, lab-gw and lab-gw-b."
    ;;
  down)
    set_compose_file ""
    docker compose -f docker-compose.yml -f docker-compose.ha.yml stop lb control-b gateway-b 2>/dev/null || true
    docker compose -f docker-compose.yml -f docker-compose.ha.yml rm -f lb control-b gateway-b 2>/dev/null || true
    ip link del wg1 2>/dev/null || true
    docker compose up -d --remove-orphans
    echo "Back to the single-server stack (lab-gw-b stays listed but unhealthy; disable it on the Gateways page)."
    ;;
  status)
    docker compose ps --format 'table {{.Service}}\t{{.Status}}'
    echo
    docker compose exec -T lb wget -qO- "http://127.0.0.1:8404/stats;csv" 2>/dev/null \
      | awk -F, '$1=="controls" && $2!="BACKEND" {printf "%-10s %s\n", $2, $18}' || echo "(HA lab isn't running)"
    ;;
  *)
    echo "usage: $0 up|down|status" >&2
    exit 1
    ;;
esac
