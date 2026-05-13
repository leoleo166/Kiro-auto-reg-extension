#!/usr/bin/env bash
# Install a single autoreg-produced token file into kiro-gateway-v2.
#
# Pipeline:
#   1. adapt JSON (autoreg format) → SQLite (kiro-gateway format)
#   2. copy to kiro-gateway-v2/credentials/acc<N>.sqlite3 where N auto-increments
#   3. upsert entry in kiro-gateway-v2/credentials/credentials.json
#   4. docker restart kiro-gateway-v2 (or create it if missing)
#
# Usage:
#   install-token.sh <path/to/token-BuilderId-IdC-*.json>

set -euo pipefail

TOKEN_JSON="${1:?usage: $0 <autoreg-token.json>}"
GW_DIR="/home/user1/workspace/kiro-gateway-v2"
ADAPTER="/home/user1/workspace/kiro-autoreg/autoreg/scripts/token_to_sqlite.py"
TEMPLATE="/home/user1/workspace/kiro-gateway/credentials/acc7.sqlite3"
CONTAINER="kiro-gateway-v2"
PORT_HOST="20131"
IMAGE="kiro-gateway-kiro-gateway:latest"

[ -f "$TOKEN_JSON" ] || { echo "ERROR: token file not found: $TOKEN_JSON" >&2; exit 2; }
[ -x "$ADAPTER" ] || chmod +x "$ADAPTER"
[ -f "$TEMPLATE" ] || { echo "ERROR: template not found: $TEMPLATE" >&2; exit 2; }

mkdir -p "$GW_DIR/credentials"

# Figure out next acc slot.
next_idx=1
while [ -f "$GW_DIR/credentials/acc${next_idx}.sqlite3" ]; do
  next_idx=$((next_idx + 1))
done
OUT_DB="$GW_DIR/credentials/acc${next_idx}.sqlite3"
echo "==> slot: acc${next_idx}"

# Step 1+2: adapt → write to final path.
python3 "$ADAPTER" "$TOKEN_JSON" "$OUT_DB" --template "$TEMPLATE"

# Step 3: credentials.json upsert.
CRED_JSON="$GW_DIR/credentials/credentials.json"
python3 - "$CRED_JSON" "/credentials/acc${next_idx}.sqlite3" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
entry_path = sys.argv[2]
d = []
if path.exists():
    try:
        d = json.loads(path.read_text())
    except Exception:
        d = []
entry = {"type": "sqlite", "path": entry_path, "enabled": True}
if not any(e.get("path") == entry_path for e in d):
    d.append(entry)
    path.write_text(json.dumps(d, indent=4))
    print(f"credentials.json: added {entry_path}")
else:
    print(f"credentials.json: {entry_path} already present")
PY

# Step 4: bring up / restart the gateway.
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
  echo "==> restart $CONTAINER"
  docker restart "$CONTAINER" >/dev/null
else
  echo "==> create $CONTAINER"
  docker run -d --name "$CONTAINER" \
    --restart unless-stopped \
    -p "127.0.0.1:${PORT_HOST}:8000" \
    -e SERVER_HOST=0.0.0.0 \
    -e SERVER_PORT=8000 \
    -e PROXY_API_KEY="$(cat ~/.kiro-gateway-key)" \
    -e ACCOUNT_SYSTEM=true \
    -e ACCOUNTS_CONFIG_FILE=/credentials/credentials.json \
    -e ACCOUNTS_STATE_FILE=/credentials/state.json \
    -e VPN_PROXY_URL=http://172.17.0.1:1082 \
    -e LOG_LEVEL=INFO \
    -e FAKE_REASONING=true \
    -e KIRO_REGION=us-east-1 \
    -v "${GW_DIR}/credentials:/credentials" \
    "$IMAGE" >/dev/null
fi

echo "==> wait for health"
for i in $(seq 1 20); do
  sleep 2
  status=$(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null || echo missing)
  if [ "$status" = "healthy" ] || [ "$status" = "none" ]; then
    echo "    $CONTAINER: $status"
    break
  fi
  echo "    [$i] $status"
done

echo "==> done: acc${next_idx} installed, listening on 127.0.0.1:${PORT_HOST}"
