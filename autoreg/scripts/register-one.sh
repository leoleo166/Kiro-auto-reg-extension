#!/usr/bin/env bash
# Full autoreg pipeline: register Builder ID → extract token → install into kiro-gateway-v2.
#
# Prerequisites:
#   - autoreg venv at /home/user1/workspace/kiro-autoreg/autoreg/.venv
#   - autoreg/.env configured with valid IMAP (tested via imaplib first)
#   - validator gateway running (socks5://127.0.0.1:11080, http://127.0.0.1:1082)
#   - kiro-gateway-v2 container EITHER running OR absent (script creates if missing)
#
# Usage:
#   register-one.sh [--email you@domain.com]           # use explicit email
#   register-one.sh                                     # auto-generate via IMAP catch-all
#   register-one.sh --count N                           # batch of N

set -euo pipefail

AUTOREG_DIR="/home/user1/workspace/kiro-autoreg/autoreg"
INSTALL="$AUTOREG_DIR/scripts/install-token.sh"

cd "$AUTOREG_DIR"

# Activate the autoreg venv.
if [ ! -d ".venv" ]; then
  echo "ERROR: autoreg venv missing at $AUTOREG_DIR/.venv" >&2
  exit 2
fi
# shellcheck disable=SC1091
source .venv/bin/activate

# Sanity: IMAP login must work before we burn a captcha round.
python3 - <<'PY' || { echo "ERROR: IMAP login failed — fix .env first" >&2; exit 3; }
import os, sys, imaplib, ssl
from dotenv import load_dotenv
load_dotenv()
host = os.environ["IMAP_SERVER"]
port = int(os.environ.get("IMAP_PORT", "993"))
user = os.environ["IMAP_USER"]
pwd  = os.environ["IMAP_PASSWORD"]
m = imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context())
m.login(user, pwd)
m.select("INBOX")
print(f"IMAP OK: {user}@{host}:{port}")
m.logout()
PY

# Snapshot tokens dir BEFORE we run autoreg so we can diff after.
TOKENS_DIR="${HOME}/.kiro-batch-login/tokens"
mkdir -p "$TOKENS_DIR"
BEFORE_LIST=$(ls "$TOKENS_DIR" 2>/dev/null | sort || true)

echo "==> starting autoreg (headless)"
python3 -m registration.register_auto --headless "$@"

# Detect new token files.
AFTER_LIST=$(ls "$TOKENS_DIR" 2>/dev/null | sort || true)
NEW_FILES=$(comm -13 <(echo "$BEFORE_LIST") <(echo "$AFTER_LIST") || true)

if [ -z "$NEW_FILES" ]; then
  echo "ERROR: no new token file appeared in $TOKENS_DIR" >&2
  exit 4
fi

for fname in $NEW_FILES; do
  echo "==> installing token: $fname"
  bash "$INSTALL" "$TOKENS_DIR/$fname"
done

echo "==> all new tokens installed"
