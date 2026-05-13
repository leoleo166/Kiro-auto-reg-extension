#!/usr/bin/env bash
# Retry wrapper для autoreg. Интермиттентные failures от AWS — нормально,
# пробуем N раз с jitter'ом, первый успех сохраняем через install-token.sh.
#
# Usage:
#   try-register.sh [max_attempts=10]

set -euo pipefail

MAX_ATTEMPTS="${1:-10}"
AUTOREG_DIR="/home/user1/workspace/kiro-autoreg/autoreg"
INSTALL="$AUTOREG_DIR/scripts/install-token.sh"
TOKENS_DIR="${HOME}/.kiro-batch-login/tokens"
LOG_DIR="$AUTOREG_DIR/logs"

mkdir -p "$TOKENS_DIR" "$LOG_DIR"

cd "$AUTOREG_DIR"
source .venv/bin/activate
set -a
source .env
set +a

attempt=0
success=0
while [ $attempt -lt $MAX_ATTEMPTS ]; do
  attempt=$((attempt + 1))
  ts=$(date +%Y%m%d-%H%M%S)
  LOG="$LOG_DIR/autoreg-attempt-${attempt}-${ts}.log"
  echo "=========================================="
  echo "[try-register] attempt ${attempt}/${MAX_ATTEMPTS}  log=$LOG"
  echo "=========================================="

  # Очистить старые профили DrissionPage — иначе AWS видит стабильный
  # fingerprint между попытками и раз за разом отдаёт тот же challenge
  rm -rf /tmp/dp-* 2>/dev/null || true

  # Snapshot BEFORE
  BEFORE=$(ls "$TOKENS_DIR" 2>/dev/null | sort || true)

  if python3 -m registration.register_auto --headless --verbose 2>&1 | tee "$LOG"; then
    :
  fi

  # Проверяем появились ли новые токены
  AFTER=$(ls "$TOKENS_DIR" 2>/dev/null | sort || true)
  NEW_FILES=$(comm -13 <(echo "$BEFORE") <(echo "$AFTER") || true)

  if [ -n "$NEW_FILES" ]; then
    echo "[try-register] ✓ Got token on attempt ${attempt}!"
    for fname in $NEW_FILES; do
      bash "$INSTALL" "$TOKENS_DIR/$fname" || echo "[try-register] install failed for $fname"
    done
    success=1
    break
  fi

  # Jitter + короткая пауза чтобы AWS не агрегировал попытки в burst
  sleep_s=$((15 + RANDOM % 25))
  echo "[try-register] attempt ${attempt} failed, sleeping ${sleep_s}s before retry"
  sleep $sleep_s
done

if [ $success -eq 1 ]; then
  echo "[try-register] DONE: succeeded on attempt ${attempt}/${MAX_ATTEMPTS}"
  exit 0
else
  echo "[try-register] DONE: all ${MAX_ATTEMPTS} attempts failed"
  exit 1
fi
