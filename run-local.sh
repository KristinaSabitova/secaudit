#!/usr/bin/env bash
# Run the secaudit dashboard on this machine, audited by the local `claude`
# binary — your Claude subscription, no API key, nothing billed per audit.
#
#   ./run-local.sh          # then open http://127.0.0.1:8899
#
# Bound to loopback and running as a single owner, so there is no sign-in.
# Do not expose this port: it authenticates nobody. The hosted instance is the
# one with accounts.
set -euo pipefail

PORT="${SECAUDIT_LOCAL_PORT:-8899}"
STATE="${SECAUDIT_LOCAL_STATE:-$HOME/.secaudit}"
mkdir -p "$STATE"

export DATABASE_URL="${DATABASE_URL:-sqlite:///$STATE/web.db}"
export SECAUDIT_BACKEND="${SECAUDIT_BACKEND:-claude-code}"
export SECAUDIT_SINGLE_USER="${SECAUDIT_SINGLE_USER:-$(whoami)}"

# Only used if you store an API key from the panel; generated once and kept
# out of the repo. claude-code needs no key at all.
if [[ ! -f "$STATE/master.key" ]]; then
  (umask 077; openssl rand -hex 32 > "$STATE/master.key")
fi
export SECAUDIT_SECRET_KEY="$(cat "$STATE/master.key")"

cd "$(dirname "$0")"
python3 -m alembic upgrade head >/dev/null

if ! command -v claude >/dev/null && [[ -z "${CLAUDE_BIN:-}" ]]; then
  echo "warning: the 'claude' binary is not on PATH, so audits will fail." >&2
  echo "         Install Claude Code, or pick another backend in the panel." >&2
fi

echo "secaudit → http://127.0.0.1:$PORT   (backend: $SECAUDIT_BACKEND)"
exec python3 -m uvicorn web.main:app --host 127.0.0.1 --port "$PORT"
