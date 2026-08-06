#!/usr/bin/env bash
# Ship the working tree to the server and restart the stack.
#
#   ./deploy.sh                 # deploy
#   ./deploy.sh --check         # connectivity and prerequisites only, no changes
#   ./deploy.sh --tunnel        # forward the dashboard to this machine over SSH
#
# The server's .env is never touched: it holds the secrets and lives only there.
set -euo pipefail

HOST="${SECAUDIT_SSH_HOST:?set SECAUDIT_SSH_HOST, e.g. kris@vps.example.com}"
KEY="${SECAUDIT_SSH_KEY:-$HOME/.ssh/spectra_key}"
REMOTE_DIR="${SECAUDIT_REMOTE_DIR:-/srv/secaudit}"
SSH=(ssh -i "$KEY" "$HOST")

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }

PORT="${SECAUDIT_PORT:-8811}"

if [[ "${1:-}" == "--tunnel" ]]; then
  # The dashboard is deliberately not published: reach it through the tunnel.
  log "forwarding $HOST:$PORT to http://127.0.0.1:$PORT (ctrl-c to stop)"
  exec ssh -i "$KEY" -N -L "$PORT:127.0.0.1:$PORT" "$HOST"
fi

if [[ "${1:-}" == "--check" ]]; then
  log "checking $HOST"
  "${SSH[@]}" 'docker --version && docker compose version && echo "remote ok"'
  "${SSH[@]}" "test -f $REMOTE_DIR/.env && echo '.env present' || echo 'MISSING: $REMOTE_DIR/.env'"
  exit 0
fi

log "syncing source to $HOST:$REMOTE_DIR"
rsync -az --delete \
  --exclude '.git/' \
  --exclude '__pycache__/' \
  --exclude '.pytest_cache/' \
  --exclude '.venv/' \
  --exclude '.env' \
  --exclude '*.db' \
  -e "ssh -i $KEY" \
  ./ "$HOST:$REMOTE_DIR/"

log "building and restarting"
"${SSH[@]}" "cd $REMOTE_DIR && docker compose up -d --build"

log "waiting for health"
"${SSH[@]}" "cd $REMOTE_DIR && for i in \$(seq 1 30); do
  if curl -fsS http://127.0.0.1:$PORT/api/health; then echo; exit 0; fi
  sleep 2
done; echo 'service did not become healthy'; docker compose logs --tail 50 app; exit 1"

log "deployed"
