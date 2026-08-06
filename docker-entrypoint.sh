#!/bin/sh
# Bring the schema up to date before serving. Alembic is idempotent, so this is
# safe on every start, including restarts that change nothing.
set -e

echo "[entrypoint] applying migrations"
alembic upgrade head

exec "$@"
