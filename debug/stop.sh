#!/usr/bin/env bash
#
# Tears down the debug stack.
#
# By default only the auth server is removed and Postgres is left running, so the
# next F5 is fast and your data survives. Pass --all to stop Postgres too, or
# --purge to additionally delete the volumes.
#
#   ./debug/stop.sh            # remove the server container
#   ./debug/stop.sh --all      # ...and stop Postgres
#   ./debug/stop.sh --purge    # ...and DELETE the database and key volumes

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ -f .env ]; then
    set -a; # shellcheck disable=SC1091
    source .env; set +a
fi

PG_CONTAINER="${PG_CONTAINER:-pixsmith-postgres}"
SERVER_CONTAINER="${SERVER_CONTAINER:-pixsmith-authserver-debug}"
NETWORK="${DOCKER_NETWORK_NAME:-pixsmith-authorization}"

MODE="${1:-server}"

ok() { printf '  \033[32m✓\033[0m %s\n' "$*"; }

docker rm -f "$SERVER_CONTAINER" >/dev/null 2>&1 && ok "removed $SERVER_CONTAINER" \
    || ok "$SERVER_CONTAINER was not running"

case "$MODE" in
    --all|--purge)
        docker stop "$PG_CONTAINER" >/dev/null 2>&1 && ok "stopped $PG_CONTAINER" \
            || ok "$PG_CONTAINER was not running"
        ;;
esac

if [ "$MODE" = "--purge" ]; then
    printf '\n\033[1;31mThis deletes the database and the data-protection keys.\033[0m\n'
    printf 'Every user, client, tenant and issued token will be gone. Type "purge" to confirm: '
    read -r confirm
    if [ "$confirm" = "purge" ]; then
        docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
        docker volume rm pixsmith-postgres-data pixsmith-auth-data >/dev/null 2>&1 || true
        docker network rm "$NETWORK" >/dev/null 2>&1 || true
        ok "volumes and network removed"
    else
        printf '  aborted — nothing was deleted\n'
    fi
fi
