#!/usr/bin/env bash
#
# Stops the staging stack.
#
#   ./staging/stop.sh          remove the server and proxy; Postgres keeps running
#   ./staging/stop.sh --all    also stop Postgres
#   ./staging/stop.sh --purge  delete everything: containers, volumes, network and
#                              staging/secrets/ (they only make sense together — the
#                              database volume holds the passwords the secrets record)
#
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

MODE="${1:-}"
ok() { printf '  \033[32m✓\033[0m %s\n' "$*"; }

for c in pixsmith-staging-proxy pixsmith-staging-authserver; do
    docker rm -f "$c" >/dev/null 2>&1 && ok "removed $c" || ok "$c was not running"
done

case "$MODE" in
    --all|--purge)
        docker stop pixsmith-staging-postgres >/dev/null 2>&1 && ok "stopped pixsmith-staging-postgres" \
            || ok "pixsmith-staging-postgres was not running"
        ;;
esac

if [ "$MODE" = --purge ]; then
    printf '\n\033[1;31mThis deletes the staging database, its data-protection keys and every staging secret.\033[0m\n'
    printf 'Type "purge" to confirm: '
    read -r confirm
    if [ "$confirm" = purge ]; then
        docker rm -f pixsmith-staging-postgres >/dev/null 2>&1 || true
        docker volume rm pixsmith-staging-postgres-data pixsmith-staging-auth-data >/dev/null 2>&1 || true
        docker network rm "${STAGING_NETWORK:-pixsmith-staging}" >/dev/null 2>&1 || true
        rm -rf staging/secrets
        ok "volumes, network and staging/secrets/ removed"
    else
        printf '  aborted — nothing was deleted\n'
    fi
fi
