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

# Must match whatever started the stack: the two engines keep separate containers,
# images and networks, so stopping with the wrong one silently finds nothing.
ENGINE="${CONTAINER_ENGINE:-podman}"

MODE="${1:-}"
ok() { printf '  \033[32m✓\033[0m %s\n' "$*"; }

# Existence is checked first because the engines disagree: `podman rm -f` exits 0 for a
# container that was never there, while `docker rm -f` exits 1. Relying on the exit code
# would report "removed" for things that did not exist.
for c in pixsmith-staging-proxy pixsmith-staging-authserver; do
    if $ENGINE container exists "$c" 2>/dev/null || $ENGINE inspect "$c" >/dev/null 2>&1; then
        $ENGINE rm -f "$c" >/dev/null 2>&1 && ok "removed $c"
    else
        ok "$c was not running"
    fi
done

case "$MODE" in
    --all|--purge)
        $ENGINE stop pixsmith-staging-postgres >/dev/null 2>&1 && ok "stopped pixsmith-staging-postgres" \
            || ok "pixsmith-staging-postgres was not running"
        ;;
esac

if [ "$MODE" = --purge ]; then
    printf '\n\033[1;31mThis deletes the staging database, its data-protection keys and every staging secret.\033[0m\n'
    printf 'Type "purge" to confirm: '
    read -r confirm
    if [ "$confirm" = purge ]; then
        $ENGINE rm -f pixsmith-staging-postgres >/dev/null 2>&1 || true
        $ENGINE volume rm pixsmith-staging-postgres-data pixsmith-staging-auth-data >/dev/null 2>&1 || true
        $ENGINE network rm "${STAGING_NETWORK:-pixsmith-staging}" >/dev/null 2>&1 || true
        rm -rf staging/secrets
        ok "volumes, network and staging/secrets/ removed"
    else
        printf '  aborted — nothing was deleted\n'
    fi
fi
