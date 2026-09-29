#!/usr/bin/env bash
#
# Brings up the full debug stack, in order, and does not return until it is
# genuinely ready to attach to:
#
#   1. the shared Docker network
#   2. PostgreSQL — started if stopped, created if missing, waited on until healthy
#   3. a connectivity check as the application role, so a credential mismatch is
#      reported here instead of surfacing as a confusing EF migration failure
#   4. development provisioning keys, so tenancies can actually be created locally
#   5. the auth server debug image (built from the `debug` target)
#   6. the auth server container, waited on until it is serving HTTP
#
# Safe to re-run. Existing containers are reused where possible; only the server
# container is recreated, because that is the one holding your code.
#
# VS Code runs this as the preLaunchTask for "Attach to Auth Server (container)",
# so F5 does all of the above and then attaches. It also works standalone.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO_ROOT="$PWD"

# ── Configuration ────────────────────────────────────────────────────────────
# Values come from .env when present so this matches what Compose would do.

if [ -f "$REPO_ROOT/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    source "$REPO_ROOT/.env"
    set +a
fi

NETWORK="${DOCKER_NETWORK_NAME:-pixsmith-authorization}"

PG_CONTAINER="${PG_CONTAINER:-pixsmith-postgres}"
PG_IMAGE="${PG_IMAGE:-pixsmith/postgres:17}"
PG_HOST_PORT="${POSTGRES_HOST_PORT:-5432}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
POSTGRES_DB="${POSTGRES_DB:-pixsmith_auth}"
APP_DB_USER="${APP_DB_USER:-pixsmith_app}"
APP_DB_PASSWORD="${APP_DB_PASSWORD:-}"

SERVER_CONTAINER="${SERVER_CONTAINER:-pixsmith-authserver-debug}"
SERVER_IMAGE="${SERVER_IMAGE:-pixsmith/authserver:debug}"
SERVER_HOST_PORT="${SERVER_HOST_PORT:-8080}"
AUTH_BASE_URI="${AUTH_BASE_URI:-http://localhost:${SERVER_HOST_PORT}}"

READY_TIMEOUT="${READY_TIMEOUT:-90}"

step() { printf '\n\033[1;36m▸ %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '  \033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is not on PATH."
docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable. Is it running?"

# ── 1. Network ───────────────────────────────────────────────────────────────

step "Network: $NETWORK"
if docker network inspect "$NETWORK" >/dev/null 2>&1; then
    ok "already exists"
else
    docker network create "$NETWORK" >/dev/null
    ok "created"
fi

# ── 2. PostgreSQL ────────────────────────────────────────────────────────────

step "PostgreSQL: $PG_CONTAINER"

pg_state="$(docker inspect -f '{{.State.Status}}' "$PG_CONTAINER" 2>/dev/null || echo "missing")"

case "$pg_state" in
    running)
        ok "already running"
        ;;
    exited|created|paused)
        docker start "$PG_CONTAINER" >/dev/null
        ok "restarted (was: $pg_state)"
        ;;
    missing)
        if ! docker image inspect "$PG_IMAGE" >/dev/null 2>&1; then
            warn "image $PG_IMAGE not found — building it"
            docker build -t "$PG_IMAGE" "$REPO_ROOT/docker/postgres" >/dev/null \
                || die "failed to build $PG_IMAGE"
        fi

        [ -n "$APP_DB_PASSWORD" ] || die \
            "APP_DB_PASSWORD is not set and no Postgres container exists yet.
     Create one: cp docker/.env.example .env   (then edit the passwords)"

        docker run -d --name "$PG_CONTAINER" \
            --network "$NETWORK" \
            --network-alias postgres \
            -e POSTGRES_USER="$POSTGRES_USER" \
            -e POSTGRES_PASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set to create the container}" \
            -e POSTGRES_DB="$POSTGRES_DB" \
            -e APP_DB_USER="$APP_DB_USER" \
            -e APP_DB_PASSWORD="$APP_DB_PASSWORD" \
            -p "127.0.0.1:${PG_HOST_PORT}:5432" \
            -v pixsmith-postgres-data:/var/lib/postgresql/data \
            "$PG_IMAGE" >/dev/null
        ok "created"
        ;;
    *)
        die "container is in an unexpected state: $pg_state"
        ;;
esac

# An existing container may predate the network (e.g. created before this script)
# and would then be invisible to the server under the hostname it dials.
if ! docker inspect -f '{{range $k,$_ := .NetworkSettings.Networks}}{{$k}} {{end}}' \
        "$PG_CONTAINER" | grep -qw "$NETWORK"; then
    warn "not attached to $NETWORK — connecting it"
    docker network connect --alias postgres "$NETWORK" "$PG_CONTAINER"
    ok "connected with alias 'postgres'"
fi

printf '  waiting for health'
for _ in $(seq 1 "$READY_TIMEOUT"); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$PG_CONTAINER" 2>/dev/null)" = "healthy" ] && break
    printf '.'; sleep 1
done
printf '\n'
[ "$(docker inspect -f '{{.State.Health.Status}}' "$PG_CONTAINER" 2>/dev/null)" = "healthy" ] \
    || die "Postgres did not become healthy within ${READY_TIMEOUT}s. Logs: docker logs $PG_CONTAINER"
ok "healthy"

# ── 3. Credentials actually work ─────────────────────────────────────────────
# Checked here so a password mismatch reads as a password mismatch, rather than
# as an EF Core migration stack trace 30 seconds later.

if [ -n "$APP_DB_PASSWORD" ]; then
    if docker exec -e PGPASSWORD="$APP_DB_PASSWORD" "$PG_CONTAINER" \
            psql -h 127.0.0.1 -U "$APP_DB_USER" -d "$POSTGRES_DB" -tAc "SELECT 1" >/dev/null 2>&1; then
        ok "application role '$APP_DB_USER' can connect"
    else
        die "role '$APP_DB_USER' cannot connect to '$POSTGRES_DB' with the password in .env.
     The init script only runs on a fresh volume, so an existing database keeps its
     original password. Either fix .env, or change it in place:
       docker exec $PG_CONTAINER psql -U $POSTGRES_USER -d $POSTGRES_DB \\
         -c \"ALTER ROLE $APP_DB_USER WITH PASSWORD '<the password in .env>';\""
    fi
else
    warn "APP_DB_PASSWORD not set — skipping the credential check"
fi


# ── 4. Provisioning keys (development only) ──────────────────────────────────
#
# Tenant provisioning requires a quorum of offline signatures and fails closed when
# none are enrolled, so without keys the debug stack cannot create a tenancy at all.
#
# These are DEVELOPMENT keys, generated on this machine and kept in debug/keys/
# (gitignored). They exist so the tenant lifecycle is exercisable locally. Production
# keys are generated by each operator on their own machine with
# tools/provision-keygen.sh and never live in the repository — see
# docs/TENANT-PROVISIONING.md.

step "Provisioning keys (development)"

KEY_DIR="$REPO_ROOT/debug/keys"
DEV_KEY_IDS=(dev-alice dev-bob dev-carol)

mkdir -p "$KEY_DIR"

generated=""
for key_id in "${DEV_KEY_IDS[@]}"; do
    if [ ! -f "$KEY_DIR/$key_id.key" ]; then
        (cd "$KEY_DIR" && "$REPO_ROOT/tools/provision-keygen.sh" "$key_id" "Development key $key_id" >/dev/null)
        generated="yes"
    fi
done

if [ -n "$generated" ]; then
    warn "generated development signing keys in debug/keys/ — never use these outside dev"
fi

# Three keys with a threshold of two: the smallest configuration that is both safe and
# operable, matching the guidance in docs/TENANT-PROVISIONING.md.
PROVISIONING_ENV=()
index=0
for key_id in "${DEV_KEY_IDS[@]}"; do
    spki="$(grep -v '^-----' "$KEY_DIR/$key_id.pub" | tr -d '\n')"
    PROVISIONING_ENV+=(
        -e "TenantProvisioning__Keys__${index}__KeyId=$key_id"
        -e "TenantProvisioning__Keys__${index}__Holder=Development key $key_id"
        -e "TenantProvisioning__Keys__${index}__PublicKey=$spki"
    )
    index=$((index + 1))
done
PROVISIONING_ENV+=(-e "TenantProvisioning__RequiredSignatures=${PROVISIONING_REQUIRED_SIGNATURES:-2}")

ok "${#DEV_KEY_IDS[@]} keys enrolled, ${PROVISIONING_REQUIRED_SIGNATURES:-2} signatures required"

# ── 5. Debug image ───────────────────────────────────────────────────────────

step "Building $SERVER_IMAGE (target: debug)"
docker build \
    --target debug \
    --build-arg BUILD_CONFIGURATION=Debug \
    -t "$SERVER_IMAGE" \
    "$REPO_ROOT" >/dev/null || die "debug image build failed. Re-run without >/dev/null to see why."
ok "built"

# ── 6. Auth server ───────────────────────────────────────────────────────────

step "Auth server: $SERVER_CONTAINER"

# Always recreated — this is the container holding the code you just changed.
docker rm -f "$SERVER_CONTAINER" >/dev/null 2>&1 || true

docker run -d --name "$SERVER_CONTAINER" \
    --network "$NETWORK" \
    -p "127.0.0.1:${SERVER_HOST_PORT}:8080" \
    -v pixsmith-auth-data:/app/data \
    -e ASPNETCORE_ENVIRONMENT=Development \
    -e Database__Provider=Postgres \
    -e ConnectionStrings__DefaultConnection="Host=postgres;Port=5432;Database=${POSTGRES_DB};Username=${APP_DB_USER};Password=${APP_DB_PASSWORD}" \
    -e OpenIddict__BlazorClient__BaseUri="$AUTH_BASE_URI" \
    ${M2M_CLIENT_SECRET:+-e OpenIddict__M2MClient__ClientSecret="$M2M_CLIENT_SECRET"} \
    ${ADMIN_SEED_EMAIL:+-e AdminSeed__Email="$ADMIN_SEED_EMAIL"} \
    ${ADMIN_SEED_USERNAME:+-e AdminSeed__Username="$ADMIN_SEED_USERNAME"} \
    ${ADMIN_SEED_PASSWORD:+-e AdminSeed__Password="$ADMIN_SEED_PASSWORD"} \
    "${PROVISIONING_ENV[@]}" \
    "$SERVER_IMAGE" >/dev/null
ok "started"

printf '  waiting for HTTP'
ready=""
for _ in $(seq 1 "$READY_TIMEOUT"); do
    if ! docker inspect -f '{{.State.Running}}' "$SERVER_CONTAINER" 2>/dev/null | grep -q true; then
        printf '\n'
        docker logs --tail 30 "$SERVER_CONTAINER" 2>&1 | sed 's/^/     /'
        die "the server container exited during startup (logs above)."
    fi
    # Requires a 200 from the discovery document, not merely an open socket:
    # OpenIddict answers on the port well before it will serve protocol requests,
    # and a 400 here means the OIDC endpoints are unusable even though the process
    # is alive.
    code="$(curl -s -o /dev/null -w '%{http_code}' \
        "http://localhost:${SERVER_HOST_PORT}/.well-known/openid-configuration" 2>/dev/null || true)"
    if [ "$code" = "200" ]; then
        ready="yes"; break
    fi
    printf '.'; sleep 1
done
printf '\n'

[ -n "$ready" ] || {
    warn "last response from the discovery endpoint was HTTP ${code:-none}"
    curl -s "http://localhost:${SERVER_HOST_PORT}/.well-known/openid-configuration" 2>/dev/null \
        | head -5 | sed 's/^/     /'
    docker logs --tail 20 "$SERVER_CONTAINER" 2>&1 | sed 's/^/     /'
    die "the server did not serve a valid discovery document within ${READY_TIMEOUT}s (details above)."
}
ok "serving at http://localhost:${SERVER_HOST_PORT}"

# ── Ready ────────────────────────────────────────────────────────────────────

# ── 7. The debugger's assumptions actually hold ──────────────────────────────
#
# .vscode/launch.json attaches to PID 1 with no process picker. That is only safe
# because the image uses an exec-form ENTRYPOINT, so dotnet is PID 1 directly.
# Assert it here rather than letting VS Code attach to the wrong process — a
# silent mis-attach looks like "breakpoints never hit", which is a miserable thing
# to debug.

step "Debugger preconditions"

pid1_cmd="$(docker exec "$SERVER_CONTAINER" sh -c 'tr "\0" " " < /proc/1/cmdline' 2>/dev/null || true)"
case "$pid1_cmd" in
    *PixSmith.Authorization.API*)
        ok "PID 1 is the app process"
        ;;
    *)
        die "PID 1 is '$pid1_cmd', not the app.
     .vscode/launch.json attaches to PID 1 unconditionally, so it would attach to
     the wrong process. This usually means the Dockerfile ENTRYPOINT was changed to
     shell form, which wraps the app in /bin/sh. Restore the exec form:
       ENTRYPOINT [\"dotnet\", \"PixSmith.Authorization.API.dll\"]"
        ;;
esac

if docker exec "$SERVER_CONTAINER" test -x /vsdbg/vsdbg 2>/dev/null; then
    ok "vsdbg present at /vsdbg/vsdbg"
else
    die "vsdbg is missing from the image — the attach will fail.
     Rebuild without cache: docker build --no-cache --target debug \\
       --build-arg BUILD_CONFIGURATION=Debug -t $SERVER_IMAGE ."
fi

pdb_count="$(docker exec "$SERVER_CONTAINER" sh -c 'ls /app/*.pdb 2>/dev/null | wc -l' || echo 0)"
if [ "${pdb_count:-0}" -gt 0 ]; then
    ok "$pdb_count PDBs present — breakpoints can bind"
else
    warn "no PDBs in the image; breakpoints will not bind. Was BUILD_CONFIGURATION=Debug used?"
fi

# ── Ready ────────────────────────────────────────────────────────────────────

printf '\n\033[1;32m▸ Debug stack ready — attaching automatically\033[0m\n'
printf '  auth server   http://localhost:%s\n' "$SERVER_HOST_PORT"
printf '  discovery     http://localhost:%s/.well-known/openid-configuration\n' "$SERVER_HOST_PORT"
printf '  postgres      127.0.0.1:%s  (as %s)\n' "$PG_HOST_PORT" "$APP_DB_USER"
printf '  container     %s  (app is PID 1)\n' "$SERVER_CONTAINER"
printf '  logs          docker logs -f %s\n' "$SERVER_CONTAINER"
printf '  tear down     ./debug/stop.sh\n\n'
