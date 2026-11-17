#!/usr/bin/env bash
#
# Brings up a production-shaped stack locally: the Release image (the Dockerfile's
# `runtime` target, no debugger, no SDK) running as ASPNETCORE_ENVIRONMENT=Staging behind a
# TLS-terminating nginx proxy. Every production code path is active:
#
#   • OpenIddict's HTTPS requirement           (off in Development)
#   • real signing/encryption certificates     (Development uses dev certs)
#   • forwarded headers from the proxy only    (Development trusts any sender)
#   • HSTS, no Swagger, no detailed errors
#
# It is entirely separate from the debug stack — its own network, Postgres, volumes and
# secrets — so the two can run side by side and staging never touches debug data.
#
#   https://localhost:8443   through the proxy: the way users reach it
#   http://localhost:8090    straight to the app, bypassing the proxy. Only exposed so you
#                            can confirm it refuses protocol requests; production must not
#                            expose this port at all.
#
# Secrets (database passwords, token certificates, TLS certificate, admin password) are
# generated on first run into staging/secrets/ (gitignored) and reused after that.
#
# Safe to re-run. Only the auth server and proxy containers are recreated.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO_ROOT="$PWD"

# ── Configuration ────────────────────────────────────────────────────────────
# Deliberately not read from .env: that file configures the debug stack, and sharing it
# would let a debug-only setting leak into what is meant to look like production.

NETWORK="${STAGING_NETWORK:-pixsmith-staging}"
SUBNET="${STAGING_SUBNET:-172.31.250.0/24}"
PROXY_IP="${STAGING_PROXY_IP:-172.31.250.10}"

PG_CONTAINER=pixsmith-staging-postgres
PG_IMAGE=pixsmith/postgres:17
PG_VOLUME=pixsmith-staging-postgres-data
POSTGRES_DB=pixsmith_auth
APP_DB_USER=pixsmith_app

SERVER_CONTAINER=pixsmith-staging-authserver
SERVER_IMAGE=pixsmith/authserver:staging
SERVER_VOLUME=pixsmith-staging-auth-data
DIRECT_PORT="${STAGING_DIRECT_PORT:-8090}"

PROXY_CONTAINER=pixsmith-staging-proxy
PROXY_IMAGE=nginx:1.27-alpine
HTTPS_PORT=8443   # fixed: nginx.conf listens on it and the issuer URL includes it

BASE_URI="https://localhost:${HTTPS_PORT}"
ADMIN_EMAIL=admin@pixsmith.local

SECRETS="$REPO_ROOT/staging/secrets"
READY_TIMEOUT="${READY_TIMEOUT:-120}"

# Off unless asked for. When on, a client flagged PKCE-exempt may use the authorization
# code grant without PKCE, for conformance-suite plans that send no code_challenge:
#   STAGING_ALLOW_PKCE_EXEMPT=true ./staging/start.sh
#   (PixSmith.PenTesting) ./tools/staging/seed-fixtures.py oidf-client create
#   ... run the suite ...
#   (PixSmith.PenTesting) ./tools/staging/seed-fixtures.py oidf-client delete
#   ./staging/start.sh                               restart with it off again
# Restarting without it puts PKCE back on any flagged client that is left.
ALLOW_PKCE_EXEMPT="${STAGING_ALLOW_PKCE_EXEMPT:-false}"
case "$ALLOW_PKCE_EXEMPT" in true|false) ;; *) die "STAGING_ALLOW_PKCE_EXEMPT must be true or false." ;; esac

step() { printf '\n\033[1;36m▸ %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '  \033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

command -v docker  >/dev/null 2>&1 || die "docker is not on PATH."
command -v openssl >/dev/null 2>&1 || die "openssl is required to generate the staging secrets."
docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable. Is it running?"

# ── 1. Secrets ───────────────────────────────────────────────────────────────

step "Secrets: staging/secrets/"

umask 077
mkdir -p "$SECRETS/keys"

# Satisfies the Identity password policy (upper, lower, digit, symbol) by construction.
random_password() { printf 'Stg-9%s' "$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=')"; }

# The database passwords are baked into the Postgres volume on first initialisation.
# Regenerating them against an existing volume would lock the app out, so refuse.
if [ ! -f "$SECRETS/db-app-password" ] && docker volume inspect "$PG_VOLUME" >/dev/null 2>&1; then
    die "the database volume $PG_VOLUME exists but its passwords in staging/secrets/ are gone.
     Start over with: ./staging/stop.sh --purge"
fi

generated=""
for name in db-superuser-password db-app-password m2m-client-secret admin-password certificate-password; do
    if [ ! -s "$SECRETS/$name" ]; then random_password > "$SECRETS/$name"; generated="yes"; fi
done

POSTGRES_PASSWORD="$(cat "$SECRETS/db-superuser-password")"
APP_DB_PASSWORD="$(cat "$SECRETS/db-app-password")"
M2M_CLIENT_SECRET="$(cat "$SECRETS/m2m-client-secret")"
ADMIN_PASSWORD="$(cat "$SECRETS/admin-password")"
CERT_PASSWORD="$(cat "$SECRETS/certificate-password")"

# Token signing and encryption: separate certificates, as production requires, each
# restricted to its own key usage.
token_cert() {
    local name="$1" usage="$2" cn="$3"
    [ -s "$SECRETS/$name.pfx" ] && return
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
        -keyout "$SECRETS/$name.key.pem" -out "$SECRETS/$name.crt.pem" \
        -subj "/CN=$cn" -addext "keyUsage=critical,$usage" 2>/dev/null
    openssl pkcs12 -export -inkey "$SECRETS/$name.key.pem" -in "$SECRETS/$name.crt.pem" \
        -out "$SECRETS/$name.pfx" -passout "pass:$CERT_PASSWORD"
    rm -f "$SECRETS/$name.key.pem" "$SECRETS/$name.crt.pem"
    generated="yes"
}
token_cert signing    digitalSignature "PixSmith Authorization Staging Signing"
token_cert encryption keyEncipherment  "PixSmith Authorization Staging Encryption"

# The proxy's TLS certificate. Self-signed, so browsers warn once; curl needs
# --cacert staging/secrets/tls.crt.
if [ ! -s "$SECRETS/tls.crt" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
        -keyout "$SECRETS/tls.key" -out "$SECRETS/tls.crt" \
        -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
    generated="yes"
fi

# Tenant provisioning keys: staging's own, never the debug stack's.
STAGING_KEY_IDS=(staging-alice staging-bob staging-carol)
for key_id in "${STAGING_KEY_IDS[@]}"; do
    if [ ! -f "$SECRETS/keys/$key_id.key" ]; then
        (cd "$SECRETS/keys" && "$REPO_ROOT/tools/provision-keygen.sh" "$key_id" "Staging key $key_id" >/dev/null)
        generated="yes"
    fi
done

# Owner-only. The containers read them as root through bind mounts.
find "$SECRETS" -type f -exec chmod 600 {} +

[ -n "$generated" ] && warn "generated new staging secrets" || ok "reusing existing secrets"

PROVISIONING_ENV=()
index=0
for key_id in "${STAGING_KEY_IDS[@]}"; do
    spki="$(grep -v '^-----' "$SECRETS/keys/$key_id.pub" | tr -d '\n')"
    PROVISIONING_ENV+=(
        -e "TenantProvisioning__Keys__${index}__KeyId=$key_id"
        -e "TenantProvisioning__Keys__${index}__Holder=Staging key $key_id"
        -e "TenantProvisioning__Keys__${index}__PublicKey=$spki"
    )
    index=$((index + 1))
done
PROVISIONING_ENV+=(-e "TenantProvisioning__RequiredSignatures=2")

# ── 2. Network ───────────────────────────────────────────────────────────────
# A fixed subnet so the proxy can have a fixed address, and the app can trust exactly that
# address. Trusting the whole subnet would also trust Docker's gateway, which is where
# host port-mapped traffic appears to come from — i.e. everyone.

step "Network: $NETWORK ($SUBNET)"
if existing="$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' "$NETWORK" 2>/dev/null)"; then
    [ "$existing" = "$SUBNET" ] || die "network $NETWORK exists with subnet $existing, not $SUBNET.
     Remove it (./staging/stop.sh --purge) or set STAGING_SUBNET/STAGING_PROXY_IP to match."
    ok "already exists"
else
    docker network create --subnet "$SUBNET" "$NETWORK" >/dev/null \
        || die "could not create $NETWORK. If $SUBNET overlaps another network, set STAGING_SUBNET and STAGING_PROXY_IP."
    ok "created"
fi

# ── 3. PostgreSQL ────────────────────────────────────────────────────────────
# Not published to the host — production databases are not reachable from outside.

step "PostgreSQL: $PG_CONTAINER"

docker image inspect "$PG_IMAGE" >/dev/null 2>&1 \
    || docker build -t "$PG_IMAGE" "$REPO_ROOT/docker/postgres" >/dev/null \
    || die "failed to build $PG_IMAGE"

pg_state="$(docker inspect -f '{{.State.Status}}' "$PG_CONTAINER" 2>/dev/null)" || pg_state=missing
case "$pg_state" in
    running) ok "already running" ;;
    exited|created|paused) docker start "$PG_CONTAINER" >/dev/null; ok "restarted (was: $pg_state)" ;;
    missing)
        docker run -d --name "$PG_CONTAINER" \
            --network "$NETWORK" --network-alias postgres \
            -e POSTGRES_USER=postgres \
            -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
            -e POSTGRES_DB="$POSTGRES_DB" \
            -e APP_DB_USER="$APP_DB_USER" \
            -e APP_DB_PASSWORD="$APP_DB_PASSWORD" \
            -v "$PG_VOLUME":/var/lib/postgresql/data \
            "$PG_IMAGE" >/dev/null
        ok "created"
        ;;
    *) die "container is in an unexpected state: $pg_state" ;;
esac

printf '  waiting for health'
for _ in $(seq 1 "$READY_TIMEOUT"); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$PG_CONTAINER" 2>/dev/null)" = healthy ] && break
    printf '.'; sleep 1
done
printf '\n'
[ "$(docker inspect -f '{{.State.Health.Status}}' "$PG_CONTAINER")" = healthy ] \
    || die "Postgres did not become healthy. Logs: docker logs $PG_CONTAINER"
ok "healthy"

# ── 4. Release image ─────────────────────────────────────────────────────────

step "Building $SERVER_IMAGE (target: runtime, Release)"
docker build --target runtime -t "$SERVER_IMAGE" "$REPO_ROOT" >/dev/null 2>&1 \
    || die "image build failed. To see why: docker build --target runtime -t $SERVER_IMAGE ."
ok "built"

# ── 5. Auth server ───────────────────────────────────────────────────────────

step "Auth server: $SERVER_CONTAINER"
docker rm -f "$SERVER_CONTAINER" >/dev/null 2>&1 || true

docker run -d --name "$SERVER_CONTAINER" \
    --network "$NETWORK" --network-alias authserver \
    -p "127.0.0.1:${DIRECT_PORT}:8080" \
    -v "$SERVER_VOLUME":/app/data \
    -v "$SECRETS/signing.pfx":/run/secrets/signing.pfx:ro,z \
    -v "$SECRETS/encryption.pfx":/run/secrets/encryption.pfx:ro,z \
    -e ASPNETCORE_ENVIRONMENT=Staging \
    -e Database__Provider=Postgres \
    -e ConnectionStrings__DefaultConnection="Host=postgres;Port=5432;Database=${POSTGRES_DB};Username=${APP_DB_USER};Password=${APP_DB_PASSWORD}" \
    -e DataProtection__KeyPath=/app/data/keys \
    -e OpenIddict__BlazorClient__BaseUri="$BASE_URI" \
    -e OpenIddict__M2MClient__ClientSecret="$M2M_CLIENT_SECRET" \
    -e OpenIddict__Certificates__Signing__Path=/run/secrets/signing.pfx \
    -e OpenIddict__Certificates__Signing__Password="$CERT_PASSWORD" \
    -e OpenIddict__Certificates__Encryption__Path=/run/secrets/encryption.pfx \
    -e OpenIddict__Certificates__Encryption__Password="$CERT_PASSWORD" \
    -e ForwardedHeaders__KnownProxies__0="$PROXY_IP" \
    -e Security__AllowPkceExemptClients="$ALLOW_PKCE_EXEMPT" \
    -e AdminSeed__Email="$ADMIN_EMAIL" \
    -e AdminSeed__Username=admin \
    -e AdminSeed__Password="$ADMIN_PASSWORD" \
    "${PROVISIONING_ENV[@]}" \
    "$SERVER_IMAGE" >/dev/null
ok "started"

# ── 6. Proxy ─────────────────────────────────────────────────────────────────

step "TLS proxy: $PROXY_CONTAINER ($PROXY_IP)"
docker rm -f "$PROXY_CONTAINER" >/dev/null 2>&1 || true

docker run -d --name "$PROXY_CONTAINER" \
    --network "$NETWORK" --ip "$PROXY_IP" \
    -p "127.0.0.1:${HTTPS_PORT}:8443" \
    -v "$REPO_ROOT/staging/nginx.conf":/etc/nginx/conf.d/default.conf:ro,z \
    -v "$SECRETS/tls.crt":/etc/nginx/tls/tls.crt:ro,z \
    -v "$SECRETS/tls.key":/etc/nginx/tls/tls.key:ro,z \
    "$PROXY_IMAGE" >/dev/null
ok "started"

# ── 7. Ready ─────────────────────────────────────────────────────────────────

curl_tls() { curl -s --cacert "$SECRETS/tls.crt" "$@"; }

printf '  waiting for HTTPS'
ready=""
for _ in $(seq 1 "$READY_TIMEOUT"); do
    for c in "$SERVER_CONTAINER" "$PROXY_CONTAINER"; do
        if [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" != true ]; then
            printf '\n'
            docker logs --tail 40 "$c" 2>&1 | sed 's/^/     /'
            die "$c exited during startup (logs above)."
        fi
    done
    code="$(curl_tls -o /dev/null -w '%{http_code}' "$BASE_URI/.well-known/openid-configuration" || true)"
    [ "$code" = 200 ] && { ready=yes; break; }
    printf '.'; sleep 1
done
printf '\n'
[ -n "$ready" ] || {
    docker logs --tail 30 "$SERVER_CONTAINER" 2>&1 | sed 's/^/     /'
    die "no valid discovery document at $BASE_URI within ${READY_TIMEOUT}s (last HTTP ${code:-none})."
}
ok "serving at $BASE_URI"

# ── 8. The production behaviour actually holds ───────────────────────────────
# Each of these is a property Development deliberately relaxes. Checked here so a stack
# that quietly fell back to development behaviour does not report itself as ready.

step "Production-shape checks"

issuer="$(curl_tls "$BASE_URI/.well-known/openid-configuration" \
    | sed -n 's/.*"issuer": *"\([^"]*\)".*/\1/p')"
[ "$issuer" = "$BASE_URI/" ] \
    || die "issuer is '$issuer', expected '$BASE_URI/'. The proxy's forwarded headers are not being honoured."
ok "issuer is $issuer"

direct="$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-Proto: https' \
    "http://localhost:${DIRECT_PORT}/.well-known/openid-configuration" || true)"
[ "$direct" = 400 ] \
    || die "plain HTTP straight to the app with a spoofed X-Forwarded-Proto returned $direct, not 400.
     Forwarded headers are being trusted from someone other than the proxy."
ok "plain HTTP with a spoofed X-Forwarded-Proto is refused (bypassing the proxy)"

env_name="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$SERVER_CONTAINER" \
    | sed -n 's/^ASPNETCORE_ENVIRONMENT=//p')"
[ "$env_name" = Staging ] || die "ASPNETCORE_ENVIRONMENT is '$env_name', not Staging."
ok "environment is Staging"

if docker exec "$SERVER_CONTAINER" sh -c '[ -e /vsdbg ] || [ -d /usr/share/dotnet/sdk ]' 2>/dev/null; then
    die "the image contains a debugger or the .NET SDK — it was not built from the runtime target."
fi
ok "release runtime image (no SDK, no debugger)"

swagger="$(curl_tls -o /dev/null -w '%{http_code}' "$BASE_URI/swagger/index.html" || true)"
[ "$swagger" != 200 ] || die "Swagger is being served — the server is running with development settings."
ok "Swagger is not served"

# ── Summary ──────────────────────────────────────────────────────────────────

printf '\n\033[1;32m▸ Staging stack ready\033[0m\n'
printf '  auth server   %s   (self-signed: curl --cacert staging/secrets/tls.crt)\n' "$BASE_URI"
printf '  discovery     %s/.well-known/openid-configuration\n' "$BASE_URI"
printf '  admin         %s / password in staging/secrets/admin-password\n' "$ADMIN_EMAIL"
printf '  direct (bypass, should refuse)  http://localhost:%s\n' "$DIRECT_PORT"
printf '  logs          docker logs -f %s\n' "$SERVER_CONTAINER"
printf '  tear down     ./staging/stop.sh   (--purge to delete data and secrets)\n\n'
if [ "$ALLOW_PKCE_EXEMPT" = true ]; then
    warn "PKCE exemptions are ON. Delete the test client when done (PixSmith.PenTesting: ./tools/staging/seed-fixtures.py oidf-client delete)"
    warn "and restart without STAGING_ALLOW_PKCE_EXEMPT."
    printf '\n'
fi
