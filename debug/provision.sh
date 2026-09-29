#!/usr/bin/env bash
#
# Performs a signed tenant-provisioning request against the local debug stack, using the
# development keys in debug/keys/.
#
# In production this is deliberately a multi-person ceremony: each operator signs the same
# canonical payload on their own machine and the signatures are collected. Locally, one
# person holds all the dev keys, so this script does both signatures at once. That is a
# development convenience and nothing more — it is exactly the property the real control
# exists to prevent, which is why these keys never leave debug/keys/.
#
# Usage:
#   ./debug/provision.sh create '{"name":"Acme Corp","description":"Test tenancy"}'
#   ./debug/provision.sh delete <tenant-id>
#   ./debug/provision.sh raw POST /api/admin/tenants '{"name":"X"}'
#
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO_ROOT="$PWD"

[ -f .env ] && { set -a; . ./.env; set +a; }

BASE="${AUTH_BASE_URI:-http://localhost:8080}"
KEY_DIR="$REPO_ROOT/debug/keys"
# Threshold is 2; dev-carol is the spare. Override to exercise quorum behaviour, e.g.
#   PROVISION_SIGNERS="dev-alice" ./debug/provision.sh create '{"name":"X"}'   -> refused
IFS=' ' read -r -a SIGNERS <<< "${PROVISION_SIGNERS:-dev-alice dev-bob}"

ADMIN_EMAIL="${ADMIN_SEED_EMAIL:-admin@pixsmith.local}"
ADMIN_PASSWORD="${ADMIN_SEED_PASSWORD:-Admin1234!}"

die() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

command -v openssl >/dev/null || die "openssl is required."
[ -f "$KEY_DIR/${SIGNERS[0]}.key" ] || die "no dev keys found. Run ./debug/start.sh first."

case "${1:-}" in
    create) METHOD=POST; REQ_PATH=/api/admin/tenants; BODY="${2:?a JSON body is required}" ;;
    delete) METHOD=DELETE; REQ_PATH="/api/admin/tenants/${2:?a tenant id is required}"; BODY="" ;;
    raw)    METHOD="${2:?method}"; REQ_PATH="${3:?path}"; BODY="${4:-}" ;;
    *)      sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac

# An interactive human administrator is required in addition to the signatures — a machine
# identity is refused outright, so this obtains a real user token.
TOKEN="$(curl -sf -X POST "$BASE/connect/token" \
    -d grant_type=password -d "username=$ADMIN_EMAIL" -d "password=$ADMIN_PASSWORD" \
    -d client_id=blazor-client -d "scope=openid profile email roles api admin" \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')" \
    || die "could not obtain an admin token from $BASE. Is the stack running?"

NONCE="$(head -c 24 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')"
TIMESTAMP="$(date -u +%s)"
BODY_HASH="$(printf '%s' "$BODY" | openssl dgst -sha256 -hex | awk '{print $NF}')"

# Must match ProvisioningSignature.BuildPayload exactly.
PAYLOAD="$(printf 'PIXSMITH-TENANT-PROVISION-v1\n%s\n%s\n%s\n%s\n%s' \
    "$METHOD" "$REQ_PATH" "$NONCE" "$TIMESTAMP" "$BODY_HASH")"

HEADERS=(-H "Authorization: Bearer $TOKEN"
         -H "Content-Type: application/json"
         -H "X-Provision-Nonce: $NONCE"
         -H "X-Provision-Timestamp: $TIMESTAMP")

for signer in "${SIGNERS[@]}"; do
    sig="$(printf '%s' "$PAYLOAD" | openssl dgst -sha256 -sign "$KEY_DIR/$signer.key" | openssl base64 -A)"
    HEADERS+=(-H "X-Provision-Signature: $signer:$sig")
done

printf '\033[1;36m▸ %s %s\033[0m  signed by: %s\n' "$METHOD" "$REQ_PATH" "${SIGNERS[*]}"

if [ -n "$BODY" ]; then
    curl -s -X "$METHOD" "$BASE$REQ_PATH" "${HEADERS[@]}" --data-binary "$BODY" -w '\n  [%{http_code}]\n'
else
    curl -s -X "$METHOD" "$BASE$REQ_PATH" "${HEADERS[@]}" -w '\n  [%{http_code}]\n'
fi
