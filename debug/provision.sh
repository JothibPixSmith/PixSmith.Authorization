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

# PROVISION_* overrides win over .env, which describes the debug stack; staging/provision.sh
# uses them to aim this script at the staging stack instead.
BASE="${PROVISION_BASE_URI:-${AUTH_BASE_URI:-http://localhost:8080}}"
# staging/provision.sh sets this to --cacert for its self-signed certificate.
CURL_OPTS="${PROVISION_CURL_OPTS:-}"
KEY_DIR="${PROVISION_KEY_DIR:-$REPO_ROOT/debug/keys}"
# Threshold is 2; dev-carol is the spare. Override to exercise quorum behaviour, e.g.
#   PROVISION_SIGNERS="dev-alice" ./debug/provision.sh create '{"name":"X"}'   -> refused
IFS=' ' read -r -a SIGNERS <<< "${PROVISION_SIGNERS:-dev-alice dev-bob}"

# No admin credentials here any more. The device authorization grant sends the human to the
# server's own login page, so this script never reads, holds or transmits a password.

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
# identity is refused outright — so this needs a real *user* token.
#
# It is obtained with the device authorization grant (RFC 8628) rather than the password
# grant, which has been removed: this script never sees the password. The server shows a
# code, a human approves it in a browser, and this polls until that happens. For a control
# whose whole purpose is "no application provisions a tenancy for itself", a step that
# cannot complete without a person at a browser is the right shape, not an inconvenience.

CLI_CLIENT="${PROVISION_CLIENT_ID:-provisioning-cli}"

device="$(curl -sf $CURL_OPTS -X POST "$BASE/connect/deviceauthorization" \
    -d "client_id=$CLI_CLIENT" -d "scope=openid profile email roles admin")" \
    || die "device authorization request failed against $BASE. Is the stack running?"

read -r DEVICE_CODE USER_CODE VERIFY_URI INTERVAL <<<"$(printf '%s' "$device" | python3 -c '
import sys, json
d = json.load(sys.stdin)
print(d["device_code"], d["user_code"],
      d.get("verification_uri_complete") or d["verification_uri"],
      d.get("interval", 5))')"

printf "\n\033[1;36m▸ Approve this request\033[0m\n"
printf "  open    %s\n" "$VERIFY_URI"
printf "  code    \033[1m%s\033[0m\n" "$USER_CODE"
printf "  sign in as an administrator, then approve.\n\n"
printf "  waiting"

TOKEN=""
# device_code lifetime is 10 minutes by default; stop well inside it.
deadline=$(( $(date -u +%s) + 300 ))
while [ -z "$TOKEN" ] && [ "$(date -u +%s)" -lt "$deadline" ]; do
    sleep "$INTERVAL"
    printf '.'
    response="$(curl -s $CURL_OPTS -X POST "$BASE/connect/token" \
        -d grant_type=urn:ietf:params:oauth:grant-type:device_code \
        -d "client_id=$CLI_CLIENT" -d "device_code=$DEVICE_CODE")"

    TOKEN="$(printf '%s' "$response" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
# authorization_pending and slow_down mean "keep waiting"; anything else is fatal.
if d.get("error") in ("authorization_pending", "slow_down"):
    sys.exit(0)
if "access_token" in d:
    print(d["access_token"]); sys.exit(0)
sys.stderr.write(d.get("error_description") or d.get("error") or "unknown error")
sys.exit(3)' 2>/tmp/device-error)" || {
        printf '\n'
        die "device authorization failed: $(cat /tmp/device-error)"
    }
done
printf '\n'

[ -n "$TOKEN" ] || die "timed out waiting for approval."

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
