#!/usr/bin/env bash
#
# Signs a tenant-provisioning request with one operator key.
#
# The private key never leaves the machine it lives on. Each holder runs this script
# independently against the SAME nonce, timestamp and body; the resulting signature headers
# are collected and sent together as one request. No single holder can produce a complete
# request alone.
#
# Usage:
#   ./provision-sign.sh <key-id> <private-key.pem> <METHOD> <path> <body-file|-> [nonce] [timestamp]
#
# Example — operator A starts a tenant creation:
#   echo -n '{"name":"Acme Corp","description":"Acme"}' > /tmp/body.json
#   ./provision-sign.sh ops-alice alice.pem POST /api/admin/tenants /tmp/body.json
#
# It prints the nonce and timestamp; operator B signs with those exact values:
#   ./provision-sign.sh ops-bob bob.pem POST /api/admin/tenants /tmp/body.json <nonce> <timestamp>
#
set -euo pipefail

if [ $# -lt 5 ]; then
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
fi

KEY_ID="$1"
KEY_FILE="$2"
METHOD="$(echo "$3" | tr '[:lower:]' '[:upper:]')"
REQ_PATH="$4"
BODY_FILE="$5"
NONCE="${6:-$(head -c 24 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')}"
TIMESTAMP="${7:-$(date -u +%s)}"

if [ "$BODY_FILE" = "-" ]; then
  BODY="$(cat)"
else
  BODY="$(cat "$BODY_FILE")"
fi

# Body hash must be over the exact bytes sent on the wire — no trailing newline, no
# reformatting. Send the request with --data-binary against the same file.
BODY_HASH="$(printf '%s' "$BODY" | openssl dgst -sha256 -hex | awk '{print $NF}')"

# Canonical payload — must match ProvisioningSignature.BuildPayload exactly.
PAYLOAD="$(printf 'PIXSMITH-TENANT-PROVISION-v1\n%s\n%s\n%s\n%s\n%s' \
  "$METHOD" "$REQ_PATH" "$NONCE" "$TIMESTAMP" "$BODY_HASH")"

SIGNATURE="$(printf '%s' "$PAYLOAD" \
  | openssl dgst -sha256 -sign "$KEY_FILE" \
  | openssl base64 -A)"

cat <<EOF
Nonce:     $NONCE
Timestamp: $TIMESTAMP

  Give the nonce and timestamp above to the other signer(s) — every signature on a
  request must cover identical values.

Headers for this signer:

  -H 'X-Provision-Nonce: $NONCE' \\
  -H 'X-Provision-Timestamp: $TIMESTAMP' \\
  -H 'X-Provision-Signature: $KEY_ID:$SIGNATURE'
EOF
