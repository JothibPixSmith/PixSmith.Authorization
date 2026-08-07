#!/usr/bin/env bash
#
# Generates one operator provisioning keypair (ECDSA P-256).
#
# Run this on the holder's own machine — ideally offline, ideally onto removable media or a
# hardware token. The private key must never be copied to the server, committed, or pasted
# into a chat. The server only ever receives the public half printed at the end.
#
# Usage:  ./provision-keygen.sh <key-id> <holder name>
# Example: ./provision-keygen.sh ops-alice "Alice Nguyen"
#
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: $0 <key-id> <holder name>" >&2
  exit 1
fi

KEY_ID="$1"; shift
HOLDER="$*"
PRIVATE="${KEY_ID}.key"
PUBLIC="${KEY_ID}.pub"

if [ -e "$PRIVATE" ]; then
  echo "Refusing to overwrite existing $PRIVATE" >&2
  exit 1
fi

umask 077
openssl ecparam -name prime256v1 -genkey -noout -out "$PRIVATE"
openssl ec -in "$PRIVATE" -pubout -out "$PUBLIC" 2>/dev/null
chmod 400 "$PRIVATE"

echo
echo "Private key: $PRIVATE  (mode 400 — keep offline, never share)"
echo "Public key:  $PUBLIC"
echo
echo "Add this entry to the server's TenantProvisioning:Keys configuration:"
echo
python3 - "$KEY_ID" "$HOLDER" "$PUBLIC" <<'PY'
import json, sys
key_id, holder, pub_path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(pub_path) as f:
    pub = f.read().strip()
print(json.dumps({"KeyId": key_id, "Holder": holder, "PublicKey": pub}, indent=2))
PY
