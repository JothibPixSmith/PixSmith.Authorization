#!/usr/bin/env bash
#
# debug/provision.sh, aimed at the staging stack: its HTTPS address, its own provisioning
# keys and admin password from staging/secrets/, and its self-signed TLS certificate.
#
# Usage is identical:
#   ./staging/provision.sh create '{"name":"Acme Corp","description":"Test tenancy"}'
#   ./staging/provision.sh delete <tenant-id>
#
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
SECRETS="$PWD/staging/secrets"

[ -f "$SECRETS/admin-password" ] || { echo "no staging secrets — run ./staging/start.sh first." >&2; exit 1; }

export PROVISION_BASE_URI=https://localhost:8443
export PROVISION_KEY_DIR="$SECRETS/keys"
export PROVISION_SIGNERS="${PROVISION_SIGNERS:-staging-alice staging-bob}"
export PROVISION_ADMIN_EMAIL=admin@pixsmith.local
PROVISION_ADMIN_PASSWORD="$(cat "$SECRETS/admin-password")"
export PROVISION_ADMIN_PASSWORD
export CURL_CA_BUNDLE="$SECRETS/tls.crt"   # curl's own variable; trusts the self-signed cert

exec ./debug/provision.sh "$@"
