#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFORMANCE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CERT_DIR="${CONFORMANCE_DIR}/certs"

if ! command -v mkcert >/dev/null 2>&1; then
	cat <<'EOF'
mkcert was not found in PATH.

Install mkcert first, then re-run this script.
Example (Ubuntu):
  sudo apt install libnss3-tools
  brew install mkcert
EOF
	exit 1
fi

mkdir -p "${CERT_DIR}"

echo "==> Installing/updating local mkcert CA trust"
mkcert -install

echo "==> Generating certificate for suite.test"
mkcert \
	-cert-file "${CERT_DIR}/suite.test.pem" \
	-key-file "${CERT_DIR}/suite.test-key.pem" \
	suite.test

echo "==> Generating certificate for rp.test"
mkcert \
	-cert-file "${CERT_DIR}/rp.test.pem" \
	-key-file "${CERT_DIR}/rp.test-key.pem" \
	rp.test

cat <<'EOF'

Required /etc/hosts entries:
  127.0.0.1 suite.test
  127.0.0.1 rp.test

Add these entries manually if they are not already present.
EOF

echo "==> Done. Certificates are in conformance/certs/."
