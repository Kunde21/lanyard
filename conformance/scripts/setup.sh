#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFORMANCE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CERT_DIR="${CONFORMANCE_DIR}/certs"
REPO_ROOT="$(cd "${CONFORMANCE_DIR}/.." && pwd)"

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

echo "==> Exporting mkcert root CA for containers"
CAROOT="$(mkcert -CAROOT)"
if [ ! -f "${CAROOT}/rootCA.pem" ]; then
	echo "mkcert root CA not found at ${CAROOT}/rootCA.pem" >&2
	exit 1
fi
cp "${CAROOT}/rootCA.pem" "${CERT_DIR}/mkcert-rootCA.pem"

echo "==> Generating certificate for suite.localhost"
mkcert \
	-cert-file "${CERT_DIR}/suite.localhost.pem" \
	-key-file "${CERT_DIR}/suite.localhost-key.pem" \
	suite.localhost

echo "==> Generating certificate for rp.localhost"
mkcert \
	-cert-file "${CERT_DIR}/rp.localhost.pem" \
	-key-file "${CERT_DIR}/rp.localhost-key.pem" \
	rp.localhost

echo "==> Generating FAPI2 test key material"

# Build the key generation tool if needed
if [ ! -f "${REPO_ROOT}/genfapikeys" ]; then
	echo "    Building key generator..."
	go build -o "${REPO_ROOT}/genfapikeys" "${REPO_ROOT}/cmd/genfapikeys"
fi

"${REPO_ROOT}/genfapikeys" -certs-dir "${CERT_DIR}"

echo "==> Done. Certificates and keys are in conformance/certs/."
echo "==> Note: *.localhost domains resolve automatically to 127.0.0.1 (no /etc/hosts modification needed)"
