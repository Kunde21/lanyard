#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFORMANCE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

UPSTREAM_REPO="${UPSTREAM_REPO:-https://gitlab.com/openid/conformance-suite.git}"
UPSTREAM_TAG="${UPSTREAM_TAG:-release-v5.1.39}"
IMAGE_NAME="${SUITE_IMAGE:-lanyard-conformance-suite:${UPSTREAM_TAG}}"

UPSTREAM_DIR="${CONFORMANCE_DIR}/.upstream/conformance-suite"
MAVEN_CACHE_DIR="${CONFORMANCE_DIR}/.cache/m2"

mkdir -p "${CONFORMANCE_DIR}/.upstream"
mkdir -p "${MAVEN_CACHE_DIR}"

if [ ! -d "${UPSTREAM_DIR}/.git" ]; then
	echo "==> Cloning upstream suite repository"
	git clone "${UPSTREAM_REPO}" "${UPSTREAM_DIR}"
fi

echo "==> Fetching upstream tags"
git -C "${UPSTREAM_DIR}" fetch --tags --prune origin

echo "==> Checking out ${UPSTREAM_TAG}"
git -C "${UPSTREAM_DIR}" checkout --detach "${UPSTREAM_TAG}"

echo "==> Building suite jar with upstream builder-compose.yml"
MAVEN_CACHE="${MAVEN_CACHE_DIR}" docker compose -f "${UPSTREAM_DIR}/builder-compose.yml" run --rm builder

if [ ! -f "${UPSTREAM_DIR}/target/fapi-test-suite.jar" ]; then
	echo "Build did not produce target/fapi-test-suite.jar" >&2
	exit 1
fi

echo "==> Building local Docker image ${IMAGE_NAME}"
docker build -t "${IMAGE_NAME}" "${UPSTREAM_DIR}"

cat <<EOF

Suite image build complete.
  Upstream tag: ${UPSTREAM_TAG}
  Local image:  ${IMAGE_NAME}

Start the stack with:
  SUITE_IMAGE=${IMAGE_NAME} docker compose -f conformance/docker-compose.yml up -d
EOF
