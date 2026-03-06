#!/bin/bash
set -e

# Run e2e integration tests in an isolated Docker container.
# Nothing touches the host network or filesystem (except Docker image layers).
#
# Usage:
#   ./run-e2e-tests.sh                   # run all e2e tests
#   ./run-e2e-tests.sh test_wg_start_ipv4  # run a specific test

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE_NAME="gotatun-e2e"

echo "Building e2e test image..."
docker build -t "$IMAGE_NAME" -f "$SCRIPT_DIR/Dockerfile.e2e" "$SCRIPT_DIR"

echo "Running e2e tests in isolated container..."

# Detect if host has IPv6 disabled and pass to container
EXTRA_DOCKER_ARGS=""
if [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)" = "1" ]; then
    echo "Host has IPv6 disabled, will skip IPv6 endpoint tests"
    EXTRA_DOCKER_ARGS="-e E2E_SKIP_IPV6_ENDPOINT=1"
fi

docker run --rm --privileged \
    -v /lib/modules:/lib/modules:ro \
    --tmpfs /var/run \
    $EXTRA_DOCKER_ARGS \
    "$IMAGE_NAME" "$@"
