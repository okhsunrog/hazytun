#!/bin/bash
set -e

echo "Starting Docker daemon..."
# Use vfs storage driver (works without overlay kernel support)
# Disable iptables (we use container bridge IPs directly, no port mapping needed)
dockerd --storage-driver=vfs --iptables=false &>/var/log/dockerd.log &

# Wait for Docker daemon to be ready
for i in $(seq 1 30); do
    if docker info &>/dev/null; then
        echo "Docker daemon ready."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: Docker daemon failed to start. Logs:"
        cat /var/log/dockerd.log
        exit 1
    fi
    sleep 1
done

echo "Pulling peer test image..."
docker pull vkrasnov/wireguard-test

# Disable IPv6 DAD (Duplicate Address Detection) so bridge addresses
# are immediately usable (DAD can leave addresses in 'tentative' state
# which prevents IPv6 connectivity)
sysctl -w net.ipv6.conf.default.accept_dad=0 2>/dev/null || true
sysctl -w net.ipv6.conf.all.accept_dad=0 2>/dev/null || true

# Create IPv6-capable network for tests that need IPv6 endpoints
docker network create --driver bridge --ipv6 --subnet fd00:e2e::/64 gotatun-e2e 2>/dev/null || true

# Disable bridge-nf-call-iptables so bridge traffic isn't filtered
# (with --iptables=false, Docker doesn't set up FORWARD ACCEPT rules)
sysctl -w net.bridge.bridge-nf-call-iptables=0 2>/dev/null || true
sysctl -w net.bridge.bridge-nf-call-ip6tables=0 2>/dev/null || true

# Export the Docker bridge gateway IP for the test code
# (docker network inspect may return empty Gateway with --iptables=false)
export DOCKER_BRIDGE_GATEWAY=$(ip -4 addr show docker0 | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+')
echo "Docker bridge gateway: $DOCKER_BRIDGE_GATEWAY"

# Remove the unshare runner - we're already root inside the container
# and need real network access for TUN devices and Docker
echo '[target."cfg(unix)"]' > .cargo/config.toml

echo "Running e2e tests..."
cargo test -- --ignored "$@"
