#!/usr/bin/env sh
# Cargo test runner for Unix targets.
#
# Wraps each test binary in a user+network namespace (via `unshare -Urn`)
# so TUN-device tests work without sudo, and brings the namespace's
# loopback interface up so tests that bind to ::1 / 127.0.0.1 still work.
exec unshare -Urn sh -c 'ip link set lo up; exec "$@"' _ "$@"
