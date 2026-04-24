#!/usr/bin/env sh
# Cargo test runner for Unix targets.
#
# Wraps each test binary in a user+network namespace (via `unshare -Urn`)
# so TUN-device tests work without sudo, and brings the namespace's
# loopback interface up so tests that bind to ::1 / 127.0.0.1 still work.
#
# On environments where unprivileged user namespaces are blocked (e.g.
# GitHub Actions ubuntu-latest with AppArmor restrictions), fall back to
# running the test binary directly — TUN tests are `#[ignore]` anyway.
if unshare -Urn true 2>/dev/null; then
    exec unshare -Urn sh -c 'ip link set lo up; exec "$@"' _ "$@"
else
    exec "$@"
fi
