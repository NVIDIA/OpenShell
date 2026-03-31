#!/bin/sh

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Smoke test for cluster-entrypoint.sh k3s flag construction.
#
# Validates that the flags the entrypoint passes to k3s are accepted by the
# k3s binary bundled in the cluster image. The entrypoint appends flags after
# "$@" (the container CMD), so when CMD is empty (bare `docker run`) the
# flags become top-level k3s args — which k3s rejects. This test ensures:
#   1. The entrypoint uses --kubelet-arg=resolv-conf= (works in all positions)
#   2. The Dockerfile provides a default CMD ["server"] as a safety net
#
# See: https://github.com/NVIDIA/OpenShell/issues/696
#
# Usage:
#   docker run --rm --entrypoint sh <cluster-image> /usr/local/bin/test-cluster-entrypoint.sh
#
# Or during local development:
#   mise run docker:build:cluster && docker run --rm --entrypoint sh openshell/cluster:dev /usr/local/bin/test-cluster-entrypoint.sh

set -eu

PASS=0
FAIL=0

assert_ok() {
    desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        PASS=$((PASS + 1))
        echo "  PASS: $desc"
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL: $desc"
        echo "        command: $*"
    fi
}

assert_fail() {
    desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        FAIL=$((FAIL + 1))
        echo "  FAIL: $desc (expected failure but got success)"
        echo "        command: $*"
    else
        PASS=$((PASS + 1))
        echo "  PASS: $desc"
    fi
}

echo "=== cluster-entrypoint.sh smoke tests ==="
echo ""

# ---------------------------------------------------------------------------
# 1. k3s binary exists and is executable
# ---------------------------------------------------------------------------
echo "--- k3s binary ---"
assert_ok "k3s binary exists" test -x /bin/k3s

# ---------------------------------------------------------------------------
# 2. k3s help works (sanity check)
# ---------------------------------------------------------------------------
echo "--- k3s help ---"
assert_ok "k3s --help succeeds" /bin/k3s --help
assert_ok "k3s server --help succeeds" /bin/k3s server --help

# ---------------------------------------------------------------------------
# 3. k3s flag compatibility for resolv-conf
# ---------------------------------------------------------------------------
echo "--- resolv-conf flag ---"

# --kubelet-arg=resolv-conf= works regardless of CMD position
assert_ok "k3s server accepts --kubelet-arg=resolv-conf" \
    sh -c '/bin/k3s server --kubelet-arg=resolv-conf=/tmp/test --help 2>&1 | grep -q "USAGE"'

# --resolv-conf works as a server subcommand flag (the historical path)
assert_ok "k3s server accepts --resolv-conf after server subcommand" \
    sh -c '/bin/k3s server --resolv-conf=/tmp/test --help 2>&1 | grep -q "USAGE"'

# --resolv-conf as a TOP-LEVEL flag (before server) is rejected by k3s.
# This is the failure mode when CMD is empty (bare `docker run`).
assert_fail "k3s rejects --resolv-conf as top-level flag (before server)" \
    sh -c '/bin/k3s --resolv-conf=/tmp/test 2>&1 | grep -q "USAGE"'

# ---------------------------------------------------------------------------
# 4. Entrypoint script exists and is executable
# ---------------------------------------------------------------------------
echo "--- entrypoint script ---"
assert_ok "entrypoint script exists" test -x /usr/local/bin/cluster-entrypoint.sh
assert_ok "healthcheck script exists" test -x /usr/local/bin/cluster-healthcheck.sh

# ---------------------------------------------------------------------------
# 5. Entrypoint uses --kubelet-arg=resolv-conf (not --resolv-conf)
# ---------------------------------------------------------------------------
echo "--- entrypoint flag format ---"
assert_ok "entrypoint uses --kubelet-arg=resolv-conf" \
    grep -q -- '--kubelet-arg=resolv-conf=' /usr/local/bin/cluster-entrypoint.sh

assert_fail "entrypoint does NOT use bare --resolv-conf flag" \
    grep -qE '^\s*exec.* --resolv-conf=' /usr/local/bin/cluster-entrypoint.sh

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
TOTAL=$((PASS + FAIL))
echo "=== Results: ${PASS}/${TOTAL} passed ==="

if [ "$FAIL" -gt 0 ]; then
    echo "FAILED: $FAIL test(s) failed"
    exit 1
fi

echo "OK"
exit 0
