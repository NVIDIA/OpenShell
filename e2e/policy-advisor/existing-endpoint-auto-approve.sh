#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Regression for #2821: a curl denial on cargo's inspected endpoint must
# become a compatible binary expansion, auto-approve, hot-reload, and retain
# the REST/read-only endpoint contract.

set -euo pipefail
export NO_COLOR=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OPENSHELL_BIN="${OPENSHELL_BIN:-${REPO_ROOT}/target/debug/openshell}"
RUN_ID="${RUN_ID:-$(date +%H%M%S)}"
SANDBOX="${SANDBOX:-advisor-2821-${RUN_ID}}"
FLUSH_WAIT="${FLUSH_WAIT:-45}"
TMP_DIR="$(mktemp -d)"

strip_ansi() {
    sed $'s/\033\\[[0-9;]*m//g'
}

cleanup() {
    "$OPENSHELL_BIN" sandbox delete "$SANDBOX" >/dev/null 2>&1 || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cat > "${TMP_DIR}/policy.yaml" <<'EOF'
version: 1
network_policies:
  cargo_registry:
    name: cargo-registry
    endpoints:
      - host: index.crates.io
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
    binaries:
      - path: /usr/bin/cargo
EOF

"$OPENSHELL_BIN" sandbox create \
    --name "$SANDBOX" \
    --policy "${TMP_DIR}/policy.yaml" \
    --approval-mode auto \
    --no-auto-providers \
    --no-tty \
    --detach \
    -- sh -c "exec sleep infinity" >/dev/null

set +e
DENY_OUTPUT="$($OPENSHELL_BIN sandbox exec --name "$SANDBOX" -- \
    /usr/bin/curl -fsS --max-time 10 https://index.crates.io/config.json 2>&1)"
DENY_STATUS=$?
set -e
if [[ "$DENY_STATUS" -eq 0 ]]; then
    echo "expected the first curl request to be denied" >&2
    exit 1
fi
printf '%s\n' "$DENY_OUTPUT"

RULE_OUTPUT=""
for _attempt in $(seq 1 "$((FLUSH_WAIT / 5))"); do
    RULE_OUTPUT="$($OPENSHELL_BIN rule get "$SANDBOX" 2>&1 | strip_ansi)"
    grep -q "Status: approved" <<<"$RULE_OUTPUT" && break
    sleep 5
done

printf '%s\n' "$RULE_OUTPUT"
grep -q "Status: approved" <<<"$RULE_OUTPUT"
grep -q "Rule: cargo_registry" <<<"$RULE_OUTPUT"
grep -q "Prover: prover: no new findings" <<<"$RULE_OUTPUT"
if grep -q "Application:" <<<"$RULE_OUTPUT"; then
    echo "auto-approved chunk unexpectedly retained an application error" >&2
    exit 1
fi

POLICY_OUTPUT="$($OPENSHELL_BIN policy get "$SANDBOX" --full 2>&1 | strip_ansi)"
grep -q "protocol: rest" <<<"$POLICY_OUTPUT"
grep -q "access: read-only" <<<"$POLICY_OUTPUT"
grep -q "/usr/bin/cargo" <<<"$POLICY_OUTPUT"
grep -q "/usr/bin/curl" <<<"$POLICY_OUTPUT"

for _attempt in $(seq 1 15); do
    if "$OPENSHELL_BIN" sandbox exec --name "$SANDBOX" -- \
        /usr/bin/curl -fsS --max-time 15 https://index.crates.io/config.json \
        >/dev/null 2>&1; then
        echo "#2821 existing-endpoint auto-approval regression passed"
        exit 0
    fi
    sleep 2
done

echo "approved policy did not hot-reload for curl" >&2
exit 1
