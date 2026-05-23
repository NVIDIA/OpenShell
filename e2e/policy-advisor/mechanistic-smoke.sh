#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Regression smoke for the mechanistic policy mapper.
#
# Triggers an L4 CONNECT deny from inside a sandbox, waits for the denial
# aggregator to flush, and asserts that a pending mechanistic chunk appears
# under `openshell rule get --status pending`.
#
# This is deliberately L4-only. L7 denials (method/path 403s) are the agent
# loop's job; the mechanistic mapper only covers L4 CONNECT denials. See #1333.
#
# Prereqs: a running gateway with agent_policy_proposals_enabled=true.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ -z "${OPENSHELL_BIN:-}" ]]; then
    if [[ -x "${REPO_ROOT}/target/debug/openshell" ]]; then
        OPENSHELL_BIN="${REPO_ROOT}/target/debug/openshell"
    else
        OPENSHELL_BIN="openshell"
    fi
fi

RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
SANDBOX="${SANDBOX:-mechanistic-smoke-${RUN_ID}}"
KEEP_SANDBOX="${KEEP_SANDBOX:-0}"
# Allow override so CI can set a shorter interval via OPENSHELL_DENIAL_FLUSH_INTERVAL_SECS.
FLUSH_WAIT="${FLUSH_WAIT:-15}"

BOLD='\033[1m'
CYAN='\033[36m'
GREEN='\033[32m'
RED='\033[31m'
RESET='\033[0m'

step() { printf "\n${BOLD}${CYAN}==> %s${RESET}\n\n" "$1"; }
ok()   { printf "  ${GREEN}✓${RESET} %s\n" "$*"; }
fail() { printf "\n${RED}FAIL:${RESET} %s\n" "$*" >&2; exit 1; }

TMP_DIR=""

cleanup() {
    if [[ "$KEEP_SANDBOX" != "1" ]]; then
        "$OPENSHELL_BIN" sandbox delete "$SANDBOX" >/dev/null 2>&1 || true
    fi
    [[ -z "$TMP_DIR" ]] || rm -rf "$TMP_DIR"
}
trap cleanup EXIT

preflight() {
    step "Preflight"
    local raw_settings
    if ! raw_settings="$("$OPENSHELL_BIN" settings get --global --json 2>&1)"; then
        fail "cannot reach gateway: ${raw_settings}"
    fi
    local enabled
    enabled="$(printf '%s' "$raw_settings" \
        | jq -r '.settings.agent_policy_proposals_enabled // "<unset>"')"
    [[ "$enabled" == "true" ]] \
        || fail "set agent_policy_proposals_enabled=true first:
  $OPENSHELL_BIN settings set --global --key agent_policy_proposals_enabled --value true --yes"
    ok "agent_policy_proposals_enabled=true"
}

create_sandbox() {
    step "Creating sandbox '${SANDBOX}' (no network policy)"
    TMP_DIR="$(mktemp -d)"
    SSH_CONFIG="${TMP_DIR}/ssh_config"

    "$OPENSHELL_BIN" sandbox delete "$SANDBOX" >/dev/null 2>&1 || true
    "$OPENSHELL_BIN" sandbox create \
        --name "$SANDBOX" \
        --no-auto-providers \
        --no-tty \
        --keep \
        -- bash -lc "echo sandbox ready" \
        | sed 's/^/  /'

    "$OPENSHELL_BIN" sandbox ssh-config "$SANDBOX" > "$SSH_CONFIG"
    SSH_HOST="$(awk '/^Host / { print $2; exit }' "$SSH_CONFIG")"
    [[ -n "$SSH_HOST" ]] || fail "could not parse SSH host"

    for _i in $(seq 1 30); do
        ssh -F "$SSH_CONFIG" "$SSH_HOST" true >/dev/null 2>&1 && { ok "SSH up"; return; }
        sleep 2
    done
    fail "SSH timed out"
}

trigger_l4_deny() {
    step "Triggering L4 CONNECT deny from inside sandbox"
    # blocked.invalid is guaranteed unroutable and not in any policy.
    ssh -F "$SSH_CONFIG" "$SSH_HOST" \
        "curl -sf --max-time 5 https://blocked.invalid/ || true" >/dev/null 2>&1 || true
    ok "curl attempted (deny expected)"
}

assert_pending_chunk() {
    step "Waiting ${FLUSH_WAIT}s then checking for pending chunk"
    sleep "$FLUSH_WAIT"
    local output
    output="$("$OPENSHELL_BIN" rule get "$SANDBOX" --status pending 2>&1)"
    printf '%s\n' "$output" | sed 's/^/  /'
    printf '%s\n' "$output" | grep -qi "blocked.invalid" \
        || fail "no pending chunk for blocked.invalid"
    ok "pending mechanistic chunk present for blocked.invalid"
}

main() {
    command -v jq >/dev/null || fail "jq is required"
    preflight
    create_sandbox
    trigger_l4_deny
    assert_pending_chunk
    step "Smoke pass"
}

main "$@"
