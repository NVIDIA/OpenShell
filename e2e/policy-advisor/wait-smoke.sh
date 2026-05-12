#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Wire-contract regression for policy.local's /wait endpoint.
#
# This is NOT a tutorial — read examples/agent-driven-policy-management/demo.sh
# (and its README) for the narrated end-to-end story with a real LLM agent.
# This script is the cheap, deterministic, no-LLM check that the underlying
# contract still holds. Pair this with a unit test diff to catch regressions
# in the gateway+supervisor integration path that the unit tests can't reach.
#
# What it pins down:
#   - Flow A — submit → /wait blocks → host approves → /wait returns
#              status=approved within seconds. Proves the wait-and-wake
#              path of the agent feedback loop.
#   - Flow B — submit → /wait blocks → host rejects with --reason "..."
#              → /wait returns status=rejected AND the reviewer's exact
#              free-form text comes back in rejection_reason. Proves the
#              revise-and-resubmit path's wire contract.
#
# What it deliberately doesn't do:
#   - No LLM (Codex) — proposals are synthetic JSON crafted by curl. The
#     real agent's prompt-following is the demo's concern, not this one.
#   - No outbound traffic — host is `example.invalid`. We never make a real
#     GitHub or HTTP call. Only policy.local and the gateway gRPC.
#   - No prover badge / TUI assertions (out of scope for this regression;
#     see the prover-validation and TUI-inbox work).
#
# Prereqs:
#   - A running gateway and the openshell CLI built from this branch.
#     The simplest local path is `mise run helm:skaffold:run`, then
#     `cargo build -p openshell-cli` and start the port-forward with its
#     output redirected so kubectl's "Handling connection for 8090" lines
#     don't bleed into your terminal:
#       KUBECONFIG=kubeconfig kubectl -n openshell \
#           port-forward svc/openshell 8090:8080 >/dev/null 2>&1 &
#   - The agent-proposals feature flag enabled. Run once:
#       openshell settings set --global \
#           --key agent_policy_proposals_enabled --value true --yes
#
# Runs in ~10s on a warm cluster (most of which is sandbox SSH bring-up).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUNNER_SOURCE="${SCRIPT_DIR}/sandbox-runner.sh"

if [[ -z "${OPENSHELL_BIN:-}" ]]; then
    if [[ -x "${REPO_ROOT}/target/debug/openshell" ]]; then
        OPENSHELL_BIN="${REPO_ROOT}/target/debug/openshell"
    else
        OPENSHELL_BIN="openshell"
    fi
fi

RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
SANDBOX="${SANDBOX:-policy-wait-smoke-${RUN_ID}}"
KEEP_SANDBOX="${KEEP_SANDBOX:-0}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-30}"

BOLD='\033[1m'
DIM='\033[2m'
CYAN='\033[36m'
GREEN='\033[32m'
RED='\033[31m'
RESET='\033[0m'

step() { printf "\n${BOLD}${CYAN}==> %s${RESET}\n\n" "$1"; }
info() { printf "  %b\n" "$*"; }
fail() { printf "\n${RED}FAIL:${RESET} %s\n" "$*" >&2; exit 1; }
ok() { printf "  ${GREEN}✓${RESET} %s\n" "$*"; }

TMP_DIR=""
SSH_CONFIG=""
SSH_HOST=""

cleanup() {
    local status=$?
    if [[ "$KEEP_SANDBOX" != "1" ]]; then
        "$OPENSHELL_BIN" sandbox delete "$SANDBOX" >/dev/null 2>&1 || true
    fi
    if [[ -n "$TMP_DIR" && $status -eq 0 ]]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

preflight() {
    step "Preflight"
    command -v jq >/dev/null || fail "jq is required"
    command -v ssh >/dev/null || fail "ssh is required"
    [[ -f "$RUNNER_SOURCE" ]] || fail "missing $RUNNER_SOURCE"

    # Capture stderr so a CLI failure (gateway unreachable, no current
    # gateway configured, etc.) surfaces a real error instead of an empty
    # pipeline that `set -euo pipefail` silently exits on.
    local raw_settings
    if ! raw_settings="$("$OPENSHELL_BIN" settings get --global --json 2>&1)"; then
        fail "openshell could not reach the gateway. CLI output:
${raw_settings}

If you just deployed via skaffold, you probably still need:
  KUBECONFIG=kubeconfig kubectl -n openshell port-forward svc/openshell 8090:8080 &
  $OPENSHELL_BIN gateway add http://localhost:8090 --name local
  $OPENSHELL_BIN gateway select local
  unset OPENSHELL_GATEWAY  # if the CLI warns about it overriding"
    fi
    local enabled
    enabled="$(printf '%s' "$raw_settings" \
        | jq -r '.settings.agent_policy_proposals_enabled // "<unset>"')"
    if [[ "$enabled" != "true" ]]; then
        fail "agent_policy_proposals_enabled must be true. Run:
  $OPENSHELL_BIN settings set --global --key agent_policy_proposals_enabled --value true --yes"
    fi
    ok "agent_policy_proposals_enabled=true"
}

create_sandbox() {
    step "Creating sandbox '${SANDBOX}'"
    TMP_DIR="$(mktemp -d)"
    SSH_CONFIG="${TMP_DIR}/ssh_config"

    "$OPENSHELL_BIN" sandbox delete "$SANDBOX" >/dev/null 2>&1 || true
    "$OPENSHELL_BIN" sandbox create \
        --name "$SANDBOX" \
        --upload "${RUNNER_SOURCE}:/sandbox/runner.sh" \
        --no-git-ignore \
        --keep \
        --no-auto-providers \
        --no-tty \
        -- bash -lc "chmod +x /sandbox/runner.sh && echo sandbox ready" \
        | sed 's/^/  /'

    "$OPENSHELL_BIN" sandbox ssh-config "$SANDBOX" > "$SSH_CONFIG"
    SSH_HOST="$(awk '/^Host / { print $2; exit }' "$SSH_CONFIG")"
    [[ -n "$SSH_HOST" ]] || fail "could not parse SSH config"

    local _i
    for _i in $(seq 1 30); do
        if ssh -F "$SSH_CONFIG" "$SSH_HOST" true >/dev/null 2>&1; then
            ok "SSH up"
            return
        fi
        sleep 2
    done
    fail "SSH connection timed out"
}

in_sandbox() { ssh -F "$SSH_CONFIG" "$SSH_HOST" "$@"; }
http_status() { awk -F= '/^HTTP_STATUS=/ { print $2; exit }'; }
http_body() { sed '/^HTTP_STATUS=/d'; }

submit() {
    local rule_id="$1"
    local out
    out="$(in_sandbox /sandbox/runner.sh submit-test-proposal "$rule_id")"
    [[ "$(printf '%s\n' "$out" | http_status)" == "202" ]] \
        || { printf '%s\n' "$out" >&2; fail "submit returned non-202"; }
    printf '%s\n' "$out" | http_body | jq -r '.accepted_chunk_ids[0]'
}

run_flow_a_approve() {
    step "Flow A — approve-and-retry"
    local chunk_id
    chunk_id="$(submit "alpha")"
    info "submitted, chunk_id=${DIM}${chunk_id}${RESET}"

    # Kick off /wait in background, capture wall-clock time to settle.
    local wait_out_file="${TMP_DIR}/wait_a.out"
    local started_at finished_at elapsed
    started_at="$(date +%s.%N)"
    in_sandbox /sandbox/runner.sh proposal-wait "$chunk_id" "$WAIT_TIMEOUT" \
        > "$wait_out_file" &
    local wait_pid=$!

    # Brief settle so the in-sandbox wait registers before we approve.
    sleep 0.3
    info "approving from host..."
    "$OPENSHELL_BIN" rule approve "$SANDBOX" --chunk-id "$chunk_id" \
        | sed 's/^/    /'

    wait "$wait_pid" || fail "in-sandbox /wait exited non-zero"
    finished_at="$(date +%s.%N)"
    elapsed="$(awk -v s="$started_at" -v f="$finished_at" 'BEGIN { printf "%.2f", f - s }')"

    local body
    body="$(http_body < "$wait_out_file")"
    [[ "$(printf '%s\n' "$body" | jq -r '.status')" == "approved" ]] \
        || { printf '%s\n' "$body" >&2; fail "Flow A: /wait did not return approved"; }
    [[ "$(printf '%s\n' "$body" | jq -r '.rejection_reason')" == "" ]] \
        || fail "Flow A: rejection_reason should be empty on approve"
    # policy_reloaded must be present on every approved response and must
    # be true once the supervisor has loaded the merged policy. A false
    # here would mean the agent is being told "go ahead and retry" when
    # the rule isn't actually in effect — exactly the regression John's
    # review caught.
    [[ "$(printf '%s\n' "$body" | jq -r '.policy_reloaded')" == "true" ]] \
        || { printf '%s\n' "$body" >&2; fail "Flow A: policy_reloaded should be true on approve"; }

    ok "/wait returned status=approved, policy_reloaded=true in ${elapsed}s"
}

run_flow_b_reject() {
    step "Flow B — reject-with-guidance"
    local chunk_id
    chunk_id="$(submit "beta")"
    info "submitted, chunk_id=${DIM}${chunk_id}${RESET}"

    local guidance="scope to docs/ paths only, not the whole repo"
    local wait_out_file="${TMP_DIR}/wait_b.out"
    local started_at finished_at elapsed
    started_at="$(date +%s.%N)"
    in_sandbox /sandbox/runner.sh proposal-wait "$chunk_id" "$WAIT_TIMEOUT" \
        > "$wait_out_file" &
    local wait_pid=$!

    sleep 0.3
    info "rejecting from host with --reason..."
    "$OPENSHELL_BIN" rule reject "$SANDBOX" \
        --chunk-id "$chunk_id" \
        --reason "$guidance" \
        | sed 's/^/    /'

    wait "$wait_pid" || fail "in-sandbox /wait exited non-zero"
    finished_at="$(date +%s.%N)"
    elapsed="$(awk -v s="$started_at" -v f="$finished_at" 'BEGIN { printf "%.2f", f - s }')"

    local body received_reason
    body="$(http_body < "$wait_out_file")"
    [[ "$(printf '%s\n' "$body" | jq -r '.status')" == "rejected" ]] \
        || { printf '%s\n' "$body" >&2; fail "Flow B: /wait did not return rejected"; }
    received_reason="$(printf '%s\n' "$body" | jq -r '.rejection_reason')"
    [[ "$received_reason" == "$guidance" ]] \
        || fail "Flow B: rejection_reason mismatch.
  sent:     $guidance
  received: $received_reason"

    ok "/wait returned status=rejected in ${elapsed}s"
    ok "rejection_reason round-tripped exactly: \"${received_reason}\""
}

main() {
    preflight
    create_sandbox
    run_flow_a_approve
    run_flow_b_reject
    step "Smoke pass"
}

main "$@"
