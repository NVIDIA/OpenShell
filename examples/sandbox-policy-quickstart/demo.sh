#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Sandbox Policy Quickstart — automated demo
#
# Runs the full walkthrough non-interactively:
#   1. Creates a sandbox with default-deny networking
#   2. Attempts a request (denied)
#   3. Applies a read-only GitHub API policy
#   4. Retries the request (allowed)
#   5. Attempts a POST (blocked by L7)
#   6. Shows logs and cleans up
#
# Usage: bash examples/sandbox-policy-quickstart/demo.sh

set -euo pipefail

SANDBOX_NAME="policy-demo"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_FILE="${SCRIPT_DIR}/policy.yaml"
SSH_CONFIG=$(mktemp)

cleanup() {
    rm -f "$SSH_CONFIG"
    printf '\n'
    step "Cleaning up"
    openshell sandbox delete "$SANDBOX_NAME" 2>/dev/null || true
}
trap cleanup EXIT

BOLD='\033[1m'
DIM='\033[2m'
CYAN='\033[36m'
GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
MAGENTA='\033[35m'
RESET='\033[0m'

STEP_PAUSE="${DEMO_PAUSE:-1}"

step() {
    sleep "$STEP_PAUSE"
    printf "\n${BOLD}${CYAN}▸ %s${RESET}\n\n" "$1"
}

run() {
    printf "  ${BOLD}\$ %s${RESET}\n" "$*"
    "$@" 2>&1 | sed 's/^/  /'
    return "${PIPESTATUS[0]}"
}

colorize_logs() {
    sed \
        -e "s/action=deny/$(printf '\033[1;31m')action=deny$(printf '\033[0m')/g" \
        -e "s/action=allow/$(printf '\033[1;32m')action=allow$(printf '\033[0m')/g" \
        -e "s/dst_host=[^ ]*/$(printf '\033[36m')&$(printf '\033[0m')/g" \
        -e "s/dst_port=[^ ]*/$(printf '\033[36m')&$(printf '\033[0m')/g" \
        -e "s/binary=[^ ]*/$(printf '\033[1m')&$(printf '\033[0m')/g" \
        -e "s/reason=[^\"]*/$(printf '\033[33m')&$(printf '\033[0m')/g" \
        -e "s/policy=[^ ]*/$(printf '\033[35m')&$(printf '\033[0m')/g" \
        -e "s/\[CONNECT\]/$(printf '\033[1m')[CONNECT]$(printf '\033[0m')/g" \
        -e "s/\[FORWARD\]/$(printf '\033[1m')[FORWARD]$(printf '\033[0m')/g"
}

sandbox_exec() {
    ssh -F "$SSH_CONFIG" "$SSH_HOST" "$@" 2>&1
}

wait_for_ssh() {
    local retries=15
    for i in $(seq 1 "$retries"); do
        if ssh -F "$SSH_CONFIG" "$SSH_HOST" true >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
    done
    printf "  ${RED}✗ SSH connection to sandbox timed out${RESET}\n"
    exit 1
}

# ------------------------------------------------------------------

step "1/7  Creating sandbox \"${SANDBOX_NAME}\" (default-deny networking)"
run openshell sandbox create \
    --name "$SANDBOX_NAME" \
    --keep \
    --no-auto-providers \
    --no-tty \
    -- echo "sandbox ready"

step "Connecting to sandbox"
openshell sandbox ssh-config "$SANDBOX_NAME" > "$SSH_CONFIG"
SSH_HOST=$(awk '/^Host / { print $2; exit }' "$SSH_CONFIG")
wait_for_ssh

# ------------------------------------------------------------------

step "2/7  Attempting to reach api.github.com — should be DENIED"
printf "  ${BOLD}\$ curl -sS https://api.github.com/zen${RESET}\n"
if sandbox_exec curl -sSf --max-time 5 https://api.github.com/zen 2>&1 | sed 's/^/  /'; then
    printf "  ${RED}✗ Expected request to be denied, but it succeeded.${RESET}\n"
    exit 1
fi
printf "  ${RED}✗ Blocked by default-deny policy.${RESET}\n"

# ------------------------------------------------------------------

step "3/7  Checking deny log"
sleep 2
printf "  ${BOLD}\$ openshell logs ${SANDBOX_NAME} --since 1m -n 10${RESET}\n"
openshell logs "$SANDBOX_NAME" --since 1m -n 10 2>&1 \
    | grep -i 'connect\|forward\|deny\|allow' \
    | colorize_logs \
    | sed 's/^/  /'

# ------------------------------------------------------------------

step "4/7  Applying read-only GitHub API policy"
printf "  Policy file: %s\n\n" "$POLICY_FILE"
run openshell policy set "$SANDBOX_NAME" \
    --policy "$POLICY_FILE" \
    --wait

# ------------------------------------------------------------------

step "5/7  Retrying GET — should be ALLOWED"
sleep 1
printf "  ${BOLD}\$ curl -sS https://api.github.com/zen${RESET}\n"
ZEN=$(sandbox_exec curl -sS --max-time 10 https://api.github.com/zen)
printf "  ${GREEN}%s${RESET}\n" "$ZEN"

printf '\n'
printf "  ${BOLD}\$ curl -sS https://api.github.com/octocat${RESET}\n"
sandbox_exec curl -sS --max-time 10 https://api.github.com/octocat | sed 's/^/  /'

# ------------------------------------------------------------------

step "6/7  Attempting POST — should be BLOCKED by L7"
printf "  ${BOLD}\$ curl -sS -X POST https://api.github.com/repos/octocat/hello-world/issues -d '{\"title\":\"oops\"}'${RESET}\n"
RESPONSE=$(sandbox_exec curl -sS --max-time 10 -X POST \
    https://api.github.com/repos/octocat/hello-world/issues \
    -H "Content-Type: application/json" \
    -d '{"title":"oops"}')
printf "  ${YELLOW}%s${RESET}\n" "$RESPONSE"

# ------------------------------------------------------------------

step "7/7  Checking L7 deny log"
sleep 2
printf "  ${BOLD}\$ openshell logs ${SANDBOX_NAME} --level warn --since 1m -n 10${RESET}\n"
openshell logs "$SANDBOX_NAME" --level warn --since 1m -n 10 2>&1 \
    | grep -i 'connect\|forward\|deny\|allow\|l7\|rest' \
    | colorize_logs \
    | sed 's/^/  /'

# ------------------------------------------------------------------

printf "\n${BOLD}${GREEN}✓ Demo complete.${RESET}\n\n"
printf "  What you saw:\n"
printf "    1. Default deny  — minimal outbound access, explicit approval required\n"
printf "    2. L7 read-only  — GET allowed, POST blocked at the HTTP method level\n"
printf "    3. Audit trail   — every request logged with method, path, and decision\n\n"
printf "  The policy is %s lines of YAML.\n" "$(wc -l < "$POLICY_FILE" | tr -d ' ')"
