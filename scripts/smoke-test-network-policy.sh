#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# =============================================================================
# Network Policy Smoke Test
# =============================================================================
#
# End-to-end smoke test for sandbox network policies, TLS auto-termination,
# credential injection, and L4/L7 enforcement. Uses GitHub's API as the target.
#
# Prerequisites:
#   - A running OpenShell gateway (`openshell status` shows Healthy)
#   - GITHUB_TOKEN env var set with a valid GitHub personal access token
#   - The `openshell` CLI on PATH
#
# Usage:
#   GITHUB_TOKEN=ghp_xxx ./scripts/smoke-test-network-policy.sh
#
# What it tests:
#
#   Phase 1 — L4 allow/deny (no L7 rules):
#     - L4 allow: curl to api.github.com succeeds (TLS auto-terminated)
#     - L4 deny: curl to httpbin.org is blocked (no matching endpoint)
#
#   Phase 2 — L7 enforcement (method + path rules):
#     - L7 allow: GET /user succeeds (read-only preset allows GET)
#     - L7 deny: POST /user/repos is blocked (read-only preset blocks POST)
#
#   Phase 3 — Credential injection:
#     - GitHub provider attached, curl without explicit auth header
#     - Proxy auto-injects GITHUB_TOKEN via TLS MITM + SecretResolver
#     - Validates authenticated response (not 401)
#
#   Phase 4 — tls: skip escape hatch:
#     - Policy with tls: skip bypasses auto-detection
#     - Credential injection does NOT work (placeholder leaks)
#     - Connection still succeeds at L4 (raw tunnel)
#
# =============================================================================
#
# Embedded Policies (self-contained — no external files needed)
# =============================================================================
#
# --- POLICY_L4_ONLY ---
# L4-only: allow api.github.com:443, deny everything else.
# No protocol/rules/tls fields. TLS auto-terminated by proxy.
#
# version: 1
# filesystem_policy:
#   include_workdir: true
#   read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
#   read_write: [/sandbox, /tmp, /dev/null]
# landlock:
#   compatibility: best_effort
# process:
#   run_as_user: sandbox
#   run_as_group: sandbox
# network_policies:
#   github_api:
#     name: github-api-l4
#     endpoints:
#       - host: api.github.com
#         port: 443
#     binaries:
#       - { path: /usr/bin/curl }
#
# --- POLICY_L7_READONLY ---
# L7 with read-only enforcement: GET/HEAD/OPTIONS allowed, POST/PUT/DELETE denied.
#
# version: 1
# filesystem_policy:
#   include_workdir: true
#   read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
#   read_write: [/sandbox, /tmp, /dev/null]
# landlock:
#   compatibility: best_effort
# process:
#   run_as_user: sandbox
#   run_as_group: sandbox
# network_policies:
#   github_api:
#     name: github-api-l7-readonly
#     endpoints:
#       - host: api.github.com
#         port: 443
#         protocol: rest
#         enforcement: enforce
#         access: read-only
#     binaries:
#       - { path: /usr/bin/curl }
#
# --- POLICY_L7_FULL_WITH_PROVIDER ---
# L7 full access with provider credential injection.
#
# version: 1
# filesystem_policy:
#   include_workdir: true
#   read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
#   read_write: [/sandbox, /tmp, /dev/null]
# landlock:
#   compatibility: best_effort
# process:
#   run_as_user: sandbox
#   run_as_group: sandbox
# network_policies:
#   github_api:
#     name: github-api-cred-inject
#     endpoints:
#       - host: api.github.com
#         port: 443
#         protocol: rest
#         enforcement: enforce
#         access: full
#     binaries:
#       - { path: /usr/bin/curl }
#
# --- POLICY_TLS_SKIP ---
# L4 with tls: skip — raw tunnel, no MITM, no credential injection.
#
# version: 1
# filesystem_policy:
#   include_workdir: true
#   read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
#   read_write: [/sandbox, /tmp, /dev/null]
# landlock:
#   compatibility: best_effort
# process:
#   run_as_user: sandbox
#   run_as_group: sandbox
# network_policies:
#   github_api:
#     name: github-api-skip
#     endpoints:
#       - host: api.github.com
#         port: 443
#         tls: skip
#     binaries:
#       - { path: /usr/bin/curl }
#
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
RESET='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

pass() { ((PASS_COUNT++)); echo -e "  ${GREEN}PASS${RESET} $1"; }
fail() { ((FAIL_COUNT++)); echo -e "  ${RED}FAIL${RESET} $1"; echo "       $2"; }
skip() { ((SKIP_COUNT++)); echo -e "  ${YELLOW}SKIP${RESET} $1"; }
header() { echo -e "\n${BOLD}=== $1 ===${RESET}"; }

PROVIDER_NAME="smoke-test-github"
SANDBOX_NAME=""
POLICY_DIR=""

cleanup() {
    echo ""
    header "Cleanup"
    if [[ -n "$SANDBOX_NAME" ]]; then
        openshell sandbox delete "$SANDBOX_NAME" 2>/dev/null && echo "  Deleted sandbox $SANDBOX_NAME" || true
    fi
    openshell provider delete "$PROVIDER_NAME" 2>/dev/null && echo "  Deleted provider $PROVIDER_NAME" || true
    if [[ -n "$POLICY_DIR" ]]; then
        rm -rf "$POLICY_DIR"
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

header "Preflight"

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    echo -e "${RED}Error: GITHUB_TOKEN env var is required${RESET}"
    echo "  export GITHUB_TOKEN=ghp_..."
    exit 1
fi
echo "  GITHUB_TOKEN is set"

if ! openshell status >/dev/null 2>&1; then
    echo -e "${RED}Error: No healthy gateway found. Run: openshell gateway start${RESET}"
    exit 1
fi
echo "  Gateway is healthy"

# Create temp dir for policy files
POLICY_DIR=$(mktemp -d)

# ---------------------------------------------------------------------------
# Helper: write a policy file from heredoc
# ---------------------------------------------------------------------------

write_policy() {
    local name="$1"
    local file="$POLICY_DIR/${name}.yaml"
    cat > "$file"
    echo "$file"
}

# ---------------------------------------------------------------------------
# Helper: create sandbox, run a command, capture output + exit code
# ---------------------------------------------------------------------------

run_in_sandbox() {
    local policy_file="$1"
    shift
    local provider_flag=""
    if [[ "${USE_PROVIDER:-}" == "1" ]]; then
        provider_flag="--provider $PROVIDER_NAME"
    fi

    # Create sandbox with policy, run command, capture output
    local sandbox_name
    sandbox_name="smoke-$(date +%s)-$RANDOM"
    SANDBOX_NAME="$sandbox_name"

    # Set policy first, then create sandbox with command
    # Actually: create sandbox with --keep, set policy, then run command via
    # a second sandbox create with --no-keep reusing the same sandbox...
    # Simpler: create with --no-keep and the command directly, set policy after
    # creation via the API.
    #
    # Simplest approach: create a keep sandbox, set policy, run command via
    # sandbox connect, then clean up.
    #
    # Actually the simplest: use sandbox create with --no-keep and a command.
    # The policy is set on the sandbox after it's created but before the
    # command runs... that's racey.
    #
    # Let's use: create --keep sandbox, wait for ready, set policy, wait for
    # policy to propagate, then run command via a new sandbox create --no-keep
    # using the same image... No, that creates a NEW sandbox.
    #
    # The right pattern for testing: create a persistent sandbox, set policy,
    # then use SSH to run commands.

    # Create persistent sandbox
    openshell sandbox create --name "$sandbox_name" --keep \
        ${provider_flag} \
        -- sh -c "echo Ready && sleep 600" >/dev/null 2>&1 &
    local create_pid=$!

    # Wait for sandbox to be ready
    local attempts=0
    while [[ $attempts -lt 30 ]]; do
        if openshell sandbox list 2>/dev/null | grep -q "$sandbox_name.*Ready"; then
            break
        fi
        sleep 2
        ((attempts++))
    done

    if [[ $attempts -ge 30 ]]; then
        echo "TIMEOUT waiting for sandbox $sandbox_name"
        kill "$create_pid" 2>/dev/null || true
        return 1
    fi

    # Set policy
    openshell policy set "$sandbox_name" --policy "$policy_file" 2>/dev/null

    # Wait for policy to propagate (poll loop is 10s, give it 15s)
    sleep 15

    # Install SSH config and run command via SSH
    local ssh_config
    ssh_config=$(openshell sandbox ssh-config "$sandbox_name" 2>/dev/null)
    local ssh_host
    ssh_host=$(echo "$ssh_config" | grep "^Host " | awk '{print $2}')

    # Write SSH config to temp file
    local ssh_config_file="$POLICY_DIR/ssh_config_${sandbox_name}"
    echo "$ssh_config" > "$ssh_config_file"

    # Run command via SSH
    local output exit_code
    set +e
    output=$(ssh -F "$ssh_config_file" -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        "$ssh_host" "$@" 2>&1)
    exit_code=$?
    set -e

    # Kill the background create process
    kill "$create_pid" 2>/dev/null || true
    wait "$create_pid" 2>/dev/null || true

    # Return output and exit code
    echo "$output"
    return $exit_code
}

# ---------------------------------------------------------------------------
# Helper: quick sandbox run (create, run one command, delete)
# ---------------------------------------------------------------------------

quick_run() {
    local policy_file="$1"
    shift
    local provider_flag=""
    if [[ "${USE_PROVIDER:-}" == "1" ]]; then
        provider_flag="--provider $PROVIDER_NAME"
    fi

    local sandbox_name="smoke-$(date +%s)-$RANDOM"
    SANDBOX_NAME="$sandbox_name"

    # Create sandbox with --keep, set policy, exec command
    openshell sandbox create --name "$sandbox_name" --keep \
        ${provider_flag} \
        -- sh -c "echo Ready && sleep 600" >/dev/null 2>&1 &
    local create_pid=$!

    # Wait for ready
    local attempts=0
    while [[ $attempts -lt 30 ]]; do
        if openshell sandbox list 2>/dev/null | grep -q "$sandbox_name.*Ready"; then
            break
        fi
        sleep 2
        ((attempts++))
    done

    if [[ $attempts -ge 30 ]]; then
        echo "TIMEOUT"
        kill "$create_pid" 2>/dev/null || true
        return 1
    fi

    # Set policy and wait for propagation
    openshell policy set "$sandbox_name" --policy "$policy_file" >/dev/null 2>&1
    sleep 15

    # Get SSH config
    local ssh_config ssh_config_file ssh_host
    ssh_config=$(openshell sandbox ssh-config "$sandbox_name" 2>/dev/null)
    ssh_host=$(echo "$ssh_config" | grep "^Host " | awk '{print $2}')
    ssh_config_file="$POLICY_DIR/ssh_config_${sandbox_name}"
    echo "$ssh_config" > "$ssh_config_file"

    # Run command
    local output
    set +e
    output=$(ssh -F "$ssh_config_file" -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        "$ssh_host" "$@" 2>&1)
    local exit_code=$?
    set -e

    # Cleanup sandbox
    kill "$create_pid" 2>/dev/null || true
    wait "$create_pid" 2>/dev/null || true
    openshell sandbox delete "$sandbox_name" >/dev/null 2>&1 || true
    SANDBOX_NAME=""

    LAST_OUTPUT="$output"
    LAST_EXIT="$exit_code"
}

# ---------------------------------------------------------------------------
# Write all policy files
# ---------------------------------------------------------------------------

POLICY_L4=$(write_policy l4-only <<'YAML'
version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_policies:
  github_api:
    name: github-api-l4
    endpoints:
      - host: api.github.com
        port: 443
    binaries:
      - { path: /usr/bin/curl }
YAML
)

POLICY_L7_RO=$(write_policy l7-readonly <<'YAML'
version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_policies:
  github_api:
    name: github-api-l7-readonly
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
    binaries:
      - { path: /usr/bin/curl }
YAML
)

POLICY_CRED=$(write_policy l7-cred-inject <<'YAML'
version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_policies:
  github_api:
    name: github-api-cred-inject
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
    binaries:
      - { path: /usr/bin/curl }
YAML
)

POLICY_SKIP=$(write_policy tls-skip <<'YAML'
version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_policies:
  github_api:
    name: github-api-skip
    endpoints:
      - host: api.github.com
        port: 443
        tls: skip
    binaries:
      - { path: /usr/bin/curl }
YAML
)

# ---------------------------------------------------------------------------
# Phase 0: Provider setup
# ---------------------------------------------------------------------------

header "Phase 0: Provider Setup"

# Delete provider if it exists from a previous run
openshell provider delete "$PROVIDER_NAME" >/dev/null 2>&1 || true

openshell provider create \
    --name "$PROVIDER_NAME" \
    --type github \
    --credential "GITHUB_TOKEN=$GITHUB_TOKEN" >/dev/null 2>&1

if openshell provider get "$PROVIDER_NAME" >/dev/null 2>&1; then
    pass "Provider '$PROVIDER_NAME' created"
else
    fail "Provider creation failed" ""
    exit 1
fi

# ---------------------------------------------------------------------------
# Phase 1: L4 allow/deny
# ---------------------------------------------------------------------------

header "Phase 1: L4 Allow/Deny (no L7 rules, TLS auto-terminated)"

echo "  Creating sandbox with L4-only policy..."
USE_PROVIDER=0 quick_run "$POLICY_L4" \
    "curl -s -o /dev/null -w '%{http_code}' --max-time 10 https://api.github.com/zen"

if [[ "$LAST_EXIT" -eq 0 && "$LAST_OUTPUT" == *"200"* ]]; then
    pass "L4 allow: curl to api.github.com:443 succeeded (HTTP 200)"
else
    fail "L4 allow: expected HTTP 200" "exit=$LAST_EXIT output=$LAST_OUTPUT"
fi

echo "  Creating sandbox for L4 deny test..."
USE_PROVIDER=0 quick_run "$POLICY_L4" \
    "curl -s -o /dev/null -w '%{http_code}' --max-time 10 https://httpbin.org/get"

if [[ "$LAST_EXIT" -ne 0 || "$LAST_OUTPUT" == *"403"* || "$LAST_OUTPUT" == *"Connection refused"* || "$LAST_OUTPUT" == *"000"* ]]; then
    pass "L4 deny: curl to httpbin.org blocked (not in policy)"
else
    fail "L4 deny: expected connection failure" "exit=$LAST_EXIT output=$LAST_OUTPUT"
fi

# ---------------------------------------------------------------------------
# Phase 2: L7 enforcement
# ---------------------------------------------------------------------------

header "Phase 2: L7 Enforcement (read-only preset, TLS auto-terminated)"

echo "  Creating sandbox with L7 read-only policy..."
USE_PROVIDER=0 quick_run "$POLICY_L7_RO" \
    "curl -s -o /dev/null -w '%{http_code}' --max-time 10 https://api.github.com/zen"

if [[ "$LAST_EXIT" -eq 0 && "$LAST_OUTPUT" == *"200"* ]]; then
    pass "L7 allow: GET /zen succeeded (read-only allows GET)"
else
    fail "L7 allow: expected HTTP 200 for GET" "exit=$LAST_EXIT output=$LAST_OUTPUT"
fi

echo "  Testing L7 deny (POST blocked by read-only)..."
USE_PROVIDER=0 quick_run "$POLICY_L7_RO" \
    "curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST https://api.github.com/user/repos -d '{\"name\":\"should-not-create\"}'"

if [[ "$LAST_OUTPUT" == *"403"* ]]; then
    pass "L7 deny: POST /user/repos blocked (read-only denies POST)"
else
    fail "L7 deny: expected HTTP 403 for POST" "exit=$LAST_EXIT output=$LAST_OUTPUT"
fi

# ---------------------------------------------------------------------------
# Phase 3: Credential injection
# ---------------------------------------------------------------------------

header "Phase 3: Credential Injection (provider attached, TLS auto-terminated)"

echo "  Creating sandbox with provider and L7 full policy..."
USE_PROVIDER=1 quick_run "$POLICY_CRED" \
    "curl -s --max-time 10 https://api.github.com/user | head -5"

if [[ "$LAST_EXIT" -eq 0 && "$LAST_OUTPUT" == *"login"* ]]; then
    pass "Credential injection: /user returned authenticated response"
elif [[ "$LAST_OUTPUT" == *"401"* || "$LAST_OUTPUT" == *"Unauthorized"* ]]; then
    fail "Credential injection: got 401 (placeholder may have leaked)" "$LAST_OUTPUT"
else
    fail "Credential injection: unexpected response" "exit=$LAST_EXIT output=$LAST_OUTPUT"
fi

# ---------------------------------------------------------------------------
# Phase 4: tls: skip escape hatch
# ---------------------------------------------------------------------------

header "Phase 4: tls: skip (raw tunnel, no MITM, no credential injection)"

echo "  Creating sandbox with tls: skip policy and provider..."
USE_PROVIDER=1 quick_run "$POLICY_SKIP" \
    "curl -s -o /dev/null -w '%{http_code}' --max-time 10 https://api.github.com/zen"

# With tls: skip, the connection should succeed at L4 (raw tunnel).
# The GITHUB_TOKEN placeholder will leak since no MITM rewriting happens.
# But the /zen endpoint doesn't require auth, so it should return 200.
if [[ "$LAST_EXIT" -eq 0 && "$LAST_OUTPUT" == *"200"* ]]; then
    pass "tls: skip: L4 connection succeeded (raw tunnel)"
else
    fail "tls: skip: expected connection to succeed" "exit=$LAST_EXIT output=$LAST_OUTPUT"
fi

echo "  Verifying credential injection does NOT work with tls: skip..."
USE_PROVIDER=1 quick_run "$POLICY_SKIP" \
    "curl -s --max-time 10 https://api.github.com/user | head -5"

if [[ "$LAST_OUTPUT" == *"401"* || "$LAST_OUTPUT" == *"Unauthorized"* || "$LAST_OUTPUT" == *"Bad credentials"* ]]; then
    pass "tls: skip: /user returned 401 (credential injection bypassed as expected)"
elif [[ "$LAST_OUTPUT" == *"login"* ]]; then
    fail "tls: skip: /user returned authenticated response (MITM should be disabled)" "$LAST_OUTPUT"
else
    # Could be a different error, but the key thing is it's not authenticated
    pass "tls: skip: /user did not return authenticated response"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

header "Results"
echo -e "  ${GREEN}Passed: ${PASS_COUNT}${RESET}"
echo -e "  ${RED}Failed: ${FAIL_COUNT}${RESET}"
echo -e "  ${YELLOW}Skipped: ${SKIP_COUNT}${RESET}"
echo ""

if [[ $FAIL_COUNT -gt 0 ]]; then
    echo -e "${RED}${BOLD}SMOKE TEST FAILED${RESET}"
    exit 1
else
    echo -e "${GREEN}${BOLD}SMOKE TEST PASSED${RESET}"
    exit 0
fi
