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
#   - GITHUB_TOKEN or GH_TOKEN env var set with a valid GitHub token
#   - The `openshell` CLI on PATH
#
# Usage:
#   GITHUB_TOKEN=ghp_xxx ./scripts/smoke-test-network-policy.sh
#
# What it tests:
#
#   Phase 1 — L4 allow/deny (credential injection, TLS auto-terminated):
#     Creates a sandbox with L4+L7 policy for api.github.com (provider
#     attached for authenticated requests).
#     - curl api.github.com/zen  -> should succeed (authenticated, 200)
#     - curl httpbin.org         -> should be blocked (implicit deny)
#
#   Phase 2 — L7 enforcement (method + path rules):
#     Creates a sandbox with read-only L7 enforcement (provider attached).
#     - GET /zen                 -> should succeed (200)
#     - POST /user/repos         -> should be blocked (403)
#
#   Phase 3 — Credential injection:
#     Creates a sandbox with provider attached and full L7 access.
#     - curl /user (no auth header) -> should return authenticated response
#       (proxy auto-injects GITHUB_TOKEN via TLS MITM)
#
#   Phase 4 — tls: skip escape hatch:
#     Creates a sandbox with tls: skip (provider attached but no MITM).
#     - curl /zen               -> should get response from upstream (raw tunnel)
#     - curl /user              -> should get 401 (no credential injection)
#
# After all tests, sandboxes are kept alive for log inspection.
# The script prompts before cleanup.
#
# =============================================================================
#
# Embedded Policy YAMLs
# =============================================================================
#
# POLICY_L4 (allow api.github.com:443 with credential injection, deny everything else):
#   network_policies:
#     github_api:
#       endpoints: [{ host: api.github.com, port: 443, protocol: rest, access: full }]
#       binaries:  [{ path: /usr/bin/curl }]
#
# POLICY_L7_READONLY (L7 read-only enforcement):
#   network_policies:
#     github_api:
#       endpoints:
#         - host: api.github.com
#           port: 443
#           protocol: rest
#           enforcement: enforce
#           access: read-only
#       binaries: [{ path: /usr/bin/curl }]
#
# POLICY_CRED_INJECT (L7 full access, provider credential injection):
#   Same as L7 but with access: full
#
# POLICY_TLS_SKIP (L4 with tls: skip — raw tunnel):
#   network_policies:
#     github_api:
#       endpoints: [{ host: api.github.com, port: 443, tls: skip }]
#       binaries:  [{ path: /usr/bin/curl }]
#
# =============================================================================

set -uo pipefail
# Note: NOT using set -e so we can capture exit codes without exiting.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
RESET='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0

pass() { ((PASS_COUNT++)); echo -e "  ${GREEN}PASS${RESET} $1"; }
fail() { ((FAIL_COUNT++)); echo -e "  ${RED}FAIL${RESET} $1\n       $2"; }
header() { echo -e "\n${BOLD}=== $1 ===${RESET}"; }

PROVIDER_NAME="smoke-test-github"
SANDBOXES=()
POLICY_DIR=""

# Resolve token from GITHUB_TOKEN or GH_TOKEN
TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

header "Preflight"

if [[ -z "$TOKEN" ]]; then
    echo -e "${RED}Error: GITHUB_TOKEN or GH_TOKEN env var is required${RESET}"
    exit 1
fi
echo "  Token is set"

if ! openshell status >/dev/null 2>&1; then
    echo -e "${RED}Error: No healthy gateway. Run: openshell gateway start${RESET}"
    exit 1
fi
echo "  Gateway is healthy"

POLICY_DIR=$(mktemp -d)
echo "  Policy dir: $POLICY_DIR"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

write_policy() {
    local name="$1"
    local file="$POLICY_DIR/${name}.yaml"
    cat > "$file"
    echo "$file"
}

# Create a sandbox with --keep and a sleep, wait for Ready.
create_sandbox() {
    local name="$1"
    shift
    local provider_flag=("$@")

    echo "  Creating sandbox: $name"
    openshell sandbox create --name "$name" --keep "${provider_flag[@]}" \
        -- sh -c "echo Ready && sleep 3600" >/dev/null 2>&1 &
    local pid=$!

    local attempts=0
    while [[ $attempts -lt 40 ]]; do
        if openshell sandbox list 2>/dev/null | grep -q "$name.*Ready"; then
            echo "  Sandbox $name is Ready"
            SANDBOXES+=("$name")
            # Kill the blocking create process (sandbox stays alive with --keep)
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            # Brief settle time — SSH server inside the sandbox may still be
            # binding its port even though the status flipped to Ready.
            sleep 3
            return 0
        fi
        sleep 2
        ((attempts++))
    done

    echo -e "  ${RED}TIMEOUT waiting for $name${RESET}"
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    return 1
}

# Run a command inside a sandbox via SSH.
sandbox_exec() {
    local name="$1"
    shift

    local ssh_config
    ssh_config=$(openshell sandbox ssh-config "$name" 2>/dev/null)
    local ssh_host
    ssh_host=$(echo "$ssh_config" | grep "^Host " | awk '{print $2}')
    local ssh_config_file="$POLICY_DIR/ssh_config_${name}"
    echo "$ssh_config" > "$ssh_config_file"

    ssh -F "$ssh_config_file" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -o ConnectTimeout=15 \
        "$ssh_host" "$@" 2>&1
}

# ---------------------------------------------------------------------------
# Write policies
# ---------------------------------------------------------------------------

POLICY_L4=$(write_policy l4-allow-deny <<'YAML'
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
        protocol: rest
        enforcement: enforce
        access: full
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

openshell provider delete "$PROVIDER_NAME" >/dev/null 2>&1 || true

if openshell provider create \
    --name "$PROVIDER_NAME" \
    --type github \
    --credential "GITHUB_TOKEN=$TOKEN" >/dev/null 2>&1; then
    pass "Provider '$PROVIDER_NAME' created"
else
    fail "Provider creation failed" ""
    exit 1
fi

# ---------------------------------------------------------------------------
# Phase 1: L4 allow/deny
# ---------------------------------------------------------------------------

header "Phase 1: L4 Allow/Deny (TLS auto-terminated, credential injection)"

SB1="smoke-l4"
if create_sandbox "$SB1" --provider "$PROVIDER_NAME"; then
    echo "  Setting L4-only policy..."
    openshell policy set "$SB1" --policy "$POLICY_L4" >/dev/null 2>&1
    echo "  Waiting for policy propagation (15s)..."
    sleep 15

    # Test 1: L4 allow (authenticated via credential injection)
    echo "  Running: curl api.github.com/zen"
    output=$(sandbox_exec "$SB1" 'curl -s -o /dev/null -w "%{http_code}" --max-time 10 -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/zen')
    if [[ "$output" == *"200"* ]]; then
        pass "L4 allow: curl to api.github.com succeeded (HTTP 200)"
    else
        fail "L4 allow: expected HTTP 200" "got: $output"
    fi

    # Test 2: L4 deny (implicit deny for httpbin.org)
    echo "  Running: curl httpbin.org (should be blocked)"
    output=$(sandbox_exec "$SB1" "curl -s -o /dev/null -w '%{http_code}' --max-time 10 https://httpbin.org/get" || true)
    if [[ "$output" == *"403"* || "$output" == *"000"* || -z "$output" ]]; then
        pass "L4 deny: curl to httpbin.org blocked"
    else
        fail "L4 deny: expected connection failure" "got: $output"
    fi
else
    fail "L4 sandbox creation failed" ""
    fail "L4 deny test skipped" "sandbox not created"
fi

# ---------------------------------------------------------------------------
# Phase 2: L7 enforcement
# ---------------------------------------------------------------------------

header "Phase 2: L7 Enforcement (read-only, TLS auto-terminated)"

SB2="smoke-l7"
if create_sandbox "$SB2" --provider "$PROVIDER_NAME"; then
    echo "  Setting L7 read-only policy..."
    openshell policy set "$SB2" --policy "$POLICY_L7_RO" >/dev/null 2>&1
    echo "  Waiting for policy propagation (15s)..."
    sleep 15

    # Test 3: L7 allow (GET, authenticated via credential injection)
    echo "  Running: GET /zen"
    output=$(sandbox_exec "$SB2" 'curl -s -o /dev/null -w "%{http_code}" --max-time 10 -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/zen')
    if [[ "$output" == *"200"* ]]; then
        pass "L7 allow: GET /zen succeeded (read-only allows GET)"
    else
        fail "L7 allow: expected HTTP 200 for GET" "got: $output"
    fi

    # Test 4: L7 deny (POST blocked by read-only)
    echo "  Running: POST /user/repos (should be blocked)"
    output=$(sandbox_exec "$SB2" "curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST https://api.github.com/user/repos -d '{\"name\":\"should-not-create\"}'" || true)
    if [[ "$output" == *"403"* ]]; then
        pass "L7 deny: POST blocked by read-only enforcement"
    else
        fail "L7 deny: expected HTTP 403 for POST" "got: $output"
    fi
else
    fail "L7 sandbox creation failed" ""
    fail "L7 deny test skipped" "sandbox not created"
fi

# ---------------------------------------------------------------------------
# Phase 3: Credential injection
# ---------------------------------------------------------------------------

header "Phase 3: Credential Injection (provider attached, TLS auto-terminated)"

SB3="smoke-cred"
if create_sandbox "$SB3" --provider "$PROVIDER_NAME"; then
    echo "  Setting L7 full policy..."
    openshell policy set "$SB3" --policy "$POLICY_CRED" >/dev/null 2>&1
    echo "  Waiting for policy propagation (15s)..."
    sleep 15

    # Test 5: Credential injection — curl /user using the placeholder env var.
    # The sandbox process sees GITHUB_TOKEN=openshell:resolve:env:GITHUB_TOKEN
    # in its environment. When curl sends this as an Authorization header,
    # the proxy's SecretResolver rewrites the placeholder to the real token.
    echo "  Running: curl /user -H 'Authorization: token \$GITHUB_TOKEN'"
    output=$(sandbox_exec "$SB3" 'curl -s --max-time 10 -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user' || true)
    if [[ "$output" == *"login"* ]]; then
        pass "Credential injection: /user returned authenticated response"
    elif [[ "$output" == *"401"* || "$output" == *"Unauthorized"* ]]; then
        fail "Credential injection: got 401 (placeholder may have leaked)" "$output"
    else
        fail "Credential injection: unexpected response" "$output"
    fi
else
    fail "Credential injection sandbox creation failed" ""
fi

# ---------------------------------------------------------------------------
# Phase 4: tls: skip escape hatch
# ---------------------------------------------------------------------------

header "Phase 4: tls: skip (raw tunnel, no MITM)"

SB4="smoke-skip"
if create_sandbox "$SB4" --provider "$PROVIDER_NAME"; then
    echo "  Setting tls: skip policy..."
    openshell policy set "$SB4" --policy "$POLICY_SKIP" >/dev/null 2>&1
    echo "  Waiting for policy propagation (15s)..."
    sleep 15

    # Test 6: L4 connection reaches upstream (raw tunnel, no MITM).
    # Without credential injection the request is unauthenticated, so
    # GitHub may return 200 or 403 (rate-limited). Either proves the
    # proxy forwarded the request — a proxy block would return "000"
    # or the sandbox-policy 403 body.
    echo "  Running: curl /zen (should reach upstream via raw tunnel)"
    output=$(sandbox_exec "$SB4" "curl -s -o /dev/null -w '%{http_code}' --max-time 10 https://api.github.com/zen" || true)
    if [[ "$output" == *"200"* || "$output" == *"403"* ]]; then
        pass "tls: skip: request reached upstream (raw tunnel, HTTP $output)"
    else
        fail "tls: skip: expected upstream response (200 or 403)" "got: $output"
    fi

    # Test 7: Credential injection does NOT work with tls: skip.
    # The placeholder leaks verbatim since there's no MITM to rewrite it.
    echo "  Running: curl /user with \$GITHUB_TOKEN (should fail, placeholder leaks)"
    output=$(sandbox_exec "$SB4" 'curl -s --max-time 10 -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user' || true)
    if [[ "$output" == *"401"* || "$output" == *"Unauthorized"* || "$output" == *"Bad credentials"* ]]; then
        pass "tls: skip: /user returned 401 (credential injection bypassed)"
    elif [[ "$output" == *"login"* ]]; then
        fail "tls: skip: /user was authenticated (MITM should be disabled)" "$output"
    else
        pass "tls: skip: /user not authenticated (expected)"
    fi
else
    fail "tls: skip sandbox creation failed" ""
fi

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

header "Results"
echo -e "  ${GREEN}Passed: ${PASS_COUNT}${RESET}"
echo -e "  ${RED}Failed: ${FAIL_COUNT}${RESET}"
echo ""

if [[ ${#SANDBOXES[@]} -gt 0 ]]; then
    echo -e "${BOLD}Sandboxes kept for inspection:${RESET}"
    for sb in "${SANDBOXES[@]}"; do
        echo "  - $sb"
    done
    echo ""
    echo "Inspect logs with:"
    echo "  openshell logs <name> --source sandbox"
    echo ""

    read -r -p "Delete all smoke test sandboxes and provider? [y/N] " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        echo ""
        for sb in "${SANDBOXES[@]}"; do
            openshell sandbox delete "$sb" >/dev/null 2>&1 && echo "  Deleted $sb" || true
        done
        openshell provider delete "$PROVIDER_NAME" >/dev/null 2>&1 && echo "  Deleted provider $PROVIDER_NAME" || true
    else
        echo "  Sandboxes left running. Clean up manually:"
        echo "  openshell sandbox delete --all"
        echo "  openshell provider delete $PROVIDER_NAME"
    fi
fi

# Clean up temp files
rm -rf "$POLICY_DIR"

echo ""
if [[ $FAIL_COUNT -gt 0 ]]; then
    echo -e "${RED}${BOLD}SMOKE TEST FAILED${RESET}"
    exit 1
else
    echo -e "${GREEN}${BOLD}SMOKE TEST PASSED${RESET}"
    exit 0
fi
