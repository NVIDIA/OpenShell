#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
POLICY_TEMPLATE="${SCRIPT_DIR}/policy.template.yaml"
RUNNER_SOURCE="${SCRIPT_DIR}/runner.sh"

if [[ -z "${OPENSHELL_BIN:-}" ]]; then
    if [[ -x "${REPO_ROOT}/target/debug/openshell" ]]; then
        OPENSHELL_BIN="${REPO_ROOT}/target/debug/openshell"
    else
        OPENSHELL_BIN="openshell"
    fi
fi

DEMO_BRANCH="${DEMO_BRANCH:-main}"
DEMO_RUN_ID="${DEMO_RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
DEMO_FILE_DIR="${DEMO_FILE_DIR:-openshell-policy-advisor-validation}"
DEMO_FILE_PATH="${DEMO_FILE_PATH:-${DEMO_FILE_DIR}/${DEMO_RUN_ID}.md}"
DEMO_SANDBOX_NAME="${DEMO_SANDBOX_NAME:-policy-agent-validation-${DEMO_RUN_ID}}"
DEMO_GITHUB_PROVIDER_NAME="${DEMO_GITHUB_PROVIDER_NAME:-github-policy-validation-${DEMO_RUN_ID}}"
DEMO_KEEP_SANDBOX="${DEMO_KEEP_SANDBOX:-0}"
DEMO_RETRY_ATTEMPTS="${DEMO_RETRY_ATTEMPTS:-30}"
DEMO_RETRY_SLEEP="${DEMO_RETRY_SLEEP:-2}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/openshell-agent-policy.XXXXXX")"
POLICY_FILE="${TMP_DIR}/policy.yaml"
SSH_CONFIG="${TMP_DIR}/ssh_config"
SSH_HOST=""

BOLD='\033[1m'
DIM='\033[2m'
CYAN='\033[36m'
GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
RESET='\033[0m'

step() {
    printf "\n${BOLD}${CYAN}==> %s${RESET}\n\n" "$1"
}

info() {
    printf "  %b\n" "$*"
}

fail() {
    printf "\n${RED}error:${RESET} %s\n" "$*" >&2
    exit 1
}

cleanup() {
    local status=$?

    if [[ "$DEMO_KEEP_SANDBOX" != "1" ]]; then
        "$OPENSHELL_BIN" sandbox delete "$DEMO_SANDBOX_NAME" >/dev/null 2>&1 || true
    else
        printf "\n${YELLOW}Keeping sandbox because DEMO_KEEP_SANDBOX=1: %s${RESET}\n" "$DEMO_SANDBOX_NAME"
    fi

    "$OPENSHELL_BIN" provider delete "$DEMO_GITHUB_PROVIDER_NAME" >/dev/null 2>&1 || true

    if [[ $status -eq 0 ]]; then
        rm -rf "$TMP_DIR"
    else
        printf "\n${YELLOW}Temporary files kept at: %s${RESET}\n" "$TMP_DIR"
    fi
}
trap cleanup EXIT

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

validate_name() {
    local label="$1"
    local value="$2"
    [[ "$value" =~ ^[A-Za-z0-9_.-]+$ ]] || fail "$label may contain only letters, numbers, '.', '_', and '-'"
}

validate_path() {
    local label="$1"
    local value="$2"
    [[ "$value" =~ ^[A-Za-z0-9._/-]+$ ]] || fail "$label may contain only letters, numbers, '.', '_', '-', and '/'"
    [[ "$value" != /* ]] || fail "$label must be relative"
    [[ "$value" != *..* ]] || fail "$label must not contain '..'"
}

resolve_token() {
    if [[ -z "${DEMO_GITHUB_TOKEN:-}" ]]; then
        if [[ -n "${GITHUB_TOKEN:-}" ]]; then
            DEMO_GITHUB_TOKEN="$GITHUB_TOKEN"
        elif [[ -n "${GH_TOKEN:-}" ]]; then
            DEMO_GITHUB_TOKEN="$GH_TOKEN"
        elif command -v gh >/dev/null 2>&1; then
            DEMO_GITHUB_TOKEN="$(gh auth token 2>/dev/null || true)"
        fi
    fi

    [[ -n "${DEMO_GITHUB_TOKEN:-}" ]] || fail "set DEMO_GITHUB_TOKEN, GITHUB_TOKEN, GH_TOKEN, or sign in with gh"
    export GITHUB_TOKEN="$DEMO_GITHUB_TOKEN"
}

validate_env() {
    require_command curl
    require_command jq
    require_command ssh
    require_command "$OPENSHELL_BIN"

    [[ -f "$RUNNER_SOURCE" ]] || fail "missing sandbox runner: $RUNNER_SOURCE"
    [[ -n "${DEMO_GITHUB_OWNER:-}" ]] || fail "set DEMO_GITHUB_OWNER"
    [[ -n "${DEMO_GITHUB_REPO:-}" ]] || fail "set DEMO_GITHUB_REPO"
    [[ "$DEMO_RUN_ID" =~ ^[a-z0-9-]+$ ]] || fail "DEMO_RUN_ID may contain only lowercase letters, numbers, and '-'"
    [[ "$DEMO_RETRY_ATTEMPTS" =~ ^[0-9]+$ ]] || fail "DEMO_RETRY_ATTEMPTS must be a number"
    [[ "$DEMO_RETRY_SLEEP" =~ ^[0-9]+$ ]] || fail "DEMO_RETRY_SLEEP must be a number"

    validate_name "DEMO_GITHUB_OWNER" "$DEMO_GITHUB_OWNER"
    validate_name "DEMO_GITHUB_REPO" "$DEMO_GITHUB_REPO"
    validate_path "DEMO_BRANCH" "$DEMO_BRANCH"
    validate_path "DEMO_FILE_PATH" "$DEMO_FILE_PATH"

    resolve_token
}

github_api_status() {
    local url="$1"
    local body="$2"
    curl -sS \
        -o "$body" \
        -w "%{http_code}" \
        -H "Accept: application/vnd.github+json" \
        -H "Authorization: Bearer ${DEMO_GITHUB_TOKEN}" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "$url"
}

check_gateway() {
    step "Checking active OpenShell gateway"
    if ! "$OPENSHELL_BIN" status >/dev/null 2>&1; then
        fail "active OpenShell gateway is not reachable; start one separately, for example: mise run cluster"
    fi
    "$OPENSHELL_BIN" status | sed 's/^/  /'
}

check_github_access() {
    step "Checking GitHub repository access"
    local body status branch branches_body branches_status branches
    body="${TMP_DIR}/github-repo.json"
    status="$(github_api_status "https://api.github.com/repos/${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}" "$body")"

    if [[ "$status" != "200" ]]; then
        printf '%s\n' "$(jq -r '.message // empty' "$body" 2>/dev/null)" | sed 's/^/  /'
        fail "GitHub returned HTTP $status for ${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}; check the repo name and token access"
    fi

    if jq -e 'has("permissions") and (.permissions.push == false and .permissions.admin == false and .permissions.maintain == false)' "$body" >/dev/null; then
        fail "GitHub token can read ${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO} but does not appear to have write access"
    fi

    branch="$(jq -rn --arg v "$DEMO_BRANCH" '$v|@uri')"
    body="${TMP_DIR}/github-branch.json"
    status="$(github_api_status "https://api.github.com/repos/${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}/branches/${branch}" "$body")"
    if [[ "$status" != "200" ]]; then
        branches_body="${TMP_DIR}/github-branches.json"
        branches_status="$(github_api_status "https://api.github.com/repos/${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}/branches?per_page=20" "$branches_body")"
        if [[ "$branches_status" == "200" ]]; then
            branches="$(jq -r 'map(.name) | join(", ")' "$branches_body")"
            if [[ -z "$branches" ]]; then
                fail "GitHub repo exists but has no branches yet; add an initial README or push ${DEMO_BRANCH} before running the demo"
            fi
            fail "GitHub returned HTTP $status for branch ${DEMO_BRANCH}; set DEMO_BRANCH to one of: ${branches}"
        fi
        fail "GitHub returned HTTP $status for branch ${DEMO_BRANCH}"
    fi

    body="${TMP_DIR}/github-demo-file.json"
    status="$(github_api_status "https://api.github.com/repos/${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}/contents/${DEMO_FILE_PATH}?ref=${branch}" "$body")"
    if [[ "$status" == "200" ]]; then
        fail "validation output file already exists: ${DEMO_FILE_PATH}; choose a new DEMO_RUN_ID or DEMO_FILE_PATH"
    fi
    [[ "$status" == "404" ]] || fail "GitHub returned HTTP $status while checking demo output path ${DEMO_FILE_PATH}"

    info "${GREEN}GitHub repo, branch, and output path are safe for this run.${RESET}"
}

create_provider() {
    step "Creating temporary GitHub provider"
    "$OPENSHELL_BIN" provider delete "$DEMO_GITHUB_PROVIDER_NAME" >/dev/null 2>&1 || true
    "$OPENSHELL_BIN" provider create \
        --name "$DEMO_GITHUB_PROVIDER_NAME" \
        --type github \
        --credential GITHUB_TOKEN
}

create_sandbox() {
    step "Creating sandbox with read-only GitHub L7 policy"
    cp "$POLICY_TEMPLATE" "$POLICY_FILE"
    "$OPENSHELL_BIN" sandbox delete "$DEMO_SANDBOX_NAME" >/dev/null 2>&1 || true
    "$OPENSHELL_BIN" sandbox create \
        --name "$DEMO_SANDBOX_NAME" \
        --provider "$DEMO_GITHUB_PROVIDER_NAME" \
        --policy "$POLICY_FILE" \
        --upload "${RUNNER_SOURCE}:/sandbox/policy-validation-runner.sh" \
        --no-git-ignore \
        --keep \
        --no-auto-providers \
        --no-tty \
        -- bash -lc "chmod +x /sandbox/policy-validation-runner.sh && echo sandbox ready"
}

connect_ssh() {
    step "Connecting to sandbox over SSH"
    "$OPENSHELL_BIN" sandbox ssh-config "$DEMO_SANDBOX_NAME" > "$SSH_CONFIG"
    SSH_HOST="$(awk '/^Host / { print $2; exit }' "$SSH_CONFIG")"
    [[ -n "$SSH_HOST" ]] || fail "could not find Host entry in sandbox SSH config"

    local retries=30
    local i
    for i in $(seq 1 "$retries"); do
        if ssh -F "$SSH_CONFIG" "$SSH_HOST" true >/dev/null 2>&1; then
            return
        fi
        sleep 2
    done
    fail "SSH connection to sandbox timed out"
}

sandbox_exec() {
    ssh -F "$SSH_CONFIG" "$SSH_HOST" "$@"
}

http_status() {
    awk -F= '/^HTTP_STATUS=/ { print $2; exit }'
}

http_body() {
    sed '/^HTTP_STATUS=/d'
}

run_policy_local_checks() {
    step "Checking sandbox-local skill and policy.local"
    sandbox_exec /sandbox/policy-validation-runner.sh check-skill >/dev/null
    info "${GREEN}Skill installed:${RESET} /etc/openshell/skills/policy_advisor.md"

    local output
    output="$(sandbox_exec /sandbox/policy-validation-runner.sh current-policy)"
    local status
    status="$(printf '%s\n' "$output" | http_status)"
    [[ "$status" == "200" ]] || fail "policy.local current policy returned HTTP $status"

    info "${GREEN}policy.local returned the current sandbox policy.${RESET}"
    info "Initial policy: read-only REST access to api.github.com for /usr/bin/curl"
}

attempt_write() {
    sandbox_exec /sandbox/policy-validation-runner.sh put-file \
        "$DEMO_GITHUB_OWNER" \
        "$DEMO_GITHUB_REPO" \
        "$DEMO_BRANCH" \
        "$DEMO_FILE_PATH" \
        "$DEMO_RUN_ID"
}

submit_policy_proposal() {
    sandbox_exec /sandbox/policy-validation-runner.sh submit-proposal \
        "$DEMO_GITHUB_OWNER" \
        "$DEMO_GITHUB_REPO" \
        "$DEMO_FILE_PATH"
}

capture_initial_denial() {
    step "Attempting GitHub contents write from inside sandbox"
    local output
    output="$(attempt_write)"
    local status
    local body
    status="$(printf '%s\n' "$output" | http_status)"
    body="$(printf '%s\n' "$output" | http_body)"

    [[ "$status" == "403" ]] || fail "expected OpenShell HTTP 403, got HTTP $status"
    printf '%s\n' "$body" | jq -e '.error == "policy_denied"' >/dev/null \
        || fail "expected structured policy_denied body"
    printf '%s\n' "$body" | jq -e '.layer == "l7" and .protocol == "rest" and .method == "PUT"' >/dev/null \
        || fail "expected structured L7 REST deny fields"

    printf '%s\n' "$body" | jq -r '
        "Denied: \(.method) \(.path)",
        "Layer: \(.layer)/\(.protocol) host=\(.host):\(.port) binary=\(.binary)",
        "Agent guidance: \(.next_steps | map(.action) | join(" -> "))"
    ' | sed 's/^/  /'
    info "${GREEN}Captured structured L7 policy denial.${RESET}"
}

submit_and_approve() {
    step "Submitting proposal through policy.local"
    local output
    output="$(submit_policy_proposal)"
    local status
    local body
    status="$(printf '%s\n' "$output" | http_status)"
    body="$(printf '%s\n' "$output" | http_body)"

    [[ "$status" == "202" ]] || fail "expected proposal submit HTTP 202, got HTTP $status"
    [[ "$(printf '%s\n' "$body" | jq -r '.accepted_chunks // 0')" != "0" ]] \
        || fail "proposal was not accepted"
    printf '%s\n' "$body" | jq -r '"Proposal submitted: \(.accepted_chunks) accepted, \(.rejected_chunks) rejected"' | sed 's/^/  /'

    step "Approving pending draft rule from outside the sandbox"
    "$OPENSHELL_BIN" rule get "$DEMO_SANDBOX_NAME" --status pending | sed 's/^/  /'
    "$OPENSHELL_BIN" rule approve-all "$DEMO_SANDBOX_NAME" | sed 's/^/  /'
}

print_success_summary() {
    jq '{
        path: .content.path,
        html_url: .content.html_url,
        commit: .commit.sha,
        message: .commit.message
    }'
}

retry_until_allowed() {
    step "Retrying GitHub contents write after approval"
    local output status body attempt

    for attempt in $(seq 1 "$DEMO_RETRY_ATTEMPTS"); do
        output="$(attempt_write)"
        status="$(printf '%s\n' "$output" | http_status)"
        body="$(printf '%s\n' "$output" | http_body)"

        if printf '%s\n' "$body" | jq -e '.error == "policy_denied"' >/dev/null 2>&1; then
            info "${DIM}Attempt ${attempt}/${DEMO_RETRY_ATTEMPTS}: policy not loaded yet; retrying...${RESET}"
            sleep "$DEMO_RETRY_SLEEP"
            continue
        fi

        if [[ "$status" == "200" || "$status" == "201" ]]; then
            printf '%s\n' "$body" | print_success_summary | sed 's/^/  /'
            info "${GREEN}GitHub write succeeded from inside the sandbox.${RESET}"
            return
        fi

        printf '%s\n' "$body" | jq . | sed 's/^/  /'
        if [[ "$status" == "404" ]]; then
            fail "policy allowed the request, but GitHub returned HTTP 404; check DEMO_GITHUB_OWNER, DEMO_GITHUB_REPO, and token access"
        fi
        fail "policy allowed the request, but GitHub returned HTTP $status"
    done

    fail "timed out waiting for approved policy to load into the sandbox"
}

show_logs() {
    step "Policy decision trace"
    "$OPENSHELL_BIN" logs "$DEMO_SANDBOX_NAME" --since 5m -n 50 2>&1 \
        | grep -E 'HTTP:PUT|CONFIG:LOADED|ReportPolicyStatus' \
        | tail -n 8 \
        | sed 's/^/  /' || true
}

main() {
    validate_env
    check_gateway
    check_github_access
    create_provider
    create_sandbox
    connect_ssh
    run_policy_local_checks
    capture_initial_denial
    submit_and_approve
    retry_until_allowed
    show_logs

    printf "\n${BOLD}${GREEN}✓ Validation complete.${RESET}\n\n"
    printf "  Sandbox:    %s\n" "$DEMO_SANDBOX_NAME"
    printf "  Repository: https://github.com/%s/%s\n" "$DEMO_GITHUB_OWNER" "$DEMO_GITHUB_REPO"
    printf "  File:       %s\n" "$DEMO_FILE_PATH"
}

main "$@"
