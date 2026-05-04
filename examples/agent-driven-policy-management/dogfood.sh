#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
POLICY_TEMPLATE="${SCRIPT_DIR}/policy.template.yaml"
RUNNER_SOURCE="${SCRIPT_DIR}/sandbox-runner.sh"
PROMPT_SOURCE="${SCRIPT_DIR}/prompts/codex-dogfood.md"

if [[ -z "${OPENSHELL_BIN:-}" ]]; then
    if [[ -x "${REPO_ROOT}/target/debug/openshell" ]]; then
        OPENSHELL_BIN="${REPO_ROOT}/target/debug/openshell"
    else
        OPENSHELL_BIN="openshell"
    fi
fi

DEMO_BRANCH="${DEMO_BRANCH:-main}"
DEMO_RUN_ID="${DEMO_RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
DEMO_FILE_DIR="${DEMO_FILE_DIR:-openshell-policy-advisor-dogfood}"
DEMO_FILE_PATH="${DEMO_FILE_PATH:-${DEMO_FILE_DIR}/${DEMO_RUN_ID}.md}"
DEMO_SANDBOX_NAME="${DEMO_SANDBOX_NAME:-policy-agent-dogfood-${DEMO_RUN_ID}}"
DEMO_CODEX_PROVIDER_NAME="${DEMO_CODEX_PROVIDER_NAME:-codex-policy-agent-${DEMO_RUN_ID}}"
DEMO_GITHUB_PROVIDER_NAME="${DEMO_GITHUB_PROVIDER_NAME:-github-policy-agent-${DEMO_RUN_ID}}"
DEMO_APPROVAL_TIMEOUT_SECS="${DEMO_APPROVAL_TIMEOUT_SECS:-180}"
DEMO_KEEP_SANDBOX="${DEMO_KEEP_SANDBOX:-0}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/openshell-agent-policy-dogfood.XXXXXX")"
PAYLOAD_DIR="${TMP_DIR}/payload"
POLICY_FILE="${TMP_DIR}/policy.yaml"
AGENT_LOG="${TMP_DIR}/codex-dogfood.log"
PENDING_FILE="${TMP_DIR}/pending-rule.txt"
mkdir -p "${PAYLOAD_DIR}/prompts"

BOLD='\033[1m'
DIM='\033[2m'
CYAN='\033[36m'
GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
RESET='\033[0m'

AGENT_PID=""

step() {
    printf "\n${BOLD}${CYAN}==> %s${RESET}\n\n" "$1"
}

info() {
    printf "  %b\n" "$*"
}

redact_output() {
    sed -E \
        -e 's|(download_url": "https://raw\.githubusercontent\.com[^?"]+\?token=)[^"]+|\1<redacted>|g' \
        -e 's|(Authorization: Bearer )[A-Za-z0-9._-]+|\1<redacted>|g'
}

fail() {
    printf "\n${RED}error:${RESET} %s\n" "$*" >&2
    if [[ -f "$AGENT_LOG" ]]; then
        printf "\n${YELLOW}Agent log tail:${RESET}\n" >&2
        tail -n 120 "$AGENT_LOG" | redact_output | sed 's/^/  /' >&2 || true
    fi
    exit 1
}

cleanup() {
    local status=$?

    if [[ "$DEMO_KEEP_SANDBOX" != "1" ]]; then
        "$OPENSHELL_BIN" sandbox delete "$DEMO_SANDBOX_NAME" >/dev/null 2>&1 || true
    else
        printf "\n${YELLOW}Keeping sandbox because DEMO_KEEP_SANDBOX=1: %s${RESET}\n" "$DEMO_SANDBOX_NAME"
    fi

    "$OPENSHELL_BIN" provider delete "$DEMO_CODEX_PROVIDER_NAME" >/dev/null 2>&1 || true
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

resolve_github_token() {
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

resolve_codex_auth() {
    [[ -f "${HOME}/.codex/auth.json" ]] || fail "missing local Codex sign-in; run: codex login"

    export CODEX_AUTH_ACCESS_TOKEN
    export CODEX_AUTH_REFRESH_TOKEN
    export CODEX_AUTH_ACCOUNT_ID
    CODEX_AUTH_ACCESS_TOKEN="$(jq -r '.tokens.access_token // empty' "${HOME}/.codex/auth.json")"
    CODEX_AUTH_REFRESH_TOKEN="$(jq -r '.tokens.refresh_token // empty' "${HOME}/.codex/auth.json")"
    CODEX_AUTH_ACCOUNT_ID="$(jq -r '.tokens.account_id // empty' "${HOME}/.codex/auth.json")"

    [[ -n "$CODEX_AUTH_ACCESS_TOKEN" ]] || fail "local Codex sign-in is missing an access token; run: codex login"
    [[ -n "$CODEX_AUTH_REFRESH_TOKEN" ]] || fail "local Codex sign-in is missing a refresh token; run: codex login"
    [[ -n "$CODEX_AUTH_ACCOUNT_ID" ]] || fail "local Codex sign-in is missing an account id; run: codex login"
}

validate_env() {
    require_command curl
    require_command jq
    require_command "$OPENSHELL_BIN"

    [[ -f "$RUNNER_SOURCE" ]] || fail "missing sandbox runner: $RUNNER_SOURCE"
    [[ -f "$PROMPT_SOURCE" ]] || fail "missing Codex prompt: $PROMPT_SOURCE"
    [[ -n "${DEMO_GITHUB_OWNER:-}" ]] || fail "set DEMO_GITHUB_OWNER"
    [[ -n "${DEMO_GITHUB_REPO:-}" ]] || fail "set DEMO_GITHUB_REPO"
    [[ "$DEMO_RUN_ID" =~ ^[a-z0-9-]+$ ]] || fail "DEMO_RUN_ID may contain only lowercase letters, numbers, and '-'"
    [[ "$DEMO_APPROVAL_TIMEOUT_SECS" =~ ^[0-9]+$ ]] || fail "DEMO_APPROVAL_TIMEOUT_SECS must be a number"

    validate_name "DEMO_GITHUB_OWNER" "$DEMO_GITHUB_OWNER"
    validate_name "DEMO_GITHUB_REPO" "$DEMO_GITHUB_REPO"
    validate_path "DEMO_BRANCH" "$DEMO_BRANCH"
    validate_path "DEMO_FILE_PATH" "$DEMO_FILE_PATH"

    resolve_github_token
    resolve_codex_auth
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

urlencode() {
    jq -rn --arg v "$1" '$v|@uri'
}

check_gateway() {
    step "Checking active OpenShell gateway"
    "$OPENSHELL_BIN" status >/dev/null 2>&1 \
        || fail "active OpenShell gateway is not reachable; start one separately"
    "$OPENSHELL_BIN" status | sed 's/^/  /'
}

check_github_access() {
    step "Checking GitHub repository access"
    local body status branch
    body="${TMP_DIR}/github-repo.json"
    status="$(github_api_status "https://api.github.com/repos/${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}" "$body")"
    [[ "$status" == "200" ]] \
        || fail "GitHub returned HTTP $status for ${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}; check the repo name and token access"

    if jq -e 'has("permissions") and (.permissions.push == false and .permissions.admin == false and .permissions.maintain == false)' "$body" >/dev/null; then
        fail "GitHub token can read ${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO} but does not appear to have write access"
    fi

    branch="$(urlencode "$DEMO_BRANCH")"
    body="${TMP_DIR}/github-branch.json"
    status="$(github_api_status "https://api.github.com/repos/${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}/branches/${branch}" "$body")"
    [[ "$status" == "200" ]] || fail "GitHub returned HTTP $status for branch ${DEMO_BRANCH}"

    body="${TMP_DIR}/github-demo-file.json"
    status="$(github_api_status "https://api.github.com/repos/${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}/contents/${DEMO_FILE_PATH}?ref=${branch}" "$body")"
    if [[ "$status" == "200" ]]; then
        fail "dogfood output file already exists: ${DEMO_FILE_PATH}; choose a new DEMO_RUN_ID or DEMO_FILE_PATH"
    fi
    [[ "$status" == "404" ]] || fail "GitHub returned HTTP $status while checking output path ${DEMO_FILE_PATH}"

    info "${GREEN}GitHub repo, branch, and output path are safe for this run.${RESET}"
}

prepare_payload() {
    cp "$POLICY_TEMPLATE" "$POLICY_FILE"
    cp "$RUNNER_SOURCE" "${PAYLOAD_DIR}/policy-demo-runner.sh"
    cp "$PROMPT_SOURCE" "${PAYLOAD_DIR}/prompts/codex-dogfood.md"
    chmod +x "${PAYLOAD_DIR}/policy-demo-runner.sh"
}

create_providers() {
    step "Creating temporary Codex and GitHub providers"
    "$OPENSHELL_BIN" provider delete "$DEMO_CODEX_PROVIDER_NAME" >/dev/null 2>&1 || true
    "$OPENSHELL_BIN" provider delete "$DEMO_GITHUB_PROVIDER_NAME" >/dev/null 2>&1 || true

    "$OPENSHELL_BIN" provider create \
        --name "$DEMO_CODEX_PROVIDER_NAME" \
        --type generic \
        --credential CODEX_AUTH_ACCESS_TOKEN \
        --credential CODEX_AUTH_REFRESH_TOKEN \
        --credential CODEX_AUTH_ACCOUNT_ID >/dev/null

    "$OPENSHELL_BIN" provider create \
        --name "$DEMO_GITHUB_PROVIDER_NAME" \
        --type github \
        --credential GITHUB_TOKEN >/dev/null

    info "${GREEN}Created provider records for this run.${RESET}"
}

start_codex_sandbox() {
    step "Starting Codex dogfood run inside the sandbox"
    "$OPENSHELL_BIN" sandbox delete "$DEMO_SANDBOX_NAME" >/dev/null 2>&1 || true
    (
        "$OPENSHELL_BIN" sandbox create \
            --name "$DEMO_SANDBOX_NAME" \
            --from base \
            --provider "$DEMO_CODEX_PROVIDER_NAME" \
            --provider "$DEMO_GITHUB_PROVIDER_NAME" \
            --policy "$POLICY_FILE" \
            --upload "${PAYLOAD_DIR}:/sandbox" \
            --no-git-ignore \
            --keep \
            --no-auto-providers \
            --no-tty \
            -- bash /sandbox/payload/policy-demo-runner.sh codex-dogfood \
                "$DEMO_GITHUB_OWNER" \
                "$DEMO_GITHUB_REPO" \
                "$DEMO_BRANCH" \
                "$DEMO_FILE_PATH" \
                "$DEMO_RUN_ID"
    ) >"$AGENT_LOG" 2>&1 &
    AGENT_PID="$!"
    info "${DIM}Codex run started; log: ${AGENT_LOG}${RESET}"
}

approve_when_pending() {
    step "Waiting for Codex to submit a policy proposal"
    local start now
    start="$(date +%s)"

    while true; do
        if ! kill -0 "$AGENT_PID" >/dev/null 2>&1; then
            wait "$AGENT_PID" || true
            fail "Codex exited before a pending proposal appeared"
        fi

        "$OPENSHELL_BIN" rule get "$DEMO_SANDBOX_NAME" --status pending >"$PENDING_FILE" 2>/dev/null || true
        if grep -q "Chunk:" "$PENDING_FILE" && grep -q "pending" "$PENDING_FILE"; then
            info "${GREEN}Codex submitted a pending proposal.${RESET}"
            sed 's/^/  /' "$PENDING_FILE"

            step "Approving pending draft rule from outside the sandbox"
            "$OPENSHELL_BIN" rule approve-all "$DEMO_SANDBOX_NAME" | sed 's/^/  /'
            return
        fi

        now="$(date +%s)"
        if (( now - start >= DEMO_APPROVAL_TIMEOUT_SECS )); then
            fail "timed out waiting for Codex to submit a policy proposal"
        fi

        sleep 2
    done
}

wait_for_codex() {
    step "Waiting for Codex to retry after approval"
    if ! wait "$AGENT_PID"; then
        fail "Codex dogfood run failed"
    fi
    info "${GREEN}Codex dogfood run completed.${RESET}"
}

show_codex_final_message() {
    step "Codex final message"
    awk '
        /CODEX_FINAL_MESSAGE_BEGIN/ { printing = 1; next }
        /CODEX_FINAL_MESSAGE_END/ { printing = 0 }
        printing { print }
    ' "$AGENT_LOG" | redact_output | sed 's/^/  /'
}

verify_github_write() {
    step "Verifying GitHub write"
    local body status branch
    branch="$(urlencode "$DEMO_BRANCH")"
    body="${TMP_DIR}/github-created-file.json"
    status="$(github_api_status "https://api.github.com/repos/${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}/contents/${DEMO_FILE_PATH}?ref=${branch}" "$body")"
    [[ "$status" == "200" ]] || fail "expected demo file to exist after Codex run; GitHub returned HTTP $status"

    jq -r '"File: \(.path)", "URL:  \(.html_url)"' "$body" | sed 's/^/  /'
}

show_logs() {
    step "Policy decision trace"
    "$OPENSHELL_BIN" logs "$DEMO_SANDBOX_NAME" --since 10m -n 80 2>&1 \
        | grep -E 'HTTP:PUT|CONFIG:LOADED|ReportPolicyStatus' \
        | tail -n 12 \
        | sed 's/^/  /' || true
}

main() {
    validate_env
    prepare_payload
    check_gateway
    check_github_access
    create_providers
    start_codex_sandbox
    approve_when_pending
    wait_for_codex
    show_codex_final_message
    verify_github_write
    show_logs

    printf "\n${BOLD}${GREEN}✓ Codex dogfood complete.${RESET}\n\n"
    printf "  Sandbox:    %s\n" "$DEMO_SANDBOX_NAME"
    printf "  Repository: https://github.com/%s/%s\n" "$DEMO_GITHUB_OWNER" "$DEMO_GITHUB_REPO"
    printf "  File:       %s\n" "$DEMO_FILE_PATH"
}

main "$@"
