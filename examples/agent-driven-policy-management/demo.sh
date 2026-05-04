#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DEFAULT_POLICY_FILE="${SCRIPT_DIR}/policy.template.yaml"
TASK_TEMPLATE="${SCRIPT_DIR}/agent-task.md"

if [[ -z "${OPENSHELL_BIN:-}" ]]; then
    if [[ -x "${REPO_ROOT}/target/debug/openshell" ]]; then
        OPENSHELL_BIN="${REPO_ROOT}/target/debug/openshell"
    else
        OPENSHELL_BIN="openshell"
    fi
fi

DEMO_POLICY_FILE="${DEMO_POLICY_FILE:-$DEFAULT_POLICY_FILE}"
DEMO_SANDBOX_FROM="${DEMO_SANDBOX_FROM:-base}"
DEMO_BRANCH="${DEMO_BRANCH:-main}"
DEMO_RUN_ID="${DEMO_RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
DEMO_FILE_DIR="${DEMO_FILE_DIR:-openshell-policy-advisor-demo}"
DEMO_FILE_PATH="${DEMO_FILE_PATH:-${DEMO_FILE_DIR}/${DEMO_RUN_ID}.md}"
DEMO_SANDBOX_NAME="${DEMO_SANDBOX_NAME:-policy-agent-${DEMO_RUN_ID}}"
DEMO_GITHUB_PROVIDER_NAME="${DEMO_GITHUB_PROVIDER_NAME:-github-policy-agent-${DEMO_RUN_ID}}"
DEMO_AGENT_PROVIDERS="${DEMO_AGENT_PROVIDERS:-}"
DEMO_APPROVAL_TIMEOUT_SECS="${DEMO_APPROVAL_TIMEOUT_SECS:-240}"
DEMO_KEEP_SANDBOX="${DEMO_KEEP_SANDBOX:-0}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/openshell-agent-policy-demo.XXXXXX")"
PAYLOAD_DIR="${TMP_DIR}/payload"
TASK_FILE="${PAYLOAD_DIR}/agent-task.md"
AGENT_LOG="${TMP_DIR}/agent.log"
PENDING_FILE="${TMP_DIR}/pending-rule.txt"
mkdir -p "$PAYLOAD_DIR"

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

validate_env() {
    require_command curl
    require_command jq
    require_command "$OPENSHELL_BIN"

    [[ -f "$DEMO_POLICY_FILE" ]] || fail "missing policy file: $DEMO_POLICY_FILE"
    [[ -f "$TASK_TEMPLATE" ]] || fail "missing agent task template: $TASK_TEMPLATE"
    [[ -n "${DEMO_GITHUB_OWNER:-}" ]] || fail "set DEMO_GITHUB_OWNER"
    [[ -n "${DEMO_GITHUB_REPO:-}" ]] || fail "set DEMO_GITHUB_REPO"
    [[ -n "${DEMO_AGENT_COMMAND:-}" ]] || fail "set DEMO_AGENT_COMMAND to a sandbox command that reads /sandbox/payload/agent-task.md"
    [[ "$DEMO_RUN_ID" =~ ^[a-z0-9-]+$ ]] || fail "DEMO_RUN_ID may contain only lowercase letters, numbers, and '-'"
    [[ "$DEMO_APPROVAL_TIMEOUT_SECS" =~ ^[0-9]+$ ]] || fail "DEMO_APPROVAL_TIMEOUT_SECS must be a number"

    validate_name "DEMO_GITHUB_OWNER" "$DEMO_GITHUB_OWNER"
    validate_name "DEMO_GITHUB_REPO" "$DEMO_GITHUB_REPO"
    validate_path "DEMO_BRANCH" "$DEMO_BRANCH"
    validate_path "DEMO_FILE_PATH" "$DEMO_FILE_PATH"

    resolve_github_token
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
        fail "demo output file already exists: ${DEMO_FILE_PATH}; choose a new DEMO_RUN_ID or DEMO_FILE_PATH"
    fi
    [[ "$status" == "404" ]] || fail "GitHub returned HTTP $status while checking output path ${DEMO_FILE_PATH}"

    info "${GREEN}GitHub repo, branch, and output path are safe for this run.${RESET}"
}

render_task() {
    python3 - "$TASK_TEMPLATE" "$TASK_FILE" "$DEMO_GITHUB_OWNER" "$DEMO_GITHUB_REPO" "$DEMO_BRANCH" "$DEMO_FILE_PATH" "$DEMO_RUN_ID" <<'PY'
from pathlib import Path
import sys

template, output, owner, repo, branch, file_path, run_id = sys.argv[1:8]
text = Path(template).read_text(encoding="utf-8")
for key, value in {
    "OWNER": owner,
    "REPO": repo,
    "BRANCH": branch,
    "FILE_PATH": file_path,
    "RUN_ID": run_id,
}.items():
    text = text.replace("{{" + key + "}}", value)
Path(output).write_text(text, encoding="utf-8")
PY
}

create_github_provider() {
    step "Creating temporary GitHub provider"
    "$OPENSHELL_BIN" provider delete "$DEMO_GITHUB_PROVIDER_NAME" >/dev/null 2>&1 || true
    "$OPENSHELL_BIN" provider create \
        --name "$DEMO_GITHUB_PROVIDER_NAME" \
        --type github \
        --credential GITHUB_TOKEN >/dev/null
    info "${GREEN}Created GitHub provider for this run.${RESET}"
}

provider_args() {
    printf '%s\n' "--provider"
    printf '%s\n' "$DEMO_GITHUB_PROVIDER_NAME"

    local normalized="${DEMO_AGENT_PROVIDERS//,/ }"
    local provider
    for provider in $normalized; do
        printf '%s\n' "--provider"
        printf '%s\n' "$provider"
    done
}

start_agent_sandbox() {
    step "Starting agent inside the sandbox"
    "$OPENSHELL_BIN" sandbox delete "$DEMO_SANDBOX_NAME" >/dev/null 2>&1 || true

    local args=()
    while IFS= read -r arg; do
        args+=("$arg")
    done < <(provider_args)

    (
        "$OPENSHELL_BIN" sandbox create \
            --name "$DEMO_SANDBOX_NAME" \
            --from "$DEMO_SANDBOX_FROM" \
            "${args[@]}" \
            --policy "$DEMO_POLICY_FILE" \
            --upload "${PAYLOAD_DIR}:/sandbox" \
            --no-git-ignore \
            --keep \
            --no-auto-providers \
            --no-tty \
            -- bash -lc "$DEMO_AGENT_COMMAND"
    ) >"$AGENT_LOG" 2>&1 &
    AGENT_PID="$!"
    info "${DIM}Agent run started; log: ${AGENT_LOG}${RESET}"
}

approve_when_pending() {
    step "Waiting for the agent to submit a policy proposal"
    local start now
    start="$(date +%s)"

    while true; do
        if ! kill -0 "$AGENT_PID" >/dev/null 2>&1; then
            wait "$AGENT_PID" || true
            fail "agent exited before a pending proposal appeared"
        fi

        "$OPENSHELL_BIN" rule get "$DEMO_SANDBOX_NAME" --status pending >"$PENDING_FILE" 2>/dev/null || true
        if grep -q "Chunk:" "$PENDING_FILE" && grep -q "pending" "$PENDING_FILE"; then
            info "${GREEN}Agent submitted a pending proposal.${RESET}"
            sed 's/^/  /' "$PENDING_FILE"

            step "Approving pending draft rule from outside the sandbox"
            "$OPENSHELL_BIN" rule approve-all "$DEMO_SANDBOX_NAME" | sed 's/^/  /'
            return
        fi

        now="$(date +%s)"
        if (( now - start >= DEMO_APPROVAL_TIMEOUT_SECS )); then
            fail "timed out waiting for the agent to submit a policy proposal"
        fi

        sleep 2
    done
}

wait_for_agent() {
    step "Waiting for the agent to retry after approval"
    if ! wait "$AGENT_PID"; then
        fail "agent run failed"
    fi
    info "${GREEN}Agent run completed.${RESET}"
}

verify_github_write() {
    step "Verifying GitHub write"
    local body status branch
    branch="$(urlencode "$DEMO_BRANCH")"
    body="${TMP_DIR}/github-created-file.json"
    status="$(github_api_status "https://api.github.com/repos/${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}/contents/${DEMO_FILE_PATH}?ref=${branch}" "$body")"
    [[ "$status" == "200" ]] || fail "expected demo file to exist after agent run; GitHub returned HTTP $status"

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
    render_task
    check_gateway
    check_github_access
    create_github_provider
    start_agent_sandbox
    approve_when_pending
    wait_for_agent
    verify_github_write
    show_logs

    printf "\n${BOLD}${GREEN}✓ Demo complete.${RESET}\n\n"
    printf "  Sandbox:    %s\n" "$DEMO_SANDBOX_NAME"
    printf "  Repository: https://github.com/%s/%s\n" "$DEMO_GITHUB_OWNER" "$DEMO_GITHUB_REPO"
    printf "  File:       %s\n" "$DEMO_FILE_PATH"
}

main "$@"
