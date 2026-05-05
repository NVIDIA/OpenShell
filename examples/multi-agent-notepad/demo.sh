#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_TEMPLATE="${SCRIPT_DIR}/policy.template.yaml"
PROMPTS_DIR="${SCRIPT_DIR}/prompts"

OPENSHELL_BIN="${OPENSHELL_BIN:-openshell}"
DEMO_TOPIC="${DEMO_TOPIC:-How should teams evaluate sandboxed coding agents?}"
DEMO_AGENT_COUNT="${DEMO_AGENT_COUNT:-5}"
DEMO_BRANCH="${DEMO_BRANCH:-main}"
DEMO_RUN_ID="${DEMO_RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
DEMO_KEEP_SANDBOXES="${DEMO_KEEP_SANDBOXES:-0}"
DEMO_CODEX_PROVIDER_NAME="${DEMO_CODEX_PROVIDER_NAME:-codex-oauth-${DEMO_RUN_ID}}"
DEMO_GITHUB_PROVIDER_NAME="${DEMO_GITHUB_PROVIDER_NAME:-github-memory-${DEMO_RUN_ID}}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/openshell-codex-github.XXXXXX")"
POLICY_FILE="${TMP_DIR}/policy.yaml"
PAYLOAD_DIR="${TMP_DIR}/payload"
RUNNER_FILE="${PAYLOAD_DIR}/demo-runner.sh"
PROMPTS_UPLOAD_DIR="${PAYLOAD_DIR}/prompts"
LOG_DIR="${TMP_DIR}/logs"
mkdir -p "$LOG_DIR" "$PROMPTS_UPLOAD_DIR"

BOLD='\033[1m'
DIM='\033[2m'
CYAN='\033[36m'
GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
RESET='\033[0m'

WORKER_SLICES=(
  "Adoption criteria: what makes a sandboxed coding-agent workflow trustworthy enough to try?"
  "Operational risks: what can go wrong when many autonomous agents run at once?"
  "Security controls: which controls make the biggest difference for credential and network safety?"
  "Developer experience: where does the workflow need to feel simple for users to adopt it?"
  "Measurement: what signals show whether the agents produced useful work?"
  "Scaling: what changes when the team runs dozens of agents instead of five?"
  "Governance: what review and approval steps should remain human-controlled?"
  "Repository hygiene: what makes the shared markdown notepad easy to review and clean up?"
)

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

    if [[ "$DEMO_KEEP_SANDBOXES" != "1" ]]; then
        for i in $(seq 1 "$DEMO_AGENT_COUNT"); do
            "$OPENSHELL_BIN" sandbox delete "codex-gh-${DEMO_RUN_ID}-a${i}" >/dev/null 2>&1 || true
        done
        "$OPENSHELL_BIN" sandbox delete "codex-gh-${DEMO_RUN_ID}-summary" >/dev/null 2>&1 || true
    else
        printf "\n${YELLOW}Keeping sandboxes because DEMO_KEEP_SANDBOXES=1.${RESET}\n"
    fi

    "$OPENSHELL_BIN" provider delete "$DEMO_CODEX_PROVIDER_NAME" >/dev/null 2>&1 || true
    "$OPENSHELL_BIN" provider delete "$DEMO_GITHUB_PROVIDER_NAME" >/dev/null 2>&1 || true

    if [[ $status -ne 0 ]]; then
        printf "\n${YELLOW}Logs kept at: %s${RESET}\n" "$LOG_DIR"
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

validate_env() {
    require_command "$OPENSHELL_BIN"
    require_command jq
    require_command sed

    [[ -n "${DEMO_GITHUB_OWNER:-}" ]] || fail "set DEMO_GITHUB_OWNER"
    [[ -n "${DEMO_GITHUB_REPO:-}" ]] || fail "set DEMO_GITHUB_REPO"
    [[ -n "${DEMO_GITHUB_TOKEN:-}" ]] || fail "set DEMO_GITHUB_TOKEN"
    [[ -f "${HOME}/.codex/auth.json" ]] || fail "missing local Codex sign-in; run: codex login"
    [[ "$DEMO_AGENT_COUNT" =~ ^[0-9]+$ ]] || fail "DEMO_AGENT_COUNT must be a number"
    (( DEMO_AGENT_COUNT >= 1 && DEMO_AGENT_COUNT <= 8 )) || fail "DEMO_AGENT_COUNT must be between 1 and 8 for this demo"
    [[ "$DEMO_RUN_ID" =~ ^[a-z0-9-]+$ ]] || fail "DEMO_RUN_ID may contain only lowercase letters, numbers, and '-'"
    [[ "$DEMO_GITHUB_OWNER" =~ ^[A-Za-z0-9_.-]+$ ]] || fail "DEMO_GITHUB_OWNER contains unsupported characters"
    [[ "$DEMO_GITHUB_REPO" =~ ^[A-Za-z0-9_.-]+$ ]] || fail "DEMO_GITHUB_REPO contains unsupported characters"
    [[ "$DEMO_BRANCH" =~ ^[A-Za-z0-9._-]+$ ]] || fail "DEMO_BRANCH may contain only letters, numbers, '.', '_', and '-'"
    info "GitHub repo ${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}@${DEMO_BRANCH} and token present"

    info "checking OpenShell gateway is reachable..."
    "$OPENSHELL_BIN" status >/dev/null 2>&1 || fail "OpenShell gateway is not reachable; run: openshell gateway start"

    export CODEX_AUTH_ACCESS_TOKEN
    export CODEX_AUTH_REFRESH_TOKEN
    export CODEX_AUTH_ACCOUNT_ID
    CODEX_AUTH_ACCESS_TOKEN="$(jq -r '.tokens.access_token // empty' "${HOME}/.codex/auth.json")"
    CODEX_AUTH_REFRESH_TOKEN="$(jq -r '.tokens.refresh_token // empty' "${HOME}/.codex/auth.json")"
    CODEX_AUTH_ACCOUNT_ID="$(jq -r '.tokens.account_id // empty' "${HOME}/.codex/auth.json")"

    [[ -n "$CODEX_AUTH_ACCESS_TOKEN" ]] || fail "local Codex sign-in is missing an access token; run: codex login"
    [[ -n "$CODEX_AUTH_REFRESH_TOKEN" ]] || fail "local Codex sign-in is missing a refresh token; run: codex login"
    [[ -n "$CODEX_AUTH_ACCOUNT_ID" ]] || fail "local Codex sign-in is missing an account id; run: codex login"
    info "local Codex OAuth tokens loaded from ~/.codex/auth.json"
}

render_policy() {
    sed \
        -e "s/__OWNER__/${DEMO_GITHUB_OWNER}/g" \
        -e "s/__REPO__/${DEMO_GITHUB_REPO}/g" \
        -e "s/__RUN_ID__/${DEMO_RUN_ID}/g" \
        "$POLICY_TEMPLATE" > "$POLICY_FILE"
}

write_runner() {
    cp "${PROMPTS_DIR}/worker.md" "${PROMPTS_UPLOAD_DIR}/worker.md"
    cp "${PROMPTS_DIR}/synthesis.md" "${PROMPTS_UPLOAD_DIR}/synthesis.md"
    cp "${SCRIPT_DIR}/runner.sh" "$RUNNER_FILE"
    chmod +x "$RUNNER_FILE"
}

create_providers() {
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
        --type generic \
        --credential DEMO_GITHUB_TOKEN >/dev/null
}

run_sandbox() {
    local name="$1"
    shift
    "$OPENSHELL_BIN" sandbox create \
        --name "$name" \
        --from base \
        --provider "$DEMO_CODEX_PROVIDER_NAME" \
        --provider "$DEMO_GITHUB_PROVIDER_NAME" \
        --policy "$POLICY_FILE" \
        --upload "${PAYLOAD_DIR}:/sandbox" \
        --no-tty \
        -- bash /sandbox/payload/demo-runner.sh "$@"
}

run_worker() {
    local index="$1"
    local slice_index=$(( (index - 1) % ${#WORKER_SLICES[@]} ))
    local name="codex-gh-${DEMO_RUN_ID}-a${index}"
    run_sandbox "$name" worker "$DEMO_GITHUB_OWNER" "$DEMO_GITHUB_REPO" "$DEMO_BRANCH" "$DEMO_RUN_ID" "$index" "$DEMO_AGENT_COUNT" "$DEMO_TOPIC" "${WORKER_SLICES[$slice_index]}"
}

run_workers() {
    local pids=()
    local failed=0

    for i in $(seq 1 "$DEMO_AGENT_COUNT"); do
        (
            run_worker "$i"
        ) >"${LOG_DIR}/agent-${i}.log" 2>&1 &
        pids+=("$!")
        info "${DIM}started worker ${i} (log: ${LOG_DIR}/agent-${i}.log)${RESET}"
    done

    for i in $(seq 1 "$DEMO_AGENT_COUNT"); do
        if ! wait "${pids[$((i - 1))]}"; then
            failed=1
            printf "\n${RED}worker ${i} failed; log follows:${RESET}\n"
            sed 's/^/  /' "${LOG_DIR}/agent-${i}.log" | tail -80
        else
            printf "  ${GREEN}worker ${i} complete${RESET}\n"
        fi
    done

    [[ "$failed" == "0" ]] || fail "one or more workers failed"
}

run_synthesis() {
    local name="codex-gh-${DEMO_RUN_ID}-summary"
    run_sandbox "$name" synthesis "$DEMO_GITHUB_OWNER" "$DEMO_GITHUB_REPO" "$DEMO_BRANCH" "$DEMO_RUN_ID" "0" "$DEMO_AGENT_COUNT" "$DEMO_TOPIC" \
        >"${LOG_DIR}/summary.log" 2>&1 || {
            printf "\n${RED}synthesis failed; log follows:${RESET}\n"
            sed 's/^/  /' "${LOG_DIR}/summary.log" | tail -120
            return 1
        }
    printf "  ${GREEN}synthesis complete${RESET}\n"
}

print_results() {
    local base_url="https://github.com/${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}/tree/${DEMO_BRANCH}/runs/${DEMO_RUN_ID}"
    printf "\n${BOLD}${GREEN}Demo complete.${RESET}\n\n"
    printf "  Shared agent notepad:\n"
    printf "    %s\n\n" "$base_url"
    printf "  What happened:\n"
    printf "    - %s isolated worker sandboxes wrote notes to a GitHub-backed markdown notepad.\n" "$DEMO_AGENT_COUNT"
    printf "    - One synthesis sandbox read those notes and wrote the final summary.\n"
    printf "    - No worker shared a filesystem or container with another worker.\n\n"
    printf "  Generated files:\n"
    for i in $(seq 1 "$DEMO_AGENT_COUNT"); do
        printf "    - %s/notes/agent-%s.md\n" "$base_url" "$i"
    done
    printf "    - %s/summary.md\n" "$base_url"
}

main() {
    step "Validating Codex and GitHub credentials"
    validate_env
    render_policy
    write_runner

    step "Creating provider-backed Codex OAuth and GitHub token records"
    create_providers

    step "Launching ${DEMO_AGENT_COUNT} Codex worker sandboxes"
    run_workers

    step "Launching synthesis Codex sandbox"
    run_synthesis

    print_results
}

main "$@"
