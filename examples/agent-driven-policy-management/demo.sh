#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Agent-driven policy management demo.
#
# Runs the full loop: a Codex agent inside a sandbox hits an OpenShell policy
# block, reads the policy advisor skill, drafts a narrow rule via policy.local,
# the developer approves from the host, and the agent retries successfully.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
POLICY_TEMPLATE="${SCRIPT_DIR}/policy.template.yaml"
TASK_TEMPLATE="${SCRIPT_DIR}/agent-task.md"
SANDBOX_AGENT="${SCRIPT_DIR}/sandbox-agent.sh"

OPENSHELL_BIN="${OPENSHELL_BIN:-}"
if [[ -z "$OPENSHELL_BIN" ]]; then
    if [[ -x "${REPO_ROOT}/target/debug/openshell" ]]; then
        OPENSHELL_BIN="${REPO_ROOT}/target/debug/openshell"
    else
        OPENSHELL_BIN="openshell"
    fi
fi

DEMO_GITHUB_OWNER="${DEMO_GITHUB_OWNER:-}"
DEMO_GITHUB_REPO="${DEMO_GITHUB_REPO:-openshell-policy-demo}"
DEMO_BRANCH="${DEMO_BRANCH:-main}"
DEMO_RUN_ID="${DEMO_RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
DEMO_FILE_DIR="${DEMO_FILE_DIR:-openshell-policy-advisor-demo}"
DEMO_FILE_PATH="${DEMO_FILE_DIR}/${DEMO_RUN_ID}.md"
DEMO_SANDBOX_NAME="${DEMO_SANDBOX_NAME:-policy-demo-${DEMO_RUN_ID}}"
DEMO_CODEX_PROVIDER_NAME="${DEMO_CODEX_PROVIDER_NAME:-codex-policy-demo-${DEMO_RUN_ID}}"
DEMO_GITHUB_PROVIDER_NAME="${DEMO_GITHUB_PROVIDER_NAME:-github-policy-demo-${DEMO_RUN_ID}}"
DEMO_APPROVAL_TIMEOUT_SECS="${DEMO_APPROVAL_TIMEOUT_SECS:-240}"
DEMO_KEEP_SANDBOX="${DEMO_KEEP_SANDBOX:-0}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/openshell-policy-demo.XXXXXX")"
PAYLOAD_DIR="${TMP_DIR}/payload"
POLICY_FILE="${TMP_DIR}/policy.yaml"
AGENT_LOG="${TMP_DIR}/agent.log"
mkdir -p "$PAYLOAD_DIR"

# Use ANSI-C quoting so the variables hold the actual ESC byte rather than a
# literal backslash sequence. This lets `cat`, heredocs, and any non-printf
# emitter render colors correctly without per-call interpretation.
BOLD=$'\033[1m'
DIM=$'\033[2m'
CYAN=$'\033[36m'
GREEN=$'\033[32m'
RED=$'\033[31m'
YELLOW=$'\033[33m'
RESET=$'\033[0m'

AGENT_PID=""

step() { printf "\n${BOLD}${CYAN}==> %s${RESET}\n\n" "$1"; }
info() { printf "  %b\n" "$*"; }

fail() {
    printf "\n${RED}error:${RESET} %s\n" "$*" >&2
    if [[ -f "$AGENT_LOG" ]]; then
        printf "\n${YELLOW}Agent log tail:${RESET}\n" >&2
        tail -n 80 "$AGENT_LOG" | sed 's/^/  /' >&2 || true
    fi
    exit 1
}

cleanup() {
    local status=$?

    if [[ -n "$AGENT_PID" ]] && kill -0 "$AGENT_PID" >/dev/null 2>&1; then
        kill "$AGENT_PID" >/dev/null 2>&1 || true
        wait "$AGENT_PID" 2>/dev/null || true
    fi

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

resolve_github_owner() {
    if [[ -n "$DEMO_GITHUB_OWNER" ]]; then
        return
    fi
    if command -v gh >/dev/null 2>&1; then
        DEMO_GITHUB_OWNER="$(gh api user --jq .login 2>/dev/null || true)"
    fi
    [[ -n "$DEMO_GITHUB_OWNER" ]] || fail "set DEMO_GITHUB_OWNER, or sign in with: gh auth login"
}

resolve_github_token() {
    DEMO_GITHUB_TOKEN="${DEMO_GITHUB_TOKEN:-${GITHUB_TOKEN:-${GH_TOKEN:-}}}"
    if [[ -z "$DEMO_GITHUB_TOKEN" ]] && command -v gh >/dev/null 2>&1; then
        DEMO_GITHUB_TOKEN="$(gh auth token 2>/dev/null || true)"
    fi
    [[ -n "$DEMO_GITHUB_TOKEN" ]] || fail "set DEMO_GITHUB_TOKEN, GITHUB_TOKEN, GH_TOKEN, or sign in with: gh auth login"
    export DEMO_GITHUB_TOKEN
}

resolve_codex_auth() {
    [[ -f "${HOME}/.codex/auth.json" ]] || fail "missing local Codex sign-in; run: codex login"
    export CODEX_AUTH_ACCESS_TOKEN CODEX_AUTH_REFRESH_TOKEN CODEX_AUTH_ACCOUNT_ID
    CODEX_AUTH_ACCESS_TOKEN="$(jq -r '.tokens.access_token // empty' "${HOME}/.codex/auth.json")"
    CODEX_AUTH_REFRESH_TOKEN="$(jq -r '.tokens.refresh_token // empty' "${HOME}/.codex/auth.json")"
    CODEX_AUTH_ACCOUNT_ID="$(jq -r '.tokens.account_id // empty' "${HOME}/.codex/auth.json")"
    [[ -n "$CODEX_AUTH_ACCESS_TOKEN" ]] || fail "Codex sign-in is missing an access token; run: codex login"
    [[ -n "$CODEX_AUTH_REFRESH_TOKEN" ]] || fail "Codex sign-in is missing a refresh token; run: codex login"
    [[ -n "$CODEX_AUTH_ACCOUNT_ID" ]] || fail "Codex sign-in is missing an account id; run: codex login"
}

validate_env() {
    require_command curl
    require_command jq
    require_command "$OPENSHELL_BIN"

    [[ -f "$POLICY_TEMPLATE" ]] || fail "missing policy template: $POLICY_TEMPLATE"
    [[ -f "$TASK_TEMPLATE" ]] || fail "missing agent task template: $TASK_TEMPLATE"
    [[ -f "$SANDBOX_AGENT" ]] || fail "missing sandbox agent script: $SANDBOX_AGENT"

    [[ "$DEMO_GITHUB_REPO" =~ ^[A-Za-z0-9_.-]+$ ]] || fail "DEMO_GITHUB_REPO contains unsupported characters"
    [[ "$DEMO_BRANCH" =~ ^[A-Za-z0-9._/-]+$ ]] || fail "DEMO_BRANCH contains unsupported characters"
    [[ "$DEMO_RUN_ID" =~ ^[A-Za-z0-9_.-]+$ ]] || fail "DEMO_RUN_ID contains unsupported characters"

    resolve_github_owner
    [[ "$DEMO_GITHUB_OWNER" =~ ^[A-Za-z0-9_.-]+$ ]] || fail "DEMO_GITHUB_OWNER contains unsupported characters"

    resolve_github_token
    resolve_codex_auth
}

github_api_status() {
    local url="$1" body="$2"
    curl -sS -o "$body" -w "%{http_code}" \
        -H "Accept: application/vnd.github+json" \
        -H "Authorization: Bearer ${DEMO_GITHUB_TOKEN}" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "$url"
}

check_gateway() {
    local raw version
    # `openshell status` colorizes labels with ANSI even when piped, so strip
    # escapes before parsing. Use NO_COLOR as a belt-and-suspenders hint for
    # libraries that respect it.
    raw="$(NO_COLOR=1 "$OPENSHELL_BIN" status 2>/dev/null \
        | sed 's/\x1b\[[0-9;]*m//g')"
    version="$(awk -F': *' '/Version:/ { print $2; exit }' <<<"$raw")"
    [[ -n "$version" ]] \
        || fail "active OpenShell gateway is not reachable; start one with: openshell gateway start"
    info "gateway:  connected · ${version}"
}

show_run_summary() {
    step "Run summary"
    printf "  %-9s %s/%s\n" "repo:"   "$DEMO_GITHUB_OWNER" "$DEMO_GITHUB_REPO"
    printf "  %-9s %s\n"    "branch:" "$DEMO_BRANCH"
    printf "  %-9s %s\n"    "target:" "$DEMO_FILE_PATH"
    printf "  %-9s %s\n"    "sandbox:" "$DEMO_SANDBOX_NAME"
}

check_github_access() {
    local body status branch sha
    body="${TMP_DIR}/github-repo.json"
    status="$(github_api_status "https://api.github.com/repos/${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}" "$body")"
    if [[ "$status" != "200" ]]; then
        info "${RED}Repo not found:${RESET} ${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}"
        info "Create a private scratch repo first, then re-run:"
        info "  ${DIM}gh repo create ${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO} --private --add-readme \\${RESET}"
        info "  ${DIM}    --description 'OpenShell policy advisor demo scratch repo'${RESET}"
        fail "GitHub returned HTTP $status for ${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}"
    fi
    if jq -e '.permissions.push == false and .permissions.admin == false and .permissions.maintain == false' "$body" >/dev/null; then
        fail "GitHub token does not have write access to ${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}"
    fi

    branch="$(jq -rn --arg v "$DEMO_BRANCH" '$v|@uri')"
    body="${TMP_DIR}/github-branch.json"
    status="$(github_api_status "https://api.github.com/repos/${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}/branches/${branch}" "$body")"
    [[ "$status" == "200" ]] || fail "GitHub returned HTTP $status for branch ${DEMO_BRANCH}"
    sha="$(jq -r '.commit.sha[0:7]' "$body")"
    info "github:   ${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO} @ ${DEMO_BRANCH} (${sha})"

    body="${TMP_DIR}/github-target.json"
    status="$(github_api_status "https://api.github.com/repos/${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}/contents/${DEMO_FILE_PATH}?ref=${branch}" "$body")"
    if [[ "$status" == "200" ]]; then
        fail "demo output file already exists: ${DEMO_FILE_PATH}; choose a new DEMO_RUN_ID"
    fi
    [[ "$status" == "404" ]] || fail "GitHub returned HTTP $status while checking output path"
}

render_payload() {
    sed \
        -e "s|{{OWNER}}|${DEMO_GITHUB_OWNER}|g" \
        -e "s|{{REPO}}|${DEMO_GITHUB_REPO}|g" \
        -e "s|{{BRANCH}}|${DEMO_BRANCH}|g" \
        -e "s|{{FILE_PATH}}|${DEMO_FILE_PATH}|g" \
        -e "s|{{RUN_ID}}|${DEMO_RUN_ID}|g" \
        "$TASK_TEMPLATE" > "${PAYLOAD_DIR}/agent-task.md"
    cp "$SANDBOX_AGENT" "${PAYLOAD_DIR}/sandbox-agent.sh"
    cp "$POLICY_TEMPLATE" "$POLICY_FILE"
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

    info "providers created (codex, github) — credentials injected as env vars only"
}

start_agent_sandbox() {
    step "Launching sandbox; agent will hit a policy block and draft a proposal"
    "$OPENSHELL_BIN" sandbox delete "$DEMO_SANDBOX_NAME" >/dev/null 2>&1 || true

    info "initial policy:  read-only access to api.github.com (no PUT)"
    info "agent task:      PUT /repos/${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}/contents/${DEMO_FILE_PATH}"
    info "live log:        ${AGENT_LOG}"

    # `--upload <dir>:/sandbox` preserves the source directory basename
    # (matches `scp -r`/`cp -r`, see PRs #952 / #1028), so `${PAYLOAD_DIR}`
    # (basename `payload`) lands at `/sandbox/payload/...`. `--upload` accepts
    # a single value, so we ship both files in one directory.
    (
        "$OPENSHELL_BIN" sandbox create \
            --name "$DEMO_SANDBOX_NAME" \
            --from base \
            --provider "$DEMO_CODEX_PROVIDER_NAME" \
            --provider "$DEMO_GITHUB_PROVIDER_NAME" \
            --policy "$POLICY_FILE" \
            --upload "${PAYLOAD_DIR}:/sandbox" \
            --no-git-ignore \
            --no-auto-providers \
            --no-tty \
            -- bash /sandbox/payload/sandbox-agent.sh
    ) >"$AGENT_LOG" 2>&1 &
    AGENT_PID="$!"
}

# Strip the rule_get output down to the lines a developer needs to make an
# informed approve/reject decision: rationale, binary, endpoint. Filters the
# noisy fields (UUID, agent-generated rule_name, hardcoded confidence,
# duplicate Binaries) until `openshell rule get` learns to print L7
# method/path itself (tracked separately).
#
# `openshell rule get` colorizes labels with ANSI escapes; strip them before
# parsing so the field-name match works in piped contexts.
summarize_pending() {
    local pending="$1"
    sed 's/\x1b\[[0-9;]*m//g' "$pending" \
        | awk '
            /Rationale:/ { sub(/^[[:space:]]*/, ""); print "  " $0; next }
            /Binary:/    { sub(/^[[:space:]]*/, ""); print "  " $0; next }
            /Endpoints:/ { sub(/^[[:space:]]*/, ""); print "  " $0; next }
        '
}

narrate_sandbox_workflow() {
    info "Inside the sandbox right now:"
    info ""
    info "  ${BOLD}[1]${RESET} agent: ${DIM}curl -X PUT https://api.github.com/repos/${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}/contents/...${RESET}"
    info "  ${BOLD}[2]${RESET} L7 proxy denies the write and returns a structured 403 the"
    info "      agent can parse and act on:"
    cat <<EOF
${DIM}        {
          "error":      "policy_denied",
          "layer":      "l7",
          "method":     "PUT",
          "path":       "/repos/${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}/contents/${DEMO_FILE_PATH}",
          "rule_missing": { "type": "rest_allow", "host": "api.github.com", "port": 443, "method": "PUT", ... },
          "next_steps": [
            { "action": "read_skill",      "path": "/etc/openshell/skills/policy_advisor.md" },
            { "action": "submit_proposal", "url":  "http://policy.local/v1/proposals" }
          ]
        }${RESET}
EOF
    info "  ${BOLD}[3]${RESET} agent reads the skill, drafts a narrow ${DIM}addRule${RESET} for exactly that path"
    info "  ${BOLD}[4]${RESET} agent POSTs the proposal to ${DIM}http://policy.local/v1/proposals${RESET}"
    info "  ${BOLD}[5]${RESET} supervisor forwards it to the gateway as a pending draft"
    info ""
    info "${DIM}Polling for the pending draft...${RESET}"
}

approve_when_pending() {
    step "Waiting for the agent to draft a policy proposal"
    narrate_sandbox_workflow

    local start now pending
    start="$(date +%s)"
    pending="${TMP_DIR}/pending.txt"

    while true; do
        if ! kill -0 "$AGENT_PID" >/dev/null 2>&1; then
            wait "$AGENT_PID" || true
            AGENT_PID=""
            fail "agent exited before a pending proposal appeared"
        fi

        if "$OPENSHELL_BIN" rule get "$DEMO_SANDBOX_NAME" --status pending >"$pending" 2>/dev/null \
            && grep -q "Chunk:" "$pending" && grep -q "pending" "$pending"; then
            info ""
            info "${GREEN}proposal received:${RESET}"
            summarize_pending "$pending"

            step "Approving and waiting for the agent to retry"
            "$OPENSHELL_BIN" rule approve-all "$DEMO_SANDBOX_NAME" \
                | awk '/approved/ { print "  " $0 }'
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
    if ! wait "$AGENT_PID"; then
        AGENT_PID=""
        fail "agent run failed"
    fi
    AGENT_PID=""
    info "agent retried after policy hot-reload — write succeeded"
}

verify_github_write() {
    step "Verifying GitHub write"
    local body status branch
    branch="$(jq -rn --arg v "$DEMO_BRANCH" '$v|@uri')"
    body="${TMP_DIR}/github-result.json"
    status="$(github_api_status "https://api.github.com/repos/${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}/contents/${DEMO_FILE_PATH}?ref=${branch}" "$body")"
    [[ "$status" == "200" ]] || fail "expected demo file to exist after agent run; GitHub returned HTTP $status"
    jq -r '"  file: \(.path)", "  url:  \(.html_url)"' "$body"
}

# Print the OCSF JSONL trace, filtered to the three events that *are* the
# demo's story: the L7 PUT deny, the policy hot-reload, and the L7 PUT allow.
# The native OCSF shorthand is informative and consistent with the rest of
# OpenShell's logging — keep it as-is rather than re-formatting.
show_logs() {
    step "Policy decision trace (OCSF)"
    "$OPENSHELL_BIN" logs "$DEMO_SANDBOX_NAME" --since 10m -n 200 2>&1 \
        | grep -E 'HTTP:PUT.*(DENIED|ALLOWED)|CONFIG:LOADED.*Policy reloaded' \
        | sed 's/^/  /' || true
}

main() {
    validate_env

    step "Preflight"
    check_gateway
    check_github_access
    render_payload
    create_providers

    show_run_summary

    start_agent_sandbox
    approve_when_pending
    wait_for_agent
    verify_github_write
    show_logs

    printf "\n${BOLD}${GREEN}✓ Demo complete.${RESET}\n"
}

main "$@"
