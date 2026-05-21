#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Agent-driven policy management demo.
#
# Shows the approval loop in one run:
#   deny → agent proposes narrow access → gateway validates → approve → retry.
# A public raw.githubusercontent.com GET auto-approves; the GitHub PUT waits
# for review because a GitHub credential is in scope. See README.md for the
# full walkthrough.

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
DEMO_CODEX_MODEL="${DEMO_CODEX_MODEL:-gpt-5.4-mini}"
DEMO_CODEX_LOCAL_BIN="${DEMO_CODEX_LOCAL_BIN:-}"
DEMO_MANUAL_APPROVE="${DEMO_MANUAL_APPROVE:-0}"
# Manual approvals need more headroom than the auto-approve loop — a human
# reads the proposal, thinks, and decides. Bump the default to 30 min when
# the developer is in the loop. Explicit overrides still win.
if [[ "$DEMO_MANUAL_APPROVE" == "1" ]]; then
    DEMO_APPROVAL_TIMEOUT_SECS="${DEMO_APPROVAL_TIMEOUT_SECS:-1800}"
else
    DEMO_APPROVAL_TIMEOUT_SECS="${DEMO_APPROVAL_TIMEOUT_SECS:-240}"
fi
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

# Wall-clock anchor so each step header can carry a "[t+1.2s]" tag and the
# reader sees where time is going. `date +%s.%N` works on macOS bash where
# `${EPOCHREALTIME}` may be unavailable in older bashes.
DEMO_START_EPOCH="$(date +%s.%N)"

elapsed() {
    awk -v s="$DEMO_START_EPOCH" -v now="$(date +%s.%N)" \
        'BEGIN { printf "%.1fs", now - s }'
}

step() {
    printf "\n${BOLD}${CYAN}==> [t+%s] %s${RESET}\n\n" "$(elapsed)" "$1"
}
info() { printf "  %b\n" "$*"; }

# ASCII spinner for the watch-for-pending loop. Renders only on a TTY so
# piped runs (CI, tee, etc.) stay clean. spin_wait pairs a message with a
# bounded sleep so the spinner animates smoothly without polling faster
# than necessary.
SPINNER_CHARS=( '⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏' )
SPINNER_IDX=0

spin_wait() {
    local message="$1"
    local duration_secs="${2:-2}"
    if [[ ! -t 1 ]]; then
        sleep "$duration_secs"
        return
    fi
    local end=$(( SECONDS + duration_secs ))
    while (( SECONDS < end )); do
        printf "\r  ${DIM}%s${RESET} %s  " \
            "${SPINNER_CHARS[SPINNER_IDX]}" "$message"
        SPINNER_IDX=$(( (SPINNER_IDX + 1) % ${#SPINNER_CHARS[@]} ))
        sleep 0.1
    done
}

spin_clear() {
    if [[ -t 1 ]]; then
        printf "\r%*s\r" "${COLUMNS:-100}" ''
    fi
}

# Redact host-side credentials from the agent log tail before printing on
# failure. Codex shouldn't echo the token, but a misbehaving tool call (e.g.,
# `curl -v`) could leak it; sanitize before showing the log.
#
# Uses python's literal `str.replace` rather than sed because tokens
# (especially JWTs) can contain characters that break sed's pattern parser
# — a sed delimiter collision in one of the substitutions blanks the entire
# log tail, hiding the very failure context we're trying to surface.
redact_log() {
    python3 -c '
import sys
tokens = [t for t in sys.argv[1:] if t]
for line in sys.stdin:
    for t in tokens:
        line = line.replace(t, "[redacted]")
    sys.stdout.write(line)
' \
        "${DEMO_GITHUB_TOKEN:-}" \
        "${CODEX_AUTH_ACCESS_TOKEN:-}" \
        "${CODEX_AUTH_REFRESH_TOKEN:-}" \
        "${CODEX_AUTH_ACCOUNT_ID:-}"
}

fail() {
    printf "\n${RED}error:${RESET} %s\n" "$*" >&2
    if [[ -f "$AGENT_LOG" ]]; then
        printf "\n${YELLOW}Agent log tail:${RESET}\n" >&2
        tail -n 80 "$AGENT_LOG" | redact_log | sed 's/^/  /' >&2 || true
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

    # Restore the agent_policy_proposals_enabled setting to what it was
    # before this run.
    if [[ -n "${PRIOR_PROPOSALS_FLAG:-}" ]]; then
        if [[ "$PRIOR_PROPOSALS_FLAG" == "(unset)" ]]; then
            "$OPENSHELL_BIN" settings delete --global --key agent_policy_proposals_enabled --yes \
                >/dev/null 2>&1 || true
        else
            "$OPENSHELL_BIN" settings set --global --key agent_policy_proposals_enabled \
                --value "$PRIOR_PROPOSALS_FLAG" --yes >/dev/null 2>&1 || true
        fi
    fi

    # Restore the providers_v2_enabled setting to what it was before this
    # run. The demo opts in to v2 composition so provider profiles
    # contribute to the effective policy; restore so the host's broader
    # workflow isn't affected.
    if [[ -n "${PRIOR_PROVIDERS_V2_FLAG:-}" ]]; then
        if [[ "$PRIOR_PROVIDERS_V2_FLAG" == "(unset)" ]]; then
            "$OPENSHELL_BIN" settings delete --global --key providers_v2_enabled --yes \
                >/dev/null 2>&1 || true
        else
            "$OPENSHELL_BIN" settings set --global --key providers_v2_enabled \
                --value "$PRIOR_PROVIDERS_V2_FLAG" --yes >/dev/null 2>&1 || true
        fi
    fi

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
    export CODEX_AUTH_ACCESS_TOKEN CODEX_AUTH_REFRESH_TOKEN CODEX_AUTH_ACCOUNT_ID DEMO_CODEX_MODEL
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
    # DEMO_FILE_DIR is interpolated through `sed` with `|` as the delimiter
    # when rendering the agent task; reject any character that would break
    # the substitution or escape into a shell context.
    [[ "$DEMO_FILE_DIR" =~ ^[A-Za-z0-9._/-]+$ ]] || fail "DEMO_FILE_DIR contains unsupported characters"

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
    # libraries that respect it. Capture stderr explicitly so a connection
    # failure (gateway down, port-forward died after a redeploy) surfaces a
    # real error message instead of `set -euo pipefail` silently exiting.
    if ! raw="$(NO_COLOR=1 "$OPENSHELL_BIN" status 2>&1)"; then
        fail "openshell could not reach the gateway. CLI output:
${raw}

If you just redeployed, the kubectl port-forward you backgrounded earlier
probably died with the old pod. Restart it (silenced so its noise doesn't
bleed into the demo):
  KUBECONFIG=kubeconfig kubectl -n openshell port-forward svc/openshell 8090:8080 >/dev/null 2>&1 &"
    fi
    raw="$(sed 's/\x1b\[[0-9;]*m//g' <<<"$raw")"
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
    sed "s|DEMO_CODEX_MODEL=\"\${DEMO_CODEX_MODEL:-gpt-5.4-mini}\"|DEMO_CODEX_MODEL=\"\${DEMO_CODEX_MODEL:-${DEMO_CODEX_MODEL}}\"|" \
        "$SANDBOX_AGENT" > "${PAYLOAD_DIR}/sandbox-agent.sh"
    if [[ -n "$DEMO_CODEX_LOCAL_BIN" ]]; then
        [[ -x "$DEMO_CODEX_LOCAL_BIN" ]] || fail "DEMO_CODEX_LOCAL_BIN is not executable: $DEMO_CODEX_LOCAL_BIN"
        cp "$DEMO_CODEX_LOCAL_BIN" "${PAYLOAD_DIR}/codex"
        chmod +x "${PAYLOAD_DIR}/codex"
    fi
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
        --type github \
        --credential DEMO_GITHUB_TOKEN >/dev/null

    info "providers created (codex, github) — credentials injected as env vars only"
}

start_agent_sandbox() {
    step "Launching sandbox; agent will hit a policy block and draft a proposal"
    "$OPENSHELL_BIN" sandbox delete "$DEMO_SANDBOX_NAME" >/dev/null 2>&1 || true

    info "policy:   raw GitHub schema path denied; GitHub writes denied"
    info "approval: auto for no new findings; review for credential risk"
    info "target:   PUT /repos/${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}/contents/${DEMO_FILE_PATH}"
    info "log:      ${AGENT_LOG}"

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
            --approval-mode auto \
            --upload "${PAYLOAD_DIR}:/sandbox" \
            --no-git-ignore \
            --no-auto-providers \
            --no-tty \
            -- bash /sandbox/payload/sandbox-agent.sh
    ) >"$AGENT_LOG" 2>&1 &
    AGENT_PID="$!"
}

# Strip `rule get` down to the approval contract: chunk, binary, access,
# and the prover's categorical findings (no severity grade — the prover
# emits category names like `credential_reach_expansion` and
# `capability_expansion`).
summarize_pending() {
    local pending="$1"
    sed 's/\x1b\[[0-9;]*m//g' "$pending" \
        | awk '
            BEGIN {
                in_validation = 0
                chunk_count = 0
                validation_printed = 0
            }
            /^[[:space:]]*Chunk:/ {
                in_validation = 0
                chunk_count++
                validation_printed = 0
                if (chunk_count > 1) print ""
                sub(/^[[:space:]]*/, "")
                chunk_id = $2
                short_id = substr(chunk_id, 1, 8)
                print "  Request " chunk_count ": chunk " short_id
                next
            }
            /Binary:/ {
                in_validation = 0
                sub(/^[[:space:]]*/, "")
                sub(/^Binary:/, "Binary:    ")
                print "    " $0
                next
            }
            /Endpoints:/ {
                in_validation = 0
                sub(/^[[:space:]]*/, "")
                if (!validation_printed) {
                    print "    Prover:    no verdict shown"
                    validation_printed = 1
                }
                sub(/^Endpoints:/, "Access:    ")
                print "    " $0
                next
            }
            /Validation:/ {
                in_validation = 1
                validation_printed = 1
                sub(/^[[:space:]]*/, "")
                sub(/^Validation:[[:space:]]*(prover:[[:space:]]*)?/, "Prover:    ")
                print "    " $0
                next
            }
            /Rationale:/ {
                in_validation = 0
                sub(/^[[:space:]]*/, "")
                sub(/^Rationale:/, "Reason:    ")
                print "    " $0
                next
            }
            # Indented continuation lines of the validation block are
            # category-named finding rows (e.g.,
            # `capability_expansion: PUT on api.github.com:443 via /usr/bin/curl`).
            in_validation && /^[[:space:]]+(credential_reach_expansion|capability_expansion|l7_bypass_credentialed|link_local_reach):/ {
                sub(/^[[:space:]]*/, "")
                print "    Finding:   " $0
                next
            }
            { in_validation = 0 }
        '
}

pending_requires_review() {
    local pending="$1"
    local clean
    # Empty-delta chunks can appear in the pending view for a moment before the
    # gateway records auto-approval. Keep the demo focused on actual review
    # work: findings, merge failures, or policy validation failures.
    clean="$(sed 's/\x1b\[[0-9;]*m//g' "$pending")"
    if grep -Eq 'Validation: (prover: [1-9][0-9]* new finding|merge failed|policy invalid)|^[[:space:]]+(credential_reach_expansion|capability_expansion|l7_bypass_credentialed|link_local_reach):' <<<"$clean"; then
        return 0
    fi
    if grep -q 'Validation:' <<<"$clean"; then
        return 1
    fi
    return 0
}

narrate_sandbox_workflow() {
    info "Loop: deny → propose → validate → decide → retry"
    info "  auto:   scoped requests with no new findings continue"
    info "  review: credentialed or risky requests pause here"
    info ""
    info "${DIM}Watching for review requests...${RESET}"
}

# In DEMO_MANUAL_APPROVE mode, swap auto-approve for a human-in-the-loop pause.
# The agent's /wait is already parked on a socket — we just stop driving the
# decision from this script and tell the user the exact commands to run from
# their other terminal. We poll `rule get --status pending` because that's the
# durable signal: a chunk leaving the pending bucket means a decision landed,
# whether approve or reject. The outer loop handles whichever path comes next
# (agent exits cleanly after approve; agent redrafts and we see a fresh
# pending chunk after reject --reason).
approve_manually() {
    local pending="$1"
    local chunk_id
    chunk_id="$(sed 's/\x1b\[[0-9;]*m//g' "$pending" \
        | awk '/^[[:space:]]*Chunk:/ { print $2; exit }')"
    [[ -n "$chunk_id" ]] || fail "could not extract chunk_id from pending output"
    local short_id="${chunk_id:0:8}"

    step "Decide from your other terminal — the agent's /wait is parked"
    info "Run ONE on the host:"
    info ""
    info "  ${BOLD}${GREEN}approve:${RESET} ${DIM}${OPENSHELL_BIN} rule approve ${DEMO_SANDBOX_NAME} --chunk-id ${chunk_id}${RESET}"
    info "  ${BOLD}reject:${RESET}  ${DIM}${OPENSHELL_BIN} rule reject ${DEMO_SANDBOX_NAME} --chunk-id ${chunk_id} --reason \"scope this to ...\"${RESET}"
    info ""
    info "  ${DIM}reject --reason sends free-form guidance back to the agent; it will${RESET}"
    info "  ${DIM}read rejection_reason, draft a revised proposal, and we'll pause again.${RESET}"
    info ""

    while true; do
        if ! "$OPENSHELL_BIN" rule get "$DEMO_SANDBOX_NAME" --status pending 2>/dev/null \
            | grep -q "$chunk_id"; then
            spin_clear
            info "  ${GREEN}✓${RESET} decision recorded for chunk ${short_id}"
            return
        fi
        spin_wait "awaiting your decision on chunk ${short_id}" 2
    done
}

approve_pending_until_agent_exits() {
    step "Waiting for the agent to draft a policy proposal"
    narrate_sandbox_workflow

    local start now pending approval_count
    start="$(date +%s)"
    pending="${TMP_DIR}/pending.txt"
    approval_count=0

    while true; do
        # Agent finished? Drain its exit status and we're done. Under v1
        # auto-approval, the agent's narrow L7 proposals auto-approve at the
        # gateway and the agent can exit without any escalation surfacing
        # here. That's the success case — no human action required.
        if ! kill -0 "$AGENT_PID" >/dev/null 2>&1; then
            spin_clear
            if ! wait "$AGENT_PID"; then
                AGENT_PID=""
                fail "agent run failed"
            fi
            AGENT_PID=""
            if (( approval_count == 0 )); then
                info "agent exited with zero review approvals (all proposals auto-approved)"
            else
                info "agent exited after ${approval_count} review approval(s)"
            fi
            return
        fi

        # Anything pending needs an explicit host-side decision. Auto mode only
        # bypasses this when the gateway validation finds no new risk.
        if "$OPENSHELL_BIN" rule get "$DEMO_SANDBOX_NAME" --status pending >"$pending" 2>/dev/null \
            && grep -q "Chunk:" "$pending" && grep -q "pending" "$pending"; then
            if ! pending_requires_review "$pending"; then
                spin_wait "waiting for auto-approvals to settle" 2
                continue
            fi
            spin_clear
            info ""
            info "${YELLOW}approval requested${RESET}"
            summarize_pending "$pending"

            if [[ "$DEMO_MANUAL_APPROVE" == "1" ]]; then
                approve_manually "$pending"
            else
                info ""
                spin_wait "letting the proposal land before approving" 2
                spin_clear
                step "Approving for demo"
                local approve_output
                if ! approve_output="$("$OPENSHELL_BIN" rule approve-all "$DEMO_SANDBOX_NAME" 2>&1)"; then
                    if grep -q "no pending chunks to approve" <<<"$approve_output"; then
                        info "  decision already recorded"
                    else
                        printf "%s\n" "$approve_output" >&2
                        fail "could not approve pending proposal"
                    fi
                else
                    awk '/approved/ { print "  " $0 }' <<<"$approve_output"
                fi
            fi
            approval_count=$((approval_count + 1))
        fi

        now="$(date +%s)"
        if (( now - start >= DEMO_APPROVAL_TIMEOUT_SECS )); then
            spin_clear
            if (( approval_count == 0 )); then
                fail "timed out waiting for the agent to submit a policy proposal"
            fi
            fail "agent did not exit within ${DEMO_APPROVAL_TIMEOUT_SECS}s after ${approval_count} approval(s)"
        fi

        spin_wait "watching for pending proposals (approved ${approval_count} so far)" 2
    done
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

# Print the concise OCSF trace that shows deny, proposal, decision, reload,
# and successful retry.
show_logs() {
    step "Decision trace"
    "$OPENSHELL_BIN" logs "$DEMO_SANDBOX_NAME" --since 10m -n 200 2>&1 \
        | grep -E 'HTTP:PUT.*(DENIED|ALLOWED)|agent_authored proposal|auto-approved: no new prover findings \(source=agent_authored\)|gateway approved draft chunk .*PUT|Policy reloaded successfully' \
        | grep -v 'source=mechanistic' \
        | sed 's/^/  /' || true
}

enable_agent_proposals() {
    # The agent-driven proposal surface (skill, policy.local routes, deny
    # next_steps) is opt-in. Snapshot the prior global value so cleanup()
    # can restore it; the sentinel "(unset)" round-trips through `settings
    # delete` rather than a value write.
    local prior
    prior="$("$OPENSHELL_BIN" settings get --global --json 2>/dev/null \
        | jq -r '.settings.agent_policy_proposals_enabled // empty | tostring | select(. == "true" or . == "false")')"
    PRIOR_PROPOSALS_FLAG="${prior:-(unset)}"
    "$OPENSHELL_BIN" settings set --global \
        --key agent_policy_proposals_enabled --value true --yes >/dev/null \
        || fail "could not enable agent_policy_proposals_enabled globally"
}

enable_providers_v2() {
    # Providers-v2 composition is behind a global flag. The demo opts in
    # so provider profiles (codex, github) contribute to the effective
    # policy via composition. Cleanup restores the prior value.
    local prior
    prior="$("$OPENSHELL_BIN" settings get --global --json 2>/dev/null \
        | jq -r '.settings.providers_v2_enabled // empty | tostring | select(. == "true" or . == "false")')"
    PRIOR_PROVIDERS_V2_FLAG="${prior:-(unset)}"
    "$OPENSHELL_BIN" settings set --global \
        --key providers_v2_enabled --value true --yes >/dev/null \
        || fail "could not enable providers_v2_enabled globally"
}

main() {
    validate_env

    step "Preflight"
    check_gateway
    check_github_access
    render_payload
    create_providers
    enable_agent_proposals
    enable_providers_v2

    show_run_summary

    start_agent_sandbox
    approve_pending_until_agent_exits
    verify_github_write
    show_logs

    printf "\n${BOLD}${GREEN}✓ Demo complete.${RESET}\n"
}

main "$@"
