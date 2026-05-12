#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Agent-driven policy management demo.
#
# Runs the full loop end-to-end:
#
#   1. A Codex agent inside an OpenShell sandbox attempts a PUT that the L7
#      proxy denies with a structured policy_denied 403.
#   2. The agent reads /etc/openshell/skills/policy_advisor.md.
#   3. The agent submits a narrow proposal (exact host, port, method, path)
#      to policy.local and saves the returned chunk_id.
#   4. The agent blocks on `GET /v1/proposals/{chunk_id}/wait` — one HTTP
#      call that sleeps on a socket. THE AGENT BURNS ZERO LLM TOKENS WHILE
#      IT WAITS; this is the load-bearing UX win over polling.
#   5. The developer (this script, simulating the host side) sees the pending
#      proposal in `openshell rule get` and approves it.
#   6. The agent's /wait returns approved within ~1 second of the approval,
#      retries the original PUT once against the hot-reloaded policy, and
#      exits.
#
# The whole loop is feature-flagged behind agent_policy_proposals_enabled and
# requires no GitHub credentials beyond the repo write token already used by
# the existing demo flow.

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
    python3 - \
        "${DEMO_GITHUB_TOKEN:-}" \
        "${CODEX_AUTH_ACCESS_TOKEN:-}" \
        "${CODEX_AUTH_REFRESH_TOKEN:-}" \
        "${CODEX_AUTH_ACCOUNT_ID:-}" \
        <<'PY'
import sys
tokens = [t for t in sys.argv[1:] if t]
for line in sys.stdin:
    for t in tokens:
        line = line.replace(t, "[redacted]")
    sys.stdout.write(line)
PY
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
    info "  • agent: ${DIM}curl -X PUT https://api.github.com/repos/${DEMO_GITHUB_OWNER}/${DEMO_GITHUB_REPO}/contents/...${RESET}"
    info "  • L7 proxy denies the write and returns a structured 403 the"
    info "    agent can parse and act on:"
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
    info "  • agent reads the skill, drafts a narrow ${DIM}addRule${RESET} for exactly that path"
    info "  • agent POSTs to ${DIM}http://policy.local/v1/proposals${RESET}, saves the"
    info "    returned ${DIM}accepted_chunk_ids[0]${RESET}"
    info "  • agent calls ${DIM}GET /v1/proposals/{chunk_id}/wait?timeout=300${RESET}"
    info "    — one HTTP call that sleeps on a socket until the developer decides."
    info "    ${BOLD}Zero LLM tokens burn during this wait.${RESET}"
    info ""
    info "${DIM}Watching for the pending draft on the gateway...${RESET}"
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
        # Agent finished? Drain its exit status and we're done.
        if ! kill -0 "$AGENT_PID" >/dev/null 2>&1; then
            spin_clear
            if ! wait "$AGENT_PID"; then
                AGENT_PID=""
                fail "agent run failed"
            fi
            AGENT_PID=""
            if (( approval_count == 0 )); then
                fail "agent exited before any pending proposal appeared"
            fi
            info "agent exited after ${approval_count} approval(s)"
            return
        fi

        # Anything pending? Approve and keep watching — the agent may
        # redraft if a previous proposal didn't yield the access it needed.
        if "$OPENSHELL_BIN" rule get "$DEMO_SANDBOX_NAME" --status pending >"$pending" 2>/dev/null \
            && grep -q "Chunk:" "$pending" && grep -q "pending" "$pending"; then
            spin_clear
            info ""
            info "${GREEN}proposal received:${RESET}"
            summarize_pending "$pending"

            if [[ "$DEMO_MANUAL_APPROVE" == "1" ]]; then
                approve_manually "$pending"
            else
                step "Approving — the agent's /wait will return within ~1s"
                "$OPENSHELL_BIN" rule approve-all "$DEMO_SANDBOX_NAME" \
                    | awk '/approved/ { print "  " $0 }'
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

# Print the OCSF JSONL trace, filtered to the three events that *are* the
# demo's story: the L7 PUT deny, the policy hot-reload, and the L7 PUT allow.
# The native OCSF shorthand is informative and consistent with the rest of
# OpenShell's logging — keep it as-is rather than re-formatting.
show_logs() {
    step "Policy decision trace (OCSF)"
    # Filter to the events that tell the loop's story end-to-end, ordered by
    # the trace's own timestamps:
    #   HTTP:PUT DENIED          — initial proxy enforcement
    #   CONFIG:PROPOSED          — agent submitted a chunk to the gateway
    #   CONFIG:APPROVED/REJECTED — developer decided; agent's /wait woke up
    #   CONFIG:LOADED            — supervisor hot-reloaded the merged policy
    #   HTTP:PUT ALLOWED         — agent's retry succeeded
    "$OPENSHELL_BIN" logs "$DEMO_SANDBOX_NAME" --since 10m -n 200 2>&1 \
        | grep -E 'HTTP:PUT.*(DENIED|ALLOWED)|CONFIG:(PROPOSED|APPROVED|REJECTED|LOADED)' \
        | sed 's/^/  /' || true
}

enable_agent_proposals() {
    # The agent-driven proposal surface (skill, policy.local routes, deny
    # next_steps) is opt-in. Snapshot the prior global value so cleanup()
    # can restore it; the sentinel "(unset)" round-trips through `settings
    # delete` rather than a value write.
    local prior
    prior="$("$OPENSHELL_BIN" settings get --global --json 2>/dev/null \
        | grep -o '"agent_policy_proposals_enabled"[^,}]*' \
        | grep -o 'true\|false' | head -1)"
    PRIOR_PROPOSALS_FLAG="${prior:-(unset)}"
    "$OPENSHELL_BIN" settings set --global \
        --key agent_policy_proposals_enabled --value true --yes >/dev/null \
        || fail "could not enable agent_policy_proposals_enabled globally"
}

main() {
    validate_env

    step "Preflight"
    check_gateway
    check_github_access
    render_payload
    create_providers
    enable_agent_proposals

    show_run_summary

    start_agent_sandbox
    approve_pending_until_agent_exits
    verify_github_write
    show_logs

    printf "\n${BOLD}${GREEN}✓ Demo complete.${RESET}\n"
}

main "$@"
