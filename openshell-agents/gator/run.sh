#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATOR_DIR="$ROOT_DIR/openshell-agents/gator"
SKILL_FILE="$ROOT_DIR/.agents/skills/gator-gate/SKILL.md"
REVIEWER_AGENT_FILE="$ROOT_DIR/.claude/agents/principal-engineer-reviewer.md"

OPENSHELL_BIN="${OPENSHELL_BIN:-openshell}"
GATEWAY="${GATOR_GATEWAY:-docker-dev}"
SANDBOX_NAME="${GATOR_SANDBOX_NAME:-gator-$(date +%Y%m%d%H%M%S)}"
SANDBOX_FROM="${GATOR_SANDBOX_FROM:-$GATOR_DIR}"
HARNESS="${GATOR_HARNESS:-codex}"
GITHUB_PROVIDER="${GATOR_GITHUB_PROVIDER:-github-gator}"
CODEX_PROVIDER="${GATOR_CODEX_PROVIDER:-codex-gator}"
CODEX_PROVIDER_PROFILE="${GATOR_CODEX_PROVIDER_PROFILE:-codex-gator}"
CODEX_ACCESS_CREDENTIAL_KEY="${GATOR_CODEX_ACCESS_CREDENTIAL_KEY:-CODEX_AUTH_ACCESS_TOKEN}"
# Upstream Codex OAuth client ID from codex-rs/login/src/auth/manager.rs.
CODEX_OAUTH_CLIENT_ID="${GATOR_CODEX_OAUTH_CLIENT_ID:-app_EMoamEEZ73f0CkXaXp7hrann}"
CODEX_MODEL="${CODEX_MODEL:-gpt-5.5}"
CODEX_REASONING="${CODEX_REASONING:-high}"
CODEX_LOCAL_BIN="${GATOR_CODEX_LOCAL_BIN:-}"
BACKGROUND=0
KEEP_SANDBOX=0

usage() {
    cat <<'EOF'
Usage: openshell-agents/gator/run.sh [options] "gator prompt"

Options:
  --gateway NAME          Gateway name to use (default: docker-dev)
  --name NAME             Sandbox name (default: gator-<timestamp>)
  --from IMAGE            Sandbox source/image (default: openshell-agents/gator)
  --harness NAME          Agent harness to run (default: codex; supported: codex)
  --github-provider NAME  GitHub provider name (default: github-gator)
  --codex-provider NAME   Codex provider name (default: codex-gator)
  --codex-access-key KEY  Codex access-token credential key (default: CODEX_AUTH_ACCESS_TOKEN)
  --codex-bin PATH        Upload this Codex executable into the sandbox
  --background            Run sandbox create in the background and write a log
  --keep                  Keep the sandbox after the harness exits (default: delete on exit)
  -h, --help              Show this help
EOF
}

fail() {
    echo "error: $*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

openshell_cmd() {
    "$OPENSHELL_BIN" --gateway "$GATEWAY" "$@"
}

upsert_provider() {
    local name="$1"
    local type="$2"
    shift 2

    if openshell_cmd provider get "$name" >/dev/null 2>&1; then
        openshell_cmd provider update "$name" "$@" >/dev/null
    else
        openshell_cmd provider create --name "$name" --type "$type" "$@" >/dev/null
    fi
}

import_provider_profile() {
    local profile_id="$1"
    local profile_file="$2"
    local import_output

    # Custom profile import is create-only. Replace it when possible so repeat
    # runs track this checkout, but keep going if a live sandbox is still using
    # the already-imported profile.
    openshell_cmd provider profile delete "$profile_id" >/dev/null 2>&1 || true
    if import_output="$(openshell_cmd provider profile import --file "$profile_file" 2>&1)"; then
        return 0
    fi
    if [[ "$import_output" == *"already exists"* ]]; then
        echo "Provider profile already exists: $profile_file"
        return 0
    fi

    printf '%s\n' "$import_output" >&2
    return 1
}

configure_codex_refresh() {
    openshell_cmd provider refresh configure "$CODEX_PROVIDER" \
        --credential-key "$CODEX_ACCESS_CREDENTIAL_KEY" \
        --strategy oauth2_refresh_token \
        --material "client_id=$CODEX_OAUTH_CLIENT_ID" \
        --material "refresh_token=$CODEX_AUTH_REFRESH_TOKEN" \
        --secret-material-key refresh_token >/dev/null
    openshell_cmd provider refresh rotate "$CODEX_PROVIDER" \
        --credential-key "$CODEX_ACCESS_CREDENTIAL_KEY" >/dev/null
    echo "Configured gateway refresh for $CODEX_PROVIDER/$CODEX_ACCESS_CREDENTIAL_KEY."
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --gateway)
            [[ $# -ge 2 ]] || fail "--gateway requires a value"
            GATEWAY="$2"
            shift 2
            ;;
        --name)
            [[ $# -ge 2 ]] || fail "--name requires a value"
            SANDBOX_NAME="$2"
            shift 2
            ;;
        --from)
            [[ $# -ge 2 ]] || fail "--from requires a value"
            SANDBOX_FROM="$2"
            shift 2
            ;;
        --harness)
            [[ $# -ge 2 ]] || fail "--harness requires a value"
            HARNESS="$2"
            shift 2
            ;;
        --github-provider)
            [[ $# -ge 2 ]] || fail "--github-provider requires a value"
            GITHUB_PROVIDER="$2"
            shift 2
            ;;
        --codex-provider)
            [[ $# -ge 2 ]] || fail "--codex-provider requires a value"
            CODEX_PROVIDER="$2"
            shift 2
            ;;
        --codex-access-key)
            [[ $# -ge 2 ]] || fail "--codex-access-key requires a value"
            CODEX_ACCESS_CREDENTIAL_KEY="$2"
            shift 2
            ;;
        --codex-bin)
            [[ $# -ge 2 ]] || fail "--codex-bin requires a value"
            CODEX_LOCAL_BIN="$2"
            shift 2
            ;;
        --background)
            BACKGROUND=1
            shift
            ;;
        --keep)
            KEEP_SANDBOX=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            fail "unknown option: $1"
            ;;
        *)
            break
            ;;
    esac
done

[[ $# -gt 0 ]] || { usage >&2; exit 2; }
USER_PROMPT="$*"

require_cmd gh
require_cmd "$OPENSHELL_BIN"
[[ -f "$SKILL_FILE" ]] || fail "missing gator skill: $SKILL_FILE"
[[ -f "$REVIEWER_AGENT_FILE" ]] || fail "missing reviewer agent: $REVIEWER_AGENT_FILE"

HARNESS_DIR="$GATOR_DIR/harnesses/$HARNESS"
HARNESS_ENTRYPOINT="/sandbox/payload/harnesses/$HARNESS/sandbox-agent.sh"
HARNESS_REVIEWER_COMMAND="bash /sandbox/payload/harnesses/$HARNESS/reviewer-agent.sh < review-task.md"
HARNESS_PROVIDER_ARGS=()
HARNESS_ENV_ARGS=()

case "$HARNESS" in
    codex)
        require_cmd jq
        [[ -d "$HARNESS_DIR" ]] || fail "missing harness directory: $HARNESS_DIR"
        [[ -f "$HOME/.codex/auth.json" ]] || fail "missing local Codex auth; run: codex login"

        CODEX_AUTH_ACCESS_TOKEN="$(jq -r '.tokens.access_token // empty' "$HOME/.codex/auth.json")"
        CODEX_AUTH_REFRESH_TOKEN="$(jq -r '.tokens.refresh_token // empty' "$HOME/.codex/auth.json")"
        CODEX_AUTH_ACCOUNT_ID="$(jq -r '.tokens.account_id // empty' "$HOME/.codex/auth.json")"
        CODEX_AUTH_ID_TOKEN="$(jq -r '.tokens.id_token // empty' "$HOME/.codex/auth.json")"
        [[ -n "$CODEX_AUTH_ACCESS_TOKEN" ]] || fail "Codex auth is missing tokens.access_token"
        [[ -n "$CODEX_AUTH_REFRESH_TOKEN" ]] || fail "Codex auth is missing tokens.refresh_token"
        [[ -n "$CODEX_AUTH_ACCOUNT_ID" ]] || fail "Codex auth is missing tokens.account_id"

        export CODEX_AUTH_ACCESS_TOKEN
        export CODEX_AUTH_ACCOUNT_ID
        export CODEX_AUTH_ID_TOKEN
        HARNESS_PROVIDER_ARGS=(--provider "$CODEX_PROVIDER")
        HARNESS_ENV_ARGS=("CODEX_MODEL=$CODEX_MODEL" "CODEX_REASONING=$CODEX_REASONING")
        ;;
    *)
        fail "unsupported harness: $HARNESS (supported: codex)"
        ;;
esac

GITHUB_TOKEN="$(gh auth token)"
[[ -n "$GITHUB_TOKEN" ]] || fail "gh auth token returned empty output"

export GITHUB_TOKEN

PAYLOAD_PARENT="$(mktemp -d "${TMPDIR:-/tmp}/openshell-gator.XXXXXX")"
PAYLOAD_DIR="$PAYLOAD_PARENT/payload"
cleanup() {
    rm -rf "$PAYLOAD_PARENT"
}
trap cleanup EXIT

mkdir -p "$PAYLOAD_DIR/.agents/skills/gator-gate"
mkdir -p "$PAYLOAD_DIR/.claude/agents"
mkdir -p "$PAYLOAD_DIR/harnesses"
cp "$SKILL_FILE" "$PAYLOAD_DIR/.agents/skills/gator-gate/SKILL.md"
cp "$REVIEWER_AGENT_FILE" "$PAYLOAD_DIR/.claude/agents/principal-engineer-reviewer.md"
cp -R "$HARNESS_DIR" "$PAYLOAD_DIR/harnesses/$HARNESS"
chmod +x "$PAYLOAD_DIR/harnesses/$HARNESS"/*.sh
if [[ -n "$CODEX_LOCAL_BIN" ]]; then
    [[ -x "$CODEX_LOCAL_BIN" ]] || fail "--codex-bin is not executable: $CODEX_LOCAL_BIN"
    [[ "$HARNESS" == "codex" ]] || fail "--codex-bin is only valid with --harness codex"
    cp "$CODEX_LOCAL_BIN" "$PAYLOAD_DIR/harnesses/codex/codex"
    chmod +x "$PAYLOAD_DIR/harnesses/codex/codex"
fi
cat > "$PAYLOAD_DIR/gator-prompt.md" <<EOF
You are running inside an OpenShell sandbox as the gator gate agent.

Active harness: $HARNESS.

Load and follow this skill exactly:

/sandbox/payload/.agents/skills/gator-gate/SKILL.md

Important sandbox constraints:

- GitHub access is intentionally REST-only and scoped to NVIDIA/OpenShell and NVIDIA/OpenShell-Community.
- Do not use GraphQL-backed gh shortcuts such as \`gh pr view\` if they fail. Prefer \`gh api\` REST endpoints under the allowed repositories.
- Keep watching active PRs until they close, merge, or the operator stops the sandbox.
- Do not push to contributor branches unless the operator explicitly instructs you to do so.
- If you receive 403 errors from the sandbox proxy, inspect the JSON response and propose a policy update to allow the requested action if the response contains a structured error message.
- When the gator skill requires the \`principal-engineer-reviewer\` sub-agent, run a bounded independent review with \`$HARNESS_REVIEWER_COMMAND\`. Include PR metadata and full diff/file context in \`review-task.md\`, save the output, and use it as the independent reviewer result while the main gator process continues labels, comments, docs, and CI gating.

Operator request:

$USER_PROMPT
EOF

openshell_cmd settings set --global --key providers_v2_enabled --value true --yes >/dev/null
openshell_cmd settings set --global --key agent_policy_proposals_enabled --value true --yes >/dev/null
openshell_cmd settings set --global --key proposal_approval_mode --value auto --yes >/dev/null

import_provider_profile github-gator "$GATOR_DIR/providers/github-gator.yaml"
upsert_provider "$GITHUB_PROVIDER" github-gator --credential GITHUB_TOKEN
case "$HARNESS" in
    codex)
        import_provider_profile "$CODEX_PROVIDER_PROFILE" "$GATOR_DIR/providers/$CODEX_PROVIDER_PROFILE.yaml"
        upsert_provider "$CODEX_PROVIDER" "$CODEX_PROVIDER_PROFILE" --from-existing
        configure_codex_refresh
        ;;
esac

KEEP_ARGS=()
if [[ "$KEEP_SANDBOX" != "1" ]]; then
    KEEP_ARGS+=(--no-keep)
fi

SANDBOX_CMD=(
    env -u OPENSHELL_SANDBOX_POLICY
    "$OPENSHELL_BIN" --gateway "$GATEWAY" sandbox create
    --name "$SANDBOX_NAME"
    --from "$SANDBOX_FROM"
    --provider "$GITHUB_PROVIDER"
    "${HARNESS_PROVIDER_ARGS[@]}"
    --upload "$PAYLOAD_DIR:/sandbox"
    --no-git-ignore
    --no-auto-providers
    --no-tty
    "${KEEP_ARGS[@]}"
    -- env "${HARNESS_ENV_ARGS[@]}" bash "$HARNESS_ENTRYPOINT"
)

echo "Launching gator sandbox '$SANDBOX_NAME' on gateway '$GATEWAY'..."
if [[ "$BACKGROUND" == "1" ]]; then
    mkdir -p "$GATOR_DIR/logs"
    LOG_FILE="$GATOR_DIR/logs/${SANDBOX_NAME}.log"
    trap - EXIT
    (
        trap cleanup EXIT
        "${SANDBOX_CMD[@]}"
    ) >"$LOG_FILE" 2>&1 &
    echo "Started in background. Log: $LOG_FILE"
else
    "${SANDBOX_CMD[@]}"
fi
