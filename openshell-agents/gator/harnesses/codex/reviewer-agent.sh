#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

REVIEWER_PROMPT="${REVIEWER_PROMPT:-/sandbox/payload/.claude/agents/principal-engineer-reviewer.md}"
[[ -f "$REVIEWER_PROMPT" ]] || {
    echo "missing reviewer prompt: $REVIEWER_PROMPT" >&2
    exit 1
}

CODEX_BIN="${CODEX_BIN:-codex}"
if [[ -x /sandbox/payload/harnesses/codex/codex ]]; then
    CODEX_BIN=/sandbox/payload/harnesses/codex/codex
fi

CODEX_MODEL="${CODEX_MODEL:-gpt-5.5}"
CODEX_REASONING="${CODEX_REASONING:-high}"

TASK_FILE="$(mktemp)"
PROMPT_FILE="$(mktemp)"
cleanup() {
    rm -f "$TASK_FILE" "$PROMPT_FILE"
}
trap cleanup EXIT

cat >"$TASK_FILE"

{
    printf '%s\n\n' 'You are running as the principal-engineer-reviewer sub-agent for OpenShell gator-gate.'
    printf '%s\n\n' 'Follow this agent definition exactly:'
    cat "$REVIEWER_PROMPT"
    printf '\n%s\n\n' 'Reviewer task:'
    cat "$TASK_FILE"
    printf '\n%s\n' 'Return the review only. Do not mutate repository state, labels, comments, or PRs.'
} >"$PROMPT_FILE"

CODEX_EXEC_ARGS=(
    exec
    --skip-git-repo-check
    --sandbox danger-full-access
    --ephemeral
)

if "$CODEX_BIN" exec --help 2>/dev/null | grep -q -- "--ignore-user-config"; then
    CODEX_EXEC_ARGS+=(--ignore-user-config)
fi
if "$CODEX_BIN" exec --help 2>/dev/null | grep -q -- "--ignore-rules"; then
    CODEX_EXEC_ARGS+=(--ignore-rules)
fi

exec "$CODEX_BIN" "${CODEX_EXEC_ARGS[@]}" \
    -c "model=\"${CODEX_MODEL}\"" \
    -c "model_reasoning_effort=\"${CODEX_REASONING}\"" \
    "$(cat "$PROMPT_FILE")"
