#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: subagent.sh <subagent-id> < task.md" >&2
    exit 2
fi

SUBAGENT_ID="$1"
ADAPTER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_DIR="$(cd "$ADAPTER_DIR/../../.." && pwd)"
SUBAGENT_PROMPT="$PAYLOAD_DIR/subagents/$SUBAGENT_ID.md"
[[ -f "$SUBAGENT_PROMPT" ]] || {
    echo "missing subagent prompt: $SUBAGENT_PROMPT" >&2
    exit 1
}

CODEX_BIN="${CODEX_BIN:-codex}"
if [[ -x "$PAYLOAD_DIR/runtime/harnesses/codex/codex" ]]; then
    CODEX_BIN="$PAYLOAD_DIR/runtime/harnesses/codex/codex"
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
    printf '%s\n\n' "You are running as the $SUBAGENT_ID sub-agent inside an OpenShell sandbox."
    printf '%s\n\n' 'Follow this agent definition exactly:'
    cat "$SUBAGENT_PROMPT"
    printf '\n%s\n\n' 'Task:'
    cat "$TASK_FILE"
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
    - <"$PROMPT_FILE"
