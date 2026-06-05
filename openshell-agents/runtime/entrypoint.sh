#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

require_env() {
    local name="$1"
    [[ -n "${!name:-}" ]] || { echo "missing required env: $name" >&2; exit 1; }
}

require_env OPENSHELL_AGENT_HARNESS

PROMPT_FILE="${OPENSHELL_AGENT_PROMPT:-/sandbox/payload/agent-prompt.md}"
ADAPTER="/sandbox/payload/runtime/harnesses/$OPENSHELL_AGENT_HARNESS/exec.sh"

[[ -f "$PROMPT_FILE" ]] || { echo "missing agent prompt: $PROMPT_FILE" >&2; exit 1; }
[[ -x "$ADAPTER" ]] || { echo "missing harness adapter: $ADAPTER" >&2; exit 1; }

exec bash "$ADAPTER" "$PROMPT_FILE"
