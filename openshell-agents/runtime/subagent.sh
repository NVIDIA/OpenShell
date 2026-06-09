#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: subagent.sh <subagent-id> < task.md" >&2
    exit 2
fi

HARNESS="${OPENSHELL_AGENT_HARNESS:-}"
[[ -n "$HARNESS" ]] || { echo "missing required env: OPENSHELL_AGENT_HARNESS" >&2; exit 1; }
RUNTIME_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_DIR="$(cd "$RUNTIME_DIR/.." && pwd)"

ADAPTER="$PAYLOAD_DIR/runtime/harnesses/$HARNESS/subagent.sh"
[[ -x "$ADAPTER" ]] || { echo "missing subagent adapter: $ADAPTER" >&2; exit 1; }

exec bash "$ADAPTER" "$1"
