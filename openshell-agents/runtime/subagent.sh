#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: /sandbox/payload/runtime/subagent.sh <subagent-id> < task.md" >&2
    exit 2
fi

HARNESS="${OPENSHELL_AGENT_HARNESS:-}"
[[ -n "$HARNESS" ]] || { echo "missing required env: OPENSHELL_AGENT_HARNESS" >&2; exit 1; }

ADAPTER="/sandbox/payload/runtime/harnesses/$HARNESS/subagent.sh"
[[ -x "$ADAPTER" ]] || { echo "missing subagent adapter: $ADAPTER" >&2; exit 1; }

exec bash "$ADAPTER" "$1"
