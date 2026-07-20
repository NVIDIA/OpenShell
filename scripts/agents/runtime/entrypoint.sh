#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

require_env() {
    local name="$1"
    [[ -n "${!name:-}" ]] || { echo "missing required env: $name" >&2; exit 1; }
}

require_env OPENSHELL_AGENT_HARNESS

RUNTIME_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_DIR="$(cd "$RUNTIME_DIR/.." && pwd)"
SUPERVISOR="$PAYLOAD_DIR/runtime/supervisor.sh"

[[ -x "$SUPERVISOR" ]] || { echo "missing agent supervisor: $SUPERVISOR" >&2; exit 1; }

exec bash "$SUPERVISOR"
