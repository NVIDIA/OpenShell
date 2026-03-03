#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# openclaw-start — Configure OpenClaw and start the gateway.
# Designed for Navigator sandboxes.
#
# Usage:
#   nav sandbox create --forward 18789 -- openclaw-start
set -euo pipefail

openclaw onboard

nohup openclaw gateway run > /tmp/gateway.log 2>&1 &

CONFIG_FILE="${HOME}/.openclaw/openclaw.json"
token=$(grep -o '"token"\s*:\s*"[^"]*"' "${CONFIG_FILE}" 2>/dev/null | head -1 | cut -d'"' -f4 || true)

echo ""
echo "OpenClaw gateway starting in background."
echo "  Logs: /tmp/gateway.log"
if [ -n "${token}" ]; then
    echo "  UI:   http://127.0.0.1:18789/?token=${token}"
else
    echo "  UI:   http://127.0.0.1:18789/"
fi
echo ""
