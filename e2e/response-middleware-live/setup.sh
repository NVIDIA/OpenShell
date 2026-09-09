#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
SUITE="$ROOT/e2e/response-middleware-live"
uv venv --python "${MIDDLEWARE_LIVE_PYTHON:-3.12}" "$SUITE/.venv"
uv pip install --python "$SUITE/.venv/bin/python" -r "$SUITE/requirements.txt"
uv run --no-project --python "$SUITE/.venv/bin/python" -m grpc_tools.protoc \
  -I "$ROOT/proto" --python_out="$SUITE" --grpc_python_out="$SUITE" \
  "$ROOT/proto/supervisor_middleware.proto"
