#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME_DIR="${ROOT}/target/debug/openshell-vm.runtime"
GATEWAY_BIN="${ROOT}/target/debug/openshell-vm"

if [ "$(uname -s)" = "Darwin" ]; then
  export DYLD_FALLBACK_LIBRARY_PATH="${RUNTIME_DIR}${DYLD_FALLBACK_LIBRARY_PATH:+:${DYLD_FALLBACK_LIBRARY_PATH}}"
fi

exec "${GATEWAY_BIN}" "$@"
