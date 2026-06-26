#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

version="${1:-${CODEX_VERSION:-latest}}"

if [[ "$version" != "latest" && ! "$version" =~ ^[0-9]+(\.[0-9]+){0,2}(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "unsupported Codex version: $version" >&2
    exit 2
fi

npm install -g "@openai/codex@${version}"
npm cache clean --force >/dev/null 2>&1 || true
codex --version
