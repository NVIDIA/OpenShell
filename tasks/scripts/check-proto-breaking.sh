#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

base_ref="${PROTO_BREAKING_BASE_REF:-}"
if [ -z "$base_ref" ]; then
  echo "Set PROTO_BREAKING_BASE_REF to the commit or ref to compare against." >&2
  exit 2
fi

base_sha=$(git rev-parse --verify "$base_ref^{commit}")

error_format=text
if [ "${GITHUB_ACTIONS:-}" = true ]; then
  error_format=github-actions
fi

echo "Checking protobuf API compatibility against $base_sha"
buf breaking proto \
  --against ".git#ref=$base_sha,subdir=proto" \
  --config buf.yaml \
  --error-format "$error_format"
