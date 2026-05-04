#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build the GPU sandbox image with the correct driver version.
# Sources versions.env so the version is never typed manually.
#
# Usage:
#   ./build.sh                         # default: tags as openshell-gpu-sandbox
#   ./build.sh -t my-registry/gpu:v1   # custom tag

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=versions.env
source "${SCRIPT_DIR}/versions.env"

if [ $# -eq 0 ]; then
  set -- -t openshell-gpu-sandbox
fi

exec docker build \
  --build-arg NVIDIA_DRIVER_VERSION="${NVIDIA_DRIVER_VERSION}" \
  "$@" \
  "${SCRIPT_DIR}"
