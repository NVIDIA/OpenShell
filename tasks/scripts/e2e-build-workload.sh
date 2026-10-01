#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tasks/scripts/container-engine.sh
source "${ROOT}/tasks/scripts/container-engine.sh"
ce_build --load --file "${ROOT}/e2e/python/Dockerfile.workload" \
  --build-arg "PYTHON_VERSION=$(cat "${ROOT}/.python-version")" \
  --tag openshell/e2e-python:dev \
  "${ROOT}/e2e/python"
