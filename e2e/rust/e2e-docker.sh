#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Backward-compatible wrapper for the Docker Rust e2e smoke path.
#
# Prefer e2e-rust.sh with OPENSHELL_E2E_RUST_TEST for new task wiring.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

export OPENSHELL_E2E_RUST_TEST="${OPENSHELL_E2E_RUST_TEST:-${OPENSHELL_E2E_DOCKER_TEST:-smoke}}"

exec "${ROOT}/e2e/rust/e2e-rust.sh"
