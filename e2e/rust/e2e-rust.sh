#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run Rust e2e tests against a standalone gateway running the bundled Docker
# compute driver. Set OPENSHELL_E2E_RUST_TEST to a Rust integration test target
# such as "smoke" or "sync" to run only that file.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
E2E_TEST="${OPENSHELL_E2E_RUST_TEST:-}"

cargo build -p openshell-cli --features openshell-core/dev-settings

cargo_args=(
  test
  --manifest-path "${ROOT}/e2e/rust/Cargo.toml"
  --features e2e
)

test_args=()

if [ -n "${E2E_TEST}" ]; then
  cargo_args+=(--test "${E2E_TEST}")
  test_args+=(--nocapture)
else
  test_args+=(--skip docker_gpu_sandbox_runs_nvidia_smi)
fi

exec "${ROOT}/e2e/with-docker-gateway.sh" cargo "${cargo_args[@]}" -- "${test_args[@]}"
