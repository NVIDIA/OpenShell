#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run the Rust e2e suite against a Helm-deployed OpenShell gateway. Set
# OPENSHELL_E2E_KUBE_CONTEXT to target an existing cluster; otherwise an
# ephemeral k3d cluster is created and torn down by with-kube-gateway.sh.
# Set OPENSHELL_E2E_KUBE_TEST to scope to a single integration test
# (e.g. smoke) for local debugging.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cargo build -p openshell-cli --features openshell-core/dev-settings

test_filter=()
if [ -n "${OPENSHELL_E2E_KUBE_TEST:-}" ]; then
  test_filter+=(--test "${OPENSHELL_E2E_KUBE_TEST}")
fi

exec "${ROOT}/e2e/with-kube-gateway.sh" \
  cargo test --manifest-path "${ROOT}/e2e/rust/Cargo.toml" \
    --features e2e \
    --no-fail-fast \
    ${test_filter[@]+"${test_filter[@]}"} \
    -- --nocapture
