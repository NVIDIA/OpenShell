#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run a Rust e2e test against a Helm-deployed OpenShell gateway. Set
# OPENSHELL_E2E_KUBE_CONTEXT to target an existing cluster; otherwise an
# ephemeral k3d cluster is created and torn down by with-kube-gateway.sh.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
E2E_TEST="${OPENSHELL_E2E_KUBE_TEST:-smoke}"

cargo build -p openshell-cli --features openshell-core/dev-settings

exec "${ROOT}/e2e/with-kube-gateway.sh" \
  cargo test --manifest-path "${ROOT}/e2e/rust/Cargo.toml" \
    --features e2e \
    --test "${E2E_TEST}" \
    -- --nocapture
