#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run the Rust e2e suite against an OpenShell gateway deployed on Kubernetes
# via Helm. Set OPENSHELL_E2E_KUBE_CONTEXT to target an existing cluster;
# otherwise an ephemeral k3d cluster is created and torn down by
# with-kube-gateway.sh. Set OPENSHELL_E2E_KUBE_TEST to scope to a single
# integration test (e.g. smoke) for local debugging.
#
# Features: the default set includes `e2e-host-gateway` so tests that rely on
# the sandbox-side `host.openshell.internal` alias compile and run. The
# wrapper detects the cluster's host-routable IP and wires it into the chart
# via `server.hostGatewayIP`. Targeting a cluster where the test host is
# unreachable from pods? Set OPENSHELL_E2E_KUBERNETES_FEATURES=e2e to drop the
# alias-dependent tests entirely.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

E2E_FEATURES="${OPENSHELL_E2E_KUBERNETES_FEATURES:-e2e,e2e-host-gateway}"

cargo build -p openshell-cli --features openshell-core/dev-settings

test_filter=()
if [ -n "${OPENSHELL_E2E_KUBE_TEST:-}" ]; then
  test_filter+=(--test "${OPENSHELL_E2E_KUBE_TEST}")
fi

exec "${ROOT}/e2e/with-kube-gateway.sh" \
  cargo test --manifest-path "${ROOT}/e2e/rust/Cargo.toml" \
    --features "${E2E_FEATURES}" \
    --no-fail-fast \
    ${test_filter[@]+"${test_filter[@]}"} \
    -- --nocapture
