#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run the Rust e2e suite against an OpenShell gateway deployed on Kubernetes
# via Helm. Set OPENSHELL_E2E_KUBE_CONTEXT to target an existing cluster;
# otherwise an ephemeral k3d cluster is created and torn down by
# with-kube-gateway.sh. Set OPENSHELL_E2E_KUBE_TEST to scope to a single
# integration test for local debugging.
#
# Features: the default set includes `e2e-host-gateway` so tests that rely on
# the sandbox-side `host.openshell.internal` alias compile and run. The
# wrapper detects the cluster's host-routable IP and wires it into the chart
# via `server.hostGatewayIP`. Targeting a cluster where the test host is
# unreachable from pods? Set OPENSHELL_E2E_KUBERNETES_FEATURES=e2e to drop the
# alias-dependent tests entirely.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_WITH_GATEWAY_COMMAND="__openshell_run_kubernetes_e2e"
# shellcheck source=e2e/support/conformance.sh
source "${ROOT}/e2e/support/conformance.sh"

E2E_FEATURES="${OPENSHELL_E2E_KUBERNETES_FEATURES-e2e,e2e-host-gateway,e2e-kubernetes}"

# Docker and Podman build their local gateway and CLI together in the shared
# gateway wrapper. Kubernetes consumes published gateway images, so only its
# local CLI needs to be built when CI has not supplied a prebuilt one.
if [ -z "${OPENSHELL_BIN:-}" ]; then
  cargo build -p openshell-cli
  export OPENSHELL_BIN="${ROOT}/target/debug/openshell"
fi

test_filter=()
if [ -n "${OPENSHELL_E2E_KUBE_TEST:-}" ]; then
  test_filter+=(--test "${OPENSHELL_E2E_KUBE_TEST}")
fi

is_operator_workspace_mode() {
  [[ ",${E2E_FEATURES}," == *",e2e-kubernetes-workspace-operator,"* ]]
}

run_conformance() {
  if is_operator_workspace_mode; then
    echo "note: skipping standalone CLI conformance in Kubernetes operator workspace mode; default workspace is not operator-allowlisted (see #2971)."
    return 0
  fi

  e2e_run_openshell_conformance "Kubernetes"
}

run_suite() {
  "${ROOT}/e2e/with-kube-gateway.sh" \
    bash "${BASH_SOURCE[0]}" "${RUN_WITH_GATEWAY_COMMAND}"
}

run_e2e() {
  run_conformance
  if [ -z "${E2E_FEATURES}" ]; then
    return 0
  fi

  cargo test --manifest-path "${ROOT}/e2e/rust/Cargo.toml" \
    --features "${E2E_FEATURES}" \
    --no-fail-fast \
    ${test_filter[@]+"${test_filter[@]}"} \
    -- --nocapture
}

if [ "${1:-}" = "${RUN_WITH_GATEWAY_COMMAND}" ]; then
  run_e2e
  exit 0
fi

if [ "${OPENSHELL_E2E_CREDENTIAL_DRIVERS:-0}" = "1" ] \
   && [ -z "${OPENSHELL_E2E_CREDENTIAL_DRIVER:-}" ]; then
  OPENSHELL_E2E_CREDENTIAL_DRIVER=kubernetes-secrets run_suite
  OPENSHELL_E2E_CREDENTIAL_DRIVER=vault run_suite
  exit 0
fi

exec "${ROOT}/e2e/with-kube-gateway.sh" \
  bash "${BASH_SOURCE[0]}" "${RUN_WITH_GATEWAY_COMMAND}"
