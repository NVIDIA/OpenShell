#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run the Rust e2e suite against a standalone gateway running the bundled Podman
# compute driver. Set OPENSHELL_GATEWAY_ENDPOINT=http://host:port to reuse an
# existing gateway instead of starting an ephemeral one.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
E2E_TEST="${OPENSHELL_E2E_PODMAN_TEST:-}"
E2E_FEATURES="${OPENSHELL_E2E_PODMAN_FEATURES-e2e-podman}"
DEFAULT_WORKLOAD_MANIFEST="${ROOT}/e2e/gpu/images/.build/workloads.yaml"
RUN_WITH_GATEWAY_COMMAND="__openshell_run_podman_e2e"
# shellcheck source=e2e/support/conformance.sh
source "${ROOT}/e2e/support/conformance.sh"

if [ "${E2E_TEST}" = "gpu" ] && [ -z "${OPENSHELL_E2E_WORKLOAD_MANIFEST:-}" ] && [ ! -f "${DEFAULT_WORKLOAD_MANIFEST}" ]; then
  echo "note: running Podman GPU e2e without a workload manifest; workload validation will log an explicit skip. Build one with 'CONTAINER_ENGINE=podman mise run e2e:workloads:build' or set OPENSHELL_E2E_WORKLOAD_MANIFEST."
fi

if [ "${1:-}" = "${RUN_WITH_GATEWAY_COMMAND}" ]; then
  e2e_run_openshell_conformance "Podman"
  if [ -z "${E2E_FEATURES}" ]; then
    exit 0
  fi

  TEST_ARGS=(
    cargo test --manifest-path "${ROOT}/e2e/rust/Cargo.toml"
    --features "${E2E_FEATURES}"
  )
  if [ -n "${E2E_TEST}" ]; then
    TEST_ARGS+=(--test "${E2E_TEST}")
  fi
  TEST_ARGS+=(-- --nocapture)
  "${TEST_ARGS[@]}"
  exit 0
fi

# An empty selector runs the full Podman suite, including provider_token_exchange.
if [ -z "${E2E_TEST}" ] || [ "${E2E_TEST}" = "provider_token_exchange" ]; then
  export OPENSHELL_E2E_SPIFFE_FIXTURE="${OPENSHELL_E2E_SPIFFE_FIXTURE:-1}"
fi

if [ -n "${OPENSHELL_GATEWAY_ENDPOINT:-}" ] && [ -z "${OPENSHELL_BIN:-}" ]; then
  cargo build -p openshell-cli
  export OPENSHELL_BIN="${ROOT}/target/debug/openshell"
fi

exec "${ROOT}/e2e/with-podman-gateway.sh" \
  bash "${BASH_SOURCE[0]}" "${RUN_WITH_GATEWAY_COMMAND}"
