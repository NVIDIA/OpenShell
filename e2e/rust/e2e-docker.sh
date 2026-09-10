#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run standalone CLI conformance, and optionally a focused Rust e2e test,
# against a gateway using the bundled Docker compute driver. Set
# OPENSHELL_GATEWAY_ENDPOINT=http://host:port to reuse an existing plaintext
# gateway instead of starting an ephemeral one.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
E2E_TEST="${OPENSHELL_E2E_DOCKER_TEST:-}"
E2E_FEATURES="${OPENSHELL_E2E_DOCKER_FEATURES-e2e-docker}"
DEFAULT_WORKLOAD_MANIFEST="${ROOT}/e2e/gpu/images/.build/workloads.yaml"
RUN_WITH_GATEWAY_COMMAND="__openshell_run_docker_e2e"
# shellcheck source=e2e/support/conformance.sh
source "${ROOT}/e2e/support/conformance.sh"

run_e2e() {
  e2e_run_openshell_conformance "Docker"

  if [ -z "${E2E_FEATURES}" ]; then
    return 0
  fi

  local cargo_args=(
    cargo test --manifest-path "${ROOT}/e2e/rust/Cargo.toml"
    --features "${E2E_FEATURES}"
  )
  if [ -n "${E2E_TEST}" ]; then
    cargo_args+=(--test "${E2E_TEST}")
  fi
  cargo_args+=(-- --nocapture)
  "${cargo_args[@]}"
}

if [ "${E2E_TEST}" = "gpu" ] && [ -z "${OPENSHELL_E2E_WORKLOAD_MANIFEST:-}" ] && [ ! -f "${DEFAULT_WORKLOAD_MANIFEST}" ]; then
  echo "note: running GPU e2e without a workload manifest; workload validation will log an explicit skip. Build one with 'mise run e2e:workloads:build' or set OPENSHELL_E2E_WORKLOAD_MANIFEST."
fi

if [ "${1:-}" = "${RUN_WITH_GATEWAY_COMMAND}" ]; then
  run_e2e
  exit 0
fi

exec "${ROOT}/e2e/with-docker-gateway.sh" \
  bash "${BASH_SOURCE[0]}" "${RUN_WITH_GATEWAY_COMMAND}"
