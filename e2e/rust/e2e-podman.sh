#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run the Rust e2e suite against a standalone gateway running the bundled Podman
# compute driver. Set OPENSHELL_GATEWAY_ENDPOINT=http://host:port to reuse an
# existing gateway instead of starting an ephemeral one.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
E2E_TEST="${OPENSHELL_E2E_PODMAN_TEST:-}"
E2E_TEST_SET="${OPENSHELL_E2E_PODMAN_TEST_SET:-}"
# Unset or empty selects Rust defaults; e2e-conformance-only skips Rust tests.
E2E_FEATURES="${OPENSHELL_E2E_PODMAN_FEATURES:-e2e-podman}"
DEFAULT_WORKLOAD_MANIFEST="${ROOT}/e2e/gpu/images/.build/workloads.yaml"
RUN_WITH_GATEWAY_COMMAND="__openshell_run_podman_e2e"
# shellcheck source=e2e/support/conformance.sh
source "${ROOT}/e2e/support/conformance.sh"

# Required branch CI runs only the Podman targets that the tmachine e2e-podman
# testsuite can't run yet (see podmanE2eFollowUpBinaries in
# tests/tmachine/artifacts.nix), plus otlp_relay, whose collector cases need the
# OTLP endpoint this script configures. tmachine runs the rest of the Podman
# targets and the conformance suite. Remove each target here once it moves to
# testkit (#5297).
PODMAN_CI_TESTS=(
  driver_config_volume
  local_driver_token_restart
  otlp_relay
  podman_corporate_proxy
  podman_gateway_start
  provider_token_exchange
)

if [ -n "${E2E_TEST}" ] && [ -n "${E2E_TEST_SET}" ]; then
  echo "error: OPENSHELL_E2E_PODMAN_TEST and OPENSHELL_E2E_PODMAN_TEST_SET cannot both be set" >&2
  exit 2
fi

case "${E2E_TEST_SET}" in
  "")
    SELECTED_TESTS=()
    ;;
  ci)
    SELECTED_TESTS=("${PODMAN_CI_TESTS[@]}")
    ;;
  *)
    echo "error: unknown Podman E2E test set '${E2E_TEST_SET}' (expected 'ci')" >&2
    exit 2
    ;;
esac

if [ -n "${E2E_TEST}" ]; then
  SELECTED_TESTS=("${E2E_TEST}")
fi

if [ "${E2E_TEST}" = "additional_ca" ]; then
  export OPENSHELL_E2E_ADDITIONAL_CA=1
  E2E_FEATURES="${E2E_FEATURES},e2e-additional-ca"
fi

if [ "${E2E_TEST}" = "gpu" ] && [ -z "${OPENSHELL_E2E_WORKLOAD_MANIFEST:-}" ] && [ ! -f "${DEFAULT_WORKLOAD_MANIFEST}" ]; then
  echo "note: running Podman GPU e2e without a workload manifest; workload validation will log an explicit skip. Build one with 'CONTAINER_ENGINE=podman mise run e2e:workloads:build' or set OPENSHELL_E2E_WORKLOAD_MANIFEST."
fi

if [ "${1:-}" = "${RUN_WITH_GATEWAY_COMMAND}" ]; then
  # The tmachine Podman rows already run conformance for the ci set.
  if [ "${E2E_TEST_SET}" != "ci" ]; then
    e2e_run_openshell_conformance "Podman"
  fi
  if [ "${E2E_FEATURES}" = "e2e-conformance-only" ]; then
    echo "::notice::Skipping Rust e2e tests (e2e-conformance-only)"
    exit 0
  fi

  TEST_ARGS=(
    cargo test --manifest-path "${ROOT}/e2e/rust/Cargo.toml"
    --features "${E2E_FEATURES}"
  )
  for test_target in "${SELECTED_TESTS[@]}"; do
    TEST_ARGS+=(--test "${test_target}")
  done
  TEST_ARGS+=(-- --nocapture)
  "${TEST_ARGS[@]}"
  exit 0
fi

# An empty selector runs the full Podman suite, including provider_token_exchange.
if [ "${#SELECTED_TESTS[@]}" -eq 0 ] || [[ " ${SELECTED_TESTS[*]} " == *" provider_token_exchange "* ]]; then
  export OPENSHELL_E2E_SPIFFE_FIXTURE="${OPENSHELL_E2E_SPIFFE_FIXTURE:-1}"
fi

# When the selection includes otlp_relay, enable OTLP export in the generated
# gateway config so the test can bind a collector stub on this port. All
# selected tests share the gateway, so they run with the relay enabled too.
# Containers reach the host through host.containers.internal. Set the
# variable to an empty string to disable export and run the relay's inert
# case instead.
if [ "${#SELECTED_TESTS[@]}" -eq 0 ] || [[ " ${SELECTED_TESTS[*]} " == *" otlp_relay "* ]]; then
  export OPENSHELL_E2E_OTLP_ENDPOINT="${OPENSHELL_E2E_OTLP_ENDPOINT-http://host.containers.internal:4317}"
fi

if [ -n "${OPENSHELL_GATEWAY_ENDPOINT:-}" ] && [ -z "${OPENSHELL_BIN:-}" ]; then
  cargo build -p openshell-cli
  export OPENSHELL_BIN="${ROOT}/target/debug/openshell"
fi

if [ "${E2E_FEATURES}" != "e2e-conformance-only" ]; then
  CONTAINER_ENGINE=podman bash "${ROOT}/tasks/scripts/e2e-build-workload.sh"
fi

exec "${ROOT}/e2e/with-podman-gateway.sh" \
  bash "${BASH_SOURCE[0]}" "${RUN_WITH_GATEWAY_COMMAND}"
