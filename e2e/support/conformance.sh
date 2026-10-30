#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Shared helpers for running conformance suites against an already
# configured e2e gateway.

e2e_require_openshell_bin() {
  if [ -z "${OPENSHELL_BIN:-}" ]; then
    echo "ERROR: OPENSHELL_BIN must point to the openshell CLI under test" >&2
    return 2
  fi

  if [ ! -x "${OPENSHELL_BIN}" ]; then
    echo "ERROR: openshell CLI is not executable: ${OPENSHELL_BIN}" >&2
    return 2
  fi

  # Cargo runs each test from its package directory, so resolve the candidate
  # relative to the caller's working directory before passing it to the tests.
  local binary_dir
  binary_dir="$(cd "$(dirname "${OPENSHELL_BIN}")" && pwd -P)" || return
  export OPENSHELL_BIN="${binary_dir}/$(basename "${OPENSHELL_BIN}")"
}

e2e_run_openshell_conformance() {
  local gateway_label=${1:-OpenShell}
  local root
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

  e2e_require_openshell_bin || return

  # The tests find the gateway as the CLI does: OPENSHELL_GATEWAY_ENDPOINT,
  # else OPENSHELL_GATEWAY, else the active gateway. The gateway wrappers set
  # these for the gateway they started.
  echo "==> Running conformance suites against the ${gateway_label} gateway"
  cargo nextest run \
    --locked \
    --manifest-path "${root}/tests/suites/conformance/Cargo.toml" \
    --package sandbox \
    --test-threads 1 \
    --no-fail-fast \
    --no-tests fail
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  e2e_run_openshell_conformance
fi
