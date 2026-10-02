#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Shared helpers for running CLI conformance suites against an already
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
}

e2e_run_openshell_conformance() {
  local gateway_label=${1:-OpenShell}
  local root
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

  e2e_require_openshell_bin || return

  echo "==> Running CLI conformance tests against the ${gateway_label} gateway"
  cargo test \
    --locked \
    --manifest-path "${root}/tests/suites/conformance/Cargo.toml" \
    --package openshell-test-conformance-cli \
    --no-fail-fast \
    -- \
    --test-threads=1 \
    --nocapture
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  e2e_run_openshell_conformance
fi
