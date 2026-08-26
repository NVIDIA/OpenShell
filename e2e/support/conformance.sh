#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Shared helpers for running standalone conformance suites against an already
# configured e2e gateway.

e2e_run_openshell_conformance() {
  local gateway_label=${1:-OpenShell}

  if [ -z "${OPENSHELL_BIN:-}" ]; then
    echo "ERROR: OPENSHELL_BIN must point to the openshell CLI under test" >&2
    return 2
  fi

  if [ -z "${OPENSHELL_CONFORMANCE_BIN:-}" ]; then
    echo "ERROR: OPENSHELL_CONFORMANCE_BIN must point to the openshell-conformance CLI under test" >&2
    return 2
  fi

  if [ ! -x "${OPENSHELL_CONFORMANCE_BIN}" ]; then
    echo "ERROR: openshell conformance binary is not executable: ${OPENSHELL_CONFORMANCE_BIN}" >&2
    return 2
  fi

  echo "==> Running standalone CLI conformance against the ${gateway_label} gateway"
  "${OPENSHELL_CONFORMANCE_BIN}" run \
    --openshell-bin "${OPENSHELL_BIN}" \
    --output json
}
