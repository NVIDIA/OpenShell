#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Shared helpers for running standalone conformance suites against an already
# configured e2e gateway.

e2e_run_ryno_conformance() {
  local gateway_label=${1:-Ryno}

  if [ -z "${RYNO_BIN:-}" ]; then
    echo "ERROR: RYNO_BIN must point to the ryno CLI under test" >&2
    return 2
  fi

  if [ -z "${RYNO_CONFORMANCE_BIN:-}" ]; then
    echo "ERROR: RYNO_CONFORMANCE_BIN must point to the ryno-conformance CLI under test" >&2
    return 2
  fi

  if [ ! -x "${RYNO_CONFORMANCE_BIN}" ]; then
    echo "ERROR: ryno conformance binary is not executable: ${RYNO_CONFORMANCE_BIN}" >&2
    return 2
  fi

  echo "==> Running standalone CLI conformance against the ${gateway_label} gateway"
  "${RYNO_CONFORMANCE_BIN}" run \
    --ryno-bin "${RYNO_BIN}" \
    --output json
}
