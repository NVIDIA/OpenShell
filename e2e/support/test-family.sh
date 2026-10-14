#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC2034 # Selection variables are consumed by sourcing harnesses.

# Select execution independently of compute-driver linkage and Cargo features.
# Keep the combined local commands compatible while CI reports families apart.
e2e_select_test_family() {
  local features="$1"
  E2E_RUN_CONFORMANCE=0
  E2E_RUN_DRIVER_TESTS=0
  case "${OPENSHELL_E2E_TEST_FAMILY:-all}" in
    all)
      E2E_RUN_CONFORMANCE=1
      if [ -n "${features}" ]; then E2E_RUN_DRIVER_TESTS=1; fi
      ;;
    conformance)
      E2E_RUN_CONFORMANCE=1
      ;;
    drivers)
      if [ -z "${features}" ]; then
        echo "error: the drivers family requires a nonempty Cargo feature selection" >&2
        return 2
      fi
      E2E_RUN_DRIVER_TESTS=1
      ;;
    *)
      echo "error: unknown OPENSHELL_E2E_TEST_FAMILY '${OPENSHELL_E2E_TEST_FAMILY}' (expected all, conformance, or drivers)" >&2
      return 2
      ;;
  esac
}
