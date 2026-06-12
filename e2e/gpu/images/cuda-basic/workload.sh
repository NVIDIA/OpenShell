#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly SUCCESS_MARKER="OPENSHELL_GPU_WORKLOAD_SUCCESS"
readonly FAILURE_MARKER="OPENSHELL_GPU_WORKLOAD_FAILURE"
readonly WORKLOAD_DIR="/usr/local/lib/openshell-gpu-workload"

run_sample() {
  local name=$1
  local expected=$2
  local binary="${WORKLOAD_DIR}/${name}"
  local output

  output="$(mktemp)"
  echo "running CUDA sample: ${name}"
  if ! "${binary}" >"${output}" 2>&1; then
    cat "${output}"
    echo "${FAILURE_MARKER} ${name} exited non-zero" >&2
    rm -f "${output}"
    exit 1
  fi

  cat "${output}"
  if ! grep -Fq "${expected}" "${output}"; then
    echo "${FAILURE_MARKER} ${name} did not print expected output: ${expected}" >&2
    rm -f "${output}"
    exit 1
  fi

  rm -f "${output}"
}

run_sample "deviceQuery" "Result = PASS"
run_sample "vectorAdd" "Test PASSED"

echo "${SUCCESS_MARKER} cuda-basic"
