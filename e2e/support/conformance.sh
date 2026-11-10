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

  # Tests may run from another directory, so resolve the candidate relative
  # to the caller's working directory before passing it to them.
  local binary_dir
  binary_dir="$(cd "$(dirname "${OPENSHELL_BIN}")" && pwd -P)" || return
  export OPENSHELL_BIN="${binary_dir}/$(basename "${OPENSHELL_BIN}")"
}

# A pullable image for testkit::python_image() on lanes that can't load the
# locally built openshell/e2e-python:dev into their compute platform. It
# matches the Rust harness's E2E_WORKLOAD_IMAGE for those lanes.
# shellcheck disable=SC2034 # Used by the scripts that source this file.
E2E_PULLABLE_PYTHON_IMAGE="ghcr.io/astral-sh/uv:0.12.17-python3.12-trixie-slim@sha256:9a59bb7206905ccaae4f7dab222fbac47c125a21e5fc16f43f427cd6c940ade3"

# Print the path of the openshell-conformance program: OPENSHELL_CONFORMANCE_BIN
# if set, else a debug build from this checkout.
e2e_openshell_conformance_bin() {
  local root=$1

  if [ -n "${OPENSHELL_CONFORMANCE_BIN:-}" ]; then
    if [ ! -x "${OPENSHELL_CONFORMANCE_BIN}" ]; then
      echo "ERROR: openshell-conformance is not executable: ${OPENSHELL_CONFORMANCE_BIN}" >&2
      return 2
    fi
    echo "${OPENSHELL_CONFORMANCE_BIN}"
    return
  fi

  # Cargo reports where it put the binary, which depends on the target
  # directory and on CARGO_BUILD_TARGET. Diagnostics still go to stderr.
  local messages program
  messages="$(cargo build \
    --locked \
    --message-format=json-render-diagnostics \
    --manifest-path "${root}/tests/suites/conformance/Cargo.toml" \
    --bin openshell-conformance)" || return
  program="$(printf '%s\n' "${messages}" \
    | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -n 1)"
  if [ -z "${program}" ] || [ ! -x "${program}" ]; then
    echo "ERROR: cargo did not report the openshell-conformance binary" >&2
    return 2
  fi
  echo "${program}"
}

# Run the conformance suite with openshell-conformance. The JUnit report goes
# to OPENSHELL_CONFORMANCE_JUNIT, else results/conformance-<gateway>.xml.
e2e_run_openshell_conformance() {
  local gateway_label=${1:-OpenShell}
  local root program junit
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

  e2e_require_openshell_bin || return
  program="$(e2e_openshell_conformance_bin "${root}")" || return
  junit="${OPENSHELL_CONFORMANCE_JUNIT:-${root}/results/conformance-$(echo "${gateway_label}" | tr '[:upper:]' '[:lower:]').xml}"
  mkdir -p "$(dirname "${junit}")" || return

  # The program finds the gateway as the CLI does: OPENSHELL_GATEWAY_ENDPOINT,
  # else OPENSHELL_GATEWAY, else the active gateway. The gateway wrappers set
  # these for the gateway they started.
  echo "==> Running conformance suites against the ${gateway_label} gateway"
  "${program}" ready || return
  "${program}" run --junit "${junit}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  e2e_run_openshell_conformance
fi
