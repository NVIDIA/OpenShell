#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Verify that the Cedar policy engine stays an explicit opt-in.
#
# Stable release binaries must not link the Cedar engine. Only the
# openshell-gateway and openshell-supervisor `cedar` features may pull it in,
# and the Release Dev workflow enables them explicitly.
#
#   1. Negative checks. Each stable binary configuration, built the way the
#      release workflows build it, must contain none of the Cedar crates.
#   2. Positive controls. The `cedar` features must pull Cedar in,
#      so a renamed feature or a pattern typo cannot make the negative checks
#      pass vacuously.
#
# Every configuration runs as its own `cargo tree` invocation. Several `-p`
# flags in one invocation unify their features, which would hide a leak.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

CEDAR_CRATES_PATTERN='^(cedar-policy|cedar-policy-core|cedar-policy-formatter|openshell-policy-cedar|openshell-policy-cedar-schema) v'
CEDAR_ENGINE_PATTERN='^cedar-policy v'

failed=0

dependency_tree() {
  cargo tree --locked -e normal --target all --prefix none "$@"
}

expect_no_cedar() {
  local label=$1
  shift
  local tree
  local crate
  local -a offending=()
  local -a invert_args=()

  if ! tree="$(dependency_tree "$@")"; then
    echo "FAIL: cargo tree failed for ${label} (cargo tree $*)" >&2
    failed=1
    return
  fi
  while IFS= read -r crate; do
    offending+=("${crate}")
  done < <(grep -E "${CEDAR_CRATES_PATTERN}" <<<"${tree}" | awk '{print $1}' | sort -u)

  if [[ "${#offending[@]}" -eq 0 ]]; then
    echo "OK: ${label} excludes the Cedar policy engine"
    return
  fi

  echo "FAIL: ${label} includes the Cedar policy engine: ${offending[*]}" >&2
  echo "      cargo tree --locked -e normal --target all $*" >&2
  for crate in "${offending[@]}"; do
    invert_args+=(-i "${crate}")
  done
  # The inverted tree shows which dependency path pulls each Cedar crate in.
  if ! cargo tree --locked -e normal --target all "$@" "${invert_args[@]}" >&2; then
    printf '%s\n' "${tree}" >&2
  fi
  failed=1
}

expect_cedar() {
  local label=$1
  shift
  local tree

  if ! tree="$(dependency_tree "$@")"; then
    echo "FAIL: cargo tree failed for ${label} (cargo tree $*)" >&2
    failed=1
    return
  fi
  if grep -Eq "${CEDAR_ENGINE_PATTERN}" <<<"${tree}"; then
    echo "OK: ${label} includes the Cedar policy engine"
    return
  fi

  echo "FAIL: ${label} does not include cedar-policy" >&2
  echo "      cargo tree --locked -e normal --target all $*" >&2
  printf '%s\n' "${tree}" >&2
  failed=1
}

# Stable configurations. These mirror the packages and features that
# .github/workflows/build-binaries.yml and build-vm-driver.yml build when no
# extra Cargo features are requested.
expect_no_cedar "openshell-gateway (default features)" -p openshell-gateway
expect_no_cedar "openshell-gateway (MXC compute driver only)" \
  -p openshell-gateway --no-default-features --features compute-driver-mxc
expect_no_cedar "openshell-supervisor (default features)" -p openshell-supervisor
expect_no_cedar "openshell-cli" -p openshell-cli
expect_no_cedar "openshell-sandbox" -p openshell-sandbox
expect_no_cedar "openshell-driver-vm (default features)" -p openshell-driver-vm
expect_no_cedar "openshell-vm-init (openshell-driver-vm without default features)" \
  -p openshell-driver-vm --no-default-features
expect_no_cedar "openshell-prover-cli" -p openshell-prover-cli

# Positive controls for the opt-in features.
expect_cedar "openshell-gateway --features cedar" -p openshell-gateway --features cedar
expect_cedar "openshell-supervisor --features cedar" -p openshell-supervisor --features cedar

exit "${failed}"
