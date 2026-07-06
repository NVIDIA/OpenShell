#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Verify whether compute-driver code is present in a compiled binary.
#
# Per-driver Cargo features (driver-kubernetes, driver-docker, driver-podman,
# driver-vm) on openshell-server, all default-on, gate the driver crates and
# their in-server plumbing. Building with --no-default-features and enabling
# only a subset must produce a binary that carries only those drivers. This
# guard inspects a built binary for markers that only exist when a given
# driver is compiled in.
#
# Markers are strings baked into each driver's code and must not overlap
# with other drivers or shared code. The `present` positive control fails
# loudly if a marker goes stale, so `absent` checks can never become
# silently vacuous.

set -euo pipefail

# Marker table: DRIVER=marker_that_only_appears_when_that_driver_is_compiled_in
#
# Each driver crate declares a `#[used] static COMPILE_MARKER` holding a
# well-known byte string; the VM driver's marker lives in compute::vm behind
# `#[cfg(feature = "driver-vm")]`. `#[used]` prevents dead-code elimination
# so the marker survives every optimization level and strip mode. Keep these
# in sync with the driver crates.
declare -A MARKERS=(
  [kubernetes]="OPENSHELL_DRIVER_MARKER:kubernetes"
  [docker]="OPENSHELL_DRIVER_MARKER:docker"
  [podman]="OPENSHELL_DRIVER_MARKER:podman"
  [vm]="OPENSHELL_DRIVER_MARKER:vm"
)

ALL_DRIVERS=(kubernetes docker podman vm)

usage() {
  cat >&2 <<'EOF'
Usage:
  verify-drivers-compiled-out.sh present <driver|all> <binary>
      Assert the driver's markers ARE present. Use as a positive control.
  verify-drivers-compiled-out.sh absent <driver|all> <binary>
      Assert the driver's markers are NOT present.
  verify-drivers-compiled-out.sh only <driver[,driver...]> <binary>
      Assert markers are present for each listed driver AND absent for
      each unlisted one. Covers presence + absence in a single pass.

Drivers: kubernetes docker podman vm  (or 'all')
EOF
}

if [[ $# -lt 3 ]]; then
  usage
  exit 2
fi

mode=$1
selector=$2
binary=$3

if [[ ! -f $binary ]]; then
  echo "error: binary not found: $binary" >&2
  exit 2
fi
if ! command -v strings >/dev/null 2>&1; then
  echo "error: 'strings' (binutils) is required to inspect the binary" >&2
  exit 2
fi

dump=$(strings -a "$binary")
failed=0

# Assert that $1 marker appears at least once in $dump for driver $2.
assert_present() {
  local driver=$1
  local marker=${MARKERS[$driver]}
  local count
  count=$(grep -c -F "$marker" <<<"$dump" || true)
  if [[ $count -eq 0 ]]; then
    echo "FAIL: driver '$driver' marker '$marker' missing from $(basename "$binary")" >&2
    failed=1
  else
    echo "OK: driver '$driver' compiled in ($count occurrence(s) of '$marker')"
  fi
}

# Assert that $1 marker does NOT appear in $dump for driver $2.
assert_absent() {
  local driver=$1
  local marker=${MARKERS[$driver]}
  local count
  count=$(grep -c -F "$marker" <<<"$dump" || true)
  if [[ $count -ne 0 ]]; then
    echo "FAIL: driver '$driver' marker '$marker' found in $(basename "$binary") ($count occurrence(s)); driver was not compiled out" >&2
    failed=1
  else
    echo "OK: driver '$driver' compiled out (0 occurrences of '$marker')"
  fi
}

# Expand 'all' or a comma-separated list into the SELECTED array in the
# caller's scope. Exits 2 on any unknown driver. Runs in the current shell
# so that exit propagates — do not call this from a subshell or process
# substitution.
resolve_drivers() {
  local input=$1
  SELECTED=()
  if [[ $input == "all" ]]; then
    SELECTED=("${ALL_DRIVERS[@]}")
    return
  fi
  local drivers
  IFS=',' read -r -a drivers <<<"$input"
  for d in "${drivers[@]}"; do
    if [[ -z ${MARKERS[$d]+set} ]]; then
      echo "error: unknown driver '$d'. known: ${ALL_DRIVERS[*]}" >&2
      exit 2
    fi
    SELECTED+=("$d")
  done
}

resolve_drivers "$selector"

case "$mode" in
  present)
    for d in "${SELECTED[@]}"; do
      assert_present "$d"
    done
    ;;
  absent)
    for d in "${SELECTED[@]}"; do
      assert_absent "$d"
    done
    ;;
  only)
    declare -A present_set=()
    for d in "${SELECTED[@]}"; do
      present_set[$d]=1
    done
    for d in "${ALL_DRIVERS[@]}"; do
      if [[ -n ${present_set[$d]+set} ]]; then
        assert_present "$d"
      else
        assert_absent "$d"
      fi
    done
    ;;
  *)
    usage
    exit 2
    ;;
esac

exit "$failed"
