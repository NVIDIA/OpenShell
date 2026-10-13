#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

echo "Building gateway without compiled compute drivers..."
cargo build -p openshell-gateway --bin openshell-gateway \
  --no-default-features --features telemetry
cargo check -p openshell-core --no-default-features --all-targets

dependency_tree="$(cargo tree -p openshell-gateway \
  --no-default-features --features telemetry --edges normal)"
server_dependency_tree="$(cargo tree -p openshell-server --edges normal)"
for driver in \
  openshell-driver-docker \
  openshell-driver-kubernetes \
  openshell-driver-podman \
  openshell-driver-vm; do
  if grep -q "${driver} v" <<<"${dependency_tree}"; then
    echo "ERROR: driver-free gateway dependency graph contains ${driver}" >&2
    exit 1
  fi
  if grep -q "${driver} v" <<<"${server_dependency_tree}"; then
    echo "ERROR: openshell-server dependency graph contains ${driver}" >&2
    exit 1
  fi
done

if rg -n \
  'ComputeDriverKind|openshell_driver_(docker|podman|kubernetes)([^_[:alnum:]]|$)|ComputeRuntime::new_(docker|podman|kubernetes)|VmComputeConfig|compute::vm|driver_config::builtin|libkrun|gvproxy|qemu' \
  crates/openshell-core crates/openshell-server; then
  echo "ERROR: backend-specific compute-driver knowledge leaked into core/server" >&2
  exit 1
fi

"${ROOT}/target/debug/openshell-gateway" --version
echo "Driver-free gateway build passed."
