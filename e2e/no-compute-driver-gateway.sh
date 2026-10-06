#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

echo "Building gateway without compiled compute drivers..."
cargo build -p ryno-gateway --bin ryno-gateway \
  --no-default-features --features telemetry
cargo check -p ryno-core --no-default-features --all-targets

dependency_tree="$(cargo tree -p ryno-gateway \
  --no-default-features --features telemetry --edges normal)"
server_dependency_tree="$(cargo tree -p ryno-server --edges normal)"
for driver in \
  ryno-driver-docker \
  ryno-driver-kubernetes \
  ryno-driver-podman \
  ryno-driver-vm; do
  if grep -q "${driver} v" <<<"${dependency_tree}"; then
    echo "ERROR: driver-free gateway dependency graph contains ${driver}" >&2
    exit 1
  fi
  if grep -q "${driver} v" <<<"${server_dependency_tree}"; then
    echo "ERROR: ryno-server dependency graph contains ${driver}" >&2
    exit 1
  fi
done

if rg -n \
  'ComputeDriverKind|ryno_driver_(docker|podman|kubernetes)([^_[:alnum:]]|$)|ComputeRuntime::new_(docker|podman|kubernetes)|VmComputeConfig|compute::vm|driver_config::builtin|libkrun|gvproxy|qemu' \
  crates/ryno-core crates/ryno-server; then
  echo "ERROR: backend-specific compute-driver knowledge leaked into core/server" >&2
  exit 1
fi

"${ROOT}/target/debug/ryno-gateway" --version
echo "Driver-free gateway build passed."
