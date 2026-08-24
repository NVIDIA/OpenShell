#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

echo "Building gateway without compiled compute drivers..."
cargo build -p openshell-server --bin openshell-gateway \
  --no-default-features --features telemetry

dependency_tree="$(cargo tree -p openshell-server \
  --no-default-features --features telemetry --edges normal)"
for driver in \
  openshell-driver-docker \
  openshell-driver-kubernetes \
  openshell-driver-podman \
  openshell-driver-vm; do
  if grep -q "${driver} v" <<<"${dependency_tree}"; then
    echo "ERROR: driver-free gateway dependency graph contains ${driver}" >&2
    exit 1
  fi
done

"${ROOT}/target/debug/openshell-gateway" --version
echo "Driver-free gateway build passed."
