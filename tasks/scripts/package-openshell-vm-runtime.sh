#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARTIFACT_DIR="${ROOT}/artifacts"
TARGET_DIR="${ROOT}/target/release"

if [ ! -x "${TARGET_DIR}/openshell-vm" ]; then
  echo "target/release/openshell-vm not found; build it first with cargo build -p openshell-vm --release" >&2
  exit 1
fi

if [ ! -d "${TARGET_DIR}/openshell-vm.runtime" ]; then
  echo "target/release/openshell-vm.runtime not found; run mise run vm:bundle-runtime first" >&2
  exit 1
fi

mkdir -p "${ARTIFACT_DIR}"
tar -czf "${ARTIFACT_DIR}/openshell-vm-aarch64-apple-darwin.tar.gz" \
  -C "${TARGET_DIR}" \
  openshell-vm \
  openshell-vm.runtime

ls -lh "${ARTIFACT_DIR}/openshell-vm-aarch64-apple-darwin.tar.gz"
