#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build GPU passthrough dependencies for the QEMU backend.
#
# Builds virtiofsd from source.
# These are only needed on Linux for VFIO GPU passthrough.
#
# Artifacts produced:
#   virtiofsd         — filesystem daemon used by the QEMU backend
#
# The vmlinux kernel is extracted separately by build-libkrun.sh during
# the kernel build step.
#
# QEMU's own binary (qemu-system-x86_64) must be installed on the host
# separately — it is not built or downloaded by this script.
# Run `mise run vm:qemu-check` to validate QEMU prerequisites.
#
# Usage:
#   ./build-gpu-deps.sh [--output-dir <DIR>]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_lib.sh"
ROOT="$(vm_lib_root)"

source "${ROOT}/crates/openshell-vm/pins.env" 2>/dev/null || true

VIRTIOFSD_VERSION="${VIRTIOFSD_VERSION:-v1.13.0}"
OUTPUT_DIR="${ROOT}/target/libkrun-build"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [ "$(uname -s)" != "Linux" ]; then
  echo "Error: GPU passthrough is Linux-only" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
  aarch64) VIRTIOFSD_ARCH="aarch64" ;;
  x86_64)  VIRTIOFSD_ARCH="x86_64" ;;
  *)       echo "Error: Unsupported architecture: ${HOST_ARCH}" >&2; exit 1 ;;
esac

echo "==> Building virtiofsd ${VIRTIOFSD_VERSION} from source..."
VIRTIOFSD_SRC="$(mktemp -d)"
VIRTIOFSD_TARBALL_URL="https://gitlab.com/virtio-fs/virtiofsd/-/archive/${VIRTIOFSD_VERSION}/virtiofsd-${VIRTIOFSD_VERSION}.tar.gz"
curl -fsSL "$VIRTIOFSD_TARBALL_URL" | tar -xzf - -C "$VIRTIOFSD_SRC" --strip-components=1
rm -f "${VIRTIOFSD_SRC}/Cargo.lock"

CARGO_CMD="cargo"
if command -v mise &>/dev/null; then
  CARGO_CMD="mise exec -- cargo"
fi
# Prevent external CARGO_TARGET_DIR from redirecting build output away from
# the local temp directory (e.g. Cursor sandbox sets this globally).
unset CARGO_TARGET_DIR
$CARGO_CMD build --release --manifest-path "${VIRTIOFSD_SRC}/Cargo.toml"
cp "${VIRTIOFSD_SRC}/target/release/virtiofsd" "${OUTPUT_DIR}/virtiofsd"
chmod +x "${OUTPUT_DIR}/virtiofsd"
rm -rf "$VIRTIOFSD_SRC"
echo "    Built: virtiofsd"

echo ""
echo "==> GPU passthrough binaries ready in ${OUTPUT_DIR}"
ls -lah "${OUTPUT_DIR}/virtiofsd" 2>/dev/null || true
