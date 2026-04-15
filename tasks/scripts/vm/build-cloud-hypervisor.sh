#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Download pre-built cloud-hypervisor and virtiofsd binaries for GPU passthrough.
#
# These are only needed on Linux for VFIO GPU passthrough via the
# cloud-hypervisor backend. The binaries are downloaded from their
# respective GitHub release pages.
#
# Usage:
#   ./build-cloud-hypervisor.sh [--output-dir <DIR>]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_lib.sh"
ROOT="$(vm_lib_root)"

source "${ROOT}/crates/openshell-vm/pins.env" 2>/dev/null || true

CLOUD_HYPERVISOR_VERSION="${CLOUD_HYPERVISOR_VERSION:-v42.0}"
VIRTIOFSD_VERSION="${VIRTIOFSD_VERSION:-v1.13.0}"
OUTPUT_DIR="${ROOT}/target/libkrun-build"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [ "$(uname -s)" != "Linux" ]; then
  echo "Error: cloud-hypervisor GPU passthrough is Linux-only" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
  aarch64) CHV_ARCH="aarch64"; VIRTIOFSD_ARCH="aarch64" ;;
  x86_64)  CHV_ARCH="x86_64";  VIRTIOFSD_ARCH="x86_64" ;;
  *)       echo "Error: Unsupported architecture: ${HOST_ARCH}" >&2; exit 1 ;;
esac

echo "==> Downloading cloud-hypervisor ${CLOUD_HYPERVISOR_VERSION} for ${HOST_ARCH}..."
CHV_URL="https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/${CLOUD_HYPERVISOR_VERSION}/cloud-hypervisor-static"
if [ "$CHV_ARCH" = "aarch64" ]; then
  CHV_URL="https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/${CLOUD_HYPERVISOR_VERSION}/cloud-hypervisor-static-aarch64"
fi

curl -fsSL -o "${OUTPUT_DIR}/cloud-hypervisor" "$CHV_URL"
chmod +x "${OUTPUT_DIR}/cloud-hypervisor"
echo "    Downloaded: cloud-hypervisor"

echo "==> Building virtiofsd ${VIRTIOFSD_VERSION} from source..."
VIRTIOFSD_SRC="$(mktemp -d)"
VIRTIOFSD_TARBALL_URL="https://gitlab.com/virtio-fs/virtiofsd/-/archive/${VIRTIOFSD_VERSION}/virtiofsd-${VIRTIOFSD_VERSION}.tar.gz"
curl -fsSL "$VIRTIOFSD_TARBALL_URL" | tar -xzf - -C "$VIRTIOFSD_SRC" --strip-components=1
rm -f "${VIRTIOFSD_SRC}/Cargo.lock"

CARGO_CMD="cargo"
if command -v mise &>/dev/null; then
  CARGO_CMD="mise exec -- cargo"
fi
$CARGO_CMD build --release --manifest-path "${VIRTIOFSD_SRC}/Cargo.toml"
cp "${VIRTIOFSD_SRC}/target/release/virtiofsd" "${OUTPUT_DIR}/virtiofsd"
chmod +x "${OUTPUT_DIR}/virtiofsd"
rm -rf "$VIRTIOFSD_SRC"
echo "    Built: virtiofsd"

echo ""
echo "==> GPU passthrough binaries ready in ${OUTPUT_DIR}"
ls -lah "${OUTPUT_DIR}/cloud-hypervisor" "${OUTPUT_DIR}/virtiofsd" 2>/dev/null || true
