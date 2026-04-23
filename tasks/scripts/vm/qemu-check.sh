#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Validate QEMU host prerequisites for GPU passthrough.
#
# Checks that qemu-system-x86_64, vhost-vsock support, and required
# runtime artifacts (vmlinux, virtiofsd) are available.
#
# Usage:
#   ./qemu-check.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/_lib.sh"
ROOT="$(vm_lib_root)"

RUNTIME_DIR="${ROOT}/target/libkrun-build"

pass=0
fail=0

ok()   { echo "  [OK]   $1"; ((pass++)); }
miss() { echo "  [MISS] $1"; ((fail++)); }

echo "==> QEMU host prerequisite check"
echo ""

# ── qemu-system-x86_64 ──────────────────────────────────────────────────

echo "--- QEMU binary ---"
if command -v qemu-system-x86_64 &>/dev/null; then
    version="$(qemu-system-x86_64 --version | head -n1)"
    ok "qemu-system-x86_64 found: ${version}"
else
    miss "qemu-system-x86_64 not found (install: sudo apt install qemu-system-x86)"
fi

# ── vhost-vsock ──────────────────────────────────────────────────────────

echo "--- vhost-vsock ---"
if [ -e /dev/vhost-vsock ]; then
    ok "/dev/vhost-vsock exists"
elif lsmod 2>/dev/null | grep -q vhost_vsock; then
    ok "vhost_vsock module loaded (but /dev/vhost-vsock missing — check permissions)"
else
    miss "vhost_vsock not loaded (hint: sudo modprobe vhost_vsock)"
fi

# ── Runtime artifacts ────────────────────────────────────────────────────

echo "--- Runtime artifacts (${RUNTIME_DIR}) ---"

if [ -f "${RUNTIME_DIR}/vmlinux" ]; then
    ok "vmlinux found"
else
    miss "vmlinux not found (run: FROM_SOURCE=1 mise run vm:setup)"
fi

if [ -f "${RUNTIME_DIR}/virtiofsd" ]; then
    ok "virtiofsd found"
else
    miss "virtiofsd not found (run: mise run vm:gpu-deps)"
fi

# ── Summary ──────────────────────────────────────────────────────────────

echo ""
echo "==> Summary: ${pass} passed, ${fail} missing"

if [ "$fail" -gt 0 ]; then
    echo ""
    echo "Fix the missing prerequisites above before running QEMU GPU passthrough."
    exit 1
fi

echo ""
echo "All QEMU prerequisites satisfied."
exit 0
