#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Sync mutable development artifacts into the existing VM rootfs.
# Runs on every `mise run vm` so that script changes, helm chart
# updates, manifest changes, and supervisor binary rebuilds are
# picked up without a full rootfs rebuild.
#
# This is fast (<1s) — it only copies files, no Docker or VM boot.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ROOTFS_DIR="${XDG_DATA_HOME:-${HOME}/.local/share}/openshell/openshell-vm/rootfs"
SCRIPT_DIR="${ROOT}/crates/openshell-vm/scripts"

if [ ! -d "${ROOTFS_DIR}/srv" ]; then
    # Rootfs doesn't exist yet — nothing to sync. ensure-vm-rootfs.sh
    # or build-rootfs.sh will create it.
    exit 0
fi

echo "Syncing development artifacts into rootfs..."

# ── Init scripts and utilities ─────────────────────────────────────────
for script in openshell-vm-init.sh openshell-vm-exec-agent.py check-vm-capabilities.sh hello-server.py; do
    src="${SCRIPT_DIR}/${script}"
    dst="${ROOTFS_DIR}/srv/${script}"
    if [ -f "$src" ]; then
        if ! cmp -s "$src" "$dst" 2>/dev/null; then
            cp "$src" "$dst"
            chmod +x "$dst"
            echo "  updated: /srv/${script}"
        fi
    fi
done

# ── Helm chart ─────────────────────────────────────────────────────────
HELM_CHART_DIR="${ROOT}/deploy/helm/openshell"
CHART_STAGING="${ROOTFS_DIR}/opt/openshell/charts"
if [ -d "${HELM_CHART_DIR}" ]; then
    mkdir -p "${CHART_STAGING}"
    # Package into a temp dir and compare — only update if changed.
    TMP_CHART=$(mktemp -d)
    helm package "${HELM_CHART_DIR}" -d "${TMP_CHART}" >/dev/null 2>&1
    for tgz in "${TMP_CHART}"/*.tgz; do
        [ -f "$tgz" ] || continue
        base=$(basename "$tgz")
        if ! cmp -s "$tgz" "${CHART_STAGING}/${base}" 2>/dev/null; then
            cp "$tgz" "${CHART_STAGING}/${base}"
            echo "  updated: /opt/openshell/charts/${base}"
        fi
    done
    rm -rf "${TMP_CHART}"
fi

# ── Kubernetes manifests ───────────────────────────────────────────────
MANIFEST_SRC="${ROOT}/deploy/k8s"
MANIFEST_DST="${ROOTFS_DIR}/opt/openshell/manifests"
if [ -d "${MANIFEST_SRC}" ]; then
    mkdir -p "${MANIFEST_DST}"
    for manifest in "${MANIFEST_SRC}"/*.yaml; do
        [ -f "$manifest" ] || continue
        base=$(basename "$manifest")
        if ! cmp -s "$manifest" "${MANIFEST_DST}/${base}" 2>/dev/null; then
            cp "$manifest" "${MANIFEST_DST}/${base}"
            echo "  updated: /opt/openshell/manifests/${base}"
        fi
    done
fi

# ── Supervisor binary ─────────────────────────────────────────────────
SUPERVISOR_TARGET="aarch64-unknown-linux-gnu"
SUPERVISOR_BIN="${ROOT}/target/${SUPERVISOR_TARGET}/release/openshell-sandbox"
SUPERVISOR_DST="${ROOTFS_DIR}/opt/openshell/bin/openshell-sandbox"
if [ -f "${SUPERVISOR_BIN}" ]; then
    mkdir -p "$(dirname "${SUPERVISOR_DST}")"
    if ! cmp -s "${SUPERVISOR_BIN}" "${SUPERVISOR_DST}" 2>/dev/null; then
        cp "${SUPERVISOR_BIN}" "${SUPERVISOR_DST}"
        chmod +x "${SUPERVISOR_DST}"
        echo "  updated: /opt/openshell/bin/openshell-sandbox"
    fi
fi

# ── Fix execute permissions on k3s data binaries ──────────────────────
# docker export and macOS virtio-fs can strip execute bits.
chmod +x "${ROOTFS_DIR}"/var/lib/rancher/k3s/data/*/bin/* 2>/dev/null || true
chmod +x "${ROOTFS_DIR}"/var/lib/rancher/k3s/data/*/bin/aux/* 2>/dev/null || true

echo "Sync complete."
