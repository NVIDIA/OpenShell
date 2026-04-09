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

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT_DIR="${ROOT}/crates/openshell-vm/scripts"
IMAGE_REPO_BASE="${IMAGE_REPO_BASE:-openshell}"
IMAGE_TAG="${IMAGE_TAG:-dev}"
SERVER_IMAGE="${IMAGE_REPO_BASE}/gateway:${IMAGE_TAG}"
NAME="default"
ROOTFS_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --name)
            NAME="$2"
            shift 2
            ;;
        --name=*)
            NAME="${1#--name=}"
            shift
            ;;
        --rootfs)
            ROOTFS_ARGS=("$1" "$2")
            shift 2
            ;;
        --rootfs=*)
            ROOTFS_ARGS=("$1")
            shift
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

ensure_args=(--name "${NAME}")
if [ "${#ROOTFS_ARGS[@]}" -gt 0 ]; then
    ensure_args=("${ROOTFS_ARGS[@]}" "${ensure_args[@]}")
fi

if ! ROOTFS_DIR="$("${ROOT}/tasks/scripts/vm/ensure-vm-rootfs.sh" "${ensure_args[@]}" | tail -n 1 | sed 's/^using openshell-vm rootfs at //')"; then
    echo "ERROR: ensure-vm-rootfs.sh failed — no rootfs available." >&2
    exit 1
fi

patch_vm_helmchart() {
    local helmchart="$1"
    [ -f "${helmchart}" ] || return 0

    sed_in_place() {
        local expr="$1"
        sed -i.bak -E "${expr}" "${helmchart}"
        rm -f "${helmchart}.bak"
    }

    # Mirror the build-rootfs patching so the VM keeps using the locally
    # imported openshell/gateway:dev image after incremental rootfs syncs.
    sed_in_place 's|__IMAGE_PULL_POLICY__|IfNotPresent|g'
    sed_in_place 's|__SANDBOX_IMAGE_PULL_POLICY__|"IfNotPresent"|g'
    sed_in_place 's|__DB_URL__|"sqlite:/tmp/openshell.db"|g'
    sed_in_place "s|repository:[[:space:]]*[^[:space:]]+|repository: ${SERVER_IMAGE%:*}|"
    sed_in_place "s|tag:[[:space:]]*\"?[^\"[:space:]]+\"?|tag: \"${IMAGE_TAG}\"|"
    sed_in_place 's|sshGatewayHost: __SSH_GATEWAY_HOST__|sshGatewayHost: ""|g'
    sed_in_place 's|sshGatewayPort: __SSH_GATEWAY_PORT__|sshGatewayPort: 0|g'
    sed_in_place 's|__DISABLE_GATEWAY_AUTH__|false|g'
    sed_in_place 's|__DISABLE_TLS__|false|g'
    sed_in_place 's|hostGatewayIP: __HOST_GATEWAY_IP__|hostGatewayIP: ""|g'
    sed_in_place '/__CHART_CHECKSUM__/d'
}

if [ ! -d "${ROOTFS_DIR}/srv" ]; then
    # Rootfs doesn't exist yet — nothing to sync. ensure-vm-rootfs.sh
    # or build-rootfs.sh will create it.
    exit 0
fi

echo "Syncing development artifacts into rootfs..."

# ── Init scripts and utilities ─────────────────────────────────────────
for script in openshell-vm-init.sh openshell-vm-exec-agent.py check-vm-capabilities.sh; do
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
MANIFEST_SRC="${ROOT}/deploy/kube/manifests"
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

patch_vm_helmchart "${MANIFEST_DST}/openshell-helmchart.yaml"
patch_vm_helmchart "${ROOTFS_DIR}/var/lib/rancher/k3s/server/manifests/openshell-helmchart.yaml"

# ── Gateway image tarball ──────────────────────────────────────────────
# The VM rootfs airgap-imports openshell/gateway:dev from k3s/agent/images/.
# Keep that tarball in sync with the local Docker image so `mise run e2e:vm`
# validates the current openshell-server code, not whatever image happened to
# be baked into the rootfs last time it was rebuilt.
SERVER_IMAGE_TAR="${ROOTFS_DIR}/var/lib/rancher/k3s/agent/images/openshell-server.tar.zst"
SERVER_IMAGE_ID_FILE="${ROOTFS_DIR}/opt/openshell/.gateway-image-id"
if command -v docker >/dev/null 2>&1 && docker image inspect "${SERVER_IMAGE}" >/dev/null 2>&1; then
    current_image_id=$(docker image inspect --format '{{.Id}}' "${SERVER_IMAGE}")
    previous_image_id=""
    if [ -f "${SERVER_IMAGE_ID_FILE}" ]; then
        previous_image_id=$(cat "${SERVER_IMAGE_ID_FILE}")
    fi

    if [ "${current_image_id}" != "${previous_image_id}" ] || [ ! -f "${SERVER_IMAGE_TAR}" ]; then
        mkdir -p "$(dirname "${SERVER_IMAGE_TAR}")" "$(dirname "${SERVER_IMAGE_ID_FILE}")"
        tmp_tar=$(mktemp /tmp/openshell-server-image.XXXXXX)
        docker save "${SERVER_IMAGE}" | zstd -f -T0 -3 -o "${tmp_tar}" >/dev/null
        mv "${tmp_tar}" "${SERVER_IMAGE_TAR}"
        printf '%s\n' "${current_image_id}" > "${SERVER_IMAGE_ID_FILE}"
        echo "  updated: /var/lib/rancher/k3s/agent/images/openshell-server.tar.zst"
    fi
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
