#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build an aarch64 Ubuntu rootfs for the openshell-vm microVM.
#
# Produces a rootfs with k3s pre-installed, the OpenShell helm chart and
# manifests baked in, container images pre-loaded, AND a fully initialized
# k3s cluster state (database, TLS, images imported, all services deployed).
#
# On first VM boot, k3s resumes from this pre-baked state instead of
# cold-starting, achieving ~3-5s startup times.
#
# Usage:
#   ./crates/openshell-vm/scripts/build-rootfs.sh [output_dir]
#
# Requires: Docker (or compatible container runtime), curl, helm, zstd

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_ROOTFS="${XDG_DATA_HOME:-${HOME}/.local/share}/openshell/openshell-vm/rootfs"
ROOTFS_DIR="${1:-${DEFAULT_ROOTFS}}"
CONTAINER_NAME="krun-rootfs-builder"
INIT_CONTAINER_NAME="krun-k3s-init"
BASE_IMAGE_TAG="krun-rootfs:openshell-vm"
# K3S_VERSION uses the semver "+" form for GitHub releases.
# The mise env may provide the Docker-tag form with "-" instead of "+";
# normalise to "+" so the GitHub download URL works.
K3S_VERSION="${K3S_VERSION:-v1.35.2+k3s1}"
K3S_VERSION="${K3S_VERSION//-k3s/+k3s}"

# Project root (two levels up from crates/openshell-vm/scripts/)
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# Container images to pre-load into k3s (arm64).
IMAGE_REPO_BASE="${IMAGE_REPO_BASE:-openshell}"
IMAGE_TAG="${IMAGE_TAG:-dev}"
SERVER_IMAGE="${IMAGE_REPO_BASE}/gateway:${IMAGE_TAG}"
AGENT_SANDBOX_IMAGE="registry.k8s.io/agent-sandbox/agent-sandbox-controller:v0.1.0"
COMMUNITY_SANDBOX_IMAGE="ghcr.io/nvidia/openshell-community/sandboxes/base:latest"

echo "==> Building openshell-vm rootfs"
echo "    k3s version: ${K3S_VERSION}"
echo "    Images:      ${SERVER_IMAGE}, ${COMMUNITY_SANDBOX_IMAGE}"
echo "    Output:      ${ROOTFS_DIR}"

# ── Check for running VM ────────────────────────────────────────────────
# If an openshell-vm is using this rootfs via virtio-fs, wiping the rootfs
# corrupts the VM's filesystem (e.g. /var disappears) causing cascading
# k3s failures. We use two checks:
#
# 1. flock: The Rust openshell-vm process holds an exclusive flock on the lock
#    file for its entire lifetime. This is the primary guard — it works
#    even if the state file was deleted, and the OS releases the lock
#    automatically when the process dies (including SIGKILL).
#
# 2. State file: Fallback check for the PID in the state file. This
#    catches VMs launched before the flock guard was added.

VM_LOCK_FILE="$(dirname "${ROOTFS_DIR}")/$(basename "${ROOTFS_DIR}")-vm.lock"
if [ -f "${VM_LOCK_FILE}" ]; then
    # Try to acquire the lock non-blocking. Use Python's fcntl.flock()
    # because the `flock` CLI tool is not available on macOS.
    if ! python3 -c "
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDONLY)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fcntl.flock(fd, fcntl.LOCK_UN)
except BlockingIOError:
    sys.exit(1)
finally:
    os.close(fd)
" "${VM_LOCK_FILE}" 2>/dev/null; then
        HOLDER_PID=$(cat "${VM_LOCK_FILE}" 2>/dev/null | tr -d '[:space:]')
        echo ""
        echo "ERROR: An openshell-vm (pid ${HOLDER_PID:-unknown}) holds a lock on this rootfs."
        echo "       Wiping the rootfs while the VM is running will corrupt its"
        echo "       filesystem and cause k3s failures."
        echo ""
        echo "       Stop the VM first:  kill ${HOLDER_PID:-<pid>}"
        echo "       Then re-run this script."
        echo ""
        exit 1
    fi
fi

VM_STATE_FILE="$(dirname "${ROOTFS_DIR}")/$(basename "${ROOTFS_DIR}")-vm-state.json"
if [ -f "${VM_STATE_FILE}" ]; then
    VM_PID=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['pid'])" "${VM_STATE_FILE}" 2>/dev/null || echo "")
    if [ -n "${VM_PID}" ] && kill -0 "${VM_PID}" 2>/dev/null; then
        echo ""
        echo "ERROR: An openshell-vm is running (pid ${VM_PID}) using this rootfs."
        echo "       Wiping the rootfs while the VM is running will corrupt its"
        echo "       filesystem and cause k3s failures."
        echo ""
        echo "       Stop the VM first:  kill ${VM_PID}"
        echo "       Then re-run this script."
        echo ""
        exit 1
    else
        # Stale state file — VM is no longer running. Clean it up.
        rm -f "${VM_STATE_FILE}"
    fi
fi

# ── Download k3s binary (outside Docker — much faster) ─────────────────

K3S_BIN="/tmp/k3s-arm64-${K3S_VERSION}"
if [ -f "${K3S_BIN}" ]; then
    echo "==> Using cached k3s binary: ${K3S_BIN}"
else
    echo "==> Downloading k3s ${K3S_VERSION} for arm64..."
    curl -fSL "https://github.com/k3s-io/k3s/releases/download/${K3S_VERSION}/k3s-arm64" \
        -o "${K3S_BIN}"
    chmod +x "${K3S_BIN}"
fi

# ── Build base image with dependencies ─────────────────────────────────

# Clean up any previous run
docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true
docker rm -f "${INIT_CONTAINER_NAME}" 2>/dev/null || true

echo "==> Building base image..."
docker build --platform linux/arm64 -t "${BASE_IMAGE_TAG}" -f - . <<'DOCKERFILE'
FROM nvcr.io/nvidia/base/ubuntu:noble-20251013
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        iptables \
        iproute2 \
        python3 \
        busybox-static \
        zstd \
    && rm -rf /var/lib/apt/lists/*
# busybox-static provides udhcpc for DHCP inside the VM.
RUN mkdir -p /usr/share/udhcpc && \
    ln -sf /bin/busybox /sbin/udhcpc
RUN mkdir -p /var/lib/rancher/k3s /etc/rancher/k3s
DOCKERFILE

# Create a container and export the filesystem
echo "==> Creating container..."
docker create --platform linux/arm64 --name "${CONTAINER_NAME}" "${BASE_IMAGE_TAG}" /bin/true

echo "==> Exporting filesystem..."
# Previous builds may leave overlayfs work/ dirs with permissions that
# prevent rm on macOS. Force-fix permissions before removing.
if [ -d "${ROOTFS_DIR}" ]; then
    chmod -R u+rwx "${ROOTFS_DIR}" 2>/dev/null || true
    rm -rf "${ROOTFS_DIR}"
fi
mkdir -p "${ROOTFS_DIR}"
docker export "${CONTAINER_NAME}" | tar -C "${ROOTFS_DIR}" -xf -

docker rm "${CONTAINER_NAME}"

# ── Inject k3s binary ────────────────────────────────────────────────

echo "==> Injecting k3s binary..."
cp "${K3S_BIN}" "${ROOTFS_DIR}/usr/local/bin/k3s"
chmod +x "${ROOTFS_DIR}/usr/local/bin/k3s"
ln -sf /usr/local/bin/k3s "${ROOTFS_DIR}/usr/local/bin/kubectl"

# k3s self-extracts runtime binaries (containerd, runc, CNI plugins,
# coreutils, etc.) into a versioned data directory the first time it
# runs. On the pre-initialized rootfs these were extracted during the
# Docker build or VM pre-init phase. docker export and macOS virtio-fs
# can strip execute bits from Linux ELF binaries, so fix them here.
echo "    Fixing execute permissions on k3s data binaries..."
chmod +x "${ROOTFS_DIR}"/var/lib/rancher/k3s/data/*/bin/* 2>/dev/null || true
chmod +x "${ROOTFS_DIR}"/var/lib/rancher/k3s/data/*/bin/aux/* 2>/dev/null || true

# ── Inject scripts ────────────────────────────────────────────────────

echo "==> Injecting openshell-vm-init.sh..."
mkdir -p "${ROOTFS_DIR}/srv"
cp "${SCRIPT_DIR}/openshell-vm-init.sh" "${ROOTFS_DIR}/srv/openshell-vm-init.sh"
chmod +x "${ROOTFS_DIR}/srv/openshell-vm-init.sh"

# Keep the hello server around for debugging
cp "${SCRIPT_DIR}/hello-server.py" "${ROOTFS_DIR}/srv/hello-server.py"
chmod +x "${ROOTFS_DIR}/srv/hello-server.py"

# Inject VM capability checker for runtime diagnostics.
cp "${SCRIPT_DIR}/check-vm-capabilities.sh" "${ROOTFS_DIR}/srv/check-vm-capabilities.sh"
chmod +x "${ROOTFS_DIR}/srv/check-vm-capabilities.sh"

# Inject the openshell-vm exec agent used by `openshell-vm exec`.
cp "${SCRIPT_DIR}/openshell-vm-exec-agent.py" "${ROOTFS_DIR}/srv/openshell-vm-exec-agent.py"
chmod +x "${ROOTFS_DIR}/srv/openshell-vm-exec-agent.py"

# ── Build and inject openshell-sandbox supervisor binary ─────────────
# The supervisor binary runs inside every sandbox pod. It is side-loaded
# from the node filesystem via a read-only hostPath volume mount at
# /opt/openshell/bin. In the Docker-based gateway this is built in the
# Dockerfile.cluster supervisor-builder stage; here we cross-compile
# from the host using cargo-zigbuild.

SUPERVISOR_TARGET="aarch64-unknown-linux-gnu"
SUPERVISOR_BIN="${PROJECT_ROOT}/target/${SUPERVISOR_TARGET}/release/openshell-sandbox"

echo "==> Building openshell-sandbox supervisor binary (${SUPERVISOR_TARGET})..."
if ! command -v cargo-zigbuild >/dev/null 2>&1; then
    echo "ERROR: cargo-zigbuild is not installed."
    echo "       Install it with: cargo install cargo-zigbuild"
    echo "       Also requires: zig (brew install zig)"
    exit 1
fi

cargo zigbuild --release -p openshell-sandbox --target "${SUPERVISOR_TARGET}" \
    --manifest-path "${PROJECT_ROOT}/Cargo.toml" 2>&1 | tail -5

if [ ! -f "${SUPERVISOR_BIN}" ]; then
    echo "ERROR: supervisor binary not found at ${SUPERVISOR_BIN}"
    exit 1
fi

echo "    Injecting supervisor binary into rootfs..."
mkdir -p "${ROOTFS_DIR}/opt/openshell/bin"
cp "${SUPERVISOR_BIN}" "${ROOTFS_DIR}/opt/openshell/bin/openshell-sandbox"
chmod +x "${ROOTFS_DIR}/opt/openshell/bin/openshell-sandbox"
echo "    Size: $(du -h "${ROOTFS_DIR}/opt/openshell/bin/openshell-sandbox" | cut -f1)"

# ── Package and inject helm chart ────────────────────────────────────

HELM_CHART_DIR="${PROJECT_ROOT}/deploy/helm/openshell"
CHART_DEST="${ROOTFS_DIR}/var/lib/rancher/k3s/server/static/charts"

if [ -d "${HELM_CHART_DIR}" ]; then
    echo "==> Packaging helm chart..."
    mkdir -p "${CHART_DEST}"
    helm package "${HELM_CHART_DIR}" -d "${CHART_DEST}"
    echo "    $(ls "${CHART_DEST}"/*.tgz 2>/dev/null | xargs -I{} basename {})"
    # Also stage to /opt/openshell/charts/ so the init script can
    # restore them after a --reset wipes server/static/charts/.
    mkdir -p "${ROOTFS_DIR}/opt/openshell/charts"
    cp "${CHART_DEST}"/*.tgz "${ROOTFS_DIR}/opt/openshell/charts/"
else
    echo "WARNING: Helm chart not found at ${HELM_CHART_DIR}, skipping"
fi

# ── Inject Kubernetes manifests ──────────────────────────────────────
# These are copied to /opt/openshell/manifests/ (staging). openshell-vm-init.sh
# moves them to /var/lib/rancher/k3s/server/manifests/ at boot so the
# k3s Helm Controller auto-deploys them.

MANIFEST_SRC="${PROJECT_ROOT}/deploy/kube/manifests"
MANIFEST_DEST="${ROOTFS_DIR}/opt/openshell/manifests"

echo "==> Injecting Kubernetes manifests..."
mkdir -p "${MANIFEST_DEST}"

for manifest in openshell-helmchart.yaml agent-sandbox.yaml; do
    if [ -f "${MANIFEST_SRC}/${manifest}" ]; then
        cp "${MANIFEST_SRC}/${manifest}" "${MANIFEST_DEST}/"
        echo "    ${manifest}"
    else
        echo "WARNING: ${manifest} not found in ${MANIFEST_SRC}"
    fi
done

# ── Pre-load container images ────────────────────────────────────────
# Pull arm64 images and save as tarballs in the k3s airgap images
# directory. k3s auto-imports from /var/lib/rancher/k3s/agent/images/
# on startup, so no internet access is needed at boot time.
#
# Tarballs are cached in a persistent directory outside the rootfs so
# they survive rebuilds. This avoids re-pulling and re-saving ~1 GiB
# of images each time.

IMAGES_DIR="${ROOTFS_DIR}/var/lib/rancher/k3s/agent/images"
IMAGE_CACHE_DIR="${XDG_CACHE_HOME:-${HOME}/.cache}/openshell/openshell-vm/images"
mkdir -p "${IMAGES_DIR}" "${IMAGE_CACHE_DIR}"

echo "==> Pre-loading container images (arm64)..."

pull_and_save() {
    local image="$1"
    local output="$2"
    local cache="${IMAGE_CACHE_DIR}/$(basename "${output}")"

    # Use cached tarball if available.
    if [ -f "${cache}" ]; then
        echo "    cached: $(basename "${output}")"
        cp "${cache}" "${output}"
        return 0
    fi

    # Try to pull; if the registry is unavailable, fall back to the
    # local Docker image cache (image may exist from a previous pull).
    echo "    pulling: ${image}..."
    if ! docker pull --platform linux/arm64 "${image}" --quiet 2>/dev/null; then
        echo "    pull failed, checking local Docker cache..."
        if ! docker image inspect "${image}" >/dev/null 2>&1; then
            echo "ERROR: image ${image} not available locally or from registry"
            exit 1
        fi
        echo "    using locally cached image"
    fi

    echo "    saving:  $(basename "${output}")..."
    # Pipe through zstd for faster decompression and smaller tarballs.
    # k3s auto-imports .tar.zst files from the airgap images directory.
    # -T0 uses all CPU cores; -3 is a good speed/ratio tradeoff.
    docker save "${image}" | zstd -T0 -3 -o "${output}"
    # Cache for next rebuild.
    cp "${output}" "${cache}"
}

pull_and_save "${SERVER_IMAGE}" "${IMAGES_DIR}/openshell-server.tar.zst"
pull_and_save "${AGENT_SANDBOX_IMAGE}" "${IMAGES_DIR}/agent-sandbox-controller.tar.zst"
pull_and_save "${COMMUNITY_SANDBOX_IMAGE}" "${IMAGES_DIR}/community-sandbox-base.tar.zst"

# ── Pre-initialize k3s cluster state ─────────────────────────────────
# Boot k3s inside a Docker container using the rootfs we just built.
# Wait for it to fully initialize (import images, deploy manifests,
# create database), then capture the state back into the rootfs.
#
# This eliminates cold-start latency: on VM boot, k3s finds existing
# state and resumes in ~3-5 seconds instead of 30-60s.

echo ""
echo "==> Pre-initializing k3s cluster state..."
echo "    This boots k3s in a container, waits for full readiness,"
echo "    then captures the initialized state into the rootfs."

# Patch the HelmChart manifest for the init container (same patches
# openshell-vm-init.sh applies at runtime).
INIT_MANIFESTS="${ROOTFS_DIR}/var/lib/rancher/k3s/server/manifests"
mkdir -p "${INIT_MANIFESTS}"

# Copy manifests from staging to the k3s manifest directory.
for manifest in "${MANIFEST_DEST}"/*.yaml; do
    [ -f "$manifest" ] || continue
    cp "$manifest" "${INIT_MANIFESTS}/"
done

# Patch HelmChart for local images and VM settings.
HELMCHART="${INIT_MANIFESTS}/openshell-helmchart.yaml"
if [ -f "$HELMCHART" ]; then
    # Use local images — explicitly imported into containerd.
    sed -i '' 's|__IMAGE_PULL_POLICY__|IfNotPresent|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|__IMAGE_PULL_POLICY__|IfNotPresent|g' "$HELMCHART"
    sed -i '' 's|__SANDBOX_IMAGE_PULL_POLICY__|IfNotPresent|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|__SANDBOX_IMAGE_PULL_POLICY__|IfNotPresent|g' "$HELMCHART"
    # Use the locally imported image references.
    sed -i '' -E "s|repository:[[:space:]]*[^[:space:]]+|repository: ${SERVER_IMAGE%:*}|" "$HELMCHART" 2>/dev/null \
        || sed -i -E "s|repository:[[:space:]]*[^[:space:]]+|repository: ${SERVER_IMAGE%:*}|" "$HELMCHART"
    sed -i '' -E "s|tag:[[:space:]]*\"?[^\"[:space:]]+\"?|tag: \"${IMAGE_TAG}\"|" "$HELMCHART" 2>/dev/null \
        || sed -i -E "s|tag:[[:space:]]*\"?[^\"[:space:]]+\"?|tag: \"${IMAGE_TAG}\"|" "$HELMCHART"
    # Bridge CNI: pods use normal pod networking, not hostNetwork.
    # This must match what openshell-vm-init.sh applies at runtime so the
    # HelmChart manifest is unchanged at boot — preventing a helm
    # upgrade job that would cycle the pre-baked pod.
    sed -i '' 's|__HOST_NETWORK__|false|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|__HOST_NETWORK__|false|g' "$HELMCHART"
    # Enable SA token automount for bridge CNI mode. Must match
    # openshell-vm-init.sh runtime value to avoid manifest delta.
    sed -i '' 's|__AUTOMOUNT_SA_TOKEN__|true|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|__AUTOMOUNT_SA_TOKEN__|true|g' "$HELMCHART"
    # Disable persistence — use /tmp for the SQLite database. PVC mounts
    # are unreliable on virtiofs.
    sed -i '' 's|__PERSISTENCE_ENABLED__|false|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|__PERSISTENCE_ENABLED__|false|g' "$HELMCHART"
    sed -i '' 's|__DB_URL__|"sqlite:/tmp/openshell.db"|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|__DB_URL__|"sqlite:/tmp/openshell.db"|g' "$HELMCHART"
    # Clear SSH gateway placeholders.
    sed -i '' 's|sshGatewayHost: __SSH_GATEWAY_HOST__|sshGatewayHost: ""|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|sshGatewayHost: __SSH_GATEWAY_HOST__|sshGatewayHost: ""|g' "$HELMCHART"
    sed -i '' 's|sshGatewayPort: __SSH_GATEWAY_PORT__|sshGatewayPort: 0|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|sshGatewayPort: __SSH_GATEWAY_PORT__|sshGatewayPort: 0|g' "$HELMCHART"
    SSH_HANDSHAKE_SECRET="$(head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n')"
    sed -i '' "s|__SSH_HANDSHAKE_SECRET__|${SSH_HANDSHAKE_SECRET}|g" "$HELMCHART" 2>/dev/null \
        || sed -i "s|__SSH_HANDSHAKE_SECRET__|${SSH_HANDSHAKE_SECRET}|g" "$HELMCHART"
    sed -i '' 's|__DISABLE_GATEWAY_AUTH__|false|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|__DISABLE_GATEWAY_AUTH__|false|g' "$HELMCHART"
    sed -i '' 's|__DISABLE_TLS__|false|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|__DISABLE_TLS__|false|g' "$HELMCHART"
    sed -i '' 's|hostGatewayIP: __HOST_GATEWAY_IP__|hostGatewayIP: ""|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|hostGatewayIP: __HOST_GATEWAY_IP__|hostGatewayIP: ""|g' "$HELMCHART"
    sed -i '' '/__CHART_CHECKSUM__/d' "$HELMCHART" 2>/dev/null \
        || sed -i '/__CHART_CHECKSUM__/d' "$HELMCHART"
fi

# Patch agent-sandbox manifest for VM networking constraints.
AGENT_MANIFEST="${INIT_MANIFESTS}/agent-sandbox.yaml"
if [ -f "$AGENT_MANIFEST" ]; then
    # Keep agent-sandbox on pod networking to avoid host port clashes.
    # Point in-cluster client traffic at the API server node IP because
    # kube-proxy is disabled in VM mode.
    sed -i '' '/hostNetwork: true/d' "$AGENT_MANIFEST" 2>/dev/null \
        || sed -i '/hostNetwork: true/d' "$AGENT_MANIFEST"
    sed -i '' '/dnsPolicy: ClusterFirstWithHostNet/d' "$AGENT_MANIFEST" 2>/dev/null \
        || sed -i '/dnsPolicy: ClusterFirstWithHostNet/d' "$AGENT_MANIFEST"
    sed -i '' 's|image: registry.k8s.io/agent-sandbox/agent-sandbox-controller:v0.1.0|image: registry.k8s.io/agent-sandbox/agent-sandbox-controller:v0.1.0\
        args:\
        - -metrics-bind-address=:8082\
        env:\
        - name: KUBERNETES_SERVICE_HOST\
          value: 192.168.127.2\
        - name: KUBERNETES_SERVICE_PORT\
          value: "6443"|g' "$AGENT_MANIFEST" 2>/dev/null \
        || sed -i 's|image: registry.k8s.io/agent-sandbox/agent-sandbox-controller:v0.1.0|image: registry.k8s.io/agent-sandbox/agent-sandbox-controller:v0.1.0\
        args:\
        - -metrics-bind-address=:8082\
        env:\
        - name: KUBERNETES_SERVICE_HOST\
          value: 192.168.127.2\
        - name: KUBERNETES_SERVICE_PORT\
          value: "6443"|g' "$AGENT_MANIFEST"
    if grep -q 'hostNetwork: true' "$AGENT_MANIFEST" \
        || grep -q 'ClusterFirstWithHostNet' "$AGENT_MANIFEST" \
        || ! grep -q 'KUBERNETES_SERVICE_HOST' "$AGENT_MANIFEST" \
        || ! grep -q 'metrics-bind-address=:8082' "$AGENT_MANIFEST"; then
        echo "ERROR: failed to patch agent-sandbox manifest for VM networking constraints: $AGENT_MANIFEST" >&2
        exit 1
    fi
fi

# local-storage implies local-path-provisioner, which requires CNI bridge
# networking that is unavailable in the VM kernel.
rm -f "${INIT_MANIFESTS}/local-storage.yaml" 2>/dev/null || true

# ── Pre-initialize using the actual libkrun VM ──────────────────────────
# Boot the real VM with the rootfs we just built. This uses the same
# kernel, networking, and kube-proxy config as production — eliminating
# Docker IP mismatches, snapshotter mismatches, and the Docker volume
# copy-back dance. The VM writes state directly into the rootfs via
# virtio-fs.
#
# Requirements: the openshell-vm binary must be built and codesigned.
# mise run vm:build:binary handles this.

GATEWAY_BIN="${PROJECT_ROOT}/target/debug/openshell-vm"
RUNTIME_DIR="${PROJECT_ROOT}/target/debug/openshell-vm.runtime"

if [ ! -x "${GATEWAY_BIN}" ]; then
    echo "ERROR: openshell-vm binary not found at ${GATEWAY_BIN}"
    echo "       Run: mise run vm:build:binary"
    exit 1
fi

if [ ! -d "${RUNTIME_DIR}" ]; then
    echo "ERROR: VM runtime bundle not found at ${RUNTIME_DIR}"
    echo "       Run: mise run vm:bundle-runtime"
    exit 1
fi

# Helper: run a command inside the VM via the exec agent.
vm_exec() {
    DYLD_FALLBACK_LIBRARY_PATH="${RUNTIME_DIR}${DYLD_FALLBACK_LIBRARY_PATH:+:${DYLD_FALLBACK_LIBRARY_PATH}}" \
        "${GATEWAY_BIN}" --rootfs "${ROOTFS_DIR}" exec -- "$@" 2>&1
}

# Ensure no stale VM is using this rootfs.
echo "    Starting VM for pre-initialization..."
export DYLD_FALLBACK_LIBRARY_PATH="${RUNTIME_DIR}${DYLD_FALLBACK_LIBRARY_PATH:+:${DYLD_FALLBACK_LIBRARY_PATH}}"
"${GATEWAY_BIN}" --rootfs "${ROOTFS_DIR}" --reset &
VM_PID=$!

# Ensure the VM is cleaned up on script exit.
cleanup_vm() {
    if kill -0 "${VM_PID}" 2>/dev/null; then
        echo "    Stopping VM (pid ${VM_PID})..."
        kill "${VM_PID}" 2>/dev/null || true
        wait "${VM_PID}" 2>/dev/null || true
    fi
}
trap cleanup_vm EXIT

# Wait for the exec agent to become reachable.
echo "    Waiting for VM exec agent..."
for i in $(seq 1 120); do
    if vm_exec true >/dev/null 2>&1; then
        echo "    Exec agent ready (${i}s)"
        break
    fi
    if [ "$i" -eq 120 ]; then
        echo "ERROR: VM exec agent did not become reachable in 120s"
        exit 1
    fi
    sleep 1
done

# Wait for containerd to be ready.
echo "    Waiting for containerd..."
for i in $(seq 1 60); do
    if vm_exec k3s ctr version >/dev/null 2>&1; then
        echo "    Containerd ready (${i}s)"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "ERROR: containerd did not become ready in 60s"
        exit 1
    fi
    sleep 1
done

# Wait for the openshell namespace (Helm controller creates it).
echo "    Waiting for openshell namespace..."
for i in $(seq 1 180); do
    if vm_exec kubectl get namespace openshell -o name 2>/dev/null | grep -q openshell; then
        echo "    Namespace ready (${i}s)"
        break
    fi
    if [ "$i" -eq 180 ]; then
        echo "ERROR: openshell namespace did not appear in 180s"
        exit 1
    fi
    sleep 1
done

# Wait for the openshell StatefulSet to have a ready replica.
# The VM init script generates PKI and writes TLS secrets manifests
# automatically — no host-side PKI generation needed.
echo "    Waiting for openshell pod to be ready..."
for i in $(seq 1 180); do
    ready=$(vm_exec kubectl -n openshell get statefulset openshell \
        -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
    if [ "$ready" = "1" ]; then
        echo "    OpenShell pod ready (${i}s)"
        break
    fi
    if [ "$i" -eq 180 ]; then
        echo "WARNING: openshell pod not ready after 180s, continuing anyway"
        vm_exec kubectl -n openshell get pods 2>/dev/null | sed 's/^/    /' || true
        break
    fi
    sleep 1
done

# Pre-unpack container images so the overlayfs snapshotter has ready-to-use
# snapshots on first boot. Without this, the first container create for each
# image triggers a full layer extraction which can take minutes.
echo "    Pre-unpacking container images..."
for img in \
    "ghcr.io/nvidia/openshell-community/sandboxes/base:latest" \
    "ghcr.io/nvidia/openshell/gateway:latest"; do
    if vm_exec k3s ctr -n k8s.io images ls -q 2>/dev/null | grep -qF "$img"; then
        echo "      unpacking: $img"
        vm_exec k3s ctr -n k8s.io run --rm "$img" "pre-unpack-$(date +%s)" true 2>/dev/null || true
    fi
done
echo "    Image pre-unpack complete."

# Stop the VM so the kine SQLite DB is flushed.
echo "    Stopping VM..."
kill "${VM_PID}" 2>/dev/null || true
wait "${VM_PID}" 2>/dev/null || true

# Surgically clean the kine SQLite DB. Runtime objects (pods, events,
# leases) would cause the VM's kubelet to reconcile against an empty
# containerd on next boot.
echo "    Cleaning runtime objects from kine DB..."
DB="${ROOTFS_DIR}/var/lib/rancher/k3s/server/db/state.db"
if [ -f "$DB" ]; then
    echo "    Before: $(sqlite3 "$DB" "SELECT COUNT(*) FROM kine;") kine records"
    sqlite3 "$DB" <<'EOSQL'
DELETE FROM kine WHERE name LIKE '/registry/pods/%';
DELETE FROM kine WHERE name LIKE '/registry/events/%';
DELETE FROM kine WHERE name LIKE '/registry/leases/%';
DELETE FROM kine WHERE name LIKE '/registry/endpointslices/%';
DELETE FROM kine WHERE name LIKE '/registry/masterleases/%';
PRAGMA wal_checkpoint(TRUNCATE);
VACUUM;
EOSQL
    echo "    After:  $(sqlite3 "$DB" "SELECT COUNT(*) FROM kine;") kine records"
else
    echo "WARNING: state.db not found at ${DB}"
fi

# Clean up runtime artifacts that shouldn't persist.
echo "    Cleaning runtime artifacts..."
rm -rf "${ROOTFS_DIR}/var/lib/rancher/k3s/server/tls/temporary-certs" 2>/dev/null || true
rm -f  "${ROOTFS_DIR}/var/lib/rancher/k3s/server/kine.sock" 2>/dev/null || true
find "${ROOTFS_DIR}/var/lib/rancher/k3s" -name '*.sock' -delete 2>/dev/null || true
find "${ROOTFS_DIR}/run" -name '*.sock' -delete 2>/dev/null || true

# Write sentinel file so openshell-vm-init.sh and the host-side bootstrap
# know this rootfs has pre-initialized state.
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${ROOTFS_DIR}/opt/openshell/.initialized"

echo "    Pre-initialization complete."

# ── Verify ────────────────────────────────────────────────────────────

if [ ! -f "${ROOTFS_DIR}/usr/local/bin/k3s" ]; then
    echo "ERROR: k3s binary not found in rootfs. Something went wrong."
    exit 1
fi

if [ ! -f "${ROOTFS_DIR}/opt/openshell/.initialized" ]; then
    echo "WARNING: Pre-initialization sentinel not found. Cold starts will be slow."
fi

if [ ! -x "${ROOTFS_DIR}/opt/openshell/bin/openshell-sandbox" ]; then
    echo "ERROR: openshell-sandbox supervisor binary not found in rootfs."
    echo "       Sandbox pods will fail with CreateContainerError."
    exit 1
fi

echo ""
echo "==> Rootfs ready at: ${ROOTFS_DIR}"
echo "    Size: $(du -sh "${ROOTFS_DIR}" | cut -f1)"
echo "    Pre-initialized: $(cat "${ROOTFS_DIR}/opt/openshell/.initialized" 2>/dev/null || echo 'no')"

# Show k3s data size
K3S_DATA="${ROOTFS_DIR}/var/lib/rancher/k3s"
if [ -d "${K3S_DATA}" ]; then
    echo "    k3s state: $(du -sh "${K3S_DATA}" | cut -f1)"
fi

# PKI is generated at first VM boot by the init script — not baked.

# Show supervisor binary
if [ -x "${ROOTFS_DIR}/opt/openshell/bin/openshell-sandbox" ]; then
    echo "    Supervisor: $(du -h "${ROOTFS_DIR}/opt/openshell/bin/openshell-sandbox" | cut -f1)"
fi

echo ""
echo "Next steps:"
echo "  1. Run:  openshell-vm"
echo "  Expected startup time: ~3-5 seconds (pre-initialized)"
