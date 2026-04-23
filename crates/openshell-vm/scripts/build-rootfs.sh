#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build a Ubuntu rootfs for the openshell-vm microVM.
#
# By default, produces a fully pre-initialized rootfs with k3s pre-installed,
# the OpenShell helm chart and manifests baked in, container images pre-loaded,
# AND a fully initialized k3s cluster state (database, TLS, images imported,
# all services deployed). On first VM boot, k3s resumes from this pre-baked
# state instead of cold-starting, achieving ~3-5s startup times.
#
# With --base, produces a lightweight rootfs (~200-300MB) with:
# - Base Ubuntu with k3s binary
# - OpenShell supervisor binary
# - Helm charts and Kubernetes manifests
# - NO pre-loaded container images (pulled on demand)
# - NO pre-initialized k3s state (cold start on first boot)
# First boot will be slower (~30-60s) as k3s initializes and pulls images.
#
# With --gpu, installs NVIDIA driver packages and the nvidia-container-toolkit
# into the rootfs, producing a GPU-capable variant. The launcher selects this
# rootfs when `--gpu` is passed. Only supported on x86_64 (NVIDIA does not
# publish aarch64 data-center drivers for Ubuntu in this packaging form).
#
# Supports aarch64 and x86_64 guest architectures. The target architecture
# is auto-detected from the host but can be overridden with --arch.
#
# Usage:
#   ./build-rootfs.sh [--base] [--gpu] [--arch aarch64|x86_64] [output_dir]
#
# If output_dir is omitted, the rootfs is built under target/rootfs-build.
#
# Requires: Docker (or compatible container runtime), curl, helm
# Full mode (default) also requires: zstd, sqlite3, a built openshell-vm binary

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source pinned dependency versions (digests, checksums, commit SHAs).
# Environment variables override pins — see pins.env for details.
PINS_FILE="${SCRIPT_DIR}/../pins.env"
if [ -f "$PINS_FILE" ]; then
    # shellcheck source=../pins.env
    source "$PINS_FILE"
fi

# ── Argument parsing ───────────────────────────────────────────────────
BASE_ONLY=false
GPU_BUILD=false
GUEST_ARCH=""
POSITIONAL_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --base)
            BASE_ONLY=true; shift ;;
        --gpu)
            GPU_BUILD=true; shift ;;
        --arch)
            GUEST_ARCH="$2"; shift 2 ;;
        *)
            POSITIONAL_ARGS+=("$1"); shift ;;
    esac
done

# ── Architecture detection ─────────────────────────────────────────────
# Allow override via --arch flag; default to host architecture.
if [ -z "$GUEST_ARCH" ]; then
    case "$(uname -m)" in
        aarch64|arm64) GUEST_ARCH="aarch64" ;;
        x86_64)        GUEST_ARCH="x86_64" ;;
        *)
            echo "ERROR: Unsupported host architecture: $(uname -m)" >&2
            echo "       Use --arch aarch64 or --arch x86_64 to override." >&2
            exit 1
            ;;
    esac
fi

case "$GUEST_ARCH" in
    aarch64)
        DOCKER_PLATFORM="linux/arm64"
        K3S_BINARY_SUFFIX="-arm64"
        K3S_CHECKSUM_VAR="K3S_ARM64_SHA256"
        RUST_TARGET="aarch64-unknown-linux-gnu"
        ;;
    x86_64)
        DOCKER_PLATFORM="linux/amd64"
        K3S_BINARY_SUFFIX=""    # x86_64 binary has no suffix
        K3S_CHECKSUM_VAR="K3S_AMD64_SHA256"
        RUST_TARGET="x86_64-unknown-linux-gnu"
        ;;
    *)
        echo "ERROR: Unsupported guest architecture: ${GUEST_ARCH}" >&2
        echo "       Supported: aarch64, x86_64" >&2
        exit 1
        ;;
esac

# GPU builds are only supported on x86_64 — NVIDIA does not publish
# aarch64 data-center driver packages in the same APT repository.
if [ "$GPU_BUILD" = true ] && [ "$GUEST_ARCH" != "x86_64" ]; then
    echo "ERROR: --gpu is only supported for x86_64 guest architecture." >&2
    echo "       Current arch: ${GUEST_ARCH}" >&2
    exit 1
fi

# Project root (two levels up from crates/openshell-vm/scripts/)
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
DEFAULT_ROOTFS="${PROJECT_ROOT}/target/rootfs-build"
ROOTFS_DIR="${POSITIONAL_ARGS[0]:-${DEFAULT_ROOTFS}}"
CONTAINER_NAME="krun-rootfs-builder"
BASE_IMAGE_TAG="krun-rootfs:openshell-vm"
# K3S_VERSION uses the semver "+" form for GitHub releases.
# The mise env may provide the Docker-tag form with "-" instead of "+";
# normalise to "+" so the GitHub download URL works.
K3S_VERSION="${K3S_VERSION:-v1.35.2+k3s1}"
K3S_VERSION="${K3S_VERSION//-k3s/+k3s}"

# Container images to pre-load into k3s (full mode only).
# AGENT_SANDBOX_IMAGE and COMMUNITY_SANDBOX_IMAGE are digest-pinned in pins.env.
# SERVER_IMAGE is intentionally unpinned (local dev artifact).
IMAGE_REPO_BASE="${IMAGE_REPO_BASE:-openshell}"
IMAGE_TAG="${IMAGE_TAG:-dev}"
SERVER_IMAGE="${IMAGE_REPO_BASE}/gateway:${IMAGE_TAG}"

# Cross-platform checksum helper
verify_checksum() {
    local expected="$1" file="$2"
    if command -v sha256sum &>/dev/null; then
        echo "${expected}  ${file}" | sha256sum -c -
    else
        echo "${expected}  ${file}" | shasum -a 256 -c -
    fi
}

verify_gpu_rootfs() {
    local rootfs_dir="$1"
    local kernel_version="$2"
    local driver_tag="$3"
    local driver_version="$4"

    echo "==> Verifying GPU components in rootfs..."
    if [ ! -f "${rootfs_dir}/usr/bin/nvidia-smi" ]; then
        echo "ERROR: nvidia-smi not found in rootfs."
        exit 1
    fi
    echo "    nvidia-smi: found"
    if ls "${rootfs_dir}"/usr/bin/nvidia-container-runtime* >/dev/null 2>&1; then
        echo "    nvidia-container-runtime: found"
    else
        echo "WARNING: nvidia-container-runtime not found — GPU pods may not work."
    fi
    if [ -z "${kernel_version}" ]; then
        echo "ERROR: VM_KERNEL_VERSION not set — kernel module injection may have been skipped" >&2
        exit 1
    fi
    if [ -d "${rootfs_dir}/lib/modules/${kernel_version}" ]; then
        local mod_count
        mod_count=$(find "${rootfs_dir}/lib/modules/${kernel_version}" -name "nvidia*.ko" | wc -l)
        echo "    nvidia kernel modules: ${mod_count} found (kernel ${kernel_version})"
        if [ "$mod_count" -eq 0 ]; then
            echo "ERROR: no nvidia kernel modules in /lib/modules/${kernel_version}/"
            echo "       Run: mise run vm:nvidia-modules"
            exit 1
        fi
    else
        echo "ERROR: /lib/modules/${kernel_version}/ not found in rootfs"
        echo "       Run: mise run vm:nvidia-modules"
        exit 1
    fi
    local fw_dir="${rootfs_dir}/lib/firmware/nvidia/${driver_tag}"
    if [ ! -d "${fw_dir}" ]; then
        fw_dir="${rootfs_dir}/usr/lib/firmware/nvidia/${driver_tag}"
    fi
    if [ -d "${fw_dir}" ]; then
        local fw_count
        fw_count=$(ls "${fw_dir}"/gsp_*.bin 2>/dev/null | wc -l)
        echo "    GSP firmware: ${fw_count} files found"
        for fw in "${fw_dir}"/gsp_*.bin; do
            [ -f "$fw" ] || continue
            echo "      $(basename "$fw") ($(du -h "$fw" | cut -f1))"
        done
        if [ "$fw_count" -eq 0 ]; then
            echo "ERROR: No GSP firmware files (gsp_*.bin) in ${fw_dir}" >&2
            echo "       nvidia-smi will fail with: RmFetchGspRmImages: No firmware image found" >&2
            exit 1
        fi
    else
        echo "ERROR: GSP firmware directory not found" >&2
        echo "       Checked: ${rootfs_dir}/lib/firmware/nvidia/${driver_tag}/" >&2
        echo "       and:     ${rootfs_dir}/usr/lib/firmware/nvidia/${driver_tag}/" >&2
        echo "       Install: nvidia-firmware-${driver_version}-${driver_tag}" >&2
        exit 1
    fi
}

if [ "$BASE_ONLY" = true ]; then
    echo "==> Building base openshell-vm rootfs"
    echo "    Guest arch:  ${GUEST_ARCH}"
    echo "    k3s version: ${K3S_VERSION}"
    echo "    Output:      ${ROOTFS_DIR}"
    echo "    Mode:        base (no pre-loaded images, cold start)"
    if [ "$GPU_BUILD" = true ]; then
        echo "    GPU:         yes (NVIDIA driver ${NVIDIA_DRIVER_VERSION}, toolkit ${NVIDIA_CONTAINER_TOOLKIT_VERSION})"
    fi
else
    echo "==> Building openshell-vm rootfs"
    echo "    Guest arch:  ${GUEST_ARCH}"
    echo "    k3s version: ${K3S_VERSION}"
    echo "    Images:      ${SERVER_IMAGE}, ${COMMUNITY_SANDBOX_IMAGE}"
    echo "    Output:      ${ROOTFS_DIR}"
    echo "    Mode:        full (pre-loaded images, pre-initialized)"
    if [ "$GPU_BUILD" = true ]; then
        echo "    GPU:         yes (NVIDIA driver ${NVIDIA_DRIVER_VERSION}, toolkit ${NVIDIA_CONTAINER_TOOLKIT_VERSION})"
    fi
fi
echo ""

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

K3S_BIN="/tmp/k3s-${GUEST_ARCH}-${K3S_VERSION}"
if [ -f "${K3S_BIN}" ]; then
    echo "==> Using cached k3s binary: ${K3S_BIN}"
else
    echo "==> Downloading k3s ${K3S_VERSION} for ${GUEST_ARCH}..."
    curl -fSL "https://github.com/k3s-io/k3s/releases/download/${K3S_VERSION}/k3s${K3S_BINARY_SUFFIX}" \
        -o "${K3S_BIN}"
    chmod +x "${K3S_BIN}"
fi

# Verify k3s binary integrity.
K3S_CHECKSUM="${!K3S_CHECKSUM_VAR:-}"
if [ -n "${K3S_CHECKSUM}" ]; then
    echo "==> Verifying k3s binary checksum..."
    verify_checksum "${K3S_CHECKSUM}" "${K3S_BIN}"
else
    echo "WARNING: ${K3S_CHECKSUM_VAR} not set, skipping checksum verification"
fi

# ── Build base image with dependencies ─────────────────────────────────

# Clean up any previous run
docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true

echo "==> Building base image..."
if [ "$GPU_BUILD" = true ]; then
    docker build --platform "${DOCKER_PLATFORM}" -t "${BASE_IMAGE_TAG}" \
        --build-arg "BASE_IMAGE=${VM_BASE_IMAGE}" \
        --build-arg "NVIDIA_DRIVER_VERSION=${NVIDIA_DRIVER_VERSION}" \
        --build-arg "NVIDIA_DRIVER_TAG=${NVIDIA_DRIVER_TAG}" \
        --build-arg "NVIDIA_CONTAINER_TOOLKIT_VERSION=${NVIDIA_CONTAINER_TOOLKIT_VERSION}" \
        -f - . <<'DOCKERFILE'
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG NVIDIA_DRIVER_VERSION
ARG NVIDIA_DRIVER_TAG
ARG NVIDIA_CONTAINER_TOOLKIT_VERSION
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        e2fsprogs \
        iptables \
        iproute2 \
        kmod \
        python3 \
        busybox-static \
        sqlite3 \
        util-linux \
        zstd \
        gnupg \
        curl \
    && rm -rf /var/lib/apt/lists/*
# busybox-static provides udhcpc for DHCP inside the VM.
RUN mkdir -p /usr/share/udhcpc && \
    ln -sf /bin/busybox /sbin/udhcpc
RUN mkdir -p /var/lib/rancher/k3s /etc/rancher/k3s
# ── NVIDIA driver and container toolkit ──────────────────────────────
# Add the NVIDIA package repository and install the open kernel module
# flavour of the driver plus nvidia-container-toolkit. The open modules
# are required for data-center GPUs (Turing+ / compute capability >= 7.0).
# Userspace packages are pinned to $NVIDIA_DRIVER_TAG so they match the
# kernel modules compiled by build-nvidia-modules.sh.
RUN curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
        | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg \
    && curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
        | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
        > /etc/apt/sources.list.d/nvidia-container-toolkit.list
RUN apt-get update && \
    HEADLESS_VER=$(apt-cache madison nvidia-headless-${NVIDIA_DRIVER_VERSION}-open \
        | awk -v tag="${NVIDIA_DRIVER_TAG}" '$3 ~ "^"tag {print $3; exit}') && \
    UTILS_VER=$(apt-cache madison nvidia-utils-${NVIDIA_DRIVER_VERSION} \
        | awk -v tag="${NVIDIA_DRIVER_TAG}" '$3 ~ "^"tag {print $3; exit}') && \
    if [ -z "$HEADLESS_VER" ] || [ -z "$UTILS_VER" ]; then \
        echo "ERROR: No APT package found for driver tag ${NVIDIA_DRIVER_TAG}" >&2; \
        echo "  headless: ${HEADLESS_VER:-not found}"; \
        echo "  utils:    ${UTILS_VER:-not found}"; \
        exit 1; \
    fi && \
    echo "Pinning NVIDIA packages: headless=${HEADLESS_VER} utils=${UTILS_VER}" && \
    apt-get install -y --no-install-recommends \
        nvidia-headless-${NVIDIA_DRIVER_VERSION}-open=${HEADLESS_VER} \
        nvidia-utils-${NVIDIA_DRIVER_VERSION}=${UTILS_VER} \
        nvidia-container-toolkit=${NVIDIA_CONTAINER_TOOLKIT_VERSION}-1 \
    && rm -rf /var/lib/apt/lists/*
# Configure the NVIDIA container runtime as the default for containerd.
RUN nvidia-ctk runtime configure --runtime=containerd --set-as-default
DOCKERFILE
else
    docker build --platform "${DOCKER_PLATFORM}" -t "${BASE_IMAGE_TAG}" \
        --build-arg "BASE_IMAGE=${VM_BASE_IMAGE}" -f - . <<'DOCKERFILE'
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        e2fsprogs \
        iptables \
        iproute2 \
        python3 \
        busybox-static \
        sqlite3 \
        util-linux \
        zstd \
    && rm -rf /var/lib/apt/lists/*
# busybox-static provides udhcpc for DHCP inside the VM.
RUN mkdir -p /usr/share/udhcpc && \
    ln -sf /bin/busybox /sbin/udhcpc
RUN mkdir -p /var/lib/rancher/k3s /etc/rancher/k3s
DOCKERFILE
fi

# Create a container and export the filesystem
echo "==> Creating container..."
docker create --platform "${DOCKER_PLATFORM}" --name "${CONTAINER_NAME}" "${BASE_IMAGE_TAG}" /bin/true

echo "==> Exporting filesystem..."
# Previous builds (especially VM pre-init) may leave root-owned files
# (k3s data, CNI, kubelet) that prevent non-root removal. Try normal
# cleanup first, fall back to sudo if needed.
if [ -d "${ROOTFS_DIR}" ]; then
    if [ -z "${ROOTFS_DIR}" ] || [ "${ROOTFS_DIR}" = "/" ]; then
        echo "ERROR: ROOTFS_DIR is empty or root — refusing to rm -rf" >&2
        exit 1
    fi
    chmod -R u+rwx "${ROOTFS_DIR}" 2>/dev/null || true
    if ! rm -rf "${ROOTFS_DIR}" 2>/dev/null; then
        echo "    Root-owned files detected in ${ROOTFS_DIR}, using sudo to clean..."
        sudo rm -rf "${ROOTFS_DIR}"
    fi
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

echo "==> Injecting scripts..."
mkdir -p "${ROOTFS_DIR}/srv"
cp "${SCRIPT_DIR}/openshell-vm-init.sh" "${ROOTFS_DIR}/srv/openshell-vm-init.sh"
chmod +x "${ROOTFS_DIR}/srv/openshell-vm-init.sh"

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

SUPERVISOR_TARGET="${RUST_TARGET}"
SUPERVISOR_BIN="${PROJECT_ROOT}/target/${SUPERVISOR_TARGET}/release/openshell-sandbox"

echo "==> Building openshell-sandbox supervisor binary (${SUPERVISOR_TARGET})..."
if command -v cargo-zigbuild >/dev/null 2>&1; then
    cargo zigbuild --release -p openshell-sandbox --target "${SUPERVISOR_TARGET}" \
        --manifest-path "${PROJECT_ROOT}/Cargo.toml" 2>&1 | tail -5
else
    # Fallback: use plain cargo build when cargo-zigbuild is not available.
    # This works for native builds (e.g. building x86_64 on x86_64) but
    # will fail for true cross-compilation without a cross toolchain.
    echo "    cargo-zigbuild not found, falling back to cargo build..."
    cargo build --release -p openshell-sandbox --target "${SUPERVISOR_TARGET}" \
        --manifest-path "${PROJECT_ROOT}/Cargo.toml" 2>&1 | tail -5
fi

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

# ── Inject GPU manifests (when building GPU rootfs) ───────────────────
# These are deployed by openshell-vm-init.sh when GPU_ENABLED=true.
GPU_MANIFEST_SRC="${SCRIPT_DIR}/gpu-manifests"
GPU_MANIFEST_DEST="${ROOTFS_DIR}/opt/openshell/gpu-manifests"
if [ "$GPU_BUILD" = true ] && [ -d "${GPU_MANIFEST_SRC}" ]; then
    echo "==> Injecting GPU manifests..."
    mkdir -p "${GPU_MANIFEST_DEST}"
    GPU_MANIFEST_COPIED=0
    for manifest in "${GPU_MANIFEST_SRC}"/*.yaml; do
        [ -f "$manifest" ] || continue
        cp "$manifest" "${GPU_MANIFEST_DEST}/"
        echo "    $(basename "$manifest")"
        GPU_MANIFEST_COPIED=$((GPU_MANIFEST_COPIED + 1))
    done
    # Sentinel only when at least one manifest was staged (empty glob must not create it).
    if [ "$GPU_MANIFEST_COPIED" -gt 0 ]; then
        echo "gpu" > "${ROOTFS_DIR}/opt/openshell/.rootfs-gpu"
    else
        echo "WARNING: No GPU manifests (*.yaml) found in ${GPU_MANIFEST_SRC}; not writing .rootfs-gpu sentinel." >&2
    fi
fi

# ── Inject NVIDIA kernel modules (GPU rootfs only) ────────────────────
# The kernel modules are compiled separately by build-nvidia-modules.sh
# against the VM kernel source tree.  We inject them here so modprobe
# can load nvidia.ko at VM boot time.
if [ "$GPU_BUILD" = true ]; then
    NVIDIA_MODULES_DIR="${PROJECT_ROOT}/target/libkrun-build/nvidia-modules"

    # Read the kernel version exported by build-libkrun.sh.
    KERNEL_VERSION_FILE="${PROJECT_ROOT}/target/libkrun-build/kernel-version.txt"
    if [ -f "$KERNEL_VERSION_FILE" ]; then
        VM_KERNEL_VERSION="$(cat "$KERNEL_VERSION_FILE")"
    else
        echo "ERROR: kernel-version.txt not found at ${KERNEL_VERSION_FILE}" >&2
        echo "       Run: FROM_SOURCE=1 mise run vm:setup" >&2
        exit 1
    fi

    MODULE_DEST="${ROOTFS_DIR}/lib/modules/${VM_KERNEL_VERSION}/kernel/drivers/video/nvidia"

    if [ -d "${NVIDIA_MODULES_DIR}" ] && ls "${NVIDIA_MODULES_DIR}"/*.ko >/dev/null 2>&1; then
        echo "==> Injecting NVIDIA kernel modules (kernel ${VM_KERNEL_VERSION})..."
        mkdir -p "${MODULE_DEST}"
        cp "${NVIDIA_MODULES_DIR}"/*.ko "${MODULE_DEST}/"
        for mod in "${MODULE_DEST}"/*.ko; do
            echo "    $(basename "$mod") ($(du -h "$mod" | cut -f1))"
        done

        # Generate module dependency metadata so modprobe works.
        KERNEL_DIR_NAME="$(grep '^KERNEL_VERSION' "${PROJECT_ROOT}/target/libkrun-build/libkrunfw/Makefile" | head -1 | awk '{print $3}')"
        SYSTEM_MAP="${PROJECT_ROOT}/target/libkrun-build/libkrunfw/${KERNEL_DIR_NAME}/System.map"
        if [ -f "$SYSTEM_MAP" ]; then
            depmod -a -b "${ROOTFS_DIR}" -F "$SYSTEM_MAP" "${VM_KERNEL_VERSION}"
        else
            depmod -a -b "${ROOTFS_DIR}" "${VM_KERNEL_VERSION}"
        fi
        echo "    depmod: module dependencies generated"
    else
        echo "ERROR: NVIDIA kernel modules not found at ${NVIDIA_MODULES_DIR}" >&2
        echo "       Run: tasks/scripts/vm/build-nvidia-modules.sh" >&2
        exit 1
    fi
fi

# ── Base mode: mark rootfs type and skip pre-loading ───────────────────

if [ "$BASE_ONLY" = true ]; then
    # k3s expects this directory to exist for airgap image loading.
    mkdir -p "${ROOTFS_DIR}/var/lib/rancher/k3s/agent/images"

    # Mark as base (not pre-initialized). The init script checks for
    # this file to determine if cold start is expected.
    echo "base" > "${ROOTFS_DIR}/opt/openshell/.rootfs-type"

    # ── Verify ─────────────────────────────────────────────────────────
    if [ ! -f "${ROOTFS_DIR}/usr/local/bin/k3s" ]; then
        echo "ERROR: k3s binary not found in rootfs."
        exit 1
    fi

    if [ ! -x "${ROOTFS_DIR}/opt/openshell/bin/openshell-sandbox" ]; then
        echo "ERROR: openshell-sandbox supervisor binary not found in rootfs."
        exit 1
    fi

    if [ "$GPU_BUILD" = true ]; then
        if [ ! -f "${ROOTFS_DIR}/opt/openshell/.rootfs-gpu" ]; then
            echo "ERROR: GPU sentinel file not found in rootfs."
            exit 1
        fi
        verify_gpu_rootfs "${ROOTFS_DIR}" "${VM_KERNEL_VERSION:-}" "${NVIDIA_DRIVER_TAG}" "${NVIDIA_DRIVER_VERSION}"
    fi

    echo ""
    echo "==> Base rootfs ready at: ${ROOTFS_DIR}"
    echo "    Size: $(du -sh "${ROOTFS_DIR}" | cut -f1)"
    if [ "$GPU_BUILD" = true ]; then
        echo "    Type: base + GPU (cold start, NVIDIA driver ${NVIDIA_DRIVER_VERSION})"
    else
        echo "    Type: base (cold start, images pulled on demand)"
    fi
    echo ""
    echo "Note: First boot will take ~30-60s as k3s initializes."
    echo "      Container images will be pulled from registries on first use."
    exit 0
fi

# ══════════════════════════════════════════════════════════════════════════
# Full mode: pre-load images and pre-initialize k3s cluster state
# ══════════════════════════════════════════════════════════════════════════

# ── Pre-load container images ────────────────────────────────────────
# Pull images for the target architecture and save as tarballs in the
# k3s airgap images directory. k3s auto-imports from
# /var/lib/rancher/k3s/agent/images/ on startup, so no internet access
# is needed at boot time.
#
# Tarballs are cached in a persistent directory outside the rootfs so
# they survive rebuilds. This avoids re-pulling and re-saving ~1 GiB
# of images each time.

IMAGES_DIR="${ROOTFS_DIR}/var/lib/rancher/k3s/agent/images"
IMAGE_CACHE_DIR="${XDG_CACHE_HOME:-${HOME}/.cache}/openshell/openshell-vm/images"
mkdir -p "${IMAGES_DIR}" "${IMAGE_CACHE_DIR}"

echo "==> Pre-loading container images (${GUEST_ARCH})..."

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
    if ! docker pull --platform "${DOCKER_PLATFORM}" "${image}" --quiet 2>/dev/null; then
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

# GPU manifests: same pre-init path as other auto-deploy manifests so k3s
# sees them during cluster bake (not only under /opt/openshell/gpu-manifests).
if [ "$GPU_BUILD" = true ] && [ -d "${GPU_MANIFEST_DEST}" ]; then
    for manifest in "${GPU_MANIFEST_DEST}"/*.yaml; do
        [ -f "$manifest" ] || continue
        cp "$manifest" "${INIT_MANIFESTS}/"
    done
fi

# Patch HelmChart for local images and VM settings.
HELMCHART="${INIT_MANIFESTS}/openshell-helmchart.yaml"
if [ -f "$HELMCHART" ]; then
    # Use local images — explicitly imported into containerd.
    sed -i '' 's|__IMAGE_PULL_POLICY__|IfNotPresent|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|__IMAGE_PULL_POLICY__|IfNotPresent|g' "$HELMCHART"
    sed -i '' 's|__SANDBOX_IMAGE_PULL_POLICY__|"IfNotPresent"|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|__SANDBOX_IMAGE_PULL_POLICY__|"IfNotPresent"|g' "$HELMCHART"
    sed -i '' 's|__DB_URL__|"sqlite:/tmp/openshell.db"|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|__DB_URL__|"sqlite:/tmp/openshell.db"|g' "$HELMCHART"
    # Use the locally imported image references.
    sed -i '' -E "s|repository:[[:space:]]*[^[:space:]]+|repository: ${SERVER_IMAGE%:*}|" "$HELMCHART" 2>/dev/null \
        || sed -i -E "s|repository:[[:space:]]*[^[:space:]]+|repository: ${SERVER_IMAGE%:*}|" "$HELMCHART"
    sed -i '' -E "s|tag:[[:space:]]*\"?[^\"[:space:]]+\"?|tag: \"${IMAGE_TAG}\"|" "$HELMCHART" 2>/dev/null \
        || sed -i -E "s|tag:[[:space:]]*\"?[^\"[:space:]]+\"?|tag: \"${IMAGE_TAG}\"|" "$HELMCHART"
    # Clear SSH gateway placeholders.
    sed -i '' 's|sshGatewayHost: __SSH_GATEWAY_HOST__|sshGatewayHost: ""|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|sshGatewayHost: __SSH_GATEWAY_HOST__|sshGatewayHost: ""|g' "$HELMCHART"
    sed -i '' 's|sshGatewayPort: __SSH_GATEWAY_PORT__|sshGatewayPort: 0|g' "$HELMCHART" 2>/dev/null \
        || sed -i 's|sshGatewayPort: __SSH_GATEWAY_PORT__|sshGatewayPort: 0|g' "$HELMCHART"
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

# local-path-provisioner (deployed by k3s from local-storage.yaml) provides
# PVC storage for sandbox workspace volumes. It requires CNI bridge
# networking, which is now available in the VM kernel.

# ── Pre-initialize using the actual libkrun VM ──────────────────────────
# Boot the real VM with the rootfs we just built. This uses the same
# kernel, networking, and kube-proxy config as production — eliminating
# Docker IP mismatches, snapshotter mismatches, and the Docker volume
# copy-back dance. The VM writes state directly into the rootfs via
# virtio-fs.
#
# Requirements: the openshell-vm binary must be built and codesigned.
# mise run vm:build handles this.

GATEWAY_BIN="${PROJECT_ROOT}/target/debug/openshell-vm"
RUNTIME_DIR="${PROJECT_ROOT}/target/debug/openshell-vm.runtime"

if [ ! -x "${GATEWAY_BIN}" ]; then
    echo "ERROR: openshell-vm binary not found at ${GATEWAY_BIN}"
    echo "       Run: mise run vm:build"
    exit 1
fi

if [ ! -d "${RUNTIME_DIR}" ]; then
    echo "ERROR: VM runtime bundle not found at ${RUNTIME_DIR}"
    echo "       Run: mise run vm:build"
    exit 1
fi

# Helper: run a command inside the VM via the exec agent.
vm_exec() {
    if [ "$(uname -s)" = "Darwin" ]; then
        DYLD_FALLBACK_LIBRARY_PATH="${RUNTIME_DIR}${DYLD_FALLBACK_LIBRARY_PATH:+:${DYLD_FALLBACK_LIBRARY_PATH}}" \
            "${GATEWAY_BIN}" --rootfs "${ROOTFS_DIR}" exec -- "$@" 2>&1
    else
        LD_LIBRARY_PATH="${RUNTIME_DIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
            "${GATEWAY_BIN}" --rootfs "${ROOTFS_DIR}" exec -- "$@" 2>&1
    fi
}

# Ensure no stale VM is using this rootfs.
echo "    Starting VM for pre-initialization..."
if [ "$(uname -s)" = "Darwin" ]; then
    export DYLD_FALLBACK_LIBRARY_PATH="${RUNTIME_DIR}${DYLD_FALLBACK_LIBRARY_PATH:+:${DYLD_FALLBACK_LIBRARY_PATH}}"
else
    export LD_LIBRARY_PATH="${RUNTIME_DIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
fi
# Pre-initialize directly on virtio-fs. Runtime boots attach a separate
# block-backed state disk and seed it from the rootfs on first launch.
rm -f "${ROOTFS_DIR}-console.log" 2>/dev/null || sudo rm -f "${ROOTFS_DIR}-console.log" 2>/dev/null || true
OPENSHELL_VM_DISABLE_STATE_DISK=1 "${GATEWAY_BIN}" --rootfs "${ROOTFS_DIR}" --reset &
VM_PID=$!

# Ensure the VM is cleaned up on script exit.
cleanup_vm() {
    if kill -0 "${VM_PID}" 2>/dev/null; then
        echo "    Stopping VM (pid ${VM_PID})..."
        kill "${VM_PID}" 2>/dev/null || true
        wait "${VM_PID}" 2>/dev/null || true
    fi
    # Kill orphaned gvproxy processes left by the VM (holds port 30051).
    local gvproxy_pids
    gvproxy_pids=$(pgrep -f "gvproxy.*listen-qemu" 2>/dev/null || true)
    if [ -n "$gvproxy_pids" ]; then
        echo "    Killing orphaned gvproxy: $gvproxy_pids"
        kill $gvproxy_pids 2>/dev/null || true
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

# Wait for containerd to be ready. The first boot after a --reset may
# need extra time for k3s to extract its data dir and start containerd.
echo "    Waiting for containerd..."
for i in $(seq 1 180); do
    if vm_exec k3s ctr version >/dev/null 2>&1; then
        echo "    Containerd ready (${i}s)"
        break
    fi
    if [ "$i" -eq 180 ]; then
        echo "ERROR: containerd did not become ready in 180s"
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
# snapshots on first boot. The snapshotter now runs directly on virtio-fs,
# so these unpacked layers persist across VM restarts — eliminating the
# per-boot layer extraction that previously added ~3-5s per container.
echo "    Pre-unpacking container images..."
for img in \
    "${COMMUNITY_SANDBOX_IMAGE}" \
    "${SERVER_IMAGE}"; do
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
# leases) created during pre-initialization would cause the VM's kubelet
# to reconcile against an empty containerd on first real boot.
#
# NOTE: This is build-time cleanup only — it produces a clean rootfs
# image. At runtime, state.db is preserved across VM restarts so that
# pods and other cluster objects persist. The init script
# (openshell-vm-init.sh) handles stale bootstrap lock cleanup via
# sqlite3, and the host-side Rust code (exec.rs) handles actual DB
# corruption by removing the file.
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

# ── GPU verification (full mode) ──────────────────────────────────────
if [ "$GPU_BUILD" = true ]; then
    verify_gpu_rootfs "${ROOTFS_DIR}" "${VM_KERNEL_VERSION:-}" "${NVIDIA_DRIVER_TAG}" "${NVIDIA_DRIVER_VERSION}"
fi

echo ""
echo "==> Rootfs ready at: ${ROOTFS_DIR}"
echo "    Size: $(du -sh "${ROOTFS_DIR}" | cut -f1)"
echo "    Pre-initialized: $(cat "${ROOTFS_DIR}/opt/openshell/.initialized" 2>/dev/null || echo 'no')"
if [ "$GPU_BUILD" = true ]; then
    echo "    GPU: NVIDIA driver ${NVIDIA_DRIVER_VERSION}, toolkit ${NVIDIA_CONTAINER_TOOLKIT_VERSION}"
fi

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
