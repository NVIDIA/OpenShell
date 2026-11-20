#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build the KubeVirt guest containerDisk for the OpenShell kubevirt runtime
# mode PoC (see e2e/kubevirt/README.md).
#
# Produces a local image `kvpoc/openshell-sandbox-vm:dev` containing:
#   /disk/disk.qcow2       bootable ext4 rootfs (Alpine + openshell-sandbox
#                          supervisor + the guest init from guest-init.sh)
#   /boot/vmlinuz-virt     guest kernel (direct kernel boot)
#   /boot/initramfs-virt   guest initramfs: the boot init
#                          (initramfs-init.sh) mounts the containerDisk
#                          rootfs read-only, stacks a writable tmpfs
#                          overlay, and switch_roots. The guest root is
#                          writable at runtime and fresh from the image on
#                          every boot — the guest is untrusted as soon as a
#                          workload executes, so nothing in-guest is a
#                          trust anchor.
#
# Usage: e2e/kubevirt/build-guest-image.sh [image-tag]
#        (then: k3d image import <image-tag> -c kvpoc)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE_TAG="${1:-kvpoc/openshell-sandbox-vm:dev}"
WORKDIR="$(mktemp -d /tmp/kvpoc-guest.XXXXXX)"
ROOTFS="${WORKDIR}/rootfs"
CARGO_TARGET="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}"
# The guest is Alpine (musl): the supervisor must be the fully static musl
# build (same requirement as the published supervisor image, see
# .github/workflows/rust-native-build.yml).
SUPERVISOR="${CARGO_TARGET}/x86_64-unknown-linux-musl/release/openshell-sandbox"

KUBEVIRT_VERSION="${KUBEVIRT_VERSION:-v1.9.1}"

command -v qemu-img >/dev/null || { echo "qemu-img is required" >&2; exit 1; }
# The build stages ~360 MB under WORKDIR; always remove it on exit unless
# KEEP_WORKDIR is set for debugging.
cleanup() {
    if [ -z "${KEEP_WORKDIR:-}" ] && [ -n "${WORKDIR:-}" ] && [ -d "${WORKDIR}" ]; then
        rm -rf "${WORKDIR}" 2>/dev/null || true
    fi
}
trap cleanup EXIT
# Always invoke cargo build: it is incremental, and a bare [ -x ] check
# silently ships a stale binary whenever a shared CARGO_TARGET_DIR already
# holds one from another checkout (which is exactly how the old-branch
# supervisor ended up in an image built from current main).
(cd "${REPO_ROOT}" && cargo build --release -p openshell-sandbox --target x86_64-unknown-linux-musl)
echo "==> guest supervisor: $("${SUPERVISOR}" --version)"

echo "==> workdir ${WORKDIR}"

# 1. Assemble the Alpine rootfs in a container. All shell setup runs in the
#    initial `docker run`; the container exits when done and `docker cp`
#    stages the host-built binaries into the stopped container's filesystem.
docker rm -f kvpoc-guest-rootfs >/dev/null 2>&1 || true
docker run --name kvpoc-guest-rootfs alpine:3.22 sh -c '
    set -eu
    apk add --no-cache linux-virt e2fsprogs iproute2 nftables iptables bash >/dev/null
    mkdir -p /opt/openshell /sandbox-seed /sandbox /usr/local/bin
    chown 10001:10001 /sandbox /sandbox-seed
    grep -q "^sandbox:" /etc/passwd ||
        printf "sandbox:x:10001:10001:OpenShell Sandbox:/sandbox:/bin/sh\n" >> /etc/passwd
    grep -q "^sandbox:" /etc/group ||
        printf "sandbox:x:10001:\n" >> /etc/group
'
docker cp "${REPO_ROOT}/e2e/kubevirt/guest-init.sh" kvpoc-guest-rootfs:/opt/openshell/init
docker cp "${SUPERVISOR}" kvpoc-guest-rootfs:/usr/local/bin/openshell-sandbox
docker export kvpoc-guest-rootfs -o "${WORKDIR}/rootfs.tar"
docker rm kvpoc-guest-rootfs >/dev/null

cp "${REPO_ROOT}/e2e/kubevirt/idmap-mount.c" "${WORKDIR}/idmap-mount.c"
cp "${REPO_ROOT}/e2e/kubevirt/initramfs-init.sh" "${WORKDIR}/initramfs-init.sh"

# 2. Unpack the exported rootfs, usr-merge it, render the ext4 disk, and
#    repack the initramfs — all as root inside a container. An unprivileged
#    `tar -xpf` cannot chown, so the rootfs (and with it the ext4 image
#    built by `mkfs.ext4 -d`) would be owned by the build uid instead of
#    root; the container keeps every filesystem step ownership-correct
#    without requiring root on the host.
docker run --rm -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    -v "${WORKDIR}:/work:Z" alpine:3.22 sh -c '
    set -eu
    apk add --no-cache e2fsprogs gcc musl-dev linux-headers >/dev/null

    mkdir -p /work/rootfs
    tar -xpf /work/rootfs.tar -C /work/rootfs

    # The idmapped-mount helper (static musl): remounts the virtiofs
    # workspace share with an idmap so the workload uid can write through
    # the unprivileged virtiofsd.
    cc -static -O2 -o /work/rootfs/usr/local/bin/idmap-mount /work/idmap-mount.c
    chmod 0755 /work/rootfs/usr/local/bin/openshell-sandbox /work/rootfs/opt/openshell/init

    # Usr-merge /bin and /sbin into /usr: the supervisor default Landlock
    # policy allows exec under /usr (glibc images are usr-merged; Alpine is
    # not, so busybox in /bin would be denied with EACCES).
    merge_into() {
        local src="$1" dest="$2"
        mkdir -p "${dest}"
        cp -a "${src}/." "${dest}/"
        rm -rf "${src}"
        ln -s "usr/$(basename "${dest}")" "${src}"
    }
    merge_into /work/rootfs/bin /work/rootfs/usr/bin
    merge_into /work/rootfs/sbin /work/rootfs/usr/sbin

    # Render the ext4 rootfs disk (700 MiB: Alpine base + kernel +
    # supervisor with headroom for runtime).
    mkfs.ext4 -F -q -d /work/rootfs /work/disk.raw 700m

    # The boot initramfs: our init (mount + overlay + switch_root). The
    # stock Alpine initramfs is unpacked, its init replaced, and repacked.
    mkdir -p /work/initrd
    cd /work/initrd
    zcat /work/rootfs/boot/initramfs-virt | cpio -idm --quiet
    cp /work/initramfs-init.sh init
    chmod 0755 init
    find . | cpio -o -H newc --quiet | gzip -9 > /work/initramfs-virt

    # Hand the workdir back to the invoking user: the docker build context
    # and the cleanup trap run unprivileged on the host.
    chown -R "${HOST_UID}:${HOST_GID}" /work
'

# 3. Compress to qcow2 and stage the kernel artifacts.
qemu-img convert -c -O qcow2 "${WORKDIR}/disk.raw" "${WORKDIR}/disk.qcow2"
cp "${ROOTFS}/boot/vmlinuz-virt" "${WORKDIR}/vmlinuz-virt"

# 5. Assemble the containerDisk image. KubeVirt >= 1.9 runs each
#    containerDisk image as a virt-launcher init container executing
#    /container-disk-binary/usr/bin/container-disk, so the helper binary
#    (taken from the matching virt-launcher image) must ship inside the
#    containerDisk image itself.
docker pull "quay.io/kubevirt/virt-launcher:${KUBEVIRT_VERSION}" >/dev/null 2>&1 || true
docker rm -f kvpoc-vl-ref >/dev/null 2>&1 || true
docker create --name kvpoc-vl-ref "quay.io/kubevirt/virt-launcher:${KUBEVIRT_VERSION}" >/dev/null
docker cp kvpoc-vl-ref:/usr/bin/container-disk "${WORKDIR}/container-disk"
docker rm kvpoc-vl-ref >/dev/null

cat > "${WORKDIR}/Dockerfile" <<EOF
# syntax=docker/dockerfile:1.4
FROM scratch
COPY disk.qcow2 /disk/disk.qcow2
COPY vmlinuz-virt /boot/vmlinuz-virt
COPY initramfs-virt /boot/initramfs-virt
COPY container-disk /container-disk-binary/usr/bin/container-disk
EOF
docker build -t "${IMAGE_TAG}" "${WORKDIR}"

echo "==> built ${IMAGE_TAG}"
docker image inspect "${IMAGE_TAG}" --format 'size: {{.Size}} bytes'
echo "==> import into the cluster with: k3d image import ${IMAGE_TAG} -c kvpoc"
