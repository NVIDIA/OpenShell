#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# OpenShell KubeVirt initramfs init (boot stage).
#
# This script is packed into the initramfs (e2e/kubevirt/build-guest-image.sh)
# and runs as PID 1 BEFORE the real root is mounted. It assembles the root
# filesystem and execs the guest init, which continues as PID 1.
#
# Boot plan (root-workload VM PoC):
#
#   /dev/vda  containerDisk ext4 carrying the rootfs. The containerDisk is
#             read-only at the device level (KubeVirt containerDisks are
#             read-only volumes), so the base image can never be modified
#             in place — every boot reads the image as built.
#   overlay   tmpfs upper + work over the read-only lower: the workload
#             gets a writable / in RAM, and every boot starts fresh from
#             the image. Nothing in the guest is a trust anchor: the guest
#             is untrusted as soon as a workload executes, so persisted
#             guest state has no security value and stale mutated state
#             would only poison later boots of the same sandbox.
#   /run/     the guest init and the boundary binary are bind-mounted from
#   openshell the image lower (inode-pinned, read-only) so the boundary
#             always starts from image bytes, but this is a freshness
#             measure, not a trust boundary: root in the guest can unmount
#             or bypass anything in-guest. The real boundary is outside
#             the guest (the fence, the supervisor's policy, the VM).

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# The stock initramfs exposes only /bin/sh; install every busybox applet
# symlink so insmod/sleep/mount/switch_root resolve as commands.
/bin/busybox --install -s /bin

fatal() {
    echo "[boot-init FATAL] $*" >&2
    echo "[boot-init FATAL] powering off" >&2
    sync
    poweroff -f
    while true; do sleep 3600; done
}

mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

# The stock initramfs's kmod modprobe resolves the module tree: the
# virtio block device carrying the rootfs.
modprobe virtio_blk 2>/dev/null || true
modprobe virtio_net 2>/dev/null || true
modprobe overlay 2>/dev/null || true
[ -e /dev/vda ] \
    || fatal "/dev/vda missing (virtio_blk did not load?)"

# Mount the containerDisk rootfs read-only (containerDisks are read-only
# volumes; noload skips journal replay on the pristine image).
mkdir -p /lower
mount -t ext4 -o ro,noload /dev/vda /lower \
    || fatal "mounting the guest rootfs failed"

# The writable root: a tmpfs-backed overlay over the read-only lower.
# NOTE: upper/work are created AFTER the tmpfs is mounted on /ovl — the
# pre-mount mkdir is hidden by the tmpfs, so the overlay's upperdir and
# workdir must exist inside it.
mkdir -p /ovl/upper /ovl/work /sysroot
mount -t tmpfs -o mode=0755,nosuid tmpfs /ovl
mkdir -p /ovl/upper /ovl/work
mount -t overlay overlay \
    -o "lowerdir=/lower,upperdir=/ovl/upper,workdir=/ovl/work" /sysroot \
    || fatal "overlayfs mount failed"

# Bind paths: pin the guest init and boundary binaries from the image
# lower into the new root so the boundary starts from image bytes (the
# workload may shadow /opt/openshell/init and
# /usr/local/bin/openshell-sandbox in the overlay; /run/openshell/* keep
# resolving to the pinned inodes until the workload tears them down —
# a freshness measure, not a trust boundary).
mkdir -p /sysroot/run/openshell
# A bind mount needs an existing target file; the bound inode is what
# resolves afterwards.
touch /sysroot/run/openshell/init /sysroot/run/openshell/openshell-sandbox
mount --bind /lower/opt/openshell/init /sysroot/run/openshell/init \
    || fatal "bind-mounting the guest init failed"
mount --bind /lower/usr/local/bin/openshell-sandbox \
    /sysroot/run/openshell/openshell-sandbox \
    || fatal "bind-mounting the boundary binary failed"

# The overlay holds references to the lower and /ovl superblocks; moving
# both mounts into the new root keeps them alive across switch_root (which
# otherwise frees the initramfs).
mkdir -p /sysroot/run/lower /sysroot/run/ovl
mount --move /lower /sysroot/run/lower || fatal "moving the lower mount failed"
mount --move /ovl /sysroot/run/ovl || fatal "moving the overlay tmpfs failed"

# /dev, /proc, /sys move with switch_root's -c or land via the guest init's
# own mounts; busybox switch_root moves them when they are mounted at the
# standard paths.
echo "[boot-init] switching to the overlay root"
exec switch_root /sysroot /run/openshell/init
