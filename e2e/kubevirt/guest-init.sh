#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# KubeVirt guest init for OpenShell sandboxes (proof of concept).
#
# Runs as PID 1 (kernel arg init=/opt/openshell/init inside the purpose-built
# containerDisk from e2e/kubevirt/build-guest-image.sh). Modeled on the libkrun
# init (crates/openshell-driver-vm/scripts/openshell-vm-sandbox-init.sh) but
# for KubeVirt hardware:
#
#   /dev/vda  rootfs      (containerDisk, read-only at the device level;
#                          the initramfs mounts the read-only lower and
#                          stacks a tmpfs overlay as the writable root —
#                          in-session writes are RAM and every boot starts
#                          fresh from the image)
#   /dev/vdb  config disk (cloudInitNoCloud ISO rendered from the driver's
#                          bootstrap Secret; shell-sourceable user-data)
#   workspace  virtio-fs share backed by the per-sandbox PVC (filesystem
#              PVCs are not exposed as block disks by KubeVirt), mounted at
#              /sandbox and seeded from the image on first boot
#
# After setup it runs the static openshell-sandbox boundary as a child
# process; PID 1 stays the init so it can power off the guest when the
# boundary exits.

set -eu

# Every exit of PID 1 must power the guest off: a dead init means either a
# kernel panic (QEMU serves a dead kernel, the VM reports ready forever) or
# a hung guest. The trap makes any `set -e` failure path, and the script's
# normal end, end the VMI so the driver maps the sandbox to Error. The
# normal poweroff path below fires the trap too; poweroff -f is idempotent
# enough at that point (the machine is already going down).
trap 'ts "init exiting (rc=$?); powering off"; sync; poweroff -f' EXIT

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export HOME=/root
export TERM=xterm

BOOT_START=$(date +%s 2>/dev/null || echo 0)
ts() {
    now=$(date +%s 2>/dev/null || echo 0)
    echo "[kvpoc-init $((now - BOOT_START))s] $*"
}

mount_fs() {
    mount -t proc proc /proc 2>/dev/null || true
    mount -t sysfs sysfs /sys 2>/dev/null || true
    # The Alpine initramfs does not mount devtmpfs on the real root, so /dev
    # is the image's static directory (no ptmx/null). The supervisor's exec
    # relay needs PTY allocation, which requires /dev/ptmx from devtmpfs.
    mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
    mkdir -p /dev/pts /dev/shm
    mount -t devpts -o gid=5,mode=620 devpts /dev/pts 2>/dev/null || true
    [ -e /dev/ptmx ] || ln -sf pts/ptmx /dev/ptmx
    mount -t tmpfs tmpfs /run 2>/dev/null || true
    mount -t tmpfs tmpfs /tmp 2>/dev/null || true
    # On the verified boot the root is the tmpfs overlay (already rw).
    # On the legacy plain boot the initramfs mounted the containerDisk
    # read-only and the remount makes it writable for the VMI's lifetime.
    mount -o remount,rw / 2>/dev/null || true
}

configure_network() {
    ip link set lo up 2>/dev/null || true
    ip link set eth0 up
    # The k3d pod network runs flannel-vxlan (MTU 1450); a guest eth0 at the
    # default 1500 black-holes full-size TCP segments — small unary RPCs work
    # but large stream frames (SSH KEX, gRPC session) stall. Clamp below the
    # launcher-side MTU before DHCP so the advertised MSS fits.
    ip link set dev eth0 mtu 1400 2>/dev/null || true
    # KubeVirt masquerade networking runs dnsmasq in the virt-launcher pod:
    # DHCP hands out the pod-network address plus cluster DNS.
    if udhcpc -i eth0 -q -n -t 30 -T 2 2>/dev/null; then
        ts "network configured via DHCP (mtu $(cat /sys/class/net/eth0/mtu 2>/dev/null || echo '?'))"
    else
        ts "WARNING: DHCP failed; supervisor will not reach the gateway"
    fi
    # The workload's resolver is the boundary's loopback DNS relay
    # (127.0.0.53), which forwards queries through the mediated control
    # stream — the workload cannot reach the cluster DNS directly (the
    # seccomp broker denies it, mirroring the libkrun VM driver's init).
    # DHCP (or its default script) may have written the cluster DNS into
    # /etc/resolv.conf; overwrite it.
    printf 'nameserver 127.0.0.53\noptions timeout:2 attempts:2\n' \
        > /etc/resolv.conf 2>/dev/null || \
        ts "WARNING: could not point /etc/resolv.conf at the loopback DNS relay"
}

read_bootstrap_config() {
    mkdir -p /config
    if ! mount -t iso9660 -o ro /dev/vdb /config 2>/dev/null; then
        mount -o ro /dev/vdb /config 2>/dev/null || {
            ts "FATAL: cannot mount bootstrap config disk"
            return 1
        }
    fi
    # The bootstrap payload is the shell-sourceable file rendered by the
    # Kubernetes driver's kubevirt runtime mode from the bootstrap Secret.
    # The Secret key is KubeVirt's cloudInitNoCloud convention (`userData`);
    # the file name inside the generated NoCloud ISO is the cloud-init
    # datasource convention (`user-data`). Accept either.
    if [ -f /config/user-data ]; then
        # shellcheck disable=SC1091
        # `set -a` exports every assignment while sourcing so the exec'd
        # supervisor inherits them (the libkrun path passes these as a real
        # VM environment; here they arrive as a file).
        set -a
        . /config/user-data
        set +a
    elif [ -f /config/userData ]; then
        # shellcheck disable=SC1091
        set -a
        . /config/userData
        set +a
    else
        ts "FATAL: no bootstrap payload on config disk"
        ls -la /config || true
        return 1
    fi
    ts "bootstrap config loaded (sandbox ${OPENSHELL_SANDBOX:-unknown})"
    umount /config
    # L1 (bootstrap config disk hygiene): read the cloud-init disk
    # exactly once, then remove the PCI function backing it so the disk
    # is not sitting attached and trivially readable for the whole
    # session. This is HYGIENE, NOT A CONTROL: root in the guest can
    # undo it (writing 1 to /sys/bus/pci/rescan re-enumerates the disk
    # — QEMU/KubeVirt still have it attached, and cloudInitNoCloud
    # volumes cannot be hot-unplugged in KubeVirt today), and the
    # boundary key is equally exposed through the boundary's own memory
    # (ptrace). The blast radius is its own sandbox. virtio-blk has no
    # SCSI-style per-device `delete`, so the ejection removes the PCI
    # function (resolved from the sysfs device path — never a hardcoded
    # address). A guest reset re-attaches the device, but the pristine
    # boot re-reads it only within the boot flow (before any workload
    # code runs), and a fresh boundary attaching to the live generation
    # ends it (P1's handle check) and the VM is halted (R3). Failing to
    # eject is fatal — it signals a broken boot environment rather
    # than silently leaving the disk attached.
    local vdb_pci=""
    vdb_pci="$(basename "$(dirname "$(readlink -f /sys/block/vdb/device 2>/dev/null)" 2>/dev/null)" 2>/dev/null)" || true
    case "${vdb_pci}" in
        *:*:*.*) ;;
        *) vdb_pci="" ;;
    esac
    if [ -n "${vdb_pci}" ] && [ -w "/sys/bus/pci/devices/${vdb_pci}/remove" ]; then
        if ! echo 1 > "/sys/bus/pci/devices/${vdb_pci}/remove" 2>/dev/null; then
            ts "FATAL: cannot eject the bootstrap config disk (pci ${vdb_pci})"
            return 1
        fi
        ts "bootstrap config disk ejected (one-shot read, pci ${vdb_pci})"
    else
        ts "FATAL: no eject handle for the bootstrap config disk"
        return 1
    fi
}

mount_workspace() {
    mkdir -p /sandbox
    # The workspace PVC arrives as a virtio-fs share (filesystem PVCs are not
    # exposed as block disks by KubeVirt). virtiofs is a kernel module in the
    # Alpine -virt kernel.
    modprobe virtiofs 2>/dev/null || true
    if ! mount -t virtiofs workspace /sandbox 2>/dev/null; then
        ts "WARNING: workspace virtio-fs share not available"
        return 0
    fi
    # The share arrives owned by the launcher fsGroup (virtiofsd runs as
    # that uid, unprivileged, and cannot switch credentials to the guest
    # workload uid): idmap the mount so the workload uid/gid and the
    # on-disk fsGroup translate into each other, then seed as the
    # workload user (root is unmapped through the idmap).
    share_gid="$(stat -c %g /sandbox 2>/dev/null || echo 0)"
    if [ -x /usr/local/bin/idmap-mount ] \
        && [ "${share_gid}" != "0" ] && [ "${share_gid}" != "10001" ] \
        && /usr/local/bin/idmap-mount /sandbox "${share_gid}" 10001; then
        ts "workspace idmapped (on-disk id ${share_gid} <-> guest 10001)"
        if [ ! -f /sandbox/.openshell-seeded ] && [ -d /sandbox-seed ]; then
            su -s /bin/sh sandbox -c \
                'cp -a /sandbox-seed/. /sandbox/ && touch /sandbox/.openshell-seeded' \
                2>/dev/null || true
        fi
        # Adopt files left by pre-idmap generations (created as other ids).
        su -s /bin/sh sandbox -c 'chown -R 10001:10001 /sandbox' 2>/dev/null || true
    else
        ts "WARNING: workspace idmap unavailable; writes as the workload uid will fail"
        if [ ! -f /sandbox/.openshell-seeded ] && [ -d /sandbox-seed ]; then
            cp -a /sandbox-seed/. /sandbox/ 2>/dev/null || true
            touch /sandbox/.openshell-seeded 2>/dev/null || true
        fi
        chown -R 10001:10001 /sandbox 2>/dev/null || true
    fi
    ts "workspace PVC mounted (virtio-fs)"
}

main() {
    ts "OpenShell KubeVirt guest init starting"
    mount_fs
    if [ -c /dev/ptmx ]; then
        ts "/dev/ptmx present"
    else
        ts "WARNING: /dev/ptmx missing — exec PTYs will fail"
    fi
    configure_network
    # The capability-free sandbox owns a loopback-only DNS relay on
    # 127.0.0.53:53. Guest init grants the low port before handing control
    # to the zero-capability workload UID (mirrors the libkrun VM driver's
    # init and the container runtimes' sysctl).
    if ! echo 0 > /proc/sys/net/ipv4/ip_unprivileged_port_start; then
        ts "FATAL: failed to permit the unprivileged DNS relay to bind port 53"
        return 1
    fi
    read_bootstrap_config
    mount_workspace
    ts "starting openshell-sandbox"
    # Stage the boundary bootstrap artifacts from the cloud-init payload
    # (base64 in the sourced userData) at the absolute paths written in the
    # BoundaryConfig, mode 0600, then launch the boundary. The boundary
    # deletes its config and TLS material after loading them.
    if [ -n "${OPENSHELL_BOUNDARY_CONFIG_B64:-}" ]; then
        # L1: capture the workload identity from the payload BEFORE
        # staging unsets it; the same values drive both the chown in
        # staging and the launch arguments. They come from the same
        # ResolvedWorkloadIdentity the boundary config carries
        # (render_guest_payload), so there is no second source of truth.
        local launch_uid launch_gid
        launch_uid="${OPENSHELL_WORKLOAD_UID}"
        launch_gid="${OPENSHELL_WORKLOAD_GID}"
        if [ -z "${launch_uid}" ] || [ -z "${launch_gid}" ]; then
            ts "FATAL: payload is missing the workload identity"
            return 1
        fi
        stage_boundary_bootstrap
        # G2: assert the environment is clean before launching the child.
        # The boundary inherits PID 1's env; any B64 or token var here
        # would leak into the boundary and its workload children.
        if env | grep -q "BOUNDARY_.*_B64\|OPENSHELL_SANDBOX_TOKEN"; then
            ts "FATAL: key material still in environment after staging"
            return 1
        fi
        ts "environment verified clean (no B64 or token vars)"
        # Run the boundary as a child (not exec) so PID 1 can power off on
        # exit (see the wait + poweroff below). Root mode (uid/gid 0)
        # launches the privileged boundary; the sandboxed default uses
        # the capability-free launch.
        # The boundary binary comes from the initramfs bind path when
        # staged (the initramfs pins the image inode at
        # /run/openshell/openshell-sandbox); otherwise the rootfs copy is
        # used. The pin is a freshness measure (the boundary starts from
        # image bytes), not a trust boundary — a root workload can unmount
        # anything in-guest.
        BOUNDARY_BIN=/usr/local/bin/openshell-sandbox
        if [ -x /run/openshell/openshell-sandbox ]; then
            BOUNDARY_BIN=/run/openshell/openshell-sandbox
            ts "boundary from the verified trusted path (${BOUNDARY_BIN})"
        fi
        if [ "${launch_uid}" = "0" ] && [ "${launch_gid}" = "0" ]; then
            ts "launching privileged (root-workload) boundary"
            "${BOUNDARY_BIN}" launch-privileged \
                /.openshell/state/bootstrap/boundary.json &
        else
            # shellcheck disable=SC2086
            "${BOUNDARY_BIN}" launch-capability-free \
                "${launch_uid}" "${launch_gid}" \
                /.openshell/state/bootstrap/boundary.json &
        fi
        SANDBOX_PID=$!
    else
        # No boundary payload: the gateway cannot have created this VM
        # (create requires launch authentication and renders the boundary
        # payload), so this is an invalid or tampered bootstrap.
        ts "FATAL: no boundary payload in bootstrap config (OPENSHELL_BOUNDARY_CONFIG_B64 unset)"
        return 1
    fi
    # `wait` returns the child's exit status, and this script runs under
    # `set -e`: an unguarded failing wait would exit PID 1 (kernel panic)
    # before the poweroff below.
    SANDBOX_RC=0
    wait "${SANDBOX_PID}" || SANDBOX_RC=$?
    ts "openshell-sandbox exited with code ${SANDBOX_RC}; powering off"
    sync
    # -f skips the shutdown script hierarchy (there is none here): the
    # kernel powers the machine off immediately, QEMU exits, and the VMI
    # reaches Succeeded so the driver maps the sandbox to Error.
    poweroff -f
    # poweroff -f does not return; sleep forever as a fallback so PID 1
    # never exits into a kernel panic if the syscall fails.
    while true; do sleep 3600; done
}

# Decode the base64 boundary artifacts from the cloud-init payload and
# stage them at the paths the BoundaryConfig expects. The boundary reads
# and DELETES these files as the zero-capability workload uid:gid, so:
# - /.openshell/state is a tmpfs (G3: the key never lands on the
#   rootfs block device);
# - the files and directory are chowned to the workload uid:gid (G1: the
#   boundary can read and unlink them);
# - the base64 environment variables are unset after staging (G2: they
#   never leak into the boundary or workload children).
stage_boundary_bootstrap() {
    local uid gid
    uid="${OPENSHELL_WORKLOAD_UID}"
    gid="${OPENSHELL_WORKLOAD_GID}"

    # G3: tmpfs so the key material never touches the containerDisk.
    mkdir -p /.openshell/state/bootstrap
    mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs /.openshell/state
    mkdir -p /.openshell/state/bootstrap
    chmod 0700 /.openshell/state /.openshell/state/bootstrap

    printf '%s' "${OPENSHELL_BOUNDARY_CONFIG_B64}" | base64 -d \
        > /.openshell/state/bootstrap/boundary.json
    printf '%s' "${OPENSHELL_BOUNDARY_CERTIFICATE_B64}" | base64 -d \
        > /.openshell/state/bootstrap/tls.crt
    printf '%s' "${OPENSHELL_BOUNDARY_PRIVATE_KEY_B64}" | base64 -d \
        > /.openshell/state/bootstrap/tls.key
    chmod 0600 \
        /.openshell/state/bootstrap/boundary.json \
        /.openshell/state/bootstrap/tls.crt \
        /.openshell/state/bootstrap/tls.key

    # G1: the boundary reads and deletes these as the workload uid.
    chown -R "${uid}:${gid}" /.openshell/state

    # G2: the base64 key material must not survive into the boundary's
    # environment or any workload child.
    unset OPENSHELL_BOUNDARY_CONFIG_B64 \
        OPENSHELL_BOUNDARY_CERTIFICATE_B64 \
        OPENSHELL_BOUNDARY_PRIVATE_KEY_B64 \
        OPENSHELL_WORKLOAD_UID OPENSHELL_WORKLOAD_GID

    ts "boundary bootstrap staged on tmpfs (uid=${uid}, gid=${gid})"
}

main
