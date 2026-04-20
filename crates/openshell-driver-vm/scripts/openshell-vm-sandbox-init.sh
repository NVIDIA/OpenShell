#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Minimal init for sandbox VMs. Runs as PID 1 inside the guest, mounts the
# essential filesystems, configures gvproxy networking when present, then
# execs the OpenShell sandbox supervisor.

set -euo pipefail

BOOT_START=$(date +%s%3N 2>/dev/null || date +%s)

ts() {
    local now
    now=$(date +%s%3N 2>/dev/null || date +%s)
    local elapsed=$((now - BOOT_START))
    printf "[%d.%03ds] %s\n" $((elapsed / 1000)) $((elapsed % 1000)) "$*"
}

parse_endpoint() {
    local endpoint="$1"
    local scheme rest authority path host port

    case "$endpoint" in
        *://*)
            scheme="${endpoint%%://*}"
            rest="${endpoint#*://}"
            ;;
        *)
            return 1
            ;;
    esac

    authority="${rest%%/*}"
    path="${rest#"$authority"}"
    if [ "$path" = "$rest" ]; then
        path=""
    fi

    if [[ "$authority" =~ ^\[([^]]+)\]:(.+)$ ]]; then
        host="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
    elif [[ "$authority" =~ ^\[([^]]+)\]$ ]]; then
        host="${BASH_REMATCH[1]}"
        port=""
    elif [[ "$authority" == *:* ]]; then
        host="${authority%%:*}"
        port="${authority##*:}"
    else
        host="$authority"
        port=""
    fi

    if [ -z "$port" ]; then
        case "$scheme" in
            https) port="443" ;;
            *) port="80" ;;
        esac
    fi

    printf '%s\n%s\n%s\n%s\n' "$scheme" "$host" "$port" "$path"
}

tcp_probe() {
    local host="$1"
    local port="$2"

    if command -v timeout >/dev/null 2>&1; then
        timeout 2 bash -c "exec 3<>/dev/tcp/${host}/${port}" >/dev/null 2>&1
    else
        bash -c "exec 3<>/dev/tcp/${host}/${port}" >/dev/null 2>&1
    fi
}

resolve_block_device_by_serial() {
    # libkrun's `krun_add_disk3` exposes the caller-supplied block_id as the
    # virtio-blk serial, which Linux surfaces at /sys/block/<dev>/serial.
    # Walk virtio-blk devices (vd*) and return the /dev path whose serial
    # matches $1. This makes the guest tolerant to attach-order changes.
    local target_serial="$1"
    local block
    for block in /sys/block/vd*; do
        [ -d "$block" ] || continue
        local serial_file="$block/serial"
        [ -r "$serial_file" ] || continue
        local serial
        serial=$(cat "$serial_file" 2>/dev/null || true)
        if [ "$serial" = "$target_serial" ]; then
            printf '/dev/%s\n' "$(basename "$block")"
            return 0
        fi
    done
    return 1
}

oci_launch_supervisor() {
    # Enter OCI overlay mode: mount the shared read-only squashfs base plus a
    # per-sandbox ext4 upper, overlay them, pivot_root into the merged view,
    # then exec the supervisor post-pivot so container paths like /sandbox and
    # /tmp are the real paths from the supervisor's POV.

    # Prefer block-ID resolution so the mount points don't silently break if
    # libkrun ever changes virtio-blk attach order. Env var overrides are kept
    # for operator escape hatches and test harnesses.
    local base_dev="${OPENSHELL_VM_OCI_BASE_DEVICE:-}"
    local state_dev="${OPENSHELL_VM_STATE_DEVICE:-}"

    if [ -z "$base_dev" ]; then
        base_dev=$(resolve_block_device_by_serial "oci-base" || true)
    fi
    if [ -z "$state_dev" ]; then
        state_dev=$(resolve_block_device_by_serial "sandbox-state" || true)
    fi

    # Fall back to attach-order defaults only when serial lookup returns nothing
    # (older guest kernels or missing /sys/block/<vd>/serial).
    if [ -z "$base_dev" ]; then
        ts "WARNING: could not resolve RO base by serial=oci-base; falling back to /dev/vda"
        base_dev=/dev/vda
    fi
    if [ -z "$state_dev" ]; then
        ts "WARNING: could not resolve state disk by serial=sandbox-state; falling back to /dev/vdb"
        state_dev=/dev/vdb
    fi

    if [ ! -b "$base_dev" ]; then
        ts "ERROR: OCI base device $base_dev not found"
        exit 1
    fi
    if [ ! -b "$state_dev" ]; then
        ts "ERROR: OCI state device $state_dev not found"
        exit 1
    fi

    ts "OCI block devices resolved: base=$base_dev state=$state_dev"

    mkdir -p /base /state
    if ! mount -o ro "$base_dev" /base 2>/dev/null; then
        ts "ERROR: failed to mount read-only base $base_dev at /base"
        exit 1
    fi

    if ! blkid "$state_dev" >/dev/null 2>&1; then
        ts "formatting sandbox state disk $state_dev"
        mkfs.ext4 -F -q -L openshell-sandbox-state "$state_dev" >/dev/null 2>&1 || {
            ts "ERROR: mkfs.ext4 failed on $state_dev"
            exit 1
        }
    fi
    if ! mount -o noatime "$state_dev" /state 2>/dev/null; then
        ts "ERROR: failed to mount state disk $state_dev at /state"
        exit 1
    fi

    mkdir -p /state/upper /state/work /state/merged /state/workspace
    if ! mount -t overlay overlay \
        -o "lowerdir=/base,upperdir=/state/upper,workdir=/state/work" \
        /state/merged 2>/dev/null; then
        ts "ERROR: failed to mount overlay at /state/merged"
        exit 1
    fi

    # The image's /sandbox is RO (it lives in the base); bind the writable
    # workspace over it so the container process can write to /sandbox.
    mkdir -p /state/merged/sandbox
    mount --bind /state/workspace /state/merged/sandbox

    # Synthesize /etc/resolv.conf inside the image if the image does not
    # provide one; reuse the guest's DHCP-populated one.
    if [ ! -s /state/merged/etc/resolv.conf ] && [ -s /etc/resolv.conf ]; then
        mkdir -p /state/merged/etc
        cp /etc/resolv.conf /state/merged/etc/resolv.conf 2>/dev/null || true
    fi

    # Mirror TLS CA bundle into the merged view so SSL trust survives the pivot.
    if [ -n "${OPENSHELL_TLS_CA:-}" ] && [ -f "$OPENSHELL_TLS_CA" ]; then
        mkdir -p /state/merged/opt/openshell/tls
        cp "$OPENSHELL_TLS_CA" /state/merged/opt/openshell/tls/ca.crt 2>/dev/null || true
    fi

    # Supervisor binary must be reachable post-pivot. Copy it into the upper
    # layer (writes land on the state disk, not the RO base).
    mkdir -p /state/merged/opt/openshell/bin
    if [ ! -x /state/merged/opt/openshell/bin/openshell-sandbox ]; then
        cp /opt/openshell/bin/openshell-sandbox \
            /state/merged/opt/openshell/bin/openshell-sandbox
        chmod 0755 /state/merged/opt/openshell/bin/openshell-sandbox
    fi

    # Ensure the kernel pseudo-filesystems are available after pivot.
    mkdir -p /state/merged/proc /state/merged/sys /state/merged/dev
    mount --bind /proc /state/merged/proc 2>/dev/null || true
    mount --bind /sys /state/merged/sys 2>/dev/null || true
    mount --bind /dev /state/merged/dev 2>/dev/null || true

    # pivot_root requires the new root to be a mount point distinct from the
    # current root, so bind-mount /state/merged onto itself.
    mount --bind /state/merged /state/merged
    mkdir -p /state/merged/.old_root
    cd /state/merged
    pivot_root . .old_root
    cd /
    umount -l /.old_root 2>/dev/null || true
    rmdir /.old_root 2>/dev/null || true

    # Translate OCI metadata env into the supervisor's container-mode contract.
    local env_count="${OPENSHELL_OCI_ENV_COUNT:-0}"
    export OPENSHELL_CONTAINER_ENV_COUNT="$env_count"
    local idx=0
    while [ "$idx" -lt "$env_count" ]; do
        local src_var="OPENSHELL_OCI_ENV_$idx"
        export "OPENSHELL_CONTAINER_ENV_$idx=${!src_var:-}"
        unset "$src_var"
        idx=$((idx + 1))
    done
    export OPENSHELL_CONTAINER_MODE=1

    local argc="${OPENSHELL_OCI_ARGC:-0}"
    if [ "$argc" -lt 1 ]; then
        ts "ERROR: OCI image has no runnable command (argc=0)"
        exit 1
    fi
    local -a argv=()
    idx=0
    while [ "$idx" -lt "$argc" ]; do
        local src_var="OPENSHELL_OCI_ARGV_$idx"
        argv+=("${!src_var:-}")
        unset "$src_var"
        idx=$((idx + 1))
    done

    local workdir="${OPENSHELL_OCI_WORKDIR:-/sandbox}"
    unset OPENSHELL_OCI_ARGC OPENSHELL_OCI_ENV_COUNT OPENSHELL_OCI_WORKDIR

    ts "OCI overlay ready; exec'ing supervisor (argc=$argc workdir=$workdir)"
    exec /opt/openshell/bin/openshell-sandbox --workdir "$workdir" -- "${argv[@]}"
}

rewrite_openshell_endpoint_if_needed() {
    local endpoint="${OPENSHELL_ENDPOINT:-}"
    [ -n "$endpoint" ] || return 0

    local parsed
    if ! parsed="$(parse_endpoint "$endpoint")"; then
        ts "WARNING: could not parse OPENSHELL_ENDPOINT=$endpoint"
        return 0
    fi

    local scheme host port path
    scheme="$(printf '%s\n' "$parsed" | sed -n '1p')"
    host="$(printf '%s\n' "$parsed" | sed -n '2p')"
    port="$(printf '%s\n' "$parsed" | sed -n '3p')"
    path="$(printf '%s\n' "$parsed" | sed -n '4p')"

    if tcp_probe "$host" "$port"; then
        return 0
    fi

    for candidate in host.containers.internal host.docker.internal 192.168.127.1; do
        if [ "$candidate" = "$host" ]; then
            continue
        fi
        if tcp_probe "$candidate" "$port"; then
            local authority="$candidate"
            if ! { [ "$scheme" = "http" ] && [ "$port" = "80" ]; } \
                && ! { [ "$scheme" = "https" ] && [ "$port" = "443" ]; }; then
                authority="${authority}:${port}"
            fi
            export OPENSHELL_ENDPOINT="${scheme}://${authority}${path}"
            ts "rewrote OPENSHELL_ENDPOINT to ${OPENSHELL_ENDPOINT}"
            return 0
        fi
    done

    ts "WARNING: could not reach OpenShell endpoint ${host}:${port}"
}

mount -t proc proc /proc 2>/dev/null &
mount -t sysfs sysfs /sys 2>/dev/null &
mount -t tmpfs tmpfs /tmp 2>/dev/null &
mount -t tmpfs tmpfs /run 2>/dev/null &
mount -t devtmpfs devtmpfs /dev 2>/dev/null &
wait

mkdir -p /dev/pts /dev/shm /sys/fs/cgroup /sandbox
mount -t devpts devpts /dev/pts 2>/dev/null &
mount -t tmpfs tmpfs /dev/shm 2>/dev/null &
mount -t cgroup2 cgroup2 /sys/fs/cgroup 2>/dev/null &
wait

mount -t tmpfs tmpfs /sandbox 2>/dev/null || true
mkdir -p /sandbox
chown sandbox:sandbox /sandbox 2>/dev/null || true

hostname openshell-sandbox-vm 2>/dev/null || true
ip link set lo up 2>/dev/null || true

if ip link show eth0 >/dev/null 2>&1; then
    ts "detected eth0 (gvproxy networking)"
    ip link set eth0 up 2>/dev/null || true

    if command -v udhcpc >/dev/null 2>&1; then
        UDHCPC_SCRIPT="/usr/share/udhcpc/default.script"
        if [ ! -f "$UDHCPC_SCRIPT" ]; then
            mkdir -p /usr/share/udhcpc
            cat > "$UDHCPC_SCRIPT" <<'DHCP_SCRIPT'
#!/bin/sh
case "$1" in
    bound|renew)
        ip addr flush dev "$interface"
        ip addr add "$ip/$mask" dev "$interface"
        if [ -n "$router" ]; then
            ip route add default via "$router" dev "$interface"
        fi
        if [ -n "$dns" ]; then
            : > /etc/resolv.conf
            for d in $dns; do
                echo "nameserver $d" >> /etc/resolv.conf
            done
        fi
        ;;
esac
DHCP_SCRIPT
            chmod +x "$UDHCPC_SCRIPT"
        fi

        if ! udhcpc -i eth0 -f -q -n -T 1 -t 3 -A 1 -s "$UDHCPC_SCRIPT" 2>&1; then
            ts "WARNING: DHCP failed, falling back to static config"
            ip addr add 192.168.127.2/24 dev eth0 2>/dev/null || true
            ip route add default via 192.168.127.1 2>/dev/null || true
        fi
    else
        ts "no DHCP client, using static config"
        ip addr add 192.168.127.2/24 dev eth0 2>/dev/null || true
        ip route add default via 192.168.127.1 2>/dev/null || true
    fi

    if [ ! -s /etc/resolv.conf ]; then
        echo "nameserver 8.8.8.8" > /etc/resolv.conf
        echo "nameserver 8.8.4.4" >> /etc/resolv.conf
    fi
else
    ts "WARNING: eth0 not found; supervisor will start without guest egress"
fi

export HOME=/sandbox
export USER=sandbox

rewrite_openshell_endpoint_if_needed

# OCI image mode: if the driver staged an OCI payload via krun set_exec env,
# prepare the overlay rootfs, pivot_root, and exec the supervisor post-pivot.
# Otherwise fall through to the default guest rootfs supervisor boot.
if [ -n "${OPENSHELL_OCI_ARGC:-}" ]; then
    ts "OCI image mode: OPENSHELL_OCI_ARGC=${OPENSHELL_OCI_ARGC}"
    oci_launch_supervisor
fi

ts "starting openshell-sandbox supervisor"
exec /opt/openshell/bin/openshell-sandbox --workdir /sandbox
