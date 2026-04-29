#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Minimal init for sandbox VMs. Runs as PID 1 inside the guest, mounts the
# essential filesystems, configures networking (gvproxy DHCP or TAP static),
# optionally loads NVIDIA GPU drivers, then execs the OpenShell sandbox
# supervisor.

set -euo pipefail

# Source QEMU-injected environment variables if present
if [ -f /srv/openshell-env.sh ]; then
    source /srv/openshell-env.sh
fi

BOOT_START=$(date +%s%3N 2>/dev/null || date +%s)
GVPROXY_GATEWAY_IP="192.168.127.1"
GATEWAY_IP="$GVPROXY_GATEWAY_IP"

# Parse kernel cmdline for GPU and TAP networking parameters
GPU_ENABLED="${GPU_ENABLED:-false}"
VM_NET_IP="${VM_NET_IP:-}"
VM_NET_GW="${VM_NET_GW:-}"
VM_NET_DNS="${VM_NET_DNS:-}"

for param in $(cat /proc/cmdline 2>/dev/null || true); do
    case "$param" in
        GPU_ENABLED=*)  GPU_ENABLED="${param#GPU_ENABLED=}" ;;
        VM_NET_IP=*)    VM_NET_IP="${param#VM_NET_IP=}" ;;
        VM_NET_GW=*)    VM_NET_GW="${param#VM_NET_GW=}" ;;
        VM_NET_DNS=*)   VM_NET_DNS="${param#VM_NET_DNS=}" ;;
    esac
done

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

ensure_host_gateway_aliases() {
    local hosts_tmp="/tmp/openshell-hosts.$$"

    if [ -f /etc/hosts ]; then
        grep -vE '(^|[[:space:]])host\.openshell\.internal([[:space:]]|$)' /etc/hosts > "$hosts_tmp" || true
    else
        : > "$hosts_tmp"
    fi

    printf '%s host.openshell.internal\n' "$GATEWAY_IP" >> "$hosts_tmp"
    cat "$hosts_tmp" > /etc/hosts
    rm -f "$hosts_tmp"
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

    for candidate in host.openshell.internal host.containers.internal host.docker.internal "$GATEWAY_IP"; do
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

create_gpu_device_nodes_mknod() {
    # Mode 666 is intentional: single-tenant microVM with the VM itself as the
    # isolation boundary. The sandbox user is the only non-root user.
    local nv_major
    nv_major=$(awk '$2 == "nvidia" {print $1}' /proc/devices 2>/dev/null || true)
    if [ -n "$nv_major" ]; then
        mknod -m 666 /dev/nvidiactl c "$nv_major" 255 2>/dev/null || true

        local gpu_count=0
        if [ -d /proc/driver/nvidia/gpus ]; then
            for gpu_dir in /proc/driver/nvidia/gpus/*/; do
                [ -d "$gpu_dir" ] || continue
                mknod -m 666 "/dev/nvidia${gpu_count}" c "$nv_major" "$gpu_count" 2>/dev/null || true
                gpu_count=$((gpu_count + 1))
            done
        fi
        if [ "$gpu_count" -eq 0 ]; then
            mknod -m 666 /dev/nvidia0 c "$nv_major" 0 2>/dev/null || true
        fi

        local modeset_major
        modeset_major=$(awk '$2 == "nvidia-modeset" {print $1}' /proc/devices 2>/dev/null || true)
        if [ -n "$modeset_major" ]; then
            mknod -m 666 /dev/nvidia-modeset c "$modeset_major" 254 2>/dev/null || true
        fi

        local uvm_major
        uvm_major=$(awk '$2 == "nvidia-uvm" {print $1}' /proc/devices 2>/dev/null || true)
        if [ -n "$uvm_major" ]; then
            mknod -m 666 /dev/nvidia-uvm c "$uvm_major" 0 2>/dev/null || true
            mknod -m 666 /dev/nvidia-uvm-tools c "$uvm_major" 1 2>/dev/null || true
        fi

        local caps_major
        caps_major=$(awk '$2 == "nvidia-caps" {print $1}' /proc/devices 2>/dev/null || true)
        if [ -n "$caps_major" ]; then
            mkdir -p /dev/nvidia-caps 2>/dev/null || true
            mknod -m 666 /dev/nvidia-caps/nvidia-cap1 c "$caps_major" 1 2>/dev/null || true
            mknod -m 666 /dev/nvidia-caps/nvidia-cap2 c "$caps_major" 2 2>/dev/null || true
        fi

        ts "GPU device nodes created via mknod (${gpu_count} GPU(s), major=${nv_major})"
    else
        ts "WARNING: 'nvidia' not in /proc/devices; device nodes unavailable"
    fi
}

setup_gpu() {
    ts "GPU_ENABLED=true — initializing GPU passthrough"

    if ! command -v modprobe >/dev/null 2>&1; then
        ts "FATAL: modprobe not found; cannot load nvidia kernel modules"
        return 1
    fi

    # Stage GSP firmware from virtiofs to tmpfs to avoid slow FUSE reads
    if [ -d /lib/firmware/nvidia ]; then
        ts "staging GPU firmware to tmpfs"
        mkdir -p /run/firmware/nvidia
        cp -a /lib/firmware/nvidia/* /run/firmware/nvidia/ 2>/dev/null || true
        if [ -e /sys/module/firmware_class/parameters/path ]; then
            echo /run/firmware > /sys/module/firmware_class/parameters/path
        fi
    fi

    ts "loading nvidia kernel modules"
    modprobe nvidia || { ts "FATAL: modprobe nvidia failed"; return 1; }
    modprobe nvidia_uvm 2>/dev/null || true
    modprobe nvidia_modeset 2>/dev/null || true

    rm -rf /run/firmware 2>/dev/null || true

    if command -v nvidia-smi >/dev/null 2>&1; then
        ts "running nvidia-smi to create device nodes and validate GPU"
        local smi_rc=0
        nvidia-smi >/dev/null 2>&1 || smi_rc=$?
        if [ "$smi_rc" -eq 0 ]; then
            nvidia-smi -L 2>/dev/null | while read -r line; do ts "  $line"; done
            ts "GPU initialization successful"
        else
            ts "WARNING: nvidia-smi failed (exit ${smi_rc}); falling back to mknod"
            create_gpu_device_nodes_mknod
        fi
    else
        ts "nvidia-smi not found; creating device nodes via mknod"
        create_gpu_device_nodes_mknod
    fi
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

# GPU initialization (before networking so nvidia-smi output is visible early)
if [ "${GPU_ENABLED}" = "true" ]; then
    setup_gpu || ts "WARNING: GPU init failed; continuing without GPU"
fi

# Networking: use TAP static config if VM_NET_IP is set (QEMU path),
# otherwise fall back to gvproxy DHCP on eth0 (libkrun path).
if [ -n "${VM_NET_IP}" ] && [ -n "${VM_NET_GW}" ]; then
    ts "configuring TAP networking (static ${VM_NET_IP} gw ${VM_NET_GW})"
    GATEWAY_IP="${VM_NET_GW}"

    TAP_NIC=""
    NIC_WAIT=0
    while [ -z "$TAP_NIC" ] && [ "$NIC_WAIT" -lt 10 ]; do
        for candidate in eth0 ens3 enp0s2 $(ls /sys/class/net/ 2>/dev/null | grep -v '^lo$'); do
            if ip link show "$candidate" >/dev/null 2>&1 && [ "$candidate" != "lo" ]; then
                TAP_NIC="$candidate"
                break
            fi
        done
        if [ -z "$TAP_NIC" ]; then
            sleep 1
            NIC_WAIT=$((NIC_WAIT + 1))
        fi
    done

    if [ -n "$TAP_NIC" ]; then
        ts "using NIC ${TAP_NIC} for TAP networking"
        ip link set "$TAP_NIC" up 2>/dev/null || true
        ip addr add "${VM_NET_IP}/30" dev "$TAP_NIC" 2>/dev/null || true
        ip route add default via "${VM_NET_GW}" 2>/dev/null || true
    else
        ts "WARNING: no network interface found for TAP networking"
    fi

    if [ -n "${VM_NET_DNS}" ]; then
        echo "nameserver ${VM_NET_DNS}" > /etc/resolv.conf
    elif [ ! -s /etc/resolv.conf ]; then
        echo "nameserver 8.8.8.8" > /etc/resolv.conf
        echo "nameserver 8.8.4.4" >> /etc/resolv.conf
    fi

    ensure_host_gateway_aliases
elif ip link show eth0 >/dev/null 2>&1; then
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
            ip route add default via "$GVPROXY_GATEWAY_IP" 2>/dev/null || true
        fi
    else
        ts "no DHCP client, using static config"
        ip addr add 192.168.127.2/24 dev eth0 2>/dev/null || true
        ip route add default via "$GVPROXY_GATEWAY_IP" 2>/dev/null || true
    fi

    if [ ! -s /etc/resolv.conf ]; then
        echo "nameserver 8.8.8.8" > /etc/resolv.conf
        echo "nameserver 8.8.4.4" >> /etc/resolv.conf
    fi

    ensure_host_gateway_aliases
else
    ts "WARNING: no network interface found; supervisor will start without guest egress"
fi

export HOME=/sandbox
export USER=sandbox

rewrite_openshell_endpoint_if_needed

# Log supervisor connectivity state for debugging stuck-in-Provisioning issues
if [ -n "${OPENSHELL_ENDPOINT:-}" ]; then
    _ep_parsed="$(parse_endpoint "$OPENSHELL_ENDPOINT" 2>/dev/null || true)"
    if [ -n "$_ep_parsed" ]; then
        _ep_host="$(printf '%s\n' "$_ep_parsed" | sed -n '2p')"
        _ep_port="$(printf '%s\n' "$_ep_parsed" | sed -n '3p')"
        if tcp_probe "$_ep_host" "$_ep_port"; then
            ts "gateway reachable at ${_ep_host}:${_ep_port}"
        else
            ts "WARNING: gateway NOT reachable at ${_ep_host}:${_ep_port} — supervisor may fail to connect"
        fi
    fi
    ts "OPENSHELL_ENDPOINT=${OPENSHELL_ENDPOINT}"
fi
if [ -n "${OPENSHELL_SANDBOX_ID:-}" ]; then
    ts "OPENSHELL_SANDBOX_ID=${OPENSHELL_SANDBOX_ID}"
fi

ts "starting openshell-sandbox supervisor"
exec /opt/openshell/bin/openshell-sandbox --workdir /sandbox
