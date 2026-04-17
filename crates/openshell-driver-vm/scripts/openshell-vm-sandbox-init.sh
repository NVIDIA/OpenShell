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

ts "starting openshell-sandbox supervisor"
exec /opt/openshell/bin/openshell-sandbox --workdir /sandbox
