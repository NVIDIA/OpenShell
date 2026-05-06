#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# VM Kernel Capability Checker
#
# Runs inside the guest VM (or a container with the same rootfs) to
# verify that the kernel has the capabilities required for bridge CNI
# networking, kube-proxy, and Kubernetes pod networking.
#
# Usage:
#   ./check-vm-capabilities.sh [--json]
#
# Exit codes:
#   0 = all required capabilities present
#   1 = one or more required capabilities missing
#   2 = script error

set -euo pipefail

JSON_OUTPUT=false
if [ "${1:-}" = "--json" ]; then
    JSON_OUTPUT=true
fi

PASS=0
FAIL=0
WARN=0
RESULTS=()

# ── Helpers ─────────────────────────────────────────────────────────────

check() {
    local name="$1"
    local category="$2"
    local required="$3"  # "required" or "optional"
    local description="$4"
    shift 4
    local cmd=("$@")

    if eval "${cmd[@]}" >/dev/null 2>&1; then
        RESULTS+=("{\"name\":\"$name\",\"category\":\"$category\",\"status\":\"pass\",\"required\":\"$required\",\"description\":\"$description\"}")
        PASS=$((PASS + 1))
        if [ "$JSON_OUTPUT" = false ]; then
            printf "  ✓ %-40s %s\n" "$name" "$description"
        fi
    else
        if [ "$required" = "required" ]; then
            RESULTS+=("{\"name\":\"$name\",\"category\":\"$category\",\"status\":\"fail\",\"required\":\"$required\",\"description\":\"$description\"}")
            FAIL=$((FAIL + 1))
            if [ "$JSON_OUTPUT" = false ]; then
                printf "  ✗ %-40s %s (REQUIRED)\n" "$name" "$description"
            fi
        else
            RESULTS+=("{\"name\":\"$name\",\"category\":\"$category\",\"status\":\"warn\",\"required\":\"$required\",\"description\":\"$description\"}")
            WARN=$((WARN + 1))
            if [ "$JSON_OUTPUT" = false ]; then
                printf "  ~ %-40s %s (optional)\n" "$name" "$description"
            fi
        fi
    fi
}

check_module() {
    local module="$1"
    # Check /proc/modules (loaded), /proc/config.gz (builtin), or /sys/module
    if [ -d "/sys/module/$module" ]; then
        return 0
    fi
    if grep -q "^${module} " /proc/modules 2>/dev/null; then
        return 0
    fi
    # Check if compiled in via /proc/config.gz or /boot/config
    local config_key
    config_key="CONFIG_$(echo "$module" | tr '[:lower:]-' '[:upper:]_')"
    if [ -f /proc/config.gz ]; then
        if zcat /proc/config.gz 2>/dev/null | grep -q "^${config_key}=[ym]"; then
            return 0
        fi
    fi
    return 1
}

# ── Capability Checks ──────────────────────────────────────────────────

if [ "$JSON_OUTPUT" = false ]; then
    echo "VM Kernel Capability Check"
    echo "=========================="
    echo ""
    echo "Kernel: $(uname -r)"
    echo ""
fi

# --- Network Namespaces ---
if [ "$JSON_OUTPUT" = false ]; then echo "[Network Namespaces]"; fi

check "net_namespace" "netns" "required" \
    "network namespace support (CONFIG_NET_NS)" \
    "test -d /proc/self/ns && ls /proc/self/ns/net"

check "veth_pair" "netns" "required" \
    "veth pair creation (CONFIG_VETH)" \
    "ip link add _chk0 type veth peer name _chk1 && ip link del _chk0"

# --- Linux Bridge ---
if [ "$JSON_OUTPUT" = false ]; then echo ""; echo "[Linux Bridge]"; fi

check "bridge_module" "bridge" "required" \
    "bridge device support (CONFIG_BRIDGE)" \
    "ip link add _chkbr0 type bridge && ip link del _chkbr0"

check "bridge_nf_call" "bridge" "required" \
    "bridge netfilter (CONFIG_BRIDGE_NETFILTER)" \
    "check_module bridge && test -f /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null || check_module br_netfilter"

# --- Netfilter / iptables ---
if [ "$JSON_OUTPUT" = false ]; then echo ""; echo "[Netfilter / iptables]"; fi

check "netfilter" "netfilter" "required" \
    "netfilter framework (CONFIG_NETFILTER)" \
    "check_module nf_conntrack || check_module ip_tables || test -d /proc/sys/net/netfilter"

check "nf_conntrack" "netfilter" "required" \
    "connection tracking (CONFIG_NF_CONNTRACK)" \
    "check_module nf_conntrack"

check "nf_nat" "netfilter" "required" \
    "NAT support (CONFIG_NF_NAT)" \
    "check_module nf_nat"

check "iptables_filter" "netfilter" "required" \
    "iptables filter (CONFIG_IP_NF_FILTER)" \
    "check_module ip_tables || iptables -L -n >/dev/null 2>&1"

check "iptables_nat" "netfilter" "required" \
    "iptables NAT (CONFIG_IP_NF_NAT)" \
    "check_module iptable_nat || iptables -t nat -L -n >/dev/null 2>&1"

check "iptables_mangle" "netfilter" "optional" \
    "iptables mangle (CONFIG_IP_NF_MANGLE)" \
    "check_module iptable_mangle || iptables -t mangle -L -n >/dev/null 2>&1"

check "nf_conntrack_netlink" "netfilter" "optional" \
    "conntrack netlink (CONFIG_NF_CT_NETLINK)" \
    "check_module nf_conntrack_netlink"

check "nftables" "netfilter" "optional" \
    "nftables (CONFIG_NF_TABLES)" \
    "check_module nf_tables || nft list ruleset >/dev/null 2>&1"

# --- IP Forwarding / Routing ---
if [ "$JSON_OUTPUT" = false ]; then echo ""; echo "[IP Forwarding]"; fi

check "ip_forward" "routing" "required" \
    "IP forwarding (sysctl)" \
    "test -f /proc/sys/net/ipv4/ip_forward"

check "ip_route" "routing" "required" \
    "IP routing" \
    "ip route show >/dev/null 2>&1"

# --- CNI Plugin Dependencies ---
if [ "$JSON_OUTPUT" = false ]; then echo ""; echo "[CNI Plugins]"; fi

check "cni_bridge_bin" "cni" "required" \
    "bridge CNI plugin binary" \
    "test -x /opt/cni/bin/bridge || find /var/lib/rancher/k3s/data -name bridge -type f 2>/dev/null | head -1 | grep -q ."

check "cni_host_local_bin" "cni" "required" \
    "host-local IPAM plugin binary" \
    "test -x /opt/cni/bin/host-local || find /var/lib/rancher/k3s/data -name host-local -type f 2>/dev/null | head -1 | grep -q ."

check "cni_loopback_bin" "cni" "required" \
    "loopback CNI plugin binary" \
    "test -x /opt/cni/bin/loopback || find /var/lib/rancher/k3s/data -name loopback -type f 2>/dev/null | head -1 | grep -q ."

check "cni_portmap_bin" "cni" "optional" \
    "portmap CNI plugin binary (needs iptables)" \
    "test -x /opt/cni/bin/portmap || find /var/lib/rancher/k3s/data -name portmap -type f 2>/dev/null | head -1 | grep -q ."

# --- Userspace Tools ---
if [ "$JSON_OUTPUT" = false ]; then echo ""; echo "[Userspace Tools]"; fi

check "iptables_bin" "userspace" "required" \
    "iptables binary" \
    "command -v iptables"

check "conntrack_bin" "userspace" "optional" \
    "conntrack binary" \
    "command -v conntrack"

check "ip_bin" "userspace" "required" \
    "iproute2 (ip command)" \
    "command -v ip"

# ── Summary ────────────────────────────────────────────────────────────

if [ "$JSON_OUTPUT" = true ]; then
    echo "{"
    echo "  \"kernel\": \"$(uname -r)\","
    echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo "  \"pass\": $PASS,"
    echo "  \"fail\": $FAIL,"
    echo "  \"warn\": $WARN,"
    echo "  \"results\": ["
    local_first=true
    for r in "${RESULTS[@]}"; do
        if [ "$local_first" = true ]; then
            local_first=false
        else
            echo ","
        fi
        printf "    %s" "$r"
    done
    echo ""
    echo "  ]"
    echo "}"
else
    echo ""
    echo "─────────────────────────────────────────"
    printf "Results: %d passed, %d failed, %d warnings\n" "$PASS" "$FAIL" "$WARN"

    if [ "$FAIL" -gt 0 ]; then
        echo ""
        echo "FAIL: $FAIL required capabilities missing."
        echo "The VM kernel needs to be rebuilt with the missing features."
        echo "See: crates/openshell-driver-vm/runtime/README.md"
        exit 1
    else
        echo ""
        echo "PASS: All required capabilities present."
        exit 0
    fi
fi
