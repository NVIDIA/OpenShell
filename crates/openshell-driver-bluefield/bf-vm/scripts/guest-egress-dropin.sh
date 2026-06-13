#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# OpenShell BlueField VF egress setup.
set -eu

find_bluefield_vf() {
    local candidate vendor

    for path in /sys/class/net/*; do
        [ -e "${path}" ] || continue
        candidate="${path##*/}"
        case "${candidate}" in
            lo|dummy*|veth*|br-*|docker*|cni*|flannel*|eth0)
                continue
                ;;
        esac
        if [ -r "${path}/device/vendor" ]; then
            vendor="$(cat "${path}/device/vendor" 2>/dev/null || true)"
            if [ "${vendor}" = "0x15b3" ]; then
                printf '%s\n' "${candidate}"
                return 0
            fi
        fi
    done

    for path in /sys/class/net/*; do
        [ -e "${path}" ] || continue
        candidate="${path##*/}"
        case "${candidate}" in
            lo|dummy*|veth*|br-*|docker*|cni*|flannel*|eth0)
                continue
                ;;
        esac
        if [ -e "${path}/device" ]; then
            printf '%s\n' "${candidate}"
            return 0
        fi
    done

    return 1
}

wait_for_bluefield_vf() {
    local vf_nic

    vf_nic=""
    for _ in 1 2 3 4 5; do
        if vf_nic="$(find_bluefield_vf)"; then
            printf '%s\n' "${vf_nic}"
            return 0
        fi
        sleep 1
    done

    echo "openshell: bluefield VF egress drop-in could not locate VF NIC" >&2
    return 1
}

set_optional_mac() {
    local vf_nic="$1"

    if [ -n "${OPENSHELL_VM_DATA_MAC:-}" ]; then
        ip link set "${vf_nic}" down 2>/dev/null || true
        ip link set dev "${vf_nic}" address "${OPENSHELL_VM_DATA_MAC}"
    fi
}

remove_inherited_default_routes() {
    while ip route show default 2>/dev/null | grep -q '^default '; do
        ip route del default
    done
}

verify_vf_default_route() {
    local vf_nic="$1"
    local route

    route="$(ip route get "${OPENSHELL_VM_DATA_GW}" 2>/dev/null || true)"
    case "${route}" in
        *" dev ${vf_nic} "*|*" dev ${vf_nic}")
            return 0
            ;;
    esac

    echo "openshell: bluefield VF egress route check failed: gateway ${OPENSHELL_VM_DATA_GW} route was ${route}" >&2
    return 1
}

configure_static_ip() {
    local vf_nic="$1"

    ip link set "${vf_nic}" up
    ip addr flush dev "${vf_nic}" 2>/dev/null || true
    ip addr add "${OPENSHELL_VM_DATA_IP}" dev "${vf_nic}"
    remove_inherited_default_routes
    ip route replace default via "${OPENSHELL_VM_DATA_GW}" dev "${vf_nic}"
    verify_vf_default_route "${vf_nic}"
}

configure_resolv_conf() {
    local resolv_conf

    resolv_conf="${ROOT_PREFIX:-}/etc/resolv.conf"
    mkdir -p "$(dirname "${resolv_conf}")" 2>/dev/null || true
    {
        echo '# OpenShell BlueField external-VF mode leaves DNS to the sandbox image or DPU-side policy.'
        echo 'options timeout:1 attempts:1'
    } > "${resolv_conf}"
}

main() {
    local vf_nic

    : "${OPENSHELL_VM_DATA_EGRESS:=}"
    [ "${OPENSHELL_VM_DATA_EGRESS}" = "external-vf" ] || exit 0

    : "${OPENSHELL_VM_DATA_IP:?OPENSHELL_VM_DATA_IP is required for BlueField VF egress}"
    : "${OPENSHELL_VM_DATA_GW:?OPENSHELL_VM_DATA_GW is required for BlueField VF egress}"

    vf_nic="$(wait_for_bluefield_vf)"
    set_optional_mac "${vf_nic}"
    configure_static_ip "${vf_nic}"
    configure_resolv_conf

    echo "openshell: bluefield VF egress configured nic=${vf_nic} ip=${OPENSHELL_VM_DATA_IP} gw=${OPENSHELL_VM_DATA_GW}"
}

main "$@"
