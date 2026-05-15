#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu

usage() {
    echo "Usage: init-gateway-config.sh <deb|homebrew|rpm|snap> <config-file> [package args...]" >&2
    exit 2
}

profile="${1:-}"
CONFIG_FILE="${2:-}"
if [ -z "$profile" ] || [ -z "$CONFIG_FILE" ]; then
    usage
fi

if [ -f "$CONFIG_FILE" ]; then
    exit 0
fi

toml_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

toml_string() {
    printf '"%s"' "$(toml_escape "$1")"
}

emit_string_field() {
    key="$1"
    value="$2"
    if [ -n "$value" ]; then
        printf '%s = %s\n' "$key" "$(toml_string "$value")"
    fi
}

write_desktop_config() {
    pki_dir="${1:-}"
    driver_dir="${2:-}"
    vm_state_dir="${3:-}"
    docker_supervisor_image="${4:-}"
    docker_tls_dir="${5:-}"
    if [ -z "$pki_dir" ] || [ -z "$driver_dir" ] || [ -z "$vm_state_dir" ]; then
        usage
    fi

    mkdir -p "$(dirname "$CONFIG_FILE")" "$vm_state_dir"

    tmp="${CONFIG_FILE}.tmp"
    {
        cat <<EOF
[openshell]
version = 1

[openshell.gateway]
bind_address = "127.0.0.1:17670"
# Leave unset to auto-detect the compute driver.
# compute_drivers = ["vm"]
default_image = "ghcr.io/nvidia/openshell-community/sandboxes/base:latest"
supervisor_image = "ghcr.io/nvidia/openshell/supervisor:latest"
guest_tls_ca = $(toml_string "${pki_dir}/ca.crt")
guest_tls_cert = $(toml_string "${pki_dir}/client/tls.crt")
guest_tls_key = $(toml_string "${pki_dir}/client/tls.key")

[openshell.gateway.tls]
cert_path = $(toml_string "${pki_dir}/server/tls.crt")
key_path = $(toml_string "${pki_dir}/server/tls.key")
client_ca_path = $(toml_string "${pki_dir}/ca.crt")

[openshell.drivers.vm]
state_dir = $(toml_string "$vm_state_dir")
driver_dir = $(toml_string "$driver_dir")
grpc_endpoint = "https://127.0.0.1:17670"

[openshell.drivers.docker]
grpc_endpoint = "https://127.0.0.1:17670"
EOF

        emit_string_field supervisor_image "$docker_supervisor_image"
        if [ -n "$docker_tls_dir" ]; then
            emit_string_field guest_tls_ca "${docker_tls_dir}/ca.crt"
            emit_string_field guest_tls_cert "${docker_tls_dir}/client/tls.crt"
            emit_string_field guest_tls_key "${docker_tls_dir}/client/tls.key"
        fi
    } > "$tmp"

    chmod 600 "$tmp"
    mv "$tmp" "$CONFIG_FILE"
}

write_snap_config() {
    supervisor_bin="${1:-}"
    if [ -z "$supervisor_bin" ]; then
        usage
    fi

    mkdir -p "$(dirname "$CONFIG_FILE")"

    tmp="${CONFIG_FILE}.tmp"
    {
        cat <<EOF
[openshell]
version = 1

[openshell.gateway]
bind_address = "127.0.0.1:17670"
disable_tls = true
# Leave unset to auto-detect the compute driver.
# compute_drivers = ["docker"]
default_image = "ghcr.io/nvidia/openshell-community/sandboxes/base:latest"

[openshell.drivers.docker]
image_pull_policy = "IfNotPresent"
sandbox_namespace = "docker-snap"
grpc_endpoint = "http://host.openshell.internal:17670"
supervisor_bin = $(toml_string "$supervisor_bin")
network_name = "openshell-snap"
EOF
    } > "$tmp"

    chmod 600 "$tmp"
    mv "$tmp" "$CONFIG_FILE"
}

write_rpm_config() {
    pki_dir="${1:-}"
    supervisor_image="${2:-}"
    if [ -z "$pki_dir" ] || [ -z "$supervisor_image" ]; then
        usage
    fi

    mkdir -p "$(dirname "$CONFIG_FILE")"

    tmp="${CONFIG_FILE}.tmp"
    {
        cat <<EOF
[openshell]
version = 1

[openshell.gateway]
bind_address = "127.0.0.1:17670"
# Leave unset to auto-detect the compute driver.
# compute_drivers = ["podman"]
default_image = "ghcr.io/nvidia/openshell-community/sandboxes/base:latest"
supervisor_image = $(toml_string "$supervisor_image")
guest_tls_ca = $(toml_string "${pki_dir}/ca.crt")
guest_tls_cert = $(toml_string "${pki_dir}/client/tls.crt")
guest_tls_key = $(toml_string "${pki_dir}/client/tls.key")

[openshell.gateway.tls]
cert_path = $(toml_string "${pki_dir}/server/tls.crt")
key_path = $(toml_string "${pki_dir}/server/tls.key")
client_ca_path = $(toml_string "${pki_dir}/ca.crt")

[openshell.drivers.podman]
image_pull_policy = "missing"
network_name = "openshell"
stop_timeout_secs = 10
EOF
    } > "$tmp"

    chmod 600 "$tmp"
    mv "$tmp" "$CONFIG_FILE"
}

case "$profile" in
    deb)
        write_desktop_config "${3:-}" "${4:-}" "${5:-}" "" ""
        ;;
    homebrew)
        write_desktop_config "${3:-}" "${4:-}" "${5:-}" "${6:-}" "${7:-}"
        ;;
    rpm)
        write_rpm_config "${3:-}" "${4:-}"
        ;;
    snap)
        write_snap_config "${3:-}"
        ;;
    *)
        usage
        ;;
esac
