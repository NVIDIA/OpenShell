#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Under sudo, PATH is reset and user-local tools (mise, cargo) disappear.
# Restore the invoking user's tool directories so mise and its shims work.
if [ -n "${SUDO_USER:-}" ]; then
    _sudo_home=$(getent passwd "${SUDO_USER}" | cut -d: -f6)
    for _p in "${_sudo_home}/.local/bin" "${_sudo_home}/.local/share/mise/shims" "${_sudo_home}/.cargo/bin"; do
        [ -d "${_p}" ] && PATH="${_p}:${PATH}"
    done
    export PATH
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${ROOT}/crates/openshell-vm/pins.env" 2>/dev/null || true
CLI_BIN="${ROOT}/scripts/bin/openshell"
ENV_FILE="${ROOT}/.env"
COMPRESSED_DIR_DEFAULT="${ROOT}/target/vm-runtime-compressed"
COMPRESSED_DIR="${OPENSHELL_VM_RUNTIME_COMPRESSED_DIR:-${COMPRESSED_DIR_DEFAULT}}"
SERVER_PORT_REQUESTED="${OPENSHELL_SERVER_PORT:-${GATEWAY_PORT:-}}"
SERVER_PORT="${SERVER_PORT_REQUESTED:-}"
STATE_DIR_ROOT="${OPENSHELL_VM_DRIVER_STATE_ROOT:-/tmp}"
VM_HOST_GATEWAY_DEFAULT="${OPENSHELL_VM_HOST_GATEWAY:-host.containers.internal}"
DRIVER_DIR_DEFAULT="${ROOT}/target/debug"
DRIVER_DIR="${OPENSHELL_DRIVER_DIR:-${DRIVER_DIR_DEFAULT}}"

normalize_name() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/--*/-/g' | sed 's/^-//;s/-$//'
}

for arg in "$@"; do
    if [ "${arg}" = "--gpu" ]; then
        export OPENSHELL_VM_GPU=true
        break
    fi
done

has_env_key() {
    local key=$1
    [ -f "${ENV_FILE}" ] || return 1
    grep -Eq "^[[:space:]]*(export[[:space:]]+)?${key}=" "${ENV_FILE}"
}

append_env_if_missing() {
    local key=$1
    local value=$2
    if has_env_key "${key}"; then
        return
    fi
    if [ -f "${ENV_FILE}" ] && [ -s "${ENV_FILE}" ]; then
        if [ "$(tail -c1 "${ENV_FILE}" | wc -l)" -eq 0 ]; then
            printf "\n" >>"${ENV_FILE}"
        fi
    fi
    printf "%s=%s\n" "${key}" "${value}" >>"${ENV_FILE}"
}

upsert_env_key() {
    local key=$1
    local value=$2
    local tmp_file

    tmp_file="$(mktemp "${ENV_FILE}.tmp.XXXXXX")"
    if [ -f "${ENV_FILE}" ]; then
        awk -v key="${key}" -v value="${value}" '
            BEGIN { updated = 0 }
            $0 ~ "^[[:space:]]*(export[[:space:]]+)?" key "=" {
                if (!updated) {
                    print key "=" value
                    updated = 1
                }
                next
            }
            { print }
            END {
                if (!updated) {
                    print key "=" value
                }
            }
        ' "${ENV_FILE}" >"${tmp_file}"
    else
        printf "%s=%s\n" "${key}" "${value}" >"${tmp_file}"
    fi
    mv "${tmp_file}" "${ENV_FILE}"
}

normalize_bool() {
    case "${1,,}" in
        1|true|yes|on) echo "true" ;;
        0|false|no|off) echo "false" ;;
        *)
            echo "invalid boolean value '$1' (expected true/false, 1/0, yes/no, on/off)" >&2
            exit 1
            ;;
    esac
}

port_is_in_use() {
    local port=$1
    if command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1
        return $?
    fi

    if command -v nc >/dev/null 2>&1; then
        nc -z 127.0.0.1 "${port}" >/dev/null 2>&1
        return $?
    fi

    (echo >/dev/tcp/127.0.0.1/"${port}") >/dev/null 2>&1
}

pick_random_port() {
    local lower=20000
    local upper=60999
    local attempts=256
    local port

    for _ in $(seq 1 "${attempts}"); do
        port=$((RANDOM % (upper - lower + 1) + lower))
        if ! port_is_in_use "${port}"; then
            echo "${port}"
            return 0
        fi
    done

    echo "ERROR: could not find a free port after ${attempts} attempts." >&2
    return 1
}

check_supervisor_cross_toolchain() {
    # The sandbox supervisor inside the guest is always Linux. On non-Linux
    # hosts (macOS) and on Linux hosts with a different arch than the guest,
    # we cross-compile via cargo-zigbuild and need the matching rustup target.
    local host_os host_arch guest_arch rust_target
    host_os="$(uname -s)"
    host_arch="$(uname -m)"
    guest_arch="${GUEST_ARCH:-${host_arch}}"
    case "${guest_arch}" in
        arm64|aarch64) rust_target="aarch64-unknown-linux-gnu" ;;
        x86_64|amd64)  rust_target="x86_64-unknown-linux-gnu" ;;
        *) return 0 ;;
    esac
    if [ "${host_os}" = "Linux" ] && [ "${host_arch}" = "${guest_arch}" ]; then
        return 0
    fi
    local missing=0
    if ! command -v cargo-zigbuild >/dev/null 2>&1; then
        echo "ERROR: cargo-zigbuild not found (required to cross-compile the guest supervisor)." >&2
        echo "       Install: cargo install --locked cargo-zigbuild && brew install zig" >&2
        missing=1
    fi
    if ! rustup target list --installed 2>/dev/null | grep -qx "${rust_target}"; then
        echo "ERROR: Rust target '${rust_target}' not installed." >&2
        echo "       Install: rustup target add ${rust_target}" >&2
        missing=1
    fi
    if [ "${missing}" -ne 0 ]; then
        exit 1
    fi
}

build_gateway_and_driver() {
    local rustc_wrapper_mode="${1:-default}"
    local cargo_prefix=()

    if [ "${rustc_wrapper_mode}" = "without-rustc-wrapper" ]; then
        cargo_prefix=(env -u RUSTC_WRAPPER)
    fi

    "${cargo_prefix[@]}" cargo build -p openshell-server -p openshell-driver-vm
}

if [ -n "${SERVER_PORT_REQUESTED}" ]; then
    if port_is_in_use "${SERVER_PORT}"; then
        echo "ERROR: requested gateway port ${SERVER_PORT} is already in use." >&2
        echo "       Update .env GATEWAY_PORT or override it for one run:" >&2
        echo "       OPENSHELL_SERVER_PORT=<free-port> mise run gateway:vm" >&2
        exit 1
    fi
else
    SERVER_PORT="$(pick_random_port)"
    append_env_if_missing "GATEWAY_PORT" "${SERVER_PORT}"
fi

GATEWAY_NAME_DEFAULT="$(basename "${ROOT}")"
GATEWAY_NAME="${OPENSHELL_VM_GATEWAY_NAME:-${GATEWAY_NAME_DEFAULT}}"
if [ -z "${GATEWAY_NAME}" ]; then
    GATEWAY_NAME="openshell"
fi

# Keep the driver socket path under AF_UNIX SUN_LEN on macOS.
STATE_LABEL_RAW="${OPENSHELL_VM_INSTANCE:-$(normalize_name "${GATEWAY_NAME}")}"
STATE_LABEL="$(printf '%s' "${STATE_LABEL_RAW}" | tr -cs '[:alnum:]._-' '-')"
if [ -z "${STATE_LABEL}" ]; then
    STATE_LABEL="gateway"
fi
STATE_DIR_DEFAULT="${STATE_DIR_ROOT}/openshell-vm-driver-dev-${USER:-user}-${STATE_LABEL}"
STATE_DIR="${OPENSHELL_VM_DRIVER_STATE_DIR:-${STATE_DIR_DEFAULT}}"
DB_PATH_DEFAULT="${STATE_DIR}/openshell.db"
LOCAL_GATEWAY_ENDPOINT_DEFAULT="http://127.0.0.1:${SERVER_PORT}"
LOCAL_GATEWAY_ENDPOINT="${OPENSHELL_VM_LOCAL_GATEWAY_ENDPOINT:-${LOCAL_GATEWAY_ENDPOINT_DEFAULT}}"

export OPENSHELL_VM_RUNTIME_COMPRESSED_DIR="${COMPRESSED_DIR}"
export OPENSHELL_GATEWAY="${GATEWAY_NAME}"

upsert_env_key "OPENSHELL_GATEWAY" "${GATEWAY_NAME}"

mkdir -p "${STATE_DIR}"

if [ ! -d "${COMPRESSED_DIR}" ] || ! find "${COMPRESSED_DIR}" -maxdepth 1 -name 'libkrun*.zst' | grep -q . || [ ! -f "${COMPRESSED_DIR}/gvproxy.zst" ]; then
    echo "==> Preparing embedded VM runtime"
    mise run vm:setup
fi

if [ ! -f "${COMPRESSED_DIR}/openshell-sandbox.zst" ]; then
    check_supervisor_cross_toolchain
    echo "==> Building bundled VM supervisor"
    mise run vm:supervisor
fi

echo "==> Building gateway and VM compute driver"
if ! build_gateway_and_driver; then
    if [ -n "${RUSTC_WRAPPER:-}" ]; then
        echo "WARNING: gateway/driver build failed through RUSTC_WRAPPER=${RUSTC_WRAPPER}; retrying without RUSTC_WRAPPER." >&2
        build_gateway_and_driver without-rustc-wrapper
    else
        exit 1
    fi
fi

if [ "$(uname -s)" = "Darwin" ]; then
    echo "==> Codesigning VM compute driver"
    codesign \
        --entitlements "${ROOT}/crates/openshell-driver-vm/entitlements.plist" \
        --force \
        -s - \
        "${ROOT}/target/debug/openshell-driver-vm"
fi

export OPENSHELL_DISABLE_TLS="$(normalize_bool "${OPENSHELL_DISABLE_TLS:-true}")"
export OPENSHELL_DB_URL="${OPENSHELL_DB_URL:-sqlite:${DB_PATH_DEFAULT}}"
export OPENSHELL_DRIVERS="${OPENSHELL_DRIVERS:-vm}"
export OPENSHELL_DRIVER_DIR="${DRIVER_DIR}"
export OPENSHELL_SERVER_PORT="${SERVER_PORT}"
export OPENSHELL_GRPC_ENDPOINT="${OPENSHELL_GRPC_ENDPOINT:-http://${VM_HOST_GATEWAY_DEFAULT}:${SERVER_PORT}}"
export OPENSHELL_SANDBOX_IMAGE="${OPENSHELL_SANDBOX_IMAGE:-${COMMUNITY_SANDBOX_IMAGE:-}}"
export OPENSHELL_SSH_GATEWAY_HOST="${OPENSHELL_SSH_GATEWAY_HOST:-127.0.0.1}"
export OPENSHELL_SSH_GATEWAY_PORT="${OPENSHELL_SSH_GATEWAY_PORT:-${SERVER_PORT}}"
export OPENSHELL_SSH_HANDSHAKE_SECRET="${OPENSHELL_SSH_HANDSHAKE_SECRET:-dev-vm-driver-secret}"
export OPENSHELL_VM_DRIVER_STATE_DIR="${STATE_DIR}"

# Resolve the VM runtime directory (contains vmlinux, virtiofsd, etc.)
# so the child --internal-run-vm process can find it under sudo.
if [ -z "${OPENSHELL_VM_RUNTIME_DIR:-}" ]; then
    _candidate="${HOME}/.local/share/openshell/vm-runtime/0.0.0"
    if [ -n "${SUDO_USER:-}" ]; then
        _sudo_home=$(getent passwd "${SUDO_USER}" | cut -d: -f6)
        _candidate="${_sudo_home}/.local/share/openshell/vm-runtime/0.0.0"
    fi
    if [ -f "${_candidate}/vmlinux" ]; then
        export OPENSHELL_VM_RUNTIME_DIR="${_candidate}"
    fi
fi

# Write gateway metadata to the invoking user's config dir, even under sudo.
# When running under sudo, $HOME points at /root and XDG_CONFIG_HOME may also
# be inherited from the root env; fall back to SUDO_USER's home directory so
# repo-local `scripts/bin/openshell` reads the same config.
if [ -n "${SUDO_USER:-}" ]; then
    _sudo_home=$(getent passwd "${SUDO_USER}" | cut -d: -f6)
    GATEWAY_CONFIG_BASE="${_sudo_home}/.config"
else
    GATEWAY_CONFIG_BASE="${XDG_CONFIG_HOME:-${HOME}/.config}"
fi
GATEWAY_METADATA_DIR="${GATEWAY_CONFIG_BASE}/openshell/gateways/${GATEWAY_NAME}"
mkdir -p "${GATEWAY_METADATA_DIR}"
cat >"${GATEWAY_METADATA_DIR}/metadata.json" <<EOF
{
  "name": "${GATEWAY_NAME}",
  "gateway_endpoint": "${LOCAL_GATEWAY_ENDPOINT}",
  "is_remote": false,
  "gateway_port": ${SERVER_PORT},
  "auth_mode": "plaintext"
}
EOF
if [ -n "${SUDO_USER:-}" ]; then
    chown -R "${SUDO_USER}" "${GATEWAY_CONFIG_BASE}/openshell" 2>/dev/null || true
fi

echo "==> Gateway config"
echo "    Name: ${GATEWAY_NAME}"
echo "    Endpoint: ${LOCAL_GATEWAY_ENDPOINT}"
echo "    .env:     OPENSHELL_GATEWAY=${GATEWAY_NAME}"
echo "    .env:     GATEWAY_PORT=${SERVER_PORT}"
echo "    Driver:   ${OPENSHELL_DRIVER_DIR}/openshell-driver-vm"
echo "    Image:    ${OPENSHELL_SANDBOX_IMAGE}"
echo "    Status:   ${CLI_BIN} status"
echo "    Create:   ${CLI_BIN} sandbox create --name vm-test --from ubuntu:24.04"

echo "==> Starting OpenShell server with VM compute driver"
exec "${ROOT}/target/debug/openshell-gateway"
