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
CLI_BIN="${ROOT}/scripts/bin/openshell"
COMPRESSED_DIR="${ROOT}/target/vm-runtime-compressed"
SERVER_PORT="${OPENSHELL_SERVER_PORT:-8080}"
# Keep the driver socket path under AF_UNIX SUN_LEN on macOS.
STATE_DIR_ROOT="${OPENSHELL_VM_DRIVER_STATE_ROOT:-/tmp}"
STATE_LABEL_RAW="${OPENSHELL_VM_INSTANCE:-port-${SERVER_PORT}}"
STATE_LABEL="$(printf '%s' "${STATE_LABEL_RAW}" | tr -cs '[:alnum:]._-' '-')"
if [ -z "${STATE_LABEL}" ]; then
    STATE_LABEL="port-${SERVER_PORT}"
fi
STATE_DIR_DEFAULT="${STATE_DIR_ROOT}/openshell-vm-driver-dev-${USER:-user}-${STATE_LABEL}"
STATE_DIR="${OPENSHELL_VM_DRIVER_STATE_DIR:-${STATE_DIR_DEFAULT}}"
DB_PATH_DEFAULT="${STATE_DIR}/openshell.db"
VM_HOST_GATEWAY_DEFAULT="${OPENSHELL_VM_HOST_GATEWAY:-host.containers.internal}"
LOCAL_GATEWAY_ENDPOINT_DEFAULT="http://127.0.0.1:${SERVER_PORT}"
LOCAL_GATEWAY_ENDPOINT="${OPENSHELL_VM_LOCAL_GATEWAY_ENDPOINT:-${LOCAL_GATEWAY_ENDPOINT_DEFAULT}}"
GATEWAY_NAME_DEFAULT="vm-driver-${STATE_LABEL}"
GATEWAY_NAME="${OPENSHELL_VM_GATEWAY_NAME:-${GATEWAY_NAME_DEFAULT}}"
DRIVER_DIR_DEFAULT="${ROOT}/target/debug"
DRIVER_DIR="${OPENSHELL_DRIVER_DIR:-${DRIVER_DIR_DEFAULT}}"

export OPENSHELL_VM_RUNTIME_COMPRESSED_DIR="${OPENSHELL_VM_RUNTIME_COMPRESSED_DIR:-${COMPRESSED_DIR}}"

for arg in "$@"; do
    if [ "${arg}" = "--gpu" ]; then
        export OPENSHELL_VM_GPU=true
        break
    fi
done

mkdir -p "${STATE_DIR}"

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

if [ ! -s "${OPENSHELL_VM_RUNTIME_COMPRESSED_DIR}/rootfs.tar.zst" ]; then
    check_supervisor_cross_toolchain
    echo "==> Building base VM rootfs tarball"
    mise run vm:rootfs -- --base
fi

if [ "${OPENSHELL_VM_GPU:-}" = "true" ] && [ ! -s "${OPENSHELL_VM_RUNTIME_COMPRESSED_DIR}/rootfs-gpu.tar.zst" ]; then
    check_supervisor_cross_toolchain
    echo "==> Building GPU VM rootfs tarball"
    mise run vm:rootfs -- --gpu
fi

if [ ! -s "${OPENSHELL_VM_RUNTIME_COMPRESSED_DIR}/rootfs.tar.zst" ] || ! find "${OPENSHELL_VM_RUNTIME_COMPRESSED_DIR}" -maxdepth 1 -name 'libkrun*.zst' | grep -q .; then
    echo "==> Preparing embedded VM runtime"
    mise run vm:setup
fi

echo "==> Building gateway and VM compute driver"
cargo build -p openshell-server -p openshell-driver-vm

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
export OPENSHELL_GRPC_ENDPOINT="${OPENSHELL_GRPC_ENDPOINT:-http://${VM_HOST_GATEWAY_DEFAULT}:${SERVER_PORT}}"
export OPENSHELL_SSH_GATEWAY_HOST="${OPENSHELL_SSH_GATEWAY_HOST:-127.0.0.1}"
export OPENSHELL_SSH_GATEWAY_PORT="${OPENSHELL_SSH_GATEWAY_PORT:-${SERVER_PORT}}"
export OPENSHELL_SSH_HANDSHAKE_SECRET="${OPENSHELL_SSH_HANDSHAKE_SECRET:-}"
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

echo "==> Registering gateway"
echo "    Name: ${GATEWAY_NAME}"
echo "    Endpoint: ${LOCAL_GATEWAY_ENDPOINT}"
echo "    Driver: ${OPENSHELL_DRIVER_DIR}/openshell-driver-vm"

# GPU passthrough requires root, but gateway config must be written to the
# real user's home directory — not /root/.config/openshell/.
# Unset XDG_CONFIG_HOME so the CLI falls back to $HOME/.config (sudo -u
# sets HOME correctly but may inherit XDG_CONFIG_HOME from the root env).
if [ -n "${SUDO_USER:-}" ]; then
    sudo -u "${SUDO_USER}" env -u XDG_CONFIG_HOME "PATH=${PATH}" "${CLI_BIN}" gateway destroy --name "${GATEWAY_NAME}" 2>/dev/null || true
    sudo -u "${SUDO_USER}" env -u XDG_CONFIG_HOME "PATH=${PATH}" "${CLI_BIN}" gateway add --name "${GATEWAY_NAME}" "${LOCAL_GATEWAY_ENDPOINT}"
    sudo -u "${SUDO_USER}" env -u XDG_CONFIG_HOME "PATH=${PATH}" "${CLI_BIN}" gateway select "${GATEWAY_NAME}"
else
    "${CLI_BIN}" gateway destroy --name "${GATEWAY_NAME}" 2>/dev/null || true
    "${CLI_BIN}" gateway add --name "${GATEWAY_NAME}" "${LOCAL_GATEWAY_ENDPOINT}"
    "${CLI_BIN}" gateway select "${GATEWAY_NAME}"
fi

echo "==> Starting OpenShell server with VM compute driver"
exec "${ROOT}/target/debug/openshell-gateway"
