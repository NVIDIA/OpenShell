#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Start a standalone openshell-gateway backed by the VM compute driver
# (openshell-driver-vm) for local manual testing.
#
# Invocation:
#   mise run gateway:vm
#
# Defaults:
# - Plaintext HTTP on 127.0.0.1:18081
# - Dedicated CLI gateway "vm-dev"
# - Persistent gateway state (SQLite DB) under .cache/gateway-vm
# - Per-sandbox VM driver state (rootfs + compute-driver.sock) under
#   /tmp/openshell-vm-driver-<user>-<gateway-name> so the AF_UNIX socket
#   path stays under macOS SUN_LEN
#
# Common overrides:
#   OPENSHELL_SERVER_PORT=18091 mise run gateway:vm
#   OPENSHELL_VM_GATEWAY_NAME=my-vm-gateway mise run gateway:vm
#   OPENSHELL_SANDBOX_NAMESPACE=my-ns mise run gateway:vm
#   OPENSHELL_SANDBOX_IMAGE=ghcr.io/... mise run gateway:vm
#   mise run gateway:vm -- --gpu
#
# This script also writes ~/.config/openshell/active_gateway so the
# `openshell` CLI automatically targets this gateway in subsequent shells.
# No need to run `openshell gateway select`. Inside this repo you can
# override per-developer with OPENSHELL_GATEWAY in `.env` (mise loads it).
# An explicit `--gateway` / `--gateway-endpoint` flag still wins.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PORT="${OPENSHELL_SERVER_PORT:-18081}"
GATEWAY_NAME="${OPENSHELL_VM_GATEWAY_NAME:-vm-dev}"
STATE_DIR="${OPENSHELL_VM_GATEWAY_STATE_DIR:-${ROOT}/.cache/gateway-vm}"
SANDBOX_NAMESPACE="${OPENSHELL_SANDBOX_NAMESPACE:-vm-dev}"
SANDBOX_IMAGE="${OPENSHELL_SANDBOX_IMAGE:-${COMMUNITY_SANDBOX_IMAGE:-ghcr.io/nvidia/openshell-community/sandboxes/base:latest}}"
SANDBOX_IMAGE_PULL_POLICY="${OPENSHELL_SANDBOX_IMAGE_PULL_POLICY:-IfNotPresent}"
LOG_LEVEL="${OPENSHELL_LOG_LEVEL:-info}"
GATEWAY_BIN="${ROOT}/target/debug/openshell-gateway"
DRIVER_DIR_DEFAULT="${ROOT}/target/debug"
DRIVER_DIR="${OPENSHELL_DRIVER_DIR:-${DRIVER_DIR_DEFAULT}}"
COMPRESSED_DIR_DEFAULT="${ROOT}/target/vm-runtime-compressed"
COMPRESSED_DIR="${OPENSHELL_VM_RUNTIME_COMPRESSED_DIR:-${COMPRESSED_DIR_DEFAULT}}"
VM_HOST_GATEWAY_DEFAULT="${OPENSHELL_VM_HOST_GATEWAY:-host.containers.internal}"
GRPC_ENDPOINT="${OPENSHELL_GRPC_ENDPOINT:-http://${VM_HOST_GATEWAY_DEFAULT}:${PORT}}"

normalize_arch() {
  case "$1" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "$1" ;;
  esac
}

normalize_bool() {
  case "${1,,}" in
    1|true|yes|on) echo "true" ;;
    0|false|no|off) echo "false" ;;
    *)
      echo "ERROR: invalid boolean value '$1' (expected true/false, 1/0, yes/no, on/off)" >&2
      exit 2
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

invoking_user() {
  if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    printf '%s\n' "${SUDO_USER}"
  else
    id -un
  fi
}

invoking_user_home() {
  local user=$1
  local home
  if [ "${user}" = "$(id -un)" ]; then
    printf '%s\n' "${HOME}"
    return
  fi
  if command -v getent >/dev/null 2>&1; then
    home="$(getent passwd "${user}" | cut -d: -f6)"
    if [ -n "${home}" ]; then
      printf '%s\n' "${home}"
      return
    fi
  fi
  if command -v dscl >/dev/null 2>&1; then
    home="$(dscl . -read "/Users/${user}" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
    if [ -n "${home}" ]; then
      printf '%s\n' "${home}"
      return
    fi
  fi
  if [ "$(uname -s)" = "Darwin" ]; then
    printf '/Users/%s\n' "${user}"
  else
    printf '/home/%s\n' "${user}"
  fi
}

gateway_config_home() {
  local user home
  user="$(invoking_user)"
  if [ -n "${SUDO_USER:-}" ] && [ "${user}" != "$(id -un)" ]; then
    home="$(invoking_user_home "${user}")"
    printf '%s\n' "${home}/.config"
  else
    printf '%s\n' "${XDG_CONFIG_HOME:-${HOME}/.config}"
  fi
}

chown_invoking_user() {
  if [ -n "${SUDO_UID:-}" ] && [ -n "${SUDO_GID:-}" ]; then
    chown -R "${SUDO_UID}:${SUDO_GID}" "$@" 2>/dev/null || true
  fi
}

register_gateway_metadata() {
  local name=$1
  local endpoint=$2
  local port=$3
  local vm_driver_state_dir=$4
  local config_home gateway_dir

  config_home="$(gateway_config_home)"
  gateway_dir="${config_home}/openshell/gateways/${name}"

  mkdir -p "${gateway_dir}"
  chmod 700 "${gateway_dir}" 2>/dev/null || true
  cat >"${gateway_dir}/metadata.json" <<EOF
{
  "name": "${name}",
  "gateway_endpoint": "${endpoint}",
  "is_remote": false,
  "gateway_port": ${port},
  "auth_mode": "plaintext",
  "vm_driver_state_dir": "${vm_driver_state_dir}"
}
EOF
  chmod 600 "${gateway_dir}/metadata.json" 2>/dev/null || true
  chown_invoking_user "${config_home}/openshell"
}

# Mirror what `openshell gateway select <name>` does: write the gateway name
# to $XDG_CONFIG_HOME/openshell/active_gateway. The CLI picks it up as the
# default target when neither --gateway nor OPENSHELL_GATEWAY is set.
save_active_gateway() {
  local name=$1
  local config_home active_gateway_path
  config_home="$(gateway_config_home)"
  active_gateway_path="${config_home}/openshell/active_gateway"
  mkdir -p "$(dirname "${active_gateway_path}")"
  printf '%s' "${name}" >"${active_gateway_path}"
  chown_invoking_user "${config_home}/openshell"
}

check_supervisor_cross_toolchain() {
  # The sandbox supervisor inside the guest is always Linux. On non-Linux
  # hosts (macOS) and on Linux hosts with a different arch than the guest,
  # `mise run vm:supervisor` cross-compiles via cargo-zigbuild and needs
  # the matching rustup target installed.
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

VM_GPU="$(normalize_bool "${OPENSHELL_VM_GPU:-false}")"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --gpu)
      VM_GPU="true"
      shift
      ;;
    --gpu-mem-mib)
      if [ "$#" -lt 2 ]; then
        echo "ERROR: --gpu-mem-mib requires a value" >&2
        exit 2
      fi
      export OPENSHELL_VM_GPU_MEM_MIB="$2"
      shift 2
      ;;
    --gpu-vcpus)
      if [ "$#" -lt 2 ]; then
        echo "ERROR: --gpu-vcpus requires a value" >&2
        exit 2
      fi
      export OPENSHELL_VM_GPU_VCPUS="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: mise run gateway:vm -- [--gpu] [--gpu-mem-mib MIB] [--gpu-vcpus N]"
      exit 0
      ;;
    *)
      echo "ERROR: unknown gateway-vm option '$1'" >&2
      exit 2
      ;;
  esac
done

if [ "${VM_GPU}" = "true" ]; then
  export OPENSHELL_VM_GPU="true"
else
  unset OPENSHELL_VM_GPU
fi

if [[ ! "${GATEWAY_NAME}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "ERROR: OPENSHELL_VM_GATEWAY_NAME must contain only letters, numbers, dots, underscores, or dashes" >&2
  exit 2
fi

if port_is_in_use "${PORT}"; then
  echo "ERROR: port ${PORT} is already in use; free it or set OPENSHELL_SERVER_PORT" >&2
  exit 2
fi

# AF_UNIX SUN_LEN on macOS is 104 bytes; the VM driver places
# `compute-driver.sock` directly under VM_DRIVER_STATE_DIR, so anchor it
# under /tmp instead of `${ROOT}/.cache` (which is typically too long on
# macOS dev boxes with worktree paths).
STATE_LABEL="$(printf '%s' "${GATEWAY_NAME}" | tr -cs '[:alnum:]._-' '-')"
if [ -z "${STATE_LABEL}" ]; then
  STATE_LABEL="vm-dev"
fi
VM_DRIVER_STATE_DIR_DEFAULT="${OPENSHELL_VM_DRIVER_STATE_ROOT:-/tmp}/openshell-vm-driver-${USER:-user}-${STATE_LABEL}"
VM_DRIVER_STATE_DIR="${OPENSHELL_VM_DRIVER_STATE_DIR:-${VM_DRIVER_STATE_DIR_DEFAULT}}"

DISABLE_TLS="$(normalize_bool "${OPENSHELL_DISABLE_TLS:-true}")"

# Build prerequisites: VM runtime artifacts + bundled supervisor.
if [ ! -d "${COMPRESSED_DIR}" ] \
    || ! find "${COMPRESSED_DIR}" -maxdepth 1 -name 'libkrun*.zst' | grep -q . \
    || [ ! -f "${COMPRESSED_DIR}/gvproxy.zst" ]; then
  echo "==> Preparing embedded VM runtime (mise run vm:setup)"
  mise run vm:setup
fi

if [ ! -f "${COMPRESSED_DIR}/openshell-sandbox.zst" ]; then
  check_supervisor_cross_toolchain
  echo "==> Building bundled VM supervisor (mise run vm:supervisor)"
  mise run vm:supervisor
fi

export OPENSHELL_VM_RUNTIME_COMPRESSED_DIR="${COMPRESSED_DIR}"

CARGO_BUILD_JOBS_ARG=()
if [[ -n "${CARGO_BUILD_JOBS:-}" ]]; then
  CARGO_BUILD_JOBS_ARG=(-j "${CARGO_BUILD_JOBS}")
fi

echo "==> Building openshell-gateway and openshell-driver-vm"
cargo build ${CARGO_BUILD_JOBS_ARG[@]+"${CARGO_BUILD_JOBS_ARG[@]}"} \
  -p openshell-server -p openshell-driver-vm

if [ "$(uname -s)" = "Darwin" ]; then
  echo "==> Codesigning openshell-driver-vm (Hypervisor entitlement)"
  codesign \
    --entitlements "${ROOT}/crates/openshell-driver-vm/entitlements.plist" \
    --force \
    -s - \
    "${DRIVER_DIR}/openshell-driver-vm"
fi

mkdir -p "${STATE_DIR}"
mkdir -p "${VM_DRIVER_STATE_DIR}"

GATEWAY_ENDPOINT="http://127.0.0.1:${PORT}"
register_gateway_metadata "${GATEWAY_NAME}" "${GATEWAY_ENDPOINT}" "${PORT}" "${VM_DRIVER_STATE_DIR}"
save_active_gateway "${GATEWAY_NAME}"

echo "Starting standalone VM gateway..."
echo "  gateway:    ${GATEWAY_NAME}"
echo "  endpoint:   ${GATEWAY_ENDPOINT}"
echo "  namespace:  ${SANDBOX_NAMESPACE}"
echo "  state dir:  ${STATE_DIR}"
echo "  driver:     ${DRIVER_DIR}/openshell-driver-vm"
echo "  driver dir: ${VM_DRIVER_STATE_DIR}"
echo "  gpu:        ${VM_GPU}"
echo "  image:      ${SANDBOX_IMAGE}"
echo
echo "Active gateway set to '${GATEWAY_NAME}'. The CLI now targets this gateway"
echo "by default — just run \`openshell <command>\`. Override with --gateway"
echo "or by setting OPENSHELL_GATEWAY (e.g. in .env)."
echo

GATEWAY_ARGS=(
  --port "${PORT}"
  --log-level "${LOG_LEVEL}"
  --drivers vm
  --db-url "sqlite:${STATE_DIR}/gateway.db?mode=rwc"
  --sandbox-namespace "${SANDBOX_NAMESPACE}"
  --sandbox-image "${SANDBOX_IMAGE}"
  --sandbox-image-pull-policy "${SANDBOX_IMAGE_PULL_POLICY}"
  --grpc-endpoint "${GRPC_ENDPOINT}"
  --driver-dir "${DRIVER_DIR}"
  --vm-driver-state-dir "${VM_DRIVER_STATE_DIR}"
)

if [ "${DISABLE_TLS}" = "true" ]; then
  GATEWAY_ARGS+=(--disable-tls)
fi

exec "${GATEWAY_BIN}" "${GATEWAY_ARGS[@]}"
