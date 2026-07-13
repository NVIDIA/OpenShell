#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Shared helpers for local gateway-backed e2e wrappers. Driver-specific setup,
# cleanup, and runtime behavior stay in the Docker/Podman wrapper scripts.

e2e_cargo_target_dir() {
  local root=$1

  if [ -n "${CARGO_TARGET_DIR:-}" ]; then
    case "${CARGO_TARGET_DIR}" in
      /*) printf '%s\n' "${CARGO_TARGET_DIR}" ;;
      *) printf '%s\n' "${root}/${CARGO_TARGET_DIR}" ;;
    esac
    return 0
  fi

  cargo metadata --format-version=1 --no-deps \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])'
}

e2e_endpoint_port() {
  python3 - "$1" <<'PY'
import sys
from urllib.parse import urlparse

parsed = urlparse(sys.argv[1])
print(parsed.port or (443 if parsed.scheme == "https" else 80))
PY
}

e2e_pick_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()'
}

e2e_generate_pki() {
  local gateway_bin=$1
  local pki_dir=$2
  shift 2
  # Remaining args are extra --server-san values (e.g. host.containers.internal).
  # host.docker.internal and localhost are already in the default SAN list.

  local san_args=()
  san_args+=(--server-san host.openshell.internal)
  for san in "$@"; do
    san_args+=(--server-san "${san}")
  done

  "${gateway_bin}" generate-certs --output-dir "${pki_dir}" "${san_args[@]}"
}

e2e_preserve_mise_dirs() {
  if ! command -v mise >/dev/null 2>&1; then
    return 0
  fi

  if [ -z "${MISE_DATA_DIR:-}" ]; then
    export MISE_DATA_DIR="${XDG_DATA_HOME:-${HOME}/.local/share}/mise"
  fi

  if [ -z "${MISE_CACHE_DIR:-}" ]; then
    case "$(uname -s)" in
      Darwin) export MISE_CACHE_DIR="${HOME}/Library/Caches/mise" ;;
      *) export MISE_CACHE_DIR="${XDG_CACHE_HOME:-${HOME}/.cache}/mise" ;;
    esac
  fi

  if [ -z "${MISE_STATE_DIR:-}" ]; then
    export MISE_STATE_DIR="${XDG_STATE_HOME:-${HOME}/.local/state}/mise"
  fi
}

e2e_align_docker_host_with_cli_context() {
  if [ -n "${DOCKER_HOST:-}" ] || ! command -v docker >/dev/null 2>&1; then
    return 0
  fi

  local endpoint
  endpoint="$(docker context inspect --format '{{ .Endpoints.docker.Host }}' 2>/dev/null || true)"
  if [ -z "${endpoint}" ] || [ "${endpoint}" = "<no value>" ]; then
    return 0
  fi

  export DOCKER_HOST="${endpoint}"
  echo "Using Docker endpoint from active context: ${DOCKER_HOST}"
}

e2e_register_plaintext_gateway() {
  local config_home=$1
  local name=$2
  local endpoint=$3
  local port=$4
  local gateway_config_dir="${config_home}/openshell/gateways/${name}"

  mkdir -p "${gateway_config_dir}"
  cat >"${gateway_config_dir}/metadata.json" <<EOF
{
  "name": "${name}",
  "gateway_endpoint": "${endpoint}",
  "is_remote": false,
  "gateway_port": ${port},
  "auth_mode": "plaintext"
}
EOF
  printf '%s' "${name}" >"${config_home}/openshell/active_gateway"
}

e2e_register_mtls_gateway() {
  local config_home=$1
  local name=$2
  local endpoint=$3
  local port=$4
  local pki_dir=$5
  local gateway_config_dir="${config_home}/openshell/gateways/${name}"

  mkdir -p "${gateway_config_dir}/mtls"
  cp "${pki_dir}/ca.crt"         "${gateway_config_dir}/mtls/ca.crt"
  cp "${pki_dir}/client/tls.crt" "${gateway_config_dir}/mtls/tls.crt"
  cp "${pki_dir}/client/tls.key" "${gateway_config_dir}/mtls/tls.key"
  cat >"${gateway_config_dir}/metadata.json" <<EOF
{
  "name": "${name}",
  "gateway_endpoint": "${endpoint}",
  "is_remote": false,
  "gateway_port": ${port}
}
EOF
  printf '%s' "${name}" >"${config_home}/openshell/active_gateway"
}

e2e_toml_string() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "${value}"
}

e2e_write_gateway_jwt_config() {
  local jwt_dir=$1
  local gateway_id=$2

  printf '[openshell.gateway.gateway_jwt]\n'
  printf 'signing_key_path = %s\n' "$(e2e_toml_string "${jwt_dir}/signing.pem")"
  printf 'public_key_path = %s\n'  "$(e2e_toml_string "${jwt_dir}/public.pem")"
  printf 'kid_path = %s\n'         "$(e2e_toml_string "${jwt_dir}/kid")"
  printf 'gateway_id = %s\n'       "$(e2e_toml_string "${gateway_id}")"
  # Local Docker/Podman e2e gateways exercise the single-player default:
  # sandbox JWTs identify the supervisor and do not expire.
  printf 'ttl_secs = 0\n\n'
}

e2e_write_gateway_mtls_auth_config() {
  printf '[openshell.gateway.mtls_auth]\n'
  printf 'enabled = true\n\n'
}

e2e_build_gateway_binaries() {
  local root=$1
  local target_var=$2
  local gateway_var=$3
  local cli_var=$4
  local target_dir
  local jobs=()

  if [ -n "${CARGO_BUILD_JOBS:-}" ]; then
    jobs=(-j "${CARGO_BUILD_JOBS}")
  fi

  target_dir="$(e2e_cargo_target_dir "${root}")"
  printf -v "${target_var}" '%s' "${target_dir}"
  printf -v "${gateway_var}" '%s' "${target_dir}/debug/openshell-gateway"
  printf -v "${cli_var}" '%s' "${target_dir}/debug/openshell"

  echo "Building openshell-gateway..."
  cargo build "${jobs[@]}" \
    -p openshell-server --bin openshell-gateway

  echo "Building openshell-cli..."
  cargo build "${jobs[@]}" \
    -p openshell-cli

  if [ ! -x "${target_dir}/debug/openshell-gateway" ]; then
    echo "ERROR: expected openshell-gateway binary at ${target_dir}/debug/openshell-gateway" >&2
    exit 1
  fi
  if [ ! -x "${target_dir}/debug/openshell" ]; then
    echo "ERROR: expected openshell CLI binary at ${target_dir}/debug/openshell" >&2
    exit 1
  fi
}

e2e_write_gateway_args_file() {
  local args_file=$1
  shift

  : >"${args_file}"
  for arg in "$@"; do
    printf '%s\0' "${arg}" >>"${args_file}"
  done
}

e2e_export_gateway_restart_metadata() {
  local gateway_bin=$1
  local args_file=$2
  local log_file=$3
  local pid_file=$4

  export OPENSHELL_E2E_GATEWAY_BIN="${gateway_bin}"
  export OPENSHELL_E2E_GATEWAY_ARGS_FILE="${args_file}"
  export OPENSHELL_E2E_GATEWAY_LOG="${log_file}"
  export OPENSHELL_E2E_GATEWAY_PID_FILE="${pid_file}"
}

e2e_stop_gateway() {
  local gateway_pid=$1
  local gateway_pid_file=$2

  if [ -f "${gateway_pid_file}" ]; then
    gateway_pid="$(cat "${gateway_pid_file}" 2>/dev/null || true)"
  fi
  if [ -n "${gateway_pid}" ] && kill -0 "${gateway_pid}" 2>/dev/null; then
    echo "Stopping openshell-gateway (pid ${gateway_pid})..."
    kill "${gateway_pid}" 2>/dev/null || true
    wait "${gateway_pid}" 2>/dev/null || true
  fi
}

e2e_print_gateway_log_on_failure() {
  local exit_code=$1
  local gateway_log=$2

  if [ "${exit_code}" -ne 0 ] && [ -f "${gateway_log}" ]; then
    echo "=== gateway log (preserved for debugging) ==="
    cat "${gateway_log}"
    echo "=== end gateway log ==="
  fi
}
