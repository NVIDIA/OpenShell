#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Shared plumbing for the local gateway launchers. Driver-specific configuration
# and runtime setup belong in gateway-<driver>.sh.

command_available() {
  command -v "$1" >/dev/null 2>&1
}

require_mise() {
  if ! command_available mise; then
    echo "ERROR: mise is required to build local gateway artifacts" >&2
    exit 1
  fi
}

run_mise_task() {
  require_mise
  mise run "$@"
}

port_is_in_use() {
  local port=$1
  if command_available lsof; then
    lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1
    return $?
  fi
  if command_available nc; then
    nc -z 127.0.0.1 "${port}" >/dev/null 2>&1
    return $?
  fi
  (echo >/dev/tcp/127.0.0.1/"${port}") >/dev/null 2>&1
}

append_local_otlp_config_if_available() {
  local config_path=$1
  if ! port_is_in_use 4317; then
    echo "OTLP collector not detected on 127.0.0.1:4317; trace export disabled."
    return
  fi

  cat >>"${config_path}" <<'EOF'

[openshell.gateway.otlp]
endpoint = "http://127.0.0.1:4317"
EOF
  echo "OTLP trace export enabled for http://127.0.0.1:4317."
}

validate_gateway_name() {
  local name=$1
  local variable_name=$2
  if [[ ! "${name}" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "ERROR: ${variable_name} must contain only letters, numbers, dots, underscores, or dashes" >&2
    exit 2
  fi
}

register_local_gateway() {
  local name=$1
  local endpoint=$2
  local port=$3
  local select_gateway=${4:-false}
  local config_home gateway_dir

  config_home="${XDG_CONFIG_HOME:-${HOME}/.config}"
  gateway_dir="${config_home}/openshell/gateways/${name}"

  mkdir -p "${gateway_dir}"
  cat >"${gateway_dir}/metadata.json" <<EOF
{
  "name": "${name}",
  "gateway_endpoint": "${endpoint}",
  "is_remote": false,
  "gateway_port": ${port},
  "auth_mode": "plaintext"
}
EOF

  if [[ "${select_gateway}" == "true" ]]; then
    printf '%s' "${name}" >"${config_home}/openshell/active_gateway"
  fi
}

ensure_container_runtime_image() {
  local engine=$1
  local image=$2
  local configured_image=$3
  local build_target=$4
  local role=$5

  if [[ -n "${configured_image}" ]]; then
    if container_image_exists "${engine}" "${image}"; then
      return
    fi
    echo "ERROR: ${role} image '${image}' not found locally." >&2
    echo "       Build it with ${engine} or unset its image override to build the local :dev image." >&2
    exit 1
  fi

  echo "Refreshing ${engine} ${role} image (${image})..."
  require_mise
  CONTAINER_ENGINE="${engine}" IMAGE_TAG=dev mise run "build:docker:${build_target}"

  if ! container_image_exists "${engine}" "${image}"; then
    echo "ERROR: expected ${role} image '${image}' after build" >&2
    exit 1
  fi
}

container_image_exists() {
  local engine=$1
  local image=$2
  case "${engine}" in
    docker) docker image inspect "${image}" >/dev/null 2>&1 ;;
    podman) podman image exists "${image}" >/dev/null 2>&1 ;;
    *)
      echo "ERROR: unsupported container engine '${engine}'" >&2
      return 2
      ;;
  esac
}
