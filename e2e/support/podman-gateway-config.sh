#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Podman gateway configuration generation shared by the local e2e wrapper and
# its deterministic configuration test. This file expects gateway-common.sh to
# have been sourced first.

e2e_podman_toml_string() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "${value}"
}

# Write the current Podman e2e gateway TOML. The RPM template opens the Podman
# driver table, so gateway-owned TLS is inserted before that table and the
# remaining driver options are appended to it.
e2e_write_podman_gateway_config() {
  local output=$1
  local root=$2
  local pki_dir=$3
  local jwt_dir=$4
  local gateway_id=$5
  local external_driver=$6
  local driver_socket=$7
  local network_name=$8
  local gateway_port=$9
  local sandbox_image=${10}
  local stop_timeout_secs=${11}
  local supervisor_image=${12}
  local sandbox_runtime_image=${13}
  local provider_spiffe_socket=${14}
  local podman_socket=${15}
  local oidc_mode=${16}
  local oidc_issuer=${17}
  local configured_with_tls

  cp "${root}/deploy/rpm/gateway.toml.default" "${output}"
  if [ "${external_driver}" = "1" ]; then
    # A remote UDS driver owns all runtime options. Keep the selected gateway
    # table transport-only so in-tree settings cannot be mistaken for external
    # driver configuration.
    sed '/^health_check_interval_secs = /d' "${output}" >"${output}.updated"
    mv "${output}.updated" "${output}"
  fi

  configured_with_tls="${output}.tls"
  while IFS= read -r line; do
    if [ "${line}" = "[ryno.drivers.podman]" ]; then
      printf 'guest_tls_ca = %s\n' "$(e2e_podman_toml_string "${pki_dir}/ca.crt")"
    fi
    printf '%s\n' "${line}"
  done <"${output}" >"${configured_with_tls}"
  mv "${configured_with_tls}" "${output}"

  {
    if [ "${external_driver}" = "1" ]; then
      printf 'socket_path = %s\n' "$(e2e_podman_toml_string "${driver_socket}")"
    else
      printf 'allow_driver_config = true\n'
      printf 'network_name = %s\n' "$(e2e_podman_toml_string "${network_name}")"
      printf 'gateway_port = %s\n' "${gateway_port}"
      printf 'default_image = %s\n' "$(e2e_podman_toml_string "${sandbox_image}")"
      printf 'image_pull_policy = "if_not_present"\n'
      printf 'stop_timeout_secs = %s\n' "${stop_timeout_secs}"
      printf 'supervisor_image = %s\n' "$(e2e_podman_toml_string "${supervisor_image}")"
      printf 'sandbox_runtime_image = %s\n' "$(e2e_podman_toml_string "${sandbox_runtime_image}")"
      printf 'enable_bind_mounts = true\n'
      if [ -n "${provider_spiffe_socket}" ]; then
        printf 'provider_spiffe_workload_api_socket = %s\n' "$(e2e_podman_toml_string "${provider_spiffe_socket}")"
      fi
      if [ -n "${podman_socket}" ]; then
        printf 'socket_path = %s\n' "$(e2e_podman_toml_string "${podman_socket}")"
      fi
      printf '\n[ryno.drivers.podman.resource_admission]\n'
      printf 'enabled = false\n'
    fi
    e2e_write_gateway_jwt_config "${jwt_dir}" "${gateway_id}"
    if [ "${oidc_mode}" != "1" ]; then
      e2e_write_gateway_mtls_auth_config
      if [ -n "${oidc_issuer}" ]; then
        e2e_write_gateway_oidc_config "${oidc_issuer}"
      fi
    fi
  } >>"${output}"
}
