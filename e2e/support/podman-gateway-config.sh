#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Schema-aware Podman gateway configuration generation shared by the local e2e
# wrapper and schema parity harness. This file expects gateway-common.sh to
# have been sourced first.

e2e_podman_config_schema_version() {
  local version="${OPENSHELL_E2E_CONFIG_SCHEMA_VERSION:-2}"

  case "${version}" in
    1|2) printf '%s\n' "${version}" ;;
    *)
      echo "ERROR: OPENSHELL_E2E_CONFIG_SCHEMA_VERSION must be 1 or 2 (got ${version})." >&2
      return 2
      ;;
  esac
}

e2e_podman_external_driver_pull_policy() {
  case "$1" in
    1) printf '%s\n' missing ;;
    2) printf '%s\n' if_not_present ;;
    *) echo "ERROR: unsupported Podman config schema version: $1" >&2; return 2 ;;
  esac
}

e2e_podman_toml_string() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "${value}"
}

# Return the explicitly selected behavioral profile. Keep the default empty so
# ordinary smoke coverage continues to exercise the minimal configuration.
e2e_podman_option_profile() {
  case "${OPENSHELL_E2E_PODMAN_OPTION_PROFILE:-}" in
    "") printf '%s\n' "" ;;
    podman-options) printf '%s\n' "podman-options" ;;
    *)
      echo "ERROR: unsupported OPENSHELL_E2E_PODMAN_OPTION_PROFILE: ${OPENSHELL_E2E_PODMAN_OPTION_PROFILE}" >&2
      return 2
      ;;
  esac
}

# Frozen baseline 74960ebfaeec4673885089ed995fad902459749f does not accept
# Podman app_armor_profile, so it is deliberately not part of this paired profile.

# Write the minimally configured Podman e2e gateway TOML. The schema-v1
# branch deliberately uses the frozen-main contract: list driver selection,
# driver-local guest TLS, the old "missing" pull-policy spelling, and zero to
# disable Podman health checks. Schema v2 uses gateway-owned guest TLS and the
# current positive health-check setting from the RPM template.
e2e_write_podman_gateway_config() {
  local output=$1
  local schema_version=$2
  local root=$3
  local pki_dir=$4
  local jwt_dir=$5
  local gateway_id=$6
  local external_driver=$7
  local driver_socket=$8
  local network_name=$9
  local gateway_port=${10}
  local sandbox_image=${11}
  local stop_timeout_secs=${12}
  local supervisor_image=${13}
  local provider_spiffe_socket=${14}
  local podman_socket=${15}
  local oidc_mode=${16}
  local oidc_issuer=${17}
  local configured_with_tls option_profile

  case "${OPENSHELL_E2E_PODMAN_OPTION_PROFILE:-}" in
    ""|podman-options) option_profile="${OPENSHELL_E2E_PODMAN_OPTION_PROFILE:-}" ;;
    *) echo "ERROR: unsupported OPENSHELL_E2E_PODMAN_OPTION_PROFILE: ${OPENSHELL_E2E_PODMAN_OPTION_PROFILE}" >&2; return 2 ;;
  esac

  case "${schema_version}" in
    1)
      cp "${root}/deploy/rpm/gateway.toml.default.v1" "${output}"
      {
        e2e_write_gateway_jwt_config "${jwt_dir}" "${gateway_id}"
        if [ "${oidc_mode}" != "1" ]; then
          e2e_write_gateway_mtls_auth_config
          if [ -n "${oidc_issuer}" ]; then
            e2e_write_gateway_oidc_config "${oidc_issuer}"
          fi
        fi
        printf '\n[openshell.drivers.podman]\n'
        if [ "${external_driver}" = "1" ]; then
          printf 'socket_path = %s\n' "$(e2e_podman_toml_string "${driver_socket}")"
        else
          printf 'network_name = %s\n' "$(e2e_podman_toml_string "${network_name}")"
          printf 'gateway_port = %s\n' "${gateway_port}"
          printf 'default_image = %s\n' "$(e2e_podman_toml_string "${sandbox_image}")"
          printf 'image_pull_policy = "missing"\n'
          if [ "${option_profile}" = "podman-options" ]; then
            printf 'sandbox_pids_limit = 31\n'
            printf 'health_check_interval_secs = 7\n'

            printf 'sandbox_ssh_socket_path = "/run/openshell/parity-ssh.sock"\n'
          else
            # In schema v1, zero explicitly disables Podman health checks.
            printf 'health_check_interval_secs = 0\n'
          fi
          printf 'stop_timeout_secs = %s\n' "${stop_timeout_secs}"
          printf 'supervisor_image = %s\n' "$(e2e_podman_toml_string "${supervisor_image}")"
          printf 'guest_tls_ca = %s\n' "$(e2e_podman_toml_string "${pki_dir}/ca.crt")"
          printf 'guest_tls_cert = %s\n' "$(e2e_podman_toml_string "${pki_dir}/client/tls.crt")"
          printf 'guest_tls_key = %s\n' "$(e2e_podman_toml_string "${pki_dir}/client/tls.key")"
          printf 'enable_bind_mounts = true\n'
          if [ -n "${provider_spiffe_socket}" ]; then
            printf 'provider_spiffe_workload_api_socket = %s\n' "$(e2e_podman_toml_string "${provider_spiffe_socket}")"
          fi
          if [ -n "${podman_socket}" ]; then
            printf 'socket_path = %s\n' "$(e2e_podman_toml_string "${podman_socket}")"
          fi
        fi
      } >>"${output}"
      ;;
    2)
      cp "${root}/deploy/rpm/gateway.toml.default" "${output}"
      if [ "${option_profile}" = "podman-options" ]; then
        sed -i 's/^health_check_interval_secs = .*/health_check_interval_secs = 7/' "${output}"
      fi
      # The v2 template opens the Podman table. Insert gateway-owned TLS
      # before it rather than reopening [openshell.gateway] later.
      configured_with_tls="${output}.tls"
      while IFS= read -r line; do
        if [ "${line}" = "[openshell.drivers.podman]" ]; then
          printf 'guest_tls_ca = %s\n' "$(e2e_podman_toml_string "${pki_dir}/ca.crt")"
          printf 'guest_tls_cert = %s\n' "$(e2e_podman_toml_string "${pki_dir}/client/tls.crt")"
          printf 'guest_tls_key = %s\n\n' "$(e2e_podman_toml_string "${pki_dir}/client/tls.key")"
        fi
        printf '%s\n' "${line}"
      done <"${output}" >"${configured_with_tls}"
      mv "${configured_with_tls}" "${output}"
      {
        if [ "${external_driver}" = "1" ]; then
          printf 'socket_path = %s\n' "$(e2e_podman_toml_string "${driver_socket}")"
        else
          printf 'network_name = %s\n' "$(e2e_podman_toml_string "${network_name}")"
          printf 'gateway_port = %s\n' "${gateway_port}"
          printf 'default_image = %s\n' "$(e2e_podman_toml_string "${sandbox_image}")"
          printf 'image_pull_policy = "if_not_present"\n'
          if [ "${option_profile}" = "podman-options" ]; then
            printf 'sandbox_pids_limit = 31\n'
            printf 'ssh_socket_path = "/run/openshell/parity-ssh.sock"\n'
          fi
          printf 'stop_timeout_secs = %s\n' "${stop_timeout_secs}"
          printf 'supervisor_image = %s\n' "$(e2e_podman_toml_string "${supervisor_image}")"
          printf 'enable_bind_mounts = true\n'
          if [ -n "${provider_spiffe_socket}" ]; then
            printf 'provider_spiffe_workload_api_socket = %s\n' "$(e2e_podman_toml_string "${provider_spiffe_socket}")"
          fi
          if [ -n "${podman_socket}" ]; then
            printf 'socket_path = %s\n' "$(e2e_podman_toml_string "${podman_socket}")"
          fi
        fi
        e2e_write_gateway_jwt_config "${jwt_dir}" "${gateway_id}"
        if [ "${oidc_mode}" != "1" ]; then
          e2e_write_gateway_mtls_auth_config
          if [ -n "${oidc_issuer}" ]; then
            e2e_write_gateway_oidc_config "${oidc_issuer}"
          fi
        fi
      } >>"${output}"
      ;;
    *)
      echo "ERROR: unsupported Podman config schema version: ${schema_version}" >&2
      return 2
      ;;
  esac
}
