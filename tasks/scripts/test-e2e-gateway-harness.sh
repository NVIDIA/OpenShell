#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# shellcheck source=e2e/support/gateway-common.sh
source "${ROOT}/e2e/support/gateway-common.sh"

assert_eq() {
  local expected=$1
  local actual=$2
  local description=$3

  if [ "${actual}" != "${expected}" ]; then
    echo "FAIL: ${description}: expected '${expected}', got '${actual}'" >&2
    exit 1
  fi
}

darwin_bind=$(e2e_podman_primary_bind_ip Darwin)
darwin_cli_host=$(e2e_podman_cli_endpoint_host Darwin)
darwin_url_host=$(e2e_url_host_for_ip "${darwin_bind}")

assert_eq '::1' "${darwin_bind}" "Podman Machine primary bind"
assert_eq 'localhost' "${darwin_cli_host}" "Podman Machine TLS authority"
assert_eq '[::1]' "${darwin_url_host}" "Podman Machine health URL host"

linux_bind=$(e2e_podman_primary_bind_ip Linux)
linux_cli_host=$(e2e_podman_cli_endpoint_host Linux)
linux_url_host=$(e2e_url_host_for_ip "${linux_bind}")

assert_eq '127.0.0.1' "${linux_bind}" "native Linux primary bind"
assert_eq '127.0.0.1' "${linux_cli_host}" "native Linux TLS authority"
assert_eq '127.0.0.1' "${linux_url_host}" "native Linux health URL host"

echo "e2e gateway harness tests passed"
