#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=e2e/support/gateway-common.sh
source "${ROOT}/e2e/support/gateway-common.sh"

PROFILE_WORK="$(mktemp -d)"
trap 'rm -rf "${PROFILE_WORK}"' EXIT
mkdir -p "${PROFILE_WORK}/providers"
printf 'id: google-cloud\n' > "${PROFILE_WORK}/providers/google-cloud.yaml"
printf 'id: acme\nrequired_platform_adapter: gcp-metadata\n' > "${PROFILE_WORK}/providers/acme.yaml"
printf 'id: future\nrequired_platform_adapter: future-adapter\n' > "${PROFILE_WORK}/providers/future.yaml"

capture_profile_import() {
  printf '%s\n' "$*" >> "${PROFILE_WORK}/imports"
}

e2e_import_example_provider_profiles capture_profile_import "${PROFILE_WORK}"
expected="provider profile import --file ${PROFILE_WORK}/providers/acme.yaml --global
provider profile import --file ${PROFILE_WORK}/providers/google-cloud.yaml --global"
if [ "$(cat "${PROFILE_WORK}/imports")" != "${expected}" ]; then
  echo "FAIL: profile selection must follow adapter declarations, independent of ID" >&2
  exit 1
fi

fail_profile_import() {
  return 1
}

if e2e_import_example_provider_profiles fail_profile_import "${PROFILE_WORK}" > "${PROFILE_WORK}/failure.log" 2>&1; then
  echo "FAIL: an import error must fail gateway setup" >&2
  exit 1
fi

echo "E2E provider profile setup tests passed."
