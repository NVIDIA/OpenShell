#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tasks/scripts/gateway-pull-policy.sh
source "${ROOT}/tasks/scripts/gateway-pull-policy.sh"

assert_policy() {
  local input=$1
  local expected=$2
  local actual
  actual="$(normalize_image_pull_policy "${input}")"
  if [[ "${actual}" != "${expected}" ]]; then
    printf 'expected %q -> %q, got %q\n' "${input}" "${expected}" "${actual}" >&2
    exit 1
  fi
}

for input in always Always ALWAYS; do
  assert_policy "${input}" always
done
for input in if_not_present IfNotPresent ifnotpresent IFNOTPRESENT missing MISSING; do
  assert_policy "${input}" if_not_present
done
for input in never Never NEVER; do
  assert_policy "${input}" never
done
for input in newer Newer NEWER; do
  assert_policy "${input}" newer
done

if normalize_image_pull_policy sometimes >/dev/null 2>&1; then
  echo "unsupported policy unexpectedly succeeded" >&2
  exit 1
fi

for script in gateway.sh gateway-docker.sh gateway-podman.sh; do
  if ! grep -q 'normalize_image_pull_policy' "${ROOT}/tasks/scripts/${script}"; then
    echo "${script} does not normalize image pull policy" >&2
    exit 1
  fi
done

echo "gateway pull-policy tests passed"
