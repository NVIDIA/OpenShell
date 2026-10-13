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

# Empty and whitespace values are invalid rather than silently falling back to a default.
# Callers must supply one of the documented names.
assert_rejected_policy() {
  local input=$1
  if normalize_image_pull_policy "${input}" >/dev/null 2>&1; then
    printf 'unsupported policy unexpectedly succeeded: %q\n' "${input}" >&2
    exit 1
  fi
}

assert_rejected_policy ""
assert_rejected_policy " "
assert_rejected_policy $'\t'
assert_rejected_policy " if_not_present"
assert_rejected_policy "if_not_present "

# The VM driver does not render an image-pull-policy field, so it is intentionally
# excluded from Docker/Podman/Kubernetes normalization. Do not add it until it consumes it.
if grep -Fq 'gateway-pull-policy.sh' "${ROOT}/tasks/scripts/gateway-vm.sh"; then
  echo "gateway-vm.sh unexpectedly normalizes an unused image pull policy" >&2
  exit 1
fi
if ! grep -Fq 'intentionally does not normalize this input' "${ROOT}/tasks/scripts/gateway-vm.sh"; then
  echo "gateway-vm.sh does not document its pull-policy exclusion" >&2
  exit 1
fi

echo "gateway pull-policy edge-case tests passed"
