#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=e2e/support/gateway-common.sh
source "${ROOT}/e2e/support/gateway-common.sh"

assert_resolves() {
  local description=$1
  local expected=$2
  shift 2
  local actual
  actual="$(e2e_resolve_image_reference "$@")"
  if [ "${actual}" != "${expected}" ]; then
    echo "FAIL: ${description}: expected '${expected}', got '${actual}'" >&2
    exit 1
  fi
}

assert_resolves "repository inherits tag" \
  "registry.example/gateway:test" \
  "registry.example/gateway" test
assert_resolves "repository trims trailing slash" \
  "registry.example/gateway:test" \
  "registry.example/gateway/" test
assert_resolves "tagged reference is unchanged" \
  "registry.example/gateway:branch" \
  "registry.example/gateway:branch" test
assert_resolves "digest reference is unchanged" \
  "registry.example/gateway@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  "registry.example/gateway@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" test
assert_resolves "registry port inherits tag" \
  "localhost:5000/openshell/gateway:test" \
  "localhost:5000/openshell/gateway" test

if e2e_image_reference_is_complete "registry.example/gateway:branch" \
  && e2e_image_reference_is_complete "registry.example/gateway@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  && ! e2e_image_reference_is_complete "registry.example/gateway" \
  && e2e_image_reference_has_digest "registry.example/gateway@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  && ! e2e_image_reference_has_digest "registry.example/gateway:branch"; then
  :
else
  echo "FAIL: image reference detection" >&2
  exit 1
fi

echo "E2E image override tests passed."
