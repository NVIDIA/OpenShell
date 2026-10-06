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

assert_reference_part() {
  local description=$1
  local expected=$2
  local actual=$3
  if [ "${actual}" != "${expected}" ]; then
    echo "FAIL: ${description}: expected '${expected}', got '${actual}'" >&2
    exit 1
  fi
}

assert_reference_part "repository strips tag" \
  "registry.example/gateway" \
  "$(e2e_image_reference_repository "registry.example/gateway:branch")"
assert_reference_part "repository preserves registry port" \
  "localhost:5000/openshell/gateway" \
  "$(e2e_image_reference_repository "localhost:5000/openshell/gateway:test")"
assert_reference_part "registry extracts hostname" \
  "registry.example" \
  "$(e2e_image_reference_registry "registry.example/openshell/gateway:branch")"
assert_reference_part "registry extracts hostname and port" \
  "localhost:5000" \
  "$(e2e_image_reference_registry "localhost:5000/openshell/gateway:test")"
assert_reference_part "repository path excludes registry" \
  "openshell/gateway" \
  "$(e2e_image_reference_repository_path "registry.example/openshell/gateway:branch")"
assert_reference_part "tag extracts tag" \
  "branch" \
  "$(e2e_image_reference_tag "registry.example/gateway:branch")"
assert_reference_part "digest extracts digest" \
  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  "$(e2e_image_reference_digest "registry.example/gateway@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")"
assert_reference_part "digest has no tag" \
  "" \
  "$(e2e_image_reference_tag "registry.example/gateway@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")"

assert_helm_image_translation() {
  local description=$1
  local image=$2
  local expected_registry=$3
  local expected_repository=$4
  local expected_tag=$5
  local expected_digest=$6

  assert_reference_part "${description} registry" "${expected_registry}" \
    "$(e2e_image_reference_registry "${image}")"
  assert_reference_part "${description} repository" "${expected_repository}" \
    "$(e2e_image_reference_repository_path "${image}")"
  assert_reference_part "${description} tag" "${expected_tag}" \
    "$(e2e_image_reference_tag "${image}")"
  assert_reference_part "${description} digest" "${expected_digest}" \
    "$(e2e_image_reference_digest "${image}")"
}

# The Kubernetes wrapper passes these three fields directly to Helm. Exercise
# a mixed tagged/digest-pinned set so each independently configurable image is
# translated without embedding a complete reference in image.repository.
assert_helm_image_translation "gateway" \
  "registry.example/gateway:branch" "registry.example" "gateway" "branch" ""
assert_helm_image_translation "supervisor" \
  "localhost:5000/openshell/supervisor:test" "localhost:5000" "openshell/supervisor" "test" ""
assert_helm_image_translation "sandbox" \
  "registry.example/sandbox@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
  "registry.example" "sandbox" "" "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

echo "E2E image override tests passed."
