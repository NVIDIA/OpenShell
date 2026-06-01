#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

assert_contains() {
  local file=$1
  local expected=$2

  if ! grep -Fq "$expected" "$file"; then
    echo "FAIL: ${file} is missing expected text:" >&2
    echo "  ${expected}" >&2
    exit 1
  fi
}

assert_not_contains() {
  local file=$1
  local unexpected=$2

  if grep -Fq "$unexpected" "$file"; then
    echo "FAIL: ${file} contains stale text:" >&2
    echo "  ${unexpected}" >&2
    exit 1
  fi
}

assert_file_exists() {
  local file=$1

  if [[ ! -f "$file" ]]; then
    echo "ERROR: ${file} not found" >&2
    exit 1
  fi
}

service="${ROOT}/deploy/deb/openshell-gateway.service"
spec="${ROOT}/openshell.spec"

assert_file_exists "$service"
assert_file_exists "$spec"

assert_contains \
  "$service" \
  'Environment=OPENSHELL_LOCAL_TLS_DIR=%h/.local/state/openshell/tls'
assert_contains \
  "$service" \
  'ExecStartPre=/usr/bin/openshell-gateway generate-certs --output-dir ${OPENSHELL_LOCAL_TLS_DIR} --server-san host.openshell.internal'
assert_not_contains "$service" '%S/openshell/tls'

assert_contains \
  "$spec" \
  'Environment=OPENSHELL_LOCAL_TLS_DIR=%%h/.local/state/openshell/tls'
assert_contains \
  "$spec" \
  'ExecStartPre=/usr/bin/openshell-gateway generate-certs --output-dir ${OPENSHELL_LOCAL_TLS_DIR} --server-san host.openshell.internal'
assert_not_contains "$spec" '%%S/openshell/tls'

echo "packaging asset tests passed"
