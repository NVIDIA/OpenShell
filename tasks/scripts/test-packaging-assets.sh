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

# Schema-v2 package startup wiring.
snap_wrapper="${ROOT}/tasks/scripts/snap-gateway-wrapper.sh"
package_deb="${ROOT}/tasks/scripts/package-deb.sh"
assert_file_exists "$snap_wrapper"
assert_file_exists "$package_deb"
assert_contains "$service" "ExecStartPre=/usr/bin/openshell-gateway config preflight"
assert_contains "$package_deb" "\$src_dir/openshell-gateway.service"
assert_contains "$package_deb" "\$pkgroot/usr/lib/systemd/user/openshell-gateway.service"
assert_contains "$snap_wrapper" "if [ -n \"\${OPENSHELL_GATEWAY_CONFIG:-}\" ]; then"
assert_contains \
  "$snap_wrapper" \
  "elif [ -e \"\$CANONICAL_CONFIG_FILE\" ] || [ -L \"\$CANONICAL_CONFIG_FILE\" ]; then"
assert_contains "$snap_wrapper" "config preflight -- --config \"\$CANONICAL_CONFIG_FILE\" \"\$@\""
assert_not_contains "$snap_wrapper" "[ -f \"\$CANONICAL_CONFIG_FILE\" ]"
bash "$ROOT/tasks/scripts/test-snap-gateway-wrapper.sh" "$snap_wrapper"
if ! awk '/config preflight/ { seen = 1 } /generate-certs/ { exit !seen }' "$service"; then
  echo "FAIL: Debian preflight must precede certificate generation" >&2
  exit 1
fi

# Build a throwaway package when Debian tooling is available to prove the
# staged unit comes from deploy/deb/. Other hosts retain the static source-to-
# destination assertion above; the real Debian upgrade lane remains required.
if command -v dpkg-deb >/dev/null 2>&1; then
  package_work=$(mktemp -d "${TMPDIR:-/tmp}/openshell-package-assets.XXXXXX")
  trap 'rm -rf "$package_work"' EXIT
  mkdir -p "$package_work/bin" "$package_work/output"
  for binary in openshell openshell-gateway openshell-driver-vm; do
    printf '#!/bin/sh\nexit 0\n' >"$package_work/bin/$binary"
    chmod +x "$package_work/bin/$binary"
  done
  OPENSHELL_CLI_BINARY="$package_work/bin/openshell" \
    OPENSHELL_GATEWAY_BINARY="$package_work/bin/openshell-gateway" \
    OPENSHELL_DRIVER_VM_BINARY="$package_work/bin/openshell-driver-vm" \
    OPENSHELL_DEB_VERSION=0.0.0 \
    OPENSHELL_DEB_ARCH=amd64 \
    OPENSHELL_OUTPUT_DIR="$package_work/output" \
    "$package_deb" >/dev/null
  dpkg-deb --fsys-tarfile "$package_work/output/openshell_0.0.0_amd64.deb" \
    | tar -xOf - ./usr/lib/systemd/user/openshell-gateway.service \
      >"$package_work/staged.service"
  if ! cmp -s "$service" "$package_work/staged.service"; then
    echo "FAIL: package-deb did not stage the current Debian service" >&2
    exit 1
  fi
else
  echo "SKIP: dpkg-deb unavailable; Debian artifact staging requires its assigned lane"
fi

echo "packaging asset tests passed"
