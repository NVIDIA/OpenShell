#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

assert_contains() {
  local file=$1
  local expected=$2

  if ! grep -Fq -- "$expected" "$file"; then
    echo "FAIL: ${file} is missing expected text:" >&2
    echo "  ${expected}" >&2
    exit 1
  fi
}

assert_not_contains() {
  local file=$1
  local unexpected=$2

  if grep -Fq -- "$unexpected" "$file"; then
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
control="${ROOT}/deploy/deb/control.in"
spec="${ROOT}/openshell.spec"

assert_file_exists "$service"
assert_file_exists "$control"
assert_file_exists "$spec"

# Debian control files are RFC822-style metadata. Older dpkg-deb releases
# reject comment lines as malformed fields, so keep SPDX metadata in the
# adjacent .license sidecar instead of emitting it into DEBIAN/control.
if grep -Eq '^[[:space:]]*#' "$control"; then
  echo "FAIL: Debian control template contains a comment field" >&2
  exit 1
fi
if [[ $(sed -n '/[^[:space:]]/ { p; q; }' "$control") != "Package: openshell" ]]; then
  echo "FAIL: Debian control template must begin with the Package field" >&2
  exit 1
fi

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
assert_contains "$spec" 'ExecStartPre=/usr/bin/openshell-gateway config preflight'
assert_contains "$spec" '%package prover'
assert_contains "$spec" '%files prover'
assert_contains "$spec" '%{_bindir}/%{name}-prover'
assert_not_contains "$spec" '%%S/openshell/tls'

# Schema-v2 package startup wiring.
snap_wrapper="${ROOT}/tasks/scripts/snap-gateway-wrapper.sh"
snapcraft="${ROOT}/snapcraft.yaml"
snap_install_docs="${ROOT}/docs/about/installation.mdx"
snap_canary="${ROOT}/.github/workflows/release-canary.yml"
snap_repro="${ROOT}/nix/test-guest/scripts/snap-gateway-repro.sh"
snap_docker_hook="${ROOT}/snap/hooks/connect-plug-docker"
snap_install_hook="${ROOT}/snap/hooks/install"
package_deb="${ROOT}/tasks/scripts/package-deb.sh"
assert_file_exists "$snap_wrapper"
assert_file_exists "$snapcraft"
assert_file_exists "$snap_install_docs"
assert_file_exists "$snap_canary"
assert_file_exists "$snap_repro"
assert_file_exists "$snap_docker_hook"
assert_file_exists "$snap_install_hook"
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

# Store installs autoconnect all required interfaces and require snapd 2.76 for
# the system Docker slot. Manual connection for locally-built snaps requires
# snapd 2.77.
assert_contains "$snapcraft" "assumes: [snapd2.76]"
for snap_file in \
  "$snapcraft" \
  "$snap_install_docs" \
  "$snap_canary" \
  "$snap_repro" \
  "$snap_docker_hook" \
  "$snap_install_hook"; do
  assert_not_contains "$snap_file" "docker:docker-daemon"
  assert_not_contains "$snap_file" "default-provider: docker"
done
if [[ ! -x "$snap_install_hook" ]]; then
  echo "FAIL: Snap install hook must be executable" >&2
  exit 1
fi
assert_not_contains "$snap_install_hook" 'compute_driver'
assert_not_contains "$snap_install_hook" 'allow_unauthenticated_users = true'
assert_contains "$snapcraft" 'refresh-mode: restart'
if [[ ! -x "$(dirname "$snap_install_hook")/post-refresh" ]]; then
  echo "FAIL: Snap post-refresh hook must be executable" >&2
  exit 1
fi
assert_not_contains "$ROOT/tasks/scripts/snap-gateway-wrapper.sh" 'OPENSHELL_DISABLE_TLS'
bash "$ROOT/tasks/scripts/test-snap-install-hook.sh" "$snap_install_hook"
assert_not_contains "$snap_install_docs" "snap connect openshell:home"
assert_not_contains "$snap_install_docs" "snap connect openshell:network"
assert_not_contains "$snap_install_docs" "snap connect openshell:network-bind"
assert_contains "$snap_install_docs" "snap connect openshell:docker :docker"
assert_contains "$snap_canary" "install.sh | sh"
assert_contains "$snap_canary" "ubuntu-snap-system-docker:"
assert_contains "$snap_canary" "ubuntu-snap-docker-preflight:"
assert_contains "$snap_repro" 'OPENSHELL_INSTALL_METHOD=snap OPENSHELL_VERSION=dev sh "${install_script}"'
assert_contains "$snap_repro" "system-docker"
assert_contains "$snap_repro" "missing-docker"
assert_contains "$snap_repro" "docker-snap"
assert_not_contains "$snap_canary" "--dangerous"
assert_not_contains "$snap_repro" "--dangerous"
assert_not_contains "$snap_canary" "snap connect openshell:docker"
assert_not_contains "$snap_repro" "snap connect openshell:docker"
if ! awk '/config preflight/ { seen = 1 } /generate-certs/ { exit !seen }' "$service"; then
  echo "FAIL: Debian preflight must precede certificate generation" >&2
  exit 1
fi
if ! awk \
  '/^ExecStartPre=.*gateway-migrate-config / { migrated = 1 } \
   /^ExecStartPre=\/usr\/bin\/openshell-gateway config preflight$/ { preflight = migrated } \
   /^ExecStartPre=\/usr\/bin\/openshell-gateway generate-certs/ { exit !(preflight && migrated) }' \
  "$spec"; then
  echo "FAIL: RPM migration and preflight must precede certificate generation" >&2
  exit 1
fi

# Build a throwaway package when Debian tooling is available to prove the
# staged unit comes from deploy/deb/. Other hosts retain the static source-to-
# destination assertion above; the real Debian upgrade lane remains required.
if command -v dpkg-deb >/dev/null 2>&1; then
  package_work=$(mktemp -d "${TMPDIR:-/tmp}/openshell-package-assets.XXXXXX")
  trap 'rm -rf "$package_work"' EXIT
  mkdir -p "$package_work/bin" "$package_work/output"
  for binary in openshell openshell-gateway openshell-prover openshell-driver-vm; do
    printf '#!/bin/sh\nexit 0\n' >"$package_work/bin/$binary"
    chmod +x "$package_work/bin/$binary"
  done
  OPENSHELL_CLI_BINARY="$package_work/bin/openshell" \
    OPENSHELL_GATEWAY_BINARY="$package_work/bin/openshell-gateway" \
    OPENSHELL_PROVER_BINARY="$package_work/bin/openshell-prover" \
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
  if ! dpkg-deb --fsys-tarfile "$package_work/output/openshell_0.0.0_amd64.deb" \
    | tar -tf - | grep -x './usr/bin/openshell-prover' >/dev/null; then
    echo "FAIL: package-deb did not stage openshell-prover" >&2
    exit 1
  fi
else
  echo "SKIP: dpkg-deb unavailable; Debian artifact staging requires its assigned lane"
fi

echo "packaging asset tests passed"
