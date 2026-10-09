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
package_qualification="${ROOT}/tests/ansible/roles/openshell_packaged_gateway/tasks/main.yaml"
tmachine_gateway_service="${ROOT}/tests/ansible/roles/openshell_gateway/templates/gateway.service.j2"
tmachine_docker_config="${ROOT}/tests/ansible/roles/openshell_gateway/templates/gateway-docker.toml.j2"
tmachine_podman_config="${ROOT}/tests/ansible/roles/openshell_gateway/templates/gateway-podman.toml.j2"
development_gateway="${ROOT}/nix/test-guest/provisioners/roles/gateway-podman/tasks/development-gateway.yml"

assert_file_exists "$service"
assert_file_exists "$control"
assert_file_exists "$spec"
assert_file_exists "$package_qualification"
assert_file_exists "$tmachine_gateway_service"
assert_file_exists "$tmachine_docker_config"
assert_file_exists "$tmachine_podman_config"
assert_file_exists "$development_gateway"

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
assert_contains "$service" 'EnvironmentFile=-%E/openshell/gateway.env'
assert_contains "$service" 'ExecStart=/usr/bin/openshell-gateway'
assert_contains \
  "$service" \
  'ExecStartPre=/usr/bin/openshell-gateway generate-certs --output-dir ${OPENSHELL_LOCAL_TLS_DIR} --server-san host.openshell.internal'
assert_not_contains "$service" '%S/openshell/tls'

assert_contains \
  "$spec" \
  'Environment=OPENSHELL_LOCAL_TLS_DIR=%%h/.local/state/openshell/tls'
assert_contains "$spec" 'EnvironmentFile=-%%E/openshell/gateway.env'
assert_contains "$spec" 'ExecStart=/usr/bin/openshell-gateway'
assert_contains \
  "$spec" \
  'ExecStartPre=/usr/bin/openshell-gateway generate-certs --output-dir ${OPENSHELL_LOCAL_TLS_DIR} --server-san host.openshell.internal'
assert_contains "$spec" 'ExecStartPre=/usr/bin/openshell-gateway config preflight'
assert_contains "$spec" '%package prover'
assert_contains "$spec" '%files prover'
assert_contains "$spec" '%{_bindir}/%{name}-prover'
assert_not_contains "$spec" '%%S/openshell/tls'

# Installed-package qualification must select the candidate trusted runtime
# images through the same environment file consumed by preflight and startup,
# without generating operator-owned gateway TOML.
assert_contains "$package_qualification" 'dest: "{{ openshell_gateway_home }}/.config/openshell/gateway.env"'
assert_contains "$package_qualification" 'OPENSHELL_COMPUTE_DRIVER={{ openshell_gateway_driver }}'
assert_contains "$package_qualification" 'OPENSHELL_SANDBOX_RUNTIME_IMAGE=docker.io/openshell/sandbox:tmachine'
assert_contains "$package_qualification" 'OPENSHELL_SUPERVISOR_IMAGE=docker.io/openshell/supervisor:tmachine'
assert_not_contains "$package_qualification" 'OPENSHELL_GATEWAY_CONFIG='
assert_not_contains "$package_qualification" '/var/lib/openshell-qualification/gateway.toml'

# Direct tmachine gateway services select trusted runtime images through the
# process environment. Driver TOML remains available for settings that do not
# have a gateway startup environment variable.
assert_contains "$tmachine_gateway_service" 'Environment=OPENSHELL_SANDBOX_RUNTIME_IMAGE=docker.io/openshell/sandbox:tmachine'
assert_contains "$tmachine_gateway_service" 'Environment=OPENSHELL_SUPERVISOR_IMAGE=docker.io/openshell/supervisor:tmachine'
assert_not_contains "$tmachine_docker_config" 'sandbox_runtime_image ='
assert_not_contains "$tmachine_docker_config" 'supervisor_image ='
assert_not_contains "$tmachine_podman_config" 'sandbox_runtime_image ='
assert_not_contains "$tmachine_podman_config" 'supervisor_image ='
assert_contains "$development_gateway" 'Environment=OPENSHELL_SUPERVISOR_IMAGE={{ openshell_supervisor_image }}'
assert_not_contains "$development_gateway" 'supervisor_image = "{{ openshell_supervisor_image }}"'

# Schema-v2 package startup wiring.
snap_wrapper="${ROOT}/tasks/scripts/snap-gateway-wrapper.sh"
snapcraft="${ROOT}/snapcraft.yaml"
snap_workflow="${ROOT}/.github/workflows/snap-package.yml"
snap_install_docs="${ROOT}/docs/about/installation.mdx"
snap_canary="${ROOT}/.github/workflows/release-canary.yml"
snap_configure_hook="${ROOT}/snap/hooks/configure"
snap_install_hook="${ROOT}/snap/hooks/install"
snap_post_refresh_hook="${ROOT}/snap/hooks/post-refresh"
package_deb="${ROOT}/tasks/scripts/package-deb.sh"
assert_file_exists "$snap_wrapper"
assert_file_exists "$snapcraft"
assert_file_exists "$snap_workflow"
assert_file_exists "$snap_install_docs"
assert_file_exists "$snap_canary"
assert_file_exists "$snap_configure_hook"
assert_file_exists "$snap_install_hook"
assert_file_exists "$snap_post_refresh_hook"
assert_file_exists "$package_deb"
assert_contains "$service" "ExecStartPre=/usr/bin/openshell-gateway config preflight"
assert_contains "$package_deb" "\$src_dir/openshell-gateway.service"
assert_contains "$package_deb" "\$pkgroot/usr/lib/systemd/user/openshell-gateway.service"
assert_contains "$snap_wrapper" '[ -z "${OPENSHELL_GATEWAY_CONFIG:-}" ]'
assert_contains "$snap_wrapper" '[ -e "$OPENSHELL_SNAP_CONFIG_FILE" ] || [ -L "$OPENSHELL_SNAP_CONFIG_FILE" ]'
assert_contains "$snap_wrapper" 'export OPENSHELL_GATEWAY_CONFIG="$OPENSHELL_SNAP_CONFIG_FILE"'
assert_contains "$snap_wrapper" 'config preflight -- "$@"'
assert_not_contains "$snap_wrapper" "CANONICAL_CONFIG_FILE"
bash "$ROOT/tasks/scripts/test-snap-gateway-wrapper.sh" "$snap_wrapper"

# Store installs autoconnect all required interfaces and require snapd 2.76 for
# the system Docker slot. Manual connection for locally-built snaps requires
# snapd 2.77.
assert_contains "$snapcraft" "assumes: [snapd2.76]"
for snap_file in \
  "$snapcraft" \
  "$snap_install_docs" \
  "$snap_canary" \
  "$snap_configure_hook" \
  "$snap_install_hook" \
  "$snap_post_refresh_hook"; do
  assert_not_contains "$snap_file" "docker:docker-daemon"
  assert_not_contains "$snap_file" "default-provider: docker"
done
if [[ -e "${ROOT}/snap/hooks/connect-plug-docker" ]]; then
  echo "FAIL: obsolete Snap Docker connection hook must not exist" >&2
  exit 1
fi
if [[ ! -x "$snap_install_hook" ]]; then
  echo "FAIL: Snap install hook must be executable" >&2
  exit 1
fi
if [[ ! -x "$snap_configure_hook" ]]; then
  echo "FAIL: Snap configure hook must be executable" >&2
  exit 1
fi
assert_contains "$snapcraft" 'daemon-scope: system'
assert_contains "$snapcraft" 'daemon-scope: user'
assert_contains "$snapcraft" 'install-mode: disable'
assert_not_contains "$snapcraft" 'install-mode: enable'
if grep -Eq '^  gateway:$' "$snapcraft"; then
  echo "FAIL: removed Snap gateway app must not remain declared" >&2
  exit 1
fi
assert_contains "$snapcraft" '  system-gateway:'
assert_contains "$snapcraft" '  user-gateway:'
assert_contains "$snapcraft" 'OPENSHELL_SNAP_CONFIG_FILE: "$SNAP_COMMON/gateway.toml"'
assert_contains "$snapcraft" 'OPENSHELL_DB_URL: "sqlite:$SNAP_COMMON/gateway.db?mode=rwc"'
assert_contains "$snapcraft" 'OPENSHELL_LOCAL_TLS_DIR: "$SNAP_COMMON/tls"'
assert_not_contains "$snapcraft" 'XDG_RUNTIME_DIR:'
assert_not_contains "$snapcraft" 'OPENSHELL_SNAP_CONFIG_FILE: "$SNAP_USER_COMMON'
assert_not_contains "$snapcraft" 'OPENSHELL_DB_URL: "sqlite:$SNAP_USER_COMMON'
assert_not_contains "$snapcraft" 'OPENSHELL_LOCAL_TLS_DIR: "$SNAP_USER_COMMON'
assert_contains "$snapcraft" 'refresh-mode: endure'
if [[ ! -x "$snap_post_refresh_hook" ]]; then
  echo "FAIL: Snap post-refresh hook must be executable" >&2
  exit 1
fi
assert_not_contains "$ROOT/tasks/scripts/snap-gateway-wrapper.sh" 'OPENSHELL_DISABLE_TLS'
bash "$ROOT/tasks/scripts/test-snap-configure-hook.sh" "$snap_configure_hook"
bash "$ROOT/tasks/scripts/test-snap-install-hook.sh" "$snap_install_hook"
bash "$ROOT/tasks/scripts/test-snap-post-refresh-hook.sh" "$snap_post_refresh_hook"
assert_contains "$snap_workflow" 'name: openshell-prover-${{ matrix.rust_arch }}-unknown-linux-musl'
assert_contains "$snap_workflow" 'chmod +x prebuilt/prover/openshell-prover'
assert_contains "$snap_workflow" 'cp prebuilt/prover/openshell-prover snap/prebuilt/openshell-prover'
assert_contains "$snapcraft" 'for bin in openshell openshell-prover openshell-gateway openshell-sandbox openshell-gateway-wrapper; do'
assert_contains "$snapcraft" '"$CRAFT_PART_INSTALL/bin/openshell-prover"'
if ! awk '
  /^  prover:$/ { in_prover = 1; next }
  in_prover && /^  [[:alnum:]_-]+:$/ { finished = 1; exit }
  in_prover && /command: bin\/openshell-prover/ { command = 1 }
  in_prover && /- openshell-prover/ { alias = 1 }
  in_prover && /^    plugs:$/ { in_plugs = 1; next }
  in_prover && in_plugs && /^      - / {
    plug_count++
    if ($0 == "      - home") home = 1
  }
  END { exit !(in_prover && finished && command && alias && home && plug_count == 1) }
' "$snapcraft"; then
  echo "FAIL: Snap prover app must expose the openshell-prover alias with only home access" >&2
  exit 1
fi
assert_not_contains "$snap_install_docs" "snap connect openshell:home"
assert_not_contains "$snap_install_docs" "snap connect openshell:network"
assert_not_contains "$snap_install_docs" "snap connect openshell:network-bind"
assert_contains "$snap_install_docs" "snap connect openshell:docker :docker"
assert_contains "$snap_install_docs" "systemctl --user reset-failed snap.openshell.user-gateway.service"
assert_contains "$snap_install_docs" "snap start --user openshell.user-gateway"
assert_contains "$snapcraft" "snap start --user openshell.user-gateway"
assert_contains "$snap_install_docs" "openshell.user-gateway"
assert_contains "$snap_install_docs" "openshell.system-gateway"
assert_contains "$snap_install_docs" "Existing HTTPS registrations continue to work"
assert_contains "$snapcraft" "Existing HTTPS registrations"
assert_contains "$snap_install_docs" "/var/snap/openshell/common/tls"
assert_contains "$snap_install_docs" 'old_registration="NAME_FROM_GATEWAY_LIST"'
assert_contains "$snap_install_docs" 'openshell gateway remove "$old_registration"'
assert_contains "$snap_install_docs" "openshell gateway add https://127.0.0.1:17670 --local --name openshell"
assert_contains "$snap_install_docs" "sudo snap set openshell gateway-mode=disable"
assert_contains "$snap_install_docs" 'tls-backup-$(date +%s%N)'
assert_contains "$snap_install_docs" "sudo snap set openshell gateway-mode=user"
assert_contains "$snap_install_docs" "sudo snap set openshell gateway-mode=system"
assert_contains "$snapcraft" "gateway-mode=disable"
assert_not_contains "$snap_install_docs" "snap services --user"
assert_contains "$snap_canary" "install.sh | sh"
assert_contains "$snap_canary" "ubuntu-snap-system-docker:"
assert_contains "$snap_canary" "ubuntu-snap-docker-preflight:"
assert_contains "$snap_canary" "openshell.prover check"
assert_not_contains "$snap_canary" "--dangerous"
assert_not_contains "$snap_canary" "snap connect openshell:docker"
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
