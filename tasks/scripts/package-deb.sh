#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

APP_NAME="openshell"
MAINTAINER="NVIDIA OpenShell Maintainers"
HOMEPAGE="https://github.com/NVIDIA/OpenShell"

usage() {
  cat <<'EOF'
Package OpenShell binaries into a Debian package.

Required environment:
  OPENSHELL_CLI_BINARY        Path to openshell
  OPENSHELL_GATEWAY_BINARY    Path to openshell-gateway
  OPENSHELL_DRIVER_VM_BINARY  Path to openshell-driver-vm
  OPENSHELL_DEB_VERSION       Debian package version
  OPENSHELL_DEB_ARCH          Debian architecture (amd64 or arm64)

Optional environment:
  OPENSHELL_OUTPUT_DIR        Output directory (default: artifacts)
EOF
}

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "error: ${name} is required" >&2
    usage >&2
    exit 2
  fi
}

install_binary() {
  local src="$1"
  local dst="$2"
  if [ ! -x "$src" ]; then
    echo "error: binary is missing or not executable: ${src}" >&2
    exit 1
  fi
  mkdir -p "$(dirname "$dst")"
  install -m 0755 "$src" "$dst"
}

require_env OPENSHELL_CLI_BINARY
require_env OPENSHELL_GATEWAY_BINARY
require_env OPENSHELL_DRIVER_VM_BINARY
require_env OPENSHELL_DEB_VERSION
require_env OPENSHELL_DEB_ARCH

case "$OPENSHELL_DEB_ARCH" in
  amd64|arm64) ;;
  *)
    echo "error: OPENSHELL_DEB_ARCH must be amd64 or arm64, got ${OPENSHELL_DEB_ARCH}" >&2
    exit 2
    ;;
esac

output_dir="${OPENSHELL_OUTPUT_DIR:-artifacts}"
package_file="${output_dir}/${APP_NAME}_${OPENSHELL_DEB_VERSION}_${OPENSHELL_DEB_ARCH}.deb"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

pkgroot="${tmpdir}/pkg"
mkdir -p "$pkgroot/DEBIAN" "$output_dir"

install_binary "$OPENSHELL_CLI_BINARY" "$pkgroot/usr/bin/openshell"
install_binary "$OPENSHELL_GATEWAY_BINARY" "$pkgroot/usr/bin/openshell-gateway"
install_binary "$OPENSHELL_DRIVER_VM_BINARY" "$pkgroot/usr/libexec/openshell/openshell-driver-vm"

mkdir -p "$pkgroot/usr/lib/systemd/system"
cat > "$pkgroot/usr/lib/systemd/system/openshell-gateway.service" <<'EOF'
[Unit]
Description=OpenShell Gateway
Documentation=https://github.com/NVIDIA/OpenShell
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=openshell
Group=openshell
EnvironmentFile=/etc/default/openshell-gateway
StateDirectory=openshell/gateway
WorkingDirectory=/var/lib/openshell/gateway
ExecStart=/usr/bin/openshell-gateway
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$pkgroot/usr/lib/systemd/system/openshell-gateway.service"

mkdir -p "$pkgroot/etc/default"
cat > "$pkgroot/etc/default/openshell-gateway" <<'EOF'
# OpenShell gateway systemd environment.
#
# The packaged service is disabled by default. Review these settings before
# running: sudo systemctl enable --now openshell-gateway

# Bind to loopback for packaged plaintext service startup. Change this only
# when the host has an explicit access-control boundary such as firewall rules
# or a reverse proxy.
OPENSHELL_BIND_ADDRESS=127.0.0.1
OPENSHELL_SERVER_PORT=8080

# Local gateway state.
OPENSHELL_DB_URL=sqlite:/var/lib/openshell/gateway/openshell.db
OPENSHELL_DRIVER_DIR=/usr/libexec/openshell

# The packaged service starts without TLS. To enable TLS, set this to false and
# provide OPENSHELL_TLS_CERT, OPENSHELL_TLS_KEY, and OPENSHELL_TLS_CLIENT_CA.
OPENSHELL_DISABLE_TLS=true

# Configure the compute driver for this host. The packaged service defaults to
# docker so it can start locally without TLS or an SSH handshake secret.
# Examples: docker, kubernetes, podman, vm.
OPENSHELL_DRIVERS=docker

# Non-docker drivers require a shared SSH handshake secret.
# OPENSHELL_SSH_HANDSHAKE_SECRET=

# Set when sandbox workers must call back to this gateway through a specific
# address, for example http://127.0.0.1:8080 in local plaintext deployments.
# OPENSHELL_GRPC_ENDPOINT=http://127.0.0.1:8080

# TLS settings used when OPENSHELL_DISABLE_TLS=false.
# OPENSHELL_TLS_CERT=/etc/openshell/gateway/tls.crt
# OPENSHELL_TLS_KEY=/etc/openshell/gateway/tls.key
# OPENSHELL_TLS_CLIENT_CA=/etc/openshell/gateway/client-ca.crt
EOF
chmod 0644 "$pkgroot/etc/default/openshell-gateway"

mkdir -p "$pkgroot/etc/openshell/gateways/default"
cat > "$pkgroot/etc/openshell/active_gateway" <<'EOF'
default
EOF
chmod 0644 "$pkgroot/etc/openshell/active_gateway"

cat > "$pkgroot/etc/openshell/gateways/default/metadata.json" <<'EOF'
{
  "name": "default",
  "gateway_endpoint": "http://127.0.0.1:8080",
  "is_remote": false,
  "gateway_port": 8080,
  "auth_mode": "plaintext"
}
EOF
chmod 0644 "$pkgroot/etc/openshell/gateways/default/metadata.json"

cat > "$pkgroot/DEBIAN/control" <<EOF
Package: ${APP_NAME}
Version: ${OPENSHELL_DEB_VERSION}
Architecture: ${OPENSHELL_DEB_ARCH}
Maintainer: ${MAINTAINER}
Section: utils
Priority: optional
Homepage: ${HOMEPAGE}
Description: OpenShell CLI for safe, sandboxed AI agent runtimes
 OpenShell provides host-side command-line and gateway components for
 launching and managing policy-enforced AI agent sandboxes.
EOF

cat > "$pkgroot/DEBIAN/conffiles" <<'EOF'
/etc/default/openshell-gateway
/etc/openshell/active_gateway
/etc/openshell/gateways/default/metadata.json
EOF

cat > "$pkgroot/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

if ! getent group openshell >/dev/null 2>&1; then
  if command -v addgroup >/dev/null 2>&1; then
    addgroup --system openshell
  else
    groupadd --system openshell
  fi
fi

if ! id openshell >/dev/null 2>&1; then
  if command -v adduser >/dev/null 2>&1; then
    adduser --system --ingroup openshell --home /var/lib/openshell --no-create-home --shell /usr/sbin/nologin openshell
  else
    useradd --system --gid openshell --home-dir /var/lib/openshell --shell /usr/sbin/nologin openshell
  fi
fi

mkdir -p /var/lib/openshell/gateway
chown openshell:openshell /var/lib/openshell /var/lib/openshell/gateway
chmod 0750 /var/lib/openshell /var/lib/openshell/gateway

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi

exit 0
EOF
chmod 0755 "$pkgroot/DEBIAN/postinst"

cat > "$pkgroot/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload || true
fi

exit 0
EOF
chmod 0755 "$pkgroot/DEBIAN/postrm"

license_file="LICENSE"
if [ -f "$license_file" ]; then
  mkdir -p "$pkgroot/usr/share/doc/openshell"
  install -m 0644 "$license_file" "$pkgroot/usr/share/doc/openshell/copyright"
else
  mkdir -p "$pkgroot/usr/share/doc/openshell"
  cat > "$pkgroot/usr/share/doc/openshell/copyright" <<'EOF'
OpenShell is distributed under the Apache-2.0 license.
EOF
  chmod 0644 "$pkgroot/usr/share/doc/openshell/copyright"
fi

gzip -n -9 -c > "$pkgroot/usr/share/doc/openshell/changelog.gz" <<EOF
openshell (${OPENSHELL_DEB_VERSION}) unstable; urgency=medium

  * Release package build.

 -- ${MAINTAINER}  Thu, 01 Jan 1970 00:00:00 +0000
EOF

dpkg-deb --build --root-owner-group "$pkgroot" "$package_file"
dpkg-deb --info "$package_file"
dpkg-deb --contents "$package_file"

extract_dir="${tmpdir}/extract"
mkdir -p "$extract_dir"
dpkg-deb -x "$package_file" "$extract_dir"
"$extract_dir/usr/bin/openshell" --version
"$extract_dir/usr/bin/openshell-gateway" --version
"$extract_dir/usr/libexec/openshell/openshell-driver-vm" --version

if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze verify "$extract_dir/usr/lib/systemd/system/openshell-gateway.service" || {
    echo "warning: systemd-analyze verify failed in the build environment" >&2
  }
fi

echo "Wrote ${package_file}"
