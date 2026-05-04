#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Build the openshell Debian package by staging pre-built binaries alongside
# the authoring tree under deploy/deb/, then invoking dpkg-deb --build.
#
# All static content (systemd unit, /etc/default file, maintainer scripts,
# default gateway metadata, control template) lives under deploy/deb/. This
# script only renders the version/arch into control.in and copies files into
# the package staging tree.

set -euo pipefail

APP_NAME="openshell"

usage() {
	cat <<'EOF'
Build the openshell Debian package.

Required environment:
  OPENSHELL_CLI_BINARY        Path to openshell
  OPENSHELL_GATEWAY_BINARY    Path to openshell-gateway
  OPENSHELL_DRIVER_VM_BINARY  Path to openshell-driver-vm
  OPENSHELL_DEB_VERSION       Debian package version

Optional environment:
  OPENSHELL_DEB_ARCH          Debian architecture (amd64 or arm64; defaults to host arch)
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

stage_binary() {
	local src="$1"
	local dst="$2"
	if [ ! -x "$src" ]; then
		echo "error: binary is missing or not executable: ${src}" >&2
		exit 1
	fi
	mkdir -p "$(dirname "$dst")"
	install -m 0755 "$src" "$dst"
}

infer_deb_arch() {
	if command -v dpkg >/dev/null 2>&1; then
		dpkg --print-architecture
		return
	fi

	case "$(uname -m)" in
	x86_64 | amd64) echo "amd64" ;;
	aarch64 | arm64) echo "arm64" ;;
	*) uname -m ;;
	esac
}

# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

require_env OPENSHELL_CLI_BINARY
require_env OPENSHELL_GATEWAY_BINARY
require_env OPENSHELL_DRIVER_VM_BINARY
require_env OPENSHELL_DEB_VERSION

OPENSHELL_DEB_ARCH="${OPENSHELL_DEB_ARCH:-$(infer_deb_arch)}"

case "$OPENSHELL_DEB_ARCH" in
amd64 | arm64) ;;
*)
	echo "error: OPENSHELL_DEB_ARCH must be amd64 or arm64, got ${OPENSHELL_DEB_ARCH}" >&2
	exit 2
	;;
esac

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
src_dir="${repo_root}/deploy/deb"
output_dir_input="${OPENSHELL_OUTPUT_DIR:-artifacts}"
case "$output_dir_input" in
/*) output_dir="$output_dir_input" ;;
*) output_dir="${repo_root}/${output_dir_input}" ;;
esac
mkdir -p "$output_dir"

if [ ! -d "$src_dir" ]; then
	echo "error: deb source directory not found: ${src_dir}" >&2
	exit 1
fi

package_file="${output_dir}/${APP_NAME}_${OPENSHELL_DEB_VERSION}_${OPENSHELL_DEB_ARCH}.deb"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

pkgroot="${tmpdir}/pkg"
mkdir -p "$pkgroot/DEBIAN"

# ---------------------------------------------------------------------------
# Stage the package payload
# ---------------------------------------------------------------------------

# Binaries.
stage_binary "$OPENSHELL_CLI_BINARY"       "$pkgroot/usr/bin/openshell"
stage_binary "$OPENSHELL_GATEWAY_BINARY"   "$pkgroot/usr/bin/openshell-gateway"
stage_binary "$OPENSHELL_DRIVER_VM_BINARY" "$pkgroot/usr/libexec/openshell/openshell-driver-vm"

# Per-user systemd unit. Each user enables it via `systemctl --user`.
install -D -m 0644 "$src_dir/openshell-gateway.service" \
	"$pkgroot/usr/lib/systemd/user/openshell-gateway.service"

# ---------------------------------------------------------------------------
# DEBIAN/ control directory
# ---------------------------------------------------------------------------

# Render control from template.
sed \
	-e "s|@VERSION@|${OPENSHELL_DEB_VERSION}|g" \
	-e "s|@ARCH@|${OPENSHELL_DEB_ARCH}|g" \
	"$src_dir/control.in" >"$pkgroot/DEBIAN/control"

# No conffiles: the package owns no /etc files. Per-user configuration
# lives under $XDG_CONFIG_HOME/openshell/.

# Maintainer scripts.
install -m 0755 "$src_dir/postinst.sh" "$pkgroot/DEBIAN/postinst"
install -m 0755 "$src_dir/prerm.sh"    "$pkgroot/DEBIAN/prerm"
install -m 0755 "$src_dir/postrm.sh"   "$pkgroot/DEBIAN/postrm"

# ---------------------------------------------------------------------------
# Documentation
# ---------------------------------------------------------------------------

doc_dir="$pkgroot/usr/share/doc/openshell"
mkdir -p "$doc_dir"

if [ -f "${repo_root}/LICENSE" ]; then
	install -m 0644 "${repo_root}/LICENSE" "$doc_dir/copyright"
else
	cat >"$doc_dir/copyright" <<'EOF'
OpenShell is distributed under the Apache-2.0 license.
EOF
	chmod 0644 "$doc_dir/copyright"
fi

# Real RFC2822 date so lintian doesn't complain about epoch-zero changelogs.
gzip -n -9 -c >"$doc_dir/changelog.gz" <<EOF
openshell (${OPENSHELL_DEB_VERSION}) unstable; urgency=medium

  * Release build.

 -- NVIDIA OpenShell Maintainers <openshell@nvidia.com>  $(date -uR)
EOF

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

dpkg-deb --build --root-owner-group "$pkgroot" "$package_file"
dpkg-deb --info "$package_file"
dpkg-deb --contents "$package_file"

# ---------------------------------------------------------------------------
# Smoke tests
# ---------------------------------------------------------------------------

extract_dir="${tmpdir}/extract"
mkdir -p "$extract_dir"
dpkg-deb -x "$package_file" "$extract_dir"
"$extract_dir/usr/bin/openshell" --version
"$extract_dir/usr/bin/openshell-gateway" --version
"$extract_dir/usr/libexec/openshell/openshell-driver-vm" --version

if command -v systemd-analyze >/dev/null 2>&1; then
	# verify --user catches user-scope-specific issues like StateDirectory=
	# resolution and the %h/%S specifiers used in this unit.
	systemd-analyze --user verify "$extract_dir/usr/lib/systemd/user/openshell-gateway.service" \
		|| echo "warning: systemd-analyze verify failed in the build environment" >&2
fi

echo "Wrote ${package_file}"
