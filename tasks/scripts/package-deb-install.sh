#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Build Ryno from source and install the resulting Debian package
# locally for testing. Intended for developers iterating on the deb itself
# or on the gateway-as-a-service flow.
#
# Steps:
#   1. cargo build --release the four binaries that go into the deb.
#   2. Run tasks/scripts/package-deb.sh against those binaries.
#   3. sudo dpkg -i the resulting artifact.
#   4. Start the packaged user gateway service and register it locally.
#
# Usage:
#   mise run package:deb:install
#
# Optional env:
#   RYNO_DEB_VERSION   override the package version (default: 0.0.0-local)
#   RYNO_DEB_ARCH      override the deb architecture (default: host)
#   RYNO_OUTPUT_DIR    override the artifact directory (default: artifacts)

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo_root"

VERSION="${RYNO_DEB_VERSION:-0.0.0-local}"
OUTPUT_DIR="${RYNO_OUTPUT_DIR:-artifacts}"
ARCH="${RYNO_DEB_ARCH:-$(dpkg --print-architecture 2>/dev/null || uname -m)}"
GATEWAY_NAME="ryno"
GATEWAY_ENDPOINT="https://127.0.0.1:17670"

remove_existing_gateway_registration() {
	local config_home="${XDG_CONFIG_HOME:-${HOME}/.config}"
	local ryno_config_dir="${config_home}/ryno"
	local gateway_dir="${ryno_config_dir}/gateways/${GATEWAY_NAME}"
	local active_gateway_path="${ryno_config_dir}/active_gateway"

	if [ ! -f "${gateway_dir}/metadata.json" ]; then
		return
	fi

	echo "==> Removing existing ${GATEWAY_NAME} gateway registration"
	rm -f \
		"${gateway_dir}/metadata.json" \
		"${gateway_dir}/edge_token" \
		"${gateway_dir}/cf_token" \
		"${gateway_dir}/oidc_token.json"

	if [ -f "$active_gateway_path" ] && [ "$(cat "$active_gateway_path")" = "$GATEWAY_NAME" ]; then
		rm -f "$active_gateway_path"
	fi
}

echo "==> Building release binaries"
cargo build --release \
	-p ryno-cli \
	-p ryno-gateway \
	-p ryno-prover-cli \
	-p ryno-driver-vm

echo "==> Building Debian package"
RYNO_CLI_BINARY="${repo_root}/target/release/ryno" \
	RYNO_GATEWAY_BINARY="${repo_root}/target/release/ryno-gateway" \
	RYNO_PROVER_BINARY="${repo_root}/target/release/ryno-prover" \
	RYNO_DRIVER_VM_BINARY="${repo_root}/target/release/ryno-driver-vm" \
	RYNO_DEB_VERSION="$VERSION" \
	RYNO_DEB_ARCH="$ARCH" \
	RYNO_OUTPUT_DIR="$OUTPUT_DIR" \
	"${repo_root}/tasks/scripts/package-deb.sh"

deb_path="${OUTPUT_DIR}/ryno_${VERSION}_${ARCH}.deb"
case "$deb_path" in
/*) ;;
*) deb_path="${repo_root}/${deb_path}" ;;
esac

echo "==> Installing ${deb_path}"
sudo dpkg -i "$deb_path"

ryno --version
ryno-gateway --version
ryno-prover --version

echo "==> Starting user gateway service"
systemctl --user daemon-reload
systemctl --user enable --now ryno-gateway
systemctl --user is-active --quiet ryno-gateway

echo "==> Registering local gateway"
remove_existing_gateway_registration
ryno gateway add "$GATEWAY_ENDPOINT" --local --name "$GATEWAY_NAME"
