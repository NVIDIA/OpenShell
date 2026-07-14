#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

install_ubuntu() {
	echo "==> Installing rootless Podman on Ubuntu"
	sudo apt-get update
	sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
		ca-certificates \
		curl \
		podman
}

enable_rootless_podman_socket() {
	echo "==> Enabling the rootless Podman socket"
	sudo loginctl enable-linger "$USER"
	systemctl --user daemon-reload
	systemctl --user enable --now podman.socket
	systemctl --user is-active --quiet podman.socket
	test "$(podman info --format '{{.Host.Security.Rootless}}')" = true
}

if [ ! -r /etc/os-release ]; then
	echo "cannot detect guest OS: /etc/os-release is missing" >&2
	exit 1
fi

# shellcheck disable=SC1091
. /etc/os-release

# Add OS-specific package installation branches here as guest support expands.
case "${ID:-}" in
ubuntu)
	install_ubuntu
	;;
*)
	echo "unsupported guest OS for rootless Podman setup: ${ID:-unknown}" >&2
	exit 1
	;;
esac

enable_rootless_podman_socket
