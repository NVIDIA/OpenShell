#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

echo "==> Configuring rootless Podman"
containers_config_dir="${HOME}/.config/containers"
containers_config_drop_in_dir="${containers_config_dir}/containers.conf.d"
mkdir -p "${containers_config_dir}" "${containers_config_drop_in_dir}"
cat >"${containers_config_dir}/containers.conf" <<'EOF'
[containers]
# Use file-backed logs so Docker-compatible log reads work reliably.
log_driver = "k8s-file"

[engine]
# Use file-backed events so open Libpod streams receive lifecycle events reliably.
events_logger = "file"
EOF
# CentOS Stream ships a containers.conf.d vendor fragment that selects
# journald after the regular user configuration has been merged. A later user
# drop-in overrides it; keeping the regular file also supports older Podman
# releases that do not load per-user drop-ins.
install -m 0644 \
	"${containers_config_dir}/containers.conf" \
	"${containers_config_drop_in_dir}/99-openshell.conf"

echo "==> Enabling the rootless Podman socket"
sudo loginctl enable-linger "$USER"
systemctl --user daemon-reload
systemctl --user enable --now podman.socket
if ! systemctl --user is-active --quiet podman.socket; then
	echo "rootless Podman socket did not become active" >&2
	systemctl --user status --no-pager podman.socket >&2 || true
	exit 1
fi

require_podman_info() {
	local format="$1"
	local expected="$2"
	local description="$3"
	local actual

	if ! actual="$(podman info --format "${format}")"; then
		echo "could not inspect Podman ${description}" >&2
		podman info >&2 || true
		exit 1
	fi
	if [ "${actual}" != "${expected}" ]; then
		echo "expected Podman ${description} to be ${expected}, found ${actual:-<empty>}" >&2
		exit 1
	fi
}

require_podman_info '{{.Host.Security.Rootless}}' true "rootless mode"
require_podman_info '{{.Host.LogDriver}}' k8s-file "log driver"
require_podman_info '{{.Host.EventLogger}}' file "event logger"
