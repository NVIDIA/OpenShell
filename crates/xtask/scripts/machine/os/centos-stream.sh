#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

if [ ! -r /etc/os-release ]; then
	echo "cannot detect guest OS: /etc/os-release is missing" >&2
	exit 1
fi

# shellcheck disable=SC1091
. /etc/os-release

if [ "${ID:-}" != "centos" ] || [[ "${VERSION_ID:-}" != 10* ]]; then
	echo "expected a CentOS Stream 10 system, found ${PRETTY_NAME:-unknown}" >&2
	exit 1
fi

echo "==> Preparing ${PRETTY_NAME:-CentOS Stream 10}"
sudo dnf install -y \
	audit \
	libselinux-utils \
	policycoreutils

selinux_mode="$(getenforce)"
echo "==> SELinux mode: ${selinux_mode}"
if [ "${selinux_mode}" != "Enforcing" ]; then
	echo "SELinux must be Enforcing for the CentOS Stream 10 e2e target" >&2
	exit 1
fi

sudo systemctl enable auditd
if ! sudo systemctl is-active --quiet auditd; then
	sudo service auditd start
fi
sudo systemctl is-active --quiet auditd
