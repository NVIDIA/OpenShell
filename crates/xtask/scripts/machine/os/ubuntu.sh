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

if [ "${ID:-}" != "ubuntu" ]; then
	echo "expected an Ubuntu guest, found ${ID:-unknown}" >&2
	exit 1
fi

echo "==> Preparing Ubuntu ${VERSION_ID:-unknown}"
sudo apt-get update
