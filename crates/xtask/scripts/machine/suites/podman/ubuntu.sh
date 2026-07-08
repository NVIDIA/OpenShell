#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

echo "==> Installing rootless Podman on Ubuntu"
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
	ca-certificates \
	curl \
	podman
