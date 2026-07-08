#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

echo "==> Installing OpenShell development dependencies on Ubuntu"
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
	build-essential \
	ca-certificates \
	clang \
	cmake \
	curl \
	git \
	jq \
	libclang-dev \
	libssl-dev \
	libz3-dev \
	musl-tools \
	openssh-client \
	pkg-config \
	python3 \
	python3-venv \
	rsync \
	socat \
	unzip \
	xz-utils \
	zstd
