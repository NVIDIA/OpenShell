#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run the Podman e2e suite and verify rootless mode.
#
# Identical to e2e-podman.sh but fails fast if Podman is not running
# rootless. Use this to explicitly validate the rootless networking
# path (pasta, host-gateway, bind address).

set -euo pipefail

rootless="$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || true)"
if [ "${rootless}" != "true" ]; then
  echo "ERROR: podman is not running rootless; expected true, got '${rootless:-<empty>}'" >&2
  exit 2
fi

exec "$(dirname "${BASH_SOURCE[0]}")/e2e-podman.sh"
