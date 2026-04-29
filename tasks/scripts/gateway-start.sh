#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Dispatcher for `mise run gateway:start <driver>`.
#
# Usage:
#   mise run gateway:start             # uses $OPENSHELL_GATEWAY_DRIVER or 'docker'
#   mise run gateway:start docker
#   mise run gateway:start vm
#
# This is a thin shim that forwards to the driver-specific script. The
# `gateway:docker` / `gateway:vm` mise aliases call those scripts directly.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

DRIVER="${1:-${OPENSHELL_GATEWAY_DRIVER:-docker}}"

case "${DRIVER}" in
  docker)
    exec bash "${ROOT}/tasks/scripts/gateway-docker.sh"
    ;;
  vm)
    exec bash "${ROOT}/tasks/scripts/gateway-vm.sh"
    ;;
  *)
    echo "ERROR: unknown gateway driver '${DRIVER}' (expected 'docker' or 'vm')" >&2
    echo "Usage: mise run gateway:start <docker|vm>" >&2
    exit 2
    ;;
esac
