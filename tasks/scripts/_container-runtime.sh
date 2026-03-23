#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Shared container runtime detection helper.
# Source this file to get CONTAINER_CMD set to "docker" or "podman".
#
# Override by setting CONTAINER_CMD in the environment before sourcing.

if [ -z "${CONTAINER_CMD:-}" ]; then
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        CONTAINER_CMD=docker
    elif command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
        CONTAINER_CMD=podman
    elif command -v docker >/dev/null 2>&1; then
        CONTAINER_CMD=docker
    elif command -v podman >/dev/null 2>&1; then
        CONTAINER_CMD=podman
    else
        echo "Error: neither docker nor podman found in PATH" >&2
        exit 1
    fi
fi

export CONTAINER_CMD
