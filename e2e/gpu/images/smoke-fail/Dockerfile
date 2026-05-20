# syntax=docker/dockerfile:1

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

ARG OPENSHELL_SANDBOX_BASE_IMAGE=ghcr.io/nvidia/openshell-community/sandboxes/base:latest

FROM ${OPENSHELL_SANDBOX_BASE_IMAGE}

USER root
COPY workload.sh /usr/local/bin/openshell-gpu-workload
RUN chmod 0755 /usr/local/bin/openshell-gpu-workload

USER sandbox
ENTRYPOINT ["/usr/local/bin/openshell-gpu-workload"]
