# syntax=docker/dockerfile:1

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

ARG RYNO_SANDBOX_BASE_IMAGE=nvcr.io/nvidia/base/ubuntu:24.04

FROM ${RYNO_SANDBOX_BASE_IMAGE}

USER root
COPY workload.sh /usr/local/bin/ryno-gpu-workload
RUN chmod 0755 /usr/local/bin/ryno-gpu-workload

USER 1000:1000
ENTRYPOINT ["/usr/local/bin/ryno-gpu-workload"]
