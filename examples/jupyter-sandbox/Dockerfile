# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/astral-sh/uv:0.11.28 AS uv
FROM python:3.13-slim

COPY --from=uv /uv /uvx /bin/

# OpenShell requires iproute2 for network isolation. nftables enables bypass
# detection, while procps is useful for inspecting the notebook processes.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates iproute2 nftables procps \
    && rm -rf /var/lib/apt/lists/*

RUN uv pip install --system --no-cache \
        jupyter-server==2.20.0 \
        ipykernel==7.3.0

RUN groupadd --gid 1000 sandbox \
    && useradd --uid 1000 --gid sandbox --home-dir /sandbox \
        --no-create-home --shell /bin/sh sandbox \
    && install -d -o sandbox -g sandbox /sandbox
WORKDIR /sandbox

EXPOSE 8888

# OpenShell replaces the image command with the sandbox supervisor. The
# example starts Jupyter after sandbox creation through the Python SDK.
