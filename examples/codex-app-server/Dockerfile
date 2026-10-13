# syntax=docker/dockerfile:1.7

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        nodejs \
        npm \
    && rm -rf /var/lib/apt/lists/*

RUN useradd \
    --create-home \
    --home-dir /sandbox \
    --shell /bin/bash \
    sandbox

RUN npm install --global --force "@openai/codex@latest" \
    && npm cache clean --force \
    && codex --version

COPY --chmod=0755 start-codex-app-server /usr/local/bin/start-codex-app-server

ENV CODEX_APP_SERVER_PORT=4500
ENV HOME=/sandbox

USER sandbox
WORKDIR /sandbox
