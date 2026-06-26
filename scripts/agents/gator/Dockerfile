# syntax=docker/dockerfile:1

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Gator sandbox image.
#
# This mirrors the OpenShell Community base image's core system and developer
# tooling, but keeps the initial agent surface focused on Codex + GitHub tooling
# for the gator-gate workflow.

FROM nvcr.io/nvidia/base/ubuntu:noble-20251013 AS system

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /sandbox

# Core system dependencies copied from the community base sandbox image.
# iproute2: network namespace management (ip netns, veth pairs)
# iptables: legacy bypass detection (kept for transition)
# nftables: bypass detection; log + reject rules for direct connection diagnostics
# dnsutils: dig, nslookup
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dnsutils \
        iproute2 \
        iptables \
        nftables \
        iputils-ping \
        net-tools \
        netcat-openbsd \
        openssh-sftp-server \
        procps \
        traceroute \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r supervisor && useradd -r -g supervisor -s /usr/sbin/nologin supervisor && \
    groupadd -r sandbox && useradd -r -g sandbox -d /sandbox -s /bin/bash sandbox

FROM system AS devtools

# Node.js 22 + build toolchain. Keep the default apt installs aligned with the
# community base image, then add the small CLI tools gator commonly needs.
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends \
        build-essential \
        git \
        jq \
        less \
        nodejs=22.22.1-1nodesource1 \
        ripgrep \
        vim-tiny \
        nano \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g npm@11.11.0

# GitHub CLI
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        -o /usr/share/keyrings/githubcli-archive-keyring.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list && \
    apt-get update && apt-get install -y --no-install-recommends gh && \
    rm -rf /var/lib/apt/lists/*

ARG CODEX_VERSION=latest
RUN npm install -g "@openai/codex@${CODEX_VERSION}" && \
    (npm cache clean --force >/dev/null 2>&1 || true) && \
    codex --version

# Provider profiles include both /usr/bin and /usr/local/bin variants for common
# tools. Create the /usr/local/bin aliases in this image so sandbox symlink
# resolution does not warn about missing alternate paths during policy reloads.
RUN ln -sf /usr/bin/gh /usr/local/bin/gh && \
    ln -sf /usr/bin/git /usr/local/bin/git && \
    ln -sf /usr/bin/codex /usr/local/bin/codex

FROM devtools AS final

ENV PATH="/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"

RUN mkdir -p /etc/openshell
COPY policy.yaml /etc/openshell/policy.yaml
COPY bin/gh /usr/local/bin/gh-gator
RUN rm -f /usr/local/bin/gh && \
    cp /usr/local/bin/gh-gator /usr/local/bin/gh && \
    chmod 755 /usr/local/bin/gh

RUN printf 'export PATH="/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"\nexport PS1="\\u@\\h:\\w\\$ "\n' \
        > /sandbox/.bashrc && \
    printf '[ -f ~/.bashrc ] && . ~/.bashrc\n' > /sandbox/.profile && \
    chown -R sandbox:sandbox /sandbox

USER sandbox

ENTRYPOINT ["/bin/bash"]
