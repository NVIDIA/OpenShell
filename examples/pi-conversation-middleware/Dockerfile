# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

FROM node:22-bookworm-slim

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates iproute2 nftables \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g --ignore-scripts \
       @earendil-works/pi-coding-agent@0.84.1

RUN install -d -o node -g node \
    /workspace \
    /workspace/.pi/agent \
    /opt/pi-conversation

COPY --chown=node:node models.json /workspace/.pi/agent/models.json
COPY --chown=node:node pi-extension.ts /opt/pi-conversation/pi-extension.ts

WORKDIR /workspace
USER node

CMD ["sleep", "infinity"]
