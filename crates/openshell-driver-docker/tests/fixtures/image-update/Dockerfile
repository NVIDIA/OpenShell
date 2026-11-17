# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

FROM alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
ARG VERSION
ARG WORKLOAD_USER=1234:1235
RUN mkdir -p /app \
    && printf '%s\n' "$VERSION" > /app/version \
    && printf 'other:x:2000:2000::/sandbox:/bin/sh\n' >> /etc/passwd \
    && printf 'other:x:2000:\n' >> /etc/group
USER ${WORKLOAD_USER}
WORKDIR /sandbox
