# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

FROM nvidia/cuda:12.4.1-base-ubuntu22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1000 sandbox && \
    useradd -m -u 1000 -g sandbox sandbox

WORKDIR /sandbox

CMD ["nvidia-smi"]
