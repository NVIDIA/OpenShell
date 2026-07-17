# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

FROM public.ecr.aws/docker/library/debian:bookworm-slim

# iproute2 is required for sandbox network namespace isolation.
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && ! getent passwd sandbox \
    && ! getent group sandbox \
    && ! getent passwd 10001 \
    && ! getent group 10001 \
    && mkdir /sandbox

# The compute driver must override image-provided identity values.
ENV OPENSHELL_SANDBOX_UID=1234
ENV OPENSHELL_SANDBOX_GID=1234

RUN echo "userless-image-e2e-marker" > /etc/marker.txt

CMD ["sleep", "infinity"]
