# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Example: a minimal Python REST API that runs inside a NemoClaw sandbox.
# The image exposes port 8080 with a /hello endpoint.  Use port forwarding
# (--forward 8080 on the CLI, or the Ports field in Gator) to reach it from
# your local machine.

FROM python:3.12-slim

# System tools useful for sandbox networking and debugging.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create the sandbox user (uid/gid 1000) for non-root execution.
RUN groupadd -g 1000 sandbox && \
    useradd -m -u 1000 -g sandbox sandbox

WORKDIR /sandbox
COPY app.py .

EXPOSE 8080

# The image's own entrypoint starts the REST API.  When creating a sandbox
# leave the Command field empty (or omit -- on the CLI) so this runs.
CMD ["python", "app.py"]
