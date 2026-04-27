# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Example: a minimal Python REST API that runs inside a OpenShell sandbox.
# The image exposes port 8080 with a /hello endpoint.  Use port forwarding
# (--forward 8080 on the CLI) to reach it from your local machine.

FROM python:3.13-slim

# System tools useful for sandbox networking and debugging.
# iproute2: required for network namespace management (ip netns, veth pairs)
# iptables: optional, enables bypass detection (LOG + REJECT for direct connections)
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*

# Create the sandbox user for non-root execution.
# Use a high UID range to avoid conflicts with host users when running without
# user namespace remapping (UID in container = UID on host).
RUN groupadd -g 1000660000 sandbox && \
    useradd -m -u 1000660000 -g sandbox sandbox

WORKDIR /sandbox
COPY app.py .

EXPOSE 8080

# NOTE: The sandbox supervisor replaces CMD at runtime.  Pass the start
# command explicitly:  openshell sandbox create ... -- python /sandbox/app.py
CMD ["python", "app.py"]
