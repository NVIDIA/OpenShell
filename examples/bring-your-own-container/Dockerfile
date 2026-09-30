# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Example: a minimal Python REST API that runs inside a OpenShell sandbox.
# The image exposes port 8080 with a /hello endpoint.  Use port forwarding
# (--forward 8080 on the CLI) to reach it from your local machine.

FROM python:3.13-slim

# curl is only for debugging. OpenShell needs no networking tools in the image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1500 app \
    && useradd --uid 1500 --gid app --create-home app

RUN install -d -o app -g app /sandbox
WORKDIR /sandbox
COPY --chown=app:app app.py .

EXPOSE 8080

# Docker and Podman use this non-root identity when policy omits either process
# identity field. OpenShell starts the supervisor as root and drops only agent
# children to this account.
USER app

# NOTE: The sandbox supervisor replaces CMD at runtime.  Pass the start
# command explicitly:  openshell sandbox create ... -- python /sandbox/app.py
CMD ["python", "app.py"]
