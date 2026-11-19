# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# The image for the make workload: gcc, make and the `sandbox` user that the
# testkit base policy runs as. The C project isn't here; the test uploads it.
FROM nvcr.io/nvidia/base/ubuntu:24.04@sha256:fef8f2708dbb85fbfcba6503d805397d89d9210f375362ff3b9f7888eb297ca5

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev make \
    && rm -rf /var/lib/apt/lists/* \
    && if getent passwd ubuntu >/dev/null; then userdel ubuntu; fi \
    && if getent group ubuntu >/dev/null; then groupdel ubuntu; fi \
    && groupadd --gid 1000 sandbox \
    && useradd --uid 1000 --gid sandbox --create-home --home-dir /sandbox --shell /bin/bash sandbox

WORKDIR /sandbox
USER sandbox:sandbox
