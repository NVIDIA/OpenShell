# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
FROM gcc:14-bookworm AS build
COPY workload.c /src/workload.c
RUN gcc -O2 -Wall -Wextra -Werror -pthread /src/workload.c -o /workload

FROM debian:bookworm-slim
RUN groupadd -g 1000 benchmark && useradd -u 1000 -g 1000 -m benchmark \
    && mkdir /sandbox && chown 1000:1000 /sandbox
COPY --from=build /workload /usr/local/bin/workload
USER 1000:1000
WORKDIR /sandbox
CMD ["sleep", "infinity"]
