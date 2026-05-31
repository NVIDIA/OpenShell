# syntax=docker/dockerfile:1

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

ARG CUDA_BUILD_IMAGE=nvcr.io/nvidia/cuda:12.8.1-base-ubuntu22.04
ARG OPENSHELL_SANDBOX_BASE_IMAGE=ghcr.io/nvidia/openshell-community/sandboxes/base:latest

FROM ${CUDA_BUILD_IMAGE} AS builder

ARG DEBIAN_FRONTEND=noninteractive
ARG CUDA_SAMPLES_REF=v12.8
ARG CUDA_SAMPLES_REPO=https://github.com/NVIDIA/cuda-samples

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        cuda-nvcc-12-8 \
        curl \
        g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/cuda-samples

RUN set -eux; \
    curl -fsSL "${CUDA_SAMPLES_REPO}/archive/refs/tags/${CUDA_SAMPLES_REF}.tar.gz" \
        -o /tmp/cuda-samples.tar.gz; \
    tar -xzf /tmp/cuda-samples.tar.gz \
        --strip-components=1 \
        --wildcards \
        '*/Common/*' \
        '*/cmake/*' \
        '*/Samples/0_Introduction/vectorAdd/*' \
        '*/Samples/1_Utilities/deviceQuery/*' \
        '*/LICENSE'; \
    sed -i 's/CUDA::cudart/CUDA::cudart_static/g' \
        Samples/1_Utilities/deviceQuery/CMakeLists.txt; \
    cmake -S Samples/1_Utilities/deviceQuery -B /tmp/build-device-query \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_CUDA_RUNTIME_LIBRARY=Static; \
    cmake --build /tmp/build-device-query --parallel; \
    cmake -S Samples/0_Introduction/vectorAdd -B /tmp/build-vector-add \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_CUDA_RUNTIME_LIBRARY=Static; \
    cmake --build /tmp/build-vector-add --parallel; \
    mkdir -p /opt/openshell-gpu-workload; \
    cp /tmp/build-device-query/deviceQuery /opt/openshell-gpu-workload/deviceQuery; \
    cp /tmp/build-vector-add/vectorAdd /opt/openshell-gpu-workload/vectorAdd; \
    cp LICENSE /opt/openshell-gpu-workload/cuda-samples.LICENSE; \
    rm -f /tmp/cuda-samples.tar.gz

FROM ${OPENSHELL_SANDBOX_BASE_IMAGE}

ARG CUDA_SAMPLES_REF=v12.8

LABEL com.nvidia.openshell.gpu-workload.name="cuda-basic" \
      com.nvidia.openshell.gpu-workload.cuda-samples-ref="${CUDA_SAMPLES_REF}"

USER root
RUN mkdir -p /usr/local/lib/openshell-gpu-workload \
    /usr/local/share/doc/openshell-gpu-workload
COPY --from=builder /opt/openshell-gpu-workload/deviceQuery /usr/local/lib/openshell-gpu-workload/deviceQuery
COPY --from=builder /opt/openshell-gpu-workload/vectorAdd /usr/local/lib/openshell-gpu-workload/vectorAdd
COPY --from=builder /opt/openshell-gpu-workload/cuda-samples.LICENSE /usr/local/share/doc/openshell-gpu-workload/cuda-samples.LICENSE
COPY workload.sh /usr/local/bin/openshell-gpu-workload
RUN chmod 0755 /usr/local/bin/openshell-gpu-workload \
    /usr/local/lib/openshell-gpu-workload/deviceQuery \
    /usr/local/lib/openshell-gpu-workload/vectorAdd

USER sandbox
ENTRYPOINT ["/usr/local/bin/openshell-gpu-workload"]
