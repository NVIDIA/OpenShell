#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
source "${SCRIPT_DIR}/container-engine.sh"

DOCKERFILE="${ROOT}/deploy/docker/Dockerfile.cluster"
CHART_SRC="${ROOT}/deploy/helm/openshell"
CHART_STAGE="${ROOT}/deploy/docker/.build/charts"

IMAGE_TAG="${IMAGE_TAG:-dev}"
IMAGE_NAME="${IMAGE_NAME:-openshell/cluster}"

if [[ -n "${IMAGE_REGISTRY:-}" ]]; then
    IMAGE_NAME="${IMAGE_REGISTRY}/${IMAGE_NAME#openshell/}"
fi

# Package the inner Helm chart from source into the staging area so it is
# available to the Docker build context (COPY deploy/docker/.build/charts/...).
echo "Packaging inner Helm chart from ${CHART_SRC}..."
mkdir -p "${CHART_STAGE}"
helm package "${CHART_SRC}" \
    --version 0.1.0 \
    --destination "${CHART_STAGE}" \
    --dependency-update=false \
    2>&1

CHART_TGZ="${CHART_STAGE}/helm-chart-0.1.0.tgz"
TARGET_TGZ="${CHART_STAGE}/openshell-0.1.0.tgz"
if [[ -f "${CHART_TGZ}" && "${CHART_TGZ}" != "${TARGET_TGZ}" ]]; then
    mv "${CHART_TGZ}" "${TARGET_TGZ}"
fi
echo "Staged: ${TARGET_TGZ} ($(wc -c < "${TARGET_TGZ}") bytes)"

if [[ -n "${DOCKER_BUILD_CACHE_DIR:-}" ]]; then
    CACHE_PATH="${DOCKER_BUILD_CACHE_DIR}/images"
else
    CACHE_PATH="${ROOT}/.cache/buildkit/images"
fi
mkdir -p "${CACHE_PATH}"

CACHE_ARGS=()
if ce_is_docker; then
    if ce_buildx_inspect 2>/dev/null | grep -q "Driver: docker-container"; then
        CACHE_ARGS=(
            --cache-from "type=local,src=${CACHE_PATH}"
            --cache-to "type=local,dest=${CACHE_PATH},mode=max"
        )
    fi
fi

TAG_ARGS=(-t "${IMAGE_NAME}:${IMAGE_TAG}")

OUTPUT_ARGS=(--load)
if [[ "${DOCKER_PUSH:-}" == "1" ]]; then
    OUTPUT_ARGS=(--push)
fi

echo "Building ${IMAGE_NAME}:${IMAGE_TAG}..."
ce_build \
    ${DOCKER_PLATFORM:+--platform ${DOCKER_PLATFORM}} \
    ${CACHE_ARGS[@]+"${CACHE_ARGS[@]}"} \
    -f "${DOCKERFILE}" \
    --build-arg BASE_IMAGE="${CLUSTER_BASE_IMAGE:-ghcr.io/nvidia/openshell/cluster:latest}" \
    "${TAG_ARGS[@]}" \
    --provenance=false \
    "$@" \
    "${OUTPUT_ARGS[@]}" \
    "${ROOT}"
