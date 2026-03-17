#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

COMPONENT=${1:?"Usage: docker-build-component.sh <gateway|ci> [extra-args...]"}
shift

case "${COMPONENT}" in
  gateway)
    exec tasks/scripts/docker-build-image.sh gateway "$@"
    ;;
  ci)
    OUTPUT_ARGS=(--load)
    if [[ "${DOCKER_PUSH:-}" == "1" ]]; then
      OUTPUT_ARGS=(--push)
    elif [[ "${DOCKER_PLATFORM:-}" == *","* ]]; then
      OUTPUT_ARGS=(--push)
    fi

    exec docker buildx build \
      ${DOCKER_BUILDER:+--builder ${DOCKER_BUILDER}} \
      ${DOCKER_PLATFORM:+--platform ${DOCKER_PLATFORM}} \
      -f deploy/docker/Dockerfile.ci \
      -t "openshell/ci:${IMAGE_TAG:-dev}" \
      --provenance=false \
      "$@" \
      ${OUTPUT_ARGS[@]+"${OUTPUT_ARGS[@]}"} \
      .
    ;;
  *)
    echo "Error: unsupported component '${COMPONENT}'" >&2
    exit 1
    ;;
esac
