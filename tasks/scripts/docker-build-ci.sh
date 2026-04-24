#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build the CI Docker image (deploy/docker/Dockerfile.ci).
# This is a standalone build, separate from the main image build graph.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/container-engine.sh"

OUTPUT_ARGS=(--load)
if [[ "${DOCKER_PUSH:-}" == "1" ]]; then
  OUTPUT_ARGS=(--push)
elif [[ "${DOCKER_PLATFORM:-}" == *","* ]]; then
  OUTPUT_ARGS=(--push)
fi

exec ce_build \
  ${DOCKER_BUILDER:+--builder ${DOCKER_BUILDER}} \
  ${DOCKER_PLATFORM:+--platform ${DOCKER_PLATFORM}} \
  -f deploy/docker/Dockerfile.ci \
  -t "openshell/ci:${IMAGE_TAG:-dev}" \
  --provenance=false \
  "$@" \
  ${OUTPUT_ARGS[@]+"${OUTPUT_ARGS[@]}"} \
  .
