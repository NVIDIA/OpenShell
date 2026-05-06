#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Build the CI container image (deploy/docker/Dockerfile.ci or Containerfile.ci).
# This is a standalone build, separate from the main image build graph.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/container-engine.sh"

# Backwards-compatible env var fallbacks: accept CONTAINER_* or DOCKER_*
CONTAINER_BUILDER="${CONTAINER_BUILDER:-${DOCKER_BUILDER:-}}"
CONTAINER_PLATFORM="${CONTAINER_PLATFORM:-${DOCKER_PLATFORM:-}}"
CONTAINER_PUSH="${CONTAINER_PUSH:-${DOCKER_PUSH:-}}"

CONTAINERFILE=$(ce_resolve_containerfile deploy/docker ci)

OUTPUT_ARGS=(--load)
if [[ "${CONTAINER_PUSH}" == "1" ]]; then
  OUTPUT_ARGS=(--push)
elif [[ "${CONTAINER_PLATFORM}" == *","* ]]; then
  OUTPUT_ARGS=(--push)
fi

SECRET_ARGS=()
if [[ -n "${MISE_GITHUB_TOKEN:-}" ]]; then
  SECRET_ARGS=(--secret id=MISE_GITHUB_TOKEN,env=MISE_GITHUB_TOKEN)
elif [[ -n "${GITHUB_TOKEN:-}" ]]; then
  SECRET_ARGS=(--secret id=MISE_GITHUB_TOKEN,env=GITHUB_TOKEN)
fi

ce_build \
  ${CONTAINER_BUILDER:+--builder ${CONTAINER_BUILDER}} \
  ${CONTAINER_PLATFORM:+--platform ${CONTAINER_PLATFORM}} \
  ${SECRET_ARGS[@]+"${SECRET_ARGS[@]}"} \
  -f "${CONTAINERFILE}" \
  -t "openshell/ci:${IMAGE_TAG:-dev}" \
  --provenance=false \
  "$@" \
  ${OUTPUT_ARGS[@]+"${OUTPUT_ARGS[@]}"} \
  .
