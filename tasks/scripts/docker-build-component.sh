#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Generic Docker image builder for OpenShell components.
# Usage: docker-build-component.sh <component> [extra docker build args...]
#
#   docker-build-component.sh gateway           -> Dockerfile.gateway -> openshell/gateway:dev
#   docker-build-component.sh cluster           -> Dockerfile.cluster -> openshell/cluster:dev
#
# Environment:
#   IMAGE_TAG          - Image tag (default: dev)
#   DOCKER_PLATFORM    - Target platform (optional, e.g. linux/amd64)
#   DOCKER_BUILDER     - Buildx builder name (default: auto-select)
#   DOCKER_PUSH        - When set to "1", push instead of loading into local daemon
#   IMAGE_REGISTRY     - Registry prefix for image name (e.g. ghcr.io/org/repo)
set -euo pipefail

sha256_16() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print substr($1, 1, 16)}'
  else
    shasum -a 256 "$1" | awk '{print substr($1, 1, 16)}'
  fi
}

sha256_16_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print substr($1, 1, 16)}'
  else
    shasum -a 256 | awk '{print substr($1, 1, 16)}'
  fi
}

detect_rust_scope() {
  local dockerfile="$1"
  local rust_from
  rust_from=$(grep -E '^FROM --platform=\$BUILDPLATFORM rust:[^ ]+' "$dockerfile" | head -n1 | sed -E 's/^FROM --platform=\$BUILDPLATFORM rust:([^ ]+).*/\1/' || true)
  if [[ -n "${rust_from}" ]]; then
    echo "rust-${rust_from}"
    return
  fi

  if grep -q "rustup.rs" "$dockerfile"; then
    echo "rustup-stable"
    return
  fi

  echo "no-rust"
}

COMPONENT=${1:?"Usage: docker-build-component.sh <component> [variant] [extra-args...]"}
shift

# Resolve Dockerfile path and image name.
# If the component has a subdirectory layout, consume the next positional arg
# as a variant name (default: base).
VARIANT=""
COMPONENT_DIR="deploy/docker/${COMPONENT}"
if [[ -d "${COMPONENT_DIR}" ]]; then
  # Subdirectory layout — check for a variant argument.
  if [[ $# -gt 0 && ! "$1" == --* ]]; then
    VARIANT="$1"
    shift
  fi
  VARIANT=${VARIANT:-base}
  DOCKERFILE="${COMPONENT_DIR}/Dockerfile.${VARIANT}"
  if [[ "${VARIANT}" == "base" ]]; then
    IMAGE_NAME="openshell/${COMPONENT}"
  else
    IMAGE_NAME="openshell/${COMPONENT}-${VARIANT}"
  fi
else
  # Flat layout: deploy/docker/Dockerfile.<component>
  DOCKERFILE="deploy/docker/Dockerfile.${COMPONENT}"
  IMAGE_NAME="openshell/${COMPONENT}"
fi

if [[ ! -f "${DOCKERFILE}" ]]; then
  echo "Error: Dockerfile not found: ${DOCKERFILE}" >&2
  exit 1
fi

# Prefix with registry when set (e.g. ghcr.io/org/repo/gateway:tag).
# Replaces the default "openshell/" prefix with the registry path.
if [[ -n "${IMAGE_REGISTRY:-}" ]]; then
  _suffix="${IMAGE_NAME#openshell/}"
  IMAGE_NAME="${IMAGE_REGISTRY}/${_suffix}"
fi

IMAGE_TAG=${IMAGE_TAG:-dev}
DOCKER_BUILD_CACHE_DIR=${DOCKER_BUILD_CACHE_DIR:-.cache/buildkit}
CACHE_PATH="${DOCKER_BUILD_CACHE_DIR}/${COMPONENT}${VARIANT:+-${VARIANT}}"

mkdir -p "${CACHE_PATH}"

# Select the builder. For local (single-arch) builds use a builder with the
# native "docker" driver so images land directly in the Docker image store —
# no slow tarball export via the docker-container driver.
# Multi-platform builds (DOCKER_PLATFORM set) keep the current builder which
# is typically docker-container.
BUILDER_ARGS=()
if [[ -n "${DOCKER_BUILDER:-}" ]]; then
  BUILDER_ARGS=(--builder "${DOCKER_BUILDER}")
elif [[ -z "${DOCKER_PLATFORM:-}" && -z "${CI:-}" ]]; then
  # Pick the builder matching the active docker context (uses docker driver).
  _ctx=$(docker context inspect --format '{{.Name}}' 2>/dev/null || echo default)
  BUILDER_ARGS=(--builder "${_ctx}")
fi

CACHE_ARGS=()
if [[ -z "${CI:-}" ]]; then
  # Local development: use filesystem cache with docker-container driver.
  if docker buildx inspect ${BUILDER_ARGS[@]+"${BUILDER_ARGS[@]}"} 2>/dev/null | grep -q "Driver: docker-container"; then
    CACHE_ARGS=(
      --cache-from "type=local,src=${CACHE_PATH}"
      --cache-to "type=local,dest=${CACHE_PATH},mode=max"
    )
  fi
fi

OUTPUT_FLAG="--load"
if [[ "${DOCKER_PUSH:-}" == "1" ]]; then
  OUTPUT_FLAG="--push"
elif [[ "${DOCKER_PLATFORM:-}" == *","* ]]; then
  # Multi-platform builds cannot use --load; push is required.
  OUTPUT_FLAG="--push"
fi

SCCACHE_ARGS=()
if [[ -n "${SCCACHE_MEMCACHED_ENDPOINT:-}" ]]; then
  SCCACHE_ARGS=(--build-arg "SCCACHE_MEMCACHED_ENDPOINT=${SCCACHE_MEMCACHED_ENDPOINT}")
fi

VERSION_ARGS=()
if [[ -n "${OPENSHELL_CARGO_VERSION:-}" ]]; then
  VERSION_ARGS=(--build-arg "OPENSHELL_CARGO_VERSION=${OPENSHELL_CARGO_VERSION}")
elif [[ "${COMPONENT}" == "gateway" ]]; then
  CARGO_VERSION=$(uv run python tasks/scripts/release.py get-version --cargo)
  VERSION_ARGS=(--build-arg "OPENSHELL_CARGO_VERSION=${CARGO_VERSION}")
fi

LOCK_HASH=$(sha256_16 Cargo.lock)
RUST_SCOPE=${RUST_TOOLCHAIN_SCOPE:-$(detect_rust_scope "${DOCKERFILE}")}
CACHE_SCOPE_INPUT="v1|${COMPONENT}|${VARIANT:-base}|${LOCK_HASH}|${RUST_SCOPE}"
CARGO_TARGET_CACHE_SCOPE=$(printf '%s' "${CACHE_SCOPE_INPUT}" | sha256_16_stdin)

docker buildx build \
  ${BUILDER_ARGS[@]+"${BUILDER_ARGS[@]}"} \
  ${DOCKER_PLATFORM:+--platform ${DOCKER_PLATFORM}} \
  ${CACHE_ARGS[@]+"${CACHE_ARGS[@]}"} \
  ${SCCACHE_ARGS[@]+"${SCCACHE_ARGS[@]}"} \
  ${VERSION_ARGS[@]+"${VERSION_ARGS[@]}"} \
  --build-arg "CARGO_TARGET_CACHE_SCOPE=${CARGO_TARGET_CACHE_SCOPE}" \
  -f "${DOCKERFILE}" \
  -t "${IMAGE_NAME}:${IMAGE_TAG}" \
  --provenance=false \
  "$@" \
  ${OUTPUT_FLAG} \
  .
