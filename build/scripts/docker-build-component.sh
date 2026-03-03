#!/usr/bin/env bash
# Generic Docker image builder for Navigator components.
# Usage: docker-build-component.sh <component> [variant] [extra docker build args...]
#
# Components with a subdirectory layout (e.g. deploy/docker/sandbox/) support
# an optional variant argument:
#   docker-build-component.sh sandbox          -> Dockerfile.base  -> navigator/sandbox:dev
#   docker-build-component.sh sandbox nvidia   -> Dockerfile.nvidia -> navigator/sandbox-nvidia:dev
#
# Components without a subdirectory use the flat layout:
#   docker-build-component.sh server           -> Dockerfile.server -> navigator/server:dev
#
# Environment:
#   IMAGE_TAG          - Image tag (default: dev)
#   DOCKER_PLATFORM    - Target platform (optional, e.g. linux/amd64)
#   DOCKER_BUILDER     - Buildx builder name (default: auto-select)
#   DOCKER_PUSH        - When set to "1", push instead of loading into local daemon
#   IMAGE_REGISTRY     - Registry prefix for image name (e.g. ghcr.io/org/repo)
set -euo pipefail

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
    IMAGE_NAME="navigator/${COMPONENT}"
  else
    IMAGE_NAME="navigator/${COMPONENT}-${VARIANT}"
  fi
else
  # Flat layout: deploy/docker/Dockerfile.<component>
  DOCKERFILE="deploy/docker/Dockerfile.${COMPONENT}"
  IMAGE_NAME="navigator/${COMPONENT}"
fi

if [[ ! -f "${DOCKERFILE}" ]]; then
  echo "Error: Dockerfile not found: ${DOCKERFILE}" >&2
  exit 1
fi

# Prefix with registry when set (e.g. ghcr.io/org/repo/server:tag).
# Replaces the default "navigator/" prefix with the registry path.
if [[ -n "${IMAGE_REGISTRY:-}" ]]; then
  _suffix="${IMAGE_NAME#navigator/}"
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
fi

SCCACHE_ARGS=()
if [[ -n "${SCCACHE_MEMCACHED_ENDPOINT:-}" ]]; then
  SCCACHE_ARGS=(--build-arg "SCCACHE_MEMCACHED_ENDPOINT=${SCCACHE_MEMCACHED_ENDPOINT}")
fi

docker buildx build \
  ${BUILDER_ARGS[@]+"${BUILDER_ARGS[@]}"} \
  ${DOCKER_PLATFORM:+--platform ${DOCKER_PLATFORM}} \
  ${CACHE_ARGS[@]+"${CACHE_ARGS[@]}"} \
  ${SCCACHE_ARGS[@]+"${SCCACHE_ARGS[@]}"} \
  -f "${DOCKERFILE}" \
  -t "${IMAGE_NAME}:${IMAGE_TAG}" \
  --provenance=false \
  "$@" \
  ${OUTPUT_FLAG} \
  .
