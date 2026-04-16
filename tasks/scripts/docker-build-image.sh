#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

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

TARGET=${1:?"Usage: docker-build-image.sh <gateway|supervisor|cluster|supervisor-builder|supervisor-output> [extra-args...]"}
shift

DOCKERFILE="deploy/docker/Dockerfile.images"
if [[ ! -f "${DOCKERFILE}" ]]; then
  echo "Error: Dockerfile not found: ${DOCKERFILE}" >&2
  exit 1
fi

IS_FINAL_IMAGE=0
IMAGE_NAME=""
DOCKER_TARGET=""
case "${TARGET}" in
  gateway)
    IS_FINAL_IMAGE=1
    IMAGE_NAME="openshell/gateway"
    DOCKER_TARGET="gateway"
    ;;
  supervisor)
    IS_FINAL_IMAGE=1
    IMAGE_NAME="openshell/supervisor"
    DOCKER_TARGET="supervisor"
    ;;
  cluster)
    IS_FINAL_IMAGE=1
    IMAGE_NAME="openshell/cluster"
    DOCKER_TARGET="cluster"
    ;;
  supervisor-builder)
    DOCKER_TARGET="supervisor-builder"
    ;;
  supervisor-output)
    DOCKER_TARGET="supervisor-output"
    ;;
  *)
    echo "Error: unsupported target '${TARGET}'" >&2
    exit 1
    ;;
esac

if [[ -n "${IMAGE_REGISTRY:-}" && "${IS_FINAL_IMAGE}" == "1" ]]; then
  IMAGE_NAME="${IMAGE_REGISTRY}/${IMAGE_NAME#openshell/}"
fi

IMAGE_TAG=${IMAGE_TAG:-dev}
DOCKER_BUILD_CACHE_DIR=${DOCKER_BUILD_CACHE_DIR:-.cache/buildkit}
CACHE_PATH="${DOCKER_BUILD_CACHE_DIR}/images"
mkdir -p "${CACHE_PATH}"

BUILDER_ARGS=()
if [[ -n "${DOCKER_BUILDER:-}" ]]; then
  BUILDER_ARGS=(--builder "${DOCKER_BUILDER}")
elif [[ -z "${DOCKER_PLATFORM:-}" && -z "${CI:-}" ]]; then
  _ctx=$(docker context inspect --format '{{.Name}}' 2>/dev/null || echo default)
  BUILDER_ARGS=(--builder "${_ctx}")
fi

CACHE_ARGS=()
if [[ -z "${CI:-}" ]]; then
  if docker buildx inspect ${BUILDER_ARGS[@]+"${BUILDER_ARGS[@]}"} 2>/dev/null | grep -q "Driver: docker-container"; then
    CACHE_ARGS=(
      --cache-from "type=local,src=${CACHE_PATH}"
      --cache-to "type=local,dest=${CACHE_PATH},mode=max"
    )
  fi
fi

SCCACHE_ARGS=()
if [[ -n "${SCCACHE_MEMCACHED_ENDPOINT:-}" ]]; then
  SCCACHE_ARGS=(--build-arg "SCCACHE_MEMCACHED_ENDPOINT=${SCCACHE_MEMCACHED_ENDPOINT}")
fi

VERSION_ARGS=()
if [[ -n "${OPENSHELL_CARGO_VERSION:-}" ]]; then
  VERSION_ARGS=(--build-arg "OPENSHELL_CARGO_VERSION=${OPENSHELL_CARGO_VERSION}")
elif [[ -n "${CI:-}" ]]; then
  CARGO_VERSION=$(uv run python tasks/scripts/release.py get-version --cargo 2>/dev/null || true)
  if [[ -n "${CARGO_VERSION}" ]]; then
    VERSION_ARGS=(--build-arg "OPENSHELL_CARGO_VERSION=${CARGO_VERSION}")
  fi
fi

LOCK_HASH=$(sha256_16 Cargo.lock)
RUST_SCOPE=${RUST_TOOLCHAIN_SCOPE:-$(detect_rust_scope "${DOCKERFILE}")}
CACHE_SCOPE_INPUT="v2|shared|release|${LOCK_HASH}|${RUST_SCOPE}"
CARGO_TARGET_CACHE_SCOPE=$(printf '%s' "${CACHE_SCOPE_INPUT}" | sha256_16_stdin)

# The cluster image embeds the packaged Helm chart.
if [[ "${TARGET}" == "cluster" ]]; then
  mkdir -p deploy/docker/.build/charts
  helm package deploy/helm/openshell -d deploy/docker/.build/charts/ >/dev/null
fi

K3S_ARGS=()
if [[ "${TARGET}" == "cluster" && -n "${K3S_VERSION:-}" ]]; then
  K3S_ARGS=(--build-arg "K3S_VERSION=${K3S_VERSION}")
fi

# CI builds use codegen-units=1 for maximum optimization; local builds omit
# the arg so cargo uses the Cargo.toml default (parallel codegen, fast links).
CODEGEN_ARGS=()
if [[ -n "${CI:-}" ]]; then
  CODEGEN_ARGS=(--build-arg "CARGO_CODEGEN_UNITS=1")
fi

TAG_ARGS=()
if [[ "${IS_FINAL_IMAGE}" == "1" ]]; then
  TAG_ARGS=(-t "${IMAGE_NAME}:${IMAGE_TAG}")
fi

OUTPUT_ARGS=()
if [[ -n "${DOCKER_OUTPUT:-}" ]]; then
  OUTPUT_ARGS=(--output "${DOCKER_OUTPUT}")
elif [[ "${IS_FINAL_IMAGE}" == "1" ]]; then
  if [[ "${DOCKER_PUSH:-}" == "1" ]]; then
    OUTPUT_ARGS=(--push)
  elif [[ "${DOCKER_PLATFORM:-}" == *","* ]]; then
    OUTPUT_ARGS=(--push)
  else
    OUTPUT_ARGS=(--load)
  fi
else
  echo "Error: DOCKER_OUTPUT must be set when building target '${TARGET}'" >&2
  exit 1
fi

# Default to dev-settings so local builds include test-only settings
# (dummy_bool, dummy_int) that e2e tests depend on, matching CI behaviour.
EXTRA_CARGO_FEATURES="${EXTRA_CARGO_FEATURES:-openshell-core/dev-settings}"

FEATURE_ARGS=()
if [[ -n "${EXTRA_CARGO_FEATURES}" ]]; then
  FEATURE_ARGS=(--build-arg "EXTRA_CARGO_FEATURES=${EXTRA_CARGO_FEATURES}")
fi

docker buildx build \
  ${BUILDER_ARGS[@]+"${BUILDER_ARGS[@]}"} \
  ${DOCKER_PLATFORM:+--platform ${DOCKER_PLATFORM}} \
  ${CACHE_ARGS[@]+"${CACHE_ARGS[@]}"} \
  ${SCCACHE_ARGS[@]+"${SCCACHE_ARGS[@]}"} \
  ${VERSION_ARGS[@]+"${VERSION_ARGS[@]}"} \
  ${K3S_ARGS[@]+"${K3S_ARGS[@]}"} \
  ${CODEGEN_ARGS[@]+"${CODEGEN_ARGS[@]}"} \
  ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"} \
  --build-arg "CARGO_TARGET_CACHE_SCOPE=${CARGO_TARGET_CACHE_SCOPE}" \
  -f "${DOCKERFILE}" \
  --target "${DOCKER_TARGET}" \
  ${TAG_ARGS[@]+"${TAG_ARGS[@]}"} \
  --provenance=false \
  "$@" \
  ${OUTPUT_ARGS[@]+"${OUTPUT_ARGS[@]}"} \
  .
