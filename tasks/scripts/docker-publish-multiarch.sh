#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Unified multi-arch build and push for all OpenShell images.
#
# Usage:
#   docker-publish-multiarch.sh --mode registry   # Push to DOCKER_REGISTRY
#   docker-publish-multiarch.sh --mode ecr         # Push to ECR
#
# Environment:
#   IMAGE_TAG                - Image tag (default: dev)
#   K3S_VERSION              - k3s version override (optional; default in Dockerfile.cluster)

#   DOCKER_PLATFORMS         - Target platforms (default: linux/amd64,linux/arm64)
#   RUST_BUILD_PROFILE       - Rust build profile for sandbox (default: release)
#   TAG_LATEST               - If true, add/update :latest tag (default: false)
#   EXTRA_DOCKER_TAGS        - Additional tags to add (comma or space separated)
#
# Registry mode env:
#   DOCKER_REGISTRY          - Registry URL (required, e.g. ghcr.io/myorg)
#
# ECR mode env:
#   AWS_ACCOUNT_ID           - AWS account ID (default: 012345678901)
#   AWS_REGION               - AWS region (default: us-west-2)
set -euo pipefail

runtime_bundle_var_name() {
  local arch="$1"
  local upper_arch
  upper_arch=$(printf '%s' "$arch" | tr '[:lower:]' '[:upper:]')
  printf 'OPENSHELL_RUNTIME_BUNDLE_TARBALL_%s\n' "$upper_arch"
}

require_runtime_bundle_tarball_for_arch() {
  local arch="$1"
  local var_name value
  var_name="$(runtime_bundle_var_name "$arch")"
  value="${!var_name:-}"

  if [[ -z "$value" ]]; then
    echo "missing required variable: ${var_name}" >&2
    exit 1
  fi

  if [[ ! -f "$value" ]]; then
    echo "runtime bundle validation failed: tarball not found: ${value}" >&2
    exit 1
  fi

  printf '%s\n' "$value"
}

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

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
MODE=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --mode) MODE="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$MODE" ]]; then
  echo "Usage: docker-publish-multiarch.sh --mode <registry|ecr>" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Common variables
# ---------------------------------------------------------------------------
IMAGE_TAG=${IMAGE_TAG:-dev}
PLATFORMS=${DOCKER_PLATFORMS:-linux/amd64,linux/arm64}
CARGO_VERSION=${OPENSHELL_CARGO_VERSION:-}
if [[ -z "${CARGO_VERSION}" ]]; then
  CARGO_VERSION=$(uv run python tasks/scripts/release.py get-version --cargo)
fi
EXTRA_BUILD_FLAGS=""
TAG_LATEST=${TAG_LATEST:-false}
EXTRA_DOCKER_TAGS_RAW=${EXTRA_DOCKER_TAGS:-}
EXTRA_TAGS=()

if [[ -n "${EXTRA_DOCKER_TAGS_RAW}" ]]; then
  EXTRA_DOCKER_TAGS_RAW=${EXTRA_DOCKER_TAGS_RAW//,/ }
  for tag in ${EXTRA_DOCKER_TAGS_RAW}; do
    if [[ -n "${tag}" ]]; then
      EXTRA_TAGS+=("${tag}")
    fi
  done
fi

# ---------------------------------------------------------------------------
# Mode-specific configuration
# ---------------------------------------------------------------------------
case "$MODE" in
  registry)
    REGISTRY=${DOCKER_REGISTRY:?Set DOCKER_REGISTRY to push multi-arch images (e.g. ghcr.io/myorg)}
    IMAGE_PREFIX="openshell-"
    ;;
  ecr)
    AWS_ACCOUNT_ID=${AWS_ACCOUNT_ID:-012345678901}
    AWS_REGION=${AWS_REGION:-us-west-2}
    ECR_HOST="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
    REGISTRY="${ECR_HOST}/openshell"
    IMAGE_PREFIX=""
    EXTRA_BUILD_FLAGS="--provenance=false --sbom=false"
    ;;
  *)
    echo "Unknown mode: $MODE (expected 'registry' or 'ecr')" >&2
    exit 1
    ;;
esac

# ---------------------------------------------------------------------------
# Select or create a multi-platform buildx builder.
# If DOCKER_BUILDER is set (e.g. by CI with remote BuildKit nodes), use it.
# Otherwise fall back to creating a local "multiarch" builder.
# ---------------------------------------------------------------------------
BUILDER_NAME=${DOCKER_BUILDER:-multiarch}
if docker buildx inspect "${BUILDER_NAME}" >/dev/null 2>&1; then
  echo "Using existing buildx builder: ${BUILDER_NAME}"
  docker buildx use "${BUILDER_NAME}"
else
  echo "Creating multi-platform buildx builder: ${BUILDER_NAME}..."
  docker buildx create --name "${BUILDER_NAME}" --use --bootstrap
fi

# ---------------------------------------------------------------------------
# Resolve Dockerfile path for a component.
# ---------------------------------------------------------------------------
resolve_dockerfile() {
  local comp="$1"
  echo "deploy/docker/Dockerfile.${comp}"
}

# ---------------------------------------------------------------------------
# Step 1: Build and push the gateway image as a multi-arch manifest.
# Uses cross-compilation in the Dockerfile (BUILDPLATFORM != TARGETPLATFORM)
# so Rust compiles natively and only the final stage runs on the target arch.
# Sandbox images are maintained in the community repo and not built here.
# ---------------------------------------------------------------------------
echo "Building multi-arch gateway image..."
LOCK_HASH=$(sha256_16 Cargo.lock)
GATEWAY_DOCKERFILE=$(resolve_dockerfile "gateway")
BUILD_ARGS="--build-arg OPENSHELL_CARGO_VERSION=${CARGO_VERSION}"
if [ -n "${SCCACHE_MEMCACHED_ENDPOINT:-}" ]; then
  BUILD_ARGS="${BUILD_ARGS} --build-arg SCCACHE_MEMCACHED_ENDPOINT=${SCCACHE_MEMCACHED_ENDPOINT}"
fi
RUST_SCOPE=${RUST_TOOLCHAIN_SCOPE:-$(detect_rust_scope "${GATEWAY_DOCKERFILE}")}
CACHE_SCOPE_INPUT="v1|gateway|base|${LOCK_HASH}|${RUST_SCOPE}"
CARGO_TARGET_CACHE_SCOPE=$(printf '%s' "${CACHE_SCOPE_INPUT}" | sha256_16_stdin)
BUILD_ARGS="${BUILD_ARGS} --build-arg CARGO_TARGET_CACHE_SCOPE=${CARGO_TARGET_CACHE_SCOPE}"
FULL_IMAGE="${REGISTRY}/${IMAGE_PREFIX}gateway"
docker buildx build \
  --platform "${PLATFORMS}" \
  -f "${GATEWAY_DOCKERFILE}" \
  -t "${FULL_IMAGE}:${IMAGE_TAG}" \
  ${EXTRA_BUILD_FLAGS} \
  ${BUILD_ARGS} \
  --push \
  .

# ---------------------------------------------------------------------------
# Step 2: Package helm charts (architecture-independent)
# ---------------------------------------------------------------------------
mkdir -p deploy/docker/.build/charts
echo "Packaging helm chart..."
helm package deploy/helm/openshell -d deploy/docker/.build/charts/

# ---------------------------------------------------------------------------
# Step 3: Build and push multi-arch cluster image.
# The cluster image includes the supervisor binary (built from Rust source)
# and k3s. Gateway images are pulled at runtime from the registry; sandbox
# images are pulled from the community registry.
# ---------------------------------------------------------------------------
echo ""
echo "Building multi-arch cluster image..."
CLUSTER_DOCKERFILE="deploy/docker/Dockerfile.cluster"
CLUSTER_RUST_SCOPE=${RUST_TOOLCHAIN_SCOPE:-$(detect_rust_scope "${CLUSTER_DOCKERFILE}")}
CLUSTER_CACHE_SCOPE_INPUT="v1|cluster|base|${LOCK_HASH}|${CLUSTER_RUST_SCOPE}"
CLUSTER_CARGO_SCOPE=$(printf '%s' "${CLUSTER_CACHE_SCOPE_INPUT}" | sha256_16_stdin)
CLUSTER_BUILD_ARGS=""
if [ -n "${SCCACHE_MEMCACHED_ENDPOINT:-}" ]; then
  CLUSTER_BUILD_ARGS="--build-arg SCCACHE_MEMCACHED_ENDPOINT=${SCCACHE_MEMCACHED_ENDPOINT}"
fi
CLUSTER_IMAGE="${REGISTRY}/${IMAGE_PREFIX:+${IMAGE_PREFIX}}cluster"
IFS=',' read -r -a PLATFORM_LIST <<< "${PLATFORMS}"
CLUSTER_PLATFORM_TAGS=()

for platform in "${PLATFORM_LIST[@]}"; do
  case "$platform" in
    linux/amd64)
      arch="amd64"
      ;;
    linux/arm64)
      arch="arm64"
      ;;
    *)
      echo "Unsupported cluster platform for runtime bundle publishing: ${platform}" >&2
      exit 1
      ;;
  esac

  runtime_bundle_tarball="$(require_runtime_bundle_tarball_for_arch "$arch")"
  arch_tag="${IMAGE_TAG}-${arch}"
  CLUSTER_PLATFORM_TAGS+=("${CLUSTER_IMAGE}:${arch_tag}")

  IMAGE_TAG="${arch_tag}" \
  DOCKER_PLATFORM="$platform" \
  DOCKER_PUSH=1 \
  OPENSHELL_RUNTIME_BUNDLE_TARBALL="$runtime_bundle_tarball" \
  OPENSHELL_CARGO_VERSION="$CARGO_VERSION" \
  K3S_VERSION="${K3S_VERSION:-}" \
  tasks/scripts/docker-build-cluster.sh
done

docker buildx imagetools create \
  --prefer-index=false \
  -t "${CLUSTER_IMAGE}:${IMAGE_TAG}" \
  "${CLUSTER_PLATFORM_TAGS[@]}"

# ---------------------------------------------------------------------------
# Step 4: Apply additional tags by copying manifests.
# Use --prefer-index=false to carbon-copy the source manifest format instead of
# wrapping it in an OCI image index (which the registry v3 proxy can't serve).
# ---------------------------------------------------------------------------
TAGS_TO_APPLY=("${EXTRA_TAGS[@]}")
if [ "$TAG_LATEST" = true ]; then
  TAGS_TO_APPLY+=("latest")
fi

if [ ${#TAGS_TO_APPLY[@]} -gt 0 ]; then
  for component in gateway cluster; do
    FULL_IMAGE="${REGISTRY}/${IMAGE_PREFIX:+${IMAGE_PREFIX}}${component}"
    for tag in "${TAGS_TO_APPLY[@]}"; do
      if [ "${tag}" = "${IMAGE_TAG}" ]; then
        continue
      fi
      echo "Tagging ${FULL_IMAGE}:${tag}..."
      docker buildx imagetools create \
        --prefer-index=false \
        -t "${FULL_IMAGE}:${tag}" \
        "${FULL_IMAGE}:${IMAGE_TAG}"
    done
  done
fi

echo ""
echo "Done! Multi-arch images pushed to ${REGISTRY}:"
echo "  ${REGISTRY}/${IMAGE_PREFIX}gateway:${IMAGE_TAG}"
echo "  ${REGISTRY}/${IMAGE_PREFIX:+${IMAGE_PREFIX}}cluster:${IMAGE_TAG}"
if [ "$TAG_LATEST" = true ]; then
  echo "  (all also tagged :latest)"
fi
if [ ${#EXTRA_TAGS[@]} -gt 0 ]; then
  echo "  (all also tagged: ${EXTRA_TAGS[*]})"
fi
