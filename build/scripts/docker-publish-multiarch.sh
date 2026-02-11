#!/usr/bin/env bash
# Unified multi-arch build and push for all Navigator images.
#
# Usage:
#   docker-publish-multiarch.sh --mode registry   # Push to DOCKER_REGISTRY
#   docker-publish-multiarch.sh --mode ecr         # Push to ECR with :latest tags
#
# Environment:
#   IMAGE_TAG                - Image tag (default: dev)
#   K3S_VERSION              - k3s version (set by mise.toml [env])
#   ENVOY_GATEWAY_VERSION    - Envoy Gateway chart version (set by mise.toml [env])
#   DOCKER_PLATFORMS         - Target platforms (default: linux/amd64,linux/arm64)
#   RUST_BUILD_PROFILE       - Rust build profile for sandbox (default: release)
#
# Registry mode env:
#   DOCKER_REGISTRY          - Registry URL (required, e.g. ghcr.io/myorg)
#
# ECR mode env:
#   AWS_ACCOUNT_ID           - AWS account ID (default: 524473328983)
#   AWS_REGION               - AWS region (default: us-west-2)
set -euo pipefail

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
EXTRA_BUILD_FLAGS=""
TAG_LATEST=false

# ---------------------------------------------------------------------------
# Mode-specific configuration
# ---------------------------------------------------------------------------
case "$MODE" in
  registry)
    REGISTRY=${DOCKER_REGISTRY:?Set DOCKER_REGISTRY to push multi-arch images (e.g. ghcr.io/myorg)}
    IMAGE_PREFIX="navigator-"

    # Ensure a multi-platform builder exists
    if ! docker buildx inspect multiarch >/dev/null 2>&1; then
      echo "Creating multi-platform buildx builder..."
      docker buildx create --name multiarch --use --bootstrap
    else
      docker buildx use multiarch
    fi
    ;;
  ecr)
    AWS_ACCOUNT_ID=${AWS_ACCOUNT_ID:-524473328983}
    AWS_REGION=${AWS_REGION:-us-west-2}
    ECR_HOST="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
    REGISTRY="${ECR_HOST}/navigator"
    IMAGE_PREFIX=""
    EXTRA_BUILD_FLAGS="--provenance=false --sbom=false"
    TAG_LATEST=true

    # Ensure a multi-platform builder exists
    if ! docker buildx inspect multiarch >/dev/null 2>&1; then
      echo "Creating multi-platform buildx builder..."
      docker buildx create --name multiarch --use --bootstrap
    else
      docker buildx use multiarch
    fi
    ;;
  *)
    echo "Unknown mode: $MODE (expected 'registry' or 'ecr')" >&2
    exit 1
    ;;
esac

# ---------------------------------------------------------------------------
# Step 1: Build and push component images as multi-arch manifests.
# These use cross-compilation in the Dockerfile (BUILDPLATFORM != TARGETPLATFORM)
# so Rust compiles natively and only the final stage runs on the target arch.
# ---------------------------------------------------------------------------
echo "Building multi-arch component images..."
for component in sandbox server pki-job; do
  echo "Building ${IMAGE_PREFIX}${component} for ${PLATFORMS}..."
  BUILD_ARGS=""
  if [ "$component" = "sandbox" ]; then
    BUILD_ARGS="--build-arg RUST_BUILD_PROFILE=${RUST_BUILD_PROFILE:-release}"
  fi
  FULL_IMAGE="${REGISTRY}/${IMAGE_PREFIX}${component}"
  docker buildx build \
    --platform "${PLATFORMS}" \
    -f "deploy/docker/Dockerfile.${component}" \
    -t "${FULL_IMAGE}:${IMAGE_TAG}" \
    --cache-from "type=registry,ref=${FULL_IMAGE}:latest" \
    --cache-to "type=inline" \
    ${EXTRA_BUILD_FLAGS} \
    ${BUILD_ARGS} \
    --push \
    .
done

# ---------------------------------------------------------------------------
# Step 2: Package helm charts (architecture-independent)
# ---------------------------------------------------------------------------
mkdir -p deploy/docker/.build/charts
echo "Packaging navigator helm chart..."
helm package deploy/helm/navigator -d deploy/docker/.build/charts/

echo "Downloading gateway-helm chart..."
helm pull oci://docker.io/envoyproxy/gateway-helm \
  --version ${ENVOY_GATEWAY_VERSION} \
  --destination deploy/docker/.build/charts/

# ---------------------------------------------------------------------------
# Step 3: Build and push multi-arch cluster image.
# Component images are no longer bundled — they are pulled at runtime via
# the distribution registry; credentials are injected at deploy time.
# ---------------------------------------------------------------------------
echo ""
echo "Building multi-arch cluster image..."
CLUSTER_TAGS="-t ${REGISTRY}/${IMAGE_PREFIX:+${IMAGE_PREFIX}}cluster:${IMAGE_TAG}"
if [ "$TAG_LATEST" = true ]; then
  CLUSTER_TAGS="${CLUSTER_TAGS} -t ${REGISTRY}/${IMAGE_PREFIX:+${IMAGE_PREFIX}}cluster:latest"
fi

CLUSTER_IMAGE="${REGISTRY}/${IMAGE_PREFIX:+${IMAGE_PREFIX}}cluster"
docker buildx build \
  --platform "${PLATFORMS}" \
  -f deploy/docker/Dockerfile.cluster \
  ${CLUSTER_TAGS} \
  --build-arg K3S_VERSION=${K3S_VERSION} \
  --cache-from "type=registry,ref=${CLUSTER_IMAGE}:latest" \
  --cache-to "type=inline" \
  ${EXTRA_BUILD_FLAGS} \
  --push \
  .

# ---------------------------------------------------------------------------
# Step 4 (ECR only): Tag component images with :latest.
# Use --prefer-index=false to carbon-copy the source manifest format instead of
# wrapping it in an OCI image index (which the registry v3 proxy can't serve).
# ---------------------------------------------------------------------------
if [ "$TAG_LATEST" = true ]; then
  for component in sandbox server pki-job; do
    echo "Tagging ${IMAGE_PREFIX}${component}:latest..."
    docker buildx imagetools create \
      --prefer-index=false \
      -t "${REGISTRY}/${IMAGE_PREFIX}${component}:latest" \
      "${REGISTRY}/${IMAGE_PREFIX}${component}:${IMAGE_TAG}"
  done
fi

echo ""
echo "Done! Multi-arch images pushed to ${REGISTRY}:"
echo "  ${REGISTRY}/${IMAGE_PREFIX}sandbox:${IMAGE_TAG}"
echo "  ${REGISTRY}/${IMAGE_PREFIX}server:${IMAGE_TAG}"
echo "  ${REGISTRY}/${IMAGE_PREFIX}pki-job:${IMAGE_TAG}"
echo "  ${REGISTRY}/${IMAGE_PREFIX:+${IMAGE_PREFIX}}cluster:${IMAGE_TAG}"
if [ "$TAG_LATEST" = true ]; then
  echo "  (all also tagged :latest)"
fi
