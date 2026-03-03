#!/usr/bin/env bash
# Unified multi-arch build and push for all Navigator images.
#
# Usage:
#   docker-publish-multiarch.sh --mode registry   # Push to DOCKER_REGISTRY
#   docker-publish-multiarch.sh --mode ecr         # Push to ECR
#
# Environment:
#   IMAGE_TAG                - Image tag (default: dev)
#   K3S_VERSION              - k3s version (set by mise.toml [env])

#   DOCKER_PLATFORMS         - Target platforms (default: linux/amd64,linux/arm64)
#   RUST_BUILD_PROFILE       - Rust build profile for sandbox (default: release)
#   TAG_LATEST               - If true, add/update :latest tag (default: false)
#   EXTRA_DOCKER_TAGS        - Additional tags to add (comma or space separated)
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
    IMAGE_PREFIX="navigator-"
    ;;
  ecr)
    AWS_ACCOUNT_ID=${AWS_ACCOUNT_ID:-524473328983}
    AWS_REGION=${AWS_REGION:-us-west-2}
    ECR_HOST="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
    REGISTRY="${ECR_HOST}/navigator"
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
# Components with a subdirectory layout (e.g. deploy/docker/sandbox/) use
# Dockerfile.base from that subdirectory; others use the flat
# deploy/docker/Dockerfile.<component> layout.
# ---------------------------------------------------------------------------
resolve_dockerfile() {
  local comp="$1"
  local comp_dir="deploy/docker/${comp}"
  if [[ -d "${comp_dir}" ]]; then
    echo "${comp_dir}/Dockerfile.base"
  else
    echo "deploy/docker/Dockerfile.${comp}"
  fi
}

# ---------------------------------------------------------------------------
# Step 1: Build and push component images as multi-arch manifests.
# These use cross-compilation in the Dockerfile (BUILDPLATFORM != TARGETPLATFORM)
# so Rust compiles natively and only the final stage runs on the target arch.
# ---------------------------------------------------------------------------
echo "Building multi-arch component images..."
for component in sandbox server; do
  echo "Building ${IMAGE_PREFIX}${component} for ${PLATFORMS}..."
  BUILD_ARGS=""
  if [ "$component" = "sandbox" ]; then
    BUILD_ARGS="--build-arg RUST_BUILD_PROFILE=${RUST_BUILD_PROFILE:-release}"
  fi
  if [ -n "${SCCACHE_MEMCACHED_ENDPOINT:-}" ]; then
    BUILD_ARGS="${BUILD_ARGS} --build-arg SCCACHE_MEMCACHED_ENDPOINT=${SCCACHE_MEMCACHED_ENDPOINT}"
  fi
  DOCKERFILE=$(resolve_dockerfile "${component}")
  FULL_IMAGE="${REGISTRY}/${IMAGE_PREFIX}${component}"
  docker buildx build \
    --platform "${PLATFORMS}" \
    -f "${DOCKERFILE}" \
    -t "${FULL_IMAGE}:${IMAGE_TAG}" \
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

# ---------------------------------------------------------------------------
# Step 3: Build and push multi-arch cluster image.
# Component images are no longer bundled — they are pulled at runtime via
# the distribution registry; credentials are injected at deploy time.
# ---------------------------------------------------------------------------
echo ""
echo "Building multi-arch cluster image..."
CLUSTER_IMAGE="${REGISTRY}/${IMAGE_PREFIX:+${IMAGE_PREFIX}}cluster"
docker buildx build \
  --platform "${PLATFORMS}" \
  -f deploy/docker/Dockerfile.cluster \
  -t "${CLUSTER_IMAGE}:${IMAGE_TAG}" \
  --build-arg K3S_VERSION=${K3S_VERSION} \
  ${EXTRA_BUILD_FLAGS} \
  --push \
  .

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
  for component in sandbox server cluster; do
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
echo "  ${REGISTRY}/${IMAGE_PREFIX}sandbox:${IMAGE_TAG}"
echo "  ${REGISTRY}/${IMAGE_PREFIX}server:${IMAGE_TAG}"
echo "  ${REGISTRY}/${IMAGE_PREFIX:+${IMAGE_PREFIX}}cluster:${IMAGE_TAG}"
if [ "$TAG_LATEST" = true ]; then
  echo "  (all also tagged :latest)"
fi
if [ ${#EXTRA_TAGS[@]} -gt 0 ]; then
  echo "  (all also tagged: ${EXTRA_TAGS[*]})"
fi
