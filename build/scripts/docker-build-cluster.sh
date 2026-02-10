#!/usr/bin/env bash
# Build the k3s cluster image with bundled helm charts.
#
# Environment:
#   IMAGE_TAG                - Image tag (default: dev)
#   K3S_VERSION              - k3s version (set by mise.toml [env])
#   ENVOY_GATEWAY_VERSION    - Envoy Gateway chart version (set by mise.toml [env])
#   DOCKER_PLATFORM          - Target platform (optional)
set -euo pipefail

IMAGE_TAG=${IMAGE_TAG:-dev}

# Create build directory for charts
mkdir -p deploy/docker/.build/charts

# Package navigator helm chart
echo "Packaging navigator helm chart..."
helm package deploy/helm/navigator -d deploy/docker/.build/charts/

# Download envoy-gateway helm chart
# This chart includes Gateway API CRDs, so we don't need a separate CRDs chart
echo "Downloading gateway-helm chart..."
helm pull oci://docker.io/envoyproxy/gateway-helm \
  --version ${ENVOY_GATEWAY_VERSION} \
  --destination deploy/docker/.build/charts/

# Build cluster image (no bundled component images — they are pulled at runtime
# from the distribution registry; credentials are injected at deploy time)
echo "Building cluster image..."
docker buildx build \
  ${DOCKER_PLATFORM:+--platform ${DOCKER_PLATFORM}} \
  -f deploy/docker/Dockerfile.cluster \
  -t navigator-cluster:${IMAGE_TAG} \
  --build-arg K3S_VERSION=${K3S_VERSION} \
  --load \
  .

echo "Done! Cluster image: navigator-cluster:${IMAGE_TAG}"
