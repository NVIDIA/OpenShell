#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Remote deploy script for NemoClaw cluster on a VM.
#
# Rsyncs the source tree to a remote VM, ensures mise is installed, then
# runs `mise run cluster` which handles everything: tool installation,
# Docker image builds, CLI compilation, registry setup, and cluster
# bootstrap.
#
# Usage:
#   ./scripts/remote-deploy.sh [SSH_HOST] [--skip-sync]
#
# Environment:
#   REMOTE_HOST       - SSH host (default: drew-cpu-sandbox)
#   REMOTE_DIR        - Remote directory (default: ~/nemoclaw)
#   GATEWAY_PORT      - Gateway port (default: 8080)
#   CLUSTER_NAME      - Cluster name (default: nemoclaw)

set -euo pipefail

REMOTE_DIR=${REMOTE_DIR:-/home/ubuntu/nemoclaw}
GATEWAY_PORT=8080
CLUSTER_NAME=${CLUSTER_NAME:-nemoclaw}
REMOTE_HOST=${REMOTE_HOST:-drew-cpu-sandbox}
SKIP_SYNC=false

for arg in "$@"; do
  case "${arg}" in
    --skip-sync) SKIP_SYNC=true ;;
    --*)
      echo "Unknown argument: ${arg}" >&2
      exit 1
      ;;
    *)
      REMOTE_HOST="${arg}"
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

info() { echo "==> $*"; }

# ---------------------------------------------------------------------------
# Step 1: rsync source to remote
# ---------------------------------------------------------------------------
if [[ "${SKIP_SYNC}" != "true" ]]; then
  info "Syncing source to ${REMOTE_HOST}:${REMOTE_DIR}"
  rsync -az --delete \
    --exclude 'target/' \
    --exclude '.git/' \
    --exclude '.cache/' \
    --exclude 'node_modules/' \
    --exclude '*.pyc' \
    --exclude '__pycache__/' \
    --exclude '.venv/' \
    --exclude 'e2e/' \
    --exclude 'deploy/docker/.build/' \
    "${REPO_ROOT}/" "${REMOTE_HOST}:${REMOTE_DIR}/"
  info "Sync complete"
fi

# ---------------------------------------------------------------------------
# Step 2: Install mise if missing, then run cluster bootstrap
# ---------------------------------------------------------------------------
info "Deploying cluster on ${REMOTE_HOST} (plaintext behind tunnel)..."
ssh -t "${REMOTE_HOST}" bash -s -- "${REMOTE_DIR}" "${CLUSTER_NAME}" "${GATEWAY_PORT}" <<'REMOTE_EOF'
set -euo pipefail

REMOTE_DIR="$1"
CLUSTER_NAME="$2"
GATEWAY_PORT="$3"
cd "${REMOTE_DIR}"

# Install mise if not present
if ! command -v mise >/dev/null 2>&1; then
  echo "==> Installing mise..."
  curl https://mise.run | sh
fi
export PATH="$HOME/.local/bin:$PATH"

# Trust the repo config and install all tools (rust, helm, kubectl, etc.)
echo "==> Installing tools via mise..."
mise trust --yes
mise install --yes

# Verify Docker is available (not managed by mise)
if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: Docker is not installed on the remote host." >&2
  exit 1
fi

# Build the nemoclaw CLI (needed by cluster-bootstrap.sh)
echo "==> Building nemoclaw CLI..."
mise exec -- cargo build --release -p navigator-cli
mkdir -p "$HOME/.local/bin"
rm -f "$HOME/.local/bin/nemoclaw"
cp target/release/nemoclaw "$HOME/.local/bin/nemoclaw"

# mise.toml adds scripts/bin/ to PATH, which contains a development shim
# that builds a *debug* binary and uses git-based fingerprinting (which
# doesn't work without .git). Replace the shim with the release binary
# so that `mise exec -- nemoclaw` uses the correct build.
rm -f scripts/bin/nemoclaw
cp target/release/nemoclaw scripts/bin/nemoclaw

# Build Docker images so the cluster has up-to-date server and chart content.
# The cluster image must be built with docker-build-cluster.sh (not the
# generic docker-build-component.sh) because it runs `helm package` first
# to produce a fresh chart tarball containing the current statefulset.yaml.
#
# NEMOCLAW_CARGO_VERSION is set explicitly because the .git directory is
# not synced to the VM, and docker-build-component.sh calls release.py
# which needs git tags to compute the version.
# Clear stale .env so mise doesn't load a cached GATEWAY_PORT from a
# previous run (mise.toml has _.file = [".env"]).
rm -f .env

# Destroy existing cluster BEFORE building images. The destroy path
# removes the cluster Docker image to prevent stale reuse, so we must
# build after destroying.
echo "==> Destroying existing cluster (if any)..."
mise exec -- nemoclaw gateway destroy --name "${CLUSTER_NAME}" 2>/dev/null || true

# Build Docker images. NEMOCLAW_CARGO_VERSION is set explicitly because
# the .git directory is not synced to the VM.
echo "==> Building Docker images..."
export NEMOCLAW_CARGO_VERSION=0.0.0-dev
mise exec -- tasks/scripts/docker-build-cluster.sh
mise exec -- tasks/scripts/docker-build-component.sh server
mise exec -- tasks/scripts/docker-build-component.sh sandbox

export NEMOCLAW_CLUSTER_IMAGE="navigator/cluster:dev"
export NEMOCLAW_PUSH_IMAGES="navigator/server:dev,navigator/sandbox:dev"
export IMAGE_TAG="dev"

echo "==> Deploying gateway (plaintext behind tunnel, port=${GATEWAY_PORT})..."
mise exec -- nemoclaw gateway start \
  --name "${CLUSTER_NAME}" \
  --port "${GATEWAY_PORT}" \
  --plaintext

echo ""
echo "============================================"
echo "  Cluster deployed successfully!"
echo "  Gateway port: ${GATEWAY_PORT}"
echo "  TLS: disabled (plaintext HTTP behind tunnel)"
echo ""
echo "  Test with:"
echo "    curl http://localhost:${GATEWAY_PORT}/health"
echo "============================================"
REMOTE_EOF

info "Done! Cluster is running on ${REMOTE_HOST}:${GATEWAY_PORT}"
info "Cloudflare tunnel should proxy https://8080-3vdegyusg.brevlab.com -> localhost:${GATEWAY_PORT}"
info ""
info "Test from your machine:"
info "  curl https://8080-3vdegyusg.brevlab.com/health"
