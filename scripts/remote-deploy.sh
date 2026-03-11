#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Deploy the current checkout to a remote machine for gateway development/testing.
#
# The script syncs the local source tree to a remote host, bootstraps the toolchain
# there, builds the CLI and Docker images from the synced checkout, then starts or
# updates a gateway using `openshell gateway start`.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./scripts/remote-deploy.sh <user@host> [options]

Options:
  --remote-dir DIR            Remote checkout directory (default: openshell)
  --name NAME                 Cluster name (default: openshell)
  --port PORT                 Gateway port (default: 8080)
  --kube-port [PORT]          Expose kube-apiserver on a host port; omit value to auto-pick
  --ssh-key PATH              SSH private key for ssh/rsync
  --skip-sync                 Skip rsync and use the existing remote checkout
  --recreate                  Destroy and recreate the gateway from scratch
  --plaintext                 Listen on plaintext HTTP instead of mTLS
  --disable-gateway-auth      Keep TLS but disable client certificate enforcement
  --image-tag TAG             Docker image tag to build/deploy (default: dev)
  --cargo-version VERSION     Override OPENSHELL_CARGO_VERSION for remote Docker builds
  --help                      Show this help

Examples:
  ./scripts/remote-deploy.sh ubuntu@devbox
  ./scripts/remote-deploy.sh ubuntu@devbox --recreate --port 18080
  ./scripts/remote-deploy.sh ubuntu@devbox --plaintext --ssh-key ~/.ssh/devbox
  ./scripts/remote-deploy.sh my-sandbox -./scripts/remote-deploy.sh my-sandbox --remote-dir --name openshell --port 8080 --recreate --plaintext
EOF
}

info() { echo "==> $*"; }
err() { echo "ERROR: $*" >&2; }

require_value() {
  local flag="$1"
  local value="${2-}"
  if [[ -z "${value}" ]]; then
    err "${flag} requires a value"
    exit 1
  fi
}

REMOTE_HOST=""
REMOTE_DIR=${REMOTE_DIR:-openshell}
CLUSTER_NAME=${CLUSTER_NAME:-openshell}
GATEWAY_PORT=${GATEWAY_PORT:-8080}
KUBE_PORT="${KUBE_PORT:-}"
SSH_KEY="${SSH_KEY:-}"
IMAGE_TAG=${IMAGE_TAG:-dev}
CARGO_VERSION=${OPENSHELL_CARGO_VERSION:-0.0.0-dev}
SKIP_SYNC=false
RECREATE=false
PLAINTEXT=false
DISABLE_GATEWAY_AUTH=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --remote-dir)
      require_value "$1" "${2-}"
      REMOTE_DIR="$2"
      shift 2
      ;;
    --name)
      require_value "$1" "${2-}"
      CLUSTER_NAME="$2"
      shift 2
      ;;
    --port)
      require_value "$1" "${2-}"
      GATEWAY_PORT="$2"
      shift 2
      ;;
    --kube-port)
      if [[ $# -gt 1 && ! "$2" =~ ^-- ]]; then
        KUBE_PORT="$2"
        shift 2
      else
        KUBE_PORT="auto"
        shift
      fi
      ;;
    --ssh-key)
      require_value "$1" "${2-}"
      SSH_KEY="$2"
      shift 2
      ;;
    --skip-sync)
      SKIP_SYNC=true
      shift
      ;;
    --recreate)
      RECREATE=true
      shift
      ;;
    --plaintext)
      PLAINTEXT=true
      shift
      ;;
    --disable-gateway-auth)
      DISABLE_GATEWAY_AUTH=true
      shift
      ;;
    --image-tag)
      require_value "$1" "${2-}"
      IMAGE_TAG="$2"
      shift 2
      ;;
    --cargo-version)
      require_value "$1" "${2-}"
      CARGO_VERSION="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    --*)
      err "Unknown argument: $1"
      usage >&2
      exit 1
      ;;
    *)
      if [[ -n "${REMOTE_HOST}" ]]; then
        err "Multiple remote hosts provided: ${REMOTE_HOST} and $1"
        usage >&2
        exit 1
      fi
      REMOTE_HOST="$1"
      shift
      ;;
  esac
done

if [[ -z "${REMOTE_HOST}" ]]; then
  err "Remote host is required"
  usage >&2
  exit 1
fi

if [[ "${PLAINTEXT}" == "true" && "${DISABLE_GATEWAY_AUTH}" == "true" ]]; then
  err "--disable-gateway-auth is ignored when --plaintext is set; choose one mode"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SSH_ARGS=()
if [[ -n "${SSH_KEY}" ]]; then
  SSH_ARGS=(-i "${SSH_KEY}")
fi

if [[ "${SKIP_SYNC}" != "true" ]]; then
  info "Preparing ${REMOTE_HOST}:${REMOTE_DIR}"
  ssh "${SSH_ARGS[@]}" "${REMOTE_HOST}" "mkdir -p '${REMOTE_DIR}'"

  info "Syncing source to ${REMOTE_HOST}:${REMOTE_DIR}"
  RSYNC_SSH=(ssh)
  if [[ -n "${SSH_KEY}" ]]; then
    RSYNC_SSH+=(-i "${SSH_KEY}")
  fi

  rsync -az --delete \
    -e "${RSYNC_SSH[*]}" \
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

SECURITY_MODE="mTLS enabled"
if [[ "${PLAINTEXT}" == "true" ]]; then
  SECURITY_MODE="plaintext HTTP"
elif [[ "${DISABLE_GATEWAY_AUTH}" == "true" ]]; then
  SECURITY_MODE="TLS enabled, client cert auth disabled"
fi

info "Deploying gateway on ${REMOTE_HOST} (port=${GATEWAY_PORT}, security=${SECURITY_MODE})"
ssh -t "${SSH_ARGS[@]}" "${REMOTE_HOST}" \
  bash -s -- \
  "${REMOTE_DIR}" \
  "${CLUSTER_NAME}" \
  "${GATEWAY_PORT}" \
  "${IMAGE_TAG}" \
  "${CARGO_VERSION}" \
  "${RECREATE}" \
  "${PLAINTEXT}" \
  "${DISABLE_GATEWAY_AUTH}" \
  "${KUBE_PORT}" <<'REMOTE_EOF'
set -euo pipefail

REMOTE_DIR="$1"
CLUSTER_NAME="$2"
GATEWAY_PORT="$3"
IMAGE_TAG="$4"
CARGO_VERSION="$5"
RECREATE="$6"
PLAINTEXT="$7"
DISABLE_GATEWAY_AUTH="$8"
KUBE_PORT="${9:-}"

cd "${REMOTE_DIR}"

if ! command -v mise >/dev/null 2>&1; then
  echo "==> Installing mise..."
  curl https://mise.run | sh
fi
export PATH="$HOME/.local/bin:$PATH"

echo "==> Installing tools via mise..."
mise trust --yes
mise install --yes

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: Docker is not installed on the remote host." >&2
  exit 1
fi

echo "==> Building openshell CLI..."
mise exec -- cargo build --release -p navigator-cli
mkdir -p "$HOME/.local/bin"
install -m 0755 target/release/openshell "$HOME/.local/bin/openshell"

# Ensure `mise exec -- openshell` uses the release binary rather than the local
# development shim, which expects git metadata that is not synced to the VM.
install -m 0755 target/release/openshell scripts/bin/openshell

# Prevent a stale repo-local .env from changing the deployment unexpectedly.
rm -f .env

echo "==> Building Docker images (tag=${IMAGE_TAG})..."
export OPENSHELL_CARGO_VERSION="${CARGO_VERSION}"
export IMAGE_TAG
mise exec -- tasks/scripts/docker-build-cluster.sh
mise exec -- tasks/scripts/docker-build-component.sh gateway
mise exec -- tasks/scripts/docker-build-component.sh sandbox

export OPENSHELL_CLUSTER_IMAGE="openshell/cluster:${IMAGE_TAG}"
export OPENSHELL_PUSH_IMAGES="openshell/gateway:${IMAGE_TAG},openshell/sandbox:${IMAGE_TAG}"

start_args=(
  gateway
  start
  --name "${CLUSTER_NAME}"
  --port "${GATEWAY_PORT}"
)

if [[ "${RECREATE}" == "true" ]]; then
  start_args+=(--recreate)
fi
if [[ "${PLAINTEXT}" == "true" ]]; then
  start_args+=(--plaintext)
fi
if [[ "${DISABLE_GATEWAY_AUTH}" == "true" ]]; then
  start_args+=(--disable-gateway-auth)
fi
if [[ -n "${KUBE_PORT}" ]]; then
  if [[ "${KUBE_PORT}" == "auto" ]]; then
    start_args+=(--kube-port)
  else
    start_args+=(--kube-port "${KUBE_PORT}")
  fi
fi

echo "==> Starting gateway..."
mise exec -- openshell "${start_args[@]}"

echo ""
echo "============================================"
echo "  Gateway deployed successfully"
echo "  Cluster: ${CLUSTER_NAME}"
echo "  Gateway port: ${GATEWAY_PORT}"
if [[ "${PLAINTEXT}" == "true" ]]; then
  echo "  Security: plaintext HTTP"
elif [[ "${DISABLE_GATEWAY_AUTH}" == "true" ]]; then
  echo "  Security: TLS enabled, client cert auth disabled"
else
  echo "  Security: mTLS enabled"
fi
echo "============================================"
REMOTE_EOF

PROTO="https"
if [[ "${PLAINTEXT}" == "true" ]]; then
  PROTO="http"
fi

info "Done. Gateway is running on ${REMOTE_HOST}:${GATEWAY_PORT}"
info "Health check:"
info "  curl ${PROTO}://${REMOTE_HOST}:${GATEWAY_PORT}/health"
