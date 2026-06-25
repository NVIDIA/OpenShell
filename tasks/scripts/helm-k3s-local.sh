#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Local k3s for Helm / Skaffold workflows using k3d. macOS gets k3d from mise;
# Linux users should install k3d explicitly or point tests at a kind/existing cluster.
# Requires Docker running. Writes merged kubeconfig to HELM_K3S_KUBECONFIG or $KUBECONFIG or ./kubeconfig.
#
# Multi-worktree: the cluster name is derived from the last component of the current
# git branch (e.g. branch "kube-support/local-dev/tmutch" → cluster "openshell-dev-tmutch").
# Each worktree therefore gets its own isolated cluster and per-worktree kubeconfig.
# Override with HELM_K3S_CLUSTER_NAME to force a specific name.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Derive a DNS-safe suffix from the last component of the current branch name.
_branch="$(git -C "${ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null)" || _branch=""
_suffix="$(printf '%s' "${_branch##*/}" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | sed 's/-*$//')"
CLUSTER_NAME="${HELM_K3S_CLUSTER_NAME:-openshell-dev${_suffix:+-${_suffix}}}"
# k3d caps cluster names at 32 chars; validated in cmd_create so the operator
# gets an actionable hint instead of a deep-stack k3d validation error.
K3D_CLUSTER_NAME_MAX=32
# Host port forwarded to port 80 via the k3d load balancer.
# Used by Envoy Gateway's LoadBalancer service (values-gateway.yaml).
HOST_LB_PORT="${HELM_K3S_LB_HOST_PORT:-8080}"
# Preload the default community sandbox image so the first sandbox create does
# not pay the full registry pull cost inside the cluster.
DEFAULT_SANDBOX_PRELOAD_IMAGE="ghcr.io/nvidia/openshell-community/sandboxes/base:latest"
PRELOAD_SANDBOX_IMAGE="${HELM_K3S_PRELOAD_SANDBOX_IMAGE-${DEFAULT_SANDBOX_PRELOAD_IMAGE}}"

# Upstream agent-sandbox release pinned for both CRDs/controller and extensions.
# The Kubernetes driver supports the v1beta1 Sandbox API introduced in v0.5.0
# and falls back to v1alpha1 for v0.4.6 clusters. Override this env var to
# exercise the v1alpha1 controller release.
AGENT_SANDBOX_VERSION="${AGENT_SANDBOX_VERSION:-v0.5.0}"

default_kubeconfig="${ROOT}/kubeconfig"
if [[ -n "${HELM_K3S_KUBECONFIG:-}" ]]; then
  KUBECONFIG_TARGET="${HELM_K3S_KUBECONFIG}"
elif [[ -n "${KUBECONFIG:-}" ]]; then
  # mise sets KUBECONFIG to a single file — use it when unambiguous
  if [[ "${KUBECONFIG}" != *:* ]]; then
    KUBECONFIG_TARGET="${KUBECONFIG}"
  else
    KUBECONFIG_TARGET="${default_kubeconfig}"
  fi
else
  KUBECONFIG_TARGET="${default_kubeconfig}"
fi

usage() {
  cat >&2 <<EOF
usage: $(basename "$0") <create|delete|start|stop|status>

Environment:
  HELM_K3S_CLUSTER_NAME        k3d cluster name (default: openshell-dev-<branch-suffix>)
                               Each git worktree gets its own cluster derived from its branch name.
                               Override to share a single cluster across worktrees.
  HELM_K3S_KUBECONFIG          kubeconfig file to write/merge (default: repo kubeconfig or \$KUBECONFIG)
  HELM_K3S_LB_HOST_PORT        Host port mapped to load balancer port 80 (default: 8080)
  HELM_K3S_PRELOAD_SANDBOX_IMAGE
                               Sandbox image to docker pull and import into k3d
                               (default: ${DEFAULT_SANDBOX_PRELOAD_IMAGE}; set empty to skip)

macOS uses k3d from mise (Docker required). Linux can use this flow only when
k3d is installed explicitly; otherwise use kind or an existing cluster context.
Pair with: mise run helm:skaffold:dev
EOF
}

require_supported_os() {
  case "$(uname -s)" in
    Darwin | Linux) ;;
    *)
      echo "error: local k3s tasks are only supported on macOS and Linux." >&2
      exit 1
      ;;
  esac
}

require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "error: Docker is required for k3d. Install Docker Desktop (macOS) or Docker Engine (Linux)." >&2
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "error: Docker does not appear to be running." >&2
    exit 1
  fi
}

require_k3d() {
  if ! command -v k3d >/dev/null 2>&1; then
    if [[ "$(uname -s)" == "Linux" ]]; then
      echo "error: k3d not found. This repo no longer installs k3d through mise on Linux." >&2
      echo "Install k3d explicitly, or use kind/an existing cluster and set OPENSHELL_E2E_KUBE_CONTEXT." >&2
    else
      echo "error: k3d not found. Run: mise install" >&2
    fi
    exit 1
  fi
}

require_kubectl() {
  if ! command -v kubectl >/dev/null 2>&1; then
    echo "error: kubectl not found. Run: mise install" >&2
    exit 1
  fi
}

k3d_context_name() {
  echo "k3d-${CLUSTER_NAME}"
}

k3d_cluster_exists() {
  k3d cluster list "${CLUSTER_NAME}" >/dev/null 2>&1
}

merge_kubeconfig() {
  require_kubectl
  local tmp k3d_cfg merged_dir
  tmp="$(mktemp)"
  k3d kubeconfig get "${CLUSTER_NAME}" >"${tmp}"

  if [[ -s "${KUBECONFIG_TARGET}" ]]; then
    KUBECONFIG="${KUBECONFIG_TARGET}:${tmp}" kubectl config view --flatten >"${tmp}.out"
    mv "${tmp}.out" "${KUBECONFIG_TARGET}"
  else
    merged_dir="$(dirname "${KUBECONFIG_TARGET}")"
    mkdir -p "${merged_dir}"
    mv "${tmp}" "${KUBECONFIG_TARGET}"
  fi
  rm -f "${tmp}"

  kubectl --kubeconfig="${KUBECONFIG_TARGET}" config use-context "$(k3d_context_name)"
}

apply_base_manifests() {
  require_kubectl
  local base="https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${AGENT_SANDBOX_VERSION}"
  echo "Applying agent-sandbox manifest (${AGENT_SANDBOX_VERSION})..."
  kubectl --kubeconfig="${KUBECONFIG_TARGET}" apply -f "${base}/manifest.yaml"
}

configure_ghcr_credentials() {
  [[ -n "${GITHUB_PAT:-}" && -n "${GITHUB_USERNAME:-}" ]] || return 0

  echo "Configuring ghcr.io credentials on cluster nodes..."

  local registries_content
  registries_content="$(printf 'configs:\n  "ghcr.io":\n    auth:\n      username: %s\n      password: %s\n' \
    "${GITHUB_USERNAME}" "${GITHUB_PAT}")"

  local -a nodes=()
  while IFS= read -r _node; do nodes+=("$_node"); done < <(docker ps --format '{{.Names}}' \
    --filter "name=k3d-${CLUSTER_NAME}-server-" 2>/dev/null || true)

  if [[ ${#nodes[@]} -eq 0 ]]; then
    echo "warning: no server nodes found for cluster '${CLUSTER_NAME}', skipping ghcr.io credential setup." >&2
    return 0
  fi

  for node in "${nodes[@]}"; do
    printf '%s\n' "${registries_content}" \
      | docker exec -i "${node}" sh -c 'mkdir -p /etc/rancher/k3s && cat > /etc/rancher/k3s/registries.yaml'
    docker exec "${node}" kill -SIGHUP 1
    echo "  Configured ghcr.io credentials on ${node}"
  done
}

cluster_has_image() {
  local image="$1"
  local -a nodes=()
  while IFS= read -r _node; do nodes+=("$_node"); done < <(docker ps --format '{{.Names}}' \
    --filter "name=k3d-${CLUSTER_NAME}-server-" 2>/dev/null || true)

  for node in "${nodes[@]}"; do
    if docker exec "${node}" sh -c 'ctr -n k8s.io images list -q | grep -Fxq "$1"' sh "${image}"; then
      return 0
    fi
  done

  return 1
}

cluster_image_platform() {
  local -a nodes=()
  while IFS= read -r _node; do nodes+=("$_node"); done < <(docker ps --format '{{.Names}}' \
    --filter "name=k3d-${CLUSTER_NAME}-server-" 2>/dev/null || true)

  if [[ ${#nodes[@]} -gt 0 ]]; then
    local platform
    platform="$(docker inspect \
      --format '{{.ImageManifestDescriptor.platform.os}}/{{.ImageManifestDescriptor.platform.architecture}}' \
      "${nodes[0]}" 2>/dev/null || true)"
    if [[ "${platform}" != "/" && -n "${platform}" ]]; then
      echo "${platform}"
      return 0
    fi
  fi

  case "$(uname -m)" in
    arm64 | aarch64) echo "linux/arm64" ;;
    x86_64 | amd64) echo "linux/amd64" ;;
    *) echo "linux/$(uname -m)" ;;
  esac
}

preload_sandbox_image() {
  if [[ -z "${PRELOAD_SANDBOX_IMAGE}" ]]; then
    echo "Skipping sandbox image preload."
    return 0
  fi

  if cluster_has_image "${PRELOAD_SANDBOX_IMAGE}"; then
    echo "Sandbox image already present in cluster: ${PRELOAD_SANDBOX_IMAGE}"
    return 0
  fi

  local platform tmp
  platform="$(cluster_image_platform)"
  echo "Preloading sandbox image into k3d cluster: ${PRELOAD_SANDBOX_IMAGE}"
  echo "Sandbox image platform: ${platform}"
  if ! docker image inspect "${PRELOAD_SANDBOX_IMAGE}" >/dev/null 2>&1; then
    echo "Pulling sandbox image..."
    docker pull --platform "${platform}" "${PRELOAD_SANDBOX_IMAGE}"
  fi

  tmp="$(mktemp "${TMPDIR:-/tmp}/openshell-sandbox-image.XXXXXX")"
  if ! docker image save --platform "${platform}" -o "${tmp}" "${PRELOAD_SANDBOX_IMAGE}"; then
    echo "Pulling sandbox image for ${platform}..."
    docker pull --platform "${platform}" "${PRELOAD_SANDBOX_IMAGE}"
    docker image save --platform "${platform}" -o "${tmp}" "${PRELOAD_SANDBOX_IMAGE}"
  fi

  if ! k3d image import "${tmp}" --cluster "${CLUSTER_NAME}"; then
    rm -f "${tmp}"
    return 1
  fi

  rm -f "${tmp}"
}

cmd_create() {
  require_supported_os
  require_docker
  require_k3d

  if (( ${#CLUSTER_NAME} > K3D_CLUSTER_NAME_MAX )); then
    cat >&2 <<EOF
error: derived cluster name '${CLUSTER_NAME}' is ${#CLUSTER_NAME} chars; k3d caps at ${K3D_CLUSTER_NAME_MAX}.
Set HELM_K3S_CLUSTER_NAME to a shorter name, e.g.:
  HELM_K3S_CLUSTER_NAME=openshell-dev-${_suffix:0:$(( K3D_CLUSTER_NAME_MAX - 14 ))} mise run helm:k3s:create
EOF
    exit 1
  fi

  local lb_port_map="${HOST_LB_PORT}:80@loadbalancer"

  if k3d_cluster_exists; then
    echo "k3d cluster '${CLUSTER_NAME}' already exists; merging kubeconfig."
  else
    echo "Creating k3d cluster '${CLUSTER_NAME}'..."
    k3d cluster create "${CLUSTER_NAME}" \
      --wait \
      --kubeconfig-update-default=false \
      --kubeconfig-switch-context=false \
      --port "${lb_port_map}" \
      --k3s-arg "--disable=traefik@server:0"
  fi
  merge_kubeconfig
  apply_base_manifests
  configure_ghcr_credentials
  preload_sandbox_image
  echo "Active context: $(k3d_context_name)"
  echo "Kubeconfig: ${KUBECONFIG_TARGET}"
  echo "Envoy Gateway LoadBalancer (port 80):  http://127.0.0.1:${HOST_LB_PORT}"
}

cmd_delete() {
  require_supported_os
  require_k3d
  if k3d_cluster_exists; then
    k3d cluster delete "${CLUSTER_NAME}"
    echo "Deleted k3d cluster '${CLUSTER_NAME}'."
  else
    echo "No k3d cluster named '${CLUSTER_NAME}'."
  fi
}

cmd_start() {
  require_supported_os
  require_k3d
  k3d cluster start "${CLUSTER_NAME}"
}

cmd_stop() {
  require_supported_os
  require_k3d
  k3d cluster stop "${CLUSTER_NAME}"
}

cmd_status() {
  require_supported_os
  require_k3d
  k3d cluster list
}

main() {
  local sub="${1:-}"
  case "${sub}" in
    create) cmd_create ;;
    delete) cmd_delete ;;
    start) cmd_start ;;
    stop) cmd_stop ;;
    status) cmd_status ;;
    -h | --help | help | "") usage ; [[ -n "${sub}" ]] || exit 1 ;;
    *)
      echo "error: unknown command '${sub}'" >&2
      usage
      exit 1
      ;;
  esac
}

main "$@"
