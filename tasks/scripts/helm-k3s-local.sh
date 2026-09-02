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

# Local OTLP receiver and trace UI. The current Aspire implementation accepts
# OTLP/gRPC directly, so the development cluster needs only one deployment.
OBSERVABILITY_NAMESPACE="observability"
COLLECTOR_IMAGE="${HELM_K3S_COLLECTOR_IMAGE:-mcr.microsoft.com/dotnet/aspire-dashboard:latest}"
COLLECTOR_HEALTH_TIMEOUT="${HELM_K3S_COLLECTOR_HEALTH_TIMEOUT:-120}"
# Host endpoint registered for the Skaffold-deployed gateway. Derive the
# gateway name from the worktree-specific cluster name so concurrent local
# clusters do not overwrite each other's CLI metadata.
GATEWAY_NAMESPACE="openshell"
GATEWAY_HOST_PORT="${HELM_K3S_GATEWAY_HOST_PORT:-8090}"
GATEWAY_NAME="${HELM_K3S_GATEWAY_NAME:-${CLUSTER_NAME}}"
FORWARD_PIDS=()

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
usage: $(basename "$0") <create|delete|start|stop|status|register|forward>

Environment:
  HELM_K3S_CLUSTER_NAME        k3d cluster name (default: openshell-dev-<branch-suffix>)
                               Each git worktree gets its own cluster derived from its branch name.
                               Override to share a single cluster across worktrees.
  HELM_K3S_KUBECONFIG          kubeconfig file to write/merge (default: repo kubeconfig or \$KUBECONFIG)
  HELM_K3S_LB_HOST_PORT        Host port mapped to load balancer port 80 (default: 8080)
  HELM_K3S_PRELOAD_SANDBOX_IMAGE
                               Sandbox image to docker pull and import into k3d
                               (default: ${DEFAULT_SANDBOX_PRELOAD_IMAGE}; set empty to skip)
  HELM_K3S_COLLECTOR_IMAGE     Image used for the local OTLP receiver and trace UI
                               (default: mcr.microsoft.com/dotnet/aspire-dashboard:latest)
  HELM_K3S_COLLECTOR_HEALTH_TIMEOUT
                               Seconds to wait for collector readiness (default: 120)
  HELM_K3S_GATEWAY_HOST_PORT   Host port forwarded to the gateway (default: 8090)
  HELM_K3S_GATEWAY_NAME        CLI gateway registration name
                               (default: worktree-specific k3d cluster name)

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
  local tmp merged_dir
  tmp="$(mktemp)"
  k3d kubeconfig get "${CLUSTER_NAME}" >"${tmp}"

  if [[ -s "${KUBECONFIG_TARGET}" ]]; then
    # Put the freshly generated k3d config first so its cluster, context, and
    # user entries replace stale entries with the same names. The API server's
    # random host port can change when Docker recreates the load balancer.
    KUBECONFIG="${tmp}:${KUBECONFIG_TARGET}" kubectl config view --flatten >"${tmp}.out"
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

install_trace_collector() {
  require_kubectl

  echo "Installing local trace collector in namespace '${OBSERVABILITY_NAMESPACE}'..."
  kubectl --kubeconfig="${KUBECONFIG_TARGET}" \
    create namespace "${OBSERVABILITY_NAMESPACE}" --dry-run=client -o yaml \
    | kubectl --kubeconfig="${KUBECONFIG_TARGET}" apply -f -

  kubectl --kubeconfig="${KUBECONFIG_TARGET}" apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openshell-collector
  namespace: ${OBSERVABILITY_NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: openshell-collector
  template:
    metadata:
      labels:
        app: openshell-collector
    spec:
      containers:
        - name: collector
          image: ${COLLECTOR_IMAGE}
          env:
            - name: ASPIRE_DASHBOARD_UNSECURED_ALLOW_ANONYMOUS
              value: "true"
          ports:
            - name: otlp-grpc
              containerPort: 18889
            - name: dashboard
              containerPort: 18888
          readinessProbe:
            httpGet:
              path: /
              port: dashboard
            initialDelaySeconds: 5
            periodSeconds: 5
            failureThreshold: 12
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              memory: 1Gi
---
apiVersion: v1
kind: Service
metadata:
  name: openshell-collector
  namespace: ${OBSERVABILITY_NAMESPACE}
spec:
  selector:
    app: openshell-collector
  ports:
    - name: otlp-grpc
      port: 4317
      targetPort: otlp-grpc
    - name: dashboard
      port: 18888
      targetPort: dashboard
EOF

  kubectl --kubeconfig="${KUBECONFIG_TARGET}" \
    rollout status deployment/openshell-collector \
    --namespace "${OBSERVABILITY_NAMESPACE}" \
    --timeout="${COLLECTOR_HEALTH_TIMEOUT}s"
}

configure_agent_sandbox_tracing() {
  require_kubectl

  case "${AGENT_SANDBOX_VERSION}" in
    v0.[0-4].*)
      echo "Agent Sandbox ${AGENT_SANDBOX_VERSION} does not support OTLP tracing; skipping controller tracing."
      return
      ;;
  esac

  local namespace="agent-sandbox-system"
  local deployment="agent-sandbox-controller"
  local controller_args
  controller_args="$(kubectl --kubeconfig="${KUBECONFIG_TARGET}" \
    --namespace="${namespace}" \
    get deployment "${deployment}" \
    -o jsonpath='{.spec.template.spec.containers[0].args}')"

  if [[ "${controller_args}" != *"--enable-tracing"* ]]; then
    kubectl --kubeconfig="${KUBECONFIG_TARGET}" \
      --namespace="${namespace}" \
      patch deployment "${deployment}" \
      --type=json \
      -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--enable-tracing"}]'
  fi

  kubectl --kubeconfig="${KUBECONFIG_TARGET}" \
    --namespace="${namespace}" \
    set env deployment/"${deployment}" \
    OTEL_EXPORTER_OTLP_ENDPOINT="http://openshell-collector.${OBSERVABILITY_NAMESPACE}.svc.cluster.local:4317" \
    OTEL_EXPORTER_OTLP_INSECURE=true

  kubectl --kubeconfig="${KUBECONFIG_TARGET}" \
    --namespace="${namespace}" \
    rollout status deployment/"${deployment}" \
    --timeout="${COLLECTOR_HEALTH_TIMEOUT}s"
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

  # Save without --platform: the platform-specific pull already constrained the
  # local image, and --platform fails on OCI index (multi-arch) manifests.
  tmp="$(mktemp "${TMPDIR:-/tmp}/openshell-sandbox-image.XXXXXX")"
  if ! docker image save -o "${tmp}" "${PRELOAD_SANDBOX_IMAGE}"; then
    echo "Pulling sandbox image for ${platform}..."
    docker pull --platform "${platform}" "${PRELOAD_SANDBOX_IMAGE}"
    docker image save -o "${tmp}" "${PRELOAD_SANDBOX_IMAGE}"
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
    echo "k3d cluster '${CLUSTER_NAME}' already exists; ensuring it is running."
    k3d cluster start "${CLUSTER_NAME}"
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
  install_trace_collector
  configure_agent_sandbox_tracing
  configure_ghcr_credentials
  preload_sandbox_image
  echo "Active context: $(k3d_context_name)"
  echo "Kubeconfig: ${KUBECONFIG_TARGET}"
  echo "Envoy Gateway LoadBalancer (port 80):  http://127.0.0.1:${HOST_LB_PORT}"
  echo "Trace collector endpoint: http://openshell-collector.${OBSERVABILITY_NAMESPACE}.svc.cluster.local:4317"
  echo "Gateway and trace collector host access: mise run helm:k3s:forward"
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

register_local_gateway() {
  local config_home openshell_dir gateway_dir endpoint

  if [[ ! "${GATEWAY_NAME}" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "error: HELM_K3S_GATEWAY_NAME must contain only letters, numbers, dots, underscores, or dashes" >&2
    return 2
  fi

  config_home="${XDG_CONFIG_HOME:-${HOME}/.config}"
  openshell_dir="${config_home}/openshell"
  gateway_dir="${openshell_dir}/gateways/${GATEWAY_NAME}"
  endpoint="http://127.0.0.1:${GATEWAY_HOST_PORT}"

  mkdir -p "${gateway_dir}"
  chmod 700 "${gateway_dir}" 2>/dev/null || true
  cat >"${gateway_dir}/metadata.json" <<EOF
{
  "name": "${GATEWAY_NAME}",
  "gateway_endpoint": "${endpoint}",
  "is_remote": false,
  "gateway_port": ${GATEWAY_HOST_PORT},
  "auth_mode": "plaintext"
}
EOF
  chmod 600 "${gateway_dir}/metadata.json" 2>/dev/null || true
  printf '%s' "${GATEWAY_NAME}" >"${openshell_dir}/active_gateway"
  chmod 600 "${openshell_dir}/active_gateway" 2>/dev/null || true

  echo "Registered and selected local gateway '${GATEWAY_NAME}' at ${endpoint}."
}

cleanup_forwards() {
  local pid
  trap - EXIT INT TERM
  for pid in "${FORWARD_PIDS[@]}"; do
    kill "${pid}" 2>/dev/null || true
  done
  for pid in "${FORWARD_PIDS[@]}"; do
    wait "${pid}" 2>/dev/null || true
  done
}

cmd_forward() {
  require_supported_os
  require_kubectl

  kubectl \
    --kubeconfig="${KUBECONFIG_TARGET}" \
    --context="$(k3d_context_name)" \
    --namespace="${OBSERVABILITY_NAMESPACE}" \
    get service/openshell-collector >/dev/null

  echo "Forwarding collector OTLP/gRPC to http://127.0.0.1:4317"
  echo "Forwarding trace UI to http://127.0.0.1:18888"

  trap cleanup_forwards EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  if kubectl \
    --kubeconfig="${KUBECONFIG_TARGET}" \
    --context="$(k3d_context_name)" \
    --namespace="${GATEWAY_NAMESPACE}" \
    get service/openshell >/dev/null 2>&1; then
    echo "Forwarding gateway to http://127.0.0.1:${GATEWAY_HOST_PORT}"
    kubectl \
      --kubeconfig="${KUBECONFIG_TARGET}" \
      --context="$(k3d_context_name)" \
      --namespace="${GATEWAY_NAMESPACE}" \
      port-forward service/openshell "${GATEWAY_HOST_PORT}:8080" &
    FORWARD_PIDS+=("$!")
  else
    echo "No Kubernetes gateway service found; forwarding collector ports only."
  fi

  kubectl \
    --kubeconfig="${KUBECONFIG_TARGET}" \
    --context="$(k3d_context_name)" \
    --namespace="${OBSERVABILITY_NAMESPACE}" \
    port-forward service/openshell-collector 4317:4317 18888:18888 &
  FORWARD_PIDS+=("$!")

  echo "Press Ctrl-C to stop."

  local pid status
  while true; do
    for pid in "${FORWARD_PIDS[@]}"; do
      if ! kill -0 "${pid}" 2>/dev/null; then
        status=0
        wait "${pid}" || status=$?
        if [[ ${status} -eq 0 ]]; then
          status=1
        fi
        echo "error: a port-forward process exited; stopping the remaining forwards" >&2
        return "${status}"
      fi
    done
    sleep 1
  done
}

main() {
  local sub="${1:-}"
  case "${sub}" in
    create) cmd_create ;;
    delete) cmd_delete ;;
    start) cmd_start ;;
    stop) cmd_stop ;;
    status) cmd_status ;;
    register) register_local_gateway ;;
    forward) cmd_forward ;;
    -h | --help | help | "") usage ; [[ -n "${sub}" ]] || exit 1 ;;
    *)
      echo "error: unknown command '${sub}'" >&2
      usage
      exit 1
      ;;
  esac
}

main "$@"
