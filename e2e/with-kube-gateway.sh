#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run an e2e command against a Helm-deployed OpenShell gateway in Kubernetes.
#
# Modes:
#   - OPENSHELL_E2E_KUBE_CONTEXT set:
#       Target the named kubectl context, install the chart into an ephemeral
#       namespace, and port-forward the gateway. Cluster lifecycle is the
#       caller's responsibility (e.g. CI provisions kind via helm/kind-action).
#   - OPENSHELL_E2E_KUBE_CONTEXT unset:
#       Create a local k3d cluster via tasks/scripts/helm-k3s-local.sh, install
#       the chart, port-forward, and tear the cluster down on exit.
#
# Helm e2e currently uses plaintext gateway traffic (ci/values-skaffold.yaml).
# The certgen hook still runs so the gateway has sandbox JWT signing keys.
#
# Image source:
#   - Ephemeral k3d mode builds local `openshell/{gateway,supervisor}:${IMAGE_TAG}`
#     images by default, imports them into k3d, then installs the chart. This
#     mirrors the Skaffold local-dev path.
#   - Existing-context mode pulls from ${OPENSHELL_REGISTRY}/{gateway,supervisor}:${IMAGE_TAG}
#     (defaults: ghcr.io/nvidia/openshell, latest). CI sets IMAGE_TAG to the
#     commit SHA and preloads or publishes the images before running this script.

set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "Usage: e2e/with-kube-gateway.sh <command> [args...]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=e2e/support/gateway-common.sh
source "${ROOT}/e2e/support/gateway-common.sh"

e2e_preserve_mise_dirs
e2e_align_docker_host_with_cli_context

WORKDIR_PARENT="${TMPDIR:-/tmp}"
WORKDIR_PARENT="${WORKDIR_PARENT%/}"
WORKDIR="$(mktemp -d "${WORKDIR_PARENT}/openshell-e2e-kube.XXXXXX")"

CLUSTER_CREATED_BY_US=0
CLUSTER_NAME=""
KUBE_CONTEXT=""
NAMESPACE="openshell"
RELEASE_NAME="openshell"
PORTFORWARD_PID=""
PORTFORWARD_LOG="${WORKDIR}/portforward.log"
PORTFORWARD_HEALTH_PID=""
PORTFORWARD_HEALTH_LOG="${WORKDIR}/portforward-health.log"
HELM_INSTALLED=0

# Isolate CLI/SDK gateway metadata from the developer's real config.
export XDG_CONFIG_HOME="${WORKDIR}/config"
export XDG_DATA_HOME="${WORKDIR}/data"

kctl() {
  kubectl --context "${KUBE_CONTEXT}" "$@"
}

helmctl() {
  helm --kube-context "${KUBE_CONTEXT}" "$@"
}

cleanup() {
  local exit_code=$?

  if [ -n "${PORTFORWARD_PID}" ]; then
    kill "${PORTFORWARD_PID}" >/dev/null 2>&1 || true
    wait "${PORTFORWARD_PID}" >/dev/null 2>&1 || true
  fi

  if [ -n "${PORTFORWARD_HEALTH_PID}" ]; then
    kill "${PORTFORWARD_HEALTH_PID}" >/dev/null 2>&1 || true
    wait "${PORTFORWARD_HEALTH_PID}" >/dev/null 2>&1 || true
  fi

  if [ "${exit_code}" -ne 0 ] && [ -n "${KUBE_CONTEXT}" ] && [ -n "${NAMESPACE}" ]; then
    if command -v kubectl >/dev/null 2>&1 \
       && kctl get namespace "${NAMESPACE}" >/dev/null 2>&1; then
      echo "=== gateway pod state (preserved for debugging) ==="
      kctl -n "${NAMESPACE}" get pods -o wide 2>&1 || true
      echo "=== gateway events ==="
      kctl -n "${NAMESPACE}" get events --sort-by=.lastTimestamp 2>&1 \
        | tail -n 80 || true
      echo "=== gateway logs (last 200 lines) ==="
      kctl -n "${NAMESPACE}" logs \
        -l "app.kubernetes.io/instance=${RELEASE_NAME}" --tail=200 \
        --all-containers --prefix 2>&1 || true
      echo "=== end gateway debug output ==="
    fi
    if [ -f "${PORTFORWARD_LOG}" ]; then
      echo "=== port-forward log ==="
      cat "${PORTFORWARD_LOG}" || true
      echo "=== end port-forward log ==="
    fi
    if [ -f "${PORTFORWARD_HEALTH_LOG}" ]; then
      echo "=== health port-forward log ==="
      cat "${PORTFORWARD_HEALTH_LOG}" || true
      echo "=== end health port-forward log ==="
    fi
  fi

  if [ "${HELM_INSTALLED}" = "1" ] && [ -n "${KUBE_CONTEXT}" ] && [ -n "${NAMESPACE}" ]; then
    if command -v helm >/dev/null 2>&1; then
      helmctl uninstall "${RELEASE_NAME}" --namespace "${NAMESPACE}" --wait \
        --timeout 60s >/dev/null 2>&1 || true
    fi
    if command -v kubectl >/dev/null 2>&1; then
      # Wait for the namespace to fully delete so back-to-back runs don't hit
      # "namespace is being terminated" when helm install creates it again.
      kctl delete namespace "${NAMESPACE}" --wait=true --timeout=60s \
        --ignore-not-found >/dev/null 2>&1 || true
    fi
  fi

  if [ "${CLUSTER_CREATED_BY_US}" = "1" ] && [ -n "${CLUSTER_NAME}" ]; then
    if command -v k3d >/dev/null 2>&1 && k3d cluster list "${CLUSTER_NAME}" \
        >/dev/null 2>&1; then
      echo "Deleting ephemeral k3d cluster ${CLUSTER_NAME}..."
      k3d cluster delete "${CLUSTER_NAME}" >/dev/null 2>&1 || true
    fi
  fi

  rm -rf "${WORKDIR}" 2>/dev/null || true
}
trap cleanup EXIT

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: $1 is required to run Helm-backed e2e tests" >&2
    exit 2
  fi
}

require_cmd helm
require_cmd kubectl
require_cmd curl

if [ -n "${OPENSHELL_E2E_KUBE_CONTEXT:-}" ]; then
  KUBE_CONTEXT="${OPENSHELL_E2E_KUBE_CONTEXT}"
  echo "Using existing kubectl context: ${KUBE_CONTEXT}"
  if ! kctl cluster-info >/dev/null 2>&1; then
    echo "ERROR: kubectl context '${KUBE_CONTEXT}' is not reachable." >&2
    exit 2
  fi
else
  if ! command -v k3d >/dev/null 2>&1; then
    if [ "$(uname -s)" = "Linux" ]; then
      echo "ERROR: k3d is not installed by mise on Linux in this repo." >&2
      echo "Set OPENSHELL_E2E_KUBE_CONTEXT to a kind/existing cluster, or install k3d explicitly." >&2
      exit 2
    fi
    require_cmd k3d
  fi
  CLUSTER_NAME="oshe2e-$$-$(date +%s | tail -c 8)"
  echo "Creating ephemeral k3d cluster ${CLUSTER_NAME}..."
  HELM_K3S_CLUSTER_NAME="${CLUSTER_NAME}" \
  HELM_K3S_KUBECONFIG="${WORKDIR}/kubeconfig" \
    bash "${ROOT}/tasks/scripts/helm-k3s-local.sh" create
  CLUSTER_CREATED_BY_US=1
  export KUBECONFIG="${WORKDIR}/kubeconfig"
  KUBE_CONTEXT="k3d-${CLUSTER_NAME}"
fi

if [ -z "${OPENSHELL_E2E_KUBE_BUILD_IMAGES+x}" ]; then
  if [ "${CLUSTER_CREATED_BY_US}" = "1" ]; then
    OPENSHELL_E2E_KUBE_BUILD_IMAGES=1
  else
    OPENSHELL_E2E_KUBE_BUILD_IMAGES=0
  fi
fi

if [ "${OPENSHELL_E2E_KUBE_BUILD_IMAGES}" = "1" ]; then
  REGISTRY_VALUE="${OPENSHELL_REGISTRY:-openshell}"
  IMAGE_TAG_VALUE="${IMAGE_TAG:-e2e-${CLUSTER_NAME:-local}}"
else
  REGISTRY_VALUE="${OPENSHELL_REGISTRY:-ghcr.io/nvidia/openshell}"
  IMAGE_TAG_VALUE="${IMAGE_TAG:-latest}"
fi
REGISTRY_VALUE="${REGISTRY_VALUE%/}"

# Resolve a host-gateway IP that sandbox pods can dial to reach test fixtures
# running on the developer/CI host (HTTP fixtures bound to 0.0.0.0 plus sibling
# Docker containers with published ports). The Helm chart wires this into pod
# hostAliases for host.openshell.internal / host.docker.internal — without it,
# every test that relies on the alias has to skip on the kube driver.
#
# Preference order:
#   1. OPENSHELL_E2E_HOST_GATEWAY_IP — operator override (remote clusters where
#      auto-detection has no signal).
#   2. k3d's CoreDNS host.k3d.internal entry. On Docker Desktop this is a
#      host-routable address; the Docker network gateway is not.
#   3. Gateway of the cluster's Docker network (k3d-<cluster> for ephemeral
#      clusters, `kind` for kind clusters used in CI). Pods SNAT through their
#      node to this IP, which lands on the host's bridge interface and reaches
#      any 0.0.0.0-bound listener / published container port.
HOST_GATEWAY_IP="${OPENSHELL_E2E_HOST_GATEWAY_IP:-}"

# k3d primes CoreDNS with `host.k3d.internal` pointing at the IP that pods can
# use to reach the host (Docker Desktop's gvisor-net loopback on macOS/Windows,
# the docker bridge gateway on Linux). That mapping handles Docker Desktop
# correctly; the docker network gateway alone does not.
if [ -z "${HOST_GATEWAY_IP}" ] && command -v kubectl >/dev/null 2>&1; then
  for _ in {1..15}; do
    detected="$(kctl -n kube-system get configmap coredns -o jsonpath='{.data.NodeHosts}' 2>/dev/null \
      | awk '$2 == "host.k3d.internal" { print $1; exit }' || true)"
    if [ -n "${detected}" ]; then
      HOST_GATEWAY_IP="${detected}"
      echo "Detected host gateway IP ${HOST_GATEWAY_IP} from CoreDNS host.k3d.internal entry."
      break
    fi
    sleep 1
  done
fi

# Fallback for non-k3d clusters (kind in CI, etc.): use the docker network
# gateway IP. Works on Linux where the bridge is reachable from pods; on macOS
# Docker Desktop without k3d, this will likely not route to the host.
use_docker_network_gateway=1
if [ "$(uname -s)" = "Darwin" ] \
   && { [ "${CLUSTER_CREATED_BY_US}" = "1" ] || [[ "${KUBE_CONTEXT}" == k3d-* ]]; }; then
  use_docker_network_gateway=0
fi
if [ -z "${HOST_GATEWAY_IP}" ] \
   && [ "${use_docker_network_gateway}" = "1" ] \
   && command -v docker >/dev/null 2>&1; then
  candidate_networks=()
  if [ "${CLUSTER_CREATED_BY_US}" = "1" ]; then
    candidate_networks+=("k3d-${CLUSTER_NAME}")
  elif [[ "${KUBE_CONTEXT}" == k3d-* ]]; then
    candidate_networks+=("k3d-${KUBE_CONTEXT#k3d-}")
  elif [[ "${KUBE_CONTEXT}" == kind-* ]]; then
    candidate_networks+=("kind")
  else
    candidate_networks+=("kind" "k3d-${KUBE_CONTEXT#k3d-}")
  fi
  for net in "${candidate_networks[@]}"; do
    [ -n "${net}" ] || continue
    # Prefer the IPv4 gateway — kind dual-stacks its network and the IPv6 entry
    # is unreachable for the typical test-host listener (0.0.0.0 bind).
    detected="$(docker network inspect "${net}" \
      -f '{{range .IPAM.Config}}{{.Gateway}}{{"\n"}}{{end}}' 2>/dev/null \
      | awk '/^[0-9.]+$/ { print; exit }')"
    if [ -n "${detected}" ]; then
      HOST_GATEWAY_IP="${detected}"
      echo "Detected host gateway IP ${HOST_GATEWAY_IP} from docker network '${net}'."
      break
    fi
  done
fi
if [ -z "${HOST_GATEWAY_IP}" ]; then
  echo "WARNING: could not resolve a host gateway IP for the active cluster." >&2
  echo "         Tests that require host.openshell.internal will be skipped." >&2
  echo "         Set OPENSHELL_E2E_HOST_GATEWAY_IP to override." >&2
fi

# Import locally-available gateway/supervisor images into the k3d cluster so
# devs working off local builds don't depend on the configured registry. For
# kind clusters (used by CI), images must be loaded before this script runs —
# the workflow handles that via `kind load docker-image`. Best-effort: when an
# image isn't present locally, the cluster falls back to its pull behavior.
import_cluster_name=""
if [ "${CLUSTER_CREATED_BY_US}" = "1" ]; then
  import_cluster_name="${CLUSTER_NAME}"
elif [[ "${KUBE_CONTEXT}" == k3d-* ]] && command -v k3d >/dev/null 2>&1; then
  candidate="${KUBE_CONTEXT#k3d-}"
  if k3d cluster list "${candidate}" >/dev/null 2>&1; then
    import_cluster_name="${candidate}"
  fi
fi
if [ "${OPENSHELL_E2E_KUBE_BUILD_IMAGES}" = "1" ]; then
  require_cmd docker
  echo "Building local Kubernetes e2e images (${REGISTRY_VALUE}/{gateway,supervisor}:${IMAGE_TAG_VALUE})..."
  CONTAINER_ENGINE=docker IMAGE_REGISTRY="${REGISTRY_VALUE}" IMAGE_TAG="${IMAGE_TAG_VALUE}" \
    bash "${ROOT}/tasks/scripts/docker-build-image.sh" gateway
  CONTAINER_ENGINE=docker IMAGE_REGISTRY="${REGISTRY_VALUE}" IMAGE_TAG="${IMAGE_TAG_VALUE}" \
    bash "${ROOT}/tasks/scripts/docker-build-image.sh" supervisor
fi

if [ -n "${import_cluster_name}" ]; then
  for image in \
    "${REGISTRY_VALUE}/gateway:${IMAGE_TAG_VALUE}" \
    "${REGISTRY_VALUE}/supervisor:${IMAGE_TAG_VALUE}"; do
    if docker image inspect "${image}" >/dev/null 2>&1; then
      echo "Importing ${image} into k3d cluster ${import_cluster_name}..."
      k3d image import "${image}" --cluster "${import_cluster_name}" \
        --mode direct >/dev/null
    fi
  done
fi

# The Kubernetes compute driver creates and watches Sandbox CRs reconciled
# by the upstream agent-sandbox-controller. Without the CRD + controller,
# every gateway K8s call 404s and CreateSandbox never produces a Pod.
echo "Installing agent-sandbox CRDs and controller..."
kctl apply -f "${ROOT}/deploy/kube/manifests/agent-sandbox.yaml"
kctl wait --for=condition=Established crd/sandboxes.agents.x-k8s.io --timeout=120s
kctl -n agent-sandbox-system rollout status statefulset/agent-sandbox-controller --timeout=300s

helm_extra_args=()
if [ -n "${HOST_GATEWAY_IP}" ]; then
  helm_extra_args+=(--set "server.hostGatewayIP=${HOST_GATEWAY_IP}")
fi

echo "Installing Helm chart (release=${RELEASE_NAME}, namespace=${NAMESPACE}, tag=${IMAGE_TAG_VALUE})..."
helmctl install "${RELEASE_NAME}" "${ROOT}/deploy/helm/openshell" \
  --namespace "${NAMESPACE}" --create-namespace \
  --values "${ROOT}/deploy/helm/openshell/ci/values-skaffold.yaml" \
  --set "fullnameOverride=openshell" \
  --set "image.repository=${REGISTRY_VALUE}/gateway" \
  --set "image.tag=${IMAGE_TAG_VALUE}" \
  --set "supervisor.image.repository=${REGISTRY_VALUE}/supervisor" \
  --set "supervisor.image.tag=${IMAGE_TAG_VALUE}" \
  "${helm_extra_args[@]}" \
  --wait --timeout 5m
HELM_INSTALLED=1

LOCAL_PORT="$(e2e_pick_port)"
echo "Starting kubectl port-forward svc/openshell ${LOCAL_PORT}:8080..."
kctl -n "${NAMESPACE}" port-forward "svc/openshell" \
  "${LOCAL_PORT}:8080" >"${PORTFORWARD_LOG}" 2>&1 &
PORTFORWARD_PID=$!

elapsed=0
timeout=30
while [ "${elapsed}" -lt "${timeout}" ]; do
  if ! kill -0 "${PORTFORWARD_PID}" 2>/dev/null; then
    echo "ERROR: kubectl port-forward exited before becoming reachable" >&2
    cat "${PORTFORWARD_LOG}" >&2 || true
    exit 1
  fi
  if curl -s -o /dev/null --connect-timeout 1 "http://127.0.0.1:${LOCAL_PORT}"; then
    break
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done
if [ "${elapsed}" -ge "${timeout}" ]; then
  echo "ERROR: port-forward did not accept TCP within ${timeout}s" >&2
  cat "${PORTFORWARD_LOG}" >&2 || true
  exit 1
fi

# Dedicated port-forward to the gateway pod's health listener. The chart's
# Service intentionally exposes only the gRPC and metrics ports — kubelet
# probes the health endpoint directly on the pod IP — so the /readyz e2e
# test reaches it through this separate forward. Target the named `health`
# containerPort declared on the StatefulSet so a future override of
# `service.healthPort` stays compatible without touching this script.
HEALTH_LOCAL_PORT="$(e2e_pick_port)"
echo "Starting kubectl port-forward sts/${RELEASE_NAME} ${HEALTH_LOCAL_PORT}:health..."
kctl -n "${NAMESPACE}" port-forward "sts/${RELEASE_NAME}" \
  "${HEALTH_LOCAL_PORT}:health" >"${PORTFORWARD_HEALTH_LOG}" 2>&1 &
PORTFORWARD_HEALTH_PID=$!

elapsed=0
timeout=30
while [ "${elapsed}" -lt "${timeout}" ]; do
  if ! kill -0 "${PORTFORWARD_HEALTH_PID}" 2>/dev/null; then
    echo "ERROR: kubectl health port-forward exited before becoming reachable" >&2
    cat "${PORTFORWARD_HEALTH_LOG}" >&2 || true
    exit 1
  fi
  if curl -s -o /dev/null --connect-timeout 1 "http://127.0.0.1:${HEALTH_LOCAL_PORT}/healthz"; then
    break
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done
if [ "${elapsed}" -ge "${timeout}" ]; then
  echo "ERROR: health port-forward did not accept TCP within ${timeout}s" >&2
  cat "${PORTFORWARD_HEALTH_LOG}" >&2 || true
  exit 1
fi

export OPENSHELL_E2E_HEALTH_PORT="${HEALTH_LOCAL_PORT}"

GATEWAY_NAME="openshell-e2e-kube-${LOCAL_PORT}"
GATEWAY_ENDPOINT="http://127.0.0.1:${LOCAL_PORT}"
e2e_register_plaintext_gateway \
  "${XDG_CONFIG_HOME}" \
  "${GATEWAY_NAME}" \
  "${GATEWAY_ENDPOINT}" \
  "${LOCAL_PORT}"

export OPENSHELL_GATEWAY="${GATEWAY_NAME}"
export OPENSHELL_E2E_DRIVER="kubernetes"
export OPENSHELL_E2E_SANDBOX_NAMESPACE="${NAMESPACE}"
export OPENSHELL_PROVISION_TIMEOUT="${OPENSHELL_PROVISION_TIMEOUT:-300}"

echo "Running e2e command against ${GATEWAY_ENDPOINT}: $*"
"$@"
