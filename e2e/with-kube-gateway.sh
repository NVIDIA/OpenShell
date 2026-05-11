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
# Helm e2e currently uses plaintext gateway traffic (ci/values-tls-disabled.yaml).
#
# Image source: helm install pulls from ${OPENSHELL_REGISTRY}/{gateway,supervisor}:${IMAGE_TAG}
# (defaults: ghcr.io/nvidia/openshell, latest). CI sets IMAGE_TAG to the commit SHA;
# local devs should set it to a tag pulled from a registry the cluster can reach,
# or build and import images via a separate bootstrap step before running this script.

set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "Usage: e2e/with-kube-gateway.sh <command> [args...]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=e2e/support/gateway-common.sh
source "${ROOT}/e2e/support/gateway-common.sh"

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
  require_cmd k3d
  CLUSTER_NAME="oshe2e-$$-$(date +%s | tail -c 8)"
  echo "Creating ephemeral k3d cluster ${CLUSTER_NAME}..."
  HELM_K3S_CLUSTER_NAME="${CLUSTER_NAME}" \
  HELM_K3S_KUBECONFIG="${WORKDIR}/kubeconfig" \
    bash "${ROOT}/tasks/scripts/helm-k3s-local.sh" create
  CLUSTER_CREATED_BY_US=1
  export KUBECONFIG="${WORKDIR}/kubeconfig"
  KUBE_CONTEXT="k3d-${CLUSTER_NAME}"
fi

IMAGE_TAG_VALUE="${IMAGE_TAG:-latest}"
REGISTRY_VALUE="${OPENSHELL_REGISTRY:-ghcr.io/nvidia/openshell}"
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
#   2. Gateway of the cluster's Docker network (k3d-<cluster> for ephemeral
#      clusters, `kind` for kind clusters used in CI). Pods SNAT through their
#      node to this IP, which lands on the host's bridge interface and reaches
#      any 0.0.0.0-bound listener / published container port.
HOST_GATEWAY_IP="${OPENSHELL_E2E_HOST_GATEWAY_IP:-}"

# k3d primes CoreDNS with `host.k3d.internal` pointing at the IP that pods can
# use to reach the host (Docker Desktop's gvisor-net loopback on macOS/Windows,
# the docker bridge gateway on Linux). That mapping handles Docker Desktop
# correctly; the docker network gateway alone does not.
if [ -z "${HOST_GATEWAY_IP}" ] && command -v kubectl >/dev/null 2>&1; then
  detected="$(kctl -n kube-system get configmap coredns -o jsonpath='{.data.NodeHosts}' 2>/dev/null \
    | awk '$2 == "host.k3d.internal" { print $1; exit }')"
  if [ -n "${detected}" ]; then
    HOST_GATEWAY_IP="${detected}"
    echo "Detected host gateway IP ${HOST_GATEWAY_IP} from CoreDNS host.k3d.internal entry."
  fi
fi

# Fallback for non-k3d clusters (kind in CI, etc.): use the docker network
# gateway IP. Works on Linux where the bridge is reachable from pods; on macOS
# Docker Desktop without k3d, this will likely not route to the host.
if [ -z "${HOST_GATEWAY_IP}" ] && command -v docker >/dev/null 2>&1; then
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
  --values "${ROOT}/deploy/helm/openshell/ci/values-tls-disabled.yaml" \
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
