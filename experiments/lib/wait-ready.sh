#!/usr/bin/env bash
# Pod and resource readiness wait functions.
# Source this file from experiment scripts: source "$(dirname "$0")/../lib/wait-ready.sh"

set -euo pipefail

wait_for_ready() {
  local resource="$1"
  local timeout_s="${2:-120}"
  kubectl wait --for=condition=Ready "$resource" --timeout="${timeout_s}s" 2>/dev/null
}

wait_for_pod_ready() {
  local pod="$1"
  local ns="${2:-default}"
  local timeout_s="${3:-120}"
  local elapsed=0

  while [[ $elapsed -lt $timeout_s ]]; do
    local status
    status=$(kubectl get pod "$pod" \
      --namespace="$ns" \
      -o jsonpath='{range .status.conditions[?(@.type=="Ready")]}{.status}{end}' \
      2>/dev/null) || true

    if [[ "$status" == "True" ]]; then
      return 0
    fi

    local phase
    phase=$(kubectl get pod "$pod" \
      --namespace="$ns" \
      -o jsonpath='{.status.phase}' \
      2>/dev/null) || true

    if [[ "$phase" == "Failed" || "$phase" == "Succeeded" ]]; then
      echo "Pod $pod terminated with phase: $phase" >&2
      return 1
    fi

    if (( elapsed % 10 == 0 && elapsed > 0 )); then
      echo "Waiting for pod $pod to be Ready... (${elapsed}s/${timeout_s}s, phase: ${phase:-unknown})" >&2
    fi

    sleep 1
    elapsed=$((elapsed + 1))
  done

  echo "Timeout: pod $pod not Ready after ${timeout_s}s" >&2
  return 1
}

wait_for_sandbox_ready() {
  local name="$1"
  local ns="${2:-default}"
  local timeout_s="${3:-120}"
  local elapsed=0

  while [[ $elapsed -lt $timeout_s ]]; do
    local status
    status=$(kubectl get sandbox "$name" \
      --namespace="$ns" \
      -o jsonpath='{range .status.conditions[?(@.type=="Ready")]}{.status}{end}' \
      2>/dev/null) || true

    if [[ "$status" == "True" ]]; then
      return 0
    fi

    if (( elapsed % 10 == 0 && elapsed > 0 )); then
      echo "Waiting for sandbox $name to be Ready... (${elapsed}s/${timeout_s}s)" >&2
    fi

    sleep 1
    elapsed=$((elapsed + 1))
  done

  echo "Timeout: sandbox $name not Ready after ${timeout_s}s" >&2
  return 1
}
