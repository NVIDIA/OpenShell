#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/wait-ready.sh"

EXPERIMENT_ID="env-injection"
CONFIG="allowed"
RUNS=5
NAMESPACE="${NAMESPACE:-default}"
TEMPLATE_NAME="${TEMPLATE_NAME:-openshell-warm}"
WARM_POOL_NAME="${WARM_POOL_NAME:-openshell-warm-pool}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Measure env var injection behavior when claiming warm pool sandboxes.

Options:
  --config CONFIG   Configuration: allowed (default), disallowed
  --runs N          Number of runs (default: 5)
  --namespace NS    Kubernetes namespace (default: default)
  -h, --help        Show this help

Configurations:
  allowed      SandboxTemplate has envVarsInjectionPolicy: Allowed.
               Claims include env vars and measure whether a warm sandbox
               is adopted or a cold-start fallback occurs.
  disallowed   SandboxTemplate has envVarsInjectionPolicy: Disallowed (or unset).
               Claims include env vars to document rejection/fallback behavior.
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)    CONFIG="$2"; shift 2 ;;
    --runs)      RUNS="$2"; shift 2 ;;
    --namespace) NAMESPACE="$2"; shift 2 ;;
    -h|--help)   usage ;;
    *)           log "ERROR: Unknown option: $1"; usage ;;
  esac
done

if [[ "$CONFIG" != "allowed" && "$CONFIG" != "disallowed" ]]; then
  log "ERROR: Invalid config: $CONFIG (must be allowed or disallowed)"
  exit 1
fi

patch_template_policy() {
  local policy="$1"
  log "Patching SandboxTemplate ${TEMPLATE_NAME} with envVarsInjectionPolicy: ${policy}"
  kubectl patch sandboxtemplate "$TEMPLATE_NAME" \
    -n "$NAMESPACE" \
    --type merge \
    -p "{\"spec\":{\"envVarsInjectionPolicy\":\"${policy}\"}}" 2>/dev/null || {
    log "WARN: Could not patch template (may not exist yet or field unsupported)"
    return 1
  }
}

get_claim_pod() {
  local claim_name="$1"
  kubectl get pods -n "$NAMESPACE" \
    -l "sandbox.agents.x-k8s.io/claim=$claim_name" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo ""
}

wait_claim_ready() {
  local name="$1"
  local timeout="${2:-120}"
  local elapsed=0
  while (( elapsed < timeout )); do
    local status
    status=$(kubectl get sandboxclaim "$name" -n "$NAMESPACE" \
      -o jsonpath='{range .status.conditions[?(@.type=="Ready")]}{.status}{end}' \
      2>/dev/null) || true

    if [[ "$status" == "True" ]]; then
      return 0
    fi

    local phase
    phase=$(kubectl get sandboxclaim "$name" -n "$NAMESPACE" \
      -o jsonpath='{.status.phase}' 2>/dev/null) || true

    if [[ "$phase" == "Failed" ]]; then
      log "Claim $name failed"
      return 1
    fi

    sleep 1
    (( elapsed++ ))
  done

  log "WARN: Claim $name did not become ready within ${timeout}s"
  return 1
}

cleanup_claim() {
  local name="$1"
  kubectl delete sandboxclaim "$name" -n "$NAMESPACE" --ignore-not-found --wait=false 2>/dev/null || true
  local elapsed=0
  while (( elapsed < 30 )); do
    if ! kubectl get sandboxclaim "$name" -n "$NAMESPACE" &>/dev/null; then
      return 0
    fi
    sleep 1
    (( elapsed++ ))
  done
}

run_allowed() {
  local num_runs="$1"
  local csv_file="${RESULTS_DIR}/env-injection-allowed.csv"

  log "Starting env injection measurement: config=allowed, runs=${num_runs}"
  ensure_results_dir

  patch_template_policy "Allowed" || true

  echo "run,experiment,config,create_ts,ready_ts,delta_ms,pod,status,adoption" > "$csv_file"

  for (( i=1; i<=num_runs; i++ )); do
    local claim_name="envinj-allowed-run-${i}"
    local status="ok"
    local adoption="unknown"

    log "Run ${i}/${num_runs}: creating claim ${claim_name} with env vars"

    local create_ts
    create_ts=$(capture_timestamp)

    if ! kubectl apply -n "$NAMESPACE" -f - <<YAML
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxClaim
metadata:
  name: ${claim_name}
spec:
  warmPoolRef:
    name: ${WARM_POOL_NAME}
  env:
  - name: AGENT_ID
    value: "agent-run-${i}"
  - name: SESSION_TOKEN
    value: "tok-session-${i}"
YAML
    then
      log "WARN: Failed to create claim ${claim_name}"
      status="create-failed"
      echo "${i},${EXPERIMENT_ID},allowed,${create_ts},,,,${status},${adoption}" >> "$csv_file"
      cleanup_claim "$claim_name"
      continue
    fi

    if wait_claim_ready "$claim_name" 120; then
      local ready_ts
      ready_ts=$(capture_timestamp)
      local delta_ms
      delta_ms=$(( (ready_ts - create_ts) / 1000000 ))

      local pod_name
      pod_name=$(get_claim_pod "$claim_name")

      if [[ -n "$pod_name" ]]; then
        local events_file="${RESULTS_DIR}/events-envinj-allowed-run-${i}.json"
        collect_pod_events "$pod_name" "$NAMESPACE" > "$events_file"
        adoption=$(detect_adoption "$pod_name" "$NAMESPACE")
      fi

      echo "${i},${EXPERIMENT_ID},allowed,${create_ts},${ready_ts},${delta_ms},${pod_name:-unknown},${status},${adoption}" >> "$csv_file"
      log "Run ${i}: ${delta_ms}ms (pod: ${pod_name:-unknown}, adoption: ${adoption})"
    else
      status="timeout"
      echo "${i},${EXPERIMENT_ID},allowed,${create_ts},,,,${status},${adoption}" >> "$csv_file"
      log "Run ${i}: TIMEOUT"
    fi

    cleanup_claim "$claim_name"
    sleep 2
  done

  log "Results written to ${csv_file}"
  compute_stats "$csv_file"
}

run_disallowed() {
  local num_runs="$1"
  local csv_file="${RESULTS_DIR}/env-injection-disallowed.csv"

  log "Starting env injection measurement: config=disallowed, runs=${num_runs}"
  ensure_results_dir

  patch_template_policy "Disallowed" || true

  echo "run,experiment,config,create_ts,ready_ts,delta_ms,pod,status,behavior" > "$csv_file"

  for (( i=1; i<=num_runs; i++ )); do
    local claim_name="envinj-disallowed-run-${i}"
    local behavior="unknown"

    log "Run ${i}/${num_runs}: creating claim ${claim_name} with env vars (policy=Disallowed)"

    local create_ts
    create_ts=$(capture_timestamp)

    local apply_output
    local apply_exit=0
    apply_output=$(kubectl apply -n "$NAMESPACE" -f - 2>&1 <<YAML
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxClaim
metadata:
  name: ${claim_name}
spec:
  warmPoolRef:
    name: ${WARM_POOL_NAME}
  env:
  - name: AGENT_ID
    value: "agent-run-${i}"
  - name: SESSION_TOKEN
    value: "tok-session-${i}"
YAML
    ) || apply_exit=$?

    if (( apply_exit != 0 )); then
      behavior="rejected-at-apply"
      log "Run ${i}: Claim rejected at apply (exit=${apply_exit}): ${apply_output}"
      echo "${i},${EXPERIMENT_ID},disallowed,${create_ts},,,,rejected,${behavior}" >> "$csv_file"
      continue
    fi

    sleep 3

    local phase
    phase=$(kubectl get sandboxclaim "$claim_name" -n "$NAMESPACE" \
      -o jsonpath='{.status.phase}' 2>/dev/null) || phase=""

    local conditions
    conditions=$(kubectl get sandboxclaim "$claim_name" -n "$NAMESPACE" \
      -o jsonpath='{.status.conditions[*].message}' 2>/dev/null) || conditions=""

    if [[ "$phase" == "Failed" ]]; then
      behavior="failed-phase"
    elif wait_claim_ready "$claim_name" 60; then
      local ready_ts
      ready_ts=$(capture_timestamp)
      local delta_ms
      delta_ms=$(( (ready_ts - create_ts) / 1000000 ))

      local pod_name
      pod_name=$(get_claim_pod "$claim_name")
      local adoption
      adoption=$(detect_adoption "${pod_name:-}" "$NAMESPACE")

      if [[ "$adoption" == "cold-fallback" ]]; then
        behavior="cold-fallback-with-env-stripped"
      else
        behavior="unexpected-warm-adopted"
      fi

      echo "${i},${EXPERIMENT_ID},disallowed,${create_ts},${ready_ts},${delta_ms},${pod_name:-unknown},ok,${behavior}" >> "$csv_file"
      log "Run ${i}: ${delta_ms}ms (behavior: ${behavior}, conditions: ${conditions})"
      cleanup_claim "$claim_name"
      continue
    else
      behavior="timeout"
    fi

    log "Run ${i}: behavior=${behavior}, phase=${phase}, conditions=${conditions}"
    echo "${i},${EXPERIMENT_ID},disallowed,${create_ts},,,,${behavior},${behavior}" >> "$csv_file"

    cleanup_claim "$claim_name"
    sleep 2
  done

  log "Results written to ${csv_file}"
  log "Review ${csv_file} for behavior observations under Disallowed policy."
}

case "$CONFIG" in
  allowed)
    run_allowed "$RUNS"
    ;;
  disallowed)
    run_disallowed "$RUNS"
    ;;
esac

log "Env injection measurement complete."
