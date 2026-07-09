#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/wait-ready.sh"

EXPERIMENT_ID="combined"
RUNS=10
NAMESPACE="${NAMESPACE:-default}"
TEMPLATE_NAME="${TEMPLATE_NAME:-openshell-warm}"
WARM_POOL_NAME="${WARM_POOL_NAME:-openshell-warm-pool}"
READINESS_METHOD="probe-1s"
INJECT_ENV="true"

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Measure claim-to-ready latency with the best readiness + env injection config.

Combines the fastest readiness pattern from prior experiments with env var
injection to produce a final "best case" warm pool performance profile.

Options:
  --runs N                Number of runs (default: 10)
  --readiness-method M    Readiness method (default: probe-1s)
                          Options: probe-default, probe-1s, readiness-gate, sidecar
  --no-env                Skip env var injection
  --namespace NS          Kubernetes namespace (default: default)
  -h, --help              Show this help

Readiness methods:
  probe-default    Standard readinessProbe with default timing
  probe-1s         readinessProbe with initialDelaySeconds=1, periodSeconds=1
  readiness-gate   Pod readiness gate set by init container or controller
  sidecar          Sidecar container that signals readiness
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runs)              RUNS="$2"; shift 2 ;;
    --readiness-method)  READINESS_METHOD="$2"; shift 2 ;;
    --no-env)            INJECT_ENV="false"; shift ;;
    --namespace)         NAMESPACE="$2"; shift 2 ;;
    -h|--help)           usage ;;
    *)                   log "ERROR: Unknown option: $1"; usage ;;
  esac
done

case "$READINESS_METHOD" in
  probe-default|probe-1s|readiness-gate|sidecar) ;;
  *) log "ERROR: Invalid readiness method: $READINESS_METHOD"; exit 1 ;;
esac

patch_template_for_readiness() {
  local method="$1"
  log "Configuring SandboxTemplate for readiness method: ${method}"

  case "$method" in
    probe-default)
      kubectl patch sandboxtemplate "$TEMPLATE_NAME" -n "$NAMESPACE" \
        --type merge -p '{
        "spec": {
          "podTemplateSpec": {
            "spec": {
              "containers": [{
                "name": "sandbox",
                "readinessProbe": {
                  "tcpSocket": {"port": 2222},
                  "initialDelaySeconds": 2,
                  "periodSeconds": 10
                }
              }]
            }
          }
        }
      }' 2>/dev/null || log "WARN: Could not patch template readiness probe"
      ;;
    probe-1s)
      kubectl patch sandboxtemplate "$TEMPLATE_NAME" -n "$NAMESPACE" \
        --type merge -p '{
        "spec": {
          "podTemplateSpec": {
            "spec": {
              "containers": [{
                "name": "sandbox",
                "readinessProbe": {
                  "tcpSocket": {"port": 2222},
                  "initialDelaySeconds": 1,
                  "periodSeconds": 1
                }
              }]
            }
          }
        }
      }' 2>/dev/null || log "WARN: Could not patch template readiness probe"
      ;;
    readiness-gate)
      kubectl patch sandboxtemplate "$TEMPLATE_NAME" -n "$NAMESPACE" \
        --type merge -p '{
        "spec": {
          "podTemplateSpec": {
            "spec": {
              "readinessGates": [{"conditionType": "sandbox.agents.x-k8s.io/Ready"}]
            }
          }
        }
      }' 2>/dev/null || log "WARN: Could not patch template readiness gates"
      ;;
    sidecar)
      log "Sidecar readiness requires custom template with sidecar container."
      log "Ensure your SandboxTemplate already includes the readiness sidecar."
      ;;
  esac
}

patch_env_policy() {
  if [[ "$INJECT_ENV" == "true" ]]; then
    log "Enabling env var injection on template"
    kubectl patch sandboxtemplate "$TEMPLATE_NAME" -n "$NAMESPACE" \
      --type merge \
      -p '{"spec":{"envVarsInjectionPolicy":"Allowed"}}' 2>/dev/null || \
      log "WARN: Could not patch env injection policy"
  fi
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
      return 1
    fi

    sleep 1
    (( elapsed++ ))
  done
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

run_combined() {
  local num_runs="$1"
  local config_label="${READINESS_METHOD}"
  if [[ "$INJECT_ENV" == "true" ]]; then
    config_label="${config_label}+env"
  fi

  local csv_file="${RESULTS_DIR}/combined.csv"

  log "Starting combined measurement: readiness=${READINESS_METHOD}, env=${INJECT_ENV}, runs=${num_runs}"
  ensure_results_dir

  patch_template_for_readiness "$READINESS_METHOD"
  patch_env_policy

  sleep 5
  log "Waiting for warm pool to stabilize after template patch..."

  echo "run,experiment,config,create_ts,ready_ts,delta_ms,pod,status,adoption" > "$csv_file"

  for (( i=1; i<=num_runs; i++ )); do
    local claim_name="combined-run-${i}"
    local status="ok"
    local adoption="unknown"

    log "Run ${i}/${num_runs}: creating claim ${claim_name} (${config_label})"

    local create_ts
    create_ts=$(capture_timestamp)

    local claim_yaml
    if [[ "$INJECT_ENV" == "true" ]]; then
      claim_yaml=$(cat <<YAML
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxClaim
metadata:
  name: ${claim_name}
spec:
  warmPoolRef:
    name: ${WARM_POOL_NAME}
  env:
  - name: AGENT_ID
    value: "agent-combined-${i}"
  - name: SESSION_TOKEN
    value: "tok-combined-${i}"
YAML
      )
    else
      claim_yaml=$(cat <<YAML
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxClaim
metadata:
  name: ${claim_name}
spec:
  warmPoolRef:
    name: ${WARM_POOL_NAME}
YAML
      )
    fi

    if ! echo "$claim_yaml" | kubectl apply -n "$NAMESPACE" -f - 2>/dev/null; then
      log "WARN: Failed to create claim ${claim_name}"
      status="create-failed"
      echo "${i},${EXPERIMENT_ID},${config_label},${create_ts},,,,${status},${adoption}" >> "$csv_file"
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
        local events_file="${RESULTS_DIR}/events-combined-run-${i}.json"
        collect_pod_events "$pod_name" "$NAMESPACE" > "$events_file"
        adoption=$(detect_adoption "$pod_name" "$NAMESPACE")
      fi

      echo "${i},${EXPERIMENT_ID},${config_label},${create_ts},${ready_ts},${delta_ms},${pod_name:-unknown},${status},${adoption}" >> "$csv_file"
      log "Run ${i}: ${delta_ms}ms (pod: ${pod_name:-unknown}, adoption: ${adoption})"
    else
      status="timeout"
      echo "${i},${EXPERIMENT_ID},${config_label},${create_ts},,,,${status},${adoption}" >> "$csv_file"
      log "Run ${i}: TIMEOUT"
    fi

    cleanup_claim "$claim_name"
    sleep 2
  done

  log "Results written to ${csv_file}"
  compute_stats "$csv_file"
}

run_combined "$RUNS"

log "Combined measurement complete (${READINESS_METHOD}, env=${INJECT_ENV})."
