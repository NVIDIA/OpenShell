#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Validates all OpenShift database-backend scenarios against a live cluster.
#
# Prerequisites:
#   - oc CLI authenticated to an OpenShift cluster
#   - helm 3.x installed
#   - Chart dependencies built (helm dependency build deploy/helm/openshell)
#
# Usage:
#   mise run e2e:openshift
#   e2e/rust/e2e-openshift.sh [--chart-path ./deploy/helm/openshell] [--image-tag dev]

set -euo pipefail

CHART_PATH="${CHART_PATH:-./deploy/helm/openshell}"
NAMESPACE="openshell"
RELEASE="openshell"
IMAGE_TAG="${IMAGE_TAG:-dev}"
WAIT_TIMEOUT="120s"
PASSED=0
FAILED=0
SCENARIOS=()

while [[ $# -gt 0 ]]; do
  case $1 in
    --chart-path) CHART_PATH="$2"; shift 2 ;;
    --image-tag)  IMAGE_TAG="$2"; shift 2 ;;
    --namespace)  NAMESPACE="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# --- helpers ----------------------------------------------------------------

log()  { echo "==> $*"; }
pass() { log "PASS: $1"; PASSED=$((PASSED + 1)); SCENARIOS+=("PASS  $1"); }
fail() { log "FAIL: $1 — $2"; FAILED=$((FAILED + 1)); SCENARIOS+=("FAIL  $1: $2"); }

wait_for_ready() {
  local label="$1" timeout="$2"
  if oc wait pod -n "$NAMESPACE" -l "$label" --for=condition=Ready --timeout="$timeout" 2>/dev/null; then
    return 0
  fi
  return 1
}

cleanup_release() {
  log "Cleaning up release $RELEASE"
  helm uninstall "$RELEASE" -n "$NAMESPACE" --wait 2>/dev/null || true
  # Wait for pods to terminate
  for i in $(seq 1 30); do
    if [ -z "$(oc get pods -n "$NAMESPACE" -l "app.kubernetes.io/instance=$RELEASE" --no-headers 2>/dev/null)" ]; then
      break
    fi
    sleep 2
  done
  # Clean up PVCs left by StatefulSets
  oc delete pvc -n "$NAMESPACE" -l "app.kubernetes.io/instance=$RELEASE" --wait=false 2>/dev/null || true
}

verify_gateway() {
  local scenario="$1"
  if wait_for_ready "app.kubernetes.io/name=openshell,app.kubernetes.io/instance=$RELEASE" "$WAIT_TIMEOUT"; then
    # Check the pod is actually running (not CrashLoopBackOff)
    local phase
    phase=$(oc get pod -n "$NAMESPACE" -l "app.kubernetes.io/name=openshell,app.kubernetes.io/instance=$RELEASE" \
      -o jsonpath='{.items[0].status.phase}' 2>/dev/null)
    if [ "$phase" = "Running" ]; then
      pass "$scenario"
    else
      fail "$scenario" "pod phase is $phase, expected Running"
    fi
  else
    local status
    status=$(oc get pods -n "$NAMESPACE" -l "app.kubernetes.io/name=openshell" --no-headers 2>/dev/null || echo "no pods found")
    fail "$scenario" "gateway pod not ready within $WAIT_TIMEOUT ($status)"
  fi
}

# --- setup ------------------------------------------------------------------

log "Setting up namespace $NAMESPACE"
oc create ns "$NAMESPACE" 2>/dev/null || true
oc adm policy add-scc-to-user privileged -z "${RELEASE}-sandbox" -n "$NAMESPACE"

OPENSHIFT_FLAGS=(
  --set server.disableTls=true
  --set podSecurityContext.fsGroup=null
  --set securityContext.runAsUser=null
  --set image.tag="$IMAGE_TAG"
)

# --- scenario 1: SQLite (default, no postgres) -----------------------------

SCENARIO="SQLite (default)"
log "Testing: $SCENARIO"
cleanup_release

helm install "$RELEASE" "$CHART_PATH" -n "$NAMESPACE" \
  "${OPENSHIFT_FLAGS[@]}"

verify_gateway "$SCENARIO"
cleanup_release

# --- scenario 2: Bundled PostgreSQL (deploy=true) ---------------------------

SCENARIO="Bundled PostgreSQL (deploy=true)"
log "Testing: $SCENARIO"
cleanup_release

helm install "$RELEASE" "$CHART_PATH" -n "$NAMESPACE" \
  "${OPENSHIFT_FLAGS[@]}" \
  --set postgres.enabled=true \
  --set postgres.deploy=true \
  --set postgres.auth.password=test-password

# Wait for postgres to be ready first
log "Waiting for bundled PostgreSQL..."
wait_for_ready "app.kubernetes.io/name=postgres,app.kubernetes.io/instance=$RELEASE" "$WAIT_TIMEOUT" || true

verify_gateway "$SCENARIO"
cleanup_release

# --- scenario 3: External PostgreSQL with existing Secret -------------------

SCENARIO="External PostgreSQL (existingSecret)"
log "Testing: $SCENARIO"
cleanup_release

# Deploy a standalone Bitnami PostgreSQL as the "external" database
EXTERNAL_PG_RELEASE="pg-external"
EXTERNAL_PG_PASSWORD="ext-test-password"
EXTERNAL_PG_DATABASE="openshell"
EXTERNAL_PG_USERNAME="openshell"

log "Deploying standalone PostgreSQL as external database..."
helm install "$EXTERNAL_PG_RELEASE" oci://registry-1.docker.io/bitnamicharts/postgresql \
  -n "$NAMESPACE" \
  --set auth.username="$EXTERNAL_PG_USERNAME" \
  --set auth.password="$EXTERNAL_PG_PASSWORD" \
  --set auth.database="$EXTERNAL_PG_DATABASE" \
  --set primary.podSecurityContext.fsGroup=null \
  --set primary.containerSecurityContext.runAsUser=null \
  --wait --timeout "$WAIT_TIMEOUT" 2>/dev/null || true

wait_for_ready "app.kubernetes.io/name=postgresql,app.kubernetes.io/instance=$EXTERNAL_PG_RELEASE" "$WAIT_TIMEOUT" || true

EXTERNAL_PG_HOST="${EXTERNAL_PG_RELEASE}-postgresql.${NAMESPACE}.svc.cluster.local"
EXTERNAL_PG_URI="postgresql://${EXTERNAL_PG_USERNAME}:${EXTERNAL_PG_PASSWORD}@${EXTERNAL_PG_HOST}:5432/${EXTERNAL_PG_DATABASE}"

# Create the existing Secret with the expected keys
log "Creating existing Secret with PostgreSQL credentials..."
oc create secret generic my-pg-credentials -n "$NAMESPACE" \
  --from-literal=host="$EXTERNAL_PG_HOST" \
  --from-literal=port="5432" \
  --from-literal=username="$EXTERNAL_PG_USERNAME" \
  --from-literal=password="$EXTERNAL_PG_PASSWORD" \
  --from-literal=database="$EXTERNAL_PG_DATABASE" \
  --from-literal=uri="$EXTERNAL_PG_URI" \
  2>/dev/null || true

# Install OpenShell pointing at the existing Secret
helm install "$RELEASE" "$CHART_PATH" -n "$NAMESPACE" \
  "${OPENSHIFT_FLAGS[@]}" \
  --set postgres.enabled=true \
  --set postgres.external.existingSecret=my-pg-credentials

verify_gateway "$SCENARIO"

# Cleanup external postgres and secret
cleanup_release
helm uninstall "$EXTERNAL_PG_RELEASE" -n "$NAMESPACE" --wait 2>/dev/null || true
oc delete secret my-pg-credentials -n "$NAMESPACE" 2>/dev/null || true
oc delete pvc -n "$NAMESPACE" -l "app.kubernetes.io/instance=$EXTERNAL_PG_RELEASE" --wait=false 2>/dev/null || true

# --- teardown ---------------------------------------------------------------

log "Removing SCC binding and namespace"
oc adm policy remove-scc-from-user privileged -z "${RELEASE}-sandbox" -n "$NAMESPACE" 2>/dev/null || true
oc delete ns "$NAMESPACE" --wait=false 2>/dev/null || true

# --- summary ----------------------------------------------------------------

echo ""
echo "========================================"
echo "  Test Summary"
echo "========================================"
for s in "${SCENARIOS[@]}"; do
  echo "  $s"
done
echo "----------------------------------------"
echo "  Passed: $PASSED  Failed: $FAILED"
echo "========================================"

if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
