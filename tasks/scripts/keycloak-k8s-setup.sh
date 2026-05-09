#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# One-time Keycloak setup for the local k3s cluster.
# Uses the same quay.io/keycloak/keycloak image and realm JSON as the local
# Docker dev setup (scripts/keycloak-dev.sh), deploying via kubectl manifests.
#
# Idempotent: safe to re-run. The Deployment and ConfigMap are applied with
# kubectl apply, and Keycloak's --import-realm flag skips the realm if it
# already exists.
#
# Usage:
#   mise run keycloak:k8s:setup
#
# After setup, add deploy/helm/openshell/values-keycloak.yaml to your Helm
# release and redeploy:
#   skaffold dev -f deploy/helm/openshell/skaffold.yaml
#   (uncomment values-keycloak.yaml in skaffold.yaml valuesFiles first)
#
# To get tokens for the CLI while the cluster is running:
#   kubectl -n keycloak port-forward svc/keycloak 9090:80
#   curl -s -X POST http://localhost:9090/realms/openshell/protocol/openid-connect/token \
#     -d 'grant_type=password&client_id=openshell-cli&username=admin@test&password=admin' \
#     | jq -r .access_token

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

NAMESPACE="keycloak"
KEYCLOAK_IMAGE="${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:24.0}"
ADMIN_USER="${KEYCLOAK_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
SETUP_PORT="${KEYCLOAK_SETUP_PORT:-9090}"
REALM_FILE="${ROOT}/scripts/keycloak-realm.json"
HEALTH_TIMEOUT="${KEYCLOAK_HEALTH_TIMEOUT:-120}"

# Keycloak's in-cluster service hostname, used as the forced KC_HOSTNAME so
# that the iss claim in tokens is consistent regardless of how they were
# obtained (e.g. via a localhost port-forward). The gateway fetches JWKS from
# this URL inside the cluster. See values-keycloak.yaml.
SVC_HOSTNAME="keycloak.${NAMESPACE}.svc.cluster.local"

if [[ ! -f "${REALM_FILE}" ]]; then
    echo "error: realm file not found: ${REALM_FILE}" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Namespace + ConfigMap
# ---------------------------------------------------------------------------

echo "Creating namespace '${NAMESPACE}'..."
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

echo "Applying realm ConfigMap..."
kubectl -n "${NAMESPACE}" create configmap openshell-realm \
    --from-file=realm.json="${REALM_FILE}" \
    --dry-run=client -o yaml | kubectl apply -f -

# ---------------------------------------------------------------------------
# Deployment + Service
# ---------------------------------------------------------------------------

echo "Applying Keycloak Deployment and Service..."
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: keycloak
  namespace: ${NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: keycloak
  template:
    metadata:
      labels:
        app: keycloak
    spec:
      containers:
        - name: keycloak
          image: ${KEYCLOAK_IMAGE}
          args: ["start-dev", "--import-realm"]
          env:
            - name: KEYCLOAK_ADMIN
              value: "${ADMIN_USER}"
            - name: KEYCLOAK_ADMIN_PASSWORD
              value: "${ADMIN_PASSWORD}"
            # Force a consistent iss claim in tokens regardless of the URL
            # used for token acquisition (e.g. a localhost port-forward).
            - name: KC_HOSTNAME
              value: "${SVC_HOSTNAME}"
            - name: KC_HOSTNAME_STRICT
              value: "false"
            - name: KC_HOSTNAME_STRICT_HTTPS
              value: "false"
            - name: KC_HTTP_ENABLED
              value: "true"
          ports:
            - containerPort: 8080
          readinessProbe:
            httpGet:
              path: /realms/master
              port: 8080
            initialDelaySeconds: 20
            periodSeconds: 5
            failureThreshold: 12
          resources:
            requests:
              cpu: 500m
              memory: 512Mi
            limits:
              memory: 1Gi
          volumeMounts:
            - name: realm
              mountPath: /opt/keycloak/data/import
      volumes:
        - name: realm
          configMap:
            name: openshell-realm
---
apiVersion: v1
kind: Service
metadata:
  name: keycloak
  namespace: ${NAMESPACE}
spec:
  selector:
    app: keycloak
  ports:
    - port: 80
      targetPort: 8080
EOF

# ---------------------------------------------------------------------------
# Wait for readiness
# ---------------------------------------------------------------------------

echo "Waiting for Keycloak to be ready (up to ${HEALTH_TIMEOUT}s)..."
kubectl rollout status deployment/keycloak -n "${NAMESPACE}" --timeout="${HEALTH_TIMEOUT}s"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

ISSUER="http://${SVC_HOSTNAME}/realms/openshell"

echo ""
echo "Keycloak is ready."
echo ""
echo "  In-cluster issuer:  ${ISSUER}"
echo "  Helm values file:   deploy/helm/openshell/values-keycloak.yaml"
echo ""
echo "  To enable OIDC on the gateway, uncomment values-keycloak.yaml in"
echo "  deploy/helm/openshell/skaffold.yaml and restart skaffold."
echo ""
echo "  To get tokens for CLI use, keep a port-forward running:"
echo "    kubectl -n ${NAMESPACE} port-forward svc/keycloak ${SETUP_PORT}:80"
echo ""
echo "  Test users (token endpoint: http://localhost:${SETUP_PORT}/realms/openshell/protocol/openid-connect/token):"
echo "    admin@test / admin  (role: openshell-admin)"
echo "    user@test  / user   (role: openshell-user)"
echo ""
echo "  Get a token:"
echo "    curl -s -X POST http://localhost:${SETUP_PORT}/realms/openshell/protocol/openid-connect/token \\"
echo "      -d 'grant_type=password&client_id=openshell-cli&username=admin@test&password=admin' \\"
echo "      | jq -r .access_token"
echo ""
