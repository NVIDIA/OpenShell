#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# TLS-enabled Keycloak setup for the local k3s cluster.
# Uses the same quay.io/keycloak/keycloak image and realm JSON as the local
# Docker dev setup (scripts/keycloak-dev.sh), deploying via kubectl manifests.
#
# Safe to re-run. Each run rotates the development CA and serving certificate;
# Keycloak's --import-realm flag skips the realm if it already exists.
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
GATEWAY_NAMESPACE="${OPENSHELL_NAMESPACE:-openshell}"
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

TLS_DIR="$(mktemp -d)"
trap 'rm -rf "${TLS_DIR}"' EXIT

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

echo "Generating a development TLS certificate for '${SVC_HOSTNAME}'..."
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${TLS_DIR}/ca.key" \
    -out "${TLS_DIR}/ca.crt" \
    -days 30 \
    -subj "/CN=OpenShell development Keycloak CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes \
    -keyout "${TLS_DIR}/tls.key" \
    -out "${TLS_DIR}/tls.csr" \
    -subj "/CN=${SVC_HOSTNAME}" \
    >/dev/null 2>&1
printf '%s\n' \
    "subjectAltName=DNS:${SVC_HOSTNAME}" \
    "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature,keyEncipherment" \
    "extendedKeyUsage=serverAuth" \
    >"${TLS_DIR}/server.ext"
openssl x509 -req \
    -in "${TLS_DIR}/tls.csr" \
    -CA "${TLS_DIR}/ca.crt" \
    -CAkey "${TLS_DIR}/ca.key" \
    -CAcreateserial \
    -out "${TLS_DIR}/tls.crt" \
    -days 30 \
    -extfile "${TLS_DIR}/server.ext" \
    >/dev/null 2>&1

kubectl -n "${NAMESPACE}" create secret tls keycloak-tls \
    --cert="${TLS_DIR}/tls.crt" \
    --key="${TLS_DIR}/tls.key" \
    --dry-run=client -o yaml | kubectl apply -f -

# The Helm chart mounts OIDC trust bundles from its own namespace. Publish the
# development trust anchor there as well; rerunning this task rotates both the
# serving certificate and the trusted copy.
kubectl create namespace "${GATEWAY_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "${GATEWAY_NAMESPACE}" create configmap openshell-keycloak-ca \
    --from-file=ca.crt="${TLS_DIR}/ca.crt" \
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
            # Keycloak listens on 8443 in the container, but clients reach it
            # through the Service's standard HTTPS port. Keep discovery and
            # token issuers aligned with the explicit Service URL.
            - name: KC_HOSTNAME_PORT
              value: "443"
            - name: KC_HOSTNAME_STRICT
              value: "false"
            - name: KC_HOSTNAME_STRICT_HTTPS
              value: "true"
            - name: KC_HTTP_ENABLED
              value: "true"
            - name: KC_HTTPS_CERTIFICATE_FILE
              value: "/etc/keycloak-tls/tls.crt"
            - name: KC_HTTPS_CERTIFICATE_KEY_FILE
              value: "/etc/keycloak-tls/tls.key"
          ports:
            - containerPort: 8080
            - containerPort: 8443
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
            - name: tls
              mountPath: /etc/keycloak-tls
              readOnly: true
      volumes:
        - name: realm
          configMap:
            name: openshell-realm
        - name: tls
          secret:
            secretName: keycloak-tls
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
      name: http
    - port: 443
      targetPort: 8443
      name: https
EOF

# Reload the freshly generated serving certificate on repeat runs. The
# deployment spec itself is otherwise unchanged, so updating the Secret alone
# would not restart Keycloak.
kubectl -n "${NAMESPACE}" rollout restart deployment/keycloak

# ---------------------------------------------------------------------------
# Wait for readiness
# ---------------------------------------------------------------------------

echo "Waiting for Keycloak to be ready (up to ${HEALTH_TIMEOUT}s)..."
kubectl rollout status deployment/keycloak -n "${NAMESPACE}" --timeout="${HEALTH_TIMEOUT}s"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

ISSUER="https://${SVC_HOSTNAME}:443/realms/openshell"

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
