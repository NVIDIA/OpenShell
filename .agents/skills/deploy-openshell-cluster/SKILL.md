---
name: deploy-openshell-cluster
description: Deploy OpenShell gateway with Helm on Kubernetes or OpenShift, auto-detect cluster type, apply OpenShift-only SCC/security overrides when needed, and configure SQLite or PostgreSQL persistence. Use when the user asks to deploy OpenShell to a cluster, reinstall the Helm release, or enable postgres.enabled with internal or external mode.
---

# Deploy OpenShell Cluster

Use `deploy/helm/openshell/README.md` as the source of truth, then apply this workflow.

Default behavior:

- SQLite by default (`postgres.enabled=false`)
- Optional PostgreSQL (`postgres.enabled=true`) via:
  - `postgres.mode=internal` (deploy bundled Postgres dependency)
  - `postgres.mode=external` (use external database settings)

## Inputs

```bash
NAMESPACE="${NAMESPACE:-openshell}"
RELEASE_NAME="${RELEASE_NAME:-openshell}"
CHART_REF="${CHART_REF:-oci://ghcr.io/nvidia/openshell/helm-chart}"
CHART_VERSION="${CHART_VERSION:-}"
GATEWAY_TAG="${GATEWAY_TAG:-}"                 # e.g. dev or fa84e437...
POSTGRES_ENABLED="${POSTGRES_ENABLED:-false}"   # true|false
POSTGRES_MODE="${POSTGRES_MODE:-internal}"      # internal|external
POSTGRES_DB="${POSTGRES_DB:-openshell}"
POSTGRES_USER="${POSTGRES_USER:-openshell}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-}"       # required when postgres is enabled
POSTGRES_HOST="${POSTGRES_HOST:-}"               # required for external mode
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
```

## Step 1: Verify cluster login

Before any deployment action, confirm the user is authenticated to a cluster.

```bash
if ! kubectl auth can-i get pods >/dev/null 2>&1; then
  echo "Not authenticated to a Kubernetes/OpenShift cluster."
  echo "Please log in first (for OpenShift: oc login <api-server>), then retry."
  exit 1
fi
```

If the check fails, stop and ask the user to log in before continuing.

## Step 2: Choose namespace (with upgrade prompt)

Namespace selection rules:

1. If user explicitly provides a namespace, use it.
2. If user does not provide a namespace, default to `openshell`.
3. If `openshell` already has a running gateway and user did not explicitly ask for upgrade, ask:
   - upgrade existing deployment in `openshell`, or
   - deploy fresh into a new namespace.

Detect existing gateway in `openshell`:

```bash
EXISTING_IN_OPENSHIFT=false
if helm status openshell -n openshell >/dev/null 2>&1; then
  EXISTING_IN_OPENSHIFT=true
elif kubectl get statefulset openshell -n openshell >/dev/null 2>&1; then
  EXISTING_IN_OPENSHIFT=true
fi
```

When `EXISTING_IN_OPENSHIFT=true` and namespace was not explicitly specified, stop and ask the user for a choice before proceeding.

## Step 3: Select gateway/chart version

If user explicitly provides `GATEWAY_TAG`, use it.

If user explicitly provides `CHART_VERSION`, use it as-is.

If neither `GATEWAY_TAG` nor `CHART_VERSION` is provided:

1. Fetch recent gateway tags from [GHCR package page](https://github.com/nvidia/OpenShell/pkgs/container/openshell%2Fgateway) (or equivalent API/CLI output).
2. Ask the user which tag to deploy.
3. Convert chosen gateway tag to Helm chart dev format:
   - gateway tag `dev` -> `CHART_VERSION=0.0.0-dev`
   - gateway tag `<tag>` (commit-like or custom) -> `CHART_VERSION=0.0.0-<tag>`

Example prompt to user:

- "I found recent gateway tags: `dev`, `fa84e437...`, `3460e5fd...`. Which one should I deploy?"

If user does not choose, default to:

```bash
GATEWAY_TAG="dev"
CHART_VERSION="0.0.0-dev"
```

If `GATEWAY_TAG` is provided and `CHART_VERSION` is empty:

```bash
CHART_VERSION="0.0.0-${GATEWAY_TAG}"
```

If `CHART_VERSION` is provided and `GATEWAY_TAG` is empty, derive `GATEWAY_TAG` when possible:

```bash
case "${CHART_VERSION}" in
  0.0.0-*) GATEWAY_TAG="${CHART_VERSION#0.0.0-}" ;;
  *) GATEWAY_TAG="dev" ;;  # fallback
esac
```

## Step 4: Detect cluster type

```bash
CLUSTER_TYPE="kubernetes"
if kubectl get clusterversion version >/dev/null 2>&1; then
  CLUSTER_TYPE="openshift"
fi
echo "Detected cluster type: ${CLUSTER_TYPE}"
```

## Step 5: Install shared prerequisites

```bash
kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/latest/download/manifest.yaml
kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1 || kubectl create namespace "${NAMESPACE}"
```

## Step 6: Apply OpenShift-only prerequisites

Run only when `CLUSTER_TYPE=openshift`.

```bash
if [ "${CLUSTER_TYPE}" = "openshift" ]; then
  oc adm policy add-scc-to-user privileged -z openshell-sandbox -n "${NAMESPACE}"

  # The PKI init job is disabled on OpenShift (SCC constraints), but the
  # gateway still needs JWT signing keys for per-sandbox authentication.
  # Generate them manually if the Secret does not already exist.
  JWT_SECRET="${RELEASE_NAME}-jwt-keys"
  if ! kubectl get secret "${JWT_SECRET}" -n "${NAMESPACE}" >/dev/null 2>&1; then
    TMPDIR=$(mktemp -d)
    openssl genpkey -algorithm Ed25519 -out "${TMPDIR}/signing.pem"
    openssl pkey -in "${TMPDIR}/signing.pem" -pubout -out "${TMPDIR}/public.pem"
    openssl rand -hex 16 > "${TMPDIR}/kid"
    kubectl create secret generic "${JWT_SECRET}" -n "${NAMESPACE}" \
      --from-file=signing.pem="${TMPDIR}/signing.pem" \
      --from-file=public.pem="${TMPDIR}/public.pem" \
      --from-file=kid="${TMPDIR}/kid"
    rm -rf "${TMPDIR}"
    echo "Created JWT signing secret ${JWT_SECRET}"
  else
    echo "JWT signing secret ${JWT_SECRET} already exists"
  fi
fi
```

## Step 7: Deploy Helm release

```bash
HELM_ARGS=(
  upgrade --install "${RELEASE_NAME}" "${CHART_REF}"
  --version "${CHART_VERSION}"
  --namespace "${NAMESPACE}"
  --set "image.tag=${GATEWAY_TAG}"
  --set "supervisor.image.tag=${GATEWAY_TAG}"
  --set "postgres.enabled=${POSTGRES_ENABLED}"
  --wait
)

if [ "${POSTGRES_ENABLED}" = "true" ]; then
  HELM_ARGS+=(--set "postgres.mode=${POSTGRES_MODE}")
  if [ "${POSTGRES_MODE}" = "external" ]; then
    HELM_ARGS+=(
      --set "postgres.external.host=${POSTGRES_HOST}"
      --set "postgres.external.port=${POSTGRES_PORT}"
      --set "postgres.external.username=${POSTGRES_USER}"
      --set "postgres.external.password=${POSTGRES_PASSWORD}"
      --set "postgres.external.database=${POSTGRES_DB}"
    )
  else
    HELM_ARGS+=(
      --set "postgres.auth.username=${POSTGRES_USER}"
      --set "postgres.auth.password=${POSTGRES_PASSWORD}"
      --set "postgres.auth.database=${POSTGRES_DB}"
    )
  fi
fi

if [ "${CLUSTER_TYPE}" = "openshift" ]; then
  HELM_ARGS+=(
    --set pkiInitJob.enabled=false
    --set server.disableTls=true
    --set podSecurityContext.fsGroup=null
    --set securityContext.runAsUser=null
  )
fi

helm "${HELM_ARGS[@]}"
```

This keeps Kubernetes installs aligned with the README default `helm install` path and applies OpenShift-specific overrides only on OpenShift.

## Step 8: Verify deployment

```bash
kubectl get pods -n "${NAMESPACE}"
kubectl rollout status statefulset/"${RELEASE_NAME}" -n "${NAMESPACE}"
helm get values "${RELEASE_NAME}" -n "${NAMESPACE}"
```

Check persistence mode:

- SQLite default: `postgres.enabled=false`
- Internal Postgres: `postgres.enabled=true`, `postgres.mode=internal`
- External Postgres: `postgres.enabled=true`, `postgres.mode=external`
