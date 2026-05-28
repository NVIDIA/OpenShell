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
# CHART_REF can be an OCI URI or a local chart path.
# - OCI (default): oci://ghcr.io/nvidia/openshell/helm-chart
# - Local chart:   deploy/helm/openshell  (for unreleased / dev changes)
CHART_REF="${CHART_REF:-oci://ghcr.io/nvidia/openshell/helm-chart}"
CHART_VERSION="${CHART_VERSION:-}"
GATEWAY_TAG="${GATEWAY_TAG:-}"                 # image tag: dev, <commit-sha>, or semver
CLEAN_INSTALL="${CLEAN_INSTALL:-false}"        # true|false (deletes PVC data)
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
EXISTING=false
if helm status "${RELEASE_NAME}" -n "${NAMESPACE}" >/dev/null 2>&1; then
  EXISTING=true
elif kubectl get statefulset "${RELEASE_NAME}" -n "${NAMESPACE}" >/dev/null 2>&1; then
  EXISTING=true
fi
```

When `EXISTING=true` and namespace was not explicitly specified, stop and ask the user for a choice before proceeding.

### Clean install: remove stale PVCs (explicit opt-in)

When performing a **clean install** (not an upgrade), optionally delete leftover PVCs from
previous releases in the namespace. The Bitnami PostgreSQL subchart persists
its password hash on the PVC — if the PVC survives an uninstall and the next
install uses a different password, PostgreSQL will reject connections with
`FATAL: password authentication failed`. The gateway SQLite PVC should also be
cleaned for a fresh start.

Safety rule:

- Never delete PVCs unless `CLEAN_INSTALL=true`.
- Before deletion, explicitly confirm with the user that data loss is expected.

```bash
if [ "${EXISTING}" = "false" ] && [ "${CLEAN_INSTALL}" = "true" ]; then
  # Delete stale postgres PVC (password baked in from prior install)
  kubectl delete pvc "data-${RELEASE_NAME}-postgres-0" -n "${NAMESPACE}" --ignore-not-found
  # Delete stale gateway data PVC
  kubectl delete pvc "openshell-data-${RELEASE_NAME}-0" -n "${NAMESPACE}" --ignore-not-found
fi
```

## Step 3: Select gateway image tag and chart version

Two independent values must be resolved:

- **`GATEWAY_TAG`** — the container image tag for the gateway and supervisor
  (e.g. `dev`, a 40-char commit SHA, or a semver like `0.6.0`). This is
  **always required** because the local `Chart.yaml` has `appVersion: "0.0.0"`
  which does not correspond to a real image.
- **`CHART_VERSION`** — only needed when pulling from the OCI registry
  (`CHART_REF` starts with `oci://`). Ignored for local chart paths.

### When deploying from a local chart path

Set `CHART_REF` to the chart directory (e.g. `deploy/helm/openshell`).
`CHART_VERSION` is not used. Only `GATEWAY_TAG` matters — it controls which
container images are pulled via `--set image.tag` / `--set supervisor.image.tag`.

### When deploying from the OCI registry

If user explicitly provides `GATEWAY_TAG`, derive `CHART_VERSION` as follows:

```bash
if [[ "${GATEWAY_TAG}" == "dev" ]] || [[ "${GATEWAY_TAG}" =~ ^[0-9a-f]{40}$ ]]; then
  CHART_VERSION="0.0.0-${GATEWAY_TAG}"
elif [[ "${GATEWAY_TAG}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.].*)?$ ]]; then
  CHART_VERSION="${GATEWAY_TAG}"
else
  # non-standard tags default to dev-style chart versioning
  CHART_VERSION="0.0.0-${GATEWAY_TAG}"
fi
```

If user explicitly provides `CHART_VERSION`, use it as-is and derive `GATEWAY_TAG`:

```bash
case "${CHART_VERSION}" in
  0.0.0-*) GATEWAY_TAG="${CHART_VERSION#0.0.0-}" ;;
  *) GATEWAY_TAG="${CHART_VERSION}" ;;  # semver release chart -> semver image tag
esac
```

If neither is provided, ask the user which tag to deploy. Default to `dev` / `0.0.0-dev`.

Final safety check before deploy:

```bash
if [[ -z "${GATEWAY_TAG}" ]]; then
  GATEWAY_TAG="dev"
fi
if [[ -z "${CHART_VERSION}" ]]; then
  if [[ "${GATEWAY_TAG}" == "dev" ]] || [[ "${GATEWAY_TAG}" =~ ^[0-9a-f]{40}$ ]]; then
    CHART_VERSION="0.0.0-${GATEWAY_TAG}"
  else
    CHART_VERSION="${GATEWAY_TAG}"
  fi
fi
```

### Available versions (OCI registry)

| Chart version | Image tag | Notes |
|---|---|---|
| `<semver>` (e.g. `0.6.0`) | `<semver>` | Tagged release. Recommended for production. |
| `0.0.0-dev` | `dev` | Latest commit on `main`. Floating tag. |
| `0.0.0-<commit-sha>` | `<commit-sha>` | Per-commit pin on `main`. |

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
  --namespace "${NAMESPACE}"
  --set "image.tag=${GATEWAY_TAG}"
  --set "supervisor.image.tag=${GATEWAY_TAG}"
  --set "postgres.enabled=${POSTGRES_ENABLED}"
  --wait
)

# --version is only meaningful for OCI/repo chart references, not local paths.
if [[ "${CHART_REF}" == oci://* ]]; then
  if [[ -z "${CHART_VERSION}" ]]; then
    if [[ "${GATEWAY_TAG}" == "dev" ]] || [[ "${GATEWAY_TAG}" =~ ^[0-9a-f]{40}$ ]]; then
      CHART_VERSION="0.0.0-${GATEWAY_TAG}"
    else
      CHART_VERSION="${GATEWAY_TAG}"
    fi
  fi
  HELM_ARGS+=(--version "${CHART_VERSION}")
fi

# When using a local chart path, build dependencies first.
if [[ -d "${CHART_REF}" ]]; then
  helm dependency build "${CHART_REF}"
fi

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
