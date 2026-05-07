# OpenShell Helm Chart

> **Experimental** — the Kubernetes deployment path is under active development. Expect rough edges and breaking changes.

This chart deploys the OpenShell gateway into a Kubernetes cluster. It is published as an OCI artifact to GHCR at `oci://ghcr.io/nvidia/openshell/helm-chart`.

## Install on Kubernetes

```bash
helm install openshell oci://ghcr.io/nvidia/openshell/helm-chart --version <version>
```

## Install on OpenShift

```bash
# Precreate the openshell namespace so we can create the SCC cluster role
oc create ns openshell

# Sandboxes are deployed into the openshell namespace and use the default service account for now
oc adm policy add-scc-to-user privileged -z default -n openshell

# Deploy openshell with overrides to allow SCC assignment of fsGroup and runAsUser for the gateway
helm install openshell oci://ghcr.io/nvidia/openshell/helm-chart --version <version> -n openshell \
	--set pkiInitJob.enabled=false \
	--set server.disableTls=true \
	--set podSecurityContext.fsGroup=null \
	--set securityContext.runAsUser=null
```

## Available versions

| Tag | Source | Notes |
| --- | --- | --- |
| `<semver>` (e.g. `0.6.0`) | Tagged GitHub release | Tracks the matching gateway and supervisor image versions. Recommended for production. |
| `0.0.0-dev` | Latest commit on `main` | Floating tag, overwritten on every push. `appVersion` is `dev`, so images resolve to the `:dev` tag. |
| `0.0.0-dev.<commit-sha>` | A specific commit on `main` | Per-commit pin. Chart version and `appVersion` both use the full 40-character commit SHA, which matches the image tag pushed by CI. |

The `dev` tags are intended for testing changes ahead of a release. Production deployments should pin to a tagged release.

## Configuration

See [`values.yaml`](values.yaml) for configurable values. Selected overlays:

- [`values-gateway.yaml`](values-gateway.yaml) — gateway-only configuration
- [`values-cert-manager.yaml`](values-cert-manager.yaml) — cert-manager integration
- [`values-keycloak.yaml`](values-keycloak.yaml) — Keycloak OIDC integration
