# OpenShell Helm Chart

> **Experimental** — the Kubernetes deployment path is under active development. Expect rough edges and breaking changes.

This chart deploys the OpenShell gateway into a Kubernetes cluster. It is published as an OCI artifact to GHCR at `oci://ghcr.io/nvidia/openshell/helm-chart`.

## Prerequisites

The Kubernetes Agent Sandbox CRDs and controller must be installed on the cluster before deploying OpenShell. Install them with:

```bash
kubectl apply -f https://github.com/kubernetes-sigs/agent-sandbox/releases/latest/download/manifest.yaml
```

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

See [`values.yaml`](values.yaml) for the full list of configurable values. Selected overlays:

- [`ci/values-gateway.yaml`](ci/values-gateway.yaml) — gateway-only configuration
- [`ci/values-cert-manager.yaml`](ci/values-cert-manager.yaml) — cert-manager integration
- [`ci/values-keycloak.yaml`](ci/values-keycloak.yaml) — Keycloak OIDC integration

Commonly configured values:

| Value | Purpose |
|---|---|
| `image.repository` / `image.tag` | Gateway image. Defaults to `ghcr.io/nvidia/openshell/gateway`. |
| `service.type` | Kubernetes service type. Use `ClusterIP`, `NodePort`, or your platform default. |
| `server.dbUrl` | Gateway database URL. Defaults to SQLite on the chart-managed persistent volume. |
| `server.sandboxNamespace` | Namespace where sandbox resources are created. |
| `server.sandboxImage` | Default sandbox image used when a sandbox does not specify one. |
| `server.grpcEndpoint` | Endpoint that sandbox supervisors use to call back to the gateway. |
| `server.sshGatewayHost` / `server.sshGatewayPort` | Public host and port returned to CLI clients for SSH proxy connections. |
| `server.disableTls` | Run the gateway over plaintext HTTP. Use only behind a trusted transport. |
| `server.tls.*` | Secret names for server and client mTLS materials. |
| `supervisor.image.repository` | Repository for the supervisor init container image. Defaults to `ghcr.io/nvidia/openshell/supervisor`. |
| `supervisor.image.tag` | Tag for the supervisor image. Defaults to the chart's `appVersion` so the supervisor and gateway stay in sync. |
| `supervisor.image.pullPolicy` | Pull policy for the supervisor image. Defaults to the Kubernetes cluster default when unset. |
