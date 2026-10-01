---
name: helm-dev-environment
description: Start up, tear down, and configure the local Kubernetes development environment for OpenShell. Uses k3d (Docker-backed k3s) + Skaffold + Helm. Covers cluster lifecycle, optional add-ons (Keycloak OIDC, Envoy Gateway), HA testing, and port mappings. Trigger keywords - local k8s, local cluster, k3d, skaffold, helm dev, start cluster, stop cluster, tear down cluster, delete cluster, create cluster, helm:k3s, helm:skaffold, local dev environment, dev cluster, k8s dev, envoy gateway local, keycloak local, high availability, HA.
metadata:
  internal: true
---

# Helm Dev Environment

Set up, run, and tear down the local Kubernetes development environment for OpenShell.
The stack is: **k3d** (Docker-backed k3s) for the cluster, **Skaffold** for image builds and Helm deploys, and the **OpenShell Helm chart** (`deploy/helm/openshell/`).

---

## Prerequisites

- Docker Desktop (macOS) or Docker Engine (Linux) running
- `mise install` completed (provides `k3d`, `kubectl`, `skaffold`, `helm`)

---

## Startup

### 1. Create the cluster

```bash
mise run helm:k3s:create
```

Creates a k3d cluster and merges its kubeconfig into the worktree-local `kubeconfig` file.
When the named cluster already exists, the task starts any stopped containers and refreshes
same-named kubeconfig entries so a recreated load balancer's current API port takes effect.
Also applies the upstream agent-sandbox CRDs/controller (pinned via `AGENT_SANDBOX_VERSION`
in `tasks/scripts/helm-k3s-local.sh`, fetched from `github.com/kubernetes-sigs/agent-sandbox`
releases), enables its OTLP tracing on v0.5 and later, installs an OTLP trace
collector and UI in the `observability` namespace,
and preloads the default sandbox image into k3d so the first sandbox create
does not wait on a large registry pull. Traefik is disabled at cluster creation time.

**Multi-worktree support:** the cluster name is derived from the last component of the
current git branch (e.g. branch `kube-support/local-dev/tmutch` → cluster
`openshell-dev-tmutch`). Each worktree therefore gets its own isolated cluster and its
own `kubeconfig` file. Override with `HELM_K3S_CLUSTER_NAME` to force a specific name
or share one cluster across worktrees.

Port mappings created at cluster time (cannot be changed without recreating):

| Host port | Target | Used by |
|-----------|--------|---------|
| `8080` | Port `80` via k3d load balancer | Envoy Gateway LoadBalancer service (`values-gateway.yaml`) |

Override with env vars before running `helm:k3s:create`:
- `HELM_K3S_LB_HOST_PORT` (default: `8080`)
- `HELM_K3S_PRELOAD_SANDBOX_IMAGE` (default:
  `nvcr.io/nvidia/base/ubuntu:24.04`; set to an empty value to skip)
- `HELM_K3S_COLLECTOR_IMAGE` (default:
  `mcr.microsoft.com/dotnet/aspire-dashboard:latest`)
- `HELM_K3S_COLLECTOR_HEALTH_TIMEOUT` (default: `120` seconds)

### 2. Deploy OpenShell

**Iterative dev** (rebuilds on file changes, recommended during active development):
```bash
mise run helm:skaffold:dev
```

**One-shot deploy** (build once and leave running):
```bash
mise run helm:skaffold:run
```

Resource admission defaults to enabled and caller driver config to disabled.
Driver-config scenarios need an explicit `allowDriverConfig` opt-in; external
attachments also need administrator-controlled approval labels in the target
namespace. GPU attachments and operator-selected image-pull Secrets are exempt
from labels. Managed workspace image-pull Secrets are copied from the configured
source in the gateway namespace; do not grant approval to the gateway database
PVC or disable admission to make tests pass.

The Skaffold flow builds distinct `gateway`, `sandbox`, and `supervisor` images
and deploys the OpenShell Helm chart. The Kubernetes driver creates a
capability-free workload Pod and a directly managed capability-free supervisor
Pod. One namespace-wide NetworkPolicy denies direct egress from every OpenShell
workload Pod. The
`pkiInitJob` hook (a pre-install Job that runs `openshell-gateway generate-certs`)
generates mTLS secrets on first install. The default Skaffold values export
gateway and Kubernetes-driver traces to the collector service installed by
`helm:k3s:create`. Envoy Gateway is opt-in; see the Optional Add-ons section.

The gateway Service uses ClusterIP. Access is via Envoy Gateway (port `8080`) or
the unified local forwarding task:

```bash
mise run helm:k3s:forward
```

The task forwards OTLP/gRPC to `http://127.0.0.1:4317` and the trace UI to
`http://127.0.0.1:18888`. When Skaffold has deployed a Kubernetes gateway, it
also forwards the gateway to `http://127.0.0.1:8090`; otherwise it continues
with the collector ports only. A successful plaintext `helm:skaffold:run`
registers the gateway under the worktree-specific k3d
cluster name and selects it as the active gateway. Keep the forwarding
task running while using those endpoints.

### Viewing local traces

The gateway exports OTLP/gRPC to
`http://openshell-collector.observability.svc.cluster.local:4317` through the
default Skaffold values. Forward OTLP/gRPC and the trace UI to the host:

```bash
mise run helm:k3s:forward
```

Open `http://127.0.0.1:18888` and exercise the gateway to inspect gateway and
Kubernetes compute-driver spans under their distinct service names, along with
Agent Sandbox controller reconciliation spans linked through the Sandbox
trace-context annotation. The same command exposes OTLP/gRPC on
`http://127.0.0.1:4317` and, when deployed, the Kubernetes gateway on
`http://127.0.0.1:8090`. The local `gateway:docker`, `gateway:podman`, and
`gateway:vm` tasks detect the collector listener at startup and enable trace
export only while it is reachable.

The Skaffold profile for HA reverse-proxy development is available from
`deploy/helm/openshell/`:

```bash
# Two gateway replicas + external PostgreSQL Secret + Envoy Gateway + Gateway API route.
KUBECONFIG=../../../kubeconfig skaffold run -p high-availability
```

The `high-availability` profile expects a Secret named `openshell-ha-pg` in the `openshell`
namespace with a `uri` key. For local manual testing, either create your own
PostgreSQL Secret or use the e2e PostgreSQL fixture manifest in
`e2e/kubernetes/postgres-fixture.yaml`.

For the `high-availability` profile, return to the repository root and apply the
GatewayClass and BackendTrafficPolicy manifest after Skaffold has installed
Envoy Gateway:

```bash
KUBECONFIG=kubeconfig mise run helm:gateway:apply
```

The BackendTrafficPolicy disables Envoy request and stream-duration timeouts for
OpenShell's `GRPCRoute`. Keep that policy in `deploy/kube/manifests/envoy-gateway-openshell.yaml`,
not in the Helm chart; it is required for long-lived gRPC create/watch/exec/relay
streams during gateway rollouts and scale events.

### TLS behaviour

`ci/values-skaffold.yaml` sets `server.disableTls: true`, so Skaffold-based deploys run
plaintext by default. Override `server.disableTls=false` to exercise TLS/mTLS.

| Mode | `server.disableTls` | Gateway scheme |
|------|---------------------|----------------|
| Skaffold dev (default) | `true` | `http://` |
| TLS enabled | `false` (or omitted) | `https://` |

### Connecting through the forwarding task

Port `8080` is already bound by the k3d load balancer when Envoy Gateway is
active, so the forwarding task uses local port `8090` for the gateway. In a
second terminal, confirm that the gateway is registered and active:

```bash
openshell gateway list
```

**Plaintext (default Skaffold deploy):**

```bash
openshell sandbox list
```

**With mTLS enabled** — extract the client cert the PKI hook wrote to the cluster,
then place it where the CLI expects it. Run once after each fresh install:

```bash
mkdir -p ~/.config/openshell/gateways/openshell/mtls
KUBECONFIG=kubeconfig kubectl get secret openshell-client-tls -n openshell \
  -o jsonpath='{.data.ca\.crt}'  | base64 -d > ~/.config/openshell/gateways/openshell/mtls/ca.crt
KUBECONFIG=kubeconfig kubectl get secret openshell-client-tls -n openshell \
  -o jsonpath='{.data.tls\.crt}' | base64 -d > ~/.config/openshell/gateways/openshell/mtls/tls.crt
KUBECONFIG=kubeconfig kubectl get secret openshell-client-tls -n openshell \
  -o jsonpath='{.data.tls\.key}' | base64 -d > ~/.config/openshell/gateways/openshell/mtls/tls.key
```

The server cert SANs include `localhost` and `127.0.0.1`, so hostname verification
passes over a port-forward without any extra flags:

```bash
openshell sandbox list --gateway-endpoint https://localhost:8090
```

---

## Teardown

### Remove the Helm releases (keep cluster)

```bash
mise run helm:skaffold:delete
```

### Delete the cluster entirely

```bash
mise run helm:k3s:delete
```

This removes the k3d cluster and all resources. Kubeconfig context is left behind
but will point to a deleted cluster — safe to ignore or clean up manually.

---

## Optional Add-ons

Some add-ons can be enabled by uncommenting values in `skaffold.yaml`, but prefer
the dedicated Skaffold profiles when they exist. Profiles avoid leaving local
manual edits in the worktree.

### Envoy Gateway (Gateway API / GRPCRoute)

Use the `high-availability` Skaffold profile for HA reverse-proxy testing. The
profile intentionally includes Envoy Gateway so multi-replica behavior is
exercised through the same Gateway API path used by reverse-proxy deployments:

```bash
cd deploy/helm/openshell
KUBECONFIG=../../../kubeconfig skaffold run -p high-availability
cd ../../..
KUBECONFIG=kubeconfig mise run helm:gateway:apply
```

`values-gateway.yaml` creates a `Gateway` (listener on port 80, class `eg`) and
`GRPCRoute` in the `openshell` namespace. The `high-availability` profile
installs the Envoy Gateway Helm chart and layers both
`values-high-availability.yaml` and `values-gateway.yaml` onto the OpenShell
release.

`deploy/kube/manifests/envoy-gateway-openshell.yaml` creates:

- `GatewayClass/eg`
- `BackendTrafficPolicy/openshell-grpc-timeouts`

The Envoy Gateway proxy Service is usually exposed through the k3d load balancer
at `http://127.0.0.1:8080`. If the cluster was created with a different
`HELM_K3S_LB_HOST_PORT`, use that host port instead.

For manual tests against an existing cluster, prefer forwarding the Envoy proxy
Service rather than `svc/openshell`. That keeps client traffic on the same path
as a real reverse proxy while gateway pods rotate behind it:

```bash
KUBECONFIG=kubeconfig kubectl get svc -A \
  -l gateway.envoyproxy.io/owning-gateway-name=openshell
KUBECONFIG=kubeconfig kubectl -n <envoy-service-namespace> port-forward \
  svc/<envoy-service-name> 8080:80
openshell gateway add http://127.0.0.1:8080 --name openshell --local
```

When running e2e tests manually through Envoy, register gateway metadata (as
above) instead of relying only on `OPENSHELL_GATEWAY_ENDPOINT`; some tests call
`openshell gateway info` and expect metadata for the active gateway.

### Kubernetes E2E Notes

Use `mise run e2e:kubernetes` for the standard Helm-backed Kubernetes suite.
The kube e2e wrapper creates only one port-forward, to `svc/openshell`; it no
longer forwards the unauthenticated health listener or runs a `/readyz` e2e
target. `/readyz` remains covered by server unit/integration tests.

Use `mise run e2e:kubernetes:ha-rebalancing` for full-suite HA coverage. The
task creates an external PostgreSQL fixture, installs Envoy Gateway, applies
`deploy/kube/manifests/envoy-gateway-openshell.yaml`, enables the chart
`GRPCRoute`, and runs the full Kubernetes e2e suite, including
`kubernetes_ha_rebalancing`. That coverage validates sandbox create/watch and
exec through the Envoy proxy while gateway replicas scale up, scale down, and
rotate. It also keeps a long-running sandbox alive and runs upload/download
operations while gateway pods roll, so file sync exercises the same relay retry
path as interactive sessions.

If you reuse an existing Skaffold cluster for the full kube suite, make sure the
chart has `server.hostGatewayIP` set so sandbox pods can resolve
`host.openshell.internal` back to the test host. The e2e wrapper detects this on
chart installs; manual reuse may require:

```bash
HOST_GATEWAY_IP="${OPENSHELL_E2E_HOST_GATEWAY_IP:?set host gateway IP}"
KUBECONFIG=kubeconfig helm upgrade openshell deploy/helm/openshell \
  --namespace openshell --reuse-values \
  --set "server.hostGatewayIP=${HOST_GATEWAY_IP}" \
  --wait --timeout 5m
```

Use the IP that pods in that cluster use to reach listeners on the test host.

### BackendTLSPolicy (end-to-end TLS)

To enable end-to-end TLS between the Gateway proxy and the gateway pod, add
BackendTLSPolicy values to the Helm install:

```bash
helm upgrade --install openshell deploy/helm/openshell \
  --set grpcRoute.enabled=true \
  --set grpcRoute.backendTLSPolicy.enabled=true \
  --set server.tls.enableMtls=false \
  ...
```

This requires `server.tls.enableMtls=false` because ingress proxies cannot
present client certificates to the backend. The certgen hook creates a backend
CA ConfigMap from the server Secret's `ca.crt` key. With cert-manager, a
separate post-install Job polls for the cert-manager-issued certificate (up to
`pkiInitJob.timeoutSeconds`); with built-in PKI the ConfigMap is created in the
same pre-install hook. The ConfigMap is reconciled on every upgrade so CA
rotations propagate automatically.

Key Helm values:
- `grpcRoute.backendTLSPolicy.enabled`: create the BackendTLSPolicy resource
- `grpcRoute.backendTLSPolicy.caCertificateConfigMapName`: override ConfigMap name
- `grpcRoute.backendTLSPolicy.hostname`: override backend validation hostname
- `server.tls.enableMtls`: must be `false` for BackendTLSPolicy
- `pkiInitJob.timeoutSeconds`: polling duration for cert-manager mode
- `pkiInitJob.failOnTimeout`: fail install if cert-manager times out

### Keycloak OIDC

Initial setup — rerun it whenever you want to rotate the development CA:

```bash
mise run keycloak:k8s:setup
```

This deploys Keycloak (`quay.io/keycloak/keycloak:24.0`) into the `keycloak` namespace,
imports the openshell realm from `scripts/keycloak-realm.json`, generates a short-lived
development TLS certificate, and publishes its trust anchor as the
`openshell-keycloak-ca` ConfigMap in the OpenShell namespace. The command prints a
port-forward command for acquiring tokens from the CLI. Rerunning setup rotates the
development certificate and trust anchor; redeploy the gateway afterward so it reloads
the mounted CA bundle.

Then activate OIDC in the OpenShell Helm chart:
1. Uncomment `#- ci/values-keycloak.yaml` in `skaffold.yaml`
2. Redeploy: `mise run helm:skaffold:run`

To remove Keycloak:
```bash
mise run keycloak:k8s:teardown
```

### SPIRE / SPIFFE Provider Token Grants

Skaffold can install SPIRE with the SPIFFE hardened Helm charts. To activate
SPIFFE JWT-SVIDs for dynamic provider token grants:

1. Uncomment the `spire-crds` and `spire` releases in `deploy/helm/openshell/skaffold.yaml`
2. Uncomment `#- ci/values-spire.yaml` in the OpenShell release values files
3. Redeploy: `mise run helm:skaffold:run`

`ci/values-spire-stack.yaml` configures the local SPIRE trust domain as
`openshell.local` and adds a `ClusterSPIFFEID` that maps sandbox pod
annotations to `spiffe://openshell.local/openshell/sandbox/<sandbox-id>`.
OpenShell mounts the SPIFFE CSI Workload API socket at
`/spiffe-workload-api/spire-agent.sock` only into supervisor Pods for provider token
grants. Supervisor-to-gateway authentication remains on the Kubernetes
ServiceAccount bootstrap and gateway-minted sandbox JWT path; the selected
Kubernetes compute driver validates the projected token before the gateway
returns the current generation-bound session JWT. The driver also returns the
runtime identity recorded during provisioning. Restart preserves its namespace
and Sandbox CR UID, rejects ambiguous label matches, and rotates only the
supervisor Pod UID; bootstrap fails when the live identity does not match the
durable sandbox record.

### Vault Credential Driver

The `credential-driver-vault` Skaffold profile applies
`ci/values-credential-driver-vault.yaml`. Its external OpenBao/Vault backend
must expose HTTPS at the configured service DNS name and publish the issuing CA
certificate as the `ca.crt` key in the `openbao-ca` ConfigMap. Local e2e uses
OpenBao dev TLS and an `openbao-0` DNS alias matching its generated certificate.
The Helm value
`server.credentialDrivers.vault.caConfigMapName` mounts that key into the
gateway and renders the driver's `ca_bundle` setting. Non-loopback HTTP
addresses fail gateway startup, and hostname verification requires the service
DNS name in the server certificate SANs.

```bash
cd deploy/helm/openshell
skaffold run -p credential-driver-vault
kubectl -n openshell logs statefulset/openshell -c openshell-gateway --tail=200
```

---

## Cluster Lifecycle (stop/start)

Stop the cluster without losing state (faster than delete/recreate):
```bash
mise run helm:k3s:stop
mise run helm:k3s:start
```

Check cluster status:
```bash
mise run helm:k3s:status
```

---

## Helm Chart Checks

Run the chart lint task before changing Helm templates, values overlays, or
Skaffold inputs:

```bash
mise run helm:lint
```

If Helm reports missing chart dependencies, remove the specific stale subchart
archive or directory named by the error from `deploy/helm/openshell/charts/`,
then rerun the lint task.

For example, when lint reports `chart metadata is missing these dependencies:
postgresql`, remove stale PostgreSQL chart artifacts:

```bash
rm -f deploy/helm/openshell/charts/postgresql-*.tgz
rm -rf deploy/helm/openshell/charts/postgresql
mise run helm:lint
```

The `charts/` directory is ignored and regenerated by `helm dependency build`
for dependencies still declared in `Chart.yaml`.

---

## Key Files

| Path | Purpose |
|------|---------|
| `deploy/helm/openshell/skaffold.yaml` | Skaffold config — images, Helm releases, values overlays |
| `deploy/helm/openshell/values.yaml` | Default Helm values |
| `deploy/helm/openshell/ci/values-skaffold.yaml` | Dev overrides (image pull policy, TLS disabled for local Skaffold) |
| `deploy/helm/openshell/ci/values-cert-manager.yaml` | cert-manager PKI overlay (opt-in; disables pkiInitJob) |
| `deploy/helm/openshell/ci/values-gateway.yaml` | Envoy Gateway GRPCRoute + Gateway overlay |
| `deploy/helm/openshell/ci/values-high-availability.yaml` | HA test overlay (`replicaCount: 2` with external PostgreSQL Secret) |
| `deploy/helm/openshell/ci/values-keycloak.yaml` | Keycloak OIDC overlay |
| `deploy/helm/openshell/ci/values-spire.yaml` | SPIFFE/SPIRE provider token grant overlay |
| `deploy/helm/openshell/ci/values-spire-stack.yaml` | SPIRE hardened chart values for local dev |
| `deploy/helm/openshell/ci/values-tls-disabled.yaml` | Lint-only: TLS + auth disabled (reverse-proxy edge termination) |
| `deploy/helm/openshell/ci/values-credential-driver-vault.yaml` | Vault credential-driver validation overlay with HTTPS and private-CA trust |
| `deploy/kube/manifests/envoy-gateway-openshell.yaml` | GatewayClass and BackendTrafficPolicy for Envoy Gateway (`mise run helm:gateway:apply`) |
| `tasks/scripts/helm-k3s-local.sh` | k3d cluster create/delete/start/stop/status |
| `tasks/scripts/keycloak-k8s-setup.sh` | Keycloak deploy, realm import, and development TLS trust anchor |
