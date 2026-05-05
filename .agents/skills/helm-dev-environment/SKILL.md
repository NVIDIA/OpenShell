---
name: helm-dev-environment
description: Start up, tear down, and configure the local Kubernetes development environment for OpenShell. Uses k3d (Docker-backed k3s) + Skaffold + Helm. Covers cluster lifecycle, optional add-ons (Keycloak OIDC, Envoy Gateway), and port mappings. Trigger keywords - local k8s, local cluster, k3d, skaffold, helm dev, start cluster, stop cluster, tear down cluster, delete cluster, create cluster, helm:k3s, helm:skaffold, local dev environment, dev cluster, k8s dev, envoy gateway local, keycloak local.
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
Also applies base manifests (`deploy/kube/manifests/agent-sandbox.yaml`). Traefik is
disabled at cluster creation time.

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

### 2. Deploy OpenShell

**Iterative dev** (rebuilds on file changes, recommended during active development):
```bash
mise run helm:skaffold:dev
```

**One-shot deploy** (build once and leave running):
```bash
mise run helm:skaffold:run
```

Both commands build the `gateway` and `supervisor` images and deploy the OpenShell Helm
chart. The `pkiInitJob` hook runs on first install to generate mTLS secrets. Envoy Gateway  opt-in; see the Optional Add-ons section below.

The gateway Service uses ClusterIP. Access is via Envoy Gateway (port `8080`) or `kubectl port-forward`.

### TLS behaviour

`values-skaffold.yaml` sets `server.disableTls: true`, so Skaffold-based deploys run
plaintext by default. To test with TLS enabled, comment out that line and redeploy.

| Mode | `server.disableTls` | Gateway scheme |
|------|---------------------|----------------|
| Skaffold dev (default) | `true` | `http://` |
| TLS enabled | `false` (or omitted) | `https://` |

### Connecting via port-forward

Port `8080` is already bound by the k3d load balancer when Envoy Gateway is active, so
the port-forward uses local port `8090` to avoid a collision:

```bash
KUBECONFIG=kubeconfig kubectl port-forward -n openshell svc/openshell 8090:8080
```

**Plaintext (default Skaffold deploy):**

```bash
openshell sandbox list --gateway-endpoint http://localhost:8090
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

Each add-on requires uncommenting the corresponding `valuesFiles` entry in
`deploy/helm/openshell/skaffold.yaml` before running `helm:skaffold:dev` or `helm:skaffold:run`.

### Envoy Gateway (Gateway API / GRPCRoute)

Envoy Gateway is already installed by Skaffold (the `envoy-gateway` Helm release in
`skaffold.yaml`). To activate routing:

1. Uncomment `#- values-gateway.yaml` in `skaffold.yaml`
2. Redeploy: `mise run helm:skaffold:run`
3. Apply the GatewayClass: `mise run helm:gateway:apply`
4. Access: `http://127.0.0.1:8080`

`values-gateway.yaml` creates a `Gateway` (listener on port 80, class `eg`) and a
`GRPCRoute` in the `openshell` namespace. Envoy Gateway provisions a LoadBalancer
service for the proxy; klipper-lb binds it to hostPort 80, reachable via the
`8080:80` load balancer port mapping.

### Keycloak OIDC

One-time setup — only needed once per cluster lifetime:

```bash
mise run keycloak:k8s:setup
```

This deploys Keycloak (`quay.io/keycloak/keycloak:24.0`) into the `keycloak` namespace,
imports the openshell realm from `scripts/keycloak-realm.json`, and prints a port-forward
command for acquiring tokens from the CLI.

Then activate OIDC in the OpenShell Helm chart:
1. Uncomment `#- values-keycloak.yaml` in `skaffold.yaml`
2. Redeploy: `mise run helm:skaffold:run`

To remove Keycloak:
```bash
mise run keycloak:k8s:teardown
```

---

## Cluster Lifecycle (suspend/resume)

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

## Key Files

| Path | Purpose |
|------|---------|
| `deploy/helm/openshell/skaffold.yaml` | Skaffold config — images, Helm releases, values overlays |
| `deploy/helm/openshell/values.yaml` | Default Helm values |
| `deploy/helm/openshell/values-skaffold.yaml` | Dev overrides (image pull policy, local image names) |
| `deploy/helm/openshell/values-cert-manager.yaml` | cert-manager TLS overlay (opt-in; disables pkiInitJob) |
| `deploy/helm/openshell/values-gateway.yaml` | Envoy Gateway GRPCRoute + Gateway overlay |
| `deploy/helm/openshell/values-keycloak.yaml` | Keycloak OIDC overlay |
| `deploy/kube/manifests/envoy-gateway-openshell.yaml` | GatewayClass for Envoy Gateway (`mise run helm:gateway:apply`) |
| `tasks/scripts/helm-k3s-local.sh` | k3d cluster create/delete/start/stop/status |
| `tasks/scripts/keycloak-k8s-setup.sh` | Keycloak deploy + realm import |
