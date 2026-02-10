# Containers and Builds

This document describes how Navigator's container images are built, organized, and deployed.

## Directory Structure

```
deploy/
├── docker/
│   ├── .dockerignore
│   ├── Dockerfile.sandbox       # Sandbox container (runs untrusted code)
│   ├── Dockerfile.server        # Navigator server (orchestration)
│   ├── Dockerfile.cluster       # Airgapped k3s cluster with pre-loaded images
│   ├── cluster-entrypoint.sh    # Entrypoint script for DNS config in Docker
│   └── .build/                  # Generated artifacts (images/*.tar, charts/*.tgz)
├── helm/
│   └── navigator/               # Navigator Helm chart
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
└── kube/
    └── manifests/               # Kubernetes manifests for k3s auto-deploy
        ├── envoy-gateway-helmchart.yaml
        └── navigator-helmchart.yaml
```

## Container Images

### navigator-sandbox

The sandbox container runs untrusted agent code in isolation.

**Build stages:**

1. **rust-builder** - Compiles `navigator-sandbox` binary from Rust
2. **base** - Python 3.12 slim with supervisor/sandbox users
3. **builder** - Installs Python dependencies via uv
4. **final** - Combines binary + Python venv, runs as `navigator-sandbox` entrypoint

**Key features:**

- Multi-user isolation: `supervisor` (privileged) and `sandbox` (restricted) users
- Policy file mount at `/var/navigator/policy.yaml`
- Debug or release builds via `RUST_BUILD_PROFILE` arg

### navigator-server

The server container runs the Navigator orchestration service.

**Build stages:**

1. **builder** - Compiles `navigator-server` in release mode with dependency caching
2. **runtime** - Debian slim with the binary, runs as non-root `navigator` user

**Key features:**

- Exposes gRPC/HTTP on port 8080
- Health checks at `/healthz`
- SQLx migrations copied from source

### navigator-cluster

An airgapped k3s image with all components pre-loaded for single-container deployment.

**Contents:**

- Pre-saved image tarballs (`navigator-sandbox.tar`, `navigator-server.tar`)
- Packaged Helm chart (`navigator-0.1.0.tgz`)
- HelmChart CRs for automatic deployment on cluster start
- Custom entrypoint script for DNS configuration

**Auto-deployed components:**

1. Envoy Gateway (v1.5.8) - includes Gateway API CRDs
2. Navigator (from embedded chart)

**DNS Configuration:**

When running k3s in Docker, the container's `/etc/resolv.conf` contains Docker's internal DNS (127.0.0.11), which is not reachable from k3s pods. While k3s auto-detects this and falls back to 8.8.8.8, external UDP traffic doesn't work reliably on Docker Desktop.

The `cluster-entrypoint.sh` script solves this by:
1. Detecting the Docker host gateway IP from `/etc/hosts` (requires `--add-host=host.docker.internal:host-gateway`)
2. Writing a custom resolv.conf with the host gateway as the nameserver
3. Passing `--resolv-conf` to k3s to use this configuration

This approach follows k3s documentation: "Manually specified resolver configuration files are not subject to viability checks."

## Build Tasks (mise)

All builds use mise tasks defined in `build/*.toml` (included from `mise.toml`):

| Task                            | Description                         |
| ------------------------------- | ----------------------------------- |
| `mise run docker:build`         | Build all images                    |
| `mise run docker:build:sandbox` | Build sandbox image                 |
| `mise run docker:build:server`  | Build server image                  |
| `mise run docker:build:cluster` | Build airgapped cluster image       |
| `mise run cluster`              | Build and deploy local k3s cluster  |
| `mise run sandbox`              | Run sandbox container interactively |
| `mise run helm:lint`            | Lint the Helm chart                 |

### Environment Variables

| Variable             | Default        | Description                             |
| -------------------- | -------------- | --------------------------------------- |
| `IMAGE_TAG`          | `dev`          | Tag for built images                    |
| `RUST_BUILD_PROFILE` | `debug`        | `debug` or `release` for sandbox builds |
| `K3S_VERSION`        | `v1.29.8-k3s1` | k3s version for cluster image           |
| `CLUSTER_NAME`       | `navigator`    | Name for local cluster deployment       |

## Helm Chart

The Navigator Helm chart (`deploy/helm/navigator/`) deploys the server to Kubernetes.

### Key Configuration (values.yaml)

```yaml
image:
  repository: navigator-server
  tag: "dev"

server:
  logLevel: info
  sandboxNamespace: navigator
  sandboxImage: "navigator-sandbox:dev"
  grpcEndpoint: "http://navigator.navigator.svc.cluster.local:8080"

gateway:
  enabled: true
  className: envoy-gateway
```

### Deployment Features

- Init container creates data directory with proper permissions
- Non-root security context (UID 1000)
- Liveness/readiness probes on `/healthz` and `/readyz`
- Service exposed as NodePort on 30051

## Navigator CLI

The `navigator-cli` crate provides commands for cluster lifecycle management. The CLI uses the `navigator-bootstrap` crate to orchestrate Docker containers.

### Cluster Admin Commands

```bash
# Deploy a local cluster (builds image first via mise)
nav cluster admin deploy --name navigator --update-kube-config

# Stop cluster (preserves state in Docker volume)
nav cluster admin stop --name navigator

# Destroy cluster and all state
nav cluster admin destroy --name navigator

# Print kubeconfig to stdout
nav cluster admin deploy --name navigator --get-kubeconfig
```

### How Cluster Deployment Works

The `navigator-bootstrap` crate handles cluster lifecycle:

1. **Network setup** - Creates `navigator-cluster` Docker bridge network
2. **Volume creation** - Creates persistent volume `navigator-cluster-{name}` for k3s state
3. **Container creation** - Runs `navigator-cluster:{tag}` with:
   - Privileged mode (required for k3s)
   - Port mappings: 6443 (API), 80/443 (ingress), 30051→8080 (Navigator gRPC)
   - Volume mount for `/var/lib/rancher/k3s`
   - Extra host: `host.docker.internal:host-gateway` (for DNS resolution)
   - k3s args: `--disable=traefik --tls-san=127.0.0.1,localhost,host.docker.internal`
4. **Kubeconfig extraction** - Waits for k3s to generate kubeconfig, rewrites server URL to `127.0.0.1:6443`
5. **Kubeconfig storage** - Saves to `~/.config/navigator/clusters/{name}/kubeconfig`

### Kubeconfig Management

The CLI manages kubeconfig files:

| Location                                         | Purpose                             |
| ------------------------------------------------ | ----------------------------------- |
| `~/.config/navigator/clusters/{name}/kubeconfig` | Stored cluster config               |
| `$KUBECONFIG` or `~/.kube/config`                | Updated with `--update-kube-config` |

The `--update-kube-config` flag merges the cluster's kubeconfig into your local config, setting context/cluster/user entries without overwriting unrelated entries.

### Environment Variables

| Variable                  | Description                                                       |
| ------------------------- | ----------------------------------------------------------------- |
| `NAVIGATOR_CLUSTER_IMAGE` | Override cluster image (default: `navigator-cluster:{IMAGE_TAG}`) |
| `IMAGE_TAG`               | Image tag when `NAVIGATOR_CLUSTER_IMAGE` not set (default: `dev`) |

## Deployment Flows

### Local Development

```bash
# Build and run local cluster (uses mise + CLI)
mise run cluster
```

The `mise run cluster` task:

1. Builds all images via `docker:build:cluster` (which builds sandbox and server first)
2. Runs `nav cluster admin deploy --name navigator --update-kube-config`
