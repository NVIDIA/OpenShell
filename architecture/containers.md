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
- Policy files mounted at `/var/navigator/policy.rego` (rules) and `/var/navigator/data.yaml` (data)
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
- Uses an embedded Rust SSH client (`russh`) for sandbox exec

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
| `mise run cluster:deploy`       | Fast deploy changed components only |
| `mise run sandbox`              | Run sandbox container interactively |
| `mise run helm:lint`            | Lint the Helm chart                 |

`cluster:deploy` determines what to rebuild from local Git changes (unstaged, staged,
and untracked files). Changes under `crates/navigator-providers/` trigger both server
and sandbox image rebuilds because both runtimes depend on provider behavior.

### Environment Variables

| Variable             | Default        | Description                             |
| -------------------- | -------------- | --------------------------------------- |
| `IMAGE_TAG`          | `dev`          | Tag for built images                    |
| `RUST_BUILD_PROFILE` | `debug`        | `debug` or `release` for sandbox builds |
| `K3S_VERSION`        | `v1.29.8-k3s1` | k3s version for cluster image           |
| `CLUSTER_NAME`       | `navigator`    | Name for local cluster deployment       |

### Build Caching

Container builds use Docker BuildKit local caches under `.cache/buildkit/`:

- `build/scripts/docker-build-component.sh` stores per-component caches in `.cache/buildkit/<component>`
- `build/scripts/docker-build-cluster.sh` stores the cluster image cache in `.cache/buildkit/cluster`
- Rust-heavy Dockerfiles use BuildKit cache mounts for cargo registry and target directories keyed by image and target architecture, with `sharing=locked` to avoid concurrent cache corruption in parallel CI builds
- When the active buildx driver is `docker` (instead of `docker-container`), local cache import/export flags are skipped automatically because that driver cannot export local caches

In CI, caching `.cache/buildkit/` between pipeline runs avoids recompiling unchanged Rust dependencies and reduces repeated image rebuild time.

The `python_e2e_sandbox_test` job does not use a localhost registry. It tags and pushes component images to the GitLab project registry (`$CI_REGISTRY_IMAGE`) and configures cluster bootstrap to pull from that remote registry with CI credentials.

The `build_ci_image` job also publishes and reuses a registry-backed BuildKit cache at `$CI_REGISTRY_IMAGE/ci:buildcache`, so layer cache survives across runners and pipelines even when local cache directories are cold.

Publish jobs mirror `crazymax/osxcross:latest` into `$CI_REGISTRY_IMAGE/third_party/osxcross:latest` (when missing) and set `OSXCROSS_IMAGE` so the macOS wheel Docker build consumes the mirrored registry image instead of pulling directly from Docker Hub on each run.

Rust lint/test jobs also cache `.cache/sccache/` and `target/` with keys derived from `Cargo.lock` and Rust task config files (scoped per runner architecture) so branches can reuse compilation artifacts. CI sets `CARGO_INCREMENTAL=0` to favor deterministic clean builds over incremental metadata churn.

### CI Runner Image

`deploy/docker/Dockerfile.ci` pre-installs tools used by pipeline jobs so they do not download at runtime:

- Docker CLI and buildx plugin for DinD-based image build/publish jobs
- AWS CLI v2 for ECR authentication and image publishing
- `uv` installed directly from Astral's installer script (avoids GitHub API rate-limit failures during image builds)
- `sccache` installed on amd64 CI images (skipped on arm64 where the pinned aqua package is unavailable)
- `socat` for Docker socket forwarding in sandbox e2e tests
- The CI image build context must include `build/` because `Dockerfile.ci` copies build task includes from that directory

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
