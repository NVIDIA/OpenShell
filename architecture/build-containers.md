# Container Management

This document describes how the project's container images are built, organized, and deployed. It covers the Dockerfiles, build automation, Helm chart configuration, and CI/CD integration.

## Directory Structure

```
deploy/
  docker/
    .dockerignore
    Dockerfile.sandbox             # Sandbox container (runs agent code in isolation)
    Dockerfile.gateway             # Gateway container (orchestration / control plane)
    Dockerfile.cluster             # Airgapped k3s cluster with Helm charts and manifests
    Dockerfile.ci                  # CI runner image with pre-installed toolchain
    Dockerfile.python-wheels       # Multi-arch Linux wheel builder for the Python CLI package
    Dockerfile.python-wheels-macos # macOS arm64 wheel builder (cross-compilation via osxcross)
    cross-build.sh                 # Shared Rust cross-compilation helpers for multi-arch builds
    cluster-entrypoint.sh          # Entrypoint script for DNS proxy and registry config in Docker
    cluster-healthcheck.sh         # Docker HEALTHCHECK script for cluster readiness
    .build/                        # Generated artifacts (charts/*.tgz)
  helm/
    navigator/                     # Helm chart for the gateway
      Chart.yaml
      values.yaml
      templates/
        _helpers.tpl
        statefulset.yaml
        service.yaml
        serviceaccount.yaml
        role.yaml
        rolebinding.yaml
  kube/
    manifests/                     # Kubernetes manifests for k3s auto-deploy
      navigator-helmchart.yaml
      agent-sandbox.yaml           # Agent Sandbox CRD controller RBAC
tasks/
  docker.toml                      # Docker image build tasks
  cluster.toml                     # Cluster bootstrap and deploy tasks
  helm.toml                        # Helm lint task
  rust.toml                        # Rust build/lint/format tasks
  ci.toml                          # Public quality tasks and CI entrypoint
  test.toml                        # Test tasks (Rust + Python)
  python.toml                      # Python build/lint/format tasks
  publish.toml                     # Release publishing tasks
  version.toml                     # Git-derived version management
  scripts/
    docker-build-component.sh      # Generic Docker image builder
    docker-build-cluster.sh        # Cluster image builder (packages Helm charts first)
    docker-publish-multiarch.sh    # Multi-arch build and push (registry or ECR)
    cluster-bootstrap.sh           # Full cluster bootstrap (registry + push + deploy)
    cluster-push-component.sh      # Tag and push a single component to the local registry
    cluster-deploy-fast.sh         # Incremental deploy from local Git changes
```

## Container Images

The project produces three runtime container images and two build-only wheel images.

### Sandbox Image (`openshell/sandbox`)

The sandbox container runs inside each sandbox pod. It contains the sandbox supervisor binary, Python runtime, AI agent tooling, and a virtual environment for the Python SDK.

**Build stages** (5 stages in `deploy/docker/Dockerfile.sandbox`):

1. **rust-builder** -- Cross-compiles the `navigator-sandbox` binary from Rust. Uses `deploy/docker/cross-build.sh` for multi-arch support (amd64/arm64). Build profile is controlled by the `RUST_BUILD_PROFILE` arg (default: `debug`).
2. **base** -- Python 3.12 slim with system dependencies (`iproute2` for network namespace management, `dnsutils`, `curl`, etc.) and two users: `supervisor` (privileged) and `sandbox` (restricted).
3. **builder** -- Installs Python dependencies via `uv` into `/app/.venv`. Includes the SDK dependencies (`cloudpickle`, `grpcio`, `protobuf`).
4. **coding-agents** -- Installs AI agent CLIs: Claude (via native installer), OpenCode (`opencode-ai` npm package), and Codex (`@openai/codex` npm package). Requires Node.js and npm.
5. **final** -- Combines the Rust binary, Python venv, SDK source, and coding agents. Creates `/var/navigator` for policy files and `/sandbox` owned by the `sandbox` user. Entrypoint is `navigator-sandbox`.

**Key details:**

- Multi-user isolation: `supervisor` (runs the sandbox supervisor) and `sandbox` (runs the restricted agent process).
- Policy files are mounted at `/var/navigator/policy.rego` (rules) and `/var/navigator/data.yaml` (data) when running in file-based policy mode.
- The Python SDK is copied directly into the venv's site-packages at `/app/.venv/lib/python3.12/site-packages/openshell/`.

### Gateway Image (`openshell/gateway`)

The gateway container runs the control plane / orchestration service.

**Build stages** (2 stages in `deploy/docker/Dockerfile.gateway`):

1. **builder** -- Two-pass Rust compilation with dependency caching:
   - First pass copies only `Cargo.toml`/`Cargo.lock` files and creates dummy source files (`fn main() {}` / empty `lib.rs`) to build dependencies in isolation. This layer is cached unless dependency manifests change.
   - Second pass copies real source, touches source files and `.proto` definitions to force rebuilding, and compiles in release mode.
   - Uses `deploy/docker/cross-build.sh` for multi-arch cross-compilation.
   - Proto files are copied and `build.rs` is touched to ensure proto code regeneration when the cache mount retains stale `OUT_DIR` artifacts.
2. **runtime** -- Debian bookworm-slim (pinned to a specific point release) with `ca-certificates`. Runs as non-root user `navigator` (created with `useradd --create-home`). SQLx migrations are copied to `/build/crates/navigator-server/migrations` (the path expected by `sqlx` at build time).

**Key details:**

- Exposes port 8080 (gRPC + HTTP multiplexed, mTLS required).
- No Docker HEALTHCHECK -- health checks are handled by Kubernetes liveness/readiness probes (`tcpSocket` on the gRPC port).
- Entrypoint: `navigator-server`, default args: `--port 8080`.

### Cluster Image (`openshell/cluster`)

A k3s image with bundled Helm charts and Kubernetes manifests for single-container deployment. Component images (sandbox, gateway) are **pulled at runtime** from the distribution registry -- they are not bundled as tarballs in this image.

**Defined in** `deploy/docker/Dockerfile.cluster`.

**Base image:** `rancher/k3s:v1.35.2-k3s1` (configurable via `K3S_VERSION` build arg).

**Layers added:**

1. Custom entrypoint: `cluster-entrypoint.sh` at `/usr/local/bin/`.
2. Healthcheck script: `cluster-healthcheck.sh` at `/usr/local/bin/`.
3. Packaged Helm charts: `deploy/docker/.build/charts/*.tgz` at `/var/lib/rancher/k3s/server/static/charts/`.
4. Kubernetes manifests: `deploy/kube/manifests/*.yaml` at `/opt/navigator/manifests/`.

**Bundled manifests:**

- `navigator-helmchart.yaml` -- HelmChart CR that auto-deploys the gateway chart from the k3s static file server.
- `agent-sandbox.yaml` -- Agent Sandbox CRD controller namespace, service account, and RBAC bindings.

**HEALTHCHECK:** `--interval=5s --timeout=5s --start-period=20s --retries=60`, runs `/usr/local/bin/cluster-healthcheck.sh`.

**Runtime image pulling:** Registry credentials are generated by the entrypoint script at container start and written to `/etc/rancher/k3s/registries.yaml`. The bootstrap code (`navigator-bootstrap`) passes registry host, endpoint, and credentials as environment variables on the container.

### Python Wheel Images (build-only)

Two Dockerfiles produce Python wheels for the CLI package distribution. These are not deployed as running containers.

- **`Dockerfile.python-wheels`** -- Builds Linux amd64/arm64 wheels using Maturin with a two-pass Rust build (dependency prebuild + final wheel build), BuildKit cache mounts for cargo registry/git/target, sccache (backed by memcached when `SCCACHE_MEMCACHED_ENDPOINT` build arg is provided), and `cross-build.sh` for conditional cross-toolchain installation. The final build step patches workspace version inside the container layer from `OPENSHELL_CARGO_VERSION` (computed before Docker build), preserving cacheable dependency layers and avoiding dirty working-tree edits. Output stage is `scratch` with only the `.whl` files.
- **`Dockerfile.python-wheels-macos`** -- Builds macOS arm64 wheels using osxcross (cross-compiling from Linux) with the same two-pass dependency caching pattern and cargo cache mounts. Version injection uses the same in-container workspace-version patch from `OPENSHELL_CARGO_VERSION`, avoiding host-side file edits that break Docker layer caching. Uses `crazymax/osxcross:latest` as the cross-toolchain source. The `OSXCROSS_IMAGE` build arg allows using a mirrored registry image instead of Docker Hub.

### CI Runner Image (`navigator-ci`)

A pre-built Ubuntu 24.04 image for CI pipeline jobs, defined in `deploy/docker/Dockerfile.ci`.

**Pre-installed tools:**

| Tool | Purpose |
|---|---|
| Docker CLI + buildx plugin | DinD-based image build/publish jobs |
| AWS CLI v2 | ECR authentication and image publishing |
| kubectl, helm, protoc | Kubernetes operations, chart packaging, proto compilation |
| mise | Task runner with Rust and Python toolchains |
| uv | Python package management (installed from Astral's installer to avoid GitHub API rate limits) |
| sccache | Rust compilation cache (amd64 only; skipped on arm64) |
| socat | Docker socket forwarding in sandbox e2e tests |

The build context must include `tasks/` because the Dockerfile copies mise task includes from that directory (`mise.toml` + `tasks/*.toml`).

## Cross-Compilation Support

All Rust-based Dockerfiles (sandbox, gateway) use `deploy/docker/cross-build.sh` for multi-architecture builds. This script:

1. Detects whether the build is cross-platform by comparing `TARGETARCH` and `BUILDARCH` (set by `docker buildx`).
2. Maps Docker arch names to Rust target triples (`arm64` -> `aarch64-unknown-linux-gnu`, `amd64` -> `x86_64-unknown-linux-gnu`).
3. Installs the gcc cross-linker and target libc for the target architecture (no-op for native builds).
4. Provides `cargo_cross_build()` which sets `CC`, `CXX`, and linker environment variables and passes the correct `--target` flag.
5. Provides `cross_output_dir()` to locate the compiled binary in the correct target-specific output directory.

This enables the `FROM --platform=$BUILDPLATFORM` pattern: Rust compilation runs natively on the build host for speed, and only the final runtime stage runs on the target platform.

## Entrypoint Script

`deploy/docker/cluster-entrypoint.sh` runs before k3s starts inside the cluster container. It performs four tasks.

### DNS proxy setup

On Docker custom networks, `/etc/resolv.conf` contains `127.0.0.11` (Docker's embedded DNS). k3s detects this loopback address and falls back to `8.8.8.8`, which does not work reliably on Docker Desktop (Mac/Windows) due to external UDP limitations.

The entrypoint solves this with an iptables-based DNS proxy:

1. Discovers Docker's real DNS listener ports from the `DOCKER_OUTPUT` iptables chain (Docker DNAT rules that redirect port 53 to random high ports on `127.0.0.11`).
2. Gets the container's `eth0` IP as a routable address.
3. Adds DNAT rules in `PREROUTING` to forward DNS traffic from k3s pod network namespaces through the container's `eth0` IP to Docker's DNS.
4. Writes a custom resolv.conf at `/etc/rancher/k3s/resolv.conf` pointing to the container IP.
5. Passes `--resolv-conf=/etc/rancher/k3s/resolv.conf` to k3s.

If iptables detection fails, falls back to writing `8.8.8.8` / `8.8.4.4` as nameservers.

### Registry configuration

Writes `/etc/rancher/k3s/registries.yaml` from environment variables passed by the bootstrap code:

| Variable | Purpose |
|---|---|
| `REGISTRY_HOST` | Registry hostname for the mirror entry |
| `REGISTRY_ENDPOINT` | Endpoint URL (defaults to `REGISTRY_HOST`) |
| `REGISTRY_INSECURE` | Use HTTP instead of HTTPS (parsed: `true`/`1`/`yes`/`on`) |
| `REGISTRY_USERNAME` | Auth username (optional) |
| `REGISTRY_PASSWORD` | Auth password (optional) |

### Manifest injection

Copies bundled manifests from `/opt/navigator/manifests/` to `/var/lib/rancher/k3s/server/manifests/`. This is necessary because the persistent volume mount on `/var/lib/rancher/k3s` overwrites any files baked into that path at image build time.

### Image configuration overrides

Modifies the HelmChart manifest at `/var/lib/rancher/k3s/server/manifests/navigator-helmchart.yaml` based on environment variables:

| Variable | Effect |
|---|---|
| `IMAGE_REPO_BASE` | Rewrites `repository:` and `sandboxImage:` to use the specified base path |
| `PUSH_IMAGE_REFS` | Parses comma-separated image refs and rewrites exact gateway and sandbox references (matching on path component `/gateway:`, `/sandbox:`) |
| `IMAGE_TAG` | Replaces `:latest` tags with the specified tag (handles both quoted and unquoted `tag: latest` formats) |
| `IMAGE_PULL_POLICY` | Replaces `pullPolicy: Always` with the specified policy (e.g., `IfNotPresent`) |
| `SSH_GATEWAY_HOST` / `SSH_GATEWAY_PORT` | Replaces `__SSH_GATEWAY_HOST__` and `__SSH_GATEWAY_PORT__` placeholders; clears to defaults if unset |


## Healthcheck Script

`deploy/docker/cluster-healthcheck.sh` validates cluster readiness through a series of sequential checks:

1. **Kubernetes API** -- `kubectl get --raw='/readyz'`.
2. **OpenShell StatefulSet** -- Checks that `statefulset/navigator` in namespace `navigator` exists and has 1 ready replica.
3. **TLS secrets** -- Verifies that `navigator-server-tls` and `navigator-client-tls` secrets exist in the `navigator` namespace (created by the bootstrap crate before the StatefulSet starts).

## Helm Chart

The Helm chart at `deploy/helm/navigator/` deploys the gateway to Kubernetes as a StatefulSet.

### Chart Metadata

| Field | Value |
|---|---|
| Name | `navigator` |
| Type | `application` |
| Version | `0.1.0` |
| appVersion | `0.1.0` |

### Key Configuration (`values.yaml`)

```yaml
replicaCount: 1

image:
  repository: ghcr.io/nvidia/openshell/gateway
  pullPolicy: Always
  tag: "latest"

server:
  logLevel: info
  sandboxNamespace: navigator
  dbUrl: "sqlite:/var/navigator/navigator.db"
  sandboxImage: "ghcr.io/nvidia/openshell/sandbox:latest"
  grpcEndpoint: "https://navigator.navigator.svc.cluster.local:8080"
  sshGatewayHost: ""     # Public host for SSH proxy CONNECT (default: 127.0.0.1)
  sshGatewayPort: 0      # Public port for SSH proxy CONNECT (default: 8080)
  tls:
    certSecretName: navigator-server-tls
    clientCaSecretName: navigator-server-client-ca
    clientTlsSecretName: navigator-client-tls

service:
  type: NodePort
  port: 8080
  nodePort: 30051
```

### Deployment Architecture

The chart deploys a **StatefulSet** (not a Deployment) with a `volumeClaimTemplate` for persistent storage:

- **PVC**: `navigator-data`, `ReadWriteOnce`, 1Gi, mounted at `/var/navigator`.
- **Security context**: non-root (UID 1000), `fsGroup: 1000`, all capabilities dropped, no privilege escalation.
- **Probes**: `tcpSocket` on the `grpc` port (8080) for both liveness and readiness. Defaults are tuned for faster local rollouts:
  - liveness: initial delay 2s, period 5s, timeout 1s, failure threshold 3
  - readiness: initial delay 1s, period 2s, timeout 1s, failure threshold 3
  TCP probes are used because the server terminates TLS directly.
- **Termination grace**: `terminationGracePeriodSeconds` is configurable via chart values (default 5s) to reduce restart latency during iterative deploys.
- **Service**: NodePort exposing port 8080, with nodePort 30051.

### Server TLS Configuration

The StatefulSet always mounts TLS secrets as volumes and sets environment variables for the server to use `rustls` with mTLS:

- **Volumes**: `tls-cert` (from `navigator-server-tls` secret, mounted at `/etc/openshell-tls/server/`) and `tls-client-ca` (from `navigator-server-client-ca` secret, mounted at `/etc/openshell-tls/client-ca/`).
- **Environment**: `OPENSHELL_TLS_CERT`, `OPENSHELL_TLS_KEY`, `OPENSHELL_TLS_CLIENT_CA` pointing to the mounted files.
- **Client TLS secret name**: `OPENSHELL_CLIENT_TLS_SECRET_NAME` set to the `clientTlsSecretName` value, used by the server to inject TLS volume mounts into sandbox pod specs.
- **gRPC endpoint**: `https://navigator.navigator.svc.cluster.local:8080` so sandbox pods connect over mTLS.

TLS certificates are generated at cluster bootstrap time by the `navigator-bootstrap` crate using `rcgen`, not by a Helm Job. The bootstrap reconciles three K8s secrets before the Helm release is installed:

- On first deploy, a full PKI hierarchy (CA, server cert, client cert) is generated and applied.
- On redeploy, existing secrets are loaded and reused if they contain valid PEM data. If secrets are missing, incomplete, or malformed, a fresh PKI is generated and applied.
- Certificate validity uses `rcgen` defaults (effectively never expires), which is appropriate for an internal dev-cluster PKI where certs are ephemeral to the cluster's lifetime.
- If PKI rotation occurs on a running cluster, the navigator workload (StatefulSet or Deployment) is automatically restarted and the rollout must complete before CLI-side credentials are updated. A failed rollout aborts the deploy.

The fast deploy script (`cluster-deploy-fast.sh`) always sets `--set-string server.grpcEndpoint=https://...` explicitly to enforce the HTTPS invariant, since the chart always terminates mTLS (there is no `server.tls.enabled` toggle).

### Server Environment Variables (from StatefulSet)

| Environment Variable | Source | Description |
|---|---|---|
| `OPENSHELL_SANDBOX_NAMESPACE` | `server.sandboxNamespace` | Kubernetes namespace for sandbox pods |
| `OPENSHELL_SANDBOX_IMAGE` | `server.sandboxImage` | Container image for sandbox pods |
| `OPENSHELL_GRPC_ENDPOINT` | `server.grpcEndpoint` | gRPC callback endpoint (reachable from pods) |
| `OPENSHELL_SSH_GATEWAY_HOST` | `server.sshGatewayHost` | Public SSH gateway hostname (conditional) |
| `OPENSHELL_SSH_GATEWAY_PORT` | `server.sshGatewayPort` | Public SSH gateway port (conditional) |

### RBAC

The chart creates a Role and RoleBinding granting the gateway's ServiceAccount permissions to manage `agents.x-k8s.io/sandboxes` resources (CRUD + watch) and read `events` in the release namespace.

## Build Tasks (mise)

All builds use mise tasks defined in `tasks/*.toml` (included from `mise.toml`).

### Docker Image Tasks

| Task | Description |
|---|---|
| `mise run docker:build` | Build all runtime images (sandbox, gateway, cluster) |
| `mise run docker:build:sandbox` | Build sandbox image |
| `mise run docker:build:gateway` | Build gateway image |
| `mise run docker:build:cluster` | Build k3s cluster image (packages Helm charts first) |
| `mise run docker:build:ci` | Build CI runner image |
| `mise run docker:build:cluster:multiarch` | Build multi-arch cluster image and push to a registry |
| `mise run docker:publish:cluster:multiarch` | Build and publish multi-arch cluster image to ECR |

### Cluster Lifecycle Tasks

| Task | Description |
|---|---|
| `mise run cluster` | Bootstrap or incremental deploy: creates cluster if needed, rebuilds changed components |

### Other Tasks

| Task | Description |
|---|---|
| `mise run cluster:sandbox` | Run sandbox container interactively (builds image first) |
| `mise run helm:lint` | Lint the Helm chart |

### How `cluster` Works (Incremental Deploy)

`tasks/scripts/cluster-deploy-fast.sh` supports two modes:

**Auto mode** (no arguments): Detects changed files from Git (unstaged, staged, and untracked), fingerprints the relevant local changes for each component, and rebuilds only components whose fingerprint changed since the last successful deploy.

| Changed Path | Triggers |
|---|---|
| `Cargo.toml`, `Cargo.lock`, `proto/*`, `deploy/docker/cross-build.sh` | Gateway + sandbox rebuild |
| `crates/navigator-core/*`, `crates/navigator-providers/*` | Gateway + sandbox rebuild |
| `crates/navigator-router/*` | Gateway rebuild |
| `crates/navigator-server/*`, `deploy/docker/Dockerfile.gateway` | Gateway rebuild |
| `crates/navigator-sandbox/*`, `deploy/docker/sandbox/*`, `python/*`, `pyproject.toml`, `uv.lock`, `crates/navigator-sandbox/data/sandbox-policy.rego` | Sandbox rebuild |
| `deploy/helm/navigator/*` | Helm upgrade |

**Explicit target mode** (arguments: `gateway`, `sandbox`, `chart`, `all`): Rebuilds only the specified components.

Auto mode persists the last deployed fingerprints in `.cache/cluster-deploy-fast.state` (or `$DEPLOY_FAST_STATE_FILE`). Re-running `mise run cluster` without new local changes prints `No new local changes since last deploy.` and skips rebuild/upgrade work.

After building, the script:

1. Tags images with the `IMAGE_REPO_BASE` prefix and pushes to the local registry.
2. Detects if the sandbox image content-addressable ID changed; if so, evicts the stale copy from k3s's containerd store via `crictl rmi` so new sandbox pods pull the updated image.
3. Runs `helm upgrade` if chart changes were detected (or `FORCE_HELM_UPGRADE=1`).
4. Restarts the gateway StatefulSet (or Deployment, if present) and waits for rollout completion.
5. On success, updates the local deploy fingerprint state file for the next incremental deploy.

### How `mise run cluster` Bootstrap Works

`tasks/scripts/cluster-bootstrap.sh` performs a full cluster bootstrap for local development:

1. Resolves the local registry address (defaults to `127.0.0.1:5000/navigator`). In CI, uses `$CI_REGISTRY_IMAGE`.
2. Ensures a local Docker registry container (`navigator-local-registry`) is running on port 5000 (creates one if needed).
3. Pushes prebuilt local component images (server, sandbox) to the local registry via `cluster-push-component.sh`.
4. Runs `nav gateway start --name <CLUSTER_NAME> --update-kube-config` to create or update the cluster container.

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `IMAGE_TAG` | `dev` | Tag for built images |
| `RUST_BUILD_PROFILE` | `debug` | `debug` or `release` for sandbox builds |
| `K3S_VERSION` | `v1.35.2-k3s1` | k3s version for cluster image (optional override; default in Dockerfile.cluster) |

| `CLUSTER_NAME` | basename of `$PWD` | Name for local cluster deployment |
| `DOCKER_PLATFORM` | (unset) | Target platform for multi-arch builds (e.g., `linux/amd64`) |
| `DOCKER_BUILDER` | (auto-selected) | Buildx builder name |
| `IMAGE_REPO_BASE` | `127.0.0.1:5000/navigator` | Image repository base for local registry pushes |
| `DEPLOY_FAST_STATE_FILE` | `.cache/cluster-deploy-fast.state` | Location of local incremental deploy fingerprint state |

### Build Caching

Container builds use Docker BuildKit with local cache directories:

- `tasks/scripts/docker-build-component.sh` stores per-component caches in `.cache/buildkit/<component>`.
- `tasks/scripts/docker-build-cluster.sh` stores the cluster image cache in `.cache/buildkit/cluster`.
- `mise run python:build:multiarch` stores per-platform wheel caches in `.cache/buildkit/python-wheels/<platform>` for local builds when using a `docker-container` buildx driver.
- Rust-heavy Dockerfiles use BuildKit cache mounts for cargo registry, cargo target, and sccache local disk directories. Cargo target cache mounts are keyed by image name, `TARGETARCH`, and a computed scope hash derived from `Cargo.lock` plus a Rust toolchain hint, with `sharing=locked` to prevent concurrent cache corruption in parallel CI builds. This reduces reuse of stale `target/` artifacts across dependency or toolchain changes while preserving incremental rebuilds within a compatible scope. sccache uses memcached in CI (`SCCACHE_MEMCACHED_ENDPOINT`) and falls back to the local disk cache mount for local dev builds, providing a second layer of caching at the compilation unit level.
- When the active buildx driver is `docker` (not `docker-container`), local cache import/export flags are skipped automatically because the docker driver cannot export local caches. In CI, cache export is also skipped.
- For local single-arch builds, the scripts auto-select a builder with the native `docker` driver (matching the active Docker context) so images land directly in the Docker image store without slow tarball export.

### CI Caching

In CI pipelines:

- Remote BuildKit daemons (`buildkit-amd64` and `buildkit-arm64`) are used as persistent builders via `driver: remote`. Their built-in layer cache persists across builds, so no external cache (registry-backed or otherwise) is needed in CI.
- Rust lint/test jobs cache `target/` with keys derived from `Cargo.lock` and Rust task config files, scoped per runner architecture. sccache uses a shared memcached backend (`SCCACHE_MEMCACHED_ENDPOINT`) instead of local disk.
- CI sets `CARGO_INCREMENTAL=0` to favor deterministic clean builds over incremental metadata churn.
- Publish jobs mirror `crazymax/osxcross:latest` into `$CI_REGISTRY_IMAGE/third_party/osxcross:latest` (when missing) and set `OSXCROSS_IMAGE` so macOS wheel Docker builds consume the mirrored image instead of pulling from Docker Hub on each run.
- The sandbox e2e test job tags and pushes component images to the GitLab project registry (`$CI_REGISTRY_IMAGE`) and configures cluster bootstrap to pull from that remote registry with CI credentials.

## Multi-Arch Publishing

`tasks/scripts/docker-publish-multiarch.sh` builds and pushes all images for multiple architectures.

**Two modes:**

| Mode | Registry | Notes |
|---|---|---|
| `registry` | `DOCKER_REGISTRY` env var | Images named `navigator-<component>` |
| `ecr` | AWS ECR (account/region configurable) | Images named `<component>` (no prefix), `--provenance=false --sbom=false` |

**Process:**

1. Builds and pushes sandbox and gateway images as multi-arch manifests using cross-compilation.
2. Packages the Helm chart.
3. Builds and pushes the multi-arch cluster image.
4. Applies additional tags (`:latest` if `TAG_LATEST=true`, plus any `EXTRA_DOCKER_TAGS`) by copying manifests with `docker buildx imagetools create --prefer-index=false`.

**Default platforms:** `linux/amd64,linux/arm64` (overridable via `DOCKER_PLATFORMS`).

## Deployment Flows

### Local Development

```bash
# Bootstrap or incremental deploy (creates cluster if needed, rebuilds changed components)
mise run cluster

# Run sandbox container interactively (for testing sandbox code)
mise run sandbox
```

### Multi-Arch Publishing

```bash
# Push to a generic Docker registry
DOCKER_REGISTRY=ghcr.io/myorg mise run docker:build:cluster:multiarch

# Push to ECR
mise run docker:publish:cluster:multiarch

# Main branch publish (dev + latest + version tags, cluster image + Python wheels)
mise run publish:main
```

GitHub Actions stages Python wheels in S3 before final publication to
Artifactory:

- Wheels are uploaded to `s3://navigator-pypi-artifacts/navigator/<wheel-version>/`.
- A follow-up job on the `nv` runner lists that version prefix, downloads the
  wheels, and publishes them to Artifactory.
- Container publish jobs compute the same Cargo version once and pass it through
  Docker builds so `navigator-server` reports the packaged artifact version at runtime.
- Published images keep the floating `latest` tag and also receive an explicit
  version tag for the same manifest.

### Auto-Deployed Components in Cluster

When the cluster container starts, k3s automatically deploys these HelmChart CRs from `/var/lib/rancher/k3s/server/manifests/`:

1. **OpenShell** (from `navigator-0.1.0.tgz` in the static charts directory) -- deployed into `navigator` namespace. The HelmChart CR's `valuesContent` configures image references, SSH gateway settings, and TLS options. These values are rewritten by the entrypoint script based on environment variables from the bootstrap code.

## Implementation References

- `deploy/docker/Dockerfile.sandbox` -- Sandbox image (5-stage multi-arch build)
- `deploy/docker/Dockerfile.gateway` -- Gateway image (2-stage with dependency caching)
- `deploy/docker/Dockerfile.cluster` -- Cluster image (k3s base + charts + manifests)
- `deploy/docker/Dockerfile.ci` -- CI runner image (Ubuntu + full toolchain)
- `deploy/docker/Dockerfile.python-wheels` -- Linux wheel builder
- `deploy/docker/Dockerfile.python-wheels-macos` -- macOS wheel builder
- `deploy/docker/cross-build.sh` -- Shared Rust cross-compilation helpers
- `deploy/docker/cluster-entrypoint.sh` -- Cluster container entrypoint
- `deploy/docker/cluster-healthcheck.sh` -- Cluster health check script
- `deploy/helm/navigator/` -- Helm chart directory
- `deploy/kube/manifests/` -- Auto-deployed Kubernetes manifests
- `tasks/docker.toml` -- Docker build task definitions
- `tasks/cluster.toml` -- Cluster lifecycle task definitions
- `tasks/scripts/docker-build-component.sh` -- Generic component image builder
- `tasks/scripts/docker-build-cluster.sh` -- Cluster image builder
- `tasks/scripts/docker-publish-multiarch.sh` -- Multi-arch publish script
- `tasks/scripts/cluster-bootstrap.sh` -- Full local cluster bootstrap
- `tasks/scripts/cluster-deploy-fast.sh` -- Incremental deploy script
- `tasks/scripts/cluster-push-component.sh` -- Single component push to registry
