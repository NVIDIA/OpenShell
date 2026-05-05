# Container Images and Deployment Packaging

OpenShell publishes the gateway image and keeps Kubernetes Helm packaging in this repository. Sandbox images are maintained in the separate OpenShell Community repository.

## Gateway Image

The gateway image runs the control plane API server. Kubernetes deployments use it through the Helm chart. Standalone container deployments can use the same image with driver-specific runtime configuration.

- **Docker target**: `gateway` in `deploy/docker/Dockerfile.images`
- **Registry**: `ghcr.io/nvidia/openshell/gateway:latest`
- **Pulled when**: Helm install or upgrade, or standalone container deployment
- **Entrypoint**: `openshell-gateway --port 8080`

The image contains the gateway binary and database migrations. Runtime configuration is supplied by Helm values and Kubernetes secrets for Kubernetes, or by driver-specific configuration for standalone gateway deployments.

## Helm Chart

The Helm chart at `deploy/helm/openshell` owns Kubernetes deployment concerns:

- Gateway StatefulSet and persistent volume claim.
- Service account, RBAC, and service.
- Gateway service exposure.
- TLS secret mounts and environment variables.
- Sandbox namespace, default sandbox image, and callback endpoint configuration.
- NetworkPolicy restricting sandbox SSH ingress to the gateway.

The chart remains the supported deployment artifact for Kubernetes.

## Image Build Pipeline

`deploy/docker/Dockerfile.images` no longer compiles Rust. CI calls `.github/workflows/shadow-rust-native-build.yml` through `workflow_call` to build `openshell-gateway` or `openshell-sandbox` natively on the target architecture. `.github/workflows/docker-build.yml` downloads the resulting artifact, stages it at `deploy/docker/.build/prebuilt-binaries/<arch>/`, builds the per-arch image with the local Buildx driver, and merges multi-arch pushes with `docker buildx imagetools create`. Callers normally publish the GitHub SHA tag, but can pass `image-tag` to publish isolated temporary tags for validation.

Local image builds use `tasks/scripts/stage-prebuilt-binaries.sh` through `tasks/scripts/docker-build-image.sh` before invoking Docker, so clean checkouts do not need to create the staging directory manually.

## Supervisor Delivery

The `openshell-sandbox` supervisor is delivered by the selected compute driver:

| Driver | Supervisor delivery |
|---|---|
| Kubernetes | Sandbox pod image or Kubernetes driver pod template configuration. |
| Docker | Local supervisor binary or supervisor image extraction configured by the gateway. |
| Podman | Read-only OCI image volume from the `supervisor-output` image. |
| VM | Embedded in the VM runtime rootfs. |

Each compute driver owns supervisor delivery for its runtime.

## Standalone Gateway Binary

OpenShell also publishes a standalone `openshell-gateway` binary as a GitHub release asset.

- **Source crate**: `crates/openshell-server`
- **Artifact name**: `openshell-gateway-<target>.tar.gz`
- **Targets**: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `aarch64-apple-darwin`
- **Release workflows**: `.github/workflows/release-dev.yml`, `.github/workflows/release-tag.yml`

Both the standalone artifact and the deployed container image use the `openshell-gateway` binary.

## Python Wheels

OpenShell also publishes Python wheels for `linux/amd64`, `linux/arm64`, and macOS ARM64.

- Linux wheels are built natively on matching Linux runners via `build:python:wheel:linux:amd64` and `build:python:wheel:linux:arm64` in `tasks/python.toml`.
- There is no local Linux multiarch wheel build task. Release workflows own the per-arch Linux wheel production.
- The macOS ARM64 wheel is cross-compiled with `deploy/docker/Dockerfile.python-wheels-macos` via `build:python:wheel:macos`.
- Release workflows mirror the CLI layout: a Linux matrix job for amd64/arm64, a separate macOS job, and release jobs that download the per-platform wheel artifacts directly before publishing.
- Release CPU jobs run on `linux-amd64-cpu8` and `linux-arm64-cpu8`; the macOS wheel is still cross-compiled in Docker from the amd64 Linux runner.

## Sandbox Images

Sandbox images are not built in this repository. They are maintained in the [openshell-community](https://github.com/nvidia/openshell-community) repository and pulled from `ghcr.io/nvidia/openshell-community/sandboxes/` at runtime.

The default sandbox image is `ghcr.io/nvidia/openshell-community/sandboxes/base:latest`. To use a named community sandbox:

```bash
openshell sandbox create --from <name>
```

This pulls `ghcr.io/nvidia/openshell-community/sandboxes/<name>:latest`.

## Local Development

Use the workflow that matches the driver you are changing:

| Area | Typical local command |
|---|---|
| Gateway image or chart | `mise run helm:lint` and `mise run docker:build:gateway` |
| Docker driver | `mise run gateway:docker` or `mise run e2e:docker` |
| Podman driver | `mise run e2e:podman` |
| VM driver | `mise run e2e:vm` |
| Published docs | `mise run docs` |

Kubernetes chart changes should be validated with `helm lint deploy/helm/openshell` and, when possible, by installing the chart into a disposable Kubernetes namespace.
