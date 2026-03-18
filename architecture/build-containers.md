# Container Images

OpenShell produces two container images, both published for `linux/amd64` and `linux/arm64`.

## Gateway (`openshell/gateway`)

The gateway runs the control plane API server. It is deployed as a StatefulSet inside the cluster container via a bundled Helm chart.

- **Dockerfile**: `deploy/docker/Dockerfile.gateway`
- **Registry**: `ghcr.io/nvidia/openshell/gateway:latest`
- **Pulled when**: Cluster startup (the Helm chart triggers the pull)
- **Entrypoint**: `openshell-server --port 8080` (gRPC + HTTP, mTLS)

## Cluster (`openshell/cluster`)

The cluster image is a single-container Kubernetes distribution that bundles the Helm charts, Kubernetes manifests, and the `openshell-sandbox` supervisor binary needed to bootstrap the control plane.

- **Dockerfile**: `deploy/docker/Dockerfile.cluster`
- **Registry**: `ghcr.io/nvidia/openshell/cluster:latest`
- **Pulled when**: `openshell gateway start`

The supervisor binary (`openshell-sandbox`) is cross-compiled in a build stage and placed at `/opt/openshell/bin/openshell-sandbox`. It is exposed to sandbox pods at runtime via a read-only `hostPath` volume mount — it is not baked into sandbox images.

## Controlled GPU Runtime Bundle Path

OpenShell's runtime bundle publication contract is tarball-first. The canonical artifact is a per-architecture release tarball whose single top-level bundle directory contains the install-root payload plus `manifest.json`. If OCI publication is added later, it is only a mirror transport for that same bundle contract.

The current cluster build now consumes that published tarball through the local staged bundle path. `tasks/scripts/docker-build-cluster.sh` requires `OPENSHELL_RUNTIME_BUNDLE_TARBALL`, fails before any Helm packaging or Docker build when the bundle is missing or invalid, and stages the verified install-root payload under `deploy/docker/.build/runtime-bundle/<arch>/`. `deploy/docker/Dockerfile.cluster` then copies the runtime binaries, config, and shared libraries from that staged local tree into the final cluster image.

That requirement now flows through all cluster-image entrypoints instead of only the direct script call:

- local bootstrap via `tasks/scripts/cluster-bootstrap.sh` requires `OPENSHELL_RUNTIME_BUNDLE_TARBALL` whenever it is going to build the cluster image; prebuilt-image flows can still set `SKIP_CLUSTER_IMAGE_BUILD=1`
- remote gateway deploy via `scripts/remote-deploy.sh` requires either `--runtime-bundle-tarball` (or local `OPENSHELL_RUNTIME_BUNDLE_TARBALL`) for sync-and-build flows, or `--remote-runtime-bundle-tarball` when `--skip-sync` should reuse a tarball already staged on the remote host; the script exports the resolved remote path before invoking the remote cluster build
- multi-arch publishing via `tasks/scripts/docker-publish-multiarch.sh` requires `OPENSHELL_RUNTIME_BUNDLE_TARBALL_AMD64` and `OPENSHELL_RUNTIME_BUNDLE_TARBALL_ARM64`, builds one verified per-arch cluster image at a time, then assembles the final multi-arch manifest from those architecture-specific tags
- GitHub workflow cluster builds now consume release-asset URLs rather than local tarball paths directly: `tasks/scripts/download-runtime-bundle.sh` downloads per-arch tarballs into `deploy/docker/.build/runtime-bundles/`, `tasks/scripts/ci-build-cluster-image.sh` maps single-arch builds to `docker:build:cluster` and multi-arch builds to `docker:build:cluster:multiarch`, and `.github/workflows/docker-build.yml` passes explicit bundle URLs from workflow inputs or repo variables into that helper path

The intended first OpenShell tarball consumption path is the `tasks/scripts/docker-build-cluster.sh` -> `deploy/docker/Dockerfile.cluster` flow:

1. `tasks/scripts/docker-build-cluster.sh` receives the per-architecture runtime bundle tarball path through `OPENSHELL_RUNTIME_BUNDLE_TARBALL` before `docker buildx build`.
2. The script verifies the single top-level bundle-directory shape, requires valid JSON `manifest.json` content inside that bundle directory with a matching `architecture`, validates manifest-declared checksums and sizes, and checks the required runtime payload paths before staging.
3. The script stages the tarball payload into `deploy/docker/.build/runtime-bundle/<arch>/`, preserving the bundle directory and install-root layout expected by OpenShell.
4. `deploy/docker/Dockerfile.cluster` loads the staged local bundle tree in a dedicated build stage and copies the verified runtime files into the same final image paths OpenShell already expects.

The tarball payload must contain the exact runtime assets the cluster image expects today:

- `/usr/bin/nvidia-cdi-hook`
- `/usr/bin/nvidia-container-runtime`
- `/usr/bin/nvidia-container-runtime-hook`
- `/usr/bin/nvidia-container-cli`
- `/usr/bin/nvidia-ctk`
- `/etc/nvidia-container-runtime/`
- `/usr/lib/*-linux-gnu/libnvidia-container*.so*`

This handoff keeps the OpenShell build package-manager-free for the runtime dependency itself. Standard OS image layers can remain upstream inputs, but the GPU runtime contents enter the build as a verified tarball payload rather than through a distro package repository. OCI, if later added, mirrors this same tarball-defined payload instead of changing the OpenShell consumption contract.

## Sandbox Images

Sandbox images are **not built in this repository**. They are maintained in the [openshell-community](https://github.com/nvidia/openshell-community) repository and pulled from `ghcr.io/nvidia/openshell-community/sandboxes/` at runtime.

The default sandbox image is `ghcr.io/nvidia/openshell-community/sandboxes/base:latest`. To use a named community sandbox:

```bash
openshell sandbox create --from <name>
```

This pulls `ghcr.io/nvidia/openshell-community/sandboxes/<name>:latest`.

## Local Development

`mise run cluster` is the primary development command. It bootstraps a cluster if one doesn't exist, then performs incremental deploys for subsequent runs.

The incremental deploy (`cluster-deploy-fast.sh`) fingerprints local Git changes and only rebuilds components whose files have changed:

| Changed files | Rebuild triggered |
|---|---|
| Cargo manifests, proto definitions, cross-build script | Gateway + supervisor |
| `crates/openshell-server/*`, `Dockerfile.gateway` | Gateway |
| `crates/openshell-sandbox/*`, `crates/openshell-policy/*` | Supervisor |
| `deploy/helm/openshell/*` | Helm upgrade |

When no local changes are detected, the command is a no-op.

**Gateway updates** are pushed to a local registry and the StatefulSet is restarted. **Supervisor updates** are copied directly into the running cluster container via `docker cp` — new sandbox pods pick up the updated binary immediately through the hostPath mount, with no image rebuild or cluster restart required.

Fingerprints are stored in `.cache/cluster-deploy-fast.state`. You can also target specific components explicitly:

```bash
mise run cluster -- gateway    # rebuild gateway only
mise run cluster -- supervisor # rebuild supervisor only
mise run cluster -- chart      # helm upgrade only
mise run cluster -- all        # rebuild everything
```
