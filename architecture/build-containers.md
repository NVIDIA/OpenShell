# Container Images

OpenShell produces two container images, both published for `linux/amd64` and `linux/arm64`.

## Gateway (`openshell/gateway`)

The gateway runs the control plane API server. It is deployed as a StatefulSet inside the cluster container via a bundled Helm chart.

- **Docker target**: `gateway` in `deploy/docker/Dockerfile.images`
- **Registry**: `ghcr.io/nvidia/openshell/gateway:latest`
- **Pulled when**: Cluster startup (the Helm chart triggers the pull)
- **Entrypoint**: `openshell-server --port 8080` (gRPC + HTTP, mTLS)

## Cluster (`openshell/cluster`)

The cluster image is a single-container Kubernetes distribution that bundles the Helm charts, Kubernetes manifests, and the `openshell-sandbox` supervisor binary needed to bootstrap the control plane.

- **Docker target**: `cluster` in `deploy/docker/Dockerfile.images`
- **Registry**: `ghcr.io/nvidia/openshell/cluster:latest`
- **Pulled when**: `openshell gateway start`

The supervisor binary (`openshell-sandbox`) is built by the shared `supervisor-builder` stage in `deploy/docker/Dockerfile.images` and placed at `/opt/openshell/bin/openshell-sandbox`. It is exposed to sandbox pods at runtime via a read-only `hostPath` volume mount — it is not baked into sandbox images.

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
| `crates/openshell-server/*`, `deploy/docker/Dockerfile.images` | Gateway |
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

To validate incremental routing and BuildKit cache reuse locally, run:

```bash
mise run cluster:test:fast-deploy-cache
```

The harness runs isolated scenarios in temporary git worktrees, keeps its own state and cache under `.cache/cluster-deploy-fast-test/`, and writes a Markdown summary with:

- auto-detection checks for gateway-only, supervisor-only, shared, Helm-only, unrelated, and explicit-target changes
- cold vs warm rebuild comparisons for gateway and supervisor code changes
- container-ID invalidation coverage to verify gateway + Helm are retriggered when the cluster container changes

