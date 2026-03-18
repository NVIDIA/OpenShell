# Build Benchmark

Validation harness for cluster deploys. Tests change detection, build routing, and image cache reuse across component changes. All operations run through `mise run cluster` to replicate the real user workflow.

## Usage

The script bootstraps a cluster automatically via `mise run cluster` if one isn't already running.

Run the full suite:

```sh
scripts/build-benchmark/cluster-deploy-fast-test.sh
```

Run specific scenarios:

```sh
scripts/build-benchmark/cluster-deploy-fast-test.sh noop gateway-auto supervisor-cache
```

## Scenarios

| Scenario | Description |
|---|---|
| `noop` | Clean tree is a no-op after state is primed |
| `gateway-auto` | Gateway-only change triggers gateway rebuild + Helm upgrade |
| `supervisor-auto` | Supervisor-only change triggers supervisor refresh only |
| `shared-auto` | Shared dependency change triggers both rebuilds |
| `helm-auto` | Helm-only change triggers Helm upgrade only |
| `unrelated-auto` | Unrelated file change stays a no-op |
| `explicit-targets` | Explicit targets override change detection |
| `gateway-cache` | Cold vs warm gateway rebuild comparison |
| `supervisor-cache` | Cold vs warm supervisor rebuild comparison |
| `container-invalidation` | Mismatched container ID invalidates gateway + Helm state |

## Environment Variables

| Variable | Description |
|---|---|
| `CLUSTER_NAME` | Override cluster name to test against |
| `FAST_DEPLOY_TEST_REPORT_DIR` | Output directory (default: `.cache/cluster-deploy-fast-test/<timestamp>`) |
| `FAST_DEPLOY_TEST_KEEP_WORKTREES` | Set to `1` to keep temporary worktrees |
| `FAST_DEPLOY_TEST_SKIP_CACHE` | Set to `1` to skip cache timing scenarios |
