# Testing

## Running Tests

```bash
mise run test          # Rust + Python unit tests
mise run e2e           # End-to-end tests (starts a Docker-backed gateway)
mise run ci            # Everything: lint, compile checks, and tests
```

## Test Layout

```text
crates/*/src/          # Inline #[cfg(test)] modules
crates/*/tests/        # Rust integration tests
python/openshell/      # Python unit tests (*_test.py suffix)
e2e/python/            # Python E2E tests (test_*.py prefix)
e2e/rust/              # Rust CLI E2E tests
```

## Rust Tests

Unit tests live inline with `#[cfg(test)] mod tests` blocks. Integration tests
go in `crates/*/tests/` and are named `*_integration.rs`.

Use `#[tokio::test]` for anything async:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_round_trip() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        store.put("sandbox", "abc", "my-sandbox", b"payload").await.unwrap();
        let record = store.get("sandbox", "abc").await.unwrap().unwrap();
        assert_eq!(record.payload, b"payload");
    }
}
```

Run Rust tests only:

```bash
mise run test:rust     # cargo test --workspace
```

## Python Unit Tests

Python unit tests use the `*_test.py` suffix convention (not `test_*` prefix)
and live alongside the source in `python/openshell/`. They use mock-based
patterns with fake gRPC stubs:

```python
def test_exec_python_serializes_callable_payload() -> None:
    stub = _FakeStub()
    client = _client_with_fake_stub(stub)

    def add(a: int, b: int) -> int:
        return a + b

    result = client.exec_python("sandbox-1", add, args=(2, 3))
    assert result.exit_code == 0
```

Run Python unit tests only:

```bash
mise run test:python   # uv run pytest python/
```

## E2E Tests

E2E tests run against a live gateway. By default, `mise run e2e` starts an
ephemeral standalone gateway with the Docker compute driver, runs the suite,
and cleans it up afterward. To run the suite against an existing plaintext
gateway, set `OPENSHELL_GATEWAY_ENDPOINT`:

```bash
OPENSHELL_GATEWAY_ENDPOINT=http://127.0.0.1:18080 mise run e2e
```

Raw endpoint mode is HTTP-only. Use a named gateway config when a gateway
requires mTLS.

### Python E2E (`e2e/python/`)

Tests use the `sandbox` fixture from `conftest.py` to create real sandboxes:

```python
def test_exec_returns_stdout(sandbox):
    with sandbox(delete_on_exit=True) as sb:
        result = sb.exec(["echo", "hello"])
        assert result.exit_code == 0
        assert "hello" in result.stdout
```

#### `Sandbox.exec_python`

`exec_python` serializes a Python callable with `cloudpickle`, sends it to the
sandbox, and returns the result. Because cloudpickle serializes module-level
functions by reference (which fails inside the sandbox), use one of these
patterns:

**Closures from factory functions:**

```python
def _make_adder():
    def add(a, b):
        return a + b
    return add

def test_addition(sandbox):
    with sandbox(delete_on_exit=True) as sb:
        result = sb.exec_python(_make_adder(), args=(2, 3))
        assert result.stdout.strip() == "5"
```

**Bound methods on local classes:**

```python
def test_multiply(sandbox):
    class Calculator:
        def multiply(self, a, b):
            return a * b

    with sandbox(delete_on_exit=True) as sb:
        result = sb.exec_python(Calculator().multiply, args=(6, 7))
        assert result.stdout.strip() == "42"
```

#### Shared Fixtures (`e2e/python/conftest.py`)

| Fixture | Scope | Purpose |
|---|---|---|
| `sandbox_client` | session | gRPC client connected to the active gateway |
| `sandbox` | function | Factory returning a `Sandbox` context manager |
| `inference_client` | session | Client for managing inference routes |
| `mock_inference_route` | session | Creates a mock OpenAI-protocol route for tests |

### Rust CLI E2E (`e2e/rust/`)

Rust-based e2e tests that exercise the `openshell` CLI binary as a subprocess.
They live in the `openshell-e2e` crate and use a shared harness for sandbox
lifecycle management, output parsing, and cleanup.

Suites:

- Common suite (`--features e2e`) - driver-neutral CLI behavior, sandbox lifecycle, sync, port forwarding, policy, and provider tests.
- CLI conformance (`openshell-conformance`) - the portable deployment smoke
  scenario plus focused tests for its reusable command runner.
- Driver suites (`--features e2e-docker`, `e2e-podman`, `e2e-kubernetes`, or
  `e2e-vm`) - CLI conformance plus the common and driver-specific coverage for
  the selected deployment.
- Docker suite (`--features e2e-docker`) - includes Docker-only coverage such as Dockerfile image builds, Docker preflight checks, and managed Docker gateway start.
- Docker GPU suite (`--features e2e-docker-gpu`) - Docker suite plus GPU sandbox smoke coverage.
- VM suite (`--features e2e-vm`) - runs e2e tests on a VM.
- Kubernetes credential-driver suite (`--features e2e-kubernetes-credential-drivers`) - targeted Kubernetes Secrets and Vault provider credential storage coverage.

GPU device-selection tests compare OpenShell sandboxes against a plain Docker or
Podman container that requests `--device nvidia.com/gpu=all`. The probe image
defaults to the image used by the `gateway` stage in
`deploy/docker/Dockerfile.images`; set `OPENSHELL_E2E_GPU_PROBE_IMAGE` to
override it. Per-device checks run only for NVIDIA CDI device IDs reported by
the runtime's discovered devices list, so WSL2 hosts that expose only
`nvidia.com/gpu=all` skip the index-based cases. Exact CDI device selection is
passed through `--driver-config-json` with the active Docker or Podman driver
key.

Run the Docker-backed Rust CLI e2e suite:

```shell
mise run e2e:docker
```

Run the minimal portable CLI conformance profile against the gateway selected
in your OpenShell CLI configuration:

```shell
mise run e2e:cli-conformance
```

The gateway must already be installed, reachable, and selected before the task
starts. The task does not provision a gateway or select a compute driver. Set
`OPENSHELL_BIN` to test a prebuilt CLI; otherwise, the task builds the CLI from
the current checkout.

The phase-1 scenario verifies the complete CLI-to-gateway-to-driver path without
depending on how the gateway was installed or which driver is configured. It
requires machine-readable gRPC status, creates a uniquely named detached
sandbox with `--from base`, verifies the sandbox is `Ready` by finding its
unique name in paginated JSON list output, executes `echo` with a run-specific
marker, deletes the sandbox, and verifies that its name no longer appears.
Driver suites enable the same profile
instead of maintaining a separate smoke implementation. Sandbox lifecycle,
label matrices, VM overlay, and TLS-key permission assertions remain regular
E2E coverage.

Each invocation prints a ten-character run ID before creating resources.
Conformance sandboxes use names such as `ct-<run-id>-01`. The runner tracks the
exact name and uses it for cleanup; phase 1 does not add ownership labels.

The runner deletes owned resources after both success and failure. If the test
process is interrupted before cleanup, locate leftovers without touching
unrelated gateway state:

```shell
openshell sandbox list --output json
openshell sandbox delete <sandbox-name>
```

Gateway-backed Rust E2E tasks build the standalone conformance CLI, run its
registered scenarios against the configured gateway, then run any lane-specific
Rust tests that still apply. Run the Podman-backed Rust CLI e2e suite:

```shell
mise run e2e:podman
```

Run the VM-backed Rust CLI e2e suite:

```shell
mise run e2e:vm
```

Run the targeted Kubernetes credential-driver e2e suite. This deploys an
OpenBao fixture for the Vault-compatible driver path and validates Kubernetes
Secrets and Vault storage backends one at a time:

```shell
mise run e2e:kubernetes:credential-drivers
```

### Kubernetes E2E (`e2e/rust/e2e-kubernetes.sh`)

Kubernetes e2e tests deploy an OpenShell gateway into a real Kubernetes cluster
via Helm and run the Rust e2e suite against it. On vanilla Kubernetes the harness
reaches the gateway through `kubectl port-forward`; on OpenShift it instead uses a
passthrough Route secured with mandatory mTLS (see the OpenShift note below).

Run with an ephemeral k3d cluster (macOS; created and torn down automatically):

```shell
mise run e2e:kubernetes
```

Target an existing cluster (kind, k3d, or OpenShift):

```shell
OPENSHELL_E2E_KUBE_CONTEXT=my-context mise run e2e:kubernetes
```

Scope to a single test for local debugging:

```shell
OPENSHELL_E2E_KUBE_TEST=smoke mise run e2e:kubernetes
```

**OpenShift**: when the target cluster exposes the `route.openshift.io` API
group, the harness automatically applies SCC-compatible Helm overrides, grants
the required SCCs (`privileged` to `openshell-sandbox`, and `anyuid` to the
PostgreSQL fixture for DB scenarios), and drives the gateway through a
passthrough Route with mandatory mTLS instead of port-forward. No extra flags are
needed, but `oc` must be installed and authenticated against the target cluster
with permission to modify SCC bindings (`oc adm policy add-scc-to-user`) — the
harness exits early if `oc` is missing. The SCC grants and extracted client
mTLS material are removed during cleanup, including on failure or interrupt.

On a **remote** cluster, drop the `e2e-host-gateway` feature. Those tests rely
on the sandbox-side `host.openshell.internal` alias reaching the machine running
the tests, which is unreachable from pods on a remote cluster, so they fail.
Left enabled, the `host_gateway_alias` suite fails because
`host.openshell.internal` does not resolve inside the pod, so the gateway
SSRF-denies the request (`DNS resolution failed` / `ssrf_denied`) — a networking
property of remote pods, not a gateway or transport fault. Override
`OPENSHELL_E2E_KUBERNETES_FEATURES` to exclude it:

```shell
OPENSHELL_E2E_KUBE_CONTEXT=$(oc config current-context) \
  OPENSHELL_E2E_KUBERNETES_FEATURES="e2e,e2e-kubernetes" \
  mise run e2e:kubernetes
```

On an existing cluster the harness builds the CLI from your branch but pulls the
**published** gateway/supervisor image (default tag `latest`). The CLI and the
image can therefore be different versions. If tests fail because of this version
difference — for example, sandbox tests fail with `Pod exists with phase: Failed`
or connect-based tests stall because the deployed image predates a feature your
branch CLI needs — set `IMAGE_TAG` to an image that matches your branch.

The `latest` tag lags to the last semver release, so it is often older than
`main`. Two better choices:

- `IMAGE_TAG=dev` — a floating tag that tracks the latest `main` build. Good for
  an ad-hoc run when your branch is close to `main` HEAD. Because it floats, two
  runs on different days can pull different images, so it is not reproducible.
- **Pin the exact commit your branch is based on** — deterministic and immune to
  a floating tag moving. Published tags are the full 40-char git SHA (semver tags
  without a `v` prefix also exist but only for released versions):

```shell
OPENSHELL_E2E_KUBE_CONTEXT=$(oc config current-context) \
  OPENSHELL_E2E_KUBERNETES_FEATURES="e2e,e2e-kubernetes" \
  IMAGE_TAG=$(git rev-parse "$(git merge-base HEAD upstream/main)") \
  mise run e2e:kubernetes
```

To pin a specific released version, use its semver tag without a `v` prefix
(`0.0.115`, not `v0.0.115`):

```shell
OPENSHELL_E2E_KUBE_CONTEXT=$(oc config current-context) \
  OPENSHELL_E2E_KUBERNETES_FEATURES="e2e,e2e-kubernetes" \
  IMAGE_TAG=0.0.115 \
  mise run e2e:kubernetes
```

A semver tag matches a released commit, which may be behind `main`; if your
branch CLI needs a newer feature, pin the SHA of your branch's base instead.

Confirm a tag exists before relying on it (set `TAG` to the tag you plan to use):

```shell
TAG=0.0.115
skopeo inspect "docker://ghcr.io/nvidia/openshell/gateway:${TAG}"
```

`IMAGE_TAG` sets only the gateway/supervisor image; the CLI under test is always
built from your branch. To validate against images from your exact commit
instead, build and push them and point `OPENSHELL_REGISTRY`/`IMAGE_TAG` at them.

Available task variants:

| Task | Purpose |
|---|---|
| `e2e:kubernetes` | Default Rust e2e against Helm-deployed gateway |
| `e2e:kubernetes:db` | All database backend scenarios (SQLite + external PostgreSQL) |
| `e2e:kubernetes:sidecar` | Supervisor sidecar topology overlay |
| `e2e:kubernetes:credential-drivers` | Kubernetes Secrets and Vault credential storage |
| `e2e:kubernetes:workspace-managed` | Managed workspace mode (auto-created namespaces) |
| `e2e:kubernetes:workspace-operator` | Operator workspace mode (pre-provisioned namespaces) |
| `e2e:kubernetes:v1alpha1` | Agent Sandbox v1alpha1 compatibility |
| `e2e:kubernetes:external-driver` | External Kubernetes driver sidecar |

Kubernetes e2e environment variables:

| Variable | Purpose |
|---|---|
| `OPENSHELL_E2E_KUBE_CONTEXT` | kubectl context for an existing cluster (skips k3d creation) |
| `OPENSHELL_E2E_KUBE_TEST` | Scope to a single test (e.g. `smoke`) |
| `OPENSHELL_E2E_KUBE_EXTRA_VALUES` | Colon-separated additional Helm values files |
| `OPENSHELL_E2E_KUBERNETES_FEATURES` | Cargo feature flags (default: `e2e,e2e-host-gateway,e2e-kubernetes`) |
| `IMAGE_TAG` | Gateway/supervisor image tag (default: `latest` for existing clusters) |
| `OPENSHELL_REGISTRY` | Image registry prefix (default: `ghcr.io/nvidia/openshell`) |

Run a single test directly with cargo:

```shell
cargo test --manifest-path e2e/rust/Cargo.toml --features e2e --test sync
```

Run a single Docker-only test directly with cargo:

```shell
cargo test --manifest-path e2e/rust/Cargo.toml --features e2e-docker --test custom_image
```

The harness (`e2e/rust/src/harness/`) provides:

| Module | Purpose |
|---|---|
| `binary` | Builds and resolves the `openshell` binary from the workspace |
| `container` | Container-engine selection and support containers for proxy tests |
| `gateway` | Managed gateway restart controls for gateway-owned e2e runs |
| `sandbox` | `SandboxGuard` RAII type — creates sandboxes and deletes them on drop |
| `output` | ANSI stripping and field extraction from CLI output |
| `port` | `wait_for_port()` and `find_free_port()` for TCP testing |

## Environment Variables

| Variable | Purpose |
|---|---|
| `OPENSHELL_GATEWAY` | Override active gateway name for E2E tests |
| `OPENSHELL_GATEWAY_ENDPOINT` | Run E2E tests against an existing plaintext HTTP gateway endpoint |
| `OPENSHELL_E2E_DRIVER` | Driver name exported by the e2e gateway wrapper (`docker`, `podman`, or `vm`) |
| `OPENSHELL_E2E_CREDENTIAL_DRIVERS` | Enables the Kubernetes credential-driver fixture path in `e2e/with-kube-gateway.sh` |
| `OPENSHELL_E2E_KUBE_CONTEXT` | kubectl context for Kubernetes e2e (skips ephemeral k3d) |
| `OPENSHELL_E2E_KUBE_TEST` | Scope Kubernetes e2e to a single test by name |
