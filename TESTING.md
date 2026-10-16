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
tests/suites/          # End-to-end suites, run by test plans
tests/testkit/         # Shared support for the suites
tests/runner/          # Test plan runner, with tests/{plans,environments}
tests/tmachine/        # VM environments, provisioned with tests/ansible
```

New end-to-end tests go under `tests/`. The suites in `e2e/` are being
migrated there; `e2e/` only takes fixes until it is empty.

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

Rust validation checks tracked Cargo lockfiles; run `mise run rust:lockfiles:check` to check them directly. If one is stale, refresh it with Cargo using its adjacent manifest, review the diff, and commit the update.

Workspaces that build root crates through path dependencies keep their own
lockfiles, which `--locked` does not compare with the root's. The check also
requires the workspaces listed in
`tasks/scripts/check_cargo_lockfile_alignment.py` to lock shared crates at the
root's versions. If it fails, re-lock them from the root lockfile and commit the
result:

```shell
uv run tasks/scripts/check_cargo_lockfile_alignment.py --fix
```

### PostgreSQL-backed tests

Tests that need a real PostgreSQL server, such as advisory-lock concurrency
across two stores, are `#[ignore]`d and named `postgres_*`. Run them with:

```shell
mise run test:rust:postgres
```

The task starts a disposable PostgreSQL container with Docker or Podman
(set `CONTAINER_ENGINE` to choose), runs the tests one at a time, and removes
the container. Each test works in its own temporary schema, except the replay
and provider refresh lock tests, which use the default schema. To use your own
disposable database, set `OPENSHELL_TEST_POSTGRES_URL`. The task overrides
`OPENSHELL_REPLAY_TEST_DATABASE_URL` so legacy tests use that same database.
Never point it at a database that a running gateway uses: the tests take
fleet-wide advisory locks.
Branch Checks runs them on x86_64 Linux.
Load-sensitive capacity checks are named `bench_postgres_*` instead, so that
task skips them. Run them on an idle machine with
`mise run test:rust:postgres:bench`.

### Native Windows validation

Use `mise run --skip-tools pre-commit` with the existing Rust/MSVC toolchain.
Windows now checks tracked Cargo lockfiles through PowerShell rather than
skipping them.

`mise run --skip-tools sdk:ts:ci` selects the x64 Biome executable on Windows
(including ARM64 hosts running it under emulation), resolves the protobuf
plugin through its Windows `.cmd` launcher, and installs the matching locked
ARM64 Rolldown binding when Node itself is ARM64. The helper preserves lockfile
resolution; it must not upgrade unrelated test dependencies.

`mise run --skip-tools go:ci` retains race detection except on Windows ARM64,
where Go does not support it. Windows token-file tests explicitly skip POSIX
mode-bit assertions; those skips do not establish Windows ACL protection.
Use a checkout with LF text files when running Unix-shell fixture checks.

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

`mise run test:gateway-config` validates generated gateway TOML without a live
runtime. It covers the current schema and the Podman in-tree versus external
driver configuration boundary.

### Python E2E (`e2e/python/`)

`mise run e2e:python` builds `openshell/e2e-python:dev` from
`e2e/python/Dockerfile.workload` and selects it only for the test gateway.
This Noble-based fixture supplies the `sandbox` user, Python tooling, Git,
and a writable `/sandbox/.venv`. Its Python version comes from `.python-version`
so cloudpickle code objects match the test runner. The production workload
default remains the unmodified NVIDIA Ubuntu image.

The Rust Docker harness also selects this fixture for tests that need tools
or the named user. Explicit `--from` or `--template` arguments and the default-image
tests retain their own image selection. Docker sandbox and support-container
fixtures use the fixed image name; no workload-image override is needed.
Podman, VM, and Kubernetes retain their existing pinned, pullable fixture and
image setup. Conformance-only runs do not need the Docker fixture.
Build the Docker fixture separately with `mise run e2e:workload:build`.

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

### Rust CLI E2E (`e2e/rust/`)

Rust-based e2e tests that exercise the `openshell` CLI binary as a subprocess.
They live in the `openshell-e2e` crate and use a shared harness for sandbox
lifecycle management, output parsing, and cleanup.

Exposed service URLs use virtual hostnames for gateway routing. Host-side tests
must connect the TCP socket directly to a reachable gateway listener address,
normally loopback, and send the service URL authority in the HTTP `Host`
header. Do not resolve `*.openshell.localhost`; resolver support for arbitrary
`.localhost` subdomains varies across local and CI environments.

Treat the advertised service URL scheme as authoritative. For HTTPS, use the
virtual service hostname for TLS SNI and the configured gateway trust roots.
When the listener requires mTLS, present the active gateway client identity;
the local e2e wrappers register these materials under
`$XDG_CONFIG_HOME/openshell/gateways/$OPENSHELL_GATEWAY/mtls/`. Do not downgrade
an HTTPS service URL to plaintext when dialing loopback. Parse the URL and load
TLS material before entering a readiness loop so permanent configuration
errors fail immediately. Retry only transient connection failures and
documented readiness responses, and include the last observation in timeout
diagnostics.

Verify exposed-service tests in both the default local mode and the
CI-equivalent HTTPS mode:

```shell
mise run e2e:rust
OPENSHELL_ENABLE_LOOPBACK_SERVICE_HTTP=false mise run e2e:rust
```

When more than one test needs this behavior, put the transport in the shared
Rust e2e harness and require callers to use it instead of duplicating DNS,
HTTP `Host`, TLS SNI, and mTLS handling.

Suites:

- Common suite (`--features e2e`) - driver-neutral CLI behavior, sandbox lifecycle, sync, port forwarding, policy, and provider tests.
- CLI conformance (`tests/suites/conformance`) - portable Cargo tests for
  lifecycle, mechanistic drafts, file transfer, and the sandbox-local API,
  including agent-authored permission requests. Driver E2E runs the complete
  Cargo test package. The installed-artifact conformance suite runs the same
  tests from a nextest archive and offers a focused `policy-advisor` testsuite
  for manual integration runs.
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

Run the portable CLI conformance suite against the gateway selected in your
OpenShell CLI configuration:

```shell
cargo build --package openshell-cli
OPENSHELL_BIN="$PWD/target/debug/openshell" \
  cargo test \
    --locked \
    --manifest-path tests/suites/conformance/Cargo.toml \
    --package openshell-test-conformance-cli \
    --no-fail-fast \
    -- \
    --test-threads=1 \
    --nocapture
```

The gateway must already be installed, reachable, and selected before the tests
start. The test suite does not provision a gateway or select a compute driver.
Set `OPENSHELL_BIN` to another executable to test a different prebuilt CLI.

The phase-1 scenario verifies the complete CLI-to-gateway-to-driver path without
depending on how the gateway was installed or which driver is configured. It
requires machine-readable gRPC status, creates a uniquely named detached
sandbox with the configured default image, verifies the sandbox is `Ready` by finding its
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

Gateway-backed Rust E2E tasks run the CLI conformance Cargo tests against the
configured gateway, then run any lane-specific Rust tests that still apply.
Run the Podman-backed Rust CLI e2e suite:

```shell
mise run e2e:podman
```

`nix run .#build-artifacts` also builds
`artifacts/packages/openshell.deb` for tmachine's `deb` installer, targeting the
host's Linux architecture (`arm64` or `amd64`). Set `OPENSHELL_DEB_VERSION` to
override the default package version, `0.0.0-local`.

Run the portable subset in a disposable rootless Podman guest:

```shell
nix run .#build-artifacts
nix run .#tmachine -- test fedora-podman-rootless binaries e2e-podman
nix run .#tmachine -- test fedora-podman-rootless binaries driver-podman
```

Print the exact tmachine archive selection as a shell `PODMAN_CI_TESTS` array:

```shell
nix run .#generate-podman-e2e-ci-tests
```

The `e2e-podman` testsuite runs a nextest archive built with the corresponding
Rust feature and preloads its Python workload image into the rootless Podman
store. The separate `driver-podman` testsuite compares OpenShell and direct
Podman user-namespace mappings for the default, `auto`, `keep-id`, and private
profiles. The E2E archive excludes binaries that still depend on wrapper-owned
gateway controls, SPIFFE fixtures, the caller driver-config setting, or other
guest setup. The `driver-podman` suite replaces the removed `podman_userns` E2E
binary. `tests/artifacts.nix` keeps the follow-up exclusions explicit and uses
the same filter for the generated inventory, so excluded binaries cannot appear
as false passes or silently re-enter the archive.

The `oci-image` feature testsuite (`tests/suites/features/oci-image`) checks
OCI image identity and working-directory behavior shared by the Docker and
Podman drivers against installed deb packages on Ubuntu and rpm packages on
Fedora. CI runs it on Docker rootful, Podman rootful, and Podman rootless guests:

```shell
nix run .#tmachine -- test ubuntu-docker-rootful deb oci-image
```

The shared suite also runs in the existing ARM64 Docker E2E workflow for
branch checks and both release workflows. That interim lane compiles the same
test crate natively and uses the architecture-matched prebuilt candidate CLI
and gateway plus the candidate multi-architecture sandbox and supervisor
images through `e2e/with-docker-gateway.sh`. The tmachine lanes still use
x86_64 artifacts; they do not replace ARM64 image coverage.

Run it against a local Docker or Podman gateway:

```shell
mise run e2e:oci-image
mise run e2e:oci-image:podman
```

Both tasks set `OPENSHELL_TEST_CONTAINER_ENGINE`, the command that builds test
images into the gateway's image store.

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

### Test plans (`tests/plans/`)

A test plan selects suites and the environments to run them in. The runner
(`tests/runner`) builds each family's suites for the guest, boots each
environment in a tmachine VM, runs the suites inside it, and copies the
results back:

```shell
nix run .#build-artifacts
nix run .#test-runner -- test --plan tests/plans/cpu-tests.yaml
```

```yaml
matrix:
  - type: conformance              # family: a workspace under tests/suites/
    suites: [sandbox-lifecycle]    # omit to run every suite in the family
    environments: [tmachine.ubuntu2404-arm64.docker-rootful.deb]
```

Add `--dry-run` to print the resolved jobs and nextest filtersets without
building or booting anything, `--env` or `--suite` to narrow a plan, and
`--keep` to leave each VM running after its tests. Results, including JUnit
reports and gateway logs for failures, go to
`artifacts/test-results/<plan>/<environment>/<family>/`.

Before running an environment's suites, the runner waits up to five minutes for
its gateway to report healthy and for the environment's CLI to reach it
(`testkit-ready`, shipped in each bundle). Failing either is reported as an
environment error, not as test failures.

Environments are defined in `tests/environments/*.yaml`. tmachine boots guests
of the host's architecture only, so the runner reports environments for other
architectures as unsupported instead of failing.

Nobody lists which tests run where. A test is expected in every environment
whose capabilities include everything the test `requires`; plans only choose
which of those to run. To see where each test runs, or why it doesn't, run:

```shell
nix run .#test-runner -- matrix          # add --host to apply this machine's limits
```

`matrix` and `test` fail if a test runs in no defined environment, or if tests
require a capability that no environment declares. When you add a capability,
declare it in every environment that provides it in the same change. If you
are unsure whether an environment provides it, declare it: a wrong claim shows
up as a test failure, while a wrong omission silently drops coverage.

To skip a test where it fails because of a known bug, add a waiver to
`tests/waivers.yaml` with the test's ID, an environment selector, the issue
tracking the bug, and a reason:

```yaml
waivers:
  - test: t-3tfdx240
    environments: { runtime: podman-rootless }   # fields of the environment; omit for all
    issue: https://github.com/NVIDIA/OpenShell/issues/NNNN
    reason: what fails, and where
```

Waived tests are skipped in every plan and listed in the run summary. Run with
`--ignore-waivers` to check whether a fix landed, and remove the waiver when
it has. Use waivers only for bugs: a feature an environment lacks is a missing
capability, and running less on a given occasion is a choice of plan.

Conformance suites (`tests/suites/conformance/`) are black-box tests of the
public client interfaces: the gateway API through the Rust SDK, and the
`openshell` CLI the environment installed. The suites are `sandbox-lifecycle`,
`file-transfer`, and `policy-advisor`. Each suite is one test binary of
`#[testkit::test]` functions. `testkit` (`tests/testkit/`) is the support
library shared by every family: it reads the target, connects to the gateway,
creates and cleans up sandboxes, and provides the attribute. The runner parses
tests with the same `testkit-spec` crate as the attribute.

```rust
/// A long-running sandbox becomes ready, runs a command with exec, and is gone
/// from get and list after delete.
#[testkit::test(id = "t-3tfdx240")]
async fn long_running_exec_delete(cx: &mut Context) -> testkit::Result {
    // ...
}
```

Every test needs a stable `id`: `t-` followed by eight random lowercase letters
or digits. Results, waivers, and coverage records refer to tests by this ID, so
never change or reuse it, including when you rename the test or move it to
another suite or family. Omit `id` when you write a new test; the compile error
suggests a fresh one. IDs must be unique across all families, which the runner
checks, and the runner adds each test's ID to its JUnit test case as the
`test_id` property.

A conformance test asserts only what the public contract promises: the
comments in `proto/` and the published docs, such as the sandbox lifecycle in
`docs/how-it-works/sandboxes/overview.mdx`. Do not encode current gateway
behavior the contract doesn't state; file an issue to document it instead.
Assert on a sandbox's `phase` and `exit_code` rather than condition reasons,
which the API leaves to the platform. Check that something did not happen
(for example, `restart_count` is 0 and a second read shows the same phase)
instead of sleeping and watching. Behavior the docs leave to the compute
driver needs a capability in `requires`.

Act through the interface that makes the promise. Upload, download, connect,
and port forwarding exist only in the CLI, so those tests call `cx.cli([...])`
and assert through the SDK where they can; rely on the CLI's exit code and
`--output json`, not its table text. For API calls the SDK does not wrap yet,
such as settings and draft policy, add a testkit helper over the generated gRPC
client rather than calling it from tests.

Every environment provides its CLI: the installer's `openshell_client` role
writes a `cli:` section (binary and gateway name) next to `gateway:` in the
target, and `testkit-ready` checks that `openshell status` reports the gateway
connected. The CLI is part of the target, not a capability, so CLI-driven tests
run everywhere.

The function name is the nextest test name and is what nextest filters
select. Rename it when a clearer name helps; the ID keeps the history.
The doc comment is the required description. Declare capabilities a test needs with
`#[testkit::test(requires = [service_exposure])]`; the runner excludes the test
in environments without them and reports it as unsupported. Tests read the
system under test from the target file named by `OPENSHELL_TEST_TARGET`, so you
can also run a suite directly against a gateway you already have:

```shell
OPENSHELL_TEST_TARGET=target.yaml cargo nextest run \
  --manifest-path tests/suites/conformance/Cargo.toml \
  -p openshell-conformance-sandbox-lifecycle
```

`cargo run --manifest-path tests/runner/Cargo.toml --bin openshell-test -- catalog`
prints every suite and test with its description and requirements.

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

`IMAGE_TAG` sets the default tag for the gateway/supervisor image pair; the CLI
under test is always built from your branch. To validate against images from
your exact commit instead, build and push them and point
`OPENSHELL_REGISTRY`/`IMAGE_TAG` at them.

Test wrappers accept independent image overrides:

```shell
GATEWAY_IMAGE=registry.example.com/custom/gateway:test \
SUPERVISOR_IMAGE=registry.example.com/custom/supervisor:test \
SANDBOX_IMAGE=registry.example.com/custom/sandbox:test \
mise run e2e:kubernetes
```

`GATEWAY_IMAGE` applies to the Kubernetes gateway container. `SUPERVISOR_IMAGE`
applies to the trusted supervisor image selected by the Kubernetes, Docker, and
Podman wrappers. `SANDBOX_IMAGE` applies to the trusted workload-side runtime
image that stages the `openshell-sandbox` binary. A repository-only value
inherits `IMAGE_TAG`; a value with an explicit tag or `@sha256:` digest is used
as-is. When these variables are unset, the existing `OPENSHELL_REGISTRY` plus
`IMAGE_TAG` behavior is retained.
The Docker and Podman wrappers continue to give
`OPENSHELL_DOCKER_SUPERVISOR_IMAGE` and `OPENSHELL_SUPERVISOR_IMAGE` precedence
over `SUPERVISOR_IMAGE`.

Digest-pinned Kubernetes overrides require disabling local image builds, because
Docker cannot tag a locally built image with a digest reference:

```shell
OPENSHELL_E2E_KUBE_BUILD_IMAGES=0 \
GATEWAY_IMAGE=registry.example.com/custom/gateway@sha256:<digest> \
SUPERVISOR_IMAGE=registry.example.com/custom/supervisor@sha256:<digest> \
mise run e2e:kubernetes
```

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
| `GATEWAY_IMAGE` | Kubernetes gateway image repository or complete tagged/digest-pinned image reference; digests require `OPENSHELL_E2E_KUBE_BUILD_IMAGES=0` |
| `SUPERVISOR_IMAGE` | Gateway/supervisor image repository or complete tagged/digest-pinned image reference; Kubernetes digests require `OPENSHELL_E2E_KUBE_BUILD_IMAGES=0` |
| `SANDBOX_IMAGE` | Trusted sandbox runtime image repository or complete tagged/digest-pinned image reference |

Run a single test directly with cargo:

```shell
cargo test --manifest-path e2e/rust/Cargo.toml --features e2e --test sync
```

Run a single Docker-only test directly with cargo:

```shell
cargo test --manifest-path e2e/rust/Cargo.toml --features e2e-docker --test docker_preflight
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
