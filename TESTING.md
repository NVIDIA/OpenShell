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
tests/testkit/         # Support library for SDK-driven E2E suites
tests/suites/          # E2E suites, grouped by test family
tests/tmachine/        # QEMU test machines, Ansible playbooks, and the Session API
tests/runner/          # openshell-test-runner: runs a test family in a tmachine environment
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

Rust validation checks tracked Cargo lockfiles; run `mise run rust:lockfiles:check` to check them directly. If one is stale, refresh it with Cargo using its adjacent manifest, review the diff, and commit the update.

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

Start with the [Windows build prerequisites](WINDOWS.md#build) in a checkout
based on `windows`. Run the lane matching the native host:

```powershell
# Native x64 host
mise run --skip-tools windows:lint:x64
mise run --skip-tools windows:build:x64
mise run --skip-tools windows:test:x64
mise run --skip-tools windows:test:unsupported:x64

# Native ARM64 host
mise run --skip-tools windows:lint:arm64
mise run --skip-tools windows:build:arm64
mise run --skip-tools windows:test:arm64
mise run --skip-tools windows:test:unsupported:arm64
```

The test tasks use the CI nextest profile and server test support. They reject
a target that does not match the host architecture. `windows:ci` is the x64-host
aggregate, including ARM64 cross-check/build unless explicitly skipped; it
does not establish native ARM64 test coverage.

For runtime validation, provision a capable MXC host and build its native
release binaries first. On x64, run:

```powershell
mise run --skip-tools windows:test:mxc-real:x64
mise run --skip-tools windows:e2e:mxc
```

Use `windows:test:mxc-real:arm64` on ARM64. The real-runtime unit tests can
report `SKIP` when the executor or backend is absent; E2E returns nonzero
when required runtime coverage is missing. Report passed, failed, and
skipped/ignored executions separately, including why any probe gated coverage.
Passing E2E does not qualify the [known Windows enforcement gaps](WINDOWS.md#runtime-and-current-limits).
See the [Windows test task definitions](https://github.com/NVIDIA/OpenShell/blob/windows/tasks/windows.toml)
for boundary, loopback, network, and audit suites.

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

### testkit (`tests/testkit/`)

`testkit` is the support library for SDK-driven end-to-end suites. Tests are
`#[testkit::test]` functions with a required doc comment. They find the
gateway the same way the CLI does, through `OPENSHELL_GATEWAY_ENDPOINT`,
`OPENSHELL_GATEWAY`, or the active gateway, and `cx.cli` runs the CLI named
by `OPENSHELL_BIN`. See
[tests/testkit/README.md](tests/testkit/README.md) for how to write and run
tests.

The conformance crate also builds `openshell-conformance`, a program that
runs the conformance suite against a gateway without cargo or nextest
(`openshell-conformance list`, `ready`, `run`). It covers only the
conformance suite. See
[tests/suites/conformance/README.md](tests/suites/conformance/README.md).

Suites live under `tests/suites/`, in Cargo workspaces with their own
lockfiles: `conformance`, `features`, and one workspace per driver suite under
`drivers/<driver>`. Run the `conformance` suites against a local Docker
gateway with:

```shell
mise run e2e:testkit
```

Workspaces that build root crates through path dependencies must lock shared
crates at the versions in the root `Cargo.lock`; otherwise CI can build against
dependencies the Nix toolchain doesn't support. `mise run rust:lockfiles:check`
verifies this, and `uv run tasks/scripts/check_cargo_lockfile_alignment.py --fix`
re-locks a workspace from the root lockfile. Add new testkit workspaces to
`ALIGNED_WORKSPACES` in that script.

#### What a conformance test may assert

Conformance tests run on every compute driver, so they check the public
contract and nothing a driver is free to change.

- Assert only what the public contract promises: the comments in `proto/` and
  the published docs.
- Assert on `phase` and `exit_code`. Don't assert on condition reasons or
  messages.
- To check that something did not happen, read the state that shows it. Don't
  sleep and hope.
- If a behavior isn't documented, open an issue to document it. Don't write a
  test for it. A behavior that only some drivers have belongs in
  `tests/suites/features` or `tests/suites/drivers`.
- The only way to skip a test is `#[ignore = "<issue link>"]`, for a broken or
  flaky test.

Adapted from the handover notes in NVIDIA/OpenShell#4629 by Evan Lezar.

### Running suites in a tmachine environment (`tests/runner/`)

`openshell-test-runner run` runs a test family inside a tmachine VM, against the
OpenShell that the VM's installer set up. `--family` is the path of the
workspace under `tests/suites/`, such as `conformance` or `drivers/podman`, and
`--package` narrows it to some of its packages. It must name a workspace, so
`drivers` alone fails. The `family` input of the `E2E Suites` workflow instead
selects every row whose family is that name or lies under it, so `drivers`
selects all the driver suites.

```shell
nix run .#openshell-test-runner -- run \
  --environment ubuntu-docker-rootful --installer deb \
  --family conformance --package conformance
```

It needs KVM on Linux or the Hypervisor framework on macOS, and tmachine only
boots guests of the host's architecture. The runner points the tests at the
installed CLI and the gateway the installer registered (`--gateway`, default
`openshell`). A run passes if nextest succeeds; nextest fails a run with no
tests. The runner exits with 1 when a test failed and 2 when the run could not
complete, for example because the environment didn't come up. It writes
`junit.xml`, `nextest.log` and, after a failure, the guest's diagnostics to
`artifacts/test-results/` (`--results`), even when the run timed out.

`--filter <filterset>` narrows the tests with a nextest filterset, and
`--keep` leaves the VM running until you press Enter. `--program <path>` runs a
prebuilt testkit program, such as a static `openshell-conformance` for the
guest's architecture, instead of building the family's tests; it can't be
combined with `--package`. With it, `--filter` (repeatable) takes parts of test
names, as the program does, such as `--filter policy_advisor::`, rather than a
nextest filterset. The runner runs the program's `ready`
and `run` commands in the guest and still writes `junit.xml` and `nextest.log`
(the program's output) to the results directory. Branch E2E builds
`openshell-conformance` once and passes it to every conformance row this way.

`openshell-test-runner build --family <family> --out <dir>` builds a family's
test bundle for the guest without booting a VM, and `run --bundle <dir>` runs
it instead of building one. `--package` then selects the tests to run from the
bundle, which must hold those packages. Branch E2E builds the `features` and
`drivers/podman` bundles once and passes them to their rows this way. Two runs on one host
need different `TMACHINE_SSH_PORT` values (default 2222). The installer
inputs, such as the Debian package and the images, come from `artifacts/`,
built by `nix run .#build-artifacts` or downloaded by CI.

A flaky or broken test is marked `#[ignore = "<issue link>"]`, which takes it
out of every environment until it's fixed.

**CI.** `.github/workflows/e2e-suites.yml` lists the environments and suites as
an explicit matrix and runs the runner once per row. Branch E2E calls it once
per family when the `test:e2e` label is set, and a failure fails the Core E2E
result. Release Dev and Release Qualification run the conformance and feature
families. To run a suite in another environment on CI, add a row.

### Adding a feature suite

Feature suites live in the `tests/suites/features` workspace, one crate per
suite, with a name that says what the suite tests.
`tests/suites/features/keycloak-provider-refresh` is the example to copy.

1. Add a crate under `tests/suites/features/<name>` that depends on
   `openshell-testkit`, and add it to `members` in
   `tests/suites/features/Cargo.toml`.
2. Write the tests in `tests/*.rs` as `#[testkit::test]` functions.
3. Re-lock the workspace: `cargo metadata --manifest-path
   tests/suites/features/Cargo.toml`, then
   `uv run tasks/scripts/check_cargo_lockfile_alignment.py --fix`. `cargo fmt`
   and `cargo clippy` already cover every package in the workspace.
4. Add a row for the suite to the matrix in `.github/workflows/e2e-suites.yml`.

If the feature only needs the gateway, run the suite in an existing
environment such as `ubuntu-docker-rootful`, and skip the rest of this
section.

**Suites that need a service.** A feature that needs something besides the
gateway, such as an OIDC issuer, runs in a tmachine environment that provides
it. The environment and the suite share a contract: a set of
`OPENSHELL_TEST_<SERVICE>_*` environment variables that say how to reach the
service.

- **Environment.** Add an environment to `tests/tmachine/config.nix` whose
  setup playbook starts the service (with a restart policy, since setup is
  cached as a disk) and writes the variables as `KEY=VALUE` lines to
  `/etc/openshell-test/env.d/<service>.env`. Pass files the playbook needs
  through the environment's setup `inputs`, and add them to the tmachine disk
  cache key in `e2e-suites.yml`. The runner rejects names without the
  `OPENSHELL_TEST_` prefix, and the tests get the variables in the guest, so
  values never appear in a runner command. Values are taken literally, without
  quoting.
- **Fixture.** Put the service's fixture in a support crate under
  `tests/support/<service>`, named `<service>-support`, so any suite can
  depend on it, or reuse the existing one. It defines the variable names as constants and a
  `<Service>Context::new(cx)` that reads them, waits for the service, and
  wraps the testkit `Context`. Each test calls it on its first line.
  Nextest runs each test in its own process, so the fixture builds its
  clients there from the variables. A missing variable fails the test; it
  never skips it.
- **Documentation.** Document the variables in the fixture's module docs, so
  anyone can run the suite against their own deployment by setting them.

The Keycloak fixture is `tests/support/keycloak`. Run the suite that uses it
with:

```shell
nix run .#openshell-test-runner -- run \
  --environment ubuntu-docker-rootful-keycloak --installer deb \
  --family features --package keycloak-provider-refresh
```

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
- Conformance (`tests/suites/conformance`) - the testkit `conformance` crate:
  lifecycle, the CLI, persistent workspaces, file transfer, the policy
  advisor, and credential gating. Driver E2E runs it with
  `openshell-conformance` against the lane's gateway and writes a JUnit report
  under `results/`; set `OPENSHELL_CONFORMANCE_BIN` to use a prebuilt program,
  as Branch E2E does with the static build it makes once per architecture.
  The Docker and Podman runners build `openshell/e2e-python:dev` for it; the
  Kubernetes and VM runners set `OPENSHELL_TEST_PYTHON_IMAGE` to a pullable
  Python image unless it is already set. The
  installed-artifact conformance lanes run the same crate through
  `openshell-test-runner` (see above).
- Driver suites (`--features e2e-docker`, `e2e-podman`, `e2e-kubernetes`, or
  `e2e-vm`) - conformance plus the common and driver-specific coverage for
  the selected deployment.
- Docker suite (`--features e2e-docker`) - includes Docker-only coverage such as Dockerfile image builds, Docker preflight checks, and managed Docker gateway start.
- Docker GPU suite (`--features e2e-docker-gpu`) - Docker suite plus GPU sandbox smoke coverage.
- Configuration push suite (`--features e2e-config-push`) - conformance and the policy tests against a Docker gateway with `config_delivery_mode = "push"`. Run it with `mise run e2e:rust:push`.
- VM suite (`--features e2e-vm`) - runs e2e tests on a VM.
- Kubernetes credential-driver suite (`--features e2e-kubernetes-credential-drivers`) - targeted Kubernetes Secrets and Vault provider credential storage coverage.

The Docker, Podman, Kubernetes, and VM runners execute conformance before
their Rust tests; a run with no conformance tests fails. Set the driver's
feature variable (`OPENSHELL_E2E_DOCKER_FEATURES`, `OPENSHELL_E2E_PODMAN_FEATURES`,
`OPENSHELL_E2E_KUBERNETES_FEATURES`, or `OPENSHELL_E2E_VM_FEATURES`) to
`e2e-conformance-only` to skip the Rust tests; the runner logs a notice when
it skips them. Unset or empty values select the driver's default Rust
features. The selector is handled by the runner; it is not a Cargo feature.

```shell
OPENSHELL_E2E_KUBERNETES_FEATURES=e2e-conformance-only mise run e2e:kubernetes
```

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

Run the conformance suite against the gateway selected in your OpenShell CLI
configuration:

```shell
cargo build --package openshell-cli
OPENSHELL_BIN="$PWD/target/debug/openshell" \
  cargo nextest run \
    --locked \
    --manifest-path tests/suites/conformance/Cargo.toml \
    --test-threads 1 \
    --no-fail-fast
```

The gateway must already be installed, reachable, and selected before the tests
start. The test suite does not provision a gateway or select a compute driver.
Set `OPENSHELL_BIN` to another executable to test a different prebuilt CLI.
[tests/testkit/README.md](tests/testkit/README.md) covers gateway selection and
cleanup.

Gateway-backed Rust E2E tasks run the conformance suite against the configured
gateway, then run any lane-specific Rust tests that still apply.
Run the Podman-backed Rust CLI e2e suite:

```shell
mise run e2e:podman
```

The `nix run` commands below need the local Nix setup in
[CONTRIBUTING.md](CONTRIBUTING.md#nix-setup).

`nix run .#build-artifacts` also builds
`artifacts/packages/openshell.deb` for tmachine's `deb` installer, targeting the
host's Linux architecture (`arm64` or `amd64`). Set `OPENSHELL_DEB_VERSION` to
override the default package version, `0.0.0-local`.

It also builds `artifacts/packages/rpm/openshell.rpm` and
`artifacts/packages/rpm/openshell-gateway.rpm` for tmachine's `rpm` installer.
The RPM step runs `packit build locally` with `openshell.spec` in the Fedora
container that CI uses, so it needs a Docker daemon that runs Linux containers
for the host's architecture (`aarch64` or `x86_64`), such as Docker Desktop on
macOS. The package version defaults to the development version that branch CI
computes; set `OPENSHELL_RPM_VERSION` and `OPENSHELL_RPM_RELEASE` to override
it. After `nix run .#build-artifacts-binaries`, `nix run .#build-artifacts-rpm`
rebuilds only the RPMs. Run conformance against the installed RPMs:

```shell
nix run .#build-artifacts
nix run .#openshell-test-runner -- run \
  --environment fedora-podman-rootful --installer rpm \
  --family conformance --package conformance
```

Run the portable subset in a disposable rootless Podman guest:

```shell
nix run .#build-artifacts
nix run .#tmachine -- test fedora-podman-rootless rpm e2e-podman
```

Print the exact tmachine archive selection as a shell `PODMAN_CI_TESTS` array:

```shell
nix run .#generate-podman-e2e-ci-tests
```

The `e2e-podman` testsuite runs a nextest archive built with the corresponding
Rust feature and preloads its Python workload image into the rootless Podman
store. The E2E archive excludes binaries that still depend on wrapper-owned
gateway controls, SPIFFE fixtures, the caller driver-config setting, or other
guest setup. `tests/tmachine/artifacts.nix` keeps the follow-up exclusions explicit and uses
the same filter for the generated inventory, so excluded binaries cannot appear
as false passes or silently re-enter the archive.

Driver suites live in `tests/suites/drivers/<driver>`, with the package named
after the driver. Each driver suite is its own workspace with its own lockfile,
so a change to one driver's tests or dependencies doesn't touch another's. Add
a new one to the `rust:format`, `rust:format:check` and `rust:lint` tasks, the
matching lines in `branch-checks.yml`, and `ALIGNED_WORKSPACES`. The Podman
driver suite (`tests/suites/drivers/podman`) compares OpenShell and direct
Podman user-namespace mappings.
Each `fedora-podman-{rootful,rootless}-userns-<mode>` environment configures
the gateway with one mode (`default`, `auto`, `keep-id` or `private`) and works
with every installer; CI runs it with `rpm`:

```shell
nix run .#openshell-test-runner -- run \
  --environment fedora-podman-rootless-userns-keep-id --installer rpm \
  --family drivers/podman
```

#### Gateway overrides in an environment

An environment overrides gateway settings by writing the tables to change to
`/etc/openshell-test/gateway-overrides.toml` in a playbook that runs before the
installer. The file holds whole tables, such as `[openshell.gateway]` or
`[openshell.drivers.podman]`, and is not a complete configuration. Each
installer applies it to the gateway's own file:

- `binaries` applies it to the `/etc/openshell/gateway.toml` it generates.
- `deb` and `rpm` apply it to the service user's
  `~/.config/openshell/gateway.toml`, the file the packaged service reads. The
  file starts as a copy of the rpm's
  `/usr/share/openshell-gateway/gateway.toml.default`, where the service would
  seed it on first start, or as a minimal `version = 2` file when the package
  has no default. No environment replaces the packaged file, and an environment
  with no overrides leaves it untouched.
- `k3s` installers ignore the file.

`tests/tmachine/ansible/roles/openshell_gateway/files/merge-gateway-toml.py`
does the work. Each key in the overrides replaces the same key in the table, or
is added to it, and a table the file lacks is appended. The rest of the file,
comments included, stays. The script parses the result and fails the setup,
leaving the file unchanged, when it isn't valid TOML. It can't remove a key.
Settings that the packaged service reads from `gateway.env` instead of the
TOML are not covered.

The `oci-image` feature suite (`tests/suites/features/oci-image`) checks OCI
image identity and working-directory behavior shared by the Docker and Podman
drivers against installed deb packages on Ubuntu and rpm packages on Fedora.
CI runs it on Docker rootful, Podman rootful, and Podman rootless guests:

```shell
nix run .#openshell-test-runner -- run \
  --environment ubuntu-docker-rootful --installer deb \
  --family features --package oci-image
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

The `host-gateway` feature suite (`tests/suites/features/host-gateway`) checks
that a sandbox from the Python test image reaches a server the test runs on the
host through `host.openshell.internal`. CI runs it on Docker rootful, Podman
rootful and rootless, and the `k3s` and `k3s-ha` installers. The tests run on
the K3s node, so the K3s installers set the chart's `server.hostGatewayIP` to
the node's address.

The `cli-attach` feature suite (`tests/suites/features/cli-attach`) checks how
`sandbox connect` supervises its `ssh` process: it reconnects after losing the
SSH transport and forwards a SIGTERM to `ssh`. The tests find those processes
in `/proc`, so they need a Linux test host. CI runs them on Docker rootful.

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

The `e2e-kubernetes` nextest profile temporarily excludes only
`canonical_main_connect_recovers_its_ssh_transport` while
[#4445](https://github.com/NVIDIA/OpenShell/issues/4445) investigates delayed SSH
input-owner release through port-forwarding. The test remains available to other
driver profiles; the remaining Kubernetes tests stay enabled.

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
group, the harness automatically applies SCC-compatible Helm overrides and
drives the gateway through a passthrough Route with mandatory mTLS instead of
port-forward. No extra flags are needed, but `oc` must be installed and
authenticated against the target cluster; the harness exits early if `oc` is
missing. DB scenarios grant `anyuid` to the PostgreSQL fixture and require
permission to modify SCC bindings (`oc adm policy add-scc-to-user`). That grant
and extracted client mTLS material are removed during cleanup, including on
failure or interrupt.

Sandbox pods use the namespace-assigned UID/GID and run under `restricted-v2`
without a privileged SCC grant to `openshell-sandbox`. Earlier versions required
that grant for in-container isolation setup. [RFC 0012](https://github.com/NVIDIA/OpenShell/blob/main/rfc/0012-isolation-backend/README.md#motivation)
explains the isolation backend separation behind the capability-free runtime.

On a **remote** cluster, drop the `e2e-host-gateway` feature. Those tests rely
on the sandbox-side `host.openshell.internal` alias reaching the machine running
the tests, which is unreachable from pods on a remote cluster, so they fail.
The conformance suite's `credential_gating` tests need the alias to reach that
machine too, and the feature selection doesn't skip them, so they fail on a
remote cluster. [#5409](https://github.com/NVIDIA/OpenShell/issues/5409)
tracks handling that.
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
| `e2e:kubernetes:shared-supervisor` | One-member shared supervisor pool for the gateway's sandboxes (gateway TLS through the port-forward) |
| `e2e:kubernetes:shared-supervisor-ha` | Two-replica shared supervisor pool behind two gateway replicas on PostgreSQL: kills the member that owns a sandbox and checks the sandbox is adopted, not restarted; crashes and restarts gateways and checks each sandbox's session stays on its supervisor's gateway |
| `e2e:kubernetes:shared-supervisor-scaling` | One-member shared supervisor pool: scales it to two members and back with `helm upgrade`, checking sandboxes stay running and the removed member hands its sandboxes off |

Kubernetes e2e environment variables:

| Variable | Purpose |
|---|---|
| `OPENSHELL_E2E_KUBE_CONTEXT` | kubectl context for an existing cluster (skips k3d creation) |
| `OPENSHELL_E2E_KUBE_TEST` | Scope to a single test (e.g. `smoke`) |
| `OPENSHELL_E2E_KUBE_EXTRA_VALUES` | Colon-separated additional Helm values files |
| `OPENSHELL_E2E_KUBE_CHART`, `OPENSHELL_E2E_KUBECONFIG` | Set by the harness for tests that upgrade the release, such as the supervisor pool scaling test: the chart it installed, and the kubeconfig passed as `--kubeconfig` to kubectl and helm. Set them yourself when running such a test directly against an existing release |
| `OPENSHELL_E2E_KUBE_TLS` | `1` reaches the gateway over mTLS through the port-forward; pair it with an overlay that keeps gateway TLS on, such as `ci/values-tls-port-forward.yaml` |
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
cargo test --manifest-path e2e/rust/Cargo.toml --features e2e-docker --test docker_corporate_proxy
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
