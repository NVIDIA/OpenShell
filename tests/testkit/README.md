# testkit

Shared support for end-to-end test suites. Suites test a running OpenShell
gateway through the Rust SDK and the installed `openshell` CLI.

This is a separate Cargo workspace with its own lockfile:

| Crate | Purpose |
|---|---|
| `testkit` | Finds and connects to the gateway, creates and cleans up sandboxes, runs the CLI, and runs test programs. Also builds `testkit-ready`. |
| `testkit-macros` | The `#[testkit::test]` attribute. |

## Writing a test

A test is an `async fn` that takes `&mut testkit::Context` and returns
`testkit::Result`:

```rust
use testkit::Context;

/// A long-running sandbox becomes ready, runs a command with exec, and is gone
/// from get and list after delete.
#[testkit::test]
async fn long_running_exec_delete(cx: &mut Context) -> testkit::Result {
    let sandbox = cx.sandbox("lr").command(["sleep", "infinity"]).create().await?;
    sandbox.wait_ready().await?;
    // ...
    Ok(())
}
```

- **The doc comment is required.** It is the test's description.
- **The function name is the nextest test name.**
- **Other attributes apply to the test.** For example, `#[ignore = "reason"]`
  skips it unless run with `--run-ignored`. `#[should_panic]` is rejected,
  because a testkit test panics on any failure. To check that something is
  refused, assert the failure in the body, for example with
  `cx.cli([...]).await?.failure()?` and `testkit::ensure!`.

Cleanup runs after every test, whether it passes, fails, or panics. It
deletes the sandboxes created through `cx.sandbox(...)` or tracked with
`cx.track(name)`, and runs the hooks registered with `cx.on_cleanup`. Register
a hook for anything else a test creates, such as a provider. Register it before
the create when the delete succeeds for a missing resource, so it also covers a
create the gateway applied but the CLI reported as failed:

```rust
let cli = cx.cli_handle();
let name = provider.clone();
cx.on_cleanup(format!("delete provider {provider}"), async move || {
    cli.run(["provider", "delete", &name]).await?.success()?;
    Ok(())
});
cx.cli(["provider", "create", "--name", &provider /* ... */]).await?.success()?;
```

Hooks and sandbox deletes run one at a time, last registered first, each
limited to `testkit::CLEANUP_TIMEOUT`. A failure, panic, or timeout is
reported, the remaining hooks still run, and a test that otherwise passed
fails. A killed test process skips cleanup, so names are unique to the run.

## What a test can do

`Context` currently provides:

- `cx.sandbox(suffix)` to build a sandbox with a run-unique name, then
  `create()` it or `create_ready()` to also wait for Ready. Set its image
  with `image(..)` and its policy with `policy(..)`. The returned
  `Sandbox` can wait for ready or finished, stop, start, exec or
  `poll_exec` until the output matches, read its config and draft policy, set
  a setting, read `sandbox get` JSON with `get_json()`, and delete. Its
  `expect_listed`, `expect_absent` and `wait_absent` check list and get.
  Exec output has `success()`, `failure()` and `expect_stdout()`.
- `cx.cli_sandbox(suffix)` for a sandbox only `openshell sandbox create`
  can make, such as one with `policy_yaml(...)` or `--no-keep`. `create()`
  detaches and returns the `Sandbox`, `create_ready()` also waits for Ready,
  and `run()` returns the attached CLI output.
- `cx.track(name)` to register a sandbox created some other way, such as
  through the CLI, for cleanup. Call it before the
  create, so a create that fails after the gateway accepted it is still cleaned
  up. `cx.adopt(name)` returns a `Sandbox` handle for one the CLI created.
- `cx.expect_compute_driver(name)` to fail unless the gateway runs only that
  compute driver. Driver suites call it first.
- `testkit::base_image()` for the image to create sandboxes from or build on:
  `OPENSHELL_TEST_BASE_IMAGE`, or OpenShell's default sandbox image.
- `testkit::python_image()` for sandboxes that run `python3`, curl, git, or
  openssl: `OPENSHELL_TEST_PYTHON_IMAGE`, or `openshell/e2e-python:dev`
  (`e2e/python/Dockerfile.workload`). The tmachine installers load it into
  every environment; `mise run e2e:workload:build` builds it locally. An
  override image must run `python3` from one of `testkit::PYTHON_BINARIES`.
- `cx.cli([...])` to run the installed CLI against the same gateway, with
  the same `success()`, `failure()` and `expect_stdout()` as exec output,
  plus `json()`, and `report_text()` for matching a wrapped error report.
  `cx.cli_handle()` returns that CLI for code that can't borrow `cx`, such as
  a cleanup hook.
- `cx.cli_spawn([...])` to start the CLI and keep it running, for commands
  that stream or read input, such as `sandbox connect`. The `CliChild` it
  returns writes stdin, reads stdout and stderr line by line or all at once,
  sends signals, and waits for the exit code. `cx.cli_spawn_with_stdin` takes
  another stdin, such as a file or a pseudo-terminal.
- `Cli::apply_env` to point another program at the same gateway, such as `ssh`
  with the `ProxyCommand` from `sandbox ssh-config`. `Cli::gateway` says which
  gateway that is.
- `cx.on_cleanup(name, hook)` to remove something when the test ends.
- `testkit::policy` for sandbox policies: `policy::base()` reads
  `testkit/src/base-policy.yaml`, which allows no network access, and
  `policy::allow(&mut policy, name, host, port, binaries)` adds an endpoint
  (binaries apply to every endpoint under `name`) that `policy::Endpoint`
  configures (`.rest(Access::Full)`, `.credential_binding(provider)`, ...).
  Pass the result to `cx.sandbox(..).policy(policy)`, or `policy::to_yaml`
  for the CLI.
  `testkit::PYTHON_BINARIES` names `python3` in `python_image()` images.
- `cx.import_profile(profile)` to import a provider profile and return its
  `id`, and `cx.create_provider(name, type, credentials)` to create a
  provider, each with cleanup. `cx.install_provider(name, profile,
  credentials)` does both.
- `testkit::YamlFile` for YAML a CLI command reads from a file.
- `cx.client()` for SDK calls testkit does not wrap.
- `?` and `.context(..)` on I/O, JSON, YAML, SDK and gRPC results, which
  convert into `testkit::Error`.
- `error.grpc_code()` for the gRPC status code (`testkit::GrpcCode`) of a
  request the gateway refused, such as a sandbox create.
- `poll_until` for waiting on other state, and `with_deadline(what, timeout,
  future)` for a step that must finish sooner than its own timeout.

## Running against a gateway

Tests find the gateway the same way the `openshell` CLI does:

1. `OPENSHELL_GATEWAY_ENDPOINT`: a gateway URL. Its credentials come from the
   gateway named by `OPENSHELL_GATEWAY`, or else the registered gateway with
   that endpoint. A URL no gateway is registered for is used as is:
   plaintext, or TLS without a client certificate.
2. `OPENSHELL_GATEWAY`: the name of a gateway registered with the CLI.
3. The CLI's active gateway, set by `openshell gateway select`.

A registered gateway's endpoint and auth mode come from
`$XDG_CONFIG_HOME/openshell/gateways/<name>/metadata.json`. For mTLS, the CA
and client certificate come from its `mtls/` directory. testkit supports
plaintext and mTLS gateways. `OPENSHELL_WORKSPACE` selects the workspace
(default `default`), and `OPENSHELL_BIN` selects the CLI that `cx.cli` runs
(default `openshell` on PATH). The CLI always targets the same gateway and
workspace as the SDK. Each test logs the gateway it used.

Wait for the gateway, then run a suite. Run tests that share a gateway one at
a time:

```shell
export OPENSHELL_GATEWAY=<name>
cargo run --manifest-path tests/testkit/Cargo.toml --bin testkit-ready -- 300
cargo nextest run --manifest-path <suite>/Cargo.toml --test-threads 1
```

`testkit-ready [TIMEOUT_SECS]` exits non-zero if the gateway is not healthy in
time or the CLI does not report it connected.

`e2e/with-docker-gateway.sh` and `e2e/with-podman-gateway.sh` start an
ephemeral gateway and export `OPENSHELL_GATEWAY` and `OPENSHELL_BIN`, so a
suite runs under them unchanged.

`mise run e2e:testkit` does this for the suites in `tests/suites/conformance`.
In a tmachine VM, the test runner (`tests/runner/`) does the same: it sets
`OPENSHELL_GATEWAY` to the gateway the installer registered and
`OPENSHELL_BIN` to the installed CLI, then runs the suites with nextest. See
[TESTING.md](../../TESTING.md).

## Test programs

`#[testkit::test]` also registers the test with testkit. A binary whose
`main` calls `testkit::main()` runs every registered test it links, without
cargo or nextest:

```rust
use conformance as _;

fn main() -> std::process::ExitCode {
    testkit::main()
}
```

The program must name each suite crate it runs, as `use conformance as _;` does
above: Rust doesn't link a dependency that is never named, and its tests would
be missing. A program that links no tests exits 2 with an error under every
command. `openshell-conformance`, a binary in the conformance crate, is the
program for the conformance suite; see
[its README](../suites/conformance/README.md).

| Command | What it does |
|---|---|
| `list [FILTER]...` | Prints each test's name and description. Ignored tests are included and marked. |
| `ready [--timeout SECS]` | Waits for the gateway, like `testkit-ready` (default 60 seconds). Exits 2 if it is not ready in time. |
| `run [FILTER]...` | Runs the tests one at a time, each in its own process. Unix only. |

A filter selects tests whose name contains it. `run` also takes:

- `--include-ignored`: runs ignored tests too, instead of reporting them as
  skipped.
- `--timeout SECS` (default 900): a test that runs longer gets SIGTERM, then
  SIGKILL after `--grace SECS` (default 10).
- `--junit PATH`: writes a JUnit report with one test suite per family.

Each test runs in its own process group. When the test's process exits, `run`
kills anything left in the group, such as CLI processes the test started.
Interrupting `run` stops the current test the same way and runs no more
tests; a second interrupt skips the grace period. If `run` itself is killed
with SIGKILL, the current test's process group keeps running. In a container
where `run` is PID 1, start it under an init, for example with
`docker run --init`.

`run` exits 0 when every test passed, 1 when a test failed, timed out, or
crashed, and 2 when tests could not run: no tests matched, a test process
could not start or run its test, or the run was interrupted.

A test that is stopped does not clean up: sandboxes it created stay on the
gateway. Run against a gateway you can throw away, or delete them by hand.

Without a subcommand, the program takes libtest's arguments instead. A
`[[test]]` target with `harness = false` therefore also runs under `cargo test`
and nextest. In that mode tests run in one process, one at a time unless
`--test-threads` says otherwise.

A test's name is its module path without the crate name, then its function
name, as in nextest. Its family, which groups tests in the JUnit report, is
the first directory under the last `suites` directory in the crate's path:
`conformance` for `tests/suites/conformance`, `features` for
`tests/suites/features/<name>`.

## Checks

```shell
cargo fmt --manifest-path tests/testkit/Cargo.toml --all -- --check
cargo clippy --locked --manifest-path tests/testkit/Cargo.toml --all-targets -- -D warnings
cargo nextest run --locked --config-file .config/nextest.toml --manifest-path tests/testkit/Cargo.toml
```

`mise run rust:lint`, `mise run rust:format:check`, and `mise run test` include
these, and Branch Checks runs them.
