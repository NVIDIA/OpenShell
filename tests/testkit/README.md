# testkit

Shared support for end-to-end test suites. Suites test a running OpenShell
gateway through the Rust SDK and the installed `openshell` CLI.

This is a separate Cargo workspace with its own lockfile:

| Crate | Purpose |
|---|---|
| `testkit` | Finds and connects to the gateway, creates and cleans up sandboxes, runs the CLI. Also builds `testkit-ready`. |
| `testkit-macros` | The `#[testkit::test]` attribute. |
| `testkit-spec` | Parses `#[testkit::test]` functions. The macro and a test runner's catalog can both use it, so tools can list tests, with their ID and description, without compiling them. |

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
- **Keep tests at the top level of the file.** `testkit_spec::scan`, which
  lists tests from source for tools such as a test runner's catalog, doesn't
  look inside `mod` blocks yet, so it refuses a test there.
- **No `#[cfg]` or `#[cfg_attr]`** on a test, or `#![cfg]` on a file with
  tests. Listing from source can't tell whether a test is compiled, so a
  runner would expect a test that never runs. A test that only applies to some
  environments belongs in a `features` or `drivers` suite.
- **No other tests in the file.** A file with `#[testkit::test]` functions
  can't also have `#[test]` or `#[tokio::test]` functions. nextest would run
  them, but a runner listing tests from source wouldn't expect them.
- **Other attributes apply to the test.** For example, `#[ignore = "reason"]`
  skips it unless run with `--run-ignored`. `#[should_panic]` is rejected,
  because a testkit test panics on any failure. To check that something is
  refused, assert the failure in the body, for example with
  `cx.cli([...]).await?.failure()?` and `testkit::ensure!`.
- **`id` is optional.** `#[testkit::test(id = "t-0123abcd")]` gives a test an
  identity that survives renames and moves. Tools that need one, such as
  result history, use it; without it the function name is the
  identity. An ID is `t-` and eight lowercase letters or digits, unique across
  all suites. A malformed ID's compile error suggests a fresh one.

Cleanup runs after every test, whether it passes, fails, or panics. It only
deletes sandboxes created through `cx.sandbox(...)`. Delete anything else a
test creates, such as providers, in the test itself.

## What a test can do

`Context` currently provides:

- `cx.sandbox(suffix)` to build and create a sandbox with a run-unique name.
  The returned `Sandbox` can wait for ready or finished, stop, start, exec,
  read its config and draft policy, set a setting, and delete.
- `cx.track(name)` to register a sandbox created some other way, such as
  through the CLI, for cleanup. Call it before the
  create, so a create that fails after the gateway accepted it is still cleaned
  up. `cx.adopt(name)` returns a `Sandbox` handle for one the CLI created.
- `cx.expect_listed` and `cx.expect_absent` to check a sandbox in list and get.
- `cx.cli([...])` to run the installed CLI against the same gateway, with
  `success()`, `failure()`, and `json()` on the output.
- `cx.client()` for SDK calls testkit does not wrap.
- `poll_until` for waiting on other state.

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
On CI the test runner (`tests/runner/`) does the same for a guest: it sets
`OPENSHELL_GATEWAY` to the gateway the installer registered, `OPENSHELL_BIN` to
the installed CLI, then runs the plan's suites with nextest. See [TESTING.md](../../TESTING.md) and
[tests/plans/README.md](../plans/README.md).

## Checks

```shell
cargo fmt --manifest-path tests/testkit/Cargo.toml --all -- --check
cargo clippy --locked --manifest-path tests/testkit/Cargo.toml --all-targets -- -D warnings
cargo nextest run --locked --config-file .config/nextest.toml --manifest-path tests/testkit/Cargo.toml
```

`mise run rust:lint`, `mise run rust:format:check`, and `mise run test` include
these, and Branch Checks runs them.
