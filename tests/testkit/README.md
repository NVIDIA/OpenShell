# testkit

Shared support for end-to-end test suites. Suites test a running OpenShell
gateway through the Rust SDK and the installed `openshell` CLI.

This is a separate Cargo workspace with its own lockfile:

| Crate | Purpose |
|---|---|
| `testkit` | Finds and connects to the gateway, creates and cleans up sandboxes, runs the CLI. Also builds `testkit-ready`. |
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

Cleanup runs after every test, whether it passes, fails, or panics. It only
deletes sandboxes created through `cx.sandbox(...)`. Delete anything else a
test creates, such as providers, in the test itself.

## What a test can do

`Context` currently provides:

- `cx.sandbox(suffix)` to build and create a sandbox with a run-unique name.
  The returned `Sandbox` can wait for ready or finished, stop, start, exec,
  read its config and draft policy, set a setting, and delete.
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

## Checks

```shell
cargo fmt --manifest-path tests/testkit/Cargo.toml --all -- --check
cargo clippy --locked --manifest-path tests/testkit/Cargo.toml --all-targets -- -D warnings
cargo nextest run --locked --config-file .config/nextest.toml --manifest-path tests/testkit/Cargo.toml
```

`mise run rust:lint`, `mise run rust:format:check`, and `mise run test` include
these, and Branch Checks runs them.
