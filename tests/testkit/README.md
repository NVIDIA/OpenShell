# testkit

Shared support for end-to-end test suites. Suites test a running OpenShell
gateway through the Rust SDK and the installed `openshell` CLI.

This is a separate Cargo workspace with its own lockfile:

| Crate | Purpose |
|---|---|
| `testkit` | Reads the target file, connects to the gateway, creates and cleans up sandboxes, runs the CLI. Also builds `testkit-ready`. |
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

Tests read the system under test from the target file named by
`OPENSHELL_TEST_TARGET`. Relative paths resolve against the file's directory.

```yaml
gateway:
  endpoint: https://127.0.0.1:17670   # http:// for plaintext
  tls:                                # optional; cert and key together select mTLS
    ca: ca.crt
    client_cert: client.crt
    client_key: client.key
  auth:                               # optional
    bearer_token_file: token
cli:                                  # needed by tests that call cx.cli
  binary: /usr/bin/openshell          # default: `openshell` on PATH
  gateway: local                      # default: the CLI's active gateway
workspace: default
```

Wait for the gateway, then run a suite. Run tests that share a gateway one at
a time:

```shell
export OPENSHELL_TEST_TARGET=$PWD/target.yaml
cargo run --manifest-path tests/testkit/Cargo.toml --bin testkit-ready -- 300
cargo nextest run --manifest-path <suite>/Cargo.toml --test-threads 1
```

`testkit-ready [TIMEOUT_SECS]` exits non-zero if the gateway is not healthy in
time or the target's CLI does not report it connected.

## Checks

```shell
cargo fmt --manifest-path tests/testkit/Cargo.toml --all -- --check
cargo clippy --locked --manifest-path tests/testkit/Cargo.toml --all-targets -- -D warnings
cargo nextest run --locked --config-file .config/nextest.toml --manifest-path tests/testkit/Cargo.toml
```

`mise run rust:lint`, `mise run rust:format:check`, and `mise run test` include
these, and Branch Checks runs them.
