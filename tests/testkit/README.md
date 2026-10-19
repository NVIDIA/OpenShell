# testkit

Shared support for end-to-end test suites under `tests/suites/`. Suites test
a running OpenShell gateway through the Rust SDK and the installed `openshell`
CLI. No suite uses testkit yet; existing suites move to it one at a time.

This is a separate Cargo workspace with its own lockfile:

| Crate | Purpose |
|---|---|
| `testkit` | Reads the target file, connects to the gateway, creates and cleans up sandboxes, runs the CLI. Also builds `testkit-ready`. |
| `testkit-macros` | The `#[testkit::test]` attribute. |
| `testkit-spec` | Parses `#[testkit::test]` functions, shared by the attribute and tools that list tests. |

## Writing a test

A test is an `async fn` that takes `&mut testkit::Context` and returns
`testkit::Result`:

```rust
use testkit::Context;

/// A long-running sandbox becomes ready, runs a command with exec, and is gone
/// from get and list after delete.
#[testkit::test(id = "t-3tfdx240")]
async fn long_running_exec_delete(cx: &mut Context) -> testkit::Result {
    let sandbox = cx.sandbox("lr").command(["sleep", "infinity"]).create().await?;
    sandbox.wait_ready().await?;
    // ...
    Ok(())
}
```

- **`id` is required.** Use `t-` followed by eight random lowercase letters or
  digits. Results and coverage records refer to tests by this ID, so never
  change or reuse it, including when you rename or move the test. Omit `id`
  on a new test and the compile error suggests a fresh one.
- **The doc comment is required.** It is the test's description.
- **`requires` declares capabilities** the test needs, for example
  `#[testkit::test(id = "...", requires = [service_exposure])]`. The names are
  the boolean fields of `capabilities` in the target file. An unknown name
  fails to compile. If the target lacks a required capability, the test
  fails rather than passing untested. See
  [Excluding tests by capability](#excluding-tests-by-capability).
- **The function name is the nextest test name.** Rename it freely; the ID
  keeps the history.

Cleanup runs after every test, whether it passes, fails, or panics. It only
deletes sandboxes created through `cx.sandbox(...)`. Delete anything else a
test creates, such as providers, in the test itself.

## What a conformance test may assert

A conformance test asserts only what the public contract promises: the
comments in `proto/` and the published docs, such as the sandbox lifecycle in
`docs/how-it-works/sandboxes/overview.mdx`. Do not encode gateway behavior
the contract does not state; file an issue to document it instead.

- Assert on a sandbox's `phase` and `exit_code`, not condition reasons, which
  the API leaves to the platform.
- To check that something did not happen, read state (for example,
  `restart_count` is 0 and a second read shows the same phase) instead of
  sleeping and watching.
- Behavior the docs leave to the compute driver needs a capability in
  `requires`.
- Act through the interface that makes the promise. Upload, download,
  connect, and port forwarding exist only in the CLI, so call
  `cx.cli([...])` and rely on its exit code and `--output json`, not its
  table text.
- For API calls the SDK does not wrap yet, add a testkit helper over the
  generated gRPC client rather than calling it from tests.

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
capabilities:
  compute_driver: docker
  service_exposure: true
  persistent_workspace: false
  gpu: false
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

### Excluding tests by capability

Nothing selects tests by capability yet, so a test whose `requires` the target
does not provide fails with `requires <capability>, which the target does not
provide`. Find those tests and exclude them by name with a nextest filter:

```shell
grep -rn 'requires = \[' <suite>/tests
cargo nextest run --manifest-path <suite>/Cargo.toml --test-threads 1 \
  -E 'not test(=stopped_sandbox_keeps_workspace)'
```

Combine names with `or` inside the parentheses, for example
`-E 'not (test(=a) or test(=b))'`.

## Checks

```shell
cargo fmt --manifest-path tests/testkit/Cargo.toml --all -- --check
cargo clippy --locked --manifest-path tests/testkit/Cargo.toml --all-targets -- -D warnings
cargo nextest run --locked --config-file .config/nextest.toml --manifest-path tests/testkit/Cargo.toml
```

`mise run rust:lint`, `mise run rust:format:check`, and `mise run test` include
these, and Branch Checks runs them.
