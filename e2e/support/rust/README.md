# Shared Rust e2e tooling

`openshell-e2e-support` provides tooling for conformance, feature, driver, and
existing Rust e2e tests. It is a standalone test crate; product crates must not
depend on it.

- The CLI runner captures stdout, stderr, exit status, duration, and diagnostic
  context. Commands have explicit timeouts, and polling preserves the last
  observation on failure.
- Resource tracking cleans up explicitly registered sandboxes through `finish()`
  and retains the original test failure when cleanup also fails.
- `executor` provides process execution and an injectable boundary for unit tests.
- `binary` resolves `OPENSHELL_BIN` or a previously built checkout CLI and supports
  PTY invocation. Archive-based suites use `OpenShellRunner::from_env()` to require
  an explicit candidate binary.
- `output` parses CLI text and strips ANSI formatting.
- `port` provides TCP readiness checks and available-port discovery.

Conformance scenarios remain in `e2e/suites/conformance/cli/tests`. Container
fixtures, gateway restart controls, and suite-specific workload defaults remain
in the existing `openshell-e2e` harness. That harness re-exports `binary`, `output`,
and `port` to preserve existing test imports.

Run the tooling unit tests without a gateway:

```shell
cargo test --locked --manifest-path e2e/support/rust/Cargo.toml
```

`mise run test:rust` and branch Rust checks include these tests.
