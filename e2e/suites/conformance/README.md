# OpenShell conformance suite

Conformance tests exercise required public behavior against a prepared gateway.
Cargo discovers and runs the tests directly. Each area retains its existing
scenario implementation and helpers in one integration-test file:
`file_transfer.rs`, `lifecycle.rs`, `policy_advisor.rs`, and `smoke.rs`.

The runner, process executor, polling, diagnostics, and cleanup remain in
`crates/openshell-conformance`. That crate no longer defines scenarios or a
registry. Existing Rust e2e, driver, and feature consumers retain their harnesses
and locations. Story-module organization and shared-runner consolidation are
separate follow-ups.

## Run

Supply the matching candidate CLI and a configured gateway:

```shell
OPENSHELL_BIN=/absolute/path/to/openshell \
  cargo test --locked --manifest-path e2e/suites/conformance/Cargo.toml \
    --package openshell-test-conformance-cli -- --test-threads=1 --nocapture
```

Use `--test file_transfer`, `--test lifecycle`, `--test policy_advisor`, or
`--test smoke` to select an area. Existing test names remain available for
focused selection. The lifecycle test retains combined stop/start persistence
and stopped-sandbox deletion checks.

## Source checks

```shell
cargo test --locked --package openshell-conformance
cargo test --locked --manifest-path e2e/suites/conformance/Cargo.toml \
  --package openshell-test-conformance-cli --test policy_advisor draft_assertion
```

The runner unit tests and three policy assertions run without a gateway. Other
integration tests require target preparation and run in the existing driver E2E
and installed nextest archive lanes. Tests register resources before creation,
use unique names, and always call `OpenShellRunner::finish` so cleanup failures
remain visible. Bounded polling observes asynchronous state; failed assertions
are not retried. Live tests and public internet dependencies remain outside
source unit checks.
