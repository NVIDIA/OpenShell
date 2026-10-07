# OpenShell conformance suite

Conformance is an end-to-end test type for required public behavior against an
already configured gateway. This workspace contains Cargo tests organized by
conformance area and user story. The CLI is the current client interface; lifecycle, file transfer, and policy behavior define the test groups.

## Layout

- `cli/tests/<area>/main.rs`: declares story modules for one Cargo test target.
- `cli/tests/<area>/<story>.rs`: test functions, steps, and assertions for a story.
- `cli/tests/<area>/helpers.rs`: setup and assertions shared by that area's stories.

The current areas are `file_transfer`, `lifecycle`, `policy_advisor`, and `smoke`.
Each area compiles into one test binary; individual stories remain selectable by
their module prefix. `main.rs` contains only module declarations.

Shared CLI execution, polling, diagnostics, and cleanup live in
[`e2e/support/rust`](../../support/rust/README.md), alongside the utilities used by
the existing Rust e2e tests. Story modules implement their tests directly; Cargo and nextest provide discovery and selection. Product crates must
not depend on the test tooling.

For example, run only file-transfer round trips against a prepared gateway:

```shell
OPENSHELL_BIN=/absolute/path/to/openshell \
  cargo test --locked --manifest-path e2e/suites/conformance/Cargo.toml \
    --test file_transfer round_trip::
```

## Run without a gateway

Run shared tooling and scenario unit tests:

```shell
cargo test --locked --manifest-path e2e/support/rust/Cargo.toml
cargo test --locked --manifest-path e2e/suites/conformance/Cargo.toml \
  --package openshell-test-conformance-cli --test policy_advisor draft_assertion::tests::
```

Compile the gateway-backed entry points without executing them:

```shell
cargo test --locked --manifest-path e2e/suites/conformance/Cargo.toml \
  --package openshell-test-conformance-cli --no-run
```

Repository formatting, Clippy, and unit-test checks include this workspace.
The unit-test commands select only the pure policy assertion tests. Running every
workspace test also executes the gateway-backed cases.

## Run against a prepared gateway

Install, register, and select the gateway before starting the suite. Supply the
matching candidate CLI explicitly:

```shell
OPENSHELL_BIN=/absolute/path/to/openshell \
  cargo test --locked --manifest-path e2e/suites/conformance/Cargo.toml \
    --package openshell-test-conformance-cli --no-fail-fast -- \
    --test-threads=1 --nocapture
```

For development, use a suite, CLI, and gateway from the same candidate build.
Cross-version qualification is not defined. The suite does not install OpenShell, start a gateway, or select a compute driver. The target
must supply the workload image and tools used by the selected scenarios. Missing
CLI or gateway prerequisites fail the run rather than silently passing.

Run one group with `--test file_transfer`, `--test lifecycle`,
`--test policy_advisor`, or `--test smoke`, before the `--` separator. A group or
individual-test filter exercises only part of the suite.

The tmachine conformance testsuite runs these same entry points from the
nextest archive built by `build-openshell-conformance-test-archive`. See
[CI.md](../../../CI.md) for the implemented integration lanes and
[the test-guest guide](../../../nix/test-guest/README.md) for preparation
and artifact execution. Archive construction selects the CLI test package;
harness unit tests run separately in source checks.

## Add or change a test

Document the expected public behavior, preconditions, required permissions, and
significant side effects beside each scenario implementation. Use descriptive,
stable test names so results can be tracked across runs. Add the Cargo entry point
in the behavior group it exercises. Preserve existing test names when moving code so
Cargo and nextest filters keep working.

Use structured CLI output and sandbox operations for behavioral assertions.
Separate end-user and administrative interactions into different tests. Tests
may modify resources and settings through public APIs within their declared
permissions; deployment configuration belongs to target preparation. Keep
runtime inspection and host-specific assertions in driver suites. Behavioral
assertions must not depend on public internet services.

Tests must clean up their changes. Use unique resource names, register resources
before creation, and call `OpenShellRunner::finish` even when the scenario fails so it
attempts cleanup. Cleanup failures must remain visible. Current policy-advisor
cases set the proposal setting on their own sandbox; the suite runs serially.

## Failures and evidence

Every conformance test checks required behavior. A failing test on a supported
target records a conformance gap; missing support must not turn the result into
a passing test. Cargo currently reports ordinary test success or failure.

Investigate failures and track their product, test, or infrastructure causes.
Retain the result and failure logs with the revision, target configuration, and
run duration. Notify the responsible maintainers of new failures. Do not
configure automatic retries for failed tests.

An explicit waiver records its scope, rationale, and tracking issue while
retaining the failed result. Waivers are review decisions, not changes to test
assertions or successful results. Automated evidence retention, notifications,
and waiver handling remain implementation work.

## Migration scope

The conformance, feature, and driver suite workspaces live under `e2e/suites/`;
target provisioning stays under `tests/`. Existing
assertions and test identities are preserved. The legacy mixed suites under
`e2e/rust/` still need classification and migration by behavioral intent.

[RFC 0016](https://github.com/NVIDIA/OpenShell/pull/3460) also proposes independent
conformance, feature, and driver PR selection, release qualification, and later
restart/upgrade disruption tests. Those execution changes and packaging for runs
without a source checkout are separate follow-ups in
[#3954](https://github.com/NVIDIA/OpenShell/issues/3954). See [CI.md](../../../CI.md) for the
implemented gates; this layout change does not establish those proposed gates.
