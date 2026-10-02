# OpenShell conformance suite

This workspace contains public-behavior scenarios and Cargo test entry points
that run against an already configured gateway. The CLI is the current client
interface; lifecycle, file transfer, and policy behavior define the test groups.

## Layout

- `cli/tests/`: gateway-backed Cargo tests grouped by behavior.
- `support/src/scenarios/`: scenario implementations and their assertions.
- `support/src/lib.rs`: CLI runner, bounded polling, diagnostics, resource cleanup,
  and harness unit tests.
- `support/src/executor.rs`: process execution and the injected executor interface.

The `openshell-conformance` support crate belongs to this test workspace. Driver
and feature suites may reuse its runner without becoming general conformance.
Product crates must not depend on it.

## Run without a gateway

Run harness unit tests:

```shell
mise run test:conformance-support
```

Compile the gateway-backed entry points without executing them:

```shell
cargo test --locked --manifest-path tests/suites/conformance/Cargo.toml \
  --package openshell-test-conformance-cli --no-run
```

Repository formatting, Clippy, and unit-test checks include this workspace.
Select the support package for unit tests; running every workspace test also
executes the gateway-backed cases.

## Run against a prepared gateway

Install, register, and select the gateway before starting the suite. Supply the
matching candidate CLI explicitly:

```shell
OPENSHELL_BIN=/absolute/path/to/openshell \
  cargo test --locked --manifest-path tests/suites/conformance/Cargo.toml \
    --package openshell-test-conformance-cli --no-fail-fast -- \
    --test-threads=1 --nocapture
```

Use the same OpenShell revision for the suite, CLI, and gateway. The suite does
not install OpenShell, start a gateway, or select a compute driver. The target
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

Keep the expected public behavior, preconditions, resource mutations, and
assertions beside the scenario implementation. Add its Cargo entry point in the
behavior group it exercises. Preserve existing test names when moving code so
Cargo and nextest filters keep working.

Use structured CLI output and sandbox operations for behavioral assertions.
Keep gateway provisioning, runtime inspection, and host-specific setup in their
own harness or driver suite. Use unique resource names, register resources before
creation, and call `OpenShellRunner::finish` even when the scenario fails so it
attempts cleanup. Cleanup failures must remain visible. Current policy-advisor
cases set the proposal setting on their own sandbox; the suite runs serially.

[RFC 0016](https://github.com/NVIDIA/OpenShell/pull/3460) proposes the wider
strategy. This consolidation does not establish conformance qualification:
effective capability discovery, distinct unsupported/skipped/infrastructure
outcomes, and attributed completeness reporting remain follow-ups in
[#3954](https://github.com/NVIDIA/OpenShell/issues/3954). Cargo currently reports
ordinary test success or failure. Existing scenario coverage is preserved here;
this move does not provide new cross-driver admission evidence.
