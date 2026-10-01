<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# CLI conformance suite

This workspace verifies that an installed `openshell` CLI and a selected gateway
implement portable, public behavior. Tests treat the CLI and gateway as black
boxes. They do not inspect driver internals or replace driver-specific
qualification.

Use this document as the source of truth for deciding whether a change needs
OpenShell conformance coverage and where that coverage belongs.

## Choose the test location

Start with the externally observable contract, not the directory changed by the
implementation.

| Behavior under test | Primary location | Why |
|---|---|---|
| Public CLI or gateway behavior that should work the same for every supporting compute driver and installation method | `crates/openshell-conformance/` and `tests/suites/conformance/` | Exercises the installed product through a portable black-box contract |
| Scenario selection, command execution, polling, parsing, diagnostics, or cleanup mechanics | Unit tests in `crates/openshell-conformance/` or `crates/openshell-conformance-cli/` | Verifies the reusable conformance machinery without requiring a live gateway |
| A compute driver's configuration, host integration, isolation mechanism, or driver-specific contract | `tests/suites/drivers/<driver>/` | The expected behavior is intentionally driver-specific |
| A feature that requires a dedicated external service or fixture, such as an identity provider | `tests/suites/features/<feature>/` | The environment is part of the feature contract rather than the portable CLI baseline |
| Deployment topology, wrapper behavior, upgrade behavior, or a workflow that depends on repository-managed gateway setup | The relevant `e2e/` suite or deployment test | The assertion depends on orchestration that an installed-artifact conformance test does not own |
| Pure internal logic or a crate-local API | Unit or integration tests next to the implementation | A black-box installed-product test would be slower and less precise |

A change can need more than one layer. For example, a new public sandbox
operation can require unit tests for parsing, portable conformance coverage for
the public contract, and a driver-specific test for a backend-only edge case.
Do not leave a portable assertion only in a driver lane or an `e2e/` wrapper
when the same contract should hold for other supported environments.

## Decide whether behavior is portable conformance

Add or update conformance coverage when all of these are true:

- A user or automation can observe the behavior through the public `openshell`
  CLI and gateway API surface.
- The contract should remain consistent across every compute driver that claims
  to support the capability.
- The test can run against an installed candidate CLI and an already reachable,
  selected gateway without importing implementation internals.
- The scenario can own, uniquely name, and clean up its resources after success
  or failure.
- Environment-specific prerequisites can be expressed by selecting an
  independent capability test rather than adding driver branches to the
  assertion.

Conformance does not mean that every environment supports every capability. A
portable capability may be selected only in environments that support it. Keep
capabilities with different runtime requirements independently selectable so a
test environment can run every applicable contract without broad skips or
short-circuiting unrelated assertions.

Do not add a portable conformance scenario merely because code under
`crates/openshell-conformance/` is convenient to reuse. If the expected result
depends on Docker, Podman, Kubernetes, VM, GPU, host policy, a particular
installer, or a dedicated external service, place the environment-specific
assertion in the matching driver, feature, or E2E suite. Shared runner helpers
may still live in the conformance crate when they are genuinely reusable.

## Understand the components

- `crates/openshell-conformance/` owns reusable scenarios and the runner that
  invokes a candidate CLI, parses observations, polls state, reports failures,
  and cleans up scenario-owned resources.
- `crates/openshell-conformance-cli/` provides the standalone
  `openshell-conformance` binary used by local driver E2E lanes. Its scenario
  registry and selection behavior must stay aligned with the reusable library.
- `tests/suites/conformance/` is the separately built installed-artifact test
  workspace. Its tests are archived and run inside supported test guests against
  the installed `openshell` binary.
- `e2e/` wrappers provision local gateways and run the standalone conformance
  binary before their lane-specific tests. They own environment setup, not the
  portable assertions.

The scenario implementation should have one source of truth in
`crates/openshell-conformance/`. The standalone runner and installed-artifact
tests should call that implementation instead of copying commands or
assertions.

## Add or change a scenario

1. Define the public contract, capability prerequisites, and supported
   environments. If the result is driver- or topology-specific, choose another
   suite using the table above.
2. Add or update the scenario in `crates/openshell-conformance/src/scenarios/`.
   Keep observations on public output and behavior. Add crate-local tests for
   parsing, selection, polling, failure diagnostics, and other mechanics.
3. Export and register the scenario in the conformance library. Use a stable,
   capability-oriented name. Give behavior with distinct prerequisites or
   cleanup an independently selectable scenario rather than hiding it in a
   broad aggregate.
4. Add or update the thin installed-artifact test in
   `tests/suites/conformance/cli/tests/`. It should construct the runner from
   `OPENSHELL_BIN`, check gateway reachability, invoke the shared scenario, and
   always finish through the runner so cleanup and diagnostics are preserved.
5. Keep the standalone `openshell-conformance` runner's listing and selection
   behavior aligned with the registered scenarios.
6. Update integration test selection or packaging only when the new capability
   changes which tests an environment can run. Do not duplicate scenario logic
   in Ansible, workflow YAML, or shell wrappers.

Each scenario must use its generated run ID for owned resource names, avoid
depending on unrelated gateway state, and delete only resources it created.
Failure output should identify the scenario and step without exposing secrets.

## Verify changes

Run focused checks for every component changed:

```shell
cargo test -p openshell-conformance
cargo test -p openshell-conformance-cli
cargo test \
  --manifest-path tests/suites/conformance/Cargo.toml \
  --no-run
```

The first two commands exercise the reusable library and standalone runner. The
third proves that the separate installed-artifact workspace still compiles; it
is not covered merely because the root workspace tests pass.

When behavior or scenario assertions change, also run the narrowest live lane
that exercises the capability. To run the installed-artifact workspace against
an already reachable and selected gateway, build the candidate CLI if needed,
then run:

```shell
cargo build -p openshell-cli
OPENSHELL_BIN="$PWD/target/debug/openshell" \
  cargo test \
    --manifest-path tests/suites/conformance/Cargo.toml \
    -- --nocapture --test-threads=1
```

Use `mise run e2e:docker`, `mise run e2e:podman`, `mise run e2e:vm`, or the
relevant Kubernetes lane when the change depends on that environment or changes
the E2E integration. Installed-artifact or cross-distribution behavior should
also be verified through the matching integration test matrix when practical.

Finally, run the repository-required checks from `AGENTS.md`. Document which
targeted and live checks ran; do not claim conformance verification based only
on an unchanged `e2e/` directory.

## Review checklist

- Is the asserted behavior a public, portable contract?
- Does the scenario avoid driver and deployment assumptions?
- Are distinct capabilities and prerequisites independently selectable?
- Do the standalone runner and installed-artifact suite share one scenario
  implementation?
- Does every test own uniquely named resources and clean them up on failure?
- Were the separate conformance workspace and an appropriate live lane
  considered during verification?
