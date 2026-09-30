<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# CLI conformance suite

This workspace verifies that an installed `openshell` CLI and a selected gateway
implement portable, public behavior. Tests treat the CLI as a black box. They do
not inspect driver internals or replace driver-specific qualification.

The suite separates portable contracts into independently executable leaves.
Logical scenario names use `/` to express groups. Conformance CI runs every leaf
so unsupported behavior remains visible instead of treating one broad scenario
as the portability boundary. In particular:

- `smoke/control-plane` covers status, create, get, list, and delete. It does
  not require `sandbox exec`.
- `smoke/exec` covers `sandbox exec`. Drivers without exec support still run
  the test and report that capability gap.
- `sandbox/lifecycle/control-plane` covers stop and stopped deletion without
  requiring exec.
- `sandbox/lifecycle/restart-persistence` covers restart and workspace
  persistence, including exec-based observations.
- The `file-transfer/*` and `policy/*` leaves have additional runtime
  requirements documented in their source modules.

The scenario implementations live in the
[`openshell-conformance` crate](../../../crates/openshell-conformance/README.md)
so the Cargo tests and the standalone `openshell-conformance` runner share
assertions and cleanup. CI may use either frontend, but must run all leaves and
continue after individual failures. Use focused selection only to reproduce or
diagnose one scenario locally.

Set `OPENSHELL_BIN` to the candidate CLI. The selected gateway must already be
reachable. Smoke workloads are selected from the conformance crate's Unix or
Windows implementation at compile time. For example:

```shell
cargo nextest run \
  --manifest-path tests/suites/conformance/Cargo.toml \
  -E 'binary(smoke) & test(=control_plane)'
```

Run the complete suite in CI without stopping after the first capability gap:

```shell
cargo nextest run \
  --profile ci \
  --manifest-path tests/suites/conformance/Cargo.toml
```

The standalone runner provides equivalent leaf and group selection:

```shell
openshell-conformance run
openshell-conformance run smoke
openshell-conformance run smoke/exec
```

It executes selected leaves serially, reports every result, and exits non-zero
after the run if any leaf failed.

The runner owns only resources named for its generated run ID and attempts to
delete them after success or failure. Tests must not depend on unrelated gateway
state or delete resources they did not create.
