<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# CLI conformance suite

This workspace verifies that an installed `openshell` CLI and a selected gateway
implement portable, public behavior. Tests treat the CLI as a black box. They do
not inspect driver internals or replace driver-specific qualification.

The suite separates portable contracts by capability. Each Cargo test creates a
fresh scenario runner, owns its resources, and completes cleanup independently.
A test environment should run every test supported by its compute driver instead
of treating a broad scenario as the portability or failure-isolation boundary.
In particular:

- `smoke::control_plane` covers status, create, get, list, and delete. It does
  not require `sandbox exec`.
- `smoke::exec` covers `sandbox exec` and runs only where the driver supports
  that operation.
- `lifecycle::control_plane` covers stop and stopped-deletion behavior without
  requiring `sandbox exec`.
- `lifecycle::restart_persistence` covers stop, start, and workspace persistence
  and requires `sandbox exec`.
- `lifecycle::canonical_main` covers successful and failing canonical-main
  terminal states, persistent status, and deletion.
- `environment::declared_environment` covers declared-environment propagation
  to canonical-main and exec processes.
- `policy-advisor/mechanistic-proposal`,
  `policy-advisor/new-hostname-proposal`, and `policy-advisor/sandbox-local` have
  additional runtime requirements documented in their source module.

The standalone runner registers the same leaves. It accepts either an exact leaf
name such as `smoke/exec` or a family prefix such as `smoke`, which expands to
every registered `smoke/...` leaf. Overlapping selectors are deduplicated, and
each selected leaf runs independently.

The scenario implementations live in the
[`openshell-conformance` crate](../../../crates/openshell-conformance/README.md)
so the archive tests and the standalone `openshell-conformance` runner share
assertions and cleanup. New installed-artifact CI should use this
test workspace and select tests with nextest filters.

Set `OPENSHELL_BIN` to the candidate CLI. The selected gateway must already be
reachable. Smoke sandboxes use the runtime's default workload and create
configuration. For example:

```shell
cargo nextest run \
  --manifest-path tests/suites/conformance/Cargo.toml \
  -E 'binary(smoke) & test(=control_plane)'
```

The runner owns only resources named for its generated run ID and attempts to
delete them after success or failure. Tests must not depend on unrelated gateway
state or delete resources they did not create.
