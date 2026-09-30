<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# OpenShell conformance scenarios

This crate defines reusable black-box conformance scenarios for the public
`openshell` CLI. It owns command execution, assertions, diagnostics, generated
resource names, and best-effort cleanup. It does not provision a gateway or
inspect compute-driver internals.

The crate is a scenario library shared by two execution frontends:

| Component | Responsibility |
|---|---|
| [`tests/suites/conformance/cli`](../../tests/suites/conformance/README.md) | Wrap exported leaf scenarios as Cargo tests. |
| `openshell-conformance` | Define portable scenarios and the shared `OpenShellRunner`. |
| [`openshell-conformance-cli`](../openshell-conformance-cli) | Run every registered leaf or select one leaf or group. |

The registry returned by `scenarios()` contains only independently executable
leaf scenarios. Names use `/` to express groups, such as
`smoke/control-plane`, `smoke/exec`, and `file-transfer/path-safety`. The
standalone CLI expands a group such as `smoke` to every leaf below that prefix,
runs every selected leaf even after failures, and returns a failing status only
after reporting all results. Cargo tests invoke the same exported leaves.

Scenarios must exercise public CLI behavior, own only resources created for
their run ID, and remain independent of unrelated gateway state. Split coverage
when a behavior requires an optional runtime capability so failures identify the
specific unsupported operation without hiding later coverage. Driver internals,
platform enforcement, and hardware qualification belong in driver-specific
tests rather than this crate.

Target-specific fixture and command construction lives in `src/platform/unix.rs`
and `src/platform/windows.rs`. Scenarios select one implementation at compile
time while their control flow and assertions remain shared. The platform layer
provides a small set of reusable operations instead of mirroring the scenario
tree. Implementations may construct temporary policies and commands, but must
exercise the same public behavior. Platform fixtures establish only the
prerequisites for a scenario: an unsupported platform capability must fail at
the public CLI operation under test, not at sandbox creation because the
fixture supplied a command or path for the wrong operating system.

When adding a scenario, export it from the library and add the appropriate Cargo
test wrapper under `tests/suites/conformance/cli`, then add the leaf to the
standalone CLI registry. Conformance CI must run all registered leaves; focused
leaf or group selection is for local diagnosis.
