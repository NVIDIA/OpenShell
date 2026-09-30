<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# OpenShell conformance scenarios

This crate defines reusable black-box conformance scenarios for the public
`openshell` CLI. It owns command execution, assertions, diagnostics, generated
resource names, and best-effort cleanup. It does not provision a gateway or
inspect compute-driver internals.

The crate is a scenario library, not the primary CI entrypoint:

| Component | Responsibility |
|---|---|
| [`tests/suites/conformance/cli`](../../tests/suites/conformance/README.md) | Wrap exported scenarios as Cargo tests and select them according to runtime capabilities. New installed-artifact CI should use this workspace. |
| `openshell-conformance` | Define portable scenarios and the shared `OpenShellRunner`. |
| [`openshell-conformance-cli`](../openshell-conformance-cli) | Run registered leaf scenarios manually or from existing E2E tooling. |

Each leaf Cargo test is both a selection boundary and a failure-isolation
boundary. It creates a fresh `OpenShellRunner`, invokes one exported `Scenario`,
and finishes cleanup independently. The standalone CLI registers the same
leaves. An exact selector such as `smoke/exec` runs one leaf, while a family
selector such as `smoke` runs every registered `smoke/...` leaf. Each selected
leaf receives its own runner and cleanup lifecycle, so one failure does not hide
results for later capabilities.

Scenarios must exercise public CLI behavior, own only resources created for
their run ID, and remain independent of unrelated gateway state. Split coverage
when a behavior requires an optional runtime capability so environments can run
the largest supported subset without weakening assertions. Driver internals,
platform enforcement, and hardware qualification belong in driver-specific
tests rather than this crate.

When adding or splitting a scenario, create one leaf per independently
selectable runtime capability, export each leaf from the library, and add a
separate Cargo test wrapper under `tests/suites/conformance/cli`. Register every
leaf with the standalone CLI and name it `<family>/<capability>`. Family-prefix
selection provides the grouped manual and E2E entrypoint without introducing an
aggregate scenario that can stop at its first failed child.
