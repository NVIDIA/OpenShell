<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# OpenShell policy prover CLI

This package builds the standalone `openshell-prover` executable. It is a thin synchronous adapter around the reusable containment engine in `openshell-prover`; it owns local file loading, command parsing, result rendering, and process exit codes.

```shell
openshell-prover check candidate.yaml --maximum maximum.yaml
openshell-prover check candidate.yaml --maximum maximum.yaml --output json
```

The command checks whether a fully composed candidate policy stays within an operator-supplied maximum. It does not discover a gateway, fetch policy state, or apply policy changes.

Results use these exit codes:

| Exit code | Meaning |
| --- | --- |
| `0` | The candidate is within the maximum. |
| `1` | The candidate exceeds the maximum. |
| `2` | Usage, input, output, or internal error. |
| `3` | Unsupported policy semantics or an inconclusive solve. |
| `130` | Interrupted with Ctrl-C on Unix; graceful JSON output reports an inconclusive cancellation. |

Build and test the package with:

```shell
cargo build -p openshell-prover-cli --bin openshell-prover
cargo test -p openshell-prover-cli
```

See the [policy prover reference](../../docs/reference/policy-prover.mdx) for installed usage and interpretation guidance.
