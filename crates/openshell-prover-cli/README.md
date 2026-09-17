<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# OpenShell policy prover CLI

This package builds the standalone `openshell-prover` executable. It is a thin synchronous adapter around the reusable containment engine in `openshell-prover`; it owns local file loading, command parsing, result rendering, and process exit codes.

```shell
openshell-prover check candidate.yaml --boundary boundary.yaml
openshell-prover check candidate.yaml --boundary boundary.yaml --output json
```

The command checks whether a fully composed candidate policy stays within an operator-supplied boundary. It does not discover a gateway, fetch policy state, or apply policy changes.

Results use these exit codes:

| Exit code | Meaning |
| --- | --- |
| `0` | The candidate is within the boundary. |
| `1` | The candidate exceeds the boundary. |
| `2` | Usage, input, output, or internal error. |
| `3` | Unsupported policy semantics or an inconclusive solve. |
| `130` | Interrupted with Ctrl-C on Unix; graceful JSON output reports an inconclusive cancellation. |

Build and test the package with:

```shell
cargo build -p openshell-prover-cli --bin openshell-prover
cargo test -p openshell-prover-cli
```

See the [policy prover reference](../../docs/reference/policy-prover.mdx) for installed usage and interpretation guidance.

JSON output uses a numeric `schema_version` for the result contract and a
`prover_version` for the implementation that produced it. Consumers must inspect
`scope.domains` for the machine-readable coverage declaration. A passing check
compares configuration under the documented assumptions; it does not attest that
a running sandbox installed its restrictions.
