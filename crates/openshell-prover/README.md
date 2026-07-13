<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# openshell-prover

Formal containment verifier for OpenShell managed maximum policies. It encodes
a candidate policy and the gateway-managed maximum as a Z3 model and looks for
one concrete action the candidate allows outside the maximum.

## What it decides

The public API exposes two checks:

```rust
check_within_maximum(maximum, candidate)
check_within_auto_eligible_maximum(maximum, requested_delta)
```

The first check proves the whole composed candidate fits inside the maximum.
The second proves a proposal's requested delta fits the maximum after removing
authority marked `review.required`. Managed admission uses the result to
return `apply`, `ask`, or `reject`; there is no separate proposal-risk gate.

The initial model covers:

- filesystem read-only and read-write paths;
- raw L4 authority over binary, host, and port;
- enforced REST authority over binary, host, port, method, and path;
- explicit REST deny rules; and
- endpoint- or allow-level `review.required` annotations in the maximum.

Unsupported protocols or fields return `Unsupported` so managed admission
fails closed instead of silently ignoring authority.

## What the prover does *not* decide

- **Whether an action is desirable.** The maximum declares delegated
  authority; reviewers still own intent inside review-required regions.
- **Runtime network decisions.** The sandbox policy engine and proxy enforce
  the active policy. This crate proves containment before the gateway commits
  an authority-changing operation.
- **Credential secrecy or protocol inspection.** Provider policy is composed
  into the candidate by the gateway. A separate non-gating advisory warns when
  a proposal grants raw L4 access to a provider credential target.
- **Multiple simultaneous maximums.** The gateway currently owns one maximum.

## Inputs

- **Maximum** — managed policy YAML parsed into [`PolicyModel`](src/policy.rs),
  including metadata and review annotations.
- **Candidate** — the fully composed sandbox and provider policy for whole
  policy containment.
- **Requested delta** — the proposal-specific authority used for automatic
  eligibility checks.

## Outputs

- `WithinMax` when no candidate action exists outside the selected maximum
  view.
- `ExceedsMax` with a concrete filesystem or network counterexample.
- `Unsupported` with the field or protocol that prevented a sound proof.

## Z3 model layout

[`envelope.rs`](src/envelope.rs) creates one symbolic action over binary,
host, port, layer, method, and path. The solver asks whether the candidate
allows that action while the selected maximum view does not. A satisfiable
model becomes the counterexample returned to managed admission. Filesystem
containment is checked directly over normalized path patterns.

## Tests

- [`policy.rs`](src/policy.rs) tests strict parsing and managed metadata.
- [`envelope.rs`](src/envelope.rs) tests containment, review filtering,
  explicit denies, filesystem access, and fail-closed unsupported fields.
- Gateway tests cover proposal, provider, creation, and update admission using
  the same managed maximum.
