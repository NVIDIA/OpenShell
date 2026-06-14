<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# openshell-prover

Formal verifier for OpenShell sandbox policies. Encodes a policy + its
attached credential set + a binary capability registry as a Z3 SMT
model, then runs reachability queries to detect credentialed-reach and
capability changes a reviewer should be aware of.

Used by the gateway to gate auto-approval of agent-authored policy
proposals: any finding blocks auto-approval, an empty delta lets the
chunk pass through (when the reviewer opts in via the
`proposal_approval_mode` setting at either gateway or sandbox scope).

## What it decides

The prover answers four formal questions. Each "yes" answer is its own
categorical finding — there is no severity grade. The categories live
in [`finding::category`](src/finding.rs).

| Category | Question the prover decides |
|---|---|
| `link_local_reach` | Does this policy grant reach to a host in `169.254.0.0/16` or `fe80::/10`? |
| `l7_bypass_credentialed` | Does it let a binary using a non-HTTP wire protocol (per the binary registry's `bypasses_l7` flag) reach a host where a credential is in scope? |
| `credential_reach_expansion` | Does it let a binary reach a (host, port) with a credential in scope, where the binary couldn't reach that endpoint before? |
| `capability_expansion` | On a (binary, host, port) the binary already reaches with credentials, does it add a new HTTP method? |

The first two are unconditional risks. The latter two are *delta*
properties — the gateway runs the prover on both the baseline policy
and the merged policy and surfaces only the new paths.

## Maximum-policy containment

The prover also exposes a maximum-policy containment check for spike
work on security-approved policy envelopes. This is separate from the
risk/finding queries above: it compares a candidate policy with a
maximum policy and asks whether the candidate allows any modeled action
outside the maximum.

The check is shaped around this counterexample query:

```text
exists x:
  candidate_allows(x)
  AND NOT maximum_allows(x)
```

The first implementation models L4, REST, and WebSocket allow surfaces
for binaries, hosts, ports, methods, paths, access presets, and the
supported host/path/binary glob subset. Rust normalizes policy schema
details such as access presets and fail-closed unsupported fields, then
encodes candidate and maximum allow predicates as Z3 constraints over
symbolic action variables (`binary`, `host`, `port`, `layer`, `method`,
and `path`). L4 endpoints cover raw L4, REST, and WebSocket actions on
the same binary/host/port; REST and WebSocket endpoints cover only their
own inspected action layer. Host, path, and binary globs are encoded as
Z3 regular-expression membership constraints. Query parameters are not
modeled yet. It returns:

- `WithinMax` when every modeled candidate action is covered.
- `ExceedsMax` with a solver-produced counterexample when the candidate
  is broader.
- `Unsupported` when either policy uses a surface not modeled yet, such
  as deny rules, query constraints, GraphQL controls, MCP controls,
  endpoint path scoping, credential rewrite flags, or CIDR-only
  `allowed_ips`.

Unsupported is intentionally fail-closed. Future work can flip those
fixtures to modeled results as deny rules, MCP, GraphQL, and richer
symbolic path/query encodings land.

The spike also includes a narrowness-budget check for candidate updates
against the current policy. It uses the same symbolic action model to
prove whether candidate grants add reach, then scores the shape of the
delta so exact grants can fit a small budget while broad globs such as
`**` and L7-to-L4 broadening exceed the conservative default. See
[`MAXIMUM_POLICY_ENVELOPE_SPIKE.md`](MAXIMUM_POLICY_ENVELOPE_SPIKE.md)
for a walkthrough of the current maximum-policy and narrowness-budget
behavior.

The spike also exposes a credentialed-L4 check that asks whether any
modeled raw L4 action can reach a credential target. This keeps
uninspected credentialed authority separate from plain outbound egress
and from the maximum-policy containment proof.

## Evidence shape

Each finding carries one or more [`FindingPath::Exfil`](src/finding.rs)
entries:

```rust
pub struct ExfilPath {
    pub binary: String,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub mechanism: String,        // human-readable description
    pub policy_name: String,      // rule the path traverses
    pub category: String,         // one of the category constants
    pub method: String,           // populated for capability_expansion; empty otherwise
}
```

The gateway's `finding_delta` keys paths by `(category, binary,
host:port, category, method)` so that adding a new method on an
already-reached host surfaces as exactly one new path (not the whole
re-emission of the existing method set).

### Category suppression at the delta layer

`capability_expansion` paths whose `(binary, host, port)` tuple is also
in the `credential_reach_expansion` delta are suppressed by the
gateway. A brand-new credentialed reach is described by the
reach-expansion finding alone, not also by N per-method findings.

## Adding a new category

1. Add a constant to `src/finding.rs::category`.
2. In `src/queries.rs::check_credential_safety`, add the branch that
   detects the new category and emits one `ExfilPath` per evidence
   row. Set `path.category` to the new constant.
3. In `src/report.rs::format_path_line`, add a `match` arm rendering
   the per-path display string the reviewer sees.
4. (Gateway) If the new category should be suppressed by another, add
   the suppression rule to `crates/openshell-server/src/grpc/policy.rs::finding_delta`.
5. Add a unit test in `src/queries.rs` and an integration test in
   `crates/openshell-server/src/grpc/policy.rs::tests`.

The four v1 categories cover the formal properties the OpenShell
auto-approval gate cares about today. Additional categories (e.g.,
"destructive method introduced," "new outbound TLS without SNI") would
be additive — they don't displace existing categories.

## What the prover does *not* decide

- **Semantic risk of an action.** The prover models *can the binary do
  this?*, not *is this destructive?*. `PUT /repos/.../contents/file.md`
  and `GET /repos/.../contents/file.md` are both authenticated actions;
  the reviewer (or a downstream layer like an LLM contextual reviewer
  or an intent file) decides if the action is desired.
- **Cross-sandbox or cross-binary intent.** The model is per-sandbox.
  If two sandboxes share a credential through external policy, the
  prover reasons about each independently.
- **Runtime behavior.** The prover analyzes the policy as written; it
  doesn't observe the proxy's actual decisions. The proxy is the
  enforcement layer; the prover is the change-review layer.

## Inputs

- **Policy** — a `SandboxPolicy` proto, parsed via
  `openshell-policy::parse_sandbox_policy`.
- **Credential set** — built from the sandbox's attached providers in
  `crates/openshell-server/src/grpc/policy.rs::build_credential_set_for_sandbox`.
  v1 captures presence only (host-coarse); no scope modeling.
- **Binary registry** — YAML descriptors at
  `crates/openshell-prover/registry/binaries/*.yaml`. Each describes
  the binary's protocols, `bypasses_l7` flag, and `can_exfiltrate`
  capability.

## Outputs

- A list of `Finding` values, one per fired category. Each finding's
  `query` field holds the category name.
- The CLI renderer (`report::render_compact` / `render_report`) prints
  human-readable output for the `openshell-prover` binary.
- The gateway calls `report::finding_shorthand` to build the
  `validation_result` string persisted on each draft chunk.

## Z3 model layout

See `src/model.rs`. Briefly:

- Bool sorts per `(binary, endpoint)` pair encode policy reachability,
  filtered by binary capability flags (`can_exfiltrate`,
  `bypasses_l7`).
- Bool sorts per `(binary, host)` encode credential-in-scope (one
  credential set per sandbox).
- The reachability formula composes these into the SAT query the
  `queries::check_credential_safety` loop iterates over.

## Tests

- Unit tests in each module (`src/queries.rs`, `src/report.rs`,
  `src/policy.rs`) cover individual primitives and category emission.
- Integration tests in `src/lib.rs::tests` exercise the full
  parse → build_model → run_all_queries pipeline against testdata
  policies in `testdata/`.
- Gateway-level acceptance tests in
  `crates/openshell-server/src/grpc/policy.rs::tests` lock in the
  end-to-end `validation_result` shape and the auto-approval gate.
