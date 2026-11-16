# PR #5006: Cedar crate and protobuf boundaries

PR: [feat(policy): support Cedar in development builds](https://github.com/NVIDIA/OpenShell/pull/5006)

Reviewed head: `e9f4a4269c8350f52ed827eb5d3588a20b25436d`.
Stacked base: #5005, commit `1c0e5390fbffb62fb80b8ded8ff57ff099c9517f`.

Status: implemented and verified. The implementation is committed for PR #5006
on `drew/cedar/dev-builds`.
The review findings below describe the original PR head.

## Implementation

- `openshell-policy-primitives` owns pure host, path, and address helpers; the
  Cedar engine no longer depends on `openshell-core`.
- `openshell-policy-runtime-interface` owns runtime contracts and shared request
  types. Networking consumes opaque policy and destination authorizers.
- `openshell-policy-cedar-runtime` owns Cedar snapshots, resolved-address
  enforcement, provider constraints, and staged reloads. Supervisor composition
  selects the optional backend.
- `SandboxPolicy.cedar_policy` is a message at tag 7. Presence selects Cedar,
  including empty source. Existing YAML fields remain unchanged. The new scalar
  introduced by this branch is replaced directly, without a migration.
- Endpoint settings and provider rule shapes remain as proposed by the PR;
  the removed section 4 is outside this implementation.
- The frozen Python SDK changes are reverted, and the non-Unix capability
  argument is corrected.

Validation: 2,972 Rust library tests, 292 policy tests without Cedar, 12
storage/schema tests, 20 gateway Cedar tests, targeted SDK/CLI tests, the full
TypeScript CI task (200 tests), strict Clippy across affected crates, and the
Cedar Docker end-to-end suite (39 checks) pass. The supervisor and Docker
gateway both build without Cedar. Formatting and whitespace checks pass.

The Docker run used fresh gateway, supervisor, and sandbox binaries from this
branch. Its local debug supervisor image used the distroless C++ base to supply
`libgcc_s`; production Dockerfile defaults were unchanged. The end-to-end policy
view check now verifies structured middleware data instead of an absent text
heading.

## Boundary follow-up

The shared policy facade now dispatches Cedar validation through
`openshell-policy-cedar-adapter`, which owns message conversion, TLS inspection
analysis, and MCP inventory. Runtime-only protocol and provider-rule translation
live in `openshell-policy-cedar-runtime`. Shared policy APIs expose no concrete
Cedar engine types.

Networking enforces always-blocked addresses and IP-literal control-plane port
restrictions before consulting backend authorizers, including transparent pinned
addresses. Explicit trusted gateway modes retain their existing exceptions.

`rust:verify:cedar-off` checks default product dependency graphs, compiles the
gateway and supervisor, and runs YAML policy and unsupported-Cedar tests. Branch
Checks runs it in the Linux x86_64 Rust test job, separately from workspace
feature unification. Standalone example/testkit lockfiles include the extracted
primitives crate.

Local verification passes: 2,911 affected Rust library tests plus the direct
transparent-address regression, 292 policy tests and 18 unsupported-Cedar tests
without Cedar, strict Clippy across affected crates,
and all 39 Docker Cedar checks with freshly built gateway, supervisor, CLI, and
static sandbox binaries. The Docker supervisor image uses the distroless C++
base to supply `libgcc_s`; production defaults are unchanged.

## Recommendation

Refactor the boundaries before merging. The two Cedar crates are a good start,
but shared policy and networking code still understand Cedar internals. Retain
the existing YAML protobuf fields, add an explicitly present Cedar message, and
select the runtime implementation in a composition layer.

## 1. Cedar implementation details leak into networking

The supposedly neutral `EgressAuthorization` contains
[`cedar_destination: Option<CedarDestination>`](https://github.com/NVIDIA/OpenShell/blob/e9f4a4269c8350f52ed827eb5d3588a20b25436d/crates/openshell-supervisor-network/src/policy_types.rs#L348).
The proxy interprets Cedar-specific address conditions and provider ranges in
[`proxy/destination.rs`](https://github.com/NVIDIA/OpenShell/blob/e9f4a4269c8350f52ed827eb5d3588a20b25436d/crates/openshell-supervisor-network/src/proxy/destination.rs#L225).

Maintaining Cedar semantics therefore requires changing the transport layer.
Another engine would require more variants and branches there.

Have authorization return a language-neutral destination authorizer bound to
the evaluated policy generation. The proxy supplies resolved IPs; the
implementation decides whether they are allowed. Preserve generation pinning
and post-resolution evaluation, including Cedar forbids that depend on the
resolved address.

## 2. Composition remains distributed

[`PolicyEngine`](https://github.com/NVIDIA/OpenShell/blob/e9f4a4269c8350f52ed827eb5d3588a20b25436d/crates/openshell-supervisor-network/src/policy_engine.rs#L34)
wraps both implementations, yet callers still inspect concrete variants:

- Supervisor startup selects filesystem derivation by engine.
- Supervisor reload implements separate OPA and Cedar transactions.
- Networking callers understand differences between policy and middleware generations.

The shared policy crate also exposes a concrete
[`Arc<CedarEngine>` in `ValidatedPolicy`](https://github.com/NVIDIA/OpenShell/blob/e9f4a4269c8350f52ed827eb5d3588a20b25436d/crates/openshell-policy/src/lib.rs#L2803).

Proposed ownership:

| Component | Responsibility |
|---|---|
| Policy interface | Neutral requests, decisions, filesystem grants, snapshots, and staged reload contracts |
| Cedar schema and engine crates | Cedar parsing, validation, analysis, and evaluation |
| Cedar runtime adapter | Translate runtime inputs, manage Cedar snapshots, and implement the shared contracts |
| Composition layer | Select and construct the implementation; own optional implementation dependencies |
| Networking and runtime consumers | Use the contracts without matching Cedar/OPA variants |

Extract the interface before moving the adapter. Cedar's adapter currently
consumes network-owned L7 types, so moving it into a crate that networking
imports would create a dependency cycle unless those contracts move first.

The Cedar engine also imports `openshell-core` for host, path, and address
helpers, bringing protobuf, gRPC, and TLS dependencies along. Move those pure
helpers into a smaller shared layer if the engine should be independently usable.

The existing split between the Cedar schema and evaluator is reasonable. The
main missing boundary is between the evaluator's runtime adapter and its consumers.

## 3. Retain YAML fields and add an explicitly present Cedar message

[`SandboxPolicy`](https://github.com/NVIDIA/OpenShell/blob/e9f4a4269c8350f52ed827eb5d3588a20b25436d/proto/sandbox.proto#L20)
puts YAML fields and Cedar source side by side.
[`is_cedar()` checks whether the string is nonempty](https://github.com/NVIDIA/OpenShell/blob/e9f4a4269c8350f52ed827eb5d3588a20b25436d/crates/openshell-core/src/proto/mod.rs#L97).

Keep the PR's additive approach: preserve existing YAML fields 1–6 with their
current names, types, and meanings. Replace the new Cedar string with a
message-valued field whose presence selects Cedar. A singular message already
has presence; a one-member `oneof` adds no benefit here. Do not introduce a YAML
wrapper or a symmetric YAML/Cedar `oneof` in this change.

Proposed shape (other fields omitted):

```proto
message SandboxPolicy {
  uint32 version = 1;
  FilesystemPolicy filesystem = 2;
  LandlockPolicy landlock = 3;
  ProcessPolicy process = 4;
  map<string, NetworkPolicyRule> network_policies = 5;
  map<string, NetworkMiddlewareConfig> network_middlewares = 6;

  CedarPolicy cedar_policy = 7;
}

message CedarPolicy {
  string source = 1;
}
```

Use presence of `cedar_policy`, rather than whether `source` is nonempty, to
select the engine. An explicitly present empty Cedar document stays a Cedar
document; Cedar validation decides whether to accept it. Absence retains the
existing YAML behavior. Continue rejecting Cedar combined with YAML network
rules or filesystem paths, since retaining the legacy fields means the schema
cannot enforce that exclusivity. Keep process identity, Landlock configuration,
and middleware in their existing shared fields.

Compatibility requirements:

- Preserve pre-existing YAML fields 1–6, decoding, serialization, and policy hashes.
- Cedar fields introduced in this branch can change directly. Replace the new
  string at tag 7 with the message; no legacy Cedar decoding, data migration, or
  capability version change is required for this branch.
- Keep capability negotiation so pre-Cedar gateways and supervisors are refused
  before Cedar delivery.
- Verify old YAML payloads still decode and hash identically, explicit Cedar
  presence survives an empty source, and mixed-format input is rejected.

Reference: [Protobuf evolution guidance](https://protobuf.dev/programming-guides/proto3/#updating).

## Additional findings

- The non-Unix test passes
  [`false`](https://github.com/NVIDIA/OpenShell/blob/e9f4a4269c8350f52ed827eb5d3588a20b25436d/crates/openshell-supervisor-process/src/delegated.rs#L420)
  for the new `Vec<String>` capabilities argument. Change it to `Vec::new()`.
  Linux tests will not exercise this test.
- The PR modifies `python/openshell/sandbox.py` and
  `python/openshell/sandbox_test.py`, contrary to the repository instruction
  freezing that SDK.
