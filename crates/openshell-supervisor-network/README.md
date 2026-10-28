# Network supervisor

This crate forbids unsafe code, including its local tests. Typed socket APIs
provide original-destination lookup for transparent proxying.

Socket attribution tests pass a duplicate connected socket as a spawned child's
stdin. Re-executing the test binary checks multiple holders with the same binary
identity; executing a different binary checks ambiguous shared-socket identity.
The fixture kills and reaps the child when the parent test ends.

The manual proxy performance baseline still counts allocations. Its test-only
global allocator uses `openshell-driver-vm::allocation_tracking`; the unsafe
allocator implementation belongs to the VM crate. The VM dependency disables
default features, so this instrumentation does not
require the compute runtime or Unix-only sandbox library. It is a development
dependency only.

## Sandbox instance inputs

`run_networking` takes a `SandboxInstanceNetwork` with the sandbox identity,
the sandbox instance's `GatewayEndpoint`, the SPIFFE Workload API socket for
provider token grants, the `policy.local` denial source, and proxy CA files.
None of these are read from the process environment, so one process can run
several sandbox instances. Each instance owns its provider token cache and
HTTP client; a token acquired for one sandbox is never served to another.
Without a Workload API socket, token grants fail closed. A process hosting
several instances serves `/v1/denials` from a per-instance
`SandboxInstanceDenialLog` instead of the shared shorthand log files.

## Policy engines

A sandbox's policy format selects one engine at load, and it decides every
network request for that sandbox: `opa::OpaEngine` evaluates a YAML policy
with Rego, and `cedar_only::CedarOnlyEngine` evaluates a policy with
`cedar_policy_source`. `policy_engine::PolicyEngine` dispatches between them,
and `policy_engine::TunnelPolicyEngine` does the same for one inspected
tunnel's L7 decisions.

- `policy_types` holds the engine-neutral inputs, results, endpoint configs,
  and generation guards the proxy, relay, and policy DNS read. The OPA engine
  converts its Rego results into them in `opa`.
- `policy_data` shapes YAML network policy data for Rego, and for the Cedar
  engine's provider rules (`cedar_provider_rules`).
- `policy_validation` validates a delivered policy, of either format, before
  an engine loads it, and keeps authored values out of its errors.
- `network_middleware` selects network middleware without Rego, for Cedar
  sandboxes.

The `cedar` feature, enabled through `openshell-supervisor/cedar`, builds
`cedar_only/`, whose `mod.rs` holds the engine and its public surface.
Without it, `cedar_disabled.rs` provides the same public surface with
uninhabited types whose `from_proto` rejects every Cedar policy, so the
Cedar branches compile but cannot run. Keep the two surfaces in step.
