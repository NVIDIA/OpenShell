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

Networking consumes `PolicyEngine` and `TunnelPolicyEngine` from
`openshell-policy-runtime-interface`. Supervisor composition selects the
backend once at startup. `opa::OpaEngine` implements the YAML backend here;
`openshell-policy-cedar-runtime` implements Cedar in a separate crate.

The proxy, relay, and policy DNS use shared decisions and generation guards.
An admitted connection carries an opaque destination authorizer that checks
resolved addresses against the same policy snapshot. Reloads stage and commit
through the backend contract, preserving atomic policy, middleware, and
credential publication without inspecting concrete engine variants.

`policy_types`, `policy_data`, `binary_resolution`, and `network_middleware`
reexport shared runtime helpers. `policy_validation` reexports the policy
composition layer's bounded validation diagnostics. The `cedar` feature enables
Cedar validation and the parity tests; it does not import the Cedar runtime into
production networking code.
