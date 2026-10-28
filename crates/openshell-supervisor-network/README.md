# Network supervisor

This crate forbids unsafe code, including its local tests. Typed socket APIs
provide original-destination lookup for transparent proxying.

Windows binary-policy comparison normalizes ordinary path separators. ASCII
case folding requires trusted directory evidence from `openshell-binary-identity`.
The L4 decision carries that evidence into its generation-pinned L7 evaluator,
so both layers use the same executable identity. Original paths remain intact
for hashing; policy loading never opens authored paths.

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
