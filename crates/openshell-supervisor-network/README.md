# Network supervisor

This crate forbids unsafe code, including its local tests. Typed socket APIs
provide original-destination lookup for transparent proxying.

Windows binary policy preserves existing matching by default. If the supervisor
opts in to normalization, ordinary drive paths support separator equivalence.
ASCII case folding requires trusted directory evidence from
`openshell-binary-identity`. The L4 decision carries that evidence into its
generation-pinned L7 evaluator. The integrity cache reserves a single pin across
potential case aliases in this mode, including when directory evidence is
unavailable. Hashing still opens the original path.

The Windows glob matcher already accepts either separator in wildcard rules.
Shared normalization also covers exact rules, and trusted case evidence applies
to both forms. MXC filesystem-grant normalization and socket-owner attribution
remain separate from these network-policy comparisons.

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
