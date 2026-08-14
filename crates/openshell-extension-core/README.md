# OpenShell extension core

`openshell-extension-core` contains protocol-neutral primitives shared by two or
more OpenShell extension mechanisms. It currently owns extension identity and
audience values, the extension JWT claim contract, refreshable bearer
credentials and the per-service store that holds them, and outbound gRPC
transport construction for HTTP, HTTPS, and Unix sockets.

`ExtensionKind` is non-exhaustive so additional extension points can join the
shared identity and audience model without breaking consumers. A new kind must
still define its own registration, transport, and authorization semantics
before gateway wiring accepts it.

Outbound HTTPS authentication is selected through the shared
`ExtensionServerTrust` policy. Platform roots and operator-provided CA bundles
are implemented today. The non-exhaustive policy boundary allows future
SPIFFE X.509-SVID or public-key pinning support to be added once without
changing middleware and interceptor clients independently. Unix sockets retain
their local operating-system access boundary.

Middleware- or interceptor-specific protobuf clients, policy selection,
orchestration, and lifecycle management stay in their owning crates. Gateway
signing authority also stays in `openshell-server`. This ownership rule keeps
this crate from becoming a general-purpose dumping ground as extension support
grows.
