# OpenShell extension core

`openshell-extension-core` contains protocol-neutral primitives shared by two or
more OpenShell extension mechanisms. It currently owns extension identity and
audience values, the extension JWT claim contract, refreshable bearer
credentials and the per-service store that holds them, and outbound gRPC
transport construction for HTTP, HTTPS, and Unix sockets.

Middleware- or interceptor-specific protobuf clients, policy selection,
orchestration, and lifecycle management stay in their owning crates. Gateway
signing authority also stays in `openshell-server`. This ownership rule keeps
this crate from becoming a general-purpose dumping ground as extension support
grows.
