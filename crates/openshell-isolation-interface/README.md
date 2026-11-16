# Isolation backend shared types

This crate contains shared data and validation for the Isolation Backend RPC
contracts. It forbids unsafe code, including in its tests.

The extension contracts are [`isolation_backend.proto`](../../proto/isolation_backend.proto)
and [`sandbox_protocol.proto`](../../proto/sandbox_protocol.proto).
The supervisor uses the concrete RPC client in `openshell-sandbox-backend`.
Both in-tree and external backends implement the generated services.
Linux process and enforcement helpers remain private to `openshell-sandbox`.
