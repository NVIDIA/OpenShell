# Isolation backend interface

This crate defines the supervisor-facing `IsolationBackend` contract, lifecycle
states, and shared types. It forbids unsafe code, including in its tests.

Linux enforcement mechanisms belong to `openshell-sandbox::linux`. Backends
implement this crate's safe contract without importing Linux mechanisms through
the interface crate.
