# Binary identity

`openshell-binary-identity` provides shared executable-identity resolution for
RFC 0012 isolation backends. Runtime-specific observers remain in their backend:
Docker obtains an authoritative thread ID from seccomp notification, while the
co-located Linux path maps an accepted socket to its owning processes.

Given an authoritative Linux PID and an optional trusted process-tree root, the
crate reads the executable path from procfs, hashes the live `/proc/<pid>/exe`
object, and collects bounded executable ancestry and diagnostic command-line
paths. Resolution failures are returned as `ResolveError` so the caller can
deny the associated connection.

The crate does not intercept connections, authenticate remote observers, or
evaluate policy. The isolation backend remains responsible for binding the
resolved identity to the active boundary and exact accepted connection before
constructing `MediatedConnection`.
