# Binary identity

`openshell-binary-identity` provides shared executable-identity resolution for
RFC 0012 isolation backends. Runtime-specific observers remain in their backend:
Docker obtains an authoritative thread ID from seccomp notification, while the
co-located Linux path maps an accepted socket to its owning processes.

Given an authoritative Linux PID and an optional trusted process-tree root, the
crate opens the leaf and bounded ancestor `/proc/<pid>/exe` objects, hashes
those already-open live objects, and returns path-and-digest evidence for the
whole executable chain. It also collects diagnostic command-line paths, which
never authorize network access. Resolution fails without returning a partial
identity if any executable cannot be opened, hashed, or validated after
hashing. The caller receives `ResolveError` and denies the associated
connection.

The crate does not intercept connections, authenticate remote observers, or
evaluate policy. The isolation backend remains responsible for binding the
resolved identity to the active boundary and exact accepted connection before
constructing `PendingTcpOpen`.

An observer whose root differs from the workload's can install an
`ExecutablePathView` with `ProcfsIdentityResolver::with_path_view`. The view
maps each `/proc/<pid>/exe` path, for the leaf and every ancestor, to the path
the identity reports, or fails the resolution. The resolver applies it again
when it revalidates a process.
