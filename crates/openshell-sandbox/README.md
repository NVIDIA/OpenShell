# Sandbox runtime

`openshell-sandbox` owns the Linux workload isolation mechanisms and their kernel
qualification probes. The `linux` module contains seccomp notifications and child
filters, task-memory access, process-signal mediation, procfs descriptor lookup,
socket identity, Landlock qualification, and the workload launch thread.

`sandbox::linux` composes policy enforcement. The top-level `linux` module owns
the lower-level mechanisms used by that orchestration and the boundary server.
Unsafe kernel ABI, process-launch, and descriptor-ownership operations stay in
this runtime crate behind safe APIs where their contracts can be enforced.

The network broker retains source socket descriptors only while preparing a
workload endpoint. A successful connection or `listen` releases that reference;
the kernel then tracks the lifetime through workload-owned descriptors. Native
`accept` and repeated `listen` preserve the socket's loopback confinement. Closing
the last workload reference to a listener removes it without waiting for registry
collection. Broker source descriptors always use close-on-exec independently of
the workload's requested descriptor flags.

## CDI policy provenance

The workload resolves trusted CDI context into filesystem requirements. Library
mounts expand to their parent directory; the expanded path must pass the same
broad-root rejection as other CDI destinations. Specs are trusted host
administrator input. A shared-library parent grant also makes sibling files
readable, so administrators must choose library directories accordingly, including
when a spec places libraries under `/etc`, `/home`, or `/root`. These checks do
not turn administrator-authored specs into an untrusted-input interface.
CDI enrichment adds only spec-derived paths; it does not grant all of `/sys`.

`WorkloadLaunchContext` retains derived filesystem requirements and required GIDs
separately from the authored policy. The initial process launcher and retained
exec executor share this context. Protobuf and boundary policy messages carry
no derived requirements or GIDs; the workload resolves them from trusted CDI context.
The sandbox processes deduplicated CDI targets sequentially: open a target,
validate its type and broad-root object identity, add matching Landlock rules
using that same descriptor, and close it before opening the next target.
Targets covered by authored ancestors are validated without adding a rule.
Only path requirements and root identities are retained; the number of open
CDI descriptors does not grow with the spec. Symlinks to legitimate library
directories remain supported. CDI validation and enforcement failures abort launch, including
when the authored Landlock compatibility is best effort. Authored paths retain
their configured opening behavior; absent authored paths can still be skipped.
Ruleset construction and enforcement remain mandatory when CDI filesystem targets
are present, so failures cannot silently discard CDI confinement.

Projected specs reside under `/.openshell/cdi-specs`, which the mandatory baseline
excludes from agent access independently of authored grants. Fixture tests use
the production resolver with injected workload mount observations; real Linux
mount-state tests verify the OS inspection separately.

Original CDI mount destinations remain separate from expanded library parents.
The workload classifies their effective read-only flags rather than trusting
spec option defaults, and checks original directory mounts for writable
submounts using one mount-table snapshot per pass. Ordinary writable file and
directory mounts are rejected, even when an exact or ancestor `read_write`
grant covers the destination. Dedicated authorization for CDI host writes is
not currently supported. The sequential Landlock pass rechecks mount access
on its opened descriptors and rejects persisted writable requirements too.
CDI does not add write access to `/proc`; existing thread-name mediation applies.
Required groups must already be supplied by the container runtime. The sandbox
checks membership before both the initial process launch and subsequent execs.

CDI Unix socket mounts are recorded as exact socket destinations, separately from
ordinary file mounts. Their opened objects must remain Unix sockets at each
launch or exec. They do not derive filesystem grants, expand to parent
directories, or require writable filesystem grants, regardless of mount flags.
Communication follows the existing Unix IPC and inode permission checks; this
validation does not pin the endpoint for later pathname-based connections.
