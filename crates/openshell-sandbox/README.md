# Sandbox runtime

`openshell-sandbox` owns the Linux workload isolation mechanisms and their kernel
qualification probes. The `linux` module contains seccomp notifications and child
filters, task-memory access, process-signal mediation, procfs descriptor lookup,
socket identity, Landlock qualification, and the workload launch thread.

`sandbox::linux` composes policy enforcement. The top-level `linux` module owns
the lower-level mechanisms used by that orchestration and the boundary server.
Unsafe kernel ABI, process-launch, and descriptor-ownership operations stay in
this runtime crate behind safe APIs where their contracts can be enforced.

Landlock policy anchors are resolved relative to open directory descriptors.
Symlinks are followed only through ancestors that the workload neither owns nor
can write, preserving system aliases while rejecting mutable workspace links.
The rule uses the resolved descriptor directly. Unsafe resolution and an empty
effective allowlist fail the launch independently of Landlock compatibility;
they cannot trigger the best-effort fallback to baseline-only restrictions.

The network broker retains source socket descriptors only while preparing a
workload endpoint. A successful connection or `listen` releases that reference;
the kernel then tracks the lifetime through workload-owned descriptors. Native
`accept` and repeated `listen` preserve the socket's loopback confinement. Closing
the last workload reference to a listener removes it without waiting for registry
collection. Broker source descriptors always use close-on-exec independently of
the workload's requested descriptor flags.

A boundary configured with `RuntimeInitiatedTlsTcp` binds no listener. It dials
only the driver-provided supervisor addresses, which must be concrete,
non-loopback, and share one port, and serves TLS and gRPC over that outbound
connection. It keeps one spare connection that the supervisor has not yet used
and dials a replacement when the supervisor starts HTTP/2 on it or the spare
closes. Live connections keep the same disconnect, freeze, and recovery-deadline
handling as listener mode, and the workload still cannot connect to the control
port.

A runtime of a supervisor shared by several sandboxes (one with a route handle)
names its route in a version 2 preface on every dial and follows the
supervisors' redirects, on the same port and never on loopback, at most two
hops. A supervisor that closes the negotiation without replying, as one from
before version 2 does, is dialed again with a version 1 preface and treated
as a lone supervisor; this changes only routing, since TLS pinning, request
authentication, and takeover grants are unaffected. It keeps a spare at the member whose connection it last confirmed, its
authenticated owner; an unauthenticated accept never makes a member the
owner. Once a supervisor names itself a pool member or redirects it, the
runtime also dials the configured addresses past every known member every 15
seconds, up to three times, so a member that hosts the route without a spare
gets one: a previous owner that stays reachable after the gateway granted the
route elsewhere, holding an unused spare, cannot keep the new owner from the
runtime. A lone shared supervisor never names itself, so it holds the one
spare and is never probed. The runtime keeps at most three unused spares, one
per member, and never closes an established connection to refresh routing. A
member's address grants nothing: a later term at a fenced owner's address
authenticates with its own grant. A retired connection that does not shut down
gracefully within two seconds, such as an unused spare, has its transport
dropped.

When `AgentSpec::otlp_relay_active` is set, `child_env::apply_otlp_relay_env`
gives every workload process (main, exec, and SSH) `OTEL_EXPORTER_OTLP_ENDPOINT`
pointing at the relay address, `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf`, and
`none` for `OTEL_EXPORTER_OTLP_COMPRESSION` and
`OTEL_EXPORTER_OTLP_TRACES_COMPRESSION`, and removes any inherited
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`. These defaults apply after the provider
variables. If the creation request or a per-exec environment names a generic
or traces-specific OTLP endpoint, the runtime injects nothing, and the
workload exports to that endpoint under the sandbox's network policy. An
endpoint in the image `ENV` does the same for the main process; exec children
start from a cleared environment (`ChildEnvironment::Cleared`), never see the
image's endpoint, and still get the relay default.

## Supervisor takeover

The boundary advertises `openshell.sandbox.supervisor-takeover`. A replacement
supervisor process may attach to a running generation only with a
gateway-signed takeover grant for a later credential epoch, its bearer of that
epoch, and the grant's supervisor process identity. The attach is staged and
promoted at confirmation, which advances the accepted epoch, pins the new
process, and closes every connection of the previous owner; credentials of
earlier epochs are refused from then on. Refused attempts emit an OCSF
configuration-state event and a `sandbox-supervisor-takeover-denied` finding.

Attach and confirmation are serialized, and the registry checks an attach
before it binds anything. Owner operations (exec, signals, termination,
provider updates, network decisions, DNS answers) hold an ownership guard from
authorization through their effect, and a promotion takes it exclusively, so
none of the replaced owner's operations takes effect afterwards. The guard is
asynchronous: tasks on the runtime's workers wait for it without blocking
them. A confirmation replay on the connection in force promotes nothing and
skips the guard. Promotion and the supervisory state change together, so a
replacement lost mid-promotion leaves the workload frozen under a fresh
recovery deadline. Each supervisor offers a recovery deadline when it attaches
(10 to 300 seconds; the runtime refuses any other before binding anything), and
the deadline of the connection in force when supervision is lost bounds the
freeze: 30 seconds without an offer. A supervisor pool offers 60 seconds unless
the gateway configures another.

The runtime keeps the trust-on-first-use executable pins of the generation
(`binary_pins`): the first digest it offers for each path, from its own
measurements. A contradicting identity is offered as a resolution failure,
which every supervisor denies, so a replacement with an empty cache cannot pin
a binary the workload replaced.

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
