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

A blocking loopback `connect` waits on a small pool of reusable worker threads
rather than a thread per call. A job never queues behind a busy worker: it goes
to a parked worker or starts a new one, and a pool with neither refuses with
`EAGAIN`, so a slow or full listener cannot delay another connect or the
dispatcher. Three bounds hold together. Each job carries an admission slot
shared with external opens (256 in all), which its worker releases only after
the pool records that worker parked or retired. Live workers are capped at that
same number under the pool's own lock. At most four workers stay parked, for up
to 30 seconds; a worker that finishes beyond that exits at once.

`setsockopt` calls for `TCP_NODELAY`, `SO_REUSEADDR`, and `SO_KEEPALIVE` run in
the kernel without a notification. The broker decides `setsockopt` from its two
scalar arguments and would continue these pairs. Every other pair, and any
level or option that does not fit a non-negative C `int`, still notifies and
keeps the broker's `EPERM` and `EINVAL` results. The active qualification
probe exercises both sides.

## Provider files

Provider files appear to the workload beneath `/run/openshell/providers`.
Every workload `open`, `openat`, and `openat2` notifies the broker, which
serves a provider path by injecting a read-only descriptor for a sealed
in-memory file and continues every other open.

Each published file is an immutable revision backed by one sealed in-memory
file (`linux::sealed_file`, the backing the CA trust files below share). The
runtime creates that file when the revision is published, not when the
workload opens it: it writes the content, seals the file against writes,
growing, shrinking, and further sealing, confirms every seal is in place, and
keeps only a read-only descriptor for it. Each workload open reopens that
descriptor through the runtime's own `/proc/self/fd`, opened once and verified
to be procfs, so every open gets its own read-only open file description and
file offset, positioned at the start. The runtime injects that descriptor and
completes the workload's syscall in one `SECCOMP_ADDFD_FLAG_SEND` operation.

An update prepares every new revision before it replaces the published set in
one step, so a failed update leaves the previous set in place. A file whose
bytes did not change keeps its revision. Opens after an update see the new
revisions, descriptors opened earlier keep the bytes they opened, and a
detached file is `ENOENT` for later opens.

All opens of one revision refer to one file, which the workload owns: it can
change that file's mode or reopen a descriptor for writing. Neither reaches
the content, which the seals protect, and the runtime restores the mode if it
denies an open. The runtime holds one descriptor per published file, at most
64.

The broker classifies each open from an exact copy of the first six bytes of
its path. Six bytes identify a `/proc/` path and the shared start of a
provider path and a CA trust path; only those candidates have their whole path
read and decided. An open whose first six bytes cannot be read, or match
neither, continues, and unrelated `openat2` calls do not require a copy of
their `open_how`. Every continued open remains subject to the kernel and
Landlock.

## Supervisor CA trust files

The supervisor's public CA certificate and combined trust bundle (system CAs
plus that certificate) are installed as real `0444` files at
`/run/openshell-supervisor-ca/material/ca.crt` and `ca-bundle.crt` before the
workload starts; the child Landlock grants keep the directory readable and the
TLS environment variables point there. Both are public material, and no
private key is delivered.

The broker also holds the same bytes as one sealed pair, and a plain read-only
`open` or `openat` of exactly one canonical path receives an injected
descriptor, the same immutable delivery as a provider file. Every other open of
those paths continues to the kernel as before: `stat`, `O_PATH`, `O_DIRECTORY`,
`openat2`, write-capable opens, relative opens, and aliases such as a path
through `..` all reach the installed files, which remain the compatibility
source.

The pair is published after installation and before the spawn, replaced only
as a whole, and never touched by a provider file update; a start without CA
material clears it. A pair is refused, and nothing changes, if either file is
empty, exceeds the 1 MiB control frame bound (the CA files have their own
bound, since a system bundle is often larger than a provider file), or the
bundle does not contain the certificate.

## Runtime boundary transport

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
