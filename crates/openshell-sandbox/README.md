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

Provider files appear to the workload beneath `/run/openshell/providers`. The
bootstrap selects one of two deliveries before the workload listener exists.

**Virtual** delivery is the default and the only one for a bootstrap without
`provider_file_store`. Every workload `open`, `openat`, and `openat2` notifies
the broker, which serves a provider path by injecting a read-only descriptor
for a sealed in-memory file and continues every other open.

Each published file is an immutable revision backed by one in-memory file. The
runtime creates that file when the revision is published, not when the
workload opens it: it writes the content, seals the file against writes,
growing, shrinking, and further sealing, and keeps only a read-only descriptor
for it. Each workload open reopens that descriptor through the runtime's own
`/proc/self/fd`, so every open gets its own read-only open file description
and file offset, positioned at the start.

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
its path. Six bytes identify a `/proc/` path and the start of a provider path;
only those candidates have their whole path read and decided. An open whose
first six bytes cannot be read, or match neither, continues, and unrelated
`openat2` calls do not require a copy of their `open_how`. Every continued
open remains subject to the kernel and Landlock.

**Native** delivery uses a store the driver provisions: one filesystem mounted
twice into the workload container.

| Mount | Access | Contents |
|---|---|---|
| Private root, beneath `/.openshell` | Writable | `public/` and `staging/`, owned by the workload identity |
| Public root, `/run/openshell` | Read-only | The store's `public/` directory |

The runtime and the workload share one UID, so file modes cannot separate them.
The mandatory Landlock baseline grants the workload no access right beneath
`/.openshell`, so through the private root it cannot open, list, create,
remove, rename, or truncate anything. The kernel refuses every write and
metadata change through the read-only public mount. Provider files keep mode
`0600`, as an injected descriptor reports.

The runtime builds each generation under `staging/`, which has no public path,
and exchanges it with `public/providers` in one `renameat2(RENAME_EXCHANGE)`.
The workload sees the previous generation or the next, never a partial one, and
no path exposes a staged or replaced generation. The public root is the parent
of `providers` because a mount of `providers` itself would pin the first
generation's inode.

A file descriptor opened before an update keeps reading the file it opened for
as long as it stays open. A directory descriptor has no such guarantee. The
runtime removes a replaced generation one second after replacing it, so that an
open already walking into the published directory at the exchange still finds
its file instead of failing with `ENOENT`.

The exchange moves the replaced generation out of `public`, the only part of
the store Landlock lets the workload read. An open caught between resolving
`providers` and opening its file then reaches a file whose parent directories
are no longer beneath the public root. A kernel with the upstream change to
Landlock's handling of disconnected directories (CVE-2025-68736) judges that
open by the read-only mount it came through and allows it. A kernel without
the change refuses it with `EACCES`, in a window of microseconds per update.

The runtime does not guess which kernel it runs on. After the store passes
validation and before the workload launcher or listener exists, it runs the
case once. A throwaway thread applies the workload's Landlock layers to itself:
the mandatory baseline and a filesystem policy that lists only the public
root. Landlock confines that thread alone, and the runtime joins it before
continuing. The thread confirms that the private root is closed to it, reads a
probe file by its public path, and holds the published directory. The runtime
exchanges that generation out to `staging`, and the thread opens the file again
beneath the directory it holds. The probe file carries no provider content and
is removed before startup continues.

| Probe outcome | Result |
|---|---|
| The open after the exchange succeeds | Native delivery |
| The open after the exchange fails with `EACCES` | Virtual delivery, once the store is proven empty |
| Anything else | Startup fails |

"Anything else" covers confinement that cannot be applied or does not hide the
private root, a probe file unreadable before the exchange, a step that times
out, and a probe generation that cannot be removed.

Linux 7.0 passes the probe. Under the Docker mounts, with the baseline alone
and with a user filesystem policy, no confined open by absolute path failed
across more than 10,000 exchanges; the ignored test
`confined_absolute_opens_survive_publication` measures that. No kernel without
the change was available, so the refusal path is tested by injecting the
outcome and by a real Landlock refusal on a store that is not a mount.

An update equal to the published generation exchanges and retains nothing,
unless the workload changed a published mode, in which case the generation is
replaced.

The store retains at most eight replaced generations and 1 MiB of their
content. An update that would exceed either bound first waits, for at most that
second, until the oldest ages out. A replaced generation whose removal fails
stays counted. If the bounds still cannot be met, the update fails before
anything is written and the published generation is unchanged.
One thread removes replaced generations and exits when none is waiting; the
next update retries a removal that failed.

Before selecting native delivery the runtime requires all of the following,
and removes whatever an earlier run left:

- The public root is `/run/openshell`, and the private root lies beneath the
  real `/.openshell` directory with no symlink on the way.
- `public` and `staging` are real directories on one filesystem, owned by the
  runtime's UID, and `public` holds nothing but `providers`.
- The public root is the same directory as `public`, on a read-only mount, and
  the private mount is writable.
- The filesystem supports the atomic exchange.

A declared store that fails any check stops startup. The runtime does not fall
back to virtual delivery: the driver mounted the store at the provider path,
where files from an earlier run could stay readable through a relative open
that path interception does not see. A driver that cannot provision a store
declares none.

A kernel that fails the capability probe described above is a separate case,
not a validation failure. The store is valid, and the runtime selects virtual
delivery only after it confirms that the store holds one empty `providers`
directory and nothing in `staging`, so no provider file remains at the
provider path. If the store cannot be shown empty, startup fails. Under this
fallback the runtime logs
`Provider files delivered virtually: kernel Landlock refuses opens in a replaced generation`,
intercepts every open, and adds no public-root grant to a user filesystem
policy.

With native delivery the listener filter lets `open` and `openat` run in the
kernel when their flags request read-only access and carry none of `O_CREAT`,
`O_TRUNC`, or `O_TMPFILE`. Every other open and every `openat2` still notify. A
user
filesystem policy that lists paths also receives the public root, read-only,
so provider files stay readable as they are under virtual delivery.

Landlock does not mediate `chmod` or `stat`. The workload owns the store's
files, so through the private path it can change their modes and can `stat` a
name it knows. A changed mode grants it nothing, because Landlock still refuses
the open; it can only deny the workload its own provider files until the next
update. The runtime restores the modes it needs before each update and at
startup, and each update publishes new inodes. Staged and replaced generations
have names from the cryptographic random source, so the workload cannot find
them to `stat`.

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
