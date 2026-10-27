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
