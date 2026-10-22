# Shared supervisor control

`openshell-supervisor-control` is the gateway side of a supervisor shared by
many sandboxes. One shared supervisor process hosts the sandbox instances (one
running generation of a stable Sandbox each) of a gateway; the gateway owns
which instances it hosts and serves that set to it over the private
`openshell.supervisor.host.v1` stream, which the supervisor opens with a
gateway-minted supervisor token. Everything about that control relationship
that is not specific to a compute platform lives here, so a compute driver
adds a shared supervisor by adapting storage and infrastructure, not by
re-implementing the control contracts.

## Modules

- `controller`: `SupervisorHostController` holds the desired set of
  `SandboxInstanceAssignment`s and serves it to the host. Desired state is
  uninitialized until the complete set has been derived from durable records
  once, so a restarted gateway never presents an empty set as authoritative;
  an explicit empty set after initialization does stop instances. Full
  replacements are compare-and-replace against the revision read before the
  records were listed. One host session at a time: a newer connection epoch
  of the same host process or a new process supersedes the current stream, a
  delayed older hello is refused, and reports from superseded streams, acks
  of revisions never sent, regressing acks, and oversized reports are
  dropped. A stream ends when the token that opened it expires; hosted
  instances keep running. At most 256 instances are assigned.
- `registration`: `SandboxInstanceRegistration` is the JSON launch material
  one assignment carries and the driver persists with the generation. It
  grants the supervisor exactly that generation's gateway and Sandbox Protocol
  credentials. `validate` binds route, sandbox, generation, launch session,
  and proxy CA together; `from_launch_material` and `from_assignment` decode
  bounded material without quoting values, which include credentials.
- `status`: `SandboxInstanceStatusReport` and its phases, converted to and
  from the stream's status message; an unknown phase reads as a failure.
- `coordinator`: `SharedSupervision` is what the gateway constructs and hands
  to the compute driver. `launch` validates the driver's registration,
  persists the encoded launch material through the driver's operation, and
  only then assigns the instance; a host at capacity is refused before the
  workload runs. `begin_recovery` captures
  the revision before the driver lists its durable records and
  `complete_recovery` reuses current assignments, reads the rest through the
  driver's operation, binds each to its recorded route and sandbox, and keeps
  the previous set when any read fails; a list that raced a lifecycle edit is
  refused and derived again. `supervision` and `wait_for_ready` interpret the
  host's observations in one place: a disconnected host is unknown, a host
  that has not reconciled to the assignment yet is degraded, and only a host
  that reconciled past it without hosting the instance, hosts it for another
  sandbox, or reports it ended makes it unavailable.
- `credential`: `deliver_credentials` delivers the current supervisor token
  and every renewal through the driver's operation, retrying a failed
  delivery until it succeeds or a newer token supersedes it.
- `proto`: the private wire protocol, generated in `openshell-core`.

## Ownership

The gateway (`openshell-server`) constructs the `SharedSupervision` when the
selected in-process driver asks for it, keeps the controller to serve the
host's `Attach` stream and to publish the token it mints and renews at half
its lifetime, and gives the coordination to the driver. The driver
(`openshell-driver-kubernetes` today) records placements, persists and reads
back launch material, provisions the workload's path to the supervisor, checks
its own infrastructure evidence alongside the coordinator's verdict, and
delivers the token into the Secret the supervisor Pod mounts. The supervisor
(`openshell-supervisor`) consumes only the registration and status types; it
owns admission, per-instance runtime, routing, and cleanup.

## Gateway leadership

With replicated gateway storage, the existing sandbox reconciler lease also
owns supervisor assignment publication. A standby refuses `Attach` with
`UNAVAILABLE`; the supervisor opens a fresh connection to the gateway endpoint
on retry. That endpoint must reach all eligible gateway replicas, without
session affinity pinning the supervisor to a standby. Single-replica storage
keeps a local publisher and does not acquire a database lease.

Acquiring the lease starts a new term with an uninitialized desired set. The
compute driver's initial watch recovers the complete set from durable records
before any snapshot is sent. A new term invalidates an older recovery pass.
Losing or releasing the lease closes the assignment stream before worker
cleanup, and a conservative monotonic deadline stops publication even when a
renewal cannot finish. Hosted instances keep running while reconnecting.
Only the publisher mints supervisor tokens; the existing delivery path carries
them to the supervisor.

Foreground sandbox operations still run on every gateway replica. Their launch
material and lifecycle changes are durable, so the leader's existing driver
reconciliation discovers creates and withdrawals from other replicas. The
leader includes credential-free, generation-routed instance observations in
the same compare-and-swap write that renews the reconciler lease. Standbys use
that view for readiness; they never publish assignments from it. Missing,
unreadable, or expired observations mean unknown supervision, not an absent
instance. A route the leader has not recovered yet stays pending, even if
its connected host has already acknowledged a snapshot without that route.
Only an acknowledged assignment can establish that an instance is absent.
Observations are eventually consistent with lease renewals (10
seconds) and standby polls (5 seconds); driver reconciliation can add up to its
normal interval before a remote lifecycle change reaches the supervisor.

This coordinates gateway ownership of one shared supervisor. It does not add
supervisor HA, scheduling, autoscaling, or recovery from supervisor process loss.
