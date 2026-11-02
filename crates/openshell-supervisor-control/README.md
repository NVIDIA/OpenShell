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

- `controller`: `SupervisorHostController` serves the shared supervisor,
  which is always a pool (high availability): several hosts (pool members)
  are served at once and each instance has one durable owner: a member, its
  process, and an ownership term. Every member names itself in its hello; a
  hello without a member, or with an invalid one, is refused with the
  `OPENSHELL_SUPERVISOR_POOL_*` setting to fix. One session per member: a
  newer connection epoch of the same member process or a new process of the
  member supersedes its stream, a delayed older hello is refused, and reports
  from superseded streams, acks of revisions never sent, regressing acks,
  and oversized reports are dropped. A stream ends when the token that opened
  it expires; hosted instances keep running. The pool's recovery deadline
  defaults to `POOL_RECOVERY_TIMEOUT_SECS` (`set_recovery_timeout_secs`
  overrides it). The gateway's pool reconciler replaces the `PoolView` as a whole
  (`update_pool`): the desired set from the gateway's durable records, the
  owners, the launch material this replica loaded, and the latest recorded
  reports of owners served elsewhere. Owners placed, instances launched, and
  instances withdrawn here since the records were listed are kept as they are.
  Each member's snapshot carries the instances its process owns (a takeover
  term with its credentials, or with the term alone when another gateway
  replica minted them), `stop_routes` for withdrawn instances it owns,
  `keep_routes` for owned desired instances whose material this replica has
  not loaded yet, the route directory for runtime redirects, and the recovery
  deadline its hosts offer each runtime (`POOL_RECOVERY_TIMEOUT_SECS`, 60 s,
  unless configured). Omission means release, never stop. Nothing is sent
  before the first view. An instance is judged by its owning process's
  session, or by that owner term's recorded report on other replicas.
  Placement keeps each member at 256 instances. Each stream remembers the term
  of every route its sent snapshots assigned and the revision that installed
  it; `member_reports` attributes a reported status to that term only once the
  stream acknowledged that revision, so the gateway never records an earlier
  term's status under a later one. `membership_changes` changes when a member
  stream attaches, ends, or announces leaving, so the gateway refreshes
  membership records at once. The gateway closes a member's stream after
  `pool_timing::GATEWAY_SILENCE_TIMEOUT` of silence, and drops a member that
  stops reading as soon.
- `pool_timing`: the timing contract between pool hosts and the gateway: the
  15 s membership TTL, the 2 s record refresh, 1 s heartbeats, host silence
  detection and bounded reconnect attempts, and `reconnect_budget`, the worst
  case for a member to reconnect past an unresponsive replica and be refreshed
  elsewhere, which a test keeps well inside the TTL.
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
  workload runs. For a pool, the gateway's installed `InstancePlacement`
  durably records the instance and its launch term's owner before the
  assignment, and a launch no member can take fails with the pool's reason
  (`LaunchError::Unplaced`). A pool's withdrawals are removed from the durable
  records by the gateway, and a recovery reconciles those records with the
  driver's listing instead of replacing the desired set. `begin_recovery` captures
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
