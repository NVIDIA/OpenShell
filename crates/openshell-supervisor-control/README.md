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
  stops reading as soon. `HostAccepted` carries this replica's peer endpoint
  (`set_peer_endpoint`); the host dials its instances' sandbox sessions
  there, so each session runs on the replica serving its supervisor.
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

## Prepared runtimes

The private assignment protocol supports a prepared runtime before it belongs
to a logical sandbox. `PreparedRuntimeRegistration` carries an unassigned
runtime descriptor with its generation, launch session, physical resource
claims, workload identity, provisioning evidence, routed endpoint, and TLS pin.
It carries no operational credentials or command. A `prepared` assignment
reserves one of the host's 256 slots and registers its route, allowing the host
to authenticate and hold the runtime's idle TLS connection. `PREPARED` reports
an installed reservation; it does not assert connection health or workload
readiness.

Activation replaces that assignment with a `SandboxInstanceRegistration` on
the same route. Only the descriptor's logical sandbox ID may change. The host
transfers the existing route registration, including its queued connections,
into the instance's backend. Activation needs no additional slot. A repeated
preparation is idempotent, conflicting preparation is rejected, `keep_routes`
retains it during material loading, and withdrawal releases it. An active
instance cannot be downgraded to prepared.

`SharedSupervision::prepare` records the preparation, its owning workspace,
bootstrap credential epoch, supervisor process, and capacity charge durably
before the driver releases the runtime. Every gateway replica can recover this
reservation. Prepared and active runtimes share the same capacity limit.
Ordinary sandbox-generation recovery excludes preparations; their lifecycle
belongs to the warm-pool controller.

`warm_pool` defines the bounded creation journal shared by gateway replicas.
`warm_runtime_trust`, `warm_pool_state` and `update_warm_pool` expose public
verification material and conditional journal writes through the installed
placement authority. No Sandbox credentials are issued for pool inventory.
The journal records provisioning/retirement intent, not allocation authority.

For a `PREPARED` wire report only, `ready` means the host has a TLS-authenticated
parked connection. `prepared_connection_ready` reads that observation from the
current acknowledged owner. Ordinary instance-status conversion still masks
this bit, so a spare cannot appear as a ready logical Sandbox. The host samples
parked connections on its existing heartbeat cadence. The router reads idle TLS
streams to detect closure and preserves at most 64 KiB of early HTTP/2 bytes for
activation. The observation cannot guarantee that a peer stays connected.

`SharedSupervision::prepared_runtimes` recovers admitted preparations for one
workspace, including their physical resource claims, bootstrap epoch, and
original supervisor process. Owner availability is a reconciliation hint;
activation checks it again. Read or material-loading failures return an error,
not an empty inventory. The listing can race claims and other pool changes.

Cleanup calls `SharedSupervision::release_preparation` with the exact revision
from the listing. Release compares the reservation ID and record version and
atomically transfers its material to cleanup, retaining a retirement fence for
the physical route. If a claim or replacement wins,
release returns `Changed` and the controller must leave the physical runtime
alone. Only `Released` permits cleanup by immutable resource UID; `Absent` is
an observation, not a fence against concurrent preparation. Host stop and capacity reclamation follow through
pool reconciliation. Do not use the unconditional `withdraw` method for warm
cleanup, and allocate a fresh route for each replacement runtime.

`retire_preparation` also handles runtimes that never reached admission. The
driver first journals retirement on its physical resource, then supplies its
workspace, route, generation and bootstrap epoch. Retirement creates a fence if
the route is absent, or conditionally retires a matching unclaimed record. A
claim wins or loses against the same record version. Retrying a completed
retirement returns `Released`; preparation can never reuse that route, even
after a gateway restart. These small records are retained without an expiry;
they hold no credentials or capacity. A claimed warm runtime retains its origin
so stopping the assigned Sandbox also permanently retires the physical route.
Prepared assignments are published only
by durable reconciliation, so a delayed preparation response cannot locally
republish a retired route.

After persisting its claim, the driver calls `SharedSupervision::activate`.
The driver supplies both the expected Sandbox launch generation/epoch and the
prepared runtime's registration. Only a Provisioning or Starting Sandbox can
claim a runtime. The gateway verifies the physical descriptor, workspace, and
expected identity, then mints a resource-bound Sandbox Protocol token and a new
gateway token lineage. One transaction adopts the prepared generation, launch
epoch, and TLS session in the Sandbox, replaces the preparation's material, and
binds the owner to the Sandbox. The supervisor process and capacity charge stay
unchanged. Concurrent claims (including two runtimes for one Sandbox), withdrawals,
and Sandbox identity changes are fenced by record versions.

Activation returns the committed registration with gateway-issued tokens. The
driver must persist that result for recovery; tokens in the request are replaced.
A retry of the winning registration returns the same material while that launch
remains current. The runtime's physical claims and TLS session are stored with
the Sandbox identity, so credential renewal and takeover retain them. In
particular, renewal before the first protocol call still supplies the binding
the unassigned runtime requires. A subsequent fresh start clears the binding.

Prepared reservations remain pinned to their original supervisor process.
Gateway restart or host-stream reconnection recovers them without migration.
An expired, leaving, or replaced supervisor process cannot activate a prepared
runtime. The warm-pool controller must conditionally release and replace that runtime;
there is no unassigned credential epoch with which to authorize takeover.
This also avoids redirecting an idle runtime away from a reachable old owner.

The Kubernetes driver's OpenShell-owned pool persists per-Pod TLS bootstrap
material before calling `prepare`, then releases its scheduling gate. Creation
selects a compatible connected spare, journals its claim with a CR CAS and a
Pod-owned Secret, and calls `activate`. Recovery completes interrupted claims;
pool reconciliation replaces unusable preparations. Activation publication uses
durable pool reconciliation so a delayed response cannot locally revive a stopped
route. Dedicated pools use the same journal and activation contracts with a
separate coordinator: no shared membership or capacity rows are created. The driver
binds the dedicated Pod UID, observes startup-probe success, and delivers the
committed registration through the dedicated supervisor’s pending
`RegisterSupervisor` stream. Initial gateway TLS trust is mounted before warming;
claim credentials and the proxy CA arrive in the response. The supervisor adopts
the held TLS route and enters normal dedicated startup.

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
