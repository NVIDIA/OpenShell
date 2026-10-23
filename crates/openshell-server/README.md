<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# OpenShell gateway server

The server owns control-plane RPCs, authentication, provider credential delivery,
and sandbox lifecycle orchestration. The `openshell-gateway` crate composes the
server with selected compute drivers.

## Sandbox launch identity

A new start, including an automatic restart, commits a fresh runtime generation
and an incremented authorization epoch before invoking the compute driver.
The launch session ID is derived from the durable sandbox ID and generation.
Retries reuse that generation and session, including after gateway restart.
Credential renewal retains both; credentials for an older launch cannot
authorize the new one.

## Shared supervisor pool

The `SharedSupervision` the gateway hands a compute driver that asks for it
always coordinates a pool of shared supervisor hosts, at any member count; the
driver itself is unchanged. `[openshell.gateway.supervisor_pool]` only tunes it
(`recovery_timeout_secs`), and the gateway refuses the table when no in-process
driver uses the shared supervisor. `supervisor_pool` keeps the
pool's durable state and reconciles it every two seconds on every gateway
replica, independent of which replica runs the compute driver's watch:

- **Membership.** The replica serving a member's host stream refreshes its
  `supervisor_pool_member` record from a task of its own, every two seconds and
  at once when a member attaches, leaves, or detaches, each write bounded, so a
  slow reconciliation pass never lets a served member expire. Only the member's
  newest stream (by accept time) writes the record, so a replica still holding
  a stale stream of the same process cannot overwrite it. A record older than 15
  seconds is dead; a member that announces it is leaving drops out at once; a
  member whose process changed lost every instance its previous process owned.
  The timings members and replicas share, and the reconnect budget that keeps a
  member reconnecting past an unresponsive replica well inside the TTL, are in
  `openshell_supervisor_control::pool_timing`.
- **Listings.** A pass reads each record type page by page after an immutable
  key (`list_by_type_after`), so a row removed meanwhile shifts nothing out of
  the listing. A listing is still not a snapshot, so before a pass drops an
  owner its previous view had, or an instance that view or an owner names, it
  reads the record by key; a failed read fails the pass, which then publishes
  nothing.
- **Desired set.** A launch records the instance (`supervisor_instance_assignment`)
  before anything else. The record holds only the handle of the launch
  material, which the configured credential store keeps, as it keeps sandbox SSH
  host keys. Every replica derives the desired set from these records and loads
  the material of instances owned by members it serves. Recording takes single
  atomic store writes and holds no lock: it reserves the route with a row named
  by the route and identified by a fresh writer token, stores the material, has
  a `supervisor_instance_material_candidate` row own the handle, and publishes
  by advancing exactly its reservation's version. A launch publishes its
  record as `Admitting`, which is not desired (nothing places, charges, or
  grants it) and keeps its candidate; a driver recovery's backfill publishes
  directly. Collection deletes a candidate's material only once its recording
  no longer holds its reserved or admitting row, after which that recording
  can never publish or be admitted; a reservation or admitting record older
  than two minutes (a stalled, failed, or crashed launch) is fenced by
  removing it at its version, and its material is then collected. A
  withdrawal removes the material and then the record, or fences a reserved or
  admitting row; an ended generation
  (sandbox gone, replaced, stopped, or deleting) is withdrawn by the sweep; and
  the compute driver's recovery backfills instances it runs without a record and
  withdraws records published before its listing that it no longer lists.
- **Placement and ownership.** A launch admits its instance on the live member
  the consistent-hash ring prefers (`gateway_ring`): one transaction creates
  the owner record, charges the member's capacity, and publishes the
  `Admitting` record, conditioned on that record's version, so an owner always
  has its published instance and a removed record never gains one. A member at
  its 256-instance capacity is skipped. With no live member, or none with
  room, the launch is refused with that reason: it removes the admitting
  record it created, only at the version it created (a concurrent launch of the same
  generation that admitted it first wins), and then that record's candidate
  and material; a removal that fails is left to fencing. One
  `supervisor_instance_owner` record per instance names the member, its
  process, and the ownership term (the sandbox's credential epoch). Records
  change only by compare-and-swap, and a live owner keeps its instances.
- **Capacity.** One `supervisor_pool_capacity` record per member lists the
  routes whose owner record, in any phase, names the member. Every owner
  create, move, or removal is one `Store::write_atomically` transaction with
  the capacity records it changes, conditioned on all of their versions, and a
  full member is refused before anything is written. Two replicas admitting
  the last slot of a member, by launch or takeover, therefore admit one, and a
  stalled admission whose slot was taken meanwhile fails. A takeover prefers
  the route's previous member, whose record already lists it, so a member
  whose process restarted re-adopts its instances even when every member is
  full.
- **Takeover.** Only an instance whose owner failed or left moves. A replica
  records the intent (new owner, next term, the process the runtime will pin,
  a new token lineage), advances the sandbox's persisted epoch with
  `advance_identity_for_takeover`, which revokes the previous owner's
  credentials on every replica, and then grants it. Any replica completes an
  interrupted intent; a stopping, stopped, or deleted sandbox, a replaced
  generation, or a term another lineage holds cancels it. A replica that just
  started waits 30 seconds before taking over, so members reconnect after a
  gateway restart first. The takeover log names its `cause`: `expired`,
  `leaving`, or `restarted`.
- **Credentials.** Each replica mints a takeover term's grant and session
  credentials only for members it serves, from the granted record and the
  persisted identity, and mints them again after half the grant's lifetime.
  Other replicas send the term without credentials; a host that already runs
  it keeps it.

- **Observations.** The replica serving an owner records what the owner reports
  of its instances (`supervisor_instance_report`; no error text), one record per
  instance and ownership term, and every replica judges an instance whose owner
  streams elsewhere from the record of the current owner term, so launch
  readiness and bootstrap completion do not depend on which replica a member
  reached. A report counts for a term only once the member's stream
  acknowledged the snapshot that installed the term, and only if the pass's
  owner record shows that term, so a status from an earlier term is never
  recorded as a later one. A record is rewritten whenever it differs from the
  report, so one another writer replaced is repaired. Reports are listed before
  owners, and only records of terms older than the listed owner, or of
  instances without one, are removed.

Owner records of withdrawn instances are removed once their generation ended,
or two minutes after the withdrawal, after their owner was told to stop them.
Pool members still authenticate with the one shared supervisor token, so a
member identity is asserted by its hello rather than bound to its Pod.

## Optional in-process sandbox updates

`SharedComputeDriver` retains the generated baseline compute-driver trait, and
`ComputeDriverInstance` retains its existing variants. Existing compiled drivers
and factories need no new trait implementation or registration method.

A supporting factory overrides `ComputeDriverFactory::build_with_configuration_updates`
to return its ordinary instance plus a separately registered updater. The default
calls `build` and returns no updater. External drivers serve
`ComputeDriverConfigurationUpdates` on their existing endpoint. Workload updates
require `openshell.compute.update-sandbox-configuration` for image, command, or
environment changes. Metadata-only replacements use one database CAS and update
the label index without invoking a driver.

New updates require operator activation and compatible gateway membership.
Accepted updates recover from private durable intent at startup and in periodic
reconciliation, including when activation is subsequently disabled. Recovery
pages through a partial database index of pending private update records instead
of scanning sandboxes or completed receipts. Acceptance and completion maintain
the indexed status in the same transaction as the intent and lifecycle interlock.
Each gateway keeps automatic recovery backoff in memory. Failed attempts wait
1, 2, 4, 8, then 15 minutes; each failure log includes the attempt and retry delay.
Replicas retry independently, and a gateway restart resets its backoff. A new
operation starts without delay. Completed or deleted updates are removed from
the backoff map as recovery observes them.
An authorized `UpdateSandbox` with no selected fields and the current resource
version resumes immediately, bypassing backoff without reconstructing its selections. Completion retains the
exact operation receipt for idempotent completion across replicas; a newer update
invalidates it. Ambiguous results retain the baseline provisioning interlock.
Explicit deletion can supersede a pending update: the driver only patches the
original immutable resource and never creates a replacement. The Deleting CAS
prevents delayed completion. Cleanup bypasses the pending-driver guard only when
the pending operation ID matches the persisted update intent. Final removal
deletes the sandbox and private intent atomically, retaining that evidence if
cleanup fails or loses a resource-version race.

Metadata replacement preserves gateway-owned keys, including retention, while
other user keys under OpenShell domains remain editable. Completion preserves
later annotation merges accepted through `UpdateConfig`.

A provisioning timeout can be repaired by Stop after its original driver work
settles and cleanup completes. Stop exposes Stopped without discarding the timeout
diagnosis or storage. This lifecycle behavior also applies when updates are disabled.

## Static credential delivery

Provider environment entries carry placement from the owning credential's
profile declaration. The gateway withholds individual entries without usable
placement and reports `CredentialsWithheld`. Placement participates in both
ordinary credential identity and stable handle derivation, so changing it
revokes incompatible retained workload references.

Polling supervisors must advertise placement enforcement before receiving static
material. Configuration push requires the same capability for the entire session;
older supervisors fall back to polling and its credential withholding checks.
