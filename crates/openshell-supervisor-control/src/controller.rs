// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway side of the private supervisor host protocol
//! (`openshell.supervisor.host.v1`).
//!
//! The gateway owns the desired set of sandbox instances a shared supervisor
//! runs. The [`SharedSupervision`](crate::SharedSupervision) coordinator
//! publishes that set here on behalf of a compute driver; the gateway's gRPC
//! server hands each host stream authenticated by a supervisor token to
//! [`SupervisorHostController::attach`], which sends complete snapshots and
//! records what the host reports. The gateway also mints that token and
//! publishes each renewal here for the driver to deliver to the host.
//!
//! Desired state is uninitialized until the complete set has been derived
//! from durable records once. Nothing is sent before that, so a restarted
//! gateway can never present an empty map as authoritative and stop running
//! instances. An explicit empty snapshot, after initialization, does stop
//! them. Full resyncs are compare-and-replace against the revision read
//! before the records were listed, so a list that raced a lifecycle edit
//! never resurrects a withdrawn instance or discards a new one.
//!
//! Only the publisher owns desired state. A replica that does not publish
//! keeps none: its lifecycle edits are durable records that the publisher's
//! next recovery discovers, so admission on a replicated gateway is eventual.
//!
//! Exactly one host serves a gateway: a new attach from a newer connection of
//! the same host process, or from a new host process, supersedes the current
//! session; reports and acks from a superseded stream are dropped, and a
//! delayed hello from an older connection of the current process is refused.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Status, Streaming};

use crate::SandboxInstanceStatusReport;
use crate::proto::{
    AssignmentSnapshot, HostAccepted, HostGatewayHeartbeat, HostGatewayMessage, HostHello,
    HostMessage, HostStatus, SandboxInstanceAssignment, SandboxInstanceStatus,
    host_gateway_message, host_message,
};

/// Interval at which both ends send heartbeats on an idle stream.
pub const HOST_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
/// Silence after which the gateway closes a host stream.
const HOST_SILENCE_TIMEOUT: Duration = Duration::from_mins(1);
/// Bound on the host sending its hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on queueing one gateway-to-host message; a host that cannot drain
/// its stream this long is disconnected rather than stalling the session.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);
/// Gateway-to-host messages queued before the stream applies backpressure.
const OUTBOUND_QUEUE: usize = 16;
/// Most sandbox instances one shared supervisor host runs. The publishing
/// gateway refuses to assign beyond it, recovery leaves any excess
/// unassigned, and the host refuses snapshots beyond it.
pub const MAX_ASSIGNED_INSTANCES: usize = 256;
/// Metadata key marking a standby replica's `UNAVAILABLE` refusal of `Attach`.
///
/// Paired with [`STANDBY_REFUSAL_VALUE`], it lets the host retry leader
/// discovery promptly rather than backing off as it would from an outage.
pub const STANDBY_REFUSAL_METADATA: &str = "x-openshell-supervisor-host";
pub const STANDBY_REFUSAL_VALUE: &str = "standby";
/// Most instances one host status report may describe: every assignment plus
/// instances still being removed.
pub const MAX_REPORTED_INSTANCES: usize = 4 * MAX_ASSIGNED_INSTANCES;

/// Verified identity of a connected supervisor host: the claims of the
/// supervisor token that authenticated its stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostIdentity {
    /// Subject of the supervisor token (`openshell-supervisor:<gateway_id>`).
    pub subject: String,
    /// `jti` of the supervisor token.
    pub token_id: String,
    /// `exp` of the supervisor token (Unix seconds). The gateway ends the
    /// stream when it passes; the host reconnects with a renewed token.
    pub expires_at: i64,
}

/// The current supervisor token, as the gateway mints and renews it.
///
/// A compute driver delivers it to the supervisor process by whatever means
/// its deployment packaging provides; the Kubernetes driver writes a Secret.
#[derive(Clone, Debug)]
pub struct SupervisorCredential {
    pub token: openshell_core::jwt::SecretJwt,
    /// Unix seconds.
    pub expires_at: i64,
}

/// What the gateway knows about one assigned route on the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservedInstance {
    /// No host session is connected.
    NoHost,
    /// A host is connected, but this gateway has not recovered the route's
    /// assignment yet or the host has not reconciled the snapshot assigning
    /// or excluding it.
    Pending,
    /// The host reconciled to the snapshot assigning this route and does
    /// not host it, or to one omitting a route the latest complete recovery
    /// left unassigned.
    Absent,
    /// The host's latest report of the instance.
    Reported(SandboxInstanceStatus),
}

/// Credential-free observations carried by the gateway's existing reconciler
/// lease. Routes are generation-specific; an omitted route is unknown, never
/// evidence that a newly created instance is absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SharedObservation {
    Pending,
    Absent,
    Reported(SandboxInstanceStatusReport),
}

#[derive(Clone, Copy)]
enum Publisher {
    Standalone,
    Standby,
    Lease(Instant),
}

impl Publisher {
    fn active(self) -> bool {
        match self {
            Self::Standalone => true,
            Self::Standby => false,
            Self::Lease(deadline) => Instant::now() < deadline,
        }
    }
}

struct Assigned {
    assignment: SandboxInstanceAssignment,
    /// Snapshot revision that first carried this exact assignment.
    revision: u64,
}

#[derive(Default)]
struct Desired {
    initialized: bool,
    revision: u64,
    assignments: BTreeMap<String, Assigned>,
    /// Edits made before initialization, applied over the first full list.
    pending: BTreeMap<String, Option<SandboxInstanceAssignment>>,
    /// Routes the latest complete recovery listed but left unassigned (no
    /// launch material, or beyond capacity), each with the first revision
    /// whose snapshot omits it. Assigning or withdrawing a route clears it.
    excluded: BTreeMap<String, u64>,
}

impl Desired {
    fn snapshot(&self) -> Option<AssignmentSnapshot> {
        self.initialized.then(|| AssignmentSnapshot {
            revision: self.revision,
            instances: self
                .assignments
                .values()
                .map(|assigned| assigned.assignment.clone())
                .collect(),
        })
    }

    /// Insert or replace one assignment; returns whether anything changed.
    fn put(&mut self, assignment: SandboxInstanceAssignment, revision: u64) -> bool {
        match self.assignments.get(&assignment.route) {
            Some(existing) if existing.assignment == assignment => false,
            _ => {
                self.assignments.insert(
                    assignment.route.clone(),
                    Assigned {
                        assignment,
                        revision,
                    },
                );
                true
            }
        }
    }
}

struct HostSession {
    id: u64,
    identity: HostIdentity,
    instance_id: String,
    connection_epoch: u64,
    superseded: watch::Sender<bool>,
    /// Highest snapshot revision sent on this stream; acks beyond it are
    /// impossible and rejected.
    sent_revision: u64,
}

#[derive(Default)]
struct Observed {
    session: Option<HostSession>,
    /// Latest report of the current session.
    status: Option<HostStatus>,
    next_session: u64,
}

struct Inner {
    publisher: Mutex<Publisher>,
    /// Standbys read only lease-fenced observations, never another replica's
    /// desired state or credentials. The local deadline also bounds cached reads.
    mirror: Mutex<Option<(Instant, BTreeMap<String, SharedObservation>)>>,
    desired: Mutex<Desired>,
    /// Latest supervisor token the gateway minted; `None` until the first.
    credential: watch::Sender<Option<SupervisorCredential>>,
    /// Monotonic local revision, also bumped at the start of a new term.
    revision: watch::Sender<u64>,
    observed: Mutex<Observed>,
}

/// Gateway-owned desired assignments and observed status of one shared
/// supervisor host.
#[derive(Clone)]
pub struct SupervisorHostController {
    inner: Arc<Inner>,
}

impl Default for SupervisorHostController {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SupervisorHostController {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SupervisorHostController")
            .finish_non_exhaustive()
    }
}

/// Why a change to the desired set was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AssignmentError {
    /// A full resync was derived from a desired set that has since changed:
    /// `baseline` is the revision the caller read before deriving its list and
    /// `current` the one now in force; derive the list again from it.
    #[error("desired assignments changed from revision {baseline} to {current} during the resync")]
    Conflict { baseline: u64, current: u64 },
    /// The change would assign more instances than one host runs.
    #[error("the shared supervisor hosts at most {MAX_ASSIGNED_INSTANCES} sandbox instances")]
    Capacity,
    /// This replica does not publish assignments, so a full resync begun in
    /// an ended term is discarded.
    #[error("this gateway replica does not publish shared supervisor assignments")]
    Standby,
}

/// The refusal a replica that does not publish gives an attaching host.
fn standby_refusal() -> Status {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert(
        STANDBY_REFUSAL_METADATA,
        tonic::metadata::MetadataValue::from_static(STANDBY_REFUSAL_VALUE),
    );
    Status::with_metadata(
        tonic::Code::Unavailable,
        "reconnect to the gateway reconciler leader",
        metadata,
    )
}

/// Whether `status` is a standby replica's refusal of `Attach`, as opposed to
/// a transport or gateway failure.
#[must_use]
pub fn is_standby_refusal(status: &Status) -> bool {
    status.code() == tonic::Code::Unavailable
        && status
            .metadata()
            .get(STANDBY_REFUSAL_METADATA)
            .is_some_and(|value| value.to_str().ok() == Some(STANDBY_REFUSAL_VALUE))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl SupervisorHostController {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                publisher: Mutex::new(Publisher::Standalone),
                mirror: Mutex::new(None),
                desired: Mutex::new(Desired::default()),
                credential: watch::Sender::new(None),
                revision: watch::Sender::new(0),
                observed: Mutex::new(Observed::default()),
            }),
        }
    }

    /// Require the existing gateway reconciler lease before serving a host.
    /// Call before exposing this controller on a replicated gateway.
    pub fn require_leadership(&self) {
        self.stop_publishing();
    }

    /// Start a new reconciler term. Discard the previous replica-local view:
    /// only a fresh complete recovery may initialize this term's assignments.
    /// Bumping the revision fences recovery work begun in an earlier term.
    pub fn start_publishing(&self, deadline: Instant) {
        let mut publisher = lock(&self.inner.publisher);
        let mut desired = lock(&self.inner.desired);
        let revision = desired.revision + 1;
        *desired = Desired {
            revision,
            ..Desired::default()
        };
        *lock(&self.inner.mirror) = None;
        Self::disconnect(&mut lock(&self.inner.observed));
        *publisher = Publisher::Lease(deadline);
        self.inner.revision.send_replace(revision);
    }

    /// Extend publication only after the existing lease was renewed.
    pub fn renew_publishing(&self, deadline: Instant) {
        let mut publisher = lock(&self.inner.publisher);
        if matches!(*publisher, Publisher::Lease(_)) && publisher.active() {
            *publisher = Publisher::Lease(deadline);
        }
    }

    /// Revoke publication before releasing the lease or waiting for worker
    /// cleanup. Existing sandbox instances survive their stream closing.
    /// The term's desired state is discarded and its revision fenced, so a
    /// standby holds none and a recovery begun in the term cannot
    /// reinitialize it.
    pub fn stop_publishing(&self) {
        let mut publisher = lock(&self.inner.publisher);
        *publisher = Publisher::Standby;
        let mut desired = lock(&self.inner.desired);
        let revision = desired.revision + 1;
        *desired = Desired {
            revision,
            ..Desired::default()
        };
        Self::disconnect(&mut lock(&self.inner.observed));
        self.inner.credential.send_replace(None);
        self.inner.revision.send_replace(revision);
    }

    fn disconnect(observed: &mut Observed) {
        if let Some(session) = observed.session.take() {
            session.superseded.send_replace(true);
        }
        observed.status = None;
    }

    #[must_use]
    pub fn is_publisher(&self) -> bool {
        lock(&self.inner.publisher).active()
    }

    /// Snapshot observations for the next CAS renewal of the reconciler
    /// lease. Contains no launch material or bearer tokens.
    #[must_use]
    pub fn shared_observations(&self) -> Option<BTreeMap<String, SharedObservation>> {
        let publisher = lock(&self.inner.publisher);
        if !publisher.active() {
            return None;
        }
        let desired = lock(&self.inner.desired);
        let observed = lock(&self.inner.observed);
        observed.session.as_ref()?;
        Some(
            desired
                .assignments
                .keys()
                .chain(desired.excluded.keys())
                .map(|route| {
                    let value = match Self::observe(&desired, &observed, route) {
                        ObservedInstance::Reported(status) => SharedObservation::Reported(
                            SandboxInstanceStatusReport::from_proto(&status),
                        ),
                        ObservedInstance::Absent => SharedObservation::Absent,
                        _ => SharedObservation::Pending,
                    };
                    (route.clone(), value)
                })
                .collect(),
        )
    }

    /// Replace the standby's view from a fresh read of the existing lease.
    /// Failed reads, absent owners, and expired leases clear it immediately.
    pub fn mirror_observations(
        &self,
        observations: Option<(Instant, BTreeMap<String, SharedObservation>)>,
    ) {
        *lock(&self.inner.mirror) = observations;
    }

    /// Publish a freshly minted supervisor token for delivery to the host.
    pub fn publish_credential(&self, credential: SupervisorCredential) {
        let publisher = lock(&self.inner.publisher);
        if publisher.active() {
            self.inner.credential.send_replace(Some(credential));
        }
    }

    /// The current supervisor token and every renewal after it.
    #[must_use]
    pub fn credential(&self) -> watch::Receiver<Option<SupervisorCredential>> {
        self.inner.credential.subscribe()
    }

    /// The complete desired set has been derived from durable records at
    /// least once.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        lock(&self.inner.desired).initialized
    }

    /// Current desired revision, including the fence for this leadership
    /// term. Read it before deriving a full list for [`Self::replace_assignments`]; the
    /// coordinator does so through
    /// [`SharedSupervision::begin_recovery`](crate::SharedSupervision::begin_recovery).
    #[must_use]
    pub fn revision(&self) -> u64 {
        lock(&self.inner.desired).revision
    }

    /// The current assignment of `route`, if any.
    #[must_use]
    pub fn assignment(&self, route: &str) -> Option<SandboxInstanceAssignment> {
        lock(&self.inner.desired)
            .assignments
            .get(route)
            .map(|assigned| assigned.assignment.clone())
    }

    /// Replace the whole desired set with `assignments`, derived from
    /// durable records while the revision was `baseline`; `excluded` names
    /// the listed routes that are deliberately left unassigned.
    ///
    /// Initializes the controller; edits made before initialization are
    /// applied on top of the list. The replacement is compare-and-replace:
    /// when the revision moved past `baseline` while
    /// the list was being derived, nothing changes and the conflict is
    /// returned so the caller derives the list again. Only the publisher
    /// replaces its set.
    ///
    /// Only listed candidates are selected. A list beyond the host's
    /// capacity keeps those currently assigned or that the host reports
    /// running, then fills the rest in route order; the remainder is
    /// excluded like `excluded`. Until this term's host has sent its initial
    /// report it is refused, since any cut could stop a running instance.
    pub fn replace_assignments(
        &self,
        baseline: u64,
        assignments: impl IntoIterator<Item = SandboxInstanceAssignment>,
        excluded: impl IntoIterator<Item = String>,
    ) -> Result<u64, AssignmentError> {
        let publisher = lock(&self.inner.publisher);
        let mut desired = lock(&self.inner.desired);
        if !publisher.active() {
            return Err(AssignmentError::Standby);
        }
        if desired.revision != baseline {
            return Err(AssignmentError::Conflict {
                baseline,
                current: desired.revision,
            });
        }
        // Resolve the list and the pending overlay first, so a refused
        // replacement leaves the current set untouched.
        let mut resolved = BTreeMap::new();
        for assignment in assignments {
            resolved.insert(assignment.route.clone(), assignment);
        }
        for (route, edit) in &desired.pending {
            match edit {
                Some(assignment) => {
                    resolved.insert(route.clone(), assignment.clone());
                }
                None => {
                    resolved.remove(route);
                }
            }
        }
        let mut excluded = excluded
            .into_iter()
            .filter(|route| !resolved.contains_key(route) && !desired.pending.contains_key(route))
            .collect::<BTreeSet<_>>();
        if resolved.len() > MAX_ASSIGNED_INSTANCES {
            let observed = lock(&self.inner.observed);
            let Some(status) = &observed.status else {
                return Err(AssignmentError::Capacity);
            };
            let running = status
                .instances
                .iter()
                .filter(|instance| {
                    !SandboxInstanceStatusReport::from_proto(instance)
                        .phase
                        .is_terminal()
                })
                .map(|instance| instance.route.as_str())
                .collect::<BTreeSet<_>>();
            // A stable sort keeps route order within each tier.
            let mut ranked = resolved.keys().cloned().collect::<Vec<_>>();
            ranked.sort_by_key(|route| {
                (
                    !desired.assignments.contains_key(route),
                    !running.contains(route.as_str()),
                )
            });
            let overflow = ranked.split_off(MAX_ASSIGNED_INSTANCES);
            tracing::warn!(
                unassigned = overflow.len(),
                "shared sandbox instances exceed the supervisor's capacity; leaving the excess unassigned"
            );
            for route in overflow {
                resolved.remove(&route);
                excluded.insert(route);
            }
        }
        desired.pending.clear();
        let next = desired.revision + 1;
        let mut changed = !desired.initialized;
        for assignment in resolved.values() {
            changed |= desired.put(assignment.clone(), next);
        }
        let before = desired.assignments.len();
        desired
            .assignments
            .retain(|route, _| resolved.contains_key(route));
        changed |= desired.assignments.len() != before;
        desired.initialized = true;
        if changed {
            desired.revision = next;
            self.inner.revision.send_replace(next);
        }
        // A route that stays excluded keeps the revision that first omitted
        // it, so an unchanged recovery needs no new snapshot or ack.
        let revision = desired.revision;
        let previous = std::mem::take(&mut desired.excluded);
        desired.excluded = excluded
            .into_iter()
            .map(|route| {
                let since = previous.get(&route).copied().unwrap_or(revision);
                (route, since)
            })
            .collect();
        Ok(revision)
    }

    /// Assign one instance. Before initialization the edit is kept until the
    /// first full list arrives. Refused when it would exceed the host's
    /// capacity, so the caller fails its create before anything runs.
    ///
    /// A replica that does not publish keeps nothing: the persisted launch
    /// material is the assignment, and the publisher's recovery admits it or
    /// leaves it unassigned beyond capacity.
    pub fn assign(&self, assignment: SandboxInstanceAssignment) -> Result<(), AssignmentError> {
        let publisher = lock(&self.inner.publisher);
        let mut desired = lock(&self.inner.desired);
        if !publisher.active() {
            return Ok(());
        }
        if !desired.initialized {
            let pending_additions = desired
                .pending
                .values()
                .filter(|edit| edit.is_some())
                .count();
            if !desired.pending.contains_key(&assignment.route)
                && pending_additions >= MAX_ASSIGNED_INSTANCES
            {
                return Err(AssignmentError::Capacity);
            }
            desired
                .pending
                .insert(assignment.route.clone(), Some(assignment));
            return Ok(());
        }
        if !desired.assignments.contains_key(&assignment.route)
            && desired.assignments.len() >= MAX_ASSIGNED_INSTANCES
        {
            return Err(AssignmentError::Capacity);
        }
        desired.excluded.remove(&assignment.route);
        let next = desired.revision + 1;
        if desired.put(assignment, next) {
            desired.revision = next;
            self.inner.revision.send_replace(next);
        }
        Ok(())
    }

    /// Withdraw one instance so the host stops it. A replica that does not
    /// publish keeps nothing; the publisher's recovery discovers the stop.
    ///
    /// After initialization every withdrawal advances the revision, even for
    /// a route that is excluded or not yet discovered, so a recovery listed
    /// before it conflicts instead of admitting the withdrawn generation. No
    /// tombstone is kept: the next recovery lists the durable records again.
    pub fn unassign(&self, route: &str) {
        let publisher = lock(&self.inner.publisher);
        let mut desired = lock(&self.inner.desired);
        if !publisher.active() {
            return;
        }
        if !desired.initialized {
            desired.pending.insert(route.to_string(), None);
            return;
        }
        desired.excluded.remove(route);
        desired.assignments.remove(route);
        desired.revision += 1;
        let revision = desired.revision;
        self.inner.revision.send_replace(revision);
    }

    /// Whether a host session is currently connected.
    #[must_use]
    pub fn host_connected(&self) -> bool {
        lock(&self.inner.observed).session.is_some()
    }

    /// What the connected host reports for `route`.
    #[must_use]
    pub fn observed(&self, route: &str) -> ObservedInstance {
        let publisher = lock(&self.inner.publisher);
        if !publisher.active() {
            let mirror = lock(&self.inner.mirror);
            return match mirror
                .as_ref()
                .filter(|(deadline, _)| Instant::now() < *deadline)
                .and_then(|(_, observations)| observations.get(route))
            {
                Some(SharedObservation::Reported(status)) => {
                    ObservedInstance::Reported(status.to_proto())
                }
                Some(SharedObservation::Absent) => ObservedInstance::Absent,
                Some(SharedObservation::Pending) => ObservedInstance::Pending,
                None => ObservedInstance::NoHost,
            };
        }
        Self::observe(
            &lock(&self.inner.desired),
            &lock(&self.inner.observed),
            route,
        )
    }

    fn observe(desired: &Desired, observed: &Observed, route: &str) -> ObservedInstance {
        if observed.session.is_none() {
            return ObservedInstance::NoHost;
        }
        let since = match desired
            .assignments
            .get(route)
            .filter(|_| desired.initialized)
        {
            Some(assigned) => assigned.revision,
            // The latest complete recovery listed the route and left it
            // unassigned; the host's ack of a snapshot omitting it is a verdict.
            None => match desired.excluded.get(route) {
                Some(since) => *since,
                // A create can have reached another replica before this
                // leader's recovery discovers its durable assignment. Never
                // suspend that workload based on a snapshot that did not
                // assign it.
                None => return ObservedInstance::Pending,
            },
        };
        let Some(status) = &observed.status else {
            return ObservedInstance::Pending;
        };
        if let Some(instance) = status
            .instances
            .iter()
            .find(|instance| instance.route == route)
        {
            return ObservedInstance::Reported(instance.clone());
        }
        if since > status.applied_revision {
            ObservedInstance::Pending
        } else {
            ObservedInstance::Absent
        }
    }

    /// Serve one authenticated host stream. Reads the hello, supersedes any
    /// current session, and returns the gateway-to-host stream.
    pub async fn attach(
        &self,
        identity: HostIdentity,
        mut inbound: Streaming<HostMessage>,
    ) -> Result<ReceiverStream<Result<HostGatewayMessage, Status>>, Status> {
        if !self.is_publisher() {
            return Err(standby_refusal());
        }
        let hello = match tokio::time::timeout(HELLO_TIMEOUT, inbound.next()).await {
            Ok(Some(Ok(HostMessage {
                payload: Some(host_message::Payload::Hello(hello)),
            }))) => hello,
            Ok(Some(Ok(_))) => {
                return Err(Status::invalid_argument(
                    "supervisor host stream must start with a hello",
                ));
            }
            Ok(Some(Err(status))) => return Err(status),
            Ok(None) => {
                return Err(Status::invalid_argument(
                    "supervisor host stream ended before its hello",
                ));
            }
            Err(_) => {
                return Err(Status::deadline_exceeded(
                    "supervisor host did not send its hello in time",
                ));
            }
        };
        if hello.instance_id.is_empty() {
            return Err(Status::invalid_argument(
                "supervisor host hello names no instance",
            ));
        }
        let (tx, rx) = mpsc::channel(OUTBOUND_QUEUE);
        let expires_at = identity.expires_at;
        let (session_id, superseded) = self.begin_session(identity, &hello)?;
        tx.send(Ok(HostGatewayMessage {
            payload: Some(host_gateway_message::Payload::Accepted(HostAccepted {
                session_id: session_id.to_string(),
                heartbeat_interval: Some(prost_types::Duration {
                    seconds: i64::try_from(HOST_HEARTBEAT_INTERVAL.as_secs()).unwrap_or(15),
                    nanos: 0,
                }),
            })),
        }))
        .await
        .map_err(|_| Status::unavailable("supervisor host stream closed"))?;
        let controller = self.clone();
        tokio::spawn(async move {
            controller
                .run_session(session_id, expires_at, inbound, tx, superseded)
                .await;
            controller.end_session(session_id);
        });
        Ok(ReceiverStream::new(rx))
    }

    /// Start a session for `hello`, superseding the current one. A hello from
    /// the current host process with a connection epoch that is not newer is
    /// a delayed or replayed connection and is refused.
    pub(crate) fn begin_session(
        &self,
        identity: HostIdentity,
        hello: &HostHello,
    ) -> Result<(u64, watch::Receiver<bool>), Status> {
        let publisher = lock(&self.inner.publisher);
        if !publisher.active() {
            return Err(standby_refusal());
        }
        let mut observed = lock(&self.inner.observed);
        if let Some(current) = &observed.session
            && current.instance_id == hello.instance_id
            && hello.connection_epoch <= current.connection_epoch
        {
            return Err(Status::failed_precondition(
                "supervisor host connection epoch is not newer than the current session",
            ));
        }
        observed.next_session += 1;
        let id = observed.next_session;
        if let Some(previous) = observed.session.take() {
            tracing::info!(
                subject = %previous.identity.subject,
                instance_id = %previous.instance_id,
                connection_epoch = previous.connection_epoch,
                "superseding supervisor host session"
            );
            previous.superseded.send_replace(true);
        }
        tracing::info!(
            subject = %identity.subject,
            instance_id = %hello.instance_id,
            connection_epoch = hello.connection_epoch,
            session = id,
            "supervisor host attached"
        );
        let (superseded, watch) = watch::channel(false);
        observed.session = Some(HostSession {
            id,
            identity,
            instance_id: hello.instance_id.clone(),
            connection_epoch: hello.connection_epoch,
            superseded,
            sent_revision: 0,
        });
        observed.status = None;
        Ok((id, watch))
    }

    fn end_session(&self, id: u64) {
        let mut observed = lock(&self.inner.observed);
        if observed
            .session
            .as_ref()
            .is_some_and(|session| session.id == id)
        {
            let session = observed.session.take();
            observed.status = None;
            if let Some(session) = session {
                tracing::info!(
                    subject = %session.identity.subject,
                    instance_id = %session.instance_id,
                    session = id,
                    "supervisor host detached; hosted instances keep running"
                );
            }
        }
    }

    /// Note that `revision` was sent on session `id`.
    pub(crate) fn record_sent(&self, id: u64, revision: u64) {
        let mut observed = lock(&self.inner.observed);
        if let Some(session) = observed.session.as_mut().filter(|session| session.id == id) {
            session.sent_revision = session.sent_revision.max(revision);
        }
    }

    /// Record a report from session `id`. Reports from other sessions, acks
    /// of revisions never sent on this session, regressing acks, and
    /// oversized reports are dropped.
    pub(crate) fn record_status(&self, id: u64, status: HostStatus) -> Result<(), &'static str> {
        let mut observed = lock(&self.inner.observed);
        let Some(session) = observed.session.as_ref().filter(|session| session.id == id) else {
            return Err("report from a superseded supervisor host session");
        };
        if status.applied_revision > session.sent_revision {
            return Err("supervisor host acknowledged a revision it was never sent");
        }
        if status.instances.len() > MAX_REPORTED_INSTANCES {
            return Err("supervisor host status reports too many instances");
        }
        if observed
            .status
            .as_ref()
            .is_some_and(|previous| status.applied_revision < previous.applied_revision)
        {
            return Err("supervisor host acknowledged an older revision than before");
        }
        observed.status = Some(status);
        Ok(())
    }

    fn snapshot(&self) -> Option<AssignmentSnapshot> {
        lock(&self.inner.desired).snapshot()
    }

    async fn run_session(
        &self,
        session_id: u64,
        expires_at: i64,
        mut inbound: Streaming<HostMessage>,
        tx: mpsc::Sender<Result<HostGatewayMessage, Status>>,
        mut superseded: watch::Receiver<bool>,
    ) {
        // A bearer is verified once per stream, so the stream lives no longer
        // than the token did. Hosted instances are unaffected; the host
        // reconnects with the renewed token it has been delivered.
        let credential_expiry = tokio::time::sleep(credential_remaining(expires_at));
        tokio::pin!(credential_expiry);
        let mut revision = self.inner.revision.subscribe();
        let mut sent_revision = 0;
        let mut last_heard = Instant::now();
        let mut heartbeat = tokio::time::interval(HOST_HEARTBEAT_INTERVAL);
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // A send that cannot complete within the bound ends the session, so a
        // stalled host can neither block supersession nor delay heartbeats.
        let send = |message: host_gateway_message::Payload| {
            let tx = tx.clone();
            async move {
                tx.send_timeout(
                    Ok(HostGatewayMessage {
                        payload: Some(message),
                    }),
                    SEND_TIMEOUT,
                )
                .await
                .is_ok()
            }
        };
        loop {
            let publisher = *lock(&self.inner.publisher);
            if !publisher.active() || *superseded.borrow() {
                return;
            }
            let lease_expiry = async move {
                if let Publisher::Lease(deadline) = publisher {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            };
            tokio::pin!(lease_expiry);
            let current = *revision.borrow_and_update();
            if current > sent_revision
                && let Some(snapshot) = self.snapshot()
            {
                tracing::debug!(
                    session = session_id,
                    revision = snapshot.revision,
                    instances = snapshot.instances.len(),
                    "sending supervisor host assignment snapshot"
                );
                let revision_sent = snapshot.revision;
                tokio::select! {
                    biased;
                    _ = superseded.changed() => return,
                    () = &mut lease_expiry => return,
                    delivered = send(host_gateway_message::Payload::Assignments(snapshot)) => {
                        if !delivered { return; }
                    }
                }
                self.record_sent(session_id, revision_sent);
                sent_revision = current;
            }
            tokio::select! {
                () = &mut lease_expiry => {},
                changed = revision.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                message = inbound.next() => match message {
                    Some(Ok(HostMessage { payload: Some(host_message::Payload::Status(status)) })) => {
                        last_heard = Instant::now();
                        if let Err(reason) = self.record_status(session_id, status) {
                            tracing::warn!(session = session_id, reason, "dropped supervisor host status report");
                        }
                    }
                    Some(Ok(HostMessage { payload: Some(host_message::Payload::Heartbeat(_)) })) => {
                        last_heard = Instant::now();
                    }
                    Some(Ok(_)) => {
                        let _ = tx
                            .send_timeout(
                                Err(Status::invalid_argument(
                                    "unexpected message on supervisor host stream",
                                )),
                                SEND_TIMEOUT,
                            )
                            .await;
                        return;
                    }
                    Some(Err(status)) => {
                        tracing::debug!(session = session_id, %status, "supervisor host stream failed");
                        return;
                    }
                    None => return,
                },
                _ = heartbeat.tick() => {
                    if last_heard.elapsed() > HOST_SILENCE_TIMEOUT {
                        tracing::warn!(session = session_id, "supervisor host stream went silent; closing it");
                        return;
                    }
                    tokio::select! {
                        biased;
                        _ = superseded.changed() => return,
                        () = &mut lease_expiry => return,
                        delivered = send(host_gateway_message::Payload::Heartbeat(HostGatewayHeartbeat {})) => {
                            if !delivered { return; }
                        }
                    }
                }
                _ = superseded.changed() => return,
                () = &mut credential_expiry => {
                    tracing::info!(session = session_id, "supervisor token expired; closing the stream for reconnection");
                    return;
                }
            }
        }
    }
}

/// Time until `expires_at` (Unix seconds); zero once it has passed.
fn credential_remaining(expires_at: i64) -> Duration {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        });
    Duration::from_secs(u64::try_from(expires_at.saturating_sub(now)).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assignment(route: &str, material: &[u8]) -> SandboxInstanceAssignment {
        SandboxInstanceAssignment {
            route: route.to_string(),
            sandbox_id: format!("sandbox-{route}"),
            generation: "gen".to_string(),
            launch_material: material.to_vec(),
        }
    }

    fn status(applied_revision: u64, routes: &[&str]) -> HostStatus {
        HostStatus {
            applied_revision,
            instances: routes
                .iter()
                .map(|route| SandboxInstanceStatus {
                    route: (*route).to_string(),
                    sandbox_id: format!("sandbox-{route}"),
                    phase: 2,
                    ready: true,
                    exit_code: 0,
                    error: String::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn full_resyncs_initialize_once_and_then_compare_and_replace() {
        let controller = SupervisorHostController::new();
        let revision = controller.inner.revision.subscribe();
        // Edits before the first full list wait for it.
        controller
            .assign(assignment("rt-created-before-list", b"a"))
            .unwrap();
        controller.unassign("rt-stopped-before-list");
        assert!(!controller.is_initialized());
        assert!(controller.snapshot().is_none());
        assert!(!revision.has_changed().unwrap());

        let baseline = controller.revision();
        assert_eq!(
            controller.replace_assignments(
                baseline,
                [
                    assignment("rt-stopped-before-list", b"old"),
                    assignment("rt-listed", b"b"),
                ],
                [],
            ),
            Ok(1)
        );
        let snapshot = controller.snapshot().unwrap();
        assert_eq!(snapshot.revision, 1);
        assert_eq!(
            snapshot
                .instances
                .iter()
                .map(|instance| instance.route.as_str())
                .collect::<Vec<_>>(),
            ["rt-created-before-list", "rt-listed"]
        );
        assert!(revision.has_changed().unwrap());

        // An identical list changes nothing.
        assert_eq!(
            controller.replace_assignments(
                1,
                [
                    assignment("rt-created-before-list", b"a"),
                    assignment("rt-listed", b"b"),
                ],
                [],
            ),
            Ok(1)
        );
        controller.assign(assignment("rt-listed", b"b")).unwrap();
        assert_eq!(controller.revision(), 1);

        // A list derived at revision 1 that races a stop cannot resurrect the
        // stopped instance; the caller derives it again.
        controller.unassign("rt-listed");
        assert_eq!(controller.revision(), 2);
        assert_eq!(
            controller.replace_assignments(
                1,
                [
                    assignment("rt-created-before-list", b"a"),
                    assignment("rt-listed", b"b"),
                ],
                [],
            ),
            Err(AssignmentError::Conflict {
                baseline: 1,
                current: 2
            })
        );
        assert!(controller.assignment("rt-listed").is_none());
        assert_eq!(controller.replace_assignments(2, [], []), Ok(3));
        assert!(controller.snapshot().unwrap().instances.is_empty());

        // The gateway refuses the assignment its host could not accept.
        let full =
            (0..MAX_ASSIGNED_INSTANCES).map(|index| assignment(&format!("rt-{index}"), b"x"));
        assert_eq!(controller.replace_assignments(3, full, []), Ok(4));
        assert_eq!(
            controller.assign(assignment("rt-one-too-many", b"x")),
            Err(AssignmentError::Capacity)
        );
        assert_eq!(controller.assign(assignment("rt-0", b"x")), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn leadership_fences_old_sessions_recovery_and_cached_observations() {
        let controller = SupervisorHostController::new();
        controller
            .replace_assignments(0, [assignment("rt-old", b"old")], [])
            .unwrap();
        let old_baseline = controller.revision();
        controller.require_leadership();
        assert!(!controller.is_initialized());
        // A standby keeps no desired state, so creates and deletes beyond the
        // host's capacity are left to the leader's durable recovery.
        for index in 0..=MAX_ASSIGNED_INSTANCES {
            controller
                .assign(assignment(&format!("rt-standby-{index}"), b"s"))
                .unwrap();
            controller.unassign(&format!("rt-standby-deleted-{index}"));
        }
        assert!(lock(&controller.inner.desired).pending.is_empty());
        let identity = HostIdentity {
            subject: "openshell-supervisor:test".to_string(),
            token_id: "token".to_string(),
            expires_at: i64::MAX,
        };
        let hello = HostHello {
            instance_id: "boot".to_string(),
            connection_epoch: 1,
        };
        // The refusal is marked, and the marker survives gRPC trailers.
        let refusal = controller
            .begin_session(identity.clone(), &hello)
            .unwrap_err();
        let mut trailers = tonic::codegen::http::HeaderMap::new();
        refusal.add_header(&mut trailers).unwrap();
        assert!(is_standby_refusal(
            &Status::from_header_map(&trailers).unwrap()
        ));
        controller.start_publishing(Instant::now() + Duration::from_secs(30));
        assert!(!controller.is_initialized());
        assert!(controller.assignment("rt-old").is_none());
        assert!(
            controller
                .replace_assignments(old_baseline, [], [])
                .is_err()
        );
        // No authoritative empty snapshot before the new term's full recovery.
        assert!(controller.snapshot().is_none());
        let (session, revoked) = controller.begin_session(identity.clone(), &hello).unwrap();
        controller.record_status(session, status(0, &[])).unwrap();
        assert_eq!(controller.observed("rt-new"), ObservedInstance::Pending);
        controller
            .replace_assignments(controller.revision(), [assignment("rt-new", b"new")], [])
            .unwrap();
        controller.record_sent(session, controller.revision());
        controller
            .record_status(session, status(controller.revision(), &["rt-new"]))
            .unwrap();

        let standby = SupervisorHostController::new();
        standby.require_leadership();
        standby.mirror_observations(Some((
            Instant::now() + Duration::from_secs(30),
            controller.shared_observations().unwrap(),
        )));
        assert!(
            matches!(standby.observed("rt-new"), ObservedInstance::Reported(status) if status.ready)
        );
        assert_eq!(
            standby.observed("rt-created-on-standby"),
            ObservedInstance::NoHost
        );

        // Renewing extends the local bound, but a cached standby view expires
        // unless it too reads a fresh lease. Expiry is unknown, never absent.
        tokio::time::advance(Duration::from_secs(20)).await;
        controller.renew_publishing(Instant::now() + Duration::from_secs(30));
        tokio::time::advance(Duration::from_secs(11)).await;
        assert!(controller.is_publisher());
        assert_eq!(standby.observed("rt-new"), ObservedInstance::NoHost);
        // Demotion discards the term's desired state, and a recovery begun in
        // the term cannot reinitialize the standby.
        let stale_baseline = controller.revision();
        controller.stop_publishing();
        assert!(*revoked.borrow());
        assert!(!controller.is_initialized());
        assert!(controller.assignment("rt-new").is_none());
        assert_eq!(
            controller.replace_assignments(stale_baseline, [assignment("rt-new", b"new")], []),
            Err(AssignmentError::Standby)
        );
        assert!(!controller.is_initialized());
        assert!(controller.record_status(session, status(0, &[])).is_err());
        assert_eq!(controller.observed("rt-new"), ObservedInstance::NoHost);
        let refusal = controller
            .begin_session(identity.clone(), &hello)
            .unwrap_err();
        assert!(is_standby_refusal(&refusal));

        controller.start_publishing(Instant::now() + Duration::from_secs(30));
        assert!(!controller.is_initialized());
        assert!(controller.snapshot().is_none());
        let expired_baseline = controller.revision();
        tokio::time::advance(Duration::from_secs(31)).await;
        // A late renewal cannot revive an expired term, and an expired
        // publisher edits nothing even before its demotion runs.
        controller.renew_publishing(Instant::now() + Duration::from_secs(30));
        assert!(!controller.is_publisher());
        controller.assign(assignment("rt-late", b"l")).unwrap();
        controller.unassign("rt-late-stop");
        assert!(lock(&controller.inner.desired).pending.is_empty());
        assert_eq!(
            controller.replace_assignments(expired_baseline, [], []),
            Err(AssignmentError::Standby)
        );
        assert!(!controller.is_initialized());
        assert!(is_standby_refusal(
            &controller.begin_session(identity, &hello).unwrap_err()
        ));
    }

    #[test]
    fn recovery_exclusions_become_absent_once_acknowledged_and_bound_capacity() {
        let controller = SupervisorHostController::new();
        let identity = HostIdentity {
            subject: "openshell-supervisor:test".to_string(),
            token_id: "token".to_string(),
            expires_at: i64::MAX,
        };
        let hello = HostHello {
            instance_id: "boot".to_string(),
            connection_epoch: 1,
        };
        let (session, _) = controller.begin_session(identity, &hello).unwrap();
        let listed = || {
            (0..MAX_ASSIGNED_INSTANCES + 2)
                .map(|index| assignment(&format!("rt-{index:03}"), b"x"))
                .collect::<Vec<_>>()
        };
        // Beyond capacity, nothing is cut until the host reports what it runs.
        assert_eq!(
            controller.replace_assignments(0, listed(), ["rt-gone".to_string()]),
            Err(AssignmentError::Capacity)
        );
        assert!(!controller.is_initialized());

        // The running instance stays; the excess is excluded in route order.
        controller
            .record_status(session, status(0, &["rt-257"]))
            .unwrap();
        assert_eq!(
            controller.replace_assignments(0, listed(), ["rt-gone".to_string()]),
            Ok(1)
        );
        assert_eq!(
            controller.snapshot().unwrap().instances.len(),
            MAX_ASSIGNED_INSTANCES
        );
        assert!(controller.assignment("rt-257").is_some());
        let excluded = ["rt-gone", "rt-255", "rt-256"];
        for route in excluded {
            assert_eq!(controller.observed(route), ObservedInstance::Pending);
        }
        controller.record_sent(session, 1);
        controller
            .record_status(session, status(1, &["rt-257"]))
            .unwrap();
        for route in excluded {
            assert_eq!(controller.observed(route), ObservedInstance::Absent);
        }
        assert_eq!(
            controller.observed("rt-undiscovered"),
            ObservedInstance::Pending
        );
        let observations = controller.shared_observations().unwrap();
        assert_eq!(
            observations.get("rt-gone"),
            Some(&SharedObservation::Absent)
        );
        assert!(!observations.contains_key("rt-undiscovered"));

        // A later recovery keeps current assignments over a new route that
        // sorts first, and an unchanged set needs no new snapshot or ack.
        let revision = controller.inner.revision.subscribe();
        let mut relisted = listed();
        relisted.push(assignment("rt-0", b"x"));
        assert_eq!(
            controller.replace_assignments(1, relisted, ["rt-gone".to_string()]),
            Ok(1)
        );
        assert!(!revision.has_changed().unwrap());
        assert_eq!(controller.observed("rt-0"), ObservedInstance::Absent);
        assert_eq!(controller.observed("rt-gone"), ObservedInstance::Absent);

        // Withdrawing or reassigning an excluded route clears its verdict, a
        // raced recovery records nothing, and restored material assigns it.
        // A withdrawal fences recovery listed before it, so a stale list
        // cannot re-admit an excluded or undiscovered withdrawn route.
        let stale = controller.revision();
        controller.unassign("rt-255");
        controller.unassign("rt-undiscovered");
        assert_eq!(controller.observed("rt-255"), ObservedInstance::Pending);
        let stale_list = [
            assignment("rt-255", b"x"),
            assignment("rt-undiscovered", b"x"),
        ];
        assert!(matches!(
            controller.replace_assignments(stale, stale_list, []),
            Err(AssignmentError::Conflict { .. })
        ));
        assert!(controller.assignment("rt-255").is_none());
        assert!(controller.assignment("rt-undiscovered").is_none());
        controller.unassign("rt-000");
        controller.assign(assignment("rt-256", b"x")).unwrap();
        assert_eq!(controller.observed("rt-256"), ObservedInstance::Pending);
        assert!(
            controller
                .replace_assignments(1, [], ["rt-raced".to_string()])
                .is_err()
        );
        assert_eq!(controller.observed("rt-raced"), ObservedInstance::Pending);
        controller
            .replace_assignments(controller.revision(), [assignment("rt-gone", b"x")], [])
            .unwrap();
        assert_eq!(controller.observed("rt-gone"), ObservedInstance::Pending);
        assert_eq!(controller.observed("rt-0"), ObservedInstance::Pending);
    }

    #[test]
    fn sessions_fence_stale_streams_epochs_and_acks() {
        let controller = SupervisorHostController::new();
        controller
            .replace_assignments(0, [assignment("rt-a", b"a")], [])
            .unwrap();
        assert_eq!(controller.observed("rt-a"), ObservedInstance::NoHost);

        let identity = HostIdentity {
            subject: "openshell-supervisor:test".to_string(),
            token_id: "token".to_string(),
            expires_at: i64::MAX,
        };
        let hello = |instance_id: &str, connection_epoch| HostHello {
            instance_id: instance_id.to_string(),
            connection_epoch,
        };
        let (first, superseded) = controller
            .begin_session(identity.clone(), &hello("boot-1", 1))
            .unwrap();
        assert_eq!(controller.observed("rt-a"), ObservedInstance::Pending);

        // A delayed hello from an older connection of the same process is
        // refused; a newer one supersedes the stream.
        assert!(
            controller
                .begin_session(identity.clone(), &hello("boot-1", 1))
                .is_err()
        );
        let (current, _) = controller
            .begin_session(identity.clone(), &hello("boot-1", 2))
            .unwrap();
        assert!(*superseded.borrow());
        assert!(controller.record_status(first, status(0, &[])).is_err());

        // Acks are bounded by what this stream was sent and never regress.
        assert!(controller.record_status(current, status(1, &[])).is_err());
        controller.record_sent(current, 1);
        controller
            .record_status(current, status(1, &["rt-a"]))
            .unwrap();
        assert!(controller.record_status(current, status(0, &[])).is_err());
        assert!(matches!(
            controller.observed("rt-a"),
            ObservedInstance::Reported(status) if status.ready
        ));

        // A newer assignment is pending until the host reconciles past it.
        controller.assign(assignment("rt-b", b"b")).unwrap();
        assert_eq!(controller.observed("rt-b"), ObservedInstance::Pending);
        assert_eq!(controller.observed("rt-unknown"), ObservedInstance::Pending);
        controller.record_sent(current, 2);
        controller.record_status(current, status(2, &[])).unwrap();
        assert_eq!(controller.observed("rt-b"), ObservedInstance::Absent);

        // A new host process always takes over; ending a stale session is a no-op.
        let (replacement, _) = controller
            .begin_session(identity, &hello("boot-2", 1))
            .unwrap();
        controller.end_session(current);
        assert!(controller.host_connected());
        controller.end_session(replacement);
        assert_eq!(controller.observed("rt-a"), ObservedInstance::NoHost);
    }
}
