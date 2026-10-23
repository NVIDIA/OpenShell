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
//! Without a pool, exactly one host serves a gateway: a new attach from a
//! newer connection of the same host process, or from a new host process,
//! supersedes the current session; reports and acks from a superseded stream
//! are dropped, and a delayed hello from an older connection of the current
//! process is refused.
//!
//! With a supervisor pool (high availability) the same rules apply per pool
//! member, and several members are served at once. Every assigned instance
//! has one durable owner (a member's process and an ownership term) that the
//! gateway maintains through [`PoolView`]; each member is sent only the
//! instances its current process owns, with the credentials of their term.
//! A pool member releases, without stopping, an instance a snapshot omits;
//! only instances whose assignment was withdrawn are listed for stopping.
//! Nothing is sent to pool members until both the desired set and the
//! ownership view have been loaded, so a restarted gateway never releases
//! running instances.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, watch};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Status, Streaming};

use crate::proto::{
    AssignmentSnapshot, HostAccepted, HostGatewayHeartbeat, HostGatewayMessage, HostHello,
    HostMessage, HostStatus, PoolMember, RouteOwner, SandboxInstanceAssignment,
    SandboxInstanceStatus, SandboxInstanceTakeover, host_gateway_message, host_message,
};

/// Interval at which both ends send heartbeats on an idle stream.
pub const HOST_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
/// Heartbeat interval of pool members, whose liveness drives failover.
pub const POOL_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
/// Silence after which the gateway closes a host stream.
const HOST_SILENCE_TIMEOUT: Duration = Duration::from_mins(1);
/// Silence after which the gateway closes a pool member's stream.
const POOL_SILENCE_TIMEOUT: Duration = Duration::from_secs(15);
/// Bound on the host sending its hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on queueing one gateway-to-host message; a host that cannot drain
/// its stream this long is disconnected rather than stalling the session.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);
/// Gateway-to-host messages queued before the stream applies backpressure.
const OUTBOUND_QUEUE: usize = 16;
/// How long a withdrawn pool instance stays on its owner's stop list.
const POOL_STOP_RETENTION: Duration = Duration::from_mins(2);
/// Most sandbox instances one shared supervisor host runs. The gateway
/// refuses to assign beyond it, and the host refuses snapshots beyond it, so
/// a sandbox is never created that its host could not accept.
pub const MAX_ASSIGNED_INSTANCES: usize = 256;
/// Most sandbox instances a supervisor pool runs across its members; the
/// gateway places at most [`MAX_ASSIGNED_INSTANCES`] on each member.
pub const MAX_POOL_INSTANCES: usize = 16 * MAX_ASSIGNED_INSTANCES;
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
    /// No host session is connected (for a pool: the owner's process is not
    /// connected to this gateway, or the route has no owner yet).
    NoHost,
    /// A host is connected but has not reconciled to the snapshot that
    /// assigned this route.
    Pending,
    /// The host reconciled to that snapshot (or the route is not assigned)
    /// and does not host the route.
    Absent,
    /// The host's latest report of the instance.
    Reported(SandboxInstanceStatus),
}

/// The process and ownership term that supervise one pool instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceOwner {
    /// Pool member that owns the instance.
    pub member_id: String,
    /// Host process of that member that owns the term.
    pub process_id: String,
    /// Ownership term: the sandbox credential epoch of the owner.
    pub auth_epoch: u64,
    /// Supervisor process identity a term after the launch term was granted
    /// for; absent for the launch term.
    pub supervisor_instance_id: Option<String>,
    /// Credentials of a term after the launch term, for the owner's host.
    /// Absent for the launch term, whose credentials the launch material
    /// carries. Minted by this gateway only for members it serves.
    pub takeover: Option<SandboxInstanceTakeover>,
}

impl InstanceOwner {
    /// The takeover term an assignment carries: with its credentials when
    /// this gateway minted them, else the term alone, so a host already
    /// running the instance for that term keeps it. Credentials minted for
    /// one term differ between gateway replicas; the term does not.
    fn takeover_term(&self) -> Option<SandboxInstanceTakeover> {
        let supervisor_instance_id = self.supervisor_instance_id.as_ref()?;
        Some(
            self.takeover
                .clone()
                .unwrap_or_else(|| SandboxInstanceTakeover {
                    auth_epoch: self.auth_epoch,
                    supervisor_instance_id: supervisor_instance_id.clone(),
                    ..SandboxInstanceTakeover::default()
                }),
        )
    }
}

/// A live pool member as the gateway's durable membership records show it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberView {
    pub member_id: String,
    /// Host process currently serving the member.
    pub process_id: String,
    /// Routed runtime listener address of the member.
    pub runtime_address: String,
    /// The member announced it is leaving the pool.
    pub leaving: bool,
}

/// The gateway's durable view of a supervisor pool: live members and the
/// owner of every placed instance, replaced as a whole by the gateway's
/// pool reconciler.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PoolView {
    pub members: Vec<MemberView>,
    /// Owner of each placed route.
    pub owners: BTreeMap<String, InstanceOwner>,
}

/// A connected pool member's stream, for the gateway's membership records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectedMember {
    pub member_id: String,
    pub member_uid: String,
    pub process_id: String,
    pub runtime_address: String,
    /// The member reported that it is leaving.
    pub leaving: bool,
    /// When this stream was accepted (Unix milliseconds); a newer stream of a
    /// member supersedes an older one on another gateway replica.
    pub connected_at_ms: i64,
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
    /// Pool only: withdrawn instances to stop, with the owner and the time of
    /// withdrawal.
    stopping: BTreeMap<String, (InstanceOwner, tokio::time::Instant)>,
}

impl Desired {
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

/// Pool state: the durable view and when each owner term was first recorded
/// here, for telling a reconciling host from one that dropped an instance.
#[derive(Default)]
struct Pool {
    loaded: bool,
    view: PoolView,
    owned_since: BTreeMap<String, u64>,
    /// Owners placed by launches on this gateway, with when, so a view whose
    /// records were listed before a placement does not drop it.
    placed: BTreeMap<String, (InstanceOwner, tokio::time::Instant)>,
}

struct HostSession {
    id: u64,
    identity: HostIdentity,
    instance_id: String,
    connection_epoch: u64,
    member: Option<PoolMember>,
    superseded: watch::Sender<bool>,
    /// Highest snapshot revision sent on this stream; acks beyond it are
    /// impossible and rejected.
    sent_revision: u64,
    /// Latest report of this session.
    status: Option<HostStatus>,
    connected_at_ms: i64,
}

impl HostSession {
    fn member_id(&self) -> Option<&str> {
        self.member.as_ref().map(|member| member.member_id.as_str())
    }
}

#[derive(Default)]
struct Observed {
    sessions: BTreeMap<u64, HostSession>,
    next_session: u64,
}

struct Inner {
    desired: Mutex<Desired>,
    /// Present when the host is a supervisor pool.
    pool: Mutex<Option<Pool>>,
    /// The gateway's durable placement of new pool instances.
    placement: Mutex<Option<Arc<dyn crate::coordinator::InstancePlacement>>>,
    /// Latest supervisor token the gateway minted; `None` until the first.
    credential: watch::Sender<Option<SupervisorCredential>>,
    /// Current revision of everything snapshots are derived from; 0 while
    /// uninitialized.
    revision: watch::Sender<u64>,
    observed: Mutex<Observed>,
}

/// Gateway-owned desired assignments and observed status of a shared
/// supervisor host or pool.
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
    #[error("the shared supervisor has no capacity for another sandbox instance")]
    Capacity,
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
                desired: Mutex::new(Desired::default()),
                pool: Mutex::new(None),
                placement: Mutex::new(None),
                credential: watch::Sender::new(None),
                revision: watch::Sender::new(0),
                observed: Mutex::new(Observed::default()),
            }),
        }
    }

    /// Serve a supervisor pool instead of a single host. Must be called
    /// before any host attaches.
    pub fn enable_pool(&self) {
        let mut pool = lock(&self.inner.pool);
        if pool.is_none() {
            *pool = Some(Pool::default());
        }
    }

    /// Whether this controller serves a supervisor pool.
    #[must_use]
    pub fn is_pool(&self) -> bool {
        lock(&self.inner.pool).is_some()
    }

    /// Install the gateway's durable placement of new pool instances.
    pub fn install_placement(&self, placement: Arc<dyn crate::coordinator::InstancePlacement>) {
        *lock(&self.inner.placement) = Some(placement);
    }

    /// The installed placement of new pool instances.
    #[must_use]
    pub fn placement(&self) -> Option<Arc<dyn crate::coordinator::InstancePlacement>> {
        lock(&self.inner.placement).clone()
    }

    /// Publish a freshly minted supervisor token for delivery to the host.
    pub fn publish_credential(&self, credential: SupervisorCredential) {
        self.inner.credential.send_replace(Some(credential));
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

    /// Current desired revision: 0 while uninitialized. Read it before
    /// deriving a full list for [`Self::replace_assignments`]; the
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

    /// Every current assignment.
    #[must_use]
    pub fn assignments(&self) -> Vec<SandboxInstanceAssignment> {
        lock(&self.inner.desired)
            .assignments
            .values()
            .map(|assigned| assigned.assignment.clone())
            .collect()
    }

    /// Most instances the desired set may hold: one host's, or a pool's.
    fn capacity(&self) -> usize {
        if self.is_pool() {
            MAX_POOL_INSTANCES
        } else {
            MAX_ASSIGNED_INSTANCES
        }
    }

    fn bump(&self, desired: &mut Desired) -> u64 {
        desired.revision += 1;
        self.inner.revision.send_replace(desired.revision);
        desired.revision
    }

    /// Record withdrawn pool instances for their owner to stop.
    fn record_stops(&self, desired: &mut Desired, routes: impl IntoIterator<Item = String>) {
        let pool = lock(&self.inner.pool);
        let Some(pool) = pool.as_ref() else {
            return;
        };
        let now = tokio::time::Instant::now();
        for route in routes {
            if let Some(owner) = pool.view.owners.get(&route) {
                desired.stopping.insert(route, (owner.clone(), now));
            }
        }
    }

    /// Replace the whole desired set with `assignments`, derived from
    /// durable records while the revision was `baseline`.
    ///
    /// Initializes the controller; edits made before initialization are
    /// applied on top of the list. After initialization the replacement is
    /// compare-and-replace: when the revision moved past `baseline` while
    /// the list was being derived, nothing changes and the conflict is
    /// returned so the caller derives the list again.
    pub fn replace_assignments(
        &self,
        baseline: u64,
        assignments: impl IntoIterator<Item = SandboxInstanceAssignment>,
    ) -> Result<u64, AssignmentError> {
        let mut desired = lock(&self.inner.desired);
        if desired.initialized && desired.revision != baseline {
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
        let mut withdrawn = Vec::new();
        for (route, edit) in &desired.pending {
            if let Some(assignment) = edit {
                resolved.insert(route.clone(), assignment.clone());
            } else {
                resolved.remove(route);
                withdrawn.push(route.clone());
            }
        }
        if resolved.len() > self.capacity() {
            return Err(AssignmentError::Capacity);
        }
        desired.pending.clear();
        // A route the list assigns is not being stopped, whatever an earlier
        // withdrawal recorded.
        desired
            .stopping
            .retain(|route, _| !resolved.contains_key(route));
        let next = desired.revision + 1;
        let mut changed = !desired.initialized;
        for assignment in resolved.values() {
            changed |= desired.put(assignment.clone(), next);
        }
        withdrawn.extend(
            desired
                .assignments
                .keys()
                .filter(|route| !resolved.contains_key(*route))
                .cloned(),
        );
        let before = desired.assignments.len();
        desired
            .assignments
            .retain(|route, _| resolved.contains_key(route));
        changed |= desired.assignments.len() != before;
        desired.initialized = true;
        self.record_stops(&mut desired, withdrawn);
        if changed {
            desired.revision = next;
            self.inner.revision.send_replace(next);
        }
        Ok(desired.revision)
    }

    /// Assign one instance. Before initialization the edit is kept until the
    /// first full list arrives. Refused when it would exceed the host's
    /// capacity, so the caller fails its create before anything runs.
    pub fn assign(&self, assignment: SandboxInstanceAssignment) -> Result<(), AssignmentError> {
        let mut desired = lock(&self.inner.desired);
        if !desired.initialized {
            let pending_additions = desired
                .pending
                .values()
                .filter(|edit| edit.is_some())
                .count();
            if !desired.pending.contains_key(&assignment.route)
                && pending_additions >= self.capacity()
            {
                return Err(AssignmentError::Capacity);
            }
            desired
                .pending
                .insert(assignment.route.clone(), Some(assignment));
            return Ok(());
        }
        if !desired.assignments.contains_key(&assignment.route)
            && desired.assignments.len() >= self.capacity()
        {
            return Err(AssignmentError::Capacity);
        }
        let next = desired.revision + 1;
        desired.stopping.remove(&assignment.route);
        if desired.put(assignment, next) {
            desired.revision = next;
            self.inner.revision.send_replace(next);
        }
        Ok(())
    }

    /// Withdraw one instance so the host stops it.
    pub fn unassign(&self, route: &str) {
        let mut desired = lock(&self.inner.desired);
        if !desired.initialized {
            desired.pending.insert(route.to_string(), None);
            return;
        }
        if desired.assignments.remove(route).is_some() {
            self.record_stops(&mut desired, [route.to_string()]);
            self.bump(&mut desired);
        }
    }

    /// Replace the durable pool view, derived from owner records listed at
    /// `listed_at`. Owners placed here since then are kept until a view
    /// includes them. Owners whose term is new to this gateway are recorded as
    /// assigned at the next revision, so their host is considered reconciling
    /// until it acknowledges it.
    pub fn update_pool(&self, mut view: PoolView, listed_at: tokio::time::Instant) {
        let mut desired = lock(&self.inner.desired);
        let mut pool_guard = lock(&self.inner.pool);
        let Some(pool) = pool_guard.as_mut() else {
            return;
        };
        pool.placed
            .retain(|_, (_, placed_at)| *placed_at >= listed_at);
        for (route, (owner, _)) in &pool.placed {
            view.owners
                .entry(route.clone())
                .or_insert_with(|| owner.clone());
        }
        if pool.loaded && pool.view == view {
            return;
        }
        let next = desired.revision + 1;
        let previous = std::mem::take(&mut pool.owned_since);
        for (route, owner) in &view.owners {
            let unchanged = pool.view.owners.get(route).is_some_and(|current| {
                current.member_id == owner.member_id
                    && current.process_id == owner.process_id
                    && current.auth_epoch == owner.auth_epoch
            });
            let since = previous
                .get(route)
                .copied()
                .filter(|_| unchanged)
                .unwrap_or(next);
            pool.owned_since.insert(route.clone(), since);
        }
        pool.view = view;
        pool.loaded = true;
        drop(pool_guard);
        desired.revision = next;
        self.inner.revision.send_replace(next);
    }

    /// Pool routes withdrawn for stopping; they must not be placed or taken
    /// over again.
    #[must_use]
    pub fn stopping_routes(&self) -> BTreeSet<String> {
        let mut desired = lock(&self.inner.desired);
        let now = tokio::time::Instant::now();
        desired
            .stopping
            .retain(|_, (_, since)| now.duration_since(*since) < POOL_STOP_RETENTION);
        desired.stopping.keys().cloned().collect()
    }

    /// Record a newly placed owner without waiting for the next pool
    /// reconciliation, so a launched instance is served at once.
    pub fn place_owner(&self, route: &str, owner: InstanceOwner) {
        let mut desired = lock(&self.inner.desired);
        let mut pool_guard = lock(&self.inner.pool);
        let Some(pool) = pool_guard.as_mut() else {
            return;
        };
        pool.placed.insert(
            route.to_string(),
            (owner.clone(), tokio::time::Instant::now()),
        );
        // Until the first load, the reconciler's view will include it.
        if !pool.loaded || pool.view.owners.get(route) == Some(&owner) {
            return;
        }
        let next = desired.revision + 1;
        pool.view.owners.insert(route.to_string(), owner);
        pool.owned_since.insert(route.to_string(), next);
        drop(pool_guard);
        desired.revision = next;
        self.inner.revision.send_replace(next);
    }

    /// The durable pool view this gateway serves, once loaded.
    #[must_use]
    pub fn pool_view(&self) -> Option<PoolView> {
        lock(&self.inner.pool)
            .as_ref()
            .filter(|pool| pool.loaded)
            .map(|pool| pool.view.clone())
    }

    /// Pool members whose streams this gateway serves, for its durable
    /// membership records.
    #[must_use]
    pub fn connected_members(&self) -> Vec<ConnectedMember> {
        lock(&self.inner.observed)
            .sessions
            .values()
            .filter_map(|session| {
                let member = session.member.as_ref()?;
                Some(ConnectedMember {
                    member_id: member.member_id.clone(),
                    member_uid: member.member_uid.clone(),
                    process_id: session.instance_id.clone(),
                    runtime_address: member.runtime_address.clone(),
                    leaving: session.status.as_ref().is_some_and(|status| status.leaving),
                    connected_at_ms: session.connected_at_ms,
                })
            })
            .collect()
    }

    /// Whether a host session is currently connected.
    #[must_use]
    pub fn host_connected(&self) -> bool {
        !lock(&self.inner.observed).sessions.is_empty()
    }

    /// What the connected host reports for `route`. For a pool, only the
    /// session of the route's owning process renders a verdict.
    #[must_use]
    pub fn observed(&self, route: &str) -> ObservedInstance {
        let desired = lock(&self.inner.desired);
        let pool = lock(&self.inner.pool);
        let observed = lock(&self.inner.observed);
        let (session, assigned_revision) = match pool.as_ref() {
            None => {
                let Some(session) = observed.sessions.values().next() else {
                    return ObservedInstance::NoHost;
                };
                (
                    session,
                    desired
                        .assignments
                        .get(route)
                        .map(|assigned| assigned.revision),
                )
            }
            Some(pool) => {
                let Some(owner) = pool.view.owners.get(route) else {
                    return ObservedInstance::NoHost;
                };
                let Some(session) = observed.sessions.values().find(|session| {
                    session.member_id() == Some(owner.member_id.as_str())
                        && session.instance_id == owner.process_id
                }) else {
                    return ObservedInstance::NoHost;
                };
                let assigned = desired
                    .assignments
                    .get(route)
                    .map(|assigned| assigned.revision);
                let since = pool.owned_since.get(route).copied();
                (session, assigned.max(since))
            }
        };
        let Some(status) = &session.status else {
            return ObservedInstance::Pending;
        };
        if let Some(instance) = status
            .instances
            .iter()
            .find(|instance| instance.route == route)
        {
            return ObservedInstance::Reported(instance.clone());
        }
        match assigned_revision {
            Some(revision) if revision > status.applied_revision => ObservedInstance::Pending,
            _ => ObservedInstance::Absent,
        }
    }

    /// Serve one authenticated host stream. Reads the hello, supersedes any
    /// session it replaces, and returns the gateway-to-host stream.
    pub async fn attach(
        &self,
        identity: HostIdentity,
        mut inbound: Streaming<HostMessage>,
    ) -> Result<ReceiverStream<Result<HostGatewayMessage, Status>>, Status> {
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
        let pool = self.is_pool();
        match (&hello.member, pool) {
            (None, true) => {
                return Err(Status::failed_precondition(
                    "this gateway serves a supervisor pool; the host must name its pool member",
                ));
            }
            (Some(_), false) => {
                return Err(Status::failed_precondition(
                    "this gateway serves a single shared supervisor, not a pool",
                ));
            }
            (Some(member), true) if !valid_member(member) => {
                return Err(Status::invalid_argument(
                    "supervisor pool member identity is incomplete",
                ));
            }
            _ => {}
        }
        let heartbeat = if pool {
            POOL_HEARTBEAT_INTERVAL
        } else {
            HOST_HEARTBEAT_INTERVAL
        };
        let (tx, rx) = mpsc::channel(OUTBOUND_QUEUE);
        let expires_at = identity.expires_at;
        let (session_id, superseded) = self.begin_session(identity, &hello)?;
        tx.send(Ok(HostGatewayMessage {
            payload: Some(host_gateway_message::Payload::Accepted(HostAccepted {
                session_id: session_id.to_string(),
                heartbeat_interval: Some(prost_types::Duration {
                    seconds: i64::try_from(heartbeat.as_secs()).unwrap_or(15),
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

    /// Start a session for `hello`, superseding the session it replaces: the
    /// only session without a pool, or the same member's session in a pool.
    /// A hello from the current host process with a connection epoch that is
    /// not newer is a delayed or replayed connection and is refused.
    fn begin_session(
        &self,
        identity: HostIdentity,
        hello: &HostHello,
    ) -> Result<(u64, watch::Receiver<bool>), Status> {
        let mut observed = lock(&self.inner.observed);
        let member_id = hello.member.as_ref().map(|member| member.member_id.clone());
        let replaced = observed
            .sessions
            .values()
            .filter(|session| member_id.is_none() || session.member_id() == member_id.as_deref())
            .map(|session| session.id)
            .collect::<Vec<_>>();
        if let Some(current) = replaced
            .iter()
            .filter_map(|id| observed.sessions.get(id))
            .find(|session| session.instance_id == hello.instance_id)
            && hello.connection_epoch <= current.connection_epoch
        {
            return Err(Status::failed_precondition(
                "supervisor host connection epoch is not newer than the current session",
            ));
        }
        observed.next_session += 1;
        let id = observed.next_session;
        for previous in replaced {
            if let Some(previous) = observed.sessions.remove(&previous) {
                tracing::info!(
                    subject = %previous.identity.subject,
                    instance_id = %previous.instance_id,
                    member = previous.member_id().unwrap_or_default(),
                    connection_epoch = previous.connection_epoch,
                    "superseding supervisor host session"
                );
                previous.superseded.send_replace(true);
            }
        }
        tracing::info!(
            subject = %identity.subject,
            instance_id = %hello.instance_id,
            member = member_id.as_deref().unwrap_or_default(),
            connection_epoch = hello.connection_epoch,
            session = id,
            "supervisor host attached"
        );
        let (superseded, watch) = watch::channel(false);
        observed.sessions.insert(
            id,
            HostSession {
                id,
                identity,
                instance_id: hello.instance_id.clone(),
                connection_epoch: hello.connection_epoch,
                member: hello.member.clone(),
                superseded,
                sent_revision: 0,
                status: None,
                connected_at_ms: unix_millis(),
            },
        );
        Ok((id, watch))
    }

    fn end_session(&self, id: u64) {
        let mut observed = lock(&self.inner.observed);
        if let Some(session) = observed.sessions.remove(&id) {
            tracing::info!(
                subject = %session.identity.subject,
                instance_id = %session.instance_id,
                member = session.member_id().unwrap_or_default(),
                session = id,
                "supervisor host detached; hosted instances keep running"
            );
        }
    }

    /// Note that `revision` was sent on session `id`.
    fn record_sent(&self, id: u64, revision: u64) {
        let mut observed = lock(&self.inner.observed);
        if let Some(session) = observed.sessions.get_mut(&id) {
            session.sent_revision = session.sent_revision.max(revision);
        }
    }

    /// Record a report from session `id`. Reports from other sessions, acks
    /// of revisions never sent on this session, regressing acks, and
    /// oversized reports are dropped.
    fn record_status(&self, id: u64, status: HostStatus) -> Result<(), &'static str> {
        let mut observed = lock(&self.inner.observed);
        let Some(session) = observed.sessions.get_mut(&id) else {
            return Err("report from a superseded supervisor host session");
        };
        if status.applied_revision > session.sent_revision {
            return Err("supervisor host acknowledged a revision it was never sent");
        }
        if status.instances.len() > MAX_REPORTED_INSTANCES {
            return Err("supervisor host status reports too many instances");
        }
        if session
            .status
            .as_ref()
            .is_some_and(|previous| status.applied_revision < previous.applied_revision)
        {
            return Err("supervisor host acknowledged an older revision than before");
        }
        let leaving = status.leaving
            && !session
                .status
                .as_ref()
                .is_some_and(|previous| previous.leaving);
        session.status = Some(status);
        drop(observed);
        if leaving {
            // Membership records follow the leaving flag at once.
            let mut desired = lock(&self.inner.desired);
            self.bump(&mut desired);
        }
        Ok(())
    }

    /// The snapshot for session `id`: every desired instance for a single
    /// host; for a pool member, the instances its process owns, the stop
    /// list, and the route directory. `None` until it can be authoritative.
    fn snapshot(&self, id: u64) -> Option<AssignmentSnapshot> {
        let mut desired = lock(&self.inner.desired);
        if !desired.initialized {
            return None;
        }
        let pool = lock(&self.inner.pool);
        let Some(pool) = pool.as_ref() else {
            return Some(AssignmentSnapshot {
                revision: desired.revision,
                instances: desired
                    .assignments
                    .values()
                    .map(|assigned| assigned.assignment.clone())
                    .collect(),
                ..AssignmentSnapshot::default()
            });
        };
        if !pool.loaded {
            return None;
        }
        let observed = lock(&self.inner.observed);
        let session = observed.sessions.get(&id)?;
        let member_id = session.member_id()?;
        let owned_by_session = |owner: &InstanceOwner| {
            owner.member_id == member_id && owner.process_id == session.instance_id
        };
        let instances = desired
            .assignments
            .values()
            .filter_map(|assigned| {
                let owner = pool.view.owners.get(&assigned.assignment.route)?;
                owned_by_session(owner).then(|| SandboxInstanceAssignment {
                    takeover: owner.takeover_term(),
                    ..assigned.assignment.clone()
                })
            })
            .collect();
        let now = tokio::time::Instant::now();
        desired
            .stopping
            .retain(|_, (_, since)| now.duration_since(*since) < POOL_STOP_RETENTION);
        let stop_routes = desired
            .stopping
            .iter()
            .filter(|(_, (owner, _))| owner.member_id == member_id)
            .map(|(route, _)| route.clone())
            .collect();
        let addresses = pool
            .view
            .members
            .iter()
            .map(|member| (member.member_id.as_str(), member.runtime_address.as_str()))
            .collect::<BTreeMap<_, _>>();
        let route_directory = pool
            .view
            .owners
            .iter()
            .filter_map(|(route, owner)| {
                Some(RouteOwner {
                    route: route.clone(),
                    runtime_address: (*addresses.get(owner.member_id.as_str())?).to_string(),
                })
            })
            .collect();
        // Owned instances whose launch material this gateway has not loaded,
        // such as one launched through another gateway moments ago, are kept
        // as they are rather than released.
        let keep_routes = pool
            .view
            .owners
            .iter()
            .filter(|(route, owner)| {
                owned_by_session(owner)
                    && !desired.assignments.contains_key(*route)
                    && !desired.stopping.contains_key(*route)
            })
            .map(|(route, _)| route.clone())
            .collect();
        Some(AssignmentSnapshot {
            revision: desired.revision,
            instances,
            pool: true,
            stop_routes,
            route_directory,
            keep_routes,
        })
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
        let (heartbeat_interval, silence_timeout) = if self.is_pool() {
            (POOL_HEARTBEAT_INTERVAL, POOL_SILENCE_TIMEOUT)
        } else {
            (HOST_HEARTBEAT_INTERVAL, HOST_SILENCE_TIMEOUT)
        };
        let mut revision = self.inner.revision.subscribe();
        let mut last_snapshot: Option<AssignmentSnapshot> = None;
        let mut sent_revision = 0;
        let mut last_heard = tokio::time::Instant::now();
        let mut heartbeat = tokio::time::interval(heartbeat_interval);
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
            let current = *revision.borrow_and_update();
            if current > sent_revision
                && let Some(snapshot) = self.snapshot(session_id)
            {
                // Pool members are only sent snapshots that change something
                // they act on.
                let unchanged = last_snapshot.as_ref().is_some_and(|previous| {
                    previous.pool
                        && previous.instances == snapshot.instances
                        && previous.stop_routes == snapshot.stop_routes
                        && previous.route_directory == snapshot.route_directory
                        && previous.keep_routes == snapshot.keep_routes
                });
                if !unchanged {
                    tracing::debug!(
                        session = session_id,
                        revision = snapshot.revision,
                        instances = snapshot.instances.len(),
                        "sending supervisor host assignment snapshot"
                    );
                    let revision_sent = snapshot.revision;
                    if !send(host_gateway_message::Payload::Assignments(snapshot.clone())).await {
                        return;
                    }
                    self.record_sent(session_id, revision_sent);
                    last_snapshot = Some(snapshot);
                }
                sent_revision = current;
            }
            tokio::select! {
                changed = revision.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                message = inbound.next() => match message {
                    Some(Ok(HostMessage { payload: Some(host_message::Payload::Status(status)) })) => {
                        last_heard = tokio::time::Instant::now();
                        if let Err(reason) = self.record_status(session_id, status) {
                            tracing::warn!(session = session_id, reason, "dropped supervisor host status report");
                        }
                    }
                    Some(Ok(HostMessage { payload: Some(host_message::Payload::Heartbeat(_)) })) => {
                        last_heard = tokio::time::Instant::now();
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
                    if last_heard.elapsed() > silence_timeout {
                        tracing::warn!(session = session_id, "supervisor host stream went silent; closing it");
                        return;
                    }
                    if !send(host_gateway_message::Payload::Heartbeat(HostGatewayHeartbeat {})).await {
                        return;
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

fn valid_member(member: &PoolMember) -> bool {
    let valid = |value: &str| {
        !value.is_empty() && value.len() <= 253 && !value.chars().any(char::is_whitespace)
    };
    valid(&member.member_id)
        && valid(&member.member_uid)
        && member
            .runtime_address
            .parse::<std::net::SocketAddr>()
            .is_ok()
}

fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
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
            takeover: None,
        }
    }

    fn status(applied_revision: u64, routes: &[&str]) -> HostStatus {
        HostStatus {
            leaving: false,
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
        assert!(controller.snapshot(0).is_none());
        assert!(!revision.has_changed().unwrap());

        let baseline = controller.revision();
        assert_eq!(
            controller.replace_assignments(
                baseline,
                [
                    assignment("rt-stopped-before-list", b"old"),
                    assignment("rt-listed", b"b"),
                ],
            ),
            Ok(1)
        );
        let snapshot = controller.snapshot(0).unwrap();
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
            ),
            Err(AssignmentError::Conflict {
                baseline: 1,
                current: 2
            })
        );
        assert!(controller.assignment("rt-listed").is_none());
        assert_eq!(controller.replace_assignments(2, []), Ok(3));
        assert!(controller.snapshot(0).unwrap().instances.is_empty());

        // The gateway refuses the assignment its host could not accept.
        let full =
            (0..MAX_ASSIGNED_INSTANCES).map(|index| assignment(&format!("rt-{index}"), b"x"));
        assert_eq!(controller.replace_assignments(3, full), Ok(4));
        assert_eq!(
            controller.assign(assignment("rt-one-too-many", b"x")),
            Err(AssignmentError::Capacity)
        );
        assert_eq!(controller.assign(assignment("rt-0", b"x")), Ok(()));
    }

    #[test]
    fn sessions_fence_stale_streams_epochs_and_acks() {
        let controller = SupervisorHostController::new();
        controller
            .replace_assignments(0, [assignment("rt-a", b"a")])
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
            member: None,
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
        assert_eq!(controller.observed("rt-unknown"), ObservedInstance::Absent);
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

    fn member_hello(member: &str, process: &str, connection_epoch: u64) -> HostHello {
        HostHello {
            instance_id: process.to_string(),
            connection_epoch,
            member: Some(PoolMember {
                member_id: member.to_string(),
                member_uid: format!("uid-{member}"),
                runtime_address: format!("10.0.0.{}:5500", member.len()),
            }),
        }
    }

    fn owner(member: &str, process: &str, auth_epoch: u64) -> InstanceOwner {
        InstanceOwner {
            member_id: member.to_string(),
            process_id: process.to_string(),
            auth_epoch,
            supervisor_instance_id: (auth_epoch > 1).then(|| format!("instance-{auth_epoch}")),
            takeover: (auth_epoch > 1).then(|| SandboxInstanceTakeover {
                auth_epoch,
                supervisor_instance_id: format!("instance-{auth_epoch}"),
                grant: format!("grant-{auth_epoch}"),
                ..SandboxInstanceTakeover::default()
            }),
        }
    }

    fn member_view(member: &str, process: &str) -> MemberView {
        MemberView {
            member_id: member.to_string(),
            process_id: process.to_string(),
            runtime_address: format!("10.0.0.{}:5500", member.len()),
            leaving: false,
        }
    }

    fn identity() -> HostIdentity {
        HostIdentity {
            subject: "openshell-supervisor:test".to_string(),
            token_id: "token".to_string(),
            expires_at: i64::MAX,
        }
    }

    fn routes(snapshot: &AssignmentSnapshot) -> Vec<&str> {
        snapshot
            .instances
            .iter()
            .map(|instance| instance.route.as_str())
            .collect()
    }

    #[tokio::test]
    async fn pool_members_receive_only_what_their_process_owns() {
        let controller = SupervisorHostController::new();
        controller.enable_pool();
        controller
            .replace_assignments(0, [assignment("rt-a", b"a"), assignment("rt-b", b"b")])
            .unwrap();
        let (one, _) = controller
            .begin_session(identity(), &member_hello("m1", "p1", 1))
            .unwrap();
        let (two, _) = controller
            .begin_session(identity(), &member_hello("m-2", "p2", 1))
            .unwrap();
        // Members coexist; nothing is authoritative before ownership loads,
        // so a restarted gateway never makes a member release its instances.
        assert!(controller.snapshot(one).is_none());
        assert_eq!(controller.connected_members().len(), 2);

        controller.update_pool(
            PoolView {
                members: vec![member_view("m1", "p1"), member_view("m-2", "p2")],
                owners: BTreeMap::from([
                    ("rt-a".to_string(), owner("m1", "p1", 1)),
                    ("rt-b".to_string(), owner("m-2", "p2", 1)),
                ]),
            },
            tokio::time::Instant::now(),
        );
        let first = controller.snapshot(one).unwrap();
        assert!(first.pool);
        assert_eq!(routes(&first), ["rt-a"]);
        assert!(first.instances[0].takeover.is_none());
        assert_eq!(routes(&controller.snapshot(two).unwrap()), ["rt-b"]);
        // Every member can redirect runtimes to any instance's owner.
        assert_eq!(
            first
                .route_directory
                .iter()
                .map(|entry| (entry.route.as_str(), entry.runtime_address.as_str()))
                .collect::<Vec<_>>(),
            [("rt-a", "10.0.0.2:5500"), ("rt-b", "10.0.0.3:5500")]
        );

        // A takeover moves rt-b to m1 with the new term's credentials; m2's
        // snapshot omits it, which releases it without stopping it.
        controller.update_pool(
            PoolView {
                members: vec![member_view("m1", "p1"), member_view("m-2", "p2")],
                owners: BTreeMap::from([
                    ("rt-a".to_string(), owner("m1", "p1", 1)),
                    ("rt-b".to_string(), owner("m1", "p1", 2)),
                ]),
            },
            tokio::time::Instant::now(),
        );
        let moved = controller.snapshot(one).unwrap();
        assert_eq!(routes(&moved), ["rt-a", "rt-b"]);
        assert_eq!(
            moved.instances[1]
                .takeover
                .as_ref()
                .map(|takeover| takeover.auth_epoch),
            Some(2)
        );
        let released = controller.snapshot(two).unwrap();
        assert!(released.instances.is_empty());
        assert!(released.stop_routes.is_empty());

        // A term whose credentials another gateway replica minted still names
        // its term, so a host that runs the instance for it keeps it.
        let mut unminted = owner("m1", "p1", 2);
        unminted.takeover = None;
        controller.update_pool(
            PoolView {
                members: vec![member_view("m1", "p1"), member_view("m-2", "p2")],
                owners: BTreeMap::from([
                    ("rt-a".to_string(), owner("m1", "p1", 1)),
                    ("rt-b".to_string(), unminted),
                ]),
            },
            tokio::time::Instant::now(),
        );
        let term = controller.snapshot(one).unwrap().instances[1]
            .takeover
            .clone()
            .expect("takeover term");
        assert_eq!(
            (term.auth_epoch, term.supervisor_instance_id.as_str()),
            (2, "instance-2")
        );
        assert!(term.grant.is_empty() && term.gateway_token.is_empty());

        // Withdrawing an instance lists it for its owner, and only its owner,
        // to stop.
        controller.unassign("rt-a");
        assert_eq!(controller.snapshot(one).unwrap().stop_routes, ["rt-a"]);
        assert!(controller.snapshot(two).unwrap().stop_routes.is_empty());
        assert!(controller.stopping_routes().contains("rt-a"));

        // A restarted process of a member supersedes that member's stream
        // only; it owns nothing until the gateway grants it a term.
        let (restarted, _) = controller
            .begin_session(identity(), &member_hello("m1", "p1-restarted", 1))
            .unwrap();
        assert!(controller.snapshot(one).is_none());
        assert!(controller.snapshot(restarted).unwrap().instances.is_empty());
        assert_eq!(
            routes(&controller.snapshot(two).unwrap()),
            Vec::<&str>::new()
        );
        // A delayed hello from an older connection of a member's current
        // process is refused.
        assert!(
            controller
                .begin_session(identity(), &member_hello("m-2", "p2", 1))
                .is_err()
        );
    }

    #[test]
    fn pool_observations_follow_the_owning_process_through_a_takeover() {
        let controller = SupervisorHostController::new();
        controller.enable_pool();
        controller
            .replace_assignments(0, [assignment("rt-b", b"b")])
            .unwrap();
        let (two, _) = controller
            .begin_session(identity(), &member_hello("m-2", "p2", 1))
            .unwrap();
        let (one, _) = controller
            .begin_session(identity(), &member_hello("m1", "p1", 1))
            .unwrap();
        // An unplaced instance has no verdict.
        assert_eq!(controller.observed("rt-b"), ObservedInstance::NoHost);
        controller.update_pool(
            PoolView {
                members: vec![member_view("m1", "p1"), member_view("m-2", "p2")],
                owners: BTreeMap::from([("rt-b".to_string(), owner("m-2", "p2", 1))]),
            },
            tokio::time::Instant::now(),
        );
        let revision = controller.revision();
        controller.record_sent(two, revision);
        controller
            .record_status(two, status(revision, &["rt-b"]))
            .unwrap();
        assert!(matches!(
            controller.observed("rt-b"),
            ObservedInstance::Reported(status) if status.ready
        ));
        // m1 reconciled before the takeover; it does not host rt-b, but that
        // is not evidence against the instance.
        controller.record_sent(one, revision);
        controller
            .record_status(one, status(revision, &[]))
            .unwrap();

        controller.update_pool(
            PoolView {
                members: vec![member_view("m1", "p1"), member_view("m-2", "p2")],
                owners: BTreeMap::from([("rt-b".to_string(), owner("m1", "p1", 2))]),
            },
            tokio::time::Instant::now(),
        );
        // The new owner has not reconciled to the takeover yet.
        assert_eq!(controller.observed("rt-b"), ObservedInstance::Pending);
        let takeover = controller.revision();
        controller.record_sent(one, takeover);
        controller
            .record_status(one, status(takeover, &["rt-b"]))
            .unwrap();
        assert!(matches!(
            controller.observed("rt-b"),
            ObservedInstance::Reported(_)
        ));
        // An owner process this gateway does not serve gives no verdict.
        controller.update_pool(
            PoolView {
                members: vec![member_view("m1", "p1")],
                owners: BTreeMap::from([("rt-b".to_string(), owner("m-3", "p3", 3))]),
            },
            tokio::time::Instant::now(),
        );
        assert_eq!(controller.observed("rt-b"), ObservedInstance::NoHost);
    }

    #[tokio::test]
    async fn pool_views_keep_fresh_placements_and_owned_instances() {
        let controller = SupervisorHostController::new();
        controller.enable_pool();
        controller
            .replace_assignments(0, [assignment("rt-a", b"a")])
            .unwrap();
        let (one, _) = controller
            .begin_session(identity(), &member_hello("m1", "p1", 1))
            .unwrap();
        let view = |routes: &[&str]| PoolView {
            members: vec![member_view("m1", "p1")],
            owners: routes
                .iter()
                .map(|route| ((*route).to_string(), owner("m1", "p1", 1)))
                .collect(),
        };
        controller.update_pool(view(&["rt-a"]), tokio::time::Instant::now());

        // A launch through this gateway places and assigns rt-b while a
        // reconciliation pass that listed owner records before it runs; the
        // pass's view must not release the new instance.
        let listed_before_launch = tokio::time::Instant::now();
        controller.place_owner("rt-b", owner("m1", "p1", 1));
        controller.assign(assignment("rt-b", b"b")).unwrap();
        controller.update_pool(view(&["rt-a"]), listed_before_launch);
        assert_eq!(routes(&controller.snapshot(one).unwrap()), ["rt-a", "rt-b"]);
        controller.update_pool(view(&["rt-a", "rt-b"]), tokio::time::Instant::now());
        assert_eq!(routes(&controller.snapshot(one).unwrap()), ["rt-a", "rt-b"]);

        // An owned instance whose launch material this gateway has not loaded
        // yet, such as one launched through another gateway, is kept as is.
        controller.update_pool(view(&["rt-a", "rt-b", "rt-c"]), tokio::time::Instant::now());
        let snapshot = controller.snapshot(one).unwrap();
        assert_eq!(routes(&snapshot), ["rt-a", "rt-b"]);
        assert_eq!(snapshot.keep_routes, ["rt-c"]);
        assert!(
            snapshot
                .route_directory
                .iter()
                .any(|entry| entry.route == "rt-c")
        );

        // A withdrawn instance is stopped, not kept, until a recovery assigns
        // it again.
        controller.unassign("rt-b");
        let snapshot = controller.snapshot(one).unwrap();
        assert_eq!(snapshot.stop_routes, ["rt-b"]);
        assert_eq!(snapshot.keep_routes, ["rt-c"]);
        controller
            .replace_assignments(
                controller.revision(),
                [assignment("rt-a", b"a"), assignment("rt-b", b"b")],
            )
            .unwrap();
        assert!(controller.snapshot(one).unwrap().stop_routes.is_empty());
        assert!(controller.stopping_routes().is_empty());
    }

    #[test]
    fn pool_member_identities_must_be_complete() {
        let member = member_hello("m1", "p1", 1).member.unwrap();
        assert!(valid_member(&member));
        for broken in [
            PoolMember {
                member_id: String::new(),
                ..member.clone()
            },
            PoolMember {
                member_uid: "uid with space".to_string(),
                ..member.clone()
            },
            PoolMember {
                runtime_address: "not-an-address".to_string(),
                ..member
            },
        ] {
            assert!(!valid_member(&broken));
        }
    }
}
