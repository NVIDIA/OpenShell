// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway side of the private supervisor host protocol
//! (`openshell.supervisor.host.v1`).
//!
//! Shared supervisors always run as a pool (high availability) that the
//! gateway coordinates. The [`SharedSupervision`](crate::SharedSupervision)
//! coordinator publishes launches and withdrawals here on behalf of a compute
//! driver; the gateway's gRPC server hands each member stream authenticated
//! by a supervisor token to [`SupervisorHostController::attach`], which sends
//! complete snapshots and records what the member reports. The gateway also
//! mints that token and publishes each renewal here for the driver to deliver.
//!
//! The pool's desired set, the durable owner of every instance (a member's
//! process and an ownership term), and the latest reports of owners served by
//! other gateway replicas come from the gateway's durable records through
//! [`PoolView`], on every gateway replica alike; each member is sent only the
//! instances its current process owns, with the credentials of their term. A
//! member releases, without stopping, an instance a snapshot omits; only
//! withdrawn instances are listed for stopping. Nothing is sent to members
//! until the first view has been loaded, so a restarted gateway never
//! releases running instances.
//!
//! Every member names itself in its hello. A new attach from a newer
//! connection of the same member process, or from a new process of the
//! member, supersedes the member's current session; reports and acks from a
//! superseded stream are dropped, and a delayed hello from an older
//! connection of the current process is refused. Several members are served
//! at once.

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

/// Recovery deadline a supervisor pool offers each sandbox runtime unless the
/// gateway configures another.
///
/// Membership expiry, one reconciliation pass, and a replacement instance's
/// startup fit with room to spare.
pub const POOL_RECOVERY_TIMEOUT_SECS: u32 = 60;

/// Heartbeat interval of pool members, whose liveness drives failover.
pub const POOL_HEARTBEAT_INTERVAL: Duration = crate::pool_timing::HEARTBEAT_INTERVAL;
/// Silence after which the gateway closes a pool member's stream.
const POOL_SILENCE_TIMEOUT: Duration = crate::pool_timing::GATEWAY_SILENCE_TIMEOUT;
/// Bound on the host sending its hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on queueing one gateway-to-host message. A member's served stream
/// keeps its membership record alive, so a member that stops reading is
/// dropped as soon as one that stops writing.
const SEND_TIMEOUT: Duration = crate::pool_timing::GATEWAY_SILENCE_TIMEOUT;
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

/// The gateway's durable view of a supervisor pool, replaced as a whole by
/// the gateway's pool reconciler on every replica.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct PoolView {
    pub members: Vec<MemberView>,
    /// Owner of each placed route.
    pub owners: BTreeMap<String, InstanceOwner>,
    /// Every route the pool must run, from the gateway's durable records. An
    /// owned route that is not desired was withdrawn.
    pub desired: BTreeSet<String>,
    /// Assignments, launch material included, this gateway replica loaded
    /// for routes its members own. An owned desired route missing here is
    /// kept by its owner as it is.
    pub assignments: BTreeMap<String, SandboxInstanceAssignment>,
    /// Latest report of each route's current owner term, recorded by the
    /// gateway replica that serves the owner, for judging instances whose
    /// owner streams to another replica.
    pub reports: BTreeMap<String, SandboxInstanceStatus>,
}

impl std::fmt::Debug for PoolView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PoolView")
            .field("members", &self.members)
            .field("owners", &self.owners)
            .field("desired", &self.desired)
            .field("assignments", &self.assignments.keys().collect::<Vec<_>>())
            .field("reports", &self.reports.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// What a pool member's stream served here last reported of one instance,
/// for the gateway to record durably under the ownership term it belongs to,
/// so other replicas can judge the instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberReport {
    pub member_id: String,
    pub process_id: String,
    /// Ownership term the reporting stream had applied for the route when it
    /// reported: the term of the snapshot that last installed the route on
    /// the stream, once the stream acknowledged it.
    pub auth_epoch: u64,
    /// When the reporting stream was accepted (Unix milliseconds).
    pub connected_at_ms: i64,
    pub status: SandboxInstanceStatus,
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
    /// Withdrawn instances to stop, with the owner and the time of
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
struct Pool {
    loaded: bool,
    view: PoolView,
    owned_since: BTreeMap<String, u64>,
    /// Owners placed by launches on this gateway, with when, so a view whose
    /// records were listed before a placement does not drop it.
    placed: BTreeMap<String, (InstanceOwner, tokio::time::Instant)>,
    /// Instances launched through this gateway, with when, kept over views
    /// listed before them.
    launched: BTreeMap<String, tokio::time::Instant>,
    /// Instances withdrawn here whose durable records the gateway has not
    /// removed yet; they are not desired whatever a view says.
    withdrawals: BTreeSet<String>,
    /// Recovery deadline offered to every instance's runtime.
    recovery_timeout_secs: u32,
}

impl Pool {
    fn new(recovery_timeout_secs: u32) -> Self {
        Self {
            loaded: false,
            view: PoolView::default(),
            owned_since: BTreeMap::new(),
            placed: BTreeMap::new(),
            launched: BTreeMap::new(),
            withdrawals: BTreeSet::new(),
            recovery_timeout_secs,
        }
    }
}

struct HostSession {
    id: u64,
    identity: HostIdentity,
    instance_id: String,
    connection_epoch: u64,
    member: PoolMember,
    superseded: watch::Sender<bool>,
    /// Highest snapshot revision sent on this stream; acks beyond it are
    /// impossible and rejected.
    sent_revision: u64,
    /// Latest report of this session.
    status: Option<HostStatus>,
    connected_at_ms: i64,
    /// Ownership term of each route the snapshots sent on this stream assign
    /// or keep, with the revision that first installed that term.
    terms: BTreeMap<String, (u64, u64)>,
    /// Terms of the last snapshot built for this stream, committed to
    /// `terms` once that snapshot is sent.
    pending_terms: Option<PendingTerms>,
}

/// Terms of one snapshot: the revision, the routes it assigns, and the routes
/// it keeps as they are.
struct PendingTerms {
    revision: u64,
    assigned: BTreeMap<String, u64>,
    kept: BTreeMap<String, u64>,
}

impl HostSession {
    fn member_id(&self) -> &str {
        &self.member.member_id
    }
}

#[derive(Default)]
struct Observed {
    sessions: BTreeMap<u64, HostSession>,
    next_session: u64,
}

struct Inner {
    desired: Mutex<Desired>,
    /// The supervisor pool: its durable view and what this gateway placed,
    /// launched, and withdrawn since.
    pool: Mutex<Pool>,
    /// The gateway's durable placement of new pool instances.
    placement: Mutex<Option<Arc<dyn crate::coordinator::InstancePlacement>>>,
    /// Latest supervisor token the gateway minted; `None` until the first.
    credential: watch::Sender<Option<SupervisorCredential>>,
    /// Current revision of everything snapshots are derived from; 0 while
    /// uninitialized.
    revision: watch::Sender<u64>,
    /// Counts changes to the pool members this gateway serves: a member
    /// stream attached or ended, or a member announced leaving.
    membership: watch::Sender<u64>,
    observed: Mutex<Observed>,
}

/// Gateway-owned desired assignments and observed status of the shared
/// supervisor pool.
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
    /// The change would assign more instances than the pool runs, or no
    /// member has room.
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
                pool: Mutex::new(Pool::new(POOL_RECOVERY_TIMEOUT_SECS)),
                placement: Mutex::new(None),
                credential: watch::Sender::new(None),
                revision: watch::Sender::new(0),
                membership: watch::Sender::new(0),
                observed: Mutex::new(Observed::default()),
            }),
        }
    }

    /// Offer every instance's runtime `recovery_timeout_secs` instead of
    /// [`POOL_RECOVERY_TIMEOUT_SECS`]. Call it before any host attaches.
    pub fn set_recovery_timeout_secs(&self, recovery_timeout_secs: u32) {
        lock(&self.inner.pool).recovery_timeout_secs = recovery_timeout_secs;
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

    /// Current desired revision: 0 while uninitialized. The coordinator reads
    /// it through
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

    fn bump(&self, desired: &mut Desired) -> u64 {
        desired.revision += 1;
        self.inner.revision.send_replace(desired.revision);
        desired.revision
    }

    /// Assign one instance, served at once and kept over views listed
    /// before it; its durable record makes it desired on every gateway
    /// replica. Refused beyond the pool's capacity, so the caller fails its
    /// create before anything runs.
    pub fn assign(&self, assignment: SandboxInstanceAssignment) -> Result<(), AssignmentError> {
        let mut desired = lock(&self.inner.desired);
        if !desired.assignments.contains_key(&assignment.route)
            && desired.assignments.len() >= MAX_POOL_INSTANCES
        {
            return Err(AssignmentError::Capacity);
        }
        {
            let mut pool = lock(&self.inner.pool);
            pool.launched
                .insert(assignment.route.clone(), tokio::time::Instant::now());
            pool.withdrawals.remove(&assignment.route);
            pool.view.desired.insert(assignment.route.clone());
        }
        let next = desired.revision + 1;
        desired.stopping.remove(&assignment.route);
        if desired.put(assignment, next) {
            desired.revision = next;
            self.inner.revision.send_replace(next);
        }
        Ok(())
    }

    /// Withdraw one instance so its owner stops it. The withdrawal is also
    /// listed for the gateway to remove the instance's durable record (see
    /// [`Self::pool_withdrawals`]).
    pub fn unassign(&self, route: &str) {
        let mut desired = lock(&self.inner.desired);
        let owner = {
            let mut pool = lock(&self.inner.pool);
            pool.launched.remove(route);
            pool.withdrawals.insert(route.to_string());
            pool.view.desired.remove(route);
            pool.view.owners.get(route).cloned()
        };
        let removed = desired.assignments.remove(route).is_some();
        if let Some(owner) = &owner {
            desired.stopping.insert(
                route.to_string(),
                (owner.clone(), tokio::time::Instant::now()),
            );
        }
        if removed || owner.is_some() {
            self.bump(&mut desired);
        }
    }

    /// Replace the durable pool view, derived from records listed at
    /// `listed_at`; the view's loaded assignments become the desired
    /// assignments this gateway serves. Owners placed and instances launched
    /// here since then are kept until a view includes them, and instances
    /// withdrawn here stay withdrawn until their records are gone. An owned
    /// instance that leaves the desired set is listed for its owner to stop.
    /// Owners whose term is new to this gateway are recorded as assigned at
    /// the next revision, so their host is considered reconciling until it
    /// acknowledges it.
    pub fn update_pool(&self, mut view: PoolView, listed_at: tokio::time::Instant) {
        let mut desired = lock(&self.inner.desired);
        let mut pool_guard = lock(&self.inner.pool);
        let pool = &mut *pool_guard;
        pool.placed
            .retain(|_, (_, placed_at)| *placed_at >= listed_at);
        for (route, (owner, _)) in &pool.placed {
            view.owners
                .entry(route.clone())
                .or_insert_with(|| owner.clone());
        }
        pool.launched
            .retain(|_, launched_at| *launched_at >= listed_at);
        for route in pool.launched.keys() {
            view.desired.insert(route.clone());
            if let Some(assigned) = desired.assignments.get(route) {
                view.assignments
                    .entry(route.clone())
                    .or_insert_with(|| assigned.assignment.clone());
            }
        }
        for route in &pool.withdrawals {
            view.desired.remove(route);
            view.assignments.remove(route);
        }
        let now = tokio::time::Instant::now();
        let stopping_before = desired.stopping.len();
        if pool.loaded {
            for route in pool.view.desired.difference(&view.desired) {
                if let Some(owner) = pool.view.owners.get(route) {
                    desired
                        .stopping
                        .entry(route.clone())
                        .or_insert_with(|| (owner.clone(), now));
                }
            }
        }
        // A desired route is not being stopped, whatever an earlier
        // withdrawal recorded.
        desired
            .stopping
            .retain(|route, _| !view.desired.contains(route));
        let stops_changed = desired.stopping.len() != stopping_before;
        if pool.loaded && desired.initialized && pool.view == view && !stops_changed {
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
        let assignments = view
            .assignments
            .iter()
            .map(|(route, assignment)| {
                let revision = desired
                    .assignments
                    .get(route)
                    .filter(|assigned| assigned.assignment == *assignment)
                    .map_or(next, |assigned| assigned.revision);
                (
                    route.clone(),
                    Assigned {
                        assignment: assignment.clone(),
                        revision,
                    },
                )
            })
            .collect();
        desired.assignments = assignments;
        desired.initialized = true;
        pool.view = view;
        pool.loaded = true;
        drop(pool_guard);
        desired.revision = next;
        self.inner.revision.send_replace(next);
    }

    /// Routes withdrawn here whose durable records the gateway still has to
    /// remove; see [`Self::forget_withdrawal`].
    #[must_use]
    pub fn pool_withdrawals(&self) -> Vec<String> {
        lock(&self.inner.pool).withdrawals.iter().cloned().collect()
    }

    /// The durable record of a route withdrawn here is gone.
    pub fn forget_withdrawal(&self, route: &str) {
        lock(&self.inner.pool).withdrawals.remove(route);
    }

    /// Recovery deadline the pool offers each instance's runtime.
    #[must_use]
    pub fn pool_recovery_timeout_secs(&self) -> u32 {
        lock(&self.inner.pool).recovery_timeout_secs
    }

    /// What the pool members served here last reported of their instances.
    /// The caller attributes each report to the owner term its own records
    /// show, and drops reports of routes the reporting process does not own.
    #[must_use]
    pub fn member_reports(&self) -> Vec<MemberReport> {
        let observed = lock(&self.inner.observed);
        let mut reports = Vec::new();
        for session in observed.sessions.values() {
            let member_id = session.member_id();
            let Some(status) = &session.status else {
                continue;
            };
            // A report counts only for a term the stream acknowledged; a
            // status from before the term's snapshot describes an earlier
            // term, even from the same process.
            reports.extend(status.instances.iter().filter_map(|instance| {
                let (auth_epoch, since) = session.terms.get(&instance.route)?;
                (status.applied_revision >= *since).then(|| MemberReport {
                    member_id: member_id.to_string(),
                    process_id: session.instance_id.clone(),
                    auth_epoch: *auth_epoch,
                    connected_at_ms: session.connected_at_ms,
                    status: instance.clone(),
                })
            }));
        }
        reports
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
        let pool = &mut *pool_guard;
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
        let pool = lock(&self.inner.pool);
        pool.loaded.then(|| pool.view.clone())
    }

    /// Pool members whose streams this gateway serves, for its durable
    /// membership records.
    #[must_use]
    pub fn connected_members(&self) -> Vec<ConnectedMember> {
        lock(&self.inner.observed)
            .sessions
            .values()
            .map(|session| ConnectedMember {
                member_id: session.member.member_id.clone(),
                member_uid: session.member.member_uid.clone(),
                process_id: session.instance_id.clone(),
                runtime_address: session.member.runtime_address.clone(),
                leaving: session.status.as_ref().is_some_and(|status| status.leaving),
                connected_at_ms: session.connected_at_ms,
            })
            .collect()
    }

    /// Changes whenever [`Self::connected_members`] gains or loses a stream
    /// or a member announces leaving, so membership records follow at once.
    #[must_use]
    pub fn membership_changes(&self) -> watch::Receiver<u64> {
        self.inner.membership.subscribe()
    }

    fn membership_changed(&self) {
        self.inner
            .membership
            .send_modify(|changes| *changes = changes.wrapping_add(1));
    }

    /// Whether a host session is currently connected.
    #[must_use]
    pub fn host_connected(&self) -> bool {
        !lock(&self.inner.observed).sessions.is_empty()
    }

    /// What the pool reports for `route`: the session of the route's owning
    /// process, or the owner's recorded report when it streams elsewhere.
    #[must_use]
    pub fn observed(&self, route: &str) -> ObservedInstance {
        let desired = lock(&self.inner.desired);
        let pool = lock(&self.inner.pool);
        let observed = lock(&self.inner.observed);
        let Some(owner) = pool.view.owners.get(route) else {
            return ObservedInstance::NoHost;
        };
        let Some(session) = observed.sessions.values().find(|session| {
            session.member_id() == owner.member_id && session.instance_id == owner.process_id
        }) else {
            // The owner streams to another gateway replica, which records its
            // reports for every replica.
            return pool
                .view
                .reports
                .get(route)
                .map_or(ObservedInstance::NoHost, |status| {
                    ObservedInstance::Reported(status.clone())
                });
        };
        let assigned = desired
            .assignments
            .get(route)
            .map(|assigned| assigned.revision);
        let assigned_revision = assigned.max(pool.owned_since.get(route).copied());
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
        let Some(member) = &hello.member else {
            return Err(Status::failed_precondition(MISSING_MEMBER));
        };
        validate_member(member).map_err(Status::invalid_argument)?;
        let heartbeat = POOL_HEARTBEAT_INTERVAL;
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

    /// Start a session for `hello`, superseding the same member's session. A
    /// hello that names no member is refused. A hello from the current host
    /// process with a connection epoch that is not newer is a delayed or
    /// replayed connection and is refused.
    fn begin_session(
        &self,
        identity: HostIdentity,
        hello: &HostHello,
    ) -> Result<(u64, watch::Receiver<bool>), Status> {
        let member = hello
            .member
            .clone()
            .ok_or_else(|| Status::failed_precondition(MISSING_MEMBER))?;
        let mut observed = lock(&self.inner.observed);
        let member_id = member.member_id.clone();
        let replaced = observed
            .sessions
            .values()
            .filter(|session| session.member_id() == member_id)
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
                    member = previous.member_id(),
                    connection_epoch = previous.connection_epoch,
                    "superseding supervisor host session"
                );
                previous.superseded.send_replace(true);
            }
        }
        tracing::info!(
            subject = %identity.subject,
            instance_id = %hello.instance_id,
            member = %member_id,
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
                member,
                superseded,
                sent_revision: 0,
                status: None,
                connected_at_ms: unix_millis(),
                terms: BTreeMap::new(),
                pending_terms: None,
            },
        );
        drop(observed);
        self.membership_changed();
        Ok((id, watch))
    }

    fn end_session(&self, id: u64) {
        let mut observed = lock(&self.inner.observed);
        let Some(session) = observed.sessions.remove(&id) else {
            return;
        };
        drop(observed);
        tracing::info!(
            subject = %session.identity.subject,
            instance_id = %session.instance_id,
            member = session.member_id(),
            session = id,
            "supervisor host detached; hosted instances keep running"
        );
        self.membership_changed();
    }

    /// Note that `revision` was sent on session `id`. A route keeps the
    /// revision that installed its term while snapshots repeat the term; a
    /// new term is installed by `revision`; a kept route keeps only the term
    /// it already had, and a route the snapshot omits has none.
    fn record_sent(&self, id: u64, revision: u64) {
        let mut observed = lock(&self.inner.observed);
        if let Some(session) = observed.sessions.get_mut(&id) {
            session.sent_revision = session.sent_revision.max(revision);
            if let Some(pending) = session
                .pending_terms
                .take()
                .filter(|pending| pending.revision == revision)
            {
                let previous = std::mem::take(&mut session.terms);
                let installed = |route: &String, epoch: u64| {
                    previous
                        .get(route)
                        .filter(|(installed, _)| *installed == epoch)
                        .map(|(_, since)| *since)
                };
                session.terms = pending
                    .assigned
                    .iter()
                    .map(|(route, epoch)| {
                        let since = installed(route, *epoch).unwrap_or(revision);
                        (route.clone(), (*epoch, since))
                    })
                    .chain(pending.kept.iter().filter_map(|(route, epoch)| {
                        let since = installed(route, *epoch)?;
                        Some((route.clone(), (*epoch, since)))
                    }))
                    .collect();
            }
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
            self.membership_changed();
            let mut desired = lock(&self.inner.desired);
            self.bump(&mut desired);
        }
        Ok(())
    }

    /// The snapshot for session `id`'s member: the instances its process
    /// owns, the stop list, and the route directory. `None` until it can be
    /// authoritative.
    fn snapshot(&self, id: u64) -> Option<AssignmentSnapshot> {
        let mut desired = lock(&self.inner.desired);
        if !desired.initialized {
            return None;
        }
        let pool = lock(&self.inner.pool);
        if !pool.loaded {
            return None;
        }
        let mut observed = lock(&self.inner.observed);
        let session = observed.sessions.get_mut(&id)?;
        let member_id = session.member_id().to_string();
        let instance_id = session.instance_id.clone();
        let owned_by_session =
            |owner: &InstanceOwner| owner.member_id == member_id && owner.process_id == instance_id;
        let mut assigned_terms = BTreeMap::new();
        let instances = desired
            .assignments
            .values()
            .filter_map(|assigned| {
                let owner = pool.view.owners.get(&assigned.assignment.route)?;
                owned_by_session(owner).then(|| {
                    assigned_terms.insert(assigned.assignment.route.clone(), owner.auth_epoch);
                    SandboxInstanceAssignment {
                        takeover: owner.takeover_term(),
                        ..assigned.assignment.clone()
                    }
                })
            })
            .collect();
        let now = tokio::time::Instant::now();
        desired
            .stopping
            .retain(|_, (_, since)| now.duration_since(*since) < POOL_STOP_RETENTION);
        // Withdrawn here, or owned yet no longer desired anywhere.
        let stop_routes = desired
            .stopping
            .iter()
            .filter(|(_, (owner, _))| owner.member_id == *member_id)
            .map(|(route, _)| route.clone())
            .chain(
                pool.view
                    .owners
                    .iter()
                    .filter(|(route, owner)| {
                        owner.member_id == *member_id
                            && !pool.view.desired.contains(*route)
                            && !desired.stopping.contains_key(*route)
                    })
                    .map(|(route, _)| route.clone()),
            )
            .collect::<BTreeSet<_>>()
            .into_iter()
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
        // Owned desired instances whose launch material this gateway has not
        // loaded yet are kept as they are rather than released.
        let kept_terms = pool
            .view
            .owners
            .iter()
            .filter(|(route, owner)| {
                owned_by_session(owner)
                    && pool.view.desired.contains(*route)
                    && !desired.assignments.contains_key(*route)
                    && !desired.stopping.contains_key(*route)
            })
            .map(|(route, owner)| (route.clone(), owner.auth_epoch))
            .collect::<BTreeMap<_, _>>();
        let keep_routes = kept_terms.keys().cloned().collect();
        session.pending_terms = Some(PendingTerms {
            revision: desired.revision,
            assigned: assigned_terms,
            kept: kept_terms,
        });
        Some(AssignmentSnapshot {
            revision: desired.revision,
            instances,
            pool: true,
            stop_routes,
            route_directory,
            keep_routes,
            recovery_timeout: Some(prost_types::Duration {
                seconds: i64::from(pool.recovery_timeout_secs),
                nanos: 0,
            }),
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
        let (heartbeat_interval, silence_timeout, send_timeout) =
            (POOL_HEARTBEAT_INTERVAL, POOL_SILENCE_TIMEOUT, SEND_TIMEOUT);
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
                    send_timeout,
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
                // Members are only sent snapshots that change something they
                // act on.
                let unchanged = last_snapshot.as_ref().is_some_and(|previous| {
                    previous.instances == snapshot.instances
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
                                send_timeout,
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

/// Why a hello without a pool member is refused.
const MISSING_MEMBER: &str = "the shared supervisor did not name its pool member; set \
OPENSHELL_SUPERVISOR_POOL_MEMBER_ID, OPENSHELL_SUPERVISOR_POOL_MEMBER_UID, and \
OPENSHELL_SUPERVISOR_POOL_ADVERTISE_IP (the OpenShell Helm chart sets them from the Pod name, \
UID, and IP)";

/// Check a pool member's identity, naming the setting that is wrong.
fn validate_member(member: &PoolMember) -> Result<(), &'static str> {
    let valid = |value: &str| {
        !value.is_empty() && value.len() <= 253 && !value.chars().any(char::is_whitespace)
    };
    if !valid(&member.member_id) {
        return Err(
            "the shared supervisor's pool member id is empty or invalid; set \
OPENSHELL_SUPERVISOR_POOL_MEMBER_ID to its Pod name",
        );
    }
    if !valid(&member.member_uid) {
        return Err(
            "the shared supervisor's pool member UID is empty or invalid; set \
OPENSHELL_SUPERVISOR_POOL_MEMBER_UID to its Pod UID",
        );
    }
    if member
        .runtime_address
        .parse::<std::net::SocketAddr>()
        .is_err()
    {
        return Err(
            "the shared supervisor's pool member runtime address is invalid; set \
OPENSHELL_SUPERVISOR_POOL_ADVERTISE_IP to its Pod IP",
        );
    }
    Ok(())
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
    fn assignments_are_refused_beyond_the_pools_capacity() {
        let controller = SupervisorHostController::new();
        for index in 0..MAX_POOL_INSTANCES {
            controller
                .assign(assignment(&format!("rt-{index}"), b"x"))
                .unwrap();
        }
        assert_eq!(
            controller.assign(assignment("rt-one-too-many", b"x")),
            Err(AssignmentError::Capacity)
        );
        // Assigning a route again is not a new instance.
        assert_eq!(controller.assign(assignment("rt-0", b"x")), Ok(()));
    }

    #[test]
    fn sessions_fence_stale_streams_epochs_and_acks() {
        let controller = SupervisorHostController::new();
        controller.update_pool(
            loaded_view(
                vec![member_view("m1", "boot-1")],
                [("rt-a", owner("m1", "boot-1", 1))],
            ),
            tokio::time::Instant::now(),
        );
        assert_eq!(controller.observed("rt-a"), ObservedInstance::NoHost);

        let (first, superseded) = controller
            .begin_session(identity(), &member_hello("m1", "boot-1", 1))
            .unwrap();
        assert_eq!(controller.observed("rt-a"), ObservedInstance::Pending);

        // A delayed hello from an older connection of the same process is
        // refused; a newer one supersedes the stream.
        assert!(
            controller
                .begin_session(identity(), &member_hello("m1", "boot-1", 1))
                .is_err()
        );
        let (current, _) = controller
            .begin_session(identity(), &member_hello("m1", "boot-1", 2))
            .unwrap();
        assert!(*superseded.borrow());
        assert!(controller.record_status(first, status(0, &[])).is_err());

        // Acks are bounded by what this stream was sent and never regress.
        let revision = controller.revision();
        assert!(
            controller
                .record_status(current, status(revision, &[]))
                .is_err()
        );
        controller.record_sent(current, revision);
        controller
            .record_status(current, status(revision, &["rt-a"]))
            .unwrap();
        assert!(controller.record_status(current, status(0, &[])).is_err());
        assert!(matches!(
            controller.observed("rt-a"),
            ObservedInstance::Reported(status) if status.ready
        ));

        // A newer instance of the process is pending until its member
        // reconciles past it; a route without an owner has no verdict.
        controller.assign(assignment("rt-b", b"b")).unwrap();
        controller.place_owner("rt-b", owner("m1", "boot-1", 1));
        assert_eq!(controller.observed("rt-b"), ObservedInstance::Pending);
        assert_eq!(controller.observed("rt-unknown"), ObservedInstance::NoHost);
        let next = controller.revision();
        controller.record_sent(current, next);
        controller
            .record_status(current, status(next, &[]))
            .unwrap();
        assert_eq!(controller.observed("rt-b"), ObservedInstance::Absent);

        // A new process of the member always takes over; ending a stale
        // session is a no-op.
        let (replacement, _) = controller
            .begin_session(identity(), &member_hello("m1", "boot-2", 1))
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

    /// A pool view in which every owned route is desired and loaded.
    fn loaded_view(
        members: Vec<MemberView>,
        owners: impl IntoIterator<Item = (&'static str, InstanceOwner)>,
    ) -> PoolView {
        let owners = owners
            .into_iter()
            .map(|(route, owner)| (route.to_string(), owner))
            .collect::<BTreeMap<_, _>>();
        PoolView {
            members,
            desired: owners.keys().cloned().collect(),
            assignments: owners
                .keys()
                .map(|route| (route.clone(), assignment(route, route.as_bytes())))
                .collect(),
            owners,
            reports: BTreeMap::new(),
        }
    }

    fn routes(snapshot: &AssignmentSnapshot) -> Vec<&str> {
        snapshot
            .instances
            .iter()
            .map(|instance| instance.route.as_str())
            .collect()
    }

    #[test]
    fn membership_changes_follow_member_streams_and_leaving() {
        let controller = SupervisorHostController::new();
        let mut changes = controller.membership_changes();
        changes.mark_unchanged();
        let (first, _) = controller
            .begin_session(identity(), &member_hello("m1", "p1", 1))
            .unwrap();
        assert!(changes.has_changed().unwrap(), "a member attached");
        changes.mark_unchanged();
        // A newer stream of the same member supersedes the first.
        let (second, _) = controller
            .begin_session(identity(), &member_hello("m1", "p1", 2))
            .unwrap();
        assert!(changes.has_changed().unwrap(), "a member reconnected");
        changes.mark_unchanged();
        // Ending the superseded stream changes nothing anyone serves.
        controller.end_session(first);
        assert!(!changes.has_changed().unwrap());
        let status = |leaving| HostStatus {
            applied_revision: 0,
            instances: Vec::new(),
            leaving,
        };
        controller.record_status(second, status(false)).unwrap();
        assert!(!changes.has_changed().unwrap(), "an ordinary report");
        controller.record_status(second, status(true)).unwrap();
        assert!(changes.has_changed().unwrap(), "the member is leaving");
        changes.mark_unchanged();
        controller.end_session(second);
        assert!(changes.has_changed().unwrap(), "the member's stream ended");
    }

    #[tokio::test]
    async fn pool_members_receive_only_what_their_process_owns() {
        let controller = SupervisorHostController::new();
        controller.set_recovery_timeout_secs(75);
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
            loaded_view(
                vec![member_view("m1", "p1"), member_view("m-2", "p2")],
                [
                    ("rt-a", owner("m1", "p1", 1)),
                    ("rt-b", owner("m-2", "p2", 1)),
                ],
            ),
            tokio::time::Instant::now(),
        );
        let first = controller.snapshot(one).unwrap();
        assert!(first.pool);
        // Every member offers its instances' runtimes the pool's deadline.
        assert_eq!(
            first.recovery_timeout,
            Some(prost_types::Duration {
                seconds: 75,
                nanos: 0
            })
        );
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
            loaded_view(
                vec![member_view("m1", "p1"), member_view("m-2", "p2")],
                [
                    ("rt-a", owner("m1", "p1", 1)),
                    ("rt-b", owner("m1", "p1", 2)),
                ],
            ),
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
            loaded_view(
                vec![member_view("m1", "p1"), member_view("m-2", "p2")],
                [("rt-a", owner("m1", "p1", 1)), ("rt-b", unminted)],
            ),
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
        // to stop, and for the gateway to remove its durable record.
        controller.unassign("rt-a");
        assert_eq!(controller.snapshot(one).unwrap().stop_routes, ["rt-a"]);
        assert!(controller.snapshot(two).unwrap().stop_routes.is_empty());
        assert!(controller.stopping_routes().contains("rt-a"));
        assert_eq!(controller.pool_withdrawals(), ["rt-a"]);

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
    fn reports_count_only_for_the_term_their_stream_acknowledged() {
        let controller = SupervisorHostController::new();
        let (one, _) = controller
            .begin_session(identity(), &member_hello("m1", "p1", 1))
            .unwrap();
        let members = || vec![member_view("m1", "p1"), member_view("m-2", "p2")];
        let send = |owner: InstanceOwner| {
            controller.update_pool(
                loaded_view(members(), [("rt-a", owner)]),
                tokio::time::Instant::now(),
            );
            let revision = controller.snapshot(one).unwrap().revision;
            controller.record_sent(one, revision);
            revision
        };
        let terms = || {
            controller
                .member_reports()
                .into_iter()
                .map(|report| (report.status.route, report.auth_epoch))
                .collect::<Vec<_>>()
        };
        let first = send(owner("m1", "p1", 1));
        controller
            .record_status(one, status(first, &["rt-a"]))
            .unwrap();
        assert_eq!(terms(), [("rt-a".to_string(), 1)]);
        // Another member takes rt-a over, then it returns to the same,
        // still running process at a later term, before the process applied
        // either snapshot.
        send(owner("m-2", "p2", 2));
        assert!(terms().is_empty());
        let third = send(owner("m1", "p1", 3));
        // Its status from term 1 still lists rt-a as ready; that is not term
        // 3's readiness.
        controller
            .record_status(one, status(first, &["rt-a"]))
            .unwrap();
        assert!(terms().is_empty());
        controller
            .record_status(one, status(third, &["rt-a"]))
            .unwrap();
        assert_eq!(terms(), [("rt-a".to_string(), 3)]);
        // A later snapshot that repeats the term keeps it installed.
        let later = send(owner("m1", "p1", 3));
        assert!(later >= third);
        assert_eq!(terms(), [("rt-a".to_string(), 3)]);
    }

    #[test]
    fn pool_observations_follow_the_owning_process_through_a_takeover() {
        let controller = SupervisorHostController::new();
        let (two, _) = controller
            .begin_session(identity(), &member_hello("m-2", "p2", 1))
            .unwrap();
        let (one, _) = controller
            .begin_session(identity(), &member_hello("m1", "p1", 1))
            .unwrap();
        // An unplaced instance has no verdict.
        assert_eq!(controller.observed("rt-b"), ObservedInstance::NoHost);
        controller.update_pool(
            loaded_view(
                vec![member_view("m1", "p1"), member_view("m-2", "p2")],
                [("rt-b", owner("m-2", "p2", 1))],
            ),
            tokio::time::Instant::now(),
        );
        let revision = controller.snapshot(two).unwrap().revision;
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
            loaded_view(
                vec![member_view("m1", "p1"), member_view("m-2", "p2")],
                [("rt-b", owner("m1", "p1", 2))],
            ),
            tokio::time::Instant::now(),
        );
        // The new owner has not reconciled to the takeover yet.
        assert_eq!(controller.observed("rt-b"), ObservedInstance::Pending);
        let takeover = controller.snapshot(one).unwrap().revision;
        controller.record_sent(one, takeover);
        controller
            .record_status(one, status(takeover, &["rt-b"]))
            .unwrap();
        assert!(matches!(
            controller.observed("rt-b"),
            ObservedInstance::Reported(_)
        ));
        // Each stream's reports are offered for recording under the term it
        // acknowledged: the new owner's under term 2, and the previous
        // owner's, which has not applied its release yet, under term 1.
        let mut reports = controller
            .member_reports()
            .into_iter()
            .map(|report| {
                (
                    report.status.route,
                    report.member_id,
                    report.process_id,
                    report.auth_epoch,
                )
            })
            .collect::<Vec<_>>();
        reports.sort();
        assert_eq!(
            reports,
            [
                ("rt-b".to_string(), "m-2".to_string(), "p2".to_string(), 1),
                ("rt-b".to_string(), "m1".to_string(), "p1".to_string(), 2),
            ]
        );

        // An owner process this gateway does not serve gives no verdict of
        // its own; another replica's recorded report of the owner gives one.
        let mut elsewhere = loaded_view(
            vec![member_view("m1", "p1")],
            [("rt-b", owner("m-3", "p3", 3))],
        );
        controller.update_pool(elsewhere.clone(), tokio::time::Instant::now());
        assert_eq!(controller.observed("rt-b"), ObservedInstance::NoHost);
        let mut recorded = status(0, &["rt-b"]).instances.remove(0);
        recorded.ready = false;
        elsewhere
            .reports
            .insert("rt-b".to_string(), recorded.clone());
        controller.update_pool(elsewhere, tokio::time::Instant::now());
        assert_eq!(
            controller.observed("rt-b"),
            ObservedInstance::Reported(recorded)
        );
    }

    #[tokio::test]
    async fn pool_views_keep_fresh_placements_and_owned_instances() {
        let controller = SupervisorHostController::new();
        let (one, _) = controller
            .begin_session(identity(), &member_hello("m1", "p1", 1))
            .unwrap();
        // `loaded` routes carry material this replica read; the rest are
        // desired and owned only.
        let view = |owned: &[&'static str], loaded: &[&str]| {
            let mut view = loaded_view(
                vec![member_view("m1", "p1")],
                owned.iter().map(|route| (*route, owner("m1", "p1", 1))),
            );
            view.assignments
                .retain(|route, _| loaded.contains(&route.as_str()));
            view
        };
        controller.update_pool(view(&["rt-a"], &["rt-a"]), tokio::time::Instant::now());

        // A launch through this gateway places and assigns rt-b while a
        // reconciliation pass that listed records before it runs; the pass's
        // view must not release the new instance.
        let listed_before_launch = tokio::time::Instant::now();
        controller.place_owner("rt-b", owner("m1", "p1", 1));
        controller.assign(assignment("rt-b", b"b")).unwrap();
        controller.update_pool(view(&["rt-a"], &["rt-a"]), listed_before_launch);
        assert_eq!(routes(&controller.snapshot(one).unwrap()), ["rt-a", "rt-b"]);
        controller.update_pool(
            view(&["rt-a", "rt-b"], &["rt-a", "rt-b"]),
            tokio::time::Instant::now(),
        );
        assert_eq!(routes(&controller.snapshot(one).unwrap()), ["rt-a", "rt-b"]);

        // An owned instance whose launch material this gateway has not loaded
        // yet, such as one launched through another gateway, is kept as is.
        controller.update_pool(
            view(&["rt-a", "rt-b", "rt-c"], &["rt-a", "rt-b"]),
            tokio::time::Instant::now(),
        );
        let snapshot = controller.snapshot(one).unwrap();
        assert_eq!(routes(&snapshot), ["rt-a", "rt-b"]);
        assert_eq!(snapshot.keep_routes, ["rt-c"]);
        assert!(
            snapshot
                .route_directory
                .iter()
                .any(|entry| entry.route == "rt-c")
        );
        // Once loaded, it is assigned.
        controller.update_pool(
            view(&["rt-a", "rt-b", "rt-c"], &["rt-a", "rt-b", "rt-c"]),
            tokio::time::Instant::now(),
        );
        let snapshot = controller.snapshot(one).unwrap();
        assert_eq!(routes(&snapshot), ["rt-a", "rt-b", "rt-c"]);
        assert!(snapshot.keep_routes.is_empty());

        // A withdrawal here is stopped, not kept, and stays withdrawn over
        // views that still list its record, until the record is gone.
        controller.unassign("rt-b");
        let snapshot = controller.snapshot(one).unwrap();
        assert_eq!(snapshot.stop_routes, ["rt-b"]);
        controller.update_pool(
            view(&["rt-a", "rt-b", "rt-c"], &["rt-a", "rt-b", "rt-c"]),
            tokio::time::Instant::now(),
        );
        let snapshot = controller.snapshot(one).unwrap();
        assert_eq!(routes(&snapshot), ["rt-a", "rt-c"]);
        assert_eq!(snapshot.stop_routes, ["rt-b"]);
        controller.forget_withdrawal("rt-b");
        assert!(controller.pool_withdrawals().is_empty());

        // An instance withdrawn through another replica leaves the desired
        // set while its owner record remains: its owner stops it.
        let mut withdrawn_elsewhere = view(&["rt-a", "rt-c"], &["rt-a", "rt-c"]);
        withdrawn_elsewhere.desired.remove("rt-c");
        withdrawn_elsewhere.assignments.remove("rt-c");
        controller.update_pool(withdrawn_elsewhere, tokio::time::Instant::now());
        let snapshot = controller.snapshot(one).unwrap();
        assert_eq!(routes(&snapshot), ["rt-a"]);
        assert_eq!(snapshot.stop_routes, ["rt-b", "rt-c"]);
        assert!(snapshot.keep_routes.is_empty());

        // An instance desired again is no longer stopped.
        controller.update_pool(
            view(&["rt-a", "rt-b", "rt-c"], &["rt-a", "rt-b", "rt-c"]),
            tokio::time::Instant::now(),
        );
        assert!(controller.snapshot(one).unwrap().stop_routes.is_empty());
        assert!(controller.stopping_routes().is_empty());
    }

    #[test]
    fn pool_member_identities_name_the_setting_to_fix() {
        let member = member_hello("m1", "p1", 1).member.unwrap();
        assert_eq!(validate_member(&member), Ok(()));
        for (broken, setting) in [
            (
                PoolMember {
                    member_id: String::new(),
                    ..member.clone()
                },
                "OPENSHELL_SUPERVISOR_POOL_MEMBER_ID",
            ),
            (
                PoolMember {
                    member_uid: "uid with space".to_string(),
                    ..member.clone()
                },
                "OPENSHELL_SUPERVISOR_POOL_MEMBER_UID",
            ),
            (
                PoolMember {
                    runtime_address: "not-an-address".to_string(),
                    ..member
                },
                "OPENSHELL_SUPERVISOR_POOL_ADVERTISE_IP",
            ),
        ] {
            let error = validate_member(&broken).unwrap_err();
            assert!(error.contains(setting), "{error}");
        }
        // A host that names no member is told every setting.
        let controller = SupervisorHostController::new();
        let error = controller
            .begin_session(
                identity(),
                &HostHello {
                    instance_id: "p1".to_string(),
                    connection_epoch: 1,
                    member: None,
                },
            )
            .unwrap_err();
        for setting in [
            "OPENSHELL_SUPERVISOR_POOL_MEMBER_ID",
            "OPENSHELL_SUPERVISOR_POOL_MEMBER_UID",
            "OPENSHELL_SUPERVISOR_POOL_ADVERTISE_IP",
        ] {
            assert!(error.message().contains(setting), "{}", error.message());
        }
        assert!(!error.message().contains("  "), "{}", error.message());
    }
}
