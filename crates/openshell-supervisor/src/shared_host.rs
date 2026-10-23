// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor shared by the sandboxes of one gateway.
//!
//! The gateway owns which sandbox instances, one running generation of a
//! stable Sandbox resource each, this process hosts. The host dials the
//! gateway presenting the supervisor token the gateway minted for it,
//! receives complete assignment snapshots over the private
//! `openshell.supervisor.host.v1` stream, reconciles the
//! [`SandboxInstanceHost`] registry to each one, and reports what it
//! observes. An assignment carries exactly the gateway-issued credentials of
//! its generation; the host never acts with any other identity toward
//! sandbox APIs. Losing the gateway stream never stops an instance;
//! only a later snapshot that omits it does. Snapshots are reconciled one at
//! a time, and a connection finishes the reconciliation it started before the
//! next connection begins, so a superseded stream can never apply after its
//! replacement. Runtime connections arrive through one routed listener.
//!
//! A member of a supervisor pool (high availability) is sent only the
//! instances its process owns. An instance a snapshot omits has moved to
//! another member: the host relinquishes it, ending supervision without
//! stopping the workload, which its runtime keeps frozen until the new owner
//! takes it over. Only instances the snapshot lists for stopping are stopped.
//! A member that shuts down announces that it is leaving, so the gateway moves
//! its instances first, and relinquishes whatever it still hosts.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use miette::Result;
use openshell_core::proto::supervisor_host::v1::supervisor_host_client::SupervisorHostClient;
use openshell_core::proto::supervisor_host::v1::{
    AssignmentSnapshot, HostGatewayMessage, HostHeartbeat, HostHello, HostMessage, HostStatus,
    PoolMember, SandboxInstanceAssignment, SandboxInstanceTakeover, host_gateway_message,
    host_message,
};
use openshell_extension_core::BearerTokenSlot;
use openshell_sandbox_backend::BoundaryTakeover;
use openshell_sandbox_backend::runtime_routed::RuntimeRouter;
use openshell_supervisor_control::{
    SandboxInstancePhaseReport, SandboxInstanceRegistration, SandboxInstanceStatusReport,
};
use tokio::sync::watch;
use tokio_stream::StreamExt as _;

use crate::sandbox_instance_host::{
    SandboxInstanceAdmission, SandboxInstanceAdmitted, SandboxInstanceBody, SandboxInstanceHost,
    SandboxInstanceHostError,
};

/// Assignment lifecycle messages. Each names the route in its text, after
/// the phrase: the console's shorthand format keeps only an event's message,
/// and operators (and the supervisor pool E2E tests) follow which member
/// supervises a route by these lines. The structured fields stay as well.
const ADMITTED: &str = "admitted assigned sandbox instance";
const REMOVING_WITHDRAWN: &str = "removing withdrawn sandbox instance";
const RELINQUISHED_TO_OTHER_MEMBER: &str =
    "relinquishing a sandbox instance owned by another pool member";
const RELINQUISHED_FOR_LATER_TERM: &str =
    "relinquishing a sandbox instance for its later ownership term";

/// Interval at which the host sends heartbeats on an idle stream, unless the
/// gateway asks for a shorter one.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
/// Shortest heartbeat interval the host accepts from the gateway.
const MIN_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
/// Silence after which the host abandons a stream and reconnects.
const GATEWAY_SILENCE_TIMEOUT: Duration = Duration::from_mins(1);
/// Bound on dialing the gateway, on the gateway answering the attach call,
/// and on it accepting the host.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on queueing one host-to-gateway message; a gateway that cannot
/// drain the stream this long is treated as lost.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);
const RECONNECT_BACKOFF_MIN: Duration = Duration::from_secs(1);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);
/// Host-to-gateway messages queued before the stream applies backpressure.
const OUTBOUND_QUEUE: usize = 16;
/// Most sandbox instances one snapshot may assign to a host; the gateway
/// enforces the same bound before it assigns.
pub const MAX_ASSIGNED_INSTANCES: usize = openshell_supervisor_control::MAX_ASSIGNED_INSTANCES;
/// Largest gateway message the host decodes: a full snapshot of
/// `MAX_ASSIGNED_INSTANCES` assignments at their largest, plus framing.
const MAX_GATEWAY_MESSAGE_BYTES: usize =
    MAX_ASSIGNED_INSTANCES * (openshell_supervisor_control::MAX_LAUNCH_MATERIAL_BYTES + 1024);
/// Largest host message: a status report is a few hundred bytes per instance.
const MAX_HOST_MESSAGE_BYTES: usize = 1024 * 1024;

/// How a host notices a silent gateway and paces its reconnects.
///
/// A pool member must reach a responsive gateway replica well before its
/// membership record expires (see [`openshell_supervisor_control::pool_timing`]);
/// a lone shared supervisor keeps its long, quiet defaults.
#[derive(Clone, Copy, Debug, PartialEq)]
struct StreamTimings {
    /// Silence after which a stream is abandoned.
    silence_timeout: Duration,
    /// How often silence is checked; `None` checks on each heartbeat.
    silence_check: Option<Duration>,
    /// First reconnect backoff; it doubles up to `backoff_max`.
    backoff_min: Duration,
    backoff_max: Duration,
    /// Most jitter added to a backoff, as a fraction of it.
    jitter: f64,
    /// Bound on connecting, attaching, and being accepted while no more than
    /// this many attempts failed since the last accepted stream; later
    /// attempts get [`CONNECT_TIMEOUT`].
    quick_attempts: Option<(Duration, u32)>,
}

impl StreamTimings {
    fn for_host(pool: bool) -> Self {
        use openshell_supervisor_control::pool_timing;
        if pool {
            Self {
                silence_timeout: pool_timing::HOST_SILENCE_TIMEOUT,
                silence_check: Some(pool_timing::HOST_SILENCE_CHECK),
                backoff_min: pool_timing::HOST_RECONNECT_BACKOFF_MIN,
                backoff_max: pool_timing::HOST_RECONNECT_BACKOFF_MAX,
                jitter: pool_timing::HOST_RECONNECT_JITTER,
                quick_attempts: Some((
                    pool_timing::HOST_ATTEMPT_TIMEOUT,
                    pool_timing::COVERED_UNANSWERED_ATTEMPTS,
                )),
            }
        } else {
            Self {
                silence_timeout: GATEWAY_SILENCE_TIMEOUT,
                silence_check: None,
                backoff_min: RECONNECT_BACKOFF_MIN,
                backoff_max: RECONNECT_BACKOFF_MAX,
                jitter: 0.0,
                quick_attempts: None,
            }
        }
    }

    /// Bound on an attempt after `unanswered` attempts since the last
    /// accepted stream that were never accepted.
    fn attempt_timeout(&self, unanswered: u32) -> Duration {
        match self.quick_attempts {
            Some((timeout, covered)) if unanswered <= covered => timeout,
            _ => CONNECT_TIMEOUT,
        }
    }

    /// Backoff before the `failed`-th (1-based) attempt since the last
    /// accepted stream; `sample` in `[0, 1)` scales the jitter.
    fn backoff(&self, failed: u32, sample: f64) -> Duration {
        let doubled = self
            .backoff_min
            .saturating_mul(1_u32 << failed.saturating_sub(1).min(16))
            .min(self.backoff_max);
        doubled.mul_f64(self.jitter.mul_add(sample.clamp(0.0, 1.0), 1.0))
    }
}

/// What bounds the stages of one connection attempt: connecting, attaching,
/// and being accepted.
#[derive(Clone, Copy)]
enum AttemptDeadline {
    /// One deadline covers every stage, so a slow stage leaves less time for
    /// the next; a pool member's reconnect budget counts on it.
    Shared(tokio::time::Instant),
    /// Each stage gets its own bound when it begins.
    PerStage(Duration),
}

impl AttemptDeadline {
    /// The deadline of a stage beginning now.
    fn stage(self) -> tokio::time::Instant {
        match self {
            Self::Shared(deadline) => deadline,
            Self::PerStage(bound) => tokio::time::Instant::now() + bound,
        }
    }
}

/// A scheduling jitter sample in `[0, 1)`; not security-relevant.
fn jitter_sample() -> f64 {
    use std::hash::BuildHasher as _;
    let bits = std::collections::hash_map::RandomState::new().hash_one(SystemTime::now());
    #[allow(clippy::cast_precision_loss)]
    let sample = (bits >> 11) as f64 / (1_u64 << 53) as f64;
    sample
}

/// Identity of a shared supervisor process in a supervisor pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolIdentity {
    /// Stable name of the member (its Pod name).
    pub member_id: String,
    /// Identity of this incarnation of the member (its Pod UID).
    pub member_uid: String,
    /// Address of this member's routed runtime listener that other members
    /// redirect its instances' runtimes to.
    pub runtime_address: SocketAddr,
}

/// Process-level inputs of a shared supervisor.
pub struct SharedHostConfig {
    /// Gateway gRPC endpoint every sandbox instance uses with its own
    /// credentials.
    pub gateway_endpoint: String,
    /// Private directory for per-instance files (`--session-root`).
    pub instance_root: PathBuf,
    /// Listener for runtime-initiated Sandbox Protocol connections.
    pub runtime_listen: SocketAddr,
    /// Time a withdrawn sandbox instance may take to stop its workload.
    pub removal_grace: Duration,
    /// Present when this process is a member of a supervisor pool.
    pub pool: Option<PoolIdentity>,
}

/// The sandbox instance registry and the routed runtime listener its
/// instances claim routes on, reconciled to the gateway's assignments.
pub struct SharedHost {
    host: SandboxInstanceHost,
    router: Arc<RuntimeRouter>,
    gateway_endpoint: String,
    removal_grace: Duration,
    /// Assignments of the latest snapshot that could not be admitted, reported
    /// as failed instances until the gateway withdraws them.
    rejected: Mutex<BTreeMap<String, SandboxInstanceStatusReport>>,
    /// Routes of the latest applied snapshot, so a withdrawal whose cleanup
    /// failed can be retried without the gateway resending the snapshot.
    desired_routes: Mutex<Option<std::collections::BTreeSet<String>>>,
    /// Present when this process is a member of a supervisor pool.
    pool: Option<PoolIdentity>,
    /// Pool only: routes of the latest snapshot listed for stopping. Every
    /// other route it omits is relinquished.
    stop_routes: Mutex<std::collections::BTreeSet<String>>,
    /// Pool only: the latest snapshot while some of its assignments wait for
    /// an earlier instance of their route to leave, or for the credentials of
    /// their term.
    deferred: Mutex<Option<AssignmentSnapshot>>,
    /// Pool only: deferred assignments, reported as starting. The gateway
    /// reads an assigned route the host does not report as gone, so a
    /// deferral must never look like one.
    deferred_reports: Mutex<BTreeMap<String, SandboxInstanceStatusReport>>,
    /// The pool member announced that it is leaving.
    leaving: watch::Sender<bool>,
    /// A gateway currently accepts this host's stream.
    gateway_connected: watch::Sender<bool>,
    /// Recovery deadline (seconds) the latest snapshot offers the runtimes
    /// of instances this host starts or takes over; `None` keeps the runtime
    /// default.
    recovery_timeout_secs: Mutex<Option<u32>>,
    /// Lets tests stall reconciliations and see how many run at once.
    #[cfg(test)]
    reconcile_probe: ReconcileProbe,
}

/// Stalls the next reconciliation until released, and records how many ran
/// and how many run at once.
#[cfg(test)]
#[derive(Default)]
struct ReconcileProbe {
    gate: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    entered: std::sync::atomic::AtomicUsize,
    running: std::sync::atomic::AtomicUsize,
    peak: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl ReconcileProbe {
    async fn enter(&self) -> impl Drop + '_ {
        use std::sync::atomic::Ordering;
        struct Running<'a>(&'a std::sync::atomic::AtomicUsize);
        impl Drop for Running<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        self.entered.fetch_add(1, Ordering::SeqCst);
        let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        let gate = self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let running = Running(&self.running);
        if let Some(gate) = gate {
            let _ = gate.await;
        }
        running
    }
}

/// A rejected sandbox instance assignment.
#[derive(Clone, Debug, thiserror::Error)]
pub enum ControlError {
    #[error("{0}")]
    Invalid(String),
    #[error("route is already hosted with different launch material")]
    Conflict,
    #[error("route is still being removed")]
    Removing,
    #[error("{0}")]
    Unavailable(String),
    /// The assignment can be admitted later without the gateway resending it.
    #[error("{0}")]
    Deferred(String),
}

impl From<SandboxInstanceHostError> for ControlError {
    fn from(error: SandboxInstanceHostError) -> Self {
        match error {
            SandboxInstanceHostError::InvalidKey => Self::Invalid(error.to_string()),
            SandboxInstanceHostError::Conflict => Self::Conflict,
            SandboxInstanceHostError::Removing => Self::Removing,
            SandboxInstanceHostError::Files(_) | SandboxInstanceHostError::Thread(_) => {
                Self::Unavailable(error.to_string())
            }
        }
    }
}

impl SharedHost {
    /// Bind the routed runtime listener and prepare the instance root.
    pub fn start(config: SharedHostConfig) -> Result<Arc<Self>> {
        let host = SandboxInstanceHost::new(config.instance_root)?;
        let router = RuntimeRouter::bind(config.runtime_listen)
            .map_err(|error| miette::miette!("{error}"))?;
        Ok(Arc::new(Self {
            host,
            router,
            gateway_endpoint: config.gateway_endpoint,
            removal_grace: config.removal_grace,
            rejected: Mutex::new(BTreeMap::new()),
            desired_routes: Mutex::new(None),
            pool: config.pool,
            stop_routes: Mutex::new(std::collections::BTreeSet::new()),
            deferred: Mutex::new(None),
            deferred_reports: Mutex::new(BTreeMap::new()),
            leaving: watch::Sender::new(false),
            gateway_connected: watch::Sender::new(false),
            recovery_timeout_secs: Mutex::new(None),
            #[cfg(test)]
            reconcile_probe: ReconcileProbe::default(),
        }))
    }

    /// Pool identity of this process, when it is a pool member.
    #[must_use]
    pub fn pool(&self) -> Option<&PoolIdentity> {
        self.pool.as_ref()
    }

    /// Whether this pool member announced that it is leaving.
    #[must_use]
    pub fn is_leaving(&self) -> bool {
        *self.leaving.borrow()
    }

    /// Announce that this pool member is leaving, and wait up to `limit` for
    /// the gateway to move its instances to other members; each is
    /// relinquished as a snapshot omits it. Does nothing for a lone shared
    /// supervisor.
    pub async fn leave(&self, limit: Duration) {
        if self.pool.is_none() {
            return;
        }
        tracing::info!(
            hosted = self.host.list().len(),
            "pool member is leaving; asking the gateway to move its sandbox instances"
        );
        self.leaving.send_replace(true);
        let mut changes = self.host.changes();
        let mut connected = self.gateway_connected.subscribe();
        // Only a gateway that hears the announcement moves the instances; one
        // that stops hearing from this member takes them over after the
        // membership TTL instead.
        let drained = tokio::time::timeout(limit, async {
            while !self.host.list().is_empty() && *connected.borrow_and_update() {
                tokio::select! {
                    hosted = changes.changed() => if hosted.is_err() { return },
                    gateway = connected.changed() => if gateway.is_err() { return },
                }
            }
        })
        .await;
        if drained.is_err() {
            tracing::warn!(
                remaining = self.host.list().len(),
                "pool member is leaving before the gateway moved all of its sandbox instances"
            );
        }
    }

    /// End supervision of every hosted instance at process shutdown: a pool
    /// member relinquishes them to the members that take them over; a lone
    /// shared supervisor stops them, since no one could take them over.
    pub async fn shut_down(&self) {
        if self.pool.is_some() {
            self.host.relinquish_all().await;
        } else {
            self.remove_all().await;
        }
    }

    /// Address of the routed runtime listener.
    #[must_use]
    pub fn runtime_addr(&self) -> SocketAddr {
        self.router.local_addr()
    }

    /// Start a sandbox instance for `registration`, or confirm an identical
    /// one.
    pub fn register(
        &self,
        registration: SandboxInstanceRegistration,
    ) -> Result<SandboxInstanceAdmitted, ControlError> {
        registration
            .validate()
            .map_err(|error| ControlError::Invalid(error.to_string()))?;
        let fingerprint = registration_digest(&registration)?;
        self.admit(registration, fingerprint, Ok(None))
    }

    /// Admit `registration` under `fingerprint`. A new instance takes over
    /// its generation with `takeover`; one whose term's credentials have not
    /// arrived yet is deferred, while an instance already hosted for the same
    /// fingerprint is kept.
    fn admit(
        &self,
        registration: SandboxInstanceRegistration,
        fingerprint: [u8; 32],
        takeover: Result<Option<BoundaryTakeover>, ControlError>,
    ) -> Result<SandboxInstanceAdmitted, ControlError> {
        let admission = SandboxInstanceAdmission {
            key: registration.route.clone(),
            fingerprint,
            sandbox_id: registration.sandbox_id.clone(),
        };
        self.host.admit(admission, |dir| {
            self.instance_launch(registration, takeover?, dir)
        })
    }

    /// Admit one assignment of a pool snapshot for its ownership term.
    async fn admit_pool_assignment(
        &self,
        assignment: &SandboxInstanceAssignment,
    ) -> Result<SandboxInstanceAdmitted, ControlError> {
        let mut registration = SandboxInstanceRegistration::from_assignment(assignment)
            .map_err(|error| ControlError::Invalid(error.to_string()))?;
        let fingerprint = pool_fingerprint(
            &assignment.launch_material,
            registration.auth.auth_epoch.get(),
            assignment.takeover.as_ref(),
        )?;
        let takeover = match &assignment.takeover {
            None => Ok(None),
            Some(takeover) => takeover_term(registration.auth.auth_epoch, takeover).map(|term| {
                registration.auth.auth_epoch = term.auth_epoch;
                registration.auth.gateway_token = term.gateway_token;
                registration.auth.gateway_expires_at = takeover.gateway_expires_at;
                registration.auth.sandbox_token = term.sandbox_token;
                registration.auth.sandbox_expires_at = takeover.sandbox_expires_at;
                Some(term.boundary)
            }),
        };
        match self.admit(registration.clone(), fingerprint, takeover.clone()) {
            // This process was granted a later term of an instance it still
            // supervises for an earlier one; hand the earlier term over first.
            Err(ControlError::Conflict) => {
                let route = &assignment.route;
                tracing::info!(
                    route = %route,
                    sandbox_id = %assignment.sandbox_id,
                    "{RELINQUISHED_FOR_LATER_TERM} {route}"
                );
                self.host.relinquish(&assignment.route).await;
                self.admit(registration, fingerprint, takeover)
            }
            outcome => outcome,
        }
    }

    /// Status of one hosted sandbox instance.
    #[must_use]
    pub fn status(&self, route: &str) -> Option<SandboxInstanceStatusReport> {
        self.host.status(route)
    }

    /// Status of every hosted sandbox instance. An assignment of the latest
    /// snapshot that could not be admitted is reported as failed, even when
    /// an earlier instance still runs under its route, so the gateway sees
    /// the rejection rather than the instance it could not replace. A
    /// deferred pool assignment is reported as starting, even while an
    /// earlier instance of its route is still leaving.
    #[must_use]
    pub fn list(&self) -> Vec<SandboxInstanceStatusReport> {
        let rejected = self
            .rejected
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let deferred = self
            .deferred_reports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut reports = self
            .host
            .list()
            .into_iter()
            .filter(|hosted| {
                !rejected.contains_key(&hosted.route) && !deferred.contains_key(&hosted.route)
            })
            .collect::<Vec<_>>();
        reports.extend(rejected.values().cloned());
        reports.extend(deferred.values().cloned());
        reports
    }

    /// Notified whenever a hosted instance is admitted, changes phase or
    /// readiness, or is removed.
    #[must_use]
    pub fn changes(&self) -> watch::Receiver<u64> {
        self.host.changes()
    }

    /// Stop one sandbox instance, delete its private files, and forget it.
    pub async fn remove(&self, route: &str) -> Option<SandboxInstanceStatusReport> {
        self.host.remove(route, self.removal_grace).await
    }

    /// Stop every sandbox instance, for process shutdown.
    pub async fn remove_all(&self) {
        self.host.remove_all(self.removal_grace).await;
    }

    /// Make the registry match `snapshot`: admit every assignment and remove
    /// every hosted instance it omits. Assignments that cannot be admitted are
    /// reported as failed instances; they never affect a running instance.
    ///
    /// A snapshot that would run more than [`MAX_ASSIGNED_INSTANCES`]
    /// instances still applies its stops, directory, and kept routes, and
    /// keeps every hosted instance it assigns; only the new instances beyond
    /// capacity are left unstarted, as kept routes are, until a later
    /// snapshot fits.
    ///
    /// # Errors
    ///
    /// A malformed snapshot (one route assigned twice, or the wrong kind for
    /// this host) is refused as a whole before anything is admitted or
    /// removed.
    pub async fn reconcile(&self, snapshot: &AssignmentSnapshot) -> Result<(), ControlError> {
        #[cfg(test)]
        let _running = self.reconcile_probe.enter().await;
        let mut routes = std::collections::BTreeSet::new();
        for assignment in &snapshot.instances {
            if !routes.insert(assignment.route.clone()) {
                return Err(ControlError::Invalid(
                    "snapshot assigns one route more than once".to_string(),
                ));
            }
        }
        self.offer_recovery_timeout(snapshot.recovery_timeout.as_ref());
        if snapshot.pool != self.pool.is_some() {
            return Err(ControlError::Invalid(if snapshot.pool {
                "the gateway sent a supervisor pool snapshot to a lone shared supervisor"
                    .to_string()
            } else {
                "the gateway sent a lone shared supervisor's snapshot to a pool member".to_string()
            }));
        }
        if let Some(pool) = &self.pool {
            *self
                .stop_routes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                snapshot.stop_routes.iter().cloned().collect();
            // Runtimes that reach this member for an instance another member
            // supervises are redirected there.
            let owners = snapshot
                .route_directory
                .iter()
                .filter_map(|entry| {
                    let address = entry.runtime_address.parse().ok();
                    if address.is_none() {
                        tracing::warn!(route = %entry.route, "ignoring a malformed route directory address");
                    }
                    Some((entry.route.clone(), address?))
                })
                .collect();
            self.router
                .set_directory(Some(pool.runtime_address), owners);
        }
        // Owned instances the gateway could not describe yet are kept as they
        // are: neither started, released, nor stopped.
        routes.extend(snapshot.keep_routes.iter().cloned());
        let hosted = self
            .host
            .list()
            .into_iter()
            .map(|status| status.route)
            .collect::<std::collections::BTreeSet<_>>();
        let (admitted, unstarted) = within_capacity(snapshot, &hosted);
        if !unstarted.is_empty() {
            tracing::warn!(
                assigned = snapshot.instances.len(),
                unstarted = unstarted.len(),
                "snapshot assigns more sandbox instances than this host runs; leaving the excess unstarted"
            );
        }
        *self
            .desired_routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(routes);
        let mut rejected = BTreeMap::new();
        let mut deferred = BTreeMap::new();
        for assignment in admitted {
            let outcome = if self.pool.is_some() {
                self.admit_pool_assignment(assignment).await
            } else {
                SandboxInstanceRegistration::from_assignment(assignment)
                    .map_err(|error| ControlError::Invalid(error.to_string()))
                    .and_then(|registration| self.register(registration))
            };
            match outcome {
                Ok(SandboxInstanceAdmitted::Created) => {
                    let route = &assignment.route;
                    tracing::info!(
                        route = %route,
                        sandbox_id = %assignment.sandbox_id,
                        "{ADMITTED} {route}"
                    );
                }
                Ok(SandboxInstanceAdmitted::Unchanged) => {}
                // An earlier instance of the route is still leaving, or the
                // term's credentials are on their way; retried shortly.
                Err(error @ (ControlError::Removing | ControlError::Deferred(_)))
                    if self.pool.is_some() =>
                {
                    tracing::debug!(
                        route = %assignment.route,
                        %error,
                        "deferred assigned sandbox instance"
                    );
                    deferred.insert(
                        assignment.route.clone(),
                        SandboxInstanceStatusReport {
                            route: assignment.route.clone(),
                            sandbox_id: assignment.sandbox_id.clone(),
                            phase: SandboxInstancePhaseReport::Starting,
                            ready: false,
                        },
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        route = %assignment.route,
                        sandbox_id = %assignment.sandbox_id,
                        %error,
                        "rejected assigned sandbox instance"
                    );
                    rejected.insert(
                        assignment.route.clone(),
                        SandboxInstanceStatusReport {
                            route: assignment.route.clone(),
                            sandbox_id: assignment.sandbox_id.clone(),
                            phase: SandboxInstancePhaseReport::Failed {
                                error: error.to_string(),
                            },
                            ready: false,
                        },
                    );
                }
            }
        }
        *self
            .rejected
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = rejected;
        *self
            .deferred
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            (!deferred.is_empty()).then(|| snapshot.clone());
        *self
            .deferred_reports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = deferred;
        self.remove_withdrawn().await;
        Ok(())
    }

    /// Retry what the latest snapshot left undone without the gateway
    /// resending it: deferred admissions and withdrawals whose cleanup failed.
    pub async fn retry_pending(&self) {
        let deferred = self
            .deferred
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        match deferred {
            Some(snapshot) => {
                if let Err(error) = self.reconcile(&snapshot).await {
                    tracing::warn!(%error, "could not retry a deferred assignment snapshot");
                }
            }
            None => self.remove_withdrawn().await,
        }
    }

    /// Whether something of the latest snapshot is still to be retried.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.deferred
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
            || self.has_withdrawn_leftovers()
    }

    /// Remove every hosted instance the latest applied snapshot omits. Also
    /// run between snapshots: a removal whose file cleanup failed keeps its
    /// key reserved and reports a failure, and the gateway does not resend an
    /// unchanged snapshot, so this retries it. Nothing happens before the
    /// first snapshot of a process, since nothing is known to be withdrawn.
    pub async fn remove_withdrawn(&self) {
        let desired = self
            .desired_routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let Some(desired) = desired else {
            return;
        };
        let withdrawn = self
            .host
            .list()
            .into_iter()
            .filter(|hosted| !desired.contains(&hosted.route))
            .collect::<Vec<_>>();
        let stop_routes = self
            .stop_routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        futures::future::join_all(withdrawn.iter().map(|hosted| {
            let stop = self.pool.is_none() || stop_routes.contains(&hosted.route);
            async move {
                let route = &hosted.route;
                if stop {
                    tracing::info!(
                        route = %route,
                        sandbox_id = %hosted.sandbox_id,
                        "{REMOVING_WITHDRAWN} {route}"
                    );
                    self.remove(&hosted.route).await;
                } else {
                    tracing::info!(
                        route = %route,
                        sandbox_id = %hosted.sandbox_id,
                        "{RELINQUISHED_TO_OTHER_MEMBER} {route}"
                    );
                    self.host.relinquish(&hosted.route).await;
                }
            }
        }))
        .await;
    }

    /// Whether an instance the latest applied snapshot omits is still hosted,
    /// such as one whose removal could not delete its private files.
    #[must_use]
    pub fn has_withdrawn_leftovers(&self) -> bool {
        let desired = self
            .desired_routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(desired) = desired.as_ref() else {
            return false;
        };
        self.host
            .list()
            .iter()
            .any(|hosted| !desired.contains(&hosted.route))
    }

    /// Keep the recovery deadline a snapshot offers for the instances admitted
    /// from now on. Absent offers none; a value the runtime would refuse is
    /// ignored, so the runtime default applies.
    fn offer_recovery_timeout(&self, offered: Option<&prost_types::Duration>) {
        let offer = offered.and_then(|offered| {
            let seconds = u32::try_from(offered.seconds)
                .ok()
                .filter(|_| offered.nanos == 0)
                .filter(|seconds| {
                    openshell_sandbox_backend::boundary_protocol::supervisor_recovery_timeout(
                        *seconds,
                    )
                    .is_some()
                });
            if seconds.is_none() {
                tracing::warn!(
                    seconds = offered.seconds,
                    "ignoring an out-of-range sandbox recovery deadline from the gateway"
                );
            }
            seconds
        });
        *self
            .recovery_timeout_secs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = offer;
    }

    /// Launch material of `registration` with its private files in `dir`.
    fn instance_launch(
        &self,
        registration: SandboxInstanceRegistration,
        takeover: Option<BoundaryTakeover>,
        dir: &Path,
    ) -> Result<(crate::SandboxInstanceBindings, SandboxInstanceBody), ControlError> {
        let failure = |error: miette::Report| ControlError::Unavailable(error.to_string());
        let main_process =
            openshell_core::sandbox_env::MainProcessConfig::decode(&registration.main_process_spec)
                .map_err(ControlError::Invalid)?;
        let descriptor = registration
            .runtime_descriptor
            .backend_descriptor()
            .map_err(|error| ControlError::Invalid(error.to_string()))?;
        let ca_certificate = dir.join("proxy-ca.crt");
        let ca_private_key = dir.join("proxy-ca.key");
        write_private_file(
            &ca_certificate,
            registration.proxy_ca.certificate_pem.as_bytes(),
        )
        .map_err(failure)?;
        write_private_file(
            &ca_private_key,
            registration
                .proxy_ca
                .private_key_pem
                .expose_secret()
                .as_bytes(),
        )
        .map_err(failure)?;
        let trust_dir = dir.join("trust");
        crate::sandbox_instance_host::prepare_private_dir(&trust_dir).map_err(failure)?;
        let ssh_socket = dir.join("ssh.sock");
        let config = crate::SandboxInstanceConfig {
            command: main_process.command,
            workdir: registration.workdir,
            timeout_secs: 0,
            interactive: main_process.tty,
            await_main_process_attachment: main_process.await_main_process_attachment,
            sandbox_id: Some(registration.sandbox_id),
            sandbox: Some(registration.sandbox_name),
            container_image: registration.container_image,
            openshell_endpoint: Some(self.gateway_endpoint.clone()),
            policy_rules: None,
            policy_data: None,
            ssh_socket_path: Some(ssh_socket.to_string_lossy().into_owned()),
            shared_ssh_socket: false,
            // The Kubernetes driver refuses the gateway topology when an
            // upstream proxy or provider workload identity is configured,
            // and it configures no extra CA for dedicated supervisors.
            upstream_proxy_args:
                openshell_supervisor_network::upstream_proxy::UpstreamProxyArgs::default(),
            additional_ca_bundle: None,
            backend_descriptor: descriptor,
            auth_bundle: registration.auth,
            admitted_isolation_backend: Some(openshell_sandbox_backend::BACKEND_NAME.to_string()),
            main_exit_marker: None,
            trace_context: registration.trace_context,
            // One process cannot hold a per-sandbox workload identity, so
            // providers that need one fail closed.
            provider_workload_api_socket: None,
            proxy_tls: openshell_supervisor_network::run::ProxyTlsFiles {
                ca_certificate: Some(ca_certificate),
                ca_private_key: Some(ca_private_key),
                directory: Some(trust_dir),
            },
            takeover,
            supervisor_recovery_timeout_secs: *self
                .recovery_timeout_secs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        };
        crate::sandbox_instance_host::sandbox_instance_launch(
            Box::new(crate::backend_setup::RoutedBackendSetup::new(
                self.router.clone(),
                registration.route,
            )),
            config,
            dir,
        )
        .map_err(failure)
    }
}

fn registration_digest(
    registration: &SandboxInstanceRegistration,
) -> Result<[u8; 32], ControlError> {
    let encoded = serde_json::to_vec(registration)
        .map_err(|error| ControlError::Invalid(format!("encode registration: {error}")))?;
    openshell_crypto::sha256(&encoded).map_err(|error| ControlError::Unavailable(error.to_string()))
}

/// Admission fingerprint of a pool instance: its launch material and its
/// ownership term (the launch term, or a takeover term with its granted
/// supervisor process). Credentials minted for a term differ between gateway
/// replicas and reconnects, so they are not part of it: a host keeps the
/// instance it runs for the same term whichever gateway it hears from.
fn pool_fingerprint(
    launch_material: &[u8],
    launch_epoch: u64,
    takeover: Option<&SandboxInstanceTakeover>,
) -> Result<[u8; 32], ControlError> {
    let (auth_epoch, supervisor_instance_id) = takeover.map_or((launch_epoch, ""), |takeover| {
        (
            takeover.auth_epoch,
            takeover.supervisor_instance_id.as_str(),
        )
    });
    let mut term = Vec::with_capacity(launch_material.len() + 96);
    term.extend_from_slice(b"openshell-pool-instance-v1\0");
    term.extend_from_slice(&auth_epoch.to_be_bytes());
    term.extend_from_slice(supervisor_instance_id.as_bytes());
    term.push(0);
    term.extend_from_slice(launch_material);
    openshell_crypto::sha256(&term).map_err(|error| ControlError::Unavailable(error.to_string()))
}

/// Credentials of one takeover term and the grant that lets a new instance
/// take its generation over.
struct TakeoverTerm {
    auth_epoch: openshell_core::jwt::CredentialEpoch,
    gateway_token: openshell_core::jwt::SecretJwt,
    sandbox_token: openshell_core::jwt::SecretJwt,
    boundary: BoundaryTakeover,
}

/// Validate a takeover term that follows the launch term `launch_epoch`. A
/// term without credentials, minted by another gateway replica, is
/// [`ControlError::Deferred`]: an instance already running for the term is
/// kept, and a new one waits for credentials from the gateway this host
/// hears from.
fn takeover_term(
    launch_epoch: openshell_core::jwt::CredentialEpoch,
    takeover: &SandboxInstanceTakeover,
) -> Result<TakeoverTerm, ControlError> {
    let invalid = |what: &str| ControlError::Invalid(format!("sandbox instance takeover {what}"));
    let auth_epoch = openshell_core::jwt::CredentialEpoch::new(takeover.auth_epoch)
        .map_err(|_| invalid("names no ownership term"))?;
    if auth_epoch <= launch_epoch {
        return Err(invalid("does not follow the launch term"));
    }
    let supervisor_instance_id = takeover
        .supervisor_instance_id
        .parse::<openshell_sandbox_backend::boundary_protocol::SupervisorInstanceId>()
        .map_err(|_| invalid("names no supervisor process"))?;
    if takeover.grant.is_empty() {
        return Err(ControlError::Deferred(
            "the takeover credentials of this ownership term have not arrived".to_string(),
        ));
    }
    let secret = |token: &str| {
        openshell_core::jwt::SecretJwt::parse(token.to_string())
            .map_err(|_| invalid("carries a malformed credential"))
    };
    Ok(TakeoverTerm {
        auth_epoch,
        gateway_token: secret(&takeover.gateway_token)?,
        sandbox_token: secret(&takeover.sandbox_token)?,
        boundary: BoundaryTakeover {
            supervisor_instance_id,
            grant: secret(&takeover.grant)?,
        },
    })
}

#[cfg(unix)]
fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    use miette::{IntoDiagnostic as _, WrapErr as _};
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("create {}", path.display()))?;
    file.write_all(contents).into_diagnostic()?;
    file.sync_all().into_diagnostic()
}

#[cfg(not(unix))]
fn write_private_file(_path: &Path, _contents: &[u8]) -> Result<()> {
    Err(miette::miette!("shared supervision requires a Unix host"))
}

/// How the host reaches the gateway's supervisor host service.
pub struct GatewayLink {
    /// Gateway gRPC endpoint; must be `https`, since the supervisor token is
    /// a bearer. Server-authenticated TLS follows the sandbox instance
    /// conventions (`OPENSHELL_TLS_CA`, `OPENSHELL_GATEWAY_TLS_SERVER_NAME`).
    pub endpoint: String,
    /// File holding the gateway-minted supervisor token. It is read on every
    /// connection attempt, so the gateway's renewals take effect at the next
    /// reconnect without a restart.
    pub token_file: PathBuf,
}

impl GatewayLink {
    /// Read the current supervisor token. A missing, empty, malformed, or
    /// already expired token is an error; the gateway keeps the file fresh,
    /// so the caller retries later.
    fn read_token(&self) -> Result<BearerTokenSlot> {
        use miette::{IntoDiagnostic as _, WrapErr as _};

        let contents = std::fs::read_to_string(&self.token_file)
            .into_diagnostic()
            .wrap_err_with(|| format!("read supervisor token {}", self.token_file.display()))?;
        let token = openshell_core::jwt::SecretJwt::parse(contents.trim())
            .map_err(|_| miette::miette!("the supervisor token file holds no token yet"))?;
        let expires_at = openshell_core::jwt::parse_exp_secs(token.expose_secret())
            .ok_or_else(|| miette::miette!("the supervisor token is not an expiring JWT"))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
            });
        if expires_at <= now {
            return Err(miette::miette!(
                "the supervisor token expired {} s ago; waiting for the gateway to renew it",
                now.saturating_sub(expires_at)
            ));
        }
        BearerTokenSlot::new(token.expose_secret(), expires_at.saturating_mul(1000))
            .map_err(|error| miette::miette!("{error}"))
    }
}

/// Everything the host reports for one snapshot revision.
fn status_message(host: &SharedHost, applied_revision: u64) -> HostMessage {
    HostMessage {
        payload: Some(host_message::Payload::Status(HostStatus {
            leaving: host.is_leaving(),
            applied_revision,
            instances: host
                .list()
                .iter()
                .map(SandboxInstanceStatusReport::to_proto)
                .collect(),
        })),
    }
}

/// Why one gateway stream ended.
enum StreamEnd {
    /// The gateway rejected or closed the stream; reconnect after a backoff.
    /// `accepted` records whether the gateway had accepted the host.
    Lost { accepted: bool },
}

/// What a gateway sends a host on its assignment stream.
type GatewayInbound = std::pin::Pin<
    Box<dyn futures::Stream<Item = Result<HostGatewayMessage, tonic::Status>> + Send>,
>;

/// Opens a host's assignment stream: hands the gateway the host's outbound
/// messages and returns the gateway's.
trait GatewayConnector: Send + Sync {
    /// Connect and attach, each stage bounded by `deadline`.
    fn open(
        &self,
        outbound: tokio::sync::mpsc::Receiver<HostMessage>,
        deadline: AttemptDeadline,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<GatewayInbound, String>> + Send + '_>>;
}

impl GatewayConnector for GatewayLink {
    fn open(
        &self,
        outbound: tokio::sync::mpsc::Receiver<HostMessage>,
        deadline: AttemptDeadline,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<GatewayInbound, String>> + Send + '_>> {
        Box::pin(async move {
            if !self.endpoint.starts_with("https://") {
                return Err("the supervisor token requires an https gateway endpoint".to_string());
            }
            let token = self
                .read_token()
                .map_err(|error| format!("no usable supervisor token: {error}"))?;
            let connect = openshell_core::grpc_client::connect_gateway_channel(&self.endpoint);
            let channel = tokio::time::timeout_at(deadline.stage(), connect)
                .await
                .map_err(|_| "connecting to the gateway timed out".to_string())?
                .map_err(|error| format!("could not connect to the gateway: {error}"))?;
            let mut client = SupervisorHostClient::with_interceptor(channel, token.interceptor())
                .max_decoding_message_size(MAX_GATEWAY_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_HOST_MESSAGE_BYTES);
            let attach = client.attach(tokio_stream::wrappers::ReceiverStream::new(outbound));
            let response = tokio::time::timeout_at(deadline.stage(), attach)
                .await
                .map_err(|_| {
                    "gateway did not answer the supervisor host stream in time".to_string()
                })?
                .map_err(|status| {
                    format!("gateway refused the supervisor host stream: {status}")
                })?;
            let inbound: GatewayInbound = Box::pin(response.into_inner());
            Ok(inbound)
        })
    }
}

/// Keep one assignment stream open to the gateway until `shutdown`
/// completes, reconnecting with backoff. Hosted instances run on across
/// disconnects.
pub async fn attach_to_gateway(
    host: Arc<SharedHost>,
    link: GatewayLink,
    shutdown: impl Future<Output = ()>,
) {
    attach_with(host, Arc::new(link), shutdown).await;
}

async fn attach_with(
    host: Arc<SharedHost>,
    connector: Arc<dyn GatewayConnector>,
    shutdown: impl Future<Output = ()>,
) {
    let instance_id = uuid::Uuid::new_v4().to_string();
    let mut connection_epoch = 0_u64;
    let timings = StreamTimings::for_host(host.pool.is_some());
    let reconciler = Reconciler::start(host.clone());
    // Streams lost since the last accepted stream, counting its own loss;
    // the backoff grows with it.
    let mut failed = 0_u32;
    // Attempts since the last accepted stream that were never accepted; the
    // attempt bound depends on it, so the attempt after the covered
    // unanswered ones is still quick.
    let mut unanswered = 0_u32;
    tokio::pin!(shutdown);
    loop {
        connection_epoch += 1;
        let hello = HostHello {
            instance_id: instance_id.clone(),
            connection_epoch,
            member: host.pool.as_ref().map(|pool| PoolMember {
                member_id: pool.member_id.clone(),
                member_uid: pool.member_uid.clone(),
                runtime_address: pool.runtime_address.to_string(),
            }),
        };
        let attempt_timeout = timings.attempt_timeout(unanswered);
        let StreamEnd::Lost { accepted } = tokio::select! {
            end = run_stream(&host, connector.as_ref(), &reconciler, hello, &timings, attempt_timeout) => end,
            () = &mut shutdown => return reconciler.shut_down().await,
        };
        if accepted {
            failed = 0;
            unanswered = 0;
        } else {
            unanswered = unanswered.saturating_add(1);
        }
        failed = failed.saturating_add(1);
        let backoff = timings.backoff(failed, jitter_sample());
        tracing::info!(
            retry_in_ms = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX),
            "gateway assignment stream lost; hosted sandbox instances keep running"
        );
        tokio::select! {
            () = tokio::time::sleep(backoff) => {}
            () = &mut shutdown => return reconciler.shut_down().await,
        }
    }
}

/// One unit of registry work.
enum ReconcileJob {
    Snapshot(AssignmentSnapshot),
    /// Retry deferred admissions and withdrawals whose cleanup failed.
    Retry,
}

/// A finished registry job of stream `stream`; `revision` is the snapshot
/// revision it applied, if any.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Applied {
    sequence: u64,
    stream: u64,
    revision: Option<u64>,
    /// The job ran, rather than refusing a malformed snapshot.
    ok: bool,
}

#[derive(Default)]
struct ReconcilerState {
    /// The stream that may queue work; older streams' work is dropped.
    stream: u64,
    queued: Option<(u64, ReconcileJob)>,
    busy: bool,
    closed: bool,
}

/// Applies assignment snapshots to the registry one at a time, across
/// streams.
///
/// A stream hands the worker the newest snapshot it received; one still
/// queued when a newer stream begins is dropped, since its session is gone.
/// A reconciliation the worker began runs to completion even when its stream
/// ends, so registry mutation stays serialized while a new stream connects,
/// reports status, and queues its own snapshots without waiting for it.
struct Reconciler {
    state: Mutex<ReconcilerState>,
    wake: tokio::sync::Notify,
    done: watch::Sender<Applied>,
}

impl Reconciler {
    /// Start the worker; it stops once the returned handle is shut down or
    /// dropped and the job in flight, if any, has finished.
    fn start(host: Arc<SharedHost>) -> ReconcilerHandle {
        let reconciler = Arc::new(Self {
            state: Mutex::new(ReconcilerState::default()),
            wake: tokio::sync::Notify::new(),
            done: watch::Sender::new(Applied::default()),
        });
        let worker = tokio::spawn(reconciler.clone().run(host));
        ReconcilerHandle {
            reconciler,
            worker: Some(worker),
        }
    }

    /// Accept no more work and drop what is queued; the job in flight, if
    /// any, still finishes.
    fn close(&self) {
        let mut state = self.state();
        state.closed = true;
        state.queued = None;
        drop(state);
        self.wake.notify_one();
    }

    fn state(&self) -> std::sync::MutexGuard<'_, ReconcilerState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Begin a stream: work still queued for earlier streams is dropped.
    fn begin_stream(&self) -> u64 {
        let mut state = self.state();
        state.stream += 1;
        state.queued = None;
        state.stream
    }

    /// Queue `snapshot` for `stream`, replacing whatever it queued before.
    fn submit(&self, stream: u64, snapshot: AssignmentSnapshot) {
        let mut state = self.state();
        if state.stream == stream && !state.closed {
            state.queued = Some((stream, ReconcileJob::Snapshot(snapshot)));
            drop(state);
            self.wake.notify_one();
        }
    }

    /// Queue a retry for `stream` when the worker has nothing to do.
    fn submit_retry(&self, stream: u64) {
        let mut state = self.state();
        if state.stream == stream && !state.closed && !state.busy && state.queued.is_none() {
            state.queued = Some((stream, ReconcileJob::Retry));
            drop(state);
            self.wake.notify_one();
        }
    }

    async fn run(self: Arc<Self>, host: Arc<SharedHost>) {
        loop {
            let job = {
                let mut state = self.state();
                match state.queued.take() {
                    Some(job) => {
                        state.busy = true;
                        Some(job)
                    }
                    None if state.closed => return,
                    None => None,
                }
            };
            let Some((stream, job)) = job else {
                self.wake.notified().await;
                continue;
            };
            let (revision, ok) = match job {
                ReconcileJob::Snapshot(snapshot) => match host.reconcile(&snapshot).await {
                    Ok(()) => (Some(snapshot.revision), true),
                    Err(error) => {
                        tracing::warn!(%error, "refused a malformed assignment snapshot");
                        (None, false)
                    }
                },
                ReconcileJob::Retry => {
                    host.retry_pending().await;
                    (None, true)
                }
            };
            self.state().busy = false;
            self.done.send_modify(|applied| {
                *applied = Applied {
                    sequence: applied.sequence + 1,
                    stream,
                    revision,
                    ok,
                };
            });
        }
    }
}

/// Owns the worker of an attach loop. Shutting it down waits for the job in
/// flight, so nothing the worker admits outlives the attachment; dropping it
/// lets the worker finish that job and stop on its own.
struct ReconcilerHandle {
    reconciler: Arc<Reconciler>,
    worker: Option<tokio::task::JoinHandle<()>>,
}

impl ReconcilerHandle {
    /// Stop the worker at process shutdown: queued work is dropped and the
    /// reconciliation in flight, if any, finishes before this returns, so the
    /// host's own shutdown sees every instance the worker admitted.
    async fn shut_down(mut self) {
        self.reconciler.close();
        if let Some(worker) = self.worker.take() {
            let _ = worker.await;
        }
    }
}

impl std::ops::Deref for ReconcilerHandle {
    type Target = Reconciler;

    fn deref(&self) -> &Reconciler {
        &self.reconciler
    }
}

impl Drop for ReconcilerHandle {
    fn drop(&mut self) {
        self.reconciler.close();
    }
}

/// The assignments of `snapshot` a host admits, and the routes it leaves
/// unstarted. Hosted instances the snapshot assigns or keeps stay; new ones
/// are admitted in route order while fewer than [`MAX_ASSIGNED_INSTANCES`]
/// would run.
fn within_capacity<'a>(
    snapshot: &'a AssignmentSnapshot,
    hosted: &std::collections::BTreeSet<String>,
) -> (Vec<&'a SandboxInstanceAssignment>, Vec<&'a str>) {
    let assigned = snapshot
        .instances
        .iter()
        .map(|assignment| assignment.route.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let staying = hosted
        .iter()
        .filter(|route| assigned.contains(route.as_str()) || snapshot.keep_routes.contains(*route))
        .count();
    let mut room = MAX_ASSIGNED_INSTANCES.saturating_sub(staying);
    let mut fresh = snapshot
        .instances
        .iter()
        .filter(|assignment| !hosted.contains(&assignment.route))
        .collect::<Vec<_>>();
    fresh.sort_by(|left, right| left.route.cmp(&right.route));
    let mut admitted = snapshot
        .instances
        .iter()
        .filter(|assignment| hosted.contains(&assignment.route))
        .collect::<Vec<_>>();
    let mut unstarted = Vec::new();
    for assignment in fresh {
        if room > 0 {
            room -= 1;
            admitted.push(assignment);
        } else {
            unstarted.push(assignment.route.as_str());
        }
    }
    (admitted, unstarted)
}

/// One connection and stream to the gateway.
///
/// One deadline bounds connecting, attaching, and being accepted. Snapshots
/// go to the attach loop's reconcile worker, so heartbeats and status reports
/// keep flowing while instances stop, and the stream ends without waiting for
/// a reconciliation in flight. A pool member also bounds every send by its
/// silence budget, so a gateway that stops reading is abandoned as promptly
/// as one that stops writing.
async fn run_stream(
    host: &Arc<SharedHost>,
    connector: &dyn GatewayConnector,
    reconciler: &Reconciler,
    hello: HostHello,
    timings: &StreamTimings,
    attempt_timeout: Duration,
) -> StreamEnd {
    let lost = |accepted| StreamEnd::Lost { accepted };
    let pool = timings.silence_check.is_some();
    let deadline = if pool {
        AttemptDeadline::Shared(tokio::time::Instant::now() + attempt_timeout)
    } else {
        AttemptDeadline::PerStage(attempt_timeout)
    };
    let stream = reconciler.begin_stream();
    let (tx, rx) = tokio::sync::mpsc::channel::<HostMessage>(OUTBOUND_QUEUE);
    // A send gives up by the ordinary bound, and on a pool member once the
    // stream has been silent for its whole silence budget.
    let send_deadline = |last_heard: tokio::time::Instant| {
        let bound = tokio::time::Instant::now() + SEND_TIMEOUT;
        if pool {
            bound.min(last_heard + timings.silence_timeout)
        } else {
            bound
        }
    };
    let send = |message: HostMessage, deadline: tokio::time::Instant| {
        let tx = tx.clone();
        async move {
            tokio::time::timeout_at(deadline, tx.send(message))
                .await
                .is_ok_and(|sent| sent.is_ok())
        }
    };
    let hello_deadline = match deadline {
        AttemptDeadline::Shared(deadline) => deadline,
        AttemptDeadline::PerStage(_) => tokio::time::Instant::now() + SEND_TIMEOUT,
    };
    if !send(
        HostMessage {
            payload: Some(host_message::Payload::Hello(hello)),
        },
        hello_deadline,
    )
    .await
    {
        return lost(false);
    }
    let opened = match deadline {
        AttemptDeadline::Shared(deadline) => tokio::time::timeout_at(
            deadline,
            connector.open(rx, AttemptDeadline::Shared(deadline)),
        )
        .await
        .unwrap_or_else(|_| Err("connecting to the gateway timed out".to_string())),
        AttemptDeadline::PerStage(_) => connector.open(rx, deadline).await,
    };
    let mut inbound = match opened {
        Ok(inbound) => inbound,
        Err(error) => {
            tracing::warn!(%error, "could not open the supervisor host stream");
            return lost(false);
        }
    };
    let accept_deadline = deadline.stage();
    let mut changes = host.changes();
    changes.mark_unchanged();
    let mut leaving = host.leaving.subscribe();
    leaving.mark_unchanged();
    let mut finished = reconciler.done.subscribe();
    finished.mark_unchanged();
    let mut applied_revision = 0_u64;
    // Highest snapshot revision received on this stream, applied or not, so a
    // snapshot that arrives behind a newer in-flight one is never applied.
    let mut received_revision = 0_u64;
    let mut accepted = false;
    let mut last_heard = tokio::time::Instant::now();
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // A pool member checks for silence and for acceptance on its own, short
    // cadence; a lone host checks on each heartbeat.
    let mut silence_check =
        tokio::time::interval(timings.silence_check.unwrap_or(HEARTBEAT_INTERVAL));
    silence_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let end = loop {
        tokio::select! {
            message = inbound.next() => {
                let payload = match message {
                    Some(Ok(message)) => message.payload,
                    Some(Err(status)) => {
                        tracing::warn!(%status, "gateway assignment stream failed");
                        break lost(accepted);
                    }
                    None => break lost(accepted),
                };
                last_heard = tokio::time::Instant::now();
                match payload {
                    Some(host_gateway_message::Payload::Accepted(accepted_message)) => {
                        accepted = true;
                        host.gateway_connected.send_replace(true);
                        tracing::info!(session = %accepted_message.session_id, "gateway accepted the supervisor host");
                        // A pool gateway detects failed members by silence,
                        // so it asks for more frequent heartbeats.
                        if let Some(interval) = accepted_message
                            .heartbeat_interval
                            .and_then(|interval| Duration::try_from(interval).ok())
                            .filter(|interval| {
                                *interval >= MIN_HEARTBEAT_INTERVAL && *interval < HEARTBEAT_INTERVAL
                            })
                        {
                            heartbeat = tokio::time::interval(interval);
                            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                        }
                        // Report what runs before any snapshot arrives.
                        if !send(status_message(host, applied_revision), send_deadline(last_heard)).await {
                            break lost(accepted);
                        }
                    }
                    Some(host_gateway_message::Payload::Rejected(rejected)) => {
                        tracing::error!(reason = %rejected.reason, "gateway rejected the supervisor host");
                        break lost(accepted);
                    }
                    Some(host_gateway_message::Payload::Assignments(snapshot)) => {
                        if !accepted {
                            tracing::warn!("gateway sent assignments before accepting the host");
                            break lost(accepted);
                        }
                        if snapshot.revision <= received_revision {
                            tracing::debug!(revision = snapshot.revision, received_revision, "ignoring stale assignment snapshot");
                            continue;
                        }
                        received_revision = snapshot.revision;
                        reconciler.submit(stream, snapshot);
                    }
                    Some(host_gateway_message::Payload::Heartbeat(_)) | None => {}
                }
            }
            worked = finished.changed() => {
                if worked.is_err() {
                    break lost(accepted);
                }
                let applied = *finished.borrow_and_update();
                if applied.stream == stream
                    && let Some(revision) = applied.revision
                {
                    applied_revision = revision;
                }
                // A refused snapshot changes nothing to report.
                if applied.ok {
                    changes.mark_unchanged();
                    if accepted && !send(status_message(host, applied_revision), send_deadline(last_heard)).await {
                        break lost(accepted);
                    }
                }
            }
            notified = changes.changed() => {
                if notified.is_err() {
                    break lost(accepted);
                }
                if accepted && !send(status_message(host, applied_revision), send_deadline(last_heard)).await {
                    break lost(accepted);
                }
            }
            // The gateway moves a leaving member's instances at once.
            _ = leaving.changed() => {
                if accepted && !send(status_message(host, applied_revision), send_deadline(last_heard)).await {
                    break lost(accepted);
                }
            }
            // A pool member gives up on acceptance exactly at its deadline.
            () = tokio::time::sleep_until(accept_deadline), if pool && !accepted => {
                tracing::warn!("gateway did not accept the supervisor host in time");
                break lost(accepted);
            }
            _ = silence_check.tick(), if pool => {
                if last_heard.elapsed() > timings.silence_timeout {
                    tracing::warn!("gateway assignment stream went silent; reconnecting");
                    break lost(accepted);
                }
            }
            _ = heartbeat.tick() => {
                if !accepted && tokio::time::Instant::now() > accept_deadline {
                    tracing::warn!("gateway did not accept the supervisor host in time");
                    break lost(accepted);
                }
                if !pool && last_heard.elapsed() > timings.silence_timeout {
                    tracing::warn!("gateway assignment stream went silent; reconnecting");
                    break lost(accepted);
                }
                let beat = HostMessage { payload: Some(host_message::Payload::Heartbeat(HostHeartbeat {})) };
                if !send(beat, send_deadline(last_heard)).await {
                    break lost(accepted);
                }
                // Deferred admissions and withdrawn instances whose cleanup
                // failed are retried at the heartbeat cadence, never
                // concurrently with a snapshot.
                if host.has_pending() {
                    reconciler.submit_retry(stream);
                }
            }
        }
    };
    host.gateway_connected.send_replace(false);
    end
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox_instance_host::SandboxInstanceAdmission;
    use openshell_core::jwt::CredentialEpoch;
    use openshell_sandbox_backend::boundary_protocol::SupervisorInstanceId;

    /// A hosted instance whose stop path reports on `stopped`.
    fn admit_supervising(host: &SharedHost, route: &str, stopped: tokio::sync::mpsc::Sender<()>) {
        let bindings = crate::SandboxInstanceBindings {
            gateway_credentials:
                openshell_core::grpc_client::GatewayCredentials::from_gateway_token(
                    "pool-test-token",
                )
                .unwrap(),
            event_context: Arc::new(crate::sandbox_instance_event_context(
                Some(route),
                Some(route),
                String::new(),
            )),
            ocsf_json: openshell_ocsf::OcsfJsonSettings::default(),
            log_sink: None,
            denial_log:
                openshell_supervisor_network::policy_local::DenialLogSource::SandboxInstance(
                    openshell_supervisor_network::policy_local::SandboxInstanceDenialLog::default(),
                ),
        };
        let body: SandboxInstanceBody = Box::new(move |controls| {
            Box::pin(async move {
                controls.readiness.send_replace(true);
                controls.shutdown.await;
                let _ = stopped.send(()).await;
                Ok(0)
            })
        });
        host.host
            .admit(
                SandboxInstanceAdmission {
                    key: route.to_string(),
                    fingerprint: [7; 32],
                    sandbox_id: route.to_string(),
                },
                |_| Ok::<_, ControlError>((bindings, body)),
            )
            .unwrap();
    }

    /// A pool snapshot sets the recovery deadline offered to the runtimes of
    /// instances admitted after it; none, or one the runtime would refuse,
    /// leaves the runtime default.
    #[tokio::test]
    async fn snapshots_set_the_recovery_deadline_offered_to_new_instances() {
        let root = tempfile::tempdir().unwrap();
        let host = SharedHost::start(SharedHostConfig {
            gateway_endpoint: "https://gateway.invalid".to_string(),
            instance_root: root.path().join("instances"),
            runtime_listen: "127.0.0.1:0".parse().unwrap(),
            removal_grace: Duration::from_secs(10),
            pool: Some(PoolIdentity {
                member_id: "member-1".to_string(),
                member_uid: "uid-1".to_string(),
                runtime_address: "127.0.0.1:5500".parse().unwrap(),
            }),
        })
        .unwrap();
        for (revision, (offered, kept)) in [
            (Some(60), Some(60)),
            (None, None),
            (Some(301), None),
            (Some(10), Some(10)),
        ]
        .into_iter()
        .enumerate()
        {
            host.reconcile(&AssignmentSnapshot {
                revision: u64::try_from(revision).unwrap() + 1,
                pool: true,
                recovery_timeout: offered
                    .map(|seconds| prost_types::Duration { seconds, nanos: 0 }),
                ..AssignmentSnapshot::default()
            })
            .await
            .unwrap();
            assert_eq!(*host.recovery_timeout_secs.lock().unwrap(), kept);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pool_members_keep_release_or_stop_unassigned_instances_as_snapshots_say() {
        let root = tempfile::tempdir().unwrap();
        let host = SharedHost::start(SharedHostConfig {
            gateway_endpoint: "https://gateway.invalid".to_string(),
            instance_root: root.path().join("instances"),
            runtime_listen: "127.0.0.1:0".parse().unwrap(),
            removal_grace: Duration::from_secs(10),
            pool: Some(PoolIdentity {
                member_id: "member-1".to_string(),
                member_uid: "uid-1".to_string(),
                runtime_address: "127.0.0.1:5500".parse().unwrap(),
            }),
        })
        .unwrap();
        let routes = [
            "rt-kept-0123456789",
            "rt-released-012345",
            "rt-stopped-0123456",
        ];
        let mut stops = Vec::new();
        for route in routes {
            let (stopped, stops_of) = tokio::sync::mpsc::channel(1);
            admit_supervising(&host, route, stopped);
            stops.push(stops_of);
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            while host
                .list()
                .iter()
                .filter(|status| status.phase == SandboxInstancePhaseReport::Supervising)
                .count()
                < routes.len()
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("instances supervise");

        // A gateway replica whose desired set lacks the kept instance, such
        // as one this member just reconnected to, still names it as owned.
        host.reconcile(&AssignmentSnapshot {
            revision: 1,
            pool: true,
            stop_routes: vec![routes[2].to_string()],
            keep_routes: vec![routes[0].to_string()],
            ..AssignmentSnapshot::default()
        })
        .await
        .unwrap();

        // The kept instance is untouched; the released one ended without
        // stopping its workload; only the withdrawn one was stopped.
        assert_eq!(
            host.status(routes[0]).map(|status| status.phase),
            Some(SandboxInstancePhaseReport::Supervising)
        );
        assert!(host.status(routes[1]).is_none());
        assert_eq!(
            stops[1].try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected),
            "a released instance never runs its stop path"
        );
        assert!(host.status(routes[2]).is_none());
        assert_eq!(
            stops[2].try_recv(),
            Ok(()),
            "a withdrawn instance is stopped"
        );
        assert!(stops[0].try_recv().is_err());

        // A lone shared supervisor's snapshot is refused by a pool member.
        assert!(
            host.reconcile(&AssignmentSnapshot {
                revision: 2,
                ..AssignmentSnapshot::default()
            })
            .await
            .is_err()
        );
        assert_eq!(
            host.status(routes[0]).map(|status| status.phase),
            Some(SandboxInstancePhaseReport::Supervising)
        );
        host.shut_down().await;
        assert!(host.list().is_empty());
        assert_eq!(
            stops[0].try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected),
            "a pool member relinquishes what it still hosts at shutdown"
        );
    }

    /// Console output of the shorthand layer the supervisor logs through.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The shorthand console format keeps only an event's message, so the
    /// lines that say which member supervises a route carry the route in
    /// their text.
    #[tokio::test]
    async fn assignment_lifecycle_lines_name_their_route_in_shorthand_output() {
        use tracing_subscriber::layer::SubscriberExt as _;
        let captured = Captured::default();
        let _logging =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(
                openshell_ocsf::OcsfShorthandLayer::new(captured.clone()).with_non_ocsf(true),
            ));
        let root = tempfile::tempdir().unwrap();
        let host = SharedHost::start(SharedHostConfig {
            gateway_endpoint: "https://gateway.invalid".to_string(),
            instance_root: root.path().join("instances"),
            runtime_listen: "127.0.0.1:0".parse().unwrap(),
            removal_grace: Duration::from_secs(10),
            pool: Some(PoolIdentity {
                member_id: "member-1".to_string(),
                member_uid: "uid-1".to_string(),
                runtime_address: "127.0.0.1:5500".parse().unwrap(),
            }),
        })
        .unwrap();
        let (released, stopped) = ("rt-released-0123456789", "rt-stopped-0123456789");
        let mut stops = Vec::new();
        for route in [released, stopped] {
            let (stop, stops_of) = tokio::sync::mpsc::channel(1);
            admit_supervising(&host, route, stop);
            stops.push(stops_of);
        }
        host.reconcile(&AssignmentSnapshot {
            revision: 1,
            pool: true,
            stop_routes: vec![stopped.to_string()],
            ..AssignmentSnapshot::default()
        })
        .await
        .unwrap();
        assert_eq!(
            stops[1].try_recv(),
            Ok(()),
            "the withdrawn instance stopped"
        );
        host.shut_down().await;
        let output = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        for line in [
            format!("{RELINQUISHED_TO_OTHER_MEMBER} {released}"),
            format!("{REMOVING_WITHDRAWN} {stopped}"),
        ] {
            assert!(output.contains(&line), "no {line:?} in:\n{output}");
        }
        // The structured fields alone would not show the route.
        assert!(!output.contains("route="), "{output}");
    }

    #[test]
    fn pool_hosts_reconnect_inside_the_membership_budget_and_lone_hosts_do_not_change() {
        use openshell_supervisor_control::pool_timing;
        let pool = StreamTimings::for_host(true);
        assert_eq!(pool.silence_timeout, pool_timing::HOST_SILENCE_TIMEOUT);
        assert_eq!(pool.silence_check, Some(pool_timing::HOST_SILENCE_CHECK));
        // The covered attempts after a lost stream are quick; later ones get
        // the ordinary bound, so a slow but responsive gateway is reached.
        for failed in 0..=pool_timing::COVERED_UNANSWERED_ATTEMPTS {
            assert_eq!(
                pool.attempt_timeout(failed),
                pool_timing::HOST_ATTEMPT_TIMEOUT
            );
        }
        assert_eq!(
            pool.attempt_timeout(pool_timing::COVERED_UNANSWERED_ATTEMPTS + 1),
            CONNECT_TIMEOUT
        );
        for failed in 1..=12 {
            for sample in [0.0, 0.5, 0.999_999, jitter_sample()] {
                let backoff = pool.backoff(failed, sample);
                assert!(backoff >= pool_timing::HOST_RECONNECT_BACKOFF_MIN);
                assert!(backoff <= pool_timing::host_backoff_bound(failed));
            }
        }
        assert_eq!(
            pool.backoff(1, 0.0),
            pool_timing::HOST_RECONNECT_BACKOFF_MIN
        );
        assert_eq!(
            pool.backoff(9, 0.0),
            pool_timing::HOST_RECONNECT_BACKOFF_MAX
        );
        let sample = jitter_sample();
        assert!((0.0..1.0).contains(&sample));

        let lone = StreamTimings::for_host(false);
        assert_eq!(lone.silence_timeout, GATEWAY_SILENCE_TIMEOUT);
        assert_eq!(lone.silence_check, None);
        assert_eq!(lone.attempt_timeout(0), CONNECT_TIMEOUT);
        assert_eq!(lone.attempt_timeout(50), CONNECT_TIMEOUT);
        let lone_backoffs = (1..=7)
            .map(|failed| lone.backoff(failed, 0.9))
            .collect::<Vec<_>>();
        assert_eq!(
            lone_backoffs,
            [1, 2, 4, 8, 16, 30, 30].map(Duration::from_secs)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_oversized_snapshot_still_stops_redirects_and_keeps_within_capacity() {
        let root = tempfile::tempdir().unwrap();
        let host = SharedHost::start(SharedHostConfig {
            gateway_endpoint: "https://gateway.invalid".to_string(),
            instance_root: root.path().join("instances"),
            runtime_listen: "127.0.0.1:0".parse().unwrap(),
            removal_grace: Duration::from_secs(10),
            pool: Some(PoolIdentity {
                member_id: "member-1".to_string(),
                member_uid: "uid-1".to_string(),
                runtime_address: "127.0.0.1:5500".parse().unwrap(),
            }),
        })
        .unwrap();
        let (hosted_route, stopped_route) = ("rt-hosted-0123456789", "rt-stopped-0123456789");
        let (stopped, mut stops) = tokio::sync::mpsc::channel(1);
        let (kept, mut kept_stops) = tokio::sync::mpsc::channel(1);
        admit_supervising(&host, hosted_route, kept);
        admit_supervising(&host, stopped_route, stopped);
        tokio::time::timeout(Duration::from_secs(10), async {
            while host
                .list()
                .iter()
                .filter(|status| status.phase == SandboxInstancePhaseReport::Supervising)
                .count()
                < 2
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("instances supervise");

        // The hosted instance plus a full host's worth of new ones: one more
        // than the host runs.
        let assignment = |route: String| SandboxInstanceAssignment {
            sandbox_id: route.clone(),
            route,
            generation: "generation".to_string(),
            launch_material: b"{}".to_vec(),
            takeover: None,
        };
        let mut instances = vec![assignment(hosted_route.to_string())];
        instances.extend(
            (0..MAX_ASSIGNED_INSTANCES)
                .map(|index| assignment(format!("rt-new-{index:04}-0123456789"))),
        );
        let elsewhere = "rt-elsewhere-0123456789";
        let owner: SocketAddr = "10.0.0.9:5500".parse().unwrap();
        host.reconcile(&AssignmentSnapshot {
            revision: 1,
            pool: true,
            instances,
            stop_routes: vec![stopped_route.to_string()],
            route_directory: vec![openshell_core::proto::supervisor_host::v1::RouteOwner {
                route: elsewhere.to_string(),
                runtime_address: owner.to_string(),
            }],
            ..AssignmentSnapshot::default()
        })
        .await
        .expect("an oversized snapshot is applied, not refused");

        // The listed stop ran, the hosted instance stays, and the directory
        // redirects runtimes of routes owned elsewhere.
        assert_eq!(stops.try_recv(), Ok(()));
        assert!(host.status(stopped_route).is_none());
        assert_eq!(
            host.status(hosted_route).map(|status| status.phase),
            Some(SandboxInstancePhaseReport::Supervising)
        );
        assert!(kept_stops.try_recv().is_err());
        let mut stream = tokio::net::TcpStream::connect(host.router.local_addr())
            .await
            .unwrap();
        assert_eq!(
            openshell_sandbox_backend::runtime_routed::negotiate_route(&mut stream, elsewhere)
                .await
                .unwrap(),
            openshell_sandbox_backend::runtime_routed::RouteReply::Redirect(owner)
        );
        // Only up to capacity was attempted: the hosted instance and all but
        // the last new one in route order; the last stays unstarted.
        let rejected = host.rejected.lock().unwrap().clone();
        assert_eq!(rejected.len(), MAX_ASSIGNED_INSTANCES);
        let last = format!("rt-new-{:04}-0123456789", MAX_ASSIGNED_INSTANCES - 1);
        assert!(!rejected.contains_key(&last));
        assert!(rejected.contains_key("rt-new-0000-0123456789"));
        assert!(host.list().iter().all(|status| status.route != last));
        host.shut_down().await;
    }

    /// How one connection attempt to a [`FakeGateway`] goes.
    enum Attempt {
        /// Never opens.
        Hang,
        /// Opens after a delay.
        After(Duration),
        /// Opens at once.
        Now,
    }

    /// A stream the fake gateway opened, driven by the test.
    struct Opened {
        /// When the host asked for it.
        at: tokio::time::Instant,
        outbound: tokio::sync::mpsc::Receiver<HostMessage>,
        inbound: tokio::sync::mpsc::Sender<Result<HostGatewayMessage, tonic::Status>>,
    }

    /// Gateway replicas behind one Service: each attempt goes as planned, and
    /// every opened stream is handed to the test.
    struct FakeGateway {
        plan: Mutex<std::collections::VecDeque<Attempt>>,
        calls: Mutex<Vec<tokio::time::Instant>>,
        opened: tokio::sync::mpsc::UnboundedSender<Opened>,
    }

    impl GatewayConnector for FakeGateway {
        fn open(
            &self,
            outbound: tokio::sync::mpsc::Receiver<HostMessage>,
            _deadline: AttemptDeadline,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<GatewayInbound, String>> + Send + '_>>
        {
            let at = tokio::time::Instant::now();
            self.calls.lock().unwrap().push(at);
            let attempt = self
                .plan
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Attempt::Now);
            Box::pin(async move {
                match attempt {
                    Attempt::Hang => std::future::pending::<()>().await,
                    Attempt::After(delay) => tokio::time::sleep(delay).await,
                    Attempt::Now => {}
                }
                let (inbound, stream) = tokio::sync::mpsc::channel(1);
                let _ = self.opened.send(Opened {
                    at,
                    outbound,
                    inbound,
                });
                let stream: GatewayInbound =
                    Box::pin(tokio_stream::wrappers::ReceiverStream::new(stream));
                Ok(stream)
            })
        }
    }

    fn gateway_message(payload: host_gateway_message::Payload) -> HostGatewayMessage {
        HostGatewayMessage {
            payload: Some(payload),
        }
    }

    fn accepted() -> HostGatewayMessage {
        gateway_message(host_gateway_message::Payload::Accepted(
            openshell_core::proto::supervisor_host::v1::HostAccepted {
                session_id: "session".to_string(),
                heartbeat_interval: Some(prost_types::Duration {
                    seconds: 1,
                    nanos: 0,
                }),
            },
        ))
    }

    fn gateway_heartbeat() -> HostGatewayMessage {
        gateway_message(host_gateway_message::Payload::Heartbeat(
            openshell_core::proto::supervisor_host::v1::HostGatewayHeartbeat {},
        ))
    }

    fn pool_snapshot(revision: u64) -> HostGatewayMessage {
        gateway_message(host_gateway_message::Payload::Assignments(
            AssignmentSnapshot {
                revision,
                pool: true,
                ..AssignmentSnapshot::default()
            },
        ))
    }

    /// A pool host attached to `plan`, and the streams it opens.
    fn attach_pool_host(
        plan: Vec<Attempt>,
    ) -> (
        Arc<SharedHost>,
        Arc<FakeGateway>,
        tokio::sync::mpsc::UnboundedReceiver<Opened>,
        tempfile::TempDir,
    ) {
        let (host, gateway, streams, root, _attachment) =
            attach_pool_host_until(plan, std::future::pending::<()>());
        (host, gateway, streams, root)
    }

    /// A pool host attached to `plan` until `shutdown`, the streams it opens,
    /// and the attachment.
    fn attach_pool_host_until(
        plan: Vec<Attempt>,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> (
        Arc<SharedHost>,
        Arc<FakeGateway>,
        tokio::sync::mpsc::UnboundedReceiver<Opened>,
        tempfile::TempDir,
        tokio::task::JoinHandle<()>,
    ) {
        let root = tempfile::tempdir().unwrap();
        let host = SharedHost::start(SharedHostConfig {
            gateway_endpoint: "https://gateway.invalid".to_string(),
            instance_root: root.path().join("instances"),
            runtime_listen: "127.0.0.1:0".parse().unwrap(),
            removal_grace: Duration::from_secs(10),
            pool: Some(PoolIdentity {
                member_id: "member-1".to_string(),
                member_uid: "uid-1".to_string(),
                runtime_address: "127.0.0.1:5500".parse().unwrap(),
            }),
        })
        .unwrap();
        let (opened, streams) = tokio::sync::mpsc::unbounded_channel();
        let gateway = Arc::new(FakeGateway {
            plan: Mutex::new(plan.into()),
            calls: Mutex::new(Vec::new()),
            opened,
        });
        let attachment = tokio::spawn(attach_with(host.clone(), gateway.clone(), shutdown));
        (host, gateway, streams, root, attachment)
    }

    fn is_hello(message: Option<HostMessage>) -> bool {
        matches!(
            message.and_then(|message| message.payload),
            Some(host_message::Payload::Hello(_))
        )
    }

    fn status_of(message: Option<HostMessage>) -> Option<HostStatus> {
        match message.and_then(|message| message.payload) {
            Some(host_message::Payload::Status(status)) => Some(status),
            _ => None,
        }
    }

    /// The next status the host reports, past its heartbeats.
    async fn next_status(
        outbound: &mut tokio::sync::mpsc::Receiver<HostMessage>,
    ) -> Option<HostStatus> {
        loop {
            match outbound.recv().await?.payload {
                Some(host_message::Payload::Status(status)) => return Some(status),
                Some(host_message::Payload::Heartbeat(_)) => {}
                _ => return None,
            }
        }
    }

    /// Accept a stream and keep it answering: heartbeats every second, and
    /// every status the host reports forwarded to the test.
    fn serve(
        mut stream: Opened,
    ) -> (
        tokio::sync::mpsc::UnboundedReceiver<HostStatus>,
        tokio::sync::mpsc::Sender<Result<HostGatewayMessage, tonic::Status>>,
    ) {
        let (statuses, reported) = tokio::sync::mpsc::unbounded_channel();
        let gateway = stream.inbound.clone();
        let inbound = stream.inbound.clone();
        tokio::spawn(async move {
            if inbound.send(Ok(accepted())).await.is_err() {
                return;
            }
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if inbound.send(Ok(gateway_heartbeat())).await.is_err() {
                    return;
                }
            }
        });
        tokio::spawn(async move {
            while let Some(message) = stream.outbound.recv().await {
                if let Some(status) = status_of(Some(message))
                    && statuses.send(status).is_err()
                {
                    return;
                }
            }
        });
        (reported, gateway)
    }

    /// The part of the reconnect budget the host itself spends: everything
    /// but the gateway's record refresh age and its two refresh rounds.
    fn host_budget(unanswered: u32) -> Duration {
        use openshell_supervisor_control::pool_timing;
        pool_timing::reconnect_budget(unanswered)
            .saturating_sub(pool_timing::MEMBER_REFRESH_INTERVAL)
            .saturating_sub(pool_timing::RECORD_WRITE_BOUND * 2)
    }

    /// A replica that accepted and then went silent is abandoned, and a
    /// responsive replica is reached within the budget even when the covered
    /// attempts reach the silent replica again; the new stream says hello and
    /// reports status at once.
    #[tokio::test(start_paused = true)]
    async fn a_silent_gateway_is_left_for_a_responsive_one_within_the_budget() {
        use openshell_supervisor_control::pool_timing;
        let covered = pool_timing::COVERED_UNANSWERED_ATTEMPTS;
        let mut plan = vec![Attempt::Now];
        plan.extend((0..covered).map(|_| Attempt::Hang));
        plan.push(Attempt::Now);
        let (_host, gateway, mut streams, _root) = attach_pool_host(plan);
        let mut silent = streams.recv().await.unwrap();
        assert!(is_hello(silent.outbound.recv().await));
        silent.inbound.send(Ok(accepted())).await.unwrap();
        assert!(next_status(&mut silent.outbound).await.is_some());
        let went_silent = tokio::time::Instant::now();

        let mut responsive = streams.recv().await.unwrap();
        let reconnected = responsive.at - went_silent;
        assert!(
            reconnected <= host_budget(covered),
            "reached a responsive replica {reconnected:?} after the silence, over {:?}",
            host_budget(covered)
        );
        assert_eq!(gateway.calls.lock().unwrap().len(), 2 + covered as usize);
        assert!(is_hello(responsive.outbound.recv().await));
        responsive.inbound.send(Ok(accepted())).await.unwrap();
        let accepted_at = tokio::time::Instant::now();
        assert!(next_status(&mut responsive.outbound).await.is_some());
        assert_eq!(
            tokio::time::Instant::now(),
            accepted_at,
            "status is reported at once"
        );
    }

    /// After an accepted stream is lost, every attempt through the one after
    /// the covered unanswered attempts, the one the budget counts on reaching
    /// a responsive replica, gets the quick bound; only later ones get the
    /// ordinary bound.
    #[tokio::test(start_paused = true)]
    async fn the_attempt_after_the_covered_unanswered_ones_is_still_quick() {
        use openshell_supervisor_control::pool_timing;
        let covered = pool_timing::COVERED_UNANSWERED_ATTEMPTS as usize;
        let mut plan = vec![Attempt::Now];
        // The covered unanswered attempts, the one after them, and one more.
        plan.extend((0..covered + 2).map(|_| Attempt::Hang));
        plan.push(Attempt::Now);
        let (_host, gateway, mut streams, _root) = attach_pool_host(plan);
        let mut silent = streams.recv().await.unwrap();
        assert!(is_hello(silent.outbound.recv().await));
        silent.inbound.send(Ok(accepted())).await.unwrap();
        assert!(next_status(&mut silent.outbound).await.is_some());
        streams.recv().await.unwrap();
        let calls = gateway.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), covered + 4);
        // Reconnect attempt `n` (1-based) runs from calls[n] to calls[n + 1].
        for attempt in 1..=covered + 2 {
            let took = calls[attempt + 1] - calls[attempt];
            let backoff = pool_timing::host_backoff_bound(u32::try_from(attempt + 1).unwrap());
            let bound = if attempt <= covered + 1 {
                pool_timing::HOST_ATTEMPT_TIMEOUT
            } else {
                CONNECT_TIMEOUT
            };
            assert!(
                took >= bound && took <= bound + backoff,
                "reconnect attempt {attempt} took {took:?}, expected its {bound:?} bound"
            );
        }
    }

    /// Connecting, attaching, and being accepted share one deadline: a
    /// stream that opens late and is never accepted is abandoned when the
    /// attempt's deadline passes, not a full timeout after it opened.
    #[tokio::test(start_paused = true)]
    async fn one_deadline_bounds_connecting_and_being_accepted() {
        use openshell_supervisor_control::pool_timing;
        let late = pool_timing::HOST_ATTEMPT_TIMEOUT.mul_f64(0.7);
        let (_host, gateway, mut streams, _root) =
            attach_pool_host(vec![Attempt::After(late), Attempt::Now]);
        let unaccepted = streams.recv().await.unwrap();
        let next = streams.recv().await.unwrap();
        let attempt = next.at - unaccepted.at;
        assert!(
            attempt <= pool_timing::HOST_ATTEMPT_TIMEOUT + pool_timing::host_backoff_bound(1),
            "the unaccepted attempt took {attempt:?}"
        );
        assert!(attempt >= pool_timing::HOST_ATTEMPT_TIMEOUT);
        assert_eq!(gateway.calls.lock().unwrap().len(), 2);
    }

    /// A replica that keeps writing but stops reading fills the host's
    /// outbound queue; the blocked send gives up within the silence budget
    /// rather than the ordinary send bound.
    #[tokio::test(start_paused = true)]
    async fn a_gateway_that_stops_reading_is_left_within_the_silence_budget() {
        use openshell_supervisor_control::pool_timing;
        let (_host, _gateway, mut streams, _root) =
            attach_pool_host(vec![Attempt::Now, Attempt::Now]);
        let unread = streams.recv().await.unwrap();
        let inbound = unread.inbound.clone();
        tokio::spawn(async move {
            if inbound.send(Ok(accepted())).await.is_err() {
                return;
            }
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if inbound.send(Ok(gateway_heartbeat())).await.is_err() {
                    return;
                }
            }
        });
        // The host fills its queue to the replica that never reads it.
        while unread.outbound.len() < OUTBOUND_QUEUE {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let full = tokio::time::Instant::now();
        let next = streams.recv().await.unwrap();
        let left = next.at - full;
        assert!(
            left <= pool_timing::HOST_SILENCE_TIMEOUT
                + pool_timing::HEARTBEAT_INTERVAL
                + pool_timing::host_backoff_bound(1),
            "a blocked send held the host {left:?}"
        );
        assert!(left < SEND_TIMEOUT);
    }

    /// A reconciliation stalled past the membership TTL keeps neither a new
    /// stream from connecting and reporting nor a second reconciliation from
    /// waiting its turn: the new stream's snapshot is applied after it, never
    /// beside it.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_reconciliation_neither_delays_reconnecting_nor_runs_twice() {
        use openshell_supervisor_control::pool_timing;
        let (host, _gateway, mut streams, _root) =
            attach_pool_host(vec![Attempt::Now, Attempt::Now]);
        let (release, gate) = tokio::sync::oneshot::channel();
        *host.reconcile_probe.gate.lock().unwrap() = Some(gate);
        let mut stalled = streams.recv().await.unwrap();
        assert!(is_hello(stalled.outbound.recv().await));
        stalled.inbound.send(Ok(accepted())).await.unwrap();
        assert!(next_status(&mut stalled.outbound).await.is_some());
        stalled.inbound.send(Ok(pool_snapshot(7))).await.unwrap();
        let went_silent = tokio::time::Instant::now();
        // The worker takes the snapshot and stalls; the replica stays silent.
        while host
            .reconcile_probe
            .running
            .load(std::sync::atomic::Ordering::SeqCst)
            == 0
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let responsive = tokio::time::timeout(pool_timing::MEMBER_TTL, streams.recv())
            .await
            .expect("reconnected while the reconciliation stalls")
            .unwrap();
        assert!(responsive.at - went_silent <= host_budget(0));
        let accepted_at = tokio::time::Instant::now();
        let (mut reported, gateway) = serve(responsive);
        let first = reported.recv().await.unwrap();
        assert_eq!(tokio::time::Instant::now(), accepted_at);
        assert_eq!(first.applied_revision, 0);

        // The new replica's snapshot waits for the stalled one, well past the
        // TTL, while the stream stays up.
        gateway.send(Ok(pool_snapshot(1))).await.unwrap();
        tokio::time::sleep(pool_timing::MEMBER_TTL + Duration::from_secs(5)).await;
        assert_eq!(
            host.reconcile_probe
                .peak
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        release.send(()).unwrap();
        let applied = loop {
            let status = reported.recv().await.unwrap();
            if status.applied_revision == 1 {
                break status;
            }
        };
        assert_eq!(applied.applied_revision, 1);
        assert_eq!(
            host.reconcile_probe
                .peak
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    /// Process shutdown ends the attachment only once the reconciliation in
    /// flight has finished, so the host's own shutdown sees everything it
    /// admitted; snapshots still queued behind it are dropped.
    #[tokio::test(start_paused = true)]
    async fn shutdown_waits_for_the_reconciliation_in_flight_and_drops_queued_work() {
        use std::sync::atomic::Ordering;
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let (host, _gateway, mut streams, _root, attachment) =
            attach_pool_host_until(vec![Attempt::Now], async {
                let _ = stopped.await;
            });
        let (release, gate) = tokio::sync::oneshot::channel();
        *host.reconcile_probe.gate.lock().unwrap() = Some(gate);
        let stream = streams.recv().await.unwrap();
        let (mut reported, gateway) = serve(stream);
        // Accepted: the host reports before any snapshot.
        reported.recv().await.unwrap();
        gateway.send(Ok(pool_snapshot(1))).await.unwrap();
        while host.reconcile_probe.running.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // A newer snapshot waits behind the stalled one.
        gateway.send(Ok(pool_snapshot(2))).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        stop.send(()).unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert!(
            !attachment.is_finished(),
            "the attachment ended while a reconciliation was still admitting"
        );
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), attachment)
            .await
            .expect("the attachment ends once the reconciliation finishes")
            .unwrap();
        assert_eq!(host.reconcile_probe.running.load(Ordering::SeqCst), 0);
        assert_eq!(
            host.reconcile_probe.entered.load(Ordering::SeqCst),
            1,
            "the queued snapshot must not run after shutdown"
        );
    }

    fn term(auth_epoch: u64, instance: &str, minted_by: &str) -> SandboxInstanceTakeover {
        SandboxInstanceTakeover {
            auth_epoch,
            supervisor_instance_id: instance.to_string(),
            grant: format!("grant.{minted_by}.signature"),
            gateway_token: format!("gateway.{minted_by}.signature"),
            gateway_expires_at: 10,
            sandbox_token: format!("sandbox.{minted_by}.signature"),
            sandbox_expires_at: 20,
        }
    }

    #[test]
    fn pool_instances_are_fingerprinted_by_their_term_not_their_credentials() {
        let instance = SupervisorInstanceId::new().to_string();
        let fingerprint = |launch: &[u8], takeover: Option<&SandboxInstanceTakeover>| {
            pool_fingerprint(launch, 1, takeover).expect("fingerprint")
        };
        let minted_here = term(2, &instance, "gateway-a");
        // Another gateway replica mints different bytes for the same term,
        // and one that minted nothing yet sends the term alone.
        let minted_elsewhere = term(2, &instance, "gateway-b");
        let unminted = SandboxInstanceTakeover {
            auth_epoch: 2,
            supervisor_instance_id: instance.clone(),
            ..SandboxInstanceTakeover::default()
        };
        let current = fingerprint(b"launch", Some(&minted_here));
        assert_eq!(current, fingerprint(b"launch", Some(&minted_elsewhere)));
        assert_eq!(current, fingerprint(b"launch", Some(&unminted)));
        // Another term, process, or launch is another instance.
        for other in [
            fingerprint(b"launch", None),
            fingerprint(b"launch", Some(&term(3, &instance, "gateway-a"))),
            fingerprint(
                b"launch",
                Some(&term(
                    2,
                    &SupervisorInstanceId::new().to_string(),
                    "gateway-a",
                )),
            ),
            fingerprint(b"other launch", Some(&minted_here)),
        ] {
            assert_ne!(current, other);
        }
    }

    #[test]
    fn takeover_terms_follow_the_launch_term_and_wait_for_their_credentials() {
        let launch = CredentialEpoch::new(1).expect("launch epoch");
        let instance = SupervisorInstanceId::new();
        let granted = takeover_term(launch, &term(2, &instance.to_string(), "gateway-a"))
            .expect("granted term");
        assert_eq!(granted.auth_epoch.get(), 2);
        assert_eq!(
            granted.boundary.supervisor_instance_id.to_string(),
            instance.to_string()
        );
        assert_eq!(
            granted.gateway_token.expose_secret(),
            "gateway.gateway-a.signature"
        );
        assert_eq!(
            granted.sandbox_token.expose_secret(),
            "sandbox.gateway-a.signature"
        );

        let unminted = SandboxInstanceTakeover {
            auth_epoch: 2,
            supervisor_instance_id: instance.to_string(),
            ..SandboxInstanceTakeover::default()
        };
        assert!(matches!(
            takeover_term(launch, &unminted),
            Err(ControlError::Deferred(_))
        ));
        for refused in [
            term(1, &instance.to_string(), "gateway-a"),
            term(0, &instance.to_string(), "gateway-a"),
            term(2, "not-a-process", "gateway-a"),
            SandboxInstanceTakeover {
                gateway_token: "has whitespace".to_string(),
                ..term(2, &instance.to_string(), "gateway-a")
            },
        ] {
            assert!(matches!(
                takeover_term(launch, &refused),
                Err(ControlError::Invalid(_))
            ));
        }
    }
}
