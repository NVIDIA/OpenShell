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
    AssignmentSnapshot, HostHeartbeat, HostHello, HostMessage, HostStatus, PoolMember,
    SandboxInstanceAssignment, SandboxInstanceTakeover, host_gateway_message, host_message,
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
                tracing::info!(
                    route = %assignment.route,
                    sandbox_id = %assignment.sandbox_id,
                    "relinquishing a sandbox instance for its later ownership term"
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
    /// # Errors
    ///
    /// A malformed snapshot (too many instances, or one route assigned twice)
    /// is refused as a whole before anything is admitted or removed.
    pub async fn reconcile(&self, snapshot: &AssignmentSnapshot) -> Result<(), ControlError> {
        if snapshot.instances.len() > MAX_ASSIGNED_INSTANCES {
            return Err(ControlError::Invalid(format!(
                "snapshot assigns {} instances; at most {MAX_ASSIGNED_INSTANCES} are supported",
                snapshot.instances.len()
            )));
        }
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
        *self
            .desired_routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(routes);
        let mut rejected = BTreeMap::new();
        let mut deferred = BTreeMap::new();
        for assignment in &snapshot.instances {
            let outcome = if self.pool.is_some() {
                self.admit_pool_assignment(assignment).await
            } else {
                SandboxInstanceRegistration::from_assignment(assignment)
                    .map_err(|error| ControlError::Invalid(error.to_string()))
                    .and_then(|registration| self.register(registration))
            };
            match outcome {
                Ok(SandboxInstanceAdmitted::Created) => {
                    tracing::info!(
                        route = %assignment.route,
                        sandbox_id = %assignment.sandbox_id,
                        "admitted assigned sandbox instance"
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
                if stop {
                    tracing::info!(
                        route = %hosted.route,
                        sandbox_id = %hosted.sandbox_id,
                        "removing withdrawn sandbox instance"
                    );
                    self.remove(&hosted.route).await;
                } else {
                    tracing::info!(
                        route = %hosted.route,
                        sandbox_id = %hosted.sandbox_id,
                        "relinquishing a sandbox instance owned by another pool member"
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

/// Keep one assignment stream open to the gateway until `shutdown`
/// completes, reconnecting with backoff. Hosted instances run on across
/// disconnects.
pub async fn attach_to_gateway(
    host: Arc<SharedHost>,
    link: GatewayLink,
    shutdown: impl Future<Output = ()>,
) {
    let instance_id = uuid::Uuid::new_v4().to_string();
    let mut connection_epoch = 0_u64;
    let mut backoff = RECONNECT_BACKOFF_MIN;
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
        let StreamEnd::Lost { accepted } = tokio::select! {
            end = run_stream(&host, &link, hello) => end,
            () = &mut shutdown => return,
        };
        if accepted {
            backoff = RECONNECT_BACKOFF_MIN;
        }
        tracing::info!(
            retry_in_secs = backoff.as_secs(),
            "gateway assignment stream lost; hosted sandbox instances keep running"
        );
        tokio::select! {
            () = tokio::time::sleep(backoff) => {}
            () = &mut shutdown => return,
        }
        backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
    }
}

/// One connection and stream to the gateway.
///
/// Snapshots are reconciled on a separate task so heartbeats and status
/// reports keep flowing while instances stop; at most one reconciliation runs
/// at a time, only the newest unapplied snapshot is kept, and the stream does
/// not end until a running reconciliation has finished.
async fn run_stream(host: &Arc<SharedHost>, link: &GatewayLink, hello: HostHello) -> StreamEnd {
    let lost = |accepted| StreamEnd::Lost { accepted };
    if !link.endpoint.starts_with("https://") {
        tracing::error!("the supervisor token requires an https gateway endpoint");
        return lost(false);
    }
    let token = match link.read_token() {
        Ok(token) => token,
        Err(error) => {
            tracing::warn!(%error, "no usable supervisor token; will retry");
            return lost(false);
        }
    };
    let connect = openshell_core::grpc_client::connect_gateway_channel(&link.endpoint);
    let channel = match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
        Ok(Ok(channel)) => channel,
        Ok(Err(error)) => {
            tracing::warn!(%error, "could not connect to the gateway");
            return lost(false);
        }
        Err(_) => {
            tracing::warn!("connecting to the gateway timed out");
            return lost(false);
        }
    };
    let mut client = SupervisorHostClient::with_interceptor(channel, token.interceptor())
        .max_decoding_message_size(MAX_GATEWAY_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_HOST_MESSAGE_BYTES);
    let (tx, rx) = tokio::sync::mpsc::channel::<HostMessage>(OUTBOUND_QUEUE);
    let send = |message: HostMessage| {
        let tx = tx.clone();
        async move { tx.send_timeout(message, SEND_TIMEOUT).await.is_ok() }
    };
    if !send(HostMessage {
        payload: Some(host_message::Payload::Hello(hello)),
    })
    .await
    {
        return lost(false);
    }
    let attach = client.attach(tokio_stream::wrappers::ReceiverStream::new(rx));
    let mut inbound = match tokio::time::timeout(CONNECT_TIMEOUT, attach).await {
        Ok(Ok(response)) => response.into_inner(),
        Ok(Err(status)) => {
            tracing::warn!(%status, "gateway refused the supervisor host stream");
            return lost(false);
        }
        Err(_) => {
            tracing::warn!("gateway did not answer the supervisor host stream in time");
            return lost(false);
        }
    };
    let mut changes = host.changes();
    changes.mark_unchanged();
    let mut leaving = host.leaving.subscribe();
    leaving.mark_unchanged();
    let mut applied_revision = 0_u64;
    // Highest snapshot revision received on this stream, applied or not, so a
    // snapshot that arrives behind a newer in-flight one is never applied.
    let mut received_revision = 0_u64;
    let mut accepted = false;
    let accept_deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    let mut last_heard = tokio::time::Instant::now();
    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The reconciliation in flight and the newest snapshot waiting for it.
    // A retry of withdrawals whose cleanup failed runs through the same slot,
    // so at most one reconciliation touches the registry at a time.
    let mut applying: Option<tokio::task::JoinHandle<Result<Option<u64>, ControlError>>> = None;
    let mut queued: Option<AssignmentSnapshot> = None;
    let start = |snapshot: AssignmentSnapshot| {
        let host = host.clone();
        tokio::spawn(async move {
            host.reconcile(&snapshot).await?;
            Ok(Some(snapshot.revision))
        })
    };
    let retry_pending = || {
        let host = host.clone();
        tokio::spawn(async move {
            host.retry_pending().await;
            Ok(None)
        })
    };
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
                        if !send(status_message(host, applied_revision)).await {
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
                        if applying.is_some() {
                            queued = Some(snapshot);
                        } else {
                            applying = Some(start(snapshot));
                        }
                    }
                    Some(host_gateway_message::Payload::Heartbeat(_)) | None => {}
                }
            }
            applied = async { applying.as_mut().expect("polled only while applying").await }, if applying.is_some() => {
                applying = None;
                match applied {
                    Ok(Ok(revision)) => {
                        if let Some(revision) = revision {
                            applied_revision = revision;
                        }
                        changes.mark_unchanged();
                        if !send(status_message(host, applied_revision)).await {
                            break lost(accepted);
                        }
                    }
                    Ok(Err(error)) => {
                        tracing::warn!(%error, "refused a malformed assignment snapshot");
                    }
                    Err(error) => {
                        tracing::error!(%error, "assignment reconciliation task failed");
                    }
                }
                if let Some(snapshot) = queued.take() {
                    applying = Some(start(snapshot));
                }
            }
            notified = changes.changed() => {
                if notified.is_err() {
                    break lost(accepted);
                }
                if accepted && !send(status_message(host, applied_revision)).await {
                    break lost(accepted);
                }
            }
            // The gateway moves a leaving member's instances at once.
            _ = leaving.changed() => {
                if accepted && !send(status_message(host, applied_revision)).await {
                    break lost(accepted);
                }
            }
            _ = heartbeat.tick() => {
                if !accepted && tokio::time::Instant::now() > accept_deadline {
                    tracing::warn!("gateway did not accept the supervisor host in time");
                    break lost(accepted);
                }
                if last_heard.elapsed() > GATEWAY_SILENCE_TIMEOUT {
                    tracing::warn!("gateway assignment stream went silent; reconnecting");
                    break lost(accepted);
                }
                let beat = HostMessage { payload: Some(host_message::Payload::Heartbeat(HostHeartbeat {})) };
                if !send(beat).await {
                    break lost(accepted);
                }
                // Deferred admissions and withdrawn instances whose cleanup
                // failed are retried at the heartbeat cadence, never
                // concurrently with a snapshot.
                if applying.is_none() && queued.is_none() && host.has_pending() {
                    applying = Some(retry_pending());
                }
            }
        }
    };
    host.gateway_connected.send_replace(false);
    // Finish the reconciliation this stream started before another stream
    // can begin one; the queued snapshot belongs to a session that is gone.
    if let Some(applying) = applying {
        let _ = applying.await;
    }
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
