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

use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use miette::Result;
use openshell_core::proto::supervisor_host::v1::supervisor_host_client::SupervisorHostClient;
use openshell_core::proto::supervisor_host::v1::{
    AssignmentSnapshot, HostHeartbeat, HostHello, HostMessage, HostStatus, host_gateway_message,
    host_message,
};
use openshell_extension_core::BearerTokenSlot;
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

/// Interval at which the host sends heartbeats on an idle stream.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
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
}

/// A rejected sandbox instance assignment.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("{0}")]
    Invalid(String),
    #[error("route is already hosted with different launch material")]
    Conflict,
    #[error("route is still being removed")]
    Removing,
    #[error("{0}")]
    Unavailable(String),
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
        }))
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
        let admission = SandboxInstanceAdmission {
            key: registration.route.clone(),
            fingerprint: registration_digest(&registration)?,
            sandbox_id: registration.sandbox_id.clone(),
        };
        self.host
            .admit(admission, |dir| self.instance_launch(registration, dir))
    }

    /// Status of one hosted sandbox instance.
    #[must_use]
    pub fn status(&self, route: &str) -> Option<SandboxInstanceStatusReport> {
        self.host.status(route)
    }

    /// Status of every hosted sandbox instance. An assignment of the latest
    /// snapshot that could not be admitted is reported as failed, even when
    /// an earlier instance still runs under its route, so the gateway sees
    /// the rejection rather than the instance it could not replace.
    #[must_use]
    pub fn list(&self) -> Vec<SandboxInstanceStatusReport> {
        let rejected = self
            .rejected
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut reports = self
            .host
            .list()
            .into_iter()
            .filter(|hosted| !rejected.contains_key(&hosted.route))
            .collect::<Vec<_>>();
        reports.extend(rejected.values().cloned());
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
        *self
            .desired_routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(routes);
        let mut rejected = BTreeMap::new();
        for assignment in &snapshot.instances {
            let outcome = SandboxInstanceRegistration::from_assignment(assignment)
                .map_err(|error| ControlError::Invalid(error.to_string()))
                .and_then(|registration| self.register(registration));
            match outcome {
                Ok(SandboxInstanceAdmitted::Created) => {
                    tracing::info!(
                        route = %assignment.route,
                        sandbox_id = %assignment.sandbox_id,
                        "admitted assigned sandbox instance"
                    );
                }
                Ok(SandboxInstanceAdmitted::Unchanged) => {}
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
        self.remove_withdrawn().await;
        Ok(())
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
        futures::future::join_all(withdrawn.iter().map(|hosted| async move {
            tracing::info!(
                route = %hosted.route,
                sandbox_id = %hosted.sandbox_id,
                "removing withdrawn sandbox instance"
            );
            self.remove(&hosted.route).await;
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

    /// Launch material of `registration` with its private files in `dir`.
    fn instance_launch(
        &self,
        registration: SandboxInstanceRegistration,
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
    let retry_withdrawn = || {
        let host = host.clone();
        tokio::spawn(async move {
            host.remove_withdrawn().await;
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
                        tracing::info!(session = %accepted_message.session_id, "gateway accepted the supervisor host");
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
                // Withdrawn instances whose cleanup failed are retried at the
                // heartbeat cadence, never concurrently with a snapshot.
                if applying.is_none() && queued.is_none() && host.has_withdrawn_leftovers() {
                    applying = Some(retry_withdrawn());
                }
            }
        }
    };
    // Finish the reconciliation this stream started before another stream
    // can begin one; the queued snapshot belongs to a session that is gone.
    if let Some(applying) = applying {
        let _ = applying.await;
    }
    end
}
