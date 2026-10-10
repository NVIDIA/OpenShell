// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Persistent supervisor-to-gateway session.
//!
//! Maintains a long-lived `ConnectSupervisor` bidirectional gRPC stream to the
//! gateway. When the gateway sends `RelayOpen`, the supervisor dials the
//! requested local target, initiates a `RelayStream` gRPC call (a new HTTP/2
//! stream multiplexed over the same TCP+TLS connection as the control stream),
//! and bridges bytes. The supervisor is a dumb byte bridge after target
//! selection — it has no protocol awareness of the bytes flowing through.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use openshell_core::grpc_client::SettingsPollResult;
use openshell_core::proto::open_shell_client::OpenShellClient;
use openshell_core::proto::{
    ConfigApplyFailure, ConfigApplyOutcome, ConfigBootstrap, ConfigBootstrapResult,
    ConfigComponent, ConfigComponentApplyResult, ConfigSnapshotRevision, ConfigUpdate,
    ConfigUpdateResult, ConfigurationAdmissionState, FinalizeMainProcessExitRequest,
    GatewayMessage, ImagePolicyDiscovery, RelayFrame, RelayInit, RelayOpen, RelayOpenResult,
    ReportMainProcessExitRequest, SandboxConfigRevision, SandboxConfigurationAdmission,
    SandboxPolicy, StartupConfigPrepared, SupervisorHeartbeat, SupervisorHello, SupervisorMessage,
    TcpRelayTarget, config_snapshot_revision, config_update, gateway_message, relay_open,
    startup_config_prepared, supervisor_message,
};
use openshell_isolation_interface::contract::{BoundaryLoopbackConnector, LoopbackTarget};
use openshell_ocsf::{
    ActivityId, BaseEventBuilder, ConnectionInfo, Endpoint, EventContext, NetworkActivityBuilder,
    OcsfEvent, SeverityId, StatusId, ocsf_emit,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio_stream::StreamExt;
use tracing::{debug, info, warn};

use openshell_core::grpc_client;
use openshell_core::transport_errors::is_expected_transport_close_status;

const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const CONFIG_APPLY_TIMEOUT: Duration = Duration::from_mins(1);
// The gateway may hold the initial stream open while an operator repairs an
// invalid image policy. Keep this above the five-minute provisioning window.
pub const SESSION_PREPARE_TIMEOUT: Duration = Duration::from_mins(6);

type StartupPolicyPreparer =
    Box<dyn FnOnce(SandboxPolicy) -> Result<Option<SandboxPolicy>, String> + Send>;

/// A stream-delivered desired-state payload awaiting application by the
/// supervisor runtime. The response travels back over `ConnectSupervisor`.
pub enum ConfigApplyRequest {
    Bootstrap {
        bootstrap: ConfigBootstrap,
        response: tokio::sync::oneshot::Sender<ConfigBootstrapResult>,
    },
    Update {
        update: ConfigUpdate,
        response: tokio::sync::oneshot::Sender<ConfigUpdateResult>,
    },
}

/// A supervisor session that has received its startup response.
///
/// It has not yet reported runtime initialization. Holding the stream open
/// across supervisor construction makes the bootstrap the source of initial
/// gateway-owned state rather than a later reconciliation input.
pub struct PreparedSupervisorSession {
    /// Configured gateway address; reconnects fall back to it.
    endpoint: String,
    /// Address this session connected to, after following any redirect.
    target: String,
    /// The session was opened by following a gateway redirect.
    redirected: bool,
    /// Epoch sent in this session's hello. Reconnects continue from it so a
    /// gateway can tell them apart from the startup attempts.
    connection_epoch: u64,
    sandbox_id: String,
    instance_id: String,
    channel: grpc_client::AuthedChannel,
    tx: mpsc::Sender<SupervisorMessage>,
    inbound: tonic::Streaming<GatewayMessage>,
    heartbeat_secs: u32,
    session_id: String,
    /// The gateway committed to authoritative streamed configuration.
    config_push_enabled: bool,
    /// The hello reported the workload as not started, so a polling gateway
    /// waits for `SupervisorRuntimeReady`.
    workload_pending: bool,
    bootstrap: Option<ConfigBootstrap>,
}

impl PreparedSupervisorSession {
    pub fn take_bootstrap(&mut self) -> Option<ConfigBootstrap> {
        self.bootstrap.take()
    }

    pub fn uses_stream_configuration(&self) -> bool {
        self.config_push_enabled
    }
}

/// Revision token the gateway correlates with a sandbox configuration result.
pub fn sandbox_config_revision(snapshot: &SettingsPollResult) -> ConfigSnapshotRevision {
    ConfigSnapshotRevision {
        component: Some(config_snapshot_revision::Component::SandboxConfig(
            SandboxConfigRevision {
                config_revision: snapshot.config_revision,
                policy_version: snapshot.version,
                policy_source: snapshot.policy_source.into(),
                global_policy_version: snapshot.global_policy_version,
                settings_revision: snapshot.settings_revision,
            },
        )),
    }
}

/// Revision token the gateway correlates with a provider environment result.
pub fn provider_config_revision(revision: u64) -> ConfigSnapshotRevision {
    ConfigSnapshotRevision {
        component: Some(config_snapshot_revision::Component::ProviderEnvironment(
            revision,
        )),
    }
}

/// Result for one configuration component. A failure is `(code, message,
/// retryable)`; the message is bounded for the wire.
pub fn config_apply_result(
    component: ConfigComponent,
    requested_revision: Option<ConfigSnapshotRevision>,
    applied_revision: Option<ConfigSnapshotRevision>,
    outcome: ConfigApplyOutcome,
    failure: Option<(&str, &str, bool)>,
) -> ConfigComponentApplyResult {
    ConfigComponentApplyResult {
        component: component.into(),
        requested_revision,
        applied_revision,
        outcome: outcome.into(),
        failure: failure.map(|(code, message, retryable)| ConfigApplyFailure {
            code: code.to_string(),
            message: message.chars().take(1024).collect(),
            retryable,
        }),
    }
}

/// Admission for a sandbox configuration snapshot. Only a gateway-admitted
/// snapshot that the runtime activated is accepted.
pub fn config_admission(
    snapshot: &SettingsPollResult,
    activated: bool,
) -> SandboxConfigurationAdmission {
    let accepted = snapshot.configuration_admitted && activated;
    SandboxConfigurationAdmission {
        instance_id: snapshot.configuration_instance_id.clone(),
        state: if accepted {
            ConfigurationAdmissionState::Accepted.into()
        } else {
            ConfigurationAdmissionState::Rejected.into()
        },
        policy_version: snapshot.version,
        policy_hash: snapshot.policy_hash.clone(),
        config_revision: snapshot.config_revision,
        provider_env_revision: snapshot.provider_env_revision,
        error: if accepted {
            String::new()
        } else if snapshot.configuration_error.is_empty() {
            "effective configuration could not be activated".to_string()
        } else {
            snapshot.configuration_error.clone()
        },
    }
}

/// Component and requested revision of a delivered snapshot.
fn snapshot_component(
    component: config_update::Component,
) -> (ConfigComponent, ConfigSnapshotRevision) {
    match component {
        config_update::Component::SandboxConfig(snapshot) => (
            ConfigComponent::SandboxConfig,
            sandbox_config_revision(&SettingsPollResult::from(snapshot)),
        ),
        config_update::Component::ProviderEnvironment(snapshot) => (
            ConfigComponent::ProviderEnvironment,
            provider_config_revision(snapshot.provider_env_revision),
        ),
    }
}

/// Result for a delivered snapshot that the runtime did not apply.
fn unapplied_result(
    component: Option<config_update::Component>,
    outcome: ConfigApplyOutcome,
    code: &str,
    message: &str,
) -> ConfigComponentApplyResult {
    let (component, requested_revision) = component.map(snapshot_component).map_or(
        (ConfigComponent::Unspecified, None),
        |(component, revision)| (component, Some(revision)),
    );
    config_apply_result(
        component,
        requested_revision,
        None,
        outcome,
        Some((code, message, false)),
    )
}

/// Bootstrap result when the runtime did not apply the bootstrap. Every
/// delivered component is answered, as for an update.
fn unapplied_bootstrap(
    bootstrap: ConfigBootstrap,
    code: &str,
    message: &str,
) -> ConfigBootstrapResult {
    let components = [
        bootstrap
            .provider_environment
            .map(config_update::Component::ProviderEnvironment),
        bootstrap
            .sandbox_config
            .map(config_update::Component::SandboxConfig),
    ];
    ConfigBootstrapResult {
        results: components
            .into_iter()
            .flatten()
            .map(|component| {
                unapplied_result(
                    Some(component),
                    ConfigApplyOutcome::Unsupported,
                    code,
                    message,
                )
            })
            .collect(),
        admission: None,
    }
}

/// Update result when the runtime did not apply the update.
fn unapplied_update(
    update: ConfigUpdate,
    outcome: ConfigApplyOutcome,
    code: &str,
    message: &str,
) -> ConfigUpdateResult {
    ConfigUpdateResult {
        update_id: update.update_id,
        component_sequence: update.component_sequence,
        result: Some(unapplied_result(update.component, outcome, code, message)),
        admission: None,
    }
}

/// Runtime identity and status channel shared with a supervisor session task.
pub struct SessionRuntimeContext {
    /// Identifies the local supervisor process across gateway reconnects.
    pub instance_id: String,
    /// Publishes the currently accepted gateway session to sibling reporters.
    pub session_id_updates: Option<watch::Sender<Option<String>>>,
    /// Applies streamed configuration updates to the running supervisor.
    pub config_apply_tx: mpsc::Sender<ConfigApplyRequest>,
}

/// Parse a gRPC endpoint URI into an OCSF `Endpoint` (host + port). Falls back
/// to treating the whole string as a domain if parsing fails.
fn ocsf_gateway_endpoint(endpoint: &str) -> Endpoint {
    let without_scheme = endpoint
        .split_once("://")
        .map_or(endpoint, |(_, rest)| rest);
    let host_and_port = without_scheme.split('/').next().unwrap_or(without_scheme);
    if let Some((host, port)) = host_and_port.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        return Endpoint::from_domain(host, port);
    }
    Endpoint::from_domain(host_and_port, 0)
}

fn session_established_event(
    ctx: &EventContext,
    endpoint: &str,
    session_id: &str,
    heartbeat_secs: u32,
) -> OcsfEvent {
    NetworkActivityBuilder::new(ctx)
        .activity(ActivityId::Open)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .dst_endpoint(ocsf_gateway_endpoint(endpoint))
        .message(format!(
            "supervisor session established (session_id={session_id}, heartbeat_secs={heartbeat_secs})"
        ))
        .build()
}

fn session_closed_event(ctx: &EventContext, endpoint: &str, sandbox_id: &str) -> OcsfEvent {
    NetworkActivityBuilder::new(ctx)
        .activity(ActivityId::Close)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .dst_endpoint(ocsf_gateway_endpoint(endpoint))
        .message(format!("supervisor session ended cleanly ({sandbox_id})"))
        .build()
}

fn session_failed_event(
    ctx: &EventContext,
    endpoint: &str,
    attempt: u64,
    error: &str,
) -> OcsfEvent {
    NetworkActivityBuilder::new(ctx)
        .activity(ActivityId::Fail)
        .severity(SeverityId::Low)
        .status(StatusId::Failure)
        .dst_endpoint(ocsf_gateway_endpoint(endpoint))
        .message(format!(
            "supervisor session failed, reconnecting (attempt {attempt}): {error}"
        ))
        .build()
}

fn relay_target_endpoint(open: &RelayOpen) -> Option<Endpoint> {
    let relay_open::Target::Tcp(target) = open.target.as_ref()? else {
        return None;
    };
    let host = target.host.trim();
    let port = u16::try_from(target.port).ok()?;
    host.parse().map_or_else(
        |_| Some(Endpoint::from_domain(host, port)),
        |ip| Some(Endpoint::from_ip(ip, port)),
    )
}

fn relay_target_kind(open: &RelayOpen) -> &'static str {
    match open.target.as_ref() {
        Some(relay_open::Target::Tcp(_)) => "tcp relay",
        Some(relay_open::Target::Ssh(_)) | None => "ssh relay",
    }
}

fn relay_target_message(
    open: &RelayOpen,
    state: &str,
    ssh_socket_path: &std::path::Path,
) -> String {
    let target = match open.target.as_ref() {
        Some(relay_open::Target::Tcp(target)) => {
            format!("{}:{}", target.host.trim(), target.port)
        }
        Some(relay_open::Target::Ssh(_)) | None => {
            format!("unix:{}", ssh_socket_path.display())
        }
    };

    format!(
        "{} {state} (channel_id={}, target={target})",
        relay_target_kind(open),
        open.channel_id
    )
}

fn relay_open_event(
    ctx: &EventContext,
    open: &RelayOpen,
    ssh_socket_path: &std::path::Path,
) -> OcsfEvent {
    let message = relay_target_message(open, "open", ssh_socket_path);
    let Some(endpoint) = relay_target_endpoint(open) else {
        return BaseEventBuilder::new(ctx)
            .activity_name("Relay open")
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .message(message)
            .build();
    };
    NetworkActivityBuilder::new(ctx)
        .activity(ActivityId::Open)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .message(message)
        .dst_endpoint(endpoint)
        .connection_info(ConnectionInfo::new("tcp"))
        .build()
}

fn relay_closed_event(
    ctx: &EventContext,
    open: &RelayOpen,
    ssh_socket_path: &std::path::Path,
) -> OcsfEvent {
    let message = relay_target_message(open, "closed", ssh_socket_path);
    let Some(endpoint) = relay_target_endpoint(open) else {
        return BaseEventBuilder::new(ctx)
            .activity_name("Relay closed")
            .severity(SeverityId::Informational)
            .status(StatusId::Success)
            .message(message)
            .build();
    };
    NetworkActivityBuilder::new(ctx)
        .activity(ActivityId::Close)
        .severity(SeverityId::Informational)
        .status(StatusId::Success)
        .message(message)
        .dst_endpoint(endpoint)
        .connection_info(ConnectionInfo::new("tcp"))
        .build()
}

fn relay_failed_event(
    ctx: &EventContext,
    open: &RelayOpen,
    ssh_socket_path: &std::path::Path,
    error: &str,
) -> OcsfEvent {
    let message = format!(
        "{}: {error}",
        relay_target_message(open, "bridge failed", ssh_socket_path)
    );
    let Some(endpoint) = relay_target_endpoint(open) else {
        return BaseEventBuilder::new(ctx)
            .activity_name("Relay failed")
            .severity(SeverityId::Low)
            .status(StatusId::Failure)
            .message(message)
            .build();
    };
    NetworkActivityBuilder::new(ctx)
        .activity(ActivityId::Fail)
        .severity(SeverityId::Low)
        .status(StatusId::Failure)
        .message(message)
        .dst_endpoint(endpoint)
        .connection_info(ConnectionInfo::new("tcp"))
        .build()
}

fn relay_close_from_gateway_event(ctx: &EventContext, channel_id: &str, reason: &str) -> OcsfEvent {
    BaseEventBuilder::new(ctx)
        .activity_name("Relay close from gateway")
        .severity(SeverityId::Informational)
        .message(format!(
            "relay close from gateway (channel_id={channel_id}, reason={reason})"
        ))
        .build()
}

/// Size of chunks read from the local SSH socket when forwarding bytes back
/// to the gateway over the gRPC response stream. 16 KiB matches the default
/// HTTP/2 frame size so each `RelayFrame::data` fits in one frame.
const RELAY_CHUNK_SIZE: usize = 16 * 1024;

trait TargetStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> TargetStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

fn map_stream_message<T>(
    message: Result<Option<T>, tonic::Status>,
    eof_error: &'static str,
) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
    match message {
        Ok(Some(msg)) => Ok(msg),
        Ok(None) => Err(eof_error.into()),
        Err(e) => Err(format!("stream error: {e}").into()),
    }
}

#[derive(Debug)]
enum SessionStreamMessage<T> {
    Message(T),
    ExpectedShutdownClose,
}

fn supervisor_is_terminating(terminating: &AtomicBool) -> bool {
    terminating.load(Ordering::Acquire)
}

fn expected_transport_close_during_shutdown(
    status: &tonic::Status,
    terminating: &AtomicBool,
) -> bool {
    supervisor_is_terminating(terminating) && is_expected_transport_close_status(status)
}

fn map_session_stream_message<T>(
    message: Result<Option<T>, tonic::Status>,
    eof_error: &'static str,
    terminating: &AtomicBool,
) -> Result<SessionStreamMessage<T>, Box<dyn std::error::Error + Send + Sync>> {
    match message {
        Ok(Some(msg)) => Ok(SessionStreamMessage::Message(msg)),
        Ok(None) if supervisor_is_terminating(terminating) => {
            debug!("supervisor session: stream closed during local shutdown");
            Ok(SessionStreamMessage::ExpectedShutdownClose)
        }
        Ok(None) => Err(eof_error.into()),
        Err(e) if expected_transport_close_during_shutdown(&e, terminating) => {
            debug!(
                error = %e,
                "supervisor session: expected transport close during local shutdown"
            );
            Ok(SessionStreamMessage::ExpectedShutdownClose)
        }
        Err(e) => Err(format!("stream error: {e}").into()),
    }
}

/// Spawn the supervisor session task.
///
/// The task runs for the lifetime of the sandbox process, reconnecting with
/// exponential backoff on failures.
#[allow(clippy::too_many_arguments)]
pub fn spawn(
    endpoint: String,
    sandbox_id: String,
    ssh_socket_path: std::path::PathBuf,
    port_forward: Arc<dyn BoundaryLoopbackConnector>,
    expected_ssh_peer_pid: Option<u32>,
    terminating: Arc<AtomicBool>,
    runtime: SessionRuntimeContext,
) -> tokio::task::JoinHandle<()> {
    spawn_with_readiness(
        endpoint,
        sandbox_id,
        ssh_socket_path,
        port_forward,
        expected_ssh_peer_pid,
        terminating,
        runtime,
    )
    .0
}

/// Spawn the supervisor session and expose when the gateway has accepted it.
pub fn spawn_with_readiness(
    endpoint: String,
    sandbox_id: String,
    ssh_socket_path: std::path::PathBuf,
    port_forward: Arc<dyn BoundaryLoopbackConnector>,
    expected_ssh_peer_pid: Option<u32>,
    terminating: Arc<AtomicBool>,
    runtime: SessionRuntimeContext,
) -> (tokio::task::JoinHandle<()>, watch::Receiver<bool>) {
    let (ready_tx, ready_rx) = watch::channel(false);
    let config = SessionConfig {
        endpoint,
        sandbox_id,
        ssh_socket_path,
        port_forward,
        expected_ssh_peer_pid,
        terminating,
        instance_id: runtime.instance_id,
        session_id_updates: runtime.session_id_updates,
        config_apply_tx: runtime.config_apply_tx,
        ready_tx,
        runtime_ready: Arc::new(AtomicBool::new(true)),
        config_push_updates: None,
    };
    (tokio::spawn(run_session_loop(config, None)), ready_rx)
}

/// Establish the control stream and, when the gateway applies configuration
/// over the stream, receive the required bootstrap before gateway-owned runtime
/// initialization begins.
pub async fn prepare(
    endpoint: String,
    sandbox_id: String,
    instance_id: String,
    image_policy_discovery: ImagePolicyDiscovery,
    prepare_policy: impl FnOnce(SandboxPolicy) -> Result<Option<SandboxPolicy>, String> + Send + 'static,
) -> Result<PreparedSupervisorSession, Box<dyn std::error::Error + Send + Sync>> {
    let prepared = tokio::time::timeout(SESSION_PREPARE_TIMEOUT, async {
        let mut prepare_policy: Option<StartupPolicyPreparer> = Some(Box::new(prepare_policy));
        let mut backoff = ReconnectBackoff::new();
        let mut connection_epoch = 1;
        // Follow gateway redirects as `run_session_loop` does.
        let mut target = endpoint.clone();
        let mut redirected = false;
        loop {
            match open_session(
                endpoint.clone(),
                target.clone(),
                redirected,
                sandbox_id.clone(),
                instance_id.clone(),
                connection_epoch,
                true,
                Some(image_policy_discovery.clone()),
                prepare_policy.take(),
            )
            .await
            {
                Ok(OpenedSession::Accepted(prepared)) => return Ok(*prepared),
                Ok(OpenedSession::Redirect {
                    peer_endpoint,
                    owner_replica_id,
                    preparer,
                }) => {
                    info!(
                        sandbox_id = %sandbox_id,
                        owner_replica_id = %owner_replica_id,
                        peer_endpoint = %peer_endpoint,
                        "supervisor session: following gateway redirect during startup"
                    );
                    prepare_policy = preparer;
                    connection_epoch += 1;
                    target = peer_endpoint;
                    redirected = true;
                    // No backoff: this is an expected handoff, not a failure.
                }
                // Retry only failures before the gateway saw this hello, so
                // the startup preparer is still unused.
                Err(OpenSessionError::Connect(error, preparer)) => {
                    warn!(error = %error, "supervisor session: startup connection failed; retrying");
                    prepare_policy = preparer;
                    connection_epoch += 1;
                    // No session was accepted, so a redirected attempt keeps
                    // asking the configured gateway to serve it locally.
                    let failed_redirect_target = target != endpoint;
                    target.clone_from(&endpoint);
                    if let Some(delay) = backoff.on_failure(false, failed_redirect_target) {
                        tokio::time::sleep(delay).await;
                    }
                }
                Err(OpenSessionError::Session(error)) => return Err(error),
            }
        }
    })
    .await
    .map_err(|_| "timed out waiting for supervisor session bootstrap")??;
    if prepared.config_push_enabled && prepared.bootstrap.is_none() {
        return Err("gateway enabled config push without a bootstrap".into());
    }
    Ok(prepared)
}

/// Resume a prepared startup session after the supervisor runtime and relay
/// endpoints are ready.
#[allow(clippy::too_many_arguments)]
pub fn spawn_prepared(
    prepared: PreparedSupervisorSession,
    bootstrap_result: Option<ConfigBootstrapResult>,
    ssh_socket_path: std::path::PathBuf,
    port_forward: Arc<dyn BoundaryLoopbackConnector>,
    expected_ssh_peer_pid: Option<u32>,
    terminating: Arc<AtomicBool>,
    config_apply_tx: mpsc::Sender<ConfigApplyRequest>,
    session_id_updates: Option<watch::Sender<Option<String>>>,
    config_push_updates: watch::Sender<bool>,
) -> (
    tokio::task::JoinHandle<()>,
    watch::Receiver<bool>,
    mpsc::Sender<SupervisorMessage>,
    Arc<AtomicBool>,
) {
    let (ready_tx, ready_rx) = watch::channel(false);
    let outbound = prepared.tx.clone();
    let runtime_ready = Arc::new(AtomicBool::new(false));
    let config = SessionConfig {
        endpoint: prepared.endpoint.clone(),
        sandbox_id: prepared.sandbox_id.clone(),
        ssh_socket_path,
        port_forward,
        expected_ssh_peer_pid,
        terminating,
        instance_id: prepared.instance_id.clone(),
        config_apply_tx,
        session_id_updates,
        ready_tx,
        runtime_ready: runtime_ready.clone(),
        config_push_updates: Some(config_push_updates),
    };
    let task = tokio::spawn(run_session_loop(config, Some((prepared, bootstrap_result))));
    (task, ready_rx, outbound, runtime_ready)
}

struct SessionConfig {
    endpoint: String,
    sandbox_id: String,
    ssh_socket_path: std::path::PathBuf,
    port_forward: Arc<dyn BoundaryLoopbackConnector>,
    expected_ssh_peer_pid: Option<u32>,
    terminating: Arc<AtomicBool>,
    instance_id: String,
    config_apply_tx: mpsc::Sender<ConfigApplyRequest>,
    /// Publishes the currently accepted session to sibling control-plane reporters.
    session_id_updates: Option<watch::Sender<Option<String>>>,
    ready_tx: watch::Sender<bool>,
    runtime_ready: Arc<AtomicBool>,
    /// Publishes whether the current session delivers configuration
    /// authoritatively, so a stream-started runtime resumes polling when a
    /// reconnect lands on a gateway that does not enable config push.
    config_push_updates: Option<watch::Sender<bool>>,
}

async fn run_session_loop(
    config: SessionConfig,
    mut prepared: Option<(PreparedSupervisorSession, Option<ConfigBootstrapResult>)>,
) {
    let mut backoff = ReconnectBackoff::new();
    // A prepared session already used the startup epochs; continue after them
    // so a reconnect can supersede the session it replaces.
    let mut attempt: u64 = prepared
        .as_ref()
        .map_or(0, |(session, _)| session.connection_epoch.saturating_sub(1));

    // The gateway may hand this sandbox to the replica that should own it. We
    // dial `target` for the next attempt and mark it as redirected so that
    // replica serves us rather than redirecting again. Any failure sends us
    // back to the configured address, which load-balances across replicas.
    let mut target = prepared.as_ref().map_or_else(
        || config.endpoint.clone(),
        |(session, _)| session.target.clone(),
    );
    let mut redirected = prepared
        .as_ref()
        .is_some_and(|(session, _)| session.redirected);

    loop {
        attempt += 1;

        let result = if let Some((session, bootstrap_result)) = prepared.take() {
            run_prepared_session(&config, session, bootstrap_result).await
        } else {
            run_single_session(&config, &target, redirected, attempt).await
        };
        if let Some(updates) = &config.session_id_updates {
            updates.send_replace(None);
        }
        match result {
            Ok(SessionOutcome::Closed) => {
                config.ready_tx.send_replace(false);
                let event =
                    session_closed_event(openshell_ocsf::ctx::ctx(), &target, &config.sandbox_id);
                ocsf_emit!(event);
                break;
            }
            Ok(SessionOutcome::Redirect {
                peer_endpoint,
                owner_replica_id,
            }) => {
                backoff.on_redirect(config.ready_tx.send_replace(false));
                info!(
                    sandbox_id = %config.sandbox_id,
                    owner_replica_id = %owner_replica_id,
                    peer_endpoint = %peer_endpoint,
                    "supervisor session: following gateway redirect"
                );
                target = peer_endpoint;
                redirected = true;
                // No backoff: this is an expected handoff, not a failure.
            }
            Err(e) => {
                let accepted = config.ready_tx.send_replace(false);
                let event = session_failed_event(
                    openshell_ocsf::ctx::ctx(),
                    &target,
                    attempt,
                    &e.to_string(),
                );
                ocsf_emit!(event);
                // Fall back to the configured gateway address so a redirect
                // to a replica that is going away cannot strand the sandbox.
                let failed_redirect_target = target != config.endpoint && !accepted;
                target.clone_from(&config.endpoint);
                redirected = redirect_survives_failure(redirected, accepted);
                if let Some(delay) = backoff.on_failure(accepted, failed_redirect_target) {
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
}

/// Reconnect delays for the supervisor session loop.
///
/// Delays double up to [`MAX_BACKOFF`] while reconnects keep failing. A session
/// the gateway accepted proves the path works again, so its loss starts the
/// delays over. Without that reset, every gateway restart over the sandbox's
/// lifetime would compound until each reconnect waited the full maximum.
#[derive(Debug)]
struct ReconnectBackoff {
    delay: Duration,
    skipped_since_accept: bool,
}

impl ReconnectBackoff {
    fn new() -> Self {
        Self {
            delay: INITIAL_BACKOFF,
            skipped_since_accept: false,
        }
    }

    /// Record a gateway redirect. Following it is an expected handoff, so the
    /// supervisor reconnects without waiting.
    fn on_redirect(&mut self, accepted: bool) {
        if accepted {
            *self = Self::new();
        }
    }

    /// Record a failed or dropped session and return how long to wait before
    /// the next attempt, or `None` to reconnect at once.
    fn on_failure(&mut self, accepted: bool, failed_redirect_target: bool) -> Option<Duration> {
        if accepted {
            *self = Self::new();
        }
        if skip_backoff(failed_redirect_target, self.skipped_since_accept) {
            self.skipped_since_accept = true;
            return None;
        }
        let delay = self.delay;
        self.delay = (self.delay * 2).min(MAX_BACKOFF);
        Some(delay)
    }
}

/// Keep asking not to be redirected when a redirected attempt never got a
/// session, so a stale ring pointing at a dead replica cannot bounce us back
/// to it. A session that was accepted and later dropped starts placement over.
fn redirect_survives_failure(redirected: bool, accepted: bool) -> bool {
    redirected && !accepted
}

/// A failed redirect target goes straight back to the configured endpoint, but
/// only once until a session is accepted, so a draining gateway and a dead
/// target cannot bounce the supervisor without backing off.
fn skip_backoff(failed_redirect_target: bool, skipped_since_accept: bool) -> bool {
    failed_redirect_target && !skipped_since_accept
}

/// How a session ended, when it ended without an error.
enum SessionOutcome {
    /// The gateway closed the session normally.
    Closed,
    /// The gateway declined to own this sandbox and named the replica that
    /// should. The caller reconnects there once.
    Redirect {
        peer_endpoint: String,
        owner_replica_id: String,
    },
}

/// Result of opening a session that the gateway answered.
enum OpenedSession {
    Accepted(Box<PreparedSupervisorSession>),
    /// The gateway declined to own this sandbox before startup preparation,
    /// so the preparer is returned unused.
    Redirect {
        peer_endpoint: String,
        owner_replica_id: String,
        preparer: Option<StartupPolicyPreparer>,
    },
}

async fn run_single_session(
    config: &SessionConfig,
    target: &str,
    redirected: bool,
    connection_epoch: u64,
) -> Result<SessionOutcome, Box<dyn std::error::Error + Send + Sync>> {
    let opened = open_session(
        config.endpoint.clone(),
        target.to_string(),
        redirected,
        config.sandbox_id.clone(),
        config.instance_id.clone(),
        connection_epoch,
        !config.runtime_ready.load(Ordering::Acquire),
        None,
        None,
    )
    .await
    .map_err(OpenSessionError::into_error)?;
    match opened {
        OpenedSession::Accepted(prepared) => run_prepared_session(config, *prepared, None).await,
        OpenedSession::Redirect {
            peer_endpoint,
            owner_replica_id,
            ..
        } => Ok(SessionOutcome::Redirect {
            peer_endpoint,
            owner_replica_id,
        }),
    }
}

type SessionError = Box<dyn std::error::Error + Send + Sync>;

enum OpenSessionError {
    /// The gateway never received the hello; the preparer is returned unused.
    Connect(SessionError, Option<StartupPolicyPreparer>),
    Session(SessionError),
}

impl OpenSessionError {
    fn into_error(self) -> SessionError {
        match self {
            Self::Connect(error, _) | Self::Session(error) => error,
        }
    }
}

impl From<SessionError> for OpenSessionError {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
    }
}

impl From<&'static str> for OpenSessionError {
    fn from(error: &'static str) -> Self {
        Self::Session(error.into())
    }
}

impl From<String> for OpenSessionError {
    fn from(error: String) -> Self {
        Self::Session(error.into())
    }
}

#[allow(clippy::too_many_arguments)]
async fn open_session(
    endpoint: String,
    target: String,
    redirected: bool,
    sandbox_id: String,
    instance_id: String,
    connection_epoch: u64,
    workload_pending: bool,
    image_policy_discovery: Option<ImagePolicyDiscovery>,
    mut prepare_policy: Option<StartupPolicyPreparer>,
) -> Result<OpenedSession, OpenSessionError> {
    // The same authenticated channel carries the long-lived control stream
    // and all data-plane RelayStream calls, so every relay rides the same
    // TCP+TLS+HTTP/2 connection with no new TLS handshake per relay.
    let channel = match grpc_client::connect_channel_pub(&target).await {
        Ok(channel) => channel,
        Err(e) => {
            return Err(OpenSessionError::Connect(
                format!("connect failed: {e}").into(),
                prepare_policy,
            ));
        }
    };
    let mut client = OpenShellClient::new(channel.clone());

    // Create the outbound message stream.
    let (tx, rx) = mpsc::channel::<SupervisorMessage>(64);
    let outbound = tokio_stream::wrappers::ReceiverStream::new(rx);

    // Send hello as the first message.
    tx.send(SupervisorMessage {
        payload: Some(supervisor_message::Payload::Hello(SupervisorHello {
            sandbox_id: sandbox_id.clone(),
            instance_id: instance_id.clone(),
            supports_config_push: true,
            workload_pending,
            connection_epoch,
            image_policy_discovery,
            supports_provider_readiness: true,
            redirected,
            supports_session_redirect: true,
        })),
    })
    .await
    .map_err(|_| "failed to queue hello")?;

    // Open the bidirectional stream. An unavailable gateway rejects the call
    // before it reads the hello, so the preparer is still unused.
    let response = match client.connect_supervisor(outbound).await {
        Ok(response) => response,
        Err(e) if e.code() == tonic::Code::Unavailable => {
            return Err(OpenSessionError::Connect(
                format!("connect_supervisor RPC failed: {e}").into(),
                prepare_policy,
            ));
        }
        Err(e) => return Err(format!("connect_supervisor RPC failed: {e}").into()),
    };
    let mut inbound = response.into_inner();

    // The gateway may ask the initial supervisor to prepare its selected
    // policy against the local image before it sends the authoritative
    // bootstrap. Reconnects do not repeat this startup-only exchange.
    let accepted = loop {
        match map_stream_message(
            inbound.message().await,
            "stream closed before session accepted",
        )?
        .payload
        {
            Some(gateway_message::Payload::StartupConfigCandidate(candidate)) => {
                let preparer = prepare_policy
                    .take()
                    .ok_or("gateway requested startup preparation on a reconnect")?;
                let result = candidate.policy.map_or_else(
                    || {
                        startup_config_prepared::Result::Failure(ConfigApplyFailure {
                            code: "startup_policy_candidate_missing".to_string(),
                            message: "gateway startup candidate omitted its policy".to_string(),
                            retryable: false,
                        })
                    },
                    |policy| match preparer(policy) {
                        Ok(Some(policy)) => startup_config_prepared::Result::PreparedPolicy(policy),
                        Ok(None) => startup_config_prepared::Result::Unchanged(()),
                        Err(message) => {
                            startup_config_prepared::Result::Failure(ConfigApplyFailure {
                                code: "startup_policy_preparation_failed".to_string(),
                                message: message.chars().take(1024).collect(),
                                retryable: false,
                            })
                        }
                    },
                );
                tx.send(SupervisorMessage {
                    payload: Some(supervisor_message::Payload::StartupConfigPrepared(
                        StartupConfigPrepared {
                            candidate_id: candidate.candidate_id,
                            result: Some(result),
                        },
                    )),
                })
                .await
                .map_err(|_| "failed to send startup configuration result")?;
            }
            Some(gateway_message::Payload::SessionAccepted(accepted)) => break accepted,
            Some(gateway_message::Payload::SessionRejected(rejected)) => {
                return Err(format!("session rejected: {}", rejected.reason).into());
            }
            Some(gateway_message::Payload::SessionRedirect(redirect)) => {
                return Ok(OpenedSession::Redirect {
                    peer_endpoint: redirect.peer_endpoint,
                    owner_replica_id: redirect.owner_replica_id,
                    preparer: prepare_policy,
                });
            }
            _ => {
                return Err(
                    "expected StartupConfigCandidate, SessionAccepted, or SessionRejected".into(),
                );
            }
        }
    };

    let heartbeat_secs = accepted
        .heartbeat_interval
        .as_ref()
        .and_then(|value| openshell_core::time::duration_to_std(value).ok())
        .map_or(5, |value| value.as_secs().max(5));
    let heartbeat_secs = u32::try_from(heartbeat_secs).unwrap_or(u32::MAX);
    if !accepted.config_push_enabled {
        debug!(
            sandbox_id = %sandbox_id,
            session_id = %accepted.session_id,
            "supervisor session: gateway did not enable streamed configuration; polling remains active"
        );
    }
    let event = session_established_event(
        openshell_ocsf::ctx::ctx(),
        &target,
        &accepted.session_id,
        heartbeat_secs,
    );
    ocsf_emit!(event);

    let config_push_enabled = accepted.config_push_enabled;
    Ok(OpenedSession::Accepted(Box::new(
        PreparedSupervisorSession {
            endpoint,
            target,
            redirected,
            connection_epoch,
            sandbox_id,
            instance_id,
            channel,
            tx,
            inbound,
            heartbeat_secs,
            session_id: accepted.session_id,
            config_push_enabled,
            workload_pending,
            bootstrap: config_push_enabled.then_some(accepted.bootstrap).flatten(),
        },
    )))
}

async fn run_prepared_session(
    config: &SessionConfig,
    mut prepared: PreparedSupervisorSession,
    startup_result: Option<ConfigBootstrapResult>,
) -> Result<SessionOutcome, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(updates) = &config.session_id_updates {
        updates.send_replace(Some(prepared.session_id.clone()));
    }
    let heartbeat_secs = prepared.heartbeat_secs;
    // Polling stays authoritative on a session without config push.
    let config_apply_tx = prepared
        .config_push_enabled
        .then_some(&config.config_apply_tx);
    let channel = prepared.channel;
    let tx = prepared.tx;
    let mut inbound = prepared.inbound;

    if let Some(result) = startup_result {
        tx.send(SupervisorMessage {
            payload: Some(supervisor_message::Payload::ConfigBootstrapResult(result)),
        })
        .await
        .map_err(|_| "failed to queue configuration bootstrap result")?;
    } else if let Some(bootstrap) = prepared.bootstrap.take() {
        let result = apply_bootstrap(&config.config_apply_tx, bootstrap).await;
        tx.send(SupervisorMessage {
            payload: Some(supervisor_message::Payload::ConfigBootstrapResult(result)),
        })
        .await
        .map_err(|_| "failed to queue configuration bootstrap result")?;
    }
    if let Some(updates) = &config.config_push_updates {
        updates.send_replace(prepared.config_push_enabled);
    }
    if !prepared.config_push_enabled {
        config.ready_tx.send_replace(true);
        // Without streamed admission the gateway learns readiness only from
        // this report. A hello that reported the workload running was already
        // ready on accept; one sent while it was pending needs the report if
        // the workload started before the session was accepted.
        if prepared.workload_pending && config.runtime_ready.load(Ordering::Acquire) {
            tx.send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::RuntimeReady(
                    openshell_core::proto::SupervisorRuntimeReady {},
                )),
            })
            .await
            .map_err(|_| "failed to queue runtime readiness")?;
        }
    }

    // Main loop: receive gateway messages + send heartbeats.
    let mut heartbeat_interval =
        tokio::time::interval(Duration::from_secs(u64::from(heartbeat_secs)));
    heartbeat_interval.tick().await; // skip immediate tick

    loop {
        tokio::select! {
            msg = inbound.message() => {
                let msg = match map_session_stream_message(
                    msg,
                    "gateway closed stream",
                    &config.terminating,
                )? {
                    SessionStreamMessage::Message(msg) => msg,
                    SessionStreamMessage::ExpectedShutdownClose => {
                        return Ok(SessionOutcome::Closed);
                    }
                };
                if let Some(gateway_message::Payload::SessionRedirect(r)) = &msg.payload {
                    if supervisor_is_terminating(&config.terminating) {
                        return Ok(SessionOutcome::Closed);
                    }
                    return Ok(SessionOutcome::Redirect {
                        peer_endpoint: r.peer_endpoint.clone(),
                        owner_replica_id: r.owner_replica_id.clone(),
                    });
                }
                let context = GatewayMessageContext {
                    sandbox_id: &config.sandbox_id,
                    ssh_socket_path: &config.ssh_socket_path,
                    port_forward: &config.port_forward,
                    expected_ssh_peer_pid: config.expected_ssh_peer_pid,
                    channel: &channel,
                    tx: &tx,
                    terminating: &config.terminating,
                    config_apply_tx,
                    ready_tx: &config.ready_tx,
                    runtime_ready: &config.runtime_ready,
                };
                handle_gateway_message(
                    &msg,
                    &context,
                );
            }
            _ = heartbeat_interval.tick() => {
                let hb = SupervisorMessage {
                    payload: Some(supervisor_message::Payload::Heartbeat(
                        SupervisorHeartbeat {},
                    )),
                };
                if tx.send(hb).await.is_err() {
                    return Err("outbound channel closed".into());
                }
            }
        }
    }
}

/// Hand one delivered payload to the supervisor runtime and wait for its
/// result. Failures return the code and message for an unapplied result.
async fn request_apply<T>(
    apply_tx: &mpsc::Sender<ConfigApplyRequest>,
    request: impl FnOnce(tokio::sync::oneshot::Sender<T>) -> ConfigApplyRequest,
) -> Result<T, (&'static str, &'static str)> {
    let (response, receiver) = tokio::sync::oneshot::channel();
    if apply_tx.send(request(response)).await.is_err() {
        return Err((
            "apply_unavailable",
            "configuration apply service is unavailable",
        ));
    }
    match tokio::time::timeout(CONFIG_APPLY_TIMEOUT, receiver).await {
        Ok(Ok(result)) => Ok(result),
        _ => Err(("apply_timeout", "configuration application timed out")),
    }
}

async fn apply_bootstrap(
    apply_tx: &mpsc::Sender<ConfigApplyRequest>,
    bootstrap: ConfigBootstrap,
) -> ConfigBootstrapResult {
    let unapplied = bootstrap.clone();
    request_apply(apply_tx, |response| ConfigApplyRequest::Bootstrap {
        bootstrap,
        response,
    })
    .await
    .unwrap_or_else(|(code, message)| unapplied_bootstrap(unapplied, code, message))
}

async fn apply_update(
    apply_tx: &mpsc::Sender<ConfigApplyRequest>,
    update: ConfigUpdate,
) -> ConfigUpdateResult {
    let unapplied = update.clone();
    request_apply(apply_tx, |response| ConfigApplyRequest::Update {
        update,
        response,
    })
    .await
    .unwrap_or_else(|(code, message)| {
        unapplied_update(unapplied, ConfigApplyOutcome::Unsupported, code, message)
    })
}

/// Report the canonical process result and wait for durable handling.
pub async fn report_main_process_exit(
    endpoint: &str,
    sandbox_id: &str,
    instance_id: &str,
    exit_code: i32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let channel = grpc_client::connect_channel_pub(endpoint)
        .await
        .map_err(|error| format!("connect failed: {error}"))?;
    let mut client = OpenShellClient::new(channel);
    client
        .report_main_process_exit(ReportMainProcessExitRequest {
            sandbox_id: sandbox_id.to_string(),
            instance_id: instance_id.to_string(),
            exit_code,
        })
        .await?;
    Ok(())
}

#[cfg(test)]
pub(crate) async fn test_bridge_ssh_relay(
    target: tokio::net::UnixStream,
    inbound: mpsc::Receiver<Result<RelayFrame, tonic::Status>>,
    out_tx: mpsc::Sender<RelayFrame>,
) {
    let _ = bridge_relay(
        Box::new(target),
        tokio_stream::wrappers::ReceiverStream::new(inbound),
        out_tx,
        "half-open-test".into(),
        Arc::new(AtomicBool::new(false)),
    )
    .await;
}

/// Confirm terminal delivery and permit ephemeral cleanup.
pub async fn finalize_main_process_exit(
    endpoint: &str,
    sandbox_id: &str,
    instance_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let channel = grpc_client::connect_channel_pub(endpoint)
        .await
        .map_err(|error| format!("connect failed: {error}"))?;
    let mut client = OpenShellClient::new(channel);
    client
        .finalize_main_process_exit(FinalizeMainProcessExitRequest {
            sandbox_id: sandbox_id.to_string(),
            instance_id: instance_id.to_string(),
        })
        .await?;
    Ok(())
}

struct GatewayMessageContext<'a> {
    sandbox_id: &'a str,
    ssh_socket_path: &'a std::path::Path,
    port_forward: &'a Arc<dyn BoundaryLoopbackConnector>,
    expected_ssh_peer_pid: Option<u32>,
    channel: &'a grpc_client::AuthedChannel,
    tx: &'a mpsc::Sender<SupervisorMessage>,
    terminating: &'a Arc<AtomicBool>,
    config_apply_tx: Option<&'a mpsc::Sender<ConfigApplyRequest>>,
    ready_tx: &'a watch::Sender<bool>,
    runtime_ready: &'a Arc<AtomicBool>,
}

fn update_session_readiness(accepted: bool, ready_tx: &watch::Sender<bool>) {
    if accepted {
        ready_tx.send_replace(true);
    }
}

fn handle_gateway_message(msg: &GatewayMessage, context: &GatewayMessageContext<'_>) {
    match &msg.payload {
        Some(gateway_message::Payload::Heartbeat(_)) => {
            // Gateway heartbeat — nothing to do.
        }
        Some(gateway_message::Payload::ConfigurationAdmission(admission)) => {
            let accepted = admission.state == i32::from(ConfigurationAdmissionState::Accepted);
            update_session_readiness(accepted, context.ready_tx);
            if accepted && context.runtime_ready.load(Ordering::Acquire) {
                let tx = context.tx.clone();
                tokio::spawn(async move {
                    let _ = tx
                        .send(SupervisorMessage {
                            payload: Some(supervisor_message::Payload::RuntimeReady(
                                openshell_core::proto::SupervisorRuntimeReady {},
                            )),
                        })
                        .await;
                });
            }
        }
        Some(gateway_message::Payload::ConfigUpdate(update)) => {
            let Some(apply_tx) = context.config_apply_tx.cloned() else {
                warn!(
                    sandbox_id = %context.sandbox_id,
                    "supervisor session: ignored configuration update on a session without config push"
                );
                return;
            };
            let update = update.clone();
            let tx = context.tx.clone();
            let sandbox_id = context.sandbox_id.to_string();
            let invalid_update = update.update_id.is_empty()
                || update.component_sequence == 0
                || update.component.is_none();
            tokio::spawn(async move {
                let result = if invalid_update {
                    unapplied_update(
                        update,
                        ConfigApplyOutcome::Unsupported,
                        "invalid_update",
                        "configuration update identity, sequence, and component are required",
                    )
                } else {
                    apply_update(&apply_tx, update).await
                };
                if tx
                    .send(SupervisorMessage {
                        payload: Some(supervisor_message::Payload::ConfigUpdateResult(result)),
                    })
                    .await
                    .is_err()
                {
                    debug!(
                        sandbox_id,
                        "configuration result dropped after session close"
                    );
                }
            });
        }
        Some(gateway_message::Payload::RelayOpen(open)) => {
            let channel_id = open.channel_id.clone();
            let relay_open = open.clone();
            let sandbox_id = context.sandbox_id.to_string();
            let channel = context.channel.clone();
            let ssh_socket_path = context.ssh_socket_path.to_path_buf();
            let tx = context.tx.clone();
            let port_forward = context.port_forward.clone();
            let expected_ssh_peer_pid = context.expected_ssh_peer_pid;
            let terminating = Arc::clone(context.terminating);

            let event = relay_open_event(openshell_ocsf::ctx::ctx(), &relay_open, &ssh_socket_path);
            ocsf_emit!(event);

            tokio::spawn(async move {
                let event_open = relay_open.clone();
                match handle_relay_open(
                    relay_open,
                    &ssh_socket_path,
                    port_forward,
                    expected_ssh_peer_pid,
                    channel,
                    tx,
                    terminating,
                )
                .await
                {
                    Ok(()) => {
                        let event = relay_closed_event(
                            openshell_ocsf::ctx::ctx(),
                            &event_open,
                            &ssh_socket_path,
                        );
                        ocsf_emit!(event);
                    }
                    Err(e) => {
                        let event = relay_failed_event(
                            openshell_ocsf::ctx::ctx(),
                            &event_open,
                            &ssh_socket_path,
                            &e.to_string(),
                        );
                        ocsf_emit!(event);
                        warn!(
                            sandbox_id = %sandbox_id,
                            channel_id = %channel_id,
                            error = %e,
                            "supervisor session: relay bridge failed"
                        );
                    }
                }
            });
        }
        Some(gateway_message::Payload::RelayClose(close)) => {
            let event = relay_close_from_gateway_event(
                openshell_ocsf::ctx::ctx(),
                &close.channel_id,
                &close.reason,
            );
            ocsf_emit!(event);
        }
        _ => {
            warn!(sandbox_id = %context.sandbox_id, "supervisor session: unexpected gateway message");
        }
    }
}

/// Handle a `RelayOpen` by initiating a `RelayStream` RPC on the gateway and
/// bridging that stream to the local SSH daemon.
///
/// This opens a new HTTP/2 stream on the existing `Channel` — no new TCP or
/// TLS handshake. The first `RelayFrame` we send is a `RelayInit`; subsequent
/// frames carry raw SSH bytes in `data`.
async fn handle_relay_open(
    relay_open: RelayOpen,
    ssh_socket_path: &std::path::Path,
    port_forward: Arc<dyn BoundaryLoopbackConnector>,
    expected_ssh_peer_pid: Option<u32>,
    channel: grpc_client::AuthedChannel,
    tx: mpsc::Sender<SupervisorMessage>,
    terminating: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let channel_id = relay_open.channel_id.clone();
    let target = match open_target(
        &relay_open,
        ssh_socket_path,
        &port_forward,
        expected_ssh_peer_pid,
    )
    .await
    {
        Ok(target) => target,
        Err(err) => {
            send_relay_open_result(&tx, &channel_id, false, err.to_string()).await;
            return Err(err);
        }
    };

    send_relay_open_result(&tx, &channel_id, true, String::new()).await;

    let mut client = OpenShellClient::new(channel);

    // Outbound chunks to the gateway.
    let (out_tx, out_rx) = mpsc::channel::<RelayFrame>(16);
    let outbound = tokio_stream::wrappers::ReceiverStream::new(out_rx);

    // First frame: identify the channel.
    out_tx
        .send(RelayFrame {
            payload: Some(openshell_core::proto::relay_frame::Payload::Init(
                RelayInit {
                    channel_id: channel_id.clone(),
                },
            )),
        })
        .await
        .map_err(|_| "outbound channel closed before init")?;

    // Initiate the RPC. This rides the existing HTTP/2 connection.
    let response = match client.relay_stream(outbound).await {
        Ok(response) => response,
        Err(e) if expected_transport_close_during_shutdown(&e, &terminating) => {
            debug!(
                channel_id = %channel_id,
                error = %e,
                "relay bridge: relay_stream RPC closed during local shutdown"
            );
            return Ok(());
        }
        Err(e) => return Err(format!("relay_stream RPC failed: {e}").into()),
    };
    bridge_relay(
        target,
        response.into_inner(),
        out_tx,
        channel_id,
        terminating,
    )
    .await
}

/// Forward the relay's data frames without interpreting the target protocol.
async fn bridge_relay(
    target: Box<dyn TargetStream>,
    inbound: impl tokio_stream::Stream<Item = Result<RelayFrame, tonic::Status>> + Unpin,
    out_tx: mpsc::Sender<RelayFrame>,
    channel_id: String,
    terminating: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Connect to the local SSH daemon on its Unix socket.
    let (target_r, target_w) = tokio::io::split(target);

    debug!(
        channel_id = %channel_id,
        "relay bridge: connected to local target"
    );

    bridge_relay_bytes(
        &channel_id,
        target_r,
        target_w,
        out_tx,
        inbound,
        &terminating,
    )
    .await
}

/// Bridge bytes between a local target socket and an inbound `RelayFrame`
/// stream, sending target bytes out through `out_tx`.
///
/// `out_tx` is moved into the target-reading task rather than cloned. A
/// clone would let the sender-side task's copy be dropped on target EOF
/// while this function's own copy stayed alive until `inbound` also ended,
/// which keeps the outbound gRPC stream open indefinitely after the target
/// closes. Moving it in means the outbound stream (and therefore the
/// client's view of the connection) closes as soon as the target does,
/// regardless of whether the client side has sent anything else.
async fn bridge_relay_bytes<S>(
    channel_id: &str,
    mut target_r: impl AsyncRead + Unpin + Send + 'static,
    mut target_w: impl AsyncWrite + Unpin,
    out_tx: mpsc::Sender<RelayFrame>,
    mut inbound: S,
    terminating: &AtomicBool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio_stream::Stream<Item = Result<RelayFrame, tonic::Status>> + Unpin,
{
    // Target → gRPC (out_tx): read local target, forward as `RelayFrame::data`.
    // `out_tx` is owned by this task, so dropping it on target EOF ends the
    // outbound stream immediately, without waiting on the inbound side.
    let target_to_grpc = tokio::spawn(async move {
        let mut buf = vec![0u8; RELAY_CHUNK_SIZE];
        loop {
            match target_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let chunk = RelayFrame {
                        payload: Some(openshell_core::proto::relay_frame::Payload::Data(
                            buf[..n].to_vec(),
                        )),
                    };
                    if out_tx.send(chunk).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // gRPC (inbound) → target: drain inbound chunks into the local target socket.
    let mut inbound_err: Option<String> = None;
    while let Some(next) = inbound.next().await {
        match next {
            Ok(frame) => {
                let Some(openshell_core::proto::relay_frame::Payload::Data(data)) = frame.payload
                else {
                    inbound_err = Some("relay inbound received non-data frame".to_string());
                    break;
                };
                if data.is_empty() {
                    continue;
                }
                if let Err(e) = target_w.write_all(&data).await {
                    inbound_err = Some(format!("write to target failed: {e}"));
                    break;
                }
            }
            Err(e) => {
                if expected_transport_close_during_shutdown(&e, terminating) {
                    debug!(
                        channel_id = %channel_id,
                        error = %e,
                        "relay bridge: inbound closed during local shutdown"
                    );
                } else {
                    inbound_err = Some(format!("relay inbound errored: {e}"));
                }
                break;
            }
        }
    }

    // Half-close the target socket's write side so the service sees EOF.
    let _ = target_w.shutdown().await;
    let _ = target_to_grpc.await;

    if let Some(e) = inbound_err {
        return Err(e.into());
    }
    Ok(())
}

async fn send_relay_open_result(
    tx: &mpsc::Sender<SupervisorMessage>,
    channel_id: &str,
    success: bool,
    error: String,
) {
    let _ = tx
        .send(SupervisorMessage {
            payload: Some(supervisor_message::Payload::RelayOpenResult(
                RelayOpenResult {
                    channel_id: channel_id.to_string(),
                    success,
                    error,
                },
            )),
        })
        .await;
}

async fn open_target(
    relay_open: &RelayOpen,
    ssh_socket_path: &std::path::Path,
    port_forward: &Arc<dyn BoundaryLoopbackConnector>,
    expected_ssh_peer_pid: Option<u32>,
) -> Result<Box<dyn TargetStream>, Box<dyn std::error::Error + Send + Sync>> {
    match relay_open.target.as_ref() {
        Some(relay_open::Target::Tcp(target)) => open_tcp_target(target, port_forward).await,
        Some(relay_open::Target::Ssh(_)) | None => {
            let runtime_path = crate::unix_socket::runtime_path(ssh_socket_path);
            let stream = tokio::net::UnixStream::connect(runtime_path.as_ref()).await?;
            if let Some(expected_pid) = expected_ssh_peer_pid {
                let credentials = stream.peer_cred()?;
                let actual_pid = credentials.pid().and_then(|pid| u32::try_from(pid).ok());
                if actual_pid != Some(expected_pid) {
                    return Err(format!(
                        "SSH relay peer PID mismatch: expected {expected_pid}, got {actual_pid:?}"
                    )
                    .into());
                }
            }
            Ok(Box::new(stream))
        }
    }
}

async fn open_tcp_target(
    target: &TcpRelayTarget,
    port_forward: &Arc<dyn BoundaryLoopbackConnector>,
) -> Result<Box<dyn TargetStream>, Box<dyn std::error::Error + Send + Sync>> {
    let host = normalize_tcp_target_host(target)?;
    let port = u16::try_from(target.port).map_err(|_| "tcp target port must fit in u16")?;
    // `normalize_tcp_target_host` returns a loopback IP string; parse it and let
    // `LoopbackTarget::new` re-validate before connecting.
    let ip: IpAddr = host
        .parse()
        .map_err(|_| "tcp target host must be a loopback IP")?;
    let target = LoopbackTarget::new(ip, port)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
    // Connect through the sandbox-owned loopback-forward interface. The
    // supervisor session remains independent of the driver's transport.
    let stream = port_forward
        .connect(target)
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
    Ok(Box::new(stream))
}

#[cfg(test)]
fn validate_tcp_target(target: &TcpRelayTarget) -> Result<(), String> {
    normalize_tcp_target_host(target).map(|_| ())
}

fn normalize_tcp_target_host(target: &TcpRelayTarget) -> Result<String, String> {
    if target.port == 0 || target.port > u32::from(u16::MAX) {
        return Err("tcp target port must be between 1 and 65535".to_string());
    }

    let host = target.host.trim();
    if host.is_empty() {
        return Err("tcp target host is required".to_string());
    }
    if host.eq_ignore_ascii_case("localhost") {
        return Ok("127.0.0.1".to_string());
    }

    let ip: IpAddr = host
        .parse()
        .map_err(|_| "tcp target host must be loopback".to_string())?;
    if ip.is_loopback() {
        Ok(ip.to_string())
    } else {
        Err("tcp target host must be loopback".to_string())
    }
}

#[cfg(test)]
mod target_tests {
    use super::*;

    fn bootstrap() -> ConfigBootstrap {
        ConfigBootstrap {
            sandbox_config: Some(openshell_core::proto::SandboxConfigSnapshot {
                config_revision: 7,
                version: 2,
                ..Default::default()
            }),
            provider_environment: Some(openshell_core::proto::ProviderEnvironmentSnapshot {
                provider_env_revision: 3,
                ..Default::default()
            }),
        }
    }

    fn assert_unapplied(result: &ConfigBootstrapResult, code: &str) {
        let sandbox = SettingsPollResult::from(bootstrap().sandbox_config.unwrap());
        let expected = [
            (
                ConfigComponent::ProviderEnvironment,
                provider_config_revision(3),
            ),
            (
                ConfigComponent::SandboxConfig,
                sandbox_config_revision(&sandbox),
            ),
        ];
        assert_eq!(result.results.len(), expected.len());
        for (result, (component, revision)) in result.results.iter().zip(expected) {
            assert_eq!(result.component, i32::from(component));
            assert_eq!(result.requested_revision, Some(revision));
            assert_eq!(result.outcome, i32::from(ConfigApplyOutcome::Unsupported));
            assert_eq!(result.failure.as_ref().unwrap().code, code);
        }
    }

    #[tokio::test]
    async fn unavailable_runtime_answers_every_bootstrap_component() {
        let (apply_tx, apply_rx) = mpsc::channel(1);
        drop(apply_rx);

        let result = apply_bootstrap(&apply_tx, bootstrap()).await;

        assert_unapplied(&result, "apply_unavailable");
    }

    #[tokio::test(start_paused = true)]
    async fn bootstrap_timeout_answers_every_component_like_an_update() {
        let (apply_tx, _apply_rx) = mpsc::channel(1);

        let result = apply_bootstrap(&apply_tx, bootstrap()).await;

        assert_unapplied(&result, "apply_timeout");
    }

    #[test]
    fn rejected_live_update_does_not_revoke_session_readiness() {
        let (ready_tx, ready_rx) = watch::channel(false);
        update_session_readiness(true, &ready_tx);
        assert!(*ready_rx.borrow());

        update_session_readiness(false, &ready_tx);
        assert!(*ready_rx.borrow());
    }

    fn tcp(host: &str, port: u32) -> TcpRelayTarget {
        TcpRelayTarget {
            host: host.to_string(),
            port,
        }
    }

    #[test]
    fn tcp_target_allows_loopback_hosts() {
        validate_tcp_target(&tcp("127.0.0.1", 8080)).expect("ipv4 loopback");
        validate_tcp_target(&tcp("::1", 8080)).expect("ipv6 loopback");
        validate_tcp_target(&tcp("localhost", 8080)).expect("localhost");
    }

    #[test]
    fn tcp_target_normalizes_localhost_before_dialing() {
        assert_eq!(
            normalize_tcp_target_host(&tcp("localhost", 8080)).expect("localhost"),
            "127.0.0.1"
        );
        assert_eq!(
            normalize_tcp_target_host(&tcp("LOCALHOST", 8080)).expect("localhost"),
            "127.0.0.1"
        );
    }

    #[test]
    fn tcp_target_rejects_non_loopback_hosts() {
        let err = validate_tcp_target(&tcp("10.0.0.1", 8080)).expect_err("private ip rejected");
        assert_eq!(err, "tcp target host must be loopback");

        let err = validate_tcp_target(&tcp("example.com", 8080)).expect_err("hostname rejected");
        assert_eq!(err, "tcp target host must be loopback");
    }

    #[test]
    fn tcp_target_rejects_invalid_ports() {
        let err = validate_tcp_target(&tcp("127.0.0.1", 0)).expect_err("zero rejected");
        assert_eq!(err, "tcp target port must be between 1 and 65535");

        let err = validate_tcp_target(&tcp("127.0.0.1", 70000)).expect_err("too large rejected");
        assert_eq!(err, "tcp target port must be between 1 and 65535");
    }
}

#[cfg(test)]
mod ocsf_event_tests {
    use super::*;

    #[cfg(target_os = "linux")]
    struct UnusedLoopbackConnector;

    #[cfg(target_os = "linux")]
    #[async_trait::async_trait]
    impl BoundaryLoopbackConnector for UnusedLoopbackConnector {
        async fn connect(
            &self,
            _target: LoopbackTarget,
        ) -> Result<
            openshell_isolation_interface::contract::BoundaryDuplexStream,
            openshell_isolation_interface::contract::BackendError,
        > {
            unreachable!("SSH relay does not use loopback port forwarding")
        }
    }

    fn ctx() -> EventContext {
        EventContext {
            sandbox_id: "sbx-1".into(),
            sandbox_name: "sandbox".into(),
            container_image: "img".into(),
            hostname: "host".into(),
            product_version: "0.0.1".into(),
            proxy_ip: "127.0.0.1".parse().unwrap(),
            proxy_port: 3128,
            origin: openshell_ocsf::EventOrigin::Supervisor,
        }
    }

    #[test]
    fn gateway_endpoint_parses_https_with_port() {
        let e = ocsf_gateway_endpoint("https://gateway.openshell:8443");
        assert_eq!(e.domain.as_deref(), Some("gateway.openshell"));
        assert_eq!(e.port, Some(8443));
    }

    #[test]
    fn gateway_endpoint_parses_http_with_port_and_path() {
        let e = ocsf_gateway_endpoint("http://gw:7000/grpc");
        assert_eq!(e.domain.as_deref(), Some("gw"));
        assert_eq!(e.port, Some(7000));
    }

    #[test]
    fn gateway_endpoint_falls_back_without_port() {
        let e = ocsf_gateway_endpoint("gateway.openshell");
        assert_eq!(e.domain.as_deref(), Some("gateway.openshell"));
        assert_eq!(e.port, Some(0));
    }

    fn network_activity(event: &OcsfEvent) -> &openshell_ocsf::NetworkActivityEvent {
        match event {
            OcsfEvent::NetworkActivity(n) => n,
            other => panic!("expected NetworkActivity, got {other:?}"),
        }
    }

    fn base_event(event: &OcsfEvent) -> &openshell_ocsf::BaseEvent {
        match event {
            OcsfEvent::Base(event) => event,
            other => panic!("expected Base Event, got {other:?}"),
        }
    }

    fn ssh_relay_open(channel_id: &str) -> RelayOpen {
        RelayOpen {
            channel_id: channel_id.to_string(),
            target: Some(relay_open::Target::Ssh(
                openshell_core::proto::SshRelayTarget::default(),
            )),
            service_id: String::new(),
        }
    }

    fn tcp_relay_open(channel_id: &str, host: &str, port: u32) -> RelayOpen {
        RelayOpen {
            channel_id: channel_id.to_string(),
            target: Some(relay_open::Target::Tcp(TcpRelayTarget {
                host: host.to_string(),
                port,
            })),
            service_id: String::new(),
        }
    }

    fn ssh_socket_path() -> &'static std::path::Path {
        std::path::Path::new("/run/openshell/ssh.sock")
    }

    #[test]
    fn session_established_emits_network_open_success() {
        let event = session_established_event(&ctx(), "https://gw:443", "sess-1", 30);
        let na = network_activity(&event);
        assert_eq!(na.base.activity_id, ActivityId::Open.as_u8());
        assert_eq!(na.base.severity, SeverityId::Informational);
        assert_eq!(na.base.status, Some(StatusId::Success));
        assert_eq!(
            na.dst_endpoint.as_ref().and_then(|e| e.domain.as_deref()),
            Some("gw")
        );
        let msg = na.base.message.as_deref().unwrap_or_default();
        assert!(msg.contains("sess-1"), "message missing session_id: {msg}");
        assert!(msg.contains("heartbeat_secs=30"), "message: {msg}");
    }

    #[test]
    fn session_closed_emits_network_close_success() {
        let event = session_closed_event(&ctx(), "https://gw:443", "sbx-1");
        let na = network_activity(&event);
        assert_eq!(na.base.activity_id, ActivityId::Close.as_u8());
        assert_eq!(na.base.severity, SeverityId::Informational);
        assert_eq!(na.base.status, Some(StatusId::Success));
    }

    #[test]
    fn session_failed_emits_network_fail_low() {
        let event = session_failed_event(&ctx(), "https://gw:443", 3, "connect refused");
        let na = network_activity(&event);
        assert_eq!(na.base.activity_id, ActivityId::Fail.as_u8());
        assert_eq!(na.base.severity, SeverityId::Low);
        assert_eq!(na.base.status, Some(StatusId::Failure));
        let msg = na.base.message.as_deref().unwrap_or_default();
        assert!(msg.contains("attempt 3"), "message: {msg}");
        assert!(msg.contains("connect refused"), "message: {msg}");
    }

    #[test]
    fn relay_open_emits_base_event() {
        let event = relay_open_event(&ctx(), &ssh_relay_open("ch-42"), ssh_socket_path());
        let event = base_event(&event);
        assert_eq!(event.base.activity_name, "Relay open");
        assert_eq!(event.base.severity, SeverityId::Informational);
        assert_eq!(event.base.status, Some(StatusId::Success));
        let msg = event.base.message.as_deref().unwrap_or_default();
        assert!(msg.contains("ch-42"), "message: {msg}");
        assert!(
            msg.contains("target=unix:/run/openshell/ssh.sock"),
            "message: {msg}"
        );
    }

    #[test]
    fn tcp_relay_open_emits_target_endpoint() {
        let event = relay_open_event(
            &ctx(),
            &tcp_relay_open("ch-42", "127.0.0.1", 8765),
            ssh_socket_path(),
        );
        let na = network_activity(&event);
        assert_eq!(na.base.activity_id, ActivityId::Open.as_u8());
        assert_eq!(
            na.dst_endpoint.as_ref().and_then(|e| e.ip.as_deref()),
            Some("127.0.0.1")
        );
        assert_eq!(na.dst_endpoint.as_ref().and_then(|e| e.port), Some(8765));
        assert_eq!(
            na.connection_info
                .as_ref()
                .map(|c| c.protocol_name.as_str()),
            Some("tcp")
        );
    }

    #[test]
    fn relay_closed_emits_base_event() {
        let event = relay_closed_event(&ctx(), &ssh_relay_open("ch-42"), ssh_socket_path());
        let event = base_event(&event);
        assert_eq!(event.base.activity_name, "Relay closed");
        assert_eq!(event.base.status, Some(StatusId::Success));
    }

    #[test]
    fn relay_failed_emits_base_event() {
        let event = relay_failed_event(
            &ctx(),
            &ssh_relay_open("ch-42"),
            ssh_socket_path(),
            "write to ssh failed",
        );
        let event = base_event(&event);
        assert_eq!(event.base.activity_name, "Relay failed");
        assert_eq!(event.base.severity, SeverityId::Low);
        assert_eq!(event.base.status, Some(StatusId::Failure));
        let msg = event.base.message.as_deref().unwrap_or_default();
        assert!(msg.contains("ch-42"), "message: {msg}");
        assert!(msg.contains("write to ssh failed"), "message: {msg}");
    }

    #[test]
    fn relay_close_from_gateway_is_base_event() {
        let event = relay_close_from_gateway_event(&ctx(), "ch-42", "sandbox deleted");
        let event = base_event(&event);
        assert_eq!(event.base.activity_name, "Relay close from gateway");
        assert_eq!(event.base.severity, SeverityId::Informational);
        let msg = event.base.message.as_deref().unwrap_or_default();
        assert!(msg.contains("sandbox deleted"), "message: {msg}");
    }

    #[test]
    fn map_stream_message_treats_eof_as_reconnectable_error() {
        let err = map_stream_message::<SupervisorMessage>(Ok(None), "gateway closed stream")
            .expect_err("eof should force reconnect");
        assert_eq!(err.to_string(), "gateway closed stream");
    }

    #[test]
    fn map_session_stream_message_allows_expected_close_during_shutdown() {
        let terminating = AtomicBool::new(true);
        let message = map_session_stream_message::<GatewayMessage>(
            Err(tonic::Status::unknown(
                "h2 protocol error: error reading a body from connection",
            )),
            "gateway closed stream",
            &terminating,
        )
        .expect("expected transport close should be non-fatal during shutdown");

        assert!(matches!(
            message,
            SessionStreamMessage::ExpectedShutdownClose
        ));
    }

    #[test]
    fn map_session_stream_message_keeps_transport_close_fatal_when_not_shutting_down() {
        let terminating = AtomicBool::new(false);
        let err = map_session_stream_message::<GatewayMessage>(
            Err(tonic::Status::unknown(
                "h2 protocol error: error reading a body from connection",
            )),
            "gateway closed stream",
            &terminating,
        )
        .expect_err("same transport close should fail before shutdown starts");

        assert!(err.to_string().contains("h2 protocol error"));
    }

    #[test]
    fn map_session_stream_message_keeps_unexpected_error_fatal_during_shutdown() {
        let terminating = AtomicBool::new(true);
        let err = map_session_stream_message::<GatewayMessage>(
            Err(tonic::Status::internal("policy evaluation failed")),
            "gateway closed stream",
            &terminating,
        )
        .expect_err("non-transport errors must stay fatal");

        assert!(err.to_string().contains("policy evaluation failed"));
    }

    #[test]
    fn failed_redirect_is_served_on_the_next_attempt() {
        assert!(redirect_survives_failure(true, false));
        assert!(!redirect_survives_failure(true, true));
        assert!(!redirect_survives_failure(false, false));
        assert!(!redirect_survives_failure(false, true));
    }

    #[test]
    fn reconnect_backoff_doubles_until_a_session_is_accepted() {
        let mut backoff = ReconnectBackoff::new();
        let delays: Vec<_> = (0..7)
            .map(|_| backoff.on_failure(false, false).unwrap())
            .collect();
        assert_eq!(
            delays,
            [1, 2, 4, 8, 16, 30, 30].map(Duration::from_secs).to_vec()
        );

        // Losing an accepted session starts over instead of waiting the maximum.
        assert_eq!(backoff.on_failure(true, false), Some(INITIAL_BACKOFF));
        assert_eq!(backoff.on_failure(false, false), Some(INITIAL_BACKOFF * 2));
    }

    #[test]
    fn reconnect_backoff_resets_when_an_accepted_session_redirects() {
        let mut backoff = ReconnectBackoff::new();
        for _ in 0..5 {
            backoff.on_failure(false, false);
        }

        backoff.on_redirect(true);
        assert_eq!(backoff.on_failure(false, false), Some(INITIAL_BACKOFF));
    }

    #[test]
    fn reconnect_backoff_skips_one_failed_redirect_target_per_accepted_session() {
        let mut backoff = ReconnectBackoff::new();
        assert_eq!(backoff.on_failure(false, true), None);
        assert_eq!(backoff.on_failure(false, true), Some(INITIAL_BACKOFF));

        backoff.on_redirect(true);
        assert_eq!(backoff.on_failure(false, true), None);
    }

    #[test]
    fn backoff_is_skipped_once_per_accepted_session() {
        assert!(skip_backoff(true, false));
        assert!(!skip_backoff(true, true));
        assert!(!skip_backoff(false, false));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn ssh_target_requires_authenticated_supervisor_peer_pid() {
        let socket =
            std::path::PathBuf::from(format!("@openshell-relay-test-{}", uuid::Uuid::new_v4()));
        let runtime_path = crate::unix_socket::runtime_path(&socket);
        let listener = tokio::net::UnixListener::bind(runtime_path.as_ref()).unwrap();
        let accept_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (_stream, _) = listener.accept().await.unwrap();
            }
        });
        let relay = ssh_relay_open("peer-check");

        // The SSH relay path does not use the port-forward (that is the TCP
        // target path); connect from the supervisor's own namespace.
        let port_forward: Arc<dyn BoundaryLoopbackConnector> = Arc::new(UnusedLoopbackConnector);

        let trusted = open_target(&relay, &socket, &port_forward, Some(std::process::id()))
            .await
            .expect("matching peer PID should be accepted");
        drop(trusted);

        let Err(err) = open_target(
            &relay,
            &socket,
            &port_forward,
            Some(std::process::id().saturating_add(1)),
        )
        .await
        else {
            panic!("mismatched peer PID must be rejected");
        };
        assert!(err.to_string().contains("peer PID mismatch"));
        accept_task.await.unwrap();
    }

    /// Regression test for #3724: when the target closes after sending
    /// data, the outbound relay stream must close too, even though the
    /// inbound (client) side is still open. Before the fix, `out_tx` was
    /// cloned into the target-reading task, so the function's own copy kept
    /// the outbound stream alive until `inbound` also ended.
    #[tokio::test]
    async fn bridge_closes_outbound_when_target_closes_first() {
        let (target, mut remote) = tokio::io::duplex(4096);
        let (target_r, target_w) = tokio::io::split(target);

        let (out_tx, mut out_rx) = mpsc::channel::<RelayFrame>(16);

        // Inbound stream the client never closes during this test.
        let (inbound_tx, inbound_rx) = mpsc::channel::<Result<RelayFrame, tonic::Status>>(16);
        let inbound = tokio_stream::wrappers::ReceiverStream::new(inbound_rx);

        let terminating = AtomicBool::new(false);
        let bridge = tokio::spawn(async move {
            bridge_relay_bytes("chan-1", target_r, target_w, out_tx, inbound, &terminating).await
        });

        remote.write_all(b"hello").await.unwrap();
        remote.shutdown().await.unwrap();

        let frame = out_rx.recv().await.expect("data frame expected");
        assert_eq!(
            frame.payload,
            Some(openshell_core::proto::relay_frame::Payload::Data(
                b"hello".to_vec()
            ))
        );

        // The outbound stream must end here, without the inbound side (still
        // held open by `inbound_tx`) ending first.
        assert!(
            out_rx.recv().await.is_none(),
            "outbound stream should close once the target closes"
        );

        drop(inbound_tx);
        bridge
            .await
            .unwrap()
            .expect("bridge should finish cleanly when target closes first");
    }

    /// A target that half-closes its output must still receive client data.
    #[tokio::test]
    async fn bridge_forwards_client_data_after_target_half_close() {
        let (target, mut remote) = tokio::io::duplex(4096);
        let (target_r, target_w) = tokio::io::split(target);

        let (out_tx, mut out_rx) = mpsc::channel::<RelayFrame>(16);
        let (inbound_tx, inbound_rx) = mpsc::channel::<Result<RelayFrame, tonic::Status>>(16);
        let inbound = tokio_stream::wrappers::ReceiverStream::new(inbound_rx);

        let terminating = AtomicBool::new(false);
        let bridge = tokio::spawn(async move {
            bridge_relay_bytes("chan-3", target_r, target_w, out_tx, inbound, &terminating).await
        });

        remote.write_all(b"ready").await.unwrap();
        remote.shutdown().await.unwrap();
        assert!(out_rx.recv().await.is_some(), "greeting frame expected");
        assert!(out_rx.recv().await.is_none(), "outbound should close");

        inbound_tx
            .send(Ok(RelayFrame {
                payload: Some(openshell_core::proto::relay_frame::Payload::Data(
                    b"upload".to_vec(),
                )),
            }))
            .await
            .unwrap();
        let mut buf = [0u8; 6];
        remote.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"upload");

        drop(inbound_tx);
        bridge.await.unwrap().expect("bridge should finish cleanly");
    }

    /// A well-behaved round trip: bytes flow both directions and the bridge
    /// ends cleanly when the client closes its side.
    #[tokio::test]
    async fn bridge_round_trips_bytes_until_client_closes() {
        let (target, mut remote) = tokio::io::duplex(4096);
        let (target_r, target_w) = tokio::io::split(target);

        let (out_tx, mut out_rx) = mpsc::channel::<RelayFrame>(16);
        let (inbound_tx, inbound_rx) = mpsc::channel::<Result<RelayFrame, tonic::Status>>(16);
        let inbound = tokio_stream::wrappers::ReceiverStream::new(inbound_rx);

        let terminating = AtomicBool::new(false);
        let bridge = tokio::spawn(async move {
            bridge_relay_bytes("chan-2", target_r, target_w, out_tx, inbound, &terminating).await
        });

        // Client -> target.
        inbound_tx
            .send(Ok(RelayFrame {
                payload: Some(openshell_core::proto::relay_frame::Payload::Data(
                    b"ping".to_vec(),
                )),
            }))
            .await
            .unwrap();
        let mut buf = [0u8; 4];
        remote.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        // Target -> client.
        remote.write_all(b"pong").await.unwrap();
        let frame = out_rx.recv().await.expect("data frame expected");
        assert_eq!(
            frame.payload,
            Some(openshell_core::proto::relay_frame::Payload::Data(
                b"pong".to_vec()
            ))
        );

        // Client closes its side first; the bridge should still complete
        // once the target also closes.
        drop(inbound_tx);
        remote.shutdown().await.unwrap();

        bridge
            .await
            .unwrap()
            .expect("bridge should finish cleanly on an ordinary round trip");
    }
}
