// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};
use uuid::Uuid;

use openshell_core::proto::{
    ConfigApplyOutcome, ConfigBootstrap, ConfigBootstrapResult, ConfigBootstrapStatus,
    ConfigUpdate, ConfigUpdateResult, GatewayMessage, InferenceBundleUpdate,
    ProviderEnvironmentUpdate, RelayFrame, RelayInit, RelayOpen, ReportMainProcessExitRequest,
    ReportMainProcessExitResponse, Sandbox, SandboxConfigUpdate, SandboxPhase, SessionAccepted,
    SshRelayTarget, SupervisorMessage, config_update, gateway_message, relay_open,
    supervisor_message,
};
use openshell_core::transport_errors::is_expected_transport_close_status;

use crate::ServerState;
use crate::auth::principal::Principal;

const HEARTBEAT_INTERVAL_SECS: u32 = 15;
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(120);
const CONFIG_UPDATE_TIMEOUT: Duration = Duration::from_secs(60);
const RELAY_PENDING_TIMEOUT: Duration = Duration::from_secs(10);
/// Initial backoff between session-availability polls in `wait_for_session`.
const SESSION_WAIT_INITIAL_BACKOFF: Duration = Duration::from_millis(100);
/// Maximum backoff between session-availability polls in `wait_for_session`.
const SESSION_WAIT_MAX_BACKOFF: Duration = Duration::from_secs(2);
/// Upper bound on unclaimed relay channels across all sandboxes. Caps the
/// memory a misbehaving caller can pin by calling `open_relay` repeatedly
/// while the supervisor never claims (or isn't responding). Sized generously
/// so normal bursts pass through; exceeding it returns `ResourceExhausted`.
const MAX_PENDING_RELAYS: usize = 256;
/// Upper bound on concurrent unclaimed relay channels for a single sandbox.
/// Enforces the same shape per sandbox so one misbehaving sandbox can't
/// consume the entire global budget. Sits above the SSH-tunnel per-sandbox
/// cap (20) so tunnel-specific limits still fire first for that caller.
const MAX_PENDING_RELAYS_PER_SANDBOX: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DesiredStateComponent {
    SandboxConfig,
    ProviderEnvironment,
    InferenceBundle,
}

#[derive(Debug)]
struct InFlightUpdate {
    request_id: String,
    component_sequence: u64,
    revision: String,
    sent_at: Instant,
}

#[derive(Debug)]
struct ComponentDeliveryState {
    applied_revision: String,
    next_sequence: u64,
    in_flight: Option<InFlightUpdate>,
    pending_revision: Option<String>,
}

impl ComponentDeliveryState {
    fn new(applied_revision: impl ToString) -> Self {
        Self {
            applied_revision: applied_revision.to_string(),
            next_sequence: 1,
            in_flight: None,
            pending_revision: None,
        }
    }
}

#[derive(Debug)]
struct DesiredStateDelivery {
    sandbox_config: ComponentDeliveryState,
    provider_environment: ComponentDeliveryState,
    inference_bundle: ComponentDeliveryState,
}

#[derive(Debug)]
struct AppliedUpdateResult {
    component: DesiredStateComponent,
    outcome: ConfigApplyOutcome,
}

impl DesiredStateDelivery {
    fn new(bootstrap: &ConfigBootstrap) -> Result<Self, Status> {
        let sandbox_config = bootstrap
            .sandbox_config
            .as_ref()
            .ok_or_else(|| Status::internal("bootstrap sandbox config is missing"))?;
        let provider_environment = bootstrap
            .provider_environment
            .as_ref()
            .ok_or_else(|| Status::internal("bootstrap provider environment is missing"))?;
        let inference_bundle = bootstrap
            .inference_bundle
            .as_ref()
            .ok_or_else(|| Status::internal("bootstrap inference bundle is missing"))?;
        Ok(Self {
            sandbox_config: ComponentDeliveryState::new(sandbox_config.config_revision),
            provider_environment: ComponentDeliveryState::new(
                provider_environment.provider_env_revision,
            ),
            inference_bundle: ComponentDeliveryState::new(&inference_bundle.revision),
        })
    }

    fn state_mut(&mut self, component: DesiredStateComponent) -> &mut ComponentDeliveryState {
        match component {
            DesiredStateComponent::SandboxConfig => &mut self.sandbox_config,
            DesiredStateComponent::ProviderEnvironment => &mut self.provider_environment,
            DesiredStateComponent::InferenceBundle => &mut self.inference_bundle,
        }
    }

    fn has_pending_update(&self) -> bool {
        self.sandbox_config.pending_revision.is_some()
            || self.provider_environment.pending_revision.is_some()
            || self.inference_bundle.pending_revision.is_some()
    }

    fn expire_timed_out(&mut self) -> Vec<DesiredStateComponent> {
        let mut expired = Vec::new();
        for (component, state) in [
            (
                DesiredStateComponent::SandboxConfig,
                &mut self.sandbox_config,
            ),
            (
                DesiredStateComponent::ProviderEnvironment,
                &mut self.provider_environment,
            ),
            (
                DesiredStateComponent::InferenceBundle,
                &mut self.inference_bundle,
            ),
        ] {
            if state
                .in_flight
                .as_ref()
                .is_some_and(|update| update.sent_at.elapsed() >= CONFIG_UPDATE_TIMEOUT)
            {
                state.in_flight = None;
                expired.push(component);
            }
        }
        expired
    }

    fn handle_result(
        &mut self,
        result: &ConfigUpdateResult,
    ) -> Result<Option<AppliedUpdateResult>, String> {
        if result.request_id.is_empty() {
            return Err("config update result has an empty request_id".to_string());
        }
        let matches = [
            DesiredStateComponent::SandboxConfig,
            DesiredStateComponent::ProviderEnvironment,
            DesiredStateComponent::InferenceBundle,
        ]
        .into_iter()
        .find(|component| {
            self.state_mut(*component)
                .in_flight
                .as_ref()
                .is_some_and(|update| update.request_id == result.request_id)
        });
        let Some(component) = matches else {
            return Ok(None);
        };
        let state = self.state_mut(component);
        let Some(update) = state.in_flight.take() else {
            return Ok(None);
        };
        if update.component_sequence != result.component_sequence {
            state.in_flight = Some(update);
            return Err("config update result component_sequence mismatch".to_string());
        }
        let outcome = ConfigApplyOutcome::try_from(result.outcome)
            .map_err(|_| "config update result has an unknown outcome".to_string())?;
        let terminal_success = matches!(
            outcome,
            ConfigApplyOutcome::Applied
                | ConfigApplyOutcome::IgnoredDuplicate
                | ConfigApplyOutcome::RetainedLocalOverride
                | ConfigApplyOutcome::Degraded
        );
        if terminal_success {
            state.applied_revision = update.revision;
        }
        Ok(Some(AppliedUpdateResult { component, outcome }))
    }
}

// ---------------------------------------------------------------------------
// Session registry
// ---------------------------------------------------------------------------

/// A live supervisor session handle.
struct LiveSession {
    #[allow(dead_code)]
    sandbox_id: String,
    /// Uniquely identifies this session instance. Used by cleanup to avoid
    /// removing a session that has since been superseded by a reconnect.
    session_id: String,
    tx: mpsc::Sender<GatewayMessage>,
    /// Fires when this session is superseded by a reconnect so the old session
    /// task can exit promptly — dropping its own `tx` clone and closing the
    /// outbound stream. Without this, a concurrent `open_relay` that grabbed
    /// the old session's `tx` just before supersede could still enqueue a
    /// `RelayOpen` onto the stale stream and sit until the relay timeout.
    shutdown: oneshot::Sender<()>,
    #[allow(dead_code)]
    connected_at: Instant,
    initialized: bool,
    runtime_ready: bool,
}

/// Holds a oneshot sender that will deliver the upgraded relay stream or a
/// target-open failure reported by the supervisor.
type RelayStreamSender = oneshot::Sender<Result<tokio::io::DuplexStream, Status>>;

/// Registry of active supervisor sessions and pending relay channels.
#[derive(Default)]
pub struct SupervisorSessionRegistry {
    /// `sandbox_id` -> live session handle.
    sessions: Mutex<HashMap<String, LiveSession>>,
    /// `channel_id` -> oneshot sender for the reverse CONNECT stream.
    pending_relays: Mutex<HashMap<String, PendingRelay>>,
}

struct PendingRelay {
    sender: RelayStreamSender,
    sandbox_id: String,
    relay_open: RelayOpen,
    created_at: Instant,
}

#[derive(Debug)]
pub struct ClaimedRelay {
    pub stream: tokio::io::DuplexStream,
    pub sandbox_id: String,
}

impl std::fmt::Debug for SupervisorSessionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let session_count = self.sessions.lock().unwrap().len();
        let pending_count = self.pending_relays.lock().unwrap().len();
        f.debug_struct("SupervisorSessionRegistry")
            .field("sessions", &session_count)
            .field("pending_relays", &pending_count)
            .finish()
    }
}

impl SupervisorSessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a live supervisor session for the given sandbox.
    ///
    /// If a previous session exists for the same sandbox, its shutdown signal
    /// is fired so the old session task exits promptly. Returns `true` iff a
    /// previous session was superseded.
    pub fn register(
        &self,
        sandbox_id: String,
        session_id: String,
        tx: mpsc::Sender<GatewayMessage>,
        shutdown: oneshot::Sender<()>,
    ) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        let previous = sessions.remove(&sandbox_id);
        sessions.insert(
            sandbox_id.clone(),
            LiveSession {
                sandbox_id,
                session_id,
                tx,
                shutdown,
                connected_at: Instant::now(),
                initialized: false,
                runtime_ready: false,
            },
        );
        match previous {
            Some(prev) => {
                // Best-effort — the old task may have already exited.
                let _ = prev.shutdown.send(());
                true
            }
            None => false,
        }
    }

    /// Remove the session for a sandbox.
    fn remove(&self, sandbox_id: &str) {
        self.sessions.lock().unwrap().remove(sandbox_id);
    }

    /// Disconnect the current supervisor session for a sandbox.
    ///
    /// Lifecycle stop uses this to ensure a later start must establish
    /// a fresh session before the sandbox can return to Ready.
    pub fn disconnect(&self, sandbox_id: &str) -> bool {
        let session = self.sessions.lock().unwrap().remove(sandbox_id);
        if let Some(session) = session {
            let _ = session.shutdown.send(());
            true
        } else {
            false
        }
    }

    /// Remove the session only if its `session_id` matches the one we are
    /// cleaning up. Returns `true` if the entry was removed.
    ///
    /// This guards against the supersede race: an old session's task may
    /// finish long after a new session has taken its place. The old task's
    /// cleanup must not evict the new registration.
    fn remove_if_current(&self, sandbox_id: &str, session_id: &str) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        let is_current = sessions
            .get(sandbox_id)
            .is_some_and(|s| s.session_id == session_id);
        if is_current {
            sessions.remove(sandbox_id);
        }
        is_current
    }

    /// Look up the sender for a supervisor session, waiting up to `timeout`
    /// for it to appear if absent.
    ///
    /// Uses exponential backoff (100ms → 2s) while polling the sessions map.
    async fn wait_for_session(
        &self,
        sandbox_id: &str,
        timeout: Duration,
    ) -> Result<mpsc::Sender<GatewayMessage>, Status> {
        let deadline = Instant::now() + timeout;
        let mut backoff = SESSION_WAIT_INITIAL_BACKOFF;

        loop {
            if let Some(tx) = self.lookup_session(sandbox_id) {
                return Ok(tx);
            }
            if Instant::now() + backoff > deadline {
                return Err(Status::unavailable("supervisor session not connected"));
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(SESSION_WAIT_MAX_BACKOFF);
        }
    }

    fn lookup_session(&self, sandbox_id: &str) -> Option<mpsc::Sender<GatewayMessage>> {
        self.sessions
            .lock()
            .unwrap()
            .get(sandbox_id)
            .filter(|session| session.initialized && session.runtime_ready)
            .map(|session| session.tx.clone())
    }

    pub fn has_session(&self, sandbox_id: &str) -> bool {
        self.sessions.lock().unwrap().contains_key(sandbox_id)
    }

    pub fn has_ready_session(&self, sandbox_id: &str) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .get(sandbox_id)
            .is_some_and(|session| session.initialized && session.runtime_ready)
    }

    fn is_initialized(&self, sandbox_id: &str, session_id: &str) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .get(sandbox_id)
            .is_some_and(|session| session.session_id == session_id && session.initialized)
    }

    /// Mark bootstrap complete. Returns whether runtime-ready was already set.
    pub fn mark_initialized(&self, sandbox_id: &str, session_id: &str) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        let Some(session) = sessions.get_mut(sandbox_id) else {
            return false;
        };
        if session.session_id != session_id {
            return false;
        }
        session.initialized = true;
        session.runtime_ready
    }

    /// Mark runtime services ready. Returns whether bootstrap is also complete.
    pub fn mark_runtime_ready(&self, sandbox_id: &str, session_id: &str) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        let Some(session) = sessions.get_mut(sandbox_id) else {
            return false;
        };
        if session.session_id != session_id {
            return false;
        }
        session.runtime_ready = true;
        session.initialized
    }

    pub fn is_current_session(&self, sandbox_id: &str, session_id: &str) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .get(sandbox_id)
            .is_some_and(|session| session.session_id == session_id)
    }

    fn pending_channel_ids(&self, sandbox_id: &str) -> Vec<String> {
        self.pending_relays
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, pending)| pending.sandbox_id == sandbox_id)
            .map(|(channel_id, _)| channel_id.clone())
            .collect()
    }

    /// Open a relay channel and return a receiver for the supervisor-side
    /// stream.
    ///
    /// Sends `RelayOpen` over the supervisor's gRPC session and returns a
    /// oneshot receiver that resolves once the supervisor opens its reverse
    /// HTTP CONNECT to `/relay/{channel_id}`.
    ///
    /// If the session is not currently registered, this method waits up to
    /// `session_wait_timeout` for it to appear. A session may be temporarily
    /// absent for several reasons — all of which look identical from here:
    ///
    /// - startup race: the sandbox just reported Ready but the supervisor's
    ///   `ConnectSupervisor` gRPC handshake hasn't completed yet
    /// - transient disconnect: the session was up but got dropped (network
    ///   blip, gateway restart, supervisor restart) and the supervisor is
    ///   in its reconnect backoff loop
    ///
    /// Callers pick the timeout based on how much patience the caller needs.
    /// A first `sandbox connect` right after `sandbox create` may need to
    /// wait for the supervisor's initial TLS + gRPC handshake (tens of
    /// seconds on a slow cluster), while mid-lifetime calls typically just
    /// need to cover a short reconnect window.
    pub async fn open_relay(
        &self,
        sandbox_id: &str,
        session_wait_timeout: Duration,
    ) -> Result<
        (
            String,
            oneshot::Receiver<Result<tokio::io::DuplexStream, Status>>,
        ),
        Status,
    > {
        self.open_relay_with_target(
            sandbox_id,
            relay_open::Target::Ssh(SshRelayTarget {}),
            String::new(),
            session_wait_timeout,
        )
        .await
    }

    pub async fn open_relay_with_target(
        &self,
        sandbox_id: &str,
        target: relay_open::Target,
        service_id: String,
        session_wait_timeout: Duration,
    ) -> Result<
        (
            String,
            oneshot::Receiver<Result<tokio::io::DuplexStream, Status>>,
        ),
        Status,
    > {
        let tx = self
            .wait_for_session(sandbox_id, session_wait_timeout)
            .await?;

        let channel_id = Uuid::new_v4().to_string();
        let relay_open = RelayOpen {
            channel_id: channel_id.clone(),
            target: Some(target),
            service_id,
        };

        // Register the pending relay before sending RelayOpen to avoid a race.
        // Both caps are checked and the insert happens under a single lock hold
        // so two concurrent calls can't both observe "under the cap" and then
        // both insert past it.
        let (relay_tx, relay_rx) = oneshot::channel();
        {
            let mut pending = self.pending_relays.lock().unwrap();
            if pending.len() >= MAX_PENDING_RELAYS {
                return Err(Status::resource_exhausted(format!(
                    "gateway relay capacity reached ({MAX_PENDING_RELAYS} in flight)"
                )));
            }
            let per_sandbox = pending
                .values()
                .filter(|p| p.sandbox_id == sandbox_id)
                .count();
            if per_sandbox >= MAX_PENDING_RELAYS_PER_SANDBOX {
                return Err(Status::resource_exhausted(format!(
                    "per-sandbox relay limit reached ({MAX_PENDING_RELAYS_PER_SANDBOX} in flight for {sandbox_id})"
                )));
            }
            pending.insert(
                channel_id.clone(),
                PendingRelay {
                    sender: relay_tx,
                    sandbox_id: sandbox_id.to_string(),
                    relay_open: relay_open.clone(),
                    created_at: Instant::now(),
                },
            );
        }

        let msg = GatewayMessage {
            payload: Some(gateway_message::Payload::RelayOpen(relay_open)),
        };

        if tx.send(msg).await.is_err() {
            // Session dropped between our lookup and send.
            self.pending_relays.lock().unwrap().remove(&channel_id);
            return Err(Status::unavailable("supervisor session disconnected"));
        }

        Ok((channel_id, relay_rx))
    }

    pub fn fail_pending_relay(&self, channel_id: &str, error: String) -> bool {
        let pending = self.pending_relays.lock().unwrap().remove(channel_id);
        if let Some(pending) = pending {
            let _ = pending.sender.send(Err(Status::unavailable(error)));
            true
        } else {
            false
        }
    }

    /// Claim a pending relay channel. Called by the `/relay/{channel_id}` HTTP handler
    /// when the supervisor's reverse CONNECT arrives.
    ///
    /// Returns the `DuplexStream` half that the supervisor side should read/write.
    // `tonic::Status` is large but is the API surface of gRPC handlers.
    #[allow(clippy::result_large_err)]
    pub fn claim_relay(
        &self,
        channel_id: &str,
        principal: Option<&Principal>,
    ) -> Result<ClaimedRelay, Status> {
        let pending = {
            let mut map = self.pending_relays.lock().unwrap();
            let pending = map
                .get(channel_id)
                .ok_or_else(|| Status::not_found("unknown or expired relay channel"))?;

            if let Some(principal) = principal
                && let Err(status) = crate::auth::guard::ensure_sandbox_principal_scope(
                    principal,
                    &pending.sandbox_id,
                )
            {
                info!(
                    channel_id = %channel_id,
                    sandbox_id = %pending.sandbox_id,
                    "relay stream: rejecting cross-sandbox claim"
                );
                return Err(status);
            }

            if pending.created_at.elapsed() > RELAY_PENDING_TIMEOUT {
                map.remove(channel_id);
                return Err(Status::deadline_exceeded("relay channel timed out"));
            }

            map.remove(channel_id)
                .expect("pending relay existed before removal")
        };

        // Create a duplex stream pair: one end for the gateway bridge, one for
        // the supervisor HTTP CONNECT handler.
        let (gateway_stream, supervisor_stream) = tokio::io::duplex(64 * 1024);

        // Send the gateway-side stream to the waiter (exec handler or forward handler).
        if pending.sender.send(Ok(gateway_stream)).is_err() {
            return Err(Status::internal("relay requester dropped"));
        }

        Ok(ClaimedRelay {
            stream: supervisor_stream,
            sandbox_id: pending.sandbox_id,
        })
    }

    /// Remove all pending relays that have exceeded the timeout.
    pub fn reap_expired_relays(&self) {
        let mut map = self.pending_relays.lock().unwrap();
        map.retain(|_, pending| pending.created_at.elapsed() <= RELAY_PENDING_TIMEOUT);
    }

    /// Clean up all state for a sandbox (session + pending relays).
    pub fn cleanup_sandbox(&self, sandbox_id: &str) {
        self.remove(sandbox_id);
    }

    pub async fn replay_pending_relays(&self, sandbox_id: &str, tx: &mpsc::Sender<GatewayMessage>) {
        for channel_id in self.pending_channel_ids(sandbox_id) {
            let relay_open = {
                let pending = self.pending_relays.lock().unwrap();
                pending
                    .get(&channel_id)
                    .map(|pending| pending.relay_open.clone())
            };
            let Some(relay_open) = relay_open else {
                continue;
            };
            let msg = GatewayMessage {
                payload: Some(gateway_message::Payload::RelayOpen(relay_open)),
            };
            if tx.send(msg).await.is_err() {
                warn!(sandbox_id = %sandbox_id, channel_id = %channel_id, "supervisor session: failed to replay pending relay to superseding session");
                break;
            }
        }
    }
}

/// Spawn a background task that periodically reaps expired pending relay
/// entries.
///
/// Pending entries are normally consumed either when the supervisor opens its
/// reverse CONNECT (via `claim_relay`) or by the gateway-side waiter timing
/// out. If neither happens — e.g., the supervisor crashed after acknowledging
/// `RelayOpen` but before initiating `RelayStream` — the entry would otherwise
/// sit in the map indefinitely. This sweeper bounds that leak.
pub fn spawn_relay_reaper(state: Arc<ServerState>, interval: Duration) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            state.supervisor_sessions.reap_expired_relays();
        }
    });
}

async fn require_persisted_sandbox(
    store: &Arc<crate::persistence::Store>,
    sandbox_id: &str,
) -> Result<Sandbox, Status> {
    let sandbox = store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .map_err(|err| Status::internal(format!("failed to load sandbox: {err}")))?;

    sandbox.ok_or_else(|| Status::not_found("sandbox not found"))
}

fn reconciliation_interval(sandbox_id: &str) -> Duration {
    let mut hasher = DefaultHasher::new();
    sandbox_id.hash(&mut hasher);
    Duration::from_secs(24 + hasher.finish() % 13)
}

async fn reconcile_desired_state(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    tx: &mpsc::Sender<GatewayMessage>,
    delivery: &mut DesiredStateDelivery,
) -> Result<(), Status> {
    for component in delivery.expire_timed_out() {
        let (condition_component, component_label) = match component {
            DesiredStateComponent::SandboxConfig => ("SandboxConfig", "sandbox config"),
            DesiredStateComponent::ProviderEnvironment => {
                ("ProviderEnvironment", "provider environment")
            }
            DesiredStateComponent::InferenceBundle => ("InferenceBundle", "inference bundle"),
        };
        if let Err(error) = state
            .compute
            .supervisor_config_update_result(
                sandbox_id,
                condition_component,
                false,
                "DesiredStateApplyTimedOut",
                &format!("Latest {component_label} desired-state update timed out"),
            )
            .await
        {
            warn!(sandbox_id = %sandbox_id, error = %error, "failed to persist desired-state update timeout");
        }
    }
    let sandbox = require_persisted_sandbox(&state.store, sandbox_id).await?;
    let (sandbox_config, provider_environment, inference_bundle) = tokio::join!(
        crate::grpc::policy::build_sandbox_config_snapshot(state, &sandbox),
        crate::grpc::policy::build_provider_environment_snapshot(state, &sandbox, true),
        crate::inference::build_inference_bundle_snapshot(state, &sandbox),
    );

    let mut errors = Vec::new();
    match sandbox_config {
        Ok(snapshot) => {
            if let Err(error) = send_component_update(
                tx,
                DesiredStateComponent::SandboxConfig,
                snapshot.config_revision.to_string(),
                config_update::Component::SandboxConfig(SandboxConfigUpdate {
                    snapshot: Some(snapshot),
                }),
                delivery,
            )
            .await
            {
                errors.push(format!("sandbox config delivery: {error}"));
            }
        }
        Err(error) => errors.push(format!("sandbox config snapshot: {error}")),
    }
    match provider_environment {
        Ok(snapshot) => {
            if let Err(error) = send_component_update(
                tx,
                DesiredStateComponent::ProviderEnvironment,
                snapshot.provider_env_revision.to_string(),
                config_update::Component::ProviderEnvironment(ProviderEnvironmentUpdate {
                    snapshot: Some(snapshot),
                }),
                delivery,
            )
            .await
            {
                errors.push(format!("provider environment delivery: {error}"));
            }
        }
        Err(error) => errors.push(format!("provider environment snapshot: {error}")),
    }
    match inference_bundle {
        Ok(snapshot) => {
            if let Err(error) = send_component_update(
                tx,
                DesiredStateComponent::InferenceBundle,
                snapshot.revision.clone(),
                config_update::Component::InferenceBundle(InferenceBundleUpdate {
                    snapshot: Some(snapshot),
                }),
                delivery,
            )
            .await
            {
                errors.push(format!("inference bundle delivery: {error}"));
            }
        }
        Err(error) => errors.push(format!("inference bundle snapshot: {error}")),
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(Status::internal(errors.join("; ")))
    }
}

async fn send_component_update(
    tx: &mpsc::Sender<GatewayMessage>,
    component: DesiredStateComponent,
    revision: String,
    payload: config_update::Component,
    delivery: &mut DesiredStateDelivery,
) -> Result<(), Status> {
    let state = delivery.state_mut(component);
    if revision == state.applied_revision {
        state.pending_revision = None;
        return Ok(());
    }
    if let Some(in_flight) = state.in_flight.as_ref() {
        state.pending_revision = (revision != in_flight.revision).then_some(revision);
        return Ok(());
    }
    let request_id = Uuid::new_v4().to_string();
    let component_sequence = state.next_sequence;
    let message = GatewayMessage {
        payload: Some(gateway_message::Payload::ConfigUpdate(ConfigUpdate {
            request_id: request_id.clone(),
            component: Some(payload),
            component_sequence,
        })),
    };
    tx.send(message)
        .await
        .map_err(|_| Status::unavailable("supervisor session outbound queue closed"))?;
    state.next_sequence = state.next_sequence.saturating_add(1);
    state.in_flight = Some(InFlightUpdate {
        request_id,
        component_sequence,
        revision,
        sent_at: Instant::now(),
    });
    state.pending_revision = None;
    Ok(())
}

// ---------------------------------------------------------------------------
// RelayStream gRPC handler
// ---------------------------------------------------------------------------

/// Size of chunks read from the gateway-side `DuplexStream` when forwarding
/// bytes back to the supervisor over the gRPC response stream.
const RELAY_STREAM_CHUNK_SIZE: usize = 16 * 1024;

type RelayStreamResponse = Response<
    Pin<Box<dyn tokio_stream::Stream<Item = Result<RelayFrame, Status>> + Send + 'static>>,
>;

/// Handle a `RelayStream` RPC from a supervisor.
///
/// The first inbound `RelayFrame` must carry a `RelayInit` identifying the
/// pending relay; subsequent frames carry raw bytes forward to the
/// gateway-side waiter. Bytes flowing the other way are chunked and sent as
/// `RelayFrame::data` messages back over the response stream.
pub async fn handle_relay_stream(
    registry: &SupervisorSessionRegistry,
    request: Request<tonic::Streaming<RelayFrame>>,
) -> Result<RelayStreamResponse, Status> {
    handle_relay_stream_inner(registry, None, request).await
}

pub async fn handle_relay_stream_for_state(
    state: &Arc<ServerState>,
    request: Request<tonic::Streaming<RelayFrame>>,
) -> Result<RelayStreamResponse, Status> {
    handle_relay_stream_inner(&state.supervisor_sessions, Some(Arc::clone(state)), request).await
}

async fn handle_relay_stream_inner(
    registry: &SupervisorSessionRegistry,
    state: Option<Arc<ServerState>>,
    request: Request<tonic::Streaming<RelayFrame>>,
) -> Result<RelayStreamResponse, Status> {
    let principal = request.extensions().get::<Principal>().cloned();
    let mut inbound = request.into_inner();

    // First frame must identify the channel.
    let first = inbound
        .message()
        .await?
        .ok_or_else(|| Status::invalid_argument("empty RelayStream"))?;
    let channel_id = match first.payload {
        Some(openshell_core::proto::relay_frame::Payload::Init(RelayInit { channel_id }))
            if !channel_id.is_empty() =>
        {
            channel_id
        }
        _ => {
            return Err(Status::invalid_argument(
                "first RelayFrame must be init with non-empty channel_id",
            ));
        }
    };

    // Claim the pending relay. Consumes the entry — it cannot be reused.
    let claimed = registry.claim_relay(&channel_id, principal.as_ref())?;
    let sandbox_id = claimed.sandbox_id;
    let supervisor_side = claimed.stream;
    info!(channel_id = %channel_id, sandbox_id = %sandbox_id, "relay stream: claimed pending relay, bridging");

    let (mut read_half, mut write_half) = tokio::io::split(supervisor_side);

    // Supervisor → gateway: drain `inbound` and write to the DuplexStream.
    let channel_id_in = channel_id.clone();
    let sandbox_id_in = sandbox_id;
    let state_in = state.clone();
    tokio::spawn(async move {
        loop {
            match inbound.message().await {
                Ok(Some(frame)) => {
                    let Some(openshell_core::proto::relay_frame::Payload::Data(data)) =
                        frame.payload
                    else {
                        warn!(channel_id = %channel_id_in, "relay stream: received non-data frame after init");
                        break;
                    };
                    if data.is_empty() {
                        continue;
                    }
                    if let Err(e) =
                        tokio::io::AsyncWriteExt::write_all(&mut write_half, &data).await
                    {
                        warn!(channel_id = %channel_id_in, error = %e, "relay stream: write to duplex failed");
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    if let Some(state) = state_in.as_ref()
                        && expected_transport_close_during_sandbox_teardown(
                            state,
                            &sandbox_id_in,
                            &e,
                        )
                        .await
                    {
                        info!(
                            sandbox_id = %sandbox_id_in,
                            channel_id = %channel_id_in,
                            error = %e,
                            "relay stream: expected transport close during sandbox teardown"
                        );
                    } else {
                        warn!(sandbox_id = %sandbox_id_in, channel_id = %channel_id_in, error = %e, "relay stream: inbound errored");
                    }
                    break;
                }
            }
        }
        // Best-effort half-close on the write side so the reader sees EOF.
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut write_half).await;
    });

    // Gateway → supervisor: read the DuplexStream and emit RelayFrame::data messages.
    let (out_tx, out_rx) = mpsc::channel::<Result<RelayFrame, Status>>(16);
    let channel_id_out = channel_id;
    tokio::spawn(async move {
        let mut buf = vec![0u8; RELAY_STREAM_CHUNK_SIZE];
        loop {
            match tokio::io::AsyncReadExt::read(&mut read_half, &mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = RelayFrame {
                        payload: Some(openshell_core::proto::relay_frame::Payload::Data(
                            buf[..n].to_vec(),
                        )),
                    };
                    if out_tx.send(Ok(chunk)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    warn!(channel_id = %channel_id_out, error = %e, "relay stream: read from duplex failed");
                    break;
                }
            }
        }
    });

    let stream = ReceiverStream::new(out_rx);
    let stream: Pin<
        Box<dyn tokio_stream::Stream<Item = Result<RelayFrame, Status>> + Send + 'static>,
    > = Box::pin(stream);
    Ok(Response::new(stream))
}

fn expected_transport_close_during_shutdown(status: &Status, terminating: bool) -> bool {
    terminating && is_expected_transport_close_status(status)
}

fn sandbox_proto_is_terminating(sandbox: &Sandbox) -> bool {
    SandboxPhase::try_from(sandbox.phase()).ok() == Some(SandboxPhase::Deleting)
        || sandbox
            .metadata
            .as_ref()
            .is_some_and(|metadata| metadata.deletion_timestamp_ms != 0)
}

async fn sandbox_is_terminating_or_gone(state: &Arc<ServerState>, sandbox_id: &str) -> bool {
    match state.store.get_message::<Sandbox>(sandbox_id).await {
        Ok(Some(sandbox)) => sandbox_proto_is_terminating(&sandbox),
        Ok(None) => true,
        Err(err) => {
            debug!(
                sandbox_id,
                error = %err,
                "failed to inspect sandbox state while classifying transport close"
            );
            false
        }
    }
}

async fn expected_transport_close_during_sandbox_teardown(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    status: &Status,
) -> bool {
    expected_transport_close_during_shutdown(
        status,
        sandbox_is_terminating_or_gone(state, sandbox_id).await,
    )
}

async fn expected_transport_close_during_session_teardown(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    status: &Status,
) -> bool {
    let session_no_longer_current = !state
        .supervisor_sessions
        .is_current_session(sandbox_id, session_id);
    expected_transport_close_during_shutdown(
        status,
        session_no_longer_current || sandbox_is_terminating_or_gone(state, sandbox_id).await,
    )
}

// ---------------------------------------------------------------------------
// ConnectSupervisor gRPC handler
// ---------------------------------------------------------------------------

pub async fn handle_connect_supervisor(
    state: &Arc<ServerState>,
    request: Request<tonic::Streaming<SupervisorMessage>>,
) -> Result<
    Response<
        Pin<Box<dyn tokio_stream::Stream<Item = Result<GatewayMessage, Status>> + Send + 'static>>,
    >,
    Status,
> {
    let principal = request.extensions().get::<Principal>().cloned();
    let mut inbound = request.into_inner();

    // Step 1: Wait for SupervisorHello.
    let hello = match inbound.message().await? {
        Some(msg) => match msg.payload {
            Some(supervisor_message::Payload::Hello(hello)) => hello,
            _ => return Err(Status::invalid_argument("expected SupervisorHello")),
        },
        None => return Err(Status::invalid_argument("stream closed before hello")),
    };

    let sandbox_id = hello.sandbox_id.clone();
    if sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }
    if let Some(principal) = principal.as_ref() {
        crate::auth::guard::ensure_sandbox_principal_scope(principal, &sandbox_id)?;
    }
    let sandbox = require_persisted_sandbox(&state.store, &sandbox_id).await?;

    let (sandbox_config, provider_environment, inference_bundle) = tokio::try_join!(
        crate::grpc::policy::build_sandbox_config_snapshot(state, &sandbox),
        crate::grpc::policy::build_provider_environment_snapshot(state, &sandbox, true),
        crate::inference::build_inference_bundle_snapshot(state, &sandbox),
    )?;
    let bootstrap = ConfigBootstrap {
        sandbox_config: Some(sandbox_config),
        provider_environment: Some(provider_environment),
        inference_bundle: Some(inference_bundle),
    };
    let delivery = DesiredStateDelivery::new(&bootstrap)?;

    let session_id = Uuid::new_v4().to_string();
    info!(
        sandbox_id = %sandbox_id,
        session_id = %session_id,
        instance_id = %hello.instance_id,
        "supervisor session: accepted"
    );

    // Step 2: Create and register the outbound channel.
    let (tx, rx) = mpsc::channel::<GatewayMessage>(64);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let superseded = state.supervisor_sessions.register(
        sandbox_id.clone(),
        session_id.clone(),
        tx.clone(),
        shutdown_tx,
    );
    if superseded {
        info!(
            sandbox_id = %sandbox_id,
            session_id = %session_id,
            "supervisor session: superseded previous session"
        );
    }

    // Step 3: Send SessionAccepted.
    let accepted = GatewayMessage {
        payload: Some(gateway_message::Payload::SessionAccepted(SessionAccepted {
            session_id: session_id.clone(),
            heartbeat_interval_secs: HEARTBEAT_INTERVAL_SECS,
            bootstrap: Some(bootstrap),
        })),
    };
    if tx.send(accepted).await.is_err() {
        // Only evict ourselves — a faster reconnect may already have
        // superseded this registration.
        state
            .supervisor_sessions
            .remove_if_current(&sandbox_id, &session_id);
        return Err(Status::internal("failed to send session accepted"));
    }

    if superseded {
        state
            .supervisor_sessions
            .replay_pending_relays(&sandbox_id, &tx)
            .await;
    }

    // Step 4: Spawn the session loop that reads inbound messages.
    let state_clone = Arc::clone(state);
    let sandbox_id_clone = sandbox_id.clone();
    tokio::spawn(async move {
        run_session_loop(
            &state_clone,
            &sandbox_id_clone,
            &session_id,
            &tx,
            delivery,
            &mut inbound,
            shutdown_rx,
        )
        .await;
        let still_ours = state_clone
            .supervisor_sessions
            .remove_if_current(&sandbox_id_clone, &session_id);
        if still_ours {
            info!(sandbox_id = %sandbox_id_clone, session_id = %session_id, "supervisor session: ended");
            state_clone
                .telemetry
                .sandbox_session_disconnected(&sandbox_id_clone);
            if let Err(err) = state_clone
                .compute
                .supervisor_session_disconnected(&sandbox_id_clone)
                .await
            {
                warn!(
                    sandbox_id = %sandbox_id_clone,
                    session_id = %session_id,
                    error = %err,
                    "supervisor session: failed to mark sandbox disconnected"
                );
            }
        } else {
            info!(sandbox_id = %sandbox_id_clone, session_id = %session_id, "supervisor session: ended (already superseded)");
        }
    });

    // Return the outbound stream.
    let stream = ReceiverStream::new(rx);
    let stream: Pin<
        Box<dyn tokio_stream::Stream<Item = Result<GatewayMessage, Status>> + Send + 'static>,
    > = Box::pin(tokio_stream::StreamExt::map(stream, Ok));

    Ok(Response::new(stream))
}

pub async fn handle_report_main_process_exit(
    state: &Arc<ServerState>,
    request: Request<ReportMainProcessExitRequest>,
) -> Result<Response<ReportMainProcessExitResponse>, Status> {
    let principal = request.extensions().get::<Principal>().cloned();
    let report = request.into_inner();
    if report.sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }
    if report.instance_id.is_empty() {
        return Err(Status::invalid_argument("instance_id is required"));
    }
    if let Some(principal) = principal.as_ref() {
        crate::auth::guard::ensure_sandbox_principal_scope(principal, &report.sandbox_id)?;
    }
    state
        .compute
        .main_process_exited(&report.sandbox_id, &report.instance_id, report.exit_code)
        .await
        .map_err(Status::failed_precondition)?;
    Ok(Response::new(ReportMainProcessExitResponse {}))
}

async fn run_session_loop(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    tx: &mpsc::Sender<GatewayMessage>,
    mut delivery: DesiredStateDelivery,
    inbound: &mut tonic::Streaming<SupervisorMessage>,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let heartbeat_interval = Duration::from_secs(u64::from(HEARTBEAT_INTERVAL_SECS));
    let mut heartbeat_timer = tokio::time::interval(heartbeat_interval);
    // Skip the first immediate tick.
    heartbeat_timer.tick().await;
    let bootstrap_timeout = tokio::time::sleep(BOOTSTRAP_TIMEOUT);
    tokio::pin!(bootstrap_timeout);
    let mut sandbox_updates = state.sandbox_watch_bus.subscribe(sandbox_id);
    let mut global_updates = state.sandbox_watch_bus.subscribe_all();
    let mut reconciliation_timer = tokio::time::interval(reconciliation_interval(sandbox_id));
    reconciliation_timer.tick().await;

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                info!(sandbox_id = %sandbox_id, session_id = %session_id, "supervisor session: superseded by reconnect, shutting down");
                break;
            }
            msg = inbound.message() => {
                match msg {
                    Ok(Some(msg)) => {
                        let is_update_result = matches!(
                            &msg.payload,
                            Some(supervisor_message::Payload::ConfigUpdateResult(_))
                        );
                        if !handle_supervisor_message(
                            state,
                            sandbox_id,
                            session_id,
                            msg,
                            &mut delivery,
                        )
                        .await
                        {
                            break;
                        }
                        if is_update_result
                            && delivery.has_pending_update()
                            && let Err(error) = reconcile_desired_state(
                                state,
                                sandbox_id,
                                tx,
                                &mut delivery,
                            )
                            .await
                        {
                            warn!(
                                sandbox_id = %sandbox_id,
                                session_id = %session_id,
                                error = %error,
                                "supervisor session: desired-state reconciliation failed"
                            );
                        }
                    }
                    Ok(None) => {
                        info!(sandbox_id = %sandbox_id, session_id = %session_id, "supervisor session: stream closed by supervisor");
                        break;
                    }
                    Err(e) => {
                        if expected_transport_close_during_session_teardown(
                            state,
                            sandbox_id,
                            session_id,
                            &e,
                        )
                        .await
                        {
                            info!(
                                sandbox_id = %sandbox_id,
                                session_id = %session_id,
                                error = %e,
                                "supervisor session: expected transport close during teardown"
                            );
                        } else {
                            warn!(sandbox_id = %sandbox_id, session_id = %session_id, error = %e, "supervisor session: stream error");
                        }
                        break;
                    }
                }
            }
            update = sandbox_updates.recv(),
                if state.supervisor_sessions.is_initialized(sandbox_id, session_id) =>
            {
                if update.is_ok()
                    && let Err(error) = reconcile_desired_state(
                        state,
                        sandbox_id,
                        tx,
                        &mut delivery,
                    )
                    .await
                {
                    warn!(
                        sandbox_id = %sandbox_id,
                        session_id = %session_id,
                        error = %error,
                        "supervisor session: desired-state notification failed"
                    );
                }
            }
            update = global_updates.recv(),
                if state.supervisor_sessions.is_initialized(sandbox_id, session_id) =>
            {
                if update.is_ok()
                    && let Err(error) = reconcile_desired_state(
                        state,
                        sandbox_id,
                        tx,
                        &mut delivery,
                    )
                    .await
                {
                    warn!(
                        sandbox_id = %sandbox_id,
                        session_id = %session_id,
                        error = %error,
                        "supervisor session: global desired-state notification failed"
                    );
                }
            }
            _ = reconciliation_timer.tick(),
                if state.supervisor_sessions.is_initialized(sandbox_id, session_id) =>
            {
                if let Err(error) = reconcile_desired_state(
                    state,
                    sandbox_id,
                    tx,
                    &mut delivery,
                )
                .await
                {
                    warn!(
                        sandbox_id = %sandbox_id,
                        session_id = %session_id,
                        error = %error,
                        "supervisor session: periodic desired-state reconciliation failed"
                    );
                }
            }
            () = &mut bootstrap_timeout,
                if !state.supervisor_sessions.is_initialized(sandbox_id, session_id) =>
            {
                warn!(
                    sandbox_id = %sandbox_id,
                    session_id = %session_id,
                    "supervisor session: bootstrap result timed out"
                );
                if let Err(error) = state
                    .compute
                    .supervisor_bootstrap_failed(
                        sandbox_id,
                        "Supervisor configuration bootstrap timed out",
                    )
                    .await
                {
                    warn!(sandbox_id = %sandbox_id, session_id = %session_id, error = %error, "supervisor session: failed to persist bootstrap timeout");
                }
                break;
            }
            _ = heartbeat_timer.tick() => {
                let hb = GatewayMessage {
                    payload: Some(gateway_message::Payload::Heartbeat(
                        openshell_core::proto::GatewayHeartbeat {},
                    )),
                };
                if tx.send(hb).await.is_err() {
                    info!(sandbox_id = %sandbox_id, session_id = %session_id, "supervisor session: outbound channel closed");
                    break;
                }
            }
        }
    }
}

async fn handle_supervisor_message(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    msg: SupervisorMessage,
    delivery: &mut DesiredStateDelivery,
) -> bool {
    match msg.payload {
        Some(supervisor_message::Payload::Heartbeat(_)) => {
            // Heartbeat received — nothing to do for now.
        }
        Some(supervisor_message::Payload::BootstrapResult(result)) => {
            if let Err(error) = validate_bootstrap_result(&result) {
                warn!(
                    sandbox_id = %sandbox_id,
                    session_id = %session_id,
                    error = %error,
                    "supervisor session: bootstrap failed"
                );
                if let Err(persist_error) = state
                    .compute
                    .supervisor_bootstrap_failed(sandbox_id, &error)
                    .await
                {
                    warn!(sandbox_id = %sandbox_id, session_id = %session_id, error = %persist_error, "supervisor session: failed to persist bootstrap failure");
                }
                return false;
            }
            for (component, component_label, outcome) in [
                (
                    "ProviderEnvironment",
                    "provider environment",
                    result.provider_environment_outcome,
                ),
                (
                    "InferenceBundle",
                    "inference bundle",
                    result.inference_bundle_outcome,
                ),
            ] {
                if ConfigApplyOutcome::try_from(outcome).ok() == Some(ConfigApplyOutcome::Degraded)
                {
                    let message = sanitize_update_error(&result.error, component_label);
                    if let Err(error) = state
                        .compute
                        .supervisor_config_update_result(
                            sandbox_id,
                            component,
                            false,
                            "DesiredStateBootstrapDegraded",
                            &message,
                        )
                        .await
                    {
                        warn!(sandbox_id = %sandbox_id, session_id = %session_id, error = %error, "supervisor session: failed to persist degraded bootstrap component");
                    }
                }
            }
            state
                .supervisor_sessions
                .mark_initialized(sandbox_id, session_id);
            info!(
                sandbox_id = %sandbox_id,
                session_id = %session_id,
                "supervisor session: bootstrap applied"
            );
        }
        Some(supervisor_message::Payload::RuntimeReady(ready)) => {
            if ready.instance_id.is_empty() {
                warn!(
                    sandbox_id = %sandbox_id,
                    session_id = %session_id,
                    "supervisor session: runtime-ready signal omitted instance_id"
                );
                return false;
            }
            if !state
                .supervisor_sessions
                .is_initialized(sandbox_id, session_id)
            {
                warn!(
                    sandbox_id = %sandbox_id,
                    session_id = %session_id,
                    "supervisor session: runtime-ready arrived before bootstrap result"
                );
                return false;
            }
            let became_ready = state
                .supervisor_sessions
                .mark_runtime_ready(sandbox_id, session_id);
            if became_ready {
                mark_supervisor_ready(state, sandbox_id, session_id, &ready.instance_id).await;
            }
        }
        Some(supervisor_message::Payload::ConfigUpdateResult(result)) => {
            match delivery.handle_result(&result) {
                Ok(Some(applied)) => {
                    let (component, component_label) = match applied.component {
                        DesiredStateComponent::SandboxConfig => ("SandboxConfig", "sandbox config"),
                        DesiredStateComponent::ProviderEnvironment => {
                            ("ProviderEnvironment", "provider environment")
                        }
                        DesiredStateComponent::InferenceBundle => {
                            ("InferenceBundle", "inference bundle")
                        }
                    };
                    let healthy = matches!(
                        applied.outcome,
                        ConfigApplyOutcome::Applied
                            | ConfigApplyOutcome::IgnoredDuplicate
                            | ConfigApplyOutcome::RetainedLocalOverride
                    );
                    let reason = if healthy {
                        "DesiredStateApplied"
                    } else if applied.outcome == ConfigApplyOutcome::Degraded {
                        "DesiredStateDegraded"
                    } else {
                        "DesiredStateApplyFailed"
                    };
                    let message = if healthy {
                        format!("Latest {component_label} desired state applied")
                    } else {
                        sanitize_update_error(&result.error, component_label)
                    };
                    if let Err(error) = state
                        .compute
                        .supervisor_config_update_result(
                            sandbox_id, component, healthy, reason, &message,
                        )
                        .await
                    {
                        warn!(
                            sandbox_id = %sandbox_id,
                            session_id = %session_id,
                            request_id = %result.request_id,
                            error = %error,
                            "supervisor session: failed to persist config update result"
                        );
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    warn!(
                        sandbox_id = %sandbox_id,
                        session_id = %session_id,
                        request_id = %result.request_id,
                        error = %error,
                        "supervisor session: invalid config update result"
                    );
                    return false;
                }
            }
        }
        Some(supervisor_message::Payload::RelayOpenResult(result)) => {
            if result.success {
                info!(
                    sandbox_id = %sandbox_id,
                    session_id = %session_id,
                    channel_id = %result.channel_id,
                    "supervisor session: relay opened successfully"
                );
            } else {
                let failed = state
                    .supervisor_sessions
                    .fail_pending_relay(&result.channel_id, result.error.clone());
                warn!(
                    sandbox_id = %sandbox_id,
                    session_id = %session_id,
                    channel_id = %result.channel_id,
                    error = %result.error,
                    pending_relay_failed = failed,
                    "supervisor session: relay open failed"
                );
            }
        }
        Some(supervisor_message::Payload::RelayClose(close)) => {
            info!(
                sandbox_id = %sandbox_id,
                session_id = %session_id,
                channel_id = %close.channel_id,
                reason = %close.reason,
                "supervisor session: relay closed by supervisor"
            );
        }
        _ => {
            warn!(
                sandbox_id = %sandbox_id,
                session_id = %session_id,
                "supervisor session: unexpected message type"
            );
        }
    }
    true
}

fn validate_bootstrap_result(result: &ConfigBootstrapResult) -> Result<(), String> {
    if ConfigBootstrapStatus::try_from(result.status).ok() != Some(ConfigBootstrapStatus::Ready) {
        return Err(sanitize_session_error(&result.error));
    }
    let config_outcome = ConfigApplyOutcome::try_from(result.sandbox_config_outcome).ok();
    if !matches!(
        config_outcome,
        Some(
            ConfigApplyOutcome::Applied
                | ConfigApplyOutcome::IgnoredDuplicate
                | ConfigApplyOutcome::RetainedLocalOverride
        )
    ) {
        return Err("sandbox_config: invalid required bootstrap outcome".to_string());
    }
    for (component, outcome) in [
        ("provider_environment", result.provider_environment_outcome),
        ("inference_bundle", result.inference_bundle_outcome),
    ] {
        if !matches!(
            ConfigApplyOutcome::try_from(outcome).ok(),
            Some(
                ConfigApplyOutcome::Applied
                    | ConfigApplyOutcome::IgnoredDuplicate
                    | ConfigApplyOutcome::RetainedLocalOverride
                    | ConfigApplyOutcome::Degraded
            )
        ) {
            return Err(format!("{component}: invalid bootstrap outcome"));
        }
    }
    Ok(())
}

fn sanitize_session_error(error: &str) -> String {
    const MAX_ERROR_BYTES: usize = 1024;
    let mut sanitized: String = error
        .chars()
        .filter(|character| !character.is_control())
        .collect();
    if sanitized.len() > MAX_ERROR_BYTES {
        let mut boundary = MAX_ERROR_BYTES;
        while !sanitized.is_char_boundary(boundary) {
            boundary -= 1;
        }
        sanitized.truncate(boundary);
    }
    if sanitized.is_empty() {
        "bootstrap rejected without an error".to_string()
    } else {
        sanitized
    }
}

fn sanitize_update_error(error: &str, component: &str) -> String {
    let sanitized = sanitize_session_error(error);
    if error.is_empty() {
        format!("Latest {component} desired state was not applied")
    } else {
        sanitized
    }
}

async fn mark_supervisor_ready(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    instance_id: &str,
) {
    if let Err(err) = state
        .compute
        .supervisor_session_connected(sandbox_id, instance_id)
        .await
    {
        warn!(
            sandbox_id = %sandbox_id,
            session_id = %session_id,
            error = %err,
            "supervisor session: failed to mark sandbox ready"
        );
    } else {
        state.telemetry.sandbox_session_connected(sandbox_id);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::{Identity, IdentityProvider};
    use crate::auth::principal::{SandboxIdentitySource, SandboxPrincipal, UserPrincipal};
    use crate::persistence::Store;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn test_store() -> Arc<Store> {
        Arc::new(crate::persistence::test_store().await)
    }

    /// Returns a shutdown sender with its receiver immediately dropped. Tests
    /// that don't observe the shutdown signal can use this to satisfy the
    /// `register` signature without the receiver noise.
    fn make_shutdown() -> oneshot::Sender<()> {
        oneshot::channel::<()>().0
    }

    fn sandbox_record(id: &str, name: &str) -> Sandbox {
        Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: id.to_string(),
                name: name.to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            ..Default::default()
        }
    }

    fn pending_relay(
        sandbox_id: &str,
        relay_tx: RelayStreamSender,
        created_at: Instant,
    ) -> PendingRelay {
        PendingRelay {
            sender: relay_tx,
            sandbox_id: sandbox_id.to_string(),
            relay_open: RelayOpen {
                channel_id: "ch-test".to_string(),
                target: Some(relay_open::Target::Ssh(SshRelayTarget {})),
                service_id: String::new(),
            },
            created_at,
        }
    }

    fn sandbox_principal(sandbox_id: &str) -> Principal {
        Principal::Sandbox(SandboxPrincipal {
            sandbox_id: sandbox_id.to_string(),
            source: SandboxIdentitySource::BootstrapJwt {
                issuer: "openshell-gateway:test".to_string(),
            },
            trust_domain: Some("openshell".to_string()),
        })
    }

    fn user_principal(subject: &str) -> Principal {
        Principal::User(UserPrincipal {
            identity: Identity {
                subject: subject.to_string(),
                display_name: None,
                roles: vec![],
                scopes: vec![],
                provider: IdentityProvider::Oidc,
            },
        })
    }

    fn desired_state_bootstrap() -> ConfigBootstrap {
        ConfigBootstrap {
            sandbox_config: Some(openshell_core::proto::SandboxConfigSnapshot {
                config_revision: 11,
                ..Default::default()
            }),
            provider_environment: Some(openshell_core::proto::ProviderEnvironmentSnapshot {
                provider_env_revision: 22,
                ..Default::default()
            }),
            inference_bundle: Some(openshell_core::proto::InferenceBundleSnapshot {
                revision: "inference-33".to_string(),
                ..Default::default()
            }),
        }
    }

    fn mark_session_ready(
        registry: &SupervisorSessionRegistry,
        sandbox_id: &str,
        session_id: &str,
    ) {
        assert!(!registry.mark_initialized(sandbox_id, session_id));
        assert!(registry.mark_runtime_ready(sandbox_id, session_id));
    }

    #[test]
    fn readiness_requires_initialized_and_runtime_ready() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, _rx) = mpsc::channel(1);
        registry.register(
            "sbx".to_string(),
            "session".to_string(),
            tx,
            make_shutdown(),
        );

        assert!(!registry.has_ready_session("sbx"));
        assert!(!registry.mark_initialized("sbx", "session"));
        assert!(!registry.has_ready_session("sbx"));
        assert!(registry.mark_runtime_ready("sbx", "session"));
        assert!(registry.has_ready_session("sbx"));
    }

    #[test]
    fn desired_state_delivery_uses_bootstrap_fingerprints() {
        let delivery = DesiredStateDelivery::new(&desired_state_bootstrap()).unwrap();

        assert_eq!(delivery.sandbox_config.applied_revision, "11");
        assert_eq!(delivery.provider_environment.applied_revision, "22");
        assert_eq!(delivery.inference_bundle.applied_revision, "inference-33");
    }

    #[tokio::test]
    async fn component_delivery_coalesces_while_one_update_is_in_flight() {
        let mut delivery = DesiredStateDelivery::new(&desired_state_bootstrap()).unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let payload = || {
            config_update::Component::SandboxConfig(SandboxConfigUpdate {
                snapshot: Some(openshell_core::proto::SandboxConfigSnapshot::default()),
            })
        };

        send_component_update(
            &tx,
            DesiredStateComponent::SandboxConfig,
            "12".to_string(),
            payload(),
            &mut delivery,
        )
        .await
        .unwrap();
        send_component_update(
            &tx,
            DesiredStateComponent::SandboxConfig,
            "13".to_string(),
            payload(),
            &mut delivery,
        )
        .await
        .unwrap();

        let first = rx.recv().await.unwrap();
        assert!(rx.try_recv().is_err());
        assert!(delivery.has_pending_update());
        let gateway_message::Payload::ConfigUpdate(first) = first.payload.unwrap() else {
            panic!("expected config update");
        };
        assert_eq!(first.component_sequence, 1);
        let applied = delivery
            .handle_result(&ConfigUpdateResult {
                request_id: first.request_id,
                component_sequence: first.component_sequence,
                outcome: ConfigApplyOutcome::Applied as i32,
                error: String::new(),
            })
            .unwrap()
            .unwrap();
        assert_eq!(applied.component, DesiredStateComponent::SandboxConfig);
        assert!(delivery.has_pending_update());

        send_component_update(
            &tx,
            DesiredStateComponent::SandboxConfig,
            "13".to_string(),
            payload(),
            &mut delivery,
        )
        .await
        .unwrap();
        let second = rx.recv().await.unwrap();
        let gateway_message::Payload::ConfigUpdate(second) = second.payload.unwrap() else {
            panic!("expected config update");
        };
        assert_eq!(second.component_sequence, 2);
        assert!(!delivery.has_pending_update());
    }

    #[tokio::test]
    async fn failed_update_waits_for_reconciliation_before_retrying() {
        let mut delivery = DesiredStateDelivery::new(&desired_state_bootstrap()).unwrap();
        let (tx, mut rx) = mpsc::channel(2);
        let payload = || {
            config_update::Component::SandboxConfig(SandboxConfigUpdate {
                snapshot: Some(openshell_core::proto::SandboxConfigSnapshot::default()),
            })
        };

        send_component_update(
            &tx,
            DesiredStateComponent::SandboxConfig,
            "12".to_string(),
            payload(),
            &mut delivery,
        )
        .await
        .unwrap();
        let first = rx.recv().await.unwrap();
        let gateway_message::Payload::ConfigUpdate(first) = first.payload.unwrap() else {
            panic!("expected config update");
        };
        delivery
            .handle_result(&ConfigUpdateResult {
                request_id: first.request_id,
                component_sequence: first.component_sequence,
                outcome: ConfigApplyOutcome::Failed as i32,
                error: "rejected".to_string(),
            })
            .unwrap();

        assert!(!delivery.has_pending_update());
        assert_eq!(delivery.sandbox_config.applied_revision, "11");
        assert!(rx.try_recv().is_err());

        send_component_update(
            &tx,
            DesiredStateComponent::SandboxConfig,
            "12".to_string(),
            payload(),
            &mut delivery,
        )
        .await
        .unwrap();
        let retry = rx.recv().await.unwrap();
        let gateway_message::Payload::ConfigUpdate(retry) = retry.payload.unwrap() else {
            panic!("expected retry update");
        };
        assert_eq!(retry.component_sequence, 2);
    }

    #[test]
    fn mismatched_component_sequence_is_a_protocol_error() {
        let mut delivery = DesiredStateDelivery::new(&desired_state_bootstrap()).unwrap();
        delivery.sandbox_config.in_flight = Some(InFlightUpdate {
            request_id: "request".to_string(),
            component_sequence: 4,
            revision: "12".to_string(),
            sent_at: Instant::now(),
        });

        let error = delivery
            .handle_result(&ConfigUpdateResult {
                request_id: "request".to_string(),
                component_sequence: 5,
                outcome: ConfigApplyOutcome::Applied as i32,
                error: String::new(),
            })
            .unwrap_err();
        assert!(error.contains("component_sequence mismatch"));
        assert!(delivery.sandbox_config.in_flight.is_some());
    }

    #[test]
    fn bootstrap_allows_degraded_optional_components_only() {
        let optional_degraded = ConfigBootstrapResult {
            status: ConfigBootstrapStatus::Ready as i32,
            sandbox_config_outcome: ConfigApplyOutcome::Applied as i32,
            provider_environment_outcome: ConfigApplyOutcome::Degraded as i32,
            inference_bundle_outcome: ConfigApplyOutcome::RetainedLocalOverride as i32,
            error: String::new(),
        };
        assert!(validate_bootstrap_result(&optional_degraded).is_ok());

        let required_degraded = ConfigBootstrapResult {
            sandbox_config_outcome: ConfigApplyOutcome::Degraded as i32,
            ..optional_degraded
        };
        assert!(validate_bootstrap_result(&required_degraded).is_err());
    }

    #[test]
    fn reconciliation_interval_stays_within_twenty_percent() {
        for sandbox_id in ["a", "sandbox-1", "sandbox-2", "a-longer-sandbox-id"] {
            let interval = reconciliation_interval(sandbox_id);
            assert!((24..=36).contains(&interval.as_secs()));
        }
    }

    // ---- registry: register / remove ----

    #[test]
    fn registry_register_and_lookup() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, _rx) = mpsc::channel(1);

        assert!(!registry.register(
            "sandbox-1".to_string(),
            "s1".to_string(),
            tx,
            make_shutdown(),
        ));

        let sessions = registry.sessions.lock().unwrap();
        assert!(sessions.contains_key("sandbox-1"));
    }

    #[test]
    fn registry_supersedes_previous_session() {
        let registry = SupervisorSessionRegistry::new();
        let (tx1, _rx1) = mpsc::channel(1);
        let (tx2, _rx2) = mpsc::channel(1);

        assert!(!registry.register(
            "sandbox-1".to_string(),
            "s1".to_string(),
            tx1,
            make_shutdown(),
        ));
        assert!(registry.register(
            "sandbox-1".to_string(),
            "s2".to_string(),
            tx2,
            make_shutdown(),
        ));
    }

    #[test]
    fn registry_remove() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, _rx) = mpsc::channel(1);
        registry.register(
            "sandbox-1".to_string(),
            "s1".to_string(),
            tx,
            make_shutdown(),
        );

        registry.remove("sandbox-1");
        let sessions = registry.sessions.lock().unwrap();
        assert!(!sessions.contains_key("sandbox-1"));
    }

    #[test]
    fn remove_if_current_removes_matching_session() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, _rx) = mpsc::channel(1);
        registry.register("sbx".to_string(), "s1".to_string(), tx, make_shutdown());

        assert!(registry.remove_if_current("sbx", "s1"));
        assert!(!registry.sessions.lock().unwrap().contains_key("sbx"));
    }

    #[test]
    fn remove_if_current_ignores_stale_session_id() {
        let registry = SupervisorSessionRegistry::new();
        let (tx_old, _rx_old) = mpsc::channel(1);
        let (tx_new, _rx_new) = mpsc::channel(1);

        // Old session registers, then is superseded by a new session.
        registry.register(
            "sbx".to_string(),
            "s-old".to_string(),
            tx_old,
            make_shutdown(),
        );
        registry.register(
            "sbx".to_string(),
            "s-new".to_string(),
            tx_new,
            make_shutdown(),
        );

        // Cleanup from the old session task runs late. It must NOT evict the
        // newly registered session.
        assert!(!registry.remove_if_current("sbx", "s-old"));
        let sessions = registry.sessions.lock().unwrap();
        assert!(
            sessions.contains_key("sbx"),
            "new session must still be registered"
        );
        assert_eq!(sessions.get("sbx").unwrap().session_id, "s-new");
    }

    #[test]
    fn remove_if_current_unknown_sandbox_is_noop() {
        let registry = SupervisorSessionRegistry::new();
        assert!(!registry.remove_if_current("sbx-does-not-exist", "s1"));
    }

    // ---- open_relay: happy path and wait semantics ----

    #[tokio::test]
    async fn open_relay_sends_relay_open_to_registered_session() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, mut rx) = mpsc::channel(4);
        registry.register("sbx".to_string(), "s1".to_string(), tx, make_shutdown());
        mark_session_ready(&registry, "sbx", "s1");

        let (channel_id, _relay_rx) = registry
            .open_relay("sbx", Duration::from_secs(1))
            .await
            .expect("open_relay should succeed when session is live");

        let msg = rx.recv().await.expect("relay open should be delivered");
        match msg.payload {
            Some(gateway_message::Payload::RelayOpen(open)) => {
                assert_eq!(open.channel_id, channel_id);
                assert!(matches!(open.target, Some(relay_open::Target::Ssh(_))));
            }
            other => panic!("expected RelayOpen, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn open_relay_times_out_without_session() {
        let registry = SupervisorSessionRegistry::new();
        let err = registry
            .open_relay("missing", Duration::from_millis(50))
            .await
            .expect_err("open_relay should time out");
        assert_eq!(err.code(), tonic::Code::Unavailable);
    }

    #[tokio::test]
    async fn open_relay_waits_for_session_to_appear() {
        let registry = Arc::new(SupervisorSessionRegistry::new());
        let registry_for_register = Arc::clone(&registry);

        // Register the session after a small delay, shorter than the wait.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let (tx, mut rx) = mpsc::channel::<GatewayMessage>(4);
            // Keep the receiver alive so the send in open_relay succeeds.
            tokio::spawn(async move { while rx.recv().await.is_some() {} });
            registry_for_register.register(
                "sbx".to_string(),
                "s1".to_string(),
                tx,
                make_shutdown(),
            );
            mark_session_ready(&registry_for_register, "sbx", "s1");
        });

        let result = registry.open_relay("sbx", Duration::from_secs(2)).await;
        assert!(
            result.is_ok(),
            "open_relay should succeed when session arrives mid-wait: {result:?}"
        );
    }

    #[tokio::test]
    async fn open_relay_fails_when_session_receiver_dropped() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, rx) = mpsc::channel::<GatewayMessage>(4);
        registry.register("sbx".to_string(), "s1".to_string(), tx, make_shutdown());
        mark_session_ready(&registry, "sbx", "s1");

        // Simulate the supervisor's stream going away between lookup and send:
        // the receiver held by `ReceiverStream` is dropped.
        drop(rx);

        let err = registry
            .open_relay("sbx", Duration::from_secs(1))
            .await
            .expect_err("open_relay should fail when mpsc is closed");
        assert_eq!(err.code(), tonic::Code::Unavailable);
        // The pending-relay entry must have been cleaned up on failure.
        assert!(registry.pending_relays.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn open_relay_rejects_when_global_cap_reached() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, _rx) = mpsc::channel::<GatewayMessage>(8);
        registry.register(
            "sbx-a".to_string(),
            "s-a".to_string(),
            tx.clone(),
            make_shutdown(),
        );
        registry.register("sbx-b".to_string(), "s-b".to_string(), tx, make_shutdown());
        mark_session_ready(&registry, "sbx-a", "s-a");
        mark_session_ready(&registry, "sbx-b", "s-b");

        // Pre-seed pending_relays to exactly the global cap, split across two
        // sandboxes so neither hits the per-sandbox cap first.
        {
            let mut pending = registry.pending_relays.lock().unwrap();
            for i in 0..MAX_PENDING_RELAYS {
                let (oneshot_tx, _) = oneshot::channel();
                let sandbox_id = if i % 2 == 0 { "sbx-a" } else { "sbx-b" };
                pending.insert(
                    format!("channel-{i}"),
                    pending_relay(sandbox_id, oneshot_tx, Instant::now()),
                );
            }
        }

        let err = registry
            .open_relay("sbx-a", Duration::from_millis(50))
            .await
            .expect_err("open_relay should reject once global cap is reached");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert!(err.message().contains("gateway relay capacity"));
    }

    #[tokio::test]
    async fn open_relay_rejects_when_per_sandbox_cap_reached() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, _rx) = mpsc::channel::<GatewayMessage>(8);
        registry.register("sbx".to_string(), "s".to_string(), tx, make_shutdown());
        mark_session_ready(&registry, "sbx", "s");

        {
            let mut pending = registry.pending_relays.lock().unwrap();
            for i in 0..MAX_PENDING_RELAYS_PER_SANDBOX {
                let (oneshot_tx, _) = oneshot::channel();
                pending.insert(
                    format!("channel-{i}"),
                    pending_relay("sbx", oneshot_tx, Instant::now()),
                );
            }
        }

        let err = registry
            .open_relay("sbx", Duration::from_millis(50))
            .await
            .expect_err("open_relay should reject when per-sandbox cap is reached");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert!(err.message().contains("per-sandbox relay limit"));

        // A different sandbox still has headroom.
        let (tx2, _rx2) = mpsc::channel::<GatewayMessage>(8);
        registry.register(
            "sbx-other".to_string(),
            "s-other".to_string(),
            tx2,
            make_shutdown(),
        );
        mark_session_ready(&registry, "sbx-other", "s-other");
        registry
            .open_relay("sbx-other", Duration::from_millis(50))
            .await
            .expect("different sandbox should still accept new relays");
    }

    #[tokio::test]
    async fn open_relay_uses_newest_session_after_supersede() {
        use tokio::sync::mpsc::error::TryRecvError;

        let registry = SupervisorSessionRegistry::new();
        let (tx_old, mut rx_old) = mpsc::channel::<GatewayMessage>(4);
        let (tx_new, mut rx_new) = mpsc::channel(4);

        // Hold a clone of the old sender so supersede doesn't close the old
        // channel — that way try_recv distinguishes "no message sent" from
        // "channel closed".
        let _tx_old_alive = tx_old.clone();

        registry.register(
            "sbx".to_string(),
            "s-old".to_string(),
            tx_old,
            make_shutdown(),
        );
        registry.register(
            "sbx".to_string(),
            "s-new".to_string(),
            tx_new,
            make_shutdown(),
        );
        mark_session_ready(&registry, "sbx", "s-new");

        let (_channel_id, _relay_rx) = registry
            .open_relay("sbx", Duration::from_secs(1))
            .await
            .expect("open_relay should succeed");

        let msg = rx_new
            .recv()
            .await
            .expect("new session should receive RelayOpen");
        assert!(matches!(
            msg.payload,
            Some(gateway_message::Payload::RelayOpen(_))
        ));

        // The old session must have received no messages — the channel is
        // still open but empty.
        match rx_old.try_recv() {
            Err(TryRecvError::Empty) => {}
            other => panic!("expected Empty on superseded session, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn register_signals_shutdown_to_previous_session() {
        let registry = SupervisorSessionRegistry::new();
        let (tx_old, _rx_old) = mpsc::channel::<GatewayMessage>(1);
        let (tx_new, _rx_new) = mpsc::channel::<GatewayMessage>(1);

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        registry.register("sbx".to_string(), "s-old".to_string(), tx_old, shutdown_tx);

        // Supersede with a new session — register must fire the old session's
        // shutdown signal so its task can exit and drop its tx clone.
        let superseded = registry.register(
            "sbx".to_string(),
            "s-new".to_string(),
            tx_new,
            make_shutdown(),
        );
        assert!(superseded, "second register should report supersede");

        // The old session's shutdown receiver must now resolve.
        shutdown_rx
            .await
            .expect("shutdown signal should arrive at superseded session");
    }

    #[tokio::test]
    async fn replay_pending_relays_reissues_open_to_superseding_session() {
        let registry = SupervisorSessionRegistry::new();
        let (tx_old, mut rx_old) = mpsc::channel::<GatewayMessage>(4);
        let (tx_new, mut rx_new) = mpsc::channel::<GatewayMessage>(4);

        registry.register(
            "sbx".to_string(),
            "s-old".to_string(),
            tx_old,
            make_shutdown(),
        );
        mark_session_ready(&registry, "sbx", "s-old");

        let (channel_id, _relay_rx) = registry
            .open_relay("sbx", Duration::from_secs(1))
            .await
            .expect("open_relay should succeed");

        let original = rx_old
            .recv()
            .await
            .expect("old session should receive initial RelayOpen");
        assert!(matches!(
            original.payload,
            Some(gateway_message::Payload::RelayOpen(_))
        ));

        let superseded = registry.register(
            "sbx".to_string(),
            "s-new".to_string(),
            tx_new,
            make_shutdown(),
        );
        assert!(superseded);
        mark_session_ready(&registry, "sbx", "s-new");

        registry
            .replay_pending_relays("sbx", &registry.lookup_session("sbx").unwrap())
            .await;

        let replayed = rx_new
            .recv()
            .await
            .expect("new session should receive replayed RelayOpen");
        match replayed.payload {
            Some(gateway_message::Payload::RelayOpen(open)) => {
                assert_eq!(open.channel_id, channel_id);
            }
            other => panic!("expected RelayOpen on replay, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn require_persisted_sandbox_rejects_missing_sandbox() {
        let store = test_store().await;

        let err = require_persisted_sandbox(&store, "missing")
            .await
            .expect_err("missing sandbox should be rejected");

        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn require_persisted_sandbox_accepts_existing_sandbox() {
        let store = test_store().await;
        store
            .put_message(&sandbox_record("sbx-1", "sandbox-one"))
            .await
            .expect("sandbox should persist");

        require_persisted_sandbox(&store, "sbx-1")
            .await
            .expect("persisted sandbox should be accepted");
    }

    #[test]
    fn expected_transport_close_is_nonfatal_only_during_shutdown() {
        let status = Status::unknown("h2 protocol error: error reading a body from connection");

        assert!(expected_transport_close_during_shutdown(&status, true));
        assert!(!expected_transport_close_during_shutdown(&status, false));
    }

    #[test]
    fn unexpected_transport_error_stays_fatal_during_shutdown() {
        let status = Status::internal("policy evaluation failed");

        assert!(!expected_transport_close_during_shutdown(&status, true));
    }

    #[test]
    fn sandbox_proto_terminating_detects_deleting_phase() {
        let mut sandbox = sandbox_record("sbx-1", "sandbox-one");
        sandbox.set_phase(SandboxPhase::Deleting as i32);

        assert!(sandbox_proto_is_terminating(&sandbox));
    }

    #[test]
    fn sandbox_proto_terminating_detects_deletion_timestamp() {
        let mut sandbox = sandbox_record("sbx-1", "sandbox-one");
        sandbox.metadata.as_mut().unwrap().deletion_timestamp_ms = 1;

        assert!(sandbox_proto_is_terminating(&sandbox));
    }

    #[test]
    fn sandbox_proto_running_is_not_terminating() {
        let mut sandbox = sandbox_record("sbx-1", "sandbox-one");
        sandbox.set_phase(SandboxPhase::Ready as i32);

        assert!(!sandbox_proto_is_terminating(&sandbox));
    }

    // ---- claim_relay: expiry, drop, wiring ----

    #[test]
    fn claim_relay_unknown_channel() {
        let registry = SupervisorSessionRegistry::new();
        let principal = sandbox_principal("sbx-test");
        let err = registry
            .claim_relay("nonexistent", Some(&principal))
            .expect_err("should err");
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[test]
    fn claim_relay_success() {
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, _relay_rx) = oneshot::channel();
        registry.pending_relays.lock().unwrap().insert(
            "ch-1".to_string(),
            pending_relay("sbx-test", relay_tx, Instant::now()),
        );

        let principal = sandbox_principal("sbx-test");
        let result = registry.claim_relay("ch-1", Some(&principal));
        assert!(result.is_ok());
        assert!(!registry.pending_relays.lock().unwrap().contains_key("ch-1"));
    }

    #[test]
    fn claim_relay_rejects_cross_sandbox_principal_without_consuming_channel() {
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, _relay_rx) = oneshot::channel();
        registry.pending_relays.lock().unwrap().insert(
            "ch-cross".to_string(),
            pending_relay("sbx-owner", relay_tx, Instant::now()),
        );

        let attacker = sandbox_principal("sbx-attacker");
        let err = registry
            .claim_relay("ch-cross", Some(&attacker))
            .expect_err("cross-sandbox relay claim must fail");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(
            registry
                .pending_relays
                .lock()
                .unwrap()
                .contains_key("ch-cross"),
            "failed cross-sandbox claim must not consume the channel"
        );
    }

    #[test]
    fn claim_relay_rejects_user_principal() {
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, _relay_rx) = oneshot::channel();
        registry.pending_relays.lock().unwrap().insert(
            "ch-user".to_string(),
            pending_relay("sbx-owner", relay_tx, Instant::now()),
        );

        let err = registry
            .claim_relay("ch-user", Some(&user_principal("alice")))
            .expect_err("users are not supervisor identities");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn relay_open_failure_completes_pending_waiter() {
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, relay_rx) = oneshot::channel();
        registry.pending_relays.lock().unwrap().insert(
            "ch-fail".to_string(),
            pending_relay("sbx-test", relay_tx, Instant::now()),
        );

        assert!(registry.fail_pending_relay("ch-fail", "target refused".to_string()));
        assert!(
            !registry
                .pending_relays
                .lock()
                .unwrap()
                .contains_key("ch-fail")
        );

        let result = relay_rx.await.expect("failure should wake waiter");
        let status = result.expect_err("waiter should receive status failure");
        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert_eq!(status.message(), "target refused");
    }

    #[test]
    fn claim_relay_expired_returns_deadline_exceeded() {
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, _relay_rx) = oneshot::channel();
        registry.pending_relays.lock().unwrap().insert(
            "ch-old".to_string(),
            pending_relay(
                "sbx-test",
                relay_tx,
                Instant::now()
                    .checked_sub(Duration::from_secs(60))
                    .expect("test duration should be before now"),
            ),
        );

        let err = registry
            .claim_relay("ch-old", Some(&sandbox_principal("sbx-test")))
            .expect_err("expired entry must fail");
        assert_eq!(err.code(), tonic::Code::DeadlineExceeded);
        // Entry must have been consumed regardless.
        assert!(
            !registry
                .pending_relays
                .lock()
                .unwrap()
                .contains_key("ch-old")
        );
    }

    #[test]
    fn claim_relay_receiver_dropped_returns_internal() {
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, relay_rx) = oneshot::channel::<Result<tokio::io::DuplexStream, Status>>();
        drop(relay_rx); // Gateway-side waiter has given up already.
        registry.pending_relays.lock().unwrap().insert(
            "ch-1".to_string(),
            pending_relay("sbx-test", relay_tx, Instant::now()),
        );

        let err = registry
            .claim_relay("ch-1", Some(&sandbox_principal("sbx-test")))
            .expect_err("should err when receiver is gone");
        assert_eq!(err.code(), tonic::Code::Internal);
    }

    #[tokio::test]
    async fn claim_relay_connects_both_ends() {
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, relay_rx) = oneshot::channel::<Result<tokio::io::DuplexStream, Status>>();
        registry.pending_relays.lock().unwrap().insert(
            "ch-io".to_string(),
            pending_relay("sbx-test", relay_tx, Instant::now()),
        );

        let mut supervisor_side = registry
            .claim_relay("ch-io", Some(&sandbox_principal("sbx-test")))
            .expect("claim should succeed")
            .stream;
        let mut gateway_side = relay_rx
            .await
            .expect("gateway side should receive result")
            .expect("gateway side should receive stream");

        // Supervisor side writes → gateway side reads.
        supervisor_side.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        gateway_side.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        // Gateway side writes → supervisor side reads.
        gateway_side.write_all(b"world").await.unwrap();
        let mut buf = [0u8; 5];
        supervisor_side.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
    }

    // ---- reap_expired_relays ----

    #[test]
    fn reap_expired_relays_removes_old_entries() {
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, _relay_rx) = oneshot::channel();
        registry.pending_relays.lock().unwrap().insert(
            "ch-old".to_string(),
            pending_relay(
                "sbx-test",
                relay_tx,
                Instant::now()
                    .checked_sub(Duration::from_secs(60))
                    .expect("test duration should be before now"),
            ),
        );

        registry.reap_expired_relays();
        assert!(
            !registry
                .pending_relays
                .lock()
                .unwrap()
                .contains_key("ch-old")
        );
    }

    #[test]
    fn reap_expired_relays_keeps_fresh_entries() {
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, _relay_rx) = oneshot::channel();
        registry.pending_relays.lock().unwrap().insert(
            "ch-fresh".to_string(),
            pending_relay("sbx-test", relay_tx, Instant::now()),
        );

        registry.reap_expired_relays();
        assert!(
            registry
                .pending_relays
                .lock()
                .unwrap()
                .contains_key("ch-fresh")
        );
    }
}
