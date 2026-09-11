// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use metrics::counter;
use prost::Message;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};
use uuid::Uuid;

use openshell_core::proto::{
    ConfigApplyOutcome, ConfigBootstrap, ConfigComponent, ConfigComponentApplyResult,
    ConfigSnapshotRevision, ConfigUpdate, ConfigUpdateResult, GatewayMessage, PolicySource,
    RelayFrame, RelayInit, RelayOpen, ReportMainProcessExitRequest, ReportMainProcessExitResponse,
    Sandbox, SandboxPhase, SessionAccepted, SshRelayTarget, SupervisorMessage,
    config_snapshot_revision, config_update, gateway_message, relay_open, supervisor_message,
};
use openshell_core::proto::{
    LEGACY_SUPERVISOR_PROTOCOL_REVISION, PREVIOUS_SUPERVISOR_PROTOCOL_REVISION,
    SUPERVISOR_PROTOCOL_REVISION,
};
use openshell_core::transport_errors::is_expected_transport_close_status;
use openshell_core::{ObjectId, ObjectWorkspace};

use crate::ServerState;
use crate::auth::principal::Principal;
use crate::config_delivery::{
    DeliveryDisposition, MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES, SupervisorConfigMessage,
};
#[cfg(test)]
use crate::config_delivery::{LocalSupervisorConfigRouter, SupervisorConfigRouter};
use crate::persistence::{CONFIG_COMPONENT_OBSERVATION_OBJECT_TYPE, ObjectType, current_time_ms};
use crate::storage_proto::StoredConfigComponentObservation;

const HEARTBEAT_INTERVAL_SECS: u32 = 15;
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

impl ObjectType for StoredConfigComponentObservation {
    fn object_type() -> &'static str {
        CONFIG_COMPONENT_OBSERVATION_OBJECT_TYPE
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
    config_sequences: ConfigSequences,
    /// Fires when this session is superseded by a reconnect so the old session
    /// task can exit promptly — dropping its own `tx` clone and closing the
    /// outbound stream. Without this, a concurrent `open_relay` that grabbed
    /// the old session's `tx` just before supersede could still enqueue a
    /// `RelayOpen` onto the stale stream and sit until the relay timeout.
    shutdown: oneshot::Sender<()>,
    /// Set after the supervisor confirms that every expected foreground
    /// attachment has closed and terminal output delivery is complete.
    terminal_delivery_finalized: bool,
    #[allow(dead_code)]
    connected_at: Instant,
}

#[derive(Debug, Default)]
struct ConfigSequences {
    sandbox_config: ComponentDeliveryState,
    provider_environment: ComponentDeliveryState,
}

#[derive(Debug, Default)]
struct ComponentDeliveryState {
    sequence: u64,
    in_flight: Option<InFlightConfigUpdate>,
    pending: Option<SupervisorConfigMessage>,
    last_acknowledged_revision: Option<ConfigSnapshotRevision>,
}

#[derive(Debug)]
struct InFlightConfigUpdate {
    update_id: String,
    component_sequence: u64,
    revision: ConfigSnapshotRevision,
    sent_at: Instant,
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

fn build_config_update(
    state: &mut ComponentDeliveryState,
    message: SupervisorConfigMessage,
) -> (GatewayMessage, InFlightConfigUpdate) {
    state.sequence = state.sequence.saturating_add(1);
    let component_sequence = state.sequence;
    let (component, revision) = match message {
        SupervisorConfigMessage::SandboxConfig(snapshot) => {
            let revision = ConfigSnapshotRevision {
                component: Some(config_snapshot_revision::Component::SandboxConfig(
                    openshell_core::proto::SandboxConfigRevision {
                        config_revision: snapshot.config_revision,
                        policy_version: snapshot.version,
                        policy_source: snapshot.policy_source,
                        global_policy_version: snapshot.global_policy_version,
                    },
                )),
            };
            (config_update::Component::SandboxConfig(*snapshot), revision)
        }
        SupervisorConfigMessage::ProviderEnvironment(snapshot) => {
            let revision = ConfigSnapshotRevision {
                component: Some(config_snapshot_revision::Component::ProviderEnvironment(
                    snapshot.provider_env_revision,
                )),
            };
            (
                config_update::Component::ProviderEnvironment(snapshot),
                revision,
            )
        }
    };
    let update_id = Uuid::new_v4().to_string();
    (
        GatewayMessage {
            payload: Some(gateway_message::Payload::ConfigUpdate(ConfigUpdate {
                update_id: update_id.clone(),
                component_sequence,
                component: Some(component),
            })),
        },
        InFlightConfigUpdate {
            update_id,
            component_sequence,
            revision,
            sent_at: Instant::now(),
        },
    )
}

fn config_message_revision(message: &SupervisorConfigMessage) -> ConfigSnapshotRevision {
    match message {
        SupervisorConfigMessage::SandboxConfig(snapshot) => ConfigSnapshotRevision {
            component: Some(config_snapshot_revision::Component::SandboxConfig(
                openshell_core::proto::SandboxConfigRevision {
                    config_revision: snapshot.config_revision,
                    policy_version: snapshot.version,
                    policy_source: snapshot.policy_source,
                    global_policy_version: snapshot.global_policy_version,
                },
            )),
        },
        SupervisorConfigMessage::ProviderEnvironment(snapshot) => ConfigSnapshotRevision {
            component: Some(config_snapshot_revision::Component::ProviderEnvironment(
                snapshot.provider_env_revision,
            )),
        },
    }
}

fn validate_component_apply_result(
    result: &ConfigComponentApplyResult,
    requested_revision: &ConfigSnapshotRevision,
) -> Result<ConfigApplyOutcome, Status> {
    if result.requested_revision.as_ref() != Some(requested_revision) {
        return Err(Status::invalid_argument(
            "configuration result revision does not match the delivered snapshot",
        ));
    }
    let outcome = ConfigApplyOutcome::try_from(result.outcome).unwrap_or_default();
    let applied_matches_request = result.applied_revision.as_ref() == Some(requested_revision);
    let applied_is_absent = result.applied_revision.is_none();
    let valid = match outcome {
        ConfigApplyOutcome::Applied
        | ConfigApplyOutcome::IgnoredDuplicate
        | ConfigApplyOutcome::Degraded => applied_matches_request,
        ConfigApplyOutcome::RetainedLocalOverride | ConfigApplyOutcome::FailedClosed => {
            applied_is_absent
        }
        ConfigApplyOutcome::FailedRetainedLastKnownGood => {
            result.applied_revision.is_some() && !applied_matches_request
        }
        ConfigApplyOutcome::IgnoredStale | ConfigApplyOutcome::Unsupported => true,
        ConfigApplyOutcome::Unspecified => false,
    };
    if !valid {
        return Err(Status::invalid_argument(
            "configuration result outcome does not match its applied revision",
        ));
    }
    Ok(outcome)
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
                config_sequences: ConfigSequences::default(),
                shutdown,
                terminal_delivery_finalized: false,
                connected_at: Instant::now(),
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
    fn remove_if_current(&self, sandbox_id: &str, session_id: &str) -> Option<bool> {
        let mut sessions = self.sessions.lock().unwrap();
        let is_current = sessions
            .get(sandbox_id)
            .is_some_and(|s| s.session_id == session_id);
        if is_current {
            return sessions
                .remove(sandbox_id)
                .map(|session| session.terminal_delivery_finalized);
        }
        None
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
            .map(|s| s.tx.clone())
    }

    pub fn has_session(&self, sandbox_id: &str) -> bool {
        self.sessions.lock().unwrap().contains_key(sandbox_id)
    }

    pub fn terminal_delivery_finalized(&self, sandbox_id: &str) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .get(sandbox_id)
            .is_some_and(|session| session.terminal_delivery_finalized)
    }

    pub fn finalize_main_process_exit(&self, sandbox_id: &str) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        let Some(session) = sessions.get_mut(sandbox_id) else {
            return false;
        };
        session.terminal_delivery_finalized = true;
        true
    }

    pub(crate) fn connected_sandbox_ids(&self) -> Vec<String> {
        self.sessions.lock().unwrap().keys().cloned().collect()
    }

    pub(crate) fn deliver_config(
        &self,
        sandbox_id: &str,
        message: SupervisorConfigMessage,
    ) -> DeliveryDisposition {
        let component_name = message.component_name();
        let mut sessions = self.sessions.lock().unwrap();
        let Some(session) = sessions.get_mut(sandbox_id) else {
            return DeliveryDisposition::NoActiveSession;
        };
        let delivery_state = match &message {
            SupervisorConfigMessage::SandboxConfig(_) => {
                &mut session.config_sequences.sandbox_config
            }
            SupervisorConfigMessage::ProviderEnvironment(_) => {
                &mut session.config_sequences.provider_environment
            }
        };
        if delivery_state.in_flight.is_none()
            && delivery_state.last_acknowledged_revision.as_ref()
                == Some(&config_message_revision(&message))
        {
            return DeliveryDisposition::SuppressedUnchanged;
        }
        if delivery_state
            .in_flight
            .as_ref()
            .is_some_and(|update| update.sent_at.elapsed() < Duration::from_mins(1))
        {
            delivery_state.pending = Some(message);
            return DeliveryDisposition::Coalesced;
        }
        delivery_state.in_flight = None;
        delivery_state.pending = None;

        let (gateway_message, in_flight) = build_config_update(delivery_state, message);

        if gateway_message.encoded_len() > MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES {
            return DeliveryDisposition::PayloadTooLarge;
        }

        match session.tx.try_send(gateway_message) {
            Ok(()) => {
                delivery_state.in_flight = Some(in_flight);
                DeliveryDisposition::Enqueued
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    sandbox_id = %sandbox_id,
                    component = component_name,
                    "supervisor configuration queue is full"
                );
                DeliveryDisposition::QueueFull
            }
            Err(mpsc::error::TrySendError::Closed(_)) => DeliveryDisposition::SessionClosed,
        }
    }

    fn complete_config_update(
        &self,
        sandbox_id: &str,
        session_id: &str,
        result: &ConfigUpdateResult,
    ) -> Result<(), Status> {
        let component = result
            .result
            .as_ref()
            .and_then(|result| ConfigComponent::try_from(result.component).ok())
            .unwrap_or_default();
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get_mut(sandbox_id)
            .filter(|session| session.session_id == session_id)
            .ok_or_else(|| Status::failed_precondition("obsolete supervisor session result"))?;
        let delivery_state = match component {
            ConfigComponent::SandboxConfig => &mut session.config_sequences.sandbox_config,
            ConfigComponent::ProviderEnvironment => {
                &mut session.config_sequences.provider_environment
            }
            ConfigComponent::Unspecified => {
                return Err(Status::invalid_argument(
                    "configuration result component is required",
                ));
            }
        };
        let in_flight = delivery_state
            .in_flight
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("no matching update is in flight"))?;
        let component_result = result
            .result
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("configuration result is required"))?;
        if in_flight.update_id != result.update_id
            || in_flight.component_sequence != result.component_sequence
        {
            return Err(Status::invalid_argument(
                "configuration result does not match the in-flight delivery",
            ));
        }
        let outcome = validate_component_apply_result(component_result, &in_flight.revision)?;
        if matches!(
            outcome,
            ConfigApplyOutcome::Applied
                | ConfigApplyOutcome::IgnoredDuplicate
                | ConfigApplyOutcome::RetainedLocalOverride
                | ConfigApplyOutcome::Degraded
        ) {
            delivery_state.last_acknowledged_revision = Some(in_flight.revision);
        }
        delivery_state.in_flight = None;
        if let Some(pending) = delivery_state.pending.take() {
            if delivery_state.last_acknowledged_revision.as_ref()
                == Some(&config_message_revision(&pending))
            {
                return Ok(());
            }
            let (message, next) = build_config_update(delivery_state, pending);
            match session.tx.try_send(message) {
                Ok(()) => delivery_state.in_flight = Some(next),
                Err(mpsc::error::TrySendError::Full(_) | mpsc::error::TrySendError::Closed(_)) => {
                    // Owner reconciliation rebuilds the newest snapshot.
                }
            }
        }
        Ok(())
    }

    fn retry_config_update_after_persistence_failure(
        &self,
        sandbox_id: &str,
        session_id: &str,
        result: &ConfigComponentApplyResult,
    ) {
        let component = ConfigComponent::try_from(result.component).unwrap_or_default();
        let Some(requested_revision) = result.requested_revision.as_ref() else {
            return;
        };
        let mut sessions = self.sessions.lock().unwrap();
        let Some(session) = sessions
            .get_mut(sandbox_id)
            .filter(|session| session.session_id == session_id)
        else {
            return;
        };
        let delivery_state = match component {
            ConfigComponent::SandboxConfig => &mut session.config_sequences.sandbox_config,
            ConfigComponent::ProviderEnvironment => {
                &mut session.config_sequences.provider_environment
            }
            ConfigComponent::Unspecified => return,
        };
        if delivery_state.last_acknowledged_revision.as_ref() == Some(requested_revision) {
            delivery_state.last_acknowledged_revision = None;
        }
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
    expected_transport_close_during_session_state(
        status,
        state.gateway_shutting_down.load(Ordering::Acquire),
        session_no_longer_current,
        sandbox_is_terminating_or_gone(state, sandbox_id).await,
    )
}

fn expected_transport_close_during_session_state(
    status: &Status,
    gateway_shutting_down: bool,
    session_no_longer_current: bool,
    sandbox_terminating_or_gone: bool,
) -> bool {
    expected_transport_close_during_shutdown(
        status,
        gateway_shutting_down || session_no_longer_current || sandbox_terminating_or_gone,
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
    let stream_applies_config = hello.protocol_revision == SUPERVISOR_PROTOCOL_REVISION;
    if sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }
    validate_protocol_revision(&sandbox_id, hello.protocol_revision)?;
    if let Some(principal) = principal.as_ref() {
        crate::auth::guard::ensure_sandbox_principal_scope(principal, &sandbox_id)?;
    }
    let sandbox = require_persisted_sandbox(&state.store, &sandbox_id).await?;

    let bootstrap_timeout = if stream_applies_config {
        crate::config_delivery::REQUIRED_CONFIG_BOOTSTRAP_BUILD_TIMEOUT
    } else {
        crate::config_delivery::OPTIONAL_CONFIG_BOOTSTRAP_BUILD_TIMEOUT
    };
    let bootstrap =
        match crate::config_delivery::build_config_bootstrap(state, &sandbox, bootstrap_timeout)
            .await
        {
            Ok(bootstrap) => {
                counter!(
                    "openshell_supervisor_config_bootstrap_total",
                    "outcome" => "built"
                )
                .increment(1);
                Some(bootstrap)
            }
            Err(error) => {
                counter!(
                    "openshell_supervisor_config_bootstrap_total",
                    "outcome" => "build_failed"
                )
                .increment(1);
                warn!(
                    sandbox_id = %sandbox_id,
                    error_code = ?error.code(),
                    "failed to build supervisor configuration bootstrap"
                );
                if stream_applies_config {
                    return Err(error);
                }
                None
            }
        };
    let expected_bootstrap_revisions = bootstrap
        .as_ref()
        .map(bootstrap_revision_fence)
        .unwrap_or_default();

    let session_id = Uuid::new_v4().to_string();
    info!(
        sandbox_id = %sandbox_id,
        session_id = %session_id,
        instance_id = %hello.instance_id,
        "supervisor session: accepted"
    );

    // Step 2: Queue SessionAccepted before the session becomes routable. This
    // keeps a concurrent ConfigUpdate from becoming the first stream message.
    let (tx, rx) = mpsc::channel::<GatewayMessage>(64);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let mut accepted = GatewayMessage {
        payload: Some(gateway_message::Payload::SessionAccepted(SessionAccepted {
            session_id: session_id.clone(),
            heartbeat_interval_secs: HEARTBEAT_INTERVAL_SECS,
            bootstrap,
            protocol_revision: hello.protocol_revision,
        })),
    };
    if accepted.encoded_len() > MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES {
        counter!(
            "openshell_supervisor_config_bootstrap_total",
            "outcome" => "payload_too_large"
        )
        .increment(1);
        if stream_applies_config {
            return Err(Status::resource_exhausted(
                "supervisor configuration bootstrap exceeds the stream message limit",
            ));
        }
        let Some(gateway_message::Payload::SessionAccepted(accepted_payload)) =
            accepted.payload.as_mut()
        else {
            unreachable!("constructed SessionAccepted payload")
        };
        accepted_payload.bootstrap = None;
    }
    if tx.send(accepted).await.is_err() {
        return Err(Status::internal("failed to send session accepted"));
    }

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

    if superseded {
        state
            .supervisor_sessions
            .replay_pending_relays(&sandbox_id, &tx)
            .await;
    }

    if !stream_applies_config {
        let _ =
            mark_supervisor_initialized(state, &sandbox_id, &session_id, &hello.instance_id).await;
    }

    // Step 4: Spawn the session loop that reads inbound messages.
    let state_clone = Arc::clone(state);
    let sandbox_id_clone = sandbox_id.clone();
    let instance_id = hello.instance_id.clone();
    tokio::spawn(async move {
        run_session_loop(
            &state_clone,
            &sandbox_id_clone,
            &session_id,
            &instance_id,
            stream_applies_config,
            &expected_bootstrap_revisions,
            &tx,
            &mut inbound,
            shutdown_rx,
        )
        .await;
        let terminal_finalized = state_clone
            .supervisor_sessions
            .remove_if_current(&sandbox_id_clone, &session_id);
        if let Some(terminal_finalized) = terminal_finalized {
            info!(sandbox_id = %sandbox_id_clone, session_id = %session_id, "supervisor session: ended");
            state_clone
                .telemetry
                .sandbox_session_disconnected(&sandbox_id_clone);
            if let Err(err) = state_clone
                .compute
                .supervisor_session_disconnected(&sandbox_id_clone, terminal_finalized)
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

fn validate_protocol_revision(sandbox_id: &str, supervisor_revision: u32) -> Result<(), Status> {
    match supervisor_revision {
        SUPERVISOR_PROTOCOL_REVISION => Ok(()),
        PREVIOUS_SUPERVISOR_PROTOCOL_REVISION => {
            counter!("openshell_supervisor_protocol_previous_sessions_total").increment(1);
            warn!(
                sandbox_id = %sandbox_id,
                "supervisor session: Stage 1 supervisor is using polling compatibility"
            );
            Ok(())
        }
        LEGACY_SUPERVISOR_PROTOCOL_REVISION => {
            counter!("openshell_supervisor_protocol_legacy_sessions_total").increment(1);
            warn!(
                sandbox_id = %sandbox_id,
                "supervisor session: supervisor predates the protocol handshake; recreate the sandbox before the next gateway upgrade"
            );
            Ok(())
        }
        other => Err(Status::failed_precondition(format!(
            "supervisor protocol revision mismatch: gateway requires {SUPERVISOR_PROTOCOL_REVISION}, supervisor offered {other}"
        ))),
    }
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
        .report_main_process_exit(&report.sandbox_id, &report.instance_id, report.exit_code)
        .await
        .map_err(Status::failed_precondition)?;
    Ok(Response::new(ReportMainProcessExitResponse {}))
}

pub async fn handle_finalize_main_process_exit(
    state: &Arc<ServerState>,
    request: Request<openshell_core::proto::FinalizeMainProcessExitRequest>,
) -> Result<Response<openshell_core::proto::FinalizeMainProcessExitResponse>, Status> {
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
        .finalize_main_process_exit(&report.sandbox_id, &report.instance_id)
        .await
        .map_err(Status::failed_precondition)?;
    if !state
        .supervisor_sessions
        .finalize_main_process_exit(&report.sandbox_id)
    {
        return Err(Status::failed_precondition(
            "supervisor session is not connected",
        ));
    }
    Ok(Response::new(
        openshell_core::proto::FinalizeMainProcessExitResponse {},
    ))
}

#[allow(clippy::too_many_arguments)]
async fn run_session_loop(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    instance_id: &str,
    stream_applies_config: bool,
    expected_bootstrap_revisions: &[(ConfigComponent, ConfigSnapshotRevision)],
    tx: &mpsc::Sender<GatewayMessage>,
    inbound: &mut tonic::Streaming<SupervisorMessage>,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let heartbeat_interval = Duration::from_secs(u64::from(HEARTBEAT_INTERVAL_SECS));
    let mut heartbeat_timer = tokio::time::interval(heartbeat_interval);
    // Skip the first immediate tick.
    heartbeat_timer.tick().await;
    let bootstrap_timeout = tokio::time::sleep(Duration::from_mins(2));
    tokio::pin!(bootstrap_timeout);
    let mut bootstrap_complete = !stream_applies_config;

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                info!(sandbox_id = %sandbox_id, session_id = %session_id, "supervisor session: superseded by reconnect, shutting down");
                break;
            }
            msg = inbound.message() => {
                match msg {
                    Ok(Some(msg)) => {
                        let bootstrap_succeeded = match msg.payload.as_ref() {
                            Some(supervisor_message::Payload::ConfigBootstrapResult(result))
                                if stream_applies_config =>
                            {
                                match validate_bootstrap_result(
                                    &result.results,
                                    expected_bootstrap_revisions,
                                ) {
                                    Ok(succeeded) => Some(succeeded),
                                    Err(error) => {
                                        warn!(
                                            sandbox_id,
                                            session_id,
                                            error = %error,
                                            "supervisor configuration bootstrap result did not match the delivered snapshot"
                                        );
                                        break;
                                    }
                                }
                            }
                            _ => None,
                        };
                        handle_supervisor_message(
                            state,
                            sandbox_id,
                            session_id,
                            stream_applies_config,
                            msg,
                        ).await;
                        match bootstrap_succeeded {
                            Some(true) => {
                                if !mark_supervisor_initialized(
                                    state,
                                    sandbox_id,
                                    session_id,
                                    instance_id,
                                )
                                .await
                                {
                                    break;
                                }
                                bootstrap_complete = true;
                            }
                            Some(false) => {
                                warn!(sandbox_id, session_id, "supervisor configuration bootstrap failed");
                                break;
                            }
                            None => {}
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
            () = &mut bootstrap_timeout, if !bootstrap_complete => {
                warn!(sandbox_id, session_id, "supervisor configuration bootstrap timed out");
                break;
            }
        }
    }
}

async fn handle_supervisor_message(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    stream_applies_config: bool,
    msg: SupervisorMessage,
) {
    match msg.payload {
        Some(supervisor_message::Payload::Heartbeat(_)) => {
            // Heartbeat received — nothing to do for now.
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
        Some(supervisor_message::Payload::ConfigUpdateResult(result)) => {
            if let Err(error) = state
                .supervisor_sessions
                .complete_config_update(sandbox_id, session_id, &result)
            {
                debug!(
                    sandbox_id,
                    session_id,
                    error = %error,
                    "ignored unmatched supervisor configuration result"
                );
                return;
            }
            if let Some(result) = result.result.as_ref()
                && let Err(error) = record_component_apply_result(state, sandbox_id, result).await
            {
                state
                    .supervisor_sessions
                    .retry_config_update_after_persistence_failure(sandbox_id, session_id, result);
                warn!(
                    sandbox_id,
                    session_id,
                    component = result.component,
                    error = %error,
                    "failed to persist supervisor configuration result"
                );
            }
        }
        Some(supervisor_message::Payload::ConfigBootstrapResult(result)) => {
            if !stream_applies_config {
                debug!(
                    sandbox_id,
                    session_id, "ignored bootstrap result from polling-compatibility supervisor"
                );
                return;
            }
            if !state
                .supervisor_sessions
                .is_current_session(sandbox_id, session_id)
            {
                return;
            }
            for component in &result.results {
                if let Err(error) =
                    record_component_apply_result(state, sandbox_id, component).await
                {
                    warn!(
                        sandbox_id,
                        session_id,
                        component = component.component,
                        error = %error,
                        "failed to persist supervisor bootstrap result"
                    );
                }
            }
        }
        _ => {
            warn!(
                sandbox_id = %sandbox_id,
                session_id = %session_id,
                "supervisor session: unexpected message type"
            );
        }
    }
}

fn bootstrap_revision_fence(
    bootstrap: &ConfigBootstrap,
) -> Vec<(ConfigComponent, ConfigSnapshotRevision)> {
    let mut revisions = Vec::with_capacity(2);
    if let Some(snapshot) = bootstrap.sandbox_config.as_ref() {
        revisions.push((
            ConfigComponent::SandboxConfig,
            ConfigSnapshotRevision {
                component: Some(config_snapshot_revision::Component::SandboxConfig(
                    openshell_core::proto::SandboxConfigRevision {
                        config_revision: snapshot.config_revision,
                        policy_version: snapshot.version,
                        policy_source: snapshot.policy_source,
                        global_policy_version: snapshot.global_policy_version,
                    },
                )),
            },
        ));
    }
    if let Some(snapshot) = bootstrap.provider_environment.as_ref() {
        revisions.push((
            ConfigComponent::ProviderEnvironment,
            ConfigSnapshotRevision {
                component: Some(config_snapshot_revision::Component::ProviderEnvironment(
                    snapshot.provider_env_revision,
                )),
            },
        ));
    }
    revisions
}

fn validate_bootstrap_result(
    results: &[ConfigComponentApplyResult],
    expected: &[(ConfigComponent, ConfigSnapshotRevision)],
) -> Result<bool, Status> {
    if expected.len() != 2 || results.len() != expected.len() {
        return Err(Status::invalid_argument(
            "bootstrap result must contain every delivered component exactly once",
        ));
    }
    let mut seen = Vec::with_capacity(results.len());
    let mut all_succeeded = true;
    for result in results {
        let component = ConfigComponent::try_from(result.component).unwrap_or_default();
        if component == ConfigComponent::Unspecified || seen.contains(&component) {
            return Err(Status::invalid_argument(
                "bootstrap result contains an invalid or duplicate component",
            ));
        }
        let Some((_, revision)) = expected
            .iter()
            .find(|(expected_component, _)| *expected_component == component)
        else {
            return Err(Status::invalid_argument(
                "bootstrap result contains an unexpected component",
            ));
        };
        let outcome = validate_component_apply_result(result, revision)?;
        seen.push(component);
        all_succeeded &= matches!(
            outcome,
            ConfigApplyOutcome::Applied
                | ConfigApplyOutcome::IgnoredDuplicate
                | ConfigApplyOutcome::RetainedLocalOverride
                | ConfigApplyOutcome::Degraded
        );
    }
    Ok(all_succeeded)
}

async fn mark_supervisor_initialized(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    instance_id: &str,
) -> bool {
    if !state
        .supervisor_sessions
        .is_current_session(sandbox_id, session_id)
    {
        return false;
    }
    if let Err(err) = state
        .compute
        .supervisor_session_connected(sandbox_id, instance_id)
        .await
    {
        warn!(
            sandbox_id,
            session_id,
            error = %err,
            "supervisor session: failed to mark sandbox initialized"
        );
        false
    } else {
        state.telemetry.sandbox_session_connected(sandbox_id);
        true
    }
}

async fn record_component_apply_result(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    result: &ConfigComponentApplyResult,
) -> Result<(), Status> {
    let component = ConfigComponent::try_from(result.component).unwrap_or_default();
    let outcome = ConfigApplyOutcome::try_from(result.outcome).unwrap_or_default();
    counter!(
        "openshell_supervisor_config_apply_results_total",
        "component" => component.as_str_name(),
        "outcome" => outcome.as_str_name(),
    )
    .increment(1);
    record_config_component_observation(state, sandbox_id, component, outcome, result).await?;
    if component != ConfigComponent::SandboxConfig {
        return Ok(());
    }
    let Some(config_snapshot_revision::Component::SandboxConfig(revision)) = result
        .requested_revision
        .as_ref()
        .and_then(|revision| revision.component.as_ref())
    else {
        return Err(Status::invalid_argument(
            "sandbox configuration result is missing its requested revision",
        ));
    };
    if PolicySource::try_from(revision.policy_source).unwrap_or_default() != PolicySource::Sandbox
        || revision.policy_version == 0
    {
        return Ok(());
    }
    let loaded = matches!(
        outcome,
        ConfigApplyOutcome::Applied | ConfigApplyOutcome::IgnoredDuplicate
    );
    let failed = matches!(
        outcome,
        ConfigApplyOutcome::FailedRetainedLastKnownGood | ConfigApplyOutcome::FailedClosed
    );
    if !loaded && !failed {
        return Ok(());
    }
    crate::grpc::policy::record_policy_apply_result(
        state,
        sandbox_id,
        revision.policy_version,
        loaded,
        result
            .failure
            .as_ref()
            .map(|failure| failure.message.as_str()),
        "stream",
    )
    .await
}

async fn record_config_component_observation(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    component: ConfigComponent,
    outcome: ConfigApplyOutcome,
    result: &ConfigComponentApplyResult,
) -> Result<(), Status> {
    let sandbox = state
        .store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .map_err(|error| {
            Status::internal(format!("fetch sandbox for observation failed: {error}"))
        })?
        .ok_or_else(|| Status::not_found("sandbox not found while recording observation"))?;
    let component_name = match component {
        ConfigComponent::SandboxConfig => "sandbox_config",
        ConfigComponent::ProviderEnvironment => "provider_environment",
        ConfigComponent::Unspecified => "unspecified",
    };
    let observation_id = format!("{sandbox_id}:{component_name}");
    let now_ms = current_time_ms();
    let sanitized_error = result
        .failure
        .as_ref()
        .map(|failure| failure.message.chars().take(1024).collect())
        .unwrap_or_default();
    let observation = StoredConfigComponentObservation {
        metadata: Some(openshell_core::proto::ObjectMeta {
            id: observation_id.clone(),
            name: observation_id,
            workspace: sandbox.object_workspace().to_string(),
            created_at_ms: now_ms,
            ..Default::default()
        }),
        sandbox_id: sandbox.object_id().to_string(),
        component: component.into(),
        requested_revision: result.requested_revision,
        applied_revision: result.applied_revision,
        outcome: outcome.into(),
        effective_source: match outcome {
            ConfigApplyOutcome::RetainedLocalOverride => "local_override",
            ConfigApplyOutcome::FailedRetainedLastKnownGood => "last_known_good",
            ConfigApplyOutcome::FailedClosed => "fail_closed",
            ConfigApplyOutcome::Degraded => "gateway_degraded",
            ConfigApplyOutcome::Unspecified
            | ConfigApplyOutcome::Applied
            | ConfigApplyOutcome::IgnoredDuplicate
            | ConfigApplyOutcome::IgnoredStale
            | ConfigApplyOutcome::Unsupported => "gateway",
        }
        .to_string(),
        observed_at_ms: now_ms,
        sanitized_error,
    };
    state
        .store
        .put_scoped_message(&observation, sandbox_id)
        .await
        .map_err(|error| Status::internal(format!("persist component observation failed: {error}")))
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
    use openshell_core::proto::{
        ProviderEnvironmentSnapshot, ProviderEnvironmentValue, SandboxConfigRevision,
        SandboxConfigSnapshot,
    };
    use prost::Message;

    #[test]
    fn configuration_stream_messages_round_trip() {
        let bootstrap = GatewayMessage {
            payload: Some(gateway_message::Payload::SessionAccepted(SessionAccepted {
                session_id: "session-1".into(),
                heartbeat_interval_secs: 15,
                bootstrap: Some(ConfigBootstrap {
                    sandbox_config: Some(SandboxConfigSnapshot::default()),
                    provider_environment: Some(ProviderEnvironmentSnapshot::default()),
                }),
                protocol_revision: SUPERVISOR_PROTOCOL_REVISION,
            })),
        };
        let updates = [
            config_update::Component::SandboxConfig(SandboxConfigSnapshot::default()),
            config_update::Component::ProviderEnvironment(ProviderEnvironmentSnapshot::default()),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, component)| GatewayMessage {
            payload: Some(gateway_message::Payload::ConfigUpdate(ConfigUpdate {
                update_id: format!("update-{index}"),
                component_sequence: u64::try_from(index + 1).unwrap(),
                component: Some(component),
            })),
        });

        for original in std::iter::once(bootstrap).chain(updates) {
            let decoded = GatewayMessage::decode(original.encode_to_vec().as_slice()).unwrap();
            assert_eq!(decoded, original);
        }

        let result = SupervisorMessage {
            payload: Some(supervisor_message::Payload::ConfigUpdateResult(
                ConfigUpdateResult {
                    update_id: "update-1".into(),
                    component_sequence: 4,
                    result: Some(ConfigComponentApplyResult {
                        component: ConfigComponent::SandboxConfig.into(),
                        requested_revision: Some(ConfigSnapshotRevision {
                            component: Some(config_snapshot_revision::Component::SandboxConfig(
                                SandboxConfigRevision {
                                    config_revision: 7,
                                    policy_version: 3,
                                    ..Default::default()
                                },
                            )),
                        }),
                        applied_revision: Some(ConfigSnapshotRevision {
                            component: Some(config_snapshot_revision::Component::SandboxConfig(
                                SandboxConfigRevision {
                                    config_revision: 7,
                                    policy_version: 3,
                                    ..Default::default()
                                },
                            )),
                        }),
                        outcome: ConfigApplyOutcome::Applied.into(),
                        failure: None,
                    }),
                },
            )),
        };
        let decoded = SupervisorMessage::decode(result.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded, result);
    }

    #[test]
    fn supervisor_protocol_revision_accepts_current_and_legacy_peers() {
        assert!(validate_protocol_revision("sb-1", SUPERVISOR_PROTOCOL_REVISION).is_ok());
        assert!(validate_protocol_revision("sb-1", PREVIOUS_SUPERVISOR_PROTOCOL_REVISION).is_ok());
        assert!(validate_protocol_revision("sb-1", LEGACY_SUPERVISOR_PROTOCOL_REVISION).is_ok());
    }

    #[test]
    fn bootstrap_requires_every_delivered_component_to_succeed() {
        let sandbox_revision = ConfigSnapshotRevision {
            component: Some(config_snapshot_revision::Component::SandboxConfig(
                SandboxConfigRevision {
                    config_revision: 7,
                    ..Default::default()
                },
            )),
        };
        let provider_revision = ConfigSnapshotRevision {
            component: Some(config_snapshot_revision::Component::ProviderEnvironment(9)),
        };
        let expected = vec![
            (ConfigComponent::SandboxConfig, sandbox_revision),
            (ConfigComponent::ProviderEnvironment, provider_revision),
        ];
        let result =
            |component: ConfigComponent,
             revision: ConfigSnapshotRevision,
             outcome: ConfigApplyOutcome| ConfigComponentApplyResult {
                component: component.into(),
                requested_revision: Some(revision),
                applied_revision: Some(revision),
                outcome: outcome.into(),
                ..Default::default()
            };
        let mut results = vec![
            result(
                ConfigComponent::SandboxConfig,
                sandbox_revision,
                ConfigApplyOutcome::Applied,
            ),
            result(
                ConfigComponent::ProviderEnvironment,
                provider_revision,
                ConfigApplyOutcome::Degraded,
            ),
        ];
        assert!(validate_bootstrap_result(&results, &expected).unwrap());

        results[1].outcome = ConfigApplyOutcome::FailedClosed.into();
        results[1].applied_revision = None;
        assert!(!validate_bootstrap_result(&results, &expected).unwrap());
        assert!(validate_bootstrap_result(&results[..1], &expected).is_err());
        results[1].requested_revision = Some(ConfigSnapshotRevision::default());
        assert!(validate_bootstrap_result(&results, &expected).is_err());
    }

    async fn state_with_sandbox(sandbox_id: &str) -> Arc<ServerState> {
        let state = crate::grpc::test_support::test_server_state().await;
        state
            .store
            .put_message(&sandbox_record(sandbox_id, sandbox_id))
            .await
            .unwrap();
        state
    }

    #[tokio::test]
    async fn component_apply_result_persists_compact_observed_state() {
        let state = state_with_sandbox("sb-observed").await;
        let requested_revision = ConfigSnapshotRevision {
            component: Some(config_snapshot_revision::Component::ProviderEnvironment(11)),
        };
        let applied_revision = ConfigSnapshotRevision {
            component: Some(config_snapshot_revision::Component::ProviderEnvironment(9)),
        };
        record_component_apply_result(
            &state,
            "sb-observed",
            &ConfigComponentApplyResult {
                component: ConfigComponent::ProviderEnvironment.into(),
                requested_revision: Some(requested_revision),
                applied_revision: Some(applied_revision),
                outcome: ConfigApplyOutcome::FailedRetainedLastKnownGood.into(),
                failure: Some(openshell_core::proto::ConfigApplyFailure {
                    message: "x".repeat(2_000),
                    ..Default::default()
                }),
            },
        )
        .await
        .unwrap();

        let observation = state
            .store
            .get_message::<StoredConfigComponentObservation>("sb-observed:provider_environment")
            .await
            .unwrap()
            .expect("component observation");
        assert_eq!(observation.sandbox_id, "sb-observed");
        assert_eq!(
            observation.component,
            ConfigComponent::ProviderEnvironment as i32
        );
        assert_eq!(
            observation.outcome,
            ConfigApplyOutcome::FailedRetainedLastKnownGood as i32
        );
        assert_eq!(observation.effective_source, "last_known_good");
        assert_eq!(observation.sanitized_error.len(), 1_024);
        assert!(observation.observed_at_ms > 0);
    }

    async fn first_gateway_message(
        harness: &mut crate::grpc::test_support::SupervisorStreamHarness,
    ) -> GatewayMessage {
        tokio::time::timeout(Duration::from_secs(5), harness.inbound.message())
            .await
            .expect("gateway response before timeout")
            .expect("stream open")
            .expect("gateway message")
    }

    #[tokio::test]
    async fn legacy_supervisor_without_protocol_revision_is_accepted() {
        let state = state_with_sandbox("sb-legacy").await;
        let mut harness = crate::grpc::test_support::connect_supervisor_stream(
            &state,
            "sb-legacy",
            LEGACY_SUPERVISOR_PROTOCOL_REVISION,
        )
        .await
        .expect("legacy supervisor must connect");

        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected SessionAccepted");
        };
        assert_eq!(
            accepted.protocol_revision,
            LEGACY_SUPERVISOR_PROTOCOL_REVISION
        );
        assert!(
            state
                .supervisor_sessions
                .is_current_session("sb-legacy", &accepted.session_id)
        );
    }

    #[tokio::test]
    async fn stage_one_supervisor_uses_polling_compatibility() {
        let state = state_with_sandbox("sb-stage-one").await;
        let mut harness = crate::grpc::test_support::connect_supervisor_stream(
            &state,
            "sb-stage-one",
            PREVIOUS_SUPERVISOR_PROTOCOL_REVISION,
        )
        .await
        .expect("Stage 1 supervisor must connect");

        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected SessionAccepted");
        };
        assert_eq!(
            accepted.protocol_revision,
            PREVIOUS_SUPERVISOR_PROTOCOL_REVISION
        );
        assert!(
            state
                .supervisor_sessions
                .is_current_session("sb-stage-one", &accepted.session_id)
        );
    }

    #[tokio::test]
    async fn unknown_supervisor_protocol_revision_is_rejected() {
        let state = state_with_sandbox("sb-future").await;
        let Err(status) = crate::grpc::test_support::connect_supervisor_stream(
            &state,
            "sb-future",
            SUPERVISOR_PROTOCOL_REVISION + 1,
        )
        .await
        else {
            panic!("mismatched revision must be rejected");
        };

        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert!(status.message().contains("revision mismatch"));
        assert!(state.supervisor_sessions.connected_sandbox_ids().is_empty());
    }

    #[test]
    fn supervisor_protocol_revision_rejects_unknown_peers() {
        let error =
            validate_protocol_revision("sb-1", SUPERVISOR_PROTOCOL_REVISION + 1).unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("revision mismatch"));
    }

    #[tokio::test]
    async fn config_router_reports_missing_session() {
        let router = LocalSupervisorConfigRouter::new(Arc::new(SupervisorSessionRegistry::new()));
        assert_eq!(
            router
                .deliver(
                    "missing",
                    SupervisorConfigMessage::SandboxConfig(Box::default()),
                )
                .await,
            DeliveryDisposition::NoActiveSession
        );
    }

    #[tokio::test]
    async fn config_router_assigns_sequences_per_component() {
        let registry = Arc::new(SupervisorSessionRegistry::new());
        let router = LocalSupervisorConfigRouter::new(Arc::clone(&registry));
        let (tx, mut rx) = mpsc::channel(4);
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        registry.register("sb-1".into(), "session-1".into(), tx, shutdown_tx);

        assert_eq!(
            router
                .deliver(
                    "sb-1",
                    SupervisorConfigMessage::SandboxConfig(Box::new(SandboxConfigSnapshot {
                        config_revision: 2,
                        ..Default::default()
                    })),
                )
                .await,
            DeliveryDisposition::Enqueued
        );
        assert_eq!(
            router
                .deliver(
                    "sb-1",
                    SupervisorConfigMessage::SandboxConfig(Box::default()),
                )
                .await,
            DeliveryDisposition::Coalesced
        );
        assert_eq!(
            router
                .deliver(
                    "sb-1",
                    SupervisorConfigMessage::ProviderEnvironment(
                        ProviderEnvironmentSnapshot::default(),
                    ),
                )
                .await,
            DeliveryDisposition::Enqueued
        );

        let first = rx.recv().await.expect("first config update");
        let third = rx.recv().await.expect("provider config update");
        let update = |message: GatewayMessage| match message.payload {
            Some(gateway_message::Payload::ConfigUpdate(update)) => update,
            other => panic!("expected config update, got {other:?}"),
        };
        let first = update(first);
        assert_eq!(first.component_sequence, 1);
        let revision = registry
            .sessions
            .lock()
            .unwrap()
            .get("sb-1")
            .unwrap()
            .config_sequences
            .sandbox_config
            .in_flight
            .as_ref()
            .unwrap()
            .revision;
        registry
            .complete_config_update(
                "sb-1",
                "session-1",
                &ConfigUpdateResult {
                    update_id: first.update_id,
                    component_sequence: first.component_sequence,
                    result: Some(ConfigComponentApplyResult {
                        component: ConfigComponent::SandboxConfig.into(),
                        requested_revision: Some(revision),
                        applied_revision: Some(revision),
                        outcome: ConfigApplyOutcome::Applied.into(),
                        failure: None,
                    }),
                },
            )
            .unwrap();
        let second = update(rx.recv().await.expect("coalesced config update"));
        assert_eq!(second.component_sequence, 2);
        assert_eq!(update(third).component_sequence, 1);
    }

    #[tokio::test]
    async fn config_router_uses_replacement_session() {
        let registry = Arc::new(SupervisorSessionRegistry::new());
        let router = LocalSupervisorConfigRouter::new(Arc::clone(&registry));
        let (old_tx, mut old_rx) = mpsc::channel(2);
        let (old_shutdown_tx, _old_shutdown_rx) = oneshot::channel();
        registry.register("sb-1".into(), "old-session".into(), old_tx, old_shutdown_tx);

        assert_eq!(
            router
                .deliver(
                    "sb-1",
                    SupervisorConfigMessage::SandboxConfig(Box::default()),
                )
                .await,
            DeliveryDisposition::Enqueued
        );
        let old_update = old_rx.recv().await.expect("old-session config update");
        let Some(gateway_message::Payload::ConfigUpdate(old_update)) = old_update.payload else {
            panic!("expected config update");
        };
        assert_eq!(old_update.component_sequence, 1);

        let (new_tx, mut new_rx) = mpsc::channel(1);
        let (new_shutdown_tx, _new_shutdown_rx) = oneshot::channel();
        assert!(registry.register("sb-1".into(), "new-session".into(), new_tx, new_shutdown_tx,));

        assert_eq!(
            router
                .deliver(
                    "sb-1",
                    SupervisorConfigMessage::SandboxConfig(Box::default()),
                )
                .await,
            DeliveryDisposition::Enqueued
        );
        assert!(old_rx.try_recv().is_err());
        let new_update = new_rx.try_recv().expect("new-session config update");
        let Some(gateway_message::Payload::ConfigUpdate(new_update)) = new_update.payload else {
            panic!("expected config update");
        };
        assert_eq!(new_update.component_sequence, 1);
    }

    #[tokio::test]
    async fn config_router_reports_full_and_closed_queues() {
        let registry = Arc::new(SupervisorSessionRegistry::new());
        let router = LocalSupervisorConfigRouter::new(Arc::clone(&registry));
        let (tx, rx) = mpsc::channel(1);
        tx.try_send(GatewayMessage::default()).unwrap();
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        registry.register("sb-1".into(), "session-1".into(), tx, shutdown_tx);
        assert_eq!(
            router
                .deliver(
                    "sb-1",
                    SupervisorConfigMessage::SandboxConfig(Box::default()),
                )
                .await,
            DeliveryDisposition::QueueFull
        );

        drop(rx);
        assert_eq!(
            router
                .deliver(
                    "sb-1",
                    SupervisorConfigMessage::SandboxConfig(Box::default()),
                )
                .await,
            DeliveryDisposition::SessionClosed
        );
    }

    #[tokio::test]
    async fn config_router_rejects_oversized_messages() {
        let registry = Arc::new(SupervisorSessionRegistry::new());
        let router = LocalSupervisorConfigRouter::new(Arc::clone(&registry));
        let (tx, mut rx) = mpsc::channel(1);
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        registry.register("sb-1".into(), "session-1".into(), tx, shutdown_tx);

        let snapshot = ProviderEnvironmentSnapshot {
            values: vec![ProviderEnvironmentValue {
                name: "TOKEN".into(),
                value: "x".repeat(MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            router
                .deliver(
                    "sb-1",
                    SupervisorConfigMessage::ProviderEnvironment(snapshot),
                )
                .await,
            DeliveryDisposition::PayloadTooLarge
        );
        assert!(rx.try_recv().is_err());
    }
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

        assert_eq!(registry.remove_if_current("sbx", "s1"), Some(false));
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
        assert_eq!(registry.remove_if_current("sbx", "s-old"), None);
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
        assert_eq!(registry.remove_if_current("sbx-does-not-exist", "s1"), None);
    }

    #[test]
    fn remove_if_current_returns_terminal_finalization_state() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, _rx) = mpsc::channel(1);
        registry.register("sbx".to_string(), "s1".to_string(), tx, make_shutdown());

        assert!(registry.finalize_main_process_exit("sbx"));
        assert!(registry.terminal_delivery_finalized("sbx"));
        assert_eq!(registry.remove_if_current("sbx", "s1"), Some(true));
    }

    // ---- open_relay: happy path and wait semantics ----

    #[tokio::test]
    async fn open_relay_sends_relay_open_to_registered_session() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, mut rx) = mpsc::channel(4);
        registry.register("sbx".to_string(), "s1".to_string(), tx, make_shutdown());

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
    fn gateway_shutdown_makes_session_transport_close_nonfatal() {
        let status =
            Status::unknown("h2 protocol error: error reading a body from connection: broken pipe");

        assert!(expected_transport_close_during_session_state(
            &status, true, false, false,
        ));
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
                    .checked_sub(Duration::from_mins(1))
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
                    .checked_sub(Duration::from_mins(1))
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
