// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use metrics::counter;
use prost::Message;
use tokio::sync::{OwnedRwLockReadGuard, RwLock, mpsc, oneshot, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};
use uuid::Uuid;

use openshell_core::proto::{
    ConfigUpdate, GatewayMessage, GetSandboxProviderStatusRequest,
    GetSandboxProviderStatusResponse, PeerNotifyConfigUpdateRequest,
    PeerNotifyConfigUpdateResponse, PeerRelayFrame, PeerRelayInit, ProviderReadinessObservation,
    RelayFrame, RelayInit, RelayOpen, ReportEndpointStatusRequest, ReportEndpointStatusResponse,
    ReportMainProcessExitRequest, ReportMainProcessExitResponse, ReportProviderReadinessRequest,
    ReportProviderReadinessResponse, Sandbox, SandboxPhase, SessionAccepted, SessionRedirect,
    SshRelayTarget, SupervisorHello, SupervisorMessage, config_update, gateway_message,
    open_shell_client, peer_relay_frame, relay_open, supervisor_message,
};
use openshell_core::transport_errors::is_expected_transport_close_status;

use crate::ServerState;
use crate::auth::principal::Principal;
use crate::config_delivery::{
    ConfigComponentKind, ConfigSlots, DeliveryDisposition, MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES,
    SessionOutbound, SupervisorConfigMessage,
};
#[cfg(test)]
use crate::config_delivery::{LocalSupervisorConfigTransport, SupervisorConfigTransport};
use crate::gateway_metrics::{
    self, GaugeSlot, PeerRpc, RelayCapacity, RelayKind, RelayRejection, RelayRoute,
    RoutedRequestTimer,
};
use crate::grpc::provider_readiness::ProviderReadinessEvidence;
use crate::persistence::{ObjectId, ObjectWorkspace};
use crate::supervisor_owner::{
    OWNER_TTL, OwnerError, OwnerGuard, SupervisorOwnerIndex, can_supersede,
};

const HEARTBEAT_INTERVAL_SECS: u32 = 15;
const OWNER_RENEW_TIMEOUT: Duration = Duration::from_secs(5);
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
/// The replica relay cap above, published as a capacity gauge when the metrics recorder is
/// installed.
pub(crate) const RELAY_CAPACITY: RelayCapacity = RelayCapacity {
    per_replica: MAX_PENDING_RELAYS,
};
const PEER_TLS_CA_FILE_ENV: &str = "OPENSHELL_PEER_TLS_CA_FILE";
const PEER_TLS_CERT_FILE_ENV: &str = "OPENSHELL_PEER_TLS_CERT_FILE";
const PEER_TLS_KEY_FILE_ENV: &str = "OPENSHELL_PEER_TLS_KEY_FILE";
const PEER_TLS_SERVER_NAME_ENV: &str = "OPENSHELL_PEER_TLS_SERVER_NAME";
/// How long a resolved owner record is reused before rereading the store.
/// Well below `OWNER_TTL` so a cache hit can never outlive the record itself.
/// Marks an owner record written by a gateway that advertises no peer endpoint.
/// Only that gateway can serve such a session, so no peer should dial it.
const LOCAL_OWNER_ENDPOINT_SCHEME: &str = "local://";
const OWNER_CACHE_TTL: Duration = Duration::from_secs(3);
/// How often the owner cache reclaims expired entries. Rate-limited so an
/// insert never scans the whole map.
const OWNER_CACHE_SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// How long the projected peer `ServiceAccount` token is held in memory.
/// The kubelet rotates the file hourly, so this only bounds staleness.
const PEER_TOKEN_CACHE_TTL: Duration = Duration::from_mins(5);

#[derive(Debug, Default)]
struct PeerTlsClientConfig {
    ca_file: Option<std::path::PathBuf>,
    cert_file: Option<std::path::PathBuf>,
    key_file: Option<std::path::PathBuf>,
    server_name: Option<String>,
}

impl PeerTlsClientConfig {
    fn from_env() -> Self {
        Self {
            ca_file: nonempty_env(PEER_TLS_CA_FILE_ENV).map(Into::into),
            cert_file: nonempty_env(PEER_TLS_CERT_FILE_ENV).map(Into::into),
            key_file: nonempty_env(PEER_TLS_KEY_FILE_ENV).map(Into::into),
            server_name: nonempty_env(PEER_TLS_SERVER_NAME_ENV),
        }
    }

    fn load(&self) -> Result<ClientTlsConfig, Status> {
        let mut tls = if let Some(path) = self.ca_file.as_deref() {
            let pem = std::fs::read(path).map_err(|err| {
                Status::failed_precondition(format!(
                    "failed to read gateway peer TLS CA {}: {err}",
                    path.display()
                ))
            })?;
            ClientTlsConfig::new().ca_certificate(Certificate::from_pem(pem))
        } else {
            ClientTlsConfig::new().with_native_roots()
        };

        match (self.cert_file.as_deref(), self.key_file.as_deref()) {
            (Some(cert_path), Some(key_path)) => {
                let cert = std::fs::read(cert_path).map_err(|err| {
                    Status::failed_precondition(format!(
                        "failed to read gateway peer TLS certificate {}: {err}",
                        cert_path.display()
                    ))
                })?;
                let key = std::fs::read(key_path).map_err(|err| {
                    Status::failed_precondition(format!(
                        "failed to read gateway peer TLS key {}: {err}",
                        key_path.display()
                    ))
                })?;
                tls = tls.identity(Identity::from_pem(cert, key));
            }
            (None, None) => {}
            _ => {
                return Err(Status::failed_precondition(format!(
                    "{PEER_TLS_CERT_FILE_ENV} and {PEER_TLS_KEY_FILE_ENV} must be configured together"
                )));
            }
        }

        if let Some(server_name) = self.server_name.as_deref() {
            tls = tls.domain_name(server_name);
        }
        Ok(tls)
    }
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Reusable peer state: one HTTP/2 channel per peer endpoint, the projected
/// `ServiceAccount` token, and recently resolved owner records.
///
/// Without this every forwarded relay paid a TLS handshake, a blocking token
/// file read, and a store read.
#[derive(Default)]
pub struct PeerRouteCache {
    channels: Mutex<HashMap<String, Channel>>,
    token: Mutex<Option<CachedPeerToken>>,
    owners: Mutex<OwnerCache>,
}

#[derive(Default)]
struct OwnerCache {
    entries: HashMap<String, CachedOwner>,
    last_sweep: Option<Instant>,
}

/// Hand-written so the cached `ServiceAccount` token is never formatted.
impl std::fmt::Debug for PeerRouteCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerRouteCache").finish_non_exhaustive()
    }
}

struct CachedPeerToken {
    token: String,
    refresh_at: Instant,
}

struct CachedOwner {
    record: crate::supervisor_owner::OwnerRecord,
    expires_at: Instant,
}

impl PeerRouteCache {
    /// Cloning a `Channel` shares the existing connection, so concurrent relays
    /// to the same peer multiplex as HTTP/2 streams instead of dialing again.
    async fn channel(&self, endpoint: &str) -> Result<Channel, Status> {
        let cached = self.channels.lock().unwrap().get(endpoint).cloned();
        if let Some(channel) = cached {
            return Ok(channel);
        }

        let connected = build_peer_channel(endpoint).await?;
        let mut channels = self.channels.lock().unwrap();
        // Two relays can miss together; keep whichever landed first so both
        // end up on one connection and the loser's channel is dropped.
        Ok(channels
            .entry(endpoint.to_string())
            .or_insert(connected)
            .clone())
    }

    /// Drops a peer connection so the next relay redials. Needed when a pod is
    /// replaced and its endpoint now points at a dead or recycled address.
    fn evict_channel(&self, endpoint: &str) {
        self.channels.lock().unwrap().remove(endpoint);
    }

    async fn peer_token(&self) -> Result<String, Status> {
        let cached = self
            .token
            .lock()
            .unwrap()
            .as_ref()
            .filter(|cached| cached.refresh_at > Instant::now())
            .map(|cached| cached.token.clone());
        if let Some(token) = cached {
            return Ok(token);
        }

        let loaded = tokio::task::spawn_blocking(
            crate::auth::peer::load_peer_service_account_token_from_env,
        )
        .await
        .map_err(|_| Status::internal("gateway peer token read task failed"))?
        .map_err(|err| {
            Status::failed_precondition(format!("gateway peer token load failed: {err}"))
        })?
        .ok_or_else(|| {
            Status::failed_precondition("gateway peer ServiceAccount token is not configured")
        })?;

        *self.token.lock().unwrap() = Some(CachedPeerToken {
            token: loaded.clone(),
            refresh_at: Instant::now() + PEER_TOKEN_CACHE_TTL,
        });
        Ok(loaded)
    }

    fn cached_owner(&self, sandbox_id: &str) -> Option<crate::supervisor_owner::OwnerRecord> {
        let now = Instant::now();
        let mut owners = self.owners.lock().unwrap();
        let entry = owners.entries.get(sandbox_id)?;
        if entry.expires_at <= now {
            owners.entries.remove(sandbox_id);
            return None;
        }
        Some(entry.record.clone())
    }

    fn store_owner(&self, sandbox_id: &str, record: &crate::supervisor_owner::OwnerRecord) {
        let now = Instant::now();
        let mut owners = self.owners.lock().unwrap();
        // Expiry is enforced per entry on read, so the full scan only needs to
        // reclaim memory. Rate-limit it to keep inserts off an O(n) path.
        if owners
            .last_sweep
            .is_none_or(|last| now.duration_since(last) >= OWNER_CACHE_SWEEP_INTERVAL)
        {
            owners.last_sweep = Some(now);
            owners.entries.retain(|_, entry| entry.expires_at > now);
        }
        owners.entries.insert(
            sandbox_id.to_string(),
            CachedOwner {
                record: record.clone(),
                expires_at: now + OWNER_CACHE_TTL,
            },
        );
    }

    fn evict_owner(&self, sandbox_id: &str) {
        self.owners.lock().unwrap().entries.remove(sandbox_id);
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
    /// Present only for push-capable sessions on a gateway in push mode.
    config_slots: Option<Arc<ConfigSlots>>,
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
    /// Becomes true only after the gateway durably resets endpoint status for
    /// this session and before it sends `SessionAccepted`.
    endpoint_status_initialized: bool,
    /// Last tool server endpoint-status batch committed for this authenticated session.
    ///
    /// The cursor is session authority state, not public sandbox status. A
    /// gateway restart invalidates every session and startup reconciliation
    /// resets any persisted endpoint result before requests are served.
    endpoint_report_cursor: Option<EndpointReportCursor>,
    /// Installation evidence belongs to this connection and is never restored
    /// from persistence or inherited by a replacement supervisor session.
    provider_readiness: Option<ProviderReadinessEvidence>,
    #[allow(dead_code)]
    connected_at: Instant,
    /// This session's share of `openshell_server_supervisor_sessions`, released when the entry
    /// leaves the registry by any path (supersede, remove, disconnect, cleanup).
    _gauge_slot: GaugeSlot,
}

#[derive(Debug, Default)]
struct ConfigSequences {
    sandbox_config: u64,
    provider_environment: u64,
}

/// Idempotency state for tool server endpoint-status reports from one live supervisor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EndpointReportCursor {
    /// Active effective policy represented by the accepted report sequence.
    pub(crate) policy_hash: String,
    /// Provider environment revision represented by the accepted sequence.
    pub(crate) provider_env_revision: u64,
    /// Last accepted sequence in this session; superseded snapshots may leave gaps.
    pub(crate) report_sequence: u64,
    /// Digest of the accepted request, used to reject a different body that
    /// reuses an already committed sequence number.
    pub(crate) report_digest: [u8; 32],
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
    /// Read guards cover owner publication through final cleanup, even after
    /// a session has left `sessions`. Shutdown waits for the write guard.
    session_lifetimes: Arc<RwLock<()>>,
    admission_closed: AtomicBool,
    shutdown: watch::Sender<bool>,
}

struct PendingRelay {
    sender: RelayStreamSender,
    sandbox_id: String,
    relay_open: RelayOpen,
    created_at: Instant,
    /// Last session whose outbound queue received this `RelayOpen`.
    delivered_session_id: Option<String>,
    /// This relay's share of `openshell_server_relay_pending`.
    _gauge_slot: GaugeSlot,
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

    fn track_session(&self) -> Result<OwnedRwLockReadGuard<()>, Status> {
        // Acquire tracking BEFORE checking admission. A concurrent shutdown
        // either sees this reader and waits for it, or prevents its admission.
        let lifetime = Arc::clone(&self.session_lifetimes)
            .try_read_owned()
            .map_err(|_| Status::unavailable("gateway is shutting down"))?;
        if self.admission_closed.load(Ordering::Acquire) {
            return Err(Status::unavailable("gateway is shutting down"));
        }
        Ok(lifetime)
    }

    /// Prevent existing HTTP connections from creating new owner records.
    pub(crate) fn close_admission(&self) {
        self.admission_closed.store(true, Ordering::Release);
    }

    /// Close control sessions and wait for tracked ownership cleanup. Call
    /// after compute shutdown so supervisors can finish normal stop reporting.
    pub(crate) async fn shutdown(&self, timeout: Duration) -> Result<(), String> {
        self.close_admission();
        self.shutdown.send_replace(true);
        tokio::time::timeout(timeout, self.session_lifetimes.write())
            .await
            .map(|_| ())
            .map_err(|_| {
                format!("supervisor session ownership cleanup did not complete within {timeout:?}")
            })
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
        self.register_with_config_slots(sandbox_id, session_id, tx, shutdown, None)
    }

    pub(crate) fn register_with_config_slots(
        &self,
        sandbox_id: String,
        session_id: String,
        tx: mpsc::Sender<GatewayMessage>,
        shutdown: oneshot::Sender<()>,
        config_slots: Option<Arc<ConfigSlots>>,
    ) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        let previous = sessions.remove(&sandbox_id);
        sessions.insert(
            sandbox_id.clone(),
            LiveSession {
                sandbox_id,
                session_id,
                config_slots,
                tx,
                config_sequences: ConfigSequences::default(),
                shutdown,
                terminal_delivery_finalized: false,
                endpoint_status_initialized: false,
                endpoint_report_cursor: None,
                provider_readiness: None,
                connected_at: Instant::now(),
                _gauge_slot: GaugeSlot::supervisor_session(),
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
    pub(crate) fn remove_if_current(&self, sandbox_id: &str, session_id: &str) -> Option<bool> {
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

    /// Look up a supervisor session without extending the setup deadline.
    ///
    /// Uses exponential backoff (100ms → 2s) while polling the sessions map.
    async fn wait_for_session(
        &self,
        sandbox_id: &str,
        deadline: tokio::time::Instant,
        wait_for_missing_session: bool,
    ) -> Result<(String, mpsc::Sender<GatewayMessage>), Status> {
        let mut backoff = SESSION_WAIT_INITIAL_BACKOFF;

        loop {
            let session = self
                .sessions
                .lock()
                .unwrap()
                .get(sandbox_id)
                .map(|session| (session.session_id.clone(), session.tx.clone()));
            if let Some(session) = session {
                return Ok(session);
            }
            if !wait_for_missing_session || tokio::time::Instant::now() + backoff > deadline {
                return Err(Status::unavailable("supervisor session not connected"));
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(SESSION_WAIT_MAX_BACKOFF);
        }
    }

    #[cfg(test)]
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

    /// Hand a snapshot to the session it was built for. A replacement session
    /// received its own bootstrap and must not receive an older build.
    pub(crate) fn deliver_config(
        &self,
        sandbox_id: &str,
        session_id: &str,
        message: SupervisorConfigMessage,
    ) -> DeliveryDisposition {
        let component = message.component();
        let mut sessions = self.sessions.lock().unwrap();
        let Some(session) = sessions
            .get_mut(sandbox_id)
            .filter(|session| session.session_id == session_id)
        else {
            return DeliveryDisposition::NoActiveSession;
        };
        let Some(slots) = session.config_slots.clone() else {
            return DeliveryDisposition::UnsupportedSession;
        };
        let sequence = match component {
            ConfigComponentKind::SandboxConfig => &mut session.config_sequences.sandbox_config,
            ConfigComponentKind::ProviderEnvironment => {
                &mut session.config_sequences.provider_environment
            }
        };
        // Replacing an unsent snapshot leaves a gap in the sequence.
        *sequence = sequence.saturating_add(1);
        let component_sequence = *sequence;

        let snapshot = match message {
            SupervisorConfigMessage::SandboxConfig(snapshot) => {
                config_update::Component::SandboxConfig(*snapshot)
            }
            SupervisorConfigMessage::ProviderEnvironment(snapshot) => {
                config_update::Component::ProviderEnvironment(snapshot)
            }
        };
        let gateway_message = GatewayMessage {
            payload: Some(gateway_message::Payload::ConfigUpdate(ConfigUpdate {
                update_id: Uuid::new_v4().to_string(),
                component_sequence,
                component: Some(snapshot),
            })),
        };

        if gateway_message.encoded_len() > MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES {
            return DeliveryDisposition::PayloadTooLarge;
        }
        drop(sessions);

        if slots.replace(component, gateway_message) {
            DeliveryDisposition::Replaced
        } else {
            DeliveryDisposition::Queued
        }
    }

    pub fn is_current_session(&self, sandbox_id: &str, session_id: &str) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .get(sandbox_id)
            .is_some_and(|session| session.session_id == session_id)
    }

    /// Bind the authenticated hello's installation capability to its session.
    /// Initialization is single-use and cannot erase accepted observations.
    pub(crate) fn initialize_provider_readiness(
        &self,
        sandbox_id: &str,
        session_id: &str,
        evidence: ProviderReadinessEvidence,
    ) -> Result<(), Status> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| Status::unavailable("supervisor session state is unavailable"))?;
        let session = sessions
            .get_mut(sandbox_id)
            .filter(|session| session.session_id == session_id)
            .ok_or_else(|| Status::failed_precondition("supervisor session was replaced"))?;
        if session.provider_readiness.is_some() {
            return Err(Status::failed_precondition(
                "provider readiness is already initialized",
            ));
        }
        session.provider_readiness = Some(evidence);
        Ok(())
    }

    /// Accept installation evidence only while its session owns this sandbox.
    /// Session comparison and publication share one lock so reconnects cannot
    /// transfer a predecessor's evidence into the replacement session.
    pub(crate) fn accept_provider_readiness(
        &self,
        sandbox_id: &str,
        active_instance_id: &str,
        observation: ProviderReadinessObservation,
    ) -> Result<(), Status> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| Status::unavailable("supervisor session state is unavailable"))?;
        let evidence = sessions
            .get_mut(sandbox_id)
            .filter(|session| {
                session.session_id == observation.session_id && session.endpoint_status_initialized
            })
            .and_then(|session| session.provider_readiness.as_mut())
            .ok_or_else(|| {
                Status::permission_denied(
                    "provider readiness requires the active supervisor session",
                )
            })?;
        if !evidence.belongs_to_instance(active_instance_id) {
            return Err(Status::failed_precondition(
                "provider readiness requires the current sandbox instance",
            ));
        }
        evidence.accept(observation)
    }

    /// Snapshot installation evidence from the current initialized session.
    /// Disconnect and replacement discard the previous connection's state.
    pub(crate) fn provider_readiness(
        &self,
        sandbox_id: &str,
    ) -> Result<Option<ProviderReadinessEvidence>, Status> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| Status::unavailable("supervisor session state is unavailable"))?;
        Ok(sessions
            .get(sandbox_id)
            .filter(|session| session.endpoint_status_initialized)
            .and_then(|session| session.provider_readiness.clone()))
    }

    /// Mark the current session as the observation authority after its
    /// public endpoint results have been durably reset.
    pub(crate) fn initialize_endpoint_status_authority(
        &self,
        sandbox_id: &str,
        session_id: &str,
    ) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        let Some(session) = sessions
            .get_mut(sandbox_id)
            .filter(|session| session.session_id == session_id)
        else {
            return false;
        };
        session.endpoint_status_initialized = true;
        true
    }

    /// Return whether the named session has completed endpoint status
    /// initialization and still owns reporting authority.
    pub(crate) fn is_endpoint_status_authority(&self, sandbox_id: &str, session_id: &str) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .get(sandbox_id)
            .is_some_and(|session| {
                session.session_id == session_id && session.endpoint_status_initialized
            })
    }

    /// Fail closed when projecting persisted endpoint status without a live,
    /// initialized observation authority in the current gateway process.
    pub(crate) fn project_endpoint_status(&self, sandbox: &mut Sandbox, remote_authority: bool) {
        let sandbox_id = sandbox.object_id();
        let has_authority = self
            .sessions
            .lock()
            .unwrap()
            .get(sandbox_id)
            .is_some_and(|session| session.endpoint_status_initialized);
        if has_authority || remote_authority {
            return;
        }
        let Some(status) = sandbox.status.as_mut() else {
            return;
        };
        // Status without its live observation authority is unknown. Keep the
        // configured address so a caller can still identify each endpoint.
        for endpoint in &mut status.endpoint_statuses {
            endpoint.last_result = openshell_core::proto::EndpointResult::NoObservedExchange as i32;
            endpoint.last_reported_time = None;
        }
    }

    /// Return the active supervisor session identifier for gateway-owned
    /// status reconciliation.
    pub fn current_session_id(&self, sandbox_id: &str) -> Option<String> {
        self.sessions
            .lock()
            .unwrap()
            .get(sandbox_id)
            .map(|session| session.session_id.clone())
    }

    /// Return the endpoint report cursor only when `session_id` still owns the
    /// sandbox. Replacement sessions never inherit predecessor sequencing.
    pub(crate) fn endpoint_report_cursor(
        &self,
        sandbox_id: &str,
        session_id: &str,
    ) -> Option<EndpointReportCursor> {
        self.sessions
            .lock()
            .unwrap()
            .get(sandbox_id)
            .filter(|session| session.session_id == session_id)
            .and_then(|session| session.endpoint_report_cursor.clone())
    }

    /// Record a committed endpoint report for the current session.
    ///
    /// Returns `false` when a reconnect replaced the caller while its storage
    /// write was in flight. The replacement performs its own pre-acknowledgment
    /// reset, so it remains the sole observation authority.
    pub(crate) fn commit_endpoint_report_cursor(
        &self,
        sandbox_id: &str,
        session_id: &str,
        cursor: EndpointReportCursor,
    ) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        let Some(session) = sessions
            .get_mut(sandbox_id)
            .filter(|session| session.session_id == session_id)
        else {
            return false;
        };
        session.endpoint_report_cursor = Some(cursor);
        true
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
    /// The timeout bounds session lookup, reconnect retries, and outbound queue
    /// capacity waits together. Callers pick it based on their patience.
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
        let channel_id = Uuid::new_v4().to_string();
        let relay_open = RelayOpen {
            channel_id: channel_id.clone(),
            target: Some(target),
            service_id,
        };
        self.open_relay_with_message(sandbox_id, relay_open, session_wait_timeout)
            .await
    }

    pub async fn open_relay_with_message(
        &self,
        sandbox_id: &str,
        relay_open: RelayOpen,
        session_wait_timeout: Duration,
    ) -> Result<
        (
            String,
            oneshot::Receiver<Result<tokio::io::DuplexStream, Status>>,
        ),
        Status,
    > {
        self.open_relay_with_message_until(
            sandbox_id,
            relay_open,
            tokio::time::Instant::now() + session_wait_timeout,
            true,
        )
        .await
    }

    /// Local routing skips waiting for a missing session, but queue capacity
    /// and reconnect retries still share the routing caller's setup deadline.
    async fn open_relay_with_message_until(
        &self,
        sandbox_id: &str,
        relay_open: RelayOpen,
        deadline: tokio::time::Instant,
        wait_for_missing_session: bool,
    ) -> Result<
        (
            String,
            oneshot::Receiver<Result<tokio::io::DuplexStream, Status>>,
        ),
        Status,
    > {
        if relay_open.channel_id.is_empty() {
            return Err(Status::invalid_argument("relay channel_id is required"));
        }
        tokio::time::timeout_at(deadline, async {
            let channel_id = relay_open.channel_id.clone();

            // Register the pending relay before sending RelayOpen to avoid a race.
            // Both caps are checked and the insert happens under a single lock hold
            // so two concurrent calls can't both observe "under the cap" and then
            // both insert past it.
            let (relay_tx, relay_rx) = oneshot::channel();
            let mut relay_tx = Some(relay_tx);
            loop {
                if tokio::time::Instant::now() >= deadline {
                    return Err(Status::deadline_exceeded("supervisor relay setup timed out"));
                }
                let (session_id, tx) = self
                    .wait_for_session(sandbox_id, deadline, wait_for_missing_session)
                    .await?;
                // Reserve capacity before taking synchronous locks. The session
                // may change while waiting; validate it again before insertion.
                let permit = tx
                    .reserve()
                    .await
                    .map_err(|_| Status::unavailable("supervisor session disconnected"))?;
                if tokio::time::Instant::now() >= deadline {
                    return Err(Status::deadline_exceeded("supervisor relay setup timed out"));
                }
                let sent = {
                    let sessions = self.sessions.lock().unwrap();
                    if sessions
                        .get(sandbox_id)
                        .is_some_and(|session| session.session_id == session_id)
                    {
                        let mut pending = self.pending_relays.lock().unwrap();
                        if pending.len() >= MAX_PENDING_RELAYS {
                            gateway_metrics::record_relay_rejected(RelayRejection::ReplicaCapacity);
                            return Err(Status::resource_exhausted(format!(
                                "gateway relay capacity reached ({MAX_PENDING_RELAYS} in flight)"
                            )));
                        }
                        let per_sandbox = pending
                            .values()
                            .filter(|p| p.sandbox_id == sandbox_id)
                            .count();
                        if per_sandbox >= MAX_PENDING_RELAYS_PER_SANDBOX {
                            gateway_metrics::record_relay_rejected(RelayRejection::SandboxCapacity);
                            return Err(Status::resource_exhausted(format!(
                                "per-sandbox relay limit reached ({MAX_PENDING_RELAYS_PER_SANDBOX} in flight for {sandbox_id})"
                            )));
                        }
                        pending.insert(
                            channel_id.clone(),
                            PendingRelay {
                                sender: relay_tx.take().unwrap(),
                                sandbox_id: sandbox_id.to_string(),
                                relay_open: relay_open.clone(),
                                created_at: Instant::now(),
                                delivered_session_id: Some(session_id),
                                _gauge_slot: GaugeSlot::relay_pending(),
                            },
                        );
                        // Insertion, delivery selection, and enqueueing are atomic with
                        // respect to registration and replay. No await holds these locks.
                        permit.send(GatewayMessage {
                            payload: Some(gateway_message::Payload::RelayOpen(relay_open.clone())),
                        });
                        true
                    } else {
                        false
                    }
                };
                if sent {
                    return Ok((channel_id, relay_rx));
                }
            }
        })
        .await
        .map_err(|_| Status::deadline_exceeded("supervisor relay setup timed out"))?
    }

    pub fn fail_pending_relay(&self, channel_id: &str, error: String) -> bool {
        // The rest of the entry, including its gauge slot, drops inside this statement while the
        // lock is still held, so `relay_pending` never exceeds capacity.
        let Some(sender) = self
            .pending_relays
            .lock()
            .unwrap()
            .remove(channel_id)
            .map(|pending| pending.sender)
        else {
            return false;
        };
        let _ = sender.send(Err(Status::unavailable(error)));
        true
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
        let (sender, sandbox_id) = {
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

            let waited = pending.created_at.elapsed();
            if waited > RELAY_PENDING_TIMEOUT {
                map.remove(channel_id);
                gateway_metrics::record_relay_expired(1);
                return Err(Status::deadline_exceeded("relay channel timed out"));
            }
            gateway_metrics::record_relay_claimed(waited);

            // The rest of the entry, including its gauge slot, drops at the end of this
            // statement while the lock is still held, so `relay_pending` never exceeds capacity.
            let PendingRelay {
                sender, sandbox_id, ..
            } = map
                .remove(channel_id)
                .expect("pending relay existed before removal");
            (sender, sandbox_id)
        };

        // Create a duplex stream pair: one end for the gateway bridge, one for
        // the supervisor HTTP CONNECT handler.
        let (gateway_stream, supervisor_stream) = tokio::io::duplex(64 * 1024);

        // Send the gateway-side stream to the waiter (exec handler or forward handler).
        if sender.send(Ok(gateway_stream)).is_err() {
            return Err(Status::internal("relay requester dropped"));
        }

        Ok(ClaimedRelay {
            stream: supervisor_stream,
            sandbox_id,
        })
    }

    /// Remove all pending relays that have exceeded the timeout.
    pub fn reap_expired_relays(&self) {
        let reaped = {
            let mut map = self.pending_relays.lock().unwrap();
            let before = map.len();
            map.retain(|_, pending| pending.created_at.elapsed() <= RELAY_PENDING_TIMEOUT);
            before - map.len()
        };
        gateway_metrics::record_relay_expired(reaped);
    }

    /// Clean up all state for a sandbox (session + pending relays).
    pub fn cleanup_sandbox(&self, sandbox_id: &str) {
        self.remove(sandbox_id);
    }

    pub async fn replay_pending_relays(
        &self,
        sandbox_id: &str,
        session_id: &str,
        tx: &mpsc::Sender<GatewayMessage>,
    ) {
        for channel_id in self.pending_channel_ids(sandbox_id) {
            let needs_replay = {
                let pending = self.pending_relays.lock().unwrap();
                pending.get(&channel_id).is_some_and(|pending| {
                    pending.delivered_session_id.as_deref() != Some(session_id)
                })
            };
            if !needs_replay {
                continue;
            }
            let Ok(permit) = tx.reserve().await else {
                warn!(sandbox_id = %sandbox_id, channel_id = %channel_id, "supervisor session: failed to replay pending relay to connected session");
                break;
            };
            let sessions = self.sessions.lock().unwrap();
            if sessions
                .get(sandbox_id)
                .is_none_or(|session| session.session_id != session_id)
            {
                break;
            }
            let mut pending = self.pending_relays.lock().unwrap();
            if let Some(pending) = pending.get_mut(&channel_id)
                && pending.delivered_session_id.as_deref() != Some(session_id)
            {
                pending.delivered_session_id = Some(session_id.to_string());
                permit.send(GatewayMessage {
                    payload: Some(gateway_message::Payload::RelayOpen(
                        pending.relay_open.clone(),
                    )),
                });
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

fn owner_error_to_status(err: OwnerError) -> Status {
    match err {
        OwnerError::AlreadyOwned => {
            Status::unavailable("supervisor session owned by another gateway replica")
        }
        OwnerError::Conflict => Status::aborted("supervisor owner record changed concurrently"),
        OwnerError::Store(err) => {
            Status::internal(format!("supervisor owner persistence failed: {err}"))
        }
    }
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
            .is_some_and(|metadata| metadata.deletion_time.is_some())
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
// PeerRelay gRPC handler and client-side forwarding
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct PeerAuthInterceptor {
    bearer: MetadataValue<Ascii>,
    replica_id: MetadataValue<Ascii>,
}

impl PeerAuthInterceptor {
    fn new(token: &str, replica_id: &str) -> Result<Self, Status> {
        let bearer = MetadataValue::try_from(format!("Bearer {token}"))
            .map_err(|_| Status::internal("invalid gateway peer SA token header value"))?;
        let replica_id = MetadataValue::try_from(replica_id.to_string())
            .map_err(|_| Status::internal("invalid gateway replica id header value"))?;
        Ok(Self { bearer, replica_id })
    }
}

impl tonic::service::Interceptor for PeerAuthInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        req.metadata_mut()
            .insert("authorization", self.bearer.clone());
        req.metadata_mut()
            .insert("x-openshell-peer-replica", self.replica_id.clone());
        Ok(req)
    }
}

async fn build_peer_channel(endpoint: &str) -> Result<Channel, Status> {
    let mut ep = Endpoint::from_shared(endpoint.to_string())
        .map_err(|err| Status::internal(format!("invalid gateway peer endpoint: {err}")))?
        .connect_timeout(Duration::from_secs(10))
        .http2_keep_alive_interval(Duration::from_secs(10))
        .keep_alive_while_idle(true)
        .keep_alive_timeout(Duration::from_secs(20))
        .http2_adaptive_window(true);

    if endpoint.starts_with("https://") {
        let peer_tls = PeerTlsClientConfig::from_env().load()?;
        ep = ep
            .tls_config(peer_tls)
            .map_err(|err| Status::internal(format!("failed to configure peer TLS: {err}")))?;
    }

    ep.connect()
        .await
        .map_err(|err| Status::unavailable(format!("gateway peer connection failed: {err}")))
}

async fn peer_rpc_client(
    state: &Arc<ServerState>,
    endpoint: &str,
) -> Result<
    open_shell_client::OpenShellClient<
        tonic::service::interceptor::InterceptedService<Channel, PeerAuthInterceptor>,
    >,
    Status,
> {
    let token = state.peer_routes.peer_token().await?;
    let channel = state.peer_routes.channel(endpoint).await?;
    let interceptor = PeerAuthInterceptor::new(&token, &state.replica_id)?;
    Ok(open_shell_client::OpenShellClient::with_interceptor(
        channel,
        interceptor,
    ))
}

pub(crate) async fn forward_config_notify_to_peer(
    state: &Arc<ServerState>,
    endpoint: &str,
    request: PeerNotifyConfigUpdateRequest,
) -> Result<PeerNotifyConfigUpdateResponse, Status> {
    let mut client = peer_rpc_client(state, endpoint).await?;
    client
        .peer_notify_config_update(request)
        .await
        .map(Response::into_inner)
        .inspect_err(|_| state.peer_routes.evict_channel(endpoint))
}

pub(crate) async fn remote_supervisor_owner(
    state: &Arc<ServerState>,
    sandbox_id: &str,
) -> Result<Option<crate::supervisor_owner::OwnerRecord>, Status> {
    let owner_index = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL);
    // Supervisor-bound state must follow the durable owner record. A cached
    // local owner can remain valid for relay discovery while ownership has
    // already moved, but it must never authorize a stale local session to
    // publish readiness or endpoint observations.
    let Some(owner) = owner_index
        .read(sandbox_id)
        .await
        .map_err(owner_error_to_status)?
    else {
        state.peer_routes.evict_owner(sandbox_id);
        return Ok(None);
    };
    if !owner_is_fresh(&owner) {
        state.peer_routes.evict_owner(sandbox_id);
        return Ok(None);
    }
    state.peer_routes.store_owner(sandbox_id, &owner);
    if owner.owner_replica_id == state.replica_id {
        return Ok(None);
    }
    if owner_endpoint_is_local_only(&owner.owner_peer_endpoint) {
        return Err(Status::failed_precondition(format!(
            "sandbox is owned by gateway replica {} which advertises no peer endpoint",
            owner.owner_replica_id
        )));
    }
    Ok(Some(owner))
}

pub(crate) async fn forward_provider_readiness_to_owner(
    state: &Arc<ServerState>,
    owner: &crate::supervisor_owner::OwnerRecord,
    request: ReportProviderReadinessRequest,
) -> Result<ReportProviderReadinessResponse, Status> {
    let sandbox_id = request.sandbox_id.clone();
    let mut timer = RoutedRequestTimer::start(PeerRpc::ReportProviderReadiness);
    let mut client = peer_rpc_client(state, &owner.owner_peer_endpoint)
        .await
        .inspect_err(|status| timer.local_error(status))?;
    let result = client.peer_report_provider_readiness(request).await;
    timer.finish(&result);
    result.map(Response::into_inner).inspect_err(|_| {
        state.peer_routes.evict_channel(&owner.owner_peer_endpoint);
        state.peer_routes.evict_owner(&sandbox_id);
    })
}

pub(crate) async fn forward_endpoint_status_to_owner(
    state: &Arc<ServerState>,
    owner: &crate::supervisor_owner::OwnerRecord,
    request: ReportEndpointStatusRequest,
) -> Result<ReportEndpointStatusResponse, Status> {
    let sandbox_id = request.sandbox_id.clone();
    let mut timer = RoutedRequestTimer::start(PeerRpc::ReportEndpointStatus);
    let mut client = peer_rpc_client(state, &owner.owner_peer_endpoint)
        .await
        .inspect_err(|status| timer.local_error(status))?;
    let result = client.peer_report_endpoint_status(request).await;
    timer.finish(&result);
    result.map(Response::into_inner).inspect_err(|_| {
        state.peer_routes.evict_channel(&owner.owner_peer_endpoint);
        state.peer_routes.evict_owner(&sandbox_id);
    })
}

pub(crate) async fn forward_provider_status_query_to_owner(
    state: &Arc<ServerState>,
    owner: &crate::supervisor_owner::OwnerRecord,
    sandbox_id: &str,
    request: GetSandboxProviderStatusRequest,
) -> Result<GetSandboxProviderStatusResponse, Status> {
    let mut timer = RoutedRequestTimer::start(PeerRpc::GetSandboxProviderStatus);
    let mut client = peer_rpc_client(state, &owner.owner_peer_endpoint)
        .await
        .inspect_err(|status| timer.local_error(status))?;
    let result = client.peer_get_sandbox_provider_status(request).await;
    timer.finish(&result);
    result.map(Response::into_inner).inspect_err(|_| {
        state.peer_routes.evict_channel(&owner.owner_peer_endpoint);
        state.peer_routes.evict_owner(sandbox_id);
    })
}

pub async fn open_routed_relay_with_target(
    state: &Arc<ServerState>,
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
    let channel_id = Uuid::new_v4().to_string();
    let relay_open = RelayOpen {
        channel_id: channel_id.clone(),
        target: Some(target),
        service_id,
    };
    open_routed_relay_with_message(state, sandbox_id, relay_open, session_wait_timeout).await
}

fn relay_kind(relay_open: &RelayOpen) -> RelayKind {
    // An absent target means SSH for compatibility with older callers.
    match relay_open.target.as_ref() {
        Some(relay_open::Target::Ssh(_)) | None => RelayKind::Ssh,
        Some(relay_open::Target::Tcp(_)) => RelayKind::Tcp,
    }
}

/// Hand the caller a receiver that forwards the local relay's claim result unchanged, and count
/// the attempt when the supervisor claims the relay, the claim window closes, or the caller
/// gives up. The owner of a `PeerRelay` answers on the same events, so a relay outcome means
/// the same thing on the local and peer routes.
///
/// The window is anchored before the caller can start its own wait, so a caller that times out
/// with the same 10 s budget is counted as an unclaimed relay, not as a cancellation. A claim
/// that lands just after the caller gave up still succeeds in the registry; the forwarder then
/// drops the stream and the supervisor sees it close, as when a caller drops right after a claim.
fn track_local_relay_claim(
    mut timer: RoutedRequestTimer,
    mut claimed: oneshot::Receiver<Result<tokio::io::DuplexStream, Status>>,
) -> oneshot::Receiver<Result<tokio::io::DuplexStream, Status>> {
    let claim_deadline = tokio::time::Instant::now() + RELAY_PENDING_TIMEOUT;
    let unclaimed = || Status::deadline_exceeded("relay was not claimed in time");
    let (mut forward_tx, forward_rx) = oneshot::channel();
    tokio::spawn(async move {
        let claim_window = tokio::time::sleep_until(claim_deadline);
        tokio::pin!(claim_window);
        let mut window_open = true;
        let result = loop {
            tokio::select! {
                biased;
                result = &mut claimed => break result,
                () = &mut claim_window, if window_open => {
                    window_open = false;
                    timer.local_error(&unclaimed());
                }
                () = forward_tx.closed() => {
                    if tokio::time::Instant::now() >= claim_deadline {
                        timer.local_error(&unclaimed());
                    }
                    // Otherwise dropping the timer records the cancellation.
                    return;
                }
            }
        };
        match result {
            Ok(claim) => {
                timer.finish(&claim);
                let _ = forward_tx.send(claim);
            }
            // The registry dropped the relay without an answer: it expired (reaper or a late
            // claim), or the registry was torn down. Dropping `forward_tx` passes the same closed
            // channel on to the caller.
            Err(_) if tokio::time::Instant::now() >= claim_deadline => {
                timer.local_error(&unclaimed());
            }
            Err(_) => timer.local_error(&Status::unavailable("relay channel dropped")),
        }
    });
    forward_rx
}

pub async fn open_routed_relay_with_message(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    relay_open: RelayOpen,
    session_wait_timeout: Duration,
) -> Result<
    (
        String,
        oneshot::Receiver<Result<tokio::io::DuplexStream, Status>>,
    ),
    Status,
> {
    let deadline = tokio::time::Instant::now() + session_wait_timeout;
    tokio::time::timeout_at(deadline, async {
        let mut backoff = SESSION_WAIT_INITIAL_BACKOFF;
        let owner_index = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL);
        loop {
            if state.supervisor_sessions.has_session(sandbox_id) {
                let mut timer =
                    RoutedRequestTimer::relay(relay_kind(&relay_open), RelayRoute::Local);
                let result = state
                    .supervisor_sessions
                    .open_relay_with_message_until(sandbox_id, relay_open.clone(), deadline, false)
                    .await;
                if let Err(status) = &result {
                    timer.local_error(status);
                }
                match result {
                    Ok((channel_id, relay_rx)) => {
                        return Ok((channel_id, track_local_relay_claim(timer, relay_rx)));
                    }
                    Err(status) if status.code() == tonic::Code::Unavailable => {
                        // The session can migrate after `has_session` but before
                        // RelayOpen reaches its sender. Fall through and reread the
                        // persisted owner instead of surfacing a handoff race.
                        warn!(
                            sandbox_id,
                            error = %status,
                            "local supervisor relay disappeared during open; resolving owner again"
                        );
                    }
                    Err(status) => return Err(status),
                }
            }

            if let Some(owner) = resolve_owner(state, &owner_index, sandbox_id).await?
                && owner_is_fresh(&owner)
            {
                if owner.owner_replica_id == state.replica_id {
                    warn!(
                        sandbox_id,
                        owner_replica_id = %owner.owner_replica_id,
                        "supervisor owner record points at this replica but no local session is registered; retrying"
                    );
                    state.peer_routes.evict_owner(sandbox_id);
                    if tokio::time::Instant::now() + backoff > deadline {
                        return Err(Status::unavailable("supervisor session not connected"));
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(SESSION_WAIT_MAX_BACKOFF);
                    continue;
                }
                if owner_endpoint_is_local_only(&owner.owner_peer_endpoint) {
                    return Err(Status::failed_precondition(format!(
                        "sandbox is owned by gateway replica {} which advertises no peer endpoint; \
                         set OPENSHELL_PEER_ENDPOINT on every replica to route across replicas",
                        owner.owner_replica_id
                    )));
                }
                match open_peer_relay(
                    state,
                    owner.owner_peer_endpoint.clone(),
                    sandbox_id,
                    relay_open.clone(),
                )
                .await
                {
                    Ok(relay) => return Ok(relay),
                    Err(status) => {
                        warn!(
                            sandbox_id,
                            owner_replica_id = %owner.owner_replica_id,
                            owner_peer_endpoint = %owner.owner_peer_endpoint,
                            error = %status,
                            "gateway peer owner relay open failed; retrying until session wait timeout"
                        );
                        // The record may name a replaced pod, so retry against a
                        // fresh read rather than the cached endpoint.
                        state.peer_routes.evict_owner(sandbox_id);
                    }
                }
            }

            if tokio::time::Instant::now() + backoff > deadline {
                return Err(Status::unavailable("supervisor session not connected"));
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(SESSION_WAIT_MAX_BACKOFF);
        }
    })
    .await
    .map_err(|_| Status::deadline_exceeded("supervisor relay setup timed out"))?
}

/// Reads the owning replica, reusing a recent result when one is cached.
async fn resolve_owner(
    state: &Arc<ServerState>,
    owner_index: &SupervisorOwnerIndex,
    sandbox_id: &str,
) -> Result<Option<crate::supervisor_owner::OwnerRecord>, Status> {
    if let Some(record) = state.peer_routes.cached_owner(sandbox_id) {
        return Ok(Some(record));
    }

    let record = owner_index
        .read(sandbox_id)
        .await
        .map_err(owner_error_to_status)?;
    if let Some(record) = record.as_ref() {
        state.peer_routes.store_owner(sandbox_id, record);
    }
    Ok(record)
}

fn owner_is_fresh(owner: &crate::supervisor_owner::OwnerRecord) -> bool {
    owner.is_fresh(OWNER_TTL)
}

/// The replica currently holding this sandbox's supervisor session, if known.
pub async fn owner_replica_id(state: &Arc<ServerState>, sandbox_id: &str) -> Option<String> {
    if state.store.is_single_replica() {
        return None;
    }
    let local = state.supervisor_sessions.has_session(sandbox_id);
    let owner = if local {
        None
    } else {
        let owner_index = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL);
        resolve_owner(state, &owner_index, sandbox_id)
            .await
            .ok()
            .flatten()
    };
    owner_hint(&state.replica_id, local, owner.as_ref())
}

fn owner_hint(
    self_replica_id: &str,
    local: bool,
    owner: Option<&crate::supervisor_owner::OwnerRecord>,
) -> Option<String> {
    if local {
        return Some(self_replica_id.to_string());
    }
    owner
        .filter(|owner| owner_is_fresh(owner))
        .map(|owner| owner.owner_replica_id.clone())
}

/// Endpoint recorded when this replica advertises none.
fn local_owner_endpoint(replica_id: &str) -> String {
    format!("{LOCAL_OWNER_ENDPOINT_SCHEME}{replica_id}")
}

/// True when an owner record names a gateway that no peer can dial.
fn owner_endpoint_is_local_only(endpoint: &str) -> bool {
    endpoint.starts_with(LOCAL_OWNER_ENDPOINT_SCHEME)
}

/// Where the ring says this sandbox belongs, when that is not this replica.
///
/// Returns `None` whenever this replica should serve the session itself, which
/// covers single-replica mode, an empty ring, the ring naming this replica, and
/// a preferred replica with no dialable peer endpoint. Falling back to local
/// ownership keeps a stale or incomplete ring from making a sandbox
/// unreachable.
fn preferred_peer_redirect(state: &Arc<ServerState>, sandbox_id: &str) -> Option<SessionRedirect> {
    if state.store.is_single_replica() {
        return None;
    }

    let preferred = {
        let ring = state.gateway_ring.read().ok()?;
        if state.gateway_shutting_down.load(Ordering::Acquire) {
            ring.without(&state.replica_id)
                .owner_for(sandbox_id)?
                .to_string()
        } else {
            ring.owner_for(sandbox_id)?.to_string()
        }
    };
    let peer_endpoint = {
        let peers = state.gateway_peers.read().ok()?;
        peers.get(&preferred).cloned()
    };

    ring_redirect(&state.replica_id, &preferred, peer_endpoint)
}

/// Decide whether a preferred replica is worth redirecting to.
///
/// Split out from the lock reads so the rules are testable on their own.
/// A replica that is shutting down redirects even an already-redirected
/// supervisor, since a peer with a stale ring may have sent it here; refusing
/// would cost the supervisor a failed attempt and its reconnect backoff.
fn may_redirect(hello: &SupervisorHello, shutting_down: bool) -> bool {
    hello.supports_session_redirect && (!hello.redirected || shutting_down)
}

fn ring_redirect(
    self_replica_id: &str,
    preferred_replica_id: &str,
    preferred_peer_endpoint: Option<String>,
) -> Option<SessionRedirect> {
    if preferred_replica_id == self_replica_id {
        return None;
    }
    let peer_endpoint = preferred_peer_endpoint?;
    // `local://` endpoints are placeholders used when no peer endpoint is
    // configured, so they are not dialable from another replica.
    if peer_endpoint.is_empty() || owner_endpoint_is_local_only(&peer_endpoint) {
        return None;
    }

    Some(SessionRedirect {
        peer_endpoint,
        owner_replica_id: preferred_replica_id.to_string(),
    })
}

async fn open_peer_relay(
    state: &Arc<ServerState>,
    owner_peer_endpoint: String,
    sandbox_id: &str,
    relay_open: RelayOpen,
) -> Result<
    (
        String,
        oneshot::Receiver<Result<tokio::io::DuplexStream, Status>>,
    ),
    Status,
> {
    let channel_id = relay_open.channel_id.clone();
    let (relay_tx, relay_rx) = oneshot::channel();
    let stream = connect_peer_relay(state, &owner_peer_endpoint, sandbox_id, relay_open).await?;
    let _ = relay_tx.send(Ok(stream));
    Ok((channel_id, relay_rx))
}

/// Open a `PeerRelay` stream to the owner replica and bridge it to a local duplex stream.
///
/// The peer request metrics count attempts, so the routed-relay retry loop spikes `unavailable`
/// during rollouts. `ok` means the owner's supervisor claimed the relay (response headers
/// arrived); later bridge failures are not counted.
async fn connect_peer_relay(
    state: &Arc<ServerState>,
    owner_peer_endpoint: &str,
    sandbox_id: &str,
    relay_open: RelayOpen,
) -> Result<tokio::io::DuplexStream, Status> {
    let mut timer = RoutedRequestTimer::relay(relay_kind(&relay_open), RelayRoute::Peer);
    let token = state
        .peer_routes
        .peer_token()
        .await
        .inspect_err(|s| timer.local_error(s))?;
    let channel = state
        .peer_routes
        .channel(owner_peer_endpoint)
        .await
        .inspect_err(|s| timer.local_error(s))?;
    let interceptor = PeerAuthInterceptor::new(&token, &state.replica_id)
        .inspect_err(|s| timer.local_error(s))?;
    let mut client = open_shell_client::OpenShellClient::with_interceptor(channel, interceptor);

    let (out_tx, out_rx) = mpsc::channel::<PeerRelayFrame>(16);
    out_tx
        .send(PeerRelayFrame {
            payload: Some(peer_relay_frame::Payload::Init(PeerRelayInit {
                sandbox_id: sandbox_id.to_string(),
                relay_open: Some(relay_open),
                requester_replica_id: state.replica_id.clone(),
            })),
        })
        .await
        .map_err(|_| Status::internal("failed to initialize peer relay stream"))
        .inspect_err(|s| timer.local_error(s))?;

    let result = client.peer_relay(ReceiverStream::new(out_rx)).await;
    // Record the owner's code before the remap below hides it as `unavailable`.
    timer.finish(&result);
    let response = result.map_err(|err| {
        state.peer_routes.evict_channel(owner_peer_endpoint);
        Status::unavailable(format!("gateway peer relay RPC failed: {err}"))
    })?;
    let inbound = response.into_inner();
    let (gateway_stream, bridge_stream) = tokio::io::duplex(64 * 1024);
    spawn_peer_bridge(bridge_stream, inbound, out_tx, sandbox_id.to_string());
    Ok(gateway_stream)
}

pub async fn handle_peer_relay(
    state: &Arc<ServerState>,
    request: Request<tonic::Streaming<PeerRelayFrame>>,
) -> Result<
    Response<
        Pin<Box<dyn tokio_stream::Stream<Item = Result<PeerRelayFrame, Status>> + Send + 'static>>,
    >,
    Status,
> {
    let peer = match request.extensions().get::<Principal>() {
        Some(Principal::Peer(peer)) => peer.clone(),
        _ => {
            return Err(Status::permission_denied(
                "gateway peer principal is required",
            ));
        }
    };
    let mut inbound = request.into_inner();

    let first = inbound
        .message()
        .await?
        .ok_or_else(|| Status::invalid_argument("empty PeerRelay stream"))?;
    let Some(peer_relay_frame::Payload::Init(init)) = first.payload else {
        return Err(Status::invalid_argument(
            "first PeerRelayFrame must be init",
        ));
    };
    if init.sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }
    if init.requester_replica_id != peer.replica_id {
        return Err(Status::permission_denied(
            "peer relay requester does not match authenticated gateway replica",
        ));
    }
    let relay_open = init
        .relay_open
        .ok_or_else(|| Status::invalid_argument("relay_open is required"))?;
    if relay_open.channel_id.is_empty() {
        return Err(Status::invalid_argument("relay channel_id is required"));
    }

    info!(
        sandbox_id = %init.sandbox_id,
        channel_id = %relay_open.channel_id,
        requester = %peer.replica_id,
        "gateway peer relay: opening local supervisor relay"
    );

    let (channel_id, relay_rx) = state
        .supervisor_sessions
        .open_relay_with_message(&init.sandbox_id, relay_open, Duration::from_secs(5))
        .await?;
    let supervisor_stream = match tokio::time::timeout(Duration::from_secs(10), relay_rx).await {
        Ok(Ok(Ok(stream))) => stream,
        Ok(Ok(Err(status))) => return Err(status),
        Ok(Err(_)) => return Err(Status::unavailable("relay channel dropped")),
        Err(_) => return Err(Status::deadline_exceeded("relay open timed out")),
    };

    let (out_tx, out_rx) = mpsc::channel::<Result<PeerRelayFrame, Status>>(16);
    spawn_peer_owner_bridge(
        supervisor_stream,
        inbound,
        out_tx,
        init.sandbox_id,
        channel_id,
    );
    let stream: Pin<
        Box<dyn tokio_stream::Stream<Item = Result<PeerRelayFrame, Status>> + Send + 'static>,
    > = Box::pin(ReceiverStream::new(out_rx));
    Ok(Response::new(stream))
}

fn spawn_peer_bridge(
    bridge_stream: tokio::io::DuplexStream,
    mut inbound: tonic::Streaming<PeerRelayFrame>,
    out_tx: mpsc::Sender<PeerRelayFrame>,
    sandbox_id: String,
) {
    let (mut read_half, mut write_half) = tokio::io::split(bridge_stream);
    let sandbox_id_in = sandbox_id.clone();
    tokio::spawn(async move {
        loop {
            match inbound.message().await {
                Ok(Some(frame)) => {
                    let Some(peer_relay_frame::Payload::Data(data)) = frame.payload else {
                        warn!(sandbox_id = %sandbox_id_in, "gateway peer relay: non-data frame after init");
                        break;
                    };
                    if data.is_empty() {
                        continue;
                    }
                    if let Err(err) =
                        tokio::io::AsyncWriteExt::write_all(&mut write_half, &data).await
                    {
                        warn!(sandbox_id = %sandbox_id_in, error = %err, "gateway peer relay: write to duplex failed");
                        break;
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    warn!(sandbox_id = %sandbox_id_in, error = %err, "gateway peer relay: inbound errored");
                    break;
                }
            }
        }
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut write_half).await;
    });

    tokio::spawn(async move {
        let mut buf = vec![0u8; RELAY_STREAM_CHUNK_SIZE];
        loop {
            match tokio::io::AsyncReadExt::read(&mut read_half, &mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if out_tx
                        .send(PeerRelayFrame {
                            payload: Some(peer_relay_frame::Payload::Data(buf[..n].to_vec())),
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(err) => {
                    warn!(sandbox_id = %sandbox_id, error = %err, "gateway peer relay: read from duplex failed");
                    break;
                }
            }
        }
    });
}

fn spawn_peer_owner_bridge(
    supervisor_stream: tokio::io::DuplexStream,
    mut inbound: tonic::Streaming<PeerRelayFrame>,
    out_tx: mpsc::Sender<Result<PeerRelayFrame, Status>>,
    sandbox_id: String,
    channel_id: String,
) {
    let (mut read_half, mut write_half) = tokio::io::split(supervisor_stream);
    let sandbox_id_in = sandbox_id.clone();
    let channel_id_in = channel_id.clone();
    tokio::spawn(async move {
        loop {
            match inbound.message().await {
                Ok(Some(frame)) => {
                    let Some(peer_relay_frame::Payload::Data(data)) = frame.payload else {
                        warn!(sandbox_id = %sandbox_id_in, channel_id = %channel_id_in, "gateway peer relay owner: non-data frame after init");
                        break;
                    };
                    if data.is_empty() {
                        continue;
                    }
                    if let Err(err) =
                        tokio::io::AsyncWriteExt::write_all(&mut write_half, &data).await
                    {
                        warn!(sandbox_id = %sandbox_id_in, channel_id = %channel_id_in, error = %err, "gateway peer relay owner: write to supervisor relay failed");
                        break;
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    warn!(sandbox_id = %sandbox_id_in, channel_id = %channel_id_in, error = %err, "gateway peer relay owner: inbound errored");
                    break;
                }
            }
        }
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut write_half).await;
    });

    tokio::spawn(async move {
        let mut buf = vec![0u8; RELAY_STREAM_CHUNK_SIZE];
        loop {
            match tokio::io::AsyncReadExt::read(&mut read_half, &mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if out_tx
                        .send(Ok(PeerRelayFrame {
                            payload: Some(peer_relay_frame::Payload::Data(buf[..n].to_vec())),
                        }))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(err) => {
                    warn!(sandbox_id = %sandbox_id, channel_id = %channel_id, error = %err, "gateway peer relay owner: read from supervisor relay failed");
                    break;
                }
            }
        }
    });
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
    // Captured before reading any bootstrap input, including the sandbox
    // record, so registration detects publications the bootstrap may miss.
    let captured_seq = (state.config.config_delivery_mode
        == openshell_core::config::ConfigDeliveryMode::Push
        && hello.supports_config_snapshots)
        .then(|| state.config_delivery.current_seq());
    let sandbox = require_persisted_sandbox(&state.store, &sandbox_id).await?;

    // Validate readiness identities before replacing a healthy session. Older
    // supervisors remain usable but cannot assert provider installation.
    let provider_readiness = ProviderReadinessEvidence::from_hello(&hello)?;

    // If the ring places this sandbox on a different live replica, send the
    // supervisor there instead of claiming ownership here. Decided before the
    // session is tracked so a redirect never consumes a session slot. An
    // established session is only relocated when this replica shuts down.
    if may_redirect(&hello, state.gateway_shutting_down.load(Ordering::Acquire))
        && let Some(redirect) = preferred_peer_redirect(state, &sandbox_id)
    {
        info!(
            sandbox_id = %sandbox_id,
            owner_replica_id = %redirect.owner_replica_id,
            replica_id = %state.replica_id,
            "supervisor session: redirecting to ring-preferred replica"
        );
        if state.supervisor_sessions.has_session(&sandbox_id) {
            let owner_index = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL);
            let supersedes = match owner_index.read(&sandbox_id).await {
                Ok(Some(owner)) => can_supersede(
                    &owner,
                    &hello.instance_id,
                    hello.connection_epoch,
                    OWNER_TTL,
                ),
                Ok(None) => true,
                Err(_) => false,
            };
            if supersedes {
                state.supervisor_sessions.disconnect(&sandbox_id);
            }
        }
        let (tx, rx) = mpsc::channel::<Result<GatewayMessage, Status>>(1);
        let message = GatewayMessage {
            payload: Some(gateway_message::Payload::SessionRedirect(redirect)),
        };
        // Capacity 1 and a fresh receiver, so this cannot block. Dropping the
        // sender ends the stream, which closes the supervisor's connection.
        let _ = tx.send(Ok(message)).await;
        drop(tx);
        return Ok(Response::new(Box::pin(ReceiverStream::new(rx))));
    }

    // Build the bootstrap only for a session this replica keeps.
    let config_push = captured_seq.map(|captured_seq| ConfigPushSetup {
        captured_seq,
        workspace: sandbox.object_workspace().to_string(),
        providers: sandbox
            .spec
            .as_ref()
            .map(|spec| spec.providers.iter().cloned().collect())
            .unwrap_or_default(),
    });
    let bootstrap = if config_push.is_none() {
        None
    } else {
        match crate::config_delivery::build_config_bootstrap(state, &sandbox).await {
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
                None
            }
        }
    };

    let session_lifetime = state.supervisor_sessions.track_session()?;
    let state = Arc::clone(state);
    // Keep setup alive if the RPC caller disconnects after publication. The
    // tracking guard moves into the session task or outlives early cleanup.
    tokio::spawn(establish_supervisor_session(
        state,
        inbound,
        hello,
        bootstrap,
        config_push,
        provider_readiness,
        session_lifetime,
    ))
    .await
    .map_err(|error| Status::internal(format!("supervisor session setup failed: {error}")))?
}

struct ConfigPushSetup {
    captured_seq: u64,
    workspace: String,
    providers: HashSet<String>,
}

async fn establish_supervisor_session(
    state: Arc<ServerState>,
    mut inbound: tonic::Streaming<SupervisorMessage>,
    hello: SupervisorHello,
    bootstrap: Option<openshell_core::proto::ConfigBootstrap>,
    config_push: Option<ConfigPushSetup>,
    provider_readiness: ProviderReadinessEvidence,
    session_lifetime: OwnedRwLockReadGuard<()>,
) -> Result<
    Response<
        Pin<Box<dyn tokio_stream::Stream<Item = Result<GatewayMessage, Status>> + Send + 'static>>,
    >,
    Status,
> {
    let sandbox_id = hello.sandbox_id.clone();
    let session_id = Uuid::new_v4().to_string();
    let owner_peer_endpoint = state.peer_endpoint.as_deref().map_or_else(
        || local_owner_endpoint(&state.replica_id),
        ToString::to_string,
    );
    let owner_index = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL);
    let owner_guard = owner_index
        .publish(
            &sandbox_id,
            &session_id,
            &hello.instance_id,
            hello.connection_epoch,
            &state.replica_id,
            &owner_peer_endpoint,
        )
        .await
        .map_err(owner_error_to_status)?;
    info!(
        sandbox_id = %sandbox_id,
        session_id = %session_id,
        instance_id = %hello.instance_id,
        connection_epoch = hello.connection_epoch,
        replica_id = %state.replica_id,
        "supervisor session: accepted"
    );

    // Step 2: Queue SessionAccepted before the session becomes routable. This
    // keeps a concurrent ConfigUpdate from becoming the first stream message.
    let (tx, rx) = mpsc::channel::<GatewayMessage>(64);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let mut accepted = GatewayMessage {
        payload: Some(gateway_message::Payload::SessionAccepted(SessionAccepted {
            session_id: session_id.clone(),
            bootstrap,
            heartbeat_interval: openshell_core::time::duration_from_std(Duration::from_secs(
                u64::from(HEARTBEAT_INTERVAL_SECS),
            ))
            .ok(),
        })),
    };
    if accepted.encoded_len() > MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES {
        counter!(
            "openshell_supervisor_config_bootstrap_total",
            "outcome" => "payload_too_large"
        )
        .increment(1);
        let Some(gateway_message::Payload::SessionAccepted(accepted_payload)) =
            accepted.payload.as_mut()
        else {
            unreachable!("constructed SessionAccepted payload")
        };
        accepted_payload.bootstrap = None;
    }
    let bootstrap_built = matches!(
        &accepted.payload,
        Some(gateway_message::Payload::SessionAccepted(SessionAccepted {
            bootstrap: Some(_),
            ..
        }))
    );
    let config_slots = config_push
        .as_ref()
        .map(|_| Arc::new(ConfigSlots::default()));
    if tx.send(accepted).await.is_err() {
        if let Err(err) = owner_index.release_if_current(&owner_guard).await {
            warn!(sandbox_id = %sandbox_id, session_id = %session_id, error = %err, "supervisor session: failed to release owner after accept queue failure");
        }
        return Err(Status::internal("failed to send session accepted"));
    }

    let superseded = state.supervisor_sessions.register_with_config_slots(
        sandbox_id.clone(),
        session_id.clone(),
        tx.clone(),
        shutdown_tx,
        config_slots.clone(),
    );
    if superseded {
        info!(
            sandbox_id = %sandbox_id,
            session_id = %session_id,
            "supervisor session: superseded previous session"
        );
    }

    // A replacement stream is a new observation authority. Reset its endpoint
    // results before acknowledging the session so it cannot inherit evidence
    // reported by the superseded stream.
    if let Err(error) = crate::grpc::policy::reset_endpoint_status_for_supervisor_session(
        &state,
        &sandbox_id,
        &session_id,
    )
    .await
    {
        state
            .supervisor_sessions
            .remove_if_current(&sandbox_id, &session_id);
        if let Err(err) = owner_index.release_if_current(&owner_guard).await {
            warn!(sandbox_id, session_id, error = %err, "supervisor session: failed to release owner after endpoint status initialization failure");
        }
        return Err(error);
    }
    if !state
        .supervisor_sessions
        .initialize_endpoint_status_authority(&sandbox_id, &session_id)
    {
        if let Err(err) = owner_index.release_if_current(&owner_guard).await {
            warn!(sandbox_id, session_id, error = %err, "supervisor session: failed to release superseded owner during endpoint status initialization");
        }
        return Err(Status::failed_precondition(
            "supervisor session was replaced during endpoint status initialization",
        ));
    }
    if let Err(error) = state.supervisor_sessions.initialize_provider_readiness(
        &sandbox_id,
        &session_id,
        provider_readiness,
    ) {
        state
            .supervisor_sessions
            .remove_if_current(&sandbox_id, &session_id);
        if let Err(err) = owner_index.release_if_current(&owner_guard).await {
            warn!(sandbox_id, session_id, error = %err, "supervisor session: failed to release owner after provider readiness initialization failure");
        }
        return Err(error);
    }

    if let Err(err) = state
        .compute
        .supervisor_session_connected(&sandbox_id, &hello.instance_id)
        .await
    {
        // Do not expose SessionAccepted to the supervisor when the gateway
        // could not durably record the connection. Dropping the buffered
        // response forces a reconnect, which gives the state transition a
        // fresh chance instead of leaving a healthy-looking supervisor tied
        // to a sandbox that never reaches Ready.
        state
            .supervisor_sessions
            .remove_if_current(&sandbox_id, &session_id);
        if let Err(release_error) = owner_index.release_if_current(&owner_guard).await {
            warn!(sandbox_id, session_id, error = %release_error, "supervisor session: failed to release owner after lifecycle persistence failure");
        }
        warn!(
            sandbox_id = %sandbox_id,
            session_id = %session_id,
            error = %err,
            "supervisor session: failed to mark sandbox ready"
        );
        return Err(Status::aborted(
            "failed to persist supervisor session state; reconnect",
        ));
    }
    state.telemetry.sandbox_session_connected(&sandbox_id);

    // A disconnected session may already have removed its registration while
    // an unclaimed RelayOpen remains pending. Replay on every accepted session,
    // including reconnects that did not supersede a live registration.
    state
        .supervisor_sessions
        .replay_pending_relays(&sandbox_id, &session_id, &tx)
        .await;

    if let Some(setup) = config_push {
        crate::config_delivery::register_session(
            &state,
            crate::config_delivery::Registration {
                sandbox_id: sandbox_id.clone(),
                session_id: session_id.clone(),
                workspace: setup.workspace,
                providers: setup.providers,
                captured_seq: setup.captured_seq,
                bootstrap_built,
            },
        );
    }

    // Step 4: Spawn the session loop that reads inbound messages.
    let state_clone = Arc::clone(&state);
    let sandbox_id_clone = sandbox_id.clone();
    let supports_session_redirect = hello.supports_session_redirect;
    tokio::spawn(async move {
        let _session_lifetime = session_lifetime;
        let mut owner_guard = owner_guard;
        run_session_loop(
            &state_clone,
            &sandbox_id_clone,
            &session_id,
            supports_session_redirect,
            &tx,
            &mut inbound,
            shutdown_rx,
            &mut owner_guard,
        )
        .await;
        let terminal_finalized = state_clone
            .supervisor_sessions
            .remove_if_current(&sandbox_id_clone, &session_id);
        // Every removal path ends this task, including supersede and disconnect.
        crate::config_delivery::unregister_session(&state_clone, &sandbox_id_clone, &session_id);
        // Release only this exact ownership record. A newer supervisor session
        // may already have published replacement ownership on another replica.
        let owner_index = SupervisorOwnerIndex::new(state_clone.store.clone(), OWNER_TTL);
        if let Err(err) = owner_index.release_if_current(&owner_guard).await {
            warn!(sandbox_id = %sandbox_id_clone, session_id = %session_id, error = %err, "supervisor session: failed to release owner record");
        }
        if let Some(terminal_finalized) = terminal_finalized {
            info!(sandbox_id = %sandbox_id_clone, session_id = %session_id, "supervisor session: ended");
            state_clone
                .telemetry
                .sandbox_session_disconnected(&sandbox_id_clone);
            tokio::spawn(
                crate::grpc::policy::retry_endpoint_status_after_supervisor_disconnect(
                    Arc::clone(&state_clone),
                    sandbox_id_clone.clone(),
                ),
            );
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
    let stream: Pin<
        Box<dyn tokio_stream::Stream<Item = Result<GatewayMessage, Status>> + Send + 'static>,
    > = match config_slots {
        Some(slots) => Box::pin(SessionOutbound::new(rx, slots)),
        None => Box::pin(tokio_stream::StreamExt::map(ReceiverStream::new(rx), Ok)),
    };

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
    let session_finalized = state
        .supervisor_sessions
        .finalize_main_process_exit(&report.sandbox_id);
    // The session can close between durable result validation and this mark.
    // Schedule cleanup in either case so a disconnect with an unfinalized
    // in-memory session cannot strand the ephemeral sandbox.
    state
        .compute
        .cleanup_finalized_ephemeral_sandbox(&report.sandbox_id, &report.instance_id)
        .await
        .map_err(Status::internal)?;
    if !session_finalized {
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
    supports_session_redirect: bool,
    tx: &mpsc::Sender<GatewayMessage>,
    inbound: &mut tonic::Streaming<SupervisorMessage>,
    mut shutdown_rx: oneshot::Receiver<()>,
    owner_guard: &mut OwnerGuard,
) {
    let mut gateway_shutdown = state.supervisor_sessions.shutdown.subscribe();
    let heartbeat_interval = Duration::from_secs(u64::from(HEARTBEAT_INTERVAL_SECS));
    let mut heartbeat_timer = tokio::time::interval(heartbeat_interval);
    // Skip the first immediate tick.
    heartbeat_timer.tick().await;

    loop {
        tokio::select! {
            () = async { let _ = gateway_shutdown.wait_for(|shutdown| *shutdown).await; } => {
                info!(sandbox_id = %sandbox_id, session_id = %session_id, "supervisor session: gateway shutting down");
                if supports_session_redirect
                    && let Some(redirect) = preferred_peer_redirect(state, sandbox_id)
                {
                    let _ = tx.try_send(GatewayMessage {
                        payload: Some(gateway_message::Payload::SessionRedirect(redirect)),
                    });
                }
                break;
            }
            _ = &mut shutdown_rx => {
                info!(sandbox_id = %sandbox_id, session_id = %session_id, "supervisor session: superseded by reconnect, shutting down");
                break;
            }
            msg = inbound.message() => {
                match msg {
                    Ok(Some(msg)) => {
                        if !handle_supervisor_message(state, sandbox_id, session_id, msg, owner_guard).await {
                            break;
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
        }
    }
}

async fn handle_supervisor_message(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    msg: SupervisorMessage,
    owner_guard: &mut OwnerGuard,
) -> bool {
    match msg.payload {
        Some(supervisor_message::Payload::Heartbeat(_)) => {
            let owner_index = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL);
            match tokio::time::timeout(OWNER_RENEW_TIMEOUT, owner_index.renew(owner_guard)).await {
                Ok(Ok(())) => {}
                // Only a real ownership change ends the session. A store error
                // means the database did not answer, and closing on that would
                // drop every session heartbeating during the outage.
                Ok(Err(err)) if err.is_ownership_lost() => {
                    warn!(
                        sandbox_id = %sandbox_id,
                        session_id = %session_id,
                        error = %err,
                        "supervisor session: ownership lost; closing session"
                    );
                    return false;
                }
                // Past the TTL our record is stale, so another replica may
                // already have superseded it. Close rather than serve a
                // session we can no longer claim.
                Ok(Err(err)) if owner_guard.claim_expired(OWNER_TTL) => {
                    warn!(
                        sandbox_id = %sandbox_id,
                        session_id = %session_id,
                        error = %err,
                        "supervisor session: owner renewal failed past the ownership TTL; \
                         closing session"
                    );
                    return false;
                }
                Ok(Err(err)) => warn!(
                    sandbox_id = %sandbox_id,
                    session_id = %session_id,
                    error = %err,
                    "supervisor session: owner renewal failed; retrying on next heartbeat"
                ),
                Err(_) if owner_guard.claim_expired(OWNER_TTL) => {
                    warn!(
                        sandbox_id = %sandbox_id,
                        session_id = %session_id,
                        timeout_ms = OWNER_RENEW_TIMEOUT.as_millis(),
                        "supervisor session: owner renewal timed out past the ownership TTL; closing session"
                    );
                    return false;
                }
                Err(_) => warn!(
                    sandbox_id = %sandbox_id,
                    session_id = %session_id,
                    timeout_ms = OWNER_RENEW_TIMEOUT.as_millis(),
                    "supervisor session: owner renewal timed out; retrying on next heartbeat"
                ),
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
        Some(supervisor_message::Payload::ConfigUpdateResult(result)) => {
            debug!(
                sandbox_id = %sandbox_id,
                session_id = %session_id,
                component_sequence = result.component_sequence,
                "supervisor session: ignoring configuration result while polling remains authoritative"
            );
        }
        Some(supervisor_message::Payload::ConfigBootstrapResult(result)) => {
            debug!(
                sandbox_id = %sandbox_id,
                session_id = %session_id,
                result_count = result.results.len(),
                "supervisor session: ignoring bootstrap result while polling remains authoritative"
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::{Identity, IdentityProvider};
    use crate::auth::principal::{SandboxIdentitySource, SandboxPrincipal, UserPrincipal};
    use crate::gateway_metrics::MetricsCapture;
    use crate::persistence::Store;
    use bytes::Bytes;
    use http_body::Frame;
    use http_body_util::{BodyExt, Empty, StreamBody};
    use openshell_core::proto::{
        ProviderEnvironmentSnapshot, ProviderEnvironmentValue, SandboxConfigRevision,
        SandboxConfigSnapshot,
    };
    use prost::Message;
    use std::convert::Infallible;

    #[test]
    fn configuration_stream_messages_round_trip() {
        let bootstrap = GatewayMessage {
            payload: Some(gateway_message::Payload::SessionAccepted(SessionAccepted {
                session_id: "session-1".into(),
                heartbeat_interval: openshell_core::time::duration_from_std(Duration::from_secs(
                    15,
                ))
                .ok(),
                bootstrap: Some(openshell_core::proto::ConfigBootstrap {
                    sandbox_config: Some(SandboxConfigSnapshot::default()),
                    provider_environment: Some(ProviderEnvironmentSnapshot::default()),
                }),
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
                openshell_core::proto::ConfigUpdateResult {
                    update_id: "update-1".into(),
                    component_sequence: 4,
                    result: Some(openshell_core::proto::ConfigComponentApplyResult {
                        component: openshell_core::proto::ConfigComponent::SandboxConfig.into(),
                        requested_revision: Some(openshell_core::proto::ConfigSnapshotRevision {
                            component: Some(
                                openshell_core::proto::config_snapshot_revision::Component::SandboxConfig(
                                    SandboxConfigRevision {
                                        config_revision: 7,
                                        policy_version: 3,
                                        ..Default::default()
                                    },
                                ),
                            ),
                        }),
                        applied_revision: Some(openshell_core::proto::ConfigSnapshotRevision {
                            component: Some(
                                openshell_core::proto::config_snapshot_revision::Component::SandboxConfig(
                                    SandboxConfigRevision {
                                        config_revision: 7,
                                        policy_version: 3,
                                        ..Default::default()
                                    },
                                ),
                            ),
                        }),
                        outcome: openshell_core::proto::ConfigApplyOutcome::Applied.into(),
                        failure: None,
                    }),
                },
            )),
        };
        let decoded = SupervisorMessage::decode(result.encode_to_vec().as_slice()).unwrap();
        assert_eq!(decoded, result);
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
    async fn supervisor_without_config_snapshots_is_accepted() {
        let state = state_with_sandbox("sb-legacy").await;
        let mut harness =
            crate::grpc::test_support::connect_supervisor_stream(&state, "sb-legacy", false)
                .await
                .expect("supervisor without configuration snapshots must connect");

        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected SessionAccepted");
        };
        assert!(accepted.bootstrap.is_none());
        assert!(
            state
                .supervisor_sessions
                .is_current_session("sb-legacy", &accepted.session_id)
        );
    }

    fn register_push_session(
        registry: &SupervisorSessionRegistry,
        sandbox_id: &str,
        session_id: &str,
    ) -> (mpsc::Sender<GatewayMessage>, SessionOutbound) {
        let (tx, rx) = mpsc::channel(4);
        let slots = Arc::new(ConfigSlots::default());
        registry.register_with_config_slots(
            sandbox_id.into(),
            session_id.into(),
            tx.clone(),
            make_shutdown(),
            Some(Arc::clone(&slots)),
        );
        (tx, SessionOutbound::new(rx, slots))
    }

    fn component_sequence(message: GatewayMessage) -> (bool, u64) {
        match message.payload {
            Some(gateway_message::Payload::ConfigUpdate(update)) => (
                matches!(
                    update.component,
                    Some(config_update::Component::SandboxConfig(_))
                ),
                update.component_sequence,
            ),
            other => panic!("expected config update, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn config_transport_reports_missing_session() {
        let transport =
            LocalSupervisorConfigTransport::new(Arc::new(SupervisorSessionRegistry::new()));
        assert_eq!(
            transport
                .deliver(
                    "missing",
                    "session",
                    SupervisorConfigMessage::SandboxConfig(Box::default()),
                )
                .await,
            DeliveryDisposition::NoActiveSession
        );
    }

    #[tokio::test]
    async fn config_transport_keeps_the_latest_unsent_snapshot_per_component() {
        use tokio_stream::StreamExt as _;

        let registry = Arc::new(SupervisorSessionRegistry::new());
        let transport = LocalSupervisorConfigTransport::new(Arc::clone(&registry));
        let (_tx, mut outbound) = register_push_session(&registry, "sb-1", "session-1");

        for expected in [DeliveryDisposition::Queued, DeliveryDisposition::Replaced] {
            assert_eq!(
                transport
                    .deliver(
                        "sb-1",
                        "session-1",
                        SupervisorConfigMessage::SandboxConfig(Box::default()),
                    )
                    .await,
                expected
            );
        }
        assert_eq!(
            transport
                .deliver(
                    "sb-1",
                    "session-1",
                    SupervisorConfigMessage::ProviderEnvironment(
                        ProviderEnvironmentSnapshot::default(),
                    ),
                )
                .await,
            DeliveryDisposition::Queued
        );

        let first = outbound.next().await.unwrap().unwrap();
        let second = outbound.next().await.unwrap().unwrap();
        assert_eq!(component_sequence(first), (true, 2));
        assert_eq!(component_sequence(second), (false, 1));
    }

    #[tokio::test]
    async fn config_transport_never_crosses_into_a_replacement_session() {
        use tokio_stream::StreamExt as _;

        let registry = Arc::new(SupervisorSessionRegistry::new());
        let transport = LocalSupervisorConfigTransport::new(Arc::clone(&registry));
        let (_old_tx, _old_outbound) = register_push_session(&registry, "sb-1", "old-session");
        let (_new_tx, mut new_outbound) = register_push_session(&registry, "sb-1", "new-session");

        assert_eq!(
            transport
                .deliver(
                    "sb-1",
                    "old-session",
                    SupervisorConfigMessage::SandboxConfig(Box::default()),
                )
                .await,
            DeliveryDisposition::NoActiveSession
        );
        assert_eq!(
            transport
                .deliver(
                    "sb-1",
                    "new-session",
                    SupervisorConfigMessage::SandboxConfig(Box::default()),
                )
                .await,
            DeliveryDisposition::Queued
        );
        let update = new_outbound.next().await.unwrap().unwrap();
        assert_eq!(component_sequence(update), (true, 1));
    }

    #[tokio::test]
    async fn config_transport_skips_sessions_without_push() {
        let registry = Arc::new(SupervisorSessionRegistry::new());
        let transport = LocalSupervisorConfigTransport::new(Arc::clone(&registry));
        let (tx, _rx) = mpsc::channel(1);
        registry.register("sb-1".into(), "session-1".into(), tx, make_shutdown());
        assert_eq!(
            transport
                .deliver(
                    "sb-1",
                    "session-1",
                    SupervisorConfigMessage::SandboxConfig(Box::default()),
                )
                .await,
            DeliveryDisposition::UnsupportedSession
        );
    }

    #[tokio::test]
    async fn config_transport_rejects_oversized_messages() {
        use tokio_stream::StreamExt as _;

        let registry = Arc::new(SupervisorSessionRegistry::new());
        let transport = LocalSupervisorConfigTransport::new(Arc::clone(&registry));
        let (tx, mut outbound) = register_push_session(&registry, "sb-1", "session-1");

        let snapshot = ProviderEnvironmentSnapshot {
            values: vec![ProviderEnvironmentValue {
                name: "TOKEN".into(),
                value: "x".repeat(MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            transport
                .deliver(
                    "sb-1",
                    "session-1",
                    SupervisorConfigMessage::ProviderEnvironment(snapshot),
                )
                .await,
            DeliveryDisposition::PayloadTooLarge
        );
        drop(tx);
        registry.remove_if_current("sb-1", "session-1");
        assert!(outbound.next().await.is_none());
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

    #[tokio::test]
    async fn shutdown_waits_for_owner_release_after_session_leaves_registry() {
        let registry = Arc::new(SupervisorSessionRegistry::new());
        let owner_index = Arc::new(SupervisorOwnerIndex::new(test_store().await, OWNER_TTL));
        let lifetime = registry.track_session().unwrap();
        let owner = owner_index
            .publish(
                "sb-1",
                "old-session",
                "old-instance",
                1,
                "old-replica",
                "local://old",
            )
            .await
            .unwrap();
        let (tx, _rx) = mpsc::channel(1);
        registry.register("sb-1".into(), "old-session".into(), tx, make_shutdown());

        let (removed_tx, removed_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let cleanup_registry = Arc::clone(&registry);
        let cleanup_index = owner_index.clone();
        let cleanup = tokio::spawn(async move {
            let _lifetime = lifetime;
            cleanup_registry.remove_if_current("sb-1", "old-session");
            removed_tx.send(()).unwrap();
            release_rx.await.unwrap();
            cleanup_index.release_if_current(&owner).await.unwrap();
        });
        removed_rx.await.unwrap();
        assert!(registry.sessions.lock().unwrap().is_empty());

        let shutdown = registry.shutdown(Duration::from_secs(5));
        tokio::pin!(shutdown);
        assert!(futures_util::poll!(&mut shutdown).is_pending());
        assert!(matches!(
            owner_index
                .publish(
                    "sb-1",
                    "new-session",
                    "new-instance",
                    1,
                    "new-replica",
                    "local://new"
                )
                .await,
            Err(OwnerError::AlreadyOwned)
        ));

        release_tx.send(()).unwrap();
        shutdown.await.unwrap();
        cleanup.await.unwrap();
        assert!(owner_index.read("sb-1").await.unwrap().is_none());
        owner_index
            .publish(
                "sb-1",
                "new-session",
                "new-instance",
                1,
                "new-replica",
                "local://new",
            )
            .await
            .expect("restart can immediately claim ownership after shutdown");
    }

    #[tokio::test]
    async fn shutdown_waits_for_admitted_setup_and_rejects_new_connections() {
        let registry = SupervisorSessionRegistry::new();
        // An RPC has been admitted but has not yet registered a live session.
        let lifetime = registry.track_session().unwrap();
        registry.close_admission();
        assert_eq!(
            registry.track_session().unwrap_err().code(),
            tonic::Code::Unavailable
        );
        // Closing admission alone must leave stop reporting available.
        assert!(!*registry.shutdown.borrow());

        let shutdown = registry.shutdown(Duration::from_secs(5));
        tokio::pin!(shutdown);
        assert!(futures_util::poll!(&mut shutdown).is_pending());
        // An admitted setup that starts its session loop after cancellation
        // must still observe the shutdown signal immediately.
        let mut late_subscriber = registry.shutdown.subscribe();
        assert!(*late_subscriber.wait_for(|closing| *closing).await.unwrap());
        drop(lifetime);
        shutdown.await.unwrap();
        assert_eq!(
            registry.track_session().unwrap_err().code(),
            tonic::Code::Unavailable
        );
    }

    #[tokio::test]
    async fn shutdown_cleanup_does_not_delete_replacement_owner() {
        let registry = Arc::new(SupervisorSessionRegistry::new());
        let owner_index = SupervisorOwnerIndex::new(test_store().await, OWNER_TTL);
        let lifetime = registry.track_session().unwrap();
        let old = owner_index
            .publish("sb-1", "old", "instance", 1, "replica-a", "local://a")
            .await
            .unwrap();
        let replacement = owner_index
            .publish("sb-1", "new", "instance", 2, "replica-b", "local://b")
            .await
            .unwrap();
        let shutdown = registry.shutdown(Duration::from_secs(5));
        tokio::pin!(shutdown);
        assert!(futures_util::poll!(&mut shutdown).is_pending());
        owner_index.release_if_current(&old).await.unwrap();
        drop(lifetime);
        shutdown.await.unwrap();
        let persisted = owner_index.read("sb-1").await.unwrap().unwrap();
        assert_eq!(persisted.session_id, replacement.session_id);
        assert_eq!(persisted.owner_replica_id, replacement.owner_replica_id);
    }

    #[tokio::test]
    async fn shutdown_reports_bounded_failure_when_cleanup_stalls() {
        let registry = SupervisorSessionRegistry::new();
        let lifetime = registry.track_session().unwrap();
        let error = registry
            .shutdown(Duration::from_millis(10))
            .await
            .unwrap_err();
        assert!(error.contains("ownership cleanup did not complete"));
        assert!(*registry.shutdown.borrow());
        assert_eq!(
            registry.track_session().unwrap_err().code(),
            tonic::Code::Unavailable
        );
        drop(lifetime);
        registry.shutdown(Duration::from_secs(1)).await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_without_sessions_completes_and_closes_admission() {
        let registry = SupervisorSessionRegistry::new();
        registry.shutdown(Duration::from_secs(1)).await.unwrap();
        assert_eq!(
            registry.track_session().unwrap_err().code(),
            tonic::Code::Unavailable
        );
    }

    #[test]
    fn peer_tls_client_config_requires_certificate_and_key_together() {
        let config = PeerTlsClientConfig {
            cert_file: Some("client.crt".into()),
            ..Default::default()
        };

        let err = config
            .load()
            .expect_err("an incomplete peer mTLS identity must fail closed");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains(PEER_TLS_KEY_FILE_ENV));
    }

    #[test]
    fn peer_tls_client_config_loads_chart_ca_identity_and_server_name() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.crt");
        let cert = dir.path().join("tls.crt");
        let key = dir.path().join("tls.key");
        std::fs::write(&ca, b"test-ca").unwrap();
        std::fs::write(&cert, b"test-cert").unwrap();
        std::fs::write(&key, b"test-key").unwrap();

        let config = PeerTlsClientConfig {
            ca_file: Some(ca),
            cert_file: Some(cert),
            key_file: Some(key),
            server_name: Some("openshell.openshell.svc.cluster.local".to_string()),
        };

        config
            .load()
            .expect("complete chart peer TLS materials should configure tonic");
    }

    fn sandbox_record(id: &str, name: &str) -> Sandbox {
        Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: id.to_string(),
                name: name.to_string(),
                created_time: openshell_core::time::timestamp_from_millis(1_000_000).ok(),
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_time: None,
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
            delivered_session_id: None,
            _gauge_slot: GaugeSlot::relay_pending(),
        }
    }

    #[test]
    fn endpoint_status_projection_requires_initialized_live_authority() {
        use openshell_core::proto::{
            EndpointResult, EndpointStatus, SandboxCondition, SandboxStatus,
        };

        let registry = SupervisorSessionRegistry::new();
        let mut sandbox = sandbox_record("sandbox-1", "sandbox-1");
        let endpoint = EndpointStatus {
            endpoint_id: "endpoint:v1:test".to_string(),
            host: "api.example.com".to_string(),
            ports: vec![443],
            path: "/mcp".to_string(),
            last_result: EndpointResult::HttpResponseReceived as i32,
            last_reported_time: Some("2026-09-05T01:01:00.000Z".parse().unwrap()),
        };
        let ready = SandboxCondition {
            r#type: "Ready".to_string(),
            status: "True".to_string(),
            ..Default::default()
        };
        sandbox.status = Some(SandboxStatus {
            endpoint_statuses: vec![endpoint.clone()],
            conditions: vec![ready.clone()],
            ..Default::default()
        });
        let unknown = EndpointStatus {
            last_result: EndpointResult::NoObservedExchange as i32,
            last_reported_time: None,
            ..endpoint.clone()
        };

        let mut without_session = sandbox.clone();
        registry.project_endpoint_status(&mut without_session, false);
        let projected_status = without_session.status.expect("status");
        assert_eq!(projected_status.endpoint_statuses, vec![unknown.clone()]);
        assert_eq!(projected_status.conditions, vec![ready.clone()]);

        let mut remotely_owned = sandbox.clone();
        registry.project_endpoint_status(&mut remotely_owned, true);
        let remote_status = remotely_owned.status.expect("status");
        assert_eq!(remote_status.endpoint_statuses, vec![endpoint.clone()]);
        assert_eq!(remote_status.conditions, vec![ready.clone()]);

        let (session_tx, _session_rx) = mpsc::channel(1);
        registry.register(
            "sandbox-1".to_string(),
            "session-1".to_string(),
            session_tx,
            make_shutdown(),
        );
        let mut before_initialization = sandbox.clone();
        registry.project_endpoint_status(&mut before_initialization, false);
        let uninitialized_status = before_initialization.status.expect("status");
        assert_eq!(uninitialized_status.endpoint_statuses, vec![unknown]);
        assert_eq!(uninitialized_status.conditions, vec![ready.clone()]);

        assert!(registry.initialize_endpoint_status_authority("sandbox-1", "session-1"));
        registry.project_endpoint_status(&mut sandbox, false);
        let initialized_status = sandbox.status.expect("status");
        assert_eq!(initialized_status.endpoint_statuses, vec![endpoint]);
        assert_eq!(initialized_status.conditions, vec![ready]);
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

    #[test]
    fn session_gauge_tracks_register_supersede_and_removal() {
        let metrics = MetricsCapture::install();
        let registry = SupervisorSessionRegistry::new();
        let (tx, _rx) = mpsc::channel(1);

        registry.register(
            "sbx-a".to_string(),
            "s1".to_string(),
            tx.clone(),
            make_shutdown(),
        );
        assert_eq!(metrics.value(gateway_metrics::SUPERVISOR_SESSIONS), Some(1));
        registry.register(
            "sbx-a".to_string(),
            "s2".to_string(),
            tx.clone(),
            make_shutdown(),
        );
        assert_eq!(
            metrics.value(gateway_metrics::SUPERVISOR_SESSIONS),
            Some(1),
            "a supersede on the same replica nets zero"
        );
        registry.register("sbx-b".to_string(), "s3".to_string(), tx, make_shutdown());
        assert_eq!(metrics.value(gateway_metrics::SUPERVISOR_SESSIONS), Some(2));

        assert_eq!(registry.remove_if_current("sbx-a", "s1"), None);
        assert_eq!(metrics.value(gateway_metrics::SUPERVISOR_SESSIONS), Some(2));
        assert_eq!(registry.remove_if_current("sbx-a", "s2"), Some(false));
        assert_eq!(metrics.value(gateway_metrics::SUPERVISOR_SESSIONS), Some(1));
        assert!(registry.disconnect("sbx-b"));
        assert_eq!(metrics.value(gateway_metrics::SUPERVISOR_SESSIONS), Some(0));
    }

    // ---- open_relay: happy path and wait semantics ----

    #[tokio::test]
    async fn open_relay_sends_relay_open_to_registered_session() {
        let metrics = MetricsCapture::install();
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
        assert!(
            !metrics
                .render()
                .contains(gateway_metrics::ROUTED_REQUEST_ATTEMPTS_TOTAL),
            "owner-side registry opens must not count another routing attempt"
        );
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
        let metrics = MetricsCapture::install();
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
        // Queue capacity is reserved before insertion, so no gauge slot was ever taken.
        assert_eq!(metrics.value(gateway_metrics::RELAY_PENDING), None);
        assert_eq!(metrics.value(gateway_metrics::RELAY_EXPIRED_TOTAL), None);
    }

    #[tokio::test]
    async fn open_relay_rejects_when_global_cap_reached() {
        let metrics = MetricsCapture::install();
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
        assert_eq!(
            metrics.value("openshell_server_relay_rejected_total{reason=\"replica_capacity\"}"),
            Some(1)
        );
        assert_eq!(metrics.value(gateway_metrics::RELAY_PENDING), Some(256));
        assert_eq!(
            metrics.value("openshell_server_relay_rejected_total{reason=\"sandbox_capacity\"}"),
            None
        );
    }

    #[tokio::test]
    async fn open_relay_rejects_when_per_sandbox_cap_reached() {
        let metrics = MetricsCapture::install();
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
        assert_eq!(
            metrics.value("openshell_server_relay_rejected_total{reason=\"sandbox_capacity\"}"),
            Some(1)
        );
        assert_eq!(metrics.value(gateway_metrics::RELAY_PENDING), Some(32));

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
        assert_eq!(metrics.value(gateway_metrics::RELAY_PENDING), Some(33));
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
    async fn local_relay_attempt_skips_missing_session_without_spending_setup_budget() {
        let registry = SupervisorSessionRegistry::new();
        let started = tokio::time::Instant::now();
        let attempt = registry.open_relay_with_message_until(
            "missing",
            RelayOpen {
                channel_id: "test-channel".into(),
                ..Default::default()
            },
            started + Duration::from_secs(15),
            false,
        );
        tokio::pin!(attempt);
        let std::task::Poll::Ready(Err(error)) = futures_util::poll!(&mut attempt) else {
            panic!("local routing must immediately fall back when its session disappears");
        };
        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert!(registry.pending_relays.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn relay_setup_deadline_bounds_queue_wait_for_nonwaiting_local_attempt() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, mut rx) = mpsc::channel(1);
        registry.register("sbx".into(), "session".into(), tx.clone(), make_shutdown());
        tx.send(GatewayMessage::default()).await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let attempt = registry.open_relay_with_message_until(
            "sbx",
            RelayOpen {
                channel_id: "test-channel".into(),
                ..Default::default()
            },
            deadline,
            false,
        );
        tokio::pin!(attempt);
        // Skipping a missing-session wait must not imply a zero queue budget.
        assert!(futures_util::poll!(&mut attempt).is_pending());
        tokio::time::advance(Duration::from_secs(15)).await;
        assert_eq!(
            attempt.await.unwrap_err().code(),
            tonic::Code::DeadlineExceeded
        );
        assert!(registry.pending_relays.lock().unwrap().is_empty());
        rx.recv().await.unwrap();
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn relay_setup_deadline_is_not_reset_by_reconnects() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, mut rx) = mpsc::channel(1);
        registry.register(
            "sbx".into(),
            "session-0".into(),
            tx.clone(),
            make_shutdown(),
        );
        tx.send(GatewayMessage::default()).await.unwrap();
        let started = tokio::time::Instant::now();
        let attempt = registry.open_relay("sbx", Duration::from_secs(9));
        tokio::pin!(attempt);
        assert!(futures_util::poll!(&mut attempt).is_pending());
        for generation in 1..=2 {
            tokio::time::advance(Duration::from_secs(3)).await;
            let (new_tx, new_rx) = mpsc::channel(1);
            new_tx.send(GatewayMessage::default()).await.unwrap();
            registry.register(
                "sbx".into(),
                format!("session-{generation}"),
                new_tx,
                make_shutdown(),
            );
            rx.recv().await.unwrap();
            assert!(futures_util::poll!(&mut attempt).is_pending());
            rx = new_rx;
        }
        tokio::time::advance(Duration::from_secs(3)).await;
        assert_eq!(
            attempt.await.unwrap_err().code(),
            tonic::Code::DeadlineExceeded
        );
        assert_eq!(started.elapsed(), Duration::from_secs(9));
        assert!(registry.pending_relays.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn replay_pending_relays_does_not_duplicate_forward_opened_after_registration() {
        let registry = SupervisorSessionRegistry::new();
        let (tx_old, mut rx_old) = mpsc::channel(4);
        registry.register("sbx".into(), "old".into(), tx_old, make_shutdown());
        let (old_channel, _old_relay_rx) = registry
            .open_relay("sbx", Duration::from_secs(1))
            .await
            .unwrap();
        rx_old.recv().await.unwrap();
        registry.remove_if_current("sbx", "old");

        // Session establishment is paused between registration and replay.
        let (tx_new, mut rx_new) = mpsc::channel(4);
        registry.register("sbx".into(), "new".into(), tx_new.clone(), make_shutdown());
        let (new_channel, new_relay_rx) = registry
            .open_relay("sbx", Duration::from_secs(1))
            .await
            .unwrap();
        registry.replay_pending_relays("sbx", "new", &tx_new).await;
        registry.replay_pending_relays("sbx", "new", &tx_new).await;

        for expected in [new_channel.clone(), old_channel] {
            let Some(gateway_message::Payload::RelayOpen(open)) =
                rx_new.recv().await.unwrap().payload
            else {
                panic!("expected RelayOpen");
            };
            assert_eq!(open.channel_id, expected);
        }
        assert!(matches!(
            rx_new.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        let principal = sandbox_principal("sbx");
        let _claimed = registry
            .claim_relay(&new_channel, Some(&principal))
            .unwrap();
        assert!(new_relay_rx.await.unwrap().is_ok());
        assert_eq!(
            registry
                .claim_relay(&new_channel, Some(&principal))
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );
    }

    #[tokio::test]
    async fn open_relay_rechecks_session_after_waiting_for_queue_capacity() {
        let registry = SupervisorSessionRegistry::new();
        let (tx_old, mut rx_old) = mpsc::channel(1);
        registry.register("sbx".into(), "old".into(), tx_old.clone(), make_shutdown());
        tx_old.send(GatewayMessage::default()).await.unwrap();
        let open = registry.open_relay("sbx", Duration::from_secs(1));
        tokio::pin!(open);
        assert!(futures_util::poll!(&mut open).is_pending());

        let (tx_new, mut rx_new) = mpsc::channel(4);
        registry.register("sbx".into(), "new".into(), tx_new.clone(), make_shutdown());
        registry.replay_pending_relays("sbx", "new", &tx_new).await;
        rx_old.recv().await.unwrap();
        let (channel_id, _relay_rx) = open.await.unwrap();
        registry.replay_pending_relays("sbx", "new", &tx_new).await;
        let Some(gateway_message::Payload::RelayOpen(message)) =
            rx_new.recv().await.unwrap().payload
        else {
            panic!("expected RelayOpen on replacement session");
        };
        assert_eq!(message.channel_id, channel_id);
        assert!(rx_old.try_recv().is_err());
        assert!(matches!(
            rx_new.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn replay_pending_relays_after_disconnected_session_was_removed() {
        let registry = SupervisorSessionRegistry::new();
        let (tx_old, mut rx_old) = mpsc::channel(4);
        registry.register("sbx".into(), "old".into(), tx_old, make_shutdown());
        let (channel_id, relay_rx) = registry
            .open_relay("sbx", Duration::from_secs(1))
            .await
            .unwrap();
        rx_old.recv().await.unwrap();
        registry.remove_if_current("sbx", "old");

        let (tx_new, mut rx_new) = mpsc::channel(4);
        assert!(!registry.register("sbx".into(), "new".into(), tx_new.clone(), make_shutdown()));
        registry.replay_pending_relays("sbx", "new", &tx_new).await;
        let replayed = rx_new.recv().await.unwrap();
        let Some(gateway_message::Payload::RelayOpen(open)) = replayed.payload else {
            panic!("expected replayed RelayOpen");
        };
        assert_eq!(open.channel_id, channel_id);
        let _claimed = registry
            .claim_relay(&channel_id, Some(&sandbox_principal("sbx")))
            .unwrap();
        assert!(relay_rx.await.unwrap().is_ok());
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
            .replay_pending_relays("sbx", "s-new", &registry.lookup_session("sbx").unwrap())
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
        sandbox.metadata.as_mut().unwrap().deletion_time =
            openshell_core::time::timestamp_from_millis(1).ok();

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
        let metrics = MetricsCapture::install();
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
        assert_eq!(metrics.value(gateway_metrics::RELAY_PENDING), Some(0));
        assert_eq!(
            metrics.value("openshell_server_relay_claim_duration_seconds_count"),
            Some(1)
        );
        assert_eq!(metrics.value(gateway_metrics::RELAY_EXPIRED_TOTAL), None);
    }

    /// Waker that reads `relay_pending` each time it is woken. `oneshot::Sender::send` wakes a
    /// registered receiver synchronously, so the probe sees the gauge exactly as a waiter on
    /// another worker thread could at that instant.
    struct PendingGaugeProbe {
        read: Box<dyn Fn() -> Option<i64> + Send + Sync>,
        seen: Mutex<Vec<Option<i64>>>,
    }

    impl PendingGaugeProbe {
        fn register<T>(metrics: &MetricsCapture, rx: &mut oneshot::Receiver<T>) -> Arc<Self> {
            let probe = Arc::new(Self {
                read: metrics.value_reader(gateway_metrics::RELAY_PENDING),
                seen: Mutex::new(Vec::new()),
            });
            let waker = std::task::Waker::from(Arc::clone(&probe));
            let mut cx = std::task::Context::from_waker(&waker);
            assert!(Pin::new(rx).poll(&mut cx).is_pending());
            probe
        }

        fn seen(&self) -> Vec<Option<i64>> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl std::task::Wake for PendingGaugeProbe {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.seen.lock().unwrap().push((self.read)());
        }
    }

    #[test]
    fn claim_relay_releases_pending_slot_before_waking_waiter() {
        let metrics = MetricsCapture::install();
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, mut relay_rx) = oneshot::channel();
        registry.pending_relays.lock().unwrap().insert(
            "ch-1".to_string(),
            pending_relay("sbx-test", relay_tx, Instant::now()),
        );
        let probe = PendingGaugeProbe::register(&metrics, &mut relay_rx);

        registry
            .claim_relay("ch-1", Some(&sandbox_principal("sbx-test")))
            .expect("claim should succeed");
        // The slot is released under the pending lock, before the waiter is woken, so a
        // concurrent open can never push `relay_pending` above capacity.
        assert_eq!(probe.seen(), vec![Some(0)]);
    }

    #[test]
    fn fail_pending_relay_releases_pending_slot_before_waking_waiter() {
        let metrics = MetricsCapture::install();
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, mut relay_rx) = oneshot::channel();
        registry.pending_relays.lock().unwrap().insert(
            "ch-fail".to_string(),
            pending_relay("sbx-test", relay_tx, Instant::now()),
        );
        let probe = PendingGaugeProbe::register(&metrics, &mut relay_rx);

        assert!(registry.fail_pending_relay("ch-fail", "target refused".to_string()));
        assert_eq!(probe.seen(), vec![Some(0)]);
    }

    #[test]
    fn claim_relay_rejects_cross_sandbox_principal_without_consuming_channel() {
        let metrics = MetricsCapture::install();
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
        assert_eq!(metrics.value(gateway_metrics::RELAY_PENDING), Some(1));
        assert_eq!(
            metrics.value("openshell_server_relay_claim_duration_seconds_count"),
            None
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
        let metrics = MetricsCapture::install();
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
        assert_eq!(metrics.value(gateway_metrics::RELAY_PENDING), Some(0));
        assert_eq!(metrics.value(gateway_metrics::RELAY_EXPIRED_TOTAL), None);
    }

    #[test]
    fn claim_relay_expired_returns_deadline_exceeded() {
        let metrics = MetricsCapture::install();
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
        assert_eq!(metrics.value(gateway_metrics::RELAY_EXPIRED_TOTAL), Some(1));
        assert_eq!(metrics.value(gateway_metrics::RELAY_PENDING), Some(0));
        assert_eq!(
            metrics.value("openshell_server_relay_claim_duration_seconds_count"),
            None
        );
    }

    #[test]
    fn claim_relay_receiver_dropped_returns_internal() {
        let metrics = MetricsCapture::install();
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
        assert_eq!(
            metrics.value("openshell_server_relay_claim_duration_seconds_count"),
            Some(1)
        );
        assert_eq!(metrics.value(gateway_metrics::RELAY_PENDING), Some(0));
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
        let metrics = MetricsCapture::install();
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
        assert_eq!(metrics.value(gateway_metrics::RELAY_EXPIRED_TOTAL), Some(1));
        assert_eq!(metrics.value(gateway_metrics::RELAY_PENDING), Some(0));
    }

    #[test]
    fn reap_expired_relays_keeps_fresh_entries() {
        let metrics = MetricsCapture::install();
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
        // Reaping nothing records nothing.
        assert_eq!(metrics.value(gateway_metrics::RELAY_EXPIRED_TOTAL), None);
        assert_eq!(metrics.value(gateway_metrics::RELAY_PENDING), Some(1));
    }

    fn owner_record(replica: &str) -> crate::supervisor_owner::OwnerRecord {
        crate::supervisor_owner::OwnerRecord {
            session_id: "session-a".to_string(),
            supervisor_instance_id: "instance-a".to_string(),
            connection_epoch: 1,
            owner_replica_id: replica.to_string(),
            owner_peer_endpoint: format!("http://{replica}:8080"),
            connected_at_ms: 0,
            updated_at_ms: openshell_core::time::now_ms(),
            resource_version: 1,
        }
    }

    #[test]
    fn a_gateway_without_a_peer_endpoint_still_records_ownership() {
        let endpoint = local_owner_endpoint("gw-0");
        assert_eq!(endpoint, "local://gw-0");
        assert!(owner_endpoint_is_local_only(&endpoint));
    }

    #[test]
    fn a_dialable_owner_endpoint_is_not_local_only() {
        assert!(!owner_endpoint_is_local_only("https://10.0.0.1:8080"));
        assert!(!owner_endpoint_is_local_only("http://10.0.0.1:8080"));
    }

    #[test]
    fn owner_cache_returns_stored_record() {
        let cache = PeerRouteCache::default();
        cache.store_owner("sbx-a", &owner_record("replica-a"));

        let cached = cache
            .cached_owner("sbx-a")
            .expect("record should be cached");
        assert_eq!(cached.owner_replica_id, "replica-a");
    }

    #[test]
    fn owner_cache_misses_for_unknown_sandbox() {
        let cache = PeerRouteCache::default();
        cache.store_owner("sbx-a", &owner_record("replica-a"));

        assert!(cache.cached_owner("sbx-b").is_none());
    }

    #[test]
    fn evict_owner_forces_a_fresh_read() {
        let cache = PeerRouteCache::default();
        cache.store_owner("sbx-a", &owner_record("replica-a"));
        cache.evict_owner("sbx-a");

        assert!(cache.cached_owner("sbx-a").is_none());
    }

    #[test]
    fn owner_cache_drops_entries_past_their_ttl() {
        let cache = PeerRouteCache::default();
        cache.owners.lock().unwrap().entries.insert(
            "sbx-a".to_string(),
            CachedOwner {
                record: owner_record("replica-a"),
                expires_at: Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
            },
        );

        assert!(cache.cached_owner("sbx-a").is_none());
        assert!(!cache.owners.lock().unwrap().entries.contains_key("sbx-a"));
    }

    #[test]
    fn owner_cache_ttl_stays_below_owner_record_ttl() {
        // A cache hit must never extend the window in which a stale owner
        // looks routable; `owner_is_fresh` is what enforces the real TTL.
        assert!(OWNER_CACHE_TTL < OWNER_TTL);
    }

    // ---- peer request metrics (requester side) ----

    #[derive(Clone, Copy)]
    enum FakePeerReply {
        Status(tonic::Code),
        EmptyOk,
    }

    /// Minimal h2c server that answers every gRPC call the same way. It stands in for an owner
    /// replica without implementing the full `OpenShell` service.
    async fn spawn_fake_peer(reply: FakePeerReply) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        move |_req: http::Request<hyper::body::Incoming>| async move {
                            Ok::<_, Infallible>(fake_peer_response(reply))
                        },
                    );
                    let _ = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
                });
            }
        });
        format!("http://{addr}")
    }

    fn fake_peer_response(
        reply: FakePeerReply,
    ) -> http::Response<http_body_util::combinators::UnsyncBoxBody<Bytes, Infallible>> {
        let builder = http::Response::builder()
            .status(200)
            .header("content-type", "application/grpc");
        match reply {
            // Trailers-only error: tonic returns Err(status) for unary and streaming calls.
            FakePeerReply::Status(code) => builder
                .header("grpc-status", i32::from(code).to_string())
                .header("grpc-message", "fake peer")
                .body(Empty::new().boxed_unsync())
                .unwrap(),
            // One empty message (5-byte frame header, zero length), then grpc-status 0. This
            // decodes as a default response for any unary RPC, and gives streaming calls an OK
            // header.
            FakePeerReply::EmptyOk => {
                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
                let frames = futures::stream::iter([
                    Ok::<_, Infallible>(Frame::data(Bytes::from_static(&[0, 0, 0, 0, 0]))),
                    Ok(Frame::trailers(trailers)),
                ]);
                builder
                    .body(StreamBody::new(frames).boxed_unsync())
                    .unwrap()
            }
        }
    }

    fn seed_peer_token(state: &ServerState) {
        *state.peer_routes.token.lock().unwrap() = Some(CachedPeerToken {
            token: "test-peer-token".to_string(),
            refresh_at: Instant::now() + Duration::from_mins(5),
        });
    }

    fn owner_at(endpoint: &str) -> crate::supervisor_owner::OwnerRecord {
        let mut owner = owner_record("replica-owner");
        owner.owner_peer_endpoint = endpoint.to_string();
        owner
    }

    fn closed_local_endpoint() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        format!("http://{addr}")
    }

    fn peer_relay_open(channel_id: &str) -> RelayOpen {
        RelayOpen {
            channel_id: channel_id.to_string(),
            target: Some(relay_open::Target::Ssh(SshRelayTarget {})),
            service_id: String::new(),
        }
    }

    #[tokio::test]
    async fn routed_relay_metrics_count_local_targets_including_legacy_ssh() {
        let metrics = MetricsCapture::install();
        let state = crate::grpc::test_support::test_server_state().await;
        let (tx, mut rx) = mpsc::channel(4);
        state.supervisor_sessions.register(
            "sbx-routing".into(),
            "session-routing".into(),
            tx,
            make_shutdown(),
        );

        for (target, label, expected) in [
            (Some(relay_open::Target::Ssh(SshRelayTarget {})), "ssh", 1),
            (
                Some(relay_open::Target::Tcp(
                    openshell_core::proto::TcpRelayTarget {
                        host: "127.0.0.1".into(),
                        port: 12345,
                    },
                )),
                "tcp",
                1,
            ),
            (None, "ssh", 2),
        ] {
            let relay_open = RelayOpen {
                target,
                ..peer_relay_open(&Uuid::new_v4().to_string())
            };
            let (channel_id, relay_rx) = open_routed_relay_with_message(
                &state,
                "sbx-routing",
                relay_open.clone(),
                Duration::from_secs(1),
            )
            .await
            .unwrap();
            assert_eq!(channel_id, relay_open.channel_id);
            assert_eq!(
                rx.recv().await.unwrap().payload,
                Some(gateway_message::Payload::RelayOpen(relay_open))
            );
            let series = format!(
                "openshell_server_routed_request_attempts_total{{operation=\"relay\",route=\"local\",relay_kind=\"{label}\",outcome=\"success\",grpc_code=\"ok\"}}"
            );
            // Enqueued but not claimed yet: success waits for the supervisor.
            assert_eq!(metrics.value(&series).unwrap_or(0), expected - 1);
            let _claimed = state
                .supervisor_sessions
                .claim_relay(&channel_id, None)
                .unwrap();
            relay_rx.await.unwrap().unwrap();
            assert_eq!(metrics.value(&series), Some(expected));
        }
        let rendered = metrics.render();
        assert!(!rendered.contains("route=\"peer\""));
        for identifier in ["sbx-routing", "session-routing", "127.0.0.1", "12345"] {
            assert!(
                !rendered.contains(identifier),
                "must not label with {identifier}"
            );
        }
    }

    #[tokio::test]
    async fn routed_relay_metrics_count_failed_local_setup() {
        let metrics = MetricsCapture::install();
        let state = crate::grpc::test_support::test_server_state().await;
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        state.supervisor_sessions.register(
            "sbx-routing".into(),
            "session-routing".into(),
            tx,
            make_shutdown(),
        );

        open_routed_relay_with_message(
            &state,
            "sbx-routing",
            peer_relay_open("ch-routing"),
            Duration::from_millis(50),
        )
        .await
        .expect_err("the local supervisor disconnected");
        assert_eq!(
            metrics.value(
                "openshell_server_routed_request_attempts_total{operation=\"relay\",route=\"local\",relay_kind=\"ssh\",outcome=\"local_error\",grpc_code=\"unavailable\"}"
            ),
            Some(1)
        );
        assert!(!metrics.render().contains("route=\"peer\""));
    }

    #[tokio::test]
    async fn routed_relay_metrics_count_local_to_peer_fallback() {
        let metrics = MetricsCapture::install();
        let state = crate::grpc::test_support::test_server_state().await;
        seed_peer_token(&state);
        let endpoint = spawn_fake_peer(FakePeerReply::EmptyOk).await;
        state
            .peer_routes
            .store_owner("sbx-routing", &owner_at(&endpoint));
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        state.supervisor_sessions.register(
            "sbx-routing".into(),
            "old-session".into(),
            tx,
            make_shutdown(),
        );

        open_routed_relay_with_message(
            &state,
            "sbx-routing",
            peer_relay_open("ch-routing"),
            Duration::from_secs(5),
        )
        .await
        .expect("the peer accepts after the local supervisor disconnects");
        for route in ["local", "peer"] {
            let (outcome, code) = if route == "local" {
                ("local_error", "unavailable")
            } else {
                ("success", "ok")
            };
            assert_eq!(
                metrics.value(&format!(
                    "openshell_server_routed_request_attempts_total{{operation=\"relay\",route=\"{route}\",relay_kind=\"ssh\",outcome=\"{outcome}\",grpc_code=\"{code}\"}}"
                )),
                Some(1)
            );
        }
    }

    #[tokio::test]
    async fn routed_relay_metrics_count_peer_targets() {
        let metrics = MetricsCapture::install();
        let state = crate::grpc::test_support::test_server_state().await;
        seed_peer_token(&state);
        let endpoint = spawn_fake_peer(FakePeerReply::EmptyOk).await;
        state
            .peer_routes
            .store_owner("sbx-routing", &owner_at(&endpoint));

        for (target, label) in [
            (relay_open::Target::Ssh(SshRelayTarget {}), "ssh"),
            (
                relay_open::Target::Tcp(openshell_core::proto::TcpRelayTarget {
                    host: "127.0.0.1".into(),
                    port: 12345,
                }),
                "tcp",
            ),
        ] {
            let (_channel_id, _relay_rx) = open_routed_relay_with_target(
                &state,
                "sbx-routing",
                target,
                String::new(),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            assert_eq!(
                metrics.value(&format!(
                    "openshell_server_routed_request_attempts_total{{operation=\"relay\",route=\"peer\",relay_kind=\"{label}\",outcome=\"success\",grpc_code=\"ok\"}}"
                )),
                Some(1)
            );
        }
        let rendered = metrics.render();
        assert!(!rendered.contains("route=\"local\""));
        assert!(!rendered.contains(endpoint.trim_start_matches("http://")));
        assert!(!rendered.contains("sbx-routing"));
    }

    #[tokio::test]
    async fn routed_relay_metrics_count_each_failed_peer_retry() {
        let metrics = MetricsCapture::install();
        let state = crate::grpc::test_support::test_server_state().await;
        seed_peer_token(&state);
        let endpoint = spawn_fake_peer(FakePeerReply::Status(tonic::Code::Unavailable)).await;
        SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL)
            .publish(
                "sbx-routing",
                "session",
                "instance",
                1,
                "replica-owner",
                &endpoint,
            )
            .await
            .unwrap();

        open_routed_relay_with_message(
            &state,
            "sbx-routing",
            peer_relay_open("ch-routing"),
            Duration::from_secs(1),
        )
        .await
        .expect_err("the peer rejects every attempt");
        let attempts = metrics
            .value("openshell_server_routed_request_attempts_total{operation=\"relay\",route=\"peer\",relay_kind=\"ssh\",outcome=\"remote_error\",grpc_code=\"unavailable\"}")
            .unwrap();
        assert!(attempts > 1, "the routing loop must have retried");
        assert_eq!(
            metrics.value(
                "openshell_server_peer_request_duration_seconds_count{operation=\"relay\",outcome=\"remote_error\"}"
            ),
            Some(attempts)
        );
        assert!(!metrics.render().contains("route=\"local\""));
    }

    #[tokio::test]
    async fn routed_relay_metrics_do_not_count_waiting_for_an_owner() {
        let metrics = MetricsCapture::install();
        let state = crate::grpc::test_support::test_server_state().await;
        open_routed_relay_with_message(
            &state,
            "sbx-missing",
            peer_relay_open("ch-routing"),
            Duration::from_millis(250),
        )
        .await
        .expect_err("no supervisor or owner is available");
        assert!(
            !metrics
                .render()
                .contains(gateway_metrics::ROUTED_REQUEST_ATTEMPTS_TOTAL)
        );
    }

    #[tokio::test]
    async fn routed_relay_metrics_count_cancelled_local_setup_once() {
        let metrics = MetricsCapture::install();
        let state = crate::grpc::test_support::test_server_state().await;
        let (tx, _rx) = mpsc::channel(1);
        tx.try_send(GatewayMessage::default()).unwrap();
        state.supervisor_sessions.register(
            "sbx-routing".into(),
            "session-routing".into(),
            tx,
            make_shutdown(),
        );
        let mut setup = Box::pin(open_routed_relay_with_message(
            &state,
            "sbx-routing",
            peer_relay_open("ch-routing"),
            Duration::from_secs(5),
        ));
        tokio::select! {
            result = &mut setup => panic!("setup should wait for queue space: {result:?}"),
            () = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
        assert!(
            !metrics
                .render()
                .contains(gateway_metrics::ROUTED_REQUEST_ATTEMPTS_TOTAL)
        );
        drop(setup);
        assert_eq!(
            metrics.value("openshell_server_routed_request_attempts_total{operation=\"relay\",route=\"local\",relay_kind=\"ssh\",outcome=\"local_error\",grpc_code=\"cancelled\"}"),
            Some(1)
        );
        assert!(
            !metrics
                .render()
                .contains(gateway_metrics::PEER_REQUEST_DURATION_SECONDS)
        );
    }

    const LOCAL_RELAY_SERIES: &str = "openshell_server_routed_request_attempts_total{operation=\"relay\",route=\"local\",relay_kind=\"ssh\"";

    fn local_relay_outcome(metrics: &MetricsCapture, outcome: &str, code: &str) -> Option<i64> {
        metrics.value(&format!(
            "{LOCAL_RELAY_SERIES},outcome=\"{outcome}\",grpc_code=\"{code}\"}}"
        ))
    }

    type RelayClaim = Result<tokio::io::DuplexStream, Status>;

    fn tracked_local_relay() -> (oneshot::Sender<RelayClaim>, oneshot::Receiver<RelayClaim>) {
        let (claim_tx, claim_rx) = oneshot::channel();
        let timer = RoutedRequestTimer::relay(RelayKind::Ssh, RelayRoute::Local);
        (claim_tx, track_local_relay_claim(timer, claim_rx))
    }

    #[tokio::test]
    async fn local_relay_claim_records_success_once() {
        let metrics = MetricsCapture::install();
        let (claim_tx, forwarded) = tracked_local_relay();
        let (stream, _peer) = tokio::io::duplex(64);
        claim_tx.send(Ok(stream)).unwrap();
        forwarded.await.unwrap().unwrap();
        assert_eq!(local_relay_outcome(&metrics, "success", "ok"), Some(1));
        assert!(!metrics.render().contains("local_error"));
    }

    #[tokio::test(start_paused = true)]
    async fn local_relay_unclaimed_in_window_records_deadline_exceeded_once() {
        let metrics = MetricsCapture::install();
        let (claim_tx, forwarded) = tracked_local_relay();
        tokio::time::sleep(RELAY_PENDING_TIMEOUT + Duration::from_millis(1)).await;
        assert_eq!(
            local_relay_outcome(&metrics, "local_error", "deadline_exceeded"),
            Some(1)
        );
        // A late answer still reaches the caller without a second count.
        claim_tx
            .send(Err(Status::unavailable("supervisor gone")))
            .unwrap();
        let answer = forwarded.await.unwrap();
        assert_eq!(answer.unwrap_err().code(), tonic::Code::Unavailable);
        assert_eq!(
            local_relay_outcome(&metrics, "local_error", "unavailable"),
            None
        );
    }

    #[tokio::test(start_paused = true)]
    async fn local_relay_caller_timeout_counts_as_unclaimed_not_cancelled() {
        let metrics = MetricsCapture::install();
        let (claim_tx, forwarded) = tracked_local_relay();
        // Callers wait with the same 10 s budget and drop the receiver when it runs out.
        assert!(
            tokio::time::timeout(RELAY_PENDING_TIMEOUT, forwarded)
                .await
                .is_err()
        );
        while !claim_tx.is_closed() {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            local_relay_outcome(&metrics, "local_error", "deadline_exceeded"),
            Some(1)
        );
        assert_eq!(
            local_relay_outcome(&metrics, "local_error", "cancelled"),
            None
        );
    }

    #[tokio::test]
    async fn local_relay_failed_by_registry_records_its_status() {
        let metrics = MetricsCapture::install();
        let (claim_tx, forwarded) = tracked_local_relay();
        claim_tx
            .send(Err(Status::unavailable("supervisor session disconnected")))
            .unwrap();
        assert_eq!(
            forwarded.await.unwrap().unwrap_err().code(),
            tonic::Code::Unavailable
        );
        assert_eq!(
            local_relay_outcome(&metrics, "local_error", "unavailable"),
            Some(1)
        );
    }

    #[tokio::test]
    async fn local_relay_dropped_by_registry_closes_the_caller_channel() {
        let metrics = MetricsCapture::install();
        let (claim_tx, forwarded) = tracked_local_relay();
        drop(claim_tx);
        assert!(
            forwarded.await.is_err(),
            "the caller sees the same closed channel"
        );
        assert_eq!(
            local_relay_outcome(&metrics, "local_error", "unavailable"),
            Some(1)
        );
    }

    #[tokio::test]
    async fn local_relay_abandoned_by_caller_records_cancelled() {
        let metrics = MetricsCapture::install();
        let (claim_tx, forwarded) = tracked_local_relay();
        drop(forwarded);
        while !claim_tx.is_closed() {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            local_relay_outcome(&metrics, "local_error", "cancelled"),
            Some(1)
        );
    }

    #[tokio::test]
    async fn peer_relay_metrics_keep_owner_code_before_unavailable_remap() {
        let metrics = MetricsCapture::install();
        let state = crate::grpc::test_support::test_server_state().await;
        seed_peer_token(&state);
        let endpoint = spawn_fake_peer(FakePeerReply::Status(tonic::Code::ResourceExhausted)).await;

        let err = connect_peer_relay(&state, &endpoint, "sbx-peer", peer_relay_open("ch-peer"))
            .await
            .expect_err("the owner rejected the relay");
        assert_eq!(err.code(), tonic::Code::Unavailable);
        assert_eq!(
            metrics.value(
                "openshell_server_routed_request_attempts_total{operation=\"relay\",route=\"peer\",relay_kind=\"ssh\",outcome=\"remote_error\",grpc_code=\"resource_exhausted\"}"
            ),
            Some(1)
        );
        assert_eq!(
            metrics.value(
                "openshell_server_peer_request_duration_seconds_count{operation=\"relay\",outcome=\"remote_error\"}"
            ),
            Some(1)
        );
        let rendered = metrics.render();
        assert!(rendered.contains(
            "openshell_server_peer_request_duration_seconds_bucket{operation=\"relay\",outcome=\"remote_error\",le=\"0.001\"}"
        ));
        assert!(
            !state
                .peer_routes
                .channels
                .lock()
                .unwrap()
                .contains_key(&endpoint),
            "a failed peer relay must evict the channel"
        );
        let host_port = endpoint.trim_start_matches("http://");
        assert!(
            !rendered.contains(host_port),
            "metrics must not carry peer endpoints"
        );
    }

    #[tokio::test]
    async fn peer_relay_metrics_record_ok_when_owner_accepts() {
        let metrics = MetricsCapture::install();
        let state = crate::grpc::test_support::test_server_state().await;
        seed_peer_token(&state);
        let endpoint = spawn_fake_peer(FakePeerReply::EmptyOk).await;

        connect_peer_relay(&state, &endpoint, "sbx-peer", peer_relay_open("ch-peer"))
            .await
            .expect("the owner accepted the relay");
        assert_eq!(
            metrics.value(
                "openshell_server_routed_request_attempts_total{operation=\"relay\",route=\"peer\",relay_kind=\"ssh\",outcome=\"success\",grpc_code=\"ok\"}"
            ),
            Some(1)
        );
    }

    #[tokio::test]
    async fn peer_forward_metrics_record_local_error_when_owner_unreachable() {
        let metrics = MetricsCapture::install();
        let state = crate::grpc::test_support::test_server_state().await;
        seed_peer_token(&state);
        let endpoint = closed_local_endpoint();

        let err = forward_provider_status_query_to_owner(
            &state,
            &owner_at(&endpoint),
            "sbx-peer",
            GetSandboxProviderStatusRequest::default(),
        )
        .await
        .expect_err("the owner is unreachable");
        assert_eq!(err.code(), tonic::Code::Unavailable);
        assert_eq!(
            metrics.value(
                "openshell_server_routed_request_attempts_total{operation=\"get_sandbox_provider_status\",route=\"peer\",relay_kind=\"none\",outcome=\"local_error\",grpc_code=\"unavailable\"}"
            ),
            Some(1)
        );
        assert!(
            !metrics
                .render()
                .contains("operation=\"get_sandbox_provider_status\",outcome=\"remote_error\"")
        );
    }

    #[tokio::test]
    async fn peer_forward_metrics_record_owner_remote_error_code() {
        let metrics = MetricsCapture::install();
        let state = crate::grpc::test_support::test_server_state().await;
        seed_peer_token(&state);
        let endpoint = spawn_fake_peer(FakePeerReply::Status(tonic::Code::PermissionDenied)).await;

        let err = forward_endpoint_status_to_owner(
            &state,
            &owner_at(&endpoint),
            ReportEndpointStatusRequest {
                sandbox_id: "sbx-peer".into(),
                ..Default::default()
            },
        )
        .await
        .expect_err("the owner rejected the report");
        // Unary forwarders return the owner's status unchanged.
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            metrics.value(
                "openshell_server_routed_request_attempts_total{operation=\"report_endpoint_status\",route=\"peer\",relay_kind=\"none\",outcome=\"remote_error\",grpc_code=\"permission_denied\"}"
            ),
            Some(1)
        );
    }

    #[tokio::test]
    async fn peer_forward_metrics_record_ok() {
        let metrics = MetricsCapture::install();
        let state = crate::grpc::test_support::test_server_state().await;
        seed_peer_token(&state);
        let endpoint = spawn_fake_peer(FakePeerReply::EmptyOk).await;

        forward_provider_readiness_to_owner(
            &state,
            &owner_at(&endpoint),
            ReportProviderReadinessRequest {
                sandbox_id: "sbx-peer".into(),
                ..Default::default()
            },
        )
        .await
        .expect("the owner accepted the report");
        assert_eq!(
            metrics.value(
                "openshell_server_routed_request_attempts_total{operation=\"report_provider_readiness\",route=\"peer\",relay_kind=\"none\",outcome=\"success\",grpc_code=\"ok\"}"
            ),
            Some(1)
        );
    }

    #[tokio::test]
    async fn evict_channel_removes_only_the_named_peer() {
        let cache = PeerRouteCache::default();
        let channel = Endpoint::from_static("http://10.0.0.1:8080").connect_lazy();
        {
            let mut channels = cache.channels.lock().unwrap();
            channels.insert("http://10.0.0.1:8080".to_string(), channel.clone());
            channels.insert("http://10.0.0.2:8080".to_string(), channel);
        }

        cache.evict_channel("http://10.0.0.1:8080");

        let channels = cache.channels.lock().unwrap();
        assert!(!channels.contains_key("http://10.0.0.1:8080"));
        assert!(channels.contains_key("http://10.0.0.2:8080"));
    }

    // ---- ring_redirect: placement handoff rules ----

    #[test]
    fn ring_redirect_targets_the_preferred_replica() {
        let redirect = ring_redirect("gw-0", "gw-1", Some("https://gw-1:8443".to_string()))
            .expect("should redirect to another replica");
        assert_eq!(redirect.owner_replica_id, "gw-1");
        assert_eq!(redirect.peer_endpoint, "https://gw-1:8443");
    }

    #[test]
    fn owner_hint_names_the_replica_holding_the_session() {
        assert_eq!(owner_hint("gw-0", true, None).as_deref(), Some("gw-0"));
        assert_eq!(
            owner_hint("gw-0", false, Some(&owner_record("gw-1"))).as_deref(),
            Some("gw-1")
        );
        assert_eq!(owner_hint("gw-0", false, None), None);

        let mut stale = owner_record("gw-1");
        stale.updated_at_ms = 0;
        assert_eq!(owner_hint("gw-0", false, Some(&stale)), None);
    }

    #[test]
    fn shutdown_ring_redirects_every_owned_sandbox_to_a_remaining_replica() {
        let ring = crate::gateway_ring::GatewayRing::new(["gw-0", "gw-1", "gw-2"]);
        let draining = ring.without("gw-0");
        let owned: Vec<String> = (0..300)
            .map(|i| format!("sb-{i}"))
            .filter(|id| ring.owner_for(id) == Some("gw-0"))
            .collect();
        assert!(!owned.is_empty());
        for id in owned {
            let preferred = draining.owner_for(&id).unwrap();
            let redirect =
                ring_redirect("gw-0", preferred, Some(format!("https://{preferred}:8443")))
                    .expect("a draining replica must hand off its own sandboxes");
            assert_ne!(redirect.owner_replica_id, "gw-0");
        }
    }

    #[test]
    fn redirected_supervisors_are_only_bounced_by_a_shutting_down_replica() {
        let hello = |redirected| SupervisorHello {
            redirected,
            supports_session_redirect: true,
            ..Default::default()
        };
        assert!(may_redirect(&hello(false), false));
        assert!(!may_redirect(&hello(true), false));
        assert!(may_redirect(&hello(true), true));
    }

    #[test]
    fn supervisors_without_redirect_support_are_never_redirected() {
        let hello = SupervisorHello::default();
        assert!(!may_redirect(&hello, false));
        assert!(!may_redirect(&hello, true));
    }

    #[test]
    fn ring_redirect_serves_locally_when_this_replica_is_preferred() {
        assert!(ring_redirect("gw-0", "gw-0", Some("https://gw-0:8443".to_string())).is_none());
    }

    /// Without a dialable address we must keep the session rather than send
    /// the supervisor somewhere it cannot reach.
    #[test]
    fn ring_redirect_serves_locally_when_the_peer_endpoint_is_unknown() {
        assert!(ring_redirect("gw-0", "gw-1", None).is_none());
    }

    #[test]
    fn ring_redirect_serves_locally_for_placeholder_endpoints() {
        assert!(ring_redirect("gw-0", "gw-1", Some(String::new())).is_none());
        assert!(ring_redirect("gw-0", "gw-1", Some("local://gw-1".to_string())).is_none());
    }
}
