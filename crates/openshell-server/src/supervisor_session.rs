// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};
use uuid::Uuid;

use openshell_core::proto::{
    GatewayMessage, GetSandboxProviderStatusRequest, GetSandboxProviderStatusResponse,
    PeerRelayFrame, PeerRelayInit, ProviderReadinessObservation, RelayFrame, RelayInit, RelayOpen,
    ReportEndpointStatusRequest, ReportEndpointStatusResponse, ReportMainProcessExitRequest,
    ReportMainProcessExitResponse, ReportProviderReadinessRequest, ReportProviderReadinessResponse,
    SandboxPhase, SessionAccepted, SshRelayTarget, SupervisorMessage, gateway_message,
    open_shell_client, peer_relay_frame, relay_open, supervisor_message,
};
use openshell_core::transport_errors::is_expected_transport_close_status;

use crate::ServerState;
use crate::auth::principal::Principal;
use crate::grpc::provider_readiness::ProviderReadinessEvidence;
use crate::persistence::ObjectId;
use crate::storage_proto::StoredSandbox as Sandbox;
use crate::supervisor_owner::{OWNER_TTL, OwnerError, OwnerGuard, SupervisorOwnerIndex};

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
    tx: mpsc::Sender<GatewayMessage>,
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
                terminal_delivery_finalized: false,
                endpoint_status_initialized: false,
                endpoint_report_cursor: None,
                provider_readiness: None,
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
        if relay_open.channel_id.is_empty() {
            return Err(Status::invalid_argument("relay channel_id is required"));
        }
        let tx = self
            .wait_for_session(sandbox_id, session_wait_timeout)
            .await?;

        let channel_id = relay_open.channel_id.clone();

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
) -> Result<(), Status> {
    let sandbox = store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .map_err(|err| Status::internal(format!("failed to load sandbox: {err}")))?;

    if sandbox.is_none() {
        return Err(Status::not_found("sandbox not found"));
    }

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
    let mut client = peer_rpc_client(state, &owner.owner_peer_endpoint).await?;
    client
        .peer_report_provider_readiness(request)
        .await
        .map(Response::into_inner)
        .inspect_err(|_| {
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
    let mut client = peer_rpc_client(state, &owner.owner_peer_endpoint).await?;
    client
        .peer_report_endpoint_status(request)
        .await
        .map(Response::into_inner)
        .inspect_err(|_| {
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
    let mut client = peer_rpc_client(state, &owner.owner_peer_endpoint).await?;
    client
        .peer_get_sandbox_provider_status(request)
        .await
        .map(Response::into_inner)
        .inspect_err(|_| {
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
    let deadline = Instant::now() + session_wait_timeout;
    let mut backoff = SESSION_WAIT_INITIAL_BACKOFF;
    let owner_index = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL);
    loop {
        if state.supervisor_sessions.has_session(sandbox_id) {
            match state
                .supervisor_sessions
                .open_relay_with_message(sandbox_id, relay_open.clone(), Duration::ZERO)
                .await
            {
                Ok(relay) => return Ok(relay),
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
                if Instant::now() + backoff > deadline {
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

        if Instant::now() + backoff > deadline {
            return Err(Status::unavailable("supervisor session not connected"));
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(SESSION_WAIT_MAX_BACKOFF);
    }
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

/// Endpoint recorded when this replica advertises none.
fn local_owner_endpoint(replica_id: &str) -> String {
    format!("{LOCAL_OWNER_ENDPOINT_SCHEME}{replica_id}")
}

/// True when an owner record names a gateway that no peer can dial.
fn owner_endpoint_is_local_only(endpoint: &str) -> bool {
    endpoint.starts_with(LOCAL_OWNER_ENDPOINT_SCHEME)
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

async fn connect_peer_relay(
    state: &Arc<ServerState>,
    owner_peer_endpoint: &str,
    sandbox_id: &str,
    relay_open: RelayOpen,
) -> Result<tokio::io::DuplexStream, Status> {
    let token = state.peer_routes.peer_token().await?;
    let channel = state.peer_routes.channel(owner_peer_endpoint).await?;
    let interceptor = PeerAuthInterceptor::new(&token, &state.replica_id)?;
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
        .map_err(|_| Status::internal("failed to initialize peer relay stream"))?;

    let response = client
        .peer_relay(ReceiverStream::new(out_rx))
        .await
        .map_err(|err| {
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
    require_persisted_sandbox(&state.store, &sandbox_id).await?;
    // Validate readiness identities before replacing a healthy session. Older
    // supervisors remain usable but cannot assert provider installation.
    let provider_readiness = ProviderReadinessEvidence::from_hello(&hello)?;

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

    // A replacement stream is a new observation authority. Reset its endpoint
    // results before acknowledging the session so it cannot inherit evidence
    // reported by the superseded stream.
    if let Err(error) = crate::grpc::policy::reset_endpoint_status_for_supervisor_session(
        state,
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

    // Step 3: Send SessionAccepted.
    let accepted = GatewayMessage {
        payload: Some(gateway_message::Payload::SessionAccepted(SessionAccepted {
            session_id: session_id.clone(),
            heartbeat_interval: openshell_core::time::duration_from_std(Duration::from_secs(
                u64::from(HEARTBEAT_INTERVAL_SECS),
            ))
            .ok(),
        })),
    };
    if tx.send(accepted).await.is_err() {
        // Only evict ourselves — a faster reconnect may already have
        // superseded this registration.
        state
            .supervisor_sessions
            .remove_if_current(&sandbox_id, &session_id);
        if let Err(err) = owner_index.release_if_current(&owner_guard).await {
            warn!(sandbox_id = %sandbox_id, session_id = %session_id, error = %err, "supervisor session: failed to release owner after accept send failure");
        }
        return Err(Status::internal("failed to send session accepted"));
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
        let mut owner_guard = owner_guard;
        run_session_loop(
            &state_clone,
            &sandbox_id_clone,
            &session_id,
            &tx,
            &mut inbound,
            shutdown_rx,
            &mut owner_guard,
        )
        .await;
        let terminal_finalized = state_clone
            .supervisor_sessions
            .remove_if_current(&sandbox_id_clone, &session_id);
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

async fn run_session_loop(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    tx: &mpsc::Sender<GatewayMessage>,
    inbound: &mut tonic::Streaming<SupervisorMessage>,
    mut shutdown_rx: oneshot::Receiver<()>,
    owner_guard: &mut OwnerGuard,
) {
    let heartbeat_interval = Duration::from_secs(u64::from(HEARTBEAT_INTERVAL_SECS));
    let mut heartbeat_timer = tokio::time::interval(heartbeat_interval);
    // Skip the first immediate tick.
    heartbeat_timer.tick().await;

    loop {
        tokio::select! {
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
}
