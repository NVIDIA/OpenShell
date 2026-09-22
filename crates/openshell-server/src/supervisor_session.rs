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
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};
use uuid::Uuid;

#[cfg(test)]
use openshell_core::proto::ConfigBootstrapResult;
use openshell_core::proto::{
    ConfigApplyOutcome, ConfigBootstrap, ConfigComponent, ConfigComponentApplyResult,
    ConfigSnapshotRevision, ConfigUpdate, ConfigUpdateResult, GatewayMessage,
    GetSandboxProviderStatusRequest, GetSandboxProviderStatusResponse, PeerRelayFrame,
    PeerRelayInit, PolicySource, ProviderReadinessObservation, RelayFrame, RelayInit, RelayOpen,
    ReportEndpointStatusRequest, ReportEndpointStatusResponse, ReportMainProcessExitRequest,
    ReportMainProcessExitResponse, ReportProviderReadinessRequest, ReportProviderReadinessResponse,
    Sandbox, SandboxConfigurationAdmission, SandboxPhase, SessionAccepted, SessionRejected,
    SshRelayTarget, StartupConfigCandidate, SupervisorMessage, config_snapshot_revision,
    config_update, gateway_message, open_shell_client, peer_relay_frame, relay_open,
    startup_config_prepared, supervisor_message,
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
use crate::grpc::provider_readiness::ProviderReadinessEvidence;
use crate::persistence::{CONFIG_COMPONENT_OBSERVATION_OBJECT_TYPE, ObjectType, current_time_ms};
use crate::storage_proto::StoredConfigComponentObservation;
use crate::supervisor_owner::{OWNER_TTL, OwnerError, OwnerGuard, SupervisorOwnerIndex};

const HEARTBEAT_INTERVAL_SECS: u32 = 15;
const OWNER_RENEW_TIMEOUT: Duration = Duration::from_secs(5);
const STARTUP_POLICY_REPAIR_TIMEOUT: Duration = Duration::from_mins(5);
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

#[cfg(test)]
static FAIL_NEXT_ADMISSION_PERSISTENCE_FOR_SANDBOX: std::sync::LazyLock<Mutex<Option<String>>> =
    std::sync::LazyLock::new(|| Mutex::new(None));

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
    /// True only after the admitted workload and relay plane are usable.
    runtime_ready: bool,
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
    last_acknowledged_fingerprint: Option<ConfigSnapshotFingerprint>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ConfigSnapshotFingerprint {
    Sandbox {
        revision: ConfigSnapshotRevision,
        provider_env_revision: u64,
        provider_attachment_epoch: String,
        policy_hash: String,
    },
    ProviderEnvironment {
        provider_env_revision: u64,
        provider_attachment_epoch: String,
        policy_hash: String,
    },
}

#[derive(Debug)]
struct InFlightConfigUpdate {
    update_id: String,
    component_sequence: u64,
    revision: ConfigSnapshotRevision,
    fingerprint: ConfigSnapshotFingerprint,
    admission: Option<SandboxConfigurationAdmission>,
    sent_at: Instant,
}

struct CompletedConfigUpdate {
    component: ConfigComponent,
    update_id: String,
    component_sequence: u64,
    revision: ConfigSnapshotRevision,
    fingerprint: ConfigSnapshotFingerprint,
    outcome: ConfigApplyOutcome,
    admission: Option<SandboxConfigurationAdmission>,
}

fn expected_configuration_admission(
    snapshot: &openshell_core::proto::SandboxConfigSnapshot,
) -> SandboxConfigurationAdmission {
    use openshell_core::proto::ConfigurationAdmissionState;

    SandboxConfigurationAdmission {
        instance_id: snapshot.configuration_instance_id.clone(),
        state: if snapshot.configuration_admitted {
            ConfigurationAdmissionState::Accepted.into()
        } else {
            ConfigurationAdmissionState::Rejected.into()
        },
        policy_version: snapshot.version,
        policy_hash: snapshot.policy_hash.clone(),
        config_revision: snapshot.config_revision,
        provider_env_revision: snapshot.provider_env_revision,
        error: snapshot.configuration_error.clone(),
    }
}

fn validate_configuration_admission(
    reported: Option<&SandboxConfigurationAdmission>,
    expected: &SandboxConfigurationAdmission,
    outcome: ConfigApplyOutcome,
) -> Result<SandboxConfigurationAdmission, Status> {
    use openshell_core::proto::ConfigurationAdmissionState;

    let reported = reported.ok_or_else(|| {
        Status::invalid_argument("sandbox configuration admission result is required")
    })?;
    if reported.instance_id != expected.instance_id
        || reported.policy_version != expected.policy_version
        || reported.policy_hash != expected.policy_hash
        || reported.config_revision != expected.config_revision
        || reported.provider_env_revision != expected.provider_env_revision
    {
        return Err(Status::invalid_argument(
            "configuration admission does not match the delivered generation",
        ));
    }
    let expected_state = ConfigurationAdmissionState::try_from(expected.state).unwrap_or_default();
    let reported_state = ConfigurationAdmissionState::try_from(reported.state).unwrap_or_default();
    if expected_state == ConfigurationAdmissionState::Rejected {
        if reported_state != ConfigurationAdmissionState::Rejected {
            return Err(Status::invalid_argument(
                "rejected gateway configuration was reported as accepted",
            ));
        }
        return Ok(expected.clone());
    }
    if outcome_acknowledges_revision(outcome)
        && reported_state == ConfigurationAdmissionState::Accepted
    {
        let mut admission = expected.clone();
        admission.error.clear();
        return Ok(admission);
    }
    if reported_state == ConfigurationAdmissionState::Rejected {
        let mut admission = expected.clone();
        admission.state = ConfigurationAdmissionState::Rejected.into();
        admission.error = "effective configuration could not be activated".to_string();
        return Ok(admission);
    }
    Err(Status::invalid_argument(
        "configuration admission is inconsistent with the apply result",
    ))
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

fn build_config_update(
    state: &mut ComponentDeliveryState,
    message: SupervisorConfigMessage,
) -> (GatewayMessage, InFlightConfigUpdate) {
    state.sequence = state.sequence.saturating_add(1);
    let component_sequence = state.sequence;
    let fingerprint = config_message_fingerprint(&message);
    let (component, revision, admission) = match message {
        SupervisorConfigMessage::SandboxConfig(snapshot) => {
            let admission = expected_configuration_admission(&snapshot);
            let revision = ConfigSnapshotRevision {
                component: Some(config_snapshot_revision::Component::SandboxConfig(
                    openshell_core::proto::SandboxConfigRevision {
                        config_revision: snapshot.config_revision,
                        policy_version: snapshot.version,
                        policy_source: snapshot.policy_source,
                        global_policy_version: snapshot.global_policy_version,
                        settings_revision: snapshot.settings_revision,
                    },
                )),
            };
            (
                config_update::Component::SandboxConfig(*snapshot),
                revision,
                Some(admission),
            )
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
                None,
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
            fingerprint,
            admission,
            sent_at: Instant::now(),
        },
    )
}

fn config_message_fingerprint(message: &SupervisorConfigMessage) -> ConfigSnapshotFingerprint {
    match message {
        SupervisorConfigMessage::SandboxConfig(snapshot) => ConfigSnapshotFingerprint::Sandbox {
            revision: config_message_revision(message),
            provider_env_revision: snapshot.provider_env_revision,
            provider_attachment_epoch: snapshot.provider_attachment_epoch.clone(),
            policy_hash: snapshot.policy_hash.clone(),
        },
        SupervisorConfigMessage::ProviderEnvironment(snapshot) => {
            ConfigSnapshotFingerprint::ProviderEnvironment {
                provider_env_revision: snapshot.provider_env_revision,
                provider_attachment_epoch: snapshot.provider_attachment_epoch.clone(),
                policy_hash: snapshot.policy_hash.clone(),
            }
        }
    }
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
                    settings_revision: snapshot.settings_revision,
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

fn outcome_acknowledges_revision(outcome: ConfigApplyOutcome) -> bool {
    matches!(
        outcome,
        ConfigApplyOutcome::Applied
            | ConfigApplyOutcome::IgnoredDuplicate
            | ConfigApplyOutcome::RetainedLocalOverride
            | ConfigApplyOutcome::Degraded
    )
}

fn generation_is_pending(result: &ConfigComponentApplyResult) -> bool {
    result
        .failure
        .as_ref()
        .is_some_and(|failure| failure.retryable && failure.code == "generation_mismatch")
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
        self.register_with_runtime_state(sandbox_id, session_id, tx, shutdown, true)
    }

    fn register_initializing(
        &self,
        sandbox_id: String,
        session_id: String,
        tx: mpsc::Sender<GatewayMessage>,
        shutdown: oneshot::Sender<()>,
    ) -> bool {
        self.register_with_runtime_state(sandbox_id, session_id, tx, shutdown, false)
    }

    fn register_with_runtime_state(
        &self,
        sandbox_id: String,
        session_id: String,
        tx: mpsc::Sender<GatewayMessage>,
        shutdown: oneshot::Sender<()>,
        runtime_ready: bool,
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
                endpoint_status_initialized: false,
                endpoint_report_cursor: None,
                provider_readiness: None,
                runtime_ready,
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

    pub fn is_runtime_ready(&self, sandbox_id: &str) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .get(sandbox_id)
            .is_some_and(|session| session.runtime_ready)
    }

    fn mark_runtime_ready(&self, sandbox_id: &str, session_id: &str) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        let Some(session) = sessions.get_mut(sandbox_id) else {
            return false;
        };
        if session.session_id != session_id {
            return false;
        }
        session.runtime_ready = true;
        true
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
            && delivery_state.last_acknowledged_fingerprint.as_ref()
                == Some(&config_message_fingerprint(&message))
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
    ) -> Result<CompletedConfigUpdate, Status> {
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
        let completed = CompletedConfigUpdate {
            component,
            update_id: in_flight.update_id.clone(),
            component_sequence: in_flight.component_sequence,
            revision: in_flight.revision.clone(),
            fingerprint: in_flight.fingerprint.clone(),
            outcome,
            admission: in_flight.admission.clone(),
        };
        Ok(completed)
    }

    /// Finish a validated update after all durable side effects have either
    /// succeeded or failed. Keeping the update in flight until this point
    /// prevents reconciliation from treating a locally reported result as an
    /// acknowledgement before its observation and admission are durable.
    fn finalize_config_update(
        &self,
        sandbox_id: &str,
        session_id: &str,
        completed: &CompletedConfigUpdate,
        acknowledge: bool,
    ) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        let Some(session) = sessions
            .get_mut(sandbox_id)
            .filter(|session| session.session_id == session_id)
        else {
            return false;
        };
        let delivery_state = match completed.component {
            ConfigComponent::SandboxConfig => &mut session.config_sequences.sandbox_config,
            ConfigComponent::ProviderEnvironment => {
                &mut session.config_sequences.provider_environment
            }
            ConfigComponent::Unspecified => return false,
        };
        let Some(in_flight) = delivery_state.in_flight.as_ref() else {
            return false;
        };
        if in_flight.update_id != completed.update_id
            || in_flight.component_sequence != completed.component_sequence
            || in_flight.revision != completed.revision
        {
            return false;
        }
        if acknowledge && outcome_acknowledges_revision(completed.outcome) {
            delivery_state.last_acknowledged_fingerprint = Some(completed.fingerprint.clone());
        }
        delivery_state.in_flight = None;
        if let Some(pending) = delivery_state.pending.take() {
            if delivery_state.last_acknowledged_fingerprint.as_ref()
                == Some(&config_message_fingerprint(&pending))
            {
                return true;
            }
            let (message, next) = build_config_update(delivery_state, pending);
            match session.tx.try_send(message) {
                Ok(()) => delivery_state.in_flight = Some(next),
                Err(mpsc::error::TrySendError::Full(_) | mpsc::error::TrySendError::Closed(_)) => {
                    // Owner reconciliation rebuilds the newest snapshot.
                }
            }
        }
        true
    }

    /// Record a successfully persisted bootstrap result in the live session's
    /// delivery state so reconciliation does not immediately redeliver it.
    ///
    /// A streamed update may be delivered while the bootstrap result is being
    /// persisted. In that case, or if this session has already acknowledged a
    /// revision, leave the newer delivery state untouched.
    fn acknowledge_bootstrap_component(
        &self,
        sandbox_id: &str,
        session_id: &str,
        result: &ConfigComponentApplyResult,
        fingerprint: &ConfigSnapshotFingerprint,
    ) -> bool {
        let component = ConfigComponent::try_from(result.component).unwrap_or_default();
        let outcome = ConfigApplyOutcome::try_from(result.outcome).unwrap_or_default();
        if !outcome_acknowledges_revision(outcome) {
            return false;
        }
        let Some(_revision) = result.requested_revision.as_ref() else {
            return false;
        };
        let mut sessions = self.sessions.lock().unwrap();
        let Some(session) = sessions
            .get_mut(sandbox_id)
            .filter(|session| session.session_id == session_id)
        else {
            return false;
        };
        let delivery_state = match component {
            ConfigComponent::SandboxConfig => &mut session.config_sequences.sandbox_config,
            ConfigComponent::ProviderEnvironment => {
                &mut session.config_sequences.provider_environment
            }
            ConfigComponent::Unspecified => return false,
        };
        if delivery_state.in_flight.is_some()
            || delivery_state.last_acknowledged_fingerprint.is_some()
        {
            return false;
        }
        delivery_state.last_acknowledged_fingerprint = Some(fingerprint.clone());
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

#[allow(clippy::too_many_arguments)]
async fn accept_supervisor_session(
    state: Arc<ServerState>,
    sandbox_id: String,
    instance_id: String,
    connection_epoch: u64,
    protocol_revision: u32,
    stream_applies_config: bool,
    bootstrap: Option<ConfigBootstrap>,
    provider_readiness: ProviderReadinessEvidence,
    outbound_tx: mpsc::Sender<GatewayMessage>,
    mut inbound: tonic::Streaming<SupervisorMessage>,
) -> Result<(), Status> {
    let expected_bootstrap_admission = bootstrap
        .as_ref()
        .and_then(|bootstrap| bootstrap.sandbox_config.as_ref())
        .map(expected_configuration_admission);
    let expected_bootstrap_revisions = bootstrap
        .as_ref()
        .map(bootstrap_revision_fence)
        .unwrap_or_default();
    let session_id = Uuid::new_v4().to_string();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    // Keep the session unroutable to the response stream until every fallible
    // acceptance step completes. Registry traffic can safely queue here while
    // endpoint-status authority is initialized; the forwarder starts only
    // after SessionAccepted has been queued on the public stream.
    let (session_tx, mut session_rx) = mpsc::channel::<GatewayMessage>(64);
    let mut accepted = GatewayMessage {
        payload: Some(gateway_message::Payload::SessionAccepted(SessionAccepted {
            session_id: session_id.clone(),
            bootstrap,
            protocol_revision,
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
    let owner_peer_endpoint = state.peer_endpoint.as_deref().map_or_else(
        || local_owner_endpoint(&state.replica_id),
        ToString::to_string,
    );
    let owner_index = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL);
    let owner_guard = owner_index
        .publish(
            &sandbox_id,
            &session_id,
            &instance_id,
            connection_epoch,
            &state.replica_id,
            &owner_peer_endpoint,
        )
        .await
        .map_err(owner_error_to_status)?;
    let superseded = if stream_applies_config {
        state.supervisor_sessions.register_initializing(
            sandbox_id.clone(),
            session_id.clone(),
            session_tx.clone(),
            shutdown_tx,
        )
    } else {
        state.supervisor_sessions.register(
            sandbox_id.clone(),
            session_id.clone(),
            session_tx.clone(),
            shutdown_tx,
        )
    };
    if superseded {
        info!(
            sandbox_id = %sandbox_id,
            session_id = %session_id,
            "supervisor session: superseded previous session"
        );
    }

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
        state
            .supervisor_sessions
            .remove_if_current(&sandbox_id, &session_id);
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

    if !stream_applies_config
        && !mark_supervisor_initialized(&state, &sandbox_id, &session_id, &instance_id, false).await
    {
        state
            .supervisor_sessions
            .remove_if_current(&sandbox_id, &session_id);
        if let Err(release_error) = owner_index.release_if_current(&owner_guard).await {
            warn!(sandbox_id, session_id, error = %release_error, "supervisor session: failed to release owner after lifecycle persistence failure");
        }
        return Err(Status::aborted(
            "failed to persist supervisor session state; reconnect",
        ));
    }

    if outbound_tx.send(accepted).await.is_err() {
        state
            .supervisor_sessions
            .remove_if_current(&sandbox_id, &session_id);
        if let Err(err) = owner_index.release_if_current(&owner_guard).await {
            warn!(sandbox_id, session_id, error = %err, "supervisor session: failed to release owner after accept send failure");
        }
        return Err(Status::internal("failed to send session accepted"));
    }
    info!(
        sandbox_id = %sandbox_id,
        session_id = %session_id,
        instance_id = %instance_id,
        "supervisor session: accepted"
    );

    let public_tx = outbound_tx.clone();
    tokio::spawn(async move {
        while let Some(message) = session_rx.recv().await {
            if public_tx.send(message).await.is_err() {
                break;
            }
        }
    });

    if superseded {
        state
            .supervisor_sessions
            .replay_pending_relays(&sandbox_id, &session_tx)
            .await;
    }

    tokio::spawn(async move {
        let mut owner_guard = owner_guard;
        run_session_loop(
            &state,
            &sandbox_id,
            &session_id,
            &instance_id,
            stream_applies_config,
            &expected_bootstrap_revisions,
            expected_bootstrap_admission.as_ref(),
            &session_tx,
            &mut inbound,
            shutdown_rx,
            &mut owner_guard,
        )
        .await;
        let terminal_finalized = state
            .supervisor_sessions
            .remove_if_current(&sandbox_id, &session_id);
        // Release only this exact ownership record. A newer supervisor session
        // may already have published replacement ownership on another replica.
        let owner_index = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL);
        if let Err(err) = owner_index.release_if_current(&owner_guard).await {
            warn!(sandbox_id = %sandbox_id, session_id = %session_id, error = %err, "supervisor session: failed to release owner record");
        }
        if let Some(terminal_finalized) = terminal_finalized {
            info!(sandbox_id = %sandbox_id, session_id = %session_id, "supervisor session: ended");
            state.telemetry.sandbox_session_disconnected(&sandbox_id);
            tokio::spawn(
                crate::grpc::policy::retry_endpoint_status_after_supervisor_disconnect(
                    Arc::clone(&state),
                    sandbox_id.clone(),
                ),
            );
            if let Err(err) = state
                .compute
                .supervisor_session_disconnected(&sandbox_id, terminal_finalized)
                .await
            {
                warn!(
                    sandbox_id = %sandbox_id,
                    session_id = %session_id,
                    error = %err,
                    "supervisor session: failed to mark sandbox disconnected"
                );
            }
        } else {
            info!(sandbox_id = %sandbox_id, session_id = %session_id, "supervisor session: ended (already superseded)");
        }
    });

    Ok(())
}

async fn reject_startup_session(tx: &mpsc::Sender<GatewayMessage>, error: &Status) {
    let _ = tx
        .send(GatewayMessage {
            payload: Some(gateway_message::Payload::SessionRejected(SessionRejected {
                reason: error.message().chars().take(1024).collect(),
            })),
        })
        .await;
}

enum ImagePolicyAdmission {
    Missing,
    Invalid,
    Policy(Box<openshell_core::proto::SandboxPolicy>),
}

fn image_policy_admission(
    hello: &openshell_core::proto::SupervisorHello,
) -> Result<ImagePolicyAdmission, Status> {
    use openshell_core::proto::image_policy_discovery::Result as DiscoveryResult;

    match hello
        .image_policy_discovery
        .as_ref()
        .and_then(|discovery| discovery.result.as_ref())
    {
        Some(DiscoveryResult::Missing(())) => Ok(ImagePolicyAdmission::Missing),
        Some(DiscoveryResult::Invalid(())) => Ok(ImagePolicyAdmission::Invalid),
        Some(DiscoveryResult::Policy(policy)) => {
            Ok(ImagePolicyAdmission::Policy(Box::new(policy.clone())))
        }
        None if hello.image_policy.is_some() => Ok(ImagePolicyAdmission::Policy(Box::new(
            hello.image_policy.clone().expect("checked above"),
        ))),
        None if hello.image_policy_discovery.is_none() => Ok(ImagePolicyAdmission::Missing),
        None => Err(Status::invalid_argument(
            "image policy discovery result is required",
        )),
    }
}

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
    // The stock supervisor includes discovery only on its first connection.
    // Reconnects from the same process intentionally omit both startup policy
    // fields and must proceed directly to the current authoritative bootstrap.
    let prepares_startup_policy = stream_applies_config
        && (hello.image_policy_discovery.is_some() || hello.image_policy.is_some());
    let image_policy_admission = image_policy_admission(&hello)?;
    if sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }
    validate_protocol_revision(&sandbox_id, hello.protocol_revision)?;
    if let Some(principal) = principal.as_ref() {
        crate::auth::guard::ensure_sandbox_principal_scope(principal, &sandbox_id)?;
    }
    let sandbox = require_persisted_sandbox(&state.store, &sandbox_id).await?;
    // Validate readiness identities before replacing a healthy session. Older
    // supervisors remain usable but cannot assert provider installation.
    let provider_readiness = ProviderReadinessEvidence::from_hello(&hello)?;

    let bootstrap_timeout = if stream_applies_config {
        crate::config_delivery::REQUIRED_CONFIG_BOOTSTRAP_BUILD_TIMEOUT
    } else {
        crate::config_delivery::OPTIONAL_CONFIG_BOOTSTRAP_BUILD_TIMEOUT
    };
    let mut repair_updates = matches!(image_policy_admission, ImagePolicyAdmission::Invalid)
        .then(|| state.sandbox_watch_bus.subscribe(&sandbox_id));
    let repair_deadline = tokio::time::Instant::now() + STARTUP_POLICY_REPAIR_TIMEOUT;
    let bootstrap = loop {
        let current_sandbox = require_persisted_sandbox(&state.store, &sandbox_id).await?;
        match crate::config_delivery::build_config_bootstrap(
            state,
            &current_sandbox,
            bootstrap_timeout,
        )
        .await
        {
            Ok(bootstrap) => {
                let has_gateway_policy = bootstrap
                    .sandbox_config
                    .as_ref()
                    .and_then(|snapshot| snapshot.policy.as_ref())
                    .is_some();
                if matches!(image_policy_admission, ImagePolicyAdmission::Invalid)
                    && !has_gateway_policy
                {
                    warn!(
                        sandbox_id = %sandbox_id,
                        "invalid image policy rejected; waiting for a gateway policy repair"
                    );
                } else {
                    counter!(
                        "openshell_supervisor_config_bootstrap_total",
                        "outcome" => "built"
                    )
                    .increment(1);
                    break Some(bootstrap);
                }
            }
            Err(error) if matches!(image_policy_admission, ImagePolicyAdmission::Invalid) => {
                warn!(
                    sandbox_id = %sandbox_id,
                    error_code = ?error.code(),
                    "invalid image policy rejected; waiting for configuration repair"
                );
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
                break None;
            }
        }

        let Some(updates) = repair_updates.as_mut() else {
            return Err(Status::failed_precondition(
                "image policy is invalid and no gateway policy is available",
            ));
        };
        match tokio::time::timeout_at(repair_deadline, updates.recv()).await {
            Ok(Ok(()) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                return Err(Status::aborted(
                    "sandbox configuration watch closed during startup repair",
                ));
            }
            Err(_) => {
                return Err(Status::deadline_exceeded(
                    "image policy repair window expired",
                ));
            }
        }
    };
    let (tx, rx) = mpsc::channel::<GatewayMessage>(64);
    let gateway_snapshot = bootstrap
        .as_ref()
        .and_then(|bootstrap| bootstrap.sandbox_config.as_ref());
    let gateway_policy = gateway_snapshot.and_then(|snapshot| snapshot.policy.clone());
    let gateway_has_policy = gateway_policy.is_some();

    if prepares_startup_policy {
        let policy = gateway_policy
            .or_else(|| match image_policy_admission {
                ImagePolicyAdmission::Policy(policy) => Some(*policy),
                ImagePolicyAdmission::Missing => {
                    Some(openshell_policy::restrictive_default_policy())
                }
                ImagePolicyAdmission::Invalid => None,
            })
            .ok_or_else(|| Status::failed_precondition("startup policy candidate is missing"))?;
        let (policy_hash, policy_source, policy_version) = if gateway_has_policy {
            let snapshot = gateway_snapshot.expect("gateway policy came from sandbox snapshot");
            (
                snapshot.policy_hash.clone(),
                snapshot.policy_source,
                snapshot.version,
            )
        } else {
            (
                openshell_core::policy_identity::deterministic_policy_hash(&policy),
                PolicySource::Sandbox.into(),
                0,
            )
        };
        let candidate_id = Uuid::new_v4().to_string();
        let candidate = GatewayMessage {
            payload: Some(gateway_message::Payload::StartupConfigCandidate(
                StartupConfigCandidate {
                    candidate_id: candidate_id.clone(),
                    policy_hash,
                    policy_source,
                    policy_version,
                    policy: Some(policy.clone()),
                },
            )),
        };
        if candidate.encoded_len() > MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES {
            return Err(Status::resource_exhausted(
                "startup configuration candidate exceeds the stream message limit",
            ));
        }
        tx.send(candidate)
            .await
            .map_err(|_| Status::internal("failed to send startup configuration candidate"))?;

        let state = Arc::clone(state);
        let provider_readiness = provider_readiness.clone();
        let tx_for_rejection = tx.clone();
        let protocol_revision = hello.protocol_revision;
        let connection_epoch = hello.connection_epoch;
        let instance_id = hello.instance_id;
        tokio::spawn(async move {
            let result = Box::pin(async {
                let prepared = tokio::time::timeout(
                    crate::config_delivery::REQUIRED_CONFIG_BOOTSTRAP_BUILD_TIMEOUT,
                    inbound.message(),
                )
                .await
                .map_err(|_| {
                    Status::deadline_exceeded("startup configuration preparation timed out")
                })??
                .ok_or_else(|| {
                    Status::aborted("supervisor disconnected during startup preparation")
                })?;
                let Some(supervisor_message::Payload::StartupConfigPrepared(prepared)) =
                    prepared.payload
                else {
                    return Err(Status::invalid_argument("expected StartupConfigPrepared"));
                };
                if prepared.candidate_id != candidate_id {
                    return Err(Status::failed_precondition(
                        "startup configuration candidate ID does not match",
                    ));
                }

                let policy_to_persist = match prepared.result {
                    Some(startup_config_prepared::Result::Unchanged(())) => {
                        (!gateway_has_policy).then_some(policy)
                    }
                    Some(startup_config_prepared::Result::PreparedPolicy(policy)) => Some(policy),
                    Some(startup_config_prepared::Result::Failure(failure)) => {
                        return Err(Status::failed_precondition(format!(
                            "supervisor could not prepare startup policy: {}: {}",
                            failure.code, failure.message
                        )));
                    }
                    None => {
                        return Err(Status::invalid_argument(
                            "startup configuration result is required",
                        ));
                    }
                };

                if let Some(policy) = policy_to_persist {
                    let principal = principal.clone().ok_or_else(|| {
                        Status::unauthenticated(
                            "startup policy preparation requires an authenticated supervisor",
                        )
                    })?;
                    crate::grpc::policy::persist_supervisor_startup_policy(
                        &state, principal, &sandbox, policy,
                    )
                    .await?;
                }

                let sandbox = require_persisted_sandbox(&state.store, &sandbox_id).await?;
                let bootstrap = crate::config_delivery::build_config_bootstrap(
                    &state,
                    &sandbox,
                    crate::config_delivery::REQUIRED_CONFIG_BOOTSTRAP_BUILD_TIMEOUT,
                )
                .await?;
                accept_supervisor_session(
                    state,
                    sandbox_id.clone(),
                    instance_id,
                    connection_epoch,
                    protocol_revision,
                    true,
                    Some(bootstrap),
                    provider_readiness,
                    tx,
                    inbound,
                )
                .await
            })
            .await;
            if let Err(error) = result {
                warn!(
                    sandbox_id = %sandbox_id,
                    error_code = ?error.code(),
                    "supervisor startup policy preparation failed"
                );
                reject_startup_session(&tx_for_rejection, &error).await;
            }
        });
    } else {
        accept_supervisor_session(
            Arc::clone(state),
            sandbox_id,
            hello.instance_id,
            hello.connection_epoch,
            hello.protocol_revision,
            stream_applies_config,
            bootstrap,
            provider_readiness,
            tx,
            inbound,
        )
        .await?;
    }

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
    expected_bootstrap_revisions: &[(
        ConfigComponent,
        ConfigSnapshotRevision,
        ConfigSnapshotFingerprint,
    )],
    expected_bootstrap_admission: Option<&SandboxConfigurationAdmission>,
    tx: &mpsc::Sender<GatewayMessage>,
    inbound: &mut tonic::Streaming<SupervisorMessage>,
    mut shutdown_rx: oneshot::Receiver<()>,
    owner_guard: &mut OwnerGuard,
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
                        if matches!(msg.payload.as_ref(), Some(supervisor_message::Payload::Heartbeat(_)))
                            && !renew_supervisor_owner(state, sandbox_id, session_id, owner_guard).await
                        {
                            break;
                        }
                        let bootstrap_result = match msg.payload.as_ref() {
                            Some(supervisor_message::Payload::ConfigBootstrapResult(result))
                                if stream_applies_config =>
                            {
                                match validate_bootstrap_result(
                                    &result.results,
                                    expected_bootstrap_revisions,
                                ) {
                                    Ok(succeeded) => Some((succeeded, result.admission.clone())),
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
                            instance_id,
                            stream_applies_config,
                            expected_bootstrap_revisions,
                            tx,
                            msg,
                        ).await;
                        if let Some((succeeded, reported_admission)) = bootstrap_result {
                                bootstrap_complete = true;
                                let Some(expected_admission) = expected_bootstrap_admission else {
                                    warn!(sandbox_id, session_id, "supervisor bootstrap omitted expected admission");
                                    break;
                                };
                                let outcome = if succeeded {
                                    ConfigApplyOutcome::Applied
                                } else {
                                    ConfigApplyOutcome::Unsupported
                                };
                                let admission = match validate_configuration_admission(
                                    reported_admission.as_ref(),
                                    expected_admission,
                                    outcome,
                                ) {
                                    Ok(admission) => admission,
                                    Err(error) => {
                                        warn!(sandbox_id, session_id, error = %error, "invalid supervisor bootstrap admission");
                                        break;
                                    }
                                };
                                if !persist_and_ack_admission(
                                    state,
                                    sandbox_id,
                                    session_id,
                                    instance_id,
                                    &admission,
                                    tx,
                                )
                                .await
                                {
                                    break;
                                }
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

async fn renew_supervisor_owner(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    owner_guard: &mut OwnerGuard,
) -> bool {
    let owner_index = SupervisorOwnerIndex::new(state.store.clone(), OWNER_TTL);
    match tokio::time::timeout(OWNER_RENEW_TIMEOUT, owner_index.renew(owner_guard)).await {
        Ok(Ok(())) => true,
        Ok(Err(err)) if err.is_ownership_lost() => {
            warn!(sandbox_id, session_id, error = %err, "supervisor session: ownership lost; closing session");
            false
        }
        Ok(Err(err)) if owner_guard.claim_expired(OWNER_TTL) => {
            warn!(sandbox_id, session_id, error = %err, "supervisor session: owner renewal failed past the ownership TTL; closing session");
            false
        }
        Ok(Err(err)) => {
            warn!(sandbox_id, session_id, error = %err, "supervisor session: owner renewal failed; retrying on next heartbeat");
            true
        }
        Err(_) if owner_guard.claim_expired(OWNER_TTL) => {
            warn!(
                sandbox_id,
                session_id,
                timeout_ms = OWNER_RENEW_TIMEOUT.as_millis(),
                "supervisor session: owner renewal timed out past the ownership TTL; closing session"
            );
            false
        }
        Err(_) => {
            warn!(
                sandbox_id,
                session_id,
                timeout_ms = OWNER_RENEW_TIMEOUT.as_millis(),
                "supervisor session: owner renewal timed out; retrying on next heartbeat"
            );
            true
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_supervisor_message(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    instance_id: &str,
    stream_applies_config: bool,
    expected_bootstrap_revisions: &[(
        ConfigComponent,
        ConfigSnapshotRevision,
        ConfigSnapshotFingerprint,
    )],
    tx: &mpsc::Sender<GatewayMessage>,
    msg: SupervisorMessage,
) {
    match msg.payload {
        Some(supervisor_message::Payload::Heartbeat(_)) => {}
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
            let completed = match state
                .supervisor_sessions
                .complete_config_update(sandbox_id, session_id, &result)
            {
                Ok(completed) => completed,
                Err(error) => {
                    debug!(
                        sandbox_id,
                        session_id,
                        error = %error,
                        "ignored unmatched supervisor configuration result"
                    );
                    return;
                }
            };
            if result.result.as_ref().is_some_and(generation_is_pending) {
                state
                    .supervisor_sessions
                    .finalize_config_update(sandbox_id, session_id, &completed, false);
                // Either projection can arrive first. Once the supervisor has
                // staged one half, rebuild both current projections so the
                // matching half and the deferred admission result are driven
                // to a fixed point even when no further mutation occurs.
                crate::config_delivery::publish_sandbox_components(
                    state,
                    sandbox_id,
                    crate::config_delivery::ConfigComponents::SANDBOX_AND_PROVIDER,
                );
                debug!(
                    sandbox_id,
                    session_id,
                    "supervisor configuration generation is waiting for its matching component; scheduled reconciliation"
                );
                return;
            }
            if let Some(result) = result.result.as_ref()
                && let Err(error) = record_component_apply_result(state, sandbox_id, result).await
            {
                state
                    .supervisor_sessions
                    .finalize_config_update(sandbox_id, session_id, &completed, false);
                warn!(
                    sandbox_id,
                    session_id,
                    component = result.component,
                    error = %error,
                    "failed to persist supervisor configuration result"
                );
                return;
            }
            if let Some(expected_admission) = completed.admission.as_ref() {
                let admission = match validate_configuration_admission(
                    result.admission.as_ref(),
                    expected_admission,
                    completed.outcome,
                ) {
                    Ok(admission) => admission,
                    Err(error) => {
                        state
                            .supervisor_sessions
                            .finalize_config_update(sandbox_id, session_id, &completed, false);
                        warn!(sandbox_id, session_id, error = %error, "invalid supervisor configuration admission");
                        return;
                    }
                };
                let acknowledged = persist_and_ack_admission(
                    state,
                    sandbox_id,
                    session_id,
                    instance_id,
                    &admission,
                    tx,
                )
                .await;
                state.supervisor_sessions.finalize_config_update(
                    sandbox_id,
                    session_id,
                    &completed,
                    acknowledged,
                );
            } else {
                state
                    .supervisor_sessions
                    .finalize_config_update(sandbox_id, session_id, &completed, true);
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
                let fingerprint = expected_bootstrap_revisions
                    .iter()
                    .find(|(expected, _, _)| i32::from(*expected) == component.component)
                    .map(|(_, _, fingerprint)| fingerprint);
                match record_component_apply_result(state, sandbox_id, component).await {
                    Ok(()) if fingerprint.is_some() => {
                        state.supervisor_sessions.acknowledge_bootstrap_component(
                            sandbox_id,
                            session_id,
                            component,
                            fingerprint.expect("checked above"),
                        );
                    }
                    Ok(()) => {}
                    Err(error) => {
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
        }
        Some(supervisor_message::Payload::RuntimeReady(_)) => {
            if !stream_applies_config {
                debug!(
                    sandbox_id,
                    session_id, "ignored runtime-ready from compatibility supervisor"
                );
                return;
            }
            if !mark_supervisor_initialized(state, sandbox_id, session_id, instance_id, true).await
            {
                warn!(
                    sandbox_id,
                    session_id, "failed to persist supervisor runtime readiness"
                );
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
) -> Vec<(
    ConfigComponent,
    ConfigSnapshotRevision,
    ConfigSnapshotFingerprint,
)> {
    let mut revisions = Vec::with_capacity(2);
    if let Some(snapshot) = bootstrap.sandbox_config.as_ref() {
        let revision = ConfigSnapshotRevision {
            component: Some(config_snapshot_revision::Component::SandboxConfig(
                openshell_core::proto::SandboxConfigRevision {
                    config_revision: snapshot.config_revision,
                    policy_version: snapshot.version,
                    policy_source: snapshot.policy_source,
                    global_policy_version: snapshot.global_policy_version,
                    settings_revision: snapshot.settings_revision,
                },
            )),
        };
        revisions.push((
            ConfigComponent::SandboxConfig,
            revision.clone(),
            ConfigSnapshotFingerprint::Sandbox {
                revision,
                provider_env_revision: snapshot.provider_env_revision,
                provider_attachment_epoch: snapshot.provider_attachment_epoch.clone(),
                policy_hash: snapshot.policy_hash.clone(),
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
            ConfigSnapshotFingerprint::ProviderEnvironment {
                provider_env_revision: snapshot.provider_env_revision,
                provider_attachment_epoch: snapshot.provider_attachment_epoch.clone(),
                policy_hash: snapshot.policy_hash.clone(),
            },
        ));
    }
    revisions
}

fn validate_bootstrap_result(
    results: &[ConfigComponentApplyResult],
    expected: &[(
        ConfigComponent,
        ConfigSnapshotRevision,
        ConfigSnapshotFingerprint,
    )],
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
        let Some((_, revision, _)) = expected
            .iter()
            .find(|(expected_component, _, _)| *expected_component == component)
        else {
            return Err(Status::invalid_argument(
                "bootstrap result contains an unexpected component",
            ));
        };
        let outcome = validate_component_apply_result(result, revision)?;
        seen.push(component);
        all_succeeded &= outcome_acknowledges_revision(outcome);
    }
    Ok(all_succeeded)
}

async fn mark_supervisor_initialized(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    instance_id: &str,
    require_activated_configuration: bool,
) -> bool {
    if !state
        .supervisor_sessions
        .is_current_session(sandbox_id, session_id)
    {
        return false;
    }
    let persisted = if require_activated_configuration {
        state
            .compute
            .supervisor_runtime_ready(sandbox_id, instance_id)
            .await
    } else {
        state
            .compute
            .supervisor_session_connected(sandbox_id, instance_id)
            .await
    };
    if let Err(err) = persisted {
        warn!(
            sandbox_id,
            session_id,
            error = %err,
            "supervisor session: failed to mark sandbox initialized"
        );
        false
    } else if state
        .supervisor_sessions
        .mark_runtime_ready(sandbox_id, session_id)
    {
        state.telemetry.sandbox_session_connected(sandbox_id);
        true
    } else {
        false
    }
}

async fn persist_and_ack_admission(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    instance_id: &str,
    admission: &SandboxConfigurationAdmission,
    tx: &mpsc::Sender<GatewayMessage>,
) -> bool {
    if !state
        .supervisor_sessions
        .is_current_session(sandbox_id, session_id)
    {
        return false;
    }
    #[cfg(test)]
    {
        let mut failure_target = FAIL_NEXT_ADMISSION_PERSISTENCE_FOR_SANDBOX.lock().unwrap();
        if failure_target.as_deref() == Some(sandbox_id) {
            failure_target.take();
            return false;
        }
    }
    if let Err(error) = state
        .compute
        .supervisor_session_admission(sandbox_id, instance_id, admission)
        .await
    {
        warn!(sandbox_id, session_id, error = %error, "failed to persist supervisor configuration admission");
        return false;
    }
    if tx
        .send(GatewayMessage {
            payload: Some(gateway_message::Payload::ConfigurationAdmission(
                admission.clone(),
            )),
        })
        .await
        .is_err()
    {
        return false;
    }
    state.telemetry.sandbox_session_connected(sandbox_id);
    true
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
            created_time: openshell_core::time::timestamp_from_millis(now_ms).ok(),
            ..Default::default()
        }),
        sandbox_id: sandbox.object_id().to_string(),
        component: component.into(),
        requested_revision: result.requested_revision.clone(),
        applied_revision: result.applied_revision.clone(),
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
        observed_at_time: openshell_core::time::timestamp_from_millis(now_ms).ok(),
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
        SandboxConfigSnapshot, SandboxSpec, StartupConfigPrepared, startup_config_prepared,
    };
    use prost::Message;

    #[test]
    fn configuration_stream_messages_round_trip() {
        let bootstrap = GatewayMessage {
            payload: Some(gateway_message::Payload::SessionAccepted(SessionAccepted {
                session_id: "session-1".into(),
                heartbeat_interval: openshell_core::time::duration_from_std(Duration::from_secs(
                    15,
                ))
                .ok(),
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

        let admission = SandboxConfigurationAdmission {
            instance_id: "configuration-1".into(),
            state: openshell_core::proto::ConfigurationAdmissionState::Accepted.into(),
            policy_version: 3,
            policy_hash: "policy-hash".into(),
            config_revision: 7,
            provider_env_revision: 5,
            error: String::new(),
        };
        let admission_ack = GatewayMessage {
            payload: Some(gateway_message::Payload::ConfigurationAdmission(
                admission.clone(),
            )),
        };
        for original in std::iter::once(bootstrap)
            .chain(updates)
            .chain(std::iter::once(admission_ack))
        {
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
                    admission: Some(admission),
                },
            )),
        };
        let runtime_ready = SupervisorMessage {
            payload: Some(supervisor_message::Payload::RuntimeReady(
                openshell_core::proto::SupervisorRuntimeReady {},
            )),
        };
        for original in [result, runtime_ready] {
            let decoded = SupervisorMessage::decode(original.encode_to_vec().as_slice()).unwrap();
            assert_eq!(decoded, original);
        }
    }

    #[test]
    fn supervisor_protocol_revision_accepts_current_and_legacy_peers() {
        assert!(validate_protocol_revision("sb-1", SUPERVISOR_PROTOCOL_REVISION).is_ok());
        assert!(validate_protocol_revision("sb-1", PREVIOUS_SUPERVISOR_PROTOCOL_REVISION).is_ok());
        assert!(validate_protocol_revision("sb-1", LEGACY_SUPERVISOR_PROTOCOL_REVISION).is_ok());
    }

    #[test]
    fn configuration_admission_preserves_gateway_rejection_and_accepts_repair() {
        use openshell_core::proto::ConfigurationAdmissionState;

        let mut expected = SandboxConfigurationAdmission {
            instance_id: "configuration-1".into(),
            state: ConfigurationAdmissionState::Rejected.into(),
            policy_version: 3,
            policy_hash: "policy-hash".into(),
            config_revision: 7,
            provider_env_revision: 5,
            error: "invalid image policy".into(),
        };
        let rejected = validate_configuration_admission(
            Some(&expected),
            &expected,
            ConfigApplyOutcome::Applied,
        )
        .unwrap();
        assert_eq!(rejected, expected);

        expected.state = ConfigurationAdmissionState::Accepted.into();
        expected.error.clear();
        let accepted = validate_configuration_admission(
            Some(&expected),
            &expected,
            ConfigApplyOutcome::Applied,
        )
        .unwrap();
        assert_eq!(accepted, expected);
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
            (
                ConfigComponent::SandboxConfig,
                sandbox_revision.clone(),
                ConfigSnapshotFingerprint::Sandbox {
                    revision: sandbox_revision.clone(),
                    provider_env_revision: 0,
                    provider_attachment_epoch: String::new(),
                    policy_hash: String::new(),
                },
            ),
            (
                ConfigComponent::ProviderEnvironment,
                provider_revision.clone(),
                ConfigSnapshotFingerprint::ProviderEnvironment {
                    provider_env_revision: 9,
                    provider_attachment_epoch: String::new(),
                    policy_hash: String::new(),
                },
            ),
        ];
        let result =
            |component: ConfigComponent,
             revision: ConfigSnapshotRevision,
             outcome: ConfigApplyOutcome| ConfigComponentApplyResult {
                component: component.into(),
                requested_revision: Some(revision.clone()),
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

    async fn state_with_startup_policy(
        sandbox_id: &str,
        policy: Option<openshell_core::proto::SandboxPolicy>,
    ) -> Arc<ServerState> {
        let state = crate::grpc::test_support::test_server_state().await;
        let mut sandbox = sandbox_record(sandbox_id, sandbox_id);
        sandbox.spec = Some(SandboxSpec {
            policy,
            ..SandboxSpec::default()
        });
        state.store.put_message(&sandbox).await.unwrap();
        state
    }

    #[tokio::test]
    async fn persisted_bootstrap_result_suppresses_unchanged_reconciliation() {
        let state = state_with_sandbox("sb-bootstrap-ack").await;
        let (tx, mut rx) = mpsc::channel(1);
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        state.supervisor_sessions.register(
            "sb-bootstrap-ack".into(),
            "session-1".into(),
            tx.clone(),
            shutdown_tx,
        );
        let snapshot = ProviderEnvironmentSnapshot {
            provider_env_revision: 11,
            ..Default::default()
        };
        let revision = config_message_revision(&SupervisorConfigMessage::ProviderEnvironment(
            snapshot.clone(),
        ));
        let result = ConfigComponentApplyResult {
            component: ConfigComponent::ProviderEnvironment.into(),
            requested_revision: Some(revision.clone()),
            applied_revision: Some(revision.clone()),
            outcome: ConfigApplyOutcome::Applied.into(),
            ..Default::default()
        };

        handle_supervisor_message(
            &state,
            "sb-bootstrap-ack",
            "session-1",
            "instance-1",
            true,
            &[(
                ConfigComponent::ProviderEnvironment,
                revision.clone(),
                config_message_fingerprint(&SupervisorConfigMessage::ProviderEnvironment(
                    snapshot.clone(),
                )),
            )],
            &tx,
            SupervisorMessage {
                payload: Some(supervisor_message::Payload::ConfigBootstrapResult(
                    ConfigBootstrapResult {
                        results: vec![result],
                        admission: None,
                    },
                )),
            },
        )
        .await;

        let observation = state
            .store
            .get_message::<StoredConfigComponentObservation>(
                "sb-bootstrap-ack:provider_environment",
            )
            .await
            .unwrap()
            .expect("bootstrap observation");
        assert_eq!(observation.requested_revision, Some(revision.clone()));
        assert_eq!(
            state.supervisor_sessions.deliver_config(
                "sb-bootstrap-ack",
                SupervisorConfigMessage::ProviderEnvironment(snapshot),
            ),
            DeliveryDisposition::SuppressedUnchanged
        );
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn failed_admission_persistence_does_not_suppress_unchanged_repair() {
        let sandbox_id = "sb-admission-persistence-retry";
        let state = state_with_sandbox(sandbox_id).await;
        let (tx, mut rx) = mpsc::channel(4);
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        state.supervisor_sessions.register(
            sandbox_id.into(),
            "session-1".into(),
            tx.clone(),
            shutdown_tx,
        );
        let snapshot = SandboxConfigSnapshot {
            configuration_instance_id: "configuration-1".into(),
            configuration_admitted: true,
            config_revision: 7,
            version: 3,
            policy_hash: "policy-hash".into(),
            provider_env_revision: 5,
            ..Default::default()
        };
        let message = SupervisorConfigMessage::SandboxConfig(Box::new(snapshot.clone()));
        assert_eq!(
            state
                .supervisor_sessions
                .deliver_config(sandbox_id, message.clone()),
            DeliveryDisposition::Enqueued
        );
        let Some(gateway_message::Payload::ConfigUpdate(update)) =
            rx.recv().await.expect("initial update").payload
        else {
            panic!("expected initial config update");
        };
        let revision = config_message_revision(&message);
        *FAIL_NEXT_ADMISSION_PERSISTENCE_FOR_SANDBOX.lock().unwrap() = Some(sandbox_id.into());

        handle_supervisor_message(
            &state,
            sandbox_id,
            "session-1",
            "instance-1",
            true,
            &[],
            &tx,
            SupervisorMessage {
                payload: Some(supervisor_message::Payload::ConfigUpdateResult(
                    ConfigUpdateResult {
                        update_id: update.update_id,
                        component_sequence: update.component_sequence,
                        result: Some(ConfigComponentApplyResult {
                            component: ConfigComponent::SandboxConfig.into(),
                            requested_revision: Some(revision.clone()),
                            applied_revision: Some(revision),
                            outcome: ConfigApplyOutcome::Applied.into(),
                            ..Default::default()
                        }),
                        admission: Some(expected_configuration_admission(&snapshot)),
                    },
                )),
            },
        )
        .await;

        assert_eq!(
            state
                .supervisor_sessions
                .deliver_config(sandbox_id, message),
            DeliveryDisposition::Enqueued,
            "a non-durable admission must leave the revision eligible for repair"
        );
        assert!(matches!(
            rx.recv().await.expect("repair update").payload,
            Some(gateway_message::Payload::ConfigUpdate(_))
        ));
    }

    #[tokio::test]
    async fn generation_pending_result_schedules_reconciliation_without_persistence() {
        use openshell_core::proto::{ConfigApplyFailure, ConfigurationAdmissionState};

        let sandbox_id = "sb-generation-pending-retry";
        let state = state_with_sandbox(sandbox_id).await;
        let mut stored_sandbox = state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .expect("sandbox is persisted");
        stored_sandbox.spec = Some(SandboxSpec::default());
        state.store.put_message(&stored_sandbox).await.unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        state.supervisor_sessions.register(
            sandbox_id.into(),
            "session-1".into(),
            tx.clone(),
            shutdown_tx,
        );
        let snapshot = SandboxConfigSnapshot {
            configuration_instance_id: "configuration-1".into(),
            configuration_admitted: true,
            config_revision: 7,
            version: 3,
            policy_hash: "policy-hash".into(),
            provider_env_revision: 5,
            ..Default::default()
        };
        let message = SupervisorConfigMessage::SandboxConfig(Box::new(snapshot.clone()));
        assert_eq!(
            state
                .supervisor_sessions
                .deliver_config(sandbox_id, message.clone()),
            DeliveryDisposition::Enqueued
        );
        let Some(gateway_message::Payload::ConfigUpdate(update)) =
            rx.recv().await.expect("initial update").payload
        else {
            panic!("expected initial config update");
        };
        let revision = config_message_revision(&message);
        let mut rejected_admission = expected_configuration_admission(&snapshot);
        rejected_admission.state = ConfigurationAdmissionState::Rejected.into();
        rejected_admission.error = "effective configuration could not be activated".into();

        handle_supervisor_message(
            &state,
            sandbox_id,
            "session-1",
            "instance-1",
            true,
            &[],
            &tx,
            SupervisorMessage {
                payload: Some(supervisor_message::Payload::ConfigUpdateResult(
                    ConfigUpdateResult {
                        update_id: update.update_id,
                        component_sequence: update.component_sequence,
                        result: Some(ConfigComponentApplyResult {
                            component: ConfigComponent::SandboxConfig.into(),
                            requested_revision: Some(revision),
                            applied_revision: None,
                            outcome: ConfigApplyOutcome::FailedClosed.into(),
                            failure: Some(ConfigApplyFailure {
                                code: "generation_mismatch".into(),
                                message: "waiting for matching provider generation".into(),
                                retryable: true,
                            }),
                        }),
                        admission: Some(rejected_admission),
                    },
                )),
            },
        )
        .await;

        assert!(
            state
                .store
                .get_message::<StoredConfigComponentObservation>(
                    "sb-generation-pending-retry:sandbox_config",
                )
                .await
                .unwrap()
                .is_none(),
            "a transient cross-component ordering result must not become durable state"
        );
        let sandbox = state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .expect("sandbox remains persisted");
        assert!(
            sandbox
                .status
                .as_ref()
                .and_then(|status| status.configuration_admission.as_ref())
                .is_none(),
            "a transient generation mismatch must not persist rejected admission"
        );
        let redriven_components = tokio::time::timeout(Duration::from_secs(2), async {
            let mut components = Vec::new();
            while components.len() < 2 {
                let Some(gateway_message::Payload::ConfigUpdate(update)) = rx
                    .recv()
                    .await
                    .expect("redriven configuration update")
                    .payload
                else {
                    continue;
                };
                components.push(match update.component.expect("redriven component") {
                    config_update::Component::SandboxConfig(_) => ConfigComponent::SandboxConfig,
                    config_update::Component::ProviderEnvironment(_) => {
                        ConfigComponent::ProviderEnvironment
                    }
                });
            }
            components
        })
        .await
        .expect("generation mismatch schedules prompt reconciliation");
        assert!(redriven_components.contains(&ConfigComponent::SandboxConfig));
        assert!(redriven_components.contains(&ConfigComponent::ProviderEnvironment));
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
        assert!(observation.observed_at_time.is_some());
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

    fn applied_bootstrap_result(bootstrap: &ConfigBootstrap) -> ConfigBootstrapResult {
        let sandbox = bootstrap
            .sandbox_config
            .as_ref()
            .expect("sandbox bootstrap component");
        let provider = bootstrap
            .provider_environment
            .as_ref()
            .expect("provider bootstrap component");
        let sandbox_revision = config_message_revision(&SupervisorConfigMessage::SandboxConfig(
            Box::new(sandbox.clone()),
        ));
        let provider_revision = config_message_revision(
            &SupervisorConfigMessage::ProviderEnvironment(provider.clone()),
        );
        ConfigBootstrapResult {
            results: vec![
                ConfigComponentApplyResult {
                    component: ConfigComponent::SandboxConfig.into(),
                    requested_revision: Some(sandbox_revision.clone()),
                    applied_revision: Some(sandbox_revision),
                    outcome: ConfigApplyOutcome::Applied.into(),
                    ..Default::default()
                },
                ConfigComponentApplyResult {
                    component: ConfigComponent::ProviderEnvironment.into(),
                    requested_revision: Some(provider_revision.clone()),
                    applied_revision: Some(provider_revision),
                    outcome: ConfigApplyOutcome::Applied.into(),
                    ..Default::default()
                },
            ],
            admission: Some(expected_configuration_admission(sandbox)),
        }
    }

    async fn report_bootstrap_and_runtime_ready(
        state: &Arc<ServerState>,
        sandbox_id: &str,
        harness: &mut crate::grpc::test_support::SupervisorStreamHarness,
        bootstrap: &ConfigBootstrap,
    ) {
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::ConfigBootstrapResult(
                    applied_bootstrap_result(bootstrap),
                )),
            })
            .await
            .unwrap();
        assert!(matches!(
            first_gateway_message(harness).await.payload,
            Some(gateway_message::Payload::ConfigurationAdmission(_))
        ));
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::RuntimeReady(
                    openshell_core::proto::SupervisorRuntimeReady {},
                )),
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !state.supervisor_sessions.is_runtime_ready(sandbox_id) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("runtime readiness before timeout");
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
    async fn revision_two_reconnect_skips_startup_preparation_and_restores_readiness() {
        let sandbox_id = "sb-reconnect-no-preparation";
        let policy = openshell_policy::restrictive_default_policy();
        let state = state_with_startup_policy(sandbox_id, Some(policy)).await;
        let mut initial = crate::grpc::test_support::connect_supervisor_stream(
            &state,
            sandbox_id,
            SUPERVISOR_PROTOCOL_REVISION,
        )
        .await
        .expect("initial supervisor connection");
        let Some(gateway_message::Payload::StartupConfigCandidate(candidate)) =
            first_gateway_message(&mut initial).await.payload
        else {
            panic!("initial session must prepare the startup policy");
        };
        initial
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::StartupConfigPrepared(
                    StartupConfigPrepared {
                        candidate_id: candidate.candidate_id,
                        result: Some(startup_config_prepared::Result::Unchanged(())),
                    },
                )),
            })
            .await
            .unwrap();
        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut initial).await.payload
        else {
            panic!("expected initial SessionAccepted");
        };
        let bootstrap = accepted.bootstrap.expect("initial authoritative bootstrap");
        report_bootstrap_and_runtime_ready(&state, sandbox_id, &mut initial, &bootstrap).await;
        drop(initial);

        let mut reconnect = crate::grpc::test_support::reconnect_supervisor_stream(
            &state,
            sandbox_id,
            SUPERVISOR_PROTOCOL_REVISION,
        )
        .await
        .expect("stock supervisor reconnect");
        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut reconnect).await.payload
        else {
            panic!("reconnect must proceed directly to SessionAccepted");
        };
        let bootstrap = accepted
            .bootstrap
            .expect("reconnect authoritative bootstrap");
        report_bootstrap_and_runtime_ready(&state, sandbox_id, &mut reconnect, &bootstrap).await;
    }

    #[tokio::test]
    async fn invalid_image_policy_waits_for_gateway_repair_on_same_stream() {
        use openshell_core::proto::image_policy_discovery::Result as DiscoveryResult;

        let sandbox_id = "sb-invalid-image-repair";
        let state = state_with_startup_policy(sandbox_id, None).await;
        let connecting_state = Arc::clone(&state);
        let connection = tokio::spawn(async move {
            crate::grpc::test_support::connect_supervisor_stream_with_image_policy_discovery(
                &connecting_state,
                sandbox_id,
                SUPERVISOR_PROTOCOL_REVISION,
                openshell_core::proto::ImagePolicyDiscovery {
                    result: Some(DiscoveryResult::Invalid(())),
                },
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !connection.is_finished(),
            "invalid image policy must keep the startup stream pending"
        );

        let repaired_policy = openshell_policy::restrictive_default_policy();
        let mut sandbox = state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .expect("sandbox exists");
        sandbox.spec.get_or_insert_default().policy = Some(repaired_policy.clone());
        state.store.put_message(&sandbox).await.unwrap();
        state.sandbox_watch_bus.notify(sandbox_id);

        let mut harness = tokio::time::timeout(Duration::from_secs(5), connection)
            .await
            .expect("repair resumes the pending stream")
            .expect("connection task")
            .expect("supervisor connects after repair");
        let Some(gateway_message::Payload::StartupConfigCandidate(candidate)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected StartupConfigCandidate after repair");
        };
        assert_eq!(candidate.policy.as_ref(), Some(&repaired_policy));
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::StartupConfigPrepared(
                    StartupConfigPrepared {
                        candidate_id: candidate.candidate_id,
                        result: Some(startup_config_prepared::Result::Unchanged(())),
                    },
                )),
            })
            .await
            .unwrap();
        assert!(matches!(
            first_gateway_message(&mut harness).await.payload,
            Some(gateway_message::Payload::SessionAccepted(_))
        ));
    }

    #[tokio::test]
    async fn startup_candidate_prefers_gateway_policy_and_accepts_unchanged_result() {
        let gateway_policy = openshell_policy::restrictive_default_policy();
        let mut image_policy = gateway_policy.clone();
        image_policy
            .filesystem
            .get_or_insert_default()
            .read_only
            .push("/image-only".into());
        let state =
            state_with_startup_policy("sb-startup-gateway", Some(gateway_policy.clone())).await;
        let mut harness = crate::grpc::test_support::connect_supervisor_stream_with_image_policy(
            &state,
            "sb-startup-gateway",
            SUPERVISOR_PROTOCOL_REVISION,
            Some(image_policy),
        )
        .await
        .expect("supervisor must connect");

        let Some(gateway_message::Payload::StartupConfigCandidate(candidate)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected StartupConfigCandidate");
        };
        assert_eq!(candidate.policy.as_ref(), Some(&gateway_policy));
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::StartupConfigPrepared(
                    StartupConfigPrepared {
                        candidate_id: candidate.candidate_id,
                        result: Some(startup_config_prepared::Result::Unchanged(())),
                    },
                )),
            })
            .await
            .unwrap();

        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected SessionAccepted");
        };
        assert_eq!(
            accepted
                .bootstrap
                .and_then(|bootstrap| bootstrap.sandbox_config)
                .and_then(|snapshot| snapshot.policy),
            Some(gateway_policy)
        );
    }

    #[tokio::test]
    async fn unchanged_image_policy_is_persisted_before_session_acceptance() {
        let image_policy = openshell_policy::restrictive_default_policy();
        let state = state_with_startup_policy("sb-startup-image", None).await;
        let mut harness = crate::grpc::test_support::connect_supervisor_stream_with_image_policy(
            &state,
            "sb-startup-image",
            SUPERVISOR_PROTOCOL_REVISION,
            Some(image_policy.clone()),
        )
        .await
        .expect("supervisor must connect");

        let Some(gateway_message::Payload::StartupConfigCandidate(candidate)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected StartupConfigCandidate");
        };
        assert_eq!(candidate.policy.as_ref(), Some(&image_policy));
        assert_eq!(candidate.policy_version, 0);
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::StartupConfigPrepared(
                    StartupConfigPrepared {
                        candidate_id: candidate.candidate_id,
                        result: Some(startup_config_prepared::Result::Unchanged(())),
                    },
                )),
            })
            .await
            .unwrap();

        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected SessionAccepted");
        };
        let snapshot = accepted
            .bootstrap
            .and_then(|bootstrap| bootstrap.sandbox_config)
            .expect("authoritative sandbox snapshot");
        assert_eq!(snapshot.policy, Some(image_policy));
        assert_eq!(snapshot.version, 1);
    }

    #[tokio::test]
    async fn prepared_policy_is_validated_and_returned_in_fresh_bootstrap() {
        let image_policy = openshell_policy::restrictive_default_policy();
        let mut prepared_policy = image_policy.clone();
        prepared_policy
            .filesystem
            .get_or_insert_default()
            .read_only
            .push("/prepared-path".into());
        let state = state_with_startup_policy("sb-startup-prepared", None).await;
        let mut harness = crate::grpc::test_support::connect_supervisor_stream_with_image_policy(
            &state,
            "sb-startup-prepared",
            SUPERVISOR_PROTOCOL_REVISION,
            Some(image_policy),
        )
        .await
        .expect("supervisor must connect");

        let Some(gateway_message::Payload::StartupConfigCandidate(candidate)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected StartupConfigCandidate");
        };
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::StartupConfigPrepared(
                    StartupConfigPrepared {
                        candidate_id: candidate.candidate_id,
                        result: Some(startup_config_prepared::Result::PreparedPolicy(
                            prepared_policy.clone(),
                        )),
                    },
                )),
            })
            .await
            .unwrap();

        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected SessionAccepted");
        };
        assert_eq!(
            accepted
                .bootstrap
                .and_then(|bootstrap| bootstrap.sandbox_config)
                .and_then(|snapshot| snapshot.policy),
            Some(prepared_policy)
        );
    }

    #[tokio::test]
    async fn invalid_prepared_policy_rejects_session_without_acceptance() {
        let image_policy = openshell_policy::restrictive_default_policy();
        let mut invalid_policy = image_policy.clone();
        invalid_policy
            .filesystem
            .get_or_insert_default()
            .read_only
            .push("relative/path".into());
        let state = state_with_startup_policy("sb-startup-invalid", None).await;
        let mut harness = crate::grpc::test_support::connect_supervisor_stream_with_image_policy(
            &state,
            "sb-startup-invalid",
            SUPERVISOR_PROTOCOL_REVISION,
            Some(image_policy),
        )
        .await
        .expect("supervisor must connect");

        let Some(gateway_message::Payload::StartupConfigCandidate(candidate)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("expected StartupConfigCandidate");
        };
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::StartupConfigPrepared(
                    StartupConfigPrepared {
                        candidate_id: candidate.candidate_id,
                        result: Some(startup_config_prepared::Result::PreparedPolicy(
                            invalid_policy,
                        )),
                    },
                )),
            })
            .await
            .unwrap();

        let Some(gateway_message::Payload::SessionRejected(rejected)) =
            first_gateway_message(&mut harness).await.payload
        else {
            panic!("invalid preparation must reject without accepting the session");
        };
        assert!(rejected.reason.contains("policy"));
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

    #[test]
    fn bootstrap_acknowledgement_suppresses_unchanged_reconciliation() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, mut rx) = mpsc::channel(1);
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        registry.register("sb-1".into(), "session-1".into(), tx, shutdown_tx);
        let snapshot = SandboxConfigSnapshot {
            config_revision: 7,
            version: 11,
            ..Default::default()
        };
        let revision = config_message_revision(&SupervisorConfigMessage::SandboxConfig(Box::new(
            snapshot.clone(),
        )));
        let fingerprint = config_message_fingerprint(&SupervisorConfigMessage::SandboxConfig(
            Box::new(snapshot.clone()),
        ));

        assert!(!registry.acknowledge_bootstrap_component(
            "sb-1",
            "session-1",
            &ConfigComponentApplyResult {
                component: ConfigComponent::SandboxConfig.into(),
                requested_revision: Some(revision.clone()),
                applied_revision: None,
                outcome: ConfigApplyOutcome::FailedClosed.into(),
                ..Default::default()
            },
            &fingerprint,
        ));
        assert!(registry.acknowledge_bootstrap_component(
            "sb-1",
            "session-1",
            &ConfigComponentApplyResult {
                component: ConfigComponent::SandboxConfig.into(),
                requested_revision: Some(revision.clone()),
                applied_revision: Some(revision),
                outcome: ConfigApplyOutcome::Applied.into(),
                ..Default::default()
            },
            &fingerprint,
        ));
        assert_eq!(
            registry.deliver_config(
                "sb-1",
                SupervisorConfigMessage::SandboxConfig(Box::new(snapshot)),
            ),
            DeliveryDisposition::SuppressedUnchanged
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn bootstrap_acknowledgement_does_not_replace_newer_delivery_state() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, mut rx) = mpsc::channel(1);
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        registry.register("sb-1".into(), "session-1".into(), tx, shutdown_tx);
        let bootstrap_revision = ConfigSnapshotRevision {
            component: Some(config_snapshot_revision::Component::ProviderEnvironment(7)),
        };
        let bootstrap_fingerprint = ConfigSnapshotFingerprint::ProviderEnvironment {
            provider_env_revision: 7,
            provider_attachment_epoch: String::new(),
            policy_hash: String::new(),
        };

        assert_eq!(
            registry.deliver_config(
                "sb-1",
                SupervisorConfigMessage::ProviderEnvironment(ProviderEnvironmentSnapshot {
                    provider_env_revision: 8,
                    ..Default::default()
                }),
            ),
            DeliveryDisposition::Enqueued
        );
        assert!(!registry.acknowledge_bootstrap_component(
            "sb-1",
            "session-1",
            &ConfigComponentApplyResult {
                component: ConfigComponent::ProviderEnvironment.into(),
                requested_revision: Some(bootstrap_revision.clone()),
                applied_revision: Some(bootstrap_revision.clone()),
                outcome: ConfigApplyOutcome::Applied.into(),
                ..Default::default()
            },
            &bootstrap_fingerprint,
        ));

        let message = rx.try_recv().expect("newer update");
        let Some(gateway_message::Payload::ConfigUpdate(update)) = message.payload else {
            panic!("expected config update");
        };
        assert_eq!(update.component_sequence, 1);
        let in_flight_revision = registry
            .sessions
            .lock()
            .unwrap()
            .get("sb-1")
            .unwrap()
            .config_sequences
            .provider_environment
            .in_flight
            .as_ref()
            .unwrap()
            .revision
            .clone();
        assert_eq!(
            in_flight_revision.component,
            Some(config_snapshot_revision::Component::ProviderEnvironment(8))
        );

        let (replacement_tx, _replacement_rx) = mpsc::channel(1);
        let (replacement_shutdown_tx, _replacement_shutdown_rx) = oneshot::channel();
        registry.register(
            "sb-1".into(),
            "session-2".into(),
            replacement_tx,
            replacement_shutdown_tx,
        );
        assert!(!registry.acknowledge_bootstrap_component(
            "sb-1",
            "session-1",
            &ConfigComponentApplyResult {
                component: ConfigComponent::ProviderEnvironment.into(),
                requested_revision: Some(bootstrap_revision.clone()),
                applied_revision: Some(bootstrap_revision),
                outcome: ConfigApplyOutcome::Applied.into(),
                ..Default::default()
            },
            &bootstrap_fingerprint,
        ));
    }

    #[test]
    fn sandbox_delivery_fingerprint_includes_provider_generation() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, mut rx) = mpsc::channel(1);
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        registry.register("sb-1".into(), "session-1".into(), tx, shutdown_tx);
        let snapshot = SandboxConfigSnapshot {
            configuration_admitted: true,
            config_revision: 7,
            provider_env_revision: 11,
            provider_attachment_epoch: "epoch-1".into(),
            policy_hash: "policy-1".into(),
            ..Default::default()
        };
        let message = SupervisorConfigMessage::SandboxConfig(Box::new(snapshot.clone()));
        let revision = config_message_revision(&message);
        assert!(registry.acknowledge_bootstrap_component(
            "sb-1",
            "session-1",
            &ConfigComponentApplyResult {
                component: ConfigComponent::SandboxConfig.into(),
                requested_revision: Some(revision.clone()),
                applied_revision: Some(revision),
                outcome: ConfigApplyOutcome::Applied.into(),
                ..Default::default()
            },
            &config_message_fingerprint(&message),
        ));
        assert_eq!(
            registry.deliver_config("sb-1", message),
            DeliveryDisposition::SuppressedUnchanged
        );
        assert_eq!(
            registry.deliver_config(
                "sb-1",
                SupervisorConfigMessage::SandboxConfig(Box::new(SandboxConfigSnapshot {
                    provider_env_revision: 12,
                    ..snapshot
                })),
            ),
            DeliveryDisposition::Enqueued
        );
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn provider_delivery_fingerprint_includes_policy_hash_and_attachment_epoch() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, mut rx) = mpsc::channel(2);
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        registry.register("sb-1".into(), "session-1".into(), tx, shutdown_tx);
        let snapshot = ProviderEnvironmentSnapshot {
            provider_env_revision: 7,
            provider_attachment_epoch: "epoch-1".into(),
            policy_hash: "policy-1".into(),
            ..Default::default()
        };
        let message = SupervisorConfigMessage::ProviderEnvironment(snapshot.clone());
        let revision = config_message_revision(&message);
        let fingerprint = config_message_fingerprint(&message);
        assert!(registry.acknowledge_bootstrap_component(
            "sb-1",
            "session-1",
            &ConfigComponentApplyResult {
                component: ConfigComponent::ProviderEnvironment.into(),
                requested_revision: Some(revision.clone()),
                applied_revision: Some(revision),
                outcome: ConfigApplyOutcome::Applied.into(),
                ..Default::default()
            },
            &fingerprint,
        ));
        assert_eq!(
            registry.deliver_config("sb-1", message),
            DeliveryDisposition::SuppressedUnchanged
        );

        let policy_changed =
            SupervisorConfigMessage::ProviderEnvironment(ProviderEnvironmentSnapshot {
                policy_hash: "policy-2".into(),
                ..snapshot.clone()
            });
        assert_eq!(
            registry.deliver_config("sb-1", policy_changed),
            DeliveryDisposition::Enqueued
        );
        assert!(rx.try_recv().is_ok());

        let (replacement_tx, mut replacement_rx) = mpsc::channel(1);
        let (replacement_shutdown_tx, _replacement_shutdown_rx) = oneshot::channel();
        registry.register(
            "sb-1".into(),
            "session-2".into(),
            replacement_tx,
            replacement_shutdown_tx,
        );
        let fingerprint = config_message_fingerprint(
            &SupervisorConfigMessage::ProviderEnvironment(snapshot.clone()),
        );
        assert!(registry.acknowledge_bootstrap_component(
            "sb-1",
            "session-2",
            &ConfigComponentApplyResult {
                component: ConfigComponent::ProviderEnvironment.into(),
                requested_revision: Some(config_message_revision(
                    &SupervisorConfigMessage::ProviderEnvironment(snapshot.clone()),
                )),
                applied_revision: Some(config_message_revision(
                    &SupervisorConfigMessage::ProviderEnvironment(snapshot.clone()),
                )),
                outcome: ConfigApplyOutcome::Applied.into(),
                ..Default::default()
            },
            &fingerprint,
        ));
        assert_eq!(
            registry.deliver_config(
                "sb-1",
                SupervisorConfigMessage::ProviderEnvironment(ProviderEnvironmentSnapshot {
                    provider_attachment_epoch: "epoch-2".into(),
                    ..snapshot
                }),
            ),
            DeliveryDisposition::Enqueued
        );
        assert!(replacement_rx.try_recv().is_ok());
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
            .revision
            .clone();
        let completed = registry
            .complete_config_update(
                "sb-1",
                "session-1",
                &ConfigUpdateResult {
                    update_id: first.update_id,
                    component_sequence: first.component_sequence,
                    result: Some(ConfigComponentApplyResult {
                        component: ConfigComponent::SandboxConfig.into(),
                        requested_revision: Some(revision.clone()),
                        applied_revision: Some(revision.clone()),
                        outcome: ConfigApplyOutcome::Applied.into(),
                        failure: None,
                    }),
                    admission: None,
                },
            )
            .unwrap();
        assert!(registry.finalize_config_update("sb-1", "session-1", &completed, true,));
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
