// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Build and deliver complete supervisor configuration.

pub mod session;
mod task;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use futures::StreamExt;
use metrics::{counter, histogram};
use openshell_core::config::ConfigDeliveryMode;
use openshell_core::proto::{
    PeerConfigProviderTarget, PeerConfigSandboxTarget, PeerNotifyConfigUpdateRequest,
    PeerNotifyConfigUpdateResponse, ProviderEnvironmentSnapshot, ProviderReadinessReason, Sandbox,
    SandboxConfigSnapshot, peer_notify_config_update_request,
};
use tokio::sync::Semaphore;
use tonic::{Code, Request, Response, Status};
use tracing::warn;

use crate::ServerState;
use crate::auth::principal::Principal;
use crate::gateway_members::{GatewayMember, GatewayMemberIndex, MEMBER_TTL};
use crate::grpc::policy::{
    SandboxConfigInputs, build_provider_environment_snapshot_from_inputs,
    build_sandbox_config_snapshot_from_inputs, is_configuration_rejection,
    load_sandbox_config_inputs, unadmitted_sandbox_config,
};
use crate::supervisor_owner::{OWNER_TTL, SupervisorOwnerIndex, dialable_peer_endpoint};

pub use task::Registration;
use task::{Deliver, FanoutScope, SessionRecord};

/// Leaves 1 MiB below the supervisor's receive limit for framing and future
/// envelope fields.
pub const MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES: usize =
    openshell_core::grpc_client::MAX_SUPERVISOR_STREAM_MESSAGE_BYTES - 1024 * 1024;
/// Loading inputs and building the sandbox configuration only read the store,
/// which answers in milliseconds when healthy; anything slower means the
/// store is in trouble.
const SANDBOX_CONFIG_BUILD_TIMEOUT: Duration = Duration::from_secs(5);
/// Building the provider environment also resolves credentials. Covers a cold
/// Vault Kubernetes-auth login plus a read at the default 10-second request
/// timeout.
const PROVIDER_ENVIRONMENT_BUILD_TIMEOUT: Duration = Duration::from_secs(20);
/// Concurrent snapshot builds allowed per pooled database connection. Builds
/// are short bursts of small queries, so a little oversubscription keeps the
/// pool busy without stacking every waiter on the acquire timeout.
const SNAPSHOT_BUILDS_PER_DB_CONNECTION: usize = 2;
const MIN_CONCURRENT_SNAPSHOT_BUILDS: usize = 4;
const MAX_CONCURRENT_PEER_NOTIFIES: usize = 8;
const PEER_NOTIFY_TIMEOUT: Duration = Duration::from_secs(5);
const PEER_FANOUT_CONCURRENCY: usize = 8;

/// Complete configuration awaiting delivery to a supervisor: the sandbox
/// configuration and the provider environment it names.
#[derive(Clone)]
pub struct SupervisorConfig {
    pub sandbox_config: SandboxConfigSnapshot,
    pub provider_environment: ProviderEnvironmentSnapshot,
}

impl fmt::Debug for SupervisorConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SupervisorConfig(<redacted>)")
    }
}

/// Whether `provider` is the environment `sandbox` names. Without a gateway
/// policy the sandbox configuration carries no policy hash and is not
/// admitted, so its supervisor installs no provider environment.
fn names_provider_environment(
    sandbox: &SandboxConfigSnapshot,
    provider: &ProviderEnvironmentSnapshot,
) -> bool {
    sandbox.provider_env_revision == provider.provider_env_revision
        && sandbox.provider_attachment_epoch == provider.provider_attachment_epoch
        && (sandbox.policy.is_none() || sandbox.policy_hash == provider.policy_hash)
}

/// The provider environment to deliver when the one `sandbox` names cannot
/// be built: no values, marked as failed. The supervisor revokes its static
/// credentials and rejects the update, as it does when a polling fetch
/// fails, and the session retries the build.
fn unresolved_provider_environment(sandbox: &SandboxConfigSnapshot) -> ProviderEnvironmentSnapshot {
    ProviderEnvironmentSnapshot {
        provider_env_revision: sandbox.provider_env_revision,
        provider_attachment_epoch: sandbox.provider_attachment_epoch.clone(),
        policy_hash: sandbox.policy_hash.clone(),
        readiness_reason: ProviderReadinessReason::CredentialInstallFailed.into(),
        ..Default::default()
    }
}

/// Result of handing one configuration to a supervisor session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryDisposition {
    Queued,
    /// Held until the supervisor answers the previous update.
    Coalesced,
    /// Matches the update the supervisor last acknowledged.
    SuppressedUnchanged,
    NoActiveSession,
    UnsupportedSession,
    PayloadTooLarge,
    /// The session's outbound stream was full or closed, so the session was
    /// closed for its supervisor to reconnect.
    StreamClosed,
}

impl DeliveryDisposition {
    fn metric_label(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Coalesced => "coalesced",
            Self::SuppressedUnchanged => "unchanged",
            Self::NoActiveSession => "no_active_session",
            Self::UnsupportedSession => "unsupported_session",
            Self::PayloadTooLarge => "payload_too_large",
            Self::StreamClosed => "stream_closed",
        }
    }
}

/// Per-session delivery tasks for this replica's push sessions, plus
/// coalesced notifications to peer replicas.
#[derive(Debug)]
pub struct ConfigDelivery {
    sessions: Mutex<Sessions>,
    /// Snapshot builds in progress, bounded by the database pool they read.
    builds: Arc<Semaphore>,
    /// Targets with a notification task running, and whether another
    /// notification arrived since that task last sent one.
    peer_notifies: Mutex<HashMap<PeerNotifyTarget, bool>>,
    peer_notify_permits: Arc<Semaphore>,
}

/// This replica's push sessions and the publications that looked for them.
#[derive(Debug, Default)]
struct Sessions {
    records: HashMap<String, Arc<SessionRecord>>,
    /// Counts publications, so a registering session can tell whether one
    /// raced its bootstrap. It shares the lock with `records`, so a
    /// publication either finds a registered session or is counted before
    /// that session compares the count.
    publications: u64,
}

/// Where a peer notification goes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PeerNotifyTarget {
    /// Sandbox without a local push session; its owner may be a peer.
    Sandbox(String),
    /// Scope notification for every peer gateway.
    Peers(FanoutScope),
}

impl ConfigDelivery {
    /// Size the build bound from the persistence pool that every build reads.
    #[must_use]
    pub fn for_db_connections(max_connections: u32) -> Self {
        let max_connections = usize::try_from(max_connections).unwrap_or(usize::MAX);
        let builds = max_connections
            .saturating_mul(SNAPSHOT_BUILDS_PER_DB_CONNECTION)
            .max(MIN_CONCURRENT_SNAPSHOT_BUILDS);
        Self {
            sessions: Mutex::new(Sessions::default()),
            builds: Arc::new(Semaphore::new(builds)),
            peer_notifies: Mutex::new(HashMap::new()),
            peer_notify_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_PEER_NOTIFIES)),
        }
    }

    pub(crate) fn publications(&self) -> u64 {
        self.sessions().publications
    }

    #[cfg(test)]
    fn has_session(&self, sandbox_id: &str) -> bool {
        self.sessions().records.contains_key(sandbox_id)
    }

    /// Delivery is best effort beside the session lifecycle, so a poisoned
    /// lock must not turn session teardown into a panic.
    fn sessions(&self) -> MutexGuard<'_, Sessions> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns false when this gateway has no push session for the sandbox.
    fn publish_sandbox(&self, sandbox_id: &str) -> bool {
        let record = {
            let mut sessions = self.sessions();
            sessions.publications += 1;
            sessions.records.get(sandbox_id).cloned()
        };
        let Some(record) = record else {
            return false;
        };
        record.mark();
        true
    }

    fn publish_fanout(&self, scope: &FanoutScope) {
        let mut sessions = self.sessions();
        sessions.publications += 1;
        for record in sessions.records.values() {
            if record.in_scope(scope) {
                record.mark();
            }
        }
    }
}

pub fn push_enabled(state: &ServerState) -> bool {
    state.config.config_delivery_mode == ConfigDeliveryMode::Push
}

/// Push a committed change to one sandbox's supervisor.
pub fn publish_sandbox(state: &Arc<ServerState>, sandbox_id: &str) {
    if !push_enabled(state) {
        return;
    }
    // A single-replica gateway owns every session, and registration covers a
    // session that is still connecting.
    if !state.config_delivery.publish_sandbox(sandbox_id) && !state.store.is_single_replica() {
        notify_peer(state, PeerNotifyTarget::Sandbox(sandbox_id.to_string()));
    }
}

/// Push a committed change to every sandbox in a workspace.
pub fn publish_workspace(state: &Arc<ServerState>, workspace: &str) {
    publish_fanout(state, &FanoutScope::Workspace(workspace.to_string()));
}

/// Push a provider change to the sandboxes that attach that provider.
pub fn publish_provider(state: &Arc<ServerState>, workspace: &str, provider_name: &str) {
    publish_fanout(
        state,
        &FanoutScope::Provider {
            workspace: workspace.to_string(),
            name: provider_name.to_string(),
        },
    );
}

/// Push a committed change to every connected sandbox.
pub fn publish_all_connected(state: &Arc<ServerState>) {
    publish_fanout(state, &FanoutScope::AllConnected);
}

/// Push a change that every replica observes on its own, such as a refreshed
/// provider profile source, to the sessions this replica holds. Each replica
/// publishes its own change, so notifying peers would repeat it.
pub fn publish_all_local(state: &Arc<ServerState>) {
    if push_enabled(state) {
        state
            .config_delivery
            .publish_fanout(&FanoutScope::AllConnected);
    }
}

fn publish_fanout(state: &Arc<ServerState>, scope: &FanoutScope) {
    if !push_enabled(state) {
        return;
    }
    state.config_delivery.publish_fanout(scope);
    if !state.store.is_single_replica() {
        notify_peer(state, PeerNotifyTarget::Peers(scope.clone()));
    }
}

/// Make a streamed-apply session visible to publications and start its
/// delivery task.
pub fn register_session(state: &Arc<ServerState>, registration: Registration) {
    let captured_seq = registration.captured_seq;
    let rebuild = registration.rebuild;
    let record = Arc::new(SessionRecord::new(registration));
    let raced = {
        let mut sessions = state.config_delivery.sessions();
        // A concurrent reconnect may already own the registry entry. Checking
        // under the sessions lock keeps the newest session registered.
        if !state
            .supervisor_sessions
            .is_current_session(&record.sandbox_id, &record.session_id)
        {
            return;
        }
        if let Some(previous) = sessions
            .records
            .insert(record.sandbox_id.clone(), Arc::clone(&record))
        {
            previous.close();
        }
        sessions.publications > captured_seq
    };
    // A publication between the bootstrap read and registration may have
    // missed this session.
    if raced || rebuild {
        record.mark();
    }
    let state = Arc::clone(state);
    tokio::spawn(async move {
        task::run(
            record,
            &state.config_delivery.builds,
            &Builder(&state),
            task::RECONCILE_INTERVAL,
        )
        .await;
    });
}

pub fn unregister_session(state: &ServerState, sandbox_id: &str, session_id: &str) {
    let mut sessions = state.config_delivery.sessions();
    if sessions
        .records
        .get(sandbox_id)
        .is_none_or(|record| record.session_id != session_id)
    {
        return;
    }
    if let Some(record) = sessions.records.remove(sandbox_id) {
        record.close();
    }
}

/// Builds and delivers a session's configuration.
struct Builder<'a>(&'a Arc<ServerState>);

impl Deliver for Builder<'_> {
    async fn deliver(&self, record: &SessionRecord) -> (bool, Option<HashSet<String>>) {
        let state = self.0;
        let sandbox_id = record.sandbox_id.as_str();
        let started = Instant::now();
        let built = tokio::time::timeout(
            SANDBOX_CONFIG_BUILD_TIMEOUT,
            build_sandbox_config(state, sandbox_id),
        )
        .await;
        let (inputs, sandbox_config) = match built {
            Ok(Ok(Some(BuiltSandboxConfig::Built(inputs, sandbox_config)))) => {
                (*inputs, sandbox_config)
            }
            Ok(Ok(Some(BuiltSandboxConfig::Rejected {
                sandbox_config,
                providers,
                error_code,
            }))) => {
                record_build_failure(sandbox_id, "rejected", error_code, started.elapsed());
                let provider_environment = unresolved_provider_environment(&sandbox_config);
                let config = SupervisorConfig {
                    sandbox_config,
                    provider_environment,
                };
                let owner = deliver_if_owner(state, sandbox_id, &record.session_id, config).await;
                if matches!(owner, OwnerCheck::Remote) {
                    notify_peer(state, PeerNotifyTarget::Sandbox(record.sandbox_id.clone()));
                }
                return (matches!(owner, OwnerCheck::Unknown), Some(providers));
            }
            Ok(Ok(None)) => {
                record_build("ok", started.elapsed());
                return (false, None);
            }
            Ok(Err(error)) => {
                record_build_failure(sandbox_id, "failed", error.code(), started.elapsed());
                return (true, None);
            }
            Err(_) => {
                record_build_failure(
                    sandbox_id,
                    "timeout",
                    Code::DeadlineExceeded,
                    started.elapsed(),
                );
                return (true, None);
            }
        };
        let providers = inputs
            .sandbox()
            .spec
            .as_ref()
            .map(|spec| spec.providers.iter().cloned().collect())
            .unwrap_or_default();
        let (provider_environment, failed) =
            provider_environment(state, record, &inputs, &sandbox_config).await;
        if failed.is_none() {
            record_build("ok", started.elapsed());
        }
        let config = SupervisorConfig {
            sandbox_config,
            provider_environment,
        };
        let owner = deliver_if_owner(state, sandbox_id, &record.session_id, config).await;
        if matches!(owner, OwnerCheck::Remote) {
            notify_peer(state, PeerNotifyTarget::Sandbox(record.sandbox_id.clone()));
        }
        if let Some((outcome, error_code)) = failed {
            record_build_failure(sandbox_id, outcome, error_code, started.elapsed());
        }
        (
            failed.is_some() || matches!(owner, OwnerCheck::Unknown),
            Some(providers),
        )
    }
}

enum BuiltSandboxConfig {
    Built(Box<SandboxConfigInputs>, SandboxConfigSnapshot),
    /// The stored configuration is invalid, so the supervisor receives the
    /// not-admitted configuration polling serves and fails closed.
    Rejected {
        sandbox_config: SandboxConfigSnapshot,
        providers: HashSet<String>,
        error_code: Code,
    },
}

/// Read the sandbox and the inputs its configuration shares, and build its
/// sandbox configuration, or `None` once the sandbox is gone.
async fn build_sandbox_config(
    state: &Arc<ServerState>,
    sandbox_id: &str,
) -> Result<Option<BuiltSandboxConfig>, Status> {
    let Some(sandbox) = state
        .store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .map_err(|error| Status::internal(format!("fetch sandbox failed: {error}")))?
    else {
        return Ok(None);
    };
    let built = async {
        let inputs = load_sandbox_config_inputs(state, sandbox.clone()).await?;
        let snapshot = build_sandbox_config_snapshot_from_inputs(state, &inputs).await?;
        Ok::<_, Status>((inputs, snapshot))
    }
    .await;
    match built {
        Ok((inputs, snapshot)) => Ok(Some(BuiltSandboxConfig::Built(Box::new(inputs), snapshot))),
        Err(error) if is_configuration_rejection(&error) => {
            Ok(Some(BuiltSandboxConfig::Rejected {
                sandbox_config: unadmitted_sandbox_config(state, &sandbox, &error),
                providers: sandbox
                    .spec
                    .as_ref()
                    .map(|spec| spec.providers.iter().cloned().collect())
                    .unwrap_or_default(),
                error_code: error.code(),
            }))
        }
        Err(error) => Err(error),
    }
}

/// The provider environment `sandbox` names. The session's last resolved
/// environment is reused while the name is unchanged, so only a change
/// resolves credentials. A failed resolution returns the unresolved
/// environment and the failure to record.
async fn provider_environment(
    state: &Arc<ServerState>,
    record: &SessionRecord,
    inputs: &SandboxConfigInputs,
    sandbox: &SandboxConfigSnapshot,
) -> (ProviderEnvironmentSnapshot, Option<(&'static str, Code)>) {
    if let Some(cached) = record
        .provider_environment()
        .filter(|cached| names_provider_environment(sandbox, cached))
    {
        return (cached, None);
    }
    let built = tokio::time::timeout(
        PROVIDER_ENVIRONMENT_BUILD_TIMEOUT,
        build_provider_environment_snapshot_from_inputs(state, inputs, true, true),
    )
    .await;
    match built {
        Ok(Ok(snapshot)) => {
            record.cache_provider_environment(snapshot.clone());
            (snapshot, None)
        }
        Ok(Err(error)) => (
            unresolved_provider_environment(sandbox),
            Some(("failed", error.code())),
        ),
        Err(_) => (
            unresolved_provider_environment(sandbox),
            Some(("timeout", Code::DeadlineExceeded)),
        ),
    }
}

/// Deliver `config` if this gateway still owns the session it was built for.
async fn deliver_if_owner(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    config: SupervisorConfig,
) -> OwnerCheck {
    let owner = owner_check(state, sandbox_id, session_id).await;
    let outcome = match owner {
        OwnerCheck::Current => state
            .supervisor_sessions
            .deliver_config(sandbox_id, session_id, config)
            .metric_label(),
        OwnerCheck::Remote => "owner_moved",
        OwnerCheck::Gone => "no_active_session",
        OwnerCheck::Unknown => "owner_lookup_failed",
    };
    record_delivery(outcome);
    owner
}

enum OwnerCheck {
    /// This gateway owns the session the build started for.
    Current,
    /// The session moved to another gateway after the build started.
    Remote,
    Gone,
    Unknown,
}

async fn owner_check(state: &Arc<ServerState>, sandbox_id: &str, session_id: &str) -> OwnerCheck {
    // A single-replica gateway owns every session, and `deliver_config`
    // already refuses a replaced session.
    if state.store.is_single_replica() {
        return OwnerCheck::Current;
    }
    let owners = SupervisorOwnerIndex::new(Arc::clone(&state.store), OWNER_TTL);
    match owners.read(sandbox_id).await {
        Ok(Some(owner)) if owner.is_fresh(OWNER_TTL) => {
            if owner.owner_replica_id != state.replica_id {
                OwnerCheck::Remote
            } else if owner.session_id == session_id {
                OwnerCheck::Current
            } else {
                OwnerCheck::Gone
            }
        }
        Ok(_) => OwnerCheck::Gone,
        Err(error) => {
            warn!(sandbox_id, error = %error, "configuration owner lookup failed");
            OwnerCheck::Unknown
        }
    }
}

/// Queue a notification for `target`. Notifications for the same target
/// coalesce while one is pending or running.
fn notify_peer(state: &Arc<ServerState>, target: PeerNotifyTarget) {
    let start = {
        let mut pending = state
            .config_delivery
            .peer_notifies
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut start = false;
        pending
            .entry(target.clone())
            .and_modify(|queued| *queued = true)
            .or_insert_with(|| {
                start = true;
                true
            });
        start
    };
    if start {
        tokio::spawn(run_peer_notifies(Arc::clone(state), target));
    }
}

async fn run_peer_notifies(state: Arc<ServerState>, target: PeerNotifyTarget) {
    let _permit = Arc::clone(&state.config_delivery.peer_notify_permits)
        .acquire_owned()
        .await
        .expect("peer notification semaphore is never closed");
    loop {
        {
            let mut pending = state
                .config_delivery
                .peer_notifies
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let Some(queued) = pending.get_mut(&target) else {
                return;
            };
            if !std::mem::take(queued) {
                pending.remove(&target);
                return;
            }
        }
        match &target {
            PeerNotifyTarget::Sandbox(sandbox_id) => {
                if notify_sandbox_owner(&state, sandbox_id).await == PeerNotifyResult::Local {
                    state.config_delivery.publish_sandbox(sandbox_id);
                }
            }
            PeerNotifyTarget::Peers(scope) => notify_peers(&state, scope).await,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PeerNotifyResult {
    Done,
    /// This gateway owns the current session for the notified sandbox.
    Local,
}

/// Send a secret-free notification to the gateway that owns the sandbox session. The
/// owner builds its own configuration from shared state.
async fn notify_sandbox_owner(state: &Arc<ServerState>, sandbox_id: &str) -> PeerNotifyResult {
    let owners = SupervisorOwnerIndex::new(Arc::clone(&state.store), OWNER_TTL);
    let mut final_outcome = "stale_owner";
    for attempt in 0..2 {
        let owner = match owners.read(sandbox_id).await {
            Ok(Some(owner)) if owner.is_fresh(OWNER_TTL) => owner,
            Ok(_) => return PeerNotifyResult::Done,
            Err(error) => {
                warn!(sandbox_id, error = %error, "configuration owner lookup failed");
                return PeerNotifyResult::Done;
            }
        };
        if owner.owner_replica_id == state.replica_id {
            return if state
                .supervisor_sessions
                .is_current_session(sandbox_id, &owner.session_id)
            {
                PeerNotifyResult::Local
            } else {
                PeerNotifyResult::Done
            };
        }
        let Some(peer_endpoint) = owner.peer_endpoint().map(ToString::to_string) else {
            warn!(sandbox_id, owner = %owner.owner_replica_id, "configuration owner has no reachable peer endpoint");
            return PeerNotifyResult::Done;
        };
        let request = PeerNotifyConfigUpdateRequest {
            scope: Some(peer_notify_config_update_request::Scope::Sandbox(
                PeerConfigSandboxTarget {
                    sandbox_id: sandbox_id.to_string(),
                    session_id: owner.session_id,
                },
            )),
        };
        match send_peer_notify(state, &peer_endpoint, request).await {
            PeerNotifyOutcome::StaleOwner => final_outcome = "stale_owner",
            PeerNotifyOutcome::Failed(outcome) => {
                final_outcome = outcome;
                warn!(sandbox_id, owner = %owner.owner_replica_id, attempt, outcome, "configuration peer notification failed");
            }
            outcome => {
                record_peer_notify(outcome.label());
                return PeerNotifyResult::Done;
            }
        }
    }
    record_peer_notify(final_outcome);
    PeerNotifyResult::Done
}

/// The endpoints of the other live replicas, the only ones that can own a
/// session this replica does not. A replica without a peer endpoint does not
/// join the membership.
fn peer_endpoints(members: Vec<GatewayMember>, local_replica_id: &str) -> Vec<String> {
    members
        .into_iter()
        .filter(|member| member.replica_id != local_replica_id)
        .filter_map(|member| dialable_peer_endpoint(&member.peer_endpoint).map(str::to_string))
        .collect()
}

async fn notify_peers(state: &Arc<ServerState>, scope: &FanoutScope) {
    let members = GatewayMemberIndex::new(Arc::clone(&state.store), MEMBER_TTL);
    let endpoints = match members.live_members().await {
        Ok(members) => peer_endpoints(members, &state.replica_id),
        Err(error) => {
            warn!(error = %error, "configuration peer fanout membership listing failed");
            return;
        }
    };
    let scope = peer_scope(scope);
    futures::stream::iter(endpoints)
        .for_each_concurrent(PEER_FANOUT_CONCURRENCY, |endpoint| {
            let request = PeerNotifyConfigUpdateRequest {
                scope: Some(scope.clone()),
            };
            async move {
                let outcome = send_peer_notify(state, &endpoint, request).await;
                if let PeerNotifyOutcome::Failed(outcome) = outcome {
                    warn!(endpoint = %endpoint, outcome, "configuration peer fanout notification failed");
                }
                record_peer_notify(outcome.label());
            }
        })
        .await;
}

fn peer_scope(scope: &FanoutScope) -> peer_notify_config_update_request::Scope {
    match scope {
        FanoutScope::AllConnected => peer_notify_config_update_request::Scope::AllConnected(true),
        FanoutScope::Workspace(workspace) => {
            peer_notify_config_update_request::Scope::Workspace(workspace.clone())
        }
        FanoutScope::Provider { workspace, name } => {
            peer_notify_config_update_request::Scope::Provider(PeerConfigProviderTarget {
                workspace: workspace.clone(),
                name: name.clone(),
            })
        }
    }
}

enum PeerNotifyOutcome {
    Accepted,
    StaleOwner,
    UnsupportedPeer,
    Failed(&'static str),
}

impl PeerNotifyOutcome {
    fn label(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::StaleOwner => "stale_owner",
            Self::UnsupportedPeer => "unsupported_peer",
            Self::Failed(outcome) => outcome,
        }
    }
}

async fn send_peer_notify(
    state: &Arc<ServerState>,
    endpoint: &str,
    request: PeerNotifyConfigUpdateRequest,
) -> PeerNotifyOutcome {
    match tokio::time::timeout(
        PEER_NOTIFY_TIMEOUT,
        crate::supervisor_session::forward_config_notify_to_peer(state, endpoint, request),
    )
    .await
    {
        Ok(Ok(response)) if response.stale_owner => PeerNotifyOutcome::StaleOwner,
        Ok(Ok(_)) => PeerNotifyOutcome::Accepted,
        Ok(Err(error)) if error.code() == Code::Unimplemented => PeerNotifyOutcome::UnsupportedPeer,
        Ok(Err(_)) => PeerNotifyOutcome::Failed("peer_error"),
        Err(_) => PeerNotifyOutcome::Failed("timeout"),
    }
}

pub fn handle_peer_notify_config_update(
    state: &Arc<ServerState>,
    request: Request<PeerNotifyConfigUpdateRequest>,
) -> Result<Response<PeerNotifyConfigUpdateResponse>, Status> {
    if !matches!(
        request.extensions().get::<Principal>(),
        Some(Principal::Peer(_))
    ) {
        return Err(Status::permission_denied("gateway peer principal required"));
    }
    if !push_enabled(state) {
        return Err(Status::failed_precondition(
            "configuration push is disabled",
        ));
    }
    let notification = request.into_inner();
    let mut response = PeerNotifyConfigUpdateResponse::default();
    // Notifications from peers never fan out to peers again.
    let scope = match notification.scope {
        Some(peer_notify_config_update_request::Scope::Sandbox(target)) => {
            if target.sandbox_id.is_empty() || target.session_id.is_empty() {
                return Err(Status::invalid_argument(
                    "sandbox and session IDs are required",
                ));
            }
            // The sender resolved this session from the owner index. The
            // owner check after the build guards against a later move.
            if state
                .supervisor_sessions
                .is_current_session(&target.sandbox_id, &target.session_id)
            {
                state.config_delivery.publish_sandbox(&target.sandbox_id);
            } else {
                response.stale_owner = true;
            }
            return Ok(Response::new(response));
        }
        Some(peer_notify_config_update_request::Scope::Workspace(workspace)) => {
            if workspace.is_empty() {
                return Err(Status::invalid_argument("workspace is required"));
            }
            FanoutScope::Workspace(workspace)
        }
        Some(peer_notify_config_update_request::Scope::Provider(target)) => {
            if target.workspace.is_empty() || target.name.is_empty() {
                return Err(Status::invalid_argument(
                    "provider workspace and name are required",
                ));
            }
            FanoutScope::Provider {
                workspace: target.workspace,
                name: target.name,
            }
        }
        Some(peer_notify_config_update_request::Scope::AllConnected(true)) => {
            FanoutScope::AllConnected
        }
        _ => {
            return Err(Status::invalid_argument(
                "configuration notification scope is required",
            ));
        }
    };
    state.config_delivery.publish_fanout(&scope);
    Ok(Response::new(response))
}

/// Streamed-apply supervisor session registered without a gRPC stream. It
/// holds each update until the previous one is acknowledged. The registry
/// keeps its outbound channel open while the session is registered.
#[cfg(test)]
pub struct TestApplySession {
    pub outbound: tokio::sync::mpsc::Receiver<openshell_core::proto::GatewayMessage>,
}

#[cfg(test)]
pub fn register_test_apply_session(
    state: &Arc<ServerState>,
    sandbox: &Sandbox,
    session_id: &str,
) -> TestApplySession {
    let captured_seq = state.config_delivery.publications();
    register_test_apply_session_after(state, sandbox, session_id, captured_seq)
}

/// Register a test session whose bootstrap was read when the publication
/// count was `captured_seq`.
#[cfg(test)]
fn register_test_apply_session_after(
    state: &Arc<ServerState>,
    sandbox: &Sandbox,
    session_id: &str,
    captured_seq: u64,
) -> TestApplySession {
    use crate::persistence::{ObjectId, ObjectWorkspace};

    let (tx, outbound) = tokio::sync::mpsc::channel(4);
    let sandbox_id = sandbox.object_id().to_string();
    state.supervisor_sessions.register_with_mode(
        sandbox_id.clone(),
        session_id.to_string(),
        tx,
        tokio::sync::oneshot::channel().0,
        crate::supervisor_session::SessionMode::Push,
    );
    register_session(
        state,
        Registration {
            sandbox_id,
            session_id: session_id.to_string(),
            workspace: sandbox.object_workspace().to_string(),
            providers: sandbox
                .spec
                .as_ref()
                .map(|spec| spec.providers.iter().cloned().collect())
                .unwrap_or_default(),
            provider_environment: None,
            captured_seq,
            rebuild: false,
        },
    );
    TestApplySession { outbound }
}

fn record_build(outcome: &'static str, elapsed: Duration) {
    counter!(
        "openshell_supervisor_config_builds_total",
        "outcome" => outcome,
    )
    .increment(1);
    histogram!(
        crate::gateway_metrics::SUPERVISOR_CONFIG_BUILD_DURATION_SECONDS,
        "outcome" => outcome,
    )
    .record(elapsed.as_secs_f64());
}

fn record_build_failure(
    sandbox_id: &str,
    outcome: &'static str,
    error_code: Code,
    elapsed: Duration,
) {
    record_build(outcome, elapsed);
    warn!(
        sandbox_id,
        ?error_code,
        "failed to build supervisor configuration"
    );
}

fn record_delivery(outcome: &'static str) {
    counter!(
        "openshell_supervisor_config_deliveries_total",
        "outcome" => outcome,
    )
    .increment(1);
}

fn record_peer_notify(outcome: &'static str) {
    counter!("openshell_supervisor_config_peer_notifications_total", "outcome" => outcome)
        .increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::test_support::{
        StreamFeatures, SupervisorStreamHarness, connect_supervisor_stream,
        reconnect_supervisor_stream, test_server_state,
    };
    use openshell_core::proto::{
        GatewayMessage, ObjectMeta, Provider, SandboxSpec, gateway_message,
    };

    fn peer_request(
        scope: peer_notify_config_update_request::Scope,
    ) -> Request<PeerNotifyConfigUpdateRequest> {
        let mut request = Request::new(PeerNotifyConfigUpdateRequest { scope: Some(scope) });
        request
            .extensions_mut()
            .insert(Principal::Peer(crate::auth::principal::PeerPrincipal {
                replica_id: "other-replica".into(),
                pod_uid: "peer-pod".into(),
            }));
        request
    }

    fn peer_notify(sandbox_id: &str, session_id: &str) -> Request<PeerNotifyConfigUpdateRequest> {
        peer_request(peer_notify_config_update_request::Scope::Sandbox(
            PeerConfigSandboxTarget {
                sandbox_id: sandbox_id.into(),
                session_id: session_id.into(),
            },
        ))
    }

    async fn push_state() -> Arc<ServerState> {
        let mut state = test_server_state().await;
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .config_delivery_mode = ConfigDeliveryMode::Push;
        state
    }

    async fn put_sandbox(state: &ServerState, sandbox_id: &str, providers: &[&str]) {
        state
            .store
            .put_message(&Sandbox {
                metadata: Some(ObjectMeta {
                    id: sandbox_id.into(),
                    name: sandbox_id.into(),
                    workspace: "default".into(),
                    ..Default::default()
                }),
                spec: Some(SandboxSpec {
                    providers: providers.iter().map(ToString::to_string).collect(),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();
    }

    async fn put_provider(state: &ServerState, name: &str) {
        put_provider_with_token(state, name, None).await;
    }

    async fn put_provider_with_token(state: &ServerState, name: &str, token: Option<&str>) {
        state
            .store
            .put_message(&Provider {
                metadata: Some(ObjectMeta {
                    id: format!("{name}-id"),
                    name: name.into(),
                    workspace: "default".into(),
                    ..Default::default()
                }),
                r#type: "github".into(),
                credentials: token
                    .map(|token| HashMap::from([("GITHUB_TOKEN".to_string(), token.to_string())]))
                    .unwrap_or_default(),
                ..Default::default()
            })
            .await
            .unwrap();
    }

    /// Commit a new policy revision, so the next sandbox configuration build
    /// differs from the bootstrap the session acknowledged.
    async fn change_policy(state: &ServerState, sandbox_id: &str, version: i64) {
        use crate::policy_store::PolicyStoreExt as _;
        use prost::Message as _;

        let policy = openshell_core::proto::SandboxPolicy {
            version: 1,
            ..Default::default()
        };
        state
            .store
            .put_policy_revision(
                &uuid::Uuid::new_v4().to_string(),
                sandbox_id,
                "default",
                version,
                &policy.encode_to_vec(),
                &crate::grpc::policy::deterministic_policy_hash(&policy),
            )
            .await
            .unwrap();
    }

    /// Connect a streamed-apply supervisor and answer the bootstrap it is
    /// accepted with.
    async fn accepted_session(
        state: &Arc<ServerState>,
        sandbox_id: &str,
    ) -> (SupervisorStreamHarness, String) {
        let (harness, session_id, _) = accepted_session_with_bootstrap(state, sandbox_id).await;
        (harness, session_id)
    }

    async fn accepted_session_with_bootstrap(
        state: &Arc<ServerState>,
        sandbox_id: &str,
    ) -> (
        SupervisorStreamHarness,
        String,
        Option<openshell_core::proto::ConfigUpdate>,
    ) {
        let mut harness = connect_supervisor_stream(state, sandbox_id, StreamFeatures::Apply)
            .await
            .unwrap();
        let first = tokio::time::timeout(Duration::from_secs(5), harness.inbound.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let Some(gateway_message::Payload::SessionAccepted(accepted)) = first.payload else {
            panic!("expected SessionAccepted");
        };
        // Live updates wait for the bootstrap result, as from a real
        // supervisor.
        if let Some(bootstrap) = accepted.bootstrap.as_ref() {
            harness
                .outbound
                .send(openshell_core::proto::SupervisorMessage {
                    payload: Some(
                        openshell_core::proto::supervisor_message::Payload::ConfigUpdateResult(
                            session::applied_result(bootstrap),
                        ),
                    ),
                })
                .await
                .unwrap();
        }
        (harness, accepted.session_id, accepted.bootstrap)
    }

    async fn next_update(
        harness: &mut SupervisorStreamHarness,
        wait: Duration,
    ) -> Option<GatewayMessage> {
        tokio::time::timeout(wait, harness.inbound.message())
            .await
            .ok()
            .map(|message| message.unwrap().unwrap())
    }

    fn is_config_update(message: &GatewayMessage) -> bool {
        matches!(
            message.payload,
            Some(gateway_message::Payload::ConfigUpdate(_))
        )
    }

    #[test]
    fn peer_fanout_dials_other_live_replicas() {
        let member = |replica_id: &str, peer_endpoint: &str| GatewayMember {
            replica_id: replica_id.into(),
            peer_endpoint: peer_endpoint.into(),
        };
        let members = vec![
            member("gw-1", "http://gw-1"),
            member("gw-2", "http://gw-2"),
            member("gw-3", "local://unreachable"),
            member("gw-4", ""),
        ];
        assert_eq!(peer_endpoints(members, "gw-1"), vec!["http://gw-2"]);
    }

    #[tokio::test]
    async fn peer_notify_requires_push_and_current_session() {
        let state = test_server_state().await;
        let error = handle_peer_notify_config_update(&state, peer_notify("sandbox", "old-session"))
            .unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition);

        let state = push_state().await;
        let response =
            handle_peer_notify_config_update(&state, peer_notify("sandbox", "old-session"))
                .unwrap()
                .into_inner();
        assert!(response.stale_owner);

        let error = handle_peer_notify_config_update(
            &state,
            Request::new(PeerNotifyConfigUpdateRequest::default()),
        )
        .unwrap_err();
        assert_eq!(error.code(), Code::PermissionDenied);

        let error = handle_peer_notify_config_update(
            &state,
            peer_request(peer_notify_config_update_request::Scope::Provider(
                PeerConfigProviderTarget {
                    workspace: "default".into(),
                    name: String::new(),
                },
            )),
        )
        .unwrap_err();
        assert_eq!(error.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn peer_notify_rebuilds_snapshot_on_the_session_owner() {
        let state = push_state().await;
        put_sandbox(&state, "owned-sandbox", &[]).await;
        let (mut harness, session_id) = accepted_session(&state, "owned-sandbox").await;
        change_policy(&state, "owned-sandbox", 1).await;

        let response =
            handle_peer_notify_config_update(&state, peer_notify("owned-sandbox", &session_id))
                .unwrap()
                .into_inner();
        assert!(!response.stale_owner);
        let update = next_update(&mut harness, Duration::from_secs(5))
            .await
            .expect("configuration update");
        assert!(is_config_update(&update));
    }

    /// Store a policy revision that decodes but fails stored-policy
    /// validation: MCP options on a non-MCP endpoint.
    async fn store_invalid_policy(state: &ServerState, sandbox_id: &str, version: i64) {
        use crate::policy_store::PolicyStoreExt as _;
        use openshell_core::proto::{McpOptions, NetworkEndpoint, NetworkPolicyRule};
        use prost::Message as _;

        let mut policy = openshell_policy::restrictive_default_policy();
        policy.network_policies.insert(
            "mcp".to_string(),
            NetworkPolicyRule {
                name: "mcp".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "mcp.example.com".to_string(),
                    port: 443,
                    protocol: "rest".to_string(),
                    mcp: Some(McpOptions {
                        strict_tool_names: Some(true),
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        state
            .store
            .put_policy_revision(
                &uuid::Uuid::new_v4().to_string(),
                sandbox_id,
                "default",
                version,
                &policy.encode_to_vec(),
                "uncanonicalized-hash",
            )
            .await
            .unwrap();
    }

    fn delivered_sandbox_config(message: GatewayMessage) -> SandboxConfigSnapshot {
        let Some(gateway_message::Payload::ConfigUpdate(update)) = message.payload else {
            panic!("expected a configuration update");
        };
        update.sandbox_config.expect("sandbox configuration")
    }

    #[tokio::test]
    async fn invalid_configuration_bootstrap_is_delivered_and_repaired_on_the_same_stream() {
        use openshell_core::proto::{ConfigApplyOutcome, SupervisorMessage, supervisor_message};

        for mode in [
            openshell_core::PolicyValidationFailureMode::FailClosed,
            openshell_core::PolicyValidationFailureMode::RetainLastValid,
        ] {
            for reconnect in [false, true] {
                let mut state = push_state().await;
                Arc::get_mut(&mut state)
                    .unwrap()
                    .config
                    .policy_validation_failure_mode = mode;
                put_sandbox(&state, "sandbox", &[]).await;
                if reconnect {
                    change_policy(&state, "sandbox", 1).await;
                    let (_old, _) = accepted_session(&state, "sandbox").await;
                    tokio::time::timeout(Duration::from_secs(5), async {
                        loop {
                            let sandbox = state
                                .store
                                .get_message::<Sandbox>("sandbox")
                                .await
                                .unwrap()
                                .unwrap();
                            if sandbox.current_policy_version() == 1 {
                                break;
                            }
                            tokio::task::yield_now().await;
                        }
                    })
                    .await
                    .expect("initial policy acknowledgement is persisted");
                    state.supervisor_sessions.disconnect("sandbox");
                }
                let invalid_version = if reconnect { 2 } else { 1 };
                store_invalid_policy(&state, "sandbox", invalid_version).await;
                let connected = if reconnect {
                    reconnect_supervisor_stream(&state, "sandbox", StreamFeatures::Apply).await
                } else {
                    connect_supervisor_stream(&state, "sandbox", StreamFeatures::Apply).await
                };
                let mut harness = connected
                    .expect("invalid configuration must not prevent explicit bootstrap rejection");
                let message = next_update(&mut harness, Duration::from_secs(5))
                    .await
                    .expect("accepted session");
                let Some(gateway_message::Payload::SessionAccepted(accepted)) = message.payload
                else {
                    panic!("expected SessionAccepted");
                };
                let bootstrap = accepted.bootstrap.expect("rejected bootstrap");
                let snapshot = bootstrap.sandbox_config.as_ref().unwrap();
                assert!(!snapshot.configuration_admitted);
                assert_eq!(snapshot.policy_validation_failure_mode, mode.as_str());
                assert!(snapshot.policy.is_none());
                assert!(!snapshot.configuration_error.is_empty());
                assert_eq!(
                    bootstrap.provider_environment.as_ref().unwrap(),
                    &unresolved_provider_environment(snapshot)
                );
                let record = tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        let record = state
                            .config_delivery
                            .sessions()
                            .records
                            .get("sandbox")
                            .cloned();
                        if let Some(record) =
                            record.filter(|record| record.session_id == accepted.session_id)
                        {
                            break record;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("accepted session is registered for configuration delivery");
                assert!(record.provider_environment().is_none());
                let mut rejected = session::applied_result(&bootstrap);
                rejected.outcome = ConfigApplyOutcome::FailedClosed.into();
                rejected.policy_load = None;
                harness
                    .outbound
                    .send(SupervisorMessage {
                        payload: Some(supervisor_message::Payload::ConfigUpdateResult(rejected)),
                    })
                    .await
                    .unwrap();

                let repaired_version = invalid_version + 1;
                change_policy(&state, "sandbox", repaired_version).await;
                publish_sandbox(&state, "sandbox");
                let repaired = sent_config(
                    &next_update(&mut harness, Duration::from_secs(5))
                        .await
                        .expect("repaired live update"),
                );
                let snapshot = repaired.sandbox_config.as_ref().unwrap();
                assert!(snapshot.configuration_admitted);
                assert_eq!(i64::from(snapshot.version), repaired_version);
            }
        }
    }

    /// The delivery record registered for `session_id`, once registration
    /// completes.
    async fn registered_record(
        state: &ServerState,
        sandbox_id: &str,
        session_id: &str,
    ) -> Arc<SessionRecord> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let record = state
                    .config_delivery
                    .sessions()
                    .records
                    .get(sandbox_id)
                    .cloned();
                if let Some(record) = record.filter(|record| record.session_id == session_id) {
                    return record;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("accepted session is registered for configuration delivery")
    }

    #[tokio::test]
    async fn bootstrap_without_a_policy_seeds_the_provider_environment() {
        let state = push_state().await;
        put_sandbox(&state, "sandbox", &[]).await;
        let (_harness, session_id, bootstrap) =
            accepted_session_with_bootstrap(&state, "sandbox").await;
        let bootstrap = bootstrap.expect("push bootstrap");
        // A sandbox without a policy is not admitted, but nothing was
        // rejected and its provider environment resolved.
        assert!(!bootstrap.sandbox_config.unwrap().configuration_admitted);
        let record = registered_record(&state, "sandbox", &session_id).await;
        assert_eq!(
            record.provider_environment(),
            bootstrap.provider_environment
        );
    }

    #[tokio::test]
    async fn bootstrap_delivers_an_unresolved_provider_environment_and_rebuilds_it() {
        let state = push_state().await;
        put_driver_provider(
            &state,
            HashMap::from([(
                "GITHUB_TOKEN".to_string(),
                openshell_core::proto::CredentialHandle {
                    driver: "test-static".into(),
                    handle: "missing".into(),
                    metadata: HashMap::new(),
                },
            )]),
        )
        .await;
        put_sandbox(&state, "sandbox", &["provider"]).await;
        change_policy(&state, "sandbox", 1).await;

        // The supervisor revokes static credentials and rejects an update
        // whose provider environment is unresolved.
        let reject = |update: &openshell_core::proto::ConfigUpdate| {
            use openshell_core::proto::{
                ConfigApplyOutcome, ConfigurationAdmissionState, SupervisorMessage,
                supervisor_message,
            };
            let mut result = session::applied_result(update);
            result.outcome = ConfigApplyOutcome::FailedRetainedLastKnownGood.into();
            result.policy_load = None;
            if let Some(admission) = result.admission.as_mut() {
                admission.state = ConfigurationAdmissionState::Rejected.into();
            }
            SupervisorMessage {
                payload: Some(supervisor_message::Payload::ConfigUpdateResult(result)),
            }
        };

        // The credential does not resolve, but the session is still accepted
        // with the admitted policy and an unresolved environment.
        let mut harness = connect_supervisor_stream(&state, "sandbox", StreamFeatures::Apply)
            .await
            .expect("an unresolved provider environment does not refuse the session");
        let first = next_update(&mut harness, Duration::from_secs(5))
            .await
            .expect("accepted session");
        let Some(gateway_message::Payload::SessionAccepted(accepted)) = first.payload else {
            panic!("expected SessionAccepted");
        };
        let bootstrap = accepted.bootstrap.expect("push bootstrap");
        let sandbox_config = bootstrap
            .sandbox_config
            .clone()
            .expect("sandbox configuration");
        assert!(sandbox_config.configuration_admitted);
        assert_eq!(sandbox_config.version, 1);
        assert_eq!(
            bootstrap
                .provider_environment
                .clone()
                .expect("provider environment"),
            unresolved_provider_environment(&sandbox_config)
        );
        let record = registered_record(&state, "sandbox", &accepted.session_id).await;
        assert!(record.provider_environment().is_none());
        harness.outbound.send(reject(&bootstrap)).await.unwrap();

        // Once the credential resolves, the session delivers it without a
        // publication or waiting for its reconciliation interval.
        let credential_handles = state
            .credentials
            .store_provider_credentials(
                "provider",
                "default",
                "provider",
                &HashMap::from([("GITHUB_TOKEN".to_string(), "token".to_string())]),
                &HashMap::new(),
            )
            .await
            .unwrap();
        put_driver_provider(&state, credential_handles).await;
        let resolved = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let message = next_update(&mut harness, Duration::from_secs(10))
                    .await
                    .expect("rebuilt configuration");
                let update = sent_config(&message);
                if !update
                    .provider_environment
                    .as_ref()
                    .unwrap()
                    .values
                    .is_empty()
                {
                    break update;
                }
                // A rebuild that still could not resolve it is rejected too.
                harness.outbound.send(reject(&update)).await.unwrap();
            }
        })
        .await
        .expect("the session rebuilds the unresolved provider environment");
        assert_eq!(resolved.sandbox_config.unwrap().version, 1);
    }

    #[tokio::test]
    async fn invalid_stored_policy_is_delivered_not_admitted() {
        let state = push_state().await;
        put_sandbox(&state, "sandbox", &[]).await;
        let (mut harness, session_id) = accepted_session(&state, "sandbox").await;

        store_invalid_policy(&state, "sandbox", 1).await;
        handle_peer_notify_config_update(&state, peer_notify("sandbox", &session_id)).unwrap();
        let rejected = delivered_sandbox_config(
            next_update(&mut harness, Duration::from_secs(5))
                .await
                .expect("configuration update"),
        );
        assert!(!rejected.configuration_admitted);
        assert!(rejected.policy.is_none());
        assert!(!rejected.configuration_error.is_empty());
    }

    #[tokio::test]
    async fn provider_change_reaches_only_attached_sessions() {
        let state = push_state().await;
        put_provider(&state, "github").await;
        put_sandbox(&state, "attached", &["github"]).await;
        put_sandbox(&state, "unattached", &[]).await;
        let (mut attached, _) = accepted_session(&state, "attached").await;
        let (mut unattached, _) = accepted_session(&state, "unattached").await;
        put_provider_with_token(&state, "github", Some("rotated")).await;

        publish_provider(&state, "default", "github");

        let update = next_update(&mut attached, Duration::from_secs(5))
            .await
            .expect("attached sandbox receives its configuration");
        assert!(is_config_update(&update));
        assert!(
            next_update(&mut unattached, Duration::from_millis(200))
                .await
                .is_none()
        );

        change_policy(&state, "unattached", 1).await;
        publish_workspace(&state, "default");
        assert!(
            next_update(&mut unattached, Duration::from_secs(5))
                .await
                .is_some_and(|update| is_config_update(&update))
        );
    }

    fn has_recipient(state: &ServerState, sandbox_id: &str) -> bool {
        state.config_delivery.has_session(sandbox_id)
    }

    #[tokio::test]
    async fn poll_mode_leaves_delivery_dormant() {
        let state = test_server_state().await;
        put_provider(&state, "github").await;
        put_sandbox(&state, "sandbox", &["github"]).await;
        let (mut harness, _) = accepted_session(&state, "sandbox").await;
        assert!(!has_recipient(&state, "sandbox"));

        publish_sandbox(&state, "sandbox");
        publish_workspace(&state, "default");
        publish_provider(&state, "default", "github");
        publish_all_connected(&state);
        publish_all_local(&state);

        assert_eq!(state.config_delivery.publications(), 0);
        assert!(
            next_update(&mut harness, Duration::from_millis(100))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn disconnected_sessions_leave_the_queue() {
        let state = push_state().await;
        put_sandbox(&state, "sandbox", &[]).await;
        let (_harness, _) = accepted_session(&state, "sandbox").await;
        assert!(has_recipient(&state, "sandbox"));

        assert!(state.supervisor_sessions.disconnect("sandbox"));
        tokio::time::timeout(Duration::from_secs(5), async {
            while has_recipient(&state, "sandbox") {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("session cleanup unregisters the recipient");
    }

    #[tokio::test]
    async fn peer_notifications_for_one_target_coalesce() {
        let state = push_state().await;
        let target = PeerNotifyTarget::Sandbox("remote".into());
        notify_peer(&state, target.clone());
        notify_peer(&state, target.clone());
        {
            let pending = state.config_delivery.peer_notifies.lock().unwrap();
            assert_eq!(pending.len(), 1);
            assert!(pending[&target]);
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while !state
                .config_delivery
                .peer_notifies
                .lock()
                .unwrap()
                .is_empty()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the notification task drains its target");
    }

    #[tokio::test]
    async fn sandbox_configuration_names_its_built_and_unresolved_provider_environment() {
        let state = push_state().await;
        put_provider_with_token(&state, "provider", Some("token")).await;
        put_sandbox(&state, "sandbox", &["provider"]).await;
        let sandbox = state
            .store
            .get_message::<Sandbox>("sandbox")
            .await
            .unwrap()
            .unwrap();
        let inputs = load_sandbox_config_inputs(&state, sandbox).await.unwrap();
        let sandbox_config = build_sandbox_config_snapshot_from_inputs(&state, &inputs)
            .await
            .unwrap();
        let built = build_provider_environment_snapshot_from_inputs(&state, &inputs, true, true)
            .await
            .unwrap();
        assert!(!built.values.is_empty());
        // The supervisor matches both to the sandbox configuration that names
        // them, and to the one it holds.
        assert!(names_provider_environment(&sandbox_config, &built));

        let unresolved = unresolved_provider_environment(&sandbox_config);
        assert!(names_provider_environment(&sandbox_config, &unresolved));
        assert!(unresolved.values.is_empty());
        assert!(unresolved.dynamic_credentials.is_empty());
        assert!(unresolved.files.is_empty());
        assert_eq!(
            unresolved.readiness_reason,
            i32::from(ProviderReadinessReason::CredentialInstallFailed)
        );
    }

    #[tokio::test]
    async fn registration_delivers_a_publication_that_found_no_session() {
        let state = push_state().await;
        put_sandbox(&state, "sandbox", &[]).await;
        let sandbox = state
            .store
            .get_message::<Sandbox>("sandbox")
            .await
            .unwrap()
            .unwrap();
        let captured_seq = state.config_delivery.publications();
        // The change commits after the session read its bootstrap, and its
        // publication runs before the session registers.
        change_policy(&state, "sandbox", 1).await;
        assert!(!state.config_delivery.publish_sandbox("sandbox"));

        let mut session =
            register_test_apply_session_after(&state, &sandbox, "session-1", captured_seq);
        // Reconciliation is at least 30 seconds away, so only registration
        // can have caught the publication.
        let update = tokio::time::timeout(Duration::from_secs(5), session.outbound.recv())
            .await
            .expect("registration delivers the missed publication")
            .expect("outbound message");
        assert!(is_config_update(&update));
    }

    #[test]
    fn fanout_marks_ten_thousand_sessions_once_each() {
        let delivery = ConfigDelivery::for_db_connections(5);
        let records: Vec<_> = (0..10_000)
            .map(|index| {
                Arc::new(SessionRecord::new(Registration {
                    sandbox_id: format!("sb-{index:05}"),
                    session_id: "session".into(),
                    workspace: "ws".into(),
                    providers: HashSet::new(),
                    provider_environment: None,
                    captured_seq: 0,
                    rebuild: false,
                }))
            })
            .collect();
        delivery.sessions().records.extend(
            records
                .iter()
                .map(|record| (record.sandbox_id.clone(), Arc::clone(record))),
        );
        for _ in 0..3 {
            delivery.publish_fanout(&FanoutScope::AllConnected);
        }
        assert_eq!(delivery.publications(), 3);
        assert!(
            records
                .iter()
                .all(|record| record.in_scope(&FanoutScope::AllConnected))
        );
    }

    #[test]
    fn build_slots_are_sized_from_the_database_pool() {
        let builds = |connections| {
            ConfigDelivery::for_db_connections(connections)
                .builds
                .available_permits()
        };
        assert_eq!(builds(10), 20);
        assert_eq!(builds(1), MIN_CONCURRENT_SNAPSHOT_BUILDS);
    }

    #[test]
    fn configuration_message_debug_output_redacts_payloads() {
        let message = SupervisorConfig {
            sandbox_config: SandboxConfigSnapshot::default(),
            provider_environment: ProviderEnvironmentSnapshot {
                values: vec![openshell_core::proto::ProviderEnvironmentValue {
                    name: "TOKEN".into(),
                    value: "secret-marker".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        };
        assert!(!format!("{message:?}").contains("secret-marker"));
    }

    #[tokio::test]
    async fn session_acceptance_precedes_live_configuration_updates() {
        let state = push_state().await;
        put_sandbox(&state, "sandbox", &[]).await;
        let (mut harness, _) = accepted_session(&state, "sandbox").await;
        assert!(has_recipient(&state, "sandbox"));
        change_policy(&state, "sandbox", 1).await;

        publish_sandbox(&state, "sandbox");
        let update = next_update(&mut harness, Duration::from_secs(5))
            .await
            .expect("configuration update");
        assert!(is_config_update(&update));
    }

    #[tokio::test]
    async fn local_publication_reaches_this_replicas_sessions_without_peers() {
        let state = push_state().await;
        put_sandbox(&state, "sandbox", &[]).await;
        let (mut harness, _) = accepted_session(&state, "sandbox").await;
        change_policy(&state, "sandbox", 1).await;

        publish_all_local(&state);

        let update = next_update(&mut harness, Duration::from_secs(5))
            .await
            .expect("configuration update");
        assert!(is_config_update(&update));
        assert!(
            state
                .config_delivery
                .peer_notifies
                .lock()
                .unwrap()
                .is_empty(),
            "a local publication notifies no peers"
        );
    }

    #[tokio::test]
    async fn legacy_supervisor_keeps_polling_when_gateway_push_is_enabled() {
        for features in [
            StreamFeatures::Legacy,
            StreamFeatures::ApplyWithoutPlacement,
        ] {
            let state = push_state().await;
            put_provider(&state, "github").await;
            put_sandbox(&state, "legacy-sandbox", &["github"]).await;
            let mut harness = connect_supervisor_stream(&state, "legacy-sandbox", features)
                .await
                .unwrap();
            let first = harness.inbound.message().await.unwrap().unwrap();
            let Some(gateway_message::Payload::SessionAccepted(accepted)) = first.payload else {
                panic!("expected SessionAccepted");
            };
            assert!(!accepted.config_push_enabled);
            assert!(accepted.bootstrap.is_none());
            assert!(!has_recipient(&state, "legacy-sandbox"));
            // Rotating protected material must not deliver it later on this stream.
            put_provider_with_token(&state, "github", Some("synthetic-rotated")).await;
            publish_provider(&state, "default", "github");
            publish_sandbox(&state, "legacy-sandbox");
            publish_all_connected(&state);
            assert!(
                next_update(&mut harness, Duration::from_millis(100))
                    .await
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn stalled_credentials_keep_the_live_session_serving_relays() {
        let state = push_state().await;
        let credential_handles = state
            .credentials
            .store_provider_credentials(
                "provider",
                "default",
                "provider",
                &HashMap::from([("GITHUB_TOKEN".to_string(), "token".to_string())]),
                &HashMap::new(),
            )
            .await
            .unwrap();
        state
            .store
            .put_message(&Provider {
                metadata: Some(ObjectMeta {
                    id: "provider".into(),
                    name: "provider".into(),
                    workspace: "default".into(),
                    ..Default::default()
                }),
                r#type: "github".into(),
                credential_handles,
                ..Default::default()
            })
            .await
            .unwrap();
        state
            .store
            .put_message(&Sandbox {
                metadata: Some(ObjectMeta {
                    id: "sandbox".into(),
                    name: "sandbox".into(),
                    workspace: "default".into(),
                    ..Default::default()
                }),
                spec: Some(SandboxSpec {
                    providers: vec!["provider".into()],
                    policy: Some(openshell_policy::restrictive_default_policy()),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();
        let mut live = connect_supervisor_stream(&state, "sandbox", StreamFeatures::Apply)
            .await
            .unwrap();
        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            next_update(&mut live, Duration::from_secs(5))
                .await
                .expect("session acceptance")
                .payload
        else {
            panic!("expected SessionAccepted");
        };
        let live_session = accepted.session_id;

        let (resolve_hit, release_resolve) = state.credentials.gate_next_resolve();
        let reconnect = tokio::spawn({
            let state = Arc::clone(&state);
            async move { reconnect_supervisor_stream(&state, "sandbox", StreamFeatures::Apply).await }
        });
        tokio::time::timeout(Duration::from_secs(5), resolve_hit)
            .await
            .expect("reconnect bootstrap must reach the stalled credential driver")
            .unwrap();

        // The bootstrap is built before the reconnect is registered, so the
        // live session keeps serving relays while credentials are stalled.
        assert!(
            state
                .supervisor_sessions
                .is_current_session("sandbox", &live_session)
        );
        let (_, relay) = state
            .supervisor_sessions
            .open_relay("sandbox", Duration::from_secs(1))
            .await
            .unwrap();
        assert!(matches!(
            next_update(&mut live, Duration::from_secs(5))
                .await
                .expect("relay open")
                .payload,
            Some(gateway_message::Payload::RelayOpen(_))
        ));
        drop(relay);

        release_resolve.send(()).unwrap();
        let mut replacement = tokio::time::timeout(Duration::from_secs(5), reconnect)
            .await
            .expect("released bootstrap completes the reconnect")
            .unwrap()
            .unwrap();
        let Some(gateway_message::Payload::SessionAccepted(accepted)) =
            next_update(&mut replacement, Duration::from_secs(5))
                .await
                .expect("replacement acceptance")
                .payload
        else {
            panic!("expected SessionAccepted");
        };
        assert!(accepted.bootstrap.is_some());
        assert!(
            state
                .supervisor_sessions
                .is_current_session("sandbox", &accepted.session_id)
        );
    }

    async fn put_driver_provider(
        state: &ServerState,
        credential_handles: HashMap<String, openshell_core::proto::CredentialHandle>,
    ) {
        state
            .store
            .put_message(&Provider {
                metadata: Some(ObjectMeta {
                    id: "provider".into(),
                    name: "provider".into(),
                    workspace: "default".into(),
                    ..Default::default()
                }),
                r#type: "github".into(),
                credential_handles,
                ..Default::default()
            })
            .await
            .unwrap();
    }

    /// Attach a provider whose credential resolves through the credential
    /// driver, and accept a session for its sandbox. The session's record
    /// holds the provider environment its bootstrap delivered.
    async fn driver_backed_session(
        state: &Arc<ServerState>,
    ) -> (SupervisorStreamHarness, SessionRecord) {
        let credential_handles = state
            .credentials
            .store_provider_credentials(
                "provider",
                "default",
                "provider",
                &HashMap::from([("GITHUB_TOKEN".to_string(), "token".to_string())]),
                &HashMap::new(),
            )
            .await
            .unwrap();
        put_driver_provider(state, credential_handles).await;
        put_sandbox(state, "sandbox", &["provider"]).await;
        let (harness, session_id, bootstrap) =
            accepted_session_with_bootstrap(state, "sandbox").await;
        let record = SessionRecord::new(Registration {
            sandbox_id: "sandbox".into(),
            session_id,
            workspace: "default".into(),
            providers: HashSet::from(["provider".to_string()]),
            provider_environment: bootstrap.and_then(|bootstrap| bootstrap.provider_environment),
            captured_seq: 0,
            rebuild: false,
        });
        (harness, record)
    }

    fn sent_config(message: &GatewayMessage) -> openshell_core::proto::ConfigUpdate {
        let Some(gateway_message::Payload::ConfigUpdate(update)) = &message.payload else {
            panic!("expected a configuration update");
        };
        update.clone()
    }

    #[tokio::test]
    async fn provider_failure_delivers_the_configuration_with_an_unresolved_environment() {
        let state = push_state().await;
        let (mut harness, record) = driver_backed_session(&state).await;
        // The provider's credential no longer resolves, and a new policy
        // revision changes the provider environment the configuration names.
        put_driver_provider(
            &state,
            HashMap::from([(
                "GITHUB_TOKEN".to_string(),
                openshell_core::proto::CredentialHandle {
                    driver: "test-static".into(),
                    handle: "missing".into(),
                    metadata: HashMap::new(),
                },
            )]),
        )
        .await;
        change_policy(&state, "sandbox", 1).await;

        let (failed, providers) = Builder(&state).deliver(&record).await;
        assert!(failed, "the session retries the build");
        assert_eq!(providers, Some(HashSet::from(["provider".to_string()])));
        let update = sent_config(
            &next_update(&mut harness, Duration::from_secs(5))
                .await
                .expect("configuration update"),
        );
        let sandbox_config = update.sandbox_config.expect("sandbox configuration");
        let provider = update.provider_environment.expect("provider environment");
        assert!(names_provider_environment(&sandbox_config, &provider));
        assert!(provider.values.is_empty());
        assert_eq!(
            provider.readiness_reason,
            i32::from(ProviderReadinessReason::CredentialInstallFailed)
        );
    }

    #[tokio::test]
    async fn unchanged_provider_environment_resolves_no_credentials() {
        let state = push_state().await;
        let (mut harness, record) = driver_backed_session(&state).await;
        let (mut resolve_hit, _release_resolve) = state.credentials.gate_next_resolve();

        let (failed, _) =
            tokio::time::timeout(Duration::from_secs(5), Builder(&state).deliver(&record))
                .await
                .expect("an unchanged provider environment must not wait on credentials");
        assert!(!failed);
        assert_eq!(
            resolve_hit.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        );
        assert!(
            next_update(&mut harness, Duration::from_millis(200))
                .await
                .is_none(),
            "the supervisor already has this configuration"
        );
    }

    #[tokio::test]
    async fn changed_provider_environment_is_resolved_and_cached() {
        let state = push_state().await;
        let (mut harness, record) = driver_backed_session(&state).await;
        change_policy(&state, "sandbox", 1).await;

        let (failed, _) = Builder(&state).deliver(&record).await;
        assert!(!failed);
        let update = sent_config(
            &next_update(&mut harness, Duration::from_secs(5))
                .await
                .expect("configuration update"),
        );
        let provider = update.provider_environment.expect("provider environment");
        assert!(!provider.values.is_empty());
        assert_eq!(record.provider_environment(), Some(provider));
    }

    async fn state_with_large_provider_environment(provider_count: usize) -> Arc<ServerState> {
        use crate::grpc::test_support::authed_request;
        use openshell_core::proto::CreateProviderRequest;
        use openshell_core::proto::open_shell_server::OpenShell as _;

        let mut state = push_state().await;
        let profiles = (0..provider_count)
            .map(|index| {
                let mut profile = openshell_providers::example_profiles::load("github").to_proto();
                profile.id = format!("large-provider-{index}");
                profile.credentials[0].env_vars = (0..32)
                    .map(|key| format!("PROVIDER_{index}_TOKEN_{key}"))
                    .collect();
                profile
            })
            .collect();
        Arc::get_mut(&mut state).unwrap().provider_profile_sources =
            crate::provider_profile_sources::ProviderProfileSources::from_test_profiles(profiles);
        let service = crate::grpc::OpenShellService::new(Arc::clone(&state));
        let mut providers = Vec::new();
        for index in 0..provider_count {
            let name = format!("large-provider-{index}");
            service
                .create_provider(authed_request(CreateProviderRequest {
                    workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                    provider: Some(Provider {
                        metadata: Some(ObjectMeta {
                            name: name.clone(),
                            ..Default::default()
                        }),
                        r#type: name.clone(),
                        credentials: (0..32)
                            .map(|key| (format!("PROVIDER_{index}_TOKEN_{key}"), "x".repeat(8192)))
                            .collect(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }))
                .await
                .expect("provider credentials within public limits are accepted");
            providers.push(name);
        }
        let provider_names = providers.iter().map(String::as_str).collect::<Vec<_>>();
        put_sandbox(&state, "large-config", &provider_names).await;
        change_policy(&state, "large-config", 1).await;

        state
    }

    #[tokio::test]
    async fn oversized_configuration_is_rejected_over_grpc_and_smaller_configuration_recovers() {
        use openshell_core::proto::{
            ConfigApplyOutcome, ConfigUpdate, ConfigUpdateResult, ConfigurationAdmissionState,
            SandboxConfigurationAdmission, SupervisorMessage, supervisor_message,
        };
        use prost::Message as _;

        let state = state_with_large_provider_environment(32).await;
        let mut harness = connect_supervisor_stream(&state, "large-config", StreamFeatures::Apply)
            .await
            .unwrap();
        let first = harness.inbound.message().await.unwrap().unwrap();
        assert!(first.encoded_len() < 1024);
        let Some(gateway_message::Payload::SessionAccepted(accepted)) = first.payload else {
            panic!("expected accepted session with explicit rejection");
        };
        let bootstrap = accepted.bootstrap.unwrap();
        let report_rejection = |update: &ConfigUpdate| {
            let snapshot = update.sandbox_config.as_ref().unwrap();
            assert!(!snapshot.configuration_admitted);
            assert!(
                snapshot
                    .configuration_error
                    .starts_with("configuration_too_large:")
            );
            assert!(snapshot.policy.is_none());
            let provider = update.provider_environment.as_ref().unwrap();
            assert!(provider.values.is_empty());
            assert!(provider.dynamic_credentials.is_empty());
            assert!(provider.files.is_empty());
            SupervisorMessage {
                payload: Some(supervisor_message::Payload::ConfigUpdateResult(
                    ConfigUpdateResult {
                        update_id: update.update_id.clone(),
                        outcome: ConfigApplyOutcome::FailedClosed.into(),
                        admission: Some(SandboxConfigurationAdmission {
                            instance_id: snapshot.configuration_instance_id.clone(),
                            state: ConfigurationAdmissionState::Rejected.into(),
                            policy_version: snapshot.version,
                            policy_hash: snapshot.policy_hash.clone(),
                            config_revision: snapshot.config_revision,
                            provider_env_revision: snapshot.provider_env_revision,
                            error: snapshot.configuration_error.clone(),
                        }),
                        ..Default::default()
                    },
                )),
            }
        };
        harness
            .outbound
            .send(report_rejection(&bootstrap))
            .await
            .unwrap();
        let expected = bootstrap.sandbox_config.as_ref().unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let stored = state
                    .store
                    .get_message::<Sandbox>("large-config")
                    .await
                    .unwrap()
                    .unwrap();
                if let Some(admission) = stored
                    .status
                    .and_then(|status| status.configuration_admission)
                    && admission.state == i32::from(ConfigurationAdmissionState::Rejected)
                {
                    assert_eq!(admission.config_revision, expected.config_revision);
                    assert_eq!(
                        admission.provider_env_revision,
                        expected.provider_env_revision
                    );
                    assert_eq!(admission.error, expected.configuration_error);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("gateway persists explicit bootstrap rejection");

        change_policy(&state, "large-config", 2).await;
        publish_sandbox(&state, "large-config");
        let live = sent_config(
            &next_update(&mut harness, Duration::from_secs(5))
                .await
                .expect("oversized live update produces explicit rejection"),
        );
        assert_eq!(live.sandbox_config.as_ref().unwrap().version, 2);
        harness
            .outbound
            .send(report_rejection(&live))
            .await
            .unwrap();

        let mut sandbox = state
            .store
            .get_message::<Sandbox>("large-config")
            .await
            .unwrap()
            .unwrap();
        sandbox.spec.as_mut().unwrap().providers.truncate(16);
        state.store.put_message(&sandbox).await.unwrap();
        change_policy(&state, "large-config", 3).await;
        publish_sandbox(&state, "large-config");
        let recovery = sent_config(
            &next_update(&mut harness, Duration::from_secs(5))
                .await
                .expect("smaller update recovers on the same stream"),
        );
        let snapshot = recovery.sandbox_config.as_ref().unwrap();
        assert!(snapshot.configuration_admitted);
        assert_eq!(snapshot.version, 3);
        assert_eq!(
            recovery.provider_environment.as_ref().unwrap().values.len(),
            16 * 32
        );
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::ConfigUpdateResult(
                    session::applied_result(&recovery),
                )),
            })
            .await
            .unwrap();
    }
}
