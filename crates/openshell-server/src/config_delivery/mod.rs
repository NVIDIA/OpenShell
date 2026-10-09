// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Build and deliver complete supervisor configuration snapshots.

pub mod session;
mod session_slots;
mod task;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use futures::StreamExt;
use metrics::{counter, histogram};
use openshell_core::config::ConfigDeliveryMode;
use openshell_core::proto::{
    ConfigComponent, PeerConfigProviderTarget, PeerConfigSandboxTarget,
    PeerNotifyConfigUpdateRequest, PeerNotifyConfigUpdateResponse, ProviderEnvironmentSnapshot,
    Sandbox, SandboxConfigSnapshot, peer_notify_config_update_request,
};
use tokio::sync::Semaphore;
use tonic::{Code, Request, Response, Status};
use tracing::warn;

use crate::ServerState;
use crate::auth::principal::Principal;
use crate::grpc::policy::{
    SandboxConfigInputs, build_provider_environment_snapshot_from_inputs,
    build_sandbox_config_snapshot_from_inputs, load_sandbox_config_inputs,
};
use crate::supervisor_owner::{OWNER_TTL, SupervisorOwnerIndex};

pub use session_slots::{ConfigSlots, SessionOutbound};
pub use task::Registration;
use task::{Deliver, FanoutScope, Lane, Permits, SessionRecord, Work};

/// Leaves headroom below tonic's default 4 MiB decode limit for framing and
/// future envelope fields.
pub const MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES: usize = 3 * 1024 * 1024;
/// Sandbox configuration builds only read the store, which answers in
/// milliseconds when healthy; anything slower means the store is in trouble.
const SANDBOX_CONFIG_BUILD_TIMEOUT: Duration = Duration::from_secs(5);
/// Provider environment builds also resolve credentials. Covers a cold Vault
/// Kubernetes-auth login plus a read at the default 10-second request timeout.
const PROVIDER_ENVIRONMENT_BUILD_TIMEOUT: Duration = Duration::from_secs(20);
/// Concurrent snapshot builds allowed per pooled database connection. Builds
/// are short bursts of small queries, so a little oversubscription keeps the
/// pool busy without stacking every waiter on the acquire timeout.
const SNAPSHOT_BUILDS_PER_DB_CONNECTION: usize = 2;
const MIN_CONCURRENT_SNAPSHOT_BUILDS: usize = 4;
const MAX_CONCURRENT_PEER_NOTIFIES: usize = 8;
const PEER_NOTIFY_TIMEOUT: Duration = Duration::from_secs(5);
const PEER_FANOUT_CONCURRENCY: usize = 8;

/// One complete configuration component awaiting delivery to a supervisor.
#[derive(Clone)]
pub enum SupervisorConfigMessage {
    SandboxConfig(Box<SandboxConfigSnapshot>),
    ProviderEnvironment(ProviderEnvironmentSnapshot),
}

impl SupervisorConfigMessage {
    pub(crate) fn component(&self) -> ConfigComponentKind {
        match self {
            Self::SandboxConfig(_) => ConfigComponentKind::SandboxConfig,
            Self::ProviderEnvironment(_) => ConfigComponentKind::ProviderEnvironment,
        }
    }
}

impl fmt::Debug for SupervisorConfigMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SandboxConfig(_) => "SandboxConfig(<redacted>)",
            Self::ProviderEnvironment(_) => "ProviderEnvironment(<redacted>)",
        })
    }
}

/// Result of handing one configuration snapshot to a supervisor session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryDisposition {
    Queued,
    /// Replaced an older snapshot the session had not sent yet.
    Replaced,
    /// Held until the supervisor acknowledges the previous update.
    Coalesced,
    /// Matches the snapshot the supervisor last acknowledged.
    SuppressedUnchanged,
    NoActiveSession,
    UnsupportedSession,
    PayloadTooLarge,
}

impl DeliveryDisposition {
    fn metric_label(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Replaced => "replaced",
            Self::Coalesced => "coalesced",
            Self::SuppressedUnchanged => "unchanged",
            Self::NoActiveSession => "no_active_session",
            Self::UnsupportedSession => "unsupported_session",
            Self::PayloadTooLarge => "payload_too_large",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConfigComponents {
    pub sandbox_config: bool,
    pub provider_environment: bool,
}

impl ConfigComponents {
    pub const ALL: Self = Self {
        sandbox_config: true,
        provider_environment: true,
    };

    pub const SANDBOX_CONFIG: Self = Self {
        sandbox_config: true,
        provider_environment: false,
    };

    pub(crate) fn only(component: ConfigComponentKind) -> Self {
        Self {
            sandbox_config: component == ConfigComponentKind::SandboxConfig,
            provider_environment: component == ConfigComponentKind::ProviderEnvironment,
        }
    }

    fn union(self, other: Self) -> Self {
        Self {
            sandbox_config: self.sandbox_config || other.sandbox_config,
            provider_environment: self.provider_environment || other.provider_environment,
        }
    }

    fn is_empty(self) -> bool {
        !self.sandbox_config && !self.provider_environment
    }

    fn selected(self) -> impl Iterator<Item = ConfigComponentKind> {
        [
            (self.sandbox_config, ConfigComponentKind::SandboxConfig),
            (
                self.provider_environment,
                ConfigComponentKind::ProviderEnvironment,
            ),
        ]
        .into_iter()
        .filter_map(|(selected, component)| selected.then_some(component))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigComponentKind {
    SandboxConfig,
    ProviderEnvironment,
}

impl ConfigComponentKind {
    /// The delivered component named by a wire value, if it is one.
    pub(crate) fn from_proto(component: i32) -> Option<Self> {
        match ConfigComponent::try_from(component).ok()? {
            ConfigComponent::SandboxConfig => Some(Self::SandboxConfig),
            ConfigComponent::ProviderEnvironment => Some(Self::ProviderEnvironment),
            ConfigComponent::Unspecified => None,
        }
    }

    /// The other half of a configuration generation.
    pub(crate) fn counterpart(self) -> Self {
        match self {
            Self::SandboxConfig => Self::ProviderEnvironment,
            Self::ProviderEnvironment => Self::SandboxConfig,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::SandboxConfig => "sandbox_config",
            Self::ProviderEnvironment => "provider_environment",
        }
    }
}

impl From<ConfigComponentKind> for ConfigComponent {
    fn from(component: ConfigComponentKind) -> Self {
        match component {
            ConfigComponentKind::SandboxConfig => Self::SandboxConfig,
            ConfigComponentKind::ProviderEnvironment => Self::ProviderEnvironment,
        }
    }
}

/// Per-session delivery tasks for this replica's push sessions, plus
/// coalesced notifications to peer replicas.
#[derive(Debug)]
pub struct ConfigDelivery {
    sessions: Mutex<HashMap<String, Arc<SessionRecord>>>,
    permits: Permits,
    /// Counts publications, so a registering session can tell whether one
    /// raced its bootstrap.
    publications: AtomicU64,
    peer_notifies: Mutex<HashMap<PeerNotifyTarget, ConfigComponents>>,
    peer_notify_permits: Arc<Semaphore>,
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
            sessions: Mutex::new(HashMap::new()),
            permits: Permits::new(builds),
            publications: AtomicU64::new(0),
            peer_notifies: Mutex::new(HashMap::new()),
            peer_notify_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_PEER_NOTIFIES)),
        }
    }

    pub(crate) fn publications(&self) -> u64 {
        self.publications.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    fn has_session(&self, sandbox_id: &str) -> bool {
        self.sessions().contains_key(sandbox_id)
    }

    /// Delivery is best effort beside the session lifecycle, so a poisoned
    /// lock must not turn session teardown into a panic.
    fn sessions(&self) -> MutexGuard<'_, HashMap<String, Arc<SessionRecord>>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns false when this gateway has no push session for the sandbox.
    fn publish_sandbox(&self, sandbox_id: &str, components: ConfigComponents) -> bool {
        self.publications.fetch_add(1, Ordering::SeqCst);
        let Some(record) = self.sessions().get(sandbox_id).cloned() else {
            return false;
        };
        record.mark(components, Lane::Sandbox);
        true
    }

    fn publish_fanout(&self, scope: &FanoutScope, components: ConfigComponents) {
        self.publications.fetch_add(1, Ordering::SeqCst);
        for record in self.sessions().values() {
            if record.in_scope(scope) {
                record.mark(components, Lane::Fanout);
            }
        }
    }
}

pub fn push_enabled(state: &ServerState) -> bool {
    state.config.config_delivery_mode == ConfigDeliveryMode::Push
}

pub fn publish_sandbox_components(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    components: ConfigComponents,
) {
    if !push_enabled(state) {
        return;
    }
    // A single-replica gateway owns every session, and registration covers a
    // session that is still connecting.
    if !state
        .config_delivery
        .publish_sandbox(sandbox_id, components)
        && !state.store.is_single_replica()
    {
        notify_peer(
            state,
            PeerNotifyTarget::Sandbox(sandbox_id.to_string()),
            components,
        );
    }
}

pub fn publish_workspace_components(
    state: &Arc<ServerState>,
    workspace: &str,
    components: ConfigComponents,
) {
    publish_fanout(
        state,
        &FanoutScope::Workspace(workspace.to_string()),
        components,
    );
}

/// Publish a provider change to the sandboxes that attach that provider.
pub fn publish_provider_components(
    state: &Arc<ServerState>,
    workspace: &str,
    provider_name: &str,
    components: ConfigComponents,
) {
    publish_fanout(
        state,
        &FanoutScope::Provider {
            workspace: workspace.to_string(),
            name: provider_name.to_string(),
        },
        components,
    );
}

pub fn publish_all_connected(state: &Arc<ServerState>, components: ConfigComponents) {
    publish_fanout(state, &FanoutScope::AllConnected, components);
}

fn publish_fanout(state: &Arc<ServerState>, scope: &FanoutScope, components: ConfigComponents) {
    if !push_enabled(state) {
        return;
    }
    state.config_delivery.publish_fanout(scope, components);
    if !state.store.is_single_replica() {
        notify_peer(state, PeerNotifyTarget::Peers(scope.clone()), components);
    }
}

/// Make a streamed-apply session visible to publications and start its
/// delivery task.
pub fn register_session(state: &Arc<ServerState>, registration: Registration) {
    let delivery = &state.config_delivery;
    let raced = delivery.publications() > registration.captured_seq;
    let record = Arc::new(SessionRecord::new(registration));
    {
        let mut sessions = delivery.sessions();
        // A concurrent reconnect may already own the registry entry. Checking
        // under the sessions lock keeps the newest session registered.
        if !state
            .supervisor_sessions
            .is_current_session(&record.sandbox_id, &record.session_id)
        {
            return;
        }
        if let Some(previous) = sessions.insert(record.sandbox_id.clone(), Arc::clone(&record)) {
            previous.close();
        }
    }
    // A publication between the bootstrap read and registration may have
    // missed this session.
    if raced {
        record.mark(ConfigComponents::ALL, Lane::Sandbox);
    }
    let state = Arc::clone(state);
    tokio::spawn(async move {
        task::run(
            record,
            &state.config_delivery.permits,
            &Builder(&state),
            task::RECONCILE_INTERVAL,
        )
        .await;
    });
}

pub fn unregister_session(state: &ServerState, sandbox_id: &str, session_id: &str) {
    let mut sessions = state.config_delivery.sessions();
    if sessions
        .get(sandbox_id)
        .is_some_and(|record| record.session_id == session_id)
        && let Some(record) = sessions.remove(sandbox_id)
    {
        record.close();
    }
}

/// Builds and delivers a session's components.
struct Builder<'a>(&'a Arc<ServerState>);

impl Deliver for Builder<'_> {
    async fn deliver(
        &self,
        record: &SessionRecord,
        work: Work,
    ) -> (ConfigComponents, Option<HashSet<String>>) {
        let state = self.0;
        let sandbox_id = record.sandbox_id.as_str();
        // Selected components share one input load. The load counts against
        // each component's own deadline, and each component still builds,
        // delivers, and fails on its own.
        let load_timeout = work
            .components
            .selected()
            .map(build_timeout)
            .max()
            .unwrap_or(SANDBOX_CONFIG_BUILD_TIMEOUT);
        let started = Instant::now();
        let loaded = tokio::time::timeout(load_timeout, load_build_inputs(state, sandbox_id)).await;
        let load_elapsed = started.elapsed();
        let inputs = match loaded {
            Ok(Ok(Some(inputs))) => inputs,
            Ok(Ok(None)) => {
                for component in work.components.selected() {
                    record_build(component, work.lane, "ok", load_elapsed);
                }
                return (ConfigComponents::default(), None);
            }
            Ok(Err(error)) => {
                for component in work.components.selected() {
                    record_build_failure(
                        sandbox_id,
                        component,
                        work.lane,
                        "failed",
                        error.code(),
                        load_elapsed,
                    );
                }
                return (work.components, None);
            }
            Err(_) => {
                for component in work.components.selected() {
                    record_build_failure(
                        sandbox_id,
                        component,
                        work.lane,
                        "timeout",
                        Code::DeadlineExceeded,
                        load_elapsed,
                    );
                }
                return (work.components, None);
            }
        };
        let mut failed = ConfigComponents::default();
        for component in work.components.selected() {
            match run_build(state, record, component, work.lane, &inputs, load_elapsed).await {
                BuildResult::Built { owner_moved } => {
                    if owner_moved {
                        notify_peer(
                            state,
                            PeerNotifyTarget::Sandbox(record.sandbox_id.clone()),
                            ConfigComponents::only(component),
                        );
                    }
                }
                BuildResult::Failed => failed = failed.union(ConfigComponents::only(component)),
            }
        }
        let providers = inputs
            .sandbox()
            .spec
            .as_ref()
            .map(|spec| spec.providers.iter().cloned().collect())
            .unwrap_or_default();
        (failed, Some(providers))
    }

    fn rejected(&self, record: &SessionRecord) -> ConfigComponents {
        self.0
            .supervisor_sessions
            .rejected_config_components(&record.sandbox_id, &record.session_id)
    }
}

enum BuildResult {
    Built {
        /// The session moved to another gateway after the build started.
        owner_moved: bool,
    },
    Failed,
}

/// Read the sandbox and the inputs its components share, or `None` once the
/// sandbox is gone.
async fn load_build_inputs(
    state: &Arc<ServerState>,
    sandbox_id: &str,
) -> Result<Option<SandboxConfigInputs>, Status> {
    let Some(sandbox) = state
        .store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .map_err(|error| Status::internal(format!("fetch sandbox failed: {error}")))?
    else {
        return Ok(None);
    };
    load_sandbox_config_inputs(state, sandbox).await.map(Some)
}

async fn run_build(
    state: &Arc<ServerState>,
    record: &SessionRecord,
    component: ConfigComponentKind,
    lane: Lane,
    inputs: &SandboxConfigInputs,
    load_elapsed: Duration,
) -> BuildResult {
    let sandbox_id = record.sandbox_id.as_str();
    let session_id = record.session_id.as_str();
    let started = Instant::now();
    let built = tokio::time::timeout(
        build_timeout(component).saturating_sub(load_elapsed),
        build_component(state, inputs, component),
    )
    .await;
    let elapsed = load_elapsed + started.elapsed();
    let message = match built {
        Ok(Ok(message)) => message,
        Ok(Err(error)) => {
            record_build_failure(sandbox_id, component, lane, "failed", error.code(), elapsed);
            return BuildResult::Failed;
        }
        Err(_) => {
            record_build_failure(
                sandbox_id,
                component,
                lane,
                "timeout",
                Code::DeadlineExceeded,
                elapsed,
            );
            return BuildResult::Failed;
        }
    };
    record_build(component, lane, "ok", elapsed);
    let owner_moved = match owner_check(state, sandbox_id, session_id).await {
        OwnerCheck::Current => {
            let disposition = state
                .supervisor_sessions
                .deliver_config(sandbox_id, session_id, message);
            record_delivery(component, disposition.metric_label());
            false
        }
        OwnerCheck::Remote => {
            record_delivery(component, "owner_moved");
            true
        }
        OwnerCheck::Gone => {
            record_delivery(component, "no_active_session");
            false
        }
        OwnerCheck::Unknown => {
            record_delivery(component, "owner_lookup_failed");
            return BuildResult::Failed;
        }
    };
    BuildResult::Built { owner_moved }
}

const fn build_timeout(component: ConfigComponentKind) -> Duration {
    match component {
        ConfigComponentKind::SandboxConfig => SANDBOX_CONFIG_BUILD_TIMEOUT,
        ConfigComponentKind::ProviderEnvironment => PROVIDER_ENVIRONMENT_BUILD_TIMEOUT,
    }
}

#[tracing::instrument(
    name = "config_build",
    level = "debug",
    skip_all,
    fields(otel.name = "config_delivery.build", sandbox_id, component = component.name())
)]
async fn build_component(
    state: &Arc<ServerState>,
    inputs: &SandboxConfigInputs,
    component: ConfigComponentKind,
) -> Result<SupervisorConfigMessage, Status> {
    Ok(match component {
        ConfigComponentKind::SandboxConfig => SupervisorConfigMessage::SandboxConfig(Box::new(
            build_sandbox_config_snapshot_from_inputs(state, inputs).await?,
        )),
        ConfigComponentKind::ProviderEnvironment => SupervisorConfigMessage::ProviderEnvironment(
            build_provider_environment_snapshot_from_inputs(state, inputs, true).await?,
        ),
    })
}

enum OwnerCheck {
    /// This gateway owns the session the build started for.
    Current,
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
fn notify_peer(state: &Arc<ServerState>, target: PeerNotifyTarget, components: ConfigComponents) {
    let start = {
        let mut pending = state
            .config_delivery
            .peer_notifies
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut start = false;
        pending
            .entry(target.clone())
            .and_modify(|queued| *queued = queued.union(components))
            .or_insert_with(|| {
                start = true;
                components
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
        let components = {
            let mut pending = state
                .config_delivery
                .peer_notifies
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let Some(queued) = pending.get_mut(&target) else {
                return;
            };
            if queued.is_empty() {
                pending.remove(&target);
                return;
            }
            std::mem::take(queued)
        };
        match &target {
            PeerNotifyTarget::Sandbox(sandbox_id) => {
                if notify_sandbox_owner(&state, sandbox_id, components).await
                    == PeerNotifyResult::Local
                {
                    state
                        .config_delivery
                        .publish_sandbox(sandbox_id, components);
                }
            }
            PeerNotifyTarget::Peers(scope) => notify_peers(&state, scope, components).await,
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
/// owner builds its own snapshot from shared state.
async fn notify_sandbox_owner(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    components: ConfigComponents,
) -> PeerNotifyResult {
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
            sandbox_config: components.sandbox_config,
            provider_environment: components.provider_environment,
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

async fn notify_peers(state: &Arc<ServerState>, scope: &FanoutScope, components: ConfigComponents) {
    let owners = SupervisorOwnerIndex::new(Arc::clone(&state.store), OWNER_TTL);
    let endpoints = match owners.list_fresh_peer_endpoints(&state.replica_id).await {
        Ok(endpoints) => endpoints,
        Err(error) => {
            warn!(error = %error, "configuration peer fanout owner listing failed");
            return;
        }
    };
    let scope = peer_scope(scope);
    futures::stream::iter(endpoints)
        .for_each_concurrent(PEER_FANOUT_CONCURRENCY, |endpoint| {
            let request = PeerNotifyConfigUpdateRequest {
                scope: Some(scope.clone()),
                sandbox_config: components.sandbox_config,
                provider_environment: components.provider_environment,
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
    let components = ConfigComponents {
        sandbox_config: notification.sandbox_config,
        provider_environment: notification.provider_environment,
    };
    if components.is_empty() {
        return Err(Status::invalid_argument(
            "at least one configuration component is required",
        ));
    }
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
                state
                    .config_delivery
                    .publish_sandbox(&target.sandbox_id, components);
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
    state.config_delivery.publish_fanout(&scope, components);
    Ok(Response::new(response))
}

/// Streamed-apply supervisor session registered without a gRPC stream. It
/// holds each component until the previous update is acknowledged.
#[cfg(test)]
pub struct TestApplySession {
    pub control: tokio::sync::mpsc::Sender<openshell_core::proto::GatewayMessage>,
    pub outbound: SessionOutbound,
}

#[cfg(test)]
pub fn register_test_apply_session(
    state: &Arc<ServerState>,
    sandbox: &Sandbox,
    session_id: &str,
) -> TestApplySession {
    use crate::persistence::{ObjectId, ObjectWorkspace};

    let (control, rx) = tokio::sync::mpsc::channel(4);
    let slots = Arc::new(ConfigSlots::default());
    let sandbox_id = sandbox.object_id().to_string();
    state.supervisor_sessions.register_with_mode(
        sandbox_id.clone(),
        session_id.to_string(),
        control.clone(),
        tokio::sync::oneshot::channel().0,
        crate::supervisor_session::SessionMode::Push(Arc::clone(&slots)),
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
            captured_seq: state.config_delivery.publications(),
        },
    );
    TestApplySession {
        control,
        outbound: SessionOutbound::new(rx, slots),
    }
}

fn record_build(
    component: ConfigComponentKind,
    lane: Lane,
    outcome: &'static str,
    elapsed: Duration,
) {
    counter!(
        "openshell_supervisor_config_builds_total",
        "component" => component.name(),
        "lane" => lane.name(),
        "outcome" => outcome,
    )
    .increment(1);
    histogram!(
        crate::gateway_metrics::SUPERVISOR_CONFIG_BUILD_DURATION_SECONDS,
        "component" => component.name(),
        "outcome" => outcome,
    )
    .record(elapsed.as_secs_f64());
}

fn record_build_failure(
    sandbox_id: &str,
    component: ConfigComponentKind,
    lane: Lane,
    outcome: &'static str,
    error_code: Code,
    elapsed: Duration,
) {
    record_build(component, lane, outcome, elapsed);
    warn!(
        sandbox_id,
        component = component.name(),
        ?error_code,
        "failed to build supervisor configuration snapshot"
    );
}

fn record_delivery(component: ConfigComponentKind, outcome: &'static str) {
    counter!(
        "openshell_supervisor_config_deliveries_total",
        "component" => component.name(),
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
        let mut request = Request::new(PeerNotifyConfigUpdateRequest {
            scope: Some(scope),
            sandbox_config: true,
            provider_environment: false,
        });
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

    /// Connect a streamed-apply supervisor. Without image policy discovery the
    /// gateway skips startup preparation and accepts it with its bootstrap.
    async fn accepted_session(
        state: &Arc<ServerState>,
        sandbox_id: &str,
    ) -> (SupervisorStreamHarness, String) {
        let mut harness = reconnect_supervisor_stream(state, sandbox_id, StreamFeatures::Apply)
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
        // supervisor; the gateway answers it with the admission.
        if let Some(bootstrap) = accepted.bootstrap {
            harness
                .outbound
                .send(openshell_core::proto::SupervisorMessage {
                    payload: Some(
                        openshell_core::proto::supervisor_message::Payload::ConfigBootstrapResult(
                            session::applied_bootstrap_result(&bootstrap),
                        ),
                    ),
                })
                .await
                .unwrap();
            let admission = next_update(&mut harness, Duration::from_secs(5))
                .await
                .expect("configuration admission");
            assert!(matches!(
                admission.payload,
                Some(gateway_message::Payload::ConfigurationAdmission(_))
            ));
        }
        (harness, accepted.session_id)
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

    #[tokio::test]
    async fn provider_change_reaches_only_attached_sessions() {
        let state = push_state().await;
        put_provider(&state, "github").await;
        put_sandbox(&state, "attached", &["github"]).await;
        put_sandbox(&state, "unattached", &[]).await;
        let (mut attached, _) = accepted_session(&state, "attached").await;
        let (mut unattached, _) = accepted_session(&state, "unattached").await;
        put_provider_with_token(&state, "github", Some("rotated")).await;

        publish_provider_components(&state, "default", "github", ConfigComponents::ALL);

        for _ in 0..2 {
            let update = next_update(&mut attached, Duration::from_secs(5))
                .await
                .expect("attached sandbox receives both components");
            assert!(is_config_update(&update));
        }
        assert!(
            next_update(&mut unattached, Duration::from_millis(200))
                .await
                .is_none()
        );

        change_policy(&state, "unattached", 1).await;
        publish_workspace_components(&state, "default", ConfigComponents::SANDBOX_CONFIG);
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

        publish_sandbox_components(&state, "sandbox", ConfigComponents::ALL);
        publish_workspace_components(&state, "default", ConfigComponents::ALL);
        publish_provider_components(&state, "default", "github", ConfigComponents::ALL);
        publish_all_connected(&state, ConfigComponents::ALL);

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
        notify_peer(&state, target.clone(), ConfigComponents::SANDBOX_CONFIG);
        notify_peer(
            &state,
            target.clone(),
            ConfigComponents::only(ConfigComponentKind::ProviderEnvironment),
        );
        {
            let pending = state.config_delivery.peer_notifies.lock().unwrap();
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[&target], ConfigComponents::ALL);
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
                    captured_seq: 0,
                }))
            })
            .collect();
        delivery.sessions().extend(
            records
                .iter()
                .map(|record| (record.sandbox_id.clone(), Arc::clone(record))),
        );
        for _ in 0..3 {
            delivery.publish_fanout(&FanoutScope::AllConnected, ConfigComponents::SANDBOX_CONFIG);
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
                .permits
                .builds()
        };
        assert_eq!(builds(10), 20);
        assert_eq!(builds(1), MIN_CONCURRENT_SNAPSHOT_BUILDS);
    }

    #[test]
    fn credential_resolving_builds_get_a_longer_deadline() {
        assert_eq!(
            build_timeout(ConfigComponentKind::SandboxConfig),
            Duration::from_secs(5)
        );
        assert_eq!(
            build_timeout(ConfigComponentKind::ProviderEnvironment),
            Duration::from_secs(20)
        );
    }

    #[test]
    fn configuration_message_debug_output_redacts_payloads() {
        let message = SupervisorConfigMessage::ProviderEnvironment(ProviderEnvironmentSnapshot {
            values: vec![openshell_core::proto::ProviderEnvironmentValue {
                name: "TOKEN".into(),
                value: "secret-marker".into(),
                ..Default::default()
            }],
            ..Default::default()
        });
        assert!(!format!("{message:?}").contains("secret-marker"));
    }

    #[tokio::test]
    async fn session_acceptance_precedes_live_configuration_updates() {
        let state = push_state().await;
        put_sandbox(&state, "sandbox", &[]).await;
        let (mut harness, _) = accepted_session(&state, "sandbox").await;
        assert!(has_recipient(&state, "sandbox"));
        change_policy(&state, "sandbox", 1).await;

        publish_sandbox_components(&state, "sandbox", ConfigComponents::SANDBOX_CONFIG);
        let update = next_update(&mut harness, Duration::from_secs(5))
            .await
            .expect("configuration update");
        assert!(is_config_update(&update));
    }

    #[tokio::test]
    async fn legacy_supervisor_keeps_polling_when_gateway_push_is_enabled() {
        let state = push_state().await;
        put_sandbox(&state, "legacy-sandbox", &[]).await;
        let mut harness =
            connect_supervisor_stream(&state, "legacy-sandbox", StreamFeatures::Legacy)
                .await
                .unwrap();
        let first = harness.inbound.message().await.unwrap().unwrap();
        let Some(gateway_message::Payload::SessionAccepted(accepted)) = first.payload else {
            panic!("expected SessionAccepted");
        };
        assert!(accepted.bootstrap.is_none());
        publish_sandbox_components(&state, "legacy-sandbox", ConfigComponents::SANDBOX_CONFIG);
        publish_all_connected(&state, ConfigComponents::ALL);
        assert!(
            next_update(&mut harness, Duration::from_millis(100))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn stalled_credentials_keep_the_live_session_serving_relays() {
        use openshell_core::proto::{StartupConfigPrepared, SupervisorMessage, supervisor_message};

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
        // A stored gateway policy leaves startup preparation nothing to persist,
        // so no publication follows the first session.
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
        let Some(gateway_message::Payload::StartupConfigCandidate(candidate)) =
            next_update(&mut live, Duration::from_secs(5))
                .await
                .expect("startup candidate")
                .payload
        else {
            panic!("expected StartupConfigCandidate");
        };
        live.outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::StartupConfigPrepared(
                    StartupConfigPrepared {
                        candidate_id: candidate.candidate_id,
                        result: Some(
                            openshell_core::proto::startup_config_prepared::Result::Unchanged(()),
                        ),
                    },
                )),
            })
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
    /// driver, and accept a session for its sandbox.
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
        let (harness, session_id) = accepted_session(state, "sandbox").await;
        let record = SessionRecord::new(Registration {
            sandbox_id: "sandbox".into(),
            session_id,
            workspace: "default".into(),
            providers: HashSet::from(["provider".to_string()]),
            captured_seq: 0,
        });
        (harness, record)
    }

    fn updated_component(message: &GatewayMessage) -> Option<ConfigComponentKind> {
        use openshell_core::proto::config_update::Component;

        let Some(gateway_message::Payload::ConfigUpdate(update)) = &message.payload else {
            return None;
        };
        match update.component.as_ref()? {
            Component::SandboxConfig(_) => Some(ConfigComponentKind::SandboxConfig),
            Component::ProviderEnvironment(_) => Some(ConfigComponentKind::ProviderEnvironment),
        }
    }

    #[tokio::test]
    async fn provider_failure_keeps_the_built_sandbox_configuration_deliverable() {
        let state = push_state().await;
        let (mut harness, record) = driver_backed_session(&state).await;
        // The provider's credential no longer resolves, and a new policy
        // revision changes the sandbox configuration.
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

        let work = Work {
            components: ConfigComponents::ALL,
            lane: Lane::Sandbox,
        };
        let (failed, providers) = Builder(&state).deliver(&record, work).await;
        assert_eq!(
            failed,
            ConfigComponents::only(ConfigComponentKind::ProviderEnvironment)
        );
        assert_eq!(providers, Some(HashSet::from(["provider".to_string()])));
        let update = next_update(&mut harness, Duration::from_secs(5))
            .await
            .expect("sandbox configuration update");
        assert_eq!(
            updated_component(&update),
            Some(ConfigComponentKind::SandboxConfig)
        );
    }

    #[tokio::test]
    async fn sandbox_configuration_builds_resolve_no_credentials() {
        let state = push_state().await;
        let (mut harness, record) = driver_backed_session(&state).await;
        let (mut resolve_hit, _release_resolve) = state.credentials.gate_next_resolve();
        change_policy(&state, "sandbox", 1).await;

        let work = Work {
            components: ConfigComponents::SANDBOX_CONFIG,
            lane: Lane::Sandbox,
        };
        let (failed, _) = tokio::time::timeout(
            Duration::from_secs(5),
            Builder(&state).deliver(&record, work),
        )
        .await
        .expect("a sandbox configuration build must not wait on credentials");
        assert!(failed.is_empty());
        let update = next_update(&mut harness, Duration::from_secs(5))
            .await
            .expect("sandbox configuration update");
        assert_eq!(
            updated_component(&update),
            Some(ConfigComponentKind::SandboxConfig)
        );
        assert_eq!(
            resolve_hit.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        );
    }
}
