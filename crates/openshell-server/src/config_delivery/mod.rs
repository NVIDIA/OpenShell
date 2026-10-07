// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Build and deliver complete supervisor configuration snapshots.

mod queue;
mod session_slots;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use futures::StreamExt;
use metrics::counter;
use openshell_core::config::ConfigDeliveryMode;
use openshell_core::proto::{
    ConfigBootstrap, PeerConfigProviderTarget, PeerConfigSandboxTarget,
    PeerNotifyConfigUpdateRequest, PeerNotifyConfigUpdateResponse, ProviderEnvironmentSnapshot,
    Sandbox, SandboxConfigSnapshot, peer_notify_config_update_request,
};
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tonic::{Code, Request, Response, Status};
use tracing::warn;

use crate::ServerState;
use crate::auth::principal::Principal;
use crate::grpc::policy::{build_provider_environment_snapshot, build_sandbox_config_snapshot};
use crate::supervisor_owner::{OWNER_TTL, SupervisorOwnerIndex};
use crate::supervisor_session::SupervisorSessionRegistry;

pub use queue::Registration;
use queue::{
    BuildOutcome, BuildTicket, DeliveryKey, DeliveryQueue, FanoutScope, Lane, Limits,
    PeerNotifyTarget, PeerNotifyTicket, Work,
};
pub use session_slots::{ConfigSlots, SessionOutbound};

/// Leaves headroom below tonic's default 4 MiB decode limit for framing and
/// future envelope fields.
pub const MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES: usize = 3 * 1024 * 1024;
/// Sandbox configuration builds only read the store, which answers in
/// milliseconds when healthy; anything slower means the store is in trouble.
const SANDBOX_CONFIG_BUILD_TIMEOUT: Duration = Duration::from_secs(5);
/// Provider environment builds also resolve credentials. Covers a cold Vault
/// Kubernetes-auth login plus a read at the default 10-second request timeout.
const PROVIDER_ENVIRONMENT_BUILD_TIMEOUT: Duration = Duration::from_secs(20);
// Stage 1 bootstrap is optional. Keep credential backend stalls well below
// the 15-second relay session-wait budget while polling remains authoritative.
const CONFIG_BOOTSTRAP_BUILD_TIMEOUT: Duration = Duration::from_secs(1);
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
    NoActiveSession,
    UnsupportedSession,
    PayloadTooLarge,
}

impl DeliveryDisposition {
    fn metric_label(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Replaced => "replaced",
            Self::NoActiveSession => "no_active_session",
            Self::UnsupportedSession => "unsupported_session",
            Self::PayloadTooLarge => "payload_too_large",
        }
    }
}

/// Transport boundary for configuration delivery.
#[tonic::async_trait]
pub trait SupervisorConfigTransport: fmt::Debug + Send + Sync {
    async fn deliver(
        &self,
        sandbox_id: &str,
        session_id: &str,
        message: SupervisorConfigMessage,
    ) -> DeliveryDisposition;
}

#[derive(Debug)]
pub struct LocalSupervisorConfigTransport {
    sessions: Arc<SupervisorSessionRegistry>,
}

impl LocalSupervisorConfigTransport {
    #[must_use]
    pub fn new(sessions: Arc<SupervisorSessionRegistry>) -> Self {
        Self { sessions }
    }
}

#[tonic::async_trait]
impl SupervisorConfigTransport for LocalSupervisorConfigTransport {
    async fn deliver(
        &self,
        sandbox_id: &str,
        session_id: &str,
        message: SupervisorConfigMessage,
    ) -> DeliveryDisposition {
        self.sessions
            .deliver_config(sandbox_id, session_id, message)
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

    pub const SANDBOX_AND_PROVIDER: Self = Self {
        sandbox_config: true,
        provider_environment: true,
    };

    pub const SANDBOX_CONFIG: Self = Self {
        sandbox_config: true,
        provider_environment: false,
    };

    fn only(component: ConfigComponentKind) -> Self {
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
    fn name(self) -> &'static str {
        match self {
            Self::SandboxConfig => "sandbox_config",
            Self::ProviderEnvironment => "provider_environment",
        }
    }
}

/// Coalescing delivery queue shared by publications, supervisor sessions,
/// and one on-demand delivery worker task.
#[derive(Debug)]
pub struct ConfigDelivery {
    state: Mutex<DeliveryState>,
    wake: Notify,
}

#[derive(Debug)]
struct DeliveryState {
    queue: DeliveryQueue,
    delivery_worker_running: bool,
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
            state: Mutex::new(DeliveryState {
                queue: DeliveryQueue::new(Limits::new(builds, MAX_CONCURRENT_PEER_NOTIFIES)),
                delivery_worker_running: false,
            }),
            wake: Notify::new(),
        }
    }

    pub(crate) fn current_seq(&self) -> u64 {
        self.lock().queue.current_seq()
    }

    fn with_queue<T>(&self, update: impl FnOnce(&mut DeliveryQueue) -> T) -> T {
        update(&mut self.lock().queue)
    }

    /// Delivery is best effort beside the session lifecycle, so a poisoned
    /// lock must not turn session teardown into a panic.
    fn lock(&self) -> MutexGuard<'_, DeliveryState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

pub async fn build_config_bootstrap(
    state: &Arc<ServerState>,
    sandbox: &Sandbox,
) -> Result<ConfigBootstrap, Status> {
    tokio::time::timeout(
        CONFIG_BOOTSTRAP_BUILD_TIMEOUT,
        build_consistent_config_bootstrap(state, sandbox),
    )
    .await
    .map_err(|_| Status::deadline_exceeded("supervisor configuration bootstrap timed out"))?
}

async fn build_consistent_config_bootstrap(
    state: &Arc<ServerState>,
    sandbox: &Sandbox,
) -> Result<ConfigBootstrap, Status> {
    const MAX_BUILD_ATTEMPTS: usize = 3;
    for _ in 0..MAX_BUILD_ATTEMPTS {
        // Components are independent projections. The provider revision is a
        // fence for the only overlapping input between sandbox configuration
        // and provider environment state.
        let (sandbox_config, provider_environment) = tokio::join!(
            build_sandbox_config_snapshot(state, sandbox),
            build_provider_environment_snapshot(state, sandbox, true),
        );
        let bootstrap = ConfigBootstrap {
            sandbox_config: Some(sandbox_config?),
            provider_environment: Some(provider_environment?),
        };
        if bootstrap_revisions_match(&bootstrap) {
            return Ok(bootstrap);
        }
        counter!("openshell_supervisor_config_bootstrap_revision_mismatches_total").increment(1);
    }
    Err(Status::aborted(
        "configuration changed while building supervisor bootstrap",
    ))
}

fn bootstrap_revisions_match(bootstrap: &ConfigBootstrap) -> bool {
    bootstrap
        .sandbox_config
        .as_ref()
        .zip(bootstrap.provider_environment.as_ref())
        .is_some_and(|(sandbox, provider)| {
            sandbox.provider_env_revision == provider.provider_env_revision
        })
}

fn push_enabled(state: &ServerState) -> bool {
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
    let now = Instant::now();
    // A single-replica gateway owns every session, and registration covers a
    // session that is still connecting.
    let may_be_remote = !state.store.is_single_replica();
    state.config_delivery.with_queue(|queue| {
        if !queue.publish_sandbox(sandbox_id, components, now) && may_be_remote {
            queue.notify_peer(
                PeerNotifyTarget::Sandbox(sandbox_id.to_string()),
                components,
            );
        }
    });
    kick(state);
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
    let notify_peers = !state.store.is_single_replica();
    state.config_delivery.with_queue(|queue| {
        queue.publish_fanout(scope, components, notify_peers, Instant::now());
    });
    kick(state);
}

/// Make a push-capable session visible to fanouts and sandbox updates.
pub fn register_session(state: &Arc<ServerState>, registration: Registration) {
    state.config_delivery.with_queue(|queue| {
        // A concurrent reconnect may already own the registry entry. Checking
        // under the queue lock keeps the newest session registered.
        if state
            .supervisor_sessions
            .is_current_session(&registration.sandbox_id, &registration.session_id)
        {
            queue.register(registration, Instant::now());
        }
    });
    kick(state);
}

pub fn unregister_session(state: &ServerState, sandbox_id: &str, session_id: &str) {
    state
        .config_delivery
        .with_queue(|queue| queue.unregister(sandbox_id, session_id));
}

fn kick(state: &Arc<ServerState>) {
    let start = {
        let mut delivery = state.config_delivery.lock();
        !std::mem::replace(&mut delivery.delivery_worker_running, true)
    };
    if start {
        tokio::spawn(run_delivery_worker(Arc::clone(state)));
    } else {
        state.config_delivery.wake.notify_one();
    }
}

/// Releases outstanding work if the delivery worker unwinds, so a later
/// publication starts a replacement with consistent slot accounting.
struct DeliveryWorkerGuard {
    state: Arc<ServerState>,
    tickets: HashMap<tokio::task::Id, Work>,
    finished: bool,
}

impl Drop for DeliveryWorkerGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let mut delivery = self.state.config_delivery.lock();
        let now = Instant::now();
        for work in self.tickets.values() {
            match work {
                Work::Build(ticket) => {
                    delivery
                        .queue
                        .complete_build(ticket, BuildOutcome::Failed, now);
                }
                Work::PeerNotify(ticket) => delivery.queue.complete_peer_notify(ticket),
            }
        }
        delivery.delivery_worker_running = false;
    }
}

async fn run_delivery_worker(state: Arc<ServerState>) {
    let delivery = &state.config_delivery;
    let mut tasks = JoinSet::new();
    let mut guard = DeliveryWorkerGuard {
        state: Arc::clone(&state),
        tickets: HashMap::new(),
        finished: false,
    };
    loop {
        let started = {
            let mut delivery_state = delivery.lock();
            let now = Instant::now();
            let mut started = Vec::new();
            while let Some(work) = delivery_state.queue.next_work(now) {
                started.push(work);
            }
            delivery_state.queue.record_gauges();
            // Clearing the flag under the queue lock means a concurrent
            // publication either sees this delivery worker running or starts one.
            if started.is_empty() && !delivery_state.queue.has_running_work() {
                delivery_state.delivery_worker_running = false;
                guard.finished = true;
                return;
            }
            started
        };
        for work in started {
            let handle = tasks.spawn(run_work(Arc::clone(&state), work.clone()));
            guard.tickets.insert(handle.id(), work);
        }
        tokio::select! {
            joined = tasks.join_next_with_id(), if !tasks.is_empty() => {
                let (id, result) = match joined.expect("join set is not empty") {
                    Ok((id, result)) => (id, Some(result)),
                    Err(error) => {
                        // Panic payloads may contain credential backend data.
                        warn!(
                            cancelled = error.is_cancelled(),
                            panicked = error.is_panic(),
                            "supervisor configuration delivery task failed"
                        );
                        (error.id(), None)
                    }
                };
                let work = guard.tickets.remove(&id).expect("delivery task has a ticket");
                complete_work(&state, &work, result);
            }
            () = delivery.wake.notified() => {}
        }
    }
}

enum WorkResult {
    Build(BuildResult),
    PeerNotify(PeerNotifyResult),
}

struct BuildResult {
    outcome: BuildOutcome,
    /// The session moved to another gateway after the build started.
    owner_moved: bool,
}

enum PeerNotifyResult {
    Done,
    /// This gateway owns the current session for the notified sandbox.
    Local,
}

async fn run_work(state: Arc<ServerState>, work: Work) -> WorkResult {
    match work {
        Work::Build(ticket) => WorkResult::Build(run_build(&state, &ticket).await),
        Work::PeerNotify(ticket) => WorkResult::PeerNotify(run_peer_notify(&state, &ticket).await),
    }
}

fn complete_work(state: &ServerState, work: &Work, result: Option<WorkResult>) {
    let now = Instant::now();
    state
        .config_delivery
        .with_queue(|queue| match (work, result) {
            (Work::Build(ticket), Some(WorkResult::Build(result))) => {
                queue.complete_build(ticket, result.outcome, now);
                if result.owner_moved {
                    queue.notify_peer(
                        PeerNotifyTarget::Sandbox(ticket.key.sandbox_id.clone()),
                        ConfigComponents::only(ticket.key.component),
                    );
                }
            }
            (Work::Build(ticket), _) => {
                queue.complete_build(ticket, BuildOutcome::Failed, now);
            }
            (Work::PeerNotify(ticket), result) => {
                queue.complete_peer_notify(ticket);
                if let (
                    PeerNotifyTarget::Sandbox(sandbox_id),
                    Some(WorkResult::PeerNotify(PeerNotifyResult::Local)),
                ) = (&ticket.target, result)
                {
                    queue.publish_sandbox(sandbox_id, ticket.components, now);
                }
            }
        });
}

async fn run_build(state: &Arc<ServerState>, ticket: &BuildTicket) -> BuildResult {
    let BuildTicket {
        key,
        lane,
        session_id,
        ..
    } = ticket;
    let failed = BuildResult {
        outcome: BuildOutcome::Failed,
        owner_moved: false,
    };
    let built =
        tokio::time::timeout(build_timeout(key.component), build_component(state, key)).await;
    let (message, providers) = match built {
        Ok(Ok(Some(built))) => built,
        Ok(Ok(None)) => {
            record_build(key.component, *lane, "ok");
            return BuildResult {
                outcome: BuildOutcome::Built { providers: None },
                owner_moved: false,
            };
        }
        Ok(Err(error)) => {
            record_build_failure(key, *lane, "failed", error.code());
            return failed;
        }
        Err(_) => {
            record_build_failure(key, *lane, "timeout", Code::DeadlineExceeded);
            return failed;
        }
    };
    record_build(key.component, *lane, "ok");
    let owner_moved = match owner_check(state, &key.sandbox_id, session_id).await {
        OwnerCheck::Current => {
            let disposition = state
                .supervisor_config_transport()
                .deliver(&key.sandbox_id, session_id, message)
                .await;
            record_delivery(key.component, disposition.metric_label());
            false
        }
        OwnerCheck::Remote => {
            record_delivery(key.component, "owner_moved");
            true
        }
        OwnerCheck::Gone => {
            record_delivery(key.component, "no_active_session");
            false
        }
        OwnerCheck::Unknown => {
            record_delivery(key.component, "owner_lookup_failed");
            return failed;
        }
    };
    BuildResult {
        outcome: BuildOutcome::Built {
            providers: Some(providers),
        },
        owner_moved,
    }
}

const fn build_timeout(component: ConfigComponentKind) -> Duration {
    match component {
        ConfigComponentKind::SandboxConfig => SANDBOX_CONFIG_BUILD_TIMEOUT,
        ConfigComponentKind::ProviderEnvironment => PROVIDER_ENVIRONMENT_BUILD_TIMEOUT,
    }
}

async fn build_component(
    state: &Arc<ServerState>,
    key: &DeliveryKey,
) -> Result<Option<(SupervisorConfigMessage, HashSet<String>)>, Status> {
    let Some(sandbox) = state
        .store
        .get_message::<Sandbox>(&key.sandbox_id)
        .await
        .map_err(|error| Status::internal(format!("fetch sandbox failed: {error}")))?
    else {
        return Ok(None);
    };
    let providers = sandbox
        .spec
        .as_ref()
        .map(|spec| spec.providers.iter().cloned().collect())
        .unwrap_or_default();
    let message = match key.component {
        ConfigComponentKind::SandboxConfig => SupervisorConfigMessage::SandboxConfig(Box::new(
            build_sandbox_config_snapshot(state, &sandbox).await?,
        )),
        ConfigComponentKind::ProviderEnvironment => SupervisorConfigMessage::ProviderEnvironment(
            build_provider_environment_snapshot(state, &sandbox, true).await?,
        ),
    };
    Ok(Some((message, providers)))
}

enum OwnerCheck {
    /// This gateway owns the session the build started for.
    Current,
    Remote,
    Gone,
    Unknown,
}

async fn owner_check(state: &Arc<ServerState>, sandbox_id: &str, session_id: &str) -> OwnerCheck {
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

async fn run_peer_notify(state: &Arc<ServerState>, ticket: &PeerNotifyTicket) -> PeerNotifyResult {
    match &ticket.target {
        PeerNotifyTarget::Sandbox(sandbox_id) => {
            notify_sandbox_owner(state, sandbox_id, ticket.components).await
        }
        PeerNotifyTarget::Peers(scope) => {
            notify_peers(state, scope, ticket.components).await;
            PeerNotifyResult::Done
        }
    }
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
        if !is_peer_endpoint(&owner.owner_peer_endpoint) {
            warn!(sandbox_id, owner = %owner.owner_replica_id, "configuration owner has no reachable peer endpoint");
            return PeerNotifyResult::Done;
        }
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
        match send_peer_notify(state, &owner.owner_peer_endpoint, request).await {
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

fn is_peer_endpoint(endpoint: &str) -> bool {
    endpoint.starts_with("http://") || endpoint.starts_with("https://")
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
                state.config_delivery.with_queue(|queue| {
                    queue.publish_sandbox(&target.sandbox_id, components, Instant::now())
                });
                kick(state);
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
    state.config_delivery.with_queue(|queue| {
        queue.publish_fanout(&scope, components, false, Instant::now());
    });
    kick(state);
    Ok(Response::new(response))
}

/// Supervisor session registered for configuration push without a gRPC stream.
#[cfg(test)]
pub struct TestPushSession {
    _control: tokio::sync::mpsc::Sender<openshell_core::proto::GatewayMessage>,
    pub outbound: SessionOutbound,
}

#[cfg(test)]
pub fn register_test_push_session(
    state: &Arc<ServerState>,
    sandbox: &Sandbox,
    session_id: &str,
) -> TestPushSession {
    use crate::persistence::{ObjectId, ObjectWorkspace};

    let (control, rx) = tokio::sync::mpsc::channel(4);
    let slots = Arc::new(ConfigSlots::default());
    let sandbox_id = sandbox.object_id().to_string();
    state.supervisor_sessions.register_with_config_slots(
        sandbox_id.clone(),
        session_id.to_string(),
        control.clone(),
        tokio::sync::oneshot::channel().0,
        Some(Arc::clone(&slots)),
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
            captured_seq: state.config_delivery.current_seq(),
            bootstrap_built: true,
        },
    );
    TestPushSession {
        _control: control,
        outbound: SessionOutbound::new(rx, slots),
    }
}

fn record_build(component: ConfigComponentKind, lane: Lane, outcome: &'static str) {
    counter!(
        "openshell_supervisor_config_builds_total",
        "component" => component.name(),
        "lane" => lane.name(),
        "outcome" => outcome,
    )
    .increment(1);
}

fn record_build_failure(key: &DeliveryKey, lane: Lane, outcome: &'static str, error_code: Code) {
    record_build(key.component, lane, outcome);
    warn!(
        sandbox_id = %key.sandbox_id,
        component = key.component.name(),
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
        SupervisorStreamHarness, connect_supervisor_stream, test_server_state,
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
                ..Default::default()
            })
            .await
            .unwrap();
    }

    async fn accepted_session(
        state: &Arc<ServerState>,
        sandbox_id: &str,
    ) -> (SupervisorStreamHarness, String) {
        let mut harness = connect_supervisor_stream(state, sandbox_id, true)
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

        publish_workspace_components(&state, "default", ConfigComponents::SANDBOX_CONFIG);
        assert!(
            next_update(&mut unattached, Duration::from_secs(5))
                .await
                .is_some_and(|update| is_config_update(&update))
        );
    }

    fn has_recipient(state: &ServerState, sandbox_id: &str) -> bool {
        state
            .config_delivery
            .with_queue(|queue| queue.has_recipient(sandbox_id))
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

        assert_eq!(state.config_delivery.current_seq(), 0);
        assert!(!state.config_delivery.lock().delivery_worker_running);
        assert!(
            next_update(&mut harness, Duration::from_millis(100))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn stale_local_session_gets_nothing_after_its_owner_moves() {
        let state = push_state().await;
        put_sandbox(&state, "moved", &[]).await;
        let (mut harness, _) = accepted_session(&state, "moved").await;
        assert!(has_recipient(&state, "moved"));
        SupervisorOwnerIndex::new(Arc::clone(&state.store), OWNER_TTL)
            .publish(
                "moved",
                "remote-session",
                "instance",
                1,
                "other-replica",
                "http://127.0.0.1:9",
            )
            .await
            .unwrap();

        publish_sandbox_components(&state, "moved", ConfigComponents::SANDBOX_CONFIG);
        assert!(
            next_update(&mut harness, Duration::from_millis(500))
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
    async fn build_for_a_moved_session_notifies_the_new_owner() {
        let state = push_state().await;
        let work = state.config_delivery.with_queue(|queue| {
            queue.register(
                Registration {
                    sandbox_id: "moved".into(),
                    session_id: "session".into(),
                    workspace: "default".into(),
                    providers: HashSet::new(),
                    captured_seq: 0,
                    bootstrap_built: true,
                },
                Instant::now(),
            );
            queue.publish_sandbox("moved", ConfigComponents::SANDBOX_CONFIG, Instant::now());
            queue.next_work(Instant::now()).unwrap()
        });

        complete_work(
            &state,
            &work,
            Some(WorkResult::Build(BuildResult {
                outcome: BuildOutcome::Built { providers: None },
                owner_moved: true,
            })),
        );
        let next = state
            .config_delivery
            .with_queue(|queue| queue.next_work(Instant::now()));
        assert_eq!(
            next,
            Some(Work::PeerNotify(PeerNotifyTicket {
                target: PeerNotifyTarget::Sandbox("moved".into()),
                components: ConfigComponents::SANDBOX_CONFIG,
            }))
        );
    }

    #[test]
    fn build_slots_are_sized_from_the_database_pool() {
        let builds = |connections| {
            ConfigDelivery::for_db_connections(connections)
                .with_queue(|queue| queue.limits().builds())
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

        publish_sandbox_components(&state, "sandbox", ConfigComponents::SANDBOX_CONFIG);
        let update = next_update(&mut harness, Duration::from_secs(5))
            .await
            .expect("configuration update");
        assert!(is_config_update(&update));
    }

    #[tokio::test]
    async fn legacy_supervisor_keeps_polling_when_gateway_shadow_push_is_enabled() {
        let state = push_state().await;
        put_sandbox(&state, "legacy-sandbox", &[]).await;
        let mut harness = connect_supervisor_stream(&state, "legacy-sandbox", false)
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

    #[test]
    fn bootstrap_requires_matching_provider_revision_fence() {
        let mut bootstrap = ConfigBootstrap {
            sandbox_config: Some(SandboxConfigSnapshot {
                provider_env_revision: 7,
                ..Default::default()
            }),
            provider_environment: Some(ProviderEnvironmentSnapshot {
                provider_env_revision: 8,
                ..Default::default()
            }),
        };
        assert!(!bootstrap_revisions_match(&bootstrap));
        bootstrap
            .provider_environment
            .as_mut()
            .unwrap()
            .provider_env_revision = 7;
        assert!(bootstrap_revisions_match(&bootstrap));
    }

    #[tokio::test]
    async fn stalled_credentials_do_not_block_session_acceptance() {
        use openshell_core::proto::CredentialHandle;

        let state = push_state().await;
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
                credential_handles: HashMap::from([(
                    "GITHUB_TOKEN".into(),
                    CredentialHandle {
                        driver: "test-static".into(),
                        handle: "blocked".into(),
                        ..Default::default()
                    },
                )]),
                ..Default::default()
            })
            .await
            .unwrap();
        put_sandbox(&state, "sandbox", &["provider"]).await;
        let (resolve_hit, _release_resolve) = state.credentials.gate_next_resolve();
        tokio::time::timeout(Duration::from_secs(10), async {
            let connect = connect_supervisor_stream(&state, "sandbox", true);
            let (response, hit) = tokio::join!(connect, resolve_hit);
            hit.expect("bootstrap must reach the stalled credential driver");
            let mut harness = response.unwrap();
            let first = harness.inbound.message().await.unwrap().unwrap();
            let Some(gateway_message::Payload::SessionAccepted(accepted)) = first.payload else {
                panic!("expected session acceptance");
            };
            assert!(accepted.bootstrap.is_none());
            assert!(
                state
                    .supervisor_sessions
                    .is_current_session("sandbox", &accepted.session_id)
            );
            // Relay control remains usable while credential resolution is stalled.
            let (_, relay) = state
                .supervisor_sessions
                .open_relay("sandbox", Duration::from_secs(1))
                .await
                .unwrap();
            let message = harness.inbound.message().await.unwrap().unwrap();
            assert!(matches!(
                message.payload,
                Some(gateway_message::Payload::RelayOpen(_))
            ));
            drop(relay);
        })
        .await
        .expect("optional bootstrap must not consume the relay reconnect budget");
    }
}
