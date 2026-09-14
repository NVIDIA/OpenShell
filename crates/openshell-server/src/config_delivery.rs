// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Build and route complete supervisor configuration snapshots.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use metrics::counter;
use openshell_core::proto::{
    ConfigBootstrap, ProviderEnvironmentSnapshot, Sandbox, SandboxConfigSnapshot,
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tonic::{Code, Status};
use tracing::warn;

use crate::ServerState;
use crate::grpc::policy::{build_provider_environment_snapshot, build_sandbox_config_snapshot};
use crate::persistence::ObjectWorkspace;
use crate::supervisor_session::SupervisorSessionRegistry;

/// Leaves headroom below tonic's default 4 MiB decode limit for framing and
/// future envelope fields.
pub const MAX_SUPERVISOR_CONFIG_MESSAGE_BYTES: usize = 3 * 1024 * 1024;
const CONFIG_SNAPSHOT_BUILD_TIMEOUT: Duration = Duration::from_secs(45);
pub const REQUIRED_CONFIG_BOOTSTRAP_BUILD_TIMEOUT: Duration = CONFIG_SNAPSHOT_BUILD_TIMEOUT;
const MAX_ACTIVE_FANOUT_WORKERS: usize = 64;
/// Concurrent snapshot builds allowed per pooled database connection. Builds
/// are short bursts of small queries, so a little oversubscription keeps the
/// pool busy without stacking every waiter on the acquire timeout.
const SNAPSHOT_BUILDS_PER_DB_CONNECTION: usize = 2;
const MIN_CONCURRENT_SNAPSHOT_BUILDS: usize = 4;
/// Admit scoped bursts independently of the database build bound. Workers
/// waiting to build still count toward this limit.
const MIN_CONCURRENT_DELIVERY_WORKERS: usize = 64;
/// Includes running and queued component keys; payloads are built on dispatch.
const MAX_PENDING_DELIVERIES: usize = 1024;

/// One complete configuration component awaiting delivery to a supervisor.
#[derive(Clone)]
pub enum SupervisorConfigMessage {
    SandboxConfig(Box<SandboxConfigSnapshot>),
    ProviderEnvironment(ProviderEnvironmentSnapshot),
}

impl SupervisorConfigMessage {
    pub(crate) fn component_name(&self) -> &'static str {
        match self {
            Self::SandboxConfig(_) => "sandbox_config",
            Self::ProviderEnvironment(_) => "provider_environment",
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

/// Result of routing one configuration snapshot toward a supervisor session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryDisposition {
    Enqueued,
    Coalesced,
    SuppressedUnchanged,
    NoActiveSession,
    QueueFull,
    SessionClosed,
    PayloadTooLarge,
}

/// Transport boundary for configuration delivery.
#[tonic::async_trait]
pub trait SupervisorConfigRouter: fmt::Debug + Send + Sync {
    async fn deliver(
        &self,
        sandbox_id: &str,
        message: SupervisorConfigMessage,
    ) -> DeliveryDisposition;

    async fn routable_sandbox_ids(&self) -> Vec<String>;
}

#[derive(Debug)]
pub struct LocalSupervisorConfigRouter {
    sessions: Arc<SupervisorSessionRegistry>,
}

impl LocalSupervisorConfigRouter {
    #[must_use]
    pub fn new(sessions: Arc<SupervisorSessionRegistry>) -> Self {
        Self { sessions }
    }
}

#[tonic::async_trait]
impl SupervisorConfigRouter for LocalSupervisorConfigRouter {
    async fn deliver(
        &self,
        sandbox_id: &str,
        message: SupervisorConfigMessage,
    ) -> DeliveryDisposition {
        self.sessions.deliver_config(sandbox_id, message)
    }

    async fn routable_sandbox_ids(&self) -> Vec<String> {
        self.sessions.connected_sandbox_ids()
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
enum ConfigComponentKind {
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DeliveryKey {
    sandbox_id: String,
    component: ConfigComponentKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum FanoutScope {
    Workspace(String),
    AllConnected,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FanoutKey {
    scope: FanoutScope,
    component: ConfigComponentKind,
}

/// Coalesces publications and bounds workers per sandbox and component.
///
/// Queued keys do not own tasks or build permits. Repeated publications mark
/// the existing key dirty. A mutation during delivery schedules another pass
/// at the FIFO tail so a busy sandbox cannot monopolize a worker.
#[derive(Debug)]
pub struct ConfigDeliveryQueue {
    pending: Mutex<PendingDeliveries>,
    fanout_pending: Mutex<HashMap<FanoutKey, bool>>,
    max_delivery_workers: usize,
    pending_slots: Arc<Semaphore>,
    ready: Notify,
    build_permits: Semaphore,
}

#[derive(Debug, Default)]
struct PendingDeliveries {
    changed: HashMap<DeliveryKey, PendingDelivery>,
    ready: VecDeque<DeliveryKey>,
    dispatcher_running: bool,
}

#[derive(Debug)]
struct PendingDelivery {
    changed: bool,
    _slot: OwnedSemaphorePermit,
}

impl Default for ConfigDeliveryQueue {
    fn default() -> Self {
        Self::new(MIN_CONCURRENT_SNAPSHOT_BUILDS)
    }
}

impl ConfigDeliveryQueue {
    #[must_use]
    pub fn new(max_concurrent_builds: usize) -> Self {
        Self::with_limits(max_concurrent_builds, max_concurrent_builds)
    }

    fn with_limits(max_concurrent_builds: usize, max_delivery_workers: usize) -> Self {
        Self::with_pending_capacity(
            max_concurrent_builds,
            max_delivery_workers,
            MAX_PENDING_DELIVERIES,
        )
    }

    fn with_pending_capacity(
        max_concurrent_builds: usize,
        max_delivery_workers: usize,
        max_pending: usize,
    ) -> Self {
        let max_concurrent_builds = max_concurrent_builds.max(1);
        Self {
            pending: Mutex::default(),
            fanout_pending: Mutex::default(),
            max_delivery_workers: max_delivery_workers.max(1),
            pending_slots: Arc::new(Semaphore::new(max_pending.max(1))),
            ready: Notify::new(),
            build_permits: Semaphore::new(max_concurrent_builds),
        }
    }

    /// Size the build bound from the persistence pool that every build reads.
    #[must_use]
    pub fn for_db_connections(max_connections: u32) -> Self {
        let max_connections = usize::try_from(max_connections).unwrap_or(usize::MAX);
        let builds = max_connections
            .saturating_mul(SNAPSHOT_BUILDS_PER_DB_CONNECTION)
            .max(MIN_CONCURRENT_SNAPSHOT_BUILDS);
        Self::with_limits(builds, builds.max(MIN_CONCURRENT_DELIVERY_WORKERS))
    }

    #[cfg(test)]
    fn max_concurrent_builds(&self) -> usize {
        self.build_permits.available_permits()
    }

    /// Run one snapshot build under the concurrency bound. The deadline starts
    /// only once a permit is held so queued builds do not spend their budget
    /// waiting.
    async fn run_bounded_build<T>(
        &self,
        build: impl Future<Output = T>,
    ) -> Result<T, tokio::time::error::Elapsed> {
        let _permit = self
            .build_permits
            .acquire()
            .await
            .expect("snapshot build semaphore is never closed");
        tokio::time::timeout(CONFIG_SNAPSHOT_BUILD_TIMEOUT, build).await
    }

    fn enqueue(&self, key: DeliveryKey) -> DeliveryEnqueue {
        let mut pending = self.pending.lock().unwrap();
        if let Some(entry) = pending.changed.get_mut(&key) {
            entry.changed = true;
            return DeliveryEnqueue::Coalesced;
        }
        let Ok(slot) = Arc::clone(&self.pending_slots).try_acquire_owned() else {
            return DeliveryEnqueue::Full;
        };
        self.admit(&mut pending, key, slot)
    }

    fn admit(
        &self,
        pending: &mut PendingDeliveries,
        key: DeliveryKey,
        slot: OwnedSemaphorePermit,
    ) -> DeliveryEnqueue {
        pending.changed.insert(
            key.clone(),
            PendingDelivery {
                changed: true,
                _slot: slot,
            },
        );
        pending.ready.push_back(key);
        self.ready.notify_one();
        if pending.dispatcher_running {
            DeliveryEnqueue::Queued
        } else {
            pending.dispatcher_running = true;
            DeliveryEnqueue::StartDispatcher
        }
    }

    async fn enqueue_from_fanout(&self, key: DeliveryKey) -> DeliveryEnqueue {
        {
            let mut pending = self.pending.lock().unwrap();
            if let Some(entry) = pending.changed.get_mut(&key) {
                entry.changed = true;
                return DeliveryEnqueue::Coalesced;
            }
        }
        // The fair semaphore reserves released slots for waiting fanouts, so
        // a stream of new direct publications cannot repeatedly bypass repair.
        let slot = Arc::clone(&self.pending_slots)
            .acquire_owned()
            .await
            .expect("pending delivery semaphore is never closed");
        let mut pending = self.pending.lock().unwrap();
        if let Some(entry) = pending.changed.get_mut(&key) {
            entry.changed = true;
            DeliveryEnqueue::Coalesced
        } else {
            self.admit(&mut pending, key, slot)
        }
    }

    fn take_ready(&self) -> Option<DeliveryKey> {
        let mut pending = self.pending.lock().unwrap();
        let key = pending.ready.pop_front()?;
        pending.changed.get_mut(&key).unwrap().changed = false;
        Some(key)
    }

    fn finish_pass(&self, key: &DeliveryKey) {
        let mut pending = self.pending.lock().unwrap();
        if pending.changed.get(key).is_some_and(|entry| entry.changed) {
            pending.ready.push_back(key.clone());
        } else {
            pending.changed.remove(key);
        }
    }

    fn stop_if_idle(&self) -> bool {
        let mut pending = self.pending.lock().unwrap();
        if pending.ready.is_empty() {
            pending.dispatcher_running = false;
            true
        } else {
            false
        }
    }

    fn enqueue_fanout(&self, key: FanoutKey) -> FanoutEnqueue {
        let mut pending = self.fanout_pending.lock().unwrap();
        if let Some(changed) = pending.get_mut(&key) {
            *changed = true;
            return FanoutEnqueue::Coalesced;
        }
        // Reserve the two all-connected component scopes for overflow repair,
        // even when workspace fanout admission is full.
        let reserved_repair = matches!(key.scope, FanoutScope::AllConnected);
        if !reserved_repair && pending.len() >= MAX_ACTIVE_FANOUT_WORKERS {
            FanoutEnqueue::Full
        } else {
            pending.insert(key, true);
            FanoutEnqueue::StartWorker
        }
    }

    fn take_fanout(&self, key: &FanoutKey) {
        let mut pending = self.fanout_pending.lock().unwrap();
        if let Some(changed) = pending.get_mut(key) {
            *changed = false;
        }
    }

    fn finish_fanout_pass(&self, key: &FanoutKey) -> bool {
        let mut pending = self.fanout_pending.lock().unwrap();
        if pending.get(key).is_some_and(|changed| !changed) {
            pending.remove(key);
            false
        } else {
            pending.contains_key(key)
        }
    }
}

#[derive(Debug)]
enum DeliveryEnqueue {
    StartDispatcher,
    Queued,
    Coalesced,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FanoutEnqueue {
    StartWorker,
    Coalesced,
    Full,
}

pub async fn build_config_bootstrap(
    state: &Arc<ServerState>,
    sandbox: &Sandbox,
    timeout: Duration,
) -> Result<ConfigBootstrap, Status> {
    tokio::time::timeout(timeout, build_consistent_config_bootstrap(state, sandbox))
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

pub fn publish_sandbox_components(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    components: ConfigComponents,
) {
    enqueue_sandbox(state, sandbox_id, components);
}

fn enqueue_sandbox(state: &Arc<ServerState>, sandbox_id: &str, components: ConfigComponents) {
    for component in components.selected() {
        let key = DeliveryKey {
            sandbox_id: sandbox_id.to_string(),
            component,
        };
        match state.config_delivery_queue.enqueue(key.clone()) {
            DeliveryEnqueue::StartDispatcher => {
                spawn_delivery_dispatcher(state);
            }
            DeliveryEnqueue::Coalesced | DeliveryEnqueue::Queued => {}
            DeliveryEnqueue::Full => {
                record_delivery_worker_full(sandbox_id, component.name());
                // Retain the recovery obligation as one coalesced fleet pass,
                // rather than a task or retry timer for every rejected key.
                enqueue_fanout(
                    state,
                    FanoutScope::AllConnected,
                    ConfigComponents {
                        sandbox_config: component == ConfigComponentKind::SandboxConfig,
                        provider_environment: component == ConfigComponentKind::ProviderEnvironment,
                    },
                );
            }
        }
    }
}

fn spawn_delivery_dispatcher(state: &Arc<ServerState>) {
    let state = Arc::clone(state);
    tokio::spawn(async move {
        let queue = &state.config_delivery_queue;
        let mut workers = JoinSet::new();
        let mut in_flight = HashMap::new();
        loop {
            while workers.len() < queue.max_delivery_workers {
                let Some(key) = queue.take_ready() else {
                    break;
                };
                let worker_state = Arc::clone(&state);
                let worker_key = key.clone();
                let handle = workers.spawn(async move {
                    publish_sandbox_component_now(&worker_state, &worker_key).await;
                });
                in_flight.insert(handle.id(), key);
            }
            // Changing the running flag under the admission lock prevents a
            // publication racing dispatcher exit from losing its wakeup.
            if workers.is_empty() && queue.stop_if_idle() {
                break;
            }
            tokio::select! {
                completed = workers.join_next_with_id(), if !workers.is_empty() => {
                    let id = match completed.expect("nonempty delivery workers") {
                        Ok((id, ())) => id,
                        Err(error) => {
                            // Panic payloads may contain credential backend data.
                            warn!(
                                cancelled = error.is_cancelled(),
                                panicked = error.is_panic(),
                                "supervisor configuration delivery worker failed"
                            );
                            error.id()
                        }
                    };
                    let key = in_flight.remove(&id).expect("delivery task has a key");
                    // Failed builds/routes rely on reconciliation as before.
                    // A concurrent mutation still gets its own subsequent pass.
                    queue.finish_pass(&key);
                }
                () = queue.ready.notified() => {}
            }
        }
    });
}

async fn enqueue_sandbox_from_fanout(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    component: ConfigComponentKind,
) {
    let key = DeliveryKey {
        sandbox_id: sandbox_id.to_string(),
        component,
    };
    match state
        .config_delivery_queue
        .enqueue_from_fanout(key.clone())
        .await
    {
        DeliveryEnqueue::StartDispatcher => spawn_delivery_dispatcher(state),
        DeliveryEnqueue::Coalesced | DeliveryEnqueue::Queued => {}
        DeliveryEnqueue::Full => unreachable!("fanout waits for delivery worker capacity"),
    }
}

async fn publish_sandbox_component_now(state: &Arc<ServerState>, key: &DeliveryKey) {
    let component = key.component.name();
    let build = async {
        let sandbox = state
            .store
            .get_message::<Sandbox>(&key.sandbox_id)
            .await
            .map_err(|error| Status::internal(format!("fetch sandbox failed: {error}")))?;
        let Some(sandbox) = sandbox else {
            return Ok(None);
        };
        match key.component {
            ConfigComponentKind::SandboxConfig => {
                let snapshot = build_sandbox_config_snapshot(state, &sandbox).await?;
                crate::config_update_operation::associate_pending_with_snapshot(
                    state,
                    &key.sandbox_id,
                    &snapshot,
                )
                .await?;
                Ok(SupervisorConfigMessage::SandboxConfig(Box::new(snapshot)))
            }
            ConfigComponentKind::ProviderEnvironment => {
                build_provider_environment_snapshot(state, &sandbox, true)
                    .await
                    .map(SupervisorConfigMessage::ProviderEnvironment)
            }
        }
        .map(Some)
    };
    match state.config_delivery_queue.run_bounded_build(build).await {
        Ok(Ok(None)) => {}
        Ok(Ok(Some(message))) => {
            let disposition = state
                .supervisor_config_router()
                .deliver(&key.sandbox_id, message)
                .await;
            record_delivery(component, disposition);
        }
        Ok(Err(error)) => {
            record_build_failure(&key.sandbox_id, component, error.code());
        }
        Err(_) => {
            record_build_failure(&key.sandbox_id, component, Code::DeadlineExceeded);
        }
    }
}

pub fn publish_workspace_components(
    state: &Arc<ServerState>,
    workspace: &str,
    components: ConfigComponents,
) {
    enqueue_fanout(
        state,
        FanoutScope::Workspace(workspace.to_string()),
        components,
    );
}

pub fn publish_all_connected(state: &Arc<ServerState>, components: ConfigComponents) {
    enqueue_fanout(state, FanoutScope::AllConnected, components);
}

fn enqueue_fanout(state: &Arc<ServerState>, scope: FanoutScope, components: ConfigComponents) {
    for component in components.selected() {
        let key = FanoutKey {
            scope: scope.clone(),
            component,
        };
        match state.config_delivery_queue.enqueue_fanout(key.clone()) {
            FanoutEnqueue::StartWorker => {
                let state = Arc::clone(state);
                tokio::spawn(async move {
                    loop {
                        state.config_delivery_queue.take_fanout(&key);
                        publish_fanout_now(&state, &key).await;
                        if !state.config_delivery_queue.finish_fanout_pass(&key) {
                            break;
                        }
                    }
                });
            }
            FanoutEnqueue::Coalesced => {}
            FanoutEnqueue::Full => {
                counter!("openshell_supervisor_config_fanout_total", "outcome" => "queue_full")
                    .increment(1);
                warn!(
                    component = component.name(),
                    "supervisor configuration fanout queue is full"
                );
            }
        }
    }
}

async fn publish_fanout_now(state: &Arc<ServerState>, key: &FanoutKey) {
    let sandbox_ids = state
        .supervisor_config_router()
        .routable_sandbox_ids()
        .await;
    for sandbox_id in sandbox_ids {
        if let FanoutScope::Workspace(workspace) = &key.scope {
            let sandbox = match state.store.get_message::<Sandbox>(&sandbox_id).await {
                Ok(Some(sandbox)) => sandbox,
                Ok(None) => continue,
                Err(_) => {
                    record_build_failure(&sandbox_id, "sandbox", Code::Internal);
                    continue;
                }
            };
            if sandbox.object_workspace() != workspace {
                continue;
            }
        }
        enqueue_sandbox_from_fanout(state, &sandbox_id, key.component).await;
    }
}

fn record_delivery_worker_full(sandbox_id: &str, component: &'static str) {
    counter!(
        "openshell_supervisor_config_delivery_workers_total",
        "outcome" => "queue_full",
    )
    .increment(1);
    warn!(
        sandbox_id,
        component, "supervisor configuration pending queue is full; scheduling reconciliation"
    );
}

fn record_delivery(component: &'static str, disposition: DeliveryDisposition) {
    let outcome = match disposition {
        DeliveryDisposition::Enqueued => "enqueued",
        DeliveryDisposition::Coalesced => "coalesced",
        DeliveryDisposition::SuppressedUnchanged => "unchanged",
        DeliveryDisposition::NoActiveSession => "no_active_session",
        DeliveryDisposition::QueueFull => "queue_full",
        DeliveryDisposition::SessionClosed => "session_closed",
        DeliveryDisposition::PayloadTooLarge => "payload_too_large",
    };
    counter!(
        "openshell_supervisor_config_deliveries_total",
        "component" => component,
        "outcome" => outcome,
    )
    .increment(1);
}

/// Periodically rebuild current snapshots for every locally routable session.
/// This repairs missed mutation notifications and queue pressure without a
/// supervisor fetch.
pub fn spawn_owner_reconciler(state: Arc<ServerState>, interval: Duration) {
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(interval);
        timer.tick().await;
        loop {
            timer.tick().await;
            publish_all_connected(&state, ConfigComponents::ALL);
        }
    });
}

fn record_build_failure(sandbox_id: &str, component: &'static str, error_code: Code) {
    counter!(
        "openshell_supervisor_config_snapshot_failures_total",
        "component" => component,
    )
    .increment(1);
    warn!(
        sandbox_id = %sandbox_id,
        component,
        ?error_code,
        "failed to build supervisor configuration snapshot"
    );
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::grpc::test_support::{connect_supervisor_stream, test_server_state};
    use openshell_core::proto::{GatewayMessage, ObjectMeta, SandboxSpec, gateway_message};

    fn key(sandbox_id: &str, component: ConfigComponentKind) -> DeliveryKey {
        DeliveryKey {
            sandbox_id: sandbox_id.to_string(),
            component,
        }
    }

    #[test]
    fn queue_coalesces_repeated_component_changes_while_worker_is_active() {
        let queue = ConfigDeliveryQueue::default();
        let key = key("sb-1", ConfigComponentKind::SandboxConfig);
        let DeliveryEnqueue::StartDispatcher = queue.enqueue(key.clone()) else {
            panic!("first publication must start the dispatcher");
        };
        assert_eq!(queue.take_ready(), Some(key.clone()));
        assert!(matches!(
            queue.enqueue(key.clone()),
            DeliveryEnqueue::Coalesced
        ));
        assert!(matches!(
            queue.enqueue(key.clone()),
            DeliveryEnqueue::Coalesced
        ));
        queue.finish_pass(&key);
        assert_eq!(queue.take_ready(), Some(key.clone()));
        queue.finish_pass(&key);
        assert!(queue.take_ready().is_none());
        assert!(queue.stop_if_idle());
    }

    #[test]
    fn pending_work_is_bounded_coalesced_and_fair_to_other_keys() {
        let queue = ConfigDeliveryQueue::with_pending_capacity(1, 1, 3);
        let a = key("a", ConfigComponentKind::SandboxConfig);
        let b = key("b", ConfigComponentKind::SandboxConfig);
        let c = key("c", ConfigComponentKind::SandboxConfig);
        assert!(matches!(
            queue.enqueue(a.clone()),
            DeliveryEnqueue::StartDispatcher
        ));
        assert_eq!(queue.take_ready(), Some(a.clone()));
        assert!(matches!(queue.enqueue(b.clone()), DeliveryEnqueue::Queued));
        assert!(matches!(queue.enqueue(c.clone()), DeliveryEnqueue::Queued));
        for _ in 0..100 {
            assert!(matches!(
                queue.enqueue(a.clone()),
                DeliveryEnqueue::Coalesced
            ));
            assert!(matches!(
                queue.enqueue(b.clone()),
                DeliveryEnqueue::Coalesced
            ));
        }
        for i in 0..10_000 {
            assert!(matches!(
                queue.enqueue(key(
                    &format!("overflow-{i}"),
                    ConfigComponentKind::SandboxConfig
                )),
                DeliveryEnqueue::Full
            ));
        }
        assert_eq!(queue.pending.lock().unwrap().changed.len(), 3);
        queue.finish_pass(&a);
        // The running key's new state goes behind both previously queued keys.
        for expected in [b, c, a] {
            assert_eq!(queue.take_ready(), Some(expected.clone()));
            queue.finish_pass(&expected);
        }
        assert!(queue.take_ready().is_none());
        assert_eq!(queue.pending_slots.available_permits(), 3);
        assert!(queue.stop_if_idle());
        assert!(matches!(
            queue.enqueue(key("new", ConfigComponentKind::SandboxConfig)),
            DeliveryEnqueue::StartDispatcher
        ));
    }

    #[tokio::test]
    async fn waiting_fanout_reserves_capacity_ahead_of_new_direct_work() {
        let queue = ConfigDeliveryQueue::with_pending_capacity(1, 1, 1);
        let a = key("a", ConfigComponentKind::SandboxConfig);
        let b = key("b", ConfigComponentKind::SandboxConfig);
        queue.enqueue(a.clone());
        assert_eq!(queue.take_ready(), Some(a.clone()));
        let waiting = queue.enqueue_from_fanout(b.clone());
        tokio::pin!(waiting);
        tokio::select! {
            biased;
            _ = &mut waiting => panic!("queue must be full"),
            () = tokio::task::yield_now() => {}
        }
        queue.finish_pass(&a);
        assert!(matches!(
            queue.enqueue(key("new", ConfigComponentKind::SandboxConfig)),
            DeliveryEnqueue::Full
        ));
        assert!(matches!(waiting.await, DeliveryEnqueue::Queued));
        assert_eq!(queue.take_ready(), Some(b));
    }

    #[test]
    fn idle_dispatcher_exit_does_not_lose_new_publications() {
        let queue = ConfigDeliveryQueue::new(1);
        let a = key("a", ConfigComponentKind::SandboxConfig);
        queue.enqueue(a.clone());
        queue.take_ready();
        queue.finish_pass(&a);
        // A publication before the exit check keeps this dispatcher alive.
        assert!(matches!(queue.enqueue(a.clone()), DeliveryEnqueue::Queued));
        assert!(!queue.stop_if_idle());
        queue.take_ready();
        queue.finish_pass(&a);
        assert!(queue.stop_if_idle());
        // A publication after the exit check starts a replacement dispatcher.
        assert!(matches!(queue.enqueue(a), DeliveryEnqueue::StartDispatcher));
    }

    #[derive(Debug)]
    struct GatedRouter {
        visits: tokio::sync::mpsc::UnboundedSender<String>,
        release: Semaphore,
        panic_next: std::sync::atomic::AtomicBool,
    }

    #[tonic::async_trait]
    impl SupervisorConfigRouter for GatedRouter {
        async fn deliver(
            &self,
            sandbox_id: &str,
            _message: SupervisorConfigMessage,
        ) -> DeliveryDisposition {
            self.visits.send(sandbox_id.to_string()).unwrap();
            assert!(
                !self.panic_next.swap(false, Ordering::SeqCst),
                "injected worker failure"
            );
            self.release.acquire().await.unwrap().forget();
            DeliveryDisposition::Enqueued
        }

        async fn routable_sandbox_ids(&self) -> Vec<String> {
            vec!["a".into(), "b".into(), "c".into()]
        }
    }

    async fn gated_delivery_state(
        capacity: usize,
    ) -> (
        Arc<ServerState>,
        Arc<GatedRouter>,
        tokio::sync::mpsc::UnboundedReceiver<String>,
    ) {
        let mut state = test_server_state().await;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let router = Arc::new(GatedRouter {
            visits: tx,
            release: Semaphore::new(0),
            panic_next: std::sync::atomic::AtomicBool::new(false),
        });
        let mutable = Arc::get_mut(&mut state).unwrap();
        mutable.config_delivery_queue = ConfigDeliveryQueue::with_pending_capacity(1, 1, capacity);
        mutable.supervisor_config_router = router.clone();
        for id in ["a", "b", "c"] {
            state
                .store
                .put_message(&Sandbox {
                    metadata: Some(ObjectMeta {
                        id: id.into(),
                        name: id.into(),
                        workspace: "default".into(),
                        ..Default::default()
                    }),
                    spec: Some(SandboxSpec::default()),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        (state, router, rx)
    }

    async fn next_visit(rx: &mut tokio::sync::mpsc::UnboundedReceiver<String>) -> String {
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap()
    }

    async fn wait_until_drained(state: &ServerState) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if !state
                    .config_delivery_queue
                    .pending
                    .lock()
                    .unwrap()
                    .dispatcher_running
                    && state
                        .config_delivery_queue
                        .fanout_pending
                        .lock()
                        .unwrap()
                        .is_empty()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn queued_changes_and_mutations_during_delivery_drain_without_reconciliation() {
        let (state, router, mut rx) = gated_delivery_state(3).await;
        publish_sandbox_components(&state, "a", ConfigComponents::SANDBOX_CONFIG);
        assert_eq!(next_visit(&mut rx).await, "a");
        for id in ["b", "b", "c", "a", "a"] {
            publish_sandbox_components(&state, id, ConfigComponents::SANDBOX_CONFIG);
        }
        assert!(rx.try_recv().is_err(), "only one worker may run");
        for expected in ["b", "c", "a"] {
            router.release.add_permits(1);
            assert_eq!(next_visit(&mut rx).await, expected);
        }
        router.release.add_permits(1);
        wait_until_drained(&state).await;
        assert!(rx.try_recv().is_err());
        assert_eq!(
            state
                .config_delivery_queue
                .pending_slots
                .available_permits(),
            3
        );
    }

    #[tokio::test]
    async fn worker_panic_does_not_strand_pending_work() {
        let (state, router, mut rx) = gated_delivery_state(3).await;
        router.panic_next.store(true, Ordering::SeqCst);
        router.release.add_permits(1);
        publish_sandbox_components(&state, "a", ConfigComponents::SANDBOX_CONFIG);
        publish_sandbox_components(&state, "b", ConfigComponents::SANDBOX_CONFIG);
        assert_eq!(next_visit(&mut rx).await, "a");
        assert_eq!(next_visit(&mut rx).await, "b");
        wait_until_drained(&state).await;
        assert_eq!(
            state
                .config_delivery_queue
                .pending_slots
                .available_permits(),
            3
        );
    }

    #[tokio::test]
    async fn overflow_repairs_rejected_keys_without_periodic_reconciliation() {
        let (state, router, mut rx) = gated_delivery_state(1).await;
        publish_sandbox_components(&state, "a", ConfigComponents::SANDBOX_CONFIG);
        assert_eq!(next_visit(&mut rx).await, "a");
        publish_sandbox_components(&state, "b", ConfigComponents::SANDBOX_CONFIG);
        publish_sandbox_components(&state, "c", ConfigComponents::SANDBOX_CONFIG);
        assert_eq!(
            state
                .config_delivery_queue
                .pending
                .lock()
                .unwrap()
                .changed
                .len(),
            1
        );
        assert!(
            state
                .config_delivery_queue
                .fanout_pending
                .lock()
                .unwrap()
                .len()
                <= 1
        );
        router.release.add_permits(16);
        let mut observed = std::collections::HashSet::new();
        while !observed.contains("b") || !observed.contains("c") {
            observed.insert(next_visit(&mut rx).await);
        }
        wait_until_drained(&state).await;
        // No owner reconciler was started in this fixture.
    }

    #[test]
    fn build_bound_is_sized_from_the_database_pool() {
        let local = ConfigDeliveryQueue::for_db_connections(5);
        assert_eq!(local.max_concurrent_builds(), 10);
        assert_eq!(local.max_delivery_workers, 64);
        assert_eq!(
            ConfigDeliveryQueue::for_db_connections(10).max_concurrent_builds(),
            20
        );
        assert_eq!(
            ConfigDeliveryQueue::for_db_connections(1).max_concurrent_builds(),
            MIN_CONCURRENT_SNAPSHOT_BUILDS
        );
        assert_eq!(ConfigDeliveryQueue::new(0).max_concurrent_builds(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn bounded_builds_never_exceed_the_permit_count() {
        const PERMITS: usize = 4;
        const BUILDS: usize = 40;
        let queue = Arc::new(ConfigDeliveryQueue::new(PERMITS));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let workers = (0..BUILDS)
            .map(|_| {
                let queue = Arc::clone(&queue);
                let active = Arc::clone(&active);
                let peak = Arc::clone(&peak);
                tokio::spawn(async move {
                    queue
                        .run_bounded_build(async {
                            let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                            peak.fetch_max(now, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            active.fetch_sub(1, Ordering::SeqCst);
                        })
                        .await
                        .expect("build must not time out");
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.await.unwrap();
        }

        assert_eq!(peak.load(Ordering::SeqCst), PERMITS);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(queue.max_concurrent_builds(), PERMITS);
    }

    #[tokio::test(start_paused = true)]
    async fn build_deadline_starts_after_a_permit_is_held() {
        let queue = Arc::new(ConfigDeliveryQueue::new(1));
        let almost_deadline = CONFIG_SNAPSHOT_BUILD_TIMEOUT
            .checked_sub(Duration::from_secs(1))
            .unwrap();
        let first = {
            let queue = Arc::clone(&queue);
            tokio::spawn(async move {
                queue
                    .run_bounded_build(tokio::time::sleep(almost_deadline))
                    .await
            })
        };
        tokio::task::yield_now().await;
        let second = queue.run_bounded_build(tokio::time::sleep(almost_deadline));

        let (first, second) = tokio::join!(first, second);
        assert!(first.unwrap().is_ok());
        assert!(
            second.is_ok(),
            "waiting for a permit must not consume the build deadline"
        );

        assert!(
            queue
                .run_bounded_build(tokio::time::sleep(
                    CONFIG_SNAPSHOT_BUILD_TIMEOUT + Duration::from_secs(1),
                ))
                .await
                .is_err()
        );
    }

    #[test]
    fn queue_runs_components_and_sandboxes_independently() {
        let queue = ConfigDeliveryQueue::new(3);
        assert!(matches!(
            queue.enqueue(key("sb-1", ConfigComponentKind::SandboxConfig)),
            DeliveryEnqueue::StartDispatcher
        ));
        assert!(matches!(
            queue.enqueue(key("sb-1", ConfigComponentKind::ProviderEnvironment)),
            DeliveryEnqueue::Queued
        ));
        assert!(matches!(
            queue.enqueue(key("sb-2", ConfigComponentKind::SandboxConfig)),
            DeliveryEnqueue::Queued
        ));
    }

    #[tokio::test]
    async fn fleet_fanout_waits_without_creating_unbounded_delivery_workers() {
        const ROUTED_SANDBOXES: usize = 10_000;
        let queue = Arc::new(ConfigDeliveryQueue::with_pending_capacity(1, 1, 2));
        let first = key("sandbox-0", ConfigComponentKind::SandboxConfig);
        let DeliveryEnqueue::StartDispatcher = queue.enqueue(first) else {
            panic!("first publication must start the dispatcher");
        };

        let sandbox_ids = (1..ROUTED_SANDBOXES)
            .map(|index| format!("sandbox-{index}"))
            .collect::<Vec<_>>();
        let fanout = async {
            for sandbox_id in sandbox_ids {
                for component in ConfigComponents::ALL.selected() {
                    let _ = queue.enqueue_from_fanout(key(&sandbox_id, component)).await;
                }
            }
        };
        tokio::pin!(fanout);
        tokio::select! {
            () = &mut fanout => panic!("fanout must wait for worker capacity"),
            () = tokio::task::yield_now() => {}
        }

        assert_eq!(queue.pending.lock().unwrap().changed.len(), 2);
    }

    #[test]
    fn fanout_queue_coalesces_and_bounds_distinct_scopes() {
        let queue = ConfigDeliveryQueue::default();
        let first = FanoutKey {
            scope: FanoutScope::Workspace("workspace-0".into()),
            component: ConfigComponentKind::SandboxConfig,
        };
        assert_eq!(
            queue.enqueue_fanout(first.clone()),
            FanoutEnqueue::StartWorker
        );
        queue.take_fanout(&first);
        assert_eq!(
            queue.enqueue_fanout(first.clone()),
            FanoutEnqueue::Coalesced
        );
        assert!(queue.finish_fanout_pass(&first));

        for index in 1..MAX_ACTIVE_FANOUT_WORKERS {
            assert_eq!(
                queue.enqueue_fanout(FanoutKey {
                    scope: FanoutScope::Workspace(format!("workspace-{index}")),
                    component: ConfigComponentKind::SandboxConfig,
                }),
                FanoutEnqueue::StartWorker
            );
        }
        assert_eq!(
            queue.enqueue_fanout(FanoutKey {
                scope: FanoutScope::Workspace("overflow".into()),
                component: ConfigComponentKind::SandboxConfig,
            }),
            FanoutEnqueue::Full
        );
        for component in ConfigComponents::ALL.selected() {
            let repair = FanoutKey {
                scope: FanoutScope::AllConnected,
                component,
            };
            assert_eq!(
                queue.enqueue_fanout(repair.clone()),
                FanoutEnqueue::StartWorker
            );
            assert_eq!(queue.enqueue_fanout(repair), FanoutEnqueue::Coalesced);
        }
        assert_eq!(
            queue.fanout_pending.lock().unwrap().len(),
            MAX_ACTIVE_FANOUT_WORKERS + 2
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
        let state = test_server_state().await;
        state
            .store
            .put_message(&Sandbox {
                metadata: Some(ObjectMeta {
                    id: "sandbox".into(),
                    name: "sandbox".into(),
                    workspace: "default".into(),
                    ..Default::default()
                }),
                spec: Some(SandboxSpec::default()),
                ..Default::default()
            })
            .await
            .unwrap();

        let mut harness = connect_supervisor_stream(
            &state,
            "sandbox",
            openshell_core::proto::SUPERVISOR_PROTOCOL_REVISION,
        )
        .await
        .unwrap();

        let first = tokio::time::timeout(Duration::from_secs(5), harness.inbound.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(
            first.payload,
            Some(gateway_message::Payload::SessionAccepted(_))
        ));

        publish_sandbox_components(&state, "sandbox", ConfigComponents::SANDBOX_CONFIG);
        let update = tokio::time::timeout(Duration::from_secs(5), harness.inbound.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(
            update,
            GatewayMessage {
                payload: Some(gateway_message::Payload::ConfigUpdate(_))
            }
        ));
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
}
