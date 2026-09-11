// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Build and route complete supervisor configuration snapshots.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use metrics::counter;
use openshell_core::proto::{
    ConfigBootstrap, ProviderEnvironmentSnapshot, Sandbox, SandboxConfigSnapshot,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
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
// Stage 1 bootstrap is optional. Keep credential backend stalls well below
// the 15-second relay session-wait budget while polling remains authoritative.
pub const OPTIONAL_CONFIG_BOOTSTRAP_BUILD_TIMEOUT: Duration = Duration::from_secs(1);
// Stage 2 supervisors apply the bootstrap directly, so allow the same bounded
// build window as an ordinary complete snapshot before rejecting the session.
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
/// The map entry is also the worker lease. Its boolean is set when another
/// mutation arrives during a build or route operation. The worker then rebuilds
/// the current full snapshot once, regardless of how many mutations arrived.
///
/// Each pending map entry owns a delivery permit for its worker. Direct
/// publications fail fast when all permits are held. Fanout workers wait for a
/// permit before admitting the next recipient, which bounds both spawned tasks
/// and pending keys while still walking the full recipient list.
#[derive(Debug)]
pub struct ConfigDeliveryQueue {
    pending: Mutex<HashMap<DeliveryKey, bool>>,
    fanout_pending: Mutex<HashMap<FanoutKey, bool>>,
    delivery_permits: Arc<Semaphore>,
    build_permits: Semaphore,
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
        let max_concurrent_builds = max_concurrent_builds.max(1);
        Self {
            pending: Mutex::default(),
            fanout_pending: Mutex::default(),
            delivery_permits: Arc::new(Semaphore::new(max_delivery_workers.max(1))),
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
        match pending.entry(key) {
            Entry::Occupied(mut entry) => {
                *entry.get_mut() = true;
                DeliveryEnqueue::Coalesced
            }
            Entry::Vacant(entry) => {
                let Ok(permit) = Arc::clone(&self.delivery_permits).try_acquire_owned() else {
                    return DeliveryEnqueue::Full;
                };
                entry.insert(true);
                DeliveryEnqueue::StartWorker(permit)
            }
        }
    }

    async fn enqueue_from_fanout(&self, key: DeliveryKey) -> DeliveryEnqueue {
        {
            let mut pending = self.pending.lock().unwrap();
            if let Entry::Occupied(mut entry) = pending.entry(key.clone()) {
                *entry.get_mut() = true;
                return DeliveryEnqueue::Coalesced;
            }
        }

        let permit = Arc::clone(&self.delivery_permits)
            .acquire_owned()
            .await
            .expect("delivery worker semaphore is never closed");
        let mut pending = self.pending.lock().unwrap();
        match pending.entry(key) {
            Entry::Occupied(mut entry) => {
                *entry.get_mut() = true;
                DeliveryEnqueue::Coalesced
            }
            Entry::Vacant(entry) => {
                entry.insert(true);
                DeliveryEnqueue::StartWorker(permit)
            }
        }
    }

    fn take(&self, key: &DeliveryKey) {
        let mut pending = self.pending.lock().unwrap();
        if let Some(changed) = pending.get_mut(key) {
            *changed = false;
        }
    }

    fn finish_pass(&self, key: &DeliveryKey) -> bool {
        let mut pending = self.pending.lock().unwrap();
        if pending.get(key).is_some_and(|changed| !changed) {
            pending.remove(key);
            false
        } else {
            pending.contains_key(key)
        }
    }

    fn enqueue_fanout(&self, key: FanoutKey) -> FanoutEnqueue {
        let mut pending = self.fanout_pending.lock().unwrap();
        if let Some(changed) = pending.get_mut(&key) {
            *changed = true;
            return FanoutEnqueue::Coalesced;
        }
        if pending.len() >= MAX_ACTIVE_FANOUT_WORKERS {
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
    StartWorker(OwnedSemaphorePermit),
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
            DeliveryEnqueue::StartWorker(permit) => {
                spawn_delivery_worker(state, key, permit);
            }
            DeliveryEnqueue::Coalesced => {}
            DeliveryEnqueue::Full => {
                record_delivery_worker_full(sandbox_id, component.name());
            }
        }
    }
}

fn spawn_delivery_worker(state: &Arc<ServerState>, key: DeliveryKey, permit: OwnedSemaphorePermit) {
    let state = Arc::clone(state);
    tokio::spawn(async move {
        let _permit = permit;
        loop {
            state.config_delivery_queue.take(&key);
            publish_sandbox_component_now(&state, &key).await;
            if !state.config_delivery_queue.finish_pass(&key) {
                break;
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
        DeliveryEnqueue::StartWorker(permit) => spawn_delivery_worker(state, key, permit),
        DeliveryEnqueue::Coalesced => {}
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
            ConfigComponentKind::SandboxConfig => build_sandbox_config_snapshot(state, &sandbox)
                .await
                .map(|snapshot| SupervisorConfigMessage::SandboxConfig(Box::new(snapshot))),
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
        component, "supervisor configuration delivery worker queue is full"
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
        let DeliveryEnqueue::StartWorker(permit) = queue.enqueue(key.clone()) else {
            panic!("first publication must start a worker");
        };
        queue.take(&key);
        assert!(matches!(
            queue.enqueue(key.clone()),
            DeliveryEnqueue::Coalesced
        ));
        assert!(matches!(
            queue.enqueue(key.clone()),
            DeliveryEnqueue::Coalesced
        ));
        assert!(queue.finish_pass(&key));
        queue.take(&key);
        assert!(!queue.finish_pass(&key));
        drop(permit);
    }

    #[test]
    fn build_bound_is_sized_from_the_database_pool() {
        let local = ConfigDeliveryQueue::for_db_connections(5);
        assert_eq!(local.max_concurrent_builds(), 10);
        assert_eq!(local.delivery_permits.available_permits(), 64);
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
            DeliveryEnqueue::StartWorker(_)
        ));
        assert!(matches!(
            queue.enqueue(key("sb-1", ConfigComponentKind::ProviderEnvironment)),
            DeliveryEnqueue::StartWorker(_)
        ));
        assert!(matches!(
            queue.enqueue(key("sb-2", ConfigComponentKind::SandboxConfig)),
            DeliveryEnqueue::StartWorker(_)
        ));
    }

    #[tokio::test]
    async fn fleet_fanout_waits_without_creating_unbounded_delivery_workers() {
        const ROUTED_SANDBOXES: usize = 10_000;
        let queue = Arc::new(ConfigDeliveryQueue::new(1));
        let first = key("sandbox-0", ConfigComponentKind::SandboxConfig);
        let DeliveryEnqueue::StartWorker(_blocked_worker) = queue.enqueue(first) else {
            panic!("first publication must start a worker");
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

        assert_eq!(queue.pending.lock().unwrap().len(), 1);
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

    #[tokio::test]
    async fn stalled_credentials_do_not_block_session_acceptance() {
        use openshell_core::proto::{CredentialHandle, Provider};

        let state = test_server_state().await;
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
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();
        let (resolve_hit, _release_resolve) = state.credentials.gate_next_resolve();
        tokio::time::timeout(Duration::from_secs(10), async {
            let connect = connect_supervisor_stream(
                &state,
                "sandbox",
                openshell_core::proto::PREVIOUS_SUPERVISOR_PROTOCOL_REVISION,
            );
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
