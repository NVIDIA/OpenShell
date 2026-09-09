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
const MAX_ACTIVE_FANOUT_WORKERS: usize = 64;

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

    fn only(component: ConfigComponentKind) -> Self {
        Self {
            sandbox_config: component == ConfigComponentKind::SandboxConfig,
            provider_environment: component == ConfigComponentKind::ProviderEnvironment,
        }
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

/// Coalesces publications and runs one worker per sandbox and component.
///
/// The map entry is also the worker lease. Its boolean is set when another
/// mutation arrives during a build or route operation. The worker then rebuilds
/// the current full snapshot once, regardless of how many mutations arrived.
#[derive(Debug, Default)]
pub struct ConfigDeliveryQueue {
    pending: Mutex<HashMap<DeliveryKey, bool>>,
    fanout_pending: Mutex<HashMap<FanoutKey, bool>>,
}

impl ConfigDeliveryQueue {
    fn enqueue(&self, key: DeliveryKey) -> bool {
        let mut pending = self.pending.lock().unwrap();
        match pending.entry(key) {
            Entry::Occupied(mut entry) => {
                *entry.get_mut() = true;
                false
            }
            Entry::Vacant(entry) => {
                entry.insert(true);
                true
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FanoutEnqueue {
    StartWorker,
    Coalesced,
    Full,
}

pub async fn build_config_bootstrap(
    state: &Arc<ServerState>,
    sandbox: &Sandbox,
) -> Result<ConfigBootstrap, Status> {
    tokio::time::timeout(
        CONFIG_SNAPSHOT_BUILD_TIMEOUT,
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
        if state.config_delivery_queue.enqueue(key.clone()) {
            let state = Arc::clone(state);
            tokio::spawn(async move {
                loop {
                    state.config_delivery_queue.take(&key);
                    publish_sandbox_component_now(&state, &key).await;
                    if !state.config_delivery_queue.finish_pass(&key) {
                        break;
                    }
                }
            });
        }
    }
}

async fn publish_sandbox_component_now(state: &Arc<ServerState>, key: &DeliveryKey) {
    let sandbox = match state.store.get_message::<Sandbox>(&key.sandbox_id).await {
        Ok(Some(sandbox)) => sandbox,
        Ok(None) => return,
        Err(_) => {
            record_build_failure(&key.sandbox_id, "sandbox", Code::Internal);
            return;
        }
    };
    let component = key.component.name();
    let build = async {
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
    };
    match tokio::time::timeout(CONFIG_SNAPSHOT_BUILD_TIMEOUT, build).await {
        Ok(Ok(message)) => {
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
        enqueue_sandbox(state, &sandbox_id, ConfigComponents::only(key.component));
    }
}

fn record_delivery(component: &'static str, disposition: DeliveryDisposition) {
    let outcome = match disposition {
        DeliveryDisposition::Enqueued => "enqueued",
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
    use super::*;
    use crate::grpc::{OpenShellService, test_support::test_server_state};
    use openshell_core::proto::{
        GatewayMessage, ObjectMeta, SandboxSpec, SupervisorHello, SupervisorMessage,
        gateway_message, open_shell_client::OpenShellClient, open_shell_server::OpenShellServer,
        supervisor_message,
    };
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};

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
        assert!(queue.enqueue(key.clone()));
        queue.take(&key);
        assert!(!queue.enqueue(key.clone()));
        assert!(!queue.enqueue(key.clone()));
        assert!(queue.finish_pass(&key));
        queue.take(&key);
        assert!(!queue.finish_pass(&key));
    }

    #[test]
    fn queue_runs_components_and_sandboxes_independently() {
        let queue = ConfigDeliveryQueue::default();
        assert!(queue.enqueue(key("sb-1", ConfigComponentKind::SandboxConfig)));
        assert!(queue.enqueue(key("sb-1", ConfigComponentKind::ProviderEnvironment)));
        assert!(queue.enqueue(key("sb-2", ConfigComponentKind::SandboxConfig)));
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

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(OpenShellServer::new(OpenShellService::new(Arc::clone(
                    &state,
                ))))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        let mut client = OpenShellClient::connect(format!("http://{address}"))
            .await
            .unwrap();
        let (tx, rx) = mpsc::channel(4);
        tx.send(SupervisorMessage {
            payload: Some(supervisor_message::Payload::Hello(SupervisorHello {
                sandbox_id: "sandbox".into(),
                instance_id: "instance".into(),
                protocol_revision: openshell_core::proto::SUPERVISOR_PROTOCOL_REVISION,
            })),
        })
        .await
        .unwrap();
        let mut stream = client
            .connect_supervisor(ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();

        let first = tokio::time::timeout(Duration::from_secs(5), stream.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(
            first.payload,
            Some(gateway_message::Payload::SessionAccepted(_))
        ));

        publish_sandbox_components(&state, "sandbox", ConfigComponents::SANDBOX_CONFIG);
        let update = tokio::time::timeout(Duration::from_secs(5), stream.message())
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

        drop(tx);
        server.abort();
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
