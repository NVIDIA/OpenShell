// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    ServerState,
    grpc::policy,
    inference,
    persistence::{ObjectCursor, ObjectId, ObjectType, ObjectWorkspace},
    supervisor_session::SupervisorSessionRegistry,
};
use openshell_core::proto::{ConfigBootstrap, ConfigUpdate, Sandbox, config_update};
use prost::Message;
use std::{
    fmt,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::sync::mpsc;

#[cfg(test)]
mod tests;

// Leave room below tonic's default 4 MiB decode limit for envelope metadata.
pub(crate) const MAX_CONFIG_BYTES: usize = 3 * 1024 * 1024;
const PUBLISH_QUEUE_CAPACITY: usize = 64;
const BUILD_TIMEOUT: Duration = Duration::from_secs(3);

pub enum SupervisorConfigMessage {
    Bootstrap(Box<ConfigBootstrap>),
    Update(Box<ConfigUpdate>),
}

impl fmt::Debug for SupervisorConfigMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bootstrap(_) => "ConfigBootstrap(<redacted>)",
            Self::Update(_) => "ConfigUpdate(<redacted>)",
        })
    }
}

impl SupervisorConfigMessage {
    pub(crate) fn encoded_len(&self) -> usize {
        match self {
            Self::Bootstrap(value) => value.encoded_len(),
            Self::Update(value) => value.encoded_len(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryDisposition {
    Delivered,
    NoActiveSession,
    RemoteOwnerUnavailable,
    QueueUnavailable,
    PayloadConstructionFailed,
    PayloadTooLarge,
    InvalidComponent,
}

impl DeliveryDisposition {
    fn label(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::NoActiveSession => "no_active_session",
            Self::RemoteOwnerUnavailable => "remote_owner_unavailable",
            Self::QueueUnavailable => "queue_unavailable",
            Self::PayloadConstructionFailed => "payload_construction_failed",
            Self::PayloadTooLarge => "payload_too_large",
            Self::InvalidComponent => "invalid_component",
        }
    }
}

#[tonic::async_trait]
pub trait SupervisorConfigRouter: fmt::Debug + Send + Sync {
    /// The session owner assigns update IDs and component sequences when enqueueing.
    async fn deliver(
        &self,
        sandbox_id: &str,
        message: SupervisorConfigMessage,
    ) -> DeliveryDisposition;
}

#[derive(Debug)]
pub struct LocalSupervisorConfigRouter {
    sessions: Arc<SupervisorSessionRegistry>,
}

impl LocalSupervisorConfigRouter {
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
        if message.encoded_len() > MAX_CONFIG_BYTES {
            return DeliveryDisposition::PayloadTooLarge;
        }
        self.sessions.deliver_config(sandbox_id, message)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Components {
    ConfigAndProviders,
    Inference,
    All,
}

#[derive(Debug)]
pub(crate) enum ConfigChange {
    Sandbox(String, Components),
    Workspace(String, Components),
    ProviderProfile(String),
    Global(Components),
}

#[derive(Debug, Default)]
pub(crate) struct SupervisorConfigPublisher {
    sender: OnceLock<mpsc::Sender<ConfigChange>>,
}

impl SupervisorConfigPublisher {
    /// Call only after the authoritative write has committed. Contains no payloads.
    pub(crate) fn publish(&self, state: &Arc<ServerState>, change: ConfigChange) {
        let sender = self.sender.get_or_init(|| {
            let (tx, mut rx) = mpsc::channel(PUBLISH_QUEUE_CAPACITY);
            let weak = Arc::downgrade(state);
            tokio::spawn(async move {
                while let Some(change) = rx.recv().await {
                    let Some(state) = weak.upgrade() else {
                        break;
                    };
                    if publish_change(&state, change).await.is_err() {
                        record_delivery("fanout", DeliveryDisposition::PayloadConstructionFailed);
                    }
                }
            });
            tx
        });
        if sender.try_send(change).is_err() {
            record_delivery("publication", DeliveryDisposition::QueueUnavailable);
        }
    }
}

fn record_delivery(component: &'static str, disposition: DeliveryDisposition) {
    metrics::counter!("openshell_supervisor_config_delivery_total", "component" => component, "disposition" => disposition.label()).increment(1);
}

async fn publish_change(state: &ServerState, change: ConfigChange) -> Result<(), tonic::Status> {
    let (workspace, components) = match change {
        ConfigChange::Sandbox(id, components) => {
            if let Some(sandbox) = state
                .store
                .get_message::<Sandbox>(&id)
                .await
                .map_err(|_| tonic::Status::internal("snapshot lookup failed"))?
            {
                publish_sandbox(state, &sandbox, components).await;
            }
            return Ok(());
        }
        ConfigChange::Workspace(workspace, components) => (Some(workspace), components),
        ConfigChange::ProviderProfile(workspace) => (
            (!workspace.is_empty()).then_some(workspace),
            Components::All,
        ),
        ConfigChange::Global(components) => (None, components),
    };
    let mut cursor: Option<ObjectCursor> = None;
    loop {
        let records = state
            .store
            .list_by_type_after(Sandbox::object_type(), cursor.as_ref(), 100)
            .await
            .map_err(|_| tonic::Status::internal("snapshot fanout lookup failed"))?;
        if records.is_empty() {
            break;
        }
        for record in &records {
            let Ok(sandbox) = Sandbox::decode(record.payload.as_slice()) else {
                record_delivery("fanout", DeliveryDisposition::PayloadConstructionFailed);
                continue;
            };
            if workspace
                .as_ref()
                .is_none_or(|workspace| sandbox.object_workspace() == workspace)
            {
                publish_sandbox(state, &sandbox, components).await;
            }
        }
        cursor = records.last().map(ObjectCursor::from);
    }
    Ok(())
}

async fn publish_sandbox(state: &ServerState, sandbox: &Sandbox, components: Components) {
    if matches!(components, Components::ConfigAndProviders | Components::All) {
        deliver_snapshot(state, sandbox.object_id(), "sandbox_config", async {
            policy::build_sandbox_config_snapshot(state, sandbox)
                .await
                .map(config_update::Component::SandboxConfig)
        })
        .await;
        deliver_snapshot(state, sandbox.object_id(), "provider_environment", async {
            policy::build_provider_environment_snapshot(state, sandbox.object_id())
                .await
                .map(config_update::Component::ProviderEnvironment)
        })
        .await;
    }
    if matches!(components, Components::Inference | Components::All) {
        deliver_snapshot(state, sandbox.object_id(), "inference_bundle", async {
            inference::resolve_inference_bundle_with_credentials(
                &state.store,
                sandbox.object_workspace(),
                Some(&state.credentials),
            )
            .await
            .map(config_update::Component::InferenceBundle)
        })
        .await;
    }
}

async fn deliver_snapshot(
    state: &ServerState,
    sandbox_id: &str,
    component: &'static str,
    build: impl Future<Output = Result<config_update::Component, tonic::Status>>,
) {
    let disposition = match tokio::time::timeout(BUILD_TIMEOUT, build).await {
        Ok(Ok(snapshot)) => {
            state
                .supervisor_config_router
                .deliver(
                    sandbox_id,
                    SupervisorConfigMessage::Update(Box::new(ConfigUpdate {
                        component: Some(snapshot),
                        ..Default::default()
                    })),
                )
                .await
        }
        _ => DeliveryDisposition::PayloadConstructionFailed,
    };
    record_delivery(component, disposition);
}

pub(crate) async fn build_bootstrap(
    state: &ServerState,
    sandbox_id: &str,
) -> Option<ConfigBootstrap> {
    let result = tokio::time::timeout(BUILD_TIMEOUT, async {
        let sandbox = state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .ok()
            .flatten()?;
        Some(ConfigBootstrap {
            sandbox_config: Some(
                policy::build_sandbox_config_snapshot(state, &sandbox)
                    .await
                    .ok()?,
            ),
            provider_environment: Some(
                policy::build_provider_environment_snapshot(state, sandbox_id)
                    .await
                    .ok()?,
            ),
            inference_bundle: Some(
                inference::resolve_inference_bundle_with_credentials(
                    &state.store,
                    sandbox.object_workspace(),
                    Some(&state.credentials),
                )
                .await
                .ok()?,
            ),
        })
    })
    .await
    .ok()
    .flatten();
    match result {
        Some(bootstrap) if bootstrap.encoded_len() <= MAX_CONFIG_BYTES => {
            metrics::counter!("openshell_supervisor_config_bootstrap_build_total", "outcome" => "built").increment(1);
            Some(bootstrap)
        }
        Some(_) => {
            record_delivery("bootstrap", DeliveryDisposition::PayloadTooLarge);
            None
        }
        None => {
            record_delivery("bootstrap", DeliveryDisposition::PayloadConstructionFailed);
            None
        }
    }
}
