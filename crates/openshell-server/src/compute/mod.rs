// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-owned compute orchestration over a pluggable compute backend.

use crate::grpc::policy::{SANDBOX_SETTINGS_OBJECT_TYPE, sandbox_settings_id};
use crate::persistence::{ObjectId, ObjectName, ObjectType, Store};
use crate::sandbox_index::SandboxIndex;
use crate::sandbox_watch::SandboxWatchBus;
use crate::tracing_bus::TracingLogBus;
use futures::{Stream, StreamExt};
use openshell_core::proto::{
    ResolveSandboxEndpointResponse, Sandbox, SandboxCondition, SandboxPhase, SandboxSpec,
    SandboxStatus, SshSession, WatchSandboxesEvent,
};
use openshell_driver_kubernetes::{
    KubernetesComputeConfig, KubernetesComputeDriver, KubernetesDriverError,
};
use prost::Message;
use std::fmt;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tonic::Status;
use tracing::{info, warn};

type ComputeWatchStream =
    Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, ComputeError>> + Send>>;

#[derive(Debug, thiserror::Error)]
pub enum ComputeError {
    #[error("sandbox already exists")]
    AlreadyExists,
    #[error("{0}")]
    Precondition(String),
    #[error("{0}")]
    Message(String),
}

impl From<KubernetesDriverError> for ComputeError {
    fn from(value: KubernetesDriverError) -> Self {
        match value {
            KubernetesDriverError::AlreadyExists => Self::AlreadyExists,
            KubernetesDriverError::Precondition(message) => Self::Precondition(message),
            KubernetesDriverError::Message(message) => Self::Message(message),
        }
    }
}

pub enum ResolvedEndpoint {
    Ip(IpAddr, u16),
    Host(String, u16),
}

#[tonic::async_trait]
pub trait ComputeBackend: fmt::Debug + Send + Sync {
    fn default_image(&self) -> &str;
    async fn validate_sandbox_create(&self, sandbox: &Sandbox) -> Result<(), Status>;
    async fn create_sandbox(&self, sandbox: &Sandbox) -> Result<(), ComputeError>;
    async fn delete_sandbox(&self, sandbox_name: &str) -> Result<bool, ComputeError>;
    async fn resolve_sandbox_endpoint(
        &self,
        sandbox: &Sandbox,
    ) -> Result<ResolvedEndpoint, ComputeError>;
    async fn watch_sandboxes(&self) -> Result<ComputeWatchStream, ComputeError>;
}

#[derive(Debug)]
pub struct InProcessKubernetesBackend {
    driver: KubernetesComputeDriver,
}

impl InProcessKubernetesBackend {
    #[must_use]
    pub fn new(driver: KubernetesComputeDriver) -> Self {
        Self { driver }
    }
}

#[tonic::async_trait]
impl ComputeBackend for InProcessKubernetesBackend {
    fn default_image(&self) -> &str {
        self.driver.default_image()
    }

    async fn validate_sandbox_create(&self, sandbox: &Sandbox) -> Result<(), Status> {
        self.driver.validate_sandbox_create(sandbox).await
    }

    async fn create_sandbox(&self, sandbox: &Sandbox) -> Result<(), ComputeError> {
        self.driver
            .create_sandbox(sandbox)
            .await
            .map_err(Into::into)
    }

    async fn delete_sandbox(&self, sandbox_name: &str) -> Result<bool, ComputeError> {
        self.driver
            .delete_sandbox(sandbox_name)
            .await
            .map_err(ComputeError::Message)
    }

    async fn resolve_sandbox_endpoint(
        &self,
        sandbox: &Sandbox,
    ) -> Result<ResolvedEndpoint, ComputeError> {
        let response = self
            .driver
            .resolve_sandbox_endpoint(sandbox)
            .await
            .map_err(ComputeError::Message)?;
        resolved_endpoint_from_response(&response)
    }

    async fn watch_sandboxes(&self) -> Result<ComputeWatchStream, ComputeError> {
        let stream = self
            .driver
            .watch_sandboxes()
            .await
            .map_err(ComputeError::Message)?;
        Ok(Box::pin(stream.map(|item| item.map_err(Into::into))))
    }
}

#[derive(Clone)]
pub struct ComputeRuntime {
    backend: Arc<dyn ComputeBackend>,
    store: Arc<Store>,
    sandbox_index: SandboxIndex,
    sandbox_watch_bus: SandboxWatchBus,
    tracing_log_bus: TracingLogBus,
}

impl fmt::Debug for ComputeRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ComputeRuntime").finish_non_exhaustive()
    }
}

impl ComputeRuntime {
    pub async fn new_kubernetes(
        config: KubernetesComputeConfig,
        store: Arc<Store>,
        sandbox_index: SandboxIndex,
        sandbox_watch_bus: SandboxWatchBus,
        tracing_log_bus: TracingLogBus,
    ) -> Result<Self, ComputeError> {
        let driver = KubernetesComputeDriver::new(config)
            .await
            .map_err(|err| ComputeError::Message(err.to_string()))?;
        Ok(Self {
            backend: Arc::new(InProcessKubernetesBackend::new(driver)),
            store,
            sandbox_index,
            sandbox_watch_bus,
            tracing_log_bus,
        })
    }

    #[must_use]
    pub fn default_image(&self) -> &str {
        self.backend.default_image()
    }

    pub async fn validate_sandbox_create(&self, sandbox: &Sandbox) -> Result<(), Status> {
        self.backend.validate_sandbox_create(sandbox).await
    }

    pub async fn create_sandbox(&self, sandbox: Sandbox) -> Result<Sandbox, Status> {
        let existing = self
            .store
            .get_message_by_name::<Sandbox>(&sandbox.name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?;
        if existing.is_some() {
            return Err(Status::already_exists(format!(
                "sandbox '{}' already exists",
                sandbox.name
            )));
        }

        self.sandbox_index.update_from_sandbox(&sandbox);
        self.store
            .put_message(&sandbox)
            .await
            .map_err(|e| Status::internal(format!("persist sandbox failed: {e}")))?;

        match self.backend.create_sandbox(&sandbox).await {
            Ok(()) => {
                self.sandbox_watch_bus.notify(&sandbox.id);
                Ok(sandbox)
            }
            Err(ComputeError::AlreadyExists) => {
                let _ = self.store.delete(Sandbox::object_type(), &sandbox.id).await;
                self.sandbox_index.remove_sandbox(&sandbox.id);
                Err(Status::already_exists("sandbox already exists"))
            }
            Err(ComputeError::Precondition(message)) => {
                let _ = self.store.delete(Sandbox::object_type(), &sandbox.id).await;
                self.sandbox_index.remove_sandbox(&sandbox.id);
                Err(Status::failed_precondition(message))
            }
            Err(err) => {
                let _ = self.store.delete(Sandbox::object_type(), &sandbox.id).await;
                self.sandbox_index.remove_sandbox(&sandbox.id);
                Err(Status::internal(format!("create sandbox failed: {err}")))
            }
        }
    }

    pub async fn delete_sandbox(&self, name: &str) -> Result<bool, Status> {
        let sandbox = self
            .store
            .get_message_by_name::<Sandbox>(name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?;

        let Some(mut sandbox) = sandbox else {
            return Err(Status::not_found("sandbox not found"));
        };

        let id = sandbox.id.clone();
        sandbox.phase = SandboxPhase::Deleting as i32;
        self.store
            .put_message(&sandbox)
            .await
            .map_err(|e| Status::internal(format!("persist sandbox failed: {e}")))?;
        self.sandbox_index.update_from_sandbox(&sandbox);
        self.sandbox_watch_bus.notify(&id);

        if let Ok(records) = self.store.list(SshSession::object_type(), 1000, 0).await {
            for record in records {
                if let Ok(session) = SshSession::decode(record.payload.as_slice())
                    && session.sandbox_id == id
                    && let Err(e) = self
                        .store
                        .delete(SshSession::object_type(), &session.id)
                        .await
                {
                    warn!(
                        session_id = %session.id,
                        error = %e,
                        "Failed to delete SSH session during sandbox cleanup"
                    );
                }
            }
        }

        if let Err(e) = self
            .store
            .delete(SANDBOX_SETTINGS_OBJECT_TYPE, &sandbox_settings_id(&id))
            .await
        {
            warn!(
                sandbox_id = %id,
                error = %e,
                "Failed to delete sandbox settings during cleanup"
            );
        }

        let deleted = self
            .backend
            .delete_sandbox(&sandbox.name)
            .await
            .map_err(|err| Status::internal(format!("delete sandbox failed: {err}")))?;

        if !deleted && let Err(e) = self.store.delete(Sandbox::object_type(), &id).await {
            warn!(sandbox_id = %id, error = %e, "Failed to clean up store after delete");
        }

        self.cleanup_sandbox_state(&id);
        Ok(deleted)
    }

    pub async fn resolve_sandbox_endpoint(
        &self,
        sandbox: &Sandbox,
    ) -> Result<ResolvedEndpoint, Status> {
        self.backend
            .resolve_sandbox_endpoint(sandbox)
            .await
            .map_err(|err| match err {
                ComputeError::Precondition(message) => Status::failed_precondition(message),
                other => Status::internal(other.to_string()),
            })
    }

    pub fn spawn_watchers(&self) {
        let runtime = Arc::new(self.clone());
        tokio::spawn(async move {
            runtime.watch_loop().await;
        });
    }

    async fn watch_loop(self: Arc<Self>) {
        loop {
            let mut stream = match self.backend.watch_sandboxes().await {
                Ok(stream) => stream,
                Err(err) => {
                    warn!(error = %err, "Compute driver watch stream failed to start");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };

            let mut restart = false;
            while let Some(item) = stream.next().await {
                match item {
                    Ok(event) => {
                        if let Err(err) = self.apply_watch_event(event).await {
                            warn!(error = %err, "Failed to apply compute driver event");
                        }
                    }
                    Err(err) => {
                        warn!(error = %err, "Compute driver watch stream errored");
                        restart = true;
                        break;
                    }
                }
            }

            if !restart {
                warn!("Compute driver watch stream ended unexpectedly");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    async fn apply_watch_event(&self, event: WatchSandboxesEvent) -> Result<(), String> {
        use openshell_core::proto::watch_sandboxes_event::Payload;

        match event.payload {
            Some(Payload::Sandbox(sandbox)) => {
                if let Some(sandbox) = sandbox.sandbox {
                    self.apply_sandbox_update(sandbox).await?;
                }
            }
            Some(Payload::Deleted(deleted)) => {
                self.apply_deleted(&deleted.sandbox_id).await?;
            }
            Some(Payload::PlatformEvent(platform_event)) => {
                if let Some(event) = platform_event.event {
                    self.tracing_log_bus.platform_event_bus.publish(
                        &platform_event.sandbox_id,
                        openshell_core::proto::SandboxStreamEvent {
                            payload: Some(
                                openshell_core::proto::sandbox_stream_event::Payload::Event(event),
                            ),
                        },
                    );
                }
            }
            None => {}
        }
        Ok(())
    }

    async fn apply_sandbox_update(&self, incoming: Sandbox) -> Result<(), String> {
        let existing = self
            .store
            .get_message::<Sandbox>(&incoming.id)
            .await
            .map_err(|e| e.to_string())?;

        let mut status = incoming.status.clone();
        rewrite_user_facing_conditions(
            &mut status,
            existing.as_ref().and_then(|sandbox| sandbox.spec.as_ref()),
        );

        let phase = SandboxPhase::try_from(incoming.phase).unwrap_or(SandboxPhase::Unknown);
        let mut sandbox = existing.unwrap_or_else(|| Sandbox {
            id: incoming.id.clone(),
            name: incoming.name.clone(),
            namespace: incoming.namespace.clone(),
            spec: None,
            status: None,
            phase: SandboxPhase::Unknown as i32,
            ..Default::default()
        });

        let old_phase = SandboxPhase::try_from(sandbox.phase).unwrap_or(SandboxPhase::Unknown);
        if old_phase != phase {
            info!(
                sandbox_id = %incoming.id,
                sandbox_name = %incoming.name,
                old_phase = ?old_phase,
                new_phase = ?phase,
                "Sandbox phase changed"
            );
        }

        if phase == SandboxPhase::Error
            && let Some(ref status) = status
        {
            for condition in &status.conditions {
                if condition.r#type == "Ready"
                    && condition.status.eq_ignore_ascii_case("false")
                    && is_terminal_failure_condition(condition)
                {
                    warn!(
                        sandbox_id = %incoming.id,
                        sandbox_name = %incoming.name,
                        reason = %condition.reason,
                        message = %condition.message,
                        "Sandbox failed to become ready"
                    );
                }
            }
        }

        sandbox.name = incoming.name;
        sandbox.namespace = incoming.namespace;
        sandbox.status = status;
        sandbox.phase = phase as i32;

        self.sandbox_index.update_from_sandbox(&sandbox);
        self.store
            .put_message(&sandbox)
            .await
            .map_err(|e| e.to_string())?;
        self.sandbox_watch_bus.notify(&sandbox.id);
        Ok(())
    }

    async fn apply_deleted(&self, sandbox_id: &str) -> Result<(), String> {
        let _ = self
            .store
            .delete(Sandbox::object_type(), sandbox_id)
            .await
            .map_err(|e| e.to_string())?;
        self.sandbox_index.remove_sandbox(sandbox_id);
        self.sandbox_watch_bus.notify(sandbox_id);
        self.cleanup_sandbox_state(sandbox_id);
        Ok(())
    }

    fn cleanup_sandbox_state(&self, sandbox_id: &str) {
        self.tracing_log_bus.remove(sandbox_id);
        self.tracing_log_bus.platform_event_bus.remove(sandbox_id);
        self.sandbox_watch_bus.remove(sandbox_id);
    }
}

impl ObjectType for Sandbox {
    fn object_type() -> &'static str {
        "sandbox"
    }
}

impl ObjectId for Sandbox {
    fn object_id(&self) -> &str {
        &self.id
    }
}

impl ObjectName for Sandbox {
    fn object_name(&self) -> &str {
        &self.name
    }
}

fn resolved_endpoint_from_response(
    response: &ResolveSandboxEndpointResponse,
) -> Result<ResolvedEndpoint, ComputeError> {
    let endpoint = response
        .endpoint
        .as_ref()
        .ok_or_else(|| ComputeError::Message("compute driver returned no endpoint".to_string()))?;
    let port = u16::try_from(endpoint.port)
        .map_err(|_| ComputeError::Message("compute driver returned invalid port".to_string()))?;

    match endpoint.target.as_ref() {
        Some(openshell_core::proto::sandbox_endpoint::Target::Ip(ip)) => ip
            .parse()
            .map(|ip| ResolvedEndpoint::Ip(ip, port))
            .map_err(|e| ComputeError::Message(format!("invalid endpoint IP: {e}"))),
        Some(openshell_core::proto::sandbox_endpoint::Target::Host(host)) => {
            Ok(ResolvedEndpoint::Host(host.clone(), port))
        }
        None => Err(ComputeError::Message(
            "compute driver returned endpoint without target".to_string(),
        )),
    }
}

fn rewrite_user_facing_conditions(status: &mut Option<SandboxStatus>, spec: Option<&SandboxSpec>) {
    let gpu_requested = spec.is_some_and(|sandbox_spec| sandbox_spec.gpu);
    if !gpu_requested {
        return;
    }

    if let Some(status) = status {
        for condition in &mut status.conditions {
            if condition.r#type == "Ready"
                && condition.status.eq_ignore_ascii_case("false")
                && condition.reason.eq_ignore_ascii_case("Unschedulable")
            {
                condition.message = "GPU sandbox could not be scheduled on the active gateway. Another GPU sandbox may already be using the available GPU, or the gateway may not currently be able to satisfy GPU placement. Please refer to documentation and use `openshell doctor` commands to inspect GPU support and gateway configuration.".to_string();
            }
        }
    }
}

fn is_terminal_failure_condition(condition: &SandboxCondition) -> bool {
    let reason = condition.reason.to_ascii_lowercase();
    let transient_reasons = ["reconcilererror", "dependenciesnotready"];
    !transient_reasons.contains(&reason.as_str())
}
