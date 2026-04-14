// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-owned compute orchestration over a pluggable compute backend.

use crate::grpc::policy::{SANDBOX_SETTINGS_OBJECT_TYPE, sandbox_settings_id};
use crate::persistence::{ObjectId, ObjectName, ObjectType, Store};
use crate::sandbox_index::SandboxIndex;
use crate::sandbox_watch::SandboxWatchBus;
use crate::tracing_bus::TracingLogBus;
use futures::{Stream, StreamExt};
use openshell_core::proto::compute::v1::{
    DriverCondition, DriverPlatformEvent, DriverResourceRequirements, DriverSandbox,
    DriverSandboxSpec, DriverSandboxStatus, DriverSandboxTemplate, ResolveSandboxEndpointResponse,
    WatchSandboxesEvent, sandbox_endpoint, watch_sandboxes_event,
};
use openshell_core::proto::{
    PlatformEvent, Sandbox, SandboxCondition, SandboxPhase, SandboxSpec, SandboxStatus,
    SandboxTemplate, SshSession,
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
use tracing::{debug, info, warn};

type ComputeWatchStream =
    Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, ComputeError>> + Send>>;

/// Interval between store-vs-backend reconciliation sweeps.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(60);

/// How long a sandbox can remain provisioning in the store without a
/// corresponding backend resource before it is considered orphaned.
const ORPHAN_GRACE_PERIOD: Duration = Duration::from_secs(300);

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

#[derive(Debug)]
pub enum ResolvedEndpoint {
    Ip(IpAddr, u16),
    Host(String, u16),
}

#[tonic::async_trait]
pub trait ComputeBackend: fmt::Debug + Send + Sync {
    fn default_image(&self) -> &str;
    async fn validate_sandbox_create(&self, sandbox: &DriverSandbox) -> Result<(), Status>;
    async fn create_sandbox(&self, sandbox: &DriverSandbox) -> Result<(), ComputeError>;
    async fn delete_sandbox(&self, sandbox_name: &str) -> Result<bool, ComputeError>;
    async fn sandbox_exists(&self, sandbox_name: &str) -> Result<bool, ComputeError>;
    async fn resolve_sandbox_endpoint(
        &self,
        sandbox: &DriverSandbox,
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

    async fn validate_sandbox_create(&self, sandbox: &DriverSandbox) -> Result<(), Status> {
        self.driver.validate_sandbox_create(sandbox).await
    }

    async fn create_sandbox(&self, sandbox: &DriverSandbox) -> Result<(), ComputeError> {
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

    async fn sandbox_exists(&self, sandbox_name: &str) -> Result<bool, ComputeError> {
        self.driver
            .sandbox_exists(sandbox_name)
            .await
            .map_err(ComputeError::Message)
    }

    async fn resolve_sandbox_endpoint(
        &self,
        sandbox: &DriverSandbox,
    ) -> Result<ResolvedEndpoint, ComputeError> {
        let response = self
            .driver
            .resolve_sandbox_endpoint(sandbox)
            .await
            .map_err(ComputeError::from)?;
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
        let driver_sandbox = driver_sandbox_from_public(sandbox);
        self.backend.validate_sandbox_create(&driver_sandbox).await
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

        let driver_sandbox = driver_sandbox_from_public(&sandbox);
        match self.backend.create_sandbox(&driver_sandbox).await {
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
        let driver_sandbox = driver_sandbox_from_public(sandbox);
        self.backend
            .resolve_sandbox_endpoint(&driver_sandbox)
            .await
            .map_err(|err| match err {
                ComputeError::Precondition(message) => Status::failed_precondition(message),
                other => Status::internal(other.to_string()),
            })
    }

    pub fn spawn_watchers(&self) {
        let runtime = Arc::new(self.clone());
        let watch_runtime = runtime.clone();
        tokio::spawn(async move {
            watch_runtime.watch_loop().await;
        });
        tokio::spawn(async move {
            runtime.reconcile_loop().await;
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

    async fn reconcile_loop(self: Arc<Self>) {
        // Let startup settle before pruning store records.
        tokio::time::sleep(RECONCILE_INTERVAL).await;

        loop {
            if let Err(err) = self.reconcile_orphaned_sandboxes(ORPHAN_GRACE_PERIOD).await {
                warn!(error = %err, "Store reconciliation sweep failed");
            }
            tokio::time::sleep(RECONCILE_INTERVAL).await;
        }
    }

    async fn reconcile_orphaned_sandboxes(&self, grace_period: Duration) -> Result<(), String> {
        let records = self
            .store
            .list(Sandbox::object_type(), 500, 0)
            .await
            .map_err(|e| e.to_string())?;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(i64::MAX);
        let grace_ms = grace_period.as_millis().try_into().unwrap_or(i64::MAX);

        for record in records {
            let sandbox = match Sandbox::decode(record.payload.as_slice()) {
                Ok(sandbox) => sandbox,
                Err(err) => {
                    warn!(error = %err, "Failed to decode sandbox record during reconciliation");
                    continue;
                }
            };

            if sandbox.phase != SandboxPhase::Provisioning as i32 {
                continue;
            }

            let age_ms = now_ms.saturating_sub(record.created_at_ms);
            if age_ms < grace_ms {
                continue;
            }

            match self.backend.sandbox_exists(&sandbox.name).await {
                Ok(true) => {}
                Ok(false) => {
                    info!(
                        sandbox_id = %sandbox.id,
                        sandbox_name = %sandbox.name,
                        age_secs = age_ms / 1000,
                        "Removing orphaned sandbox from store (no corresponding backend resource)"
                    );
                    if let Err(err) = self.store.delete(Sandbox::object_type(), &sandbox.id).await {
                        warn!(sandbox_id = %sandbox.id, error = %err, "Failed to remove orphaned sandbox");
                        continue;
                    }
                    self.sandbox_index.remove_sandbox(&sandbox.id);
                    self.sandbox_watch_bus.notify(&sandbox.id);
                    self.cleanup_sandbox_state(&sandbox.id);
                }
                Err(err) => {
                    debug!(
                        sandbox_id = %sandbox.id,
                        sandbox_name = %sandbox.name,
                        error = %err,
                        "Skipping orphan check due to backend error"
                    );
                }
            }
        }

        Ok(())
    }

    async fn apply_watch_event(&self, event: WatchSandboxesEvent) -> Result<(), String> {
        match event.payload {
            Some(watch_sandboxes_event::Payload::Sandbox(sandbox)) => {
                if let Some(sandbox) = sandbox.sandbox {
                    self.apply_sandbox_update(sandbox).await?;
                }
            }
            Some(watch_sandboxes_event::Payload::Deleted(deleted)) => {
                self.apply_deleted(&deleted.sandbox_id).await?;
            }
            Some(watch_sandboxes_event::Payload::PlatformEvent(platform_event)) => {
                if let Some(event) = platform_event.event {
                    self.tracing_log_bus.platform_event_bus.publish(
                        &platform_event.sandbox_id,
                        openshell_core::proto::SandboxStreamEvent {
                            payload: Some(
                                openshell_core::proto::sandbox_stream_event::Payload::Event(
                                    public_platform_event_from_driver(&event),
                                ),
                            ),
                        },
                    );
                }
            }
            None => {}
        }
        Ok(())
    }

    async fn apply_sandbox_update(&self, incoming: DriverSandbox) -> Result<(), String> {
        let existing = self
            .store
            .get_message::<Sandbox>(&incoming.id)
            .await
            .map_err(|e| e.to_string())?;

        let mut status = incoming.status.as_ref().map(public_status_from_driver);
        rewrite_user_facing_conditions(
            &mut status,
            existing.as_ref().and_then(|sandbox| sandbox.spec.as_ref()),
        );

        let phase = derive_phase(incoming.status.as_ref());
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
                    && is_terminal_failure_reason(&condition.reason)
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

fn driver_sandbox_from_public(sandbox: &Sandbox) -> DriverSandbox {
    DriverSandbox {
        id: sandbox.id.clone(),
        name: sandbox.name.clone(),
        namespace: sandbox.namespace.clone(),
        spec: sandbox.spec.as_ref().map(driver_sandbox_spec_from_public),
        status: sandbox
            .status
            .as_ref()
            .map(|status| driver_status_from_public(status, sandbox.phase)),
    }
}

fn driver_sandbox_spec_from_public(spec: &SandboxSpec) -> DriverSandboxSpec {
    DriverSandboxSpec {
        log_level: spec.log_level.clone(),
        environment: spec.environment.clone(),
        template: spec
            .template
            .as_ref()
            .map(driver_sandbox_template_from_public),
        gpu: spec.gpu,
    }
}

fn driver_sandbox_template_from_public(template: &SandboxTemplate) -> DriverSandboxTemplate {
    DriverSandboxTemplate {
        image: template.image.clone(),
        agent_socket_path: template.agent_socket.clone(),
        labels: template.labels.clone(),
        environment: template.environment.clone(),
        resources: extract_typed_resources(&template.resources),
        platform_config: build_platform_config(template),
    }
}

/// Extract typed CPU/memory quantities from the public `resources` Struct.
///
/// The public API exposes resources as an untyped `google.protobuf.Struct`
/// with the Kubernetes limits/requests shape. We pull out the well-known
/// keys into the typed `DriverResourceRequirements` message.
fn extract_typed_resources(
    resources: &Option<prost_types::Struct>,
) -> Option<DriverResourceRequirements> {
    let s = resources.as_ref()?;

    fn get_quantity(s: &prost_types::Struct, section: &str, key: &str) -> String {
        s.fields
            .get(section)
            .and_then(|v| match v.kind.as_ref() {
                Some(prost_types::value::Kind::StructValue(inner)) => inner.fields.get(key),
                _ => None,
            })
            .and_then(|v| match v.kind.as_ref() {
                Some(prost_types::value::Kind::StringValue(val)) => Some(val.clone()),
                _ => None,
            })
            .unwrap_or_default()
    }

    let req = DriverResourceRequirements {
        cpu_request: get_quantity(s, "requests", "cpu"),
        cpu_limit: get_quantity(s, "limits", "cpu"),
        memory_request: get_quantity(s, "requests", "memory"),
        memory_limit: get_quantity(s, "limits", "memory"),
    };

    // Return None when all fields are empty so drivers can distinguish
    // "no resource requirements" from "zero requirements".
    if req.cpu_request.is_empty()
        && req.cpu_limit.is_empty()
        && req.memory_request.is_empty()
        && req.memory_limit.is_empty()
    {
        None
    } else {
        Some(req)
    }
}

/// Build the opaque `platform_config` Struct from platform-specific public
/// template fields (runtime_class_name, annotations, volume_claim_templates)
/// plus any resource fields beyond CPU/memory.
fn build_platform_config(template: &SandboxTemplate) -> Option<prost_types::Struct> {
    use prost_types::{Struct, Value, value::Kind};

    let mut fields = std::collections::BTreeMap::new();

    if !template.runtime_class_name.is_empty() {
        fields.insert(
            "runtime_class_name".to_string(),
            Value {
                kind: Some(Kind::StringValue(template.runtime_class_name.clone())),
            },
        );
    }

    if !template.annotations.is_empty() {
        let annotation_fields = template
            .annotations
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    Value {
                        kind: Some(Kind::StringValue(v.clone())),
                    },
                )
            })
            .collect();
        fields.insert(
            "annotations".to_string(),
            Value {
                kind: Some(Kind::StructValue(Struct {
                    fields: annotation_fields,
                })),
            },
        );
    }

    // Pass through the raw volume_claim_templates Struct as a nested value.
    if let Some(ref vct) = template.volume_claim_templates {
        fields.insert(
            "volume_claim_templates".to_string(),
            Value {
                kind: Some(Kind::StructValue(vct.clone())),
            },
        );
    }

    // Pass through any non-cpu/memory resource fields from the original
    // resources Struct so the driver can handle GPU limits, custom resources,
    // etc. that don't map to the typed DriverResourceRequirements.
    if let Some(ref res) = template.resources {
        fields.insert(
            "resources_raw".to_string(),
            Value {
                kind: Some(Kind::StructValue(res.clone())),
            },
        );
    }

    if fields.is_empty() {
        None
    } else {
        Some(Struct { fields })
    }
}

fn driver_status_from_public(status: &SandboxStatus, phase: i32) -> DriverSandboxStatus {
    DriverSandboxStatus {
        sandbox_name: status.sandbox_name.clone(),
        instance_id: status.agent_pod.clone(),
        agent_fd: status.agent_fd.clone(),
        sandbox_fd: status.sandbox_fd.clone(),
        conditions: status
            .conditions
            .iter()
            .map(driver_condition_from_public)
            .collect(),
        deleting: SandboxPhase::try_from(phase) == Ok(SandboxPhase::Deleting),
    }
}

fn driver_condition_from_public(condition: &SandboxCondition) -> DriverCondition {
    DriverCondition {
        r#type: condition.r#type.clone(),
        status: condition.status.clone(),
        reason: condition.reason.clone(),
        message: condition.message.clone(),
        last_transition_time: condition.last_transition_time.clone(),
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
        Some(sandbox_endpoint::Target::Ip(ip)) => ip
            .parse()
            .map(|ip| ResolvedEndpoint::Ip(ip, port))
            .map_err(|e| ComputeError::Message(format!("invalid endpoint IP: {e}"))),
        Some(sandbox_endpoint::Target::Host(host)) => {
            Ok(ResolvedEndpoint::Host(host.clone(), port))
        }
        None => Err(ComputeError::Message(
            "compute driver returned endpoint without target".to_string(),
        )),
    }
}

fn public_status_from_driver(status: &DriverSandboxStatus) -> SandboxStatus {
    SandboxStatus {
        sandbox_name: status.sandbox_name.clone(),
        agent_pod: status.instance_id.clone(),
        agent_fd: status.agent_fd.clone(),
        sandbox_fd: status.sandbox_fd.clone(),
        conditions: status
            .conditions
            .iter()
            .map(public_condition_from_driver)
            .collect(),
    }
}

fn public_condition_from_driver(condition: &DriverCondition) -> SandboxCondition {
    SandboxCondition {
        r#type: condition.r#type.clone(),
        status: condition.status.clone(),
        reason: condition.reason.clone(),
        message: condition.message.clone(),
        last_transition_time: condition.last_transition_time.clone(),
    }
}

fn public_platform_event_from_driver(event: &DriverPlatformEvent) -> PlatformEvent {
    PlatformEvent {
        timestamp_ms: event.timestamp_ms,
        source: event.source.clone(),
        r#type: event.r#type.clone(),
        reason: event.reason.clone(),
        message: event.message.clone(),
        metadata: event.metadata.clone(),
    }
}

fn derive_phase(status: Option<&DriverSandboxStatus>) -> SandboxPhase {
    if let Some(status) = status {
        if status.deleting {
            return SandboxPhase::Deleting;
        }

        for condition in &status.conditions {
            if condition.r#type == "Ready" {
                return if condition.status.eq_ignore_ascii_case("true") {
                    SandboxPhase::Ready
                } else if condition.status.eq_ignore_ascii_case("false") {
                    if is_terminal_failure_reason(&condition.reason) {
                        SandboxPhase::Error
                    } else {
                        SandboxPhase::Provisioning
                    }
                } else {
                    SandboxPhase::Provisioning
                };
            }
        }
        return SandboxPhase::Provisioning;
    }

    SandboxPhase::Unknown
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

fn is_terminal_failure_reason(reason: &str) -> bool {
    let reason = reason.to_ascii_lowercase();
    let transient_reasons = ["reconcilererror", "dependenciesnotready"];
    !transient_reasons.contains(&reason.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;
    use std::sync::Arc;

    #[derive(Debug, Default)]
    struct TestBackend {
        sandbox_exists: bool,
        resolve_precondition: Option<String>,
    }

    #[tonic::async_trait]
    impl ComputeBackend for TestBackend {
        fn default_image(&self) -> &'static str {
            "openshell/sandbox:test"
        }

        async fn validate_sandbox_create(&self, _sandbox: &DriverSandbox) -> Result<(), Status> {
            Ok(())
        }

        async fn create_sandbox(&self, _sandbox: &DriverSandbox) -> Result<(), ComputeError> {
            Ok(())
        }

        async fn delete_sandbox(&self, _sandbox_name: &str) -> Result<bool, ComputeError> {
            Ok(true)
        }

        async fn sandbox_exists(&self, _sandbox_name: &str) -> Result<bool, ComputeError> {
            Ok(self.sandbox_exists)
        }

        async fn resolve_sandbox_endpoint(
            &self,
            _sandbox: &DriverSandbox,
        ) -> Result<ResolvedEndpoint, ComputeError> {
            if let Some(message) = &self.resolve_precondition {
                return Err(ComputeError::Precondition(message.clone()));
            }

            Ok(ResolvedEndpoint::Host(
                "sandbox.default.svc.cluster.local".to_string(),
                2222,
            ))
        }

        async fn watch_sandboxes(&self) -> Result<ComputeWatchStream, ComputeError> {
            Ok(Box::pin(stream::empty()))
        }
    }

    async fn test_runtime(backend: Arc<dyn ComputeBackend>) -> ComputeRuntime {
        let store = Arc::new(Store::connect("sqlite::memory:").await.unwrap());
        ComputeRuntime {
            backend,
            store,
            sandbox_index: SandboxIndex::new(),
            sandbox_watch_bus: SandboxWatchBus::new(),
            tracing_log_bus: TracingLogBus::new(),
        }
    }

    fn sandbox_record(id: &str, name: &str, phase: SandboxPhase) -> Sandbox {
        Sandbox {
            id: id.to_string(),
            name: name.to_string(),
            namespace: "default".to_string(),
            phase: phase as i32,
            ..Default::default()
        }
    }

    fn make_driver_condition(reason: &str, message: &str) -> DriverCondition {
        DriverCondition {
            r#type: "Ready".to_string(),
            status: "False".to_string(),
            reason: reason.to_string(),
            message: message.to_string(),
            last_transition_time: String::new(),
        }
    }

    fn make_driver_status(condition: DriverCondition) -> DriverSandboxStatus {
        DriverSandboxStatus {
            sandbox_name: "test".to_string(),
            instance_id: "test-pod".to_string(),
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![condition],
            deleting: false,
        }
    }

    #[test]
    fn terminal_failure_treats_unknown_reasons_as_terminal() {
        let terminal_cases = [
            ("Failed", "Something went wrong"),
            ("CrashLoopBackOff", "Container keeps crashing"),
            ("ImagePullBackOff", "Failed to pull image"),
            ("ErrImagePull", "Error pulling image"),
            ("Unschedulable", "No nodes match"),
            ("SomeOtherReason", "Any other reason is terminal"),
        ];

        for (reason, message) in terminal_cases {
            assert!(
                is_terminal_failure_reason(reason),
                "Expected terminal failure for reason={reason}, message={message}"
            );
        }
    }

    #[test]
    fn terminal_failure_ignores_transient_reasons() {
        let transient_cases = [
            (
                "ReconcilerError",
                "Error seen: failed to update pod: Operation cannot be fulfilled",
            ),
            ("reconcilererror", "lowercase also works"),
            ("RECONCILERERROR", "uppercase also works"),
            (
                "DependenciesNotReady",
                "Pod exists with phase: Pending; Service Exists",
            ),
            ("dependenciesnotready", "lowercase also works"),
        ];

        for (reason, message) in transient_cases {
            assert!(
                !is_terminal_failure_reason(reason),
                "Expected transient (non-terminal) for reason={reason}, message={message}"
            );
        }
    }

    #[test]
    fn derive_phase_returns_unknown_without_status() {
        assert_eq!(derive_phase(None), SandboxPhase::Unknown);
    }

    #[test]
    fn derive_phase_returns_deleting_when_driver_marks_deleting() {
        let status = DriverSandboxStatus {
            deleting: true,
            ..make_driver_status(make_driver_condition(
                "DependenciesNotReady",
                "Pod still pending",
            ))
        };

        assert_eq!(derive_phase(Some(&status)), SandboxPhase::Deleting);
    }

    #[test]
    fn derive_phase_returns_provisioning_for_transient_conditions() {
        let transient_conditions = [
            ("ReconcilerError", "Error seen: failed to update pod"),
            (
                "DependenciesNotReady",
                "Pod exists with phase: Pending; Service Exists",
            ),
        ];

        for (reason, message) in transient_conditions {
            let status = make_driver_status(make_driver_condition(reason, message));
            assert_eq!(
                derive_phase(Some(&status)),
                SandboxPhase::Provisioning,
                "Expected Provisioning for transient reason={reason}"
            );
        }
    }

    #[test]
    fn derive_phase_returns_error_for_terminal_ready_false() {
        let status = make_driver_status(make_driver_condition(
            "ImagePullBackOff",
            "Failed to pull image",
        ));

        assert_eq!(derive_phase(Some(&status)), SandboxPhase::Error);
    }

    #[test]
    fn derive_phase_returns_ready_for_ready_true() {
        let status = DriverSandboxStatus {
            conditions: vec![DriverCondition {
                r#type: "Ready".to_string(),
                status: "True".to_string(),
                reason: "DependenciesReady".to_string(),
                message: "Pod is Ready; Service Exists".to_string(),
                last_transition_time: String::new(),
            }],
            ..make_driver_status(make_driver_condition("", ""))
        };

        assert_eq!(derive_phase(Some(&status)), SandboxPhase::Ready);
    }

    #[test]
    fn rewrite_user_facing_conditions_rewrites_gpu_unschedulable_message() {
        let mut status = Some(SandboxStatus {
            sandbox_name: "test".to_string(),
            agent_pod: "test-pod".to_string(),
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![SandboxCondition {
                r#type: "Ready".to_string(),
                status: "False".to_string(),
                reason: "Unschedulable".to_string(),
                message: "0/1 nodes are available: 1 Insufficient nvidia.com/gpu.".to_string(),
                last_transition_time: String::new(),
            }],
        });

        rewrite_user_facing_conditions(
            &mut status,
            Some(&SandboxSpec {
                gpu: true,
                ..Default::default()
            }),
        );

        let message = &status.unwrap().conditions[0].message;
        assert_eq!(
            message,
            "GPU sandbox could not be scheduled on the active gateway. Another GPU sandbox may already be using the available GPU, or the gateway may not currently be able to satisfy GPU placement. Please refer to documentation and use `openshell doctor` commands to inspect GPU support and gateway configuration."
        );
    }

    #[test]
    fn rewrite_user_facing_conditions_leaves_non_gpu_unschedulable_message_unchanged() {
        let original = "0/1 nodes are available: 1 Insufficient cpu.";
        let mut status = Some(SandboxStatus {
            sandbox_name: "test".to_string(),
            agent_pod: "test-pod".to_string(),
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![SandboxCondition {
                r#type: "Ready".to_string(),
                status: "False".to_string(),
                reason: "Unschedulable".to_string(),
                message: original.to_string(),
                last_transition_time: String::new(),
            }],
        });

        rewrite_user_facing_conditions(
            &mut status,
            Some(&SandboxSpec {
                gpu: false,
                ..Default::default()
            }),
        );

        assert_eq!(status.unwrap().conditions[0].message, original);
    }

    #[tokio::test]
    async fn apply_sandbox_update_allows_delete_failures_to_recover() {
        let runtime = test_runtime(Arc::new(TestBackend::default())).await;
        let sandbox = sandbox_record("sb-1", "sandbox-a", SandboxPhase::Deleting);
        runtime.store.put_message(&sandbox).await.unwrap();

        runtime
            .apply_sandbox_update(DriverSandbox {
                id: "sb-1".to_string(),
                name: "sandbox-a".to_string(),
                namespace: "default".to_string(),
                spec: None,
                status: Some(DriverSandboxStatus {
                    sandbox_name: "sandbox-a".to_string(),
                    instance_id: "agent-pod".to_string(),
                    agent_fd: String::new(),
                    sandbox_fd: String::new(),
                    conditions: vec![DriverCondition {
                        r#type: "Ready".to_string(),
                        status: "True".to_string(),
                        reason: "DependenciesReady".to_string(),
                        message: "Pod is Ready".to_string(),
                        last_transition_time: String::new(),
                    }],
                    deleting: false,
                }),
            })
            .await
            .unwrap();

        let stored = runtime
            .store
            .get_message::<Sandbox>("sb-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            SandboxPhase::try_from(stored.phase).unwrap(),
            SandboxPhase::Ready
        );
    }

    #[tokio::test]
    async fn resolve_sandbox_endpoint_preserves_precondition_errors() {
        let runtime = test_runtime(Arc::new(TestBackend {
            sandbox_exists: true,
            resolve_precondition: Some("sandbox agent pod IP is not available".to_string()),
        }))
        .await;

        let err = runtime
            .resolve_sandbox_endpoint(&sandbox_record("sb-1", "sandbox-a", SandboxPhase::Ready))
            .await
            .expect_err("endpoint resolution should preserve failed-precondition errors");

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert_eq!(err.message(), "sandbox agent pod IP is not available");
    }

    #[tokio::test]
    async fn reconcile_orphaned_sandboxes_removes_stale_provisioning_records() {
        let runtime = test_runtime(Arc::new(TestBackend::default())).await;
        let sandbox = sandbox_record("sb-1", "sandbox-a", SandboxPhase::Provisioning);
        runtime.store.put_message(&sandbox).await.unwrap();
        runtime.sandbox_index.update_from_sandbox(&sandbox);

        let mut watch_rx = runtime.sandbox_watch_bus.subscribe(&sandbox.id);

        runtime
            .reconcile_orphaned_sandboxes(Duration::ZERO)
            .await
            .unwrap();

        assert!(
            runtime
                .store
                .get_message::<Sandbox>(&sandbox.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            runtime
                .sandbox_index
                .sandbox_id_for_sandbox_name(&sandbox.name)
                .is_none()
        );
        let _ = watch_rx.try_recv();
        assert!(matches!(
            watch_rx.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Closed)
        ));
    }
}
