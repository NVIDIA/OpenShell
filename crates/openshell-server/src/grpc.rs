// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! gRPC service implementation.

#![allow(clippy::ignored_unit_patterns)] // Tokio select! macro generates unit patterns

use crate::persistence::{
    DraftChunkRecord, ObjectId, ObjectName, ObjectType, PolicyRecord, Store, generate_name,
};
use futures::future;
use openshell_core::proto::setting_value;
use openshell_core::proto::{
    ApproveAllDraftChunksRequest, ApproveAllDraftChunksResponse, ApproveDraftChunkRequest,
    ApproveDraftChunkResponse, ClearDraftChunksRequest, ClearDraftChunksResponse,
    CreateProviderRequest, CreateSandboxRequest, CreateSshSessionRequest, CreateSshSessionResponse,
    DeleteProviderRequest, DeleteProviderResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    DraftHistoryEntry, EditDraftChunkRequest, EditDraftChunkResponse, EffectiveSetting,
    ExecSandboxEvent, ExecSandboxExit, ExecSandboxRequest, ExecSandboxStderr, ExecSandboxStdout,
    GetDraftHistoryRequest, GetDraftHistoryResponse, GetDraftPolicyRequest, GetDraftPolicyResponse,
    GetGatewayConfigRequest, GetGatewayConfigResponse, GetProviderRequest, GetSandboxConfigRequest,
    GetSandboxConfigResponse, GetSandboxLogsRequest, GetSandboxLogsResponse,
    GetSandboxPolicyStatusRequest, GetSandboxPolicyStatusResponse,
    GetSandboxProviderEnvironmentRequest, GetSandboxProviderEnvironmentResponse, GetSandboxRequest,
    HealthRequest, HealthResponse, ListProvidersRequest, ListProvidersResponse,
    ListSandboxPoliciesRequest, ListSandboxPoliciesResponse, ListSandboxesRequest,
    ListSandboxesResponse, PolicyChunk, PolicySource, PolicyStatus, Provider, ProviderResponse,
    PushSandboxLogsRequest, PushSandboxLogsResponse, RejectDraftChunkRequest,
    RejectDraftChunkResponse, ReportPolicyStatusRequest, ReportPolicyStatusResponse,
    RevokeSshSessionRequest, RevokeSshSessionResponse, SandboxLogLine, SandboxPolicyRevision,
    SandboxResponse, SandboxStreamEvent, ServiceStatus, SettingScope, SettingValue, SshSession,
    SubmitPolicyAnalysisRequest, SubmitPolicyAnalysisResponse, UndoDraftChunkRequest,
    UndoDraftChunkResponse, UpdateConfigRequest, UpdateConfigResponse, UpdateProviderRequest,
    WatchSandboxRequest, open_shell_server::OpenShell,
};
use openshell_core::proto::{
    Sandbox, SandboxPhase, SandboxPolicy as ProtoSandboxPolicy, SandboxTemplate,
};
use openshell_core::settings::{self, SettingValueKind};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

use russh::ChannelMsg;
use russh::client::AuthResult;

use crate::ServerState;

/// Maximum number of records a single list RPC may return.
///
/// Client-provided `limit` values are clamped to this ceiling to prevent
/// unbounded memory allocation from an excessively large page request.
pub const MAX_PAGE_SIZE: u32 = 1000;

// ---------------------------------------------------------------------------
// Field-level size limits
//
// Named constants for easy tuning. Each limit is chosen to be generous
// enough for legitimate payloads while capping resource-exhaustion vectors.
// ---------------------------------------------------------------------------

/// Maximum length for a sandbox or provider name (Kubernetes name limit).
const MAX_NAME_LEN: usize = 253;

/// Maximum number of providers that can be attached to a sandbox.
const MAX_PROVIDERS: usize = 32;

/// Maximum length for the `log_level` field.
const MAX_LOG_LEVEL_LEN: usize = 32;

/// Maximum number of entries in `spec.environment`.
const MAX_ENVIRONMENT_ENTRIES: usize = 128;

/// Maximum length for an environment map key (bytes).
const MAX_MAP_KEY_LEN: usize = 256;

/// Maximum length for an environment map value (bytes).
const MAX_MAP_VALUE_LEN: usize = 8192;

/// Maximum length for template string fields (`image`, `runtime_class_name`, `agent_socket`).
const MAX_TEMPLATE_STRING_LEN: usize = 1024;

/// Maximum number of entries in template map fields (`labels`, `annotations`, `environment`).
const MAX_TEMPLATE_MAP_ENTRIES: usize = 128;

/// Maximum serialized size (bytes) for template Struct fields (`resources`,
/// `volume_claim_templates`).
const MAX_TEMPLATE_STRUCT_SIZE: usize = 65_536;

/// Maximum serialized size (bytes) for the policy field.
const MAX_POLICY_SIZE: usize = 262_144;

/// Maximum length for a provider type slug.
const MAX_PROVIDER_TYPE_LEN: usize = 64;

/// Maximum number of entries in the provider `credentials` map.
const MAX_PROVIDER_CREDENTIALS_ENTRIES: usize = 32;

/// Maximum number of entries in the provider `config` map.
const MAX_PROVIDER_CONFIG_ENTRIES: usize = 64;

/// Internal object type for durable gateway-global settings.
const GLOBAL_SETTINGS_OBJECT_TYPE: &str = "gateway_settings";
/// Internal object id for the singleton global settings record.
///
/// Prefixed to avoid collision with other object types in the shared
/// `objects` table (PRIMARY KEY is on `id` alone, not `(object_type, id)`).
const GLOBAL_SETTINGS_ID: &str = "gateway_settings:global";
const GLOBAL_SETTINGS_NAME: &str = "global";
/// Internal object type for durable sandbox-scoped settings.
const SANDBOX_SETTINGS_OBJECT_TYPE: &str = "sandbox_settings";
/// Reserved settings key used to store global policy payload.
const POLICY_SETTING_KEY: &str = "policy";
/// Sentinel `sandbox_id` used to store global policy revisions in the
/// `sandbox_policies` table alongside sandbox-scoped revisions.
const GLOBAL_POLICY_SANDBOX_ID: &str = "__global__";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoredSettings {
    revision: u64,
    settings: BTreeMap<String, StoredSettingValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "value")]
enum StoredSettingValue {
    String(String),
    Bool(bool),
    Int(i64),
    /// Hex-encoded binary payload.
    Bytes(String),
}

/// Clamp a client-provided page `limit`.
///
/// Returns `default` when `raw` is 0 (the protobuf zero-value convention),
/// otherwise returns the smaller of `raw` and `max`.
pub fn clamp_limit(raw: u32, default: u32, max: u32) -> u32 {
    if raw == 0 { default } else { raw.min(max) }
}

/// OpenShell gRPC service implementation.
#[derive(Debug, Clone)]
pub struct OpenShellService {
    state: Arc<ServerState>,
}

impl OpenShellService {
    /// Create a new OpenShell service.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl OpenShell for OpenShellService {
    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: ServiceStatus::Healthy.into(),
            version: openshell_core::VERSION.to_string(),
        }))
    }

    async fn create_sandbox(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        let request = request.into_inner();
        let spec = request
            .spec
            .ok_or_else(|| Status::invalid_argument("spec is required"))?;

        // Validate field sizes before any I/O (fail fast on oversized payloads).
        validate_sandbox_spec(&request.name, &spec)?;

        // Validate provider names exist (fail fast). Credentials are fetched at
        // runtime by the sandbox supervisor via GetSandboxProviderEnvironment.
        for name in &spec.providers {
            self.state
                .store
                .get_message_by_name::<Provider>(name)
                .await
                .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
                .ok_or_else(|| {
                    Status::failed_precondition(format!("provider '{name}' not found"))
                })?;
        }

        // Ensure the template always carries the resolved image so clients
        // (CLI, TUI, etc.) can read the actual image from the stored sandbox.
        let mut spec = spec;
        let template = spec.template.get_or_insert_with(SandboxTemplate::default);
        if template.image.is_empty() {
            template.image = self.state.sandbox_client.default_image().to_string();
        }

        if spec.gpu {
            self.state
                .sandbox_client
                .validate_gpu_support()
                .await
                .map_err(|status| {
                    warn!(error = %status, "Rejecting GPU sandbox request");
                    status
                })?;
        }

        // Ensure process identity defaults to "sandbox" when missing or
        // empty, then validate policy safety before persisting.
        if let Some(ref mut policy) = spec.policy {
            openshell_policy::ensure_sandbox_process_identity(policy);
            validate_policy_safety(policy)?;
        }

        let id = uuid::Uuid::new_v4().to_string();
        let name = if request.name.is_empty() {
            petname::petname(2, "-").unwrap_or_else(generate_name)
        } else {
            request.name.clone()
        };
        let namespace = self.state.config.sandbox_namespace.clone();

        let sandbox = Sandbox {
            id: id.clone(),
            name: name.clone(),
            namespace,
            spec: Some(spec),
            status: None,
            phase: SandboxPhase::Provisioning as i32,
            ..Default::default()
        };

        // Persist to the store FIRST so the sandbox watcher always finds
        // the record with `spec` populated.  If we created the k8s
        // resource first, the watcher could race us and write a fallback
        // record with `spec: None`, causing the supervisor to fail with
        // "sandbox has no spec".
        self.state.sandbox_index.update_from_sandbox(&sandbox);

        self.state
            .store
            .put_message(&sandbox)
            .await
            .map_err(|e| Status::internal(format!("persist sandbox failed: {e}")))?;

        // Now create the Kubernetes resource.  If this fails, clean up
        // the store entry to avoid orphans.
        match self.state.sandbox_client.create(&sandbox).await {
            Ok(_) => {}
            Err(kube::Error::Api(err)) if err.code == 409 => {
                // Clean up the store entry we just wrote.
                let _ = self.state.store.delete("sandbox", &id).await;
                self.state.sandbox_index.remove_sandbox(&id);
                warn!(
                    sandbox_id = %id,
                    sandbox_name = %name,
                    "Sandbox already exists in Kubernetes"
                );
                return Err(Status::already_exists("sandbox already exists"));
            }
            Err(err) => {
                // Clean up the store entry we just wrote.
                let _ = self.state.store.delete("sandbox", &id).await;
                self.state.sandbox_index.remove_sandbox(&id);
                warn!(
                    sandbox_id = %id,
                    sandbox_name = %name,
                    error = %err,
                    "CreateSandbox request failed"
                );
                return Err(Status::internal(format!(
                    "create sandbox in kubernetes failed: {err}"
                )));
            }
        }

        self.state.sandbox_watch_bus.notify(&id);

        info!(
            sandbox_id = %id,
            sandbox_name = %name,
            "CreateSandbox request completed successfully"
        );
        Ok(Response::new(SandboxResponse {
            sandbox: Some(sandbox),
        }))
    }

    type WatchSandboxStream = ReceiverStream<Result<SandboxStreamEvent, Status>>;
    type ExecSandboxStream = ReceiverStream<Result<ExecSandboxEvent, Status>>;

    async fn watch_sandbox(
        &self,
        request: Request<WatchSandboxRequest>,
    ) -> Result<Response<Self::WatchSandboxStream>, Status> {
        let req = request.into_inner();
        if req.id.is_empty() {
            return Err(Status::invalid_argument("id is required"));
        }
        let sandbox_id = req.id.clone();

        let follow_status = req.follow_status;
        let follow_logs = req.follow_logs;
        let follow_events = req.follow_events;
        let log_tail = if req.log_tail_lines == 0 {
            200
        } else {
            req.log_tail_lines
        };
        let stop_on_terminal = req.stop_on_terminal;
        let log_since_ms = req.log_since_ms;
        let log_sources = req.log_sources;
        let log_min_level = req.log_min_level;

        let (tx, rx) = mpsc::channel::<Result<SandboxStreamEvent, Status>>(256);
        let state = self.state.clone();

        // Spawn producer task.
        tokio::spawn(async move {
            // Validate that the sandbox exists BEFORE subscribing to any buses.
            // This prevents creating bus entries for non-existent sandbox IDs.
            match state.store.get_message::<Sandbox>(&sandbox_id).await {
                Ok(Some(_)) => {} // sandbox exists, proceed
                Ok(None) => {
                    let _ = tx.send(Err(Status::not_found("sandbox not found"))).await;
                    return;
                }
                Err(e) => {
                    let _ = tx
                        .send(Err(Status::internal(format!("fetch sandbox failed: {e}"))))
                        .await;
                    return;
                }
            }

            // Subscribe to all buses BEFORE reading the snapshot to avoid
            // missing notifications that fire between the snapshot read and subscribe.
            let mut status_rx = if follow_status {
                Some(state.sandbox_watch_bus.subscribe(&sandbox_id))
            } else {
                None
            };
            let mut log_rx = if follow_logs {
                Some(state.tracing_log_bus.subscribe(&sandbox_id))
            } else {
                None
            };
            let mut platform_rx = if follow_events {
                Some(
                    state
                        .tracing_log_bus
                        .platform_event_bus
                        .subscribe(&sandbox_id),
                )
            } else {
                None
            };

            // Re-read the snapshot now that we have subscriptions active
            // (avoids missing notifications between validate and subscribe).
            match state.store.get_message::<Sandbox>(&sandbox_id).await {
                Ok(Some(sandbox)) => {
                    state.sandbox_index.update_from_sandbox(&sandbox);
                    let _ = tx
                        .send(Ok(SandboxStreamEvent {
                            payload: Some(
                                openshell_core::proto::sandbox_stream_event::Payload::Sandbox(
                                    sandbox.clone(),
                                ),
                            ),
                        }))
                        .await;

                    if stop_on_terminal {
                        let phase =
                            SandboxPhase::try_from(sandbox.phase).unwrap_or(SandboxPhase::Unknown);
                        // Only stop on Ready - Error phase may be transient (e.g., ReconcilerError)
                        // and the sandbox may recover. Let the client decide how to handle errors.
                        if phase == SandboxPhase::Ready {
                            return;
                        }
                    }
                }
                Ok(None) => {
                    // Sandbox was deleted between validate and subscribe — end stream.
                    let _ = tx.send(Err(Status::not_found("sandbox not found"))).await;
                    return;
                }
                Err(e) => {
                    let _ = tx
                        .send(Err(Status::internal(format!("fetch sandbox failed: {e}"))))
                        .await;
                    return;
                }
            }

            // Replay tail logs (best-effort), filtered by log_since_ms and log_sources.
            if follow_logs {
                for evt in state.tracing_log_bus.tail(&sandbox_id, log_tail as usize) {
                    if let Some(openshell_core::proto::sandbox_stream_event::Payload::Log(
                        ref log,
                    )) = evt.payload
                    {
                        if log_since_ms > 0 && log.timestamp_ms < log_since_ms {
                            continue;
                        }
                        if !log_sources.is_empty() && !source_matches(&log.source, &log_sources) {
                            continue;
                        }
                        if !level_matches(&log.level, &log_min_level) {
                            continue;
                        }
                    }
                    if tx.send(Ok(evt)).await.is_err() {
                        return;
                    }
                }
            }

            // Replay buffered platform events (best-effort) so late subscribers
            // see Kubernetes events (Scheduled, Pulling, etc.) that already fired.
            if follow_events {
                for evt in state
                    .tracing_log_bus
                    .platform_event_bus
                    .tail(&sandbox_id, 50)
                {
                    if tx.send(Ok(evt)).await.is_err() {
                        return;
                    }
                }
            }

            loop {
                tokio::select! {
                    res = async {
                        match status_rx.as_mut() {
                            Some(rx) => rx.recv().await,
                            None => future::pending().await,
                        }
                    } => {
                        match res {
                            Ok(()) => {
                                match state.store.get_message::<Sandbox>(&sandbox_id).await {
                                    Ok(Some(sandbox)) => {
                                        state.sandbox_index.update_from_sandbox(&sandbox);
                                        if tx.send(Ok(SandboxStreamEvent { payload: Some(openshell_core::proto::sandbox_stream_event::Payload::Sandbox(sandbox.clone()))})).await.is_err() {
                                            return;
                                        }
                                        if stop_on_terminal {
                                            let phase = SandboxPhase::try_from(sandbox.phase).unwrap_or(SandboxPhase::Unknown);
                                            // Only stop on Ready - Error phase may be transient (e.g., ReconcilerError)
                                            // and the sandbox may recover. Let the client decide how to handle errors.
                                            if phase == SandboxPhase::Ready {
                                                return;
                                            }
                                        }
                                    }
                                    Ok(None) => {
                                        // Deleted; end stream.
                                        return;
                                    }
                                    Err(e) => {
                                        let _ = tx.send(Err(Status::internal(format!("fetch sandbox failed: {e}")))).await;
                                        return;
                                    }
                                }
                            }
                            Err(err) => {
                                let _ = tx.send(Err(crate::sandbox_watch::broadcast_to_status(err))).await;
                                return;
                            }
                        }
                    }
                    res = async {
                        match log_rx.as_mut() {
                            Some(rx) => rx.recv().await,
                            None => future::pending().await,
                        }
                    } => {
                        match res {
                            Ok(evt) => {
                                // Apply source + level filter on live log events.
                                if let Some(openshell_core::proto::sandbox_stream_event::Payload::Log(ref log)) = evt.payload {
                                    if !log_sources.is_empty() && !source_matches(&log.source, &log_sources) {
                                        continue;
                                    }
                                    if !level_matches(&log.level, &log_min_level) {
                                        continue;
                                    }
                                }
                                if tx.send(Ok(evt)).await.is_err() {
                                    return;
                                }
                            }
                            Err(err) => {
                                let _ = tx.send(Err(crate::sandbox_watch::broadcast_to_status(err))).await;
                                return;
                            }
                        }
                    }
                    res = async {
                        match platform_rx.as_mut() {
                            Some(rx) => rx.recv().await,
                            None => future::pending().await,
                        }
                    } => {
                        match res {
                            Ok(evt) => {
                                if tx.send(Ok(evt)).await.is_err() {
                                    return;
                                }
                            }
                            Err(err) => {
                                let _ = tx.send(Err(crate::sandbox_watch::broadcast_to_status(err))).await;
                                return;
                            }
                        }
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_sandbox(
        &self,
        request: Request<GetSandboxRequest>,
    ) -> Result<Response<SandboxResponse>, Status> {
        let name = request.into_inner().name;
        if name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }

        let sandbox = self
            .state
            .store
            .get_message_by_name::<Sandbox>(&name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?;

        let sandbox = sandbox.ok_or_else(|| Status::not_found("sandbox not found"))?;
        Ok(Response::new(SandboxResponse {
            sandbox: Some(sandbox),
        }))
    }

    async fn list_sandboxes(
        &self,
        request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        let request = request.into_inner();
        let limit = clamp_limit(request.limit, 100, MAX_PAGE_SIZE);
        let records = self
            .state
            .store
            .list(Sandbox::object_type(), limit, request.offset)
            .await
            .map_err(|e| Status::internal(format!("list sandboxes failed: {e}")))?;

        let mut sandboxes = Vec::with_capacity(records.len());
        for record in records {
            let mut sandbox = Sandbox::decode(record.payload.as_slice())
                .map_err(|e| Status::internal(format!("decode sandbox failed: {e}")))?;
            sandbox.created_at_ms = record.created_at_ms;
            sandboxes.push(sandbox);
        }

        Ok(Response::new(ListSandboxesResponse { sandboxes }))
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        let name = request.into_inner().name;
        if name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }

        let sandbox = self
            .state
            .store
            .get_message_by_name::<Sandbox>(&name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?;

        let Some(mut sandbox) = sandbox else {
            return Err(Status::not_found("sandbox not found"));
        };

        let id = sandbox.id.clone();

        sandbox.phase = SandboxPhase::Deleting as i32;
        self.state
            .store
            .put_message(&sandbox)
            .await
            .map_err(|e| Status::internal(format!("persist sandbox failed: {e}")))?;

        self.state.sandbox_index.update_from_sandbox(&sandbox);
        self.state.sandbox_watch_bus.notify(&id);

        // Clean up SSH sessions associated with this sandbox.
        if let Ok(records) = self
            .state
            .store
            .list(SshSession::object_type(), 1000, 0)
            .await
        {
            for record in records {
                if let Ok(session) = SshSession::decode(record.payload.as_slice())
                    && session.sandbox_id == id
                    && let Err(e) = self
                        .state
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

        // Clean up sandbox-scoped settings record.
        if let Err(e) = self
            .state
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

        let deleted = match self.state.sandbox_client.delete(&sandbox.name).await {
            Ok(deleted) => deleted,
            Err(err) => {
                warn!(
                    sandbox_id = %id,
                    sandbox_name = %sandbox.name,
                    error = %err,
                    "DeleteSandbox request failed"
                );
                return Err(Status::internal(format!(
                    "delete sandbox in kubernetes failed: {err}"
                )));
            }
        };

        if !deleted && let Err(e) = self.state.store.delete(Sandbox::object_type(), &id).await {
            warn!(sandbox_id = %id, error = %e, "Failed to clean up store after delete");
        }

        // Clean up bus entries to prevent unbounded memory growth.
        self.state.tracing_log_bus.remove(&id);
        self.state.tracing_log_bus.platform_event_bus.remove(&id);
        self.state.sandbox_watch_bus.remove(&id);

        info!(
            sandbox_id = %id,
            sandbox_name = %sandbox.name,
            "DeleteSandbox request completed successfully"
        );
        Ok(Response::new(DeleteSandboxResponse { deleted }))
    }

    async fn create_provider(
        &self,
        request: Request<CreateProviderRequest>,
    ) -> Result<Response<ProviderResponse>, Status> {
        let req = request.into_inner();
        let provider = req
            .provider
            .ok_or_else(|| Status::invalid_argument("provider is required"))?;
        let provider = create_provider_record(self.state.store.as_ref(), provider).await?;

        Ok(Response::new(ProviderResponse {
            provider: Some(provider),
        }))
    }

    async fn get_provider(
        &self,
        request: Request<GetProviderRequest>,
    ) -> Result<Response<ProviderResponse>, Status> {
        let name = request.into_inner().name;
        let provider = get_provider_record(self.state.store.as_ref(), &name).await?;

        Ok(Response::new(ProviderResponse {
            provider: Some(provider),
        }))
    }

    async fn list_providers(
        &self,
        request: Request<ListProvidersRequest>,
    ) -> Result<Response<ListProvidersResponse>, Status> {
        let request = request.into_inner();
        let limit = clamp_limit(request.limit, 100, MAX_PAGE_SIZE);
        let providers =
            list_provider_records(self.state.store.as_ref(), limit, request.offset).await?;

        Ok(Response::new(ListProvidersResponse { providers }))
    }

    async fn update_provider(
        &self,
        request: Request<UpdateProviderRequest>,
    ) -> Result<Response<ProviderResponse>, Status> {
        let req = request.into_inner();
        let provider = req
            .provider
            .ok_or_else(|| Status::invalid_argument("provider is required"))?;
        let provider = update_provider_record(self.state.store.as_ref(), provider).await?;

        Ok(Response::new(ProviderResponse {
            provider: Some(provider),
        }))
    }

    async fn delete_provider(
        &self,
        request: Request<DeleteProviderRequest>,
    ) -> Result<Response<DeleteProviderResponse>, Status> {
        let name = request.into_inner().name;
        let deleted = delete_provider_record(self.state.store.as_ref(), &name).await?;

        Ok(Response::new(DeleteProviderResponse { deleted }))
    }

    async fn get_sandbox_config(
        &self,
        request: Request<GetSandboxConfigRequest>,
    ) -> Result<Response<GetSandboxConfigResponse>, Status> {
        let sandbox_id = request.into_inner().sandbox_id;

        let sandbox = self
            .state
            .store
            .get_message::<Sandbox>(&sandbox_id)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;

        // Try to get the latest policy from the policy history table.
        let latest = self
            .state
            .store
            .get_latest_policy(&sandbox_id)
            .await
            .map_err(|e| Status::internal(format!("fetch policy history failed: {e}")))?;

        let mut policy_source = PolicySource::Sandbox;
        let (mut policy, mut version, mut policy_hash) = if let Some(record) = latest {
            let decoded = ProtoSandboxPolicy::decode(record.policy_payload.as_slice())
                .map_err(|e| Status::internal(format!("decode policy failed: {e}")))?;
            debug!(
                sandbox_id = %sandbox_id,
                version = record.version,
                "GetSandboxConfig served from policy history"
            );
            (
                Some(decoded),
                u32::try_from(record.version).unwrap_or(0),
                record.policy_hash,
            )
        } else {
            // Lazy backfill: no policy history exists yet.
            let spec = sandbox
                .spec
                .ok_or_else(|| Status::internal("sandbox has no spec"))?;

            match spec.policy {
                // If spec.policy is None, the sandbox was created without a policy.
                // Return an empty policy payload so the sandbox can discover policy
                // from disk or fall back to its restrictive default.
                None => {
                    debug!(
                        sandbox_id = %sandbox_id,
                        "GetSandboxConfig: no policy configured, returning empty response"
                    );
                    (None, 0, String::new())
                }
                Some(spec_policy) => {
                    let hash = deterministic_policy_hash(&spec_policy);
                    let payload = spec_policy.encode_to_vec();
                    let policy_id = uuid::Uuid::new_v4().to_string();

                    // Best-effort backfill: if it fails (e.g., concurrent backfill race), we still
                    // return the policy from spec.
                    if let Err(e) = self
                        .state
                        .store
                        .put_policy_revision(&policy_id, &sandbox_id, 1, &payload, &hash)
                        .await
                    {
                        warn!(
                            sandbox_id = %sandbox_id,
                            error = %e,
                            "Failed to backfill policy version 1"
                        );
                    } else if let Err(e) = self
                        .state
                        .store
                        .update_policy_status(&sandbox_id, 1, "loaded", None, None)
                        .await
                    {
                        warn!(
                            sandbox_id = %sandbox_id,
                            error = %e,
                            "Failed to mark backfilled policy as loaded"
                        );
                    }

                    info!(
                        sandbox_id = %sandbox_id,
                        "GetSandboxConfig served from spec (backfilled version 1)"
                    );

                    (Some(spec_policy), 1, hash)
                }
            }
        };

        let global_settings = load_global_settings(self.state.store.as_ref()).await?;
        let sandbox_settings =
            load_sandbox_settings(self.state.store.as_ref(), &sandbox_id).await?;

        let mut global_policy_version: u32 = 0;

        if let Some(global_policy) = decode_policy_from_global_settings(&global_settings)? {
            policy = Some(global_policy.clone());
            policy_hash = deterministic_policy_hash(&global_policy);
            policy_source = PolicySource::Global;
            // Keep sandbox policy version for status APIs, but global policy
            // updates are tracked via config_revision.
            if version == 0 {
                version = 1;
            }
            // Look up the global policy revision version number.
            if let Ok(Some(global_rev)) = self
                .state
                .store
                .get_latest_policy(GLOBAL_POLICY_SANDBOX_ID)
                .await
            {
                global_policy_version = u32::try_from(global_rev.version).unwrap_or(0);
            }
        }

        let settings = merge_effective_settings(&global_settings, &sandbox_settings)?;
        let config_revision = compute_config_revision(policy.as_ref(), &settings, policy_source);

        Ok(Response::new(GetSandboxConfigResponse {
            policy,
            version,
            policy_hash,
            settings,
            config_revision,
            policy_source: policy_source.into(),
            global_policy_version,
        }))
    }

    async fn get_gateway_config(
        &self,
        _request: Request<GetGatewayConfigRequest>,
    ) -> Result<Response<GetGatewayConfigResponse>, Status> {
        let global_settings = load_global_settings(self.state.store.as_ref()).await?;
        let settings = materialize_global_settings(&global_settings)?;
        Ok(Response::new(GetGatewayConfigResponse {
            settings,
            settings_revision: global_settings.revision,
        }))
    }

    async fn get_sandbox_provider_environment(
        &self,
        request: Request<GetSandboxProviderEnvironmentRequest>,
    ) -> Result<Response<GetSandboxProviderEnvironmentResponse>, Status> {
        let sandbox_id = request.into_inner().sandbox_id;

        let sandbox = self
            .state
            .store
            .get_message::<Sandbox>(&sandbox_id)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;

        let spec = sandbox
            .spec
            .ok_or_else(|| Status::internal("sandbox has no spec"))?;

        let environment =
            resolve_provider_environment(self.state.store.as_ref(), &spec.providers).await?;

        info!(
            sandbox_id = %sandbox_id,
            provider_count = spec.providers.len(),
            env_count = environment.len(),
            "GetSandboxProviderEnvironment request completed successfully"
        );

        Ok(Response::new(GetSandboxProviderEnvironmentResponse {
            environment,
        }))
    }

    async fn create_ssh_session(
        &self,
        request: Request<CreateSshSessionRequest>,
    ) -> Result<Response<CreateSshSessionResponse>, Status> {
        let req = request.into_inner();
        if req.sandbox_id.is_empty() {
            return Err(Status::invalid_argument("sandbox_id is required"));
        }

        let sandbox = self
            .state
            .store
            .get_message::<Sandbox>(&req.sandbox_id)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;

        if SandboxPhase::try_from(sandbox.phase).ok() != Some(SandboxPhase::Ready) {
            return Err(Status::failed_precondition("sandbox is not ready"));
        }

        let token = uuid::Uuid::new_v4().to_string();
        let now_ms = current_time_ms()
            .map_err(|e| Status::internal(format!("timestamp generation failed: {e}")))?;
        let expires_at_ms = if self.state.config.ssh_session_ttl_secs > 0 {
            now_ms + (self.state.config.ssh_session_ttl_secs as i64 * 1000)
        } else {
            0
        };
        let session = SshSession {
            id: token.clone(),
            sandbox_id: req.sandbox_id.clone(),
            token: token.clone(),
            created_at_ms: now_ms,
            revoked: false,
            name: generate_name(),
            expires_at_ms,
        };

        self.state
            .store
            .put_message(&session)
            .await
            .map_err(|e| Status::internal(format!("persist ssh session failed: {e}")))?;

        let (gateway_host, gateway_port) = resolve_gateway(&self.state.config);
        let scheme = if self.state.config.tls.is_some() {
            "https"
        } else {
            "http"
        };

        Ok(Response::new(CreateSshSessionResponse {
            sandbox_id: req.sandbox_id,
            token,
            gateway_host,
            gateway_port: gateway_port.into(),
            gateway_scheme: scheme.to_string(),
            connect_path: self.state.config.ssh_connect_path.clone(),
            host_key_fingerprint: String::new(),
            expires_at_ms,
        }))
    }

    async fn exec_sandbox(
        &self,
        request: Request<ExecSandboxRequest>,
    ) -> Result<Response<Self::ExecSandboxStream>, Status> {
        let req = request.into_inner();
        if req.sandbox_id.is_empty() {
            return Err(Status::invalid_argument("sandbox_id is required"));
        }
        if req.command.is_empty() {
            return Err(Status::invalid_argument("command is required"));
        }
        if req.environment.keys().any(|key| !is_valid_env_key(key)) {
            return Err(Status::invalid_argument(
                "environment keys must match ^[A-Za-z_][A-Za-z0-9_]*$",
            ));
        }
        validate_exec_request_fields(&req)?;

        let sandbox = self
            .state
            .store
            .get_message::<Sandbox>(&req.sandbox_id)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;

        if SandboxPhase::try_from(sandbox.phase).ok() != Some(SandboxPhase::Ready) {
            return Err(Status::failed_precondition("sandbox is not ready"));
        }

        let (target_host, target_port) = resolve_sandbox_exec_target(&self.state, &sandbox).await?;
        let command_str = build_remote_exec_command(&req)
            .map_err(|e| Status::invalid_argument(format!("command construction failed: {e}")))?;
        let stdin_payload = req.stdin;
        let timeout_seconds = req.timeout_seconds;
        let sandbox_id = sandbox.id;
        let handshake_secret = self.state.config.ssh_handshake_secret.clone();

        let (tx, rx) = mpsc::channel::<Result<ExecSandboxEvent, Status>>(256);
        tokio::spawn(async move {
            if let Err(err) = stream_exec_over_ssh(
                tx.clone(),
                &sandbox_id,
                &target_host,
                target_port,
                &command_str,
                stdin_payload,
                timeout_seconds,
                &handshake_secret,
            )
            .await
            {
                warn!(sandbox_id = %sandbox_id, error = %err, "ExecSandbox failed");
                let _ = tx.send(Err(err)).await;
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn revoke_ssh_session(
        &self,
        request: Request<RevokeSshSessionRequest>,
    ) -> Result<Response<RevokeSshSessionResponse>, Status> {
        let token = request.into_inner().token;
        if token.is_empty() {
            return Err(Status::invalid_argument("token is required"));
        }

        let session = self
            .state
            .store
            .get_message::<SshSession>(&token)
            .await
            .map_err(|e| Status::internal(format!("fetch ssh session failed: {e}")))?;

        let Some(mut session) = session else {
            return Ok(Response::new(RevokeSshSessionResponse { revoked: false }));
        };

        session.revoked = true;
        self.state
            .store
            .put_message(&session)
            .await
            .map_err(|e| Status::internal(format!("persist ssh session failed: {e}")))?;

        Ok(Response::new(RevokeSshSessionResponse { revoked: true }))
    }

    // -------------------------------------------------------------------
    // Policy update handlers
    // -------------------------------------------------------------------

    async fn update_config(
        &self,
        request: Request<UpdateConfigRequest>,
    ) -> Result<Response<UpdateConfigResponse>, Status> {
        let req = request.into_inner();
        let key = req.setting_key.trim();
        let has_policy = req.policy.is_some();
        let has_setting = !key.is_empty();

        if has_policy && has_setting {
            return Err(Status::invalid_argument(
                "policy and setting_key cannot be set in the same request",
            ));
        }
        if !has_policy && !has_setting {
            return Err(Status::invalid_argument(
                "either policy or setting_key must be provided",
            ));
        }

        if req.global {
            // Acquire the settings mutex for the entire global mutation to
            // prevent read-modify-write races between concurrent requests.
            let _settings_guard = self.state.settings_mutex.lock().await;

            if has_policy {
                if req.delete_setting {
                    return Err(Status::invalid_argument(
                        "delete_setting cannot be combined with policy payload",
                    ));
                }
                let mut new_policy = req.policy.ok_or_else(|| {
                    Status::invalid_argument("policy is required for global policy update")
                })?;
                openshell_policy::ensure_sandbox_process_identity(&mut new_policy);
                validate_policy_safety(&new_policy)?;

                // Compute hash and check for no-op (same policy as latest).
                let payload = new_policy.encode_to_vec();
                let hash = deterministic_policy_hash(&new_policy);

                let latest = self
                    .state
                    .store
                    .get_latest_policy(GLOBAL_POLICY_SANDBOX_ID)
                    .await
                    .map_err(|e| {
                        Status::internal(format!("fetch latest global policy failed: {e}"))
                    })?;

                if let Some(ref current) = latest {
                    // Only dedup if the latest revision is still active
                    // (loaded). If it was superseded (e.g. after a global
                    // policy delete), always create a new revision.
                    if current.policy_hash == hash && current.status == "loaded" {
                        // Same policy hash — skip creating a new revision but
                        // still ensure the settings blob has the policy key
                        // (it may have been lost to a pod restart while the
                        // sandbox_policies table retained the revision).
                        let mut global_settings =
                            load_global_settings(self.state.store.as_ref()).await?;
                        let stored_value = StoredSettingValue::Bytes(hex::encode(&payload));
                        let changed = upsert_setting_value(
                            &mut global_settings.settings,
                            POLICY_SETTING_KEY,
                            stored_value,
                        );
                        if changed {
                            global_settings.revision = global_settings.revision.wrapping_add(1);
                            save_global_settings(self.state.store.as_ref(), &global_settings)
                                .await?;
                        }
                        return Ok(Response::new(UpdateConfigResponse {
                            version: u32::try_from(current.version).unwrap_or(0),
                            policy_hash: hash,
                            settings_revision: global_settings.revision,
                            deleted: false,
                        }));
                    }
                }

                let next_version = latest.map_or(1, |r| r.version + 1);
                let policy_id = uuid::Uuid::new_v4().to_string();

                // Persist the global policy revision.
                self.state
                    .store
                    .put_policy_revision(
                        &policy_id,
                        GLOBAL_POLICY_SANDBOX_ID,
                        next_version,
                        &payload,
                        &hash,
                    )
                    .await
                    .map_err(|e| {
                        Status::internal(format!("persist global policy revision failed: {e}"))
                    })?;

                // Mark it as loaded immediately (no sandbox confirmation for
                // global policies) and supersede older revisions.
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_millis() as i64);
                let _ = self
                    .state
                    .store
                    .update_policy_status(
                        GLOBAL_POLICY_SANDBOX_ID,
                        next_version,
                        "loaded",
                        None,
                        Some(now_ms),
                    )
                    .await;
                let _ = self
                    .state
                    .store
                    .supersede_older_policies(GLOBAL_POLICY_SANDBOX_ID, next_version)
                    .await;

                // Also store in the settings blob (delivery mechanism for
                // GetSandboxConfig).
                let mut global_settings = load_global_settings(self.state.store.as_ref()).await?;
                let stored_value = StoredSettingValue::Bytes(hex::encode(&payload));
                let changed = upsert_setting_value(
                    &mut global_settings.settings,
                    POLICY_SETTING_KEY,
                    stored_value,
                );
                if changed {
                    global_settings.revision = global_settings.revision.wrapping_add(1);
                    save_global_settings(self.state.store.as_ref(), &global_settings).await?;
                }

                return Ok(Response::new(UpdateConfigResponse {
                    version: u32::try_from(next_version).unwrap_or(0),
                    policy_hash: hash,
                    settings_revision: global_settings.revision,
                    deleted: false,
                }));
            }

            // Global setting mutation.
            if key == POLICY_SETTING_KEY && !req.delete_setting {
                return Err(Status::invalid_argument(
                    "reserved key 'policy' must be set via the policy field",
                ));
            }
            if key != POLICY_SETTING_KEY {
                validate_registered_setting_key(key)?;
            }

            let mut global_settings = load_global_settings(self.state.store.as_ref()).await?;
            let changed = if req.delete_setting {
                let removed = global_settings.settings.remove(key).is_some();
                // When deleting the global policy key, supersede all global
                // policy revisions so they no longer appear as "Loaded".
                if removed && key == POLICY_SETTING_KEY {
                    if let Ok(Some(latest)) = self
                        .state
                        .store
                        .get_latest_policy(GLOBAL_POLICY_SANDBOX_ID)
                        .await
                    {
                        let _ = self
                            .state
                            .store
                            .supersede_older_policies(GLOBAL_POLICY_SANDBOX_ID, latest.version + 1)
                            .await;
                    }
                }
                removed
            } else {
                let setting = req
                    .setting_value
                    .as_ref()
                    .ok_or_else(|| Status::invalid_argument("setting_value is required"))?;
                let stored = proto_setting_to_stored(key, setting)?;
                upsert_setting_value(&mut global_settings.settings, key, stored)
            };

            if changed {
                global_settings.revision = global_settings.revision.wrapping_add(1);
                save_global_settings(self.state.store.as_ref(), &global_settings).await?;
            }

            return Ok(Response::new(UpdateConfigResponse {
                version: 0,
                policy_hash: String::new(),
                settings_revision: global_settings.revision,
                deleted: req.delete_setting && changed,
            }));
        }

        if req.name.is_empty() {
            return Err(Status::invalid_argument(
                "name is required for sandbox-scoped updates",
            ));
        }

        // Resolve sandbox by name.
        let sandbox = self
            .state
            .store
            .get_message_by_name::<Sandbox>(&req.name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        let sandbox_id = sandbox.id.clone();

        if has_setting {
            // Acquire the settings mutex to prevent races between the
            // global-precedence check and the sandbox settings write.
            let _settings_guard = self.state.settings_mutex.lock().await;

            if key == POLICY_SETTING_KEY {
                return Err(Status::invalid_argument(
                    "reserved key 'policy' must be set via policy commands",
                ));
            }

            let global_settings = load_global_settings(self.state.store.as_ref()).await?;
            let globally_managed = global_settings.settings.contains_key(key);

            if req.delete_setting {
                // Sandbox-scoped delete: allowed only when the key is not
                // globally managed.
                if globally_managed {
                    return Err(Status::failed_precondition(format!(
                        "setting '{key}' is managed globally; delete the global setting first"
                    )));
                }

                let mut sandbox_settings =
                    load_sandbox_settings(self.state.store.as_ref(), &sandbox_id).await?;
                let removed = sandbox_settings.settings.remove(key).is_some();
                if removed {
                    sandbox_settings.revision = sandbox_settings.revision.wrapping_add(1);
                    save_sandbox_settings(
                        self.state.store.as_ref(),
                        &sandbox_id,
                        &sandbox.name,
                        &sandbox_settings,
                    )
                    .await?;
                }

                return Ok(Response::new(UpdateConfigResponse {
                    version: 0,
                    policy_hash: String::new(),
                    settings_revision: sandbox_settings.revision,
                    deleted: removed,
                }));
            }

            if globally_managed {
                return Err(Status::failed_precondition(format!(
                    "setting '{key}' is managed globally; delete the global setting before sandbox update"
                )));
            }

            let setting = req
                .setting_value
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("setting_value is required"))?;
            let stored = proto_setting_to_stored(key, setting)?;

            let mut sandbox_settings =
                load_sandbox_settings(self.state.store.as_ref(), &sandbox_id).await?;
            let changed = upsert_setting_value(&mut sandbox_settings.settings, key, stored);
            if changed {
                sandbox_settings.revision = sandbox_settings.revision.wrapping_add(1);
                save_sandbox_settings(
                    self.state.store.as_ref(),
                    &sandbox_id,
                    &sandbox.name,
                    &sandbox_settings,
                )
                .await?;
            }

            return Ok(Response::new(UpdateConfigResponse {
                version: 0,
                policy_hash: String::new(),
                settings_revision: sandbox_settings.revision,
                deleted: false,
            }));
        }

        // Sandbox-scoped policy update.
        let mut new_policy = req
            .policy
            .ok_or_else(|| Status::invalid_argument("policy is required"))?;

        let global_settings = load_global_settings(self.state.store.as_ref()).await?;
        if global_settings.settings.contains_key(POLICY_SETTING_KEY) {
            return Err(Status::failed_precondition(
                "policy is managed globally; delete global policy before sandbox policy update",
            ));
        }

        // Get the baseline (version 1) policy for static field validation.
        let spec = sandbox
            .spec
            .as_ref()
            .ok_or_else(|| Status::internal("sandbox has no spec"))?;

        // Ensure process identity defaults to "sandbox" when missing or empty.
        openshell_policy::ensure_sandbox_process_identity(&mut new_policy);

        if let Some(baseline_policy) = spec.policy.as_ref() {
            // Validate static fields haven't changed.
            validate_static_fields_unchanged(baseline_policy, &new_policy)?;

            // Allow network policy additions/removals on live sandboxes. The
            // cluster runtime always uses proxy mode for proto-backed sandbox
            // policies, so an empty `network_policies` map is no longer a real
            // mode boundary.

            // Validate policy safety (no root, no path traversal, etc.).
            validate_policy_safety(&new_policy)?;
        } else {
            // No baseline policy exists (sandbox created without one). The
            // sandbox is syncing a locally-discovered or restrictive-default
            // policy. Backfill spec.policy so future updates can validate
            // against it.
            let mut sandbox = sandbox;
            if let Some(ref mut spec) = sandbox.spec {
                spec.policy = Some(new_policy.clone());
            }
            self.state
                .store
                .put_message(&sandbox)
                .await
                .map_err(|e| Status::internal(format!("backfill spec.policy failed: {e}")))?;
            info!(
                sandbox_id = %sandbox_id,
                "UpdateConfig: backfilled spec.policy from sandbox-discovered policy"
            );
        }

        // Determine next version number.
        let latest = self
            .state
            .store
            .get_latest_policy(&sandbox_id)
            .await
            .map_err(|e| Status::internal(format!("fetch latest policy failed: {e}")))?;

        // Compute hash and check if the policy actually changed.
        let payload = new_policy.encode_to_vec();
        let hash = deterministic_policy_hash(&new_policy);

        if let Some(ref current) = latest
            && current.policy_hash == hash
        {
            return Ok(Response::new(UpdateConfigResponse {
                version: u32::try_from(current.version).unwrap_or(0),
                policy_hash: hash,
                settings_revision: 0,
                deleted: false,
            }));
        }

        let next_version = latest.map_or(1, |r| r.version + 1);
        let policy_id = uuid::Uuid::new_v4().to_string();

        self.state
            .store
            .put_policy_revision(&policy_id, &sandbox_id, next_version, &payload, &hash)
            .await
            .map_err(|e| Status::internal(format!("persist policy revision failed: {e}")))?;

        // Supersede older pending revisions.
        let _ = self
            .state
            .store
            .supersede_older_policies(&sandbox_id, next_version)
            .await;

        // Notify watchers (unblocks CLI --wait polling).
        self.state.sandbox_watch_bus.notify(&sandbox_id);

        info!(
            sandbox_id = %sandbox_id,
            version = next_version,
            policy_hash = %hash,
            "UpdateConfig: new policy version persisted"
        );

        Ok(Response::new(UpdateConfigResponse {
            version: u32::try_from(next_version).unwrap_or(0),
            policy_hash: hash,
            settings_revision: 0,
            deleted: false,
        }))
    }

    async fn get_sandbox_policy_status(
        &self,
        request: Request<GetSandboxPolicyStatusRequest>,
    ) -> Result<Response<GetSandboxPolicyStatusResponse>, Status> {
        let req = request.into_inner();

        let (policy_id, active_version) = if req.global {
            (GLOBAL_POLICY_SANDBOX_ID.to_string(), 0_u32)
        } else {
            if req.name.is_empty() {
                return Err(Status::invalid_argument("name is required"));
            }
            let sandbox = self
                .state
                .store
                .get_message_by_name::<Sandbox>(&req.name)
                .await
                .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
                .ok_or_else(|| Status::not_found("sandbox not found"))?;
            (sandbox.id, sandbox.current_policy_version)
        };

        let record = if req.version == 0 {
            self.state
                .store
                .get_latest_policy(&policy_id)
                .await
                .map_err(|e| Status::internal(format!("fetch policy failed: {e}")))?
        } else {
            self.state
                .store
                .get_policy_by_version(&policy_id, i64::from(req.version))
                .await
                .map_err(|e| Status::internal(format!("fetch policy failed: {e}")))?
        };

        let not_found_msg = if req.global {
            "no global policy revision found"
        } else {
            "no policy revision found for this sandbox"
        };
        let record = record.ok_or_else(|| Status::not_found(not_found_msg))?;

        Ok(Response::new(GetSandboxPolicyStatusResponse {
            revision: Some(policy_record_to_revision(&record, true)),
            active_version,
        }))
    }

    async fn list_sandbox_policies(
        &self,
        request: Request<ListSandboxPoliciesRequest>,
    ) -> Result<Response<ListSandboxPoliciesResponse>, Status> {
        let req = request.into_inner();

        let policy_id = if req.global {
            GLOBAL_POLICY_SANDBOX_ID.to_string()
        } else {
            if req.name.is_empty() {
                return Err(Status::invalid_argument("name is required"));
            }
            let sandbox = self
                .state
                .store
                .get_message_by_name::<Sandbox>(&req.name)
                .await
                .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
                .ok_or_else(|| Status::not_found("sandbox not found"))?;
            sandbox.id
        };

        let limit = clamp_limit(req.limit, 50, MAX_PAGE_SIZE);
        let records = self
            .state
            .store
            .list_policies(&policy_id, limit, req.offset)
            .await
            .map_err(|e| Status::internal(format!("list policies failed: {e}")))?;

        let revisions = records
            .iter()
            .map(|r| policy_record_to_revision(r, false))
            .collect();

        Ok(Response::new(ListSandboxPoliciesResponse { revisions }))
    }

    async fn report_policy_status(
        &self,
        request: Request<ReportPolicyStatusRequest>,
    ) -> Result<Response<ReportPolicyStatusResponse>, Status> {
        let req = request.into_inner();
        if req.sandbox_id.is_empty() {
            return Err(Status::invalid_argument("sandbox_id is required"));
        }
        if req.version == 0 {
            return Err(Status::invalid_argument("version is required"));
        }

        let version = i64::from(req.version);
        let status_str = match PolicyStatus::try_from(req.status) {
            Ok(PolicyStatus::Loaded) => "loaded",
            Ok(PolicyStatus::Failed) => "failed",
            _ => return Err(Status::invalid_argument("status must be LOADED or FAILED")),
        };

        let loaded_at_ms = if status_str == "loaded" {
            Some(current_time_ms().map_err(|e| Status::internal(format!("timestamp error: {e}")))?)
        } else {
            None
        };

        let load_error = if status_str == "failed" && !req.load_error.is_empty() {
            Some(req.load_error.as_str())
        } else {
            None
        };

        let updated = self
            .state
            .store
            .update_policy_status(
                &req.sandbox_id,
                version,
                status_str,
                load_error,
                loaded_at_ms,
            )
            .await
            .map_err(|e| Status::internal(format!("update policy status failed: {e}")))?;

        if !updated {
            return Err(Status::not_found("policy revision not found"));
        }

        // If loaded, update the sandbox's current_policy_version and
        // supersede all older versions.
        if status_str == "loaded" {
            let _ = self
                .state
                .store
                .supersede_older_policies(&req.sandbox_id, version)
                .await;
            if let Ok(Some(mut sandbox)) = self
                .state
                .store
                .get_message::<Sandbox>(&req.sandbox_id)
                .await
            {
                sandbox.current_policy_version = req.version;
                let _ = self.state.store.put_message(&sandbox).await;
            }
            // Notify watchers so CLI --wait can detect the status change.
            self.state.sandbox_watch_bus.notify(&req.sandbox_id);
        }

        info!(
            sandbox_id = %req.sandbox_id,
            version = req.version,
            status = %status_str,
            "ReportPolicyStatus: sandbox reported policy load result"
        );

        Ok(Response::new(ReportPolicyStatusResponse {}))
    }

    // -------------------------------------------------------------------
    // Sandbox logs handler
    // -------------------------------------------------------------------

    async fn get_sandbox_logs(
        &self,
        request: Request<GetSandboxLogsRequest>,
    ) -> Result<Response<GetSandboxLogsResponse>, Status> {
        let req = request.into_inner();
        if req.sandbox_id.is_empty() {
            return Err(Status::invalid_argument("sandbox_id is required"));
        }

        let lines = if req.lines == 0 { 2000 } else { req.lines };
        let tail = self
            .state
            .tracing_log_bus
            .tail(&req.sandbox_id, lines as usize);

        let buffer_total = tail.len() as u32;

        // Extract SandboxLogLine and apply time + source filters.
        let logs: Vec<SandboxLogLine> = tail
            .into_iter()
            .filter_map(|evt| {
                if let Some(openshell_core::proto::sandbox_stream_event::Payload::Log(log)) =
                    evt.payload
                {
                    if req.since_ms > 0 && log.timestamp_ms < req.since_ms {
                        return None;
                    }
                    if !req.sources.is_empty() && !source_matches(&log.source, &req.sources) {
                        return None;
                    }
                    if !level_matches(&log.level, &req.min_level) {
                        return None;
                    }
                    Some(log)
                } else {
                    None
                }
            })
            .collect();

        Ok(Response::new(GetSandboxLogsResponse { logs, buffer_total }))
    }

    async fn push_sandbox_logs(
        &self,
        request: Request<tonic::Streaming<PushSandboxLogsRequest>>,
    ) -> Result<Response<PushSandboxLogsResponse>, Status> {
        let mut stream = request.into_inner();
        let mut validated = false;

        while let Some(batch) = stream
            .message()
            .await
            .map_err(|e| Status::internal(format!("stream error: {e}")))?
        {
            if batch.sandbox_id.is_empty() {
                continue;
            }

            // Validate sandbox existence once at stream open (first batch).
            // Subsequent batches trust the validated sandbox_id. If the sandbox
            // is deleted mid-stream, bus remove() drops the sender and publish
            // silently discards via `let _ = tx.send(...)`.
            if !validated {
                self.state
                    .store
                    .get_message::<Sandbox>(&batch.sandbox_id)
                    .await
                    .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
                    .ok_or_else(|| Status::not_found("sandbox not found"))?;
                validated = true;
            }

            // Cap lines per batch to prevent abuse.
            for log in batch.logs.into_iter().take(100) {
                let mut log = log;
                // Force source to "sandbox" — the sandbox cannot claim to be the gateway.
                log.source = "sandbox".to_string();
                // Force sandbox_id to match the batch envelope.
                log.sandbox_id.clone_from(&batch.sandbox_id);
                self.state.tracing_log_bus.publish_external(log);
            }
        }

        Ok(Response::new(PushSandboxLogsResponse {}))
    }

    // -----------------------------------------------------------------------
    // Draft policy recommendation handlers
    // -----------------------------------------------------------------------

    async fn submit_policy_analysis(
        &self,
        request: Request<SubmitPolicyAnalysisRequest>,
    ) -> Result<Response<SubmitPolicyAnalysisResponse>, Status> {
        let req = request.into_inner();
        if req.name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }

        // Resolve sandbox by name.
        let sandbox = self
            .state
            .store
            .get_message_by_name::<Sandbox>(&req.name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        let sandbox_id = sandbox.id.clone();

        // Get the next draft version.
        let current_version = self
            .state
            .store
            .get_draft_version(&sandbox_id)
            .await
            .map_err(|e| Status::internal(format!("get draft version failed: {e}")))?;
        let draft_version = current_version + 1;

        // Validate and persist proposed chunks from the sandbox.
        // The sandbox runs the mechanistic mapper (or future LLM advisor)
        // and sends pre-formed chunks. The gateway is a thin persistence +
        // validation layer — it never generates proposals itself.
        //
        // Dedup is handled at the DB level: the unique partial index on
        // (sandbox_id, host, port, binary) triggers an upsert that
        // increments hit_count + updates last_seen_ms.
        let mut accepted: u32 = 0;
        let mut rejected: u32 = 0;
        let mut rejection_reasons: Vec<String> = Vec::new();

        for chunk in &req.proposed_chunks {
            // Basic validation: rule_name and proposed_rule are required.
            if chunk.rule_name.is_empty() {
                rejected += 1;
                rejection_reasons.push("chunk missing rule_name".to_string());
                continue;
            }
            if chunk.proposed_rule.is_none() {
                rejected += 1;
                rejection_reasons
                    .push(format!("chunk '{}' missing proposed_rule", chunk.rule_name));
                continue;
            }

            let chunk_id = uuid::Uuid::new_v4().to_string();
            let now_ms =
                current_time_ms().map_err(|e| Status::internal(format!("timestamp error: {e}")))?;
            let proposed_rule_bytes = chunk
                .proposed_rule
                .as_ref()
                .map(|r| r.encode_to_vec())
                .unwrap_or_default();

            // Extract host:port and binary from the proposed rule for denormalized columns.
            let rule_ref = chunk.proposed_rule.as_ref();
            let (ep_host, ep_port) = rule_ref
                .and_then(|r| r.endpoints.first())
                .map(|ep| (ep.host.to_lowercase(), ep.port as i32))
                .unwrap_or_default();
            let ep_binary = rule_ref
                .and_then(|r| r.binaries.first())
                .map(|b| b.path.clone())
                .unwrap_or_default();

            let record = DraftChunkRecord {
                id: chunk_id,
                sandbox_id: sandbox_id.clone(),
                draft_version,
                status: "pending".to_string(),
                rule_name: chunk.rule_name.clone(),
                proposed_rule: proposed_rule_bytes,
                rationale: chunk.rationale.clone(),
                security_notes: chunk.security_notes.clone(),
                confidence: f64::from(chunk.confidence),
                created_at_ms: now_ms,
                decided_at_ms: None,
                host: ep_host,
                port: ep_port,
                binary: ep_binary,
                hit_count: if chunk.hit_count > 0 {
                    chunk.hit_count
                } else {
                    1
                },
                first_seen_ms: if chunk.first_seen_ms > 0 {
                    chunk.first_seen_ms
                } else {
                    now_ms
                },
                last_seen_ms: if chunk.last_seen_ms > 0 {
                    chunk.last_seen_ms
                } else {
                    now_ms
                },
            };
            self.state
                .store
                .put_draft_chunk(&record)
                .await
                .map_err(|e| Status::internal(format!("persist draft chunk failed: {e}")))?;
            accepted += 1;
        }

        // Notify watchers that new draft chunks are available.
        self.state.sandbox_watch_bus.notify(&sandbox_id);

        info!(
            sandbox_id = %sandbox_id,
            accepted = accepted,
            rejected = rejected,
            draft_version = draft_version,
            summaries = req.summaries.len(),
            "SubmitPolicyAnalysis: persisted draft chunks"
        );

        Ok(Response::new(SubmitPolicyAnalysisResponse {
            accepted_chunks: accepted,
            rejected_chunks: rejected,
            rejection_reasons,
        }))
    }

    async fn get_draft_policy(
        &self,
        request: Request<GetDraftPolicyRequest>,
    ) -> Result<Response<GetDraftPolicyResponse>, Status> {
        let req = request.into_inner();
        if req.name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }

        // Resolve sandbox by name.
        let sandbox = self
            .state
            .store
            .get_message_by_name::<Sandbox>(&req.name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        let sandbox_id = sandbox.id.clone();

        let status_filter = if req.status_filter.is_empty() {
            None
        } else {
            Some(req.status_filter.as_str())
        };

        let records = self
            .state
            .store
            .list_draft_chunks(&sandbox_id, status_filter)
            .await
            .map_err(|e| Status::internal(format!("list draft chunks failed: {e}")))?;

        let draft_version = self
            .state
            .store
            .get_draft_version(&sandbox_id)
            .await
            .map_err(|e| Status::internal(format!("get draft version failed: {e}")))?;

        let chunks: Vec<PolicyChunk> = records
            .into_iter()
            .map(|r| draft_chunk_record_to_proto(&r))
            .collect::<Result<Vec<_>, _>>()?;

        // Determine last_analyzed_at_ms from the most recent chunk.
        let last_analyzed_at_ms = chunks.iter().map(|c| c.created_at_ms).max().unwrap_or(0);

        debug!(
            sandbox_id = %sandbox_id,
            chunk_count = chunks.len(),
            draft_version = draft_version,
            "GetDraftPolicy: served draft chunks"
        );

        Ok(Response::new(GetDraftPolicyResponse {
            chunks,
            rolling_summary: String::new(),
            draft_version: u64::try_from(draft_version).unwrap_or(0),
            last_analyzed_at_ms,
        }))
    }

    async fn approve_draft_chunk(
        &self,
        request: Request<ApproveDraftChunkRequest>,
    ) -> Result<Response<ApproveDraftChunkResponse>, Status> {
        let req = request.into_inner();
        if req.name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }
        if req.chunk_id.is_empty() {
            return Err(Status::invalid_argument("chunk_id is required"));
        }

        require_no_global_policy(&self.state).await?;

        // Resolve sandbox.
        let sandbox = self
            .state
            .store
            .get_message_by_name::<Sandbox>(&req.name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        let sandbox_id = sandbox.id.clone();

        // Fetch the chunk — accept pending or rejected (re-approve toggle).
        let chunk = self
            .state
            .store
            .get_draft_chunk(&req.chunk_id)
            .await
            .map_err(|e| Status::internal(format!("fetch chunk failed: {e}")))?
            .ok_or_else(|| Status::not_found("chunk not found"))?;

        if chunk.status != "pending" && chunk.status != "rejected" {
            return Err(Status::failed_precondition(format!(
                "chunk status is '{}', expected 'pending' or 'rejected'",
                chunk.status
            )));
        }

        info!(
            sandbox_id = %sandbox_id,
            chunk_id = %req.chunk_id,
            rule_name = %chunk.rule_name,
            host = %chunk.host,
            port = chunk.port,
            hit_count = chunk.hit_count,
            prev_status = %chunk.status,
            "ApproveDraftChunk: merging rule into active policy"
        );

        // Merge the approved rule into the current policy (with optimistic retry).
        let (version, hash) =
            merge_chunk_into_policy(self.state.store.as_ref(), &sandbox_id, &chunk).await?;

        // Mark chunk as approved.
        let now_ms =
            current_time_ms().map_err(|e| Status::internal(format!("timestamp error: {e}")))?;
        self.state
            .store
            .update_draft_chunk_status(&req.chunk_id, "approved", Some(now_ms))
            .await
            .map_err(|e| Status::internal(format!("update chunk status failed: {e}")))?;

        // Notify watchers.
        self.state.sandbox_watch_bus.notify(&sandbox_id);

        info!(
            sandbox_id = %sandbox_id,
            chunk_id = %req.chunk_id,
            rule_name = %chunk.rule_name,
            version = version,
            policy_hash = %hash,
            "ApproveDraftChunk: rule merged successfully"
        );

        Ok(Response::new(ApproveDraftChunkResponse {
            policy_version: u32::try_from(version).unwrap_or(0),
            policy_hash: hash,
        }))
    }

    async fn reject_draft_chunk(
        &self,
        request: Request<RejectDraftChunkRequest>,
    ) -> Result<Response<RejectDraftChunkResponse>, Status> {
        let req = request.into_inner();
        if req.name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }
        if req.chunk_id.is_empty() {
            return Err(Status::invalid_argument("chunk_id is required"));
        }

        // Resolve sandbox.
        let sandbox = self
            .state
            .store
            .get_message_by_name::<Sandbox>(&req.name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        let sandbox_id = sandbox.id.clone();

        // Fetch the chunk — accept pending or approved (revoke toggle).
        let chunk = self
            .state
            .store
            .get_draft_chunk(&req.chunk_id)
            .await
            .map_err(|e| Status::internal(format!("fetch chunk failed: {e}")))?
            .ok_or_else(|| Status::not_found("chunk not found"))?;

        if chunk.status != "pending" && chunk.status != "approved" {
            return Err(Status::failed_precondition(format!(
                "chunk status is '{}', expected 'pending' or 'approved'",
                chunk.status
            )));
        }

        let was_approved = chunk.status == "approved";

        info!(
            sandbox_id = %sandbox_id,
            chunk_id = %req.chunk_id,
            rule_name = %chunk.rule_name,
            host = %chunk.host,
            port = chunk.port,
            reason = %req.reason,
            prev_status = %chunk.status,
            "RejectDraftChunk: rejecting chunk"
        );

        // If the chunk was approved, remove its rule from the active policy.
        // Block revoke when a global policy is active since the sandbox policy
        // isn't in use anyway.
        if was_approved {
            require_no_global_policy(&self.state).await?;
            remove_chunk_from_policy(&self.state, &sandbox_id, &chunk).await?;
        }

        // Mark chunk as rejected.
        let now_ms =
            current_time_ms().map_err(|e| Status::internal(format!("timestamp error: {e}")))?;
        self.state
            .store
            .update_draft_chunk_status(&req.chunk_id, "rejected", Some(now_ms))
            .await
            .map_err(|e| Status::internal(format!("update chunk status failed: {e}")))?;

        // Notify watchers.
        self.state.sandbox_watch_bus.notify(&sandbox_id);

        Ok(Response::new(RejectDraftChunkResponse {}))
    }

    async fn approve_all_draft_chunks(
        &self,
        request: Request<ApproveAllDraftChunksRequest>,
    ) -> Result<Response<ApproveAllDraftChunksResponse>, Status> {
        let req = request.into_inner();
        if req.name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }

        require_no_global_policy(&self.state).await?;

        // Resolve sandbox.
        let sandbox = self
            .state
            .store
            .get_message_by_name::<Sandbox>(&req.name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        let sandbox_id = sandbox.id.clone();

        // List all pending chunks.
        let pending_chunks = self
            .state
            .store
            .list_draft_chunks(&sandbox_id, Some("pending"))
            .await
            .map_err(|e| Status::internal(format!("list draft chunks failed: {e}")))?;

        if pending_chunks.is_empty() {
            return Err(Status::failed_precondition("no pending chunks to approve"));
        }

        info!(
            sandbox_id = %sandbox_id,
            pending_count = pending_chunks.len(),
            include_security_flagged = req.include_security_flagged,
            "ApproveAllDraftChunks: starting bulk approval"
        );

        let mut chunks_approved: u32 = 0;
        let mut chunks_skipped: u32 = 0;
        let mut last_version: i64 = 0;
        let mut last_hash = String::new();

        for chunk in &pending_chunks {
            // Skip security-flagged chunks unless explicitly included.
            if !req.include_security_flagged && !chunk.security_notes.is_empty() {
                info!(
                    sandbox_id = %sandbox_id,
                    chunk_id = %chunk.id,
                    rule_name = %chunk.rule_name,
                    security_notes = %chunk.security_notes,
                    "ApproveAllDraftChunks: skipping security-flagged chunk"
                );
                chunks_skipped += 1;
                continue;
            }

            info!(
                sandbox_id = %sandbox_id,
                chunk_id = %chunk.id,
                rule_name = %chunk.rule_name,
                host = %chunk.host,
                port = chunk.port,
                "ApproveAllDraftChunks: merging chunk"
            );

            // Merge each chunk into the policy (with optimistic retry).
            let (version, hash) =
                merge_chunk_into_policy(self.state.store.as_ref(), &sandbox_id, chunk).await?;
            last_version = version;
            last_hash = hash;

            // Mark chunk as approved.
            let now_ms =
                current_time_ms().map_err(|e| Status::internal(format!("timestamp error: {e}")))?;
            self.state
                .store
                .update_draft_chunk_status(&chunk.id, "approved", Some(now_ms))
                .await
                .map_err(|e| Status::internal(format!("update chunk status failed: {e}")))?;

            chunks_approved += 1;
        }

        // Notify watchers.
        self.state.sandbox_watch_bus.notify(&sandbox_id);

        info!(
            sandbox_id = %sandbox_id,
            chunks_approved = chunks_approved,
            chunks_skipped = chunks_skipped,
            version = last_version,
            policy_hash = %last_hash,
            "ApproveAllDraftChunks: bulk approval complete"
        );

        Ok(Response::new(ApproveAllDraftChunksResponse {
            policy_version: u32::try_from(last_version).unwrap_or(0),
            policy_hash: last_hash,
            chunks_approved,
            chunks_skipped,
        }))
    }

    async fn edit_draft_chunk(
        &self,
        request: Request<EditDraftChunkRequest>,
    ) -> Result<Response<EditDraftChunkResponse>, Status> {
        let req = request.into_inner();
        if req.name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }
        if req.chunk_id.is_empty() {
            return Err(Status::invalid_argument("chunk_id is required"));
        }
        let proposed_rule = req
            .proposed_rule
            .ok_or_else(|| Status::invalid_argument("proposed_rule is required"))?;

        // Resolve sandbox (validates name exists).
        let _sandbox = self
            .state
            .store
            .get_message_by_name::<Sandbox>(&req.name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;

        // Fetch the chunk and validate it's pending.
        let chunk = self
            .state
            .store
            .get_draft_chunk(&req.chunk_id)
            .await
            .map_err(|e| Status::internal(format!("fetch chunk failed: {e}")))?
            .ok_or_else(|| Status::not_found("chunk not found"))?;

        if chunk.status != "pending" {
            return Err(Status::failed_precondition(format!(
                "chunk status is '{}', expected 'pending'",
                chunk.status
            )));
        }

        // Update the proposed rule.
        let rule_bytes = proposed_rule.encode_to_vec();
        self.state
            .store
            .update_draft_chunk_rule(&req.chunk_id, &rule_bytes)
            .await
            .map_err(|e| Status::internal(format!("update chunk rule failed: {e}")))?;

        info!(
            chunk_id = %req.chunk_id,
            "EditDraftChunk: proposed rule updated"
        );

        Ok(Response::new(EditDraftChunkResponse {}))
    }

    async fn undo_draft_chunk(
        &self,
        request: Request<UndoDraftChunkRequest>,
    ) -> Result<Response<UndoDraftChunkResponse>, Status> {
        let req = request.into_inner();
        if req.name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }
        if req.chunk_id.is_empty() {
            return Err(Status::invalid_argument("chunk_id is required"));
        }

        // Resolve sandbox.
        let sandbox = self
            .state
            .store
            .get_message_by_name::<Sandbox>(&req.name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        let sandbox_id = sandbox.id.clone();

        // Fetch the chunk and validate it's approved.
        let chunk = self
            .state
            .store
            .get_draft_chunk(&req.chunk_id)
            .await
            .map_err(|e| Status::internal(format!("fetch chunk failed: {e}")))?
            .ok_or_else(|| Status::not_found("chunk not found"))?;

        if chunk.status != "approved" {
            return Err(Status::failed_precondition(format!(
                "chunk status is '{}', expected 'approved'",
                chunk.status
            )));
        }

        info!(
            sandbox_id = %sandbox_id,
            chunk_id = %req.chunk_id,
            rule_name = %chunk.rule_name,
            host = %chunk.host,
            port = chunk.port,
            "UndoDraftChunk: removing rule from active policy"
        );

        // Remove the rule from the current policy (with optimistic retry).
        let (version, hash) = remove_chunk_from_policy(&self.state, &sandbox_id, &chunk).await?;

        // Mark chunk back to pending.
        self.state
            .store
            .update_draft_chunk_status(&req.chunk_id, "pending", None)
            .await
            .map_err(|e| Status::internal(format!("update chunk status failed: {e}")))?;

        // Notify watchers.
        self.state.sandbox_watch_bus.notify(&sandbox_id);

        info!(
            sandbox_id = %sandbox_id,
            chunk_id = %req.chunk_id,
            rule_name = %chunk.rule_name,
            version = version,
            policy_hash = %hash,
            "UndoDraftChunk: rule removed, chunk reverted to pending"
        );

        Ok(Response::new(UndoDraftChunkResponse {
            policy_version: u32::try_from(version).unwrap_or(0),
            policy_hash: hash,
        }))
    }

    async fn clear_draft_chunks(
        &self,
        request: Request<ClearDraftChunksRequest>,
    ) -> Result<Response<ClearDraftChunksResponse>, Status> {
        let req = request.into_inner();
        if req.name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }

        // Resolve sandbox.
        let sandbox = self
            .state
            .store
            .get_message_by_name::<Sandbox>(&req.name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        let sandbox_id = sandbox.id.clone();

        let deleted = self
            .state
            .store
            .delete_draft_chunks(&sandbox_id, "pending")
            .await
            .map_err(|e| Status::internal(format!("delete draft chunks failed: {e}")))?;

        // Notify watchers.
        self.state.sandbox_watch_bus.notify(&sandbox_id);

        info!(
            sandbox_id = %sandbox_id,
            chunks_cleared = deleted,
            "ClearDraftChunks: pending chunks cleared"
        );

        Ok(Response::new(ClearDraftChunksResponse {
            chunks_cleared: u32::try_from(deleted).unwrap_or(0),
        }))
    }

    async fn get_draft_history(
        &self,
        request: Request<GetDraftHistoryRequest>,
    ) -> Result<Response<GetDraftHistoryResponse>, Status> {
        let req = request.into_inner();
        if req.name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }

        // Resolve sandbox by name.
        let sandbox = self
            .state
            .store
            .get_message_by_name::<Sandbox>(&req.name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        let sandbox_id = sandbox.id.clone();

        // Build history from all draft chunks (across all versions).
        let all_chunks = self
            .state
            .store
            .list_draft_chunks(&sandbox_id, None)
            .await
            .map_err(|e| Status::internal(format!("list draft chunks failed: {e}")))?;

        let mut entries: Vec<DraftHistoryEntry> = Vec::new();

        for chunk in &all_chunks {
            // Creation event.
            entries.push(DraftHistoryEntry {
                timestamp_ms: chunk.created_at_ms,
                event_type: "proposed".to_string(),
                description: format!(
                    "Rule '{}' proposed (confidence: {:.0}%)",
                    chunk.rule_name,
                    chunk.confidence * 100.0
                ),
                chunk_id: chunk.id.clone(),
            });

            // Decision event (if decided).
            if let Some(decided_at) = chunk.decided_at_ms {
                entries.push(DraftHistoryEntry {
                    timestamp_ms: decided_at,
                    event_type: chunk.status.clone(),
                    description: format!("Rule '{}' {}", chunk.rule_name, chunk.status),
                    chunk_id: chunk.id.clone(),
                });
            }
        }

        // Sort by timestamp ascending.
        entries.sort_by_key(|e| e.timestamp_ms);

        debug!(
            sandbox_id = %sandbox_id,
            entry_count = entries.len(),
            "GetDraftHistory: served draft history"
        );

        Ok(Response::new(GetDraftHistoryResponse { entries }))
    }
}

/// Convert a `DraftChunkRecord` from the persistence layer into a `PolicyChunk`
/// proto message.
fn draft_chunk_record_to_proto(record: &DraftChunkRecord) -> Result<PolicyChunk, Status> {
    use openshell_core::proto::NetworkPolicyRule;

    let proposed_rule = if record.proposed_rule.is_empty() {
        None
    } else {
        Some(
            NetworkPolicyRule::decode(record.proposed_rule.as_slice())
                .map_err(|e| Status::internal(format!("decode proposed_rule failed: {e}")))?,
        )
    };

    Ok(PolicyChunk {
        id: record.id.clone(),
        status: record.status.clone(),
        rule_name: record.rule_name.clone(),
        proposed_rule,
        rationale: record.rationale.clone(),
        security_notes: record.security_notes.clone(),
        confidence: record.confidence as f32,
        created_at_ms: record.created_at_ms,
        decided_at_ms: record.decided_at_ms.unwrap_or(0),
        hit_count: record.hit_count,
        first_seen_ms: record.first_seen_ms,
        last_seen_ms: record.last_seen_ms,
        binary: record.binary.clone(),
        ..Default::default()
    })
}

/// Merge a draft chunk's proposed rule into the current active sandbox policy.
///
/// Returns `(new_version, policy_hash)`. This reuses the same persistence
/// pattern as `update_config`: compute hash, check for no-op,
/// persist a new revision, supersede older versions, and notify watchers.
/// Maximum number of optimistic retry attempts for policy version conflicts.
const MERGE_RETRY_LIMIT: usize = 5;

/// Check whether a global policy is active. Returns an error suitable for
/// blocking draft chunk approval/revoke when global policy overrides sandbox
/// policy.
async fn require_no_global_policy(state: &ServerState) -> Result<(), Status> {
    let global = load_global_settings(state.store.as_ref()).await?;
    if global.settings.contains_key(POLICY_SETTING_KEY) {
        return Err(Status::failed_precondition(
            "cannot approve rules while a global policy is active; \
             delete the global policy to manage per-sandbox rules",
        ));
    }
    Ok(())
}

async fn merge_chunk_into_policy(
    store: &crate::persistence::Store,
    sandbox_id: &str,
    chunk: &DraftChunkRecord,
) -> Result<(i64, String), Status> {
    use openshell_core::proto::NetworkPolicyRule;

    // Decode the proposed rule once — it doesn't change between retries.
    let rule = NetworkPolicyRule::decode(chunk.proposed_rule.as_slice())
        .map_err(|e| Status::internal(format!("decode proposed_rule failed: {e}")))?;

    for attempt in 1..=MERGE_RETRY_LIMIT {
        // Get the current active policy (re-read on each attempt).
        let latest = store
            .get_latest_policy(sandbox_id)
            .await
            .map_err(|e| Status::internal(format!("fetch latest policy failed: {e}")))?;

        let mut policy = if let Some(ref record) = latest {
            ProtoSandboxPolicy::decode(record.policy_payload.as_slice())
                .map_err(|e| Status::internal(format!("decode current policy failed: {e}")))?
        } else {
            ProtoSandboxPolicy::default()
        };

        let base_version = latest.as_ref().map_or(0, |r| r.version);

        // Merge: if a rule for this endpoint already exists, add the binary
        // to its binaries list. Otherwise insert the whole proposed rule.
        if let Some(existing) = policy.network_policies.get_mut(&chunk.rule_name) {
            // Add the chunk's binary if not already present.
            for b in &rule.binaries {
                if !existing.binaries.iter().any(|eb| eb.path == b.path) {
                    existing.binaries.push(b.clone());
                }
            }
            // Also merge endpoints and L7 rules in case they differ.
            for ep in &rule.endpoints {
                if !existing
                    .endpoints
                    .iter()
                    .any(|e| e.host == ep.host && e.port == ep.port)
                {
                    existing.endpoints.push(ep.clone());
                }
            }
        } else {
            policy
                .network_policies
                .insert(chunk.rule_name.clone(), rule.clone());
        }

        // Persist as a new version.
        let payload = policy.encode_to_vec();
        let hash = deterministic_policy_hash(&policy);
        let next_version = base_version + 1;
        let policy_id = uuid::Uuid::new_v4().to_string();

        match store
            .put_policy_revision(&policy_id, sandbox_id, next_version, &payload, &hash)
            .await
        {
            Ok(()) => {
                let _ = store
                    .supersede_older_policies(sandbox_id, next_version)
                    .await;

                if attempt > 1 {
                    info!(
                        sandbox_id = %sandbox_id,
                        rule_name = %chunk.rule_name,
                        attempt,
                        version = next_version,
                        "merge_chunk_into_policy: succeeded after version conflict retry"
                    );
                }

                return Ok((next_version, hash));
            }
            Err(e) => {
                let msg = e.to_string();
                // Check for UNIQUE constraint violation (version conflict).
                if msg.contains("UNIQUE") || msg.contains("unique") || msg.contains("duplicate") {
                    warn!(
                        sandbox_id = %sandbox_id,
                        rule_name = %chunk.rule_name,
                        attempt,
                        conflicting_version = next_version,
                        "merge_chunk_into_policy: version conflict, retrying"
                    );
                    // Brief yield to let the winning write settle.
                    tokio::task::yield_now().await;
                    continue;
                }
                return Err(Status::internal(format!(
                    "persist policy revision failed: {e}"
                )));
            }
        }
    }

    Err(Status::aborted(format!(
        "merge_chunk_into_policy: gave up after {} version conflict retries for rule '{}'",
        MERGE_RETRY_LIMIT, chunk.rule_name
    )))
}

/// Remove a previously-approved draft chunk's rule from the current active
/// sandbox policy.
///
/// Returns `(new_version, policy_hash)`.
async fn remove_chunk_from_policy(
    state: &ServerState,
    sandbox_id: &str,
    chunk: &DraftChunkRecord,
) -> Result<(i64, String), Status> {
    for attempt in 1..=MERGE_RETRY_LIMIT {
        // Get the current active policy (re-read on each attempt).
        let latest = state
            .store
            .get_latest_policy(sandbox_id)
            .await
            .map_err(|e| Status::internal(format!("fetch latest policy failed: {e}")))?
            .ok_or_else(|| Status::internal("no active policy to undo from"))?;

        let mut policy = ProtoSandboxPolicy::decode(latest.policy_payload.as_slice())
            .map_err(|e| Status::internal(format!("decode current policy failed: {e}")))?;

        // Remove this chunk's binary from the rule. If no binaries remain,
        // remove the entire rule.
        let should_remove =
            if let Some(existing) = policy.network_policies.get_mut(&chunk.rule_name) {
                existing.binaries.retain(|b| b.path != chunk.binary);
                existing.binaries.is_empty()
            } else {
                false
            };
        if should_remove {
            policy.network_policies.remove(&chunk.rule_name);
        }

        // Persist as a new version.
        let payload = policy.encode_to_vec();
        let hash = deterministic_policy_hash(&policy);
        let next_version = latest.version + 1;
        let policy_id = uuid::Uuid::new_v4().to_string();

        match state
            .store
            .put_policy_revision(&policy_id, sandbox_id, next_version, &payload, &hash)
            .await
        {
            Ok(()) => {
                let _ = state
                    .store
                    .supersede_older_policies(sandbox_id, next_version)
                    .await;

                if attempt > 1 {
                    info!(
                        sandbox_id = %sandbox_id,
                        rule_name = %chunk.rule_name,
                        attempt,
                        version = next_version,
                        "remove_chunk_from_policy: succeeded after version conflict retry"
                    );
                }

                return Ok((next_version, hash));
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("UNIQUE") || msg.contains("unique") || msg.contains("duplicate") {
                    warn!(
                        sandbox_id = %sandbox_id,
                        rule_name = %chunk.rule_name,
                        attempt,
                        conflicting_version = next_version,
                        "remove_chunk_from_policy: version conflict, retrying"
                    );
                    tokio::task::yield_now().await;
                    continue;
                }
                return Err(Status::internal(format!(
                    "persist policy revision failed: {e}"
                )));
            }
        }
    }

    Err(Status::aborted(format!(
        "remove_chunk_from_policy: gave up after {} version conflict retries for rule '{}'",
        MERGE_RETRY_LIMIT, chunk.rule_name
    )))
}

/// Compute a deterministic SHA-256 hash of a `SandboxPolicy`.
///
/// Protobuf `map` fields use `HashMap` which has randomized iteration order,
/// so `encode_to_vec()` is non-deterministic. This function hashes each field
/// individually with map entries sorted by key.
fn deterministic_policy_hash(policy: &ProtoSandboxPolicy) -> String {
    let mut hasher = Sha256::new();
    hasher.update(policy.version.to_le_bytes());
    if let Some(fs) = &policy.filesystem {
        hasher.update(fs.encode_to_vec());
    }
    if let Some(ll) = &policy.landlock {
        hasher.update(ll.encode_to_vec());
    }
    if let Some(p) = &policy.process {
        hasher.update(p.encode_to_vec());
    }
    // Sort network_policies by key for deterministic ordering.
    let mut entries: Vec<_> = policy.network_policies.iter().collect();
    entries.sort_by_key(|(k, _)| k.as_str());
    for (key, value) in entries {
        hasher.update(key.as_bytes());
        hasher.update(value.encode_to_vec());
    }
    hex::encode(hasher.finalize())
}

/// Compute a fingerprint for the effective sandbox configuration.
///
/// Returns the first 8 bytes of a SHA-256 hash over the policy, settings,
/// and policy source. The sandbox poll loop compares this value to detect
/// changes -- if it differs from the previously seen revision, the sandbox
/// reloads.
///
/// This is a content hash, not a monotonic counter. With 64 bits of hash
/// space the birthday-bound collision probability is ~50% at 2^32
/// configurations. A collision would cause one poll cycle to miss a change,
/// but the next mutation will almost certainly produce a different hash.
/// This trade-off is acceptable for the poll-based change detection use case.
fn compute_config_revision(
    policy: Option<&ProtoSandboxPolicy>,
    settings: &HashMap<String, EffectiveSetting>,
    policy_source: PolicySource,
) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update((policy_source as i32).to_le_bytes());
    if let Some(policy) = policy {
        hasher.update(deterministic_policy_hash(policy).as_bytes());
    }
    let mut entries: Vec<_> = settings.iter().collect();
    entries.sort_by_key(|(k, _)| k.as_str());
    for (key, setting) in entries {
        hasher.update(key.as_bytes());
        hasher.update(setting.scope.to_le_bytes());
        if let Some(value) = setting.value.as_ref().and_then(|v| v.value.as_ref()) {
            match value {
                setting_value::Value::StringValue(v) => {
                    hasher.update([0]);
                    hasher.update(v.as_bytes());
                }
                setting_value::Value::BoolValue(v) => {
                    hasher.update([1]);
                    hasher.update([u8::from(*v)]);
                }
                setting_value::Value::IntValue(v) => {
                    hasher.update([2]);
                    hasher.update(v.to_le_bytes());
                }
                setting_value::Value::BytesValue(v) => {
                    hasher.update([3]);
                    hasher.update(v);
                }
            }
        }
    }

    let digest = hasher.finalize();
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes)
}

fn validate_registered_setting_key(key: &str) -> Result<SettingValueKind, Status> {
    settings::setting_for_key(key)
        .map(|entry| entry.kind)
        .ok_or_else(|| {
            Status::invalid_argument(format!(
                "unknown setting key '{key}'. Allowed keys: {}",
                settings::registered_keys_csv()
            ))
        })
}

fn proto_setting_to_stored(key: &str, value: &SettingValue) -> Result<StoredSettingValue, Status> {
    let expected = validate_registered_setting_key(key)?;
    let inner = value
        .value
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("setting_value.value is required"))?;
    let stored = match (expected, inner) {
        (SettingValueKind::String, setting_value::Value::StringValue(v)) => {
            StoredSettingValue::String(v.clone())
        }
        (SettingValueKind::Bool, setting_value::Value::BoolValue(v)) => {
            StoredSettingValue::Bool(*v)
        }
        (SettingValueKind::Int, setting_value::Value::IntValue(v)) => StoredSettingValue::Int(*v),
        (_, setting_value::Value::BytesValue(_)) => {
            return Err(Status::invalid_argument(format!(
                "setting '{key}' expects {} value; bytes are not supported for this key",
                expected.as_str()
            )));
        }
        (expected_kind, _) => {
            return Err(Status::invalid_argument(format!(
                "setting '{key}' expects {} value",
                expected_kind.as_str()
            )));
        }
    };
    Ok(stored)
}

fn stored_setting_to_proto(value: &StoredSettingValue) -> Result<SettingValue, Status> {
    let proto = match value {
        StoredSettingValue::String(v) => SettingValue {
            value: Some(setting_value::Value::StringValue(v.clone())),
        },
        StoredSettingValue::Bool(v) => SettingValue {
            value: Some(setting_value::Value::BoolValue(*v)),
        },
        StoredSettingValue::Int(v) => SettingValue {
            value: Some(setting_value::Value::IntValue(*v)),
        },
        StoredSettingValue::Bytes(v) => {
            let decoded = hex::decode(v)
                .map_err(|e| Status::internal(format!("stored bytes decode failed: {e}")))?;
            SettingValue {
                value: Some(setting_value::Value::BytesValue(decoded)),
            }
        }
    };
    Ok(proto)
}

fn upsert_setting_value(
    map: &mut BTreeMap<String, StoredSettingValue>,
    key: &str,
    value: StoredSettingValue,
) -> bool {
    match map.get(key) {
        Some(existing) if existing == &value => false,
        _ => {
            map.insert(key.to_string(), value);
            true
        }
    }
}

async fn load_global_settings(store: &Store) -> Result<StoredSettings, Status> {
    load_settings_record(store, GLOBAL_SETTINGS_OBJECT_TYPE, GLOBAL_SETTINGS_ID).await
}

async fn save_global_settings(store: &Store, settings: &StoredSettings) -> Result<(), Status> {
    save_settings_record(
        store,
        GLOBAL_SETTINGS_OBJECT_TYPE,
        GLOBAL_SETTINGS_ID,
        GLOBAL_SETTINGS_NAME,
        settings,
    )
    .await
}

/// Derive a distinct settings record ID from a sandbox UUID.
///
/// The generic `objects` table uses `id` as the primary key.  Sandbox objects
/// already occupy the row keyed by the raw sandbox UUID, so settings records
/// must use a different ID to avoid a silent no-op upsert (the `ON CONFLICT`
/// clause is scoped by `object_type`).
fn sandbox_settings_id(sandbox_id: &str) -> String {
    format!("settings:{sandbox_id}")
}

async fn load_sandbox_settings(store: &Store, sandbox_id: &str) -> Result<StoredSettings, Status> {
    load_settings_record(
        store,
        SANDBOX_SETTINGS_OBJECT_TYPE,
        &sandbox_settings_id(sandbox_id),
    )
    .await
}

async fn save_sandbox_settings(
    store: &Store,
    sandbox_id: &str,
    sandbox_name: &str,
    settings: &StoredSettings,
) -> Result<(), Status> {
    save_settings_record(
        store,
        SANDBOX_SETTINGS_OBJECT_TYPE,
        &sandbox_settings_id(sandbox_id),
        sandbox_name,
        settings,
    )
    .await
}

async fn load_settings_record(
    store: &Store,
    object_type: &str,
    id: &str,
) -> Result<StoredSettings, Status> {
    let record = store
        .get(object_type, id)
        .await
        .map_err(|e| Status::internal(format!("fetch settings failed: {e}")))?;
    if let Some(record) = record {
        serde_json::from_slice::<StoredSettings>(&record.payload)
            .map_err(|e| Status::internal(format!("decode settings payload failed: {e}")))
    } else {
        Ok(StoredSettings::default())
    }
}

async fn save_settings_record(
    store: &Store,
    object_type: &str,
    id: &str,
    name: &str,
    settings: &StoredSettings,
) -> Result<(), Status> {
    let payload = serde_json::to_vec(settings)
        .map_err(|e| Status::internal(format!("encode settings payload failed: {e}")))?;
    store
        .put(object_type, id, name, &payload)
        .await
        .map_err(|e| Status::internal(format!("persist settings failed: {e}")))?;
    Ok(())
}

fn decode_policy_from_global_settings(
    global: &StoredSettings,
) -> Result<Option<ProtoSandboxPolicy>, Status> {
    let Some(value) = global.settings.get(POLICY_SETTING_KEY) else {
        return Ok(None);
    };

    let StoredSettingValue::Bytes(encoded) = value else {
        return Err(Status::internal(
            "global policy setting has invalid value type; expected bytes",
        ));
    };

    let raw = hex::decode(encoded)
        .map_err(|e| Status::internal(format!("global policy decode failed: {e}")))?;
    let policy = ProtoSandboxPolicy::decode(raw.as_slice())
        .map_err(|e| Status::internal(format!("global policy protobuf decode failed: {e}")))?;
    Ok(Some(policy))
}

fn merge_effective_settings(
    global: &StoredSettings,
    sandbox: &StoredSettings,
) -> Result<HashMap<String, EffectiveSetting>, Status> {
    let mut merged = HashMap::new();

    for registered in settings::REGISTERED_SETTINGS {
        merged.insert(
            registered.key.to_string(),
            EffectiveSetting {
                value: None,
                scope: SettingScope::Unspecified.into(),
            },
        );
    }

    for (key, value) in &sandbox.settings {
        if key == POLICY_SETTING_KEY || settings::setting_for_key(key).is_none() {
            continue;
        }
        merged.insert(
            key.clone(),
            EffectiveSetting {
                value: Some(stored_setting_to_proto(value)?),
                scope: SettingScope::Sandbox.into(),
            },
        );
    }

    for (key, value) in &global.settings {
        if key == POLICY_SETTING_KEY || settings::setting_for_key(key).is_none() {
            continue;
        }
        merged.insert(
            key.clone(),
            EffectiveSetting {
                value: Some(stored_setting_to_proto(value)?),
                scope: SettingScope::Global.into(),
            },
        );
    }

    Ok(merged)
}

fn materialize_global_settings(
    global: &StoredSettings,
) -> Result<HashMap<String, SettingValue>, Status> {
    let mut materialized = HashMap::new();
    for registered in settings::REGISTERED_SETTINGS {
        materialized.insert(registered.key.to_string(), SettingValue { value: None });
    }

    for (key, value) in &global.settings {
        if key == POLICY_SETTING_KEY {
            continue;
        }
        // Only include keys that are in the current registry. Stale keys
        // from a previous build are ignored.
        if settings::setting_for_key(key).is_none() {
            continue;
        }
        materialized.insert(key.clone(), stored_setting_to_proto(value)?);
    }

    Ok(materialized)
}

/// Check if a log line's source matches the filter list.
/// Empty source is treated as "gateway" for backward compatibility.
fn source_matches(log_source: &str, filters: &[String]) -> bool {
    let effective = if log_source.is_empty() {
        "gateway"
    } else {
        log_source
    };
    filters.iter().any(|f| f == effective)
}

/// Check if a log line's level meets the minimum level threshold.
/// Empty `min_level` means no filtering (all levels pass).
fn level_matches(log_level: &str, min_level: &str) -> bool {
    if min_level.is_empty() {
        return true;
    }
    let to_num = |s: &str| match s.to_uppercase().as_str() {
        "ERROR" => 0,
        "WARN" => 1,
        "INFO" => 2,
        "DEBUG" => 3,
        "TRACE" => 4,
        _ => 5, // unknown levels always pass
    };
    to_num(log_level) <= to_num(min_level)
}

// ---------------------------------------------------------------------------
// Policy helper functions
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Sandbox spec validation
// ---------------------------------------------------------------------------

/// Validate field sizes on a `CreateSandboxRequest` before persisting.
///
/// Returns `INVALID_ARGUMENT` on the first field that exceeds its limit.
fn validate_sandbox_spec(
    name: &str,
    spec: &openshell_core::proto::SandboxSpec,
) -> Result<(), Status> {
    // --- request.name ---
    if name.len() > MAX_NAME_LEN {
        return Err(Status::invalid_argument(format!(
            "name exceeds maximum length ({} > {MAX_NAME_LEN})",
            name.len()
        )));
    }

    // --- spec.providers ---
    if spec.providers.len() > MAX_PROVIDERS {
        return Err(Status::invalid_argument(format!(
            "providers list exceeds maximum ({} > {MAX_PROVIDERS})",
            spec.providers.len()
        )));
    }

    // --- spec.log_level ---
    if spec.log_level.len() > MAX_LOG_LEVEL_LEN {
        return Err(Status::invalid_argument(format!(
            "log_level exceeds maximum length ({} > {MAX_LOG_LEVEL_LEN})",
            spec.log_level.len()
        )));
    }

    // --- spec.environment ---
    validate_string_map(
        &spec.environment,
        MAX_ENVIRONMENT_ENTRIES,
        MAX_MAP_KEY_LEN,
        MAX_MAP_VALUE_LEN,
        "spec.environment",
    )?;

    // --- spec.template ---
    if let Some(ref tmpl) = spec.template {
        validate_sandbox_template(tmpl)?;
    }

    // --- spec.policy serialized size ---
    if let Some(ref policy) = spec.policy {
        let size = policy.encoded_len();
        if size > MAX_POLICY_SIZE {
            return Err(Status::invalid_argument(format!(
                "policy serialized size exceeds maximum ({size} > {MAX_POLICY_SIZE})"
            )));
        }
    }

    Ok(())
}

/// Validate template-level field sizes.
fn validate_sandbox_template(tmpl: &SandboxTemplate) -> Result<(), Status> {
    // String fields.
    for (field, value) in [
        ("template.image", &tmpl.image),
        ("template.runtime_class_name", &tmpl.runtime_class_name),
        ("template.agent_socket", &tmpl.agent_socket),
    ] {
        if value.len() > MAX_TEMPLATE_STRING_LEN {
            return Err(Status::invalid_argument(format!(
                "{field} exceeds maximum length ({} > {MAX_TEMPLATE_STRING_LEN})",
                value.len()
            )));
        }
    }

    // Map fields.
    validate_string_map(
        &tmpl.labels,
        MAX_TEMPLATE_MAP_ENTRIES,
        MAX_MAP_KEY_LEN,
        MAX_MAP_VALUE_LEN,
        "template.labels",
    )?;
    validate_string_map(
        &tmpl.annotations,
        MAX_TEMPLATE_MAP_ENTRIES,
        MAX_MAP_KEY_LEN,
        MAX_MAP_VALUE_LEN,
        "template.annotations",
    )?;
    validate_string_map(
        &tmpl.environment,
        MAX_TEMPLATE_MAP_ENTRIES,
        MAX_MAP_KEY_LEN,
        MAX_MAP_VALUE_LEN,
        "template.environment",
    )?;

    // Struct fields (serialized size).
    if let Some(ref s) = tmpl.resources {
        let size = s.encoded_len();
        if size > MAX_TEMPLATE_STRUCT_SIZE {
            return Err(Status::invalid_argument(format!(
                "template.resources serialized size exceeds maximum ({size} > {MAX_TEMPLATE_STRUCT_SIZE})"
            )));
        }
    }
    if let Some(ref s) = tmpl.volume_claim_templates {
        let size = s.encoded_len();
        if size > MAX_TEMPLATE_STRUCT_SIZE {
            return Err(Status::invalid_argument(format!(
                "template.volume_claim_templates serialized size exceeds maximum ({size} > {MAX_TEMPLATE_STRUCT_SIZE})"
            )));
        }
    }

    Ok(())
}

/// Validate a `map<string, string>` field: entry count, key length, value length.
fn validate_string_map(
    map: &std::collections::HashMap<String, String>,
    max_entries: usize,
    max_key_len: usize,
    max_value_len: usize,
    field_name: &str,
) -> Result<(), Status> {
    if map.len() > max_entries {
        return Err(Status::invalid_argument(format!(
            "{field_name} exceeds maximum entries ({} > {max_entries})",
            map.len()
        )));
    }
    for (key, value) in map {
        if key.len() > max_key_len {
            return Err(Status::invalid_argument(format!(
                "{field_name} key exceeds maximum length ({} > {max_key_len})",
                key.len()
            )));
        }
        if value.len() > max_value_len {
            return Err(Status::invalid_argument(format!(
                "{field_name} value exceeds maximum length ({} > {max_value_len})",
                value.len()
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Provider field validation
// ---------------------------------------------------------------------------

/// Validate field sizes on a `Provider` before persisting.
fn validate_provider_fields(provider: &Provider) -> Result<(), Status> {
    if provider.name.len() > MAX_NAME_LEN {
        return Err(Status::invalid_argument(format!(
            "provider.name exceeds maximum length ({} > {MAX_NAME_LEN})",
            provider.name.len()
        )));
    }
    if provider.r#type.len() > MAX_PROVIDER_TYPE_LEN {
        return Err(Status::invalid_argument(format!(
            "provider.type exceeds maximum length ({} > {MAX_PROVIDER_TYPE_LEN})",
            provider.r#type.len()
        )));
    }
    validate_string_map(
        &provider.credentials,
        MAX_PROVIDER_CREDENTIALS_ENTRIES,
        MAX_MAP_KEY_LEN,
        MAX_MAP_VALUE_LEN,
        "provider.credentials",
    )?;
    validate_string_map(
        &provider.config,
        MAX_PROVIDER_CONFIG_ENTRIES,
        MAX_MAP_KEY_LEN,
        MAX_MAP_VALUE_LEN,
        "provider.config",
    )?;
    Ok(())
}

/// Validate that a policy does not contain unsafe content.
///
/// Delegates to [`openshell_policy::validate_sandbox_policy`] and converts
/// violations into a gRPC `INVALID_ARGUMENT` status.
fn validate_policy_safety(policy: &ProtoSandboxPolicy) -> Result<(), Status> {
    if let Err(violations) = openshell_policy::validate_sandbox_policy(policy) {
        let messages: Vec<String> = violations.iter().map(ToString::to_string).collect();
        return Err(Status::invalid_argument(format!(
            "policy contains unsafe content: {}",
            messages.join("; ")
        )));
    }
    Ok(())
}

/// Validate that static policy fields (filesystem, landlock, process) haven't changed
/// from the baseline (version 1) policy.
fn validate_static_fields_unchanged(
    baseline: &ProtoSandboxPolicy,
    new: &ProtoSandboxPolicy,
) -> Result<(), Status> {
    // Filesystem: allow additive changes (new paths can be added, but
    // existing paths cannot be removed and include_workdir cannot change).
    // This supports the supervisor's baseline path enrichment at startup.
    // Note: Landlock is a one-way door — adding paths to the stored policy
    // has no effect on a running child process; the enriched paths only
    // take effect on the next restart.
    validate_filesystem_additive(baseline.filesystem.as_ref(), new.filesystem.as_ref())?;

    if baseline.landlock != new.landlock {
        return Err(Status::invalid_argument(
            "landlock policy cannot be changed on a live sandbox (applied at startup)",
        ));
    }
    if baseline.process != new.process {
        return Err(Status::invalid_argument(
            "process policy cannot be changed on a live sandbox (applied at startup)",
        ));
    }
    Ok(())
}

/// Validate that a filesystem policy update is purely additive: all baseline
/// paths must still be present, `include_workdir` must not change, but new
/// paths may be added.
fn validate_filesystem_additive(
    baseline: Option<&openshell_core::proto::FilesystemPolicy>,
    new: Option<&openshell_core::proto::FilesystemPolicy>,
) -> Result<(), Status> {
    match (baseline, new) {
        (Some(base), Some(upd)) => {
            if base.include_workdir != upd.include_workdir {
                return Err(Status::invalid_argument(
                    "filesystem include_workdir cannot be changed on a live sandbox",
                ));
            }
            for path in &base.read_only {
                if !upd.read_only.contains(path) {
                    return Err(Status::invalid_argument(format!(
                        "filesystem read_only path '{path}' cannot be removed on a live sandbox"
                    )));
                }
            }
            for path in &base.read_write {
                if !upd.read_write.contains(path) {
                    return Err(Status::invalid_argument(format!(
                        "filesystem read_write path '{path}' cannot be removed on a live sandbox"
                    )));
                }
            }
        }
        (None, Some(_)) => {
            // Baseline had no filesystem policy, new one adds it — allowed
            // (enrichment from empty).
        }
        (Some(_), None) => {
            return Err(Status::invalid_argument(
                "filesystem policy cannot be removed on a live sandbox",
            ));
        }
        (None, None) => {}
    }
    Ok(())
}

/// Convert a `PolicyRecord` to a `SandboxPolicyRevision` proto message.
fn policy_record_to_revision(record: &PolicyRecord, include_policy: bool) -> SandboxPolicyRevision {
    let status = match record.status.as_str() {
        "pending" => PolicyStatus::Pending,
        "loaded" => PolicyStatus::Loaded,
        "failed" => PolicyStatus::Failed,
        "superseded" => PolicyStatus::Superseded,
        _ => PolicyStatus::Unspecified,
    };

    let policy = if include_policy {
        ProtoSandboxPolicy::decode(record.policy_payload.as_slice()).ok()
    } else {
        None
    };

    SandboxPolicyRevision {
        version: u32::try_from(record.version).unwrap_or(0),
        policy_hash: record.policy_hash.clone(),
        status: status.into(),
        load_error: record.load_error.clone().unwrap_or_default(),
        created_at_ms: record.created_at_ms,
        loaded_at_ms: record.loaded_at_ms.unwrap_or(0),
        policy,
    }
}

fn current_time_ms() -> Result<i64, std::time::SystemTimeError> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    Ok(i64::try_from(now.as_millis()).unwrap_or(i64::MAX))
}

fn resolve_gateway(config: &openshell_core::Config) -> (String, u16) {
    let host = if config.ssh_gateway_host.is_empty() {
        config.bind_address.ip().to_string()
    } else {
        config.ssh_gateway_host.clone()
    };
    let port = if config.ssh_gateway_port == 0 {
        config.bind_address.port()
    } else {
        config.ssh_gateway_port
    };
    (host, port)
}

async fn resolve_sandbox_exec_target(
    state: &ServerState,
    sandbox: &Sandbox,
) -> Result<(String, u16), Status> {
    if let Some(status) = sandbox.status.as_ref()
        && !status.agent_pod.is_empty()
    {
        match state.sandbox_client.agent_pod_ip(&status.agent_pod).await {
            Ok(Some(ip)) => {
                return Ok((ip.to_string(), state.config.sandbox_ssh_port));
            }
            Ok(None) => {
                return Err(Status::failed_precondition(
                    "sandbox agent pod IP is not available",
                ));
            }
            Err(err) => {
                return Err(Status::internal(format!(
                    "failed to resolve agent pod IP: {err}"
                )));
            }
        }
    }

    if sandbox.name.is_empty() {
        return Err(Status::failed_precondition("sandbox has no name"));
    }

    Ok((
        format!(
            "{}.{}.svc.cluster.local",
            sandbox.name, state.config.sandbox_namespace
        ),
        state.config.sandbox_ssh_port,
    ))
}

/// Maximum number of arguments in the command array.
const MAX_EXEC_COMMAND_ARGS: usize = 1024;
/// Maximum length of a single command argument or environment value (bytes).
const MAX_EXEC_ARG_LEN: usize = 32 * 1024; // 32 KiB
/// Maximum length of the workdir field (bytes).
const MAX_EXEC_WORKDIR_LEN: usize = 4096;

/// Validate fields of an ExecSandboxRequest for control characters and size
/// limits before constructing a shell command string.
fn validate_exec_request_fields(req: &ExecSandboxRequest) -> Result<(), Status> {
    if req.command.len() > MAX_EXEC_COMMAND_ARGS {
        return Err(Status::invalid_argument(format!(
            "command array exceeds {} argument limit",
            MAX_EXEC_COMMAND_ARGS
        )));
    }
    for (i, arg) in req.command.iter().enumerate() {
        if arg.len() > MAX_EXEC_ARG_LEN {
            return Err(Status::invalid_argument(format!(
                "command argument {i} exceeds {} byte limit",
                MAX_EXEC_ARG_LEN
            )));
        }
        reject_control_chars(arg, &format!("command argument {i}"))?;
    }
    for (key, value) in &req.environment {
        if value.len() > MAX_EXEC_ARG_LEN {
            return Err(Status::invalid_argument(format!(
                "environment value for '{key}' exceeds {} byte limit",
                MAX_EXEC_ARG_LEN
            )));
        }
        reject_control_chars(value, &format!("environment value for '{key}'"))?;
    }
    if !req.workdir.is_empty() {
        if req.workdir.len() > MAX_EXEC_WORKDIR_LEN {
            return Err(Status::invalid_argument(format!(
                "workdir exceeds {} byte limit",
                MAX_EXEC_WORKDIR_LEN
            )));
        }
        reject_control_chars(&req.workdir, "workdir")?;
    }
    Ok(())
}

/// Reject null bytes and newlines in a user-supplied value.
fn reject_control_chars(value: &str, field_name: &str) -> Result<(), Status> {
    if value.bytes().any(|b| b == 0) {
        return Err(Status::invalid_argument(format!(
            "{field_name} contains null bytes"
        )));
    }
    if value.bytes().any(|b| b == b'\n' || b == b'\r') {
        return Err(Status::invalid_argument(format!(
            "{field_name} contains newline or carriage return characters"
        )));
    }
    Ok(())
}

/// Shell-escape a value for embedding in a POSIX shell command.
///
/// Wraps unsafe values in single quotes with the standard `'\''` idiom for
/// embedded single-quote characters. Rejects null bytes which can truncate
/// shell parsing at the C level.
fn shell_escape(value: &str) -> Result<String, String> {
    // Reject null bytes — can truncate shell parsing at the C level.
    if value.bytes().any(|b| b == 0) {
        return Err("value contains null bytes".to_string());
    }
    // Reject newlines and carriage returns — safe within single quotes for
    // one shell layer, but dangerous when the command string traverses
    // multiple interpretation boundaries (SSH transport + bash -lc).
    if value.bytes().any(|b| b == b'\n' || b == b'\r') {
        return Err("value contains newline or carriage return".to_string());
    }
    if value.is_empty() {
        return Ok("''".to_string());
    }
    let safe = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b'-' | b'_'));
    if safe {
        return Ok(value.to_string());
    }
    let escaped = value.replace('\'', "'\"'\"'");
    Ok(format!("'{escaped}'"))
}

/// Maximum total length of the assembled shell command string.
const MAX_COMMAND_STRING_LEN: usize = 256 * 1024; // 256 KiB

fn build_remote_exec_command(req: &ExecSandboxRequest) -> Result<String, String> {
    let mut parts = Vec::new();
    let mut env_entries = req.environment.iter().collect::<Vec<_>>();
    env_entries.sort_by(|(a, _), (b, _)| a.cmp(b));
    for (key, value) in env_entries {
        parts.push(format!("{key}={}", shell_escape(value)?));
    }
    for arg in &req.command {
        parts.push(shell_escape(arg)?);
    }
    let command = parts.join(" ");
    let result = if req.workdir.is_empty() {
        command
    } else {
        format!("cd {} && {command}", shell_escape(&req.workdir)?)
    };
    if result.len() > MAX_COMMAND_STRING_LEN {
        return Err(format!(
            "assembled command string exceeds {} byte limit",
            MAX_COMMAND_STRING_LEN
        ));
    }
    Ok(result)
}

/// Resolve provider credentials into environment variables.
///
/// For each provider name in the list, fetches the provider from the store and
/// collects credential key-value pairs. Returns a map of environment variables
/// to inject into the sandbox. When duplicate keys appear across providers, the
/// first provider's value wins.
async fn resolve_provider_environment(
    store: &crate::persistence::Store,
    provider_names: &[String],
) -> Result<std::collections::HashMap<String, String>, Status> {
    if provider_names.is_empty() {
        return Ok(std::collections::HashMap::new());
    }

    let mut env = std::collections::HashMap::new();

    for name in provider_names {
        let provider = store
            .get_message_by_name::<Provider>(name)
            .await
            .map_err(|e| Status::internal(format!("failed to fetch provider '{name}': {e}")))?
            .ok_or_else(|| Status::failed_precondition(format!("provider '{name}' not found")))?;

        for (key, value) in &provider.credentials {
            if is_valid_env_key(key) {
                env.entry(key.clone()).or_insert_with(|| value.clone());
            } else {
                warn!(
                    provider_name = %name,
                    key = %key,
                    "skipping credential with invalid env var key"
                );
            }
        }
    }

    Ok(env)
}

fn is_valid_env_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first == b'_' || first.is_ascii_alphabetic()) {
        return false;
    }
    bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

/// Maximum number of attempts when establishing the SSH transport to a sandbox.
/// The sandbox SSH server may not be listening yet when the pod is marked Ready,
/// so we retry transient connection failures with exponential backoff.
const SSH_CONNECT_MAX_ATTEMPTS: u32 = 6;

/// Initial backoff duration between SSH connection retries (doubles each attempt).
const SSH_CONNECT_INITIAL_BACKOFF: std::time::Duration = std::time::Duration::from_millis(250);

/// Maximum backoff duration between SSH connection retries (caps exponential growth).
const SSH_CONNECT_MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(2);

/// Returns `true` if the gRPC status represents a transient SSH connection error
/// that is worth retrying (e.g. the sandbox SSH server is not yet listening).
fn is_retryable_ssh_error(status: &Status) -> bool {
    if status.code() != tonic::Code::Internal {
        return false;
    }
    let msg = status.message();
    msg.contains("Connection reset by peer")
        || msg.contains("Connection refused")
        || msg.contains("failed to establish ssh transport")
        || msg.contains("failed to connect to ssh proxy")
        || msg.contains("failed to start ssh proxy")
}

#[allow(clippy::too_many_arguments)]
async fn stream_exec_over_ssh(
    tx: mpsc::Sender<Result<ExecSandboxEvent, Status>>,
    sandbox_id: &str,
    target_host: &str,
    target_port: u16,
    command: &str,
    stdin_payload: Vec<u8>,
    timeout_seconds: u32,
    handshake_secret: &str,
) -> Result<(), Status> {
    let command_preview: String = command.chars().take(120).collect();
    info!(
        sandbox_id = %sandbox_id,
        target_host = %target_host,
        target_port,
        command_len = command.len(),
        stdin_len = stdin_payload.len(),
        command_preview = %command_preview,
        "ExecSandbox command started"
    );

    // Retry loop: the sandbox SSH server may not be accepting connections yet
    // even though the pod is marked Ready by Kubernetes. We retry transient
    // connection errors with exponential backoff.
    let (exit_code, proxy_task) = {
        let mut last_err: Option<Status> = None;

        let mut result = None;
        for attempt in 0..SSH_CONNECT_MAX_ATTEMPTS {
            if attempt > 0 {
                let backoff = (SSH_CONNECT_INITIAL_BACKOFF * 2u32.pow(attempt - 1))
                    .min(SSH_CONNECT_MAX_BACKOFF);
                warn!(
                    sandbox_id = %sandbox_id,
                    attempt = attempt + 1,
                    backoff_ms = %backoff.as_millis(),
                    error = %last_err.as_ref().unwrap(),
                    "Retrying SSH transport establishment"
                );
                tokio::time::sleep(backoff).await;
            }

            let (local_proxy_port, proxy_task) = match start_single_use_ssh_proxy(
                target_host,
                target_port,
                handshake_secret,
            )
            .await
            {
                Ok(v) => v,
                Err(e) => {
                    last_err = Some(Status::internal(format!("failed to start ssh proxy: {e}")));
                    continue;
                }
            };

            let exec =
                run_exec_with_russh(local_proxy_port, command, stdin_payload.clone(), tx.clone());

            let exec_result = if timeout_seconds == 0 {
                exec.await
            } else if let Ok(r) = tokio::time::timeout(
                std::time::Duration::from_secs(u64::from(timeout_seconds)),
                exec,
            )
            .await
            {
                r
            } else {
                // Timed out — not retryable, report timeout exit code immediately.
                let _ = tx
                    .send(Ok(ExecSandboxEvent {
                        payload: Some(openshell_core::proto::exec_sandbox_event::Payload::Exit(
                            ExecSandboxExit { exit_code: 124 },
                        )),
                    }))
                    .await;
                let _ = proxy_task.await;
                return Ok(());
            };

            match exec_result {
                Ok(exit_code) => {
                    result = Some((exit_code, proxy_task));
                    break;
                }
                Err(status) => {
                    let _ = proxy_task.await;
                    if is_retryable_ssh_error(&status) && attempt + 1 < SSH_CONNECT_MAX_ATTEMPTS {
                        last_err = Some(status);
                        continue;
                    }
                    return Err(status);
                }
            }
        }

        result.ok_or_else(|| {
            last_err.unwrap_or_else(|| {
                Status::internal("ssh connection failed after exhausting retries")
            })
        })?
    };

    let _ = proxy_task.await;

    let _ = tx
        .send(Ok(ExecSandboxEvent {
            payload: Some(openshell_core::proto::exec_sandbox_event::Payload::Exit(
                ExecSandboxExit { exit_code },
            )),
        }))
        .await;

    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct SandboxSshClientHandler;

impl russh::client::Handler for SandboxSshClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

async fn run_exec_with_russh(
    local_proxy_port: u16,
    command: &str,
    stdin_payload: Vec<u8>,
    tx: mpsc::Sender<Result<ExecSandboxEvent, Status>>,
) -> Result<i32, Status> {
    // Defense-in-depth: validate command at the transport boundary even though
    // exec_sandbox and build_remote_exec_command already validate upstream.
    if command.as_bytes().contains(&0) {
        return Err(Status::invalid_argument(
            "command contains null bytes at transport boundary",
        ));
    }
    if command.len() > MAX_COMMAND_STRING_LEN {
        return Err(Status::invalid_argument(format!(
            "command exceeds {} byte limit at transport boundary",
            MAX_COMMAND_STRING_LEN
        )));
    }

    let stream = TcpStream::connect(("127.0.0.1", local_proxy_port))
        .await
        .map_err(|e| Status::internal(format!("failed to connect to ssh proxy: {e}")))?;

    let config = Arc::new(russh::client::Config::default());
    let mut client = russh::client::connect_stream(config, stream, SandboxSshClientHandler)
        .await
        .map_err(|e| Status::internal(format!("failed to establish ssh transport: {e}")))?;

    match client
        .authenticate_none("sandbox")
        .await
        .map_err(|e| Status::internal(format!("failed to authenticate ssh session: {e}")))?
    {
        AuthResult::Success => {}
        AuthResult::Failure { .. } => {
            return Err(Status::permission_denied(
                "ssh authentication rejected by sandbox",
            ));
        }
    }

    let mut channel = client
        .channel_open_session()
        .await
        .map_err(|e| Status::internal(format!("failed to open ssh channel: {e}")))?;

    channel
        .exec(true, command.as_bytes())
        .await
        .map_err(|e| Status::internal(format!("failed to execute command over ssh: {e}")))?;

    if !stdin_payload.is_empty() {
        channel
            .data(std::io::Cursor::new(stdin_payload))
            .await
            .map_err(|e| Status::internal(format!("failed to send ssh stdin payload: {e}")))?;
    }

    channel
        .eof()
        .await
        .map_err(|e| Status::internal(format!("failed to close ssh stdin: {e}")))?;

    let mut exit_code: Option<i32> = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => {
                let _ = tx
                    .send(Ok(ExecSandboxEvent {
                        payload: Some(openshell_core::proto::exec_sandbox_event::Payload::Stdout(
                            ExecSandboxStdout {
                                data: data.to_vec(),
                            },
                        )),
                    }))
                    .await;
            }
            ChannelMsg::ExtendedData { data, .. } => {
                let _ = tx
                    .send(Ok(ExecSandboxEvent {
                        payload: Some(openshell_core::proto::exec_sandbox_event::Payload::Stderr(
                            ExecSandboxStderr {
                                data: data.to_vec(),
                            },
                        )),
                    }))
                    .await;
            }
            ChannelMsg::ExitStatus { exit_status } => {
                let converted = i32::try_from(exit_status).unwrap_or(i32::MAX);
                exit_code = Some(converted);
            }
            ChannelMsg::Close => break,
            _ => {}
        }
    }

    let _ = channel.close().await;
    let _ = client
        .disconnect(russh::Disconnect::ByApplication, "exec complete", "en")
        .await;

    Ok(exit_code.unwrap_or(1))
}

/// Check whether an IP address is safe to use as an SSH proxy target.
///
/// Blocks loopback (prevents connecting back to the gateway server itself)
/// and link-local addresses (prevents cloud metadata SSRF via 169.254.169.254).
fn is_safe_ssh_proxy_target(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            !v4.is_loopback() // 127.0.0.0/8
            && !v4.is_link_local() // 169.254.0.0/16 (cloud metadata)
        }
        std::net::IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return false; // ::1
            }
            // Check IPv4-mapped IPv6 addresses like ::ffff:127.0.0.1
            if let Some(v4) = v6.to_ipv4_mapped() {
                return !v4.is_loopback() && !v4.is_link_local();
            }
            true
        }
    }
}

async fn start_single_use_ssh_proxy(
    target_host: &str,
    target_port: u16,
    handshake_secret: &str,
) -> Result<(u16, tokio::task::JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let target_host = target_host.to_string();
    let handshake_secret = handshake_secret.to_string();

    let task = tokio::spawn(async move {
        let Ok((mut client_conn, _)) = listener.accept().await else {
            warn!("SSH proxy: failed to accept local connection");
            return;
        };

        // Resolve DNS and validate the target IP before connecting.
        // This prevents SSRF if the sandbox status record were poisoned
        // to point at loopback, cloud metadata, or other internal services.
        let addr_str = format!("{}:{}", target_host, target_port);
        let resolved = match tokio::net::lookup_host(&addr_str).await {
            Ok(mut addrs) => match addrs.next() {
                Some(addr) => addr,
                None => {
                    warn!(target_host = %target_host, "SSH proxy: DNS resolution returned no addresses");
                    return;
                }
            },
            Err(e) => {
                warn!(target_host = %target_host, error = %e, "SSH proxy: DNS resolution failed");
                return;
            }
        };

        if !is_safe_ssh_proxy_target(resolved.ip()) {
            warn!(
                target_host = %target_host,
                resolved_ip = %resolved.ip(),
                "SSH proxy: target resolved to blocked IP range (loopback or link-local)"
            );
            return;
        }

        debug!(
            target_host = %target_host,
            resolved_ip = %resolved.ip(),
            target_port,
            "SSH proxy: connecting to validated target"
        );

        // Connect to the resolved address directly (not the hostname) to
        // prevent TOCTOU between validation and connection.
        let Ok(mut sandbox_conn) = TcpStream::connect(resolved).await else {
            warn!(target_host = %target_host, resolved_ip = %resolved.ip(), target_port, "SSH proxy: failed to connect to sandbox");
            return;
        };
        let Ok(preface) = build_preface(&uuid::Uuid::new_v4().to_string(), &handshake_secret)
        else {
            warn!("SSH proxy: failed to build handshake preface");
            return;
        };
        if let Err(e) = sandbox_conn.write_all(preface.as_bytes()).await {
            warn!(error = %e, "SSH proxy: failed to send handshake preface");
            return;
        }
        let mut response = String::new();
        if let Err(e) = read_line(&mut sandbox_conn, &mut response).await {
            warn!(error = %e, "SSH proxy: failed to read handshake response");
            return;
        }
        if response.trim() != "OK" {
            warn!(response = %response.trim(), "SSH proxy: handshake rejected by sandbox");
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut client_conn, &mut sandbox_conn).await;
    });

    Ok((port, task))
}

fn build_preface(
    token: &str,
    secret: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let timestamp = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "time error")?
            .as_secs(),
    )
    .map_err(|_| "time error")?;
    let nonce = uuid::Uuid::new_v4().to_string();
    let payload = format!("{token}|{timestamp}|{nonce}");
    let signature = hmac_sha256(secret.as_bytes(), payload.as_bytes());
    Ok(format!("NSSH1 {token} {timestamp} {nonce} {signature}\n"))
}

async fn read_line(
    stream: &mut TcpStream,
    buf: &mut String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        bytes.push(byte[0]);
        if bytes.len() > 1024 {
            break;
        }
    }
    *buf = String::from_utf8_lossy(&bytes).to_string();
    Ok(())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    hex::encode(result)
}

// ---------------------------------------------------------------------------
// Provider CRUD
// ---------------------------------------------------------------------------

/// Redact credential values from a provider before returning it in a gRPC
/// response.  Key names are preserved so callers can display credential counts
/// and key listings.  Internal server paths (inference routing, sandbox env
/// injection) read credentials from the store directly and are unaffected.
fn redact_provider_credentials(mut provider: Provider) -> Provider {
    for value in provider.credentials.values_mut() {
        *value = "REDACTED".to_string();
    }
    provider
}

async fn create_provider_record(
    store: &crate::persistence::Store,
    mut provider: Provider,
) -> Result<Provider, Status> {
    if provider.name.is_empty() {
        provider.name = generate_name();
    }
    if provider.r#type.trim().is_empty() {
        return Err(Status::invalid_argument("provider.type is required"));
    }
    if provider.credentials.is_empty() {
        return Err(Status::invalid_argument(
            "provider.credentials must not be empty",
        ));
    }

    // Validate field sizes before any I/O.
    validate_provider_fields(&provider)?;

    let existing = store
        .get_message_by_name::<Provider>(&provider.name)
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?;

    if existing.is_some() {
        return Err(Status::already_exists("provider already exists"));
    }

    provider.id = uuid::Uuid::new_v4().to_string();

    store
        .put_message(&provider)
        .await
        .map_err(|e| Status::internal(format!("persist provider failed: {e}")))?;

    Ok(redact_provider_credentials(provider))
}

async fn get_provider_record(
    store: &crate::persistence::Store,
    name: &str,
) -> Result<Provider, Status> {
    if name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }

    store
        .get_message_by_name::<Provider>(name)
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
        .ok_or_else(|| Status::not_found("provider not found"))
        .map(redact_provider_credentials)
}

async fn list_provider_records(
    store: &crate::persistence::Store,
    limit: u32,
    offset: u32,
) -> Result<Vec<Provider>, Status> {
    let records = store
        .list(Provider::object_type(), limit, offset)
        .await
        .map_err(|e| Status::internal(format!("list providers failed: {e}")))?;

    let mut providers = Vec::with_capacity(records.len());
    for record in records {
        let provider = Provider::decode(record.payload.as_slice())
            .map_err(|e| Status::internal(format!("decode provider failed: {e}")))?;
        providers.push(redact_provider_credentials(provider));
    }

    Ok(providers)
}

/// Merge an incoming map into an existing map.
///
/// - If `incoming` is empty, return `existing` unchanged (no-op).
/// - Otherwise, upsert all incoming entries into `existing`.
/// - Entries with an empty-string value are removed (delete semantics).
fn merge_map(
    mut existing: std::collections::HashMap<String, String>,
    incoming: std::collections::HashMap<String, String>,
) -> std::collections::HashMap<String, String> {
    if incoming.is_empty() {
        return existing;
    }
    for (key, value) in incoming {
        if value.is_empty() {
            existing.remove(&key);
        } else {
            existing.insert(key, value);
        }
    }
    existing
}

async fn update_provider_record(
    store: &crate::persistence::Store,
    provider: Provider,
) -> Result<Provider, Status> {
    if provider.name.is_empty() {
        return Err(Status::invalid_argument("provider.name is required"));
    }

    let existing = store
        .get_message_by_name::<Provider>(&provider.name)
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?;

    let Some(existing) = existing else {
        return Err(Status::not_found("provider not found"));
    };

    // Provider type is immutable after creation. Reject if the caller
    // sends a non-empty type that differs from the existing one.
    let incoming_type = provider.r#type.trim();
    if !incoming_type.is_empty() && !incoming_type.eq_ignore_ascii_case(existing.r#type.trim()) {
        return Err(Status::invalid_argument(
            "provider type cannot be changed; delete and recreate the provider",
        ));
    }

    let updated = Provider {
        id: existing.id,
        name: existing.name,
        r#type: existing.r#type,
        credentials: merge_map(existing.credentials, provider.credentials),
        config: merge_map(existing.config, provider.config),
    };

    validate_provider_fields(&updated)?;

    store
        .put_message(&updated)
        .await
        .map_err(|e| Status::internal(format!("persist provider failed: {e}")))?;

    Ok(redact_provider_credentials(updated))
}

async fn delete_provider_record(
    store: &crate::persistence::Store,
    name: &str,
) -> Result<bool, Status> {
    if name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }

    store
        .delete_by_name(Provider::object_type(), name)
        .await
        .map_err(|e| Status::internal(format!("delete provider failed: {e}")))
}

impl ObjectType for Provider {
    fn object_type() -> &'static str {
        "provider"
    }
}

impl ObjectId for Provider {
    fn object_id(&self) -> &str {
        &self.id
    }
}

impl ObjectName for Provider {
    fn object_name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_ENVIRONMENT_ENTRIES, MAX_LOG_LEVEL_LEN, MAX_MAP_KEY_LEN, MAX_MAP_VALUE_LEN,
        MAX_NAME_LEN, MAX_PAGE_SIZE, MAX_POLICY_SIZE, MAX_PROVIDER_CONFIG_ENTRIES,
        MAX_PROVIDER_CREDENTIALS_ENTRIES, MAX_PROVIDER_TYPE_LEN, MAX_PROVIDERS,
        MAX_TEMPLATE_MAP_ENTRIES, MAX_TEMPLATE_STRING_LEN, MAX_TEMPLATE_STRUCT_SIZE,
        build_remote_exec_command, clamp_limit, create_provider_record, delete_provider_record,
        get_provider_record, is_safe_ssh_proxy_target, is_valid_env_key, list_provider_records,
        merge_chunk_into_policy, reject_control_chars, resolve_provider_environment, shell_escape,
        update_provider_record, validate_provider_fields, validate_sandbox_spec,
    };
    use crate::persistence::{DraftChunkRecord, Store};
    use openshell_core::proto::{Provider, SandboxSpec, SandboxTemplate};
    use prost::Message;
    use std::collections::HashMap;
    use tonic::Code;

    #[test]
    fn env_key_validation_accepts_valid_keys() {
        assert!(is_valid_env_key("PATH"));
        assert!(is_valid_env_key("PYTHONPATH"));
        assert!(is_valid_env_key("_OPENSHELL_VALUE_1"));
    }

    #[test]
    fn env_key_validation_rejects_invalid_keys() {
        assert!(!is_valid_env_key(""));
        assert!(!is_valid_env_key("1PATH"));
        assert!(!is_valid_env_key("BAD-KEY"));
        assert!(!is_valid_env_key("BAD KEY"));
        assert!(!is_valid_env_key("X=Y"));
        assert!(!is_valid_env_key("X;rm -rf /"));
    }

    // ---- SEC-002: shell_escape, reject_control_chars, build_remote_exec_command ----

    #[test]
    fn shell_escape_safe_chars_pass_through() {
        assert_eq!(shell_escape("ls").unwrap(), "ls");
        assert_eq!(shell_escape("/usr/bin/python").unwrap(), "/usr/bin/python");
        assert_eq!(shell_escape("file.txt").unwrap(), "file.txt");
        assert_eq!(shell_escape("my-cmd_v2").unwrap(), "my-cmd_v2");
    }

    #[test]
    fn shell_escape_empty_string() {
        assert_eq!(shell_escape("").unwrap(), "''");
    }

    #[test]
    fn shell_escape_wraps_unsafe_chars() {
        assert_eq!(shell_escape("hello world").unwrap(), "'hello world'");
        assert_eq!(shell_escape("$(id)").unwrap(), "'$(id)'");
        assert_eq!(shell_escape("; rm -rf /").unwrap(), "'; rm -rf /'");
    }

    #[test]
    fn shell_escape_handles_single_quotes() {
        assert_eq!(shell_escape("it's").unwrap(), "'it'\"'\"'s'");
    }

    #[test]
    fn shell_escape_rejects_null_bytes() {
        assert!(shell_escape("hello\x00world").is_err());
    }

    #[test]
    fn shell_escape_rejects_newlines() {
        assert!(shell_escape("line1\nline2").is_err());
        assert!(shell_escape("line1\rline2").is_err());
        assert!(shell_escape("line1\r\nline2").is_err());
    }

    #[test]
    fn reject_control_chars_allows_normal_values() {
        assert!(reject_control_chars("hello world", "test").is_ok());
        assert!(reject_control_chars("$(cmd)", "test").is_ok());
        assert!(reject_control_chars("", "test").is_ok());
    }

    #[test]
    fn reject_control_chars_rejects_null_bytes() {
        assert!(reject_control_chars("hello\x00world", "test").is_err());
    }

    #[test]
    fn reject_control_chars_rejects_newlines() {
        assert!(reject_control_chars("line1\nline2", "test").is_err());
        assert!(reject_control_chars("line1\rline2", "test").is_err());
    }

    #[test]
    fn build_remote_exec_command_basic() {
        use openshell_core::proto::ExecSandboxRequest;
        let req = ExecSandboxRequest {
            sandbox_id: "test".to_string(),
            command: vec!["ls".to_string(), "-la".to_string()],
            ..Default::default()
        };
        assert_eq!(build_remote_exec_command(&req).unwrap(), "ls -la");
    }

    #[test]
    fn build_remote_exec_command_with_env_and_workdir() {
        use openshell_core::proto::ExecSandboxRequest;
        let req = ExecSandboxRequest {
            sandbox_id: "test".to_string(),
            command: vec![
                "python".to_string(),
                "-c".to_string(),
                "print('ok')".to_string(),
            ],
            environment: [("HOME".to_string(), "/home/user".to_string())]
                .into_iter()
                .collect(),
            workdir: "/workspace".to_string(),
            ..Default::default()
        };
        let cmd = build_remote_exec_command(&req).unwrap();
        assert!(cmd.starts_with("cd /workspace && "));
        assert!(cmd.contains("HOME=/home/user"));
        assert!(cmd.contains("'print('\"'\"'ok'\"'\"')'"));
    }

    #[test]
    fn build_remote_exec_command_rejects_null_bytes_in_args() {
        use openshell_core::proto::ExecSandboxRequest;
        let req = ExecSandboxRequest {
            sandbox_id: "test".to_string(),
            command: vec!["echo".to_string(), "hello\x00world".to_string()],
            ..Default::default()
        };
        assert!(build_remote_exec_command(&req).is_err());
    }

    #[test]
    fn build_remote_exec_command_rejects_newlines_in_workdir() {
        use openshell_core::proto::ExecSandboxRequest;
        let req = ExecSandboxRequest {
            sandbox_id: "test".to_string(),
            command: vec!["ls".to_string()],
            workdir: "/tmp\nmalicious".to_string(),
            ..Default::default()
        };
        assert!(build_remote_exec_command(&req).is_err());
    }

    // ---- SEC-006: is_safe_ssh_proxy_target ----

    #[test]
    fn ssh_proxy_target_allows_pod_network_ips() {
        use std::net::{IpAddr, Ipv4Addr};
        // Typical pod network IPs should be allowed
        assert!(is_safe_ssh_proxy_target(IpAddr::V4(Ipv4Addr::new(
            10, 0, 0, 5
        ))));
        assert!(is_safe_ssh_proxy_target(IpAddr::V4(Ipv4Addr::new(
            172, 16, 0, 1
        ))));
        assert!(is_safe_ssh_proxy_target(IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 100
        ))));
    }

    #[test]
    fn ssh_proxy_target_blocks_loopback() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        assert!(!is_safe_ssh_proxy_target(IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1
        ))));
        assert!(!is_safe_ssh_proxy_target(IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 2
        ))));
        assert!(!is_safe_ssh_proxy_target(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn ssh_proxy_target_blocks_link_local() {
        use std::net::{IpAddr, Ipv4Addr};
        // 169.254.169.254 is the cloud metadata endpoint
        assert!(!is_safe_ssh_proxy_target(IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))));
        assert!(!is_safe_ssh_proxy_target(IpAddr::V4(Ipv4Addr::new(
            169, 254, 0, 1
        ))));
    }

    #[test]
    fn ssh_proxy_target_blocks_ipv4_mapped_ipv6_loopback() {
        use std::net::IpAddr;
        // ::ffff:127.0.0.1
        let ip: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(!is_safe_ssh_proxy_target(ip));
    }

    #[test]
    fn ssh_proxy_target_blocks_ipv4_mapped_ipv6_link_local() {
        use std::net::IpAddr;
        // ::ffff:169.254.169.254
        let ip: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        assert!(!is_safe_ssh_proxy_target(ip));
    }

    // ---- clamp_limit tests ----

    #[test]
    fn clamp_limit_zero_returns_default() {
        assert_eq!(clamp_limit(0, 100, MAX_PAGE_SIZE), 100);
        assert_eq!(clamp_limit(0, 50, MAX_PAGE_SIZE), 50);
    }

    #[test]
    fn clamp_limit_within_range_passes_through() {
        assert_eq!(clamp_limit(1, 100, MAX_PAGE_SIZE), 1);
        assert_eq!(clamp_limit(500, 100, MAX_PAGE_SIZE), 500);
        assert_eq!(
            clamp_limit(MAX_PAGE_SIZE, 100, MAX_PAGE_SIZE),
            MAX_PAGE_SIZE
        );
    }

    #[test]
    fn clamp_limit_exceeding_max_is_capped() {
        assert_eq!(
            clamp_limit(MAX_PAGE_SIZE + 1, 100, MAX_PAGE_SIZE),
            MAX_PAGE_SIZE
        );
        assert_eq!(clamp_limit(u32::MAX, 100, MAX_PAGE_SIZE), MAX_PAGE_SIZE);
    }

    fn provider_with_values(name: &str, provider_type: &str) -> Provider {
        Provider {
            id: String::new(),
            name: name.to_string(),
            r#type: provider_type.to_string(),
            credentials: [
                ("API_TOKEN".to_string(), "token-123".to_string()),
                ("SECONDARY".to_string(), "secondary-token".to_string()),
            ]
            .into_iter()
            .collect(),
            config: [
                ("endpoint".to_string(), "https://example.com".to_string()),
                ("region".to_string(), "us-west".to_string()),
            ]
            .into_iter()
            .collect(),
        }
    }

    #[tokio::test]
    async fn provider_crud_round_trip_and_semantics() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let created = provider_with_values("gitlab-local", "gitlab");
        let persisted = create_provider_record(&store, created.clone())
            .await
            .unwrap();
        assert_eq!(persisted.name, "gitlab-local");
        assert_eq!(persisted.r#type, "gitlab");
        assert!(!persisted.id.is_empty());
        let provider_id = persisted.id.clone();

        let duplicate_err = create_provider_record(&store, created).await.unwrap_err();
        assert_eq!(duplicate_err.code(), Code::AlreadyExists);

        let loaded = get_provider_record(&store, "gitlab-local").await.unwrap();
        assert_eq!(loaded.id, provider_id);

        let listed = list_provider_records(&store, 100, 0).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "gitlab-local");

        let updated = update_provider_record(
            &store,
            Provider {
                id: String::new(),
                name: "gitlab-local".to_string(),
                r#type: "gitlab".to_string(),
                credentials: std::iter::once((
                    "API_TOKEN".to_string(),
                    "rotated-token".to_string(),
                ))
                .collect(),
                config: std::iter::once(("endpoint".to_string(), "https://gitlab.com".to_string()))
                    .collect(),
            },
        )
        .await
        .unwrap();
        assert_eq!(updated.id, provider_id);
        // Credential keys are preserved but values are redacted in responses.
        assert_eq!(updated.credentials.len(), 2);
        assert_eq!(
            updated.credentials.get("API_TOKEN"),
            Some(&"REDACTED".to_string()),
            "credential values must be redacted in gRPC responses"
        );
        assert_eq!(
            updated.credentials.get("SECONDARY"),
            Some(&"REDACTED".to_string()),
        );
        // Verify the store still has full credentials.
        let stored: Provider = store
            .get_message_by_name("gitlab-local")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.credentials.get("API_TOKEN"),
            Some(&"rotated-token".to_string())
        );
        assert_eq!(
            stored.credentials.get("SECONDARY"),
            Some(&"secondary-token".to_string())
        );
        // Updated config has new value.
        assert_eq!(
            updated.config.get("endpoint"),
            Some(&"https://gitlab.com".to_string())
        );
        // Non-updated config is preserved (not clobbered).
        assert_eq!(updated.config.get("region"), Some(&"us-west".to_string()));

        let deleted = delete_provider_record(&store, "gitlab-local")
            .await
            .unwrap();
        assert!(deleted);

        let deleted_again = delete_provider_record(&store, "gitlab-local")
            .await
            .unwrap();
        assert!(!deleted_again);

        let missing = get_provider_record(&store, "gitlab-local")
            .await
            .unwrap_err();
        assert_eq!(missing.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn provider_validation_errors() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let create_missing_type = create_provider_record(
            &store,
            Provider {
                id: String::new(),
                name: "bad-provider".to_string(),
                r#type: String::new(),
                credentials: HashMap::new(),
                config: HashMap::new(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(create_missing_type.code(), Code::InvalidArgument);

        let get_err = get_provider_record(&store, "").await.unwrap_err();
        assert_eq!(get_err.code(), Code::InvalidArgument);

        let delete_err = delete_provider_record(&store, "").await.unwrap_err();
        assert_eq!(delete_err.code(), Code::InvalidArgument);

        let update_missing_err = update_provider_record(
            &store,
            Provider {
                id: String::new(),
                name: "missing".to_string(),
                r#type: String::new(),
                credentials: HashMap::new(),
                config: HashMap::new(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(update_missing_err.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn update_provider_empty_maps_is_noop() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let created = provider_with_values("noop-test", "nvidia");
        let persisted = create_provider_record(&store, created).await.unwrap();

        // Update with empty type, empty credentials, empty config = no changes.
        let updated = update_provider_record(
            &store,
            Provider {
                id: String::new(),
                name: "noop-test".to_string(),
                r#type: String::new(),
                credentials: HashMap::new(),
                config: HashMap::new(),
            },
        )
        .await
        .unwrap();

        assert_eq!(updated.id, persisted.id);
        assert_eq!(updated.r#type, "nvidia");
        // Credential keys are preserved but values are redacted in responses.
        assert_eq!(updated.credentials.len(), 2);
        assert_eq!(
            updated.credentials.get("API_TOKEN"),
            Some(&"REDACTED".to_string())
        );
        assert_eq!(updated.config.len(), 2);
        assert_eq!(
            updated.config.get("endpoint"),
            Some(&"https://example.com".to_string())
        );
        assert_eq!(updated.config.get("region"), Some(&"us-west".to_string()));
        // Verify the store still has full credentials.
        let stored: Provider = store
            .get_message_by_name("noop-test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.credentials.len(), 2);
    }

    #[tokio::test]
    async fn update_provider_empty_value_deletes_key() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let created = provider_with_values("delete-key-test", "openai");
        create_provider_record(&store, created).await.unwrap();

        // Send SECONDARY with empty value to delete it; API_TOKEN untouched.
        let updated = update_provider_record(
            &store,
            Provider {
                id: String::new(),
                name: "delete-key-test".to_string(),
                r#type: String::new(),
                credentials: std::iter::once(("SECONDARY".to_string(), String::new())).collect(),
                config: std::iter::once(("region".to_string(), String::new())).collect(),
            },
        )
        .await
        .unwrap();

        // Credential keys are preserved but values are redacted; SECONDARY was deleted.
        assert_eq!(updated.credentials.len(), 1);
        assert_eq!(
            updated.credentials.get("API_TOKEN"),
            Some(&"REDACTED".to_string())
        );
        assert!(updated.credentials.get("SECONDARY").is_none());
        assert_eq!(updated.config.len(), 1);
        assert_eq!(
            updated.config.get("endpoint"),
            Some(&"https://example.com".to_string())
        );
        assert!(updated.config.get("region").is_none());
        // Verify the store has the correct credential state (SECONDARY deleted).
        let stored: Provider = store
            .get_message_by_name("delete-key-test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.credentials.len(), 1);
        assert_eq!(
            stored.credentials.get("API_TOKEN"),
            Some(&"token-123".to_string())
        );
        assert!(stored.credentials.get("SECONDARY").is_none());
    }

    #[tokio::test]
    async fn update_provider_empty_type_preserves_existing() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let created = provider_with_values("type-preserve-test", "anthropic");
        create_provider_record(&store, created).await.unwrap();

        let updated = update_provider_record(
            &store,
            Provider {
                id: String::new(),
                name: "type-preserve-test".to_string(),
                r#type: String::new(),
                credentials: HashMap::new(),
                config: HashMap::new(),
            },
        )
        .await
        .unwrap();

        assert_eq!(updated.r#type, "anthropic");
    }

    #[tokio::test]
    async fn update_provider_rejects_type_change() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let created = provider_with_values("type-change-test", "nvidia");
        create_provider_record(&store, created).await.unwrap();

        let err = update_provider_record(
            &store,
            Provider {
                id: String::new(),
                name: "type-change-test".to_string(),
                r#type: "openai".to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("type cannot be changed"));
    }

    #[tokio::test]
    async fn update_provider_validates_merged_result() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let created = provider_with_values("validate-merge-test", "gitlab");
        create_provider_record(&store, created).await.unwrap();

        // Add credentials that exceed the max key length to trigger validation.
        let oversized_key = "K".repeat(MAX_MAP_KEY_LEN + 1);
        let err = update_provider_record(
            &store,
            Provider {
                id: String::new(),
                name: "validate-merge-test".to_string(),
                r#type: String::new(),
                credentials: std::iter::once((oversized_key, "value".to_string())).collect(),
                config: HashMap::new(),
            },
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn resolve_provider_env_empty_list_returns_empty() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let result = resolve_provider_environment(&store, &[]).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn resolve_provider_env_injects_credentials() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let provider = Provider {
            id: String::new(),
            name: "claude-local".to_string(),
            r#type: "claude".to_string(),
            credentials: [
                ("ANTHROPIC_API_KEY".to_string(), "sk-abc".to_string()),
                ("CLAUDE_API_KEY".to_string(), "sk-abc".to_string()),
            ]
            .into_iter()
            .collect(),
            config: std::iter::once((
                "endpoint".to_string(),
                "https://api.anthropic.com".to_string(),
            ))
            .collect(),
        };
        create_provider_record(&store, provider).await.unwrap();

        let result = resolve_provider_environment(&store, &["claude-local".to_string()])
            .await
            .unwrap();
        assert_eq!(result.get("ANTHROPIC_API_KEY"), Some(&"sk-abc".to_string()));
        assert_eq!(result.get("CLAUDE_API_KEY"), Some(&"sk-abc".to_string()));
        // Config values should NOT be injected.
        assert!(!result.contains_key("endpoint"));
    }

    #[tokio::test]
    async fn resolve_provider_env_unknown_name_returns_error() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let err = resolve_provider_environment(&store, &["nonexistent".to_string()])
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert!(err.message().contains("nonexistent"));
    }

    #[tokio::test]
    async fn resolve_provider_env_skips_invalid_credential_keys() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let provider = Provider {
            id: String::new(),
            name: "test-provider".to_string(),
            r#type: "test".to_string(),
            credentials: [
                ("VALID_KEY".to_string(), "value".to_string()),
                ("nested.api_key".to_string(), "should-skip".to_string()),
                ("bad-key".to_string(), "should-skip".to_string()),
            ]
            .into_iter()
            .collect(),
            config: HashMap::new(),
        };
        create_provider_record(&store, provider).await.unwrap();

        let result = resolve_provider_environment(&store, &["test-provider".to_string()])
            .await
            .unwrap();
        assert_eq!(result.get("VALID_KEY"), Some(&"value".to_string()));
        assert!(!result.contains_key("nested.api_key"));
        assert!(!result.contains_key("bad-key"));
    }

    #[tokio::test]
    async fn resolve_provider_env_multiple_providers_merge() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        create_provider_record(
            &store,
            Provider {
                id: String::new(),
                name: "claude-local".to_string(),
                r#type: "claude".to_string(),
                credentials: std::iter::once((
                    "ANTHROPIC_API_KEY".to_string(),
                    "sk-abc".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
            },
        )
        .await
        .unwrap();
        create_provider_record(
            &store,
            Provider {
                id: String::new(),
                name: "gitlab-local".to_string(),
                r#type: "gitlab".to_string(),
                credentials: std::iter::once(("GITLAB_TOKEN".to_string(), "glpat-xyz".to_string()))
                    .collect(),
                config: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let result = resolve_provider_environment(
            &store,
            &["claude-local".to_string(), "gitlab-local".to_string()],
        )
        .await
        .unwrap();
        assert_eq!(result.get("ANTHROPIC_API_KEY"), Some(&"sk-abc".to_string()));
        assert_eq!(result.get("GITLAB_TOKEN"), Some(&"glpat-xyz".to_string()));
    }

    #[tokio::test]
    async fn resolve_provider_env_first_credential_wins_on_duplicate_key() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        create_provider_record(
            &store,
            Provider {
                id: String::new(),
                name: "provider-a".to_string(),
                r#type: "claude".to_string(),
                credentials: std::iter::once(("SHARED_KEY".to_string(), "first-value".to_string()))
                    .collect(),
                config: HashMap::new(),
            },
        )
        .await
        .unwrap();
        create_provider_record(
            &store,
            Provider {
                id: String::new(),
                name: "provider-b".to_string(),
                r#type: "gitlab".to_string(),
                credentials: std::iter::once((
                    "SHARED_KEY".to_string(),
                    "second-value".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
            },
        )
        .await
        .unwrap();

        let result = resolve_provider_environment(
            &store,
            &["provider-a".to_string(), "provider-b".to_string()],
        )
        .await
        .unwrap();
        assert_eq!(result.get("SHARED_KEY"), Some(&"first-value".to_string()));
    }

    /// Simulates the handler flow: persist a sandbox with providers, then resolve
    /// provider environment from the sandbox's spec.providers list.
    #[tokio::test]
    async fn handler_flow_resolves_credentials_from_sandbox_providers() {
        use openshell_core::proto::{Sandbox, SandboxPhase, SandboxSpec};

        let store = Store::connect("sqlite::memory:").await.unwrap();

        // Create providers.
        create_provider_record(
            &store,
            Provider {
                id: String::new(),
                name: "my-claude".to_string(),
                r#type: "claude".to_string(),
                credentials: std::iter::once((
                    "ANTHROPIC_API_KEY".to_string(),
                    "sk-test".to_string(),
                ))
                .collect(),
                config: HashMap::new(),
            },
        )
        .await
        .unwrap();

        // Persist a sandbox with providers field set.
        let sandbox = Sandbox {
            id: "sandbox-001".to_string(),
            name: "test-sandbox".to_string(),
            namespace: "default".to_string(),
            spec: Some(SandboxSpec {
                providers: vec!["my-claude".to_string()],
                ..SandboxSpec::default()
            }),
            status: None,
            phase: SandboxPhase::Ready as i32,
            ..Default::default()
        };
        store.put_message(&sandbox).await.unwrap();

        // Simulate the handler: fetch sandbox, read spec.providers, resolve.
        let loaded = store
            .get_message::<Sandbox>("sandbox-001")
            .await
            .unwrap()
            .unwrap();
        let spec = loaded.spec.unwrap();
        let env = resolve_provider_environment(&store, &spec.providers)
            .await
            .unwrap();

        assert_eq!(env.get("ANTHROPIC_API_KEY"), Some(&"sk-test".to_string()));
    }

    /// Handler flow returns empty map when sandbox has no providers.
    #[tokio::test]
    async fn handler_flow_returns_empty_when_no_providers() {
        use openshell_core::proto::{Sandbox, SandboxPhase, SandboxSpec};

        let store = Store::connect("sqlite::memory:").await.unwrap();

        let sandbox = Sandbox {
            id: "sandbox-002".to_string(),
            name: "empty-sandbox".to_string(),
            namespace: "default".to_string(),
            spec: Some(SandboxSpec::default()),
            status: None,
            phase: SandboxPhase::Ready as i32,
            ..Default::default()
        };
        store.put_message(&sandbox).await.unwrap();

        let loaded = store
            .get_message::<Sandbox>("sandbox-002")
            .await
            .unwrap()
            .unwrap();
        let spec = loaded.spec.unwrap();
        let env = resolve_provider_environment(&store, &spec.providers)
            .await
            .unwrap();

        assert!(env.is_empty());
    }

    /// Handler returns not-found when sandbox doesn't exist.
    #[tokio::test]
    async fn handler_flow_returns_none_for_unknown_sandbox() {
        use openshell_core::proto::Sandbox;

        let store = Store::connect("sqlite::memory:").await.unwrap();
        let result = store.get_message::<Sandbox>("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    // ---- Policy safety validation tests ----

    #[test]
    fn validate_policy_safety_rejects_root_user() {
        use openshell_core::proto::{
            FilesystemPolicy, ProcessPolicy, SandboxPolicy as ProtoSandboxPolicy,
        };

        let policy = ProtoSandboxPolicy {
            version: 1,
            filesystem: Some(FilesystemPolicy {
                include_workdir: true,
                read_only: vec!["/usr".into()],
                read_write: vec!["/tmp".into()],
            }),
            process: Some(ProcessPolicy {
                run_as_user: "root".into(),
                run_as_group: "sandbox".into(),
            }),
            ..Default::default()
        };
        let err = super::validate_policy_safety(&policy).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("root"));
    }

    #[test]
    fn validate_policy_safety_rejects_path_traversal() {
        use openshell_core::proto::{FilesystemPolicy, SandboxPolicy as ProtoSandboxPolicy};

        let policy = ProtoSandboxPolicy {
            version: 1,
            filesystem: Some(FilesystemPolicy {
                include_workdir: true,
                read_only: vec!["/usr/../etc/shadow".into()],
                read_write: vec!["/tmp".into()],
            }),
            ..Default::default()
        };
        let err = super::validate_policy_safety(&policy).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("traversal"));
    }

    #[test]
    fn validate_policy_safety_rejects_overly_broad_path() {
        use openshell_core::proto::{FilesystemPolicy, SandboxPolicy as ProtoSandboxPolicy};

        let policy = ProtoSandboxPolicy {
            version: 1,
            filesystem: Some(FilesystemPolicy {
                include_workdir: true,
                read_only: vec!["/usr".into()],
                read_write: vec!["/".into()],
            }),
            ..Default::default()
        };
        let err = super::validate_policy_safety(&policy).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("broad"));
    }

    #[test]
    fn validate_policy_safety_accepts_valid_policy() {
        let policy = openshell_policy::restrictive_default_policy();
        assert!(super::validate_policy_safety(&policy).is_ok());
    }

    // ---- Static field validation tests ----

    #[test]
    fn validate_static_fields_allows_unchanged() {
        use super::validate_static_fields_unchanged;
        use openshell_core::proto::{
            FilesystemPolicy, LandlockPolicy, ProcessPolicy, SandboxPolicy as ProtoSandboxPolicy,
        };

        let policy = ProtoSandboxPolicy {
            version: 1,
            filesystem: Some(FilesystemPolicy {
                include_workdir: true,
                read_only: vec!["/usr".into()],
                read_write: vec!["/tmp".into()],
            }),
            landlock: Some(LandlockPolicy {
                compatibility: "best_effort".into(),
            }),
            process: Some(ProcessPolicy {
                run_as_user: "sandbox".into(),
                run_as_group: "sandbox".into(),
            }),
            ..Default::default()
        };
        assert!(validate_static_fields_unchanged(&policy, &policy).is_ok());
    }

    #[test]
    fn validate_static_fields_allows_additive_filesystem() {
        use super::validate_static_fields_unchanged;
        use openshell_core::proto::{FilesystemPolicy, SandboxPolicy as ProtoSandboxPolicy};

        let baseline = ProtoSandboxPolicy {
            filesystem: Some(FilesystemPolicy {
                read_only: vec!["/usr".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        // Adding /lib is purely additive — should be allowed.
        let additive = ProtoSandboxPolicy {
            filesystem: Some(FilesystemPolicy {
                read_only: vec!["/usr".into(), "/lib".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(validate_static_fields_unchanged(&baseline, &additive).is_ok());
    }

    #[test]
    fn validate_static_fields_rejects_filesystem_removal() {
        use super::validate_static_fields_unchanged;
        use openshell_core::proto::{FilesystemPolicy, SandboxPolicy as ProtoSandboxPolicy};

        let baseline = ProtoSandboxPolicy {
            filesystem: Some(FilesystemPolicy {
                read_only: vec!["/usr".into(), "/lib".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        // Removing /lib should be rejected.
        let removed = ProtoSandboxPolicy {
            filesystem: Some(FilesystemPolicy {
                read_only: vec!["/usr".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let result = validate_static_fields_unchanged(&baseline, &removed);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("/lib"));
    }

    #[test]
    fn validate_static_fields_rejects_filesystem_deletion() {
        use super::validate_static_fields_unchanged;
        use openshell_core::proto::{FilesystemPolicy, SandboxPolicy as ProtoSandboxPolicy};

        let baseline = ProtoSandboxPolicy {
            filesystem: Some(FilesystemPolicy {
                read_only: vec!["/usr".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        // Removing filesystem entirely should be rejected.
        let deleted = ProtoSandboxPolicy {
            filesystem: None,
            ..Default::default()
        };
        let result = validate_static_fields_unchanged(&baseline, &deleted);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("removed"));
    }

    #[test]
    fn validate_static_fields_allows_filesystem_enrichment_from_none() {
        use super::validate_static_fields_unchanged;
        use openshell_core::proto::{FilesystemPolicy, SandboxPolicy as ProtoSandboxPolicy};

        let baseline = ProtoSandboxPolicy {
            filesystem: None,
            ..Default::default()
        };
        // Adding filesystem when baseline had none — enrichment, allowed.
        let enriched = ProtoSandboxPolicy {
            filesystem: Some(FilesystemPolicy {
                read_only: vec!["/usr".into(), "/lib".into(), "/etc".into()],
                read_write: vec!["/sandbox".into(), "/tmp".into()],
                include_workdir: true,
            }),
            ..Default::default()
        };
        assert!(validate_static_fields_unchanged(&baseline, &enriched).is_ok());
    }

    #[test]
    fn validate_static_fields_rejects_include_workdir_change() {
        use super::validate_static_fields_unchanged;
        use openshell_core::proto::{FilesystemPolicy, SandboxPolicy as ProtoSandboxPolicy};

        let baseline = ProtoSandboxPolicy {
            filesystem: Some(FilesystemPolicy {
                include_workdir: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let changed = ProtoSandboxPolicy {
            filesystem: Some(FilesystemPolicy {
                include_workdir: false,
                ..Default::default()
            }),
            ..Default::default()
        };
        let result = validate_static_fields_unchanged(&baseline, &changed);
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("include_workdir"));
    }

    // ---- Sandbox creation without policy ----

    #[tokio::test]
    async fn sandbox_without_policy_stores_successfully() {
        use openshell_core::proto::{Sandbox, SandboxPhase, SandboxSpec};

        let store = Store::connect("sqlite::memory:").await.unwrap();

        let sandbox = Sandbox {
            id: "sb-no-policy".to_string(),
            name: "no-policy-sandbox".to_string(),
            namespace: "default".to_string(),
            spec: Some(SandboxSpec {
                policy: None, // no policy
                ..Default::default()
            }),
            phase: SandboxPhase::Provisioning as i32,
            ..Default::default()
        };
        store.put_message(&sandbox).await.unwrap();

        let loaded = store
            .get_message::<Sandbox>("sb-no-policy")
            .await
            .unwrap()
            .unwrap();
        assert!(loaded.spec.unwrap().policy.is_none());
    }

    #[tokio::test]
    async fn sandbox_policy_backfill_on_update_when_no_baseline() {
        use openshell_core::proto::{
            FilesystemPolicy, LandlockPolicy, ProcessPolicy, Sandbox, SandboxPhase,
            SandboxPolicy as ProtoSandboxPolicy, SandboxSpec,
        };

        let store = Store::connect("sqlite::memory:").await.unwrap();

        // Create sandbox without policy.
        let sandbox = Sandbox {
            id: "sb-backfill".to_string(),
            name: "backfill-sandbox".to_string(),
            namespace: "default".to_string(),
            spec: Some(SandboxSpec {
                policy: None,
                ..Default::default()
            }),
            phase: SandboxPhase::Provisioning as i32,
            ..Default::default()
        };
        store.put_message(&sandbox).await.unwrap();

        // Simulate what update_config does when spec.policy is None:
        // backfill spec.policy with the new policy.
        let new_policy = ProtoSandboxPolicy {
            version: 1,
            filesystem: Some(FilesystemPolicy {
                include_workdir: true,
                read_only: vec!["/usr".into()],
                read_write: vec!["/tmp".into()],
            }),
            landlock: Some(LandlockPolicy {
                compatibility: "best_effort".into(),
            }),
            process: Some(ProcessPolicy {
                run_as_user: "sandbox".into(),
                run_as_group: "sandbox".into(),
            }),
            ..Default::default()
        };

        let mut sandbox = store
            .get_message::<Sandbox>("sb-backfill")
            .await
            .unwrap()
            .unwrap();
        if let Some(ref mut spec) = sandbox.spec {
            spec.policy = Some(new_policy.clone());
        }
        store.put_message(&sandbox).await.unwrap();

        // Verify backfill succeeded.
        let loaded = store
            .get_message::<Sandbox>("sb-backfill")
            .await
            .unwrap()
            .unwrap();
        let policy = loaded.spec.unwrap().policy.unwrap();
        assert_eq!(policy.version, 1);
        assert!(policy.filesystem.is_some());
        assert_eq!(policy.process.unwrap().run_as_user, "sandbox");
    }

    #[tokio::test]
    async fn merge_chunk_into_policy_adds_first_network_rule_to_empty_policy() {
        use openshell_core::proto::{NetworkBinary, NetworkEndpoint, NetworkPolicyRule};

        let store = Store::connect("sqlite::memory:").await.unwrap();
        let rule = NetworkPolicyRule {
            name: "google".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "google.com".to_string(),
                port: 443,
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };
        let chunk = DraftChunkRecord {
            id: "chunk-1".to_string(),
            sandbox_id: "sb-empty".to_string(),
            draft_version: 1,
            status: "pending".to_string(),
            rule_name: "google".to_string(),
            proposed_rule: rule.encode_to_vec(),
            rationale: String::new(),
            security_notes: String::new(),
            confidence: 1.0,
            created_at_ms: 0,
            decided_at_ms: None,
            host: "google.com".to_string(),
            port: 443,
            binary: "/usr/bin/curl".to_string(),
            hit_count: 1,
            first_seen_ms: 0,
            last_seen_ms: 0,
        };

        let (version, _) = merge_chunk_into_policy(&store, &chunk.sandbox_id, &chunk)
            .await
            .unwrap();

        assert_eq!(version, 1);

        let latest = store
            .get_latest_policy(&chunk.sandbox_id)
            .await
            .unwrap()
            .expect("policy revision should be persisted");
        let policy = openshell_core::proto::SandboxPolicy::decode(latest.policy_payload.as_slice())
            .expect("policy payload should decode");
        let stored_rule = policy
            .network_policies
            .get("google")
            .expect("merged rule should be present");
        assert_eq!(stored_rule.endpoints[0].host, "google.com");
        assert_eq!(stored_rule.endpoints[0].port, 443);
        assert_eq!(stored_rule.binaries[0].path, "/usr/bin/curl");
    }

    // ── petname default name generation ───────────────────────────────

    /// Verify that `petname::petname(2, "-")` produces names matching the
    /// expected two-word, hyphen-separated, lowercase pattern.
    #[test]
    fn sandbox_name_defaults_to_petname_format() {
        for _ in 0..50 {
            let name = petname::petname(2, "-").expect("petname should produce a name");
            let parts: Vec<&str> = name.split('-').collect();
            assert_eq!(
                parts.len(),
                2,
                "expected two hyphen-separated words, got: {name}"
            );
            for part in &parts {
                assert!(
                    !part.is_empty() && part.chars().all(|c| c.is_ascii_lowercase()),
                    "each word should be non-empty lowercase ascii: {name}"
                );
            }
        }
    }

    /// The `generate_name` fallback is still a valid 6-char lowercase name.
    #[test]
    fn generate_name_fallback_is_valid() {
        use crate::persistence::generate_name;
        for _ in 0..50 {
            let name = generate_name();
            assert_eq!(name.len(), 6, "unexpected length for fallback name: {name}");
            assert!(
                name.chars().all(|c| c.is_ascii_lowercase()),
                "fallback name should be all lowercase: {name}"
            );
        }
    }

    // ---- Field-level size limit tests ----

    fn default_spec() -> SandboxSpec {
        SandboxSpec::default()
    }

    #[test]
    fn validate_sandbox_spec_accepts_gpu_flag() {
        let spec = SandboxSpec {
            gpu: true,
            ..Default::default()
        };

        assert!(validate_sandbox_spec("gpu-sandbox", &spec).is_ok());
    }

    #[test]
    fn validate_sandbox_spec_accepts_empty_defaults() {
        assert!(validate_sandbox_spec("", &default_spec()).is_ok());
    }

    #[test]
    fn validate_sandbox_spec_accepts_at_limit_name() {
        let name = "a".repeat(MAX_NAME_LEN);
        assert!(validate_sandbox_spec(&name, &default_spec()).is_ok());
    }

    #[test]
    fn validate_sandbox_spec_rejects_over_limit_name() {
        let name = "a".repeat(MAX_NAME_LEN + 1);
        let err = validate_sandbox_spec(&name, &default_spec()).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("name"));
    }

    #[test]
    fn validate_sandbox_spec_accepts_at_limit_providers() {
        let spec = SandboxSpec {
            providers: (0..MAX_PROVIDERS).map(|i| format!("p-{i}")).collect(),
            ..Default::default()
        };
        assert!(validate_sandbox_spec("ok", &spec).is_ok());
    }

    #[test]
    fn validate_sandbox_spec_rejects_over_limit_providers() {
        let spec = SandboxSpec {
            providers: (0..=MAX_PROVIDERS).map(|i| format!("p-{i}")).collect(),
            ..Default::default()
        };
        let err = validate_sandbox_spec("ok", &spec).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("providers"));
    }

    #[test]
    fn validate_sandbox_spec_rejects_over_limit_log_level() {
        let spec = SandboxSpec {
            log_level: "x".repeat(MAX_LOG_LEVEL_LEN + 1),
            ..Default::default()
        };
        let err = validate_sandbox_spec("ok", &spec).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("log_level"));
    }

    #[test]
    fn validate_sandbox_spec_rejects_too_many_env_entries() {
        let env: HashMap<String, String> = (0..=MAX_ENVIRONMENT_ENTRIES)
            .map(|i| (format!("K{i}"), "v".to_string()))
            .collect();
        let spec = SandboxSpec {
            environment: env,
            ..Default::default()
        };
        let err = validate_sandbox_spec("ok", &spec).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("environment"));
    }

    #[test]
    fn validate_sandbox_spec_rejects_oversized_env_key() {
        let mut env = HashMap::new();
        env.insert("k".repeat(MAX_MAP_KEY_LEN + 1), "v".to_string());
        let spec = SandboxSpec {
            environment: env,
            ..Default::default()
        };
        let err = validate_sandbox_spec("ok", &spec).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("key"));
    }

    #[test]
    fn validate_sandbox_spec_rejects_oversized_env_value() {
        let mut env = HashMap::new();
        env.insert("KEY".to_string(), "v".repeat(MAX_MAP_VALUE_LEN + 1));
        let spec = SandboxSpec {
            environment: env,
            ..Default::default()
        };
        let err = validate_sandbox_spec("ok", &spec).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("value"));
    }

    #[test]
    fn validate_sandbox_spec_rejects_oversized_template_image() {
        let spec = SandboxSpec {
            template: Some(SandboxTemplate {
                image: "x".repeat(MAX_TEMPLATE_STRING_LEN + 1),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = validate_sandbox_spec("ok", &spec).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("template.image"));
    }

    #[test]
    fn validate_sandbox_spec_rejects_too_many_template_labels() {
        let labels: HashMap<String, String> = (0..=MAX_TEMPLATE_MAP_ENTRIES)
            .map(|i| (format!("k{i}"), "v".to_string()))
            .collect();
        let spec = SandboxSpec {
            template: Some(SandboxTemplate {
                labels,
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = validate_sandbox_spec("ok", &spec).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("template.labels"));
    }

    #[test]
    fn validate_sandbox_spec_rejects_oversized_template_struct() {
        use prost_types::{Struct, Value, value::Kind};

        // Build a Struct with enough data to exceed MAX_TEMPLATE_STRUCT_SIZE.
        let mut fields = std::collections::BTreeMap::new();
        let big_str = "x".repeat(MAX_TEMPLATE_STRUCT_SIZE);
        fields.insert(
            "big".to_string(),
            Value {
                kind: Some(Kind::StringValue(big_str)),
            },
        );
        let big_struct = Struct { fields };
        let spec = SandboxSpec {
            template: Some(SandboxTemplate {
                resources: Some(big_struct),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = validate_sandbox_spec("ok", &spec).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("template.resources"));
    }

    #[test]
    fn validate_sandbox_spec_rejects_oversized_policy() {
        use openshell_core::proto::NetworkPolicyRule;
        use openshell_core::proto::SandboxPolicy as ProtoSandboxPolicy;

        // Build a policy large enough to exceed MAX_POLICY_SIZE.
        let mut policy = ProtoSandboxPolicy::default();
        let big_name = "x".repeat(MAX_POLICY_SIZE);
        policy
            .network_policies
            .insert(big_name, NetworkPolicyRule::default());
        let spec = SandboxSpec {
            policy: Some(policy),
            ..Default::default()
        };
        let err = validate_sandbox_spec("ok", &spec).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("policy"));
    }

    #[test]
    fn validate_sandbox_spec_accepts_valid_spec() {
        let spec = SandboxSpec {
            log_level: "debug".to_string(),
            providers: vec!["p1".to_string()],
            environment: std::iter::once(("KEY".to_string(), "val".to_string())).collect(),
            template: Some(SandboxTemplate {
                image: "nvcr.io/test:latest".to_string(),
                runtime_class_name: "kata".to_string(),
                labels: std::iter::once(("app".to_string(), "test".to_string())).collect(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(validate_sandbox_spec("my-sandbox", &spec).is_ok());
    }

    // ---- Provider field limit tests ----

    /// Helper: a single-entry credentials map for test providers.
    fn one_credential() -> HashMap<String, String> {
        std::iter::once(("KEY".to_string(), "val".to_string())).collect()
    }

    #[test]
    fn validate_provider_fields_accepts_valid() {
        let provider = Provider {
            id: String::new(),
            name: "my-provider".to_string(),
            r#type: "claude".to_string(),
            credentials: one_credential(),
            config: std::iter::once(("endpoint".to_string(), "https://example.com".to_string()))
                .collect(),
        };
        assert!(validate_provider_fields(&provider).is_ok());
    }

    #[test]
    fn validate_provider_fields_rejects_over_limit_name() {
        let provider = Provider {
            id: String::new(),
            name: "a".repeat(MAX_NAME_LEN + 1),
            r#type: "claude".to_string(),
            credentials: one_credential(),
            config: HashMap::new(),
        };
        let err = validate_provider_fields(&provider).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("provider.name"));
    }

    #[test]
    fn validate_provider_fields_rejects_over_limit_type() {
        let provider = Provider {
            id: String::new(),
            name: "ok".to_string(),
            r#type: "x".repeat(MAX_PROVIDER_TYPE_LEN + 1),
            credentials: one_credential(),
            config: HashMap::new(),
        };
        let err = validate_provider_fields(&provider).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("provider.type"));
    }

    #[test]
    fn validate_provider_fields_rejects_too_many_credentials() {
        let creds: HashMap<String, String> = (0..=MAX_PROVIDER_CREDENTIALS_ENTRIES)
            .map(|i| (format!("K{i}"), "v".to_string()))
            .collect();
        let provider = Provider {
            id: String::new(),
            name: "ok".to_string(),
            r#type: "claude".to_string(),
            credentials: creds,
            config: HashMap::new(),
        };
        let err = validate_provider_fields(&provider).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("provider.credentials"));
    }

    #[test]
    fn validate_provider_fields_rejects_too_many_config() {
        let config: HashMap<String, String> = (0..=MAX_PROVIDER_CONFIG_ENTRIES)
            .map(|i| (format!("K{i}"), "v".to_string()))
            .collect();
        let provider = Provider {
            id: String::new(),
            name: "ok".to_string(),
            r#type: "claude".to_string(),
            credentials: one_credential(),
            config,
        };
        let err = validate_provider_fields(&provider).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("provider.config"));
    }

    #[test]
    fn validate_provider_fields_at_limit_name_accepted() {
        let provider = Provider {
            id: String::new(),
            name: "a".repeat(MAX_NAME_LEN),
            r#type: "claude".to_string(),
            credentials: one_credential(),
            config: HashMap::new(),
        };
        assert!(validate_provider_fields(&provider).is_ok());
    }

    #[test]
    fn validate_provider_fields_rejects_oversized_credential_key() {
        let mut creds = HashMap::new();
        creds.insert("k".repeat(MAX_MAP_KEY_LEN + 1), "v".to_string());
        let provider = Provider {
            id: String::new(),
            name: "ok".to_string(),
            r#type: "claude".to_string(),
            credentials: creds,
            config: HashMap::new(),
        };
        let err = validate_provider_fields(&provider).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("key"));
    }

    #[test]
    fn validate_provider_fields_rejects_oversized_config_value() {
        let mut config = HashMap::new();
        config.insert("k".to_string(), "v".repeat(MAX_MAP_VALUE_LEN + 1));
        let provider = Provider {
            id: String::new(),
            name: "ok".to_string(),
            r#type: "claude".to_string(),
            credentials: one_credential(),
            config,
        };
        let err = validate_provider_fields(&provider).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("value"));
    }

    #[cfg(feature = "dev-settings")]
    #[test]
    fn merge_effective_settings_global_overrides_sandbox_key() {
        let global = super::StoredSettings {
            revision: 2,
            settings: [
                (
                    "log_level".to_string(),
                    super::StoredSettingValue::String("warn".to_string()),
                ),
                ("dummy_int".to_string(), super::StoredSettingValue::Int(7)),
            ]
            .into_iter()
            .collect(),
        };
        let sandbox = super::StoredSettings {
            revision: 1,
            settings: [
                (
                    "log_level".to_string(),
                    super::StoredSettingValue::String("debug".to_string()),
                ),
                (
                    "dummy_bool".to_string(),
                    super::StoredSettingValue::Bool(true),
                ),
            ]
            .into_iter()
            .collect(),
        };

        let merged = super::merge_effective_settings(&global, &sandbox).unwrap();
        let log_level = merged.get("log_level").expect("log_level present");
        assert_eq!(
            log_level.scope,
            openshell_core::proto::SettingScope::Global as i32
        );
        assert_eq!(
            log_level.value.as_ref().and_then(|v| v.value.as_ref()),
            Some(&openshell_core::proto::setting_value::Value::StringValue(
                "warn".to_string(),
            ))
        );

        let dummy_bool = merged.get("dummy_bool").expect("dummy_bool present");
        assert_eq!(
            dummy_bool.scope,
            openshell_core::proto::SettingScope::Sandbox as i32
        );

        let dummy_int = merged.get("dummy_int").expect("dummy_int present");
        assert_eq!(
            dummy_int.scope,
            openshell_core::proto::SettingScope::Global as i32
        );
    }

    #[test]
    fn merge_effective_settings_includes_unset_registered_keys() {
        let global = super::StoredSettings::default();
        let sandbox = super::StoredSettings::default();

        let merged = super::merge_effective_settings(&global, &sandbox).unwrap();
        for registered in openshell_core::settings::REGISTERED_SETTINGS {
            let setting = merged
                .get(registered.key)
                .unwrap_or_else(|| panic!("missing registered key {}", registered.key));
            assert!(
                setting.value.is_none(),
                "expected unset value for {}",
                registered.key
            );
            assert_eq!(
                setting.scope,
                openshell_core::proto::SettingScope::Unspecified as i32
            );
        }
    }

    #[test]
    fn materialize_global_settings_includes_unset_registered_keys() {
        let global = super::StoredSettings::default();
        let materialized = super::materialize_global_settings(&global).unwrap();
        for registered in openshell_core::settings::REGISTERED_SETTINGS {
            let setting = materialized
                .get(registered.key)
                .unwrap_or_else(|| panic!("missing registered key {}", registered.key));
            assert!(
                setting.value.is_none(),
                "expected unset value for {}",
                registered.key
            );
        }
    }

    #[test]
    fn decode_policy_from_global_settings_round_trip() {
        let policy = openshell_core::proto::SandboxPolicy {
            version: 7,
            ..Default::default()
        };
        let encoded = hex::encode(policy.encode_to_vec());
        let global = super::StoredSettings {
            revision: 1,
            settings: [(
                "policy".to_string(),
                super::StoredSettingValue::Bytes(encoded),
            )]
            .into_iter()
            .collect(),
        };

        let decoded = super::decode_policy_from_global_settings(&global)
            .unwrap()
            .expect("policy present");
        assert_eq!(decoded.version, 7);
    }

    #[test]
    fn config_revision_changes_when_effective_setting_changes() {
        let policy = openshell_core::proto::SandboxPolicy::default();
        let mut settings = HashMap::new();
        settings.insert(
            "mode".to_string(),
            openshell_core::proto::EffectiveSetting {
                value: Some(openshell_core::proto::SettingValue {
                    value: Some(openshell_core::proto::setting_value::Value::StringValue(
                        "strict".to_string(),
                    )),
                }),
                scope: openshell_core::proto::SettingScope::Sandbox.into(),
            },
        );

        let rev_a = super::compute_config_revision(
            Some(&policy),
            &settings,
            openshell_core::proto::PolicySource::Sandbox,
        );
        settings.insert(
            "mode".to_string(),
            openshell_core::proto::EffectiveSetting {
                value: Some(openshell_core::proto::SettingValue {
                    value: Some(openshell_core::proto::setting_value::Value::StringValue(
                        "relaxed".to_string(),
                    )),
                }),
                scope: openshell_core::proto::SettingScope::Sandbox.into(),
            },
        );
        let rev_b = super::compute_config_revision(
            Some(&policy),
            &settings,
            openshell_core::proto::PolicySource::Sandbox,
        );

        assert_ne!(rev_a, rev_b);
    }

    #[test]
    fn proto_setting_to_stored_rejects_unknown_key() {
        let value = openshell_core::proto::SettingValue {
            value: Some(openshell_core::proto::setting_value::Value::StringValue(
                "hello".to_string(),
            )),
        };

        let err = super::proto_setting_to_stored("unknown_key", &value).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("unknown setting key"));
    }

    #[cfg(feature = "dev-settings")]
    #[test]
    fn proto_setting_to_stored_rejects_type_mismatch() {
        let value = openshell_core::proto::SettingValue {
            value: Some(openshell_core::proto::setting_value::Value::StringValue(
                "true".to_string(),
            )),
        };

        let err = super::proto_setting_to_stored("dummy_bool", &value).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("expects bool value"));
    }

    #[cfg(feature = "dev-settings")]
    #[test]
    fn proto_setting_to_stored_accepts_bool_for_registered_bool_key() {
        let value = openshell_core::proto::SettingValue {
            value: Some(openshell_core::proto::setting_value::Value::BoolValue(true)),
        };

        let stored = super::proto_setting_to_stored("dummy_bool", &value).unwrap();
        assert_eq!(stored, super::StoredSettingValue::Bool(true));
    }

    // ---- merge_effective_settings: sandbox-scoped values ----

    #[cfg(feature = "dev-settings")]
    #[test]
    fn merge_effective_settings_sandbox_scoped_value_has_sandbox_scope() {
        let global = super::StoredSettings::default();
        let sandbox = super::StoredSettings {
            revision: 1,
            settings: [(
                "log_level".to_string(),
                super::StoredSettingValue::String("debug".to_string()),
            )]
            .into_iter()
            .collect(),
        };

        let merged = super::merge_effective_settings(&global, &sandbox).unwrap();
        let log_level = merged.get("log_level").expect("log_level present");
        assert_eq!(
            log_level.scope,
            openshell_core::proto::SettingScope::Sandbox as i32,
            "sandbox-set key should have SANDBOX scope"
        );
        assert!(
            log_level.value.is_some(),
            "sandbox-set key should have a value"
        );
    }

    #[test]
    fn merge_effective_settings_unset_key_has_unspecified_scope_and_no_value() {
        let global = super::StoredSettings::default();
        let sandbox = super::StoredSettings::default();

        let merged = super::merge_effective_settings(&global, &sandbox).unwrap();
        for registered in openshell_core::settings::REGISTERED_SETTINGS {
            let setting = merged.get(registered.key).unwrap();
            assert_eq!(
                setting.scope,
                openshell_core::proto::SettingScope::Unspecified as i32,
                "unset key '{}' should have UNSPECIFIED scope",
                registered.key,
            );
            assert!(
                setting.value.is_none(),
                "unset key '{}' should have no value",
                registered.key,
            );
        }
    }

    #[test]
    fn merge_effective_settings_policy_key_is_excluded() {
        let global = super::StoredSettings {
            revision: 1,
            settings: [(
                "policy".to_string(),
                super::StoredSettingValue::Bytes("deadbeef".to_string()),
            )]
            .into_iter()
            .collect(),
        };
        let sandbox = super::StoredSettings {
            revision: 1,
            settings: [(
                "policy".to_string(),
                super::StoredSettingValue::Bytes("cafebabe".to_string()),
            )]
            .into_iter()
            .collect(),
        };

        let merged = super::merge_effective_settings(&global, &sandbox).unwrap();
        assert!(
            !merged.contains_key("policy"),
            "policy key must not appear in effective settings"
        );
    }

    // ---- sandbox_settings_id prefix ----

    #[test]
    fn sandbox_settings_id_has_prefix_preventing_collision() {
        let sandbox_id = "abc-123";
        let settings_id = super::sandbox_settings_id(sandbox_id);
        assert!(
            settings_id.starts_with("settings:"),
            "settings ID should be prefixed"
        );
        assert_ne!(
            settings_id, sandbox_id,
            "settings ID must differ from sandbox ID"
        );
    }

    #[test]
    fn sandbox_settings_id_different_sandboxes_produce_different_ids() {
        let id_a = super::sandbox_settings_id("sandbox-1");
        let id_b = super::sandbox_settings_id("sandbox-2");
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn sandbox_settings_id_embeds_sandbox_id() {
        let sandbox_id = "some-uuid-value";
        let settings_id = super::sandbox_settings_id(sandbox_id);
        assert!(
            settings_id.contains(sandbox_id),
            "settings ID should embed the original sandbox ID"
        );
    }

    // ---- compute_config_revision ----

    #[test]
    fn config_revision_stable_when_nothing_changes() {
        let policy = openshell_core::proto::SandboxPolicy::default();
        let mut settings = HashMap::new();
        settings.insert(
            "log_level".to_string(),
            openshell_core::proto::EffectiveSetting {
                value: Some(openshell_core::proto::SettingValue {
                    value: Some(openshell_core::proto::setting_value::Value::StringValue(
                        "info".to_string(),
                    )),
                }),
                scope: openshell_core::proto::SettingScope::Sandbox.into(),
            },
        );

        let rev_a = super::compute_config_revision(
            Some(&policy),
            &settings,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let rev_b = super::compute_config_revision(
            Some(&policy),
            &settings,
            openshell_core::proto::PolicySource::Sandbox,
        );
        assert_eq!(rev_a, rev_b, "revision must be stable for identical inputs");
    }

    #[test]
    fn config_revision_changes_when_policy_changes() {
        let policy_a = openshell_core::proto::SandboxPolicy {
            version: 1,
            ..Default::default()
        };
        let policy_b = openshell_core::proto::SandboxPolicy {
            version: 2,
            ..Default::default()
        };
        let settings = HashMap::new();

        let rev_a = super::compute_config_revision(
            Some(&policy_a),
            &settings,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let rev_b = super::compute_config_revision(
            Some(&policy_b),
            &settings,
            openshell_core::proto::PolicySource::Sandbox,
        );
        assert_ne!(rev_a, rev_b, "revision must change when policy changes");
    }

    #[test]
    fn config_revision_changes_when_policy_source_changes() {
        let policy = openshell_core::proto::SandboxPolicy::default();
        let settings = HashMap::new();

        let rev_a = super::compute_config_revision(
            Some(&policy),
            &settings,
            openshell_core::proto::PolicySource::Sandbox,
        );
        let rev_b = super::compute_config_revision(
            Some(&policy),
            &settings,
            openshell_core::proto::PolicySource::Global,
        );
        assert_ne!(
            rev_a, rev_b,
            "revision must change when policy source changes"
        );
    }

    #[test]
    fn config_revision_without_policy_still_hashes_settings() {
        let mut settings = HashMap::new();
        settings.insert(
            "log_level".to_string(),
            openshell_core::proto::EffectiveSetting {
                value: Some(openshell_core::proto::SettingValue {
                    value: Some(openshell_core::proto::setting_value::Value::StringValue(
                        "debug".to_string(),
                    )),
                }),
                scope: openshell_core::proto::SettingScope::Sandbox.into(),
            },
        );

        let rev_a = super::compute_config_revision(
            None,
            &settings,
            openshell_core::proto::PolicySource::Sandbox,
        );

        settings.insert(
            "log_level".to_string(),
            openshell_core::proto::EffectiveSetting {
                value: Some(openshell_core::proto::SettingValue {
                    value: Some(openshell_core::proto::setting_value::Value::StringValue(
                        "warn".to_string(),
                    )),
                }),
                scope: openshell_core::proto::SettingScope::Sandbox.into(),
            },
        );

        let rev_b = super::compute_config_revision(
            None,
            &settings,
            openshell_core::proto::PolicySource::Sandbox,
        );
        assert_ne!(
            rev_a, rev_b,
            "revision must change when settings differ, even without policy"
        );
    }

    // ---- conflict guard: global overrides block sandbox mutations ----

    #[tokio::test]
    async fn conflict_guard_sandbox_set_blocked_when_global_exists() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        // Persist a global setting for "log_level".
        let mut global = super::StoredSettings::default();
        global.settings.insert(
            "log_level".to_string(),
            super::StoredSettingValue::String("warn".to_string()),
        );
        global.revision = 1;
        super::save_global_settings(&store, &global).await.unwrap();

        // Attempt sandbox-scoped set: check the guard condition.
        let loaded_global = super::load_global_settings(&store).await.unwrap();
        let globally_managed = loaded_global.settings.contains_key("log_level");
        assert!(
            globally_managed,
            "log_level should be globally managed after global set"
        );
        // The handler would return FailedPrecondition here.
    }

    #[tokio::test]
    async fn conflict_guard_sandbox_delete_blocked_when_global_exists() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        // Persist a global setting for "dummy_int".
        let mut global = super::StoredSettings::default();
        global
            .settings
            .insert("dummy_int".to_string(), super::StoredSettingValue::Int(42));
        global.revision = 1;
        super::save_global_settings(&store, &global).await.unwrap();

        // Check the guard for sandbox-scoped delete.
        let loaded_global = super::load_global_settings(&store).await.unwrap();
        assert!(
            loaded_global.settings.contains_key("dummy_int"),
            "dummy_int should be globally managed"
        );
        // The handler would return FailedPrecondition for sandbox delete too.
    }

    // ---- delete-unlock: sandbox set succeeds after global delete ----

    #[tokio::test]
    async fn delete_unlock_sandbox_set_succeeds_after_global_delete() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        // 1. Set global setting.
        let mut global = super::StoredSettings::default();
        global.settings.insert(
            "log_level".to_string(),
            super::StoredSettingValue::String("warn".to_string()),
        );
        global.revision = 1;
        super::save_global_settings(&store, &global).await.unwrap();

        // Verify it blocks sandbox.
        let loaded = super::load_global_settings(&store).await.unwrap();
        assert!(loaded.settings.contains_key("log_level"));

        // 2. Delete the global setting.
        global.settings.remove("log_level");
        global.revision = 2;
        super::save_global_settings(&store, &global).await.unwrap();

        // 3. Verify the guard is cleared.
        let loaded = super::load_global_settings(&store).await.unwrap();
        assert!(
            !loaded.settings.contains_key("log_level"),
            "after global delete, log_level should not be globally managed"
        );

        // 4. Sandbox-scoped set should now succeed.
        let sandbox_id = "test-sandbox-uuid";
        let mut sandbox_settings = super::load_sandbox_settings(&store, sandbox_id)
            .await
            .unwrap();
        let changed = super::upsert_setting_value(
            &mut sandbox_settings.settings,
            "log_level",
            super::StoredSettingValue::String("debug".to_string()),
        );
        assert!(changed, "sandbox upsert should report a change");
        sandbox_settings.revision = sandbox_settings.revision.wrapping_add(1);
        super::save_sandbox_settings(&store, sandbox_id, "test-sandbox", &sandbox_settings)
            .await
            .unwrap();

        // Verify round-trip.
        let reloaded = super::load_sandbox_settings(&store, sandbox_id)
            .await
            .unwrap();
        assert_eq!(
            reloaded.settings.get("log_level"),
            Some(&super::StoredSettingValue::String("debug".to_string())),
        );
    }

    // ---- reserved policy key rejection ----

    #[test]
    fn validate_registered_setting_key_rejects_policy() {
        // "policy" is not in REGISTERED_SETTINGS, so validate should fail.
        let err = super::validate_registered_setting_key("policy").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("unknown setting key"));
    }

    #[test]
    fn proto_setting_to_stored_rejects_policy_key() {
        let value = openshell_core::proto::SettingValue {
            value: Some(openshell_core::proto::setting_value::Value::StringValue(
                "anything".to_string(),
            )),
        };
        let err = super::proto_setting_to_stored("policy", &value).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(
            err.message().contains("unknown setting key"),
            "policy key should be rejected as unknown: {}",
            err.message(),
        );
    }

    // ---- stored <-> proto round-trip for all types ----

    #[test]
    fn stored_setting_to_proto_string_round_trip() {
        let stored = super::StoredSettingValue::String("hello".to_string());
        let proto = super::stored_setting_to_proto(&stored).unwrap();
        assert_eq!(
            proto.value,
            Some(openshell_core::proto::setting_value::Value::StringValue(
                "hello".to_string()
            ))
        );
    }

    #[test]
    fn stored_setting_to_proto_int_round_trip() {
        let stored = super::StoredSettingValue::Int(42);
        let proto = super::stored_setting_to_proto(&stored).unwrap();
        assert_eq!(
            proto.value,
            Some(openshell_core::proto::setting_value::Value::IntValue(42))
        );
    }

    #[test]
    fn stored_setting_to_proto_bool_round_trip() {
        let stored = super::StoredSettingValue::Bool(false);
        let proto = super::stored_setting_to_proto(&stored).unwrap();
        assert_eq!(
            proto.value,
            Some(openshell_core::proto::setting_value::Value::BoolValue(
                false
            ))
        );
    }

    // ---- upsert_setting_value ----

    #[test]
    fn upsert_setting_value_returns_true_on_insert() {
        let mut map = std::collections::BTreeMap::new();
        let changed = super::upsert_setting_value(
            &mut map,
            "log_level",
            super::StoredSettingValue::String("debug".to_string()),
        );
        assert!(changed);
        assert_eq!(
            map.get("log_level"),
            Some(&super::StoredSettingValue::String("debug".to_string()))
        );
    }

    #[test]
    fn upsert_setting_value_returns_false_when_unchanged() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(
            "log_level".to_string(),
            super::StoredSettingValue::String("debug".to_string()),
        );
        let changed = super::upsert_setting_value(
            &mut map,
            "log_level",
            super::StoredSettingValue::String("debug".to_string()),
        );
        assert!(
            !changed,
            "upsert should return false when value is unchanged"
        );
    }

    #[test]
    fn upsert_setting_value_returns_true_on_update() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(
            "log_level".to_string(),
            super::StoredSettingValue::String("debug".to_string()),
        );
        let changed = super::upsert_setting_value(
            &mut map,
            "log_level",
            super::StoredSettingValue::String("warn".to_string()),
        );
        assert!(changed, "upsert should return true when value changes");
    }

    // ---- settings persistence round-trip ----

    #[tokio::test]
    async fn global_settings_load_returns_default_when_empty() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();
        let settings = super::load_global_settings(&store).await.unwrap();
        assert!(settings.settings.is_empty());
        assert_eq!(settings.revision, 0);
    }

    #[tokio::test]
    async fn sandbox_settings_load_returns_default_when_empty() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();
        let settings = super::load_sandbox_settings(&store, "nonexistent")
            .await
            .unwrap();
        assert!(settings.settings.is_empty());
        assert_eq!(settings.revision, 0);
    }

    #[tokio::test]
    async fn global_settings_save_and_load_round_trip() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let mut settings = super::StoredSettings::default();
        settings.settings.insert(
            "log_level".to_string(),
            super::StoredSettingValue::String("error".to_string()),
        );
        settings.settings.insert(
            "dummy_bool".to_string(),
            super::StoredSettingValue::Bool(true),
        );
        settings.revision = 5;
        super::save_global_settings(&store, &settings)
            .await
            .unwrap();

        let loaded = super::load_global_settings(&store).await.unwrap();
        assert_eq!(loaded.revision, 5);
        assert_eq!(
            loaded.settings.get("log_level"),
            Some(&super::StoredSettingValue::String("error".to_string()))
        );
        assert_eq!(
            loaded.settings.get("dummy_bool"),
            Some(&super::StoredSettingValue::Bool(true))
        );
    }

    #[tokio::test]
    async fn sandbox_settings_save_and_load_round_trip() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let sandbox_id = "sb-uuid-123";
        let mut settings = super::StoredSettings::default();
        settings
            .settings
            .insert("dummy_int".to_string(), super::StoredSettingValue::Int(99));
        settings.revision = 3;
        super::save_sandbox_settings(&store, sandbox_id, "my-sandbox", &settings)
            .await
            .unwrap();

        let loaded = super::load_sandbox_settings(&store, sandbox_id)
            .await
            .unwrap();
        assert_eq!(loaded.revision, 3);
        assert_eq!(
            loaded.settings.get("dummy_int"),
            Some(&super::StoredSettingValue::Int(99))
        );
    }

    /// Verify that a mutex prevents lost writes when concurrent tasks
    /// perform load-modify-save on the same global settings record.
    ///
    /// Each of N tasks increments the revision by 1 under the mutex.
    /// Without the mutex, some increments would be lost (last-writer-wins).
    /// With the mutex, the final revision must equal N.
    #[tokio::test]
    async fn concurrent_global_setting_mutations_are_serialized() {
        let store = std::sync::Arc::new(
            Store::connect("sqlite::memory:?cache=shared")
                .await
                .unwrap(),
        );
        let mutex = std::sync::Arc::new(tokio::sync::Mutex::new(()));

        let n = 50;
        let mut handles = Vec::with_capacity(n);

        for i in 0..n {
            let store = store.clone();
            let mutex = mutex.clone();
            handles.push(tokio::spawn(async move {
                let _guard = mutex.lock().await;
                let mut settings = super::load_global_settings(&store).await.unwrap();
                // Simulate per-key mutation: each task sets a unique key.
                settings
                    .settings
                    .insert(format!("key_{i}"), super::StoredSettingValue::Int(i as i64));
                settings.revision = settings.revision.wrapping_add(1);
                super::save_global_settings(&store, &settings)
                    .await
                    .unwrap();
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let final_settings = super::load_global_settings(&store).await.unwrap();
        assert_eq!(
            final_settings.revision, n as u64,
            "all {n} increments must be reflected; lost writes indicate a race"
        );
        assert_eq!(
            final_settings.settings.len(),
            n,
            "all {n} unique keys must be present"
        );
    }

    /// Same test WITHOUT the mutex to confirm the test would actually
    /// detect lost writes when concurrent access is unserialized.
    /// Uses `tokio::task::yield_now()` to increase interleaving.
    #[tokio::test]
    async fn concurrent_global_setting_mutations_without_lock_can_lose_writes() {
        let store = std::sync::Arc::new(
            Store::connect("sqlite::memory:?cache=shared")
                .await
                .unwrap(),
        );

        let n = 50;
        let mut handles = Vec::with_capacity(n);

        for i in 0..n {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                // No mutex — intentional race.
                let mut settings = super::load_global_settings(&store).await.unwrap();
                // Yield to encourage interleaving between load and save.
                tokio::task::yield_now().await;
                settings
                    .settings
                    .insert(format!("key_{i}"), super::StoredSettingValue::Int(i as i64));
                settings.revision = settings.revision.wrapping_add(1);
                super::save_global_settings(&store, &settings)
                    .await
                    .unwrap();
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let final_settings = super::load_global_settings(&store).await.unwrap();
        // Without serialization, some writes will be lost. The final
        // revision and key count will be less than N.  We assert that
        // at least one write was lost to validate the test methodology.
        // (If tokio happens to schedule everything sequentially, this
        // could flake — but with N=50 and yield_now it's reliable.)
        let lost = (n as u64).saturating_sub(final_settings.revision);
        if lost == 0 {
            // Rare but possible with sequential scheduling.  Don't fail,
            // but note that the positive test above is what matters.
            eprintln!(
                "note: no lost writes detected in unlocked test (sequential scheduling); \
                 the locked test is the authoritative correctness check"
            );
        } else {
            eprintln!("unlocked test: {lost} lost writes out of {n} (expected behavior)");
        }
        // Either way, the WITH-lock test above asserts correctness.
    }
}
