// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! gRPC service implementation.

#![allow(clippy::ignored_unit_patterns)] // Tokio select! macro generates unit patterns

use crate::persistence::{ObjectId, ObjectName, ObjectType, PolicyRecord, generate_name};
use futures::future;
use navigator_core::proto::{
    CreateProviderRequest, CreateSandboxRequest, CreateSshSessionRequest, CreateSshSessionResponse,
    DeleteProviderRequest, DeleteProviderResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    ExecSandboxEvent, ExecSandboxExit, ExecSandboxRequest, ExecSandboxStderr, ExecSandboxStdout,
    GetProviderRequest, GetSandboxLogsRequest, GetSandboxLogsResponse, GetSandboxPolicyRequest,
    GetSandboxPolicyResponse, GetSandboxPolicyStatusRequest, GetSandboxPolicyStatusResponse,
    GetSandboxProviderEnvironmentRequest, GetSandboxProviderEnvironmentResponse, GetSandboxRequest,
    HealthRequest, HealthResponse, ListProvidersRequest, ListProvidersResponse,
    ListSandboxPoliciesRequest, ListSandboxPoliciesResponse, ListSandboxesRequest,
    ListSandboxesResponse, PolicyStatus, Provider, ProviderResponse, PushSandboxLogsRequest,
    PushSandboxLogsResponse, ReportPolicyStatusRequest, ReportPolicyStatusResponse,
    RevokeSshSessionRequest, RevokeSshSessionResponse, SandboxLogLine, SandboxPolicyRevision,
    SandboxResponse, SandboxStreamEvent, ServiceStatus, SshSession, UpdateProviderRequest,
    UpdateSandboxPolicyRequest, UpdateSandboxPolicyResponse, WatchSandboxRequest,
    navigator_server::Navigator,
};
use navigator_core::proto::{
    Sandbox, SandboxPhase, SandboxPolicy as ProtoSandboxPolicy, SandboxTemplate,
};
use prost::Message;
use sha2::{Digest, Sha256};
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
pub(crate) const MAX_PAGE_SIZE: u32 = 1000;

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

/// Maximum serialized size (bytes) for template Struct fields (`resources`, `pod_template`,
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

/// Clamp a client-provided page `limit`.
///
/// Returns `default` when `raw` is 0 (the protobuf zero-value convention),
/// otherwise returns the smaller of `raw` and `max`.
pub(crate) fn clamp_limit(raw: u32, default: u32, max: u32) -> u32 {
    if raw == 0 { default } else { raw.min(max) }
}

/// Navigator gRPC service implementation.
#[derive(Debug, Clone)]
pub struct NavigatorService {
    state: Arc<ServerState>,
}

impl NavigatorService {
    /// Create a new Navigator service.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl Navigator for NavigatorService {
    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: ServiceStatus::Healthy.into(),
            version: env!("CARGO_PKG_VERSION").to_string(),
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

        // Validate policy safety before persisting.
        if let Some(ref policy) = spec.policy {
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
                                navigator_core::proto::sandbox_stream_event::Payload::Sandbox(
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
                    if let Some(navigator_core::proto::sandbox_stream_event::Payload::Log(
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
                                        if tx.send(Ok(SandboxStreamEvent { payload: Some(navigator_core::proto::sandbox_stream_event::Payload::Sandbox(sandbox.clone()))})).await.is_err() {
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
                                if let Some(navigator_core::proto::sandbox_stream_event::Payload::Log(ref log)) = evt.payload {
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
                if let Ok(session) = SshSession::decode(record.payload.as_slice()) {
                    if session.sandbox_id == id {
                        if let Err(e) = self
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
            }
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

    async fn get_sandbox_policy(
        &self,
        request: Request<GetSandboxPolicyRequest>,
    ) -> Result<Response<GetSandboxPolicyResponse>, Status> {
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

        if let Some(record) = latest {
            let policy = ProtoSandboxPolicy::decode(record.policy_payload.as_slice())
                .map_err(|e| Status::internal(format!("decode policy failed: {e}")))?;
            debug!(
                sandbox_id = %sandbox_id,
                version = record.version,
                "GetSandboxPolicy served from policy history"
            );
            return Ok(Response::new(GetSandboxPolicyResponse {
                policy: Some(policy),
                version: u32::try_from(record.version).unwrap_or(0),
                policy_hash: record.policy_hash,
            }));
        }

        // Lazy backfill: no policy history exists yet.
        let spec = sandbox
            .spec
            .ok_or_else(|| Status::internal("sandbox has no spec"))?;

        // If spec.policy is None, the sandbox was created without a policy.
        // Return an empty response so the sandbox can discover policy from disk
        // or fall back to its restrictive default.
        let Some(policy) = spec.policy else {
            debug!(
                sandbox_id = %sandbox_id,
                "GetSandboxPolicy: no policy configured, returning empty response"
            );
            return Ok(Response::new(GetSandboxPolicyResponse {
                policy: None,
                version: 0,
                policy_hash: String::new(),
            }));
        };

        // Create version 1 from spec.policy.
        let payload = policy.encode_to_vec();
        let hash = deterministic_policy_hash(&policy);
        let policy_id = uuid::Uuid::new_v4().to_string();

        // Best-effort backfill: if it fails (e.g., concurrent backfill race), we still
        // return the policy from spec.
        if let Err(e) = self
            .state
            .store
            .put_policy_revision(&policy_id, &sandbox_id, 1, &payload, &hash)
            .await
        {
            warn!(sandbox_id = %sandbox_id, error = %e, "Failed to backfill policy version 1");
        } else if let Err(e) = self
            .state
            .store
            .update_policy_status(&sandbox_id, 1, "loaded", None, None)
            .await
        {
            warn!(sandbox_id = %sandbox_id, error = %e, "Failed to mark backfilled policy as loaded");
        }

        info!(
            sandbox_id = %sandbox_id,
            "GetSandboxPolicy served from spec (backfilled version 1)"
        );

        Ok(Response::new(GetSandboxPolicyResponse {
            policy: Some(policy),
            version: 1,
            policy_hash: hash,
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
        let command_str = build_remote_exec_command(&req);
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

    async fn update_sandbox_policy(
        &self,
        request: Request<UpdateSandboxPolicyRequest>,
    ) -> Result<Response<UpdateSandboxPolicyResponse>, Status> {
        let req = request.into_inner();
        if req.name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }
        let new_policy = req
            .policy
            .ok_or_else(|| Status::invalid_argument("policy is required"))?;

        // Resolve sandbox by name.
        let sandbox = self
            .state
            .store
            .get_message_by_name::<Sandbox>(&req.name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;

        let sandbox_id = sandbox.id.clone();

        // Get the baseline (version 1) policy for static field validation.
        let spec = sandbox
            .spec
            .as_ref()
            .ok_or_else(|| Status::internal("sandbox has no spec"))?;

        if let Some(baseline_policy) = spec.policy.as_ref() {
            // Validate static fields haven't changed.
            validate_static_fields_unchanged(baseline_policy, &new_policy)?;

            // Validate network mode hasn't changed (Block ↔ Proxy).
            validate_network_mode_unchanged(baseline_policy, &new_policy)?;

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
                "UpdateSandboxPolicy: backfilled spec.policy from sandbox-discovered policy"
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

        if let Some(ref current) = latest {
            if current.policy_hash == hash {
                return Ok(Response::new(UpdateSandboxPolicyResponse {
                    version: u32::try_from(current.version).unwrap_or(0),
                    policy_hash: hash,
                }));
            }
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
            "UpdateSandboxPolicy: new policy version persisted"
        );

        Ok(Response::new(UpdateSandboxPolicyResponse {
            version: u32::try_from(next_version).unwrap_or(0),
            policy_hash: hash,
        }))
    }

    async fn get_sandbox_policy_status(
        &self,
        request: Request<GetSandboxPolicyStatusRequest>,
    ) -> Result<Response<GetSandboxPolicyStatusResponse>, Status> {
        let req = request.into_inner();
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

        let sandbox_id = sandbox.id;

        let record = if req.version == 0 {
            self.state
                .store
                .get_latest_policy(&sandbox_id)
                .await
                .map_err(|e| Status::internal(format!("fetch policy failed: {e}")))?
        } else {
            self.state
                .store
                .get_policy_by_version(&sandbox_id, i64::from(req.version))
                .await
                .map_err(|e| Status::internal(format!("fetch policy failed: {e}")))?
        };

        let record =
            record.ok_or_else(|| Status::not_found("no policy revision found for this sandbox"))?;

        let active_version = sandbox.current_policy_version;

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

        let limit = clamp_limit(req.limit, 50, MAX_PAGE_SIZE);
        let records = self
            .state
            .store
            .list_policies(&sandbox.id, limit, req.offset)
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
                if let Some(navigator_core::proto::sandbox_stream_event::Payload::Log(log)) =
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
    spec: &navigator_core::proto::SandboxSpec,
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
    if let Some(ref s) = tmpl.pod_template {
        let size = s.encoded_len();
        if size > MAX_TEMPLATE_STRUCT_SIZE {
            return Err(Status::invalid_argument(format!(
                "template.pod_template serialized size exceeds maximum ({size} > {MAX_TEMPLATE_STRUCT_SIZE})"
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
/// Delegates to [`navigator_policy::validate_sandbox_policy`] and converts
/// violations into a gRPC `INVALID_ARGUMENT` status.
fn validate_policy_safety(policy: &ProtoSandboxPolicy) -> Result<(), Status> {
    if let Err(violations) = navigator_policy::validate_sandbox_policy(policy) {
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
    baseline: Option<&navigator_core::proto::FilesystemPolicy>,
    new: Option<&navigator_core::proto::FilesystemPolicy>,
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

/// Validate that network mode hasn't changed (Block ↔ Proxy).
/// Adding network_policies when none existed (or removing all) changes the mode.
fn validate_network_mode_unchanged(
    baseline: &ProtoSandboxPolicy,
    new: &ProtoSandboxPolicy,
) -> Result<(), Status> {
    let baseline_has_policies = !baseline.network_policies.is_empty();
    let new_has_policies = !new.network_policies.is_empty();
    if baseline_has_policies != new_has_policies {
        let msg = if new_has_policies {
            "cannot add network policies to a sandbox created without them (Block → Proxy mode change requires restart)"
        } else {
            "cannot remove all network policies from a sandbox created with them (Proxy → Block mode change requires restart)"
        };
        return Err(Status::invalid_argument(msg));
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

fn resolve_gateway(config: &navigator_core::Config) -> (String, u16) {
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

fn shell_escape(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    let safe = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b'-' | b'_'));
    if safe {
        return value.to_string();
    }
    let escaped = value.replace('\'', "'\"'\"'");
    format!("'{escaped}'")
}

fn build_remote_exec_command(req: &ExecSandboxRequest) -> String {
    let mut parts = Vec::new();
    let mut env_entries = req.environment.iter().collect::<Vec<_>>();
    env_entries.sort_by(|(a, _), (b, _)| a.cmp(b));
    for (key, value) in env_entries {
        parts.push(format!("{key}={}", shell_escape(value)));
    }
    parts.extend(req.command.iter().map(|arg| shell_escape(arg)));
    let command = parts.join(" ");
    if req.workdir.is_empty() {
        command
    } else {
        format!("cd {} && {command}", shell_escape(&req.workdir))
    }
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
    info!(
        sandbox_id = %sandbox_id,
        target_host = %target_host,
        target_port,
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
                        payload: Some(navigator_core::proto::exec_sandbox_event::Payload::Exit(
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
            payload: Some(navigator_core::proto::exec_sandbox_event::Payload::Exit(
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
                        payload: Some(navigator_core::proto::exec_sandbox_event::Payload::Stdout(
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
                        payload: Some(navigator_core::proto::exec_sandbox_event::Payload::Stderr(
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
        let Ok(mut sandbox_conn) = TcpStream::connect((target_host.as_str(), target_port)).await
        else {
            warn!(target_host = %target_host, target_port, "SSH proxy: failed to connect to sandbox");
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

    Ok(provider)
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
        providers.push(provider);
    }

    Ok(providers)
}

async fn update_provider_record(
    store: &crate::persistence::Store,
    provider: Provider,
) -> Result<Provider, Status> {
    if provider.name.is_empty() {
        return Err(Status::invalid_argument("provider.name is required"));
    }
    if provider.r#type.trim().is_empty() {
        return Err(Status::invalid_argument("provider.type is required"));
    }

    let existing = store
        .get_message_by_name::<Provider>(&provider.name)
        .await
        .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?;

    let Some(existing) = existing else {
        return Err(Status::not_found("provider not found"));
    };

    let updated = Provider {
        id: existing.id,
        name: existing.name,
        r#type: provider.r#type,
        credentials: provider.credentials,
        config: provider.config,
    };

    store
        .put_message(&updated)
        .await
        .map_err(|e| Status::internal(format!("persist provider failed: {e}")))?;

    Ok(updated)
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
        MAX_TEMPLATE_MAP_ENTRIES, MAX_TEMPLATE_STRING_LEN, MAX_TEMPLATE_STRUCT_SIZE, clamp_limit,
        create_provider_record, delete_provider_record, get_provider_record, is_valid_env_key,
        list_provider_records, resolve_provider_environment, update_provider_record,
        validate_provider_fields, validate_sandbox_spec,
    };
    use crate::persistence::Store;
    use navigator_core::proto::{Provider, SandboxSpec, SandboxTemplate};
    use std::collections::HashMap;
    use tonic::Code;

    #[test]
    fn env_key_validation_accepts_valid_keys() {
        assert!(is_valid_env_key("PATH"));
        assert!(is_valid_env_key("PYTHONPATH"));
        assert!(is_valid_env_key("_NAVIGATOR_VALUE_1"));
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
        assert_eq!(
            updated.credentials.get("API_TOKEN"),
            Some(&"rotated-token".to_string())
        );

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
                r#type: "gitlab".to_string(),
                credentials: HashMap::new(),
                config: HashMap::new(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(update_missing_err.code(), Code::NotFound);
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
        use navigator_core::proto::{Sandbox, SandboxPhase, SandboxSpec};

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
        use navigator_core::proto::{Sandbox, SandboxPhase, SandboxSpec};

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
        use navigator_core::proto::Sandbox;

        let store = Store::connect("sqlite::memory:").await.unwrap();
        let result = store.get_message::<Sandbox>("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    // ---- Policy safety validation tests ----

    #[test]
    fn validate_policy_safety_rejects_root_user() {
        use navigator_core::proto::{
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
        use navigator_core::proto::{FilesystemPolicy, SandboxPolicy as ProtoSandboxPolicy};

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
        use navigator_core::proto::{FilesystemPolicy, SandboxPolicy as ProtoSandboxPolicy};

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
        let policy = navigator_policy::restrictive_default_policy();
        assert!(super::validate_policy_safety(&policy).is_ok());
    }

    // ---- Static field validation tests ----

    #[test]
    fn validate_static_fields_allows_unchanged() {
        use super::{validate_network_mode_unchanged, validate_static_fields_unchanged};
        use navigator_core::proto::{
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
        assert!(validate_network_mode_unchanged(&policy, &policy).is_ok());
    }

    #[test]
    fn validate_static_fields_allows_additive_filesystem() {
        use super::validate_static_fields_unchanged;
        use navigator_core::proto::{FilesystemPolicy, SandboxPolicy as ProtoSandboxPolicy};

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
        use navigator_core::proto::{FilesystemPolicy, SandboxPolicy as ProtoSandboxPolicy};

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
        use navigator_core::proto::{FilesystemPolicy, SandboxPolicy as ProtoSandboxPolicy};

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
        use navigator_core::proto::{FilesystemPolicy, SandboxPolicy as ProtoSandboxPolicy};

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
        use navigator_core::proto::{FilesystemPolicy, SandboxPolicy as ProtoSandboxPolicy};

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

    #[test]
    fn validate_network_mode_rejects_block_to_proxy() {
        use super::validate_network_mode_unchanged;
        use navigator_core::proto::{NetworkPolicyRule, SandboxPolicy as ProtoSandboxPolicy};

        let baseline = ProtoSandboxPolicy::default(); // no network policies = Block
        let mut changed = ProtoSandboxPolicy::default();
        changed.network_policies.insert(
            "test".into(),
            NetworkPolicyRule {
                name: "test".into(),
                ..Default::default()
            },
        );
        assert!(validate_network_mode_unchanged(&baseline, &changed).is_err());
    }

    // ---- Sandbox creation without policy ----

    #[tokio::test]
    async fn sandbox_without_policy_stores_successfully() {
        use navigator_core::proto::{Sandbox, SandboxPhase, SandboxSpec};

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
        use navigator_core::proto::{
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

        // Simulate what update_sandbox_policy does when spec.policy is None:
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
        use navigator_core::proto::NetworkPolicyRule;
        use navigator_core::proto::SandboxPolicy as ProtoSandboxPolicy;

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
}
