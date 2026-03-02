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
        if spec.policy.is_none() {
            return Err(Status::invalid_argument("spec.policy is required"));
        }

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

        let id = uuid::Uuid::new_v4().to_string();
        let name = if request.name.is_empty() {
            format!("sandbox-{id}")
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

        self.state.sandbox_index.update_from_sandbox(&sandbox);

        self.state
            .store
            .put_message(&sandbox)
            .await
            .map_err(|e| Status::internal(format!("persist sandbox failed: {e}")))?;

        self.state.sandbox_watch_bus.notify(&id);

        match self.state.sandbox_client.create(&sandbox).await {
            Ok(_) => {
                info!(
                    sandbox_id = %id,
                    sandbox_name = %name,
                    "CreateSandbox request completed successfully"
                );
                Ok(Response::new(SandboxResponse {
                    sandbox: Some(sandbox),
                }))
            }
            Err(kube::Error::Api(err)) if err.code == 409 => {
                warn!(
                    sandbox_id = %id,
                    sandbox_name = %name,
                    "Sandbox already exists in Kubernetes"
                );
                if let Err(e) = self.state.store.delete(Sandbox::object_type(), &id).await {
                    warn!(sandbox_id = %id, error = %e, "Failed to clean up store after conflict");
                }
                self.state.sandbox_index.remove_sandbox(&id);
                self.state.sandbox_watch_bus.notify(&id);
                Err(Status::already_exists("sandbox already exists"))
            }
            Err(err) => {
                warn!(
                    sandbox_id = %id,
                    sandbox_name = %name,
                    error = %err,
                    "CreateSandbox request failed"
                );
                if let Err(e) = self.state.store.delete(Sandbox::object_type(), &id).await {
                    warn!(sandbox_id = %id, error = %e, "Failed to clean up store after creation failure");
                }
                self.state.sandbox_index.remove_sandbox(&id);
                self.state.sandbox_watch_bus.notify(&id);
                Err(Status::internal(format!(
                    "create sandbox in kubernetes failed: {err}"
                )))
            }
        }
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
            // Subscribe to all buses BEFORE reading the initial snapshot to avoid
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

            // Always start with a snapshot if present.
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
        let limit = if request.limit == 0 {
            100
        } else {
            request.limit
        };
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
        let (limit, offset) = (
            if request.limit == 0 {
                100
            } else {
                request.limit
            },
            request.offset,
        );
        let providers = list_provider_records(self.state.store.as_ref(), limit, offset).await?;

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

        // Lazy backfill: no policy history exists yet, create version 1 from spec.policy.
        let spec = sandbox
            .spec
            .ok_or_else(|| Status::internal("sandbox has no spec"))?;
        let policy = spec
            .policy
            .ok_or_else(|| Status::failed_precondition("sandbox has no policy configured"))?;

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
        let session = SshSession {
            id: token.clone(),
            sandbox_id: req.sandbox_id.clone(),
            token: token.clone(),
            created_at_ms: current_time_ms()
                .map_err(|e| Status::internal(format!("timestamp generation failed: {e}")))?,
            revoked: false,
            name: generate_name(),
        };

        self.state
            .store
            .put_message(&session)
            .await
            .map_err(|e| Status::internal(format!("persist ssh session failed: {e}")))?;

        let (gateway_host, gateway_port) = resolve_gateway(&self.state.config);
        let scheme = "https";

        Ok(Response::new(CreateSshSessionResponse {
            sandbox_id: req.sandbox_id,
            token,
            gateway_host,
            gateway_port: gateway_port.into(),
            gateway_scheme: scheme.to_string(),
            connect_path: self.state.config.ssh_connect_path.clone(),
            host_key_fingerprint: String::new(),
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
        let baseline_policy = spec
            .policy
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("sandbox has no policy configured"))?;

        // Validate static fields haven't changed.
        validate_static_fields_unchanged(baseline_policy, &new_policy)?;

        // Validate network mode hasn't changed (Block ↔ Proxy).
        validate_network_mode_unchanged(baseline_policy, &new_policy)?;

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

        let limit = if req.limit == 0 { 50 } else { req.limit };
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

        while let Some(batch) = stream
            .message()
            .await
            .map_err(|e| Status::internal(format!("stream error: {e}")))?
        {
            if batch.sandbox_id.is_empty() {
                continue;
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
    if let Some(inf) = &policy.inference {
        hasher.update(inf.encode_to_vec());
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

/// Validate that static policy fields (filesystem, landlock, process) haven't changed
/// from the baseline (version 1) policy.
fn validate_static_fields_unchanged(
    baseline: &ProtoSandboxPolicy,
    new: &ProtoSandboxPolicy,
) -> Result<(), Status> {
    if baseline.filesystem != new.filesystem {
        return Err(Status::invalid_argument(
            "filesystem policy cannot be changed on a live sandbox (applied at startup)",
        ));
    }
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

    let (local_proxy_port, proxy_task) =
        start_single_use_ssh_proxy(target_host, target_port, handshake_secret)
            .await
            .map_err(|e| Status::internal(format!("failed to start ssh proxy: {e}")))?;

    let exec = run_exec_with_russh(local_proxy_port, command, stdin_payload, tx.clone());
    let exit_code = if timeout_seconds == 0 {
        exec.await?
    } else if let Ok(result) = tokio::time::timeout(
        std::time::Duration::from_secs(u64::from(timeout_seconds)),
        exec,
    )
    .await
    {
        result?
    } else {
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
            return;
        };
        let Ok(mut sandbox_conn) = TcpStream::connect((target_host.as_str(), target_port)).await
        else {
            return;
        };
        let Ok(preface) = build_preface(&uuid::Uuid::new_v4().to_string(), &handshake_secret)
        else {
            return;
        };
        if sandbox_conn.write_all(preface.as_bytes()).await.is_err() {
            return;
        }
        let mut response = String::new();
        if read_line(&mut sandbox_conn, &mut response).await.is_err() {
            return;
        }
        if response.trim() != "OK" {
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
        create_provider_record, delete_provider_record, get_provider_record, is_valid_env_key,
        list_provider_records, resolve_provider_environment, update_provider_record,
    };
    use crate::persistence::Store;
    use navigator_core::proto::Provider;
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
}
