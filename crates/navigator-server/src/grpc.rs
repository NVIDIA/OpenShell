//! gRPC service implementation.

#![allow(clippy::ignored_unit_patterns)] // Tokio select! macro generates unit patterns

use crate::persistence::ObjectType;
use futures::future;
use navigator_core::proto::{
    CreateSandboxRequest, CreateSshSessionRequest, CreateSshSessionResponse, DeleteSandboxRequest,
    DeleteSandboxResponse, GetSandboxPolicyRequest, GetSandboxPolicyResponse, GetSandboxRequest,
    HealthRequest, HealthResponse, ListSandboxesRequest, ListSandboxesResponse,
    RevokeSshSessionRequest, RevokeSshSessionResponse, SandboxResponse, SandboxStreamEvent,
    ServiceStatus, SshSession, WatchSandboxRequest, navigator_server::Navigator,
};
use navigator_core::proto::{Sandbox, SandboxPhase};
use prost::Message;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

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

        let id = uuid::Uuid::new_v4().to_string();
        let name = format!("sandbox-{id}");
        let namespace = self.state.config.sandbox_namespace.clone();

        let sandbox = Sandbox {
            id: id.clone(),
            name: name.clone(),
            namespace,
            spec: Some(spec),
            status: None,
            phase: SandboxPhase::Provisioning as i32,
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

            // Replay tail logs (best-effort).
            if follow_logs {
                for evt in state.tracing_log_bus.tail(&sandbox_id, log_tail as usize) {
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
        let id = request.into_inner().id;
        let sandbox = self
            .state
            .store
            .get_message::<Sandbox>(&id)
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
            let sandbox = Sandbox::decode(record.payload.as_slice())
                .map_err(|e| Status::internal(format!("decode sandbox failed: {e}")))?;
            sandboxes.push(sandbox);
        }

        Ok(Response::new(ListSandboxesResponse { sandboxes }))
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        let id = request.into_inner().id;
        let sandbox = self
            .state
            .store
            .get_message::<Sandbox>(&id)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?;

        let Some(mut sandbox) = sandbox else {
            return Err(Status::not_found("sandbox not found"));
        };

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

        let spec = sandbox
            .spec
            .ok_or_else(|| Status::internal("sandbox has no spec"))?;

        let policy = spec
            .policy
            .ok_or_else(|| Status::failed_precondition("sandbox has no policy configured"))?;

        info!(
            sandbox_id = %sandbox_id,
            "GetSandboxPolicy request completed successfully"
        );

        Ok(Response::new(GetSandboxPolicyResponse {
            policy: Some(policy),
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
        }))
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
