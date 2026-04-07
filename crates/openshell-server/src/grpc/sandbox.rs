// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox lifecycle, exec, and SSH session handlers.

#![allow(clippy::ignored_unit_patterns)] // Tokio select! macro generates unit patterns
#![allow(clippy::result_large_err)] // gRPC handlers return Result<Response<_>, Status>
#![allow(clippy::cast_possible_truncation)] // Intentional u128->i64 etc. for timestamp math
#![allow(clippy::cast_sign_loss)] // Intentional i32->u32 conversions from proto types
#![allow(clippy::cast_possible_wrap)] // Intentional u32->i32 conversions for proto compat

use crate::ServerState;
use crate::persistence::{ObjectType, generate_name};
use futures::future;
use openshell_core::proto::{
    CreateSandboxRequest, CreateSshSessionRequest, CreateSshSessionResponse, DeleteSandboxRequest,
    DeleteSandboxResponse, ExecSandboxEvent, ExecSandboxExit, ExecSandboxRequest,
    ExecSandboxStderr, ExecSandboxStdout, GetSandboxRequest, ListSandboxesRequest,
    ListSandboxesResponse, RevokeSshSessionRequest, RevokeSshSessionResponse, SandboxResponse,
    SandboxStreamEvent, WatchSandboxRequest,
};
use openshell_core::proto::{Sandbox, SandboxPhase, SandboxTemplate, SshSession};
use prost::Message;
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

use super::provider::is_valid_env_key;
use super::validation::{
    level_matches, source_matches, validate_exec_request_fields, validate_policy_safety,
    validate_sandbox_spec,
};
use super::{MAX_PAGE_SIZE, clamp_limit, current_time_ms};

// ---------------------------------------------------------------------------
// Sandbox lifecycle handlers
// ---------------------------------------------------------------------------

pub(super) async fn handle_create_sandbox(
    state: &Arc<ServerState>,
    request: Request<CreateSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    let request = request.into_inner();
    let spec = request
        .spec
        .ok_or_else(|| Status::invalid_argument("spec is required"))?;

    // Validate field sizes before any I/O (fail fast on oversized payloads).
    validate_sandbox_spec(&request.name, &spec)?;

    // Validate provider names exist (fail fast).
    for name in &spec.providers {
        state
            .store
            .get_message_by_name::<openshell_core::proto::Provider>(name)
            .await
            .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
            .ok_or_else(|| Status::failed_precondition(format!("provider '{name}' not found")))?;
    }

    // Ensure the template always carries the resolved image.
    let mut spec = spec;
    let template = spec.template.get_or_insert_with(SandboxTemplate::default);
    if template.image.is_empty() {
        template.image = state.sandbox_client.default_image().to_string();
    }

    if spec.gpu {
        state
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
    let namespace = state.config.sandbox_namespace.clone();

    let sandbox = Sandbox {
        id: id.clone(),
        name: name.clone(),
        namespace,
        spec: Some(spec),
        status: None,
        phase: SandboxPhase::Provisioning as i32,
        ..Default::default()
    };

    // Reject duplicate names early.
    let existing = state
        .store
        .get_message_by_name::<Sandbox>(&name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?;
    if existing.is_some() {
        return Err(Status::already_exists(format!(
            "sandbox '{name}' already exists"
        )));
    }

    // Persist to the store FIRST so the sandbox watcher always finds
    // the record with `spec` populated.
    state.sandbox_index.update_from_sandbox(&sandbox);

    state
        .store
        .put_message(&sandbox)
        .await
        .map_err(|e| Status::internal(format!("persist sandbox failed: {e}")))?;

    // Now create the Kubernetes resource.
    match state.sandbox_client.create(&sandbox).await {
        Ok(_) => {}
        Err(kube::Error::Api(err)) if err.code == 409 => {
            let _ = state.store.delete("sandbox", &id).await;
            state.sandbox_index.remove_sandbox(&id);
            warn!(
                sandbox_id = %id,
                sandbox_name = %name,
                "Sandbox already exists in Kubernetes"
            );
            return Err(Status::already_exists("sandbox already exists"));
        }
        Err(err) => {
            let _ = state.store.delete("sandbox", &id).await;
            state.sandbox_index.remove_sandbox(&id);
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

    state.sandbox_watch_bus.notify(&id);

    info!(
        sandbox_id = %id,
        sandbox_name = %name,
        "CreateSandbox request completed successfully"
    );
    Ok(Response::new(SandboxResponse {
        sandbox: Some(sandbox),
    }))
}

pub(super) async fn handle_get_sandbox(
    state: &Arc<ServerState>,
    request: Request<GetSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    let name = request.into_inner().name;
    if name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }

    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?;

    let sandbox = sandbox.ok_or_else(|| Status::not_found("sandbox not found"))?;
    Ok(Response::new(SandboxResponse {
        sandbox: Some(sandbox),
    }))
}

pub(super) async fn handle_list_sandboxes(
    state: &Arc<ServerState>,
    request: Request<ListSandboxesRequest>,
) -> Result<Response<ListSandboxesResponse>, Status> {
    let request = request.into_inner();
    let limit = clamp_limit(request.limit, 100, MAX_PAGE_SIZE);
    let records = state
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

pub(super) async fn handle_delete_sandbox(
    state: &Arc<ServerState>,
    request: Request<DeleteSandboxRequest>,
) -> Result<Response<DeleteSandboxResponse>, Status> {
    let name = request.into_inner().name;
    if name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }

    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?;

    let Some(mut sandbox) = sandbox else {
        return Err(Status::not_found("sandbox not found"));
    };

    let id = sandbox.id.clone();

    sandbox.phase = SandboxPhase::Deleting as i32;
    state
        .store
        .put_message(&sandbox)
        .await
        .map_err(|e| Status::internal(format!("persist sandbox failed: {e}")))?;

    state.sandbox_index.update_from_sandbox(&sandbox);
    state.sandbox_watch_bus.notify(&id);

    // Clean up SSH sessions associated with this sandbox.
    if let Ok(records) = state.store.list(SshSession::object_type(), 1000, 0).await {
        for record in records {
            if let Ok(session) = SshSession::decode(record.payload.as_slice())
                && session.sandbox_id == id
                && let Err(e) = state
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
    if let Err(e) = state
        .store
        .delete(
            super::policy::SANDBOX_SETTINGS_OBJECT_TYPE,
            &super::policy::sandbox_settings_id(&id),
        )
        .await
    {
        warn!(
            sandbox_id = %id,
            error = %e,
            "Failed to delete sandbox settings during cleanup"
        );
    }

    let deleted = match state.sandbox_client.delete(&sandbox.name).await {
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

    if !deleted && let Err(e) = state.store.delete(Sandbox::object_type(), &id).await {
        warn!(sandbox_id = %id, error = %e, "Failed to clean up store after delete");
    }

    // Clean up bus entries to prevent unbounded memory growth.
    state.tracing_log_bus.remove(&id);
    state.tracing_log_bus.platform_event_bus.remove(&id);
    state.sandbox_watch_bus.remove(&id);

    info!(
        sandbox_id = %id,
        sandbox_name = %sandbox.name,
        "DeleteSandbox request completed successfully"
    );
    Ok(Response::new(DeleteSandboxResponse { deleted }))
}

// ---------------------------------------------------------------------------
// Watch handler
// ---------------------------------------------------------------------------

#[allow(clippy::unused_async)] // Must be async to match the trait signature
pub(super) async fn handle_watch_sandbox(
    state: &Arc<ServerState>,
    request: Request<WatchSandboxRequest>,
) -> Result<Response<ReceiverStream<Result<SandboxStreamEvent, Status>>>, Status> {
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
    let state = state.clone();

    // Spawn producer task.
    tokio::spawn(async move {
        // Validate that the sandbox exists BEFORE subscribing to any buses.
        match state.store.get_message::<Sandbox>(&sandbox_id).await {
            Ok(Some(_)) => {}
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

        // Subscribe to all buses BEFORE reading the snapshot.
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

        // Re-read the snapshot now that we have subscriptions active.
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
                if let Some(openshell_core::proto::sandbox_stream_event::Payload::Log(ref log)) =
                    evt.payload
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

        // Replay buffered platform events.
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
                                        if phase == SandboxPhase::Ready {
                                            return;
                                        }
                                    }
                                }
                                Ok(None) => {
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

// ---------------------------------------------------------------------------
// Exec handler
// ---------------------------------------------------------------------------

pub(super) async fn handle_exec_sandbox(
    state: &Arc<ServerState>,
    request: Request<ExecSandboxRequest>,
) -> Result<Response<ReceiverStream<Result<ExecSandboxEvent, Status>>>, Status> {
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

    let sandbox = state
        .store
        .get_message::<Sandbox>(&req.sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;

    if SandboxPhase::try_from(sandbox.phase).ok() != Some(SandboxPhase::Ready) {
        return Err(Status::failed_precondition("sandbox is not ready"));
    }

    let (target_host, target_port) = resolve_sandbox_exec_target(state, &sandbox).await?;
    let command_str = build_remote_exec_command(&req)
        .map_err(|e| Status::invalid_argument(format!("command construction failed: {e}")))?;
    let stdin_payload = req.stdin;
    let timeout_seconds = req.timeout_seconds;
    let request_tty = req.tty;
    let sandbox_id = sandbox.id;
    let handshake_secret = state.config.ssh_handshake_secret.clone();

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
            request_tty,
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

// ---------------------------------------------------------------------------
// SSH session handlers
// ---------------------------------------------------------------------------

pub(super) async fn handle_create_ssh_session(
    state: &Arc<ServerState>,
    request: Request<CreateSshSessionRequest>,
) -> Result<Response<CreateSshSessionResponse>, Status> {
    let req = request.into_inner();
    if req.sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }

    let sandbox = state
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
    let expires_at_ms = if state.config.ssh_session_ttl_secs > 0 {
        now_ms + (state.config.ssh_session_ttl_secs as i64 * 1000)
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

    state
        .store
        .put_message(&session)
        .await
        .map_err(|e| Status::internal(format!("persist ssh session failed: {e}")))?;

    let (gateway_host, gateway_port) = resolve_gateway(&state.config);
    let scheme = if state.config.tls.is_some() {
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
        connect_path: state.config.ssh_connect_path.clone(),
        host_key_fingerprint: String::new(),
        expires_at_ms,
    }))
}

pub(super) async fn handle_revoke_ssh_session(
    state: &Arc<ServerState>,
    request: Request<RevokeSshSessionRequest>,
) -> Result<Response<RevokeSshSessionResponse>, Status> {
    let token = request.into_inner().token;
    if token.is_empty() {
        return Err(Status::invalid_argument("token is required"));
    }

    let session = state
        .store
        .get_message::<SshSession>(&token)
        .await
        .map_err(|e| Status::internal(format!("fetch ssh session failed: {e}")))?;

    let Some(mut session) = session else {
        return Ok(Response::new(RevokeSshSessionResponse { revoked: false }));
    };

    session.revoked = true;
    state
        .store
        .put_message(&session)
        .await
        .map_err(|e| Status::internal(format!("persist ssh session failed: {e}")))?;

    Ok(Response::new(RevokeSshSessionResponse { revoked: true }))
}

// ---------------------------------------------------------------------------
// Exec transport helpers
// ---------------------------------------------------------------------------

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

/// Shell-escape a value for embedding in a POSIX shell command.
///
/// Wraps unsafe values in single quotes with the standard `'\''` idiom for
/// embedded single-quote characters. Rejects null bytes which can truncate
/// shell parsing at the C level.
fn shell_escape(value: &str) -> Result<String, String> {
    if value.bytes().any(|b| b == 0) {
        return Err("value contains null bytes".to_string());
    }
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
            "assembled command string exceeds {MAX_COMMAND_STRING_LEN} byte limit"
        ));
    }
    Ok(result)
}

/// Maximum number of attempts when establishing the SSH transport to a sandbox.
const SSH_CONNECT_MAX_ATTEMPTS: u32 = 6;

/// Initial backoff duration between SSH connection retries.
const SSH_CONNECT_INITIAL_BACKOFF: std::time::Duration = std::time::Duration::from_millis(250);

/// Maximum backoff duration between SSH connection retries.
const SSH_CONNECT_MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(2);

/// Returns `true` if the gRPC status represents a transient SSH connection error.
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
    request_tty: bool,
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

            let exec = run_exec_with_russh(
                local_proxy_port,
                command,
                stdin_payload.clone(),
                request_tty,
                tx.clone(),
            );

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
    request_tty: bool,
    tx: mpsc::Sender<Result<ExecSandboxEvent, Status>>,
) -> Result<i32, Status> {
    // Defense-in-depth: validate command at the transport boundary.
    if command.as_bytes().contains(&0) {
        return Err(Status::invalid_argument(
            "command contains null bytes at transport boundary",
        ));
    }
    if command.len() > MAX_COMMAND_STRING_LEN {
        return Err(Status::invalid_argument(format!(
            "command exceeds {MAX_COMMAND_STRING_LEN} byte limit at transport boundary"
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

    if request_tty {
        channel
            .request_pty(false, "xterm-256color", 0, 0, 0, 0, &[])
            .await
            .map_err(|e| Status::internal(format!("failed to allocate PTY: {e}")))?;
    }

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
fn is_safe_ssh_proxy_target(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local(),
        std::net::IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return false;
            }
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

        let addr_str = format!("{target_host}:{target_port}");
        let resolved = match tokio::net::lookup_host(&addr_str).await {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    addr
                } else {
                    warn!(target_host = %target_host, "SSH proxy: DNS resolution returned no addresses");
                    return;
                }
            }
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- shell_escape ----

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

    // ---- build_remote_exec_command ----

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

    // ---- is_safe_ssh_proxy_target ----

    #[test]
    fn ssh_proxy_target_allows_pod_network_ips() {
        use std::net::{IpAddr, Ipv4Addr};
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
        let ip: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(!is_safe_ssh_proxy_target(ip));
    }

    #[test]
    fn ssh_proxy_target_blocks_ipv4_mapped_ipv6_link_local() {
        use std::net::IpAddr;
        let ip: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        assert!(!is_safe_ssh_proxy_target(ip));
    }

    // ---- petname / generate_name ----

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

    #[test]
    fn generate_name_fallback_is_valid() {
        for _ in 0..50 {
            let name = generate_name();
            assert_eq!(name.len(), 6, "unexpected length for fallback name: {name}");
            assert!(
                name.chars().all(|c| c.is_ascii_lowercase()),
                "fallback name should be all lowercase: {name}"
            );
        }
    }
}
