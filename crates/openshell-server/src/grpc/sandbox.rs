// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox lifecycle, exec, and SSH session handlers.

#![allow(clippy::ignored_unit_patterns)] // Tokio select! macro generates unit patterns
#![allow(clippy::result_large_err)] // gRPC handlers return Result<Response<_>, Status>
#![allow(clippy::cast_possible_truncation)] // Intentional u128->i64 etc. for timestamp math
#![allow(clippy::cast_sign_loss)] // Intentional i32->u32 conversions from proto types
#![allow(clippy::cast_possible_wrap)] // Intentional u32->i32 conversions for proto compat

use crate::ServerState;
use crate::persistence::{ObjectLabels, ObjectType, WriteCondition, generate_name};
use futures::future;
use openshell_core::proto::{
    AttachSandboxProviderRequest, AttachSandboxProviderResponse, CreateSandboxRequest,
    CreateSshSessionRequest, CreateSshSessionResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    DetachSandboxProviderRequest, DetachSandboxProviderResponse, ExecSandboxEvent, ExecSandboxExit,
    ExecSandboxInput, ExecSandboxRequest, ExecSandboxStderr, ExecSandboxStdout, GetSandboxRequest,
    ListSandboxProvidersRequest, ListSandboxProvidersResponse, ListSandboxesRequest,
    ListSandboxesResponse, Provider, RevokeSshSessionRequest, RevokeSshSessionResponse,
    SandboxResponse, SandboxStreamEvent, SshRelayTarget, TcpForwardFrame, TcpForwardInit,
    TcpRelayTarget, WatchSandboxRequest, relay_open, tcp_forward_init,
};
use openshell_core::proto::{Sandbox, SandboxPhase, SandboxTemplate, SshSession};
use openshell_core::telemetry::{
    LifecycleOperation, LifecycleResource, SandboxTemplateSource, TelemetryComputeDriver,
    TelemetryOutcome,
};
use openshell_core::{ObjectId, ObjectName, ObjectWorkspace};
use prost::Message;
use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

use russh::ChannelMsg;
use russh::client::AuthResult;

use super::provider::{
    get_provider_record, is_valid_env_key, validate_provider_environment_keys_unique,
};
use super::validation::{
    level_matches, source_matches, validate_exec_request_fields,
    validate_no_reserved_provider_policy_keys, validate_policy_safety, validate_sandbox_spec,
};
use super::{MAX_PAGE_SIZE, MAX_PROVIDERS, MAX_ROUTABLE_NAME_LEN, clamp_limit};
use crate::persistence::current_time_ms;

const TCP_FORWARD_CHUNK_SIZE: usize = 64 * 1024;

fn generate_routable_name() -> String {
    let name = petname::petname(2, "-").unwrap_or_else(generate_name);
    let mut truncated = &name[..name.len().min(MAX_ROUTABLE_NAME_LEN)];
    truncated = truncated.trim_end_matches('-');
    truncated.to_string()
}

// ---------------------------------------------------------------------------
// Sandbox lifecycle handlers
// ---------------------------------------------------------------------------

pub(super) async fn handle_create_sandbox(
    state: &Arc<ServerState>,
    request: Request<CreateSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    let create_request = request.get_ref().clone();
    let result = handle_create_sandbox_inner(state, request).await;
    emit_sandbox_create_telemetry(
        state,
        &create_request,
        TelemetryOutcome::from_success(result.is_ok()),
    );
    result
}

fn emit_sandbox_create_telemetry(
    state: &Arc<ServerState>,
    request: &CreateSandboxRequest,
    outcome: TelemetryOutcome,
) {
    let compute_driver = telemetry_compute_driver(state.compute.driver_kind());
    let Some(spec) = request.spec.as_ref() else {
        openshell_core::telemetry::emit_sandbox_create(
            outcome,
            false,
            0,
            false,
            SandboxTemplateSource::Undefined,
            compute_driver,
        );
        return;
    };
    let template_source = if spec
        .template
        .as_ref()
        .is_some_and(|template| !template.image.trim().is_empty())
    {
        SandboxTemplateSource::Image
    } else {
        SandboxTemplateSource::Default
    };
    let gpu_requested =
        openshell_core::gpu::sandbox_gpu_requested(spec.resource_requirements.as_ref());
    openshell_core::telemetry::emit_sandbox_create(
        outcome,
        gpu_requested,
        spec.providers.len() as u64,
        spec.policy.is_some(),
        template_source,
        compute_driver,
    );
}

fn telemetry_compute_driver(
    driver_kind: Option<openshell_core::ComputeDriverKind>,
) -> TelemetryComputeDriver {
    TelemetryComputeDriver::from_driver_kind(driver_kind)
}

async fn handle_create_sandbox_inner(
    state: &Arc<ServerState>,
    request: Request<CreateSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    let request = request.into_inner();
    let spec = request
        .spec
        .ok_or_else(|| Status::invalid_argument("spec is required"))?;

    // Validate field sizes before any I/O (fail fast on oversized payloads).
    validate_sandbox_spec(&request.name, &spec)?;

    // Validate labels (keys and values must meet Kubernetes requirements).
    for (key, value) in &request.labels {
        crate::grpc::validation::validate_label_key(key)?;
        crate::grpc::validation::validate_label_value(value)?;
    }
    crate::grpc::validation::validate_annotations(&request.annotations, "annotations")?;

    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &request.workspace)
        .await?
        .ensure_active()?;

    let _sandbox_sync_guard = if spec.providers.is_empty() {
        None
    } else {
        Some(state.compute.sandbox_sync_guard().await)
    };

    // Validate provider names exist (fail fast).
    for name in &spec.providers {
        state
            .store
            .get_message_by_name::<Provider>(&workspace, name)
            .await
            .map_err(|e| Status::internal(format!("fetch provider failed: {e}")))?
            .ok_or_else(|| Status::failed_precondition(format!("provider '{name}' not found")))?;
    }
    validate_provider_environment_keys_unique(state.store.as_ref(), &workspace, &spec.providers)
        .await?;

    // Ensure the template always carries the resolved image.
    let mut spec = spec;
    let template = spec.template.get_or_insert_with(SandboxTemplate::default);
    if template.image.is_empty() {
        template.image = state.compute.default_image().to_string();
    }

    // Ensure process identity defaults to "sandbox" when missing or
    // empty, then validate policy safety before persisting.
    if let Some(ref mut policy) = spec.policy {
        openshell_policy::ensure_sandbox_process_identity(policy);
        validate_no_reserved_provider_policy_keys(policy)?;
        validate_policy_safety(policy)?;
        crate::middleware::validate_policy(state.middleware_registry.as_ref(), policy).await?;
    }

    let id = uuid::Uuid::new_v4().to_string();
    let name = if request.name.is_empty() {
        generate_routable_name()
    } else {
        request.name.clone()
    };

    let now_ms = current_time_ms();

    let mut sandbox = Sandbox {
        metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: id.clone(),
            name: name.clone(),
            created_at_ms: now_ms,
            labels: request.labels.clone(),
            resource_version: 0,
            annotations: request.annotations.clone(),
            workspace,
            deletion_timestamp_ms: 0,
        }),
        spec: Some(spec),
        status: None,
    };
    sandbox.set_phase(SandboxPhase::Provisioning as i32);

    // Ensure metadata is valid (defense in depth - should always be true for server-constructed metadata)
    super::validation::validate_object_metadata(sandbox.metadata.as_ref(), "sandbox")?;

    state
        .compute
        .validate_sandbox_create(&sandbox)
        .await
        .map_err(|status| {
            warn!(error = %status, "Rejecting sandbox create request");
            status
        })?;

    // Mint the gateway JWT for singleplayer drivers. K8s sandboxes skip
    // this mint and bootstrap via `IssueSandboxToken` at supervisor
    // startup; identifying "is this K8s?" lives in the compute layer, so
    // we mint unconditionally here when the issuer is configured and let
    // the K8s driver simply ignore the field.
    let sandbox_token = state.sandbox_jwt_issuer.as_ref().map(|issuer| {
        issuer.mint(&id).map(|minted| {
            tracing::info!(
                sandbox_id = %id,
                "minted sandbox JWT"
            );
            minted.token
        })
    });
    let sandbox_token = match sandbox_token {
        Some(Ok(token)) => Some(token),
        Some(Err(status)) => return Err(status),
        None => None,
    };

    let sandbox = state.compute.create_sandbox(sandbox, sandbox_token).await?;

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
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &req.workspace)
        .await?
        .name;

    let sandbox = state
        .store
        .get_message_by_name::<Sandbox>(&workspace, &req.name)
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
    if request.all_workspaces && !request.workspace.is_empty() {
        return Err(Status::invalid_argument(
            "all_workspaces and workspace are mutually exclusive",
        ));
    }
    let limit = clamp_limit(request.limit, 100, MAX_PAGE_SIZE);

    let sandboxes: Vec<Sandbox> = if request.all_workspaces {
        if request.label_selector.is_empty() {
            state
                .store
                .list_all_messages(limit, request.offset)
                .await
                .map_err(|e| Status::internal(format!("list sandboxes failed: {e}")))?
        } else {
            crate::grpc::validation::validate_label_selector(&request.label_selector)?;
            state
                .store
                .list_all_messages_with_selector(&request.label_selector, limit, request.offset)
                .await
                .map_err(|e| Status::internal(format!("list sandboxes failed: {e}")))?
        }
    } else {
        let workspace =
            super::workspace::resolve_workspace(state.store.as_ref(), &request.workspace)
                .await?
                .name;
        if request.label_selector.is_empty() {
            state
                .store
                .list_messages(&workspace, limit, request.offset)
                .await
                .map_err(|e| Status::internal(format!("list sandboxes failed: {e}")))?
        } else {
            crate::grpc::validation::validate_label_selector(&request.label_selector)?;
            state
                .store
                .list_messages_with_selector(
                    &workspace,
                    &request.label_selector,
                    limit,
                    request.offset,
                )
                .await
                .map_err(|e| {
                    Status::internal(format!("list sandboxes with selector failed: {e}"))
                })?
        }
    };

    Ok(Response::new(ListSandboxesResponse { sandboxes }))
}

pub(super) async fn handle_list_sandbox_providers(
    state: &Arc<ServerState>,
    request: Request<ListSandboxProvidersRequest>,
) -> Result<Response<ListSandboxProvidersResponse>, Status> {
    let req = request.into_inner();
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &req.workspace)
        .await?
        .name;
    let sandbox = sandbox_by_name(state, &workspace, &req.sandbox_name).await?;
    let providers = providers_for_sandbox(state, &sandbox, &workspace).await?;
    Ok(Response::new(ListSandboxProvidersResponse { providers }))
}

pub(super) async fn handle_attach_sandbox_provider(
    state: &Arc<ServerState>,
    request: Request<AttachSandboxProviderRequest>,
) -> Result<Response<AttachSandboxProviderResponse>, Status> {
    let request = request.into_inner();
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &request.workspace)
        .await?
        .ensure_active()?;
    if request.provider_name.is_empty() {
        return Err(Status::invalid_argument("provider_name is required"));
    }

    // Validate provider name would not violate sandbox spec constraints if added
    // (pre-validation ensures CAS mutations preserve invariants)
    if request.provider_name.len() > super::MAX_NAME_LEN {
        return Err(Status::invalid_argument(format!(
            "provider_name exceeds maximum length ({} > {})",
            request.provider_name.len(),
            super::MAX_NAME_LEN
        )));
    }

    get_provider_record(state.store.as_ref(), &workspace, &request.provider_name)
        .await
        .map_err(|err| {
            if err.code() == tonic::Code::NotFound {
                Status::failed_precondition(format!(
                    "provider '{}' not found",
                    request.provider_name
                ))
            } else {
                err
            }
        })?;

    let _sandbox_sync_guard = state.compute.sandbox_sync_guard().await;
    let sandbox = sandbox_by_name(state, &workspace, &request.sandbox_name).await?;
    let sandbox_id = sandbox
        .metadata
        .as_ref()
        .ok_or_else(|| Status::internal("sandbox metadata is missing"))?
        .id
        .clone();

    // Pre-check: fail fast if sandbox spec is missing (invariant violation)
    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| Status::internal("sandbox spec is missing"))?;

    // Pre-check: fail fast if already at MAX_PROVIDERS limit (avoid spurious CAS conflicts)
    // Note: This is an optimization; the CAS closure rechecks after dedupe in case of races
    if spec.providers.len() >= MAX_PROVIDERS
        && !spec
            .providers
            .iter()
            .any(|name| name == &request.provider_name)
    {
        return Err(Status::invalid_argument(format!(
            "providers list exceeds maximum ({MAX_PROVIDERS})"
        )));
    }
    let mut candidate_spec = spec.clone();
    dedupe_provider_names(&mut candidate_spec.providers);
    if !candidate_spec
        .providers
        .iter()
        .any(|name| name == &request.provider_name)
    {
        candidate_spec.providers.push(request.provider_name.clone());
    }
    validate_sandbox_spec(&request.sandbox_name, &candidate_spec)?;
    validate_provider_environment_keys_unique(
        state.store.as_ref(),
        &workspace,
        &candidate_spec.providers,
    )
    .await?;

    let provider_name = request.provider_name.clone();
    let attached = Arc::new(AtomicBool::new(false));
    let attached_clone = attached.clone();

    let sandbox = state
        .store
        .update_message_cas::<Sandbox, _>(
            &sandbox_id,
            request.expected_resource_version,
            |sandbox| {
                let Some(ref mut spec) = sandbox.spec else {
                    // Spec should always exist post-creation; if missing, fail CAS to surface error
                    return;
                };

                dedupe_provider_names(&mut spec.providers);
                if !spec.providers.iter().any(|name| name == &provider_name)
                    && spec.providers.len() < MAX_PROVIDERS
                {
                    spec.providers.push(provider_name.clone());
                    attached_clone.store(true, Ordering::Relaxed);
                }
            },
        )
        .await
        .map_err(|e| super::persistence_error_to_status(e, "attach sandbox provider"))?;

    let attached = attached.load(Ordering::Relaxed);

    info!(
        sandbox_name = %request.sandbox_name,
        provider_name = %request.provider_name,
        attached,
        "AttachSandboxProvider request completed successfully"
    );

    Ok(Response::new(AttachSandboxProviderResponse {
        sandbox: Some(sandbox),
        attached,
    }))
}

pub(super) async fn handle_detach_sandbox_provider(
    state: &Arc<ServerState>,
    request: Request<DetachSandboxProviderRequest>,
) -> Result<Response<DetachSandboxProviderResponse>, Status> {
    let request = request.into_inner();
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &request.workspace)
        .await?
        .name;
    if request.provider_name.is_empty() {
        return Err(Status::invalid_argument("provider_name is required"));
    }

    // Validate provider name (pre-validation ensures CAS mutations preserve invariants)
    if request.provider_name.len() > super::MAX_NAME_LEN {
        return Err(Status::invalid_argument(format!(
            "provider_name exceeds maximum length ({} > {})",
            request.provider_name.len(),
            super::MAX_NAME_LEN
        )));
    }

    let _sandbox_sync_guard = state.compute.sandbox_sync_guard().await;
    let sandbox = sandbox_by_name(state, &workspace, &request.sandbox_name).await?;
    let sandbox_id = sandbox
        .metadata
        .as_ref()
        .ok_or_else(|| Status::internal("sandbox metadata is missing"))?
        .id
        .clone();

    // Pre-check: fail fast if sandbox spec is missing (invariant violation)
    let _spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| Status::internal("sandbox spec is missing"))?;

    let provider_name = request.provider_name.clone();
    let detached = Arc::new(AtomicBool::new(false));
    let detached_clone = detached.clone();

    let sandbox = state
        .store
        .update_message_cas::<Sandbox, _>(
            &sandbox_id,
            request.expected_resource_version,
            |sandbox| {
                let Some(ref mut spec) = sandbox.spec else {
                    // Spec should always exist post-creation; if missing, fail CAS to surface error
                    return;
                };

                let before_len = spec.providers.len();
                spec.providers.retain(|name| name != &provider_name);
                if spec.providers.len() != before_len {
                    detached_clone.store(true, Ordering::Relaxed);
                    // Only dedupe after making a change
                    dedupe_provider_names(&mut spec.providers);
                }
            },
        )
        .await
        .map_err(|e| super::persistence_error_to_status(e, "detach sandbox provider"))?;

    let detached = detached.load(Ordering::Relaxed);

    info!(
        sandbox_name = %request.sandbox_name,
        provider_name = %request.provider_name,
        detached,
        "DetachSandboxProvider request completed successfully"
    );

    Ok(Response::new(DetachSandboxProviderResponse {
        sandbox: Some(sandbox),
        detached,
    }))
}

pub(super) async fn handle_delete_sandbox(
    state: &Arc<ServerState>,
    request: Request<DeleteSandboxRequest>,
) -> Result<Response<DeleteSandboxResponse>, Status> {
    let result = handle_delete_sandbox_inner(state, request).await;
    let outcome = match &result {
        Ok(response) if response.get_ref().deleted => TelemetryOutcome::Success,
        _ => TelemetryOutcome::Failure,
    };
    openshell_core::telemetry::emit_lifecycle(
        LifecycleResource::Sandbox,
        LifecycleOperation::Delete,
        outcome,
    );
    result
}

async fn handle_delete_sandbox_inner(
    state: &Arc<ServerState>,
    request: Request<DeleteSandboxRequest>,
) -> Result<Response<DeleteSandboxResponse>, Status> {
    let req = request.into_inner();
    let name = req.name;
    if name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &req.workspace)
        .await?
        .name;

    let result = state.compute.delete_sandbox(&workspace, &name).await?;
    if result.deleted {
        state.telemetry.end_sandbox_session(&result.sandbox_id);
    }
    info!(sandbox_name = %name, "DeleteSandbox request completed successfully");
    Ok(Response::new(DeleteSandboxResponse {
        deleted: result.deleted,
    }))
}

async fn sandbox_by_name(
    state: &Arc<ServerState>,
    workspace: &str,
    name: &str,
) -> Result<Sandbox, Status> {
    if name.is_empty() {
        return Err(Status::invalid_argument("sandbox_name is required"));
    }

    state
        .store
        .get_message_by_name::<Sandbox>(workspace, name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))
}

async fn providers_for_sandbox(
    state: &Arc<ServerState>,
    sandbox: &Sandbox,
    workspace: &str,
) -> Result<Vec<Provider>, Status> {
    let provider_names = sandbox
        .spec
        .as_ref()
        .map(|spec| spec.providers.as_slice())
        .ok_or_else(|| Status::failed_precondition("sandbox spec is missing"))?;

    let mut providers = Vec::with_capacity(provider_names.len());
    for name in provider_names {
        let provider = get_provider_record(state.store.as_ref(), workspace, name)
            .await
            .map_err(|err| {
                if err.code() == tonic::Code::NotFound {
                    Status::failed_precondition(format!("provider '{name}' not found"))
                } else {
                    err
                }
            })?;
        providers.push(provider);
    }
    Ok(providers)
}

fn dedupe_provider_names(provider_names: &mut Vec<String>) {
    let mut index = 0;
    while index < provider_names.len() {
        if provider_names[..index].contains(&provider_names[index]) {
            provider_names.remove(index);
        } else {
            index += 1;
        }
    }
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
    let event_tail = req.event_tail;

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
                        SandboxPhase::try_from(sandbox.phase()).unwrap_or(SandboxPhase::Unknown);
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
                .tail(&sandbox_id, event_tail as usize)
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
                                        let phase = SandboxPhase::try_from(sandbox.phase()).unwrap_or(SandboxPhase::Unknown);
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
    use openshell_core::ObjectId;

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

    if SandboxPhase::try_from(sandbox.phase()).ok() != Some(SandboxPhase::Ready) {
        return Err(Status::failed_precondition("sandbox is not ready"));
    }

    // Open a relay channel through the supervisor session. Use a 15s
    // session-wait timeout, enough to cover a transient supervisor reconnect
    // while still failing quickly during normal operation.
    let (channel_id, relay_rx) = state
        .supervisor_sessions
        .open_relay(sandbox.object_id(), std::time::Duration::from_secs(15))
        .await
        .map_err(|e| Status::unavailable(format!("supervisor relay failed: {e}")))?;

    let command_str = build_remote_exec_command(&req)
        .map_err(|e| Status::invalid_argument(format!("command construction failed: {e}")))?;
    let stdin_payload = req.stdin;
    let timeout_seconds = req.timeout_seconds;
    let request_tty = req.tty;

    let sandbox_id = sandbox.object_id().to_string();

    let (tx, rx) = mpsc::channel::<Result<ExecSandboxEvent, Status>>(256);
    tokio::spawn(async move {
        // Wait for the supervisor's reverse CONNECT to deliver the relay stream.
        let Some(relay_stream) =
            await_relay_stream(relay_rx, &tx, &sandbox_id, &channel_id, "ExecSandbox").await
        else {
            return;
        };

        if let Err(err) = stream_exec_over_relay(
            tx.clone(),
            &sandbox_id,
            &channel_id,
            relay_stream,
            &command_str,
            stdin_payload,
            timeout_seconds,
            request_tty,
        )
        .await
        {
            warn!(sandbox_id = %sandbox_id, error = %err, "ExecSandbox failed");
            let _ = tx.send(Err(err)).await;
        }
    });

    Ok(Response::new(ReceiverStream::new(rx)))
}

/// Wait for the supervisor's reverse CONNECT to deliver a relay stream.
///
/// Returns `Some(stream)` on success. On any failure the error is sent on `tx`
/// and `None` is returned; the caller should then `return` immediately.
async fn await_relay_stream<T: Send + 'static>(
    relay_rx: oneshot::Receiver<Result<tokio::io::DuplexStream, Status>>,
    tx: &mpsc::Sender<Result<T, Status>>,
    sandbox_id: &str,
    channel_id: &str,
    context: &str,
) -> Option<tokio::io::DuplexStream> {
    match tokio::time::timeout(std::time::Duration::from_secs(10), relay_rx).await {
        Ok(Ok(Ok(stream))) => Some(stream),
        Ok(Ok(Err(status))) => {
            warn!(sandbox_id = %sandbox_id, channel_id = %channel_id, error = %status.message(), "{context}: relay target open failed");
            let _ = tx.send(Err(status)).await;
            None
        }
        Ok(Err(_)) => {
            warn!(sandbox_id = %sandbox_id, channel_id = %channel_id, "{context}: relay channel dropped");
            let _ = tx
                .send(Err(Status::unavailable("relay channel dropped")))
                .await;
            None
        }
        Err(_) => {
            warn!(sandbox_id = %sandbox_id, channel_id = %channel_id, "{context}: relay open timed out");
            let _ = tx
                .send(Err(Status::deadline_exceeded("relay open timed out")))
                .await;
            None
        }
    }
}

pub(super) async fn handle_forward_tcp(
    state: &Arc<ServerState>,
    request: Request<tonic::Streaming<TcpForwardFrame>>,
) -> Result<
    Response<
        Pin<Box<dyn tokio_stream::Stream<Item = Result<TcpForwardFrame, Status>> + Send + 'static>>,
    >,
    Status,
> {
    let mut inbound = request.into_inner();
    let first = inbound
        .message()
        .await?
        .ok_or_else(|| Status::invalid_argument("empty ForwardTcp stream"))?;
    let Some(openshell_core::proto::tcp_forward_frame::Payload::Init(init)) = first.payload else {
        return Err(Status::invalid_argument(
            "first TcpForwardFrame must be init",
        ));
    };

    let target = validate_tcp_forward_init(&init)?;

    let sandbox = state
        .store
        .get_message::<Sandbox>(&init.sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;

    if SandboxPhase::try_from(sandbox.phase()).ok() != Some(SandboxPhase::Ready) {
        return Err(Status::failed_precondition("sandbox is not ready"));
    }

    let connection_guard = acquire_forward_connection_guard(state, &init, &sandbox).await?;
    let (channel_id, relay_rx) = state
        .supervisor_sessions
        .open_relay_with_target(
            sandbox.object_id(),
            target,
            init.service_id.clone(),
            std::time::Duration::from_secs(15),
        )
        .await
        .map_err(|e| Status::unavailable(format!("supervisor relay failed: {e}")))?;

    let sandbox_id = sandbox.object_id().to_string();
    let (tx, rx) = mpsc::channel::<Result<TcpForwardFrame, Status>>(256);
    tokio::spawn(async move {
        let _connection_guard = connection_guard;
        let Some(relay_stream) =
            await_relay_stream(relay_rx, &tx, &sandbox_id, &channel_id, "ForwardTcp").await
        else {
            return;
        };

        bridge_forward_tcp_stream(inbound, relay_stream, tx, &sandbox_id, &channel_id).await;
    });

    let stream: Pin<
        Box<dyn tokio_stream::Stream<Item = Result<TcpForwardFrame, Status>> + Send + 'static>,
    > = Box::pin(ReceiverStream::new(rx));
    Ok(Response::new(stream))
}

struct ForwardConnectionGuard {
    state: Arc<ServerState>,
    token: Option<String>,
    sandbox_id: String,
}

impl Drop for ForwardConnectionGuard {
    fn drop(&mut self) {
        if let Some(token) = self.token.as_deref() {
            decrement_ssh_connection_count(&self.state.ssh_connections_by_token, token);
            decrement_ssh_connection_count(
                &self.state.ssh_connections_by_sandbox,
                &self.sandbox_id,
            );
        }
    }
}

async fn acquire_forward_connection_guard(
    state: &Arc<ServerState>,
    init: &TcpForwardInit,
    sandbox: &Sandbox,
) -> Result<ForwardConnectionGuard, Status> {
    let sandbox_id = sandbox.object_id().to_string();
    let token = init.authorization_token.trim();
    if token.is_empty() {
        return Err(Status::unauthenticated(
            "authorization_token is required for ForwardTcp",
        ));
    }

    validate_ssh_forward_token(state, token, &sandbox_id).await?;
    acquire_ssh_connection_slots(
        &state.ssh_connections_by_token,
        &state.ssh_connections_by_sandbox,
        token,
        &sandbox_id,
    )?;

    Ok(ForwardConnectionGuard {
        state: state.clone(),
        token: Some(token.to_string()),
        sandbox_id,
    })
}

async fn validate_ssh_forward_token(
    state: &Arc<ServerState>,
    token: &str,
    sandbox_id: &str,
) -> Result<(), Status> {
    let session = state
        .store
        .get_message::<SshSession>(token)
        .await
        .map_err(|e| Status::internal(format!("fetch SSH session failed: {e}")))?
        .ok_or_else(|| Status::unauthenticated("SSH session token not found"))?;

    if session.revoked || session.sandbox_id != sandbox_id {
        return Err(Status::unauthenticated("SSH session token is not valid"));
    }

    if session.expires_at_ms > 0 {
        let now_ms = current_time_ms();
        if now_ms > session.expires_at_ms {
            return Err(Status::unauthenticated("SSH session token expired"));
        }
    }

    Ok(())
}

fn acquire_ssh_connection_slots(
    token_counts: &std::sync::Mutex<HashMap<String, u32>>,
    sandbox_counts: &std::sync::Mutex<HashMap<String, u32>>,
    token: &str,
    sandbox_id: &str,
) -> Result<(), Status> {
    const MAX_CONNECTIONS_PER_TOKEN: u32 = 3;
    const MAX_CONNECTIONS_PER_SANDBOX: u32 = 20;

    {
        let mut counts = token_counts.lock().unwrap();
        let count = counts.entry(token.to_string()).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_TOKEN {
            return Err(Status::resource_exhausted(
                "SSH session connection limit reached",
            ));
        }
        *count += 1;
    }

    {
        let mut counts = sandbox_counts.lock().unwrap();
        let count = counts.entry(sandbox_id.to_string()).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_SANDBOX {
            decrement_ssh_connection_count(token_counts, token);
            return Err(Status::resource_exhausted(
                "sandbox SSH connection limit reached",
            ));
        }
        *count += 1;
    }

    Ok(())
}

fn decrement_ssh_connection_count(counts: &std::sync::Mutex<HashMap<String, u32>>, key: &str) {
    let mut counts = counts.lock().unwrap();
    if let Some(count) = counts.get_mut(key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(key);
        }
    }
}

fn validate_tcp_forward_init(init: &TcpForwardInit) -> Result<relay_open::Target, Status> {
    if init.sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }

    if let Some(target) = init.target.as_ref() {
        return match target {
            tcp_forward_init::Target::Ssh(_) => {
                Ok(relay_open::Target::Ssh(SshRelayTarget::default()))
            }
            tcp_forward_init::Target::Tcp(target) => Ok(relay_open::Target::Tcp(
                validate_tcp_forward_target(target)?,
            )),
        };
    }

    Err(Status::invalid_argument("tcp forward target is required"))
}

fn validate_tcp_forward_target(target: &TcpRelayTarget) -> Result<TcpRelayTarget, Status> {
    if target.port == 0 || target.port > u32::from(u16::MAX) {
        return Err(Status::invalid_argument(
            "tcp target port must be between 1 and 65535",
        ));
    }

    validate_tcp_target_parts(target.host.trim(), target.port).map(|host| TcpRelayTarget {
        host,
        port: target.port,
    })
}

fn validate_tcp_target_parts(host: &str, _port: u32) -> Result<String, Status> {
    if host.is_empty() {
        return Err(Status::invalid_argument("tcp target host is required"));
    }
    if host.eq_ignore_ascii_case("localhost") {
        return Ok("127.0.0.1".to_string());
    }

    let ip: IpAddr = host
        .parse()
        .map_err(|_| Status::invalid_argument("tcp target host must be loopback"))?;
    if ip.is_loopback() {
        Ok(ip.to_string())
    } else {
        Err(Status::invalid_argument("tcp target host must be loopback"))
    }
}

async fn bridge_forward_tcp_stream(
    mut inbound: tonic::Streaming<TcpForwardFrame>,
    relay_stream: tokio::io::DuplexStream,
    tx: mpsc::Sender<Result<TcpForwardFrame, Status>>,
    sandbox_id: &str,
    channel_id: &str,
) {
    let (mut relay_read, mut relay_write) = tokio::io::split(relay_stream);

    let sandbox_id_in = sandbox_id.to_string();
    let channel_id_in = channel_id.to_string();
    tokio::spawn(async move {
        loop {
            match inbound.message().await {
                Ok(Some(frame)) => {
                    let Some(openshell_core::proto::tcp_forward_frame::Payload::Data(data)) =
                        frame.payload
                    else {
                        warn!(sandbox_id = %sandbox_id_in, channel_id = %channel_id_in, "ForwardTcp: received non-data frame after init");
                        break;
                    };
                    if data.is_empty() {
                        continue;
                    }
                    if let Err(err) =
                        tokio::io::AsyncWriteExt::write_all(&mut relay_write, &data).await
                    {
                        warn!(sandbox_id = %sandbox_id_in, channel_id = %channel_id_in, error = %err, "ForwardTcp: write to relay failed");
                        break;
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    debug!(sandbox_id = %sandbox_id_in, channel_id = %channel_id_in, error = %err, "ForwardTcp: inbound stream ended");
                    break;
                }
            }
        }
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut relay_write).await;
    });

    let mut buf = vec![0u8; TCP_FORWARD_CHUNK_SIZE];
    loop {
        match tokio::io::AsyncReadExt::read(&mut relay_read, &mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let frame = TcpForwardFrame {
                    payload: Some(openshell_core::proto::tcp_forward_frame::Payload::Data(
                        buf[..n].to_vec(),
                    )),
                };
                if tx.send(Ok(frame)).await.is_err() {
                    break;
                }
            }
            Err(err) => {
                warn!(sandbox_id = %sandbox_id, channel_id = %channel_id, error = %err, "ForwardTcp: read from relay failed");
                let _ = tx
                    .send(Err(Status::unavailable(format!(
                        "relay read failed: {err}"
                    ))))
                    .await;
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Interactive exec handler (bidirectional stdin streaming)
// ---------------------------------------------------------------------------

fn validate_interactive_exec_start(
    msg: Option<ExecSandboxInput>,
) -> Result<ExecSandboxRequest, Status> {
    use openshell_core::proto::exec_sandbox_input::Payload;

    let msg =
        msg.ok_or_else(|| Status::invalid_argument("empty stream: expected start message"))?;

    let Some(Payload::Start(req)) = msg.payload else {
        return Err(Status::invalid_argument(
            "first message must be a start payload",
        ));
    };

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

    Ok(req)
}

pub(super) async fn handle_exec_sandbox_interactive(
    state: &Arc<ServerState>,
    request: Request<tonic::Streaming<ExecSandboxInput>>,
) -> Result<Response<ReceiverStream<Result<ExecSandboxEvent, Status>>>, Status> {
    use openshell_core::ObjectId;

    let mut input_stream = request.into_inner();

    let first_msg = input_stream
        .message()
        .await
        .map_err(|e| Status::internal(format!("failed to read first message: {e}")))?;

    let req = validate_interactive_exec_start(first_msg)?;

    let sandbox = state
        .store
        .get_message::<Sandbox>(&req.sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;

    if SandboxPhase::try_from(sandbox.phase()).ok() != Some(SandboxPhase::Ready) {
        return Err(Status::failed_precondition("sandbox is not ready"));
    }

    let (channel_id, relay_rx) = state
        .supervisor_sessions
        .open_relay(sandbox.object_id(), std::time::Duration::from_secs(15))
        .await
        .map_err(|e| Status::unavailable(format!("supervisor relay failed: {e}")))?;

    let command_str = build_remote_exec_command(&req)
        .map_err(|e| Status::invalid_argument(format!("command construction failed: {e}")))?;
    let request_tty = req.tty;
    let timeout_seconds = req.timeout_seconds;
    let cols = if req.cols == 0 { 80 } else { req.cols };
    let rows = if req.rows == 0 { 24 } else { req.rows };

    let sandbox_id = sandbox.object_id().to_string();

    let (tx, rx) = mpsc::channel::<Result<ExecSandboxEvent, Status>>(256);
    tokio::spawn(async move {
        let Some(relay_stream) = await_relay_stream(
            relay_rx,
            &tx,
            &sandbox_id,
            &channel_id,
            "ExecSandboxInteractive",
        )
        .await
        else {
            return;
        };

        if let Err(err) = stream_interactive_exec_over_relay(
            tx.clone(),
            &sandbox_id,
            &channel_id,
            relay_stream,
            &command_str,
            input_stream,
            request_tty,
            timeout_seconds,
            cols,
            rows,
        )
        .await
        {
            warn!(sandbox_id = %sandbox_id, error = %err, "ExecSandboxInteractive failed");
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

    if SandboxPhase::try_from(sandbox.phase()).ok() != Some(SandboxPhase::Ready) {
        return Err(Status::failed_precondition("sandbox is not ready"));
    }

    let token = uuid::Uuid::new_v4().to_string();
    let now_ms = current_time_ms();
    let expires_at_ms = if state.config.ssh_session_ttl_secs > 0 {
        now_ms + (state.config.ssh_session_ttl_secs as i64 * 1000)
    } else {
        0
    };
    let session = SshSession {
        metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: token.clone(),
            name: generate_name(),
            created_at_ms: now_ms,
            labels: HashMap::new(),
            resource_version: 0,
            annotations: HashMap::new(),
            workspace: sandbox.object_workspace().to_string(),
            deletion_timestamp_ms: 0,
        }),
        sandbox_id: req.sandbox_id.clone(),
        token: token.clone(),
        revoked: false,
        expires_at_ms,
    };

    // Ensure metadata is valid (defense in depth - should always be true for server-constructed metadata)
    super::validation::validate_object_metadata(session.metadata.as_ref(), "ssh_session")?;

    // Use MustCreate to atomically ensure the session token is unique
    let session_labels = session.object_labels();
    let session_labels_json = if session_labels.as_ref().is_none_or(HashMap::is_empty) {
        None
    } else {
        Some(
            serde_json::to_string(&session_labels)
                .map_err(|e| Status::internal(format!("failed to serialize labels: {e}")))?,
        )
    };
    state
        .store
        .put_if(
            SshSession::object_type(),
            &token,
            session.object_name(),
            session.object_workspace(),
            &session.encode_to_vec(),
            session_labels_json.as_deref(),
            WriteCondition::MustCreate,
        )
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

    let resource_version = session
        .metadata
        .as_ref()
        .map_or(0, |metadata| metadata.resource_version);

    session.revoked = true;

    // Use CAS to prevent lost updates from concurrent revocations
    let session_labels = session.object_labels();
    let session_labels_json = if session_labels.as_ref().is_none_or(HashMap::is_empty) {
        None
    } else {
        Some(
            serde_json::to_string(&session_labels)
                .map_err(|e| Status::internal(format!("failed to serialize labels: {e}")))?,
        )
    };
    state
        .store
        .put_if(
            SshSession::object_type(),
            session.object_id(),
            session.object_name(),
            session.object_workspace(),
            &session.encode_to_vec(),
            session_labels_json.as_deref(),
            WriteCondition::MatchResourceVersion(resource_version),
        )
        .await
        .map_err(|e| super::persistence_error_to_status(e, "revoke ssh session"))?;

    Ok(Response::new(RevokeSshSessionResponse { revoked: true }))
}

// ---------------------------------------------------------------------------
// Exec transport helpers
// ---------------------------------------------------------------------------

fn resolve_gateway(config: &openshell_core::Config) -> (String, u16) {
    (
        config.bind_address.ip().to_string(),
        config.bind_address.port(),
    )
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

/// SSH keepalive for silent exec relays; stdout idle is not a timeout signal.
const EXEC_KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// Allow this many missed keepalive responses before russh fails the relay.
const EXEC_KEEPALIVE_MAX: usize = 4;

/// Max wait for a trailing `Close` after `ExitStatus`.
const EXEC_POST_EXIT_CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// russh client config for exec relays.
fn exec_ssh_client_config() -> russh::client::Config {
    russh::client::Config {
        keepalive_interval: Some(EXEC_KEEPALIVE_INTERVAL),
        keepalive_max: EXEC_KEEPALIVE_MAX,
        ..Default::default()
    }
}

/// Treat channel EOF before an exit status as relay failure, not exit code 1.
fn exec_loop_result(exit_code: Option<i32>) -> Result<i32, Status> {
    exit_code.map_or_else(
        || {
            Err(Status::unavailable(
                "exec relay closed before the command reported an exit status",
            ))
        },
        Ok,
    )
}

fn build_remote_exec_command(req: &ExecSandboxRequest) -> Result<String, String> {
    let mut parts = Vec::new();
    let mut env_entries = req.environment.iter().collect::<Vec<_>>();
    env_entries.sort_by_key(|(a, _)| *a);
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

/// Execute a command over an SSH transport relayed through a supervisor session.
///
/// This is the relay equivalent of `stream_exec_over_ssh`. Instead of dialing a
/// sandbox endpoint directly, the SSH transport runs over a `DuplexStream` that
/// is bridged to the supervisor's local SSH daemon via `RelayStream`.
#[allow(clippy::too_many_arguments)]
async fn stream_exec_over_relay(
    tx: mpsc::Sender<Result<ExecSandboxEvent, Status>>,
    sandbox_id: &str,
    channel_id: &str,
    relay_stream: tokio::io::DuplexStream,
    command: &str,
    stdin_payload: Vec<u8>,
    timeout_seconds: u32,
    request_tty: bool,
) -> Result<(), Status> {
    let command_preview: String = command
        .chars()
        .take(120)
        .flat_map(char::escape_default)
        .collect();
    info!(
        sandbox_id = %sandbox_id,
        channel_id = %channel_id,
        command_len = command.len(),
        stdin_len = stdin_payload.len(),
        command_preview = %command_preview,
        "ExecSandbox (relay): command started"
    );

    let (local_proxy_port, proxy_task) = start_single_use_ssh_proxy_over_relay(relay_stream)
        .await
        .map_err(|e| Status::internal(format!("failed to start relay proxy: {e}")))?;

    let exec = run_exec_with_russh(
        local_proxy_port,
        command,
        stdin_payload,
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

    let exit_code = match exec_result {
        Ok(code) => code,
        Err(status) => {
            let _ = proxy_task.await;
            return Err(status);
        }
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

#[allow(clippy::too_many_arguments)]
async fn stream_interactive_exec_over_relay(
    tx: mpsc::Sender<Result<ExecSandboxEvent, Status>>,
    sandbox_id: &str,
    channel_id: &str,
    relay_stream: tokio::io::DuplexStream,
    command: &str,
    input_stream: tonic::Streaming<ExecSandboxInput>,
    request_tty: bool,
    timeout_seconds: u32,
    cols: u32,
    rows: u32,
) -> Result<(), Status> {
    let command_preview: String = command
        .chars()
        .take(120)
        .flat_map(char::escape_default)
        .collect();
    info!(
        sandbox_id = %sandbox_id,
        channel_id = %channel_id,
        command_len = command.len(),
        command_preview = %command_preview,
        "ExecSandboxInteractive (relay): command started"
    );

    let (local_proxy_port, proxy_task) = start_single_use_ssh_proxy_over_relay(relay_stream)
        .await
        .map_err(|e| Status::internal(format!("failed to start relay proxy: {e}")))?;

    let exec = run_interactive_exec_with_russh(
        local_proxy_port,
        command,
        input_stream,
        request_tty,
        cols,
        rows,
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

    let exit_code = match exec_result {
        Ok(code) => code,
        Err(status) => {
            let _ = proxy_task.await;
            return Err(status);
        }
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

async fn run_interactive_exec_with_russh(
    local_proxy_port: u16,
    command: &str,
    mut input_stream: tonic::Streaming<ExecSandboxInput>,
    request_tty: bool,
    cols: u32,
    rows: u32,
    tx: mpsc::Sender<Result<ExecSandboxEvent, Status>>,
) -> Result<i32, Status> {
    use openshell_core::proto::exec_sandbox_input::Payload;
    use russh::ChannelMsg;

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

    let config = Arc::new(exec_ssh_client_config());
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

    let channel = client
        .channel_open_session()
        .await
        .map_err(|e| Status::internal(format!("failed to open ssh channel: {e}")))?;

    if request_tty {
        channel
            .request_pty(false, "xterm-256color", cols, rows, 0, 0, &[])
            .await
            .map_err(|e| Status::internal(format!("failed to allocate PTY: {e}")))?;
    }

    channel
        .exec(true, command.as_bytes())
        .await
        .map_err(|e| Status::internal(format!("failed to execute command over ssh: {e}")))?;

    let (mut read_half, write_half) = channel.split();

    let stdin_task = tokio::spawn(async move {
        while let Ok(Some(msg)) = input_stream.message().await {
            match msg.payload {
                Some(Payload::Stdin(data)) => {
                    if write_half.data(std::io::Cursor::new(data)).await.is_err() {
                        break;
                    }
                }
                Some(Payload::Resize(resize)) => {
                    if request_tty {
                        let _ = write_half
                            .window_change(resize.cols, resize.rows, 0, 0)
                            .await;
                    }
                }
                Some(Payload::Start(_)) | None => {}
            }
        }
        let _ = write_half.eof().await;
        let _ = write_half.close().await;
    });

    let mut exit_code: Option<i32> = None;
    loop {
        // Bound the post-ExitStatus wait against a lost Close.
        let msg = if exit_code.is_some() {
            match tokio::time::timeout(EXEC_POST_EXIT_CLOSE_TIMEOUT, read_half.wait()).await {
                Ok(Some(msg)) => msg,
                Ok(None) | Err(_) => break,
            }
        } else {
            match read_half.wait().await {
                Some(msg) => msg,
                None => break,
            }
        };
        match msg {
            ChannelMsg::Data { data } => {
                let event = Ok(ExecSandboxEvent {
                    payload: Some(openshell_core::proto::exec_sandbox_event::Payload::Stdout(
                        ExecSandboxStdout {
                            data: data.to_vec(),
                        },
                    )),
                });
                if tx.send(event).await.is_err() {
                    break;
                }
            }
            ChannelMsg::ExtendedData { data, .. } => {
                let event = Ok(ExecSandboxEvent {
                    payload: Some(openshell_core::proto::exec_sandbox_event::Payload::Stderr(
                        ExecSandboxStderr {
                            data: data.to_vec(),
                        },
                    )),
                });
                if tx.send(event).await.is_err() {
                    break;
                }
            }
            ChannelMsg::ExitStatus { exit_status } => {
                let converted = i32::try_from(exit_status).unwrap_or(i32::MAX);
                exit_code = Some(converted);
            }
            ChannelMsg::Close => break,
            _ => {}
        }
    }

    stdin_task.abort();

    let _ = client
        .disconnect(russh::Disconnect::ByApplication, "exec complete", "en")
        .await;

    exec_loop_result(exit_code)
}

/// Create a localhost SSH proxy that bridges to a relay `DuplexStream`.
///
/// The proxy forwards raw SSH bytes between the `russh` client and the relay.
/// The supervisor bridges the relay to its Unix-socket SSH daemon; filesystem
/// permissions on that socket are the only access-control boundary.
async fn start_single_use_ssh_proxy_over_relay(
    mut relay_stream: tokio::io::DuplexStream,
) -> Result<(u16, tokio::task::JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();

    let task = tokio::spawn(async move {
        let Ok((mut client_conn, _)) = listener.accept().await else {
            warn!("SSH relay proxy: failed to accept local connection");
            return;
        };
        let _ = tokio::io::copy_bidirectional(&mut client_conn, &mut relay_stream).await;
    });

    Ok((port, task))
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

    let config = Arc::new(exec_ssh_client_config());
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
    loop {
        // Bound the post-ExitStatus wait against a lost Close.
        let msg = if exit_code.is_some() {
            match tokio::time::timeout(EXEC_POST_EXIT_CLOSE_TIMEOUT, channel.wait()).await {
                Ok(Some(msg)) => msg,
                Ok(None) | Err(_) => break,
            }
        } else {
            match channel.wait().await {
                Some(msg) => msg,
                None => break,
            }
        };
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

    exec_loop_result(exit_code)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::test_support::test_server_state;
    use openshell_core::proto::datamodel::v1::ObjectMeta;

    // ---- shell_escape ----

    #[test]
    fn telemetry_compute_driver_uses_resolved_driver_kind() {
        assert_eq!(
            telemetry_compute_driver(Some(openshell_core::ComputeDriverKind::Docker)),
            TelemetryComputeDriver::Docker
        );
        assert_eq!(
            telemetry_compute_driver(Some(openshell_core::ComputeDriverKind::Kubernetes)),
            TelemetryComputeDriver::Kubernetes
        );
        assert_eq!(
            telemetry_compute_driver(Some(openshell_core::ComputeDriverKind::Podman)),
            TelemetryComputeDriver::Podman
        );
        assert_eq!(
            telemetry_compute_driver(Some(openshell_core::ComputeDriverKind::Vm)),
            TelemetryComputeDriver::Vm
        );
        assert_eq!(
            telemetry_compute_driver(None),
            TelemetryComputeDriver::Unknown
        );
    }

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
    fn shell_escape_allows_newlines() {
        assert!(shell_escape("line1\nline2").is_ok());
        assert!(shell_escape("line1\rline2").is_ok());
        assert!(shell_escape("line1\r\nline2").is_ok());
    }

    #[test]
    fn shell_escape_preserves_newlines_in_single_quotes() {
        assert_eq!(shell_escape("line1\nline2").unwrap(), "'line1\nline2'");
        assert_eq!(
            shell_escape("def f():\n    return 1").unwrap(),
            "'def f():\n    return 1'"
        );
        assert_eq!(shell_escape("line1\r\nline2").unwrap(), "'line1\r\nline2'");
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
            environment: std::iter::once(("HOME".to_string(), "/home/user".to_string())).collect(),
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
        // Validation layer rejects newlines in workdir
        assert!(validate_exec_request_fields(&req).is_err());
    }

    #[test]
    fn build_remote_exec_command_accepts_multiline_script() {
        use openshell_core::proto::ExecSandboxRequest;
        let req = ExecSandboxRequest {
            sandbox_id: "test".to_string(),
            command: vec![
                "python3".to_string(),
                "-c".to_string(),
                "def f():\n    return 1\nprint(f())".to_string(),
            ],
            ..Default::default()
        };
        let cmd = build_remote_exec_command(&req).unwrap();
        assert!(cmd.starts_with("python3 -c "));
        assert!(cmd.contains("'def f():\n    return 1\nprint(f())'"));
    }

    #[test]
    fn build_remote_exec_command_multiline_with_single_quotes() {
        use openshell_core::proto::ExecSandboxRequest;
        let req = ExecSandboxRequest {
            sandbox_id: "test".to_string(),
            command: vec![
                "python3".to_string(),
                "-c".to_string(),
                "print('one')\r\nprint('two')".to_string(),
            ],
            ..Default::default()
        };
        let cmd = build_remote_exec_command(&req).unwrap();
        assert!(cmd.starts_with("python3 -c "));
        assert!(
            cmd.contains("'print('\"'\"'one'\"'\"')\r\nprint('\"'\"'two'\"'\"')'"),
            "CR/LF with embedded single quotes must compose correctly: {cmd}"
        );
    }

    #[test]
    fn tcp_forward_init_allows_loopback_targets() {
        for host in ["127.0.0.1", "::1", "localhost"] {
            let init = TcpForwardInit {
                sandbox_id: "sbx".to_string(),
                service_id: String::new(),
                target: Some(tcp_forward_init::Target::Tcp(TcpRelayTarget {
                    host: host.to_string(),
                    port: 8080,
                })),
                authorization_token: String::new(),
            };
            validate_tcp_forward_init(&init).expect("loopback target should pass");
        }
    }

    #[test]
    fn tcp_forward_init_allows_ssh_target() {
        let init = TcpForwardInit {
            sandbox_id: "sbx".to_string(),
            target: Some(tcp_forward_init::Target::Ssh(SshRelayTarget::default())),
            ..Default::default()
        };
        match validate_tcp_forward_init(&init).expect("ssh target should pass") {
            relay_open::Target::Ssh(_) => {}
            other @ relay_open::Target::Tcp(_) => panic!("expected SSH target, got {other:?}"),
        }
    }

    #[test]
    fn tcp_forward_init_rejects_non_loopback_targets() {
        let init = TcpForwardInit {
            sandbox_id: "sbx".to_string(),
            service_id: String::new(),
            target: Some(tcp_forward_init::Target::Tcp(TcpRelayTarget {
                host: "example.com".to_string(),
                port: 8080,
            })),
            authorization_token: String::new(),
        };
        assert_eq!(
            validate_tcp_forward_init(&init)
                .expect_err("hostname rejected")
                .message(),
            "tcp target host must be loopback"
        );
    }

    #[test]
    fn tcp_forward_init_rejects_invalid_port() {
        let init = TcpForwardInit {
            sandbox_id: "sbx".to_string(),
            service_id: String::new(),
            target: Some(tcp_forward_init::Target::Tcp(TcpRelayTarget {
                host: "127.0.0.1".to_string(),
                port: 0,
            })),
            authorization_token: String::new(),
        };
        assert_eq!(
            validate_tcp_forward_init(&init)
                .expect_err("zero port rejected")
                .message(),
            "tcp target port must be between 1 and 65535"
        );
    }

    #[test]
    fn tcp_forward_init_requires_target() {
        let init = TcpForwardInit {
            sandbox_id: "sbx".to_string(),
            ..Default::default()
        };
        assert_eq!(
            validate_tcp_forward_init(&init)
                .expect_err("missing target rejected")
                .message(),
            "tcp forward target is required"
        );
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
    fn generate_routable_name_respects_length_limit() {
        for _ in 0..200 {
            let name = generate_routable_name();
            assert!(
                name.len() <= MAX_ROUTABLE_NAME_LEN,
                "generated name '{name}' exceeds {MAX_ROUTABLE_NAME_LEN} chars"
            );
            assert!(!name.is_empty(), "generated name should not be empty");
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

    fn test_provider(name: &str, provider_type: &str) -> Provider {
        test_provider_with_credential_key(name, provider_type, "TOKEN")
    }

    fn test_provider_with_credential_key(
        name: &str,
        provider_type: &str,
        credential_key: &str,
    ) -> Provider {
        Provider {
            metadata: Some(ObjectMeta {
                id: format!("provider-{name}"),
                name: name.to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            r#type: provider_type.to_string(),
            credentials: std::iter::once((credential_key.to_string(), "secret".to_string()))
                .collect(),
            config: HashMap::new(),
            credential_expires_at_ms: HashMap::new(),
            profile_workspace: "default".to_string(),
        }
    }

    fn test_sandbox(name: &str, providers: Vec<String>) -> Sandbox {
        let mut sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: format!("sandbox-{name}"),
                name: name.to_string(),
                created_at_ms: 1_000_000,
                labels: std::iter::once(("team".to_string(), "agents".to_string())).collect(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            spec: Some(openshell_core::proto::SandboxSpec {
                log_level: "debug".to_string(),
                policy: Some(openshell_core::proto::SandboxPolicy::default()),
                providers,
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        sandbox.set_current_policy_version(7);
        sandbox
    }

    #[tokio::test]
    async fn delete_handler_ends_telemetry_for_the_resolved_sandbox_id() {
        let state = test_server_state().await;
        let mut original = test_sandbox("reused-name", Vec::new());
        original.metadata.as_mut().unwrap().id = "sandbox-original".to_string();
        state.store.put_message(&original).await.unwrap();

        // Hold the global guard so the handler can resolve the original ID and
        // acquire its delete gate, but cannot yet revalidate or mutate it.
        let global_guard = state.compute.sandbox_sync_guard().await;
        let delete_state = state.clone();
        let delete = tokio::spawn(async move {
            handle_delete_sandbox_inner(
                &delete_state,
                Request::new(DeleteSandboxRequest {
                    name: "reused-name".to_string(),
                    workspace: "default".to_string(),
                }),
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while state.compute.delete_gate_entry_count() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("delete did not resolve and acquire the original sandbox gate");

        state
            .store
            .delete(Sandbox::object_type(), original.object_id())
            .await
            .unwrap();
        let mut replacement = test_sandbox("reused-name", Vec::new());
        replacement.metadata.as_mut().unwrap().id = "sandbox-replacement".to_string();
        state.store.put_message(&replacement).await.unwrap();
        drop(global_guard);

        let response = delete.await.unwrap().unwrap().into_inner();
        assert!(response.deleted);
        assert!(
            state
                .store
                .get_message::<Sandbox>(replacement.object_id())
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            state.telemetry.ended_sandbox_sessions(),
            [original.object_id().to_string()]
        );
    }

    #[tokio::test]
    async fn attach_sandbox_provider_persists_current_provider_list() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox("work", Vec::new()))
            .await
            .unwrap();

        let response = handle_attach_sandbox_provider(
            &state,
            Request::new(AttachSandboxProviderRequest {
                sandbox_name: "work".to_string(),
                provider_name: "work-github".to_string(),
                expected_resource_version: 0,
                workspace: String::new(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(response.attached);
        let sandbox = state
            .store
            .get_message_by_name::<Sandbox>("default", "work")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sandbox.phase(), SandboxPhase::Ready as i32);
        assert_eq!(sandbox.current_policy_version(), 7);
        let spec = sandbox.spec.unwrap();
        assert_eq!(spec.providers, vec!["work-github"]);
        assert_eq!(spec.log_level, "debug");
    }

    #[tokio::test]
    async fn attach_sandbox_provider_is_idempotent_and_avoids_duplicates() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox(
                "work",
                vec!["work-github".to_string(), "work-github".to_string()],
            ))
            .await
            .unwrap();

        let response = handle_attach_sandbox_provider(
            &state,
            Request::new(AttachSandboxProviderRequest {
                sandbox_name: "work".to_string(),
                provider_name: "work-github".to_string(),
                expected_resource_version: 0,
                workspace: String::new(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(!response.attached);
        let providers = state
            .store
            .get_message_by_name::<Sandbox>("default", "work")
            .await
            .unwrap()
            .unwrap()
            .spec
            .unwrap()
            .providers;
        assert_eq!(providers, vec!["work-github"]);
    }

    #[tokio::test]
    async fn detach_sandbox_provider_is_idempotent_and_removes_all_matches() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_sandbox(
                "work",
                vec![
                    "work-github".to_string(),
                    "other".to_string(),
                    "work-github".to_string(),
                ],
            ))
            .await
            .unwrap();

        let response = handle_detach_sandbox_provider(
            &state,
            Request::new(DetachSandboxProviderRequest {
                sandbox_name: "work".to_string(),
                provider_name: "work-github".to_string(),
                expected_resource_version: 0,
                workspace: String::new(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(response.detached);
        let providers = state
            .store
            .get_message_by_name::<Sandbox>("default", "work")
            .await
            .unwrap()
            .unwrap()
            .spec
            .unwrap()
            .providers;
        assert_eq!(providers, vec!["other"]);

        let response = handle_detach_sandbox_provider(
            &state,
            Request::new(DetachSandboxProviderRequest {
                sandbox_name: "work".to_string(),
                provider_name: "work-github".to_string(),
                expected_resource_version: 0,
                workspace: String::new(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(!response.detached);
    }

    #[tokio::test]
    async fn list_sandbox_providers_returns_attached_provider_records() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox("work", vec!["work-github".to_string()]))
            .await
            .unwrap();

        let response = handle_list_sandbox_providers(
            &state,
            Request::new(ListSandboxProvidersRequest {
                sandbox_name: "work".to_string(),
                workspace: String::new(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(response.providers.len(), 1);
        assert_eq!(response.providers[0].r#type, "github");
        assert_eq!(
            response.providers[0].credentials.get("TOKEN"),
            Some(&"REDACTED".to_string())
        );
    }

    #[tokio::test]
    async fn attach_sandbox_provider_validates_provider_exists() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_sandbox("work", Vec::new()))
            .await
            .unwrap();

        let err = handle_attach_sandbox_provider(
            &state,
            Request::new(AttachSandboxProviderRequest {
                sandbox_name: "work".to_string(),
                provider_name: "missing".to_string(),
                expected_resource_version: 0,
                workspace: String::new(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    // ---- validate_interactive_exec_start ----

    #[test]
    fn interactive_exec_rejects_empty_stream() {
        let err = validate_interactive_exec_start(None).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("expected start message"));
    }

    #[test]
    fn interactive_exec_rejects_stdin_as_first_message() {
        use openshell_core::proto::exec_sandbox_input;
        let msg = ExecSandboxInput {
            payload: Some(exec_sandbox_input::Payload::Stdin(b"hello".to_vec())),
        };
        let err = validate_interactive_exec_start(Some(msg)).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("start payload"));
    }

    #[test]
    fn interactive_exec_rejects_resize_as_first_message() {
        use openshell_core::proto::{ExecSandboxWindowResize, exec_sandbox_input};
        let msg = ExecSandboxInput {
            payload: Some(exec_sandbox_input::Payload::Resize(
                ExecSandboxWindowResize { cols: 80, rows: 24 },
            )),
        };
        let err = validate_interactive_exec_start(Some(msg)).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("start payload"));
    }

    #[test]
    fn interactive_exec_rejects_none_payload() {
        let msg = ExecSandboxInput { payload: None };
        let err = validate_interactive_exec_start(Some(msg)).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn interactive_exec_rejects_missing_sandbox_id() {
        use openshell_core::proto::exec_sandbox_input;
        let msg = ExecSandboxInput {
            payload: Some(exec_sandbox_input::Payload::Start(ExecSandboxRequest {
                command: vec!["bash".to_string()],
                ..Default::default()
            })),
        };
        let err = validate_interactive_exec_start(Some(msg)).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("sandbox_id"));
    }

    #[test]
    fn interactive_exec_rejects_missing_command() {
        use openshell_core::proto::exec_sandbox_input;
        let msg = ExecSandboxInput {
            payload: Some(exec_sandbox_input::Payload::Start(ExecSandboxRequest {
                sandbox_id: "test-id".to_string(),
                ..Default::default()
            })),
        };
        let err = validate_interactive_exec_start(Some(msg)).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("command"));
    }

    #[test]
    fn interactive_exec_rejects_invalid_env_key() {
        use openshell_core::proto::exec_sandbox_input;
        let msg = ExecSandboxInput {
            payload: Some(exec_sandbox_input::Payload::Start(ExecSandboxRequest {
                sandbox_id: "test-id".to_string(),
                command: vec!["bash".to_string()],
                environment: std::iter::once(("bad key!".to_string(), "val".to_string())).collect(),
                ..Default::default()
            })),
        };
        let err = validate_interactive_exec_start(Some(msg)).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("environment"));
    }

    #[test]
    fn interactive_exec_accepts_valid_start() {
        use openshell_core::proto::exec_sandbox_input;
        let msg = ExecSandboxInput {
            payload: Some(exec_sandbox_input::Payload::Start(ExecSandboxRequest {
                sandbox_id: "test-id".to_string(),
                command: vec!["bash".to_string()],
                tty: true,
                cols: 120,
                rows: 40,
                ..Default::default()
            })),
        };
        let req = validate_interactive_exec_start(Some(msg)).unwrap();
        assert_eq!(req.sandbox_id, "test-id");
        assert_eq!(req.command, vec!["bash"]);
        assert!(req.tty);
        assert_eq!(req.cols, 120);
        assert_eq!(req.rows, 40);
    }

    #[tokio::test]
    async fn interactive_exec_rejects_sandbox_not_found() {
        let state = test_server_state().await;

        let req = ExecSandboxRequest {
            sandbox_id: "nonexistent".to_string(),
            command: vec!["bash".to_string()],
            tty: true,
            ..Default::default()
        };
        let sandbox_result = state
            .store
            .get_message::<Sandbox>(&req.sandbox_id)
            .await
            .unwrap();
        assert!(sandbox_result.is_none());
    }

    #[tokio::test]
    async fn interactive_exec_rejects_sandbox_not_ready() {
        let state = test_server_state().await;
        let mut sandbox = test_sandbox("not-ready", Vec::new());
        sandbox.set_phase(SandboxPhase::Provisioning as i32);
        state.store.put_message(&sandbox).await.unwrap();

        let stored = state
            .store
            .get_message::<Sandbox>("sandbox-not-ready")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            SandboxPhase::try_from(stored.phase()).ok(),
            Some(SandboxPhase::Ready)
        );
    }

    #[tokio::test]
    async fn create_sandbox_rejects_provider_credential_key_collisions() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("provider-a", "outlook"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_provider("provider-b", "google-drive"))
            .await
            .unwrap();

        let err = handle_create_sandbox(
            &state,
            Request::new(CreateSandboxRequest {
                name: "collision".to_string(),
                spec: Some(openshell_core::proto::SandboxSpec {
                    providers: vec!["provider-a".to_string(), "provider-b".to_string()],
                    ..Default::default()
                }),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace: String::new(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("TOKEN"));
        assert!(err.message().contains("provider-a"));
        assert!(err.message().contains("provider-b"));
    }

    #[tokio::test]
    async fn create_sandbox_rejects_reserved_provider_policy_key() {
        let state = test_server_state().await;
        let mut policy = openshell_core::proto::SandboxPolicy::default();
        policy.network_policies.insert(
            "_provider_work_github".to_string(),
            openshell_core::proto::NetworkPolicyRule {
                name: "_provider_work_github".to_string(),
                ..Default::default()
            },
        );

        let err = handle_create_sandbox(
            &state,
            Request::new(CreateSandboxRequest {
                name: "reserved-policy-key".to_string(),
                spec: Some(openshell_core::proto::SandboxSpec {
                    policy: Some(policy),
                    ..Default::default()
                }),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace: String::new(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("_provider_work_github"));
        assert!(err.message().contains("reserved '_provider_' prefix"));
    }

    #[tokio::test]
    async fn create_sandbox_persists_long_metadata_annotations() {
        let state = test_server_state().await;
        let annotation_key = "openshell.nvidia.com/policy-signature".to_string();
        let annotation_value = "x".repeat(512);

        let response = handle_create_sandbox(
            &state,
            Request::new(CreateSandboxRequest {
                name: "annotated".to_string(),
                spec: Some(openshell_core::proto::SandboxSpec::default()),
                labels: HashMap::new(),
                annotations: HashMap::from([(annotation_key.clone(), annotation_value.clone())]),
                workspace: String::new(),
            }),
        )
        .await
        .expect("long annotations should be accepted")
        .into_inner();

        let created = response.sandbox.expect("created sandbox");
        assert_eq!(
            created
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.annotations.get(&annotation_key)),
            Some(&annotation_value)
        );

        let fetched = handle_get_sandbox(
            &state,
            Request::new(GetSandboxRequest {
                name: "annotated".to_string(),
                workspace: String::new(),
            }),
        )
        .await
        .expect("created sandbox should be fetchable")
        .into_inner()
        .sandbox
        .expect("fetched sandbox");
        assert_eq!(
            fetched
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.annotations.get(&annotation_key)),
            Some(&annotation_value)
        );
    }

    #[tokio::test]
    async fn create_sandbox_still_rejects_long_label_values() {
        let state = test_server_state().await;
        let err = handle_create_sandbox(
            &state,
            Request::new(CreateSandboxRequest {
                name: "bad-label".to_string(),
                spec: Some(openshell_core::proto::SandboxSpec::default()),
                labels: HashMap::from([("team".to_string(), "x".repeat(512))]),
                annotations: HashMap::new(),
                workspace: String::new(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("label value exceeds"));
    }

    #[tokio::test]
    async fn create_sandbox_with_providers_waits_for_sandbox_sync_guard() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();

        let guard = state.compute.sandbox_sync_guard().await;
        let task_state = state.clone();
        let task = tokio::spawn(async move {
            handle_create_sandbox(
                &task_state,
                Request::new(CreateSandboxRequest {
                    name: "guarded-create".to_string(),
                    spec: Some(openshell_core::proto::SandboxSpec {
                        providers: vec!["work-github".to_string()],
                        ..Default::default()
                    }),
                    labels: HashMap::new(),
                    annotations: HashMap::new(),
                    workspace: String::new(),
                }),
            )
            .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            !task.is_finished(),
            "sandbox create with initial providers should wait for sandbox sync guard"
        );
        drop(guard);

        let response = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("create should finish after guard release")
            .expect("join create task")
            .expect("create should succeed")
            .into_inner();
        assert_eq!(
            response.sandbox.unwrap().spec.unwrap().providers,
            vec!["work-github".to_string()]
        );
    }

    #[tokio::test]
    async fn attach_sandbox_provider_rejects_credential_key_collisions() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("provider-a", "outlook"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_provider("provider-b", "google-drive"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox("work", vec!["provider-a".to_string()]))
            .await
            .unwrap();

        let err = handle_attach_sandbox_provider(
            &state,
            Request::new(AttachSandboxProviderRequest {
                sandbox_name: "work".to_string(),
                provider_name: "provider-b".to_string(),
                expected_resource_version: 0,
                workspace: String::new(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("TOKEN"));
        assert!(err.message().contains("provider-a"));
        assert!(err.message().contains("provider-b"));
    }

    #[tokio::test]
    async fn attach_sandbox_provider_accepts_at_max_providers_limit() {
        let state = test_server_state().await;

        // Create MAX_PROVIDERS (32) providers
        for i in 0..MAX_PROVIDERS {
            state
                .store
                .put_message(&test_provider_with_credential_key(
                    &format!("provider-{i}"),
                    "generic",
                    &format!("TOKEN_{i}"),
                ))
                .await
                .unwrap();
        }

        // Create sandbox with 31 providers already attached
        let mut existing_providers = Vec::new();
        for i in 0..(MAX_PROVIDERS - 1) {
            existing_providers.push(format!("provider-{i}"));
        }
        state
            .store
            .put_message(&test_sandbox("work", existing_providers))
            .await
            .unwrap();

        // Attaching the 32nd provider should succeed
        let response = handle_attach_sandbox_provider(
            &state,
            Request::new(AttachSandboxProviderRequest {
                sandbox_name: "work".to_string(),
                provider_name: "provider-31".to_string(),
                expected_resource_version: 0,
                workspace: String::new(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(response.attached);
        let providers = state
            .store
            .get_message_by_name::<Sandbox>("default", "work")
            .await
            .unwrap()
            .unwrap()
            .spec
            .unwrap()
            .providers;
        assert_eq!(providers.len(), MAX_PROVIDERS);
    }

    #[tokio::test]
    async fn attach_sandbox_provider_rejects_beyond_max_providers_limit() {
        let state = test_server_state().await;

        // Create MAX_PROVIDERS + 1 providers
        for i in 0..=MAX_PROVIDERS {
            state
                .store
                .put_message(&test_provider_with_credential_key(
                    &format!("provider-{i}"),
                    "generic",
                    &format!("TOKEN_{i}"),
                ))
                .await
                .unwrap();
        }

        // Create sandbox with MAX_PROVIDERS already attached
        let mut existing_providers = Vec::new();
        for i in 0..MAX_PROVIDERS {
            existing_providers.push(format!("provider-{i}"));
        }
        state
            .store
            .put_message(&test_sandbox("work", existing_providers))
            .await
            .unwrap();

        // Attempting to attach the 33rd provider should fail
        let err = handle_attach_sandbox_provider(
            &state,
            Request::new(AttachSandboxProviderRequest {
                sandbox_name: "work".to_string(),
                provider_name: "provider-32".to_string(),
                expected_resource_version: 0,
                workspace: String::new(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("exceeds maximum"));

        // Verify sandbox was not modified
        let providers = state
            .store
            .get_message_by_name::<Sandbox>("default", "work")
            .await
            .unwrap()
            .unwrap()
            .spec
            .unwrap()
            .providers;
        assert_eq!(providers.len(), MAX_PROVIDERS);
    }

    #[tokio::test]
    async fn attach_sandbox_provider_pre_validation_fails_fast() {
        let state = test_server_state().await;

        // Provider name that exceeds validation limits
        let long_name = "a".repeat(1000);
        state
            .store
            .put_message(&test_provider(&long_name, "generic"))
            .await
            .unwrap();

        state
            .store
            .put_message(&test_sandbox("work", Vec::new()))
            .await
            .unwrap();

        // Should fail validation before attempting CAS
        let err = handle_attach_sandbox_provider(
            &state,
            Request::new(AttachSandboxProviderRequest {
                sandbox_name: "work".to_string(),
                provider_name: long_name,
                expected_resource_version: 0,
                workspace: String::new(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn detach_sandbox_provider_pre_validation_rejects_invalid_names() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_sandbox("work", vec!["valid".to_string()]))
            .await
            .unwrap();

        // Provider name that exceeds validation limits
        let long_name = "a".repeat(1000);

        let err = handle_detach_sandbox_provider(
            &state,
            Request::new(DetachSandboxProviderRequest {
                sandbox_name: "work".to_string(),
                provider_name: long_name,
                expected_resource_version: 0,
                workspace: String::new(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn concurrent_create_ssh_session_prevents_duplicate_tokens() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_sandbox("work", Vec::new()))
            .await
            .unwrap();

        // Both requests try to create sessions for the same sandbox
        // The token generation is random, so we can't force a collision,
        // but we can verify that both succeed with different tokens
        let state1 = state.clone();
        let handle1 = tokio::spawn(async move {
            handle_create_ssh_session(
                &state1,
                Request::new(CreateSshSessionRequest {
                    sandbox_id: "sandbox-work".to_string(),
                }),
            )
            .await
        });

        let state2 = state.clone();
        let handle2 = tokio::spawn(async move {
            handle_create_ssh_session(
                &state2,
                Request::new(CreateSshSessionRequest {
                    sandbox_id: "sandbox-work".to_string(),
                }),
            )
            .await
        });

        let result1 = handle1.await.unwrap();
        let result2 = handle2.await.unwrap();

        // Both should succeed (tokens are random UUIDs, collision is astronomically unlikely)
        assert!(result1.is_ok(), "first create should succeed");
        assert!(result2.is_ok(), "second create should succeed");

        let token1 = result1.unwrap().into_inner().token;
        let token2 = result2.unwrap().into_inner().token;

        // Tokens must be different
        assert_ne!(token1, token2, "tokens should be unique");

        // Both sessions should be in the database
        let session1 = state
            .store
            .get_message::<SshSession>(&token1)
            .await
            .unwrap();
        let session2 = state
            .store
            .get_message::<SshSession>(&token2)
            .await
            .unwrap();
        assert!(session1.is_some());
        assert!(session2.is_some());
    }

    #[tokio::test]
    async fn concurrent_revoke_ssh_session_handles_cas_properly() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_sandbox("work", Vec::new()))
            .await
            .unwrap();

        // Create a session first
        let response = handle_create_ssh_session(
            &state,
            Request::new(CreateSshSessionRequest {
                sandbox_id: "sandbox-work".to_string(),
            }),
        )
        .await
        .unwrap();
        let token = response.into_inner().token;

        // Spawn two concurrent revocation attempts
        let state1 = state.clone();
        let token1 = token.clone();
        let handle1 = tokio::spawn(async move {
            handle_revoke_ssh_session(
                &state1,
                Request::new(RevokeSshSessionRequest { token: token1 }),
            )
            .await
        });

        let state2 = state.clone();
        let token2 = token.clone();
        let handle2 = tokio::spawn(async move {
            handle_revoke_ssh_session(
                &state2,
                Request::new(RevokeSshSessionRequest { token: token2 }),
            )
            .await
        });

        let result1 = handle1.await.unwrap();
        let result2 = handle2.await.unwrap();

        // One should succeed, one may fail with ABORTED due to CAS conflict
        let successes = [&result1, &result2]
            .iter()
            .filter(|r| r.is_ok() && r.as_ref().unwrap().get_ref().revoked)
            .count();

        // At least one should succeed in revoking
        assert!(
            successes >= 1,
            "at least one revocation should succeed, got: {result1:?}, {result2:?}"
        );

        // The session should be revoked in the database
        let session = state.store.get_message::<SshSession>(&token).await.unwrap();
        assert!(session.is_some());
        assert!(session.unwrap().revoked, "session should be revoked");
    }

    // ---- CAS (Client-driven optimistic concurrency) tests ----

    #[tokio::test]
    async fn attach_sandbox_provider_client_driven_cas_succeeds_with_correct_version() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("github", "github"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox("work", Vec::new()))
            .await
            .unwrap();

        // Fetch the sandbox to get its current resource_version
        let sandbox = state
            .store
            .get_message_by_name::<Sandbox>("default", "work")
            .await
            .unwrap()
            .unwrap();
        let current_version = sandbox.metadata.as_ref().unwrap().resource_version;

        // Attach with correct expected_resource_version
        let response = handle_attach_sandbox_provider(
            &state,
            Request::new(AttachSandboxProviderRequest {
                sandbox_name: "work".to_string(),
                provider_name: "github".to_string(),
                expected_resource_version: current_version,
                workspace: String::new(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(response.attached);

        // Verify the resource_version incremented
        let updated_sandbox = state
            .store
            .get_message_by_name::<Sandbox>("default", "work")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            updated_sandbox.metadata.as_ref().unwrap().resource_version,
            current_version + 1
        );
    }

    #[tokio::test]
    async fn attach_sandbox_provider_client_driven_cas_rejects_stale_version() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("github", "github"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox("work", Vec::new()))
            .await
            .unwrap();

        // Get current version
        let sandbox = state
            .store
            .get_message_by_name::<Sandbox>("default", "work")
            .await
            .unwrap()
            .unwrap();
        let current_version = sandbox.metadata.as_ref().unwrap().resource_version;

        // Try to attach with a stale version (current_version - 1 would be 0, use 99 instead)
        let err = handle_attach_sandbox_provider(
            &state,
            Request::new(AttachSandboxProviderRequest {
                sandbox_name: "work".to_string(),
                provider_name: "github".to_string(),
                expected_resource_version: 99,
                workspace: String::new(),
            }),
        )
        .await
        .unwrap_err();

        // Should get ABORTED status for CAS conflict
        assert_eq!(err.code(), tonic::Code::Aborted);
        assert!(
            err.message().contains("modified concurrently")
                || err.message().contains("resource_version"),
            "error message should mention concurrency conflict: {}",
            err.message()
        );

        // Verify the sandbox was not modified
        let unchanged_sandbox = state
            .store
            .get_message_by_name::<Sandbox>("default", "work")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            unchanged_sandbox
                .metadata
                .as_ref()
                .unwrap()
                .resource_version,
            current_version
        );
        assert!(unchanged_sandbox.spec.unwrap().providers.is_empty());
    }

    #[tokio::test]
    async fn detach_sandbox_provider_client_driven_cas_succeeds_with_correct_version() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("github", "github"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox("work", vec!["github".to_string()]))
            .await
            .unwrap();

        // Fetch the sandbox to get its current resource_version
        let sandbox = state
            .store
            .get_message_by_name::<Sandbox>("default", "work")
            .await
            .unwrap()
            .unwrap();
        let current_version = sandbox.metadata.as_ref().unwrap().resource_version;

        // Detach with correct expected_resource_version
        let response = handle_detach_sandbox_provider(
            &state,
            Request::new(DetachSandboxProviderRequest {
                sandbox_name: "work".to_string(),
                provider_name: "github".to_string(),
                expected_resource_version: current_version,
                workspace: String::new(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert!(response.detached);

        // Verify the resource_version incremented
        let updated_sandbox = state
            .store
            .get_message_by_name::<Sandbox>("default", "work")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            updated_sandbox.metadata.as_ref().unwrap().resource_version,
            current_version + 1
        );
    }

    #[tokio::test]
    async fn detach_sandbox_provider_client_driven_cas_rejects_stale_version() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("github", "github"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox("work", vec!["github".to_string()]))
            .await
            .unwrap();

        // Get current version
        let sandbox = state
            .store
            .get_message_by_name::<Sandbox>("default", "work")
            .await
            .unwrap()
            .unwrap();
        let current_version = sandbox.metadata.as_ref().unwrap().resource_version;

        // Try to detach with a stale version
        let err = handle_detach_sandbox_provider(
            &state,
            Request::new(DetachSandboxProviderRequest {
                sandbox_name: "work".to_string(),
                provider_name: "github".to_string(),
                expected_resource_version: 99,
                workspace: String::new(),
            }),
        )
        .await
        .unwrap_err();

        // Should get ABORTED status for CAS conflict
        assert_eq!(err.code(), tonic::Code::Aborted);
        assert!(
            err.message().contains("modified concurrently")
                || err.message().contains("resource_version"),
            "error message should mention concurrency conflict: {}",
            err.message()
        );

        // Verify the sandbox was not modified
        let unchanged_sandbox = state
            .store
            .get_message_by_name::<Sandbox>("default", "work")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            unchanged_sandbox
                .metadata
                .as_ref()
                .unwrap()
                .resource_version,
            current_version
        );
        assert_eq!(unchanged_sandbox.spec.unwrap().providers, vec!["github"]);
    }

    #[tokio::test]
    async fn attach_sandbox_provider_concurrent_with_stale_versions() {
        use std::sync::Arc;

        let state = Arc::new(test_server_state().await);

        // Create multiple providers
        for i in 0..3 {
            state
                .store
                .put_message(&test_provider_with_credential_key(
                    &format!("provider-{i}"),
                    "generic",
                    &format!("TOKEN_{i}"),
                ))
                .await
                .unwrap();
        }

        state
            .store
            .put_message(&test_sandbox("work", Vec::new()))
            .await
            .unwrap();

        // All three clients fetch the sandbox and see version 1
        let initial_version = state
            .store
            .get_message_by_name::<Sandbox>("default", "work")
            .await
            .unwrap()
            .unwrap()
            .metadata
            .as_ref()
            .unwrap()
            .resource_version;

        // Launch 3 concurrent attach operations, all using the same initial version
        let mut handles = vec![];
        for i in 0..3 {
            let state_clone = Arc::clone(&state);
            let handle = tokio::spawn(async move {
                handle_attach_sandbox_provider(
                    &state_clone,
                    Request::new(AttachSandboxProviderRequest {
                        sandbox_name: "work".to_string(),
                        provider_name: format!("provider-{i}"),
                        expected_resource_version: initial_version,
                        workspace: String::new(),
                    }),
                )
                .await
            });
            handles.push(handle);
        }

        let results: Vec<_> = future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        // Only one should succeed; others should get ABORTED
        let successes = results.iter().filter(|r| r.is_ok()).count();
        let aborted_conflicts = results
            .iter()
            .filter(|r| {
                r.as_ref()
                    .err()
                    .is_some_and(|e| e.code() == tonic::Code::Aborted)
            })
            .count();

        assert_eq!(
            successes, 1,
            "exactly one attach should succeed with client-driven CAS"
        );
        assert_eq!(
            aborted_conflicts, 2,
            "two attaches should fail with ABORTED due to stale version"
        );

        // Final sandbox should have exactly 1 provider and resource_version = initial_version + 1
        let final_sandbox = state
            .store
            .get_message_by_name::<Sandbox>("default", "work")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(final_sandbox.spec.as_ref().unwrap().providers.len(), 1);
        assert_eq!(
            final_sandbox.metadata.as_ref().unwrap().resource_version,
            initial_version + 1
        );
    }

    #[tokio::test]
    async fn sandbox_crud_is_workspace_isolated() {
        use crate::persistence::ObjectType;
        use openshell_core::proto::{
            CreateWorkspaceRequest, GetSandboxRequest, ListSandboxesRequest,
        };

        let state = test_server_state().await;

        // Create a second workspace "beta".
        crate::grpc::workspace::handle_create_workspace(
            &state,
            Request::new(CreateWorkspaceRequest {
                name: "beta".to_string(),
                labels: HashMap::new(),
            }),
        )
        .await
        .unwrap();

        // Seed a sandbox named "shared-name" in each workspace.
        let mut sbx_default = test_sandbox("shared-name", Vec::new());
        sbx_default.metadata.as_mut().unwrap().id = "sbx-default-id".to_string();
        sbx_default.metadata.as_mut().unwrap().workspace = "default".to_string();
        state.store.put_message(&sbx_default).await.unwrap();

        let mut sbx_beta = test_sandbox("shared-name", Vec::new());
        sbx_beta.metadata.as_mut().unwrap().id = "sbx-beta-id".to_string();
        sbx_beta.metadata.as_mut().unwrap().workspace = "beta".to_string();
        state.store.put_message(&sbx_beta).await.unwrap();

        // Get in "default" returns the default sandbox.
        let got = handle_get_sandbox(
            &state,
            Request::new(GetSandboxRequest {
                name: "shared-name".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(got.sandbox.as_ref().unwrap().object_id(), "sbx-default-id");

        // Get in "beta" returns the beta sandbox.
        let got = handle_get_sandbox(
            &state,
            Request::new(GetSandboxRequest {
                name: "shared-name".to_string(),
                workspace: "beta".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(got.sandbox.as_ref().unwrap().object_id(), "sbx-beta-id");

        // List in "default" returns 1 sandbox.
        let listed = handle_list_sandboxes(
            &state,
            Request::new(ListSandboxesRequest {
                limit: 100,
                offset: 0,
                label_selector: String::new(),
                workspace: "default".to_string(),
                all_workspaces: false,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(listed.sandboxes.len(), 1);
        assert_eq!(listed.sandboxes[0].object_id(), "sbx-default-id",);

        // List in "beta" returns 1 sandbox.
        let listed = handle_list_sandboxes(
            &state,
            Request::new(ListSandboxesRequest {
                limit: 100,
                offset: 0,
                label_selector: String::new(),
                workspace: "beta".to_string(),
                all_workspaces: false,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(listed.sandboxes.len(), 1);
        assert_eq!(listed.sandboxes[0].object_id(), "sbx-beta-id");

        // Delete in "default" (via store) does not affect "beta".
        state
            .store
            .delete_by_name(Sandbox::object_type(), "default", "shared-name")
            .await
            .unwrap();

        // "default" now has 0 sandboxes.
        let listed = handle_list_sandboxes(
            &state,
            Request::new(ListSandboxesRequest {
                limit: 100,
                offset: 0,
                label_selector: String::new(),
                workspace: "default".to_string(),
                all_workspaces: false,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(listed.sandboxes.is_empty());

        // "beta" still has its sandbox.
        let got = handle_get_sandbox(
            &state,
            Request::new(GetSandboxRequest {
                name: "shared-name".to_string(),
                workspace: "beta".to_string(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(got.sandbox.as_ref().unwrap().object_id(), "sbx-beta-id");

        // all_workspaces returns sandboxes from all workspaces.
        // Re-create the "default" sandbox so both workspaces have one.
        state
            .store
            .put(
                Sandbox::object_type(),
                "sbx-default-2",
                "sandbox-d",
                "default",
                &Sandbox::default().encode_to_vec(),
                None,
            )
            .await
            .unwrap();
        let listed = handle_list_sandboxes(
            &state,
            Request::new(ListSandboxesRequest {
                limit: 100,
                offset: 0,
                label_selector: String::new(),
                workspace: String::new(),
                all_workspaces: true,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(listed.sandboxes.len(), 2);

        // all_workspaces with non-empty workspace is rejected.
        let err = handle_list_sandboxes(
            &state,
            Request::new(ListSandboxesRequest {
                limit: 100,
                offset: 0,
                label_selector: String::new(),
                workspace: "default".to_string(),
                all_workspaces: true,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn revoke_ssh_session_preserves_workspace() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_sandbox("ws-test", Vec::new()))
            .await
            .unwrap();

        let response = handle_create_ssh_session(
            &state,
            Request::new(CreateSshSessionRequest {
                sandbox_id: "sandbox-ws-test".to_string(),
            }),
        )
        .await
        .unwrap();
        let token = response.into_inner().token;

        handle_revoke_ssh_session(
            &state,
            Request::new(RevokeSshSessionRequest {
                token: token.clone(),
            }),
        )
        .await
        .unwrap();

        let session: SshSession = state
            .store
            .get_message::<SshSession>(&token)
            .await
            .unwrap()
            .expect("session should still exist after revocation");
        assert!(session.revoked);
        assert_eq!(session.object_workspace(), "default");
    }
}
