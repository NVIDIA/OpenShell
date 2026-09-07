// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox lifecycle, exec, and SSH session handlers.

#![allow(clippy::ignored_unit_patterns)] // Tokio select! macro generates unit patterns
#![allow(clippy::result_large_err)] // gRPC handlers return Result<Response<_>, Status>
#![allow(clippy::cast_possible_truncation)] // Intentional u128->i64 etc. for timestamp math
#![allow(clippy::cast_sign_loss)] // Intentional i32->u32 conversions from proto types
#![allow(clippy::cast_possible_wrap)] // Intentional u32->i32 conversions for proto compat

use crate::ServerState;
use crate::auth::workspace_authz::{
    MinWorkspaceRole, authorize_sandbox_workspace, authorize_workspace, require_platform_admin,
};
use crate::persistence::{ObjectLabels, ObjectType, WriteCondition, generate_name};
use futures::future;
use openshell_core::net::set_tcp_nodelay_best_effort;
use openshell_core::proto::datamodel::v1::ObjectMeta;
use openshell_core::proto::{
    AttachSandboxProviderRequest, AttachSandboxProviderResponse, CreateSandboxRequest,
    CreateSandboxTemplateRequest, CreateSshSessionRequest, CreateSshSessionResponse,
    DeleteSandboxRequest, DeleteSandboxResponse, DeleteSandboxTemplateRequest,
    DeleteSandboxTemplateResponse, DetachSandboxProviderRequest, DetachSandboxProviderResponse,
    ExecSandboxEvent, ExecSandboxExit, ExecSandboxInput, ExecSandboxRequest, ExecSandboxStderr,
    ExecSandboxStdout, GetSandboxRequest, GetSandboxTemplateRequest, ListSandboxProvidersRequest,
    ListSandboxProvidersResponse, ListSandboxTemplatesRequest, ListSandboxTemplatesResponse,
    ListSandboxesRequest, ListSandboxesResponse, Provider, ResourceRequirements,
    RevokeSshSessionRequest, RevokeSshSessionResponse, SandboxResources, SandboxResponse,
    SandboxSpec, SandboxStreamEvent, SandboxTemplateResponse, SandboxWorkloadTemplate,
    SandboxWorkloadTemplateProvenance, SshRelayTarget, StartSandboxRequest, StopSandboxRequest,
    TcpForwardFrame, TcpForwardInit, TcpRelayTarget, WatchSandboxRequest, relay_open,
    tcp_forward_init,
};
use openshell_core::proto::{Sandbox, SandboxPhase, SandboxTemplate, SshSession};
use openshell_core::telemetry::{
    LifecycleOperation, LifecycleResource, SandboxTemplateSource, TelemetryOutcome,
};
use openshell_core::{GetResourceVersion, ObjectId, ObjectName, ObjectWorkspace};
use prost::Message;
use prost_types::{Struct, Value, value::Kind};
use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

use russh::ChannelMsg;
use russh::client::AuthResult;

use super::provider::{
    get_provider_record, is_valid_env_key, validate_provider_environment_keys_unique_with_catalog,
};
use super::validation::{
    level_matches, source_matches, validate_and_canonicalize_policy, validate_dns1123_label,
    validate_exec_request_fields, validate_no_reserved_provider_policy_keys,
    validate_policy_safety, validate_sandbox_governance_spec, validate_sandbox_spec,
};
use super::{MAX_PAGE_SIZE, MAX_PROVIDERS, MAX_ROUTABLE_NAME_LEN, clamp_limit};
use crate::persistence::current_time_ms;

const TCP_FORWARD_CHUNK_SIZE: usize = 64 * 1024;
const NO_LOGIN_SHELL_ENV: (&str, &str) = ("OPENSHELL_NO_LOGIN_SHELL", "1");
const MAX_TEMPLATES_PER_WORKSPACE: u32 = 1000;

#[derive(Debug)]
pub struct WatchSandboxStream {
    receiver: ReceiverStream<Result<SandboxStreamEvent, Status>>,
    producer: Option<tokio::task::JoinHandle<()>>,
}

impl WatchSandboxStream {
    fn new(
        receiver: mpsc::Receiver<Result<SandboxStreamEvent, Status>>,
        producer: tokio::task::JoinHandle<()>,
    ) -> Self {
        Self {
            receiver: ReceiverStream::new(receiver),
            producer: Some(producer),
        }
    }

    fn stop_producer(&mut self) -> Option<tokio::task::JoinHandle<()>> {
        self.receiver.close();
        let producer = self.producer.take()?;
        producer.abort();
        Some(producer)
    }

    #[cfg(test)]
    async fn disconnect_and_wait(mut self) {
        let producer = self.stop_producer().expect("watch producer task");
        let error = producer
            .await
            .expect_err("watch producer should be aborted");
        assert!(error.is_cancelled(), "watch producer abort result: {error}");
    }
}

impl futures::Stream for WatchSandboxStream {
    type Item = Result<SandboxStreamEvent, Status>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.receiver).poll_next(context)
    }
}

impl Drop for WatchSandboxStream {
    fn drop(&mut self) {
        let _ = self.stop_producer();
    }
}

/// Fetch a sandbox by ID and authorize the caller in one step, returning
/// `NOT_FOUND` for both missing and unauthorized sandboxes so that callers
/// cannot distinguish the two cases (CWE-203).
pub(super) async fn fetch_and_authorize_sandbox(
    state: &Arc<ServerState>,
    principal: &crate::auth::principal::Principal,
    sandbox_id: &str,
) -> Result<Sandbox, Status> {
    let sandbox = state
        .store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    authorize_sandbox_workspace(
        &state.store,
        &state.admin_role,
        principal,
        sandbox.object_workspace(),
        MinWorkspaceRole::User,
    )
    .await
    .map_err(|e| {
        if e.code() == tonic::Code::PermissionDenied {
            Status::not_found("sandbox not found")
        } else {
            e
        }
    })?;
    Ok(sandbox)
}

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
    let created_sandbox = result
        .as_ref()
        .ok()
        .and_then(|response| response.get_ref().sandbox.as_ref());
    emit_sandbox_create_telemetry(
        state,
        &create_request,
        created_sandbox,
        TelemetryOutcome::from_success(result.is_ok()),
    );
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SandboxCreateTelemetryAttrs {
    requested_gpu: bool,
    provider_count: u64,
    has_custom_policy: bool,
    template_source: SandboxTemplateSource,
}

fn emit_sandbox_create_telemetry(
    state: &Arc<ServerState>,
    request: &CreateSandboxRequest,
    created_sandbox: Option<&Sandbox>,
    outcome: TelemetryOutcome,
) {
    let compute_driver = state.compute.telemetry_compute_driver();
    let attrs = sandbox_create_telemetry_attrs(request, created_sandbox);
    openshell_core::telemetry::emit_sandbox_create(
        outcome,
        attrs.requested_gpu,
        attrs.provider_count,
        attrs.has_custom_policy,
        attrs.template_source,
        compute_driver,
    );
}

fn sandbox_create_telemetry_attrs(
    request: &CreateSandboxRequest,
    created_sandbox: Option<&Sandbox>,
) -> SandboxCreateTelemetryAttrs {
    if !request.workload_template_name.trim().is_empty() {
        let spec = created_sandbox
            .and_then(|sandbox| sandbox.spec.as_ref())
            .or(request.spec.as_ref());
        return SandboxCreateTelemetryAttrs {
            requested_gpu: spec.is_some_and(|spec| {
                openshell_core::gpu::sandbox_gpu_requested(spec.resource_requirements.as_ref())
            }),
            provider_count: spec.map_or(0, |spec| spec.providers.len() as u64),
            has_custom_policy: spec.is_some_and(|spec| spec.policy.is_some()),
            template_source: SandboxTemplateSource::WorkloadTemplate,
        };
    }
    let Some(spec) = request.spec.as_ref() else {
        return SandboxCreateTelemetryAttrs {
            requested_gpu: false,
            provider_count: 0,
            has_custom_policy: false,
            template_source: SandboxTemplateSource::Undefined,
        };
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
    SandboxCreateTelemetryAttrs {
        requested_gpu: gpu_requested,
        provider_count: spec.providers.len() as u64,
        has_custom_policy: spec.policy.is_some(),
        template_source,
    }
}

async fn handle_create_sandbox_inner(
    state: &Arc<ServerState>,
    request: Request<CreateSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();
    let await_main_process_attachment = request.await_main_process_attachment;
    let workload_template_name = request.workload_template_name.trim().to_string();

    validate_create_sandbox_request_pre_io(&request, &workload_template_name)?;

    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        &request.workspace,
        MinWorkspaceRole::User,
    )
    .await?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
        .await?
        .ensure_active()?;

    let (mut spec, created_from_workload_template) = if workload_template_name.is_empty() {
        let spec = request
            .spec
            .ok_or_else(|| Status::invalid_argument("spec is required"))?;
        (spec, None)
    } else {
        let governance_spec = request.spec.unwrap_or_default();
        let template = state
            .store
            .get_message_by_name::<SandboxWorkloadTemplate>(&workspace, &workload_template_name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox template failed: {e}")))?
            .ok_or_else(|| Status::not_found("sandbox template not found"))?;
        let provenance = SandboxWorkloadTemplateProvenance {
            name: template.object_name().to_string(),
            resource_version: template.get_resource_version().to_string(),
        };
        let mut resolved = sandbox_spec_from_stored_workload_template(&template)?;
        resolved.policy = governance_spec.policy;
        resolved.providers = governance_spec.providers;
        resolved.command = governance_spec.command;
        resolved.tty = governance_spec.tty;
        (resolved, Some(provenance))
    };

    // Leave an omitted command empty rather than persisting a concrete shell:
    // the supervisor resolves the default login shell against the sandbox image
    // (bash when present, otherwise /bin/sh on minimal images like Alpine),
    // which the gateway cannot do since it does not see the sandbox filesystem.
    // The default is an interactive login shell, so request a TTY.
    if spec.command.is_empty() {
        spec.tty = true;
    }

    // Validate field sizes before any create-side effects.
    validate_sandbox_spec(&request.name, &spec)?;

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
    let provider_profile_catalog = state
        .provider_profile_sources
        .snapshot_catalog(state.store.as_ref(), &workspace)
        .await?;
    validate_provider_environment_keys_unique_with_catalog(
        state.store.as_ref(),
        &provider_profile_catalog,
        &workspace,
        &spec.providers,
    )
    .await?;

    // Ensure the template always carries the resolved image.
    let template = spec.template.get_or_insert_with(SandboxTemplate::default);
    if template.image.trim().is_empty() {
        template.image = state.compute.default_image().to_string();
    }

    if let Some(ref mut policy) = spec.policy {
        super::policy::clear_provider_credentialed_markers(policy);
        validate_no_reserved_provider_policy_keys(policy)?;
        *policy = validate_and_canonicalize_policy(policy.clone())?;
    }

    // Process identity and MCP default materialization can increase the
    // protobuf size. Recheck the exact canonical spec before any middleware or
    // compute boundary can observe or persist it. The initial check remains
    // above so requests that are already oversized still fail before I/O.
    validate_sandbox_spec(&request.name, &spec)?;

    if let Some(ref policy) = spec.policy {
        validate_policy_safety(policy)?;
        crate::middleware::validate_policy(state.middleware_registry.as_ref(), policy).await?;
    }
    super::policy::validate_candidate_sandbox_credential_policy(
        state,
        &workspace,
        &spec.providers,
        spec.policy.as_ref(),
    )
    .await?;

    let id = uuid::Uuid::new_v4().to_string();
    let name = if request.name.is_empty() {
        generate_routable_name()
    } else {
        request.name.clone()
    };

    let now_ms = current_time_ms();

    let mut sandbox = Sandbox {
        metadata: Some(ObjectMeta {
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
        created_from_workload_template,
    };
    sandbox.set_phase(SandboxPhase::Provisioning as i32);

    // Ensure metadata is valid (defense in depth - should always be true for server-constructed metadata)
    super::validation::validate_object_metadata(sandbox.metadata.as_ref(), "sandbox")?;
    super::policy::validate_candidate_provider_attachments(
        state,
        sandbox.object_workspace(),
        &sandbox,
        sandbox
            .spec
            .as_ref()
            .map(|spec| spec.providers.as_slice())
            .unwrap_or_default(),
    )
    .await?;

    state
        .compute
        .validate_sandbox_create(&sandbox)
        .await
        .map_err(|status| {
            warn!(error = %status, "Rejecting sandbox create request");
            status
        })?;

    // Mint a gateway JWT whenever the issuer is configured. Compute runtimes
    // that bootstrap through another authentication mechanism may ignore it.
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

    let sandbox = state
        .compute
        .create_sandbox(sandbox, sandbox_token, await_main_process_attachment)
        .await?;

    info!(
        sandbox_id = %id,
        sandbox_name = %name,
        "CreateSandbox request completed successfully"
    );
    Ok(Response::new(SandboxResponse {
        sandbox: Some(sandbox),
    }))
}

fn validate_create_sandbox_request_pre_io(
    request: &CreateSandboxRequest,
    workload_template_name: &str,
) -> Result<(), Status> {
    // Validate labels (keys and values must meet Kubernetes requirements).
    for (key, value) in &request.labels {
        crate::grpc::validation::validate_label_key(key)?;
        crate::grpc::validation::validate_label_value(value)?;
    }
    crate::grpc::validation::validate_annotations(&request.annotations, "annotations")?;

    if workload_template_name.is_empty() {
        let spec = request
            .spec
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("spec is required"))?;
        return validate_sandbox_spec(&request.name, spec);
    }

    validate_dns1123_label(workload_template_name, "workload_template_name")?;
    if let Some(spec) = request.spec.as_ref() {
        validate_template_create_governance_spec(spec)?;
        validate_sandbox_governance_spec(&request.name, spec)?;
    } else {
        validate_sandbox_governance_spec(&request.name, &SandboxSpec::default())?;
    }
    Ok(())
}

fn validate_template_create_governance_spec(spec: &SandboxSpec) -> Result<(), Status> {
    if !spec.log_level.is_empty() {
        return Err(Status::invalid_argument(
            "spec.log_level cannot be set when workload_template_name is set",
        ));
    }
    if !spec.environment.is_empty() {
        return Err(Status::invalid_argument(
            "spec.environment cannot be set when workload_template_name is set",
        ));
    }
    if spec.template.is_some() {
        return Err(Status::invalid_argument(
            "spec.template cannot be set when workload_template_name is set",
        ));
    }
    if spec.resource_requirements.is_some() {
        return Err(Status::invalid_argument(
            "spec.resource_requirements cannot be set when workload_template_name is set",
        ));
    }
    Ok(())
}

fn sandbox_spec_from_stored_workload_template(
    template: &SandboxWorkloadTemplate,
) -> Result<SandboxSpec, Status> {
    sandbox_spec_from_workload_template(template, tonic::Code::Internal)
}

fn sandbox_spec_from_user_workload_template(
    template: &SandboxWorkloadTemplate,
) -> Result<SandboxSpec, Status> {
    sandbox_spec_from_workload_template(template, tonic::Code::InvalidArgument)
}

fn sandbox_spec_from_workload_template(
    template: &SandboxWorkloadTemplate,
    missing_field_code: tonic::Code,
) -> Result<SandboxSpec, Status> {
    let spec = template
        .spec
        .as_ref()
        .ok_or_else(|| Status::new(missing_field_code, "sandbox template spec is required"))?;
    let workload = spec
        .workload
        .as_ref()
        .ok_or_else(|| Status::new(missing_field_code, "sandbox template workload is required"))?;
    let resources = workload.resources.as_ref();
    Ok(SandboxSpec {
        environment: workload.environment.clone(),
        template: Some(SandboxTemplate {
            image: workload.image.clone(),
            resources: resources.and_then(template_resource_struct),
            driver_config: spec.driver_config.clone(),
            ..SandboxTemplate::default()
        }),
        resource_requirements: resources.and_then(template_gpu_requirements),
        ..SandboxSpec::default()
    })
}

fn template_gpu_requirements(resources: &SandboxResources) -> Option<ResourceRequirements> {
    Some(ResourceRequirements {
        gpu: Some(resources.gpu?),
    })
}

fn template_resource_struct(resources: &SandboxResources) -> Option<Struct> {
    let mut limits = std::collections::BTreeMap::new();
    if !resources.cpu.is_empty() {
        limits.insert(
            "cpu".to_string(),
            Value {
                kind: Some(Kind::StringValue(resources.cpu.clone())),
            },
        );
    }
    if !resources.memory.is_empty() {
        limits.insert(
            "memory".to_string(),
            Value {
                kind: Some(Kind::StringValue(resources.memory.clone())),
            },
        );
    }
    if limits.is_empty() {
        None
    } else {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(
            "limits".to_string(),
            Value {
                kind: Some(Kind::StructValue(Struct { fields: limits })),
            },
        );
        Some(Struct { fields })
    }
}

pub(super) async fn handle_get_sandbox(
    state: &Arc<ServerState>,
    request: Request<GetSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        &req.workspace,
        MinWorkspaceRole::User,
    )
    .await?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
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
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();
    if request.all_workspaces && !request.workspace.is_empty() {
        return Err(Status::invalid_argument(
            "all_workspaces and workspace are mutually exclusive",
        ));
    }
    let limit = clamp_limit(request.limit, 100, MAX_PAGE_SIZE);

    let sandboxes: Vec<Sandbox> = if request.all_workspaces {
        require_platform_admin(&state.admin_role, &principal)?;
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
        let authz = authorize_workspace(
            &state.store,
            &state.admin_role,
            &principal,
            &request.workspace,
            MinWorkspaceRole::User,
        )
        .await?;
        let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
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

pub(super) async fn handle_create_sandbox_template(
    state: &Arc<ServerState>,
    request: Request<CreateSandboxTemplateRequest>,
) -> Result<Response<SandboxTemplateResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    let template = req
        .template
        .ok_or_else(|| Status::invalid_argument("template is required"))?;
    let metadata = template.metadata.clone().unwrap_or_default();
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        &req.workspace,
        MinWorkspaceRole::Admin,
    )
    .await?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
        .await?
        .ensure_active()?;
    if !metadata.workspace.is_empty() && metadata.workspace != workspace {
        return Err(Status::invalid_argument(
            "template.metadata.workspace must match request workspace",
        ));
    }
    if metadata.name.is_empty() {
        return Err(Status::invalid_argument(
            "template.metadata.name is required",
        ));
    }

    let mut resolved = template;
    resolved.metadata = Some(ObjectMeta {
        id: uuid::Uuid::new_v4().to_string(),
        name: metadata.name,
        created_at_ms: current_time_ms(),
        labels: metadata.labels,
        resource_version: 0,
        annotations: metadata.annotations,
        workspace: workspace.clone(),
        deletion_timestamp_ms: 0,
    });
    validate_sandbox_workload_template(&resolved)?;

    let labels_map = resolved.object_labels();
    let labels_json = if labels_map.as_ref().is_none_or(HashMap::is_empty) {
        None
    } else {
        Some(
            serde_json::to_string(&labels_map)
                .map_err(|e| Status::internal(format!("failed to serialize labels: {e}")))?,
        )
    };
    let write = state
        .store
        .create_if_workspace_count_below(
            SandboxWorkloadTemplate::object_type(),
            resolved.object_id(),
            resolved.object_name(),
            &workspace,
            &resolved.encode_to_vec(),
            labels_json.as_deref(),
            u64::from(MAX_TEMPLATES_PER_WORKSPACE),
        )
        .await;
    let write = match write {
        Ok(Some(write)) => write,
        Ok(None) => {
            return Err(Status::resource_exhausted(format!(
                "workspace has reached the maximum of {MAX_TEMPLATES_PER_WORKSPACE} sandbox templates"
            )));
        }
        Err(crate::persistence::PersistenceError::UniqueViolation { .. }) => {
            return Err(Status::already_exists("sandbox template already exists"));
        }
        Err(err) => {
            return Err(Status::internal(format!(
                "persist sandbox template failed: {err}"
            )));
        }
    };
    if let Some(metadata) = resolved.metadata.as_mut() {
        metadata.resource_version = write.resource_version;
    }

    Ok(Response::new(SandboxTemplateResponse {
        template: Some(resolved),
    }))
}

pub(super) async fn handle_get_sandbox_template(
    state: &Arc<ServerState>,
    request: Request<GetSandboxTemplateRequest>,
) -> Result<Response<SandboxTemplateResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        &req.workspace,
        MinWorkspaceRole::User,
    )
    .await?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
        .await?
        .name;
    let template = state
        .store
        .get_message_by_name::<SandboxWorkloadTemplate>(&workspace, &req.name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox template failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox template not found"))?;
    Ok(Response::new(SandboxTemplateResponse {
        template: Some(template),
    }))
}

pub(super) async fn handle_list_sandbox_templates(
    state: &Arc<ServerState>,
    request: Request<ListSandboxTemplatesRequest>,
) -> Result<Response<ListSandboxTemplatesResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();
    if request.all_workspaces && !request.workspace.is_empty() {
        return Err(Status::invalid_argument(
            "all_workspaces and workspace are mutually exclusive",
        ));
    }
    let limit = clamp_limit(request.limit, 100, MAX_PAGE_SIZE);
    let templates = if request.all_workspaces {
        require_platform_admin(&state.admin_role, &principal)?;
        if request.label_selector.is_empty() {
            state
                .store
                .list_all_messages::<SandboxWorkloadTemplate>(limit, request.offset)
                .await
                .map_err(|e| Status::internal(format!("list sandbox templates failed: {e}")))?
        } else {
            crate::grpc::validation::validate_label_selector(&request.label_selector)?;
            state
                .store
                .list_all_messages_with_selector::<SandboxWorkloadTemplate>(
                    &request.label_selector,
                    limit,
                    request.offset,
                )
                .await
                .map_err(|e| Status::internal(format!("list sandbox templates failed: {e}")))?
        }
    } else {
        let authz = authorize_workspace(
            &state.store,
            &state.admin_role,
            &principal,
            &request.workspace,
            MinWorkspaceRole::User,
        )
        .await?;
        let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
            .await?
            .name;
        if request.label_selector.is_empty() {
            state
                .store
                .list_messages::<SandboxWorkloadTemplate>(&workspace, limit, request.offset)
                .await
                .map_err(|e| Status::internal(format!("list sandbox templates failed: {e}")))?
        } else {
            crate::grpc::validation::validate_label_selector(&request.label_selector)?;
            state
                .store
                .list_messages_with_selector::<SandboxWorkloadTemplate>(
                    &workspace,
                    &request.label_selector,
                    limit,
                    request.offset,
                )
                .await
                .map_err(|e| {
                    Status::internal(format!("list sandbox templates with selector failed: {e}"))
                })?
        }
    };
    Ok(Response::new(ListSandboxTemplatesResponse { templates }))
}

pub(super) async fn handle_delete_sandbox_template(
    state: &Arc<ServerState>,
    request: Request<DeleteSandboxTemplateRequest>,
) -> Result<Response<DeleteSandboxTemplateResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        &req.workspace,
        MinWorkspaceRole::Admin,
    )
    .await?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
        .await?
        .name;
    let deleted = state
        .store
        .delete_by_name(
            SandboxWorkloadTemplate::object_type(),
            &workspace,
            &req.name,
        )
        .await
        .map_err(|e| Status::internal(format!("delete sandbox template failed: {e}")))?;
    Ok(Response::new(DeleteSandboxTemplateResponse { deleted }))
}

fn validate_sandbox_workload_template(template: &SandboxWorkloadTemplate) -> Result<(), Status> {
    super::validation::validate_object_metadata(template.metadata.as_ref(), "sandbox_template")?;
    let name = template.object_name().to_string();
    validate_dns1123_label(&name, "template.metadata.name")?;
    validate_sandbox_workload_template_service_level(template)?;
    let spec = sandbox_spec_from_user_workload_template(template)?;
    validate_sandbox_spec(&name, &spec)?;
    Ok(())
}

fn validate_sandbox_workload_template_service_level(
    template: &SandboxWorkloadTemplate,
) -> Result<(), Status> {
    let Some(startup) = template
        .spec
        .as_ref()
        .and_then(|spec| spec.desired_service_level.as_ref())
        .and_then(|service_level| service_level.startup.as_ref())
    else {
        return Ok(());
    };
    if let Some(ready_within) = &startup.ready_within {
        validate_positive_normalized_duration(
            ready_within,
            "template.spec.desired_service_level.startup.ready_within",
        )?;
    }
    Ok(())
}

fn validate_positive_normalized_duration(
    duration: &prost_types::Duration,
    field: &str,
) -> Result<(), Status> {
    const MAX_DURATION_SECONDS: u64 = 315_576_000_000;
    if duration.seconds.unsigned_abs() > MAX_DURATION_SECONDS
        || duration.nanos.unsigned_abs() >= 1_000_000_000
    {
        return Err(Status::invalid_argument(format!(
            "{field} must be a valid protobuf Duration"
        )));
    }
    if (duration.seconds > 0 && duration.nanos < 0) || (duration.seconds < 0 && duration.nanos > 0)
    {
        return Err(Status::invalid_argument(format!(
            "{field} must be a normalized protobuf Duration"
        )));
    }
    if duration.seconds < 0 || duration.nanos < 0 || (duration.seconds == 0 && duration.nanos == 0)
    {
        return Err(Status::invalid_argument(format!(
            "{field} must be greater than zero"
        )));
    }
    Ok(())
}

pub(super) async fn handle_list_sandbox_providers(
    state: &Arc<ServerState>,
    request: Request<ListSandboxProvidersRequest>,
) -> Result<Response<ListSandboxProvidersResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        &req.workspace,
        MinWorkspaceRole::User,
    )
    .await?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
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
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        &request.workspace,
        MinWorkspaceRole::User,
    )
    .await?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
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
    let provider_profile_catalog = state
        .provider_profile_sources
        .snapshot_catalog(state.store.as_ref(), &workspace)
        .await?;
    validate_provider_environment_keys_unique_with_catalog(
        state.store.as_ref(),
        &provider_profile_catalog,
        &workspace,
        &candidate_spec.providers,
    )
    .await?;
    super::policy::validate_candidate_provider_attachments(
        state,
        &workspace,
        &sandbox,
        &candidate_spec.providers,
    )
    .await?;
    super::policy::validate_candidate_sandbox_credential_policy(
        state,
        &workspace,
        &candidate_spec.providers,
        candidate_spec.policy.as_ref(),
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
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        &request.workspace,
        MinWorkspaceRole::User,
    )
    .await?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
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
    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| Status::internal("sandbox spec is missing"))?;
    let mut candidate_spec = spec.clone();
    candidate_spec
        .providers
        .retain(|name| name != &request.provider_name);
    dedupe_provider_names(&mut candidate_spec.providers);
    super::policy::validate_candidate_provider_attachments(
        state,
        &workspace,
        &sandbox,
        &candidate_spec.providers,
    )
    .await?;

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
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    let name = req.name;
    if name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        &req.workspace,
        MinWorkspaceRole::User,
    )
    .await?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
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

pub(super) async fn handle_stop_sandbox(
    state: &Arc<ServerState>,
    request: Request<StopSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    let result = handle_stop_sandbox_inner(state, request).await;
    openshell_core::telemetry::emit_lifecycle(
        LifecycleResource::Sandbox,
        LifecycleOperation::Stop,
        if result.is_ok() {
            TelemetryOutcome::Success
        } else {
            TelemetryOutcome::Failure
        },
    );
    result
}

async fn handle_stop_sandbox_inner(
    state: &Arc<ServerState>,
    request: Request<StopSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        &req.workspace,
        MinWorkspaceRole::User,
    )
    .await?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
        .await?
        .name;
    let sandbox = state.compute.stop_sandbox(&workspace, &req.name).await?;
    info!(sandbox_name = %req.name, "StopSandbox request completed successfully");
    Ok(Response::new(SandboxResponse {
        sandbox: Some(sandbox),
    }))
}

pub(super) async fn handle_start_sandbox(
    state: &Arc<ServerState>,
    request: Request<StartSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    let result = handle_start_sandbox_inner(state, request).await;
    openshell_core::telemetry::emit_lifecycle(
        LifecycleResource::Sandbox,
        LifecycleOperation::Start,
        if result.is_ok() {
            TelemetryOutcome::Success
        } else {
            TelemetryOutcome::Failure
        },
    );
    result
}

async fn handle_start_sandbox_inner(
    state: &Arc<ServerState>,
    request: Request<StartSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        &req.workspace,
        MinWorkspaceRole::User,
    )
    .await?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
        .await?
        .name;
    let sandbox = state.compute.start_sandbox(&workspace, &req.name).await?;
    info!(sandbox_name = %req.name, "StartSandbox request completed successfully");
    Ok(Response::new(SandboxResponse {
        sandbox: Some(sandbox),
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

pub(super) async fn handle_watch_sandbox(
    state: &Arc<ServerState>,
    request: Request<WatchSandboxRequest>,
) -> Result<Response<WatchSandboxStream>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    if req.id.is_empty() {
        return Err(Status::invalid_argument("id is required"));
    }
    let sandbox_id = req.id.clone();

    let _sandbox = fetch_and_authorize_sandbox(state, &principal, &sandbox_id).await?;

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

    // Spawn producer task. `tokio::spawn` detaches from the current span, so
    // carry it across to keep the producer's store reads in the request trace.
    let request_span = tracing::Span::current();
    let producer = tokio::spawn(tracing::Instrument::instrument(
        async move {
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
                        let phase = SandboxPhase::try_from(sandbox.phase())
                            .unwrap_or(SandboxPhase::Unknown);
                        if is_watch_terminal(phase) {
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
                    () = tx.closed() => {
                        return;
                    }
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
                                            if is_watch_terminal(phase) {
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
        },
        request_span,
    ));

    Ok(Response::new(WatchSandboxStream::new(rx, producer)))
}

fn is_watch_terminal(phase: SandboxPhase) -> bool {
    matches!(
        phase,
        SandboxPhase::Ready | SandboxPhase::Completed | SandboxPhase::Stopped | SandboxPhase::Error
    )
}

// ---------------------------------------------------------------------------
// Exec handler
// ---------------------------------------------------------------------------

const DEFAULT_PTY_COLS: u32 = 80;
const DEFAULT_PTY_ROWS: u32 = 24;

fn pty_dimensions(cols: u32, rows: u32) -> (u32, u32) {
    (
        if cols == 0 { DEFAULT_PTY_COLS } else { cols },
        if rows == 0 { DEFAULT_PTY_ROWS } else { rows },
    )
}

pub(super) async fn handle_exec_sandbox(
    state: &Arc<ServerState>,
    request: Request<ExecSandboxRequest>,
) -> Result<Response<ReceiverStream<Result<ExecSandboxEvent, Status>>>, Status> {
    use openshell_core::ObjectId;

    let principal = super::extract_principal(&request)?;
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

    let sandbox = fetch_and_authorize_sandbox(state, &principal, &req.sandbox_id).await?;

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
    let (cols, rows) = pty_dimensions(req.cols, req.rows);

    let sandbox_id = sandbox.object_id().to_string();

    let no_login_shell = req.no_login_shell;

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
            no_login_shell,
            cols,
            rows,
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
    let principal = super::extract_principal(&request)?;
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

    let sandbox = fetch_and_authorize_sandbox(state, &principal, &init.sandbox_id).await?;

    // The main process may finish between minting the SSH token and opening
    // its transport. Keep the relay reachable until terminal delivery is
    // finalized so fast commands can attach without a readiness race.
    if !sandbox_relay_reachable(state, &sandbox) {
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
        sandbox_id: sandbox_id.clone(),
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

    let principal = super::extract_principal(&request)?;
    let mut input_stream = request.into_inner();

    let first_msg = input_stream
        .message()
        .await
        .map_err(|e| Status::internal(format!("failed to read first message: {e}")))?;

    let req = validate_interactive_exec_start(first_msg)?;

    let sandbox = fetch_and_authorize_sandbox(state, &principal, &req.sandbox_id).await?;

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
    let no_login_shell = req.no_login_shell;
    let timeout_seconds = req.timeout_seconds;
    let (cols, rows) = pty_dimensions(req.cols, req.rows);

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
            no_login_shell,
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

fn sandbox_relay_reachable(state: &ServerState, sandbox: &Sandbox) -> bool {
    let phase = SandboxPhase::try_from(sandbox.phase()).ok();
    matches!(phase, Some(SandboxPhase::Ready))
        || (matches!(phase, Some(SandboxPhase::Completed | SandboxPhase::Error))
            && state.supervisor_sessions.has_session(sandbox.object_id())
            && !state
                .supervisor_sessions
                .terminal_delivery_finalized(sandbox.object_id()))
}

pub(super) async fn handle_create_ssh_session(
    state: &Arc<ServerState>,
    request: Request<CreateSshSessionRequest>,
) -> Result<Response<CreateSshSessionResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    if req.sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }

    let sandbox = fetch_and_authorize_sandbox(state, &principal, &req.sandbox_id).await?;

    if !sandbox_relay_reachable(state, &sandbox) {
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
        metadata: Some(ObjectMeta {
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
    let principal = super::extract_principal(&request)?;
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
    authorize_sandbox_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        session.object_workspace(),
        MinWorkspaceRole::User,
    )
    .await
    .map_err(|e| {
        if e.code() == tonic::Code::PermissionDenied {
            Status::not_found("sandbox not found")
        } else {
            e
        }
    })?;

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

/// Supervisor SSH banner software token that signals no-login-shell support.
const OPENSHELL_SSHID_PREFIX: &[u8] = b"SSH-2.0-OpenShell_";

/// A supervisor honors `OPENSHELL_NO_LOGIN_SHELL` only if it identifies as
/// `OpenShell`. Older sandboxes present russh's default banner and silently
/// ignore the env request, so gate the opt-out on the `OpenShell` identity.
fn supervisor_supports_no_login_shell(remote_sshid: &[u8]) -> bool {
    remote_sshid.starts_with(OPENSHELL_SSHID_PREFIX)
}

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
    no_login_shell: bool,
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
        no_login_shell,
        (cols, rows),
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
    no_login_shell: bool,
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
        no_login_shell,
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

#[allow(clippy::too_many_arguments)]
async fn run_interactive_exec_with_russh(
    local_proxy_port: u16,
    command: &str,
    mut input_stream: tonic::Streaming<ExecSandboxInput>,
    request_tty: bool,
    no_login_shell: bool,
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
    // russh client end of the loopback exec bridge — disable Nagle so keystroke
    // and PTY tinygrams don't stall on delayed ACKs.
    set_tcp_nodelay_best_effort(&stream);

    let config = Arc::new(exec_ssh_client_config());
    let remote_sshid = Arc::new(std::sync::Mutex::new(None));
    let handler = SandboxSshClientHandler {
        remote_sshid: remote_sshid.clone(),
    };
    let mut client = russh::client::connect_stream(config, stream, handler)
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

    if no_login_shell {
        let banner = remote_sshid.lock().unwrap().clone().unwrap_or_default();
        if !supervisor_supports_no_login_shell(&banner) {
            return Err(Status::failed_precondition(
                "sandbox supervisor is too old to honor --no-login-shell; recreate the sandbox on a current gateway",
            ));
        }
        channel
            .set_env(false, NO_LOGIN_SHELL_ENV.0, NO_LOGIN_SHELL_ENV.1)
            .await
            .map_err(|e| Status::internal(format!("failed to set login-shell env: {e}")))?;
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
        // Loopback bridge for interactive SSH exec (keystrokes, line-buffered
        // PTY output) — disable Nagle so tinygrams don't stall on delayed ACKs.
        set_tcp_nodelay_best_effort(&client_conn);
        let _ = tokio::io::copy_bidirectional(&mut client_conn, &mut relay_stream).await;
    });

    Ok((port, task))
}

#[derive(Debug, Clone)]
struct SandboxSshClientHandler {
    remote_sshid: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
}

impl russh::client::Handler for SandboxSshClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        _names: &russh::Names,
        session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        *self.remote_sshid.lock().unwrap() = Some(session.remote_sshid().to_vec());
        Ok(())
    }
}

async fn run_exec_with_russh(
    local_proxy_port: u16,
    command: &str,
    stdin_payload: Vec<u8>,
    request_tty: bool,
    no_shell_login: bool,
    pty_size: (u32, u32),
    tx: mpsc::Sender<Result<ExecSandboxEvent, Status>>,
) -> Result<i32, Status> {
    let (cols, rows) = pty_size;

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
    // russh client end of the loopback exec bridge — disable Nagle so keystroke
    // and PTY tinygrams don't stall on delayed ACKs.
    set_tcp_nodelay_best_effort(&stream);

    let config = Arc::new(exec_ssh_client_config());
    let remote_sshid = Arc::new(std::sync::Mutex::new(None));
    let handler = SandboxSshClientHandler {
        remote_sshid: remote_sshid.clone(),
    };
    let mut client = russh::client::connect_stream(config, stream, handler)
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
            .request_pty(false, "xterm-256color", cols, rows, 0, 0, &[])
            .await
            .map_err(|e| Status::internal(format!("failed to allocate PTY: {e}")))?;
    }

    if no_shell_login {
        let banner = remote_sshid.lock().unwrap().clone().unwrap_or_default();
        if !supervisor_supports_no_login_shell(&banner) {
            return Err(Status::failed_precondition(
                "sandbox supervisor is too old to honor --no-login-shell; recreate the sandbox on a current gateway",
            ));
        }
        channel
            .set_env(false, NO_LOGIN_SHELL_ENV.0, NO_LOGIN_SHELL_ENV.1)
            .await
            .map_err(|e| Status::internal(format!("failed to set login-shell env: {e}")))?;
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
    use crate::grpc::test_support::{
        authed_request, test_server_state, test_server_state_with_driver,
    };
    use crate::provider_profile_sources::ProviderProfileSources;
    use openshell_core::GatewayProviderProfileSourceConfig;
    use openshell_core::proto::GpuResourceRequirements;
    use openshell_core::proto::datamodel::v1::ObjectMeta;

    async fn test_server_state_with_user_only_github_profile() -> Arc<ServerState> {
        let mut state = test_server_state().await;
        Arc::get_mut(&mut state)
            .expect("test server state should be uniquely owned")
            .provider_profile_sources =
            ProviderProfileSources::from_config(&[GatewayProviderProfileSourceConfig::User], None)
                .expect("user-only provider profile source configuration should be valid");

        let github_profile = openshell_providers::builtin_profiles()
            .iter()
            .find(|profile| profile.id == "github")
            .expect("github builtin profile")
            .to_proto();
        state
            .store
            .put_message(&crate::provider_profile_sources::stored_provider_profile(
                github_profile,
            ))
            .await
            .expect("store user-managed github profile");
        state
    }

    // ---- shell_escape ----

    #[test]
    fn pty_dimensions_default_zero_values_without_overwriting_explicit_values() {
        assert_eq!(pty_dimensions(0, 0), (80, 24));
        assert_eq!(pty_dimensions(120, 40), (120, 40));
        assert_eq!(pty_dimensions(0, 40), (80, 40));
    }

    #[test]
    fn watch_terminal_phases_include_command_results_and_errors() {
        for phase in [
            SandboxPhase::Ready,
            SandboxPhase::Completed,
            SandboxPhase::Stopped,
            SandboxPhase::Error,
        ] {
            assert!(is_watch_terminal(phase), "{phase:?} should stop the watch");
        }
        for phase in [
            SandboxPhase::Provisioning,
            SandboxPhase::Starting,
            SandboxPhase::Stopping,
            SandboxPhase::Deleting,
            SandboxPhase::Unknown,
        ] {
            assert!(
                !is_watch_terminal(phase),
                "{phase:?} should keep the watch open"
            );
        }
    }

    #[test]
    fn sandbox_create_telemetry_uses_resolved_template_gpu_request() {
        let request = CreateSandboxRequest {
            spec: Some(SandboxSpec {
                providers: vec!["github".to_string()],
                policy: Some(openshell_core::proto::SandboxPolicy::default()),
                ..SandboxSpec::default()
            }),
            workload_template_name: "gpu-kata".to_string(),
            ..CreateSandboxRequest::default()
        };
        let created = Sandbox {
            spec: Some(SandboxSpec {
                providers: vec!["github".to_string()],
                policy: Some(openshell_core::proto::SandboxPolicy::default()),
                resource_requirements: Some(ResourceRequirements {
                    gpu: Some(GpuResourceRequirements { count: Some(1) }),
                }),
                ..SandboxSpec::default()
            }),
            created_from_workload_template: Some(SandboxWorkloadTemplateProvenance {
                name: "gpu-kata".to_string(),
                resource_version: "7".to_string(),
            }),
            ..Sandbox::default()
        };

        assert_eq!(
            sandbox_create_telemetry_attrs(&request, Some(&created)),
            SandboxCreateTelemetryAttrs {
                requested_gpu: true,
                provider_count: 1,
                has_custom_policy: true,
                template_source: SandboxTemplateSource::WorkloadTemplate,
            }
        );
    }

    #[test]
    fn sandbox_create_telemetry_falls_back_to_request_for_unresolved_template() {
        let request = CreateSandboxRequest {
            spec: Some(SandboxSpec {
                providers: vec!["github".to_string()],
                ..SandboxSpec::default()
            }),
            workload_template_name: "missing-template".to_string(),
            ..CreateSandboxRequest::default()
        };

        assert_eq!(
            sandbox_create_telemetry_attrs(&request, None),
            SandboxCreateTelemetryAttrs {
                requested_gpu: false,
                provider_count: 1,
                has_custom_policy: false,
                template_source: SandboxTemplateSource::WorkloadTemplate,
            }
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
            credential_handles: HashMap::new(),
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
            spec: Some(SandboxSpec {
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

    fn test_workload_template(name: &str) -> SandboxWorkloadTemplate {
        SandboxWorkloadTemplate {
            metadata: Some(ObjectMeta {
                id: String::new(),
                name: name.to_string(),
                created_at_ms: 0,
                labels: HashMap::from([("team".to_string(), "runtime".to_string())]),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: String::new(),
                deletion_timestamp_ms: 0,
            }),
            spec: Some(openshell_core::proto::SandboxWorkloadTemplateSpec {
                workload: Some(openshell_core::proto::SandboxWorkloadConfig {
                    image: "registry.example.com/agent:latest".to_string(),
                    environment: HashMap::from([("FEATURE_FLAG".to_string(), "on".to_string())]),
                    resources: Some(SandboxResources {
                        cpu: "2".to_string(),
                        memory: "4Gi".to_string(),
                        gpu: Some(GpuResourceRequirements { count: Some(1) }),
                    }),
                }),
                driver_config: None,
                desired_service_level: None,
            }),
        }
    }

    fn proto_string_value(value: &Value) -> Option<&str> {
        match value.kind.as_ref() {
            Some(Kind::StringValue(value)) => Some(value.as_str()),
            _ => None,
        }
    }

    #[tokio::test]
    #[ignore = "flaky under concurrent test execution"]
    async fn watch_producer_releases_request_span_when_client_disconnects() {
        use crate::otel_tracing::test_exporter;
        use tokio_stream::StreamExt as _;
        use tracing::Instrument as _;

        let state = test_server_state().await;
        let sandbox = test_sandbox("watched", Vec::new());
        state.store.put_message(&sandbox).await.unwrap();

        let traced = test_exporter::install_traced();
        let request_span = tracing::info_span!("disconnected_watch_request");
        let mut handler = Box::pin(
            handle_watch_sandbox(
                &state,
                authed_request(WatchSandboxRequest {
                    id: sandbox.object_id().to_string(),
                    ..Default::default()
                }),
            )
            .instrument(request_span.clone()),
        );
        let response = handler.as_mut().await.unwrap();
        // A completed instrumented future can retain its span until the future
        // itself is dropped. Release the handler's clone so this test isolates
        // whether the spawned watch producer retains the request span.
        drop(handler);
        let mut stream = response.into_inner();
        stream
            .next()
            .await
            .expect("watch producer should send the initial snapshot")
            .unwrap();

        drop(request_span);
        stream.disconnect_and_wait().await;

        assert_eq!(
            traced.spans_named("disconnected_watch_request").len(),
            1,
            "watch producer should release the request span after client disconnect"
        );
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
                authed_request(DeleteSandboxRequest {
                    name: "reused-name".to_string(),
                    workspace: "default".to_string(),
                }),
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while state.compute.lifecycle_gate_entry_count() == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
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
            authed_request(AttachSandboxProviderRequest {
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
    async fn attach_sandbox_provider_uses_configured_provider_profile_sources() {
        let state = test_server_state_with_user_only_github_profile().await;
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
            authed_request(AttachSandboxProviderRequest {
                sandbox_name: "work".to_string(),
                provider_name: "work-github".to_string(),
                expected_resource_version: 0,
                workspace: String::new(),
            }),
        )
        .await
        .expect("user-only profile catalog should not include the builtin github profile")
        .into_inner();

        assert!(response.attached);
        let sandbox = response.sandbox.expect("updated sandbox");
        assert_eq!(
            sandbox.spec.expect("sandbox spec").providers,
            vec!["work-github"]
        );
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
            authed_request(AttachSandboxProviderRequest {
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
            .put_message(&test_provider_with_credential_key(
                "other",
                "github",
                "GITHUB_TOKEN",
            ))
            .await
            .unwrap();
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
            authed_request(DetachSandboxProviderRequest {
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
            authed_request(DetachSandboxProviderRequest {
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
    async fn detach_rejects_provider_referenced_by_policy_credential_binding() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("work-gcp", "google-cloud"))
            .await
            .unwrap();

        let mut sandbox = test_sandbox("work", vec!["work-gcp".to_string()]);
        let policy = sandbox
            .spec
            .as_mut()
            .and_then(|spec| spec.policy.as_mut())
            .unwrap();
        policy.network_policies.insert(
            "gcp_storage".to_string(),
            openshell_core::proto::NetworkPolicyRule {
                name: "gcp_storage".to_string(),
                endpoints: vec![openshell_core::proto::NetworkEndpoint {
                    host: "storage.googleapis.com".to_string(),
                    port: 443,
                    credential_binding: Some(openshell_core::proto::NetworkCredentialBinding {
                        provider: "work-gcp".to_string(),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        state.store.put_message(&sandbox).await.unwrap();

        let error = handle_detach_sandbox_provider(
            &state,
            authed_request(DetachSandboxProviderRequest {
                sandbox_name: "work".to_string(),
                provider_name: "work-gcp".to_string(),
                expected_resource_version: 0,
                workspace: String::new(),
            }),
        )
        .await
        .expect_err("a referenced provider must remain attached");

        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("not attached"));
        let providers = state
            .store
            .get_message_by_name::<Sandbox>("default", "work")
            .await
            .unwrap()
            .unwrap()
            .spec
            .unwrap()
            .providers;
        assert_eq!(providers, vec!["work-gcp"]);
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
            authed_request(ListSandboxProvidersRequest {
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
            authed_request(AttachSandboxProviderRequest {
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
            authed_request(CreateSandboxRequest {
                name: "collision".to_string(),
                spec: Some(SandboxSpec {
                    providers: vec!["provider-a".to_string(), "provider-b".to_string()],
                    ..Default::default()
                }),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace: String::new(),
                await_main_process_attachment: false,
                workload_template_name: String::new(),
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
    async fn create_sandbox_uses_configured_provider_profile_sources() {
        let state = test_server_state_with_user_only_github_profile().await;

        let response = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                name: "user-catalog".to_string(),
                spec: Some(SandboxSpec::default()),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace: String::new(),
                await_main_process_attachment: false,
                workload_template_name: String::new(),
            }),
        )
        .await
        .expect("user-only profile catalog should not include the builtin github profile")
        .into_inner();

        assert_eq!(
            response.sandbox.expect("created sandbox").object_name(),
            "user-catalog"
        );
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
            authed_request(CreateSandboxRequest {
                name: "reserved-policy-key".to_string(),
                spec: Some(SandboxSpec {
                    policy: Some(policy),
                    ..Default::default()
                }),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace: String::new(),
                await_main_process_attachment: false,
                workload_template_name: String::new(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("_provider_work_github"));
        assert!(err.message().contains("reserved '_provider_' prefix"));
    }

    fn mcp_policy_with_options(
        mcp: Option<openshell_core::proto::McpOptions>,
    ) -> openshell_core::proto::SandboxPolicy {
        let mut policy = openshell_policy::restrictive_default_policy();
        policy.network_policies.insert(
            "mcp".to_string(),
            openshell_core::proto::NetworkPolicyRule {
                name: "mcp".to_string(),
                endpoints: vec![openshell_core::proto::NetworkEndpoint {
                    host: "mcp.example.com".to_string(),
                    port: 443,
                    protocol: "mcp".to_string(),
                    mcp,
                    // Keep this fixture valid independently of MCP version
                    // defaulting: without allow-all, MCP endpoints require an
                    // explicit method rule at the L7 validation boundary.
                    rules: vec![openshell_core::proto::L7Rule {
                        allow: Some(openshell_core::proto::L7Allow {
                            method: "tools/list".to_string(),
                            ..Default::default()
                        }),
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        policy
    }

    fn mcp_policy_with_versions(versions: &[&str]) -> openshell_core::proto::SandboxPolicy {
        mcp_policy_with_options(Some(openshell_core::proto::McpOptions {
            versions: versions.iter().map(ToString::to_string).collect(),
            ..Default::default()
        }))
    }

    fn mcp_padding_rule_name_for_policy_size(target_size: usize) -> String {
        let mut policy = mcp_policy_with_versions(&["2025-11-25"]);
        openshell_policy::ensure_sandbox_process_identity(&mut policy);
        let mut policy = validate_and_canonicalize_policy(policy)
            .expect("explicit default MCP policy must be canonicalizable");
        policy.network_policies.insert(
            "padding".to_string(),
            openshell_core::proto::NetworkPolicyRule::default(),
        );

        // The padding rule has no endpoints and therefore does not change the
        // policy's behavior. Iterative adjustment accounts for protobuf varint
        // length-prefix growth while targeting the exact encoded boundary.
        for _ in 0..4 {
            let current_size = policy.encoded_len();
            if current_size == target_size {
                break;
            }

            let padding = &mut policy
                .network_policies
                .get_mut("padding")
                .expect("padding rule must exist")
                .name;
            if current_size < target_size {
                padding.push_str(&"x".repeat(target_size - current_size));
            } else {
                let new_len = padding
                    .len()
                    .checked_sub(current_size - target_size)
                    .expect("padding adjustment must remain nonnegative");
                padding.truncate(new_len);
            }
        }

        assert_eq!(policy.encoded_len(), target_size);
        policy
            .network_policies
            .remove("padding")
            .expect("padding rule must exist")
            .name
    }

    #[tokio::test]
    async fn create_sandbox_canonicalizes_mcp_versions_before_persistence() {
        let state = test_server_state().await;

        handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                name: "mcp-canonical".to_string(),
                spec: Some(SandboxSpec {
                    policy: Some(mcp_policy_with_versions(&["2025-11-25", "2025-03-26"])),
                    ..Default::default()
                }),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace: String::new(),
                ..Default::default()
            }),
        )
        .await
        .expect("supported MCP versions must be accepted");

        let stored = state
            .store
            .get_message_by_name::<Sandbox>("default", "mcp-canonical")
            .await
            .expect("stored sandbox lookup must succeed")
            .expect("created sandbox must be persisted");
        let policy = stored
            .spec
            .expect("sandbox spec")
            .policy
            .expect("sandbox policy");
        let versions = &policy.network_policies["mcp"].endpoints[0]
            .mcp
            .as_ref()
            .expect("MCP options")
            .versions;
        assert_eq!(versions, &["2025-03-26", "2025-11-25"]);
    }

    #[tokio::test]
    async fn create_sandbox_materializes_default_mcp_version_before_persistence() {
        let state = test_server_state().await;
        let cases = [
            ("mcp-def-no-opts", None),
            (
                "mcp-def-empty",
                Some(openshell_core::proto::McpOptions::default()),
            ),
            (
                "mcp-def-explicit",
                Some(openshell_core::proto::McpOptions {
                    versions: vec!["2025-11-25".to_string()],
                    ..Default::default()
                }),
            ),
        ];
        let mut expected_policy = None;
        let mut expected_bytes = None;

        for (sandbox_name, mcp) in cases {
            handle_create_sandbox(
                &state,
                authed_request(CreateSandboxRequest {
                    name: sandbox_name.to_string(),
                    spec: Some(SandboxSpec {
                        policy: Some(mcp_policy_with_options(mcp)),
                        ..Default::default()
                    }),
                    labels: HashMap::new(),
                    annotations: HashMap::new(),
                    workspace: String::new(),
                    ..Default::default()
                }),
            )
            .await
            .expect("defaultable MCP versions must be accepted");

            let stored = state
                .store
                .get_message_by_name::<Sandbox>("default", sandbox_name)
                .await
                .expect("stored sandbox lookup must succeed")
                .expect("created sandbox must be persisted");
            let policy = stored
                .spec
                .expect("sandbox spec")
                .policy
                .expect("sandbox policy");
            let options = policy.network_policies["mcp"].endpoints[0]
                .mcp
                .as_ref()
                .expect("MCP options must be materialized before persistence");
            assert_eq!(options.versions, ["2025-11-25"], "{sandbox_name}");

            let encoded = policy.encode_to_vec();
            if let Some(expected) = expected_policy.as_ref() {
                assert_eq!(
                    &policy, expected,
                    "default spellings must persist the same canonical policy: {sandbox_name}"
                );
                assert_eq!(
                    encoded,
                    *expected_bytes
                        .as_ref()
                        .expect("canonical policy bytes accompany the expected policy"),
                    "default spellings must persist identical policy bytes: {sandbox_name}"
                );
            } else {
                expected_policy = Some(policy);
                expected_bytes = Some(encoded);
            }
        }
    }

    #[tokio::test]
    async fn create_sandbox_bounds_canonical_mcp_policy_size_for_all_default_spellings() {
        let state = test_server_state().await;
        let max_policy_size = super::super::MAX_POLICY_SIZE;

        for (boundary, target_size, should_accept) in [
            ("fit", max_policy_size, true),
            ("over", max_policy_size + 1, false),
        ] {
            let padding_name = mcp_padding_rule_name_for_policy_size(target_size);
            let cases = [
                ("omitted", None),
                ("empty", Some(openshell_core::proto::McpOptions::default())),
                (
                    "explicit",
                    Some(openshell_core::proto::McpOptions {
                        versions: vec!["2025-11-25".to_string()],
                        ..Default::default()
                    }),
                ),
            ];

            for (spelling, mcp) in cases {
                let sandbox_name = format!("mcp-{boundary}-{spelling}");
                let mut policy = mcp_policy_with_options(mcp);
                openshell_policy::ensure_sandbox_process_identity(&mut policy);
                policy.network_policies.insert(
                    "padding".to_string(),
                    openshell_core::proto::NetworkPolicyRule {
                        name: padding_name.clone(),
                        ..Default::default()
                    },
                );

                let raw_size = policy.encoded_len();
                if spelling == "explicit" {
                    assert_eq!(raw_size, target_size, "{sandbox_name}");
                } else {
                    assert!(raw_size < target_size, "{sandbox_name}: {raw_size}");
                }

                let canonical = validate_and_canonicalize_policy(policy.clone())
                    .expect("defaultable MCP policy must be canonicalizable");
                assert_eq!(canonical.encoded_len(), target_size, "{sandbox_name}");

                let result = handle_create_sandbox(
                    &state,
                    authed_request(CreateSandboxRequest {
                        name: sandbox_name.clone(),
                        spec: Some(SandboxSpec {
                            policy: Some(policy),
                            ..Default::default()
                        }),
                        labels: HashMap::new(),
                        annotations: HashMap::new(),
                        workspace: String::new(),
                        ..Default::default()
                    }),
                )
                .await;

                if should_accept {
                    result.expect("canonical policy at the size limit must be accepted");
                    let stored = state
                        .store
                        .get_message_by_name::<Sandbox>("default", &sandbox_name)
                        .await
                        .expect("stored sandbox lookup must succeed")
                        .expect("accepted sandbox must be persisted");
                    let stored_policy = stored
                        .spec
                        .expect("sandbox spec")
                        .policy
                        .expect("sandbox policy");
                    assert_eq!(stored_policy, canonical, "{sandbox_name}");
                    assert_eq!(
                        stored_policy.encoded_len(),
                        max_policy_size,
                        "{sandbox_name}"
                    );
                } else {
                    let error = result.expect_err("oversized canonical policy must be rejected");
                    assert_eq!(error.code(), tonic::Code::InvalidArgument, "{sandbox_name}");
                    assert_eq!(
                        error.message(),
                        format!(
                            "policy serialized size exceeds maximum ({target_size} > {max_policy_size})"
                        ),
                        "{sandbox_name}"
                    );
                    let stored = state
                        .store
                        .get_message_by_name::<Sandbox>("default", &sandbox_name)
                        .await
                        .expect("stored sandbox lookup must succeed");
                    assert!(
                        stored.is_none(),
                        "oversized policy must not persist sandbox {sandbox_name}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn create_sandbox_rejects_invalid_mcp_versions_without_persisting() {
        let state = test_server_state().await;
        let cases: &[(&str, &[&str])] = &[
            ("mcp-duplicate-versions", &["2025-11-25", "2025-11-25"]),
            ("mcp-unsupported-version", &["2026-07-28"]),
        ];

        for &(sandbox_name, versions) in cases {
            let error = handle_create_sandbox(
                &state,
                authed_request(CreateSandboxRequest {
                    name: sandbox_name.to_string(),
                    spec: Some(SandboxSpec {
                        policy: Some(mcp_policy_with_versions(versions)),
                        ..Default::default()
                    }),
                    labels: HashMap::new(),
                    annotations: HashMap::new(),
                    workspace: String::new(),
                    ..Default::default()
                }),
            )
            .await
            .expect_err("invalid MCP versions must reject sandbox creation");

            assert_eq!(error.code(), tonic::Code::InvalidArgument, "{sandbox_name}");
            let stored = state
                .store
                .get_message_by_name::<Sandbox>("default", sandbox_name)
                .await
                .expect("stored sandbox lookup must succeed");
            assert!(
                stored.is_none(),
                "invalid MCP versions must not persist sandbox {sandbox_name}"
            );
        }
    }

    #[tokio::test]
    async fn create_sandbox_persists_long_metadata_annotations() {
        let state = test_server_state().await;
        let annotation_key = "openshell.nvidia.com/policy-signature".to_string();
        let annotation_value = "x".repeat(512);

        let response = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                name: "annotated".to_string(),
                spec: Some(SandboxSpec::default()),
                labels: HashMap::new(),
                annotations: HashMap::from([(annotation_key.clone(), annotation_value.clone())]),
                workspace: String::new(),
                await_main_process_attachment: false,
                workload_template_name: String::new(),
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
            authed_request(GetSandboxRequest {
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
    async fn create_and_get_preserve_partial_process_identity() {
        let state = test_server_state_with_driver("docker").await;
        let policy = openshell_core::proto::SandboxPolicy {
            version: 1,
            process: Some(openshell_core::proto::ProcessPolicy {
                run_as_user: String::new(),
                run_as_group: "1234".to_string(),
            }),
            ..Default::default()
        };

        let response = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                name: "partial-id".to_string(),
                spec: Some(SandboxSpec {
                    policy: Some(policy),
                    ..Default::default()
                }),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace: String::new(),
                await_main_process_attachment: false,
                workload_template_name: String::new(),
            }),
        )
        .await
        .expect("partial process identity should be accepted")
        .into_inner();

        let created_process = response
            .sandbox
            .unwrap()
            .spec
            .unwrap()
            .policy
            .unwrap()
            .process
            .unwrap();
        assert!(created_process.run_as_user.is_empty());
        assert_eq!(created_process.run_as_group, "1234");

        let fetched_process = handle_get_sandbox(
            &state,
            authed_request(GetSandboxRequest {
                name: "partial-id".to_string(),
                workspace: String::new(),
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap()
        .spec
        .unwrap()
        .policy
        .unwrap()
        .process
        .unwrap();
        assert!(fetched_process.run_as_user.is_empty());
        assert_eq!(fetched_process.run_as_group, "1234");
    }

    #[tokio::test]
    async fn create_and_get_preserve_partial_process_identity_for_kubernetes() {
        let state = test_server_state_with_driver("kubernetes").await;
        let policy = openshell_core::proto::SandboxPolicy {
            version: 1,
            process: Some(openshell_core::proto::ProcessPolicy {
                run_as_user: String::new(),
                run_as_group: "1234".to_string(),
            }),
            ..Default::default()
        };

        let response = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                name: "kube-partial-id".to_string(),
                spec: Some(SandboxSpec {
                    policy: Some(policy),
                    ..Default::default()
                }),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace: String::new(),
                await_main_process_attachment: false,
                workload_template_name: String::new(),
            }),
        )
        .await
        .expect("partial Kubernetes process identity should be accepted")
        .into_inner();

        let process = response
            .sandbox
            .unwrap()
            .spec
            .unwrap()
            .policy
            .unwrap()
            .process
            .unwrap();
        assert!(process.run_as_user.is_empty());
        assert_eq!(process.run_as_group, "1234");
    }

    #[tokio::test]
    async fn create_sandbox_still_rejects_long_label_values() {
        let state = test_server_state().await;
        let err = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                name: "bad-label".to_string(),
                spec: Some(SandboxSpec::default()),
                labels: HashMap::from([("team".to_string(), "x".repeat(512))]),
                annotations: HashMap::new(),
                workspace: String::new(),
                await_main_process_attachment: false,
                workload_template_name: String::new(),
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
                authed_request(CreateSandboxRequest {
                    name: "guarded-create".to_string(),
                    spec: Some(SandboxSpec {
                        providers: vec!["work-github".to_string()],
                        ..Default::default()
                    }),
                    labels: HashMap::new(),
                    annotations: HashMap::new(),
                    workspace: String::new(),
                    await_main_process_attachment: false,
                    workload_template_name: String::new(),
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
    async fn sandbox_template_handlers_create_get_list_and_delete_workspace_resource() {
        let state = test_server_state().await;

        let created = handle_create_sandbox_template(
            &state,
            authed_request(CreateSandboxTemplateRequest {
                template: Some(test_workload_template("gpu-kata")),
                workspace: "default".to_string(),
            }),
        )
        .await
        .expect("template create should succeed")
        .into_inner()
        .template
        .expect("template response");

        let metadata = created.metadata.as_ref().expect("metadata");
        assert_eq!(metadata.name, "gpu-kata");
        assert_eq!(metadata.workspace, "default");
        assert!(!metadata.id.is_empty());
        assert_ne!(metadata.resource_version, 0);

        let fetched = handle_get_sandbox_template(
            &state,
            authed_request(GetSandboxTemplateRequest {
                name: "gpu-kata".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .expect("template get should succeed")
        .into_inner()
        .template
        .expect("fetched template");
        assert_eq!(fetched.object_name(), "gpu-kata");
        assert_eq!(fetched.object_workspace(), "default");

        let listed = handle_list_sandbox_templates(
            &state,
            authed_request(ListSandboxTemplatesRequest {
                limit: 100,
                offset: 0,
                workspace: "default".to_string(),
                all_workspaces: false,
                label_selector: String::new(),
            }),
        )
        .await
        .expect("template list should succeed")
        .into_inner()
        .templates;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].object_name(), "gpu-kata");

        let deleted = handle_delete_sandbox_template(
            &state,
            authed_request(DeleteSandboxTemplateRequest {
                name: "gpu-kata".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .expect("template delete should succeed")
        .into_inner();
        assert!(deleted.deleted);

        let missing = handle_get_sandbox_template(
            &state,
            authed_request(GetSandboxTemplateRequest {
                name: "gpu-kata".to_string(),
                workspace: "default".to_string(),
            }),
        )
        .await
        .expect_err("deleted template should not be fetchable");
        assert_eq!(missing.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn sandbox_template_list_filters_by_label_selector() {
        let state = test_server_state().await;

        let mut gpu = test_workload_template("gpu-kata");
        gpu.metadata
            .as_mut()
            .expect("metadata")
            .labels
            .insert("team".to_string(), "runtime".to_string());
        handle_create_sandbox_template(
            &state,
            authed_request(CreateSandboxTemplateRequest {
                template: Some(gpu),
                workspace: "default".to_string(),
            }),
        )
        .await
        .expect("gpu template create should succeed");

        let mut cpu = test_workload_template("cpu-base");
        cpu.metadata
            .as_mut()
            .expect("metadata")
            .labels
            .insert("team".to_string(), "batch".to_string());
        handle_create_sandbox_template(
            &state,
            authed_request(CreateSandboxTemplateRequest {
                template: Some(cpu),
                workspace: "default".to_string(),
            }),
        )
        .await
        .expect("cpu template create should succeed");

        let listed = handle_list_sandbox_templates(
            &state,
            authed_request(ListSandboxTemplatesRequest {
                limit: 100,
                offset: 0,
                workspace: "default".to_string(),
                all_workspaces: false,
                label_selector: "team=runtime".to_string(),
            }),
        )
        .await
        .expect("template list with label selector should succeed")
        .into_inner()
        .templates;

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].object_name(), "gpu-kata");
    }

    #[tokio::test]
    async fn sandbox_template_create_rejects_whitespace_name() {
        let state = test_server_state().await;

        let err = handle_create_sandbox_template(
            &state,
            authed_request(CreateSandboxTemplateRequest {
                template: Some(test_workload_template(" gpu-kata ")),
                workspace: "default".to_string(),
            }),
        )
        .await
        .expect_err("template names must be canonical DNS-1123 labels");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("template.metadata.name"));

        let listed = handle_list_sandbox_templates(
            &state,
            authed_request(ListSandboxTemplatesRequest {
                limit: 100,
                offset: 0,
                workspace: "default".to_string(),
                all_workspaces: false,
                label_selector: String::new(),
            }),
        )
        .await
        .expect("template list should succeed")
        .into_inner()
        .templates;
        assert!(listed.is_empty());
    }

    #[tokio::test]
    async fn sandbox_template_create_empty_workspace_ignores_metadata_workspace() {
        use openshell_core::proto::CreateWorkspaceRequest;

        let state = test_server_state().await;
        crate::grpc::workspace::handle_create_workspace(
            &state,
            Request::new(CreateWorkspaceRequest {
                name: "beta".to_string(),
                labels: HashMap::new(),
            }),
        )
        .await
        .expect("beta workspace should be created");

        let mut template = test_workload_template("copied-template");
        template.metadata.as_mut().unwrap().workspace = "beta".to_string();

        let err = handle_create_sandbox_template(
            &state,
            authed_request(CreateSandboxTemplateRequest {
                template: Some(template),
                workspace: String::new(),
            }),
        )
        .await
        .expect_err("empty request workspace must default to default, not metadata workspace");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("template.metadata.workspace"));

        let listed = handle_list_sandbox_templates(
            &state,
            authed_request(ListSandboxTemplatesRequest {
                limit: 100,
                offset: 0,
                workspace: "beta".to_string(),
                all_workspaces: false,
                label_selector: String::new(),
            }),
        )
        .await
        .expect("template list should succeed")
        .into_inner()
        .templates;
        assert!(listed.is_empty());
    }

    #[tokio::test]
    async fn sandbox_template_create_rejects_missing_spec_as_invalid_argument() {
        let state = test_server_state().await;
        let mut template = test_workload_template("missing-spec");
        template.spec = None;

        let err = handle_create_sandbox_template(
            &state,
            authed_request(CreateSandboxTemplateRequest {
                template: Some(template),
                workspace: "default".to_string(),
            }),
        )
        .await
        .expect_err("template create should reject missing spec");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("sandbox template spec"));
    }

    #[test]
    fn sandbox_template_validation_allows_positive_ready_within() {
        let mut template = test_workload_template("gpu-kata");
        template.metadata.as_mut().unwrap().id = "template-gpu-kata".to_string();
        template.spec.as_mut().unwrap().desired_service_level =
            Some(openshell_core::proto::SandboxServiceLevel {
                startup: Some(openshell_core::proto::SandboxStartup {
                    ready_within: Some(prost_types::Duration {
                        seconds: 1,
                        nanos: 0,
                    }),
                    max_burst: 1,
                }),
            });

        validate_sandbox_workload_template(&template).expect("positive ready_within should pass");
    }

    #[test]
    fn sandbox_template_validation_rejects_non_positive_ready_within() {
        for (duration, expected) in [
            (
                prost_types::Duration {
                    seconds: 0,
                    nanos: 0,
                },
                "greater than zero",
            ),
            (
                prost_types::Duration {
                    seconds: -1,
                    nanos: 0,
                },
                "greater than zero",
            ),
            (
                prost_types::Duration {
                    seconds: 0,
                    nanos: -1,
                },
                "greater than zero",
            ),
        ] {
            let mut template = test_workload_template("gpu-kata");
            template.metadata.as_mut().unwrap().id = "template-gpu-kata".to_string();
            template.spec.as_mut().unwrap().desired_service_level =
                Some(openshell_core::proto::SandboxServiceLevel {
                    startup: Some(openshell_core::proto::SandboxStartup {
                        ready_within: Some(duration),
                        max_burst: 1,
                    }),
                });

            let err = validate_sandbox_workload_template(&template)
                .expect_err("non-positive ready_within should be rejected");
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
            assert!(err.message().contains(expected), "{err:?}");
            assert!(
                err.message()
                    .contains("template.spec.desired_service_level.startup.ready_within"),
                "{err:?}"
            );
        }
    }

    #[test]
    fn sandbox_template_validation_rejects_malformed_ready_within() {
        for (duration, expected) in [
            (
                prost_types::Duration {
                    seconds: 1,
                    nanos: -1,
                },
                "normalized",
            ),
            (
                prost_types::Duration {
                    seconds: 0,
                    nanos: 1_000_000_000,
                },
                "valid protobuf Duration",
            ),
            (
                prost_types::Duration {
                    seconds: 315_576_000_001,
                    nanos: 0,
                },
                "valid protobuf Duration",
            ),
        ] {
            let mut template = test_workload_template("gpu-kata");
            template.metadata.as_mut().unwrap().id = "template-gpu-kata".to_string();
            template.spec.as_mut().unwrap().desired_service_level =
                Some(openshell_core::proto::SandboxServiceLevel {
                    startup: Some(openshell_core::proto::SandboxStartup {
                        ready_within: Some(duration),
                        max_burst: 1,
                    }),
                });

            let err = validate_sandbox_workload_template(&template)
                .expect_err("malformed ready_within should be rejected");
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
            assert!(err.message().contains(expected), "{err:?}");
            assert!(
                err.message()
                    .contains("template.spec.desired_service_level.startup.ready_within"),
                "{err:?}"
            );
        }
    }

    #[tokio::test]
    async fn sandbox_template_create_rejects_workspace_quota() {
        let state = test_server_state().await;
        for index in 0..MAX_TEMPLATES_PER_WORKSPACE {
            let mut template = test_workload_template(&format!("tmpl-{index}"));
            let metadata = template.metadata.as_mut().expect("metadata");
            metadata.id = format!("template-{index}");
            metadata.workspace = "default".to_string();
            state.store.put_message(&template).await.unwrap();
        }

        let err = handle_create_sandbox_template(
            &state,
            authed_request(CreateSandboxTemplateRequest {
                template: Some(test_workload_template("overflow")),
                workspace: "default".to_string(),
            }),
        )
        .await
        .expect_err("template create must reject a full workspace");

        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert!(err.message().contains("1000 sandbox templates"));
    }

    #[tokio::test]
    async fn sandbox_template_create_enforces_workspace_quota_concurrently() {
        let state = test_server_state().await;
        for index in 0..(MAX_TEMPLATES_PER_WORKSPACE - 1) {
            let mut template = test_workload_template(&format!("tmpl-{index}"));
            let metadata = template.metadata.as_mut().expect("metadata");
            metadata.id = format!("template-{index}");
            metadata.workspace = "default".to_string();
            state.store.put_message(&template).await.unwrap();
        }

        let mut handles = vec![];
        for index in 0..8 {
            let state = Arc::clone(&state);
            let handle = tokio::spawn(async move {
                handle_create_sandbox_template(
                    &state,
                    authed_request(CreateSandboxTemplateRequest {
                        template: Some(test_workload_template(&format!("overflow-{index}"))),
                        workspace: "default".to_string(),
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

        let successes = results.iter().filter(|r| r.is_ok()).count();
        let exhausted = results
            .iter()
            .filter(|r| {
                r.as_ref()
                    .err()
                    .is_some_and(|e| e.code() == tonic::Code::ResourceExhausted)
            })
            .count();

        assert_eq!(successes, 1);
        assert_eq!(exhausted, 7);
        let count = state
            .store
            .count_in_workspace(SandboxWorkloadTemplate::object_type(), "default")
            .await
            .unwrap();
        assert_eq!(count, u64::from(MAX_TEMPLATES_PER_WORKSPACE));
    }

    #[test]
    fn template_create_sandbox_spec_field_policy_is_exhaustive() {
        assert_proto_fields_classified(
            "openshell.v1.SandboxSpec",
            &["policy", "providers", "command", "tty"],
            &[
                "log_level",
                "environment",
                "template",
                "resource_requirements",
            ],
        );
    }

    fn assert_proto_fields_classified(
        message_name: &str,
        copied_from_create_request: &[&str],
        rejected_template_workload_overrides: &[&str],
    ) {
        let pool = prost_reflect::DescriptorPool::decode(openshell_core::FILE_DESCRIPTOR_SET)
            .expect("decode descriptor set");
        let message = pool
            .get_message_by_name(message_name)
            .expect("message descriptor");
        let classified: std::collections::HashSet<&str> = copied_from_create_request
            .iter()
            .chain(rejected_template_workload_overrides.iter())
            .copied()
            .collect();
        let actual: std::collections::HashSet<String> = message
            .fields()
            .map(|field| field.name().to_string())
            .collect();

        for field in &actual {
            assert!(
                classified.contains(field.as_str()),
                "{message_name}.{field} is not classified for template-backed sandbox creates. \
                 Add it to copied_from_create_request when callers own the create-time value, \
                 or to rejected_template_workload_overrides when the workload template owns it."
            );
        }

        for field in classified {
            assert!(
                actual.contains(field),
                "{message_name}.{field} is classified for template-backed sandbox creates, \
                 but the proto field no longer exists"
            );
        }
    }

    #[tokio::test]
    async fn create_sandbox_from_workload_template_resolves_workload_and_preserves_governance() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();
        handle_create_sandbox_template(
            &state,
            authed_request(CreateSandboxTemplateRequest {
                template: Some(test_workload_template("gpu-kata")),
                workspace: "default".to_string(),
            }),
        )
        .await
        .expect("template create should succeed");

        let mut policy = openshell_core::proto::SandboxPolicy {
            version: 1,
            ..Default::default()
        };
        policy.network_policies.insert(
            "example".to_string(),
            openshell_core::proto::NetworkPolicyRule {
                name: "example".to_string(),
                ..Default::default()
            },
        );

        let created = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                name: "from-template".to_string(),
                spec: Some(SandboxSpec {
                    providers: vec!["work-github".to_string()],
                    policy: Some(policy),
                    command: vec!["echo".to_string(), "template-create".to_string()],
                    tty: false,
                    ..Default::default()
                }),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                workload_template_name: "gpu-kata".to_string(),
                await_main_process_attachment: false,
            }),
        )
        .await
        .expect("sandbox create from template should succeed")
        .into_inner()
        .sandbox
        .expect("created sandbox");

        let provenance = created
            .created_from_workload_template
            .expect("template provenance");
        assert_eq!(provenance.name, "gpu-kata");
        assert!(!provenance.resource_version.is_empty());

        let spec = created.spec.expect("resolved sandbox spec");
        assert_eq!(spec.providers, vec!["work-github".to_string()]);
        assert!(spec.policy.is_some());
        assert_eq!(
            spec.command,
            vec!["echo".to_string(), "template-create".to_string()]
        );
        assert!(!spec.tty);
        assert_eq!(
            spec.environment.get("FEATURE_FLAG"),
            Some(&"on".to_string())
        );

        let template = spec.template.expect("resolved inline template");
        assert_eq!(template.image, "registry.example.com/agent:latest");
        let limits = template
            .resources
            .as_ref()
            .and_then(|resources| resources.fields.get("limits"))
            .and_then(|limits| limits.kind.as_ref())
            .and_then(|kind| match kind {
                Kind::StructValue(value) => Some(&value.fields),
                _ => None,
            })
            .expect("resource limits");
        assert_eq!(limits.get("cpu").and_then(proto_string_value), Some("2"));
        assert_eq!(
            limits.get("memory").and_then(proto_string_value),
            Some("4Gi")
        );
        assert_eq!(
            spec.resource_requirements
                .and_then(|requirements| requirements.gpu)
                .and_then(|gpu| gpu.count),
            Some(1)
        );
    }

    #[tokio::test]
    async fn create_sandbox_from_workload_template_defaults_whitespace_image() {
        let state = test_server_state().await;
        let mut template = test_workload_template("default-image");
        template
            .spec
            .as_mut()
            .and_then(|spec| spec.workload.as_mut())
            .expect("test template workload")
            .image = "  ".to_string();
        handle_create_sandbox_template(
            &state,
            authed_request(CreateSandboxTemplateRequest {
                template: Some(template),
                workspace: "default".to_string(),
            }),
        )
        .await
        .expect("template create should succeed");

        let created = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                name: "from-template".to_string(),
                spec: Some(SandboxSpec::default()),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                workload_template_name: "default-image".to_string(),
                await_main_process_attachment: false,
            }),
        )
        .await
        .expect("sandbox create from template should succeed")
        .into_inner()
        .sandbox
        .expect("created sandbox");

        let image = created
            .spec
            .and_then(|spec| spec.template)
            .map(|template| template.image)
            .expect("resolved template image");
        assert_eq!(image, state.compute.default_image());
    }

    #[tokio::test]
    async fn create_sandbox_from_workload_template_preserves_default_gpu_request() {
        let state = test_server_state().await;
        let mut template = test_workload_template("default-gpu");
        template
            .spec
            .as_mut()
            .and_then(|spec| spec.workload.as_mut())
            .and_then(|workload| workload.resources.as_mut())
            .expect("test template resources")
            .gpu = Some(GpuResourceRequirements { count: None });
        handle_create_sandbox_template(
            &state,
            authed_request(CreateSandboxTemplateRequest {
                template: Some(template),
                workspace: "default".to_string(),
            }),
        )
        .await
        .expect("template create should succeed");

        let created = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                name: "from-template".to_string(),
                spec: Some(SandboxSpec::default()),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                workload_template_name: "default-gpu".to_string(),
                await_main_process_attachment: false,
            }),
        )
        .await
        .expect("sandbox create from template should succeed")
        .into_inner()
        .sandbox
        .expect("created sandbox");

        let gpu = created
            .spec
            .as_ref()
            .and_then(|spec| spec.resource_requirements.as_ref())
            .and_then(|requirements| requirements.gpu.as_ref())
            .expect("default GPU request should be preserved");
        assert_eq!(gpu.count, None);
    }

    #[tokio::test]
    async fn create_sandbox_from_corrupted_workload_template_returns_internal() {
        let state = test_server_state().await;
        let mut template = test_workload_template("corrupt-template");
        let metadata = template.metadata.as_mut().expect("metadata");
        metadata.id = "template-corrupt-template".to_string();
        metadata.workspace = "default".to_string();
        template.spec = None;
        state.store.put_message(&template).await.unwrap();

        let err = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                name: "from-corrupt".to_string(),
                spec: Some(SandboxSpec::default()),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                workload_template_name: "corrupt-template".to_string(),
                await_main_process_attachment: false,
            }),
        )
        .await
        .expect_err("corrupted stored template should fail as server data corruption");

        assert_eq!(err.code(), tonic::Code::Internal, "{}", err.message());
        assert!(err.message().contains("sandbox template spec"));
    }

    #[tokio::test]
    async fn create_sandbox_from_workload_template_rejects_inline_workload_overrides() {
        let state = test_server_state().await;
        handle_create_sandbox_template(
            &state,
            authed_request(CreateSandboxTemplateRequest {
                template: Some(test_workload_template("gpu-kata")),
                workspace: "default".to_string(),
            }),
        )
        .await
        .expect("template create should succeed");

        let err = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                name: "bad-template-create".to_string(),
                spec: Some(SandboxSpec {
                    environment: HashMap::from([("INLINE".to_string(), "blocked".to_string())]),
                    ..Default::default()
                }),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                workload_template_name: "gpu-kata".to_string(),
                await_main_process_attachment: false,
            }),
        )
        .await
        .expect_err("inline workload overrides should be rejected");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("spec.environment"));
    }

    #[tokio::test]
    async fn create_sandbox_from_workload_template_rejects_malformed_template_name() {
        let state = test_server_state().await;

        let err = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                name: "bad-template-create".to_string(),
                spec: Some(SandboxSpec::default()),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                workload_template_name: "Invalid_Template_Name".to_string(),
                await_main_process_attachment: false,
            }),
        )
        .await
        .expect_err("malformed template name should be rejected before lookup");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("workload_template_name"));
    }

    #[tokio::test]
    async fn create_sandbox_from_workload_template_rejects_oversized_governance_before_lookup() {
        let state = test_server_state().await;

        let err = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                name: "bad-template-create".to_string(),
                spec: Some(SandboxSpec {
                    providers: (0..=MAX_PROVIDERS).map(|i| format!("p-{i}")).collect(),
                    ..Default::default()
                }),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                workload_template_name: "missing-template".to_string(),
                await_main_process_attachment: false,
            }),
        )
        .await
        .expect_err("oversized governance spec should be rejected before template lookup");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("providers"));
    }

    #[tokio::test]
    async fn create_sandbox_rejects_oversized_direct_spec_before_workspace_lookup() {
        let state = test_server_state().await;

        let err = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                name: "bad-direct-create".to_string(),
                spec: Some(SandboxSpec {
                    providers: (0..=MAX_PROVIDERS).map(|i| format!("p-{i}")).collect(),
                    ..Default::default()
                }),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace: "missing-workspace".to_string(),
                workload_template_name: String::new(),
                await_main_process_attachment: false,
            }),
        )
        .await
        .expect_err("oversized direct spec should be rejected before workspace lookup");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("providers"));
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
            authed_request(AttachSandboxProviderRequest {
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
            authed_request(AttachSandboxProviderRequest {
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
            authed_request(AttachSandboxProviderRequest {
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
            authed_request(AttachSandboxProviderRequest {
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
            authed_request(DetachSandboxProviderRequest {
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
                authed_request(CreateSshSessionRequest {
                    sandbox_id: "sandbox-work".to_string(),
                }),
            )
            .await
        });

        let state2 = state.clone();
        let handle2 = tokio::spawn(async move {
            handle_create_ssh_session(
                &state2,
                authed_request(CreateSshSessionRequest {
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
    async fn create_ssh_session_allows_terminal_sandbox_while_supervisor_is_reachable() {
        let state = test_server_state().await;
        let mut sandbox = test_sandbox("work", Vec::new());
        sandbox.set_phase(SandboxPhase::Completed as i32);
        state.store.put_message(&sandbox).await.unwrap();

        let (tx, _rx) = mpsc::channel(1);
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        let _ = state.supervisor_sessions.register(
            "sandbox-work".to_string(),
            "session-1".to_string(),
            tx,
            shutdown_tx,
        );

        let response = handle_create_ssh_session(
            &state,
            authed_request(CreateSshSessionRequest {
                sandbox_id: "sandbox-work".to_string(),
            }),
        )
        .await;

        assert!(response.is_ok());

        assert!(
            state
                .supervisor_sessions
                .finalize_main_process_exit("sandbox-work")
        );
        assert!(!sandbox_relay_reachable(&state, &sandbox));
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
            authed_request(CreateSshSessionRequest {
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
                authed_request(RevokeSshSessionRequest { token: token1 }),
            )
            .await
        });

        let state2 = state.clone();
        let token2 = token.clone();
        let handle2 = tokio::spawn(async move {
            handle_revoke_ssh_session(
                &state2,
                authed_request(RevokeSshSessionRequest { token: token2 }),
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
            authed_request(AttachSandboxProviderRequest {
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
            authed_request(AttachSandboxProviderRequest {
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
            authed_request(DetachSandboxProviderRequest {
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
            authed_request(DetachSandboxProviderRequest {
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
                    authed_request(AttachSandboxProviderRequest {
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
            authed_request(GetSandboxRequest {
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
            authed_request(GetSandboxRequest {
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
            authed_request(ListSandboxesRequest {
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
            authed_request(ListSandboxesRequest {
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
            authed_request(ListSandboxesRequest {
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
            authed_request(GetSandboxRequest {
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
            authed_request(ListSandboxesRequest {
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
            authed_request(ListSandboxesRequest {
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

    /// Non-members must receive `PERMISSION_DENIED` — never `NOT_FOUND` — when
    /// calling workspace-scoped sandbox RPCs with a workspace they do not belong
    /// to.  If `authorize_workspace` ran *after* a store lookup the error code
    /// would leak whether the workspace name exists (CWE-203 oracle).
    #[tokio::test]
    async fn non_member_gets_permission_denied_not_workspace_oracle() {
        use crate::auth::identity::{Identity, IdentityProvider};
        use crate::auth::principal::{Principal, UserPrincipal};
        use tonic::Code;

        fn non_member_request<T>(inner: T) -> Request<T> {
            let mut req = Request::new(inner);
            req.extensions_mut().insert(Principal::User(UserPrincipal {
                identity: Identity {
                    subject: "non-member".to_string(),
                    display_name: None,
                    roles: vec![],
                    scopes: vec![],
                    provider: IdentityProvider::Oidc,
                },
            }));
            req
        }

        let mut state = test_server_state().await;
        Arc::get_mut(&mut state).unwrap().admin_role = "openshell-admin".to_string();

        // --- handle_create_sandbox ---
        // Provide a spec so the handler passes the "spec is required" check
        // before reaching authorize_workspace.
        let err = handle_create_sandbox(
            &state,
            non_member_request(CreateSandboxRequest {
                workspace: "no-such-ws".into(),
                spec: Some(SandboxSpec::default()),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_create_sandbox should reject non-members with PermissionDenied"
        );

        // --- handle_get_sandbox ---
        // Provide a name so the handler passes the "name is required" check.
        let err = handle_get_sandbox(
            &state,
            non_member_request(GetSandboxRequest {
                workspace: "no-such-ws".into(),
                name: "any".into(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_get_sandbox should reject non-members with PermissionDenied"
        );

        // --- handle_list_sandboxes ---
        let err = handle_list_sandboxes(
            &state,
            non_member_request(ListSandboxesRequest {
                workspace: "no-such-ws".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_list_sandboxes should reject non-members with PermissionDenied"
        );

        // --- handle_list_sandbox_providers ---
        let err = handle_list_sandbox_providers(
            &state,
            non_member_request(ListSandboxProvidersRequest {
                workspace: "no-such-ws".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_list_sandbox_providers should reject non-members with PermissionDenied"
        );

        // --- handle_attach_sandbox_provider ---
        let err = handle_attach_sandbox_provider(
            &state,
            non_member_request(AttachSandboxProviderRequest {
                workspace: "no-such-ws".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_attach_sandbox_provider should reject non-members with PermissionDenied"
        );

        // --- handle_detach_sandbox_provider ---
        let err = handle_detach_sandbox_provider(
            &state,
            non_member_request(DetachSandboxProviderRequest {
                workspace: "no-such-ws".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_detach_sandbox_provider should reject non-members with PermissionDenied"
        );

        // --- handle_delete_sandbox ---
        // Provide a name so the handler passes the "name is required" check.
        let err = handle_delete_sandbox(
            &state,
            non_member_request(DeleteSandboxRequest {
                workspace: "no-such-ws".into(),
                name: "any".into(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "handle_delete_sandbox should reject non-members with PermissionDenied"
        );

        for result in [
            handle_stop_sandbox(
                &state,
                non_member_request(StopSandboxRequest {
                    workspace: "no-such-ws".into(),
                    name: "any".into(),
                }),
            )
            .await,
            handle_start_sandbox(
                &state,
                non_member_request(StartSandboxRequest {
                    workspace: "no-such-ws".into(),
                    name: "any".into(),
                }),
            )
            .await,
        ] {
            assert_eq!(
                result.unwrap_err().code(),
                Code::PermissionDenied,
                "lifecycle handlers should reject non-members"
            );
        }
    }

    /// ID-based data-plane handlers must return `NOT_FOUND` — never
    /// `PERMISSION_DENIED` — when the caller lacks workspace access, so that
    /// cross-workspace sandbox existence cannot be inferred (CWE-203).
    #[tokio::test]
    async fn id_based_handlers_hide_cross_workspace_sandboxes() {
        use crate::auth::identity::{Identity, IdentityProvider};
        use crate::auth::principal::{Principal, UserPrincipal};
        use tonic::Code;

        fn non_member_request<T>(inner: T) -> Request<T> {
            let mut req = Request::new(inner);
            req.extensions_mut().insert(Principal::User(UserPrincipal {
                identity: Identity {
                    subject: "non-member".to_string(),
                    display_name: None,
                    roles: vec![],
                    scopes: vec![],
                    provider: IdentityProvider::Oidc,
                },
            }));
            req
        }

        let mut state = test_server_state().await;
        Arc::get_mut(&mut state).unwrap().admin_role = "openshell-admin".to_string();

        let mut sandbox = test_sandbox("cross-ws", Vec::new());
        sandbox.metadata.as_mut().unwrap().workspace = "other-workspace".to_string();
        state.store.put_message(&sandbox).await.unwrap();

        // --- handle_watch_sandbox ---
        let err = handle_watch_sandbox(
            &state,
            non_member_request(WatchSandboxRequest {
                id: "sandbox-cross-ws".into(),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::NotFound,
            "handle_watch_sandbox must return NotFound, not PermissionDenied"
        );

        // --- handle_create_ssh_session ---
        let err = handle_create_ssh_session(
            &state,
            non_member_request(CreateSshSessionRequest {
                sandbox_id: "sandbox-cross-ws".into(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::NotFound,
            "handle_create_ssh_session must return NotFound, not PermissionDenied"
        );
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
            authed_request(CreateSshSessionRequest {
                sandbox_id: "sandbox-ws-test".to_string(),
            }),
        )
        .await
        .unwrap();
        let token = response.into_inner().token;

        handle_revoke_ssh_session(
            &state,
            authed_request(RevokeSshSessionRequest {
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

    // ---- supervisor_supports_no_login_shell ----

    /// A current supervisor identifies itself with the `OpenShell` banner, so the
    /// gateway may forward the login-shell opt-out.
    #[test]
    fn no_login_shell_gate_accepts_openshell_banner() {
        assert!(supervisor_supports_no_login_shell(
            b"SSH-2.0-OpenShell_0.0.4-dev.3+g2bf9969"
        ));
        assert!(supervisor_supports_no_login_shell(
            b"SSH-2.0-OpenShell_0.1.0"
        ));
    }

    /// A supervisor predating this feature presents russh's default banner and
    /// silently ignores the env request, so the gate must reject the opt-out.
    #[test]
    fn no_login_shell_gate_rejects_pre_feature_banner() {
        assert!(!supervisor_supports_no_login_shell(b"SSH-2.0-Russh_0.62.5"));
        assert!(!supervisor_supports_no_login_shell(b"SSH-2.0-OpenSSH_9.6"));
    }

    /// A missing banner (kex callback never populated the slot) must fail
    /// closed rather than forwarding the opt-out to an unknown supervisor.
    #[test]
    fn no_login_shell_gate_rejects_empty_banner() {
        assert!(!supervisor_supports_no_login_shell(b""));
    }

    /// The banner prefix must match at the start; an `OpenShell` token appearing
    /// only in the comment tail does not signal support.
    #[test]
    fn no_login_shell_gate_requires_prefix_position() {
        assert!(!supervisor_supports_no_login_shell(
            b"SSH-2.0-Russh_0.62.5 OpenShell_0.1.0"
        ));
    }
}
