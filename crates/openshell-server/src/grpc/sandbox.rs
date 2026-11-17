// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox lifecycle, exec, and SSH session handlers.

#![allow(clippy::ignored_unit_patterns)] // Tokio select! macro generates unit patterns
#![allow(clippy::result_large_err)] // gRPC handlers return Result<Response<_>, Status>
#![allow(clippy::cast_possible_truncation)] // Intentional u128->i64 etc. for timestamp math
#![allow(clippy::cast_sign_loss)] // Intentional i32->u32 conversions from proto types
#![allow(clippy::cast_possible_wrap)] // Intentional u32->i32 conversions for proto compat

use crate::ServerState;
use crate::auth::authenticator::{AuthFailureReason, AuthMechanism, AuthRejection};
use crate::auth::workspace_authz::{
    AuthorizedWorkspaceScope, MinWorkspaceRole, authorize_list_workspace_selector,
    authorize_sandbox_workspace, authorize_workspace,
};
use crate::compute::{MutationScope, SandboxDeletePreconditions};
use crate::pagination::Pagination;
use crate::persistence::{
    ObjectLabels, ObjectListQuery, ObjectType, WriteCondition, generate_name,
};
use crate::policy_store::PolicyStoreExt;
use crate::tracing_bus::CursoredEvent;
use crate::watch_cursor::WatchCursor;
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
    ListSandboxesRequest, ListSandboxesResponse, Provider, ProviderMutationKind,
    ResourceRequirements, ResumeSandboxRequest, RevokeSshSessionRequest, RevokeSshSessionResponse,
    SandboxResources, SandboxResponse, SandboxSpec, SandboxStreamEvent, SandboxTemplateResponse,
    SandboxWorkloadTemplate, SandboxWorkloadTemplateProvenance, SshRelayTarget,
    StartSandboxRequest, StopSandboxRequest, SuspendSandboxRequest, TcpForwardFrame,
    TcpForwardInit, TcpRelayTarget, WatchSandboxRequest, relay_open, tcp_forward_init,
};
use openshell_core::proto::{
    BeginRootfsTarStagingRequest, BeginRootfsTarStagingResponse, Sandbox, SandboxPhase,
    SandboxRestartPolicy, SandboxTemplate, SshSession,
};
use openshell_core::telemetry::{
    LifecycleOperation, LifecycleResource, SandboxTemplateSource, TelemetryOutcome,
};
use openshell_core::{GetResourceVersion, ObjectId, ObjectName, ObjectWorkspace};
use prost::Message;
use prost_types::{Struct, Value, value::Kind};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, oneshot};
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
use super::{MAX_PROVIDERS, MAX_ROUTABLE_NAME_LEN};
use crate::persistence::current_time_ms;

const TCP_FORWARD_CHUNK_SIZE: usize = 64 * 1024;
const NO_LOGIN_SHELL_ENV: (&str, &str) = ("OPENSHELL_NO_LOGIN_SHELL", "1");
const MAX_TEMPLATES_PER_WORKSPACE: u32 = 1000;
const MAX_CREATE_SERVICE_EXPOSURES: usize = 32;
const SANDBOX_CAS_RETRY_LIMIT: usize = 16;

#[cfg(test)]
#[path = "interactive_exec_tests.rs"]
mod interactive_exec_tests;

/// Terminal status for a resume cursor issued by a cursor space that is gone.
///
/// Retrying the same token fails identically, so the guidance has to be
/// "restart without one" -- otherwise an SDK that reconnects on `OUT_OF_RANGE`
/// spins. The token is not echoed back.
const RESUME_SPACE_GONE: &str = "resume_after_cursor belongs to a cursor space that no longer \
     exists; the gateway restarted or the sandbox's buffers were torn down. Restart the watch \
     with an empty resume_after_cursor. Events published in the meantime are not recoverable.";

/// Terminal status for a resume cursor ahead of everything its space issued.
const RESUME_CURSOR_AHEAD: &str = "resume_after_cursor is ahead of every cursor this sandbox has \
     issued. Restart the watch with an empty resume_after_cursor.";

/// Whether `sandbox_id`'s cursor space is still the one that issued `epoch`.
///
/// A teardown retires the space and the next publish mints a replacement that
/// renumbers from 1, so a surviving epoch is the only proof that a seq validated
/// earlier still addresses the same numbering. Absent counts as changed: there
/// is nothing left for the cursor to point into.
fn cursor_space_is(state: &ServerState, sandbox_id: &str, epoch: uuid::Uuid) -> bool {
    state
        .tracing_log_bus
        .cursor_space(sandbox_id)
        .is_some_and(|space| space.epoch == epoch)
}

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

/// Fetch a runtime sandbox ID and authorize its persisted workspace without
/// revealing whether an inaccessible object exists.
pub(super) async fn fetch_and_authorize_sandbox(
    state: &ServerState,
    principal: &crate::auth::principal::Principal,
    sandbox_id: &str,
) -> Result<Sandbox, Status> {
    let sandbox = state
        .store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .map_err(|error| Status::internal(format!("fetch sandbox failed: {error}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    authorize_sandbox_workspace(
        &state.store,
        &state.admin_role,
        principal,
        sandbox.object_workspace(),
        MinWorkspaceRole::User,
    )
    .await
    .map_err(|error| {
        if error.code() == tonic::Code::PermissionDenied {
            Status::not_found("sandbox not found")
        } else {
            error
        }
    })?;
    Ok(sandbox)
}

/// Resolve a public sandbox name and authorize its persisted workspace.
/// Missing and unauthorized objects deliberately share one response so names
/// cannot be used as an existence oracle.
pub(super) async fn resolve_and_authorize_sandbox_name(
    state: &ServerState,
    principal: &crate::auth::principal::Principal,
    sandbox_name: &str,
    workspace: &str,
    min_role: MinWorkspaceRole,
) -> Result<Sandbox, Status> {
    if sandbox_name.is_empty() {
        return Err(Status::invalid_argument("sandbox is required"));
    }
    let crate::auth::principal::Principal::Sandbox(sandbox_principal) = principal else {
        authorize_sandbox_workspace(
            &state.store,
            &state.admin_role,
            principal,
            workspace,
            min_role,
        )
        .await
        .map_err(|error| {
            if error.code() == tonic::Code::PermissionDenied {
                Status::not_found("sandbox not found")
            } else {
                error
            }
        })?;

        return state
            .store
            .get_message_by_name::<Sandbox>(workspace, sandbox_name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
            .ok_or_else(|| Status::not_found("sandbox not found"));
    };

    let not_owned = || Status::permission_denied("sandbox not found or not owned by caller");
    // The caller's own record can disappear between authentication and this
    // read when the sandbox is deleted; that is not misuse.
    let sandbox = state
        .store
        .get_message::<Sandbox>(&sandbox_principal.sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(not_owned)?;
    let names_itself = sandbox.metadata.as_ref().is_some_and(|metadata| {
        metadata.name == sandbox_name
            && (workspace.is_empty() || workspace == sandbox.object_workspace())
    });
    if !names_itself {
        // A supervisor only ever names its own sandbox.
        crate::auth::audit::emit_authorization_denial(
            principal,
            crate::auth::audit::AuthzDenial::CrossSandboxName { name: sandbox_name },
        );
        return Err(not_owned());
    }

    authorize_sandbox_workspace(
        &state.store,
        &state.admin_role,
        principal,
        sandbox.object_workspace(),
        min_role,
    )
    .await
    .map_err(|error| {
        if error.code() == tonic::Code::PermissionDenied {
            Status::not_found("sandbox not found")
        } else {
            error
        }
    })?;
    crate::auth::guard::ensure_sandbox_scope(principal, sandbox.object_id()).map_err(|error| {
        if error.code() == tonic::Code::PermissionDenied {
            Status::permission_denied("sandbox not found or not owned by caller")
        } else {
            error
        }
    })?;
    Ok(sandbox)
}

/// Resolve `name` for a sandbox caller (only through `/mcp`): one of its own
/// children, in its own workspace. Everything else, the caller itself
/// included, reads as missing.
pub(super) async fn resolve_caller_child(
    state: &ServerState,
    caller: &crate::auth::principal::SandboxPrincipal,
    name: &str,
) -> Result<Sandbox, Status> {
    let not_found = || Status::not_found(format!("sandbox '{name}' not found"));
    let caller = state
        .store
        .get_message::<Sandbox>(&caller.sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(not_found)?;
    let child = state
        .store
        .get_message_by_name::<Sandbox>(caller.object_workspace(), name)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(not_found)?;
    if child
        .parent
        .as_ref()
        .is_some_and(|parent| parent.id == caller.object_id())
    {
        Ok(child)
    } else {
        Err(not_found())
    }
}

/// A sandbox caller's exec may set only the target, command, working
/// directory, stdin and timeout.
fn refuse_exec_fields_for_sandbox_caller(request: &ExecSandboxRequest) -> Result<(), Status> {
    let set = [
        ("workspace_scope", request.workspace_scope.is_some()),
        ("environment", !request.environment.is_empty()),
        ("tty", request.tty),
        ("cols", request.cols != 0),
        ("rows", request.rows != 0),
        ("no_login_shell", request.no_login_shell),
        ("request_id", !request.request_id.is_empty()),
    ];
    if let Some((field, _)) = set.iter().find(|(_, is_set)| *is_set) {
        return Err(Status::invalid_argument(format!(
            "field '{field}' is not allowed for sandbox callers"
        )));
    }
    let allowed = ExecSandboxRequest {
        sandbox: request.sandbox.clone(),
        command: request.command.clone(),
        workdir: request.workdir.clone(),
        stdin: request.stdin.clone(),
        execution_timeout: request.execution_timeout,
        ..Default::default()
    };
    if *request == allowed {
        Ok(())
    } else {
        Err(Status::invalid_argument(
            "the request sets fields that are not allowed for sandbox callers",
        ))
    }
}

fn require_ready_sandbox(sandbox: &Sandbox) -> Result<(), Status> {
    match SandboxPhase::try_from(sandbox.phase()).ok() {
        Some(SandboxPhase::Ready) => Ok(()),
        _ => Err(Status::failed_precondition("sandbox is not ready")),
    }
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
    // Sandbox creation retains large configuration values across awaits.
    // Box the inner future to keep this wrapper small for every caller.
    let result = Box::pin(handle_create_sandbox_inner(state, request)).await;
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

/// Only the workload image is mutable in the first update contract. Runtime
/// replacement is an explicit Stop/Update/Start workflow, never Delete/Create.
pub(super) async fn handle_update_sandbox(
    state: &Arc<ServerState>,
    request: Request<openshell_core::proto::UpdateSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();
    validate_image_update_request(&request)?;
    let sandbox = resolve_and_authorize_sandbox_name(
        state,
        &principal,
        &request.name,
        crate::auth::workspace_authz::selected_workspace_name(request.workspace_scope.as_ref())?,
        MinWorkspaceRole::User,
    )
    .await?;
    super::workspace::resolve_workspace(state.store.as_ref(), sandbox.object_workspace())
        .await?
        .ensure_active()?;
    let mut candidate = sandbox.clone();
    let spec = candidate
        .spec
        .as_mut()
        .ok_or_else(|| Status::failed_precondition("sandbox has no spec"))?;
    if let Some(image) = &request.image {
        spec.template
            .get_or_insert_with(Default::default)
            .image
            .clone_from(image);
    }
    openshell_core::sandbox_update::apply_configuration(
        &mut candidate,
        request.command.as_ref(),
        request.environment.as_ref(),
        request.labels.as_ref(),
        request.annotations.as_ref(),
    );
    let candidate_spec = candidate.spec.as_ref().expect("spec checked above");
    validate_sandbox_spec(&request.name, candidate_spec)?;

    let sandbox = Box::pin(
        state
            .compute
            .update_sandbox_configuration(sandbox.object_id(), &request),
    )
    .await?;
    Ok(Response::new(SandboxResponse {
        sandbox: Some(sandbox),
        service_urls: HashMap::new(),
    }))
}

fn validate_image_update_request(
    request: &openshell_core::proto::UpdateSandboxRequest,
) -> Result<(), Status> {
    if request.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    if request.expected_resource_version == 0 {
        return Err(Status::invalid_argument(
            "expected_resource_version must be nonzero",
        ));
    }
    if let Some(image) = &request.image
        && (image.is_empty()
            || image.len() > super::MAX_TEMPLATE_STRING_LEN
            || image.chars().any(|c| c.is_whitespace() || c.is_control()))
    {
        return Err(Status::invalid_argument(
            "image must be a nonempty bounded OCI reference without whitespace or control characters",
        ));
    }
    for map in [request.labels.as_ref(), request.annotations.as_ref()]
        .into_iter()
        .flatten()
    {
        if map
            .values
            .keys()
            .any(|key| openshell_core::sandbox_update::is_system_metadata_key(key))
        {
            return Err(Status::invalid_argument(
                "system metadata cannot be updated",
            ));
        }
    }
    if let Some(labels) = &request.labels {
        super::validation::validate_labels(&labels.values)?;
    }
    if let Some(annotations) = &request.annotations {
        super::validation::validate_annotations(&annotations.values, "annotations")?;
    }
    Ok(())
}

/// Allocate a gateway-owned staging slot for a local rootfs tar archive.
///
/// The caller writes the archive to the returned path and then names the token
/// on `CreateSandbox`. It never names a filesystem path of its own choosing.
pub(super) async fn handle_begin_rootfs_tar_staging(
    state: &Arc<ServerState>,
    request: Request<BeginRootfsTarStagingRequest>,
) -> Result<Response<BeginRootfsTarStagingResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();

    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        crate::auth::workspace_authz::selected_workspace_name(request.workspace_scope.as_ref())?,
        MinWorkspaceRole::User,
    )
    .await?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
        .await?
        .ensure_active()?;

    let subject = principal_subject(&principal)?;
    let slot = state.compute.rootfs_tar_staging().begin(
        &workspace,
        &subject,
        &request.file_name,
        request.size_bytes,
    )?;

    Ok(Response::new(BeginRootfsTarStagingResponse {
        staging_token: slot.token,
        upload_path: slot.upload_path.to_string_lossy().into_owned(),
        max_bytes: slot.max_bytes,
        expiration_time: openshell_core::time::timestamp_from_millis(slot.expires_at_ms)
            .map(Some)
            .map_err(|error| Status::internal(error.to_string()))?,
    }))
}

/// Stable caller identity used to bind a staging slot to its requester.
fn principal_subject(principal: &crate::auth::principal::Principal) -> Result<String, Status> {
    match principal {
        crate::auth::principal::Principal::User(user) => Ok(user.identity.subject.clone()),
        crate::auth::principal::Principal::Operator(operator) => {
            Ok(format!("operator:{}", operator.identity.subject))
        }
        _ => Err(Status::permission_denied(
            "rootfs tar staging requires a user principal",
        )),
    }
}

/// The user recorded as a new sandbox's creator. Only users are recorded;
/// operators are not workspace members, so they leave the field empty.
fn creator_subject(principal: &crate::auth::principal::Principal) -> String {
    match principal {
        crate::auth::principal::Principal::User(user) => user.identity.subject.clone(),
        _ => String::new(),
    }
}

/// Read the staging token a caller named for the active driver, without
/// removing it. The gateway consumes it later, inside `create_sandbox`.
fn staging_token_in_spec(spec: &SandboxSpec, driver_name: &str) -> Option<String> {
    let config = spec.template.as_ref()?.driver_config.as_ref()?;
    let Kind::StructValue(driver_config) = config.fields.get(driver_name)?.kind.as_ref()? else {
        return None;
    };
    match driver_config
        .fields
        .get(crate::compute::rootfs_tar::STAGING_TOKEN_FIELD)?
        .kind
        .as_ref()?
    {
        Kind::StringValue(token) => Some(token.clone()),
        _ => None,
    }
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
    if !request.workload_template.trim().is_empty() {
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

/// Check the parent named in a create request and return the link to store on
/// the new child. Returns `None` when no parent is named, for a root sandbox.
async fn resolve_create_parent(
    state: &ServerState,
    workspace: &str,
    parent_name: &str,
    spec: &mut SandboxSpec,
) -> Result<Option<openshell_core::proto::SandboxParent>, Status> {
    if parent_name.is_empty() {
        return Ok(None);
    }
    ensure_child_sandboxes_enabled(state)?;
    let parent = state
        .store
        .get_message_by_name::<Sandbox>(workspace, parent_name)
        .await
        .map_err(|e| Status::internal(format!("fetch parent sandbox failed: {e}")))?
        .ok_or_else(|| {
            Status::failed_precondition(format!("parent sandbox '{parent_name}' not found"))
        })?;
    check_create_parent(&parent, spec).map(Some)
}

fn ensure_child_sandboxes_enabled(state: &ServerState) -> Result<(), Status> {
    if state.config.enable_child_sandboxes {
        Ok(())
    } else {
        Err(Status::failed_precondition(
            "child sandboxes are disabled on this gateway",
        ))
    }
}

/// Check that `parent` can take a child with `spec`, and return the link to
/// store on the child. A child that names no providers gets all of its
/// parent's providers. Users and sandbox callers share these checks.
fn check_create_parent(
    parent: &Sandbox,
    spec: &mut SandboxSpec,
) -> Result<openshell_core::proto::SandboxParent, Status> {
    let parent_name = parent.object_name();
    if crate::compute::is_being_deleted(parent) {
        return Err(Status::failed_precondition(format!(
            "parent sandbox '{parent_name}' is being deleted"
        )));
    }
    if parent.parent.is_some() {
        return Err(Status::failed_precondition(
            "only one level of child sandboxes is supported",
        ));
    }
    if spec.policy.is_some() {
        return Err(Status::invalid_argument(
            "a child sandbox uses its parent's policy; omit the policy",
        ));
    }
    let parent_providers = parent
        .spec
        .as_ref()
        .map_or(&[][..], |parent_spec| parent_spec.providers.as_slice());
    if let Some(provider) = spec
        .providers
        .iter()
        .find(|provider| !parent_providers.contains(provider))
    {
        return Err(Status::failed_precondition(format!(
            "provider '{provider}' is not attached to parent '{parent_name}'"
        )));
    }
    if spec.providers.is_empty() {
        spec.providers = parent_providers.to_vec();
    }
    Ok(openshell_core::proto::SandboxParent {
        name: parent_name.to_string(),
        id: parent.object_id().to_string(),
    })
}

/// A sandbox caller (only through `/mcp`) creating a child of itself: read its
/// own record and check the request and its creator. The child always goes in
/// the caller's workspace with the caller as its parent.
async fn sandbox_caller_create(
    state: &ServerState,
    caller: &crate::auth::principal::SandboxPrincipal,
    request: &CreateSandboxRequest,
) -> Result<Sandbox, Status> {
    refuse_fields_for_sandbox_caller(request)?;
    ensure_child_sandboxes_enabled(state)?;
    let caller = state
        .store
        .get_message::<Sandbox>(&caller.sandbox_id)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    if caller.parent.is_some() {
        return Err(Status::failed_precondition(
            "only root sandboxes can create child sandboxes",
        ));
    }
    refuse_caller_with_driver_config(&caller)?;
    check_creator_has_access(state, &caller).await?;
    Ok(caller)
}

/// A sandbox caller may set only `name`, `workload_template` and
/// `spec.providers`; the gateway decides everything else.
fn refuse_fields_for_sandbox_caller(request: &CreateSandboxRequest) -> Result<(), Status> {
    let spec = request.spec.clone().unwrap_or_default();
    let set = [
        ("workspace_scope", request.workspace_scope.is_some()),
        ("parent", !request.parent.is_empty()),
        ("labels", !request.labels.is_empty()),
        ("annotations", !request.annotations.is_empty()),
        (
            "await_main_process_attachment",
            request.await_main_process_attachment,
        ),
        ("request_id", !request.request_id.is_empty()),
        ("service_exposures", !request.service_exposures.is_empty()),
        ("spec.log_level", !spec.log_level.is_empty()),
        ("spec.environment", !spec.environment.is_empty()),
        ("spec.template", spec.template.is_some()),
        ("spec.policy", spec.policy.is_some()),
        (
            "spec.resource_requirements",
            spec.resource_requirements.is_some(),
        ),
        ("spec.command", !spec.command.is_empty()),
        ("spec.tty", spec.tty),
        (
            "spec.provider_attachment_epoch",
            !spec.provider_attachment_epoch.is_empty(),
        ),
        ("spec.restart_policy", spec.restart_policy != 0),
    ];
    if let Some((field, _)) = set.iter().find(|(_, is_set)| *is_set) {
        return Err(Status::invalid_argument(format!(
            "field '{field}' is not allowed for sandbox callers"
        )));
    }
    refuse_unlisted_fields_for_sandbox_caller(request)
}

/// Backstop for fields the named checks above do not list, such as ones added
/// to the request later: anything beyond what a sandbox caller may send.
fn refuse_unlisted_fields_for_sandbox_caller(request: &CreateSandboxRequest) -> Result<(), Status> {
    let allowed = CreateSandboxRequest {
        name: request.name.clone(),
        workload_template: request.workload_template.clone(),
        spec: request.spec.as_ref().map(|spec| SandboxSpec {
            providers: spec.providers.clone(),
            ..Default::default()
        }),
        ..Default::default()
    };
    if *request == allowed {
        Ok(())
    } else {
        Err(Status::invalid_argument(
            "the request sets fields that are not allowed for sandbox callers",
        ))
    }
}

/// The user who created a root must still be a workspace member with at least
/// the user role for the root to create children. A root with no recorded
/// creator fails closed. Checked on every create.
async fn check_creator_has_access(state: &ServerState, caller: &Sandbox) -> Result<(), Status> {
    let creator = caller.created_by.as_str();
    if creator.is_empty() {
        return Err(Status::failed_precondition(
            "this sandbox was not started by a workspace user, so it cannot create children",
        ));
    }
    // With no admin role configured every authenticated user is a platform
    // admin and needs no membership, as in `authorize_workspace`. Only the
    // creator's subject is recorded, so an admin by role is not recognized
    // once an admin role is configured.
    if state.admin_role.is_empty() {
        return Ok(());
    }
    // Development gateways create roots as the built-in local user, which has
    // no membership; it counts only while such users are still allowed.
    if state.config.auth.allow_unauthenticated_users
        && creator == crate::multiplex::UNAUTHENTICATED_DEV_SUBJECT
    {
        return Ok(());
    }
    if !crate::auth::workspace_authz::subject_has_workspace_role(
        &state.store,
        caller.object_workspace(),
        creator,
        MinWorkspaceRole::User,
    )
    .await?
    {
        // The agent is not told who the creator is; the audit event records it.
        let workspace = caller.object_workspace();
        return Err(Status::permission_denied(format!(
            "the user who started this sandbox is not a member of workspace '{workspace}' \
             with the user role; a platform admin can add them with: openshell workspace \
             member add --workspace {workspace} --subject <user> --role user"
        )));
    }
    Ok(())
}

/// The spec a sandbox caller's child gets without a template: the caller's
/// image, CPU and memory, isolation settings, and the named providers.
/// Nothing else is copied, so no GPU or other device.
fn spec_copied_from_caller(caller: &Sandbox, providers: Vec<String>) -> SandboxSpec {
    let template = caller.spec.as_ref().and_then(|spec| spec.template.as_ref());
    let mut child = SandboxTemplate {
        image: template.map(|t| t.image.clone()).unwrap_or_default(),
        resources: template.and_then(|t| cpu_and_memory_only(t.resources.as_ref())),
        ..Default::default()
    };
    copy_isolation_from_caller(caller, &mut child);
    SandboxSpec {
        template: Some(child),
        providers,
        ..Default::default()
    }
}

/// A child is never less isolated than its root or its template: the root's
/// runtime class wins when it has one, and user namespaces stay on when
/// either asks for them.
fn copy_isolation_from_caller(caller: &Sandbox, child: &mut SandboxTemplate) {
    let root = caller.spec.as_ref().and_then(|spec| spec.template.as_ref());
    if let Some(root) = root.filter(|root| !root.runtime_class_name.is_empty()) {
        child
            .runtime_class_name
            .clone_from(&root.runtime_class_name);
    }
    if root.and_then(|root| root.user_namespaces) == Some(true) {
        child.user_namespaces = Some(true);
    }
}

/// Driver configuration can set isolation, devices and mounts that cannot be
/// copied safely, so a root that has any cannot create children over MCP.
fn refuse_caller_with_driver_config(caller: &Sandbox) -> Result<(), Status> {
    let has_driver_config = caller
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .is_some_and(|template| template.driver_config.is_some());
    if has_driver_config {
        return Err(Status::failed_precondition(
            "this sandbox has driver configuration, which children cannot copy",
        ));
    }
    Ok(())
}

/// Keep only `cpu` and `memory` under `limits` and `requests`; drop GPUs and
/// any other extended resource.
fn cpu_and_memory_only(resources: Option<&Struct>) -> Option<Struct> {
    let fields: std::collections::BTreeMap<_, _> = resources?
        .fields
        .iter()
        .filter(|(section, _)| matches!(section.as_str(), "limits" | "requests"))
        .filter_map(|(section, value)| {
            let Some(Kind::StructValue(quantities)) = value.kind.as_ref() else {
                return None;
            };
            let kept: std::collections::BTreeMap<_, _> = quantities
                .fields
                .iter()
                .filter(|(name, _)| matches!(name.as_str(), "cpu" | "memory"))
                .map(|(name, quantity)| (name.clone(), quantity.clone()))
                .collect();
            (!kept.is_empty()).then(|| {
                let value = Value {
                    kind: Some(Kind::StructValue(Struct { fields: kept })),
                };
                (section.clone(), value)
            })
        })
        .collect();
    (!fields.is_empty()).then_some(Struct { fields })
}

/// Agents may create children only from templates an administrator marked
/// for them, and never from one with driver configuration.
fn check_agent_usable_template(template: &SandboxWorkloadTemplate) -> Result<(), Status> {
    let labelled = template
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.labels.get(AGENT_USABLE_TEMPLATE_LABEL))
        .is_some_and(|value| value == "true");
    let has_driver_config = template
        .spec
        .as_ref()
        .is_some_and(|spec| spec.driver_config.is_some());
    if labelled && !has_driver_config {
        Ok(())
    } else {
        Err(template_not_available(template.object_name()))
    }
}

const AGENT_USABLE_TEMPLATE_LABEL: &str = "openshell.ai/agent-usable";

fn template_not_available(name: &str) -> Status {
    Status::failed_precondition(format!("template '{name}' is not available to agents"))
}

/// Under the child-create lock, re-read the parent and check that it can take
/// one more child and still has the child's providers. Every existing child
/// counts, whatever its state.
async fn check_parent_has_room(
    state: &ServerState,
    workspace: &str,
    parent: &openshell_core::proto::SandboxParent,
    providers: &[String],
) -> Result<(), Status> {
    let current = state
        .store
        .get_message::<Sandbox>(&parent.id)
        .await
        .map_err(|e| Status::internal(format!("fetch parent sandbox failed: {e}")))?;
    let usable = current.as_ref().is_some_and(|current| {
        current.parent.is_none()
            && current
                .metadata
                .as_ref()
                .is_some_and(|metadata| metadata.deletion_time.is_none())
    });
    if !usable {
        return Err(Status::failed_precondition(format!(
            "parent sandbox '{}' is no longer available",
            parent.name
        )));
    }
    let parent_providers = current
        .as_ref()
        .and_then(|current| current.spec.as_ref())
        .map_or(&[][..], |parent_spec| parent_spec.providers.as_slice());
    if let Some(provider) = providers
        .iter()
        .find(|provider| !parent_providers.contains(provider))
    {
        return Err(Status::failed_precondition(format!(
            "provider '{provider}' is not attached to parent '{}'",
            parent.name
        )));
    }
    // A child keeps its slot until its delete finishes: until then its
    // compute resources may still run, and a stuck delete must not let a
    // looping agent exceed the limit.
    let limit = state.config.max_concurrent_children;
    let children = crate::compute::count_children(&state.store, workspace, &parent.id).await?;
    if children.total() >= limit as usize {
        let leaving = match children.being_deleted {
            0 => String::new(),
            n => format!(", {n} of them still being deleted; try again shortly"),
        };
        return Err(Status::resource_exhausted(format!(
            "sandbox '{}' has reached its limit of {limit} children{leaving}",
            parent.name
        )));
    }
    Ok(())
}

/// Policy-revision provenance naming the parent a child's policy was copied
/// from. Gateway-owned: the `internal.openshell.ai/` prefix is reserved.
const COPIED_FROM_PARENT_ID: &str = "internal.openshell.ai/copied-from-parent-id";
/// The parent policy version a child's policy revision was copied from.
const COPIED_FROM_PARENT_VERSION: &str = "internal.openshell.ai/copied-from-parent-version";

/// A parent's policy as copied into a child: the policy, cleaned exactly as a
/// create cleans it, and the provenance naming the parent version.
struct ParentPolicyCopy {
    policy: openshell_core::proto::SandboxPolicy,
    provenance: HashMap<String, String>,
}

impl ParentPolicyCopy {
    /// Copy one parent revision. Create and sync both copy through here, so a
    /// child's first revision and its later copies of the same parent version
    /// are identical.
    fn of(record: &crate::persistence::PolicyRecord, parent_id: &str) -> Result<Self, Status> {
        let (mut policy, _) = super::policy::canonical_policy_record_identity(record)?;
        super::policy::clear_provider_credentialed_markers(&mut policy);
        validate_no_reserved_provider_policy_keys(&policy)?;
        let policy = validate_and_canonicalize_policy(policy)?;
        let provenance = HashMap::from([
            (COPIED_FROM_PARENT_ID.to_string(), parent_id.to_string()),
            (
                COPIED_FROM_PARENT_VERSION.to_string(),
                record.version.to_string(),
            ),
        ]);
        Ok(Self { policy, provenance })
    }

    fn parent_version(&self) -> i64 {
        self.provenance
            .get(COPIED_FROM_PARENT_VERSION)
            .and_then(|version| version.parse().ok())
            .unwrap_or(0)
    }
}

/// The revisions that decide what a parent enforces: the one at its
/// `current_policy_version`, the last version it reported loaded, and under
/// `fail_closed` a failed revision at or above it, which makes the parent
/// deny all new egress. The newest revision with status "loaded" is not
/// used: a newer revision marks it superseded before it loads, and a later
/// failure of the same version, such as a re-apply, marks it failed.
async fn parent_policy_revisions(
    state: &ServerState,
    parent_id: &str,
) -> Result<
    Option<(
        crate::persistence::PolicyRecord,
        Option<crate::persistence::PolicyRecord>,
    )>,
    Status,
> {
    let current = state
        .store
        .get_message::<Sandbox>(parent_id)
        .await
        .map_err(|e| Status::internal(format!("fetch parent sandbox failed: {e}")))?
        .map_or(0, |parent| parent.current_policy_version());
    if current == 0 {
        return Ok(None);
    }
    let Some(enforced) = state
        .store
        .get_policy_by_version(parent_id, i64::from(current))
        .await
        .map_err(|e| Status::internal(format!("fetch parent policy failed: {e}")))?
    else {
        return Ok(None);
    };
    let blocking = if state.config.policy_validation_failure_mode
        == openshell_core::PolicyValidationFailureMode::FailClosed
    {
        failed_policy_at_or_above(state, parent_id, enforced.version).await?
    } else {
        None
    };
    Ok(Some((enforced, blocking)))
}

/// Under the child-create lock, copy the policy the parent is enforcing: the
/// revision at its current policy version, not a newer pending or failed one.
/// A `fail_closed` parent that rejected a newer revision denies all new
/// egress, so its enforced revision would give a new child more access than
/// the parent has.
async fn copy_parent_policy(
    state: &ServerState,
    parent: &openshell_core::proto::SandboxParent,
) -> Result<ParentPolicyCopy, Status> {
    match parent_policy_revisions(state, &parent.id).await? {
        None => Err(Status::failed_precondition(format!(
            "parent sandbox '{}' has no policy yet; try again once it is running",
            parent.name
        ))),
        Some((_, Some(_))) => Err(Status::failed_precondition(format!(
            "parent sandbox '{}' rejected its latest policy; fix it before creating children",
            parent.name
        ))),
        Some((loaded, None)) => ParentPolicyCopy::of(&loaded, &parent.id),
    }
}

/// The newest revision at or above the parent's enforced version that failed
/// to load. At the enforced version itself, that is a failed re-apply.
async fn failed_policy_at_or_above(
    state: &ServerState,
    parent_id: &str,
    enforced_version: i64,
) -> Result<Option<crate::persistence::PolicyRecord>, Status> {
    const PAGE_SIZE: u32 = 100;
    let mut before_version = None;
    loop {
        let page = state
            .store
            .list_policies_before(parent_id, PAGE_SIZE, before_version)
            .await
            .map_err(|e| Status::internal(format!("list parent policies failed: {e}")))?;
        for record in &page {
            if record.version < enforced_version {
                return Ok(None);
            }
            if record.status == "failed" {
                return Ok(Some(record.clone()));
            }
        }
        match page.last() {
            Some(last) if page.len() == PAGE_SIZE as usize => {
                before_version = Some(last.version);
            }
            _ => return Ok(None),
        }
    }
}

/// The parent policy version a child's revision was copied from, or 0 when it
/// was not copied from this parent.
fn copied_parent_version(record: &crate::persistence::PolicyRecord, parent_id: &str) -> i64 {
    if record
        .provenance
        .get(COPIED_FROM_PARENT_ID)
        .map(String::as_str)
        != Some(parent_id)
    {
        return 0;
    }
    record
        .provenance
        .get(COPIED_FROM_PARENT_VERSION)
        .and_then(|version| version.parse().ok())
        .unwrap_or(0)
}

/// Bring each live child of a root up to it, then push every child: remove
/// providers the root no longer has, and copy the policy the root has loaded
/// into a child that is behind. Safe to run again. A blocked root's revisions
/// are not copied; its children are refused at delivery until it loads a fix.
pub(super) async fn sync_children(state: &Arc<ServerState>, parent_id: &str) -> Result<(), Status> {
    let Some(parent) = state
        .store
        .get_message::<Sandbox>(parent_id)
        .await
        .map_err(|e| Status::internal(format!("fetch parent sandbox failed: {e}")))?
    else {
        return Ok(());
    };
    if parent.parent.is_some() {
        return Ok(());
    }
    let workspace = parent.object_workspace().to_string();

    // Read the parent's policy and list its children under the parent's lock,
    // which every child create also holds: a create either finished before
    // the list or reads the newer policy itself.
    let (copy, children) = {
        let _parent_guard = state
            .compute
            .mutation_guard(MutationScope::sandbox(&workspace, parent_id))
            .await
            .map_err(|e| super::persistence_error_to_status(e, "acquire sandbox mutation lock"))?;
        let copy = parent_policy_copy(state, parent_id).await?;
        let children: Vec<String> = state
            .store
            .collect_messages::<Sandbox>(ObjectListQuery::Workspace(&workspace))
            .await
            .map_err(|e| Status::internal(format!("list sandboxes failed: {e}")))?
            .iter()
            .filter(|sandbox| {
                sandbox
                    .parent
                    .as_ref()
                    .is_some_and(|parent| parent.id == parent_id)
            })
            .map(|sandbox| sandbox.object_id().to_string())
            .collect();
        (copy, children)
    };

    // One child's failure must not hold the parent's change back from the
    // others: log it, carry on, and report it at the end.
    let mut failed = 0_usize;
    for child_id in children {
        if let Err(error) = sync_child(state, &workspace, parent_id, &child_id, copy.as_ref()).await
        {
            warn!(parent_id, child_id, error = %error, "failed to sync child sandbox");
            failed += 1;
        }
        // Push every child, copied or not: the parent can become blocked or
        // unblocked without a new copy, and the child must see that.
        state.sandbox_watch_bus.notify(&child_id);
        crate::config_delivery::publish_sandbox(state, &child_id);
    }
    if failed > 0 {
        return Err(Status::unavailable(format!(
            "{failed} child sandboxes of '{}' were not synced",
            parent.object_name()
        )));
    }
    Ok(())
}

/// The copy of the policy a parent has loaded, or none when it has nothing
/// loaded or is blocked: a blocked parent's children are refused at delivery.
async fn parent_policy_copy(
    state: &ServerState,
    parent_id: &str,
) -> Result<Option<ParentPolicyCopy>, Status> {
    match parent_policy_revisions(state, parent_id).await? {
        Some((loaded, None)) => ParentPolicyCopy::of(&loaded, parent_id).map(Some),
        _ => Ok(None),
    }
}

/// Bring every root's children up to the root, for syncs lost while the
/// gateway was down or published by a replica the child is not on, and stop
/// every child whose parent record is gone.
pub async fn sync_all_children(state: &Arc<ServerState>) -> Result<(), Status> {
    let mut children_by_parent: std::collections::BTreeMap<String, Vec<Sandbox>> =
        std::collections::BTreeMap::new();
    for sandbox in state
        .store
        .collect_messages::<Sandbox>(ObjectListQuery::AllWorkspaces)
        .await
        .map_err(|e| Status::internal(format!("list sandboxes failed: {e}")))?
    {
        if let Some(parent_id) = sandbox.parent.as_ref().map(|parent| parent.id.clone()) {
            children_by_parent
                .entry(parent_id)
                .or_default()
                .push(sandbox);
        }
    }
    let mut failed = 0_usize;
    for (parent_id, children) in children_by_parent {
        // Only a parent read as not found makes orphans: a store error means
        // the scan cannot tell, so it leaves these children alone.
        let result = match parent_is_missing(state, &parent_id).await {
            Ok(true) => {
                for child in &children {
                    stop_orphaned_child(state, child).await;
                }
                Ok(())
            }
            Ok(false) => sync_children(state, &parent_id).await,
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            warn!(parent_id, error = %error, "failed to sync child sandboxes");
            failed += 1;
        }
    }
    if failed > 0 {
        return Err(Status::unavailable(format!(
            "the children of {failed} parent sandboxes were not all synced"
        )));
    }
    Ok(())
}

/// Whether a child's parent record is gone. Read by id, so a root created
/// later under the same name is never taken for it. A store error is
/// returned, never taken as missing.
pub(super) async fn parent_is_missing(
    state: &ServerState,
    parent_id: &str,
) -> Result<bool, Status> {
    Ok(state
        .store
        .get_message::<Sandbox>(parent_id)
        .await
        .map_err(|e| Status::internal(format!("fetch parent sandbox failed: {e}")))?
        .is_none())
}

/// Before a child's configuration is built, check it against its parent's
/// live record: refuse it while the parent is missing or blocked, and keep
/// only the providers the parent still has, in the child's order. Returns the
/// parent's loaded revision, which the child's copy must have reached. A root
/// passes unchanged.
pub(super) async fn admit_child(
    state: &ServerState,
    child: &mut Sandbox,
) -> Result<Option<crate::persistence::PolicyRecord>, Status> {
    let Some(parent_ref) = child.parent.clone() else {
        return Ok(None);
    };
    let Some(parent) = state
        .store
        .get_message::<Sandbox>(&parent_ref.id)
        .await
        .map_err(|e| Status::internal(format!("fetch parent sandbox failed: {e}")))?
    else {
        return Err(child_refusal::status(
            child_refusal::PARENT_MISSING,
            crate::compute::orphaned_child_message(&parent_ref),
        ));
    };
    let loaded = match parent_policy_revisions(state, &parent_ref.id).await? {
        Some((_, Some(_))) => {
            return Err(child_refusal::status(
                child_refusal::PARENT_POLICY_REJECTED,
                format!(
                    "parent sandbox '{}' rejected its latest policy",
                    parent_ref.name
                ),
            ));
        }
        Some((loaded, None)) => Some(loaded),
        None => None,
    };
    let parent_providers = parent.spec.map(|spec| spec.providers).unwrap_or_default();
    if let Some(spec) = child.spec.as_mut() {
        spec.providers
            .retain(|name| parent_providers.contains(name));
    }
    Ok(loaded)
}

/// Whether `provider` is attached to `sandbox` as delivery sees it: for a
/// child, attached to the child and still to its parent.
pub(super) async fn provider_attached_for_delivery(
    state: &ServerState,
    sandbox: &Sandbox,
    provider: &str,
) -> Result<bool, Status> {
    let attached = |sandbox: &Sandbox| {
        sandbox
            .spec
            .as_ref()
            .is_some_and(|spec| spec.providers.iter().any(|name| name == provider))
    };
    if !attached(sandbox) {
        return Ok(false);
    }
    let Some(parent) = sandbox.parent.as_ref() else {
        return Ok(true);
    };
    Ok(state
        .store
        .get_message::<Sandbox>(&parent.id)
        .await
        .map_err(|e| Status::internal(format!("fetch parent sandbox failed: {e}")))?
        .is_some_and(|parent| attached(&parent)))
}

/// Reasons a child is refused configuration or a start, carried as an
/// `ErrorInfo` alongside the message so callers never match its wording.
pub mod child_refusal {
    use openshell_core::rpc_error;
    use tonic::Status;

    pub const PARENT_MISSING: &str = "PARENT_SANDBOX_MISSING";
    pub const PARENT_POLICY_REJECTED: &str = "PARENT_POLICY_REJECTED";
    pub const PARENT_POLICY_NOT_COPIED: &str = "PARENT_POLICY_NOT_COPIED";
    pub const PARENT_POLICY_UNCOPYABLE: &str = "PARENT_POLICY_UNCOPYABLE";

    pub fn status(reason: &str, message: impl Into<String>) -> Status {
        rpc_error::failed_precondition(reason, message)
    }

    /// The gateway's reason on `status`, if it set one.
    pub fn reason(status: &Status) -> Option<String> {
        rpc_error::decode_details(status)?
            .error_info()
            .filter(|info| info.domain == rpc_error::ERROR_DOMAIN)
            .map(|info| info.reason.clone())
    }
}

/// Refuse a child whose policy copy is older than the policy its parent has
/// loaded, so a missed or failed sync fails closed. Starts a sync, which
/// publishes the child once its copy lands.
pub(super) fn refuse_child_behind_parent(
    state: &Arc<ServerState>,
    child: &Sandbox,
    parent_loaded: &crate::persistence::PolicyRecord,
    child_latest: Option<&crate::persistence::PolicyRecord>,
) -> Result<(), Status> {
    let Some(parent) = child.parent.as_ref() else {
        return Ok(());
    };
    let copied = child_latest.map_or(0, |record| copied_parent_version(record, &parent.id));
    if copied >= parent_loaded.version {
        return Ok(());
    }
    // A copy that can never succeed would refuse the child for good; say why
    // once per parent version instead of retrying every rebuild.
    if let Err(reason) = ParentPolicyCopy::of(parent_loaded, &parent.id) {
        warn_uncopyable_parent_policy_once(&parent.id, parent_loaded.version, &reason);
        return Err(child_refusal::status(
            child_refusal::PARENT_POLICY_UNCOPYABLE,
            format!(
                "parent sandbox '{}' policy version {} cannot be copied to its children",
                parent.name, parent_loaded.version
            ),
        ));
    }
    spawn_child_sync(state, child);
    Err(child_refusal::status(
        child_refusal::PARENT_POLICY_NOT_COPIED,
        format!(
            "parent sandbox '{}' policy version {} is not yet copied to this child",
            parent.name, parent_loaded.version
        ),
    ))
}

fn warn_uncopyable_parent_policy_once(parent_id: &str, version: i64, reason: &Status) {
    static WARNED: std::sync::LazyLock<std::sync::Mutex<HashMap<String, i64>>> =
        std::sync::LazyLock::new(Default::default);
    let mut warned = WARNED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if warned.insert(parent_id.to_string(), version) != Some(version) {
        warn!(
            parent_id,
            version,
            reason = %reason.message(),
            "parent sandbox policy cannot be copied to its children; they are refused configuration"
        );
    }
}

/// The children with a background sync running on this replica.
static CHILD_SYNCS_IN_FLIGHT: std::sync::LazyLock<std::sync::Mutex<HashSet<String>>> =
    std::sync::LazyLock::new(Default::default);

/// A child's entry in [`CHILD_SYNCS_IN_FLIGHT`]. Dropping it clears the entry
/// on every exit, a panic included, so one failed sync never blocks the
/// child's later ones.
struct InFlightChildSync(String);

impl InFlightChildSync {
    fn claim(child_id: &str) -> Option<Self> {
        Self::syncs()
            .insert(child_id.to_string())
            .then(|| Self(child_id.to_string()))
    }

    fn syncs() -> std::sync::MutexGuard<'static, HashSet<String>> {
        CHILD_SYNCS_IN_FLIGHT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for InFlightChildSync {
    fn drop(&mut self) {
        Self::syncs().remove(&self.0);
    }
}

/// Bring one child up to its parent in the background, at most one sync per
/// child on this replica at a time. Stops the child if its parent is gone.
pub fn spawn_child_sync(state: &Arc<ServerState>, child: &Sandbox) {
    let child_id = child.object_id().to_string();
    let Some(entry) = InFlightChildSync::claim(&child_id) else {
        return;
    };
    let state = Arc::clone(state);
    let child = child.clone();
    tokio::spawn(async move {
        let _entry = entry;
        match sync_one_child(&state, &child).await {
            Ok(ChildSync::Done) => {
                state.sandbox_watch_bus.notify(&child_id);
                crate::config_delivery::publish_sandbox(&state, &child_id);
            }
            // Stopping waits on the child's session, so it runs here, apart
            // from any build. Delivery refuses the orphan meanwhile.
            Ok(ChildSync::Orphaned) => stop_orphaned_child(&state, &child).await,
            Err(error) => warn!(child_id, error = %error, "child sandbox sync failed"),
        }
    });
}

/// Stop a child whose parent record is gone. Delivery already refuses it
/// configuration, which ends new egress; stopping it ends the connections
/// its supervisor still holds open. Its record and files are kept for
/// inspection and deletion, and it cannot be started again.
pub async fn stop_orphaned_child(state: &Arc<ServerState>, child: &Sandbox) {
    let child_id = child.object_id();
    // Stop works by name: skip if the orphan was deleted and the name reused.
    let current = state
        .store
        .get_message_by_name::<Sandbox>(child.object_workspace(), child.object_name())
        .await;
    if !matches!(&current, Ok(Some(sandbox)) if sandbox.object_id() == child_id) {
        warn!(
            child_id,
            "not stopping orphaned child sandbox: its record is gone, replaced or unreadable"
        );
        return;
    }
    match state
        .compute
        .stop_sandbox(child.object_workspace(), child.object_name())
        .await
    {
        Ok(_) => warn!(
            child_id,
            parent_id = child
                .parent
                .as_ref()
                .map_or("", |parent| parent.id.as_str()),
            "stopped child sandbox whose parent no longer exists"
        ),
        Err(error) => warn!(
            child_id,
            error = %error,
            "failed to stop child sandbox whose parent no longer exists"
        ),
    }
}

/// Refuse to start or resume a child whose parent record is gone. A parent
/// is never recreated under the same id, so no lock is needed.
async fn refuse_orphaned_child(state: &ServerState, sandbox: &Sandbox) -> Result<(), Status> {
    if let Some(parent) = sandbox.parent.as_ref()
        && parent_is_missing(state, &parent.id).await?
    {
        return Err(child_refusal::status(
            child_refusal::PARENT_MISSING,
            crate::compute::orphaned_child_message(parent),
        ));
    }
    Ok(())
}

/// What a connecting child's sync found.
#[derive(Debug, PartialEq, Eq)]
pub enum ChildSync {
    /// Not a child, or brought up to its parent.
    Done,
    /// The parent record is gone; the caller stops the child.
    Orphaned,
}

/// Bring one child up to its parent, for a child that may have missed a
/// sync. The child-sandbox lock set includes the parent, so the parent is
/// read and the child written under one guard.
pub async fn sync_one_child(
    state: &Arc<ServerState>,
    child: &Sandbox,
) -> Result<ChildSync, Status> {
    let Some(parent) = child.parent.as_ref() else {
        return Ok(ChildSync::Done);
    };
    let workspace = child.object_workspace();
    let _guard = state
        .compute
        .mutation_guard(MutationScope::ChildSandbox {
            workspace,
            sandbox_id: child.object_id(),
            parent_id: &parent.id,
        })
        .await
        .map_err(|e| super::persistence_error_to_status(e, "acquire sandbox mutation lock"))?;
    if parent_is_missing(state, &parent.id).await? {
        return Ok(ChildSync::Orphaned);
    }
    let copy = parent_policy_copy(state, &parent.id).await?;
    sync_child_locked(
        state,
        workspace,
        &parent.id,
        child.object_id(),
        copy.as_ref(),
    )
    .await?;
    Ok(ChildSync::Done)
}

/// Bring one child up to its parent. Takes the same lock set as a provider
/// attach on that child, so the parent's lock is never held while waiting
/// for a child's.
async fn sync_child(
    state: &Arc<ServerState>,
    workspace: &str,
    parent_id: &str,
    child_id: &str,
    copy: Option<&ParentPolicyCopy>,
) -> Result<(), Status> {
    let _guard = state
        .compute
        .mutation_guard(MutationScope::ChildSandbox {
            workspace,
            sandbox_id: child_id,
            parent_id,
        })
        .await
        .map_err(|e| super::persistence_error_to_status(e, "acquire sandbox mutation lock"))?;
    sync_child_locked(state, workspace, parent_id, child_id, copy).await
}

/// Detach from a live child every provider its parent no longer has, then
/// write `copy` as its next revision unless it already holds this parent
/// version or a newer one. Providers are removed whatever the parent's
/// policy state: losing one is a revocation. The caller holds the
/// child-sandbox lock set, so the parent's providers read here are current.
async fn sync_child_locked(
    state: &Arc<ServerState>,
    workspace: &str,
    parent_id: &str,
    child_id: &str,
    copy: Option<&ParentPolicyCopy>,
) -> Result<(), Status> {
    let Some(child) = state
        .store
        .get_message::<Sandbox>(child_id)
        .await
        .map_err(|e| Status::internal(format!("fetch child sandbox failed: {e}")))?
    else {
        return Ok(());
    };
    if crate::compute::is_being_deleted(&child) {
        return Ok(());
    }
    let parent_providers = state
        .store
        .get_message::<Sandbox>(parent_id)
        .await
        .map_err(|e| Status::internal(format!("fetch parent sandbox failed: {e}")))?
        .and_then(|parent| parent.spec.map(|spec| spec.providers));
    if let Some(parent_providers) = parent_providers {
        let lost: Vec<String> = child
            .spec
            .as_ref()
            .map(|spec| spec.providers.as_slice())
            .unwrap_or_default()
            .iter()
            .filter(|name| !parent_providers.contains(name))
            .cloned()
            .collect();
        for provider in lost {
            detach_provider_locked(state, child_id, 0, &provider).await?;
            info!(
                parent_id,
                child_id, provider, "detached a provider its parent lost from child sandbox"
            );
        }
    }

    let Some(copy) = copy else {
        return Ok(());
    };
    let parent_version = copy.parent_version();
    let latest = state
        .store
        .get_latest_policy(child_id)
        .await
        .map_err(|e| Status::internal(format!("fetch child policy failed: {e}")))?;
    if latest
        .as_ref()
        .is_some_and(|record| copied_parent_version(record, parent_id) >= parent_version)
    {
        return Ok(());
    }
    let write = crate::policy_store::AtomicPolicyRevisionWrite {
        id: uuid::Uuid::new_v4().to_string(),
        sandbox_id: child_id.to_string(),
        workspace: workspace.to_string(),
        version: latest.as_ref().map_or(1, |record| record.version + 1),
        policy_payload: copy.policy.encode_to_vec(),
        policy_hash: openshell_core::policy_identity::deterministic_policy_hash(&copy.policy),
        provenance: copy.provenance.clone(),
        expected_resource_version: 0,
        annotations: HashMap::new(),
        backfill_policy: None,
    };
    state
        .store
        .put_policy_revision_atomic(&write)
        .await
        .map_err(|e| super::persistence_error_to_status(e, "write child policy"))?;
    info!(
        parent_id,
        child_id,
        parent_version,
        version = write.version,
        "copied parent policy into child sandbox"
    );
    Ok(())
}

/// Under the parent's lock, check that a provider being attached to a child is
/// attached to its parent.
async fn check_parent_has_provider(
    state: &ServerState,
    parent: &openshell_core::proto::SandboxParent,
    provider: &str,
) -> Result<(), Status> {
    let current = state
        .store
        .get_message::<Sandbox>(&parent.id)
        .await
        .map_err(|e| Status::internal(format!("fetch parent sandbox failed: {e}")))?;
    let attached = current
        .as_ref()
        .and_then(|current| current.spec.as_ref())
        .is_some_and(|spec| spec.providers.iter().any(|name| name == provider));
    if !attached {
        return Err(Status::failed_precondition(format!(
            "provider '{provider}' is not attached to parent '{}'",
            parent.name
        )));
    }
    Ok(())
}

async fn handle_create_sandbox_inner(
    state: &Arc<ServerState>,
    request: Request<CreateSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();
    let await_main_process_attachment = request.await_main_process_attachment;
    let workload_template_name = request.workload_template.trim().to_string();

    validate_create_sandbox_request_pre_io(&request, &workload_template_name)?;

    // `authorize_workspace` admits a sandbox caller to any workspace, so a
    // sandbox caller's workspace comes from its own record instead.
    let caller = match &principal {
        crate::auth::principal::Principal::Sandbox(caller) => {
            Some(sandbox_caller_create(state, caller, &request).await?)
        }
        _ => None,
    };
    let workspace = match &caller {
        Some(caller) => caller.object_workspace().to_string(),
        None => {
            authorize_workspace(
                &state.store,
                &state.admin_role,
                &principal,
                crate::auth::workspace_authz::selected_workspace_name(
                    request.workspace_scope.as_ref(),
                )?,
                MinWorkspaceRole::User,
            )
            .await?
            .workspace
        }
    };
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &workspace)
        .await?
        .ensure_active()?;

    let (mut spec, created_from_workload_template) = if workload_template_name.is_empty() {
        let spec = match &caller {
            Some(caller) => spec_copied_from_caller(
                caller,
                request.spec.map(|spec| spec.providers).unwrap_or_default(),
            ),
            None => request
                .spec
                .ok_or_else(|| Status::invalid_argument("spec is required"))?,
        };
        (spec, None)
    } else {
        let governance_spec = request.spec.unwrap_or_default();
        let template = state
            .store
            .get_message_by_name::<SandboxWorkloadTemplate>(&workspace, &workload_template_name)
            .await
            .map_err(|e| Status::internal(format!("fetch sandbox template failed: {e}")))?;
        let template = match (template, &caller) {
            (Some(template), Some(_)) => {
                check_agent_usable_template(&template)?;
                template
            }
            (Some(template), None) => template,
            (None, Some(_)) => return Err(template_not_available(&workload_template_name)),
            (None, None) => return Err(Status::not_found("sandbox template not found")),
        };
        let provenance = SandboxWorkloadTemplateProvenance {
            name: template.object_name().to_string(),
            resource_version: template.get_resource_version().to_string(),
        };
        let mut resolved = sandbox_spec_from_stored_workload_template(&template)?;
        if let Some(caller) = &caller {
            copy_isolation_from_caller(caller, resolved.template.get_or_insert_default());
        }
        resolved.policy = governance_spec.policy;
        resolved.providers = governance_spec.providers;
        resolved.command = governance_spec.command;
        resolved.tty = governance_spec.tty;
        resolved.restart_policy = governance_spec.restart_policy;
        (resolved, Some(provenance))
    };

    // Attachment identity belongs to the gateway. Accepting an epoch from a
    // create request or workload template could revive stale installation proof.
    spec.provider_attachment_epoch = uuid::Uuid::new_v4().to_string();
    if spec.restart_policy == SandboxRestartPolicy::Unspecified as i32 {
        spec.restart_policy = SandboxRestartPolicy::Never as i32;
    }

    // Leave an omitted command empty rather than persisting a concrete shell:
    // the sandbox boundary resolves the default login shell against the agent image
    // (bash when present, otherwise /bin/sh on minimal images like Alpine),
    // which the gateway cannot do since it does not see the sandbox filesystem.
    // The default is an interactive login shell, so request a TTY.
    if spec.command.is_empty() {
        spec.tty = true;
    }

    let parent = match &caller {
        Some(caller) => Some(check_create_parent(caller, &mut spec)?),
        None => resolve_create_parent(state, &workspace, &request.parent, &mut spec).await?,
    };

    // Validate field sizes before any create-side effects.
    validate_sandbox_spec(&request.name, &spec)?;

    // A staging slot may only be redeemed by the caller it was issued to. This
    // is the only point in the create path where the principal is in scope.
    if let Some(token) = staging_token_in_spec(&spec, state.compute.configured_driver_name()) {
        let subject = principal_subject(&principal)?;
        state
            .compute
            .rootfs_tar_staging()
            .authorize(&token, &workspace, &subject)?;
    }

    let id = uuid::Uuid::new_v4().to_string();
    let name = if request.name.is_empty() {
        generate_routable_name()
    } else {
        request.name.clone()
    };
    let guards = match &parent {
        Some(parent) => {
            state
                .compute
                .child_sandbox_create_guards(&workspace, &id, &parent.id)
                .await
        }
        None => state.compute.sandbox_create_guards(&workspace, &id).await,
    };
    let (sandbox_lifecycle_guard, mutation_guard) = guards
        .map_err(|err| super::persistence_error_to_status(err, "acquire sandbox mutation lock"))?;
    let initial_policy_provenance = if let Some(parent) = &parent {
        check_parent_has_room(state, &workspace, parent, &spec.providers).await?;
        let copy = copy_parent_policy(state, parent).await?;
        spec.policy = Some(copy.policy);
        copy.provenance
    } else {
        HashMap::new()
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
    super::provider::validate_provider_profiles_present(
        state.store.as_ref(),
        &provider_profile_catalog,
        &workspace,
        &spec.providers,
    )
    .await?;
    validate_provider_environment_keys_unique_with_catalog(
        state.store.as_ref(),
        crate::provider_refresh::RefreshStateReader::Runtime(&state.refresh),
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

    let now_ms = current_time_ms();

    let mut sandbox = Sandbox {
        host_key_fingerprint: String::new(),
        metadata: Some(ObjectMeta {
            id: id.clone(),
            name: name.clone(),
            created_time: openshell_core::time::timestamp_from_millis(now_ms).ok(),
            labels: request.labels.clone(),
            resource_version: 0,
            annotations: request.annotations.clone(),
            workspace,
            deletion_time: None,
        }),
        spec: Some(spec),
        status: None,
        created_from_workload_template,
        parent,
        // Records who decided: the user, or for a child created over MCP,
        // the root sandbox. The user a root acts for is the root's creator.
        created_by: caller.as_ref().map_or_else(
            || creator_subject(&principal),
            |root| format!("sandbox:{}", root.object_id()),
        ),
    };
    sandbox.set_phase(SandboxPhase::Provisioning as i32);
    sandbox
        .status
        .get_or_insert_with(Default::default)
        .configuration_admission = Some(openshell_core::proto::SandboxConfigurationAdmission {
        state: openshell_core::proto::ConfigurationAdmissionState::Pending.into(),
        ..Default::default()
    });
    sandbox
        .status
        .as_mut()
        .expect("status initialized")
        .configuration_activated = Some(false);
    sandbox
        .status
        .as_mut()
        .expect("status initialized")
        .provisioning = Some(
        crate::compute::provisioning_deadline::new_preparation_record(
            now_ms,
            state.config.image_preparation_timeout_seconds,
            state.config.provisioning_repair_window_seconds * 1000,
        ),
    );
    crate::compute::provisioning_deadline::refresh_configuration(
        &state.store,
        &mut sandbox,
        now_ms,
        state.config.provisioning_repair_window_seconds * 1000,
    )
    .await
    .map_err(Status::internal)?;
    crate::compute::apply_configuration_readiness(&mut sandbox);

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

    // Provider and policy reads must stay under the create mutation guard so
    // their revisions cannot change before the sandbox's launch is committed.
    let mut runtime_inputs =
        super::policy::resolve_sandbox_create_runtime_inputs(state.as_ref(), &sandbox).await?;
    runtime_inputs.initial_policy_provenance = initial_policy_provenance;

    state
        .compute
        .validate_launch_signer_configured(state.sandbox_session_jwt_authority.is_some())?;
    state
        .compute
        .validate_sandbox_create_with_runtime_inputs(
            &sandbox,
            &runtime_inputs,
            await_main_process_attachment,
        )
        .await
        .map_err(|status| {
            warn!(error = %status, "Rejecting sandbox create request");
            status
        })?;

    let runtime_identity = crate::auth::sandbox_session::PersistedSandboxIdentity::new()
        .map_err(|error| Status::internal(error.to_string()))?;
    if let Some(metadata) = sandbox.metadata.as_mut() {
        runtime_identity.write(&mut metadata.annotations);
    }
    let launch_authentication = if let Some(authority) = &state.sandbox_session_jwt_authority {
        Some(authority.mint_persisted_launch(&id, &runtime_identity)?)
    } else {
        None
    };
    let sandbox_token = launch_authentication.as_ref().map(|authentication| {
        authentication
            .supervisor
            .gateway_token
            .expose_secret()
            .to_string()
    });
    let launch_authentication = launch_authentication
        .map(|authentication| {
            serde_json::to_vec(&authentication)
                .map_err(|error| Status::internal(format!("encode launch authentication: {error}")))
        })
        .transpose()?;
    runtime_inputs.launch_authentication = launch_authentication;

    let sandbox = Box::pin(state.compute.create_sandbox_with_runtime_inputs_and_guards(
        sandbox,
        sandbox_token,
        await_main_process_attachment,
        runtime_inputs,
        sandbox_lifecycle_guard,
        mutation_guard,
    ))
    .await?;

    let mut service_urls = HashMap::with_capacity(request.service_exposures.len());
    for exposure in &request.service_exposures {
        let endpoint = match super::service::expose_service_endpoint(
            state,
            sandbox.object_workspace(),
            &sandbox,
            &exposure.service,
            exposure.target_port,
            super::service::validate_service_exposure_request(
                &exposure.service,
                exposure.target_port,
                exposure.authorization_mode,
            )?,
        )
        .await
        {
            Ok(endpoint) => endpoint,
            Err(exposure_error) => {
                let rollback = state
                    .compute
                    .delete_sandbox_by_id(sandbox.object_id(), sandbox.object_name())
                    .await;
                if let Err(rollback_error) = rollback {
                    warn!(
                        sandbox_id = %sandbox.object_id(),
                        sandbox_name = %sandbox.object_name(),
                        service_name = %exposure.service,
                        exposure_error = %exposure_error,
                        rollback_error = %rollback_error,
                        "Failed to roll back sandbox after service exposure failed"
                    );
                    return Err(Status::internal(format!(
                        "create sandbox failed while exposing service '{}': {}; rollback failed: {}; sandbox '{}' may require manual deletion",
                        exposure.service,
                        exposure_error.message(),
                        rollback_error.message(),
                        sandbox.object_name(),
                    )));
                }
                return Err(exposure_error);
            }
        };
        service_urls.insert(exposure.service.clone(), endpoint.into_inner().url);
    }

    info!(
        sandbox_id = %id,
        sandbox_name = %name,
        "CreateSandbox request completed successfully"
    );
    Ok(Response::new(SandboxResponse {
        sandbox: Some(sandbox),
        service_urls,
    }))
}

fn validate_create_sandbox_request_pre_io(
    request: &CreateSandboxRequest,
    workload_template_name: &str,
) -> Result<(), Status> {
    // Validate labels (keys and values must meet Kubernetes requirements).
    crate::grpc::validation::validate_labels(&request.labels)?;
    crate::grpc::validation::validate_caller_annotations(&request.annotations, "annotations")?;

    if request.service_exposures.len() > MAX_CREATE_SERVICE_EXPOSURES {
        return Err(Status::invalid_argument(format!(
            "service_exposures must contain at most {MAX_CREATE_SERVICE_EXPOSURES} entries"
        )));
    }
    let mut service_names = HashSet::with_capacity(request.service_exposures.len());
    for exposure in &request.service_exposures {
        super::service::validate_service_exposure_request(
            &exposure.service,
            exposure.target_port,
            exposure.authorization_mode,
        )?;
        if !service_names.insert(exposure.service.as_str()) {
            return Err(Status::invalid_argument(format!(
                "duplicate service exposure name: '{}'",
                exposure.service
            )));
        }
    }

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

fn owner_requested<T>(request: &Request<T>) -> bool {
    request
        .metadata()
        .contains_key(openshell_core::replica_routing::OWNER_REQUEST_HEADER)
}

pub(super) async fn handle_get_sandbox(
    state: &Arc<ServerState>,
    request: Request<GetSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let wants_owner = owner_requested(&request);
    let req = request.into_inner();
    let sandbox = resolve_and_authorize_sandbox_name(
        state,
        &principal,
        &req.name,
        crate::auth::workspace_authz::selected_workspace_name(req.workspace_scope.as_ref())?,
        MinWorkspaceRole::User,
    )
    .await?;
    let owner = if wants_owner {
        crate::supervisor_session::owner_replica_id(state, sandbox.object_id()).await
    } else {
        None
    };
    let mut response = Response::new(SandboxResponse {
        sandbox: Some(sandbox),
        service_urls: HashMap::new(),
    });
    if let Some(value) = owner.and_then(|owner| owner.parse().ok()) {
        response
            .metadata_mut()
            .insert(openshell_core::replica_routing::OWNER_REPLICA_HEADER, value);
    }
    Ok(response)
}

pub(super) async fn handle_list_sandboxes(
    state: &Arc<ServerState>,
    request: Request<ListSandboxesRequest>,
) -> Result<Response<ListSandboxesResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();
    if !request.label_selector.is_empty() {
        crate::grpc::validation::validate_label_selector(&request.label_selector)?;
    }
    let (workspace, parent_id) =
        if let crate::auth::principal::Principal::Sandbox(caller) = &principal {
            // A sandbox caller (only through `/mcp`) lists its own children, in
            // its own workspace, whatever scope or parent the request names.
            let caller = state
                .store
                .get_message::<Sandbox>(&caller.sandbox_id)
                .await
                .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
                .ok_or_else(|| Status::not_found("sandbox not found"))?;
            (
                Some(caller.object_workspace().to_string()),
                Some(caller.object_id().to_string()),
            )
        } else {
            let scope = authorize_list_workspace_selector(
                &state.store,
                &state.admin_role,
                &principal,
                request.workspace_scope.as_ref(),
                MinWorkspaceRole::User,
            )
            .await?;
            let workspace = if matches!(scope, AuthorizedWorkspaceScope::AllWorkspaces) {
                None
            } else {
                let AuthorizedWorkspaceScope::Workspace(authz) = scope else {
                    unreachable!("all-workspaces scope handled above")
                };
                let workspace =
                    super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
                        .await?
                        .name;
                Some(workspace)
            };
            // Names are unique only within a workspace, so the parent is resolved
            // there, once, and filtered on by id.
            let parent_id = if request.parent.is_empty() {
                None
            } else {
                let Some(workspace) = workspace.as_deref() else {
                    return Err(Status::invalid_argument(
                        "a parent filter needs a single workspace",
                    ));
                };
                let parent = state
                    .store
                    .get_message_by_name::<Sandbox>(workspace, &request.parent)
                    .await
                    .map_err(|e| Status::internal(format!("fetch parent sandbox failed: {e}")))?
                    .ok_or_else(|| {
                        Status::not_found(format!("parent sandbox '{}' not found", request.parent))
                    })?;
                Some(parent.object_id().to_string())
            };
            (workspace, parent_id)
        };
    let scope_fingerprint = workspace.as_deref().unwrap_or("*");
    // The parent's id, not its name, so a token stops working if the parent
    // is deleted and a new sandbox takes its name.
    let mut fingerprint = vec![scope_fingerprint, request.label_selector.as_str()];
    if let Some(parent_id) = parent_id.as_deref() {
        fingerprint.push(parent_id);
    }
    let pagination = Pagination::new(
        request.page_size,
        &request.page_token,
        "ListSandboxes",
        &fingerprint,
    )?;
    let after = pagination.object_cursor()?;
    let query = match (workspace.as_deref(), request.label_selector.as_str()) {
        (None, "") => ObjectListQuery::AllWorkspaces,
        (None, selector) => ObjectListQuery::AllWorkspacesSelector(selector),
        (Some(workspace), "") => ObjectListQuery::Workspace(workspace),
        (Some(workspace), selector) => ObjectListQuery::WorkspaceSelector {
            workspace,
            label_selector: selector,
        },
    };
    if let Some(parent_id) = parent_id {
        let (sandboxes, next_cursor) =
            list_children_page(state, query, after, pagination.page_size(), &parent_id).await?;
        return Ok(Response::new(ListSandboxesResponse {
            sandboxes,
            next_page_token: pagination.next_object_token(next_cursor.as_ref()),
        }));
    }
    let page = state
        .store
        .list_message_page::<Sandbox>(query, after.as_ref(), pagination.page_size())
        .await
        .map_err(|e| Status::internal(format!("list sandboxes failed: {e}")))?;
    let next_page_token = pagination.next_object_token(page.next_cursor.as_ref());
    Ok(Response::new(ListSandboxesResponse {
        sandboxes: page.messages,
        next_page_token,
    }))
}

/// Fill one response page with a parent's children, reading as many store
/// pages as needed. When the response fills partway through a store page,
/// the next cursor is the last record read, so the next page starts right
/// after it instead of skipping the rest of that store page.
async fn list_children_page(
    state: &ServerState,
    query: ObjectListQuery<'_>,
    mut after: Option<crate::persistence::ObjectCursor>,
    page_size: u32,
    parent_id: &str,
) -> Result<(Vec<Sandbox>, Option<crate::persistence::ObjectCursor>), Status> {
    let limit = page_size as usize;
    let mut children = Vec::new();
    loop {
        let page = state
            .store
            .list_object_page(Sandbox::object_type(), query, after.as_ref(), page_size)
            .await
            .map_err(|e| Status::internal(format!("list sandboxes failed: {e}")))?;
        let read = page.records.len();
        for (index, record) in page.records.into_iter().enumerate() {
            let cursor = crate::persistence::ObjectCursor::from(&record);
            let sandbox: Sandbox = crate::persistence::decode_record(record)
                .map_err(|e| Status::internal(format!("list sandboxes failed: {e}")))?;
            if sandbox
                .parent
                .as_ref()
                .is_some_and(|parent| parent.id == parent_id)
            {
                children.push(sandbox);
            }
            if children.len() == limit && index + 1 < read {
                return Ok((children, Some(cursor)));
            }
        }
        match page.next_cursor {
            Some(cursor) if children.len() < limit => after = Some(cursor),
            next_cursor => return Ok((children, next_cursor)),
        }
    }
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
        crate::auth::workspace_authz::selected_workspace_name(req.workspace_scope.as_ref())?,
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
        created_time: openshell_core::time::timestamp_from_millis(current_time_ms()).ok(),
        labels: metadata.labels,
        resource_version: 0,
        annotations: metadata.annotations,
        workspace: workspace.clone(),
        deletion_time: None,
    });
    validate_sandbox_workload_template(&resolved)?;
    let spec = sandbox_spec_from_user_workload_template(&resolved)?;
    state
        .compute
        .validate_caller_driver_config(spec.template.as_ref())?;

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
        crate::auth::workspace_authz::selected_workspace_name(req.workspace_scope.as_ref())?,
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
    if let crate::auth::principal::Principal::Sandbox(caller) = &principal {
        return list_agent_templates(state, &caller.sandbox_id).await;
    }
    let scope = authorize_list_workspace_selector(
        &state.store,
        &state.admin_role,
        &principal,
        request.workspace_scope.as_ref(),
        MinWorkspaceRole::User,
    )
    .await?;
    if !request.label_selector.is_empty() {
        crate::grpc::validation::validate_label_selector(&request.label_selector)?;
    }
    let workspace = if matches!(scope, AuthorizedWorkspaceScope::AllWorkspaces) {
        None
    } else {
        let AuthorizedWorkspaceScope::Workspace(authz) = scope else {
            unreachable!("all-workspaces scope handled above")
        };
        let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
            .await?
            .name;
        Some(workspace)
    };
    let scope_fingerprint = workspace.as_deref().unwrap_or("*");
    let pagination = Pagination::new(
        request.page_size,
        &request.page_token,
        "ListSandboxTemplates",
        &[scope_fingerprint, &request.label_selector],
    )?;
    let after = pagination.object_cursor()?;
    let query = match (workspace.as_deref(), request.label_selector.as_str()) {
        (None, "") => ObjectListQuery::AllWorkspaces,
        (None, selector) => ObjectListQuery::AllWorkspacesSelector(selector),
        (Some(workspace), "") => ObjectListQuery::Workspace(workspace),
        (Some(workspace), selector) => ObjectListQuery::WorkspaceSelector {
            workspace,
            label_selector: selector,
        },
    };
    let page = state
        .store
        .list_message_page::<SandboxWorkloadTemplate>(query, after.as_ref(), pagination.page_size())
        .await
        .map_err(|e| Status::internal(format!("list sandbox templates failed: {e}")))?;
    let next_page_token = pagination.next_object_token(page.next_cursor.as_ref());
    Ok(Response::new(ListSandboxTemplatesResponse {
        templates: page.messages,
        next_page_token,
    }))
}

/// Most templates a sandbox caller is shown; MCP puts every name into the
/// `create_sandbox` tool, so the list stays short.
const MAX_AGENT_TEMPLATES: u32 = 50;

/// A sandbox caller (only through `/mcp`) sees the templates it may create
/// children from, in its own workspace, whatever scope or selector the request
/// names, and without their environment.
async fn list_agent_templates(
    state: &ServerState,
    caller_id: &str,
) -> Result<Response<ListSandboxTemplatesResponse>, Status> {
    let caller = state
        .store
        .get_message::<Sandbox>(caller_id)
        .await
        .map_err(|e| Status::internal(format!("fetch sandbox failed: {e}")))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let selector = format!("{AGENT_USABLE_TEMPLATE_LABEL}=true");
    let page = state
        .store
        .list_message_page::<SandboxWorkloadTemplate>(
            ObjectListQuery::WorkspaceSelector {
                workspace: caller.object_workspace(),
                label_selector: &selector,
            },
            None,
            MAX_AGENT_TEMPLATES,
        )
        .await
        .map_err(|e| Status::internal(format!("list sandbox templates failed: {e}")))?;
    let templates = page
        .messages
        .into_iter()
        .filter(|template| check_agent_usable_template(template).is_ok())
        .map(|mut template| {
            if let Some(workload) = template
                .spec
                .as_mut()
                .and_then(|spec| spec.workload.as_mut())
            {
                workload.environment.clear();
            }
            template
        })
        .collect();
    Ok(Response::new(ListSandboxTemplatesResponse {
        templates,
        next_page_token: String::new(),
    }))
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
        crate::auth::workspace_authz::selected_workspace_name(req.workspace_scope.as_ref())?,
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
    Ok(Response::new(DeleteSandboxTemplateResponse {
        outcome: super::deletion_outcome(deleted, req.allow_missing, "sandbox template")?,
    }))
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
    let sandbox = resolve_and_authorize_sandbox_name(
        state,
        &principal,
        &req.sandbox,
        crate::auth::workspace_authz::selected_workspace_name(req.workspace_scope.as_ref())?,
        MinWorkspaceRole::User,
    )
    .await?;
    let workspace = sandbox.object_workspace().to_string();
    let pagination = Pagination::new(
        req.page_size,
        &req.page_token,
        "ListSandboxProviders",
        &[&workspace, &req.sandbox],
    )?;
    let mut providers = providers_for_sandbox(state, &sandbox, &workspace)
        .await?
        .into_iter()
        .map(|provider| {
            let name = provider
                .metadata
                .as_ref()
                .filter(|metadata| !metadata.name.is_empty())
                .map(|metadata| metadata.name.clone())
                .ok_or_else(|| Status::internal("provider metadata name is missing"))?;
            Ok((name, provider))
        })
        .collect::<Result<Vec<_>, Status>>()?;
    providers.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let start = pagination.provider_cursor()?.map_or(0, |cursor| {
        providers.partition_point(|(name, _)| name.as_str() <= cursor)
    });
    let end = start
        .saturating_add(usize::try_from(pagination.page_size()).expect("u32 fits in usize"))
        .min(providers.len());
    let next_page_token = pagination
        .next_provider_token((end < providers.len()).then(|| providers[end - 1].0.as_str()));
    Ok(Response::new(ListSandboxProvidersResponse {
        providers: providers
            .into_iter()
            .skip(start)
            .take(end - start)
            .map(|(_, provider)| provider)
            .collect(),
        next_page_token,
    }))
}

pub(super) async fn handle_attach_sandbox_provider(
    state: &Arc<ServerState>,
    request: Request<AttachSandboxProviderRequest>,
) -> Result<Response<AttachSandboxProviderResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    #[cfg(test)]
    let attach_wait_probe = request
        .extensions()
        .get::<Arc<tokio::sync::Notify>>()
        .cloned();
    let request = request.into_inner();
    let sandbox = resolve_and_authorize_sandbox_name(
        state,
        &principal,
        &request.sandbox,
        crate::auth::workspace_authz::selected_workspace_name(request.workspace_scope.as_ref())?,
        MinWorkspaceRole::User,
    )
    .await?;
    let workspace =
        super::workspace::resolve_workspace(state.store.as_ref(), sandbox.object_workspace())
            .await?
            .ensure_active()?;
    if request.provider.is_empty() {
        return Err(Status::invalid_argument("provider_name is required"));
    }

    // Validate provider name would not violate sandbox spec constraints if added
    // (pre-validation ensures CAS mutations preserve invariants)
    if request.provider.len() > super::MAX_NAME_LEN {
        return Err(Status::invalid_argument(format!(
            "provider_name exceeds maximum length ({} > {})",
            request.provider.len(),
            super::MAX_NAME_LEN
        )));
    }

    // The receipt must capture the provider revision selected by this
    // serialized mutation, after any preceding credential update has finished.
    #[cfg(test)]
    if let Some(probe) = attach_wait_probe {
        probe.notify_one();
    }
    // A child also locks its parent, so the parent's providers cannot change
    // before the attach is saved.
    let scope = sandbox.parent.as_ref().map_or_else(
        || MutationScope::sandbox(sandbox.object_workspace(), sandbox.object_id()),
        |parent| MutationScope::ChildSandbox {
            workspace: sandbox.object_workspace(),
            sandbox_id: sandbox.object_id(),
            parent_id: &parent.id,
        },
    );
    let _mutation_guard =
        state.compute.mutation_guard(scope).await.map_err(|err| {
            super::persistence_error_to_status(err, "acquire sandbox mutation lock")
        })?;
    if let Some(parent) = &sandbox.parent {
        check_parent_has_provider(state, parent, &request.provider).await?;
    }
    let provider_record = get_provider_record(state.store.as_ref(), &workspace, &request.provider)
        .await
        .map_err(|err| {
            if err.code() == tonic::Code::NotFound {
                Status::failed_precondition(format!("provider '{}' not found", request.provider))
            } else {
                err
            }
        })?;
    let sandbox_name = sandbox.object_name().to_string();
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
        && !spec.providers.iter().any(|name| name == &request.provider)
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
        .any(|name| name == &request.provider)
    {
        candidate_spec.providers.push(request.provider.clone());
    }
    validate_sandbox_spec(&sandbox_name, &candidate_spec)?;
    let provider_profile_catalog = state
        .provider_profile_sources
        .snapshot_catalog(state.store.as_ref(), &workspace)
        .await?;
    super::provider::validate_provider_profiles_present(
        state.store.as_ref(),
        &provider_profile_catalog,
        &workspace,
        &candidate_spec.providers,
    )
    .await?;
    validate_provider_environment_keys_unique_with_catalog(
        state.store.as_ref(),
        crate::provider_refresh::RefreshStateReader::Runtime(&state.refresh),
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
    let current_policy =
        super::policy::current_base_policy_for_sandbox(state.store.as_ref(), &sandbox).await?;
    super::policy::validate_candidate_sandbox_credential_policy(
        state,
        &workspace,
        &candidate_spec.providers,
        Some(&current_policy),
    )
    .await?;

    let provider_name = request.provider.clone();
    let attached = Arc::new(AtomicBool::new(false));
    let attached_clone = attached.clone();
    let mutation_id = uuid::Uuid::new_v4().to_string();

    let sandbox = update_sandbox_cas(
        state,
        &sandbox_id,
        request.expected_resource_version,
        |sandbox| {
            attached_clone.store(false, Ordering::Relaxed);
            let Some(ref mut spec) = sandbox.spec else {
                // Spec should always exist post-creation; if missing, fail CAS to surface error
                return;
            };

            if spec.provider_attachment_epoch.is_empty() {
                spec.provider_attachment_epoch.clone_from(&mutation_id);
            }

            dedupe_provider_names(&mut spec.providers);
            if !spec.providers.iter().any(|name| name == &provider_name)
                && spec.providers.len() < MAX_PROVIDERS
            {
                spec.providers.push(provider_name.clone());
                spec.provider_attachment_epoch.clone_from(&mutation_id);
                attached_clone.store(true, Ordering::Relaxed);
                crate::compute::provisioning_deadline::attachments_changed(
                    sandbox,
                    current_time_ms(),
                );
            }
        },
    )
    .await
    .map_err(|e| super::persistence_error_to_status(e, "attach sandbox provider"))?;

    let attached = attached.load(Ordering::Relaxed);
    if attached {
        crate::config_delivery::publish_sandbox(state, &sandbox_id);
        state.sandbox_watch_bus.notify(&sandbox_id);
    }
    let receipt = super::provider_readiness::record_provider_mutation(
        state,
        &sandbox,
        &request.provider,
        ProviderMutationKind::Attach,
        Some((
            provider_record.object_id(),
            provider_record.get_resource_version(),
        )),
        &mutation_id,
    )
    .await?;

    info!(
        sandbox_name = %sandbox_name,
        provider_name = %request.provider,
        attached,
        "AttachSandboxProvider request completed successfully"
    );

    Ok(Response::new(AttachSandboxProviderResponse {
        sandbox: Some(sandbox),
        attached,
        receipt: Some(receipt),
    }))
}

pub(super) async fn handle_detach_sandbox_provider(
    state: &Arc<ServerState>,
    request: Request<DetachSandboxProviderRequest>,
) -> Result<Response<DetachSandboxProviderResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let request = request.into_inner();
    let sandbox = resolve_and_authorize_sandbox_name(
        state,
        &principal,
        &request.sandbox,
        crate::auth::workspace_authz::selected_workspace_name(request.workspace_scope.as_ref())?,
        MinWorkspaceRole::User,
    )
    .await?;
    let workspace = sandbox.object_workspace().to_string();
    if request.provider.is_empty() {
        return Err(Status::invalid_argument("provider_name is required"));
    }

    // Validate provider name (pre-validation ensures CAS mutations preserve invariants)
    if request.provider.len() > super::MAX_NAME_LEN {
        return Err(Status::invalid_argument(format!(
            "provider_name exceeds maximum length ({} > {})",
            request.provider.len(),
            super::MAX_NAME_LEN
        )));
    }

    let mutation_guard = state
        .compute
        .mutation_guard(MutationScope::sandbox(
            sandbox.object_workspace(),
            sandbox.object_id(),
        ))
        .await
        .map_err(|err| super::persistence_error_to_status(err, "acquire sandbox mutation lock"))?;
    let sandbox_name = sandbox.object_name().to_string();
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
        .retain(|name| name != &request.provider);
    dedupe_provider_names(&mut candidate_spec.providers);
    super::policy::validate_candidate_provider_attachments(
        state,
        &workspace,
        &sandbox,
        &candidate_spec.providers,
    )
    .await?;

    let (sandbox, detached, receipt) = detach_provider_locked(
        state,
        &sandbox_id,
        request.expected_resource_version,
        &request.provider,
    )
    .await?;
    drop(mutation_guard);

    info!(
        sandbox_name = %sandbox_name,
        provider_name = %request.provider,
        detached,
        "DetachSandboxProvider request completed successfully"
    );

    // A root's children lose what it loses. Delivery already serves them only
    // the root's providers; the sync, never cancelled, removes the provider
    // from their records and pushes each child. It runs for every root, so a
    // retried detach still reaches children an earlier sync missed. Every
    // session that follows the provider rebuilds at once, which includes
    // the children: their records name it until the sync runs.
    if sandbox.parent.is_none() {
        if detached {
            crate::config_delivery::publish_provider(state, &workspace, &request.provider);
        }
        super::policy::spawn_child_policy_sync(state, &sandbox_id);
    }

    Ok(Response::new(DetachSandboxProviderResponse {
        sandbox: Some(sandbox),
        detached,
        receipt: Some(receipt),
    }))
}

/// Detach `provider` from a sandbox: bump its attachment epoch so its
/// supervisor drops the credential, push the change, and record the
/// readiness receipt. The caller holds the sandbox's mutation lock.
async fn detach_provider_locked(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    expected_resource_version: u64,
    provider: &str,
) -> Result<
    (
        Sandbox,
        bool,
        openshell_core::proto::ProviderMutationReceipt,
    ),
    Status,
> {
    let provider_name = provider.to_string();
    let detached = Arc::new(AtomicBool::new(false));
    let detached_clone = detached.clone();
    let mutation_id = uuid::Uuid::new_v4().to_string();

    let sandbox = update_sandbox_cas(state, sandbox_id, expected_resource_version, |sandbox| {
        detached_clone.store(false, Ordering::Relaxed);
        let Some(ref mut spec) = sandbox.spec else {
            // Spec should always exist post-creation; if missing, fail CAS to surface error
            return;
        };

        if spec.provider_attachment_epoch.is_empty() {
            spec.provider_attachment_epoch.clone_from(&mutation_id);
        }

        let before_len = spec.providers.len();
        spec.providers.retain(|name| name != &provider_name);
        if spec.providers.len() != before_len {
            spec.provider_attachment_epoch.clone_from(&mutation_id);
            detached_clone.store(true, Ordering::Relaxed);
            // Only dedupe after making a change
            dedupe_provider_names(&mut spec.providers);
            crate::compute::provisioning_deadline::attachments_changed(sandbox, current_time_ms());
        }
    })
    .await
    .map_err(|e| super::persistence_error_to_status(e, "detach sandbox provider"))?;

    let detached = detached.load(Ordering::Relaxed);
    if detached {
        crate::config_delivery::publish_sandbox(state, sandbox_id);
        state.sandbox_watch_bus.notify(sandbox_id);
    }
    let receipt = super::provider_readiness::record_provider_mutation(
        state,
        &sandbox,
        provider,
        ProviderMutationKind::Detach,
        None,
        &mutation_id,
    )
    .await?;
    Ok((sandbox, detached, receipt))
}

pub(super) async fn handle_delete_sandbox(
    state: &Arc<ServerState>,
    request: Request<DeleteSandboxRequest>,
) -> Result<Response<DeleteSandboxResponse>, Status> {
    let result = handle_delete_sandbox_inner(state, request).await;
    let outcome = match &result {
        Ok(_) => TelemetryOutcome::Success,
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
    if let crate::auth::principal::Principal::Sandbox(caller) = &principal {
        return delete_caller_child(state, caller, &req).await;
    }
    let name = req.name;
    if name.is_empty() {
        return Err(Status::invalid_argument("sandbox is required"));
    }
    let authz = authorize_workspace(
        &state.store,
        &state.admin_role,
        &principal,
        crate::auth::workspace_authz::selected_workspace_name(req.workspace_scope.as_ref())?,
        MinWorkspaceRole::User,
    )
    .await
    .map_err(|status| {
        if status.code() == tonic::Code::PermissionDenied {
            Status::not_found("sandbox not found")
        } else {
            status
        }
    })?;
    let workspace = super::workspace::resolve_workspace(state.store.as_ref(), &authz.workspace)
        .await?
        .name;
    // Main's canonical public delete request contains no caller-provided
    // identity/version fields. The compute layer still binds the resolved
    // object ID and lifecycle guards before committing deletion.
    let preconditions = SandboxDeletePreconditions::default();
    let result = state
        .compute
        .delete_sandbox_allow_missing_with_preconditions(
            &workspace,
            &name,
            req.allow_missing,
            preconditions,
        )
        .await?;
    if !result.sandbox_id.is_empty() {
        state.telemetry.end_sandbox_session(&result.sandbox_id);
    }
    info!(sandbox_name = %name, "DeleteSandbox request completed successfully");
    Ok(Response::new(DeleteSandboxResponse {
        outcome: result.outcome.into(),
        sandbox_id: result.sandbox_id,
    }))
}

/// A sandbox caller (only through `/mcp`) deleting one of its own children.
/// The delete is bound to the id that was checked, so a name reused in the
/// meantime is never deleted in its place.
async fn delete_caller_child(
    state: &Arc<ServerState>,
    caller: &crate::auth::principal::SandboxPrincipal,
    request: &DeleteSandboxRequest,
) -> Result<Response<DeleteSandboxResponse>, Status> {
    let set = [
        ("workspace_scope", request.workspace_scope.is_some()),
        ("allow_missing", request.allow_missing),
        ("request_id", !request.request_id.is_empty()),
    ];
    if let Some((field, _)) = set.iter().find(|(_, is_set)| *is_set) {
        return Err(Status::invalid_argument(format!(
            "field '{field}' is not allowed for sandbox callers"
        )));
    }
    if *request
        != (DeleteSandboxRequest {
            name: request.name.clone(),
            ..Default::default()
        })
    {
        return Err(Status::invalid_argument(
            "the request sets fields that are not allowed for sandbox callers",
        ));
    }
    let child = resolve_caller_child(state, caller, &request.name).await?;
    let preconditions = SandboxDeletePreconditions {
        expected_sandbox_id: Some(child.object_id().to_string()),
        ..Default::default()
    };
    let result = match state
        .compute
        .delete_sandbox_allow_missing_with_preconditions(
            child.object_workspace(),
            child.object_name(),
            false,
            preconditions,
        )
        .await
    {
        Ok(result) => result,
        // The checked child is gone when its name no longer resolves to it;
        // any other conflict is reported as it is.
        Err(status) if status.code() == tonic::Code::Aborted => {
            return Err(aborted_child_delete(
                state,
                caller,
                &request.name,
                child.object_id(),
                status,
            )
            .await);
        }
        Err(status) => return Err(status),
    };
    state.telemetry.end_sandbox_session(&result.sandbox_id);
    info!(sandbox_name = %request.name, "DeleteSandbox request completed successfully");
    Ok(Response::new(DeleteSandboxResponse {
        outcome: result.outcome.into(),
        sandbox_id: result.sandbox_id,
    }))
}

/// An aborted delete means the checked child is gone when its name no longer
/// resolves to it (a name reused in the meantime); any other conflict is
/// reported as it is.
async fn aborted_child_delete(
    state: &ServerState,
    caller: &crate::auth::principal::SandboxPrincipal,
    name: &str,
    checked_id: &str,
    status: Status,
) -> Status {
    match resolve_caller_child(state, caller, name).await {
        Ok(current) if current.object_id() == checked_id => status,
        _ => Status::not_found(format!("sandbox '{name}' not found")),
    }
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
    let resolved = resolve_and_authorize_sandbox_name(
        state,
        &principal,
        &req.name,
        crate::auth::workspace_authz::selected_workspace_name(req.workspace_scope.as_ref())?,
        MinWorkspaceRole::User,
    )
    .await?;
    let workspace = resolved.object_workspace();
    let name = resolved.object_name();
    let sandbox = state.compute.stop_sandbox(workspace, name).await?;
    info!(sandbox_name = %name, "StopSandbox request completed successfully");
    Ok(Response::new(SandboxResponse {
        sandbox: Some(sandbox),
        service_urls: HashMap::new(),
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
    let resolved = resolve_and_authorize_sandbox_name(
        state,
        &principal,
        &req.name,
        crate::auth::workspace_authz::selected_workspace_name(req.workspace_scope.as_ref())?,
        MinWorkspaceRole::User,
    )
    .await?;
    refuse_orphaned_child(state, &resolved).await?;
    let workspace = resolved.object_workspace().to_string();
    let name = resolved.object_name().to_string();
    let mut sandbox = state
        .compute
        .start_sandbox_authenticated(
            &workspace,
            &name,
            state.sandbox_session_jwt_authority.as_deref(),
        )
        .await?;
    let remote_authority =
        crate::supervisor_session::remote_supervisor_owner(state, sandbox.object_id())
            .await?
            .is_some();
    state
        .supervisor_sessions
        .project_endpoint_status(&mut sandbox, remote_authority);
    info!(sandbox_name = %name, "StartSandbox request completed successfully");
    Ok(Response::new(SandboxResponse {
        sandbox: Some(sandbox),
        service_urls: HashMap::new(),
    }))
}

pub(super) async fn handle_suspend_sandbox(
    state: &Arc<ServerState>,
    request: Request<SuspendSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    let result = handle_suspend_sandbox_inner(state, request).await;
    openshell_core::telemetry::emit_lifecycle(
        LifecycleResource::Sandbox,
        LifecycleOperation::Suspend,
        if result.is_ok() {
            TelemetryOutcome::Success
        } else {
            TelemetryOutcome::Failure
        },
    );
    result
}

async fn handle_suspend_sandbox_inner(
    state: &Arc<ServerState>,
    request: Request<SuspendSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    let resolved = resolve_and_authorize_sandbox_name(
        state,
        &principal,
        &req.name,
        crate::auth::workspace_authz::selected_workspace_name(req.workspace_scope.as_ref())?,
        MinWorkspaceRole::User,
    )
    .await?;
    let workspace = resolved.object_workspace();
    let name = resolved.object_name();
    let sandbox = state.compute.suspend_sandbox(workspace, name).await?;
    info!(sandbox_name = %name, "SuspendSandbox request completed successfully");
    Ok(Response::new(SandboxResponse {
        sandbox: Some(sandbox),
        service_urls: HashMap::new(),
    }))
}

pub(super) async fn handle_resume_sandbox(
    state: &Arc<ServerState>,
    request: Request<ResumeSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    let result = handle_resume_sandbox_inner(state, request).await;
    openshell_core::telemetry::emit_lifecycle(
        LifecycleResource::Sandbox,
        LifecycleOperation::Resume,
        if result.is_ok() {
            TelemetryOutcome::Success
        } else {
            TelemetryOutcome::Failure
        },
    );
    result
}

async fn handle_resume_sandbox_inner(
    state: &Arc<ServerState>,
    request: Request<ResumeSandboxRequest>,
) -> Result<Response<SandboxResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    let resolved = resolve_and_authorize_sandbox_name(
        state,
        &principal,
        &req.name,
        crate::auth::workspace_authz::selected_workspace_name(req.workspace_scope.as_ref())?,
        MinWorkspaceRole::User,
    )
    .await?;
    refuse_orphaned_child(state, &resolved).await?;
    let workspace = resolved.object_workspace().to_string();
    let name = resolved.object_name().to_string();
    let mut sandbox = state
        .compute
        .resume_sandbox_authenticated(
            &workspace,
            &name,
            req.restart_if_restore_fails,
            state.sandbox_session_jwt_authority.as_deref(),
        )
        .await?;
    let remote_authority =
        crate::supervisor_session::remote_supervisor_owner(state, sandbox.object_id())
            .await?
            .is_some();
    state
        .supervisor_sessions
        .project_endpoint_status(&mut sandbox, remote_authority);
    info!(sandbox_name = %name, "ResumeSandbox request completed successfully");
    Ok(Response::new(SandboxResponse {
        sandbox: Some(sandbox),
        service_urls: HashMap::new(),
    }))
}

pub async fn mint_persisted_authentication(
    state: &ServerState,
    sandbox: &Sandbox,
) -> Result<openshell_core::jwt::SandboxLaunchAuthentication, Status> {
    let authority = state
        .sandbox_session_jwt_authority
        .as_ref()
        .ok_or_else(|| Status::failed_precondition("sandbox session authority is unavailable"))?;
    let metadata = sandbox
        .metadata
        .as_ref()
        .ok_or_else(|| Status::failed_precondition("sandbox metadata is missing"))?;
    let identity =
        crate::auth::sandbox_session::PersistedSandboxIdentity::read(&metadata.annotations)
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
    let mut authentication = authority.mint_persisted_launch(sandbox.object_id(), &identity)?;
    let mut with_identity = sandbox.clone();
    state
        .compute
        .prepare_ssh_identity(&mut with_identity, &mut authentication)
        .await?;
    Ok(authentication)
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

/// Retry a pure server-owned mutation on a fresh resource version. Explicit
/// client versions still fail on conflict so clients retain their CAS contract.
async fn update_sandbox_cas<F>(
    state: &ServerState,
    sandbox_id: &str,
    expected_resource_version: u64,
    mut mutate: F,
) -> crate::persistence::PersistenceResult<Sandbox>
where
    F: FnMut(&mut Sandbox),
{
    for attempt in 1..=SANDBOX_CAS_RETRY_LIMIT {
        match state
            .store
            .update_message_cas::<Sandbox, _>(sandbox_id, expected_resource_version, &mut mutate)
            .await
        {
            Ok(sandbox) => return Ok(sandbox),
            Err(crate::persistence::PersistenceError::Conflict { .. })
                if expected_resource_version == 0 && attempt < SANDBOX_CAS_RETRY_LIMIT => {}
            Err(error) => return Err(error),
        }
    }

    unreachable!("sandbox CAS retry loop always returns on its final attempt")
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
    let sandbox = resolve_and_authorize_sandbox_name(
        state,
        &principal,
        &req.sandbox,
        crate::auth::workspace_authz::selected_workspace_name(req.workspace_scope.as_ref())?,
        MinWorkspaceRole::User,
    )
    .await?;
    let sandbox_id = sandbox.object_id().to_string();

    let follow_status = req.follow_status;
    let follow_logs = req.follow_logs;
    let follow_events = req.follow_events;
    let log_tail = if req.log_tail_lines == 0 {
        200
    } else {
        req.log_tail_lines
    };
    let stop_on_terminal = req.stop_on_terminal;
    if let Some(since_time) = req.since_time.as_ref() {
        openshell_core::time::validate_timestamp(since_time)
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
    }
    let log_since_time = req.since_time;
    let log_sources = req.log_sources;
    let log_min_level = req.log_min_level;
    let event_tail = req.event_tail;

    // Decode the resume cursor before spawning the producer. A token this
    // server could not have issued is pure input validation, in the same class
    // as the `id is required` check above, so it fails the RPC rather than
    // arriving as the first item of an otherwise-established stream.
    let resume_after = if req.resume_after_cursor.is_empty() {
        None
    } else {
        Some(
            WatchCursor::parse(&req.resume_after_cursor)
                .map_err(|e| Status::invalid_argument(e.to_string()))?,
        )
    };

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
                            // Status snapshots are re-read, not resumed by cursor.
                            cursor: String::new(),
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

            // Highest seq the tail/replay phase already handled, tracked per
            // source. The broadcast receivers were subscribed before replay ran,
            // so an event published during initialization can sit in both the
            // replay buffer and a live receiver; the live loop suppresses events
            // at or below its source's mark so each is delivered exactly once.
            //
            // The two marks must stay separate. Both buses number from one
            // shared cursor space, but they are read at different instants and
            // bounded independently (`log_tail_lines` vs `event_tail`, which has
            // no default and so replays nothing unless the client asks). A
            // single shared mark therefore lets the deeper source censor the
            // shallower one: with the default `event_tail` of 0 the mark rises
            // to the newest buffered log while no platform event was replayed at
            // all, and every platform event published in the initialization
            // window is dropped as a duplicate of something never sent. Keyed by
            // source, an event is suppressed only if its own source's replay
            // actually covered it.
            //
            // No unit test pins this. The only reachable window is between the
            // subscribe above and the log tail read below -- an event published
            // earlier is replayed rather than live, and one published later
            // outranks the mark -- and the producer crosses that window with no
            // await a test can wedge open. Reproducing it needs a seam in the
            // producer, which is not worth adding to production code.
            let resume_seq = resume_after.map_or(0, |resume| resume.seq);
            let mut log_cutoff: u64 = resume_seq;
            let mut platform_cutoff: u64 = resume_seq;

            if let Some(resume) = resume_after {
                // Resume: replay events strictly after the client's cursor from both
                // resumable buses. Either bus reporting a trimmed range is an
                // unrecoverable gap -> terminate with a documented status.
                use openshell_core::proto::sandbox_stream_event::Payload;

                // A cursor is only a position inside the space that issued it.
                // A gateway restart, a bus teardown, or a reconnect landing on
                // another replica starts a new space numbered from 1 with no
                // record of the cursors the old one handed out. The buses then
                // look merely empty, so `tail_after` reports no gap -- treating
                // that as "caught up" would pin the cutoff to a stale number
                // and silently swallow every live event beneath it. Comparing
                // epochs answers "did this cursor come from *this* space?",
                // which no numeric bound can.
                match state.tracing_log_bus.cursor_space(&sandbox_id) {
                    None => {
                        let _ = tx.send(Err(Status::out_of_range(RESUME_SPACE_GONE))).await;
                        return;
                    }
                    Some(space) if space.epoch != resume.epoch => {
                        let _ = tx.send(Err(Status::out_of_range(RESUME_SPACE_GONE))).await;
                        return;
                    }
                    // Right space, but ahead of anything it issued: only a
                    // fabricated token gets here. Reject rather than accept a
                    // cutoff no event can ever exceed.
                    Some(space) if resume.seq > space.highest_seq => {
                        let _ = tx
                            .send(Err(Status::out_of_range(RESUME_CURSOR_AHEAD)))
                            .await;
                        return;
                    }
                    Some(_) => {}
                }

                let log_replay = if follow_logs {
                    Some(state.tracing_log_bus.tail_after(&sandbox_id, resume.seq))
                } else {
                    None
                };

                let platform_replay = if follow_events {
                    Some(
                        state
                            .tracing_log_bus
                            .platform_event_bus
                            .tail_after(&sandbox_id, resume.seq),
                    )
                } else {
                    None
                };

                // Re-check the epoch now that both tails are in hand. The check
                // above and each `tail_after` take their locks independently, so
                // a teardown plus a republish can retire the validated space and
                // install a replacement in between. The reads would then have
                // applied the old space's seq to the new space's buffers, and
                // `tail_after` -- which only knows numbers -- would report no gap
                // while skipping every replacement event at or below it. The
                // second look is cheap and runs before anything is emitted, so a
                // space that moved under us ends the stream instead of serving a
                // truncated replay.
                //
                // Ordering is unchanged: this takes only the allocator lock and
                // releases it, never held across a bus lock.
                if !cursor_space_is(&state, &sandbox_id, resume.epoch) {
                    let _ = tx.send(Err(Status::out_of_range(RESUME_SPACE_GONE))).await;
                    return;
                }

                // Gap check FIRST (borrows), before the merge moves the vecs.
                for replay in [&log_replay, &platform_replay] {
                    if let Some(Err(gap)) = replay {
                        let _ = tx.send(Err(Status::out_of_range(format!(
                                "resume cursor {} is no longer available; earliest resumable cursor is {}",
                                gap.requested_after, gap.oldest_available
                            ))))
                            .await;
                        return;
                    }
                }

                // Merge both buses by shared seq, then emit ascending. Each
                // source's mark comes from its own replay -- `tail_after`
                // returns ascending, so its last entry is that source's high
                // water. Marking every event the phase examined, not only the
                // ones that survived the filters, keeps a filtered event's live
                // duplicate suppressed: the live loop does not re-apply
                // `log_since_time` and would otherwise let it through.
                let mut merged: Vec<CursoredEvent> = Vec::new();
                if let Some(Ok(v)) = log_replay {
                    if let Some(last) = v.last() {
                        log_cutoff = log_cutoff.max(last.seq);
                    }
                    merged.extend(v);
                }
                if let Some(Ok(v)) = platform_replay {
                    if let Some(last) = v.last() {
                        platform_cutoff = platform_cutoff.max(last.seq);
                    }
                    merged.extend(v);
                }

                merged.sort_by_key(|c| c.seq);

                for cursored in merged {
                    if let Some(Payload::Log(ref log)) = cursored.event.payload {
                        if let Some(since_time) = log_since_time.as_ref() {
                            let Some(event_time) = log.event_time.as_ref() else {
                                continue;
                            };
                            let Ok(ordering) =
                                openshell_core::time::compare_timestamps(event_time, since_time)
                            else {
                                continue;
                            };
                            if ordering == std::cmp::Ordering::Less {
                                continue;
                            }
                        }
                        if !log_sources.is_empty() && !source_matches(&log.source, &log_sources) {
                            continue;
                        }
                        if !level_matches(&log.level, &log_min_level) {
                            continue;
                        }
                    }
                    if tx.send(Ok(cursored.event)).await.is_err() {
                        return;
                    }
                }
            } else {
                // Initial tail, best-effort. Both buses draw from one shared
                // cursor space, so draining each in its own pass would order the
                // tail by source and only incidentally by cursor: every buffered
                // log would precede every buffered platform event regardless of
                // which was published first. Collect both windows, sort by the
                // shared seq, and emit one ascending run -- the same shape the
                // resume path above uses, and the order a client comparing
                // cursors expects.
                //
                // The two windows are truncated independently (log_tail vs
                // event_tail), so this merges whatever each bus retained; it
                // does not align their depths.
                let mut tail: Vec<CursoredEvent> = Vec::new();
                if follow_logs {
                    let logs = state.tracing_log_bus.tail(&sandbox_id, log_tail as usize);
                    if let Some(last) = logs.last() {
                        log_cutoff = log_cutoff.max(last.seq);
                    }
                    tail.extend(logs);
                }
                if follow_events {
                    let events = state
                        .tracing_log_bus
                        .platform_event_bus
                        .tail(&sandbox_id, event_tail as usize);
                    if let Some(last) = events.last() {
                        platform_cutoff = platform_cutoff.max(last.seq);
                    }
                    tail.extend(events);
                }

                tail.sort_by_key(|cursored| cursored.seq);

                for cursored in tail {
                    // Log filters; platform events carry no log fields and pass.
                    if let Some(openshell_core::proto::sandbox_stream_event::Payload::Log(
                        ref log,
                    )) = cursored.event.payload
                    {
                        if let Some(since_time) = log_since_time.as_ref() {
                            let Some(event_time) = log.event_time.as_ref() else {
                                continue;
                            };
                            let Ok(ordering) =
                                openshell_core::time::compare_timestamps(event_time, since_time)
                            else {
                                continue;
                            };
                            if ordering == std::cmp::Ordering::Less {
                                continue;
                            }
                        }
                        if !log_sources.is_empty() && !source_matches(&log.source, &log_sources) {
                            continue;
                        }
                        if !level_matches(&log.level, &log_min_level) {
                            continue;
                        }
                    }
                    if tx.send(Ok(cursored.event)).await.is_err() {
                        return;
                    }
                }
            }

            // Events drained above the publication watermark. They are held
            // back rather than emitted so the client's highest delivered cursor
            // is never above an event still queued on the other source.
            let mut deferred: Vec<Arc<CursoredEvent>> = Vec::new();

            loop {
                // Events withheld by the previous round are already in hand, so
                // this round must not block on a new publication: the watermark
                // that covers them has already advanced past them, and waiting
                // for unrelated traffic would stall their delivery indefinitely.
                let first = if deferred.is_empty() {
                    Some(tokio::select! {
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
                                        if tx.send(Ok(SandboxStreamEvent { payload: Some(openshell_core::proto::sandbox_stream_event::Payload::Sandbox(sandbox.clone())), cursor: String::new() })).await.is_err() {
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
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                // Lag is recoverable: surface a warning and keep streaming.
                                if tx.send(Ok(crate::sandbox_watch::lag_warning_event(n))).await.is_err() {
                                    return;
                                }
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                let _ = tx.send(Err(Status::cancelled("stream closed"))).await;
                                return;
                            }
                        }
                        // Status snapshots carry cursor 0 and are outside the
                        // resumable cursor space, so they never join a batch.
                        continue;
                    }
                    // Both resumable sources feed one cursor space, so neither
                    // can be emitted on its own: `select!` picks an arbitrary
                    // ready branch, which would emit a higher cursor ahead of a
                    // lower one waiting on the other source. Take whichever woke
                    // us as the start of a batch and merge below.
                    res = async {
                        match log_rx.as_mut() {
                            Some(rx) => rx.recv().await,
                            None => future::pending().await,
                        }
                    } => res,
                    res = async {
                        match platform_rx.as_mut() {
                            Some(rx) => rx.recv().await,
                            None => future::pending().await,
                        }
                    } => res,
                    })
                } else {
                    None
                };

                let mut batch = std::mem::take(&mut deferred);
                match first {
                    None => {}
                    Some(Ok(evt)) => batch.push(evt),
                    Some(Err(broadcast::error::RecvError::Lagged(n))) => {
                        // Lag is recoverable: surface a warning and keep streaming.
                        if tx
                            .send(Ok(crate::sandbox_watch::lag_warning_event(n)))
                            .await
                            .is_err()
                        {
                            return;
                        }
                        // Carry any withheld events into the next round rather
                        // than dropping them with this batch.
                        deferred = batch;
                        continue;
                    }
                    Some(Err(broadcast::error::RecvError::Closed)) => {
                        let _ = tx.send(Err(Status::cancelled("stream closed"))).await;
                        return;
                    }
                }

                // Read the publication watermark before draining. Publishers
                // assign a sequence and push it onto their broadcast channel
                // under one allocator lock, so every event at or below the
                // sequence observed here has already reached its channel and
                // the drain below is guaranteed to see it. Reading after the
                // drain would admit a publish into the gap and defeat this.
                //
                // `None` means the cursor space is gone (teardown). Nothing
                // further can be published into it, so nothing is withheld.
                let watermark = state
                    .tracing_log_bus
                    .cursor_space(&sandbox_id)
                    .map_or(u64::MAX, |space| space.highest_seq);

                // Drain what is already queued on both sources. Sorting the
                // batch restores cursor order across the two sources without
                // waiting on either one.
                let mut lagged = 0u64;
                let mut closed = false;
                for rx in [log_rx.as_mut(), platform_rx.as_mut()]
                    .into_iter()
                    .flatten()
                {
                    loop {
                        match rx.try_recv() {
                            Ok(evt) => batch.push(evt),
                            Err(broadcast::error::TryRecvError::Empty) => break,
                            // Keep draining: the receiver is usable after a skip.
                            Err(broadcast::error::TryRecvError::Lagged(n)) => lagged += n,
                            Err(broadcast::error::TryRecvError::Closed) => {
                                closed = true;
                                break;
                            }
                        }
                    }
                }

                batch.sort_by_key(|cursored| cursored.seq);

                // Withhold anything above the watermark. Such an event was
                // published after the drain started, so a lower-cursor event
                // from the other source may still be queued behind it. Emitting
                // it now would let the client checkpoint above an event it has
                // not seen, and resume past it after a disconnect. The next
                // round re-reads the watermark, which by then covers these.
                let held_from = batch.partition_point(|cursored| cursored.seq <= watermark);
                deferred = batch.split_off(held_from);

                // Announce the gap before any event from this batch. A warning
                // carries no cursor and is never replayed, so emitting it after
                // the events lets a disconnect at the wrong moment strand the
                // client past the gap: it would resume from a cursor above the
                // skipped events having never learned they were dropped.
                if lagged > 0
                    && tx
                        .send(Ok(crate::sandbox_watch::lag_warning_event(lagged)))
                        .await
                        .is_err()
                {
                    return;
                }

                for cursored in batch {
                    // Skip events the tail/replay phase already handled, judged
                    // against the mark for this event's own source. Bus events
                    // always carry seq >= 1, so no sentinel is needed here:
                    // non-resumable events never reach this batch.
                    let is_log = matches!(
                        cursored.event.payload,
                        Some(openshell_core::proto::sandbox_stream_event::Payload::Log(_))
                    );
                    let cutoff = if is_log { log_cutoff } else { platform_cutoff };
                    if cursored.seq <= cutoff {
                        continue;
                    }
                    if let Some(openshell_core::proto::sandbox_stream_event::Payload::Log(
                        ref log,
                    )) = cursored.event.payload
                    {
                        if !log_sources.is_empty() && !source_matches(&log.source, &log_sources) {
                            continue;
                        }
                        if !level_matches(&log.level, &log_min_level) {
                            continue;
                        }
                    }
                    if tx
                        .send(Ok(Arc::unwrap_or_clone(cursored).event))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }

                if closed {
                    let _ = tx.send(Err(Status::cancelled("stream closed"))).await;
                    return;
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
        SandboxPhase::Ready
            | SandboxPhase::Completed
            | SandboxPhase::Stopped
            | SandboxPhase::Suspended
            | SandboxPhase::Error
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
    let completion = request
        .extensions()
        .get::<super::mutation_replay::Completion>()
        .cloned();
    let req = request.into_inner();
    validate_exec_start(&req)?;

    // Only `/mcp` lets a sandbox caller reach this method, and it may act on
    // its own children only, never on itself.
    let sandbox = if let crate::auth::principal::Principal::Sandbox(caller) = &principal {
        refuse_exec_fields_for_sandbox_caller(&req)?;
        resolve_caller_child(state, caller, &req.sandbox).await?
    } else {
        resolve_and_authorize_sandbox_name(
            state,
            &principal,
            &req.sandbox,
            crate::auth::workspace_authz::selected_workspace_name(req.workspace_scope.as_ref())?,
            MinWorkspaceRole::User,
        )
        .await?
    };

    if let Some(completion) = &completion {
        completion.ensure_target(sandbox.object_id())?;
    }

    require_ready_sandbox(&sandbox)?;

    // Open a relay channel through the supervisor session. Use a 15s
    // session-wait timeout, enough to cover a transient supervisor reconnect
    // while still failing quickly during normal operation.
    let (channel_id, relay_rx) = crate::supervisor_session::open_routed_relay_with_target(
        state,
        sandbox.object_id(),
        relay_open::Target::Ssh(SshRelayTarget {}),
        String::new(),
        std::time::Duration::from_secs(15),
    )
    .await
    .map_err(|e| Status::unavailable(format!("supervisor relay failed: {e}")))?;

    let command_str = build_remote_exec_command(&req)
        .map_err(|e| Status::invalid_argument(format!("command construction failed: {e}")))?;
    let stdin_payload = req.stdin;
    let execution_timeout = req
        .execution_timeout
        .as_ref()
        .map(openshell_core::time::duration_to_std)
        .transpose()
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
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
            execution_timeout,
            request_tty,
            no_login_shell,
            cols,
            rows,
            completion,
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

    let sandbox = resolve_and_authorize_sandbox_name(
        state,
        &principal,
        &init.sandbox,
        &init.workspace,
        MinWorkspaceRole::User,
    )
    .await?;

    // The main process may finish between minting the SSH token and opening
    // its transport. Keep the relay reachable until terminal delivery is
    // finalized so fast commands can attach without a readiness race.
    if !sandbox_relay_reachable(state, &sandbox) {
        return Err(Status::failed_precondition("sandbox is not ready"));
    }

    let connection_guard =
        acquire_forward_connection_guard(state, &principal, &init, &sandbox).await?;
    let (channel_id, relay_rx) = crate::supervisor_session::open_routed_relay_with_target(
        state,
        sandbox.object_id(),
        target,
        init.service_id.clone(),
        std::time::Duration::from_secs(15),
    )
    .await
    .map_err(|e| Status::unavailable(format!("supervisor relay failed: {e}")))?;

    let (tx, rx) = mpsc::channel::<Result<TcpForwardFrame, Status>>(256);
    let sandbox_id = sandbox.object_id().to_string();
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

/// The per-sandbox relay budget a forward stream draws from. SSH relays and
/// service forwards are counted apart so open forwards cannot starve SSH.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelayBudget {
    Ssh,
    Service,
}

impl RelayBudget {
    fn of(init: &TcpForwardInit) -> Self {
        match init.target {
            Some(tcp_forward_init::Target::Tcp(_)) => Self::Service,
            _ => Self::Ssh,
        }
    }

    fn counts(self, state: &ServerState) -> &std::sync::Mutex<HashMap<String, u32>> {
        match self {
            Self::Ssh => &state.ssh_connections_by_sandbox,
            Self::Service => &state.service_connections_by_sandbox,
        }
    }

    fn limit(self, config: &openshell_core::Config) -> u32 {
        match self {
            Self::Ssh => config.max_ssh_connections_per_sandbox,
            Self::Service => config.max_service_connections_per_sandbox,
        }
    }

    const fn exhausted_message(self) -> &'static str {
        match self {
            Self::Ssh => "sandbox SSH connection limit reached",
            Self::Service => "sandbox service forward connection limit reached",
        }
    }
}

struct ForwardConnectionGuard {
    state: Arc<ServerState>,
    token: Option<String>,
    budget: RelayBudget,
    sandbox_id: String,
}

impl Drop for ForwardConnectionGuard {
    fn drop(&mut self) {
        if let Some(token) = self.token.as_deref() {
            decrement_ssh_connection_count(&self.state.ssh_connections_by_token, token);
        }
        decrement_ssh_connection_count(self.budget.counts(&self.state), &self.sandbox_id);
    }
}

/// Reserve a relay slot for one `ForwardTcp` stream.
///
/// `target.tcp` streams are authorized by the caller's gateway principal, which
/// `handle_forward_tcp` has already checked against the sandbox's workspace, so
/// they carry no session token and touch no store: the only per-connection
/// state is the in-memory per-sandbox connection count, kept in a budget apart
/// from SSH relays (see [`RelayBudget`]). `target.ssh` streams
/// keep requiring the `CreateSshSession` token because the process that opens
/// them is an ssh `ProxyCommand` that holds nothing else. A token supplied with
/// a TCP target (older clients) is still validated and counted per token.
async fn acquire_forward_connection_guard(
    state: &Arc<ServerState>,
    principal: &crate::auth::principal::Principal,
    init: &TcpForwardInit,
    sandbox: &Sandbox,
) -> Result<ForwardConnectionGuard, Status> {
    let sandbox_id = sandbox.object_id().to_string();
    let budget = RelayBudget::of(init);
    let token = init.authorization_token.trim();
    if token.is_empty() {
        if budget == RelayBudget::Ssh {
            return Err(crate::auth::audit::reject_credential(
                Some(principal),
                AuthRejection::new(
                    AuthMechanism::SshSessionToken,
                    AuthFailureReason::MissingCredential,
                    Status::unauthenticated("authorization_token is required for SSH targets"),
                ),
            ));
        }
        acquire_sandbox_connection_slot(state, budget, &sandbox_id)?;
        return Ok(ForwardConnectionGuard {
            state: state.clone(),
            token: None,
            budget,
            sandbox_id,
        });
    }

    validate_ssh_forward_token(state, token, &sandbox_id)
        .await
        .map_err(|rejection| crate::auth::audit::reject_credential(Some(principal), rejection))?;
    crate::auth::audit::emit_ssh_session_logon(&state.logons, principal, token);
    acquire_ssh_connection_slots(state, budget, token, &sandbox_id)?;

    Ok(ForwardConnectionGuard {
        state: state.clone(),
        token: Some(token.to_string()),
        budget,
        sandbox_id,
    })
}

#[allow(clippy::result_large_err)]
async fn validate_ssh_forward_token(
    state: &Arc<ServerState>,
    token: &str,
    sandbox_id: &str,
) -> Result<(), AuthRejection> {
    let reject =
        |reason, status| AuthRejection::new(AuthMechanism::SshSessionToken, reason, status);
    let session = state
        .store
        .get_message::<SshSession>(token)
        .await
        .map_err(|e| {
            reject(
                AuthFailureReason::IdentityProviderUnavailable,
                Status::internal(format!("fetch SSH session failed: {e}")),
            )
        })?
        .ok_or_else(|| {
            reject(
                AuthFailureReason::InvalidCredential,
                Status::unauthenticated("SSH session token not found"),
            )
        })?;

    if session.revoked || session.sandbox_id != sandbox_id {
        // A token minted for another sandbox was issued for a different party.
        let reason = if session.revoked {
            AuthFailureReason::InvalidCredential
        } else {
            AuthFailureReason::AudienceOrIssuerMismatch
        };
        return Err(reject(
            reason,
            Status::unauthenticated("SSH session token is not valid"),
        ));
    }

    if let Some(expiration_time) = session.expiration_time.as_ref() {
        let now_ms = current_time_ms();
        let expires_at_ms =
            openshell_core::time::timestamp_to_millis(expiration_time).map_err(|error| {
                reject(
                    AuthFailureReason::IdentityProviderUnavailable,
                    Status::internal(error.to_string()),
                )
            })?;
        if now_ms > expires_at_ms {
            return Err(reject(
                AuthFailureReason::ExpiredCredential,
                Status::unauthenticated("SSH session token expired"),
            ));
        }
    }

    Ok(())
}

const MAX_CONNECTIONS_PER_TOKEN: u32 = 3;

fn acquire_ssh_connection_slots(
    state: &ServerState,
    budget: RelayBudget,
    token: &str,
    sandbox_id: &str,
) -> Result<(), Status> {
    {
        let mut counts = state.ssh_connections_by_token.lock().unwrap();
        let count = counts.entry(token.to_string()).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_TOKEN {
            return Err(Status::resource_exhausted(
                "SSH session connection limit reached",
            ));
        }
        *count += 1;
    }

    if let Err(status) = acquire_sandbox_connection_slot(state, budget, sandbox_id) {
        decrement_ssh_connection_count(&state.ssh_connections_by_token, token);
        return Err(status);
    }

    Ok(())
}

/// Reserve one of the sandbox's relay slots in the given budget.
fn acquire_sandbox_connection_slot(
    state: &ServerState,
    budget: RelayBudget,
    sandbox_id: &str,
) -> Result<(), Status> {
    let mut counts = budget.counts(state).lock().unwrap();
    let count = counts.entry(sandbox_id.to_string()).or_insert(0);
    if *count >= budget.limit(&state.config) {
        return Err(Status::resource_exhausted(budget.exhausted_message()));
    }
    *count += 1;
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

async fn bridge_forward_tcp_stream<S>(
    mut inbound: tonic::Streaming<TcpForwardFrame>,
    relay_stream: S,
    tx: mpsc::Sender<Result<TcpForwardFrame, Status>>,
    sandbox_id: &str,
    channel_id: &str,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
{
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

pub(super) fn validate_exec_start(req: &ExecSandboxRequest) -> Result<(), Status> {
    use openshell_core::rpc_error;
    if req.sandbox.is_empty() {
        return Err(rpc_error::invalid_argument(
            "sandbox",
            "sandbox is required",
        ));
    }
    if req.command.is_empty() {
        return Err(rpc_error::invalid_argument(
            "command",
            "command is required",
        ));
    }
    if req.environment.keys().any(|key| !is_valid_env_key(key)) {
        return Err(rpc_error::invalid_argument(
            "environment",
            "environment keys must match ^[A-Za-z_][A-Za-z0-9_]*$",
        ));
    }
    validate_exec_request_fields(req)
}

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

    validate_exec_start(&req)?;

    Ok(req)
}

pub(super) async fn handle_exec_sandbox_interactive(
    state: &Arc<ServerState>,
    request: Request<tonic::Streaming<ExecSandboxInput>>,
) -> Result<Response<ReceiverStream<Result<ExecSandboxEvent, Status>>>, Status> {
    let (metadata, extensions, mut input_stream) = request.into_parts();

    let first_msg = input_stream
        .message()
        .await
        .map_err(|e| Status::internal(format!("failed to read first message: {e}")))?;

    let req = validate_interactive_exec_start(first_msg)?;

    let mut request = Request::from_parts(
        metadata,
        extensions,
        ExecSandboxInput {
            payload: Some(openshell_core::proto::exec_sandbox_input::Payload::Start(
                req,
            )),
        },
    );
    request
        .extensions_mut()
        .insert(super::mutation_replay::streaming::InteractiveInput(
            Arc::new(tokio::sync::Mutex::new(Some(input_stream))),
        ));
    super::mutation_replay::run(state, request).await
}

pub(super) async fn handle_exec_sandbox_interactive_start(
    state: &Arc<ServerState>,
    request: Request<ExecSandboxInput>,
) -> Result<Response<ReceiverStream<Result<ExecSandboxEvent, Status>>>, Status> {
    let principal = super::extract_principal(&request)?;
    let completion = request
        .extensions()
        .get::<super::mutation_replay::Completion>()
        .cloned();
    let input = request
        .extensions()
        .get::<super::mutation_replay::streaming::InteractiveInput>()
        .ok_or_else(|| Status::internal("interactive input handoff missing"))?
        .clone();
    let input_stream = input
        .0
        .lock()
        .await
        .take()
        .ok_or_else(|| Status::internal("interactive input already claimed"))?;
    let req = super::mutation_replay::streaming::start(request.get_ref())?;
    validate_exec_start(req)?;

    let sandbox = resolve_and_authorize_sandbox_name(
        state,
        &principal,
        &req.sandbox,
        crate::auth::workspace_authz::selected_workspace_name(req.workspace_scope.as_ref())?,
        MinWorkspaceRole::User,
    )
    .await?;

    if let Some(completion) = &completion {
        completion.ensure_target(sandbox.object_id())?;
    }

    require_ready_sandbox(&sandbox)?;

    let (channel_id, relay_rx) = crate::supervisor_session::open_routed_relay_with_target(
        state,
        sandbox.object_id(),
        relay_open::Target::Ssh(SshRelayTarget {}),
        String::new(),
        std::time::Duration::from_secs(15),
    )
    .await
    .map_err(|e| Status::unavailable(format!("supervisor relay failed: {e}")))?;

    let command_str = build_remote_exec_command(req)
        .map_err(|e| Status::invalid_argument(format!("command construction failed: {e}")))?;
    let request_tty = req.tty;
    let no_login_shell = req.no_login_shell;
    let execution_timeout = req
        .execution_timeout
        .as_ref()
        .map(openshell_core::time::duration_to_std)
        .transpose()
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
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
            execution_timeout,
            cols,
            rows,
            completion,
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
            && state.supervisor_sessions.has_session(sandbox.object_id()))
}

pub(super) async fn handle_create_ssh_session(
    state: &Arc<ServerState>,
    request: Request<CreateSshSessionRequest>,
) -> Result<Response<CreateSshSessionResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    let sandbox = resolve_and_authorize_sandbox_name(
        state,
        &principal,
        &req.sandbox,
        crate::auth::workspace_authz::selected_workspace_name(req.workspace_scope.as_ref())?,
        MinWorkspaceRole::User,
    )
    .await?;
    let sandbox_id = sandbox.object_id().to_string();

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
            created_time: openshell_core::time::timestamp_from_millis(now_ms).ok(),
            labels: HashMap::new(),
            resource_version: 0,
            annotations: HashMap::new(),
            workspace: sandbox.object_workspace().to_string(),
            deletion_time: None,
        }),
        sandbox_id: sandbox_id.clone(),
        token: token.clone(),
        revoked: false,
        expiration_time: openshell_core::time::optional_timestamp_from_legacy_millis(expires_at_ms)
            .map_err(|error| Status::internal(error.to_string()))?,
    };

    // Ensure metadata is valid (defense in depth - should always be true for server-constructed metadata)
    super::validation::validate_object_metadata(session.metadata.as_ref(), "ssh_session")?;

    // `create_relaxed` fails if the token already exists, like MustCreate, but
    // skips the per-commit fsync on SQLite. Losing a freshly minted token in a
    // crash only makes it invalid; revocation stays on the durable `put_if`.
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
        .create_relaxed(
            SshSession::object_type(),
            &token,
            session.object_name(),
            session.object_workspace(),
            &session.encode_to_vec(),
            session_labels_json.as_deref(),
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
        sandbox_id,
        token,
        gateway_host,
        gateway_port: gateway_port.into(),
        gateway_scheme: scheme.to_string(),
        host_key_fingerprint: sandbox.host_key_fingerprint.clone(),
        expiration_time: openshell_core::time::optional_timestamp_from_legacy_millis(expires_at_ms)
            .map_err(|error| Status::internal(error.to_string()))?,
    }))
}

pub(super) async fn handle_revoke_ssh_session(
    state: &Arc<ServerState>,
    request: Request<RevokeSshSessionRequest>,
) -> Result<Response<RevokeSshSessionResponse>, Status> {
    let principal = super::extract_principal(&request)?;
    let req = request.into_inner();
    let token = req.token;
    if token.is_empty() {
        return Err(Status::invalid_argument("token is required"));
    }

    let session = state
        .store
        .get_message::<SshSession>(&token)
        .await
        .map_err(|e| Status::internal(format!("fetch ssh session failed: {e}")))?;

    let Some(mut session) = session else {
        return Ok(Response::new(RevokeSshSessionResponse {
            outcome: super::deletion_outcome(false, req.allow_missing, "ssh session")?,
        }));
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

    if session.revoked {
        return Ok(Response::new(RevokeSshSessionResponse {
            outcome: openshell_core::proto::DeletionOutcome::Completed.into(),
        }));
    }

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

    Ok(Response::new(RevokeSshSessionResponse {
        outcome: openshell_core::proto::DeletionOutcome::Completed.into(),
    }))
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

/// Require both the command status and channel close before reporting success.
fn exec_loop_result(exit_code: Option<i32>, close_seen: bool) -> Result<i32, Status> {
    match (exit_code, close_seen) {
        (Some(code), true) => Ok(code),
        (None, _) => Err(Status::unavailable(
            "exec relay closed before the command reported an exit status",
        )),
        (Some(_), false) => Err(Status::unavailable(
            "exec relay closed before the SSH channel finished",
        )),
    }
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
    execution_timeout: Option<std::time::Duration>,
    request_tty: bool,
    no_login_shell: bool,
    cols: u32,
    rows: u32,
    completion: Option<super::mutation_replay::Completion>,
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

    let exec_result = wait_for_exec_terminal(exec, execution_timeout, completion).await;
    if matches!(exec_result, Ok(None)) {
        let _ = tx
            .send(Ok(ExecSandboxEvent {
                payload: Some(openshell_core::proto::exec_sandbox_event::Payload::Exit(
                    ExecSandboxExit { exit_code: 124 },
                )),
            }))
            .await;
        finish_interactive_exec_proxy(proxy_task).await;
        return Ok(());
    }

    let exit_code = match exec_result {
        Ok(Some(code)) => code,
        Ok(None) => unreachable!("timeout returned above"),
        Err(status) => {
            finish_interactive_exec_proxy(proxy_task).await;
            return Err(status);
        }
    };

    finish_interactive_exec_proxy(proxy_task).await;

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
    execution_timeout: Option<std::time::Duration>,
    cols: u32,
    rows: u32,
    completion: Option<super::mutation_replay::Completion>,
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

    let exec_result = wait_for_exec_terminal(exec, execution_timeout, completion).await;
    if matches!(exec_result, Ok(None)) {
        let _ = tx
            .send(Ok(ExecSandboxEvent {
                payload: Some(openshell_core::proto::exec_sandbox_event::Payload::Exit(
                    ExecSandboxExit { exit_code: 124 },
                )),
            }))
            .await;
        finish_interactive_exec_proxy(proxy_task).await;
        return Ok(());
    }

    let exit_code = match exec_result {
        Ok(Some(code)) => code,
        Ok(None) => unreachable!("timeout returned above"),
        Err(status) => {
            finish_interactive_exec_proxy(proxy_task).await;
            return Err(status);
        }
    };

    finish_interactive_exec_proxy(proxy_task).await;

    let _ = tx
        .send(Ok(ExecSandboxEvent {
            payload: Some(openshell_core::proto::exec_sandbox_event::Payload::Exit(
                ExecSandboxExit { exit_code },
            )),
        }))
        .await;

    Ok(())
}

/// `Ok(Some(code))` requires a real SSH `ExitStatus`, including nonzero codes.
/// Synthetic gateway timeouts, lost status, and dropped futures leave the claim
/// unresolved. Finalization precedes terminal delivery to the client.
pub(super) async fn wait_for_exec_terminal(
    exec: impl Future<Output = Result<i32, Status>>,
    execution_timeout: Option<std::time::Duration>,
    completion: Option<super::mutation_replay::Completion>,
) -> Result<Option<i32>, Status> {
    let result = if let Some(execution_timeout) = execution_timeout {
        match tokio::time::timeout(execution_timeout, exec).await {
            Ok(result) => result,
            Err(_) => return Ok(None),
        }
    } else {
        exec.await
    };
    let exit_code = result?;
    if let Some(completion) = completion {
        completion.stream_terminal().await?;
    }
    Ok(Some(exit_code))
}

async fn finish_interactive_exec_proxy(mut task: tokio::task::JoinHandle<()>) {
    if tokio::time::timeout(EXEC_POST_EXIT_CLOSE_TIMEOUT, &mut task)
        .await
        .is_err()
    {
        task.abort();
        let _ = task.await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_interactive_exec_with_russh(
    local_proxy_port: u16,
    command: &str,
    mut input_stream: impl futures::Stream<Item = Result<ExecSandboxInput, Status>> + Unpin,
    request_tty: bool,
    no_login_shell: bool,
    cols: u32,
    rows: u32,
    tx: mpsc::Sender<Result<ExecSandboxEvent, Status>>,
) -> Result<i32, Status> {
    use futures::StreamExt;
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

    let stream =
        openshell_core::net::connect_tcp_nodelay_best_effort(("127.0.0.1", local_proxy_port))
            .await
            .map_err(|e| Status::internal(format!("failed to connect to ssh proxy: {e}")))?;

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

    // Keep both directions independently polled, but owned by this operation.
    // A detached stdin task would survive operation timeout and retain the SSH
    // channel. Normal request EOF closes stdin only, never the output channel.
    let input = async {
        while let Some(msg) = input_stream.next().await {
            // Even ignored non-PTY resize frames must cooperate with output
            // and cancellation when the request stream stays continuously ready.
            tokio::task::consume_budget().await;
            let msg = msg?;
            match msg.payload {
                Some(Payload::Stdin(data)) => {
                    write_half
                        .data(std::io::Cursor::new(data))
                        .await
                        .map_err(|_| {
                            Status::unavailable("exec relay failed while writing stdin")
                        })?;
                }
                Some(Payload::Resize(resize)) => {
                    if request_tty {
                        write_half
                            .window_change(resize.cols, resize.rows, 0, 0)
                            .await
                            .map_err(|_| Status::unavailable("exec relay failed while resizing"))?;
                    }
                }
                Some(Payload::Start(_)) | None => {
                    return Err(Status::invalid_argument(
                        "expected stdin or resize after exec start",
                    ));
                }
            }
        }
        write_half
            .eof()
            .await
            .map_err(|_| Status::unavailable("exec relay failed while closing stdin"))
    };

    let output = async {
        let mut exit_code: Option<i32> = None;
        let mut close_seen = false;
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
                ChannelMsg::Close => {
                    close_seen = true;
                    break;
                }
                _ => {}
            }
        }

        exec_loop_result(exit_code, close_seen)
    };

    let result = {
        tokio::pin!(input, output);
        let exchange = async {
            tokio::select! {
                result = &mut input => {
                    result?;
                    output.await
                }
                result = &mut output => result,
            }
        };
        tokio::select! {
            biased;
            () = tx.closed() => Err(Status::cancelled("exec response stream closed")),
            result = exchange => result,
        }
    };

    // EOF above deliberately leaves this channel open until output completes.
    // Bound cleanup even if the SSH peer is no longer making progress.
    let _ = tokio::time::timeout(EXEC_POST_EXIT_CLOSE_TIMEOUT, write_half.close()).await;
    let _ = tokio::time::timeout(
        EXEC_POST_EXIT_CLOSE_TIMEOUT,
        client.disconnect(russh::Disconnect::ByApplication, "exec complete", "en"),
    )
    .await;

    result
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
        _server_public_key: &russh::keys::PublicKeyOrCertificate,
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

    let stream =
        openshell_core::net::connect_tcp_nodelay_best_effort(("127.0.0.1", local_proxy_port))
            .await
            .map_err(|e| Status::internal(format!("failed to connect to ssh proxy: {e}")))?;

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
    let mut close_seen = false;
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
            ChannelMsg::Close => {
                close_seen = true;
                break;
            }
            _ => {}
        }
    }

    let _ = channel.close().await;
    let _ = client
        .disconnect(russh::Disconnect::ByApplication, "exec complete", "en")
        .await;

    exec_loop_result(exit_code, close_seen)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::audit::test_support::{
        assert_authentication_failure, assert_boundary_finding, assert_logon, assert_origin,
        assert_redacted, audited,
    };
    use crate::compute::NoopTestDriver;

    #[test]
    fn exec_requires_ssh_channel_close_after_exit_status() {
        assert_eq!(exec_loop_result(Some(0), true).unwrap(), 0);
        assert!(exec_loop_result(Some(0), false).is_err());
        assert!(exec_loop_result(None, true).is_err());
    }
    use crate::grpc::test_support::{
        authed_request, test_server_state, test_server_state_with_compute_driver,
        test_server_state_with_driver,
    };
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{
        GpuResourceRequirements, SandboxServiceExposure, ServiceAuthorizationMode, ServiceEndpoint,
    };

    #[tokio::test]
    async fn missing_launch_signer_precedes_driver_validation_and_preserves_staged_archive() {
        let directory = tempfile::tempdir().unwrap();
        let mut state = test_server_state().await;
        let mut metadata = openshell_core::extension_protocol::extension_metadata(
            openshell_core::extension_protocol::ExtensionFamily::Compute,
            "test/launch-authentication",
            "test",
            [],
        );
        metadata
            .required_capabilities
            .push(openshell_core::extension_protocol::COMPUTE_LAUNCH_AUTHENTICATION.to_string());
        let admission = openshell_core::resource_admission::DriverAdmissionConfig {
            allow_driver_config: true,
            ..Default::default()
        };
        let driver = Arc::new(
            crate::test_support::FakeComputeDriver::new().with_capabilities(
                openshell_core::proto::compute::v1::GetCapabilitiesResponse {
                    driver_name: "test".to_string(),
                    default_image: "test/image:latest".to_string(),
                    rootfs_tar_staging_dir: directory.path().to_string_lossy().into_owned(),
                    rootfs_tar_max_bytes: 1024,
                    resource_admission_policy: admission.acknowledgement(),
                    extension: Some(metadata),
                    ..Default::default()
                },
            ),
        );
        let compute = crate::compute::ComputeRuntime::from_driver(
            "test".to_string(),
            driver.clone(),
            None,
            state.store.clone(),
            crate::sandbox_index::SandboxIndex::new(),
            crate::sandbox_watch::SandboxWatchBus::new(),
            crate::tracing_bus::TracingLogBus::new(),
            Arc::new(crate::supervisor_session::SupervisorSessionRegistry::new()),
        )
        .await
        .unwrap()
        .with_admission_policy(admission)
        .unwrap();
        Arc::get_mut(&mut state).unwrap().compute = compute;
        let staging = state.compute.rootfs_tar_staging();
        let slot = staging
            .begin("default", "dev-user", "rootfs.tar", 7)
            .unwrap();
        std::fs::write(&slot.upload_path, b"archive").unwrap();
        let driver_config = Struct {
            fields: std::iter::once((
                "test".to_string(),
                Value {
                    kind: Some(Kind::StructValue(Struct {
                        fields: std::iter::once((
                            crate::compute::rootfs_tar::STAGING_TOKEN_FIELD.to_string(),
                            Value {
                                kind: Some(Kind::StringValue(slot.token.clone())),
                            },
                        ))
                        .collect(),
                    })),
                },
            ))
            .collect(),
        };
        driver.clear_calls();
        let error = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                name: "missing-signer".to_string(),
                spec: Some(SandboxSpec {
                    template: Some(SandboxTemplate {
                        driver_config: Some(driver_config),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("sandbox launch signing"));
        assert!(
            driver.calls().is_empty(),
            "driver validation must not precede signing preflight"
        );
        assert_eq!(
            staging.peek(&slot.token).unwrap(),
            std::path::PathBuf::from(&slot.upload_path)
        );
        assert_eq!(std::fs::read(&slot.upload_path).unwrap(), b"archive");
        assert!(
            state
                .store
                .get_message_by_name::<Sandbox>("default", "missing-signer")
                .await
                .unwrap()
                .is_none()
        );
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
            SandboxPhase::Suspended,
            SandboxPhase::Error,
        ] {
            assert!(is_watch_terminal(phase), "{phase:?} should stop the watch");
        }
        for phase in [
            SandboxPhase::Provisioning,
            SandboxPhase::Starting,
            SandboxPhase::Stopping,
            SandboxPhase::Suspending,
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
            request_id: String::new(),
            spec: Some(SandboxSpec {
                providers: vec!["github".to_string()],
                policy: Some(openshell_core::proto::SandboxPolicy::default()),
                ..SandboxSpec::default()
            }),
            workload_template: "gpu-kata".to_string(),
            workspace_scope: Some(openshell_core::proto::workspace_selector(
                "default".to_string(),
            )),
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
            request_id: String::new(),
            spec: Some(SandboxSpec {
                providers: vec!["github".to_string()],
                ..SandboxSpec::default()
            }),
            workload_template: "missing-template".to_string(),
            workspace_scope: Some(openshell_core::proto::workspace_selector(
                "default".to_string(),
            )),
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
            sandbox: "test".to_string(),
            workspace_scope: None,
            command: vec!["ls".to_string(), "-la".to_string()],
            ..Default::default()
        };
        assert_eq!(build_remote_exec_command(&req).unwrap(), "ls -la");
    }

    #[test]
    fn build_remote_exec_command_with_env_and_workdir() {
        use openshell_core::proto::ExecSandboxRequest;
        let req = ExecSandboxRequest {
            sandbox: "test".to_string(),
            workspace_scope: None,
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
            sandbox: "test".to_string(),
            workspace_scope: None,
            command: vec!["echo".to_string(), "hello\x00world".to_string()],
            ..Default::default()
        };
        assert!(build_remote_exec_command(&req).is_err());
    }

    #[test]
    fn build_remote_exec_command_rejects_newlines_in_workdir() {
        use openshell_core::proto::ExecSandboxRequest;
        let req = ExecSandboxRequest {
            sandbox: "test".to_string(),
            workspace_scope: None,
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
            sandbox: "test".to_string(),
            workspace_scope: None,
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
            sandbox: "test".to_string(),
            workspace_scope: None,
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

    fn forward_init(target: tcp_forward_init::Target, token: &str) -> TcpForwardInit {
        TcpForwardInit {
            sandbox: "sbx".to_string(),
            workspace: String::new(),
            service_id: String::new(),
            target: Some(target),
            authorization_token: token.to_string(),
        }
    }

    fn loopback_tcp_target() -> tcp_forward_init::Target {
        tcp_forward_init::Target::Tcp(TcpRelayTarget {
            host: "127.0.0.1".to_string(),
            port: 8080,
        })
    }

    fn sandbox_connection_count(state: &ServerState, budget: RelayBudget, sandbox_id: &str) -> u32 {
        budget
            .counts(state)
            .lock()
            .unwrap()
            .get(sandbox_id)
            .copied()
            .unwrap_or(0)
    }

    #[tokio::test]
    async fn tcp_forward_without_token_is_admitted_on_the_principal_alone() {
        let state = test_server_state().await;
        let sandbox = test_sandbox("fwd", Vec::new());

        let guard = acquire_forward_connection_guard(
            &state,
            &forward_caller(),
            &forward_init(loopback_tcp_target(), ""),
            &sandbox,
        )
        .await
        .expect("tcp forward without a session token");

        assert!(
            guard.token.is_none(),
            "no per-token accounting without a token"
        );
        assert!(state.ssh_connections_by_token.lock().unwrap().is_empty());
        assert_eq!(
            sandbox_connection_count(&state, RelayBudget::Service, sandbox.object_id()),
            1
        );
        drop(guard);
        assert_eq!(
            sandbox_connection_count(&state, RelayBudget::Service, sandbox.object_id()),
            0,
            "dropping the guard releases the sandbox slot"
        );
    }

    const FORWARD_TCP_PATH: &str = "/openshell.v1.OpenShell/ForwardTcp";

    fn forward_caller() -> crate::auth::principal::Principal {
        authed_request(())
            .extensions_mut()
            .remove::<crate::auth::principal::Principal>()
            .expect("dev principal")
    }

    /// Acquire a forward slot inside a routed `ForwardTcp` request, returning
    /// the result and the OCSF events it emitted.
    async fn acquire_audited(
        state: &Arc<ServerState>,
        init: &TcpForwardInit,
        sandbox: &Sandbox,
    ) -> (
        Result<ForwardConnectionGuard, Status>,
        Vec<serde_json::Value>,
    ) {
        audited(
            FORWARD_TCP_PATH,
            acquire_forward_connection_guard(state, &forward_caller(), init, sandbox),
        )
        .await
    }

    async fn store_ssh_session(
        state: &ServerState,
        token: &str,
        sandbox_id: &str,
        revoked: bool,
        expires_at_ms: i64,
    ) {
        let session = SshSession {
            metadata: Some(ObjectMeta {
                id: token.to_string(),
                name: format!("session-{token}"),
                created_time: None,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_time: None,
            }),
            sandbox_id: sandbox_id.to_string(),
            token: token.to_string(),
            revoked,
            expiration_time: openshell_core::time::optional_timestamp_from_legacy_millis(
                expires_at_ms,
            )
            .unwrap(),
        };
        state.store.put_message(&session).await.unwrap();
    }

    /// Assert `events` is one SSH session token failure for `reason` that
    /// never mentions `token`.
    fn assert_ssh_token_failure(events: &[serde_json::Value], reason: &str, token: &str) {
        assert_eq!(events.len(), 1, "{events:?}");
        let event = &events[0];
        assert_authentication_failure(event, FORWARD_TCP_PATH, reason);
        assert_eq!(event["auth_protocol"], "ssh_session_token");
        assert_eq!(event["user"]["uid"], "dev-user");
        assert_origin(event);
        if !token.is_empty() {
            assert_redacted(event, token);
        }
    }

    #[tokio::test]
    async fn ssh_forward_without_token_is_rejected() {
        let state = test_server_state().await;
        let sandbox = test_sandbox("fwd", Vec::new());

        let (result, events) = acquire_audited(
            &state,
            &forward_init(tcp_forward_init::Target::Ssh(SshRelayTarget::default()), ""),
            &sandbox,
        )
        .await;
        let err = result
            .err()
            .expect("ssh targets keep requiring the session token");

        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert_eq!(
            err.message(),
            "authorization_token is required for SSH targets"
        );
        assert_eq!(
            sandbox_connection_count(&state, RelayBudget::Ssh, sandbox.object_id()),
            0
        );
        assert_ssh_token_failure(&events, "missing_credential", "");
    }

    #[tokio::test]
    async fn tcp_forward_with_unknown_token_is_still_rejected() {
        let state = test_server_state().await;
        let sandbox = test_sandbox("fwd", Vec::new());

        let (result, events) = acquire_audited(
            &state,
            &forward_init(loopback_tcp_target(), "canary-ssh-token-unknown"),
            &sandbox,
        )
        .await;
        let err = result.err().expect("a supplied token is always validated");

        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert_eq!(err.message(), "SSH session token not found");
        assert_eq!(
            sandbox_connection_count(&state, RelayBudget::Service, sandbox.object_id()),
            0
        );
        assert_ssh_token_failure(&events, "invalid_credential", "canary-ssh-token-unknown");
    }

    #[tokio::test]
    async fn rejected_ssh_session_tokens_name_their_reason() {
        let state = test_server_state().await;
        let sandbox = test_sandbox("fwd", Vec::new());
        let future_ms = current_time_ms() + 60_000;
        store_ssh_session(
            &state,
            "canary-ssh-token-revoked",
            "sandbox-fwd",
            true,
            future_ms,
        )
        .await;
        store_ssh_session(
            &state,
            "canary-ssh-token-other",
            "sandbox-other",
            false,
            future_ms,
        )
        .await;
        store_ssh_session(
            &state,
            "canary-ssh-token-expired",
            "sandbox-fwd",
            false,
            1_000,
        )
        .await;

        for (token, message, reason) in [
            (
                "canary-ssh-token-revoked",
                "SSH session token is not valid",
                "invalid_credential",
            ),
            (
                "canary-ssh-token-other",
                "SSH session token is not valid",
                "audience_or_issuer_mismatch",
            ),
            (
                "canary-ssh-token-expired",
                "SSH session token expired",
                "expired_credential",
            ),
        ] {
            let (result, events) = acquire_audited(
                &state,
                &forward_init(
                    tcp_forward_init::Target::Ssh(SshRelayTarget::default()),
                    token,
                ),
                &sandbox,
            )
            .await;
            let err = result.err().expect(token);

            assert_eq!(err.code(), tonic::Code::Unauthenticated, "{token}");
            assert_eq!(err.message(), message, "{token}");
            assert_ssh_token_failure(&events, reason, token);
        }
    }

    #[tokio::test]
    async fn session_token_on_a_tcp_target_logs_on() {
        let state = test_server_state().await;
        let sandbox = test_sandbox("fwd", Vec::new());
        store_ssh_session(&state, "canary-ssh-token-tcp", "sandbox-fwd", false, 0).await;

        let (result, events) = acquire_audited(
            &state,
            &forward_init(loopback_tcp_target(), "canary-ssh-token-tcp"),
            &sandbox,
        )
        .await;
        result.expect("older clients still send a session token");

        assert_eq!(events.len(), 1, "{events:?}");
        assert_logon(&events[0], FORWARD_TCP_PATH);
        assert_eq!(events[0]["auth_protocol"], "ssh_session_token");
        assert_redacted(&events[0], "canary-ssh-token");
    }

    #[tokio::test]
    async fn ssh_session_token_logs_on_once() {
        let state = test_server_state().await;
        let sandbox = test_sandbox("fwd", Vec::new());
        store_ssh_session(&state, "canary-ssh-token-valid", "sandbox-fwd", false, 0).await;
        let init = forward_init(
            tcp_forward_init::Target::Ssh(SshRelayTarget::default()),
            "canary-ssh-token-valid",
        );

        let (first, events) = acquire_audited(&state, &init, &sandbox).await;
        let (second, repeated) = acquire_audited(&state, &init, &sandbox).await;
        first.expect("valid session token");
        second.expect("valid session token");

        assert!(repeated.is_empty(), "{repeated:?}");
        assert_eq!(events.len(), 1, "{events:?}");
        let event = &events[0];
        assert_logon(event, FORWARD_TCP_PATH);
        assert_eq!(event["auth_protocol"], "ssh_session_token");
        assert_eq!(event["user"]["uid"], "dev-user");
        assert_origin(event);
        assert_redacted(event, "canary-ssh-token");
    }

    #[tokio::test]
    async fn tcp_forwards_are_capped_per_sandbox() {
        let state = test_server_state().await;
        let sandbox = test_sandbox("fwd", Vec::new());
        let init = forward_init(loopback_tcp_target(), "");
        let cap = openshell_core::config::DEFAULT_MAX_CONNECTIONS_PER_SANDBOX;

        let mut guards = Vec::new();
        for _ in 0..cap {
            guards.push(
                acquire_forward_connection_guard(&state, &forward_caller(), &init, &sandbox)
                    .await
                    .expect("within the per-sandbox cap"),
            );
        }
        let err = acquire_forward_connection_guard(&state, &forward_caller(), &init, &sandbox)
            .await
            .err()
            .expect("cap reached");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert_eq!(
            err.message(),
            "sandbox service forward connection limit reached"
        );
        assert_eq!(
            sandbox_connection_count(&state, RelayBudget::Service, sandbox.object_id()),
            cap
        );

        guards.pop();
        let guard = acquire_forward_connection_guard(&state, &forward_caller(), &init, &sandbox)
            .await
            .expect("slot freed by a closed connection");
        drop(guard);
        drop(guards);
        assert_eq!(
            sandbox_connection_count(&state, RelayBudget::Service, sandbox.object_id()),
            0
        );
    }

    #[tokio::test]
    async fn ssh_and_service_budgets_are_independent() {
        let mut state = test_server_state().await;
        {
            let config = &mut Arc::get_mut(&mut state).expect("sole state owner").config;
            config.max_ssh_connections_per_sandbox = 1;
            config.max_service_connections_per_sandbox = 2;
        }
        let sandbox = test_sandbox("fwd", Vec::new());
        store_ssh_session(&state, "canary-ssh-token-a", "sandbox-fwd", false, 0).await;
        store_ssh_session(&state, "canary-ssh-token-b", "sandbox-fwd", false, 0).await;
        let tcp = forward_init(loopback_tcp_target(), "");
        let ssh = |token: &str| {
            forward_init(
                tcp_forward_init::Target::Ssh(SshRelayTarget::default()),
                token,
            )
        };
        let acquire = |init: TcpForwardInit| {
            let state = state.clone();
            let sandbox = sandbox.clone();
            async move {
                acquire_forward_connection_guard(&state, &forward_caller(), &init, &sandbox).await
            }
        };

        let _forwards = [
            acquire(tcp.clone()).await.expect("first forward"),
            acquire(tcp.clone()).await.expect("second forward"),
        ];
        let err = acquire(tcp).await.err().expect("forward budget spent");
        assert_eq!(
            err.message(),
            "sandbox service forward connection limit reached"
        );

        let _ssh = acquire(ssh("canary-ssh-token-a"))
            .await
            .expect("open forwards leave the SSH budget alone");
        let err = acquire(ssh("canary-ssh-token-b"))
            .await
            .err()
            .expect("SSH budget spent");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert_eq!(err.message(), "sandbox SSH connection limit reached");
        assert_eq!(
            sandbox_connection_count(&state, RelayBudget::Ssh, sandbox.object_id()),
            1
        );
        assert_eq!(
            sandbox_connection_count(&state, RelayBudget::Service, sandbox.object_id()),
            2
        );
    }

    #[test]
    fn tcp_forward_init_allows_loopback_targets() {
        for host in ["127.0.0.1", "::1", "localhost"] {
            let init = TcpForwardInit {
                sandbox: "sbx".to_string(),
                workspace: String::new(),
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
            sandbox: "sbx".to_string(),
            workspace: String::new(),
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
            sandbox: "sbx".to_string(),
            workspace: String::new(),
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
            sandbox: "sbx".to_string(),
            workspace: String::new(),
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
            sandbox: "sbx".to_string(),
            workspace: String::new(),
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

    /// Import a minimal profile so a synthetic provider type resolves.
    ///
    /// Provider profiles are import-only: a provider whose type no profile
    /// declares cannot compose a sandbox. Tests about limits, CAS or credential
    /// collisions still need their placeholder types to exist.
    async fn import_test_profile(state: &ServerState, id: &str) {
        state
            .store
            .put_message(&crate::provider_profile_sources::stored_provider_profile(
                openshell_core::proto::ProviderProfile {
                    id: id.to_string(),
                    display_name: id.to_string(),
                    category: openshell_core::proto::ProviderProfileCategory::Other as i32,
                    ..Default::default()
                },
            ))
            .await
            .expect("store test provider profile");
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
                created_time: openshell_core::time::timestamp_from_millis(1_000_000).ok(),
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_time: None,
            }),
            r#type: provider_type.to_string(),
            credentials: std::iter::once((credential_key.to_string(), "secret".to_string()))
                .collect(),
            config: HashMap::new(),
            credential_expiration_times: HashMap::new(),
            profile_workspace: "default".to_string(),
            credential_handles: HashMap::new(),
        }
    }

    fn test_sandbox(name: &str, providers: Vec<String>) -> Sandbox {
        let mut sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: format!("sandbox-{name}"),
                name: name.to_string(),
                created_time: openshell_core::time::timestamp_from_millis(1_000_000).ok(),
                labels: std::iter::once(("team".to_string(), "agents".to_string())).collect(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_time: None,
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
                created_time: openshell_core::time::timestamp_from_millis(0).ok(),
                labels: HashMap::from([("team".to_string(), "runtime".to_string())]),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: String::new(),
                deletion_time: None,
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
                    sandbox: "watched".to_string(),
                    workspace_scope: Some(openshell_core::proto::workspace_selector(
                        "default".to_string(),
                    )),
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
        traced.wait_for_span("disconnected_watch_request").await;

        assert_eq!(
            traced.spans_named("disconnected_watch_request").len(),
            1,
            "watch producer should release the request span after client disconnect"
        );
    }

    #[tokio::test]
    async fn logs_only_watch_ends_when_sweeper_frees_sandbox_deleted_elsewhere() {
        use tokio_stream::StreamExt as _;

        let state = test_server_state().await;
        let sandbox = test_sandbox("swept", Vec::new());
        state.store.put_message(&sandbox).await.unwrap();
        let id = sandbox.object_id().to_string();

        let response = handle_watch_sandbox(
            &state,
            authed_request(WatchSandboxRequest {
                sandbox: sandbox.object_name().to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                follow_logs: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        let mut stream = response.into_inner();

        // A delivered log line proves the watch has subscribed.
        seed_log_lines(&state, &id, 1);
        loop {
            let event = stream.next().await.unwrap().unwrap();
            if !event.cursor.is_empty() {
                break;
            }
        }

        // Another replica deletes the record; this one never runs delete cleanup.
        state
            .store
            .delete(Sandbox::object_type(), &id)
            .await
            .unwrap();
        let mut suspects = HashSet::new();
        for expected in [0, 1] {
            let closed = crate::bus_sweeper::sweep_once(
                &state.store,
                &state.tracing_log_bus,
                std::time::Duration::ZERO,
                &mut suspects,
            )
            .await
            .unwrap();
            assert_eq!(closed, expected);
        }

        let ended = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while let Some(item) = stream.next().await {
                if item.is_err() {
                    break;
                }
            }
        })
        .await;
        assert!(
            ended.is_ok(),
            "logs-only watch should end once its buffers are freed"
        );
    }

    /// Seed `n` log lines onto the log bus; cursors run 1..=n.
    fn seed_log_lines(state: &ServerState, sandbox_id: &str, n: usize) {
        for i in 0..n {
            state
                .tracing_log_bus
                .publish_external(openshell_core::proto::SandboxLogLine {
                    sandbox_id: sandbox_id.to_string(),
                    event_time: openshell_core::time::timestamp_from_millis(i as i64).ok(),
                    level: "INFO".to_string(),
                    target: "test".to_string(),
                    message: format!("line {i}"),
                    source: "gateway".to_string(),
                    ..Default::default()
                });
        }
    }

    fn seed_platform_event(state: &ServerState, sandbox_id: &str, reason: &str) {
        state.tracing_log_bus.platform_event_bus.publish(
            sandbox_id,
            SandboxStreamEvent {
                payload: Some(openshell_core::proto::sandbox_stream_event::Payload::Event(
                    openshell_core::proto::PlatformEvent {
                        event_time: openshell_core::time::timestamp_from_millis(0).ok(),
                        source: "test".to_string(),
                        r#type: "Normal".to_string(),
                        reason: reason.to_string(),
                        message: reason.to_string(),
                        metadata: HashMap::new(),
                    },
                )),
                cursor: String::new(),
            },
        );
    }

    /// Build the token a client would hold for `seq` in this sandbox's *current*
    /// cursor space. Capture it before any teardown to model a real reconnect.
    fn cursor_token(state: &ServerState, sandbox_id: &str, seq: u64) -> String {
        let space = state
            .tracing_log_bus
            .cursor_space(sandbox_id)
            .expect("cursor space exists; publish before taking a token");
        WatchCursor::new(space.epoch, seq).encode()
    }

    /// A well-formed token from an epoch this server never issued.
    fn foreign_cursor(seq: u64) -> String {
        WatchCursor::new(uuid::Uuid::new_v4(), seq).encode()
    }

    /// Sequence number carried by a delivered event. Panics on non-resumable
    /// events, so a test that expects a log line cannot silently pass on a
    /// snapshot.
    fn seq_of(evt: &SandboxStreamEvent) -> u64 {
        WatchCursor::parse(&evt.cursor)
            .expect("resumable event must carry a valid cursor")
            .seq
    }

    #[tokio::test]
    async fn resume_replays_only_events_after_cursor() {
        use tokio_stream::StreamExt as _;

        let state = test_server_state().await;
        let sandbox = test_sandbox("resumed", Vec::new());
        state.store.put_message(&sandbox).await.unwrap();
        let id = sandbox.object_id().to_string();

        // Cursors 1,2,3.
        seed_log_lines(&state, &id, 3);

        let response = handle_watch_sandbox(
            &state,
            authed_request(WatchSandboxRequest {
                sandbox: sandbox.object_name().to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                follow_logs: true,
                resume_after_cursor: cursor_token(&state, &id, 1),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let mut stream = response.into_inner();
        // Snapshot first (status re-read, no cursor).
        let snap = stream.next().await.unwrap().unwrap();
        assert!(
            snap.cursor.is_empty(),
            "first event should be the status snapshot"
        );

        // Then only seqs 2 and 3; seq 1 already seen by the client.
        let a = stream.next().await.unwrap().unwrap();
        let b = stream.next().await.unwrap().unwrap();
        assert_eq!(seq_of(&a), 2);
        assert_eq!(seq_of(&b), 3);
    }

    #[tokio::test]
    async fn resume_merges_log_and_platform_events_in_cursor_order() {
        use tokio_stream::StreamExt as _;

        let state = test_server_state().await;
        let sandbox = test_sandbox("merged", Vec::new());
        state.store.put_message(&sandbox).await.unwrap();
        let id = sandbox.object_id().to_string();

        // Interleave across the shared allocator: log=1, platform=2, log=3, platform=4.
        seed_log_lines(&state, &id, 1); // cursor 1
        seed_platform_event(&state, &id, "e2"); // cursor 2
        state
            .tracing_log_bus
            .publish_external(openshell_core::proto::SandboxLogLine {
                sandbox_id: id.clone(),
                event_time: openshell_core::time::timestamp_from_millis(3).ok(),
                level: "INFO".to_string(),
                target: "test".to_string(),
                message: "line 3".to_string(),
                source: "gateway".to_string(),
                ..Default::default()
            }); // cursor 3
        seed_platform_event(&state, &id, "e4"); // cursor 4

        let response = handle_watch_sandbox(
            &state,
            authed_request(WatchSandboxRequest {
                sandbox: sandbox.object_name().to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                follow_logs: true,
                follow_events: true,
                resume_after_cursor: cursor_token(&state, &id, 1),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let mut stream = response.into_inner();
        let snap = stream.next().await.unwrap().unwrap();
        assert!(snap.cursor.is_empty());

        // Merged from both buses, ascending by shared seq: 2,3,4.
        let mut got = Vec::new();
        for _ in 0..3 {
            got.push(seq_of(&stream.next().await.unwrap().unwrap()));
        }
        assert_eq!(got, vec![2, 3, 4]);
    }

    /// The initial tail is the resume path's twin: it draws from the same two
    /// buses over the same shared cursor space, so it owes the client the same
    /// ascending order.
    ///
    /// Before the merge, each bus was drained in its own pass and the tail came
    /// out grouped by source -- logs 1,3 then platform 2,4 -- so a client
    /// tracking the highest cursor saw it go backwards mid-tail.
    #[tokio::test]
    async fn initial_tail_merges_log_and_platform_events_in_cursor_order() {
        use tokio_stream::StreamExt as _;

        let state = test_server_state().await;
        let sandbox = test_sandbox("tailmerged", Vec::new());
        state.store.put_message(&sandbox).await.unwrap();
        let id = sandbox.object_id().to_string();

        // Interleave across the shared allocator: log=1, platform=2, log=3, platform=4.
        seed_log_lines(&state, &id, 1); // cursor 1
        seed_platform_event(&state, &id, "e2"); // cursor 2
        state
            .tracing_log_bus
            .publish_external(openshell_core::proto::SandboxLogLine {
                sandbox_id: id.clone(),
                event_time: openshell_core::time::timestamp_from_millis(3).ok(),
                level: "INFO".to_string(),
                target: "test".to_string(),
                message: "line 3".to_string(),
                source: "gateway".to_string(),
                ..Default::default()
            }); // cursor 3
        seed_platform_event(&state, &id, "e4"); // cursor 4

        let response = handle_watch_sandbox(
            &state,
            authed_request(WatchSandboxRequest {
                sandbox: sandbox.object_name().to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                follow_logs: true,
                follow_events: true,
                // event_tail has no default; 0 would replay no platform events.
                event_tail: 10,
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let mut stream = response.into_inner();
        let snap = stream.next().await.unwrap().unwrap();
        assert!(snap.cursor.is_empty());

        let mut got = Vec::new();
        for _ in 0..4 {
            got.push(seq_of(&stream.next().await.unwrap().unwrap()));
        }
        assert_eq!(got, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn live_delivery_orders_events_across_sources_by_cursor() {
        use tokio_stream::StreamExt as _;

        let state = test_server_state().await;
        let sandbox = test_sandbox("liveorder", Vec::new());
        state.store.put_message(&sandbox).await.unwrap();
        let id = sandbox.object_id().to_string();

        let response = handle_watch_sandbox(
            &state,
            authed_request(WatchSandboxRequest {
                sandbox: sandbox.object_name().to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                follow_logs: true,
                follow_events: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let mut stream = response.into_inner();
        // The snapshot itself only proves both subscriptions are live -- the
        // replay reads come after it. But on this current-thread runtime the
        // producer cannot yield between the two, so by the time the test task
        // is scheduled again the producer has run through to the live loop.
        let snap = stream.next().await.unwrap().unwrap();
        assert!(snap.cursor.is_empty());

        // Publish without awaiting in between. On the current-thread runtime
        // the producer cannot interleave, so both channels hold ready events
        // when it next polls -- the state where `select!` picks arbitrarily and
        // would otherwise emit a log cursor ahead of a lower platform cursor.
        for i in 0..5 {
            seed_log_lines(&state, &id, 1); // odd cursors
            seed_platform_event(&state, &id, &format!("e{i}")); // even cursors
        }

        let mut got = Vec::new();
        for _ in 0..10 {
            got.push(seq_of(&stream.next().await.unwrap().unwrap()));
        }
        assert_eq!(got, (1..=10).collect::<Vec<u64>>());
    }

    /// A reconnect resumes from the highest cursor the client saw, so live
    /// delivery may never emit a cursor while a lower one is still undelivered.
    /// The producer drains the log receiver before the platform one: a log line
    /// published after that first drain but before the platform drain finishes
    /// misses the batch, and its seq is below platform cursors the same batch
    /// carries. Emitting them strands the log line -- a disconnect there resumes
    /// above it, and no replay ever returns it. The publication watermark holds
    /// back anything the drain cannot prove it saw in full.
    ///
    /// Reaching that interleaving takes a wide drain: the producer is first
    /// parked on a full stream channel so a platform backlog accumulates, then
    /// both sources are hammered from other worker threads while it walks that
    /// backlog. Serialized against the test task the window does not exist --
    /// the drain holds no await a single-threaded test could wedge open.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn live_delivery_never_emits_a_cursor_above_an_undrained_event() {
        use tokio_stream::StreamExt as _;

        /// Enough to overrun the 256-slot stream channel and park the producer.
        const PARK: usize = 400;
        /// Platform events queued while it is parked. The next drain walks all
        /// of them, and that walk is the window the hammers below publish into.
        /// Kept under the 1024-slot broadcast capacity so nothing is dropped.
        const BACKLOG: usize = 600;
        const HAMMER: usize = 300;
        /// Hitting the window is a race, so repeat it. One round reproduced the
        /// unfixed behavior in two runs of three; four caught it in ten of ten.
        const ROUNDS: u64 = 4;
        /// The single line published to confirm the producer finished
        /// initialization before the rounds below start publishing.
        const HANDSHAKE: u64 = 1;
        const PER_ROUND: u64 = (PARK + BACKLOG + HAMMER * 2) as u64;
        const TOTAL: u64 = PER_ROUND * ROUNDS + HANDSHAKE;

        let state = test_server_state().await;
        let sandbox = test_sandbox("watermark", Vec::new());
        state.store.put_message(&sandbox).await.unwrap();
        let id = sandbox.object_id().to_string();

        let response = handle_watch_sandbox(
            &state,
            authed_request(WatchSandboxRequest {
                sandbox: sandbox.object_name().to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                follow_logs: true,
                follow_events: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        let mut stream = response.into_inner();
        // The snapshot only proves both subscriptions are live; the producer
        // sends it before reading either replay window. Publishing the rest of
        // this test against that state is unsound: the log tail is capped at
        // 200 by default, so a burst landing before the read is truncated, the
        // rest is suppressed as already replayed, and the test stalls.
        //
        // One line is the handshake. Receiving it with a cursor -- replayed or
        // live, either way -- proves the producer is past both tail reads, and
        // one line cannot overflow any tail. Everything below is published into
        // a producer known to be in the live loop.
        let snap = stream.next().await.unwrap().unwrap();
        assert!(snap.cursor.is_empty());
        seed_log_lines(&state, &id, 1);
        let handshake = stream.next().await.unwrap().unwrap();
        assert_eq!(
            seq_of(&handshake),
            HANDSHAKE,
            "handshake line should be seq 1"
        );

        let mut highest = HANDSHAKE;
        let mut seen = HANDSHAKE;
        let mut last_cursor = handshake.cursor;

        for round in 0..ROUNDS {
            // Nothing reads during this round's setup, so the producer fills
            // the stream channel and blocks part-way through this batch.
            seed_log_lines(&state, &id, PARK);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;

            for i in 0..BACKLOG {
                seed_platform_event(&state, &id, &format!("b{round}-{i}"));
            }

            let log_hammer = {
                let state = Arc::clone(&state);
                let id = id.clone();
                tokio::spawn(async move {
                    for _ in 0..HAMMER {
                        seed_log_lines(&state, &id, 1);
                    }
                })
            };
            let platform_hammer = {
                let state = Arc::clone(&state);
                let id = id.clone();
                tokio::spawn(async move {
                    for i in 0..HAMMER {
                        seed_platform_event(&state, &id, &format!("h{round}-{i}"));
                    }
                })
            };

            while seen < PER_ROUND * (round + 1) + HANDSHAKE {
                let evt = tokio::time::timeout(std::time::Duration::from_secs(30), stream.next())
                    .await
                    .unwrap_or_else(|_| {
                        panic!(
                            "live delivery stalled after {seen}/{TOTAL} events, highest {highest}"
                        )
                    })
                    .unwrap()
                    .unwrap();
                let seq = seq_of(&evt);
                // Ascending delivery is what makes a highest-cursor resume safe.
                // Without the watermark this trips: a log line published during
                // the platform walk follows platform cursors emitted above it.
                assert!(seq > highest, "cursor {seq} emitted after {highest}");
                highest = seq;
                last_cursor = evt.cursor;
                seen += 1;
            }

            log_hammer.await.unwrap();
            platform_hammer.await.unwrap();
        }

        // Every seq in the space belongs to one of the two buses, so `TOTAL`
        // ascending events ending at `TOTAL` means none was skipped.
        assert_eq!(highest, TOTAL, "live delivery skipped a cursor");

        // Reconnecting from that cursor is consistent with what was delivered:
        // the replay resumes at the next event rather than past one.
        seed_log_lines(&state, &id, 1);
        seed_platform_event(&state, &id, "after-resume");
        drop(stream);

        let response = handle_watch_sandbox(
            &state,
            authed_request(WatchSandboxRequest {
                sandbox: sandbox.object_name().to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                follow_logs: true,
                follow_events: true,
                resume_after_cursor: last_cursor,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        let mut stream = response.into_inner();
        let snap = stream.next().await.unwrap().unwrap();
        assert!(snap.cursor.is_empty());

        let a = stream.next().await.unwrap().unwrap();
        let b = stream.next().await.unwrap().unwrap();
        assert_eq!(seq_of(&a), TOTAL + 1);
        assert_eq!(seq_of(&b), TOTAL + 2);
    }

    /// A lag warning carries no cursor, so it is never replayed on resume. Sent
    /// after the surviving events of its own batch, a disconnect in between
    /// leaves the client checkpointed past the dropped range having never been
    /// told anything was dropped. The warning must lead the batch.
    ///
    /// Which branch `select!` takes is arbitrary, so the run is repeated: the
    /// assertion holds on both paths, but only the platform-first path reaches
    /// the drain's lag counter, which is where the ordering used to be wrong.
    /// Eight attempts caught the unfixed ordering in three runs of five; forty
    /// caught it in six of six.
    #[tokio::test]
    async fn lag_warning_precedes_the_events_of_its_batch() {
        use openshell_core::proto::sandbox_stream_event::Payload;
        use tokio_stream::StreamExt as _;

        /// `select!` polls the log receiver before the platform one in three of
        /// its four rotations, and only the platform-first path reaches the
        /// drain's lag counter. Repeat enough that missing it is negligible.
        const ATTEMPTS: usize = 40;

        let state = test_server_state().await;

        for attempt in 0..ATTEMPTS {
            let sandbox = test_sandbox(&format!("lagorder{attempt}"), Vec::new());
            state.store.put_message(&sandbox).await.unwrap();
            let id = sandbox.object_id().to_string();

            let response = handle_watch_sandbox(
                &state,
                authed_request(WatchSandboxRequest {
                    sandbox: sandbox.object_name().to_string(),
                    workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                    follow_logs: true,
                    follow_events: true,
                    ..Default::default()
                }),
            )
            .await
            .unwrap();
            let mut stream = response.into_inner();
            let snap = stream.next().await.unwrap().unwrap();
            assert!(snap.cursor.is_empty());

            // One platform event plus a log burst past the 1024-slot broadcast
            // capacity, published without an await in between so the producer
            // sees both on a single wake-up: a deliverable event and a drop.
            seed_platform_event(&state, &id, "e1");
            seed_log_lines(&state, &id, 1100);

            let first = stream.next().await.unwrap().unwrap();
            assert!(
                matches!(first.payload, Some(Payload::Warning(_))),
                "the lag warning must arrive before any event of the lagged batch, got {:?}",
                first.payload
            );
        }
    }

    #[tokio::test]
    async fn resume_at_latest_cursor_suppresses_duplicates() {
        use tokio_stream::StreamExt as _;

        let state = test_server_state().await;
        let sandbox = test_sandbox("nodup", Vec::new());
        state.store.put_message(&sandbox).await.unwrap();
        let id = sandbox.object_id().to_string();

        // Cursors 1,2,3; client already saw through 3.
        seed_log_lines(&state, &id, 3);

        let response = handle_watch_sandbox(
            &state,
            authed_request(WatchSandboxRequest {
                sandbox: sandbox.object_name().to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                follow_logs: true,
                resume_after_cursor: cursor_token(&state, &id, 3),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let mut stream = response.into_inner();
        let snap = stream.next().await.unwrap().unwrap();
        assert!(snap.cursor.is_empty());

        // No resumable events remain; the live loop yields nothing promptly.
        let next = tokio::time::timeout(std::time::Duration::from_millis(200), stream.next()).await;
        assert!(
            next.is_err(),
            "expected no further events after resume at latest cursor, got {next:?}"
        );
    }

    #[tokio::test]
    async fn resume_from_trimmed_cursor_terminates_out_of_range() {
        use tokio_stream::StreamExt as _;

        let state = test_server_state().await;
        let sandbox = test_sandbox("gap", Vec::new());
        state.store.put_message(&sandbox).await.unwrap();
        let id = sandbox.object_id().to_string();

        // Exceed the 2000-line tail so the earliest cursors are trimmed.
        seed_log_lines(&state, &id, 2005);

        let response = handle_watch_sandbox(
            &state,
            authed_request(WatchSandboxRequest {
                sandbox: sandbox.object_name().to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                follow_logs: true,
                // Seq 2 was trimmed; this is an unrecoverable gap.
                resume_after_cursor: cursor_token(&state, &id, 2),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let mut stream = response.into_inner();
        // Snapshot still arrives first (fresh state), then the terminal gap status.
        let snap = stream.next().await.unwrap().unwrap();
        assert!(snap.cursor.is_empty());

        let err = stream
            .next()
            .await
            .unwrap()
            .expect_err("trimmed cursor must terminate the stream");
        assert_eq!(err.code(), tonic::Code::OutOfRange, "{err:?}");
        assert!(
            err.message().contains('2'),
            "gap status should report the requested cursor: {}",
            err.message()
        );

        // Stream ends after the terminal status.
        assert!(stream.next().await.is_none());
    }

    /// The guard behind the producer's post-replay epoch re-check.
    ///
    /// Validation and the two `tail_after` reads take their locks separately, so
    /// a teardown plus a republish can swap the space in between and leave the
    /// reads applying an old seq to a replacement's buffers -- `tail_after` only
    /// compares numbers, so it reports no gap while skipping every replacement
    /// event at or below that seq. The producer re-checks the epoch once both
    /// tails are in hand and before emitting anything; this pins what that check
    /// must answer.
    ///
    /// The interleaving itself is not reachable from a test: the producer runs
    /// validation, both reads, and the re-check with no await in between, so
    /// there is nothing to suspend it on.
    #[tokio::test]
    async fn cursor_space_is_rejects_a_replacement_space() {
        let state = test_server_state().await;
        let sandbox = test_sandbox("respace", Vec::new());
        state.store.put_message(&sandbox).await.unwrap();
        let id = sandbox.object_id().to_string();

        seed_log_lines(&state, &id, 1);
        let original = state.tracing_log_bus.cursor_space(&id).unwrap().epoch;
        assert!(cursor_space_is(&state, &id, original));

        // Teardown alone leaves no space to point into.
        state.tracing_log_bus.remove(&id);
        assert!(state.tracing_log_bus.cursor_space(&id).is_none());
        assert!(!cursor_space_is(&state, &id, original));

        // The republish installs a replacement renumbered from 1. Its seqs
        // overlap the retired space's, so only the epoch separates them.
        seed_log_lines(&state, &id, 1);
        let replacement = state.tracing_log_bus.cursor_space(&id).unwrap();
        assert_ne!(replacement.epoch, original);
        assert_eq!(replacement.highest_seq, 1);
        assert!(!cursor_space_is(&state, &id, original));
        assert!(cursor_space_is(&state, &id, replacement.epoch));
    }

    #[tokio::test]
    async fn resume_from_reset_cursor_space_terminates_out_of_range() {
        use tokio_stream::StreamExt as _;

        let state = test_server_state().await;
        let sandbox = test_sandbox("reset", Vec::new());
        state.store.put_message(&sandbox).await.unwrap();
        let id = sandbox.object_id().to_string();

        // The reported repro. Before cursors carried an epoch, a bare number
        // was all the server had: 2 <= 3 passed the old "is this plausible?"
        // bound, the tail replayed only seq 3, and the new space's seqs 1 and 2
        // -- real, unseen events -- were silently swallowed as duplicates.
        seed_log_lines(&state, &id, 2);
        let retired_cursor = cursor_token(&state, &id, 2);

        // Teardown retires the space; the next publish starts over at seq 1,
        // indistinguishable by number from the client's view of a restart.
        state.tracing_log_bus.remove(&id);
        seed_log_lines(&state, &id, 3);

        let response = handle_watch_sandbox(
            &state,
            authed_request(WatchSandboxRequest {
                sandbox: sandbox.object_name().to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                follow_logs: true,
                resume_after_cursor: retired_cursor,
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let mut stream = response.into_inner();
        let snap = stream.next().await.unwrap().unwrap();
        assert!(snap.cursor.is_empty());

        let item = stream
            .next()
            .await
            .unwrap()
            .expect_err("a cursor from a retired space must terminate the stream");
        assert_eq!(item.code(), tonic::Code::OutOfRange, "{item:?}");
        assert!(
            item.message().contains("empty resume_after_cursor"),
            "status must tell the client to restart without a cursor, not retry: {}",
            item.message()
        );

        // Nothing from the new space may be delivered before the error: a
        // partial stream would read as "here is everything after your cursor".
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn resume_from_reset_cursor_space_rejected_when_new_space_is_shorter() {
        use tokio_stream::StreamExt as _;

        let state = test_server_state().await;
        let sandbox = test_sandbox("reset-short", Vec::new());
        state.store.put_message(&sandbox).await.unwrap();
        let id = sandbox.object_id().to_string();

        // The shape the old numeric bound did catch (5 > 2), kept so it keeps
        // passing -- but now it fails for the reason that generalizes.
        seed_log_lines(&state, &id, 5);
        let retired_cursor = cursor_token(&state, &id, 5);
        state.tracing_log_bus.remove(&id);
        seed_log_lines(&state, &id, 2);

        let response = handle_watch_sandbox(
            &state,
            authed_request(WatchSandboxRequest {
                sandbox: sandbox.object_name().to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                follow_logs: true,
                resume_after_cursor: retired_cursor,
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let mut stream = response.into_inner();
        assert!(stream.next().await.unwrap().unwrap().cursor.is_empty());
        let err = stream.next().await.unwrap().expect_err("out of range");
        assert_eq!(err.code(), tonic::Code::OutOfRange, "{err:?}");
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn resume_from_reset_cursor_space_rejected_when_seq_is_within_new_range() {
        use tokio_stream::StreamExt as _;

        let state = test_server_state().await;
        let sandbox = test_sandbox("reset-within", Vec::new());
        state.store.put_message(&sandbox).await.unwrap();
        let id = sandbox.object_id().to_string();

        // Seq 1 sits comfortably inside the new space's 1..=3, so every numeric
        // bound accepts it. Only the epoch distinguishes the two spaces. This is
        // the assertion the pre-fix design structurally could not make.
        seed_log_lines(&state, &id, 3);
        let retired_cursor = cursor_token(&state, &id, 1);
        state.tracing_log_bus.remove(&id);
        seed_log_lines(&state, &id, 3);

        let response = handle_watch_sandbox(
            &state,
            authed_request(WatchSandboxRequest {
                sandbox: sandbox.object_name().to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                follow_logs: true,
                resume_after_cursor: retired_cursor,
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let mut stream = response.into_inner();
        assert!(stream.next().await.unwrap().unwrap().cursor.is_empty());
        let err = stream.next().await.unwrap().expect_err("out of range");
        assert_eq!(err.code(), tonic::Code::OutOfRange, "{err:?}");
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn resume_after_remove_without_republish_terminates_out_of_range() {
        use tokio_stream::StreamExt as _;

        let state = test_server_state().await;
        let sandbox = test_sandbox("reset-empty", Vec::new());
        state.store.put_message(&sandbox).await.unwrap();
        let id = sandbox.object_id().to_string();

        // No space at all: nothing has been published since teardown. The buses
        // look merely empty, so `tail_after` reports no gap -- "caught up" would
        // be the wrong reading, because the client's events are gone.
        seed_log_lines(&state, &id, 3);
        let retired_cursor = cursor_token(&state, &id, 3);
        state.tracing_log_bus.remove(&id);

        let response = handle_watch_sandbox(
            &state,
            authed_request(WatchSandboxRequest {
                sandbox: sandbox.object_name().to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                follow_logs: true,
                resume_after_cursor: retired_cursor,
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let mut stream = response.into_inner();
        assert!(stream.next().await.unwrap().unwrap().cursor.is_empty());
        let err = stream.next().await.unwrap().expect_err("out of range");
        assert_eq!(err.code(), tonic::Code::OutOfRange, "{err:?}");
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn resume_with_cursor_from_another_sandbox_terminates_out_of_range() {
        use tokio_stream::StreamExt as _;

        let state = test_server_state().await;
        let a = test_sandbox("epoch-a", Vec::new());
        let b = test_sandbox("epoch-b", Vec::new());
        state.store.put_message(&a).await.unwrap();
        state.store.put_message(&b).await.unwrap();
        let a_id = a.object_id().to_string();
        let b_id = b.object_id().to_string();

        // Epochs are per sandbox, not per process. A token valid for A must not
        // address B's space, even though both are on seq 1..=3 right now.
        seed_log_lines(&state, &a_id, 3);
        seed_log_lines(&state, &b_id, 3);
        let a_cursor = cursor_token(&state, &a_id, 1);

        let response = handle_watch_sandbox(
            &state,
            authed_request(WatchSandboxRequest {
                sandbox: b.object_name().to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                follow_logs: true,
                resume_after_cursor: a_cursor,
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let mut stream = response.into_inner();
        assert!(stream.next().await.unwrap().unwrap().cursor.is_empty());
        let err = stream.next().await.unwrap().expect_err("out of range");
        assert_eq!(err.code(), tonic::Code::OutOfRange, "{err:?}");
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn resume_with_cursor_ahead_of_the_space_terminates_out_of_range() {
        use tokio_stream::StreamExt as _;

        let state = test_server_state().await;
        let sandbox = test_sandbox("ahead", Vec::new());
        state.store.put_message(&sandbox).await.unwrap();
        let id = sandbox.object_id().to_string();

        seed_log_lines(&state, &id, 2);
        // Right epoch, but a seq this space has never issued: only a fabricated
        // token gets here. Accepting it would pin the cutoff above every future
        // event and stall the stream silently.
        let ahead = cursor_token(&state, &id, 99);

        let response = handle_watch_sandbox(
            &state,
            authed_request(WatchSandboxRequest {
                sandbox: sandbox.object_name().to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                follow_logs: true,
                resume_after_cursor: ahead,
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let mut stream = response.into_inner();
        assert!(stream.next().await.unwrap().unwrap().cursor.is_empty());
        let err = stream.next().await.unwrap().expect_err("out of range");
        assert_eq!(err.code(), tonic::Code::OutOfRange, "{err:?}");
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn resume_with_malformed_cursor_rejects_invalid_argument() {
        let state = test_server_state().await;
        let sandbox = test_sandbox("malformed", Vec::new());
        state.store.put_message(&sandbox).await.unwrap();
        let id = sandbox.object_id().to_string();

        seed_log_lines(&state, &id, 3);

        // Input validation, so it fails the RPC before any stream exists rather
        // than arriving as the first item of an apparently-healthy stream.
        for raw in ["5", "v1:not-a-uuid:0", &foreign_cursor(1)[..40]] {
            let err = handle_watch_sandbox(
                &state,
                authed_request(WatchSandboxRequest {
                    sandbox: sandbox.object_name().to_string(),
                    workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                    follow_logs: true,
                    resume_after_cursor: raw.to_string(),
                    ..Default::default()
                }),
            )
            .await
            .expect_err("malformed cursor must fail the call");
            assert_eq!(err.code(), tonic::Code::InvalidArgument, "{raw:?}: {err:?}");
            assert!(
                !err.message().contains(raw),
                "status must not echo the client token: {}",
                err.message()
            );
        }
    }

    #[tokio::test]
    async fn resume_with_foreign_epoch_terminates_out_of_range() {
        use tokio_stream::StreamExt as _;

        let state = test_server_state().await;
        let sandbox = test_sandbox("foreign", Vec::new());
        state.store.put_message(&sandbox).await.unwrap();
        let id = sandbox.object_id().to_string();

        seed_log_lines(&state, &id, 3);

        // Well-formed, so it clears input validation, but from an epoch this
        // gateway never minted -- the shape a reconnect to another replica
        // takes.
        let response = handle_watch_sandbox(
            &state,
            authed_request(WatchSandboxRequest {
                sandbox: sandbox.object_name().to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                follow_logs: true,
                resume_after_cursor: foreign_cursor(1),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let mut stream = response.into_inner();
        assert!(stream.next().await.unwrap().unwrap().cursor.is_empty());
        let err = stream.next().await.unwrap().expect_err("out of range");
        assert_eq!(err.code(), tonic::Code::OutOfRange, "{err:?}");
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn watch_delivers_each_event_once_during_init_race() {
        use tokio_stream::StreamExt as _;

        let state = test_server_state().await;
        let sandbox = test_sandbox("race", Vec::new());
        state.store.put_message(&sandbox).await.unwrap();
        let id = sandbox.object_id().to_string();

        // Seed events that land in the tail before the watch subscribes.
        seed_log_lines(&state, &id, 5);

        let response = handle_watch_sandbox(
            &state,
            authed_request(WatchSandboxRequest {
                sandbox: sandbox.object_name().to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                follow_logs: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        // Publish more concurrently with producer initialization. Some of these
        // can land after the broadcast subscription but before the tail read,
        // putting them in both replay and the live receiver.
        for i in 5..15 {
            state
                .tracing_log_bus
                .publish_external(openshell_core::proto::SandboxLogLine {
                    sandbox_id: id.clone(),
                    event_time: openshell_core::time::timestamp_from_millis(i64::from(i)).ok(),
                    level: "INFO".to_string(),
                    target: "test".to_string(),
                    message: format!("line {i}"),
                    source: "gateway".to_string(),
                    ..Default::default()
                });
        }

        let mut stream = response.into_inner();
        let mut cursors = Vec::new();
        while let Ok(Some(item)) =
            tokio::time::timeout(std::time::Duration::from_millis(200), stream.next()).await
        {
            let evt = item.unwrap();
            if !evt.cursor.is_empty() {
                cursors.push(seq_of(&evt));
            }
        }

        // Every delivered cursor is unique (no double delivery) and monotonically
        // increasing (replay ordered, then live in cursor order for one source).
        let mut sorted = cursors.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            cursors.len(),
            "duplicate cursors delivered: {cursors:?}"
        );
        assert_eq!(
            cursors, sorted,
            "cursors not delivered in order: {cursors:?}"
        );
    }

    #[tokio::test]
    async fn delete_handler_ends_telemetry_for_the_resolved_sandbox_id() {
        let state = test_server_state().await;
        let mut original = test_sandbox("reused-name", Vec::new());
        original.metadata.as_mut().unwrap().id = "sandbox-original".to_string();
        state.store.put_message(&original).await.unwrap();

        // Hold the global guard so the handler can resolve the original ID and
        // acquire its delete gate, but cannot yet take the sandbox's local
        // lifecycle lock (shared global key) to revalidate or mutate it.
        let global_guard = state
            .compute
            .mutation_guard(MutationScope::Global)
            .await
            .unwrap();
        let delete_state = state.clone();
        let delete = tokio::spawn(async move {
            handle_delete_sandbox_inner(
                &delete_state,
                authed_request(DeleteSandboxRequest {
                    request_id: String::new(),
                    allow_missing: false,
                    name: "reused-name".to_string(),
                    workspace_scope: Some(openshell_core::proto::workspace_selector(
                        "default".to_string(),
                    )),
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
        assert_eq!(
            response.outcome(),
            openshell_core::proto::DeletionOutcome::Completed
        );
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
    async fn internal_delete_rejects_expected_identity_drift_before_mutation() {
        let state = test_server_state().await;
        let mut sandbox = test_sandbox("guarded-delete", Vec::new());
        sandbox.metadata.as_mut().unwrap().id = "sb-current".to_string();
        state.store.put_message(&sandbox).await.unwrap();

        let error = state
            .compute
            .delete_sandbox_with_preconditions(
                "default",
                "guarded-delete",
                SandboxDeletePreconditions {
                    expected_sandbox_id: Some("sb-stale".to_string()),
                    expected_resource_version: None,
                },
            )
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::Aborted);
        assert!(
            state
                .store
                .get_message::<Sandbox>("sb-current")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn internal_delete_rejects_resource_version_without_immutable_identity() {
        let state = test_server_state().await;
        let mut sandbox = test_sandbox("guarded-delete", Vec::new());
        sandbox.metadata.as_mut().unwrap().id = "sb-current".to_string();
        state.store.put_message(&sandbox).await.unwrap();

        let error = state
            .compute
            .delete_sandbox_with_preconditions(
                "default",
                "guarded-delete",
                SandboxDeletePreconditions {
                    expected_sandbox_id: None,
                    expected_resource_version: Some(17),
                },
            )
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(
            state
                .store
                .get_message::<Sandbox>("sb-current")
                .await
                .unwrap()
                .is_some()
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
                request_id: String::new(),
                sandbox: "work".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                provider: "work-github".to_string(),
                expected_resource_version: 0,
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
                request_id: String::new(),
                sandbox: "work".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                provider: "work-github".to_string(),
                expected_resource_version: 0,
            }),
        )
        .await
        .expect("an imported github profile should resolve from the user source")
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
                request_id: String::new(),
                sandbox: "work".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                provider: "work-github".to_string(),
                expected_resource_version: 0,
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

    fn attach_request(sandbox: &str, provider: &str) -> Request<AttachSandboxProviderRequest> {
        authed_request(AttachSandboxProviderRequest {
            request_id: String::new(),
            sandbox: sandbox.to_string(),
            workspace_scope: Some(openshell_core::proto::workspace_selector(
                "default".to_string(),
            )),
            provider: provider.to_string(),
            expected_resource_version: 0,
        })
    }

    #[tokio::test]
    async fn attach_provider_does_not_wait_for_unrelated_sandbox_guard() {
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
        let unrelated = test_sandbox("unrelated", Vec::new());
        state.store.put_message(&unrelated).await.unwrap();
        let unrelated_guard = crate::persistence::lock_order::branch(
            state
                .compute
                .mutation_guard(MutationScope::sandbox("default", unrelated.object_id())),
        )
        .await
        .unwrap();

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            handle_attach_sandbox_provider(&state, attach_request("work", "work-github")),
        )
        .await
        .expect("attach should not wait for an unrelated sandbox mutation")
        .expect("attach should succeed")
        .into_inner();
        assert!(response.attached);
        drop(unrelated_guard);
    }

    #[tokio::test]
    async fn attach_provider_waits_for_workspace_guard() {
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
        let workspace_guard = state
            .compute
            .mutation_guard(MutationScope::Workspace("default"))
            .await
            .unwrap();

        let task_state = state.clone();
        let mut attach = tokio::spawn(async move {
            handle_attach_sandbox_provider(&task_state, attach_request("work", "work-github")).await
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut attach)
                .await
                .is_err(),
            "attach should wait for a provider writer in its workspace"
        );
        drop(workspace_guard);

        let response = tokio::time::timeout(std::time::Duration::from_secs(5), attach)
            .await
            .expect("attach should finish after the workspace guard is released")
            .expect("join attach task")
            .expect("attach should succeed")
            .into_inner();
        assert!(response.attached);
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
                request_id: String::new(),
                sandbox: "work".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                provider: "work-github".to_string(),
                expected_resource_version: 0,
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
                request_id: String::new(),
                sandbox: "work".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                provider: "work-github".to_string(),
                expected_resource_version: 0,
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
                request_id: String::new(),
                sandbox: "work".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                provider: "work-gcp".to_string(),
                expected_resource_version: 0,
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
        use openshell_core::proto::CreateWorkspaceRequest;

        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_provider("work-gitlab", "gitlab"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox(
                "work",
                vec!["work-github".to_string(), "work-gitlab".to_string()],
            ))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox("other", vec!["work-github".to_string()]))
            .await
            .unwrap();

        let first_page = handle_list_sandbox_providers(
            &state,
            authed_request(ListSandboxProvidersRequest {
                sandbox: "work".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                page_size: 1,
                page_token: String::new(),
            }),
        )
        .await
        .unwrap()
        .into_inner();

        assert_eq!(first_page.providers.len(), 1);
        assert_eq!(first_page.providers[0].r#type, "github");
        assert_eq!(
            first_page.providers[0].credentials.get("TOKEN"),
            Some(&"REDACTED".to_string())
        );
        assert!(!first_page.next_page_token.is_empty());

        crate::grpc::workspace::handle_create_workspace(
            &state,
            Request::new(CreateWorkspaceRequest {
                request_id: String::new(),
                name: "beta".to_string(),
                labels: HashMap::new(),
            }),
        )
        .await
        .expect("beta workspace should be created");
        let mut beta_provider = test_provider("work-github", "github");
        beta_provider.metadata.as_mut().unwrap().id = "provider-beta-work-github".to_string();
        beta_provider.metadata.as_mut().unwrap().workspace = "beta".to_string();
        state.store.put_message(&beta_provider).await.unwrap();
        let mut beta_sandbox = test_sandbox("work", vec!["work-github".to_string()]);
        beta_sandbox.metadata.as_mut().unwrap().id = "sandbox-beta-work".to_string();
        beta_sandbox.metadata.as_mut().unwrap().workspace = "beta".to_string();
        state.store.put_message(&beta_sandbox).await.unwrap();

        let err = handle_list_sandbox_providers(
            &state,
            authed_request(ListSandboxProvidersRequest {
                sandbox: "work".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("beta")),
                page_size: 1,
                page_token: first_page.next_page_token.clone(),
            }),
        )
        .await
        .expect_err("a token for one workspace must not list a same-named sandbox elsewhere");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let mut sandbox = state
            .store
            .get_message_by_name::<Sandbox>("default", "work")
            .await
            .unwrap()
            .expect("sandbox exists");
        sandbox
            .spec
            .as_mut()
            .expect("sandbox has a spec")
            .providers
            .retain(|name| name != "work-github");
        state.store.put_message(&sandbox).await.unwrap();

        let err = handle_list_sandbox_providers(
            &state,
            authed_request(ListSandboxProvidersRequest {
                sandbox: "other".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                page_size: 1,
                page_token: first_page.next_page_token.clone(),
            }),
        )
        .await
        .expect_err("a token for one sandbox must not list another sandbox");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let second_page = handle_list_sandbox_providers(
            &state,
            authed_request(ListSandboxProvidersRequest {
                sandbox: "work".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                page_size: 100,
                page_token: first_page.next_page_token,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(second_page.providers.len(), 1);
        assert_eq!(second_page.providers[0].r#type, "gitlab");
        assert!(second_page.next_page_token.is_empty());
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
                request_id: String::new(),
                sandbox: "work".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                provider: "missing".to_string(),
                expected_resource_version: 0,
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
    fn interactive_exec_rejects_missing_sandbox_name() {
        use openshell_core::proto::exec_sandbox_input;
        let msg = ExecSandboxInput {
            payload: Some(exec_sandbox_input::Payload::Start(ExecSandboxRequest {
                command: vec!["bash".to_string()],
                ..Default::default()
            })),
        };
        let err = validate_interactive_exec_start(Some(msg)).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("sandbox"));
    }

    #[test]
    fn interactive_exec_rejects_missing_command() {
        use openshell_core::proto::exec_sandbox_input;
        let msg = ExecSandboxInput {
            payload: Some(exec_sandbox_input::Payload::Start(ExecSandboxRequest {
                sandbox: "test-id".to_string(),
                workspace_scope: None,
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
                sandbox: "test-id".to_string(),
                workspace_scope: None,
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
                sandbox: "test-id".to_string(),
                workspace_scope: None,
                command: vec!["bash".to_string()],
                tty: true,
                cols: 120,
                rows: 40,
                ..Default::default()
            })),
        };
        let req = validate_interactive_exec_start(Some(msg)).unwrap();
        assert_eq!(req.sandbox, "test-id");
        assert_eq!(req.command, vec!["bash"]);
        assert!(req.tty);
        assert_eq!(req.cols, 120);
        assert_eq!(req.rows, 40);
    }

    #[tokio::test]
    async fn interactive_exec_rejects_sandbox_not_found() {
        let state = test_server_state().await;

        let req = ExecSandboxRequest {
            sandbox: "nonexistent".to_string(),
            workspace_scope: None,
            command: vec!["bash".to_string()],
            tty: true,
            ..Default::default()
        };
        let sandbox_result = state
            .store
            .get_message_by_name::<Sandbox>("default", &req.sandbox)
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
        import_test_profile(&state, "outlook").await;
        import_test_profile(&state, "google-drive").await;
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
                parent: String::new(),
                request_id: String::new(),
                name: "collision".to_string(),
                spec: Some(SandboxSpec {
                    providers: vec!["provider-a".to_string(), "provider-b".to_string()],
                    ..Default::default()
                }),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                await_main_process_attachment: false,
                workload_template: String::new(),
                service_exposures: Vec::new(),
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
    async fn provider_create_failure_releases_global_guard_before_compensation() {
        let state = test_server_state_with_compute_driver(
            "test",
            Arc::new(NoopTestDriver::authenticating_sandbox_with_runtime(
                "unused", "",
            )),
        )
        .await;
        state
            .store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            handle_create_sandbox(
                &state,
                authed_request(CreateSandboxRequest {
                    name: "provider-fail".to_string(),
                    spec: Some(SandboxSpec {
                        providers: vec!["work-github".to_string()],
                        ..Default::default()
                    }),
                    workspace_scope: Some(openshell_core::proto::workspace_selector(
                        "default".to_string(),
                    )),
                    ..Default::default()
                }),
            ),
        )
        .await
        .expect("create compensation must not deadlock")
        .expect_err("empty runtime identity must fail create");

        assert_eq!(result.code(), tonic::Code::Internal, "{}", result.message());
        let retained = state
            .store
            .get_message_by_name::<Sandbox>("default", "provider-fail")
            .await
            .unwrap()
            .expect("accepted asynchronous cleanup must retain the sandbox record");
        assert_eq!(retained.phase(), SandboxPhase::Deleting as i32);
    }

    #[tokio::test]
    async fn create_sandbox_uses_configured_provider_profile_sources() {
        let state = test_server_state().await;

        let response = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                parent: String::new(),
                request_id: String::new(),
                name: "user-catalog".to_string(),
                spec: Some(SandboxSpec::default()),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                await_main_process_attachment: false,
                workload_template: String::new(),
                service_exposures: Vec::new(),
            }),
        )
        .await
        .expect("an imported github profile should resolve from the user source")
        .into_inner();

        assert_eq!(
            response.sandbox.expect("created sandbox").object_name(),
            "user-catalog"
        );
    }

    async fn child_sandboxes_state() -> Arc<ServerState> {
        child_sandboxes_state_with_limit(10).await
    }

    async fn child_sandboxes_state_with_limit(limit: u32) -> Arc<ServerState> {
        let mut state = test_server_state().await;
        let config = &mut Arc::get_mut(&mut state).unwrap().config;
        config.enable_child_sandboxes = true;
        config.max_concurrent_children = limit;
        state
    }

    async fn put_parent_record(
        state: &ServerState,
        name: &str,
        providers: &[&str],
        parent: Option<openshell_core::proto::SandboxParent>,
        deleting: bool,
    ) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        state
            .store
            .put_message(&Sandbox {
                metadata: Some(ObjectMeta {
                    id: id.clone(),
                    name: name.to_string(),
                    workspace: "default".to_string(),
                    deletion_time: deleting.then(|| {
                        openshell_core::time::timestamp_from_millis(current_time_ms()).unwrap()
                    }),
                    ..Default::default()
                }),
                spec: Some(SandboxSpec {
                    providers: providers.iter().map(ToString::to_string).collect(),
                    ..Default::default()
                }),
                parent,
                ..Default::default()
            })
            .await
            .unwrap();
        put_policy_revision_with_status(
            state,
            &id,
            1,
            &openshell_policy::restrictive_default_policy(),
            "loaded",
        )
        .await;
        id
    }

    async fn put_policy_revision_with_status(
        state: &ServerState,
        sandbox_id: &str,
        version: i64,
        policy: &openshell_core::proto::SandboxPolicy,
        status: &str,
    ) {
        state
            .store
            .put_policy_revision(
                &uuid::Uuid::new_v4().to_string(),
                sandbox_id,
                "default",
                version,
                &policy.encode_to_vec(),
                &openshell_core::policy_identity::deterministic_policy_hash(policy),
            )
            .await
            .unwrap();
        state
            .store
            .update_policy_status(
                sandbox_id,
                version,
                status,
                None,
                (status == "loaded").then(current_time_ms),
            )
            .await
            .unwrap();
        // As the report handler does: a load moves the sandbox's current
        // policy version forward.
        if status == "loaded"
            && let Some(mut sandbox) = state
                .store
                .get_message::<Sandbox>(sandbox_id)
                .await
                .unwrap()
            && i64::from(sandbox.current_policy_version()) < version
        {
            sandbox.set_current_policy_version(u32::try_from(version).unwrap());
            state.store.put_message(&sandbox).await.unwrap();
        }
    }

    fn lead_policy(advisor_proposed: bool) -> openshell_core::proto::SandboxPolicy {
        let mut policy = openshell_policy::restrictive_default_policy();
        policy.network_policies.insert(
            "api".to_string(),
            openshell_core::proto::NetworkPolicyRule {
                name: "api".to_string(),
                endpoints: vec![openshell_core::proto::NetworkEndpoint {
                    host: "api.example.com".to_string(),
                    port: 443,
                    advisor_proposed,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        policy
    }

    async fn latest_policy(
        state: &ServerState,
        sandbox_id: &str,
    ) -> crate::persistence::PolicyRecord {
        state
            .store
            .get_latest_policy(sandbox_id)
            .await
            .unwrap()
            .expect("policy revision")
    }

    async fn create_child(state: &Arc<ServerState>, name: &str, parent: &str) -> Sandbox {
        handle_create_sandbox(
            state,
            authed_request(child_request(name, parent, SandboxSpec::default())),
        )
        .await
        .expect("child sandbox is created")
        .into_inner()
        .sandbox
        .expect("created sandbox")
    }

    fn child_request(name: &str, parent: &str, spec: SandboxSpec) -> CreateSandboxRequest {
        CreateSandboxRequest {
            parent: parent.to_string(),
            name: name.to_string(),
            spec: Some(spec),
            workspace_scope: Some(openshell_core::proto::workspace_selector(
                "default".to_string(),
            )),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn create_child_sandbox_records_its_parent() {
        let state = child_sandboxes_state().await;
        let lead_id = put_parent_record(&state, "lead", &[], None, false).await;

        let child = handle_create_sandbox(
            &state,
            authed_request(child_request("worker1", "lead", SandboxSpec::default())),
        )
        .await
        .expect("a child of a root sandbox is created")
        .into_inner()
        .sandbox
        .expect("created sandbox");

        assert_eq!(
            child.parent,
            Some(openshell_core::proto::SandboxParent {
                name: "lead".to_string(),
                id: lead_id,
            })
        );
    }

    #[tokio::test]
    async fn create_sandbox_records_its_creator() {
        let state = child_sandboxes_state().await;
        let root = handle_create_sandbox(
            &state,
            authed_request(child_request("lead", "", SandboxSpec::default())),
        )
        .await
        .expect("root sandbox is created")
        .into_inner()
        .sandbox
        .expect("created sandbox");
        put_policy_revision_with_status(
            &state,
            root.object_id(),
            1,
            &openshell_policy::restrictive_default_policy(),
            "loaded",
        )
        .await;
        let child = handle_create_sandbox(
            &state,
            authed_request(child_request("worker1", "lead", SandboxSpec::default())),
        )
        .await
        .expect("child sandbox is created")
        .into_inner()
        .sandbox
        .expect("created sandbox");

        assert_eq!(root.created_by, "dev-user");
        assert_eq!(child.created_by, "dev-user");
    }

    #[tokio::test]
    async fn child_without_providers_copies_the_parent_providers() {
        let state = child_sandboxes_state().await;
        put_parent_record(&state, "lead", &["a", "b"], None, false).await;

        let mut spec = SandboxSpec::default();
        resolve_create_parent(&state, "default", "lead", &mut spec)
            .await
            .expect("parent resolves");
        assert_eq!(spec.providers, vec!["a".to_string(), "b".to_string()]);

        let mut spec = SandboxSpec {
            providers: vec!["a".to_string()],
            ..Default::default()
        };
        resolve_create_parent(&state, "default", "lead", &mut spec)
            .await
            .expect("parent resolves");
        assert_eq!(spec.providers, vec!["a".to_string()]);
    }

    #[tokio::test]
    async fn child_provider_detached_before_the_lock_is_refused() {
        let state = child_sandboxes_state().await;
        let lead_id = put_parent_record(&state, "lead", &["a"], None, false).await;
        let parent = openshell_core::proto::SandboxParent {
            name: "lead".to_string(),
            id: lead_id,
        };

        // The child resolved its providers when the lead still had "b".
        let err = check_parent_has_room(
            &state,
            "default",
            &parent,
            &["a".to_string(), "b".to_string()],
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(
            err.message()
                .contains("provider 'b' is not attached to parent 'lead'"),
            "{}",
            err.message()
        );
        check_parent_has_room(&state, "default", &parent, &["a".to_string()])
            .await
            .expect("providers the lead still has are accepted");
    }

    #[tokio::test]
    async fn child_copies_the_policy_its_parent_enforces() {
        let state = child_sandboxes_state().await;
        let lead = handle_create_sandbox(
            &state,
            authed_request(child_request(
                "lead",
                "",
                SandboxSpec {
                    policy: Some(lead_policy(false)),
                    ..Default::default()
                },
            )),
        )
        .await
        .expect("root sandbox is created")
        .into_inner()
        .sandbox
        .expect("created sandbox");
        let lead_id = lead.object_id().to_string();
        super::super::policy::record_policy_apply_result(&state, &lead_id, 1, true, None, "test")
            .await
            .unwrap();

        let child = create_child(&state, "worker1", "lead").await;

        let lead_record = latest_policy(&state, &lead_id).await;
        let child_record = latest_policy(&state, child.object_id()).await;
        assert_eq!(child_record.version, 1);
        assert_eq!(
            super::super::policy::canonical_policy_record_identity(&child_record).unwrap(),
            super::super::policy::canonical_policy_record_identity(&lead_record).unwrap(),
        );
        assert_eq!(
            child_record.provenance.get(COPIED_FROM_PARENT_ID),
            Some(&lead_id)
        );
        assert_eq!(
            child_record.provenance.get(COPIED_FROM_PARENT_VERSION),
            Some(&"1".to_string())
        );
    }

    #[tokio::test]
    async fn child_copies_the_parent_loaded_revision_not_a_newer_one() {
        let mut state = child_sandboxes_state().await;
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .policy_validation_failure_mode =
            openshell_core::PolicyValidationFailureMode::RetainLastValid;
        let lead_id = put_parent_record(&state, "lead", &[], None, false).await;
        put_policy_revision_with_status(&state, &lead_id, 2, &lead_policy(false), "failed").await;
        put_policy_revision_with_status(&state, &lead_id, 3, &lead_policy(false), "pending").await;

        let child = create_child(&state, "worker1", "lead").await;

        let child_record = latest_policy(&state, child.object_id()).await;
        let (child_policy, _) =
            super::super::policy::canonical_policy_record_identity(&child_record).unwrap();
        assert!(
            child_policy.network_policies.is_empty(),
            "the child must not get the failed or pending revision"
        );
        assert_eq!(
            child_record.provenance.get(COPIED_FROM_PARENT_VERSION),
            Some(&"1".to_string())
        );
    }

    #[tokio::test]
    async fn child_of_a_fail_closed_parent_that_rejected_its_policy_is_refused() {
        let state = child_sandboxes_state().await;
        let lead_id = put_parent_record(&state, "lead", &[], None, false).await;
        put_policy_revision_with_status(&state, &lead_id, 2, &lead_policy(false), "failed").await;
        put_policy_revision_with_status(&state, &lead_id, 3, &lead_policy(false), "pending").await;

        let err = handle_create_sandbox(
            &state,
            authed_request(child_request("worker1", "lead", SandboxSpec::default())),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(
            err.message()
                .contains("parent sandbox 'lead' rejected its latest policy"),
            "{}",
            err.message()
        );
    }

    #[tokio::test]
    async fn child_of_a_parent_with_no_loaded_policy_is_refused() {
        let state = child_sandboxes_state().await;
        handle_create_sandbox(
            &state,
            authed_request(child_request(
                "lead",
                "",
                SandboxSpec {
                    policy: Some(lead_policy(false)),
                    ..Default::default()
                },
            )),
        )
        .await
        .expect("root sandbox is created");

        let err = handle_create_sandbox(
            &state,
            authed_request(child_request("worker1", "lead", SandboxSpec::default())),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(
            err.message()
                .contains("parent sandbox 'lead' has no policy yet"),
            "{}",
            err.message()
        );
    }

    #[tokio::test]
    async fn child_keeps_advisor_markers_from_an_approved_proposal() {
        let state = child_sandboxes_state().await;
        let lead_id = put_parent_record(&state, "lead", &[], None, false).await;
        // An approved proposal leaves its endpoints marked as advisor-proposed.
        put_policy_revision_with_status(&state, &lead_id, 2, &lead_policy(true), "loaded").await;

        let child = create_child(&state, "worker1", "lead").await;

        let child_record = latest_policy(&state, child.object_id()).await;
        let (child_policy, _) =
            super::super::policy::canonical_policy_record_identity(&child_record).unwrap();
        assert!(child_policy.network_policies["api"].endpoints[0].advisor_proposed);
        assert_eq!(
            child_record.provenance.get(COPIED_FROM_PARENT_VERSION),
            Some(&"2".to_string())
        );
    }

    fn delete_request(name: &str) -> DeleteSandboxRequest {
        DeleteSandboxRequest {
            request_id: String::new(),
            allow_missing: false,
            name: name.to_string(),
            workspace_scope: Some(openshell_core::proto::workspace_selector(
                "default".to_string(),
            )),
        }
    }

    #[tokio::test]
    async fn deleting_a_parent_with_live_children_is_refused() {
        let state = child_sandboxes_state().await;
        let lead_id = put_parent_record(&state, "lead", &[], None, false).await;
        let link = openshell_core::proto::SandboxParent {
            name: "lead".to_string(),
            id: lead_id.clone(),
        };
        put_parent_record(&state, "worker1", &[], Some(link.clone()), false).await;
        put_parent_record(&state, "worker2", &[], Some(link), false).await;

        let err = handle_delete_sandbox_inner(&state, authed_request(delete_request("lead")))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(
            err.message()
                .contains("sandbox 'lead' has 2 child sandboxes; delete them first"),
            "{}",
            err.message()
        );
        let lead = state
            .store
            .get_message::<Sandbox>(&lead_id)
            .await
            .unwrap()
            .expect("the refused parent still exists");
        assert!(
            lead.metadata.unwrap().deletion_time.is_none(),
            "a refused delete must not mark the parent as deleting"
        );
    }

    #[tokio::test]
    async fn children_already_being_deleted_do_not_block_the_parent() {
        let state = child_sandboxes_state().await;
        let lead_id = put_parent_record(&state, "lead", &[], None, false).await;
        put_parent_record(
            &state,
            "worker1",
            &[],
            Some(openshell_core::proto::SandboxParent {
                name: "lead".to_string(),
                id: lead_id,
            }),
            true,
        )
        .await;

        handle_delete_sandbox_inner(&state, authed_request(delete_request("lead")))
            .await
            .expect("only deleting children remain, so the parent can be deleted");
    }

    /// A root `lead` with one child `worker1`. Returns the child's id.
    async fn put_lead_and_worker(state: &ServerState) -> String {
        let lead_id = put_parent_record(state, "lead", &[], None, false).await;
        let link = openshell_core::proto::SandboxParent {
            name: "lead".to_string(),
            id: lead_id,
        };
        put_parent_record(state, "worker1", &[], Some(link), false).await
    }

    fn default_scope() -> openshell_core::proto::WorkspaceSelector {
        openshell_core::proto::workspace_selector("default".to_string())
    }

    /// A root `lead` with provider `work-github` and a child `worker1` created
    /// through the API, so the child has the provider and a current copy of
    /// the lead's v1. Returns both ids.
    async fn lead_and_child_sharing_a_provider(state: &Arc<ServerState>) -> (String, String) {
        state
            .store
            .put_message(&test_provider_with_credential_key(
                "work-github",
                "github",
                "GITHUB_TOKEN",
            ))
            .await
            .unwrap();
        let lead_id = put_parent_record(state, "lead", &["work-github"], None, false).await;
        let worker = create_child(state, "worker1", "lead").await;
        assert_eq!(worker.spec.as_ref().unwrap().providers, vec!["work-github"]);
        (lead_id, worker.object_id().to_string())
    }

    async fn sandbox_spec(state: &ServerState, sandbox_id: &str) -> SandboxSpec {
        state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .unwrap()
            .spec
            .unwrap()
    }

    async fn detach_from_lead(state: &Arc<ServerState>, provider: &str) {
        let response = handle_detach_sandbox_provider(
            state,
            authed_request(DetachSandboxProviderRequest {
                request_id: String::new(),
                sandbox: "lead".to_string(),
                workspace_scope: Some(default_scope()),
                provider: provider.to_string(),
                expected_resource_version: 0,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(response.detached);
    }

    /// A root `lead` with a child `worker1` whose `lead` record is then
    /// removed, as a downgraded gateway or a stalled delete can leave it.
    /// Returns both ids.
    async fn orphaned_child(state: &Arc<ServerState>) -> (String, String) {
        let (lead_id, worker_id) = lead_with_copied_child(state).await;
        state
            .store
            .delete(Sandbox::object_type(), &lead_id)
            .await
            .unwrap();
        (lead_id, worker_id)
    }

    #[tokio::test]
    async fn an_orphaned_child_is_refused_configuration() {
        let state = child_sandboxes_state().await;
        let (_, worker_id) = orphaned_child(&state).await;

        let config = child_config(&state, &worker_id).await;
        assert!(!config.configuration_admitted);
        assert!(
            config
                .configuration_error
                .contains("parent sandbox no longer exists"),
            "{}",
            config.configuration_error
        );
        assert_eq!(config.policy_validation_failure_mode, "fail_closed");
    }

    #[tokio::test]
    async fn an_orphaned_child_cannot_be_started_or_resumed() {
        let state = child_sandboxes_state().await;
        let (lead_id, _) = orphaned_child(&state).await;

        let start = handle_start_sandbox(
            &state,
            authed_request(StartSandboxRequest {
                request_id: String::new(),
                name: "worker1".to_string(),
                workspace_scope: Some(default_scope()),
            }),
        )
        .await
        .unwrap_err();
        let resume = handle_resume_sandbox(
            &state,
            authed_request(ResumeSandboxRequest {
                name: "worker1".to_string(),
                workspace_scope: Some(default_scope()),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        for err in [start, resume] {
            assert_eq!(err.code(), tonic::Code::FailedPrecondition);
            assert!(
                err.message().contains(&lead_id)
                    && err.message().contains("delete this child sandbox"),
                "{}",
                err.message()
            );
        }
    }

    #[tokio::test]
    async fn the_startup_scan_stops_an_orphaned_child_and_keeps_it() {
        let state = child_sandboxes_state().await;
        let (_, worker_id) = orphaned_child(&state).await;
        let mut running = state
            .store
            .get_message::<Sandbox>(&worker_id)
            .await
            .unwrap()
            .unwrap();
        running.set_phase(SandboxPhase::Ready as i32);
        state.store.put_message(&running).await.unwrap();

        sync_all_children(&state).await.unwrap();

        let worker = state
            .store
            .get_message::<Sandbox>(&worker_id)
            .await
            .unwrap()
            .expect("the orphan's record is kept");
        assert_eq!(
            SandboxPhase::try_from(worker.phase()).unwrap(),
            SandboxPhase::Stopped
        );
    }

    #[tokio::test]
    async fn a_new_root_under_the_old_name_does_not_adopt_an_orphan() {
        let state = child_sandboxes_state().await;
        let (_, worker_id) = orphaned_child(&state).await;
        let before = latest_policy(&state, &worker_id).await;
        let new_lead_id = put_parent_record(&state, "lead", &[], None, false).await;
        put_policy_revision_with_status(&state, &new_lead_id, 2, &lead_policy(false), "loaded")
            .await;
        let worker = state
            .store
            .get_message::<Sandbox>(&worker_id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            sync_one_child(&state, &worker).await.unwrap(),
            ChildSync::Orphaned
        );
        sync_all_children(&state).await.unwrap();

        let after = latest_policy(&state, &worker_id).await;
        assert_eq!(after.version, before.version, "nothing is copied");
        assert!(
            !child_config(&state, &worker_id)
                .await
                .configuration_admitted
        );
    }

    fn list_children_request(
        parent: &str,
        page_size: i32,
        page_token: String,
    ) -> ListSandboxesRequest {
        ListSandboxesRequest {
            page_size,
            page_token,
            label_selector: String::new(),
            parent: parent.to_string(),
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        }
    }

    fn listed_names(response: &ListSandboxesResponse) -> Vec<&str> {
        response
            .sandboxes
            .iter()
            .map(ObjectName::object_name)
            .collect()
    }

    #[tokio::test]
    async fn a_parent_filter_pages_through_only_that_parents_children() {
        let state = child_sandboxes_state().await;
        // Store order is creation time, then name: a-lead, b, c, d, e-other.
        let lead_id = put_parent_record(&state, "a-lead", &[], None, false).await;
        let link = openshell_core::proto::SandboxParent {
            name: "a-lead".to_string(),
            id: lead_id,
        };
        for name in ["b-child", "c-child", "d-child"] {
            put_parent_record(&state, name, &[], Some(link.clone()), false).await;
        }
        put_parent_record(&state, "e-other", &[], None, false).await;

        // Store pages of two are [a-lead, b-child] [c-child, d-child]
        // [e-other], so the first response fills on c-child, partway through
        // the second store page; d-child must still come next.
        let first = handle_list_sandboxes(
            &state,
            authed_request(list_children_request("a-lead", 2, String::new())),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(listed_names(&first), ["b-child", "c-child"]);
        assert!(!first.next_page_token.is_empty());

        let second = handle_list_sandboxes(
            &state,
            authed_request(list_children_request("a-lead", 2, first.next_page_token)),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(listed_names(&second), ["d-child"]);
        assert!(second.next_page_token.is_empty());
    }

    #[tokio::test]
    async fn a_parent_filter_does_not_list_an_old_roots_orphans() {
        let state = child_sandboxes_state().await;
        orphaned_child(&state).await;
        put_parent_record(&state, "lead", &[], None, false).await;

        let listed = handle_list_sandboxes(
            &state,
            authed_request(list_children_request("lead", 100, String::new())),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(listed.sandboxes.is_empty());
    }

    #[tokio::test]
    async fn a_sandbox_caller_lists_only_its_own_children_whatever_it_asks_for() {
        let state = child_sandboxes_state().await;
        let lead_id = put_parent_record(&state, "lead", &[], None, false).await;
        let other_id = put_parent_record(&state, "other", &[], None, false).await;
        for (name, parent, id) in [
            ("w1", "lead", &lead_id),
            ("w2", "lead", &lead_id),
            ("x1", "other", &other_id),
        ] {
            let link = openshell_core::proto::SandboxParent {
                name: parent.to_string(),
                id: id.clone(),
            };
            put_parent_record(&state, name, &[], Some(link), false).await;
        }

        // Another root's name and every workspace are both ignored.
        let mut request = list_children_request("other", 100, String::new());
        request.workspace_scope = Some(openshell_core::proto::all_workspaces_selector());
        let listed = handle_list_sandboxes(&state, sandbox_request(&lead_id, request))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed_names(&listed), ["w1", "w2"]);
    }

    /// Call an MCP tool as the sandbox `caller_id`, through the real gRPC
    /// stack and handlers, and return the tool result.
    async fn call_mcp_tool(
        state: &Arc<ServerState>,
        caller_id: &str,
        tool: &str,
        arguments: serde_json::Value,
    ) -> serde_json::Value {
        call_mcp_as(
            state,
            sandbox_caller(caller_id),
            None,
            None,
            tool,
            arguments,
        )
        .await
    }

    fn sandbox_caller(sandbox_id: &str) -> crate::auth::principal::Principal {
        use crate::auth::principal::{Principal, SandboxIdentitySource, SandboxPrincipal};

        Principal::Sandbox(SandboxPrincipal {
            sandbox_id: sandbox_id.to_string(),
            source: SandboxIdentitySource::BootstrapJwt {
                issuer: "openshell-gateway:test".to_string(),
                auth_epoch: None,
            },
            trust_domain: Some("openshell".to_string()),
        })
    }

    /// Call one MCP tool as `caller` through the real router and handlers,
    /// with an RBAC policy and a bridge workspace header when given.
    async fn call_mcp_as(
        state: &Arc<ServerState>,
        caller: crate::auth::principal::Principal,
        authz_policy: Option<crate::auth::authz::AuthzPolicy>,
        workspace: Option<&str>,
        tool: &str,
        arguments: serde_json::Value,
    ) -> serde_json::Value {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        });
        post_mcp_as(state, caller, authz_policy, workspace, body).await["result"].clone()
    }

    /// Post one JSON-RPC message to `/mcp` as `caller` through the real
    /// router and handlers, and return the whole reply.
    async fn post_mcp_as(
        state: &Arc<ServerState>,
        caller: crate::auth::principal::Principal,
        authz_policy: Option<crate::auth::authz::AuthzPolicy>,
        workspace: Option<&str>,
        body: serde_json::Value,
    ) -> serde_json::Value {
        use crate::auth::authenticator::test_support::MockAuthenticator;
        use crate::auth::authenticator::{Authentication, AuthenticatorChain};
        use tower::ServiceExt;

        let chain = AuthenticatorChain::new(vec![Arc::new(MockAuthenticator::returning(Ok(
            Authentication::Accepted(caller),
        )))]);
        let stack = crate::multiplex::AuthGrpcRouter::new(
            openshell_core::proto::open_shell_server::OpenShellServer::new(
                crate::OpenShellService::new(state.clone()),
            ),
            Some(chain),
            authz_policy,
        );
        let connection = crate::mcp::McpConnection::new(stack.caller_authenticator(), stack)
            .with_short_create_wait()
            .with_store(state.store.clone());
        let mut request = http::Request::post("/mcp")
            .header("content-type", "application/json")
            .header("authorization", "Bearer caller-token");
        if let Some(workspace) = workspace {
            request = request.header("x-openshell-workspace", workspace);
        }
        let response = crate::mcp::router()
            .layer(axum::Extension(connection))
            .oneshot(
                request
                    .body(axum::body::Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let reply: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        reply
    }

    #[tokio::test]
    async fn mcp_list_reaches_the_handler_through_the_grpc_stack() {
        let state = child_sandboxes_state().await;
        let lead_id = put_parent_record(&state, "lead", &[], None, false).await;
        let link = openshell_core::proto::SandboxParent {
            name: "lead".to_string(),
            id: lead_id.clone(),
        };
        put_parent_record(&state, "w1", &[], Some(link), false).await;

        let result = call_mcp_tool(&state, &lead_id, "list", serde_json::json!({})).await;
        assert_eq!(result["isError"], false, "{result}");
        let names: Vec<_> = result["structuredContent"]["sandboxes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|child| child["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["w1"]);
    }

    /// Record `subject` as the creator of sandbox `id`.
    async fn set_creator(state: &ServerState, id: &str, subject: &str) {
        let mut sandbox = state
            .store
            .get_message::<Sandbox>(id)
            .await
            .unwrap()
            .unwrap();
        sandbox.created_by = subject.to_string();
        state.store.put_message(&sandbox).await.unwrap();
    }

    async fn put_member(state: &ServerState, subject: &str) {
        state
            .store
            .put_message(&openshell_core::proto::WorkspaceMember {
                metadata: Some(ObjectMeta {
                    id: uuid::Uuid::new_v4().to_string(),
                    name: subject.to_string(),
                    workspace: "default".to_string(),
                    ..Default::default()
                }),
                principal_subject: subject.to_string(),
                role: openshell_core::proto::WorkspaceRole::User.into(),
            })
            .await
            .unwrap();
    }

    /// A root created by a workspace member, ready to create children.
    async fn member_root(state: &Arc<ServerState>, name: &str, providers: &[&str]) -> String {
        let id = put_parent_record(state, name, providers, None, false).await;
        put_member(state, "alice").await;
        set_creator(state, &id, "alice").await;
        id
    }

    fn sandbox_child_request(name: &str) -> CreateSandboxRequest {
        CreateSandboxRequest {
            name: name.to_string(),
            spec: Some(SandboxSpec::default()),
            ..Default::default()
        }
    }

    fn quantities(pairs: &[(&str, &str)]) -> Value {
        let fields = pairs
            .iter()
            .map(|(name, quantity)| {
                let value = Value {
                    kind: Some(Kind::StringValue((*quantity).to_string())),
                };
                ((*name).to_string(), value)
            })
            .collect();
        Value {
            kind: Some(Kind::StructValue(Struct { fields })),
        }
    }

    fn resources(sections: &[(&str, Value)]) -> Struct {
        Struct {
            fields: sections
                .iter()
                .map(|(section, value)| ((*section).to_string(), value.clone()))
                .collect(),
        }
    }

    /// Give the root a template, as `sandbox create --from` would.
    async fn set_root_template(state: &Arc<ServerState>, id: &str, template: SandboxTemplate) {
        let mut root = state
            .store
            .get_message::<Sandbox>(id)
            .await
            .unwrap()
            .unwrap();
        root.spec.as_mut().unwrap().template = Some(template);
        state.store.put_message(&root).await.unwrap();
    }

    fn isolated_template() -> SandboxTemplate {
        SandboxTemplate {
            image: "registry.example.com/lead:1".to_string(),
            runtime_class_name: "gvisor".to_string(),
            user_namespaces: Some(true),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_sandbox_caller_child_copies_image_cpu_memory_and_isolation_only() {
        let state = child_sandboxes_state().await;
        let lead_id = member_root(&state, "lead", &[]).await;
        let mut lead = state
            .store
            .get_message::<Sandbox>(&lead_id)
            .await
            .unwrap()
            .unwrap();
        let lead_resources = resources(&[
            (
                "limits",
                quantities(&[("cpu", "2"), ("memory", "4Gi"), ("nvidia.com/gpu", "1")]),
            ),
            (
                "requests",
                quantities(&[("cpu", "1"), ("example.com/fpga", "1")]),
            ),
            ("claims", quantities(&[("gpu", "a100")])),
        ]);
        let spec = lead.spec.as_mut().unwrap();
        spec.template = Some(SandboxTemplate {
            resources: Some(lead_resources),
            labels: HashMap::from([("team".to_string(), "a".to_string())]),
            agent_socket: "/run/agent.sock".to_string(),
            ..isolated_template()
        });
        spec.resource_requirements = Some(ResourceRequirements {
            gpu: Some(GpuResourceRequirements { count: Some(1) }),
        });
        spec.environment = HashMap::from([("SECRET_MODE".to_string(), "on".to_string())]);
        lead.metadata.as_mut().unwrap().labels =
            HashMap::from([("team".to_string(), "a".to_string())]);
        state.store.put_message(&lead).await.unwrap();

        let child = handle_create_sandbox(
            &state,
            sandbox_request(&lead_id, sandbox_child_request("worker")),
        )
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();

        assert_eq!(child.parent.as_ref().unwrap().id, lead_id);
        assert_eq!(child.object_workspace(), "default");
        let spec = child.spec.as_ref().unwrap();
        let template = spec.template.as_ref().unwrap();
        assert_eq!(template.image, "registry.example.com/lead:1");
        assert_eq!(
            template.resources,
            Some(resources(&[
                ("limits", quantities(&[("cpu", "2"), ("memory", "4Gi")])),
                ("requests", quantities(&[("cpu", "1")])),
            ])),
            "only CPU and memory are copied"
        );
        assert_eq!(template.runtime_class_name, "gvisor");
        assert_eq!(template.user_namespaces, Some(true));
        assert!(template.labels.is_empty());
        assert!(template.agent_socket.is_empty());
        assert!(spec.resource_requirements.is_none(), "no GPU is copied");
        assert!(spec.environment.is_empty());
        assert!(child.metadata.as_ref().unwrap().labels.is_empty());
    }

    #[tokio::test]
    async fn a_sandbox_caller_may_set_only_name_template_and_providers() {
        let state = child_sandboxes_state().await;
        let lead_id = member_root(&state, "lead", &[]).await;
        let with_spec = |spec: SandboxSpec| CreateSandboxRequest {
            spec: Some(spec),
            ..sandbox_child_request("worker")
        };
        for (request, field) in [
            (
                CreateSandboxRequest {
                    workspace_scope: Some(openshell_core::proto::workspace_selector(
                        "other".to_string(),
                    )),
                    ..sandbox_child_request("worker")
                },
                "workspace_scope",
            ),
            (
                CreateSandboxRequest {
                    parent: "lead".to_string(),
                    ..sandbox_child_request("worker")
                },
                "parent",
            ),
            (
                CreateSandboxRequest {
                    labels: HashMap::from([("a".to_string(), "b".to_string())]),
                    ..sandbox_child_request("worker")
                },
                "labels",
            ),
            (
                with_spec(SandboxSpec {
                    template: Some(SandboxTemplate {
                        image: "evil".to_string(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                "spec.template",
            ),
            (
                with_spec(SandboxSpec {
                    environment: HashMap::from([("A".to_string(), "b".to_string())]),
                    ..Default::default()
                }),
                "spec.environment",
            ),
            (
                with_spec(SandboxSpec {
                    command: vec!["sh".to_string()],
                    ..Default::default()
                }),
                "spec.command",
            ),
            (
                with_spec(SandboxSpec {
                    policy: Some(openshell_policy::restrictive_default_policy()),
                    ..Default::default()
                }),
                "spec.policy",
            ),
        ] {
            let err = handle_create_sandbox(&state, sandbox_request(&lead_id, request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument, "{field}");
            assert_eq!(
                err.message(),
                format!("field '{field}' is not allowed for sandbox callers")
            );
        }
    }

    #[test]
    fn the_backstop_refuses_fields_the_named_checks_miss() {
        // Checked on its own, as for a field added to the request later.
        let allowed = CreateSandboxRequest {
            spec: Some(SandboxSpec {
                providers: vec!["github".to_string()],
                ..Default::default()
            }),
            workload_template: "agents".to_string(),
            ..sandbox_child_request("worker")
        };
        refuse_unlisted_fields_for_sandbox_caller(&allowed).unwrap();
        for request in [
            CreateSandboxRequest {
                request_id: "r1".to_string(),
                ..allowed.clone()
            },
            CreateSandboxRequest {
                spec: Some(SandboxSpec {
                    resource_requirements: Some(ResourceRequirements {
                        gpu: Some(GpuResourceRequirements { count: Some(1) }),
                    }),
                    ..Default::default()
                }),
                ..allowed
            },
        ] {
            let err = refuse_unlisted_fields_for_sandbox_caller(&request).unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument);
            assert_eq!(
                err.message(),
                "the request sets fields that are not allowed for sandbox callers"
            );
        }
    }

    #[tokio::test]
    async fn a_sandbox_caller_uses_only_templates_made_available_to_agents() {
        let state = child_sandboxes_state().await;
        let lead_id = member_root(&state, "lead", &[]).await;
        let put_template = |name: &str, labelled: bool, driver_config: bool| {
            let mut template = test_workload_template(name);
            let metadata = template.metadata.as_mut().unwrap();
            metadata.id = uuid::Uuid::new_v4().to_string();
            metadata.workspace = "default".to_string();
            if labelled {
                metadata
                    .labels
                    .insert(AGENT_USABLE_TEMPLATE_LABEL.to_string(), "true".to_string());
            }
            if driver_config {
                template.spec.as_mut().unwrap().driver_config = Some(Struct::default());
            }
            let state = state.clone();
            async move { state.store.put_message(&template).await.unwrap() }
        };
        put_template("agents", true, false).await;
        put_template("unlabelled", false, false).await;
        put_template("driver", true, true).await;
        let from_template = |name: &str, template: &str| CreateSandboxRequest {
            workload_template: template.to_string(),
            ..sandbox_child_request(name)
        };

        let child = handle_create_sandbox(
            &state,
            sandbox_request(&lead_id, from_template("w1", "agents")),
        )
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
        let template = child.spec.as_ref().unwrap().template.as_ref().unwrap();
        assert_eq!(template.image, "registry.example.com/agent:latest");

        // A template child still runs with the root's isolation settings.
        set_root_template(&state, &lead_id, isolated_template()).await;
        let child = handle_create_sandbox(
            &state,
            sandbox_request(&lead_id, from_template("w3", "agents")),
        )
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
        let template = child.spec.as_ref().unwrap().template.as_ref().unwrap();
        assert_eq!(template.image, "registry.example.com/agent:latest");
        assert_eq!(template.runtime_class_name, "gvisor");
        assert_eq!(template.user_namespaces, Some(true));

        for name in ["unlabelled", "driver", "missing"] {
            let err =
                handle_create_sandbox(&state, sandbox_request(&lead_id, from_template("w2", name)))
                    .await
                    .unwrap_err();
            assert_eq!(err.code(), tonic::Code::FailedPrecondition, "{name}");
            assert_eq!(
                err.message(),
                format!("template '{name}' is not available to agents")
            );
        }
    }

    /// Store a template in `workspace`, labelled for agents when `labelled`,
    /// with driver configuration when `driver_config`.
    async fn put_agent_template(
        state: &Arc<ServerState>,
        workspace: &str,
        name: &str,
        labelled: bool,
        driver_config: bool,
    ) {
        let mut template = test_workload_template(name);
        let metadata = template.metadata.as_mut().unwrap();
        metadata.id = uuid::Uuid::new_v4().to_string();
        metadata.workspace = workspace.to_string();
        if labelled {
            metadata
                .labels
                .insert(AGENT_USABLE_TEMPLATE_LABEL.to_string(), "true".to_string());
        }
        if driver_config {
            template.spec.as_mut().unwrap().driver_config = Some(Struct::default());
        }
        state.store.put_message(&template).await.unwrap();
    }

    #[tokio::test]
    async fn a_sandbox_caller_lists_only_templates_made_available_to_agents() {
        let state = child_sandboxes_state().await;
        let lead_id = member_root(&state, "lead", &[]).await;
        put_agent_template(&state, "default", "agents", true, false).await;
        put_agent_template(&state, "default", "unlabelled", false, false).await;
        put_agent_template(&state, "default", "driver", true, true).await;
        put_agent_template(&state, "other", "elsewhere", true, false).await;

        // Whatever scope or selector the request names.
        let request = ListSandboxTemplatesRequest {
            workspace_scope: Some(openshell_core::proto::all_workspaces_selector()),
            label_selector: "team=runtime".to_string(),
            ..Default::default()
        };
        let listed = handle_list_sandbox_templates(&state, sandbox_request(&lead_id, request))
            .await
            .unwrap()
            .into_inner();
        let names: Vec<&str> = listed
            .templates
            .iter()
            .map(ObjectName::object_name)
            .collect();
        assert_eq!(names, ["agents"]);
        let workload = listed.templates[0]
            .spec
            .as_ref()
            .unwrap()
            .workload
            .as_ref()
            .unwrap();
        assert_eq!(workload.image, "registry.example.com/agent:latest");
        assert!(workload.environment.is_empty(), "environment is withheld");
    }

    #[tokio::test]
    async fn mcp_tools_list_offers_a_sandbox_its_agent_templates() {
        let state = child_sandboxes_state().await;
        let lead_id = member_root(&state, "lead", &[]).await;
        put_agent_template(&state, "default", "agents", true, false).await;
        put_agent_template(&state, "default", "unlabelled", false, false).await;

        let reply = post_mcp_as(
            &state,
            sandbox_caller(&lead_id),
            None,
            None,
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        )
        .await;
        let create = reply["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "create_sandbox")
            .unwrap();
        let template = &create["inputSchema"]["properties"]["template"];
        assert_eq!(template["enum"], serde_json::json!(["agents"]), "{create}");
        let description = create["description"].as_str().unwrap();
        assert!(
            description.contains("agents (image registry.example.com/agent:latest)"),
            "{description}"
        );
        assert!(!description.contains("unlabelled"), "{description}");
    }

    #[test]
    fn a_child_keeps_isolation_its_template_asked_for() {
        let plain_root = Sandbox {
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate::default()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut child = isolated_template();
        copy_isolation_from_caller(&plain_root, &mut child);
        assert_eq!(child.runtime_class_name, "gvisor");
        assert_eq!(child.user_namespaces, Some(true));

        let kata_root = Sandbox {
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    runtime_class_name: "kata".to_string(),
                    user_namespaces: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut child = isolated_template();
        copy_isolation_from_caller(&kata_root, &mut child);
        assert_eq!(child.runtime_class_name, "kata", "the root's class wins");
        assert_eq!(child.user_namespaces, Some(true), "never turned off");
    }

    #[tokio::test]
    async fn a_root_with_driver_config_cannot_create_children_over_mcp() {
        let state = child_sandboxes_state().await;
        let lead_id = member_root(&state, "lead", &[]).await;
        set_root_template(
            &state,
            &lead_id,
            SandboxTemplate {
                driver_config: Some(Struct::default()),
                ..isolated_template()
            },
        )
        .await;

        let err = handle_create_sandbox(
            &state,
            sandbox_request(&lead_id, sandbox_child_request("worker")),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            err.message(),
            "this sandbox has driver configuration, which children cannot copy"
        );
    }

    #[tokio::test]
    async fn a_sandbox_caller_child_may_not_take_a_provider_its_parent_lacks() {
        let state = child_sandboxes_state().await;
        let lead_id = member_root(&state, "lead", &["github"]).await;
        let request = CreateSandboxRequest {
            spec: Some(SandboxSpec {
                providers: vec!["gitlab".to_string()],
                ..Default::default()
            }),
            ..sandbox_child_request("worker")
        };
        let err = handle_create_sandbox(&state, sandbox_request(&lead_id, request))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            err.message(),
            "provider 'gitlab' is not attached to parent 'lead'"
        );
    }

    #[tokio::test]
    async fn a_sandbox_caller_needs_a_creator_who_still_has_access() {
        let mut state = member_checked_state().await;
        let create = |state: Arc<ServerState>, id: String, name: &'static str| async move {
            handle_create_sandbox(&state, sandbox_request(&id, sandbox_child_request(name))).await
        };

        let no_creator = put_parent_record(&state, "no-creator", &[], None, false).await;
        let err = create(state.clone(), no_creator, "w1").await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            err.message(),
            "this sandbox was not started by a workspace user, so it cannot create children"
        );

        let lost = put_parent_record(&state, "lost", &[], None, false).await;
        set_creator(&state, &lost, "bob").await;
        let err = create(state.clone(), lost, "w2").await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            err.message(),
            "the user who started this sandbox is not a member of workspace 'default' with \
             the user role; a platform admin can add them with: openshell workspace member \
             add --workspace default --subject <user> --role user"
        );

        let member = member_root(&state, "member", &[]).await;
        create(state.clone(), member, "w3").await.unwrap();

        // The built-in development user counts only while such users are
        // allowed, checked at each create.
        let dev = put_parent_record(&state, "dev", &[], None, false).await;
        set_creator(&state, &dev, crate::multiplex::UNAUTHENTICATED_DEV_SUBJECT).await;
        let err = create(state.clone(), dev.clone(), "w4").await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .auth
            .allow_unauthenticated_users = true;
        create(state.clone(), dev, "w5").await.unwrap();
    }

    /// With no admin role configured every authenticated user is a platform
    /// admin, so a creator needs no membership; a root with no recorded
    /// creator is still refused.
    #[tokio::test]
    async fn a_creator_needs_no_membership_when_no_admin_role_is_configured() {
        let state = child_sandboxes_state().await;
        assert!(state.admin_role.is_empty());

        let lead = put_parent_record(&state, "lead", &[], None, false).await;
        set_creator(&state, &lead, "bob").await;
        handle_create_sandbox(&state, sandbox_request(&lead, sandbox_child_request("w1")))
            .await
            .unwrap();

        let no_creator = put_parent_record(&state, "no-creator", &[], None, false).await;
        let err = handle_create_sandbox(
            &state,
            sandbox_request(&no_creator, sandbox_child_request("w2")),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn an_mcp_child_records_the_root_that_created_it() {
        let state = child_sandboxes_state().await;
        let lead_id = member_root(&state, "lead", &[]).await;

        let child = handle_create_sandbox(
            &state,
            sandbox_request(&lead_id, sandbox_child_request("worker")),
        )
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();

        // The lead decided, so the child names the lead; the lead names the
        // user it acts for.
        let by_lead = format!("sandbox:{lead_id}");
        assert_eq!(child.created_by, by_lead);
        assert_eq!(
            sandbox_record(&state, child.object_id()).await.created_by,
            by_lead,
            "stored, not only returned"
        );
        assert_eq!(sandbox_record(&state, &lead_id).await.created_by, "alice");
    }

    #[tokio::test]
    async fn an_audit_event_records_the_user_a_sandbox_acts_for() {
        let state = child_sandboxes_state().await;
        let lead_id = member_root(&state, "lead", &[]).await;
        let unknown_root = put_parent_record(&state, "old-root", &[], None, false).await;
        let stack = crate::multiplex::AuthGrpcRouter::new(
            openshell_core::proto::open_shell_server::OpenShellServer::new(
                crate::OpenShellService::new(state.clone()),
            ),
            None,
            None,
        );
        let connection = crate::mcp::McpConnection::new(stack.caller_authenticator(), stack);

        // Without a store, and for a root without a creator, it is unknown.
        assert_eq!(
            crate::mcp::acting_for(&connection, &lead_id).await,
            "unknown"
        );
        let connection = connection.with_store(state.store.clone());
        assert_eq!(crate::mcp::acting_for(&connection, &lead_id).await, "alice");
        assert_eq!(
            crate::mcp::acting_for(&connection, &unknown_root).await,
            "unknown"
        );
        assert_eq!(
            crate::mcp::acting_for(&connection, "missing").await,
            "unknown"
        );
    }

    #[tokio::test]
    async fn a_child_sandbox_cannot_create_children() {
        let state = child_sandboxes_state().await;
        let lead_id = member_root(&state, "lead", &[]).await;
        let link = openshell_core::proto::SandboxParent {
            name: "lead".to_string(),
            id: lead_id,
        };
        let child_id = put_parent_record(&state, "child", &[], Some(link), false).await;
        set_creator(&state, &child_id, "alice").await;
        let err = handle_create_sandbox(
            &state,
            sandbox_request(&child_id, sandbox_child_request("grandchild")),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            err.message(),
            "only root sandboxes can create child sandboxes"
        );
    }

    #[tokio::test]
    async fn a_sandbox_caller_execs_only_in_its_own_children() {
        let state = child_sandboxes_state().await;
        let lead_id = member_root(&state, "lead", &[]).await;
        let other_id = put_parent_record(&state, "other", &[], None, false).await;
        for (name, parent, id) in [("mine", "lead", &lead_id), ("theirs", "other", &other_id)] {
            let link = openshell_core::proto::SandboxParent {
                name: parent.to_string(),
                id: id.clone(),
            };
            put_parent_record(&state, name, &[], Some(link), false).await;
        }
        let exec = |name: &str| ExecSandboxRequest {
            sandbox: name.to_string(),
            command: vec!["ls".to_string()],
            ..Default::default()
        };

        for name in ["theirs", "other", "lead", "missing"] {
            let err = handle_exec_sandbox(&state, sandbox_request(&lead_id, exec(name)))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound, "{name}");
            assert_eq!(err.message(), format!("sandbox '{name}' not found"));
        }

        // Its own child is found; this one is not ready yet.
        let err = handle_exec_sandbox(&state, sandbox_request(&lead_id, exec("mine")))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert_eq!(err.message(), "sandbox is not ready");

        for (request, field) in [
            (
                ExecSandboxRequest {
                    environment: HashMap::from([("A".to_string(), "b".to_string())]),
                    ..exec("mine")
                },
                "environment",
            ),
            (
                ExecSandboxRequest {
                    tty: true,
                    ..exec("mine")
                },
                "tty",
            ),
            (
                ExecSandboxRequest {
                    cols: 80,
                    ..exec("mine")
                },
                "cols",
            ),
            (
                ExecSandboxRequest {
                    rows: 24,
                    ..exec("mine")
                },
                "rows",
            ),
        ] {
            let err = handle_exec_sandbox(&state, sandbox_request(&lead_id, request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument, "{field}");
            assert_eq!(
                err.message(),
                format!("field '{field}' is not allowed for sandbox callers")
            );
        }
    }

    fn sandbox_principal_for(sandbox_id: &str) -> crate::auth::principal::SandboxPrincipal {
        let request = sandbox_request(sandbox_id, ());
        match request
            .extensions()
            .get::<crate::auth::principal::Principal>()
        {
            Some(crate::auth::principal::Principal::Sandbox(principal)) => principal.clone(),
            _ => unreachable!("sandbox_request sets a sandbox principal"),
        }
    }

    #[tokio::test]
    async fn a_sandbox_caller_deletes_only_its_own_children() {
        let state = child_sandboxes_state().await;
        let lead_id = member_root(&state, "lead", &[]).await;
        let other_id = put_parent_record(&state, "other", &[], None, false).await;
        for (name, parent, id) in [("mine", "lead", &lead_id), ("theirs", "other", &other_id)] {
            let link = openshell_core::proto::SandboxParent {
                name: parent.to_string(),
                id: id.clone(),
            };
            put_parent_record(&state, name, &[], Some(link), false).await;
        }
        let delete = |name: &str| DeleteSandboxRequest {
            name: name.to_string(),
            ..Default::default()
        };

        for name in ["theirs", "other", "lead", "missing"] {
            let err = handle_delete_sandbox(&state, sandbox_request(&lead_id, delete(name)))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound, "{name}");
            assert_eq!(err.message(), format!("sandbox '{name}' not found"));
        }
        for (request, field) in [
            (
                DeleteSandboxRequest {
                    allow_missing: true,
                    ..delete("mine")
                },
                "allow_missing",
            ),
            (
                DeleteSandboxRequest {
                    workspace_scope: Some(openshell_core::proto::workspace_selector(
                        "default".to_string(),
                    )),
                    ..delete("mine")
                },
                "workspace_scope",
            ),
        ] {
            let err = handle_delete_sandbox(&state, sandbox_request(&lead_id, request))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument, "{field}");
            assert_eq!(
                err.message(),
                format!("field '{field}' is not allowed for sandbox callers")
            );
        }

        handle_delete_sandbox(&state, sandbox_request(&lead_id, delete("mine")))
            .await
            .expect("its own child is deleted");
        // Deleting a root with children is refused for users; "other" still
        // has its child, so the sandbox caller's delete reached only "mine".
        assert!(
            state
                .store
                .get_message_by_name::<Sandbox>("default", "theirs")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_reused_name_is_not_deleted_in_place_of_the_checked_child() {
        let state = child_sandboxes_state().await;
        let lead_id = member_root(&state, "lead", &[]).await;
        let link = openshell_core::proto::SandboxParent {
            name: "lead".to_string(),
            id: lead_id.clone(),
        };
        let checked_id = put_parent_record(&state, "w", &[], Some(link), false).await;
        let caller = sandbox_principal_for(&lead_id);

        // While the checked child still holds the name, a conflict is
        // reported as it is.
        let conflict = Status::aborted("some other conflict");
        let status =
            aborted_child_delete(&state, &caller, "w", &checked_id, conflict.clone()).await;
        assert_eq!(status.code(), tonic::Code::Aborted);

        // The name now belongs to another root: the delete bound to the
        // checked id is refused and the new sandbox survives.
        state
            .store
            .delete(Sandbox::object_type(), &checked_id)
            .await
            .unwrap();
        let reused_id = put_parent_record(&state, "w", &[], None, false).await;
        let err = state
            .compute
            .delete_sandbox_allow_missing_with_preconditions(
                "default",
                "w",
                false,
                SandboxDeletePreconditions {
                    expected_sandbox_id: Some(checked_id.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Aborted);
        assert!(
            state
                .store
                .get_message::<Sandbox>(&reused_id)
                .await
                .unwrap()
                .is_some()
        );

        // ...and the agent is told its child is gone.
        let status = aborted_child_delete(&state, &caller, "w", &checked_id, err).await;
        assert_eq!(status.code(), tonic::Code::NotFound);
        assert_eq!(status.message(), "sandbox 'w' not found");
    }

    #[tokio::test]
    async fn a_sandbox_caller_reads_only_its_own_childs_own_lines() {
        use openshell_core::proto::{GetSandboxLogsRequest, SandboxLogLine};
        let state = child_sandboxes_state().await;
        let lead_id = member_root(&state, "lead", &[]).await;
        let other_id = put_parent_record(&state, "other", &[], None, false).await;
        let mut child_id = String::new();
        for (name, parent, id) in [("mine", "lead", &lead_id), ("theirs", "other", &other_id)] {
            let link = openshell_core::proto::SandboxParent {
                name: parent.to_string(),
                id: id.clone(),
            };
            let id = put_parent_record(&state, name, &[], Some(link), false).await;
            if name == "mine" {
                child_id = id;
            }
        }
        let logs = |name: &str, lines: u32| GetSandboxLogsRequest {
            sandbox: name.to_string(),
            lines,
            ..Default::default()
        };

        for name in ["theirs", "other", "lead", "missing"] {
            let err = crate::grpc::policy::handle_get_sandbox_logs(
                &state,
                sandbox_request(&lead_id, logs(name, 10)),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound, "{name}");
        }
        for (request, field) in [
            (
                GetSandboxLogsRequest {
                    sources: vec!["gateway".to_string()],
                    ..logs("mine", 10)
                },
                "sources",
            ),
            (
                GetSandboxLogsRequest {
                    min_level: "ERROR".to_string(),
                    ..logs("mine", 10)
                },
                "min_level",
            ),
        ] {
            let err = crate::grpc::policy::handle_get_sandbox_logs(
                &state,
                sandbox_request(&lead_id, request),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument, "{field}");
            assert_eq!(
                err.message(),
                format!("field '{field}' is not allowed for sandbox callers")
            );
        }

        // The child is not ready; its newest sandbox lines still come back,
        // counted after the gateway lines between them are dropped.
        for i in 0..6 {
            for source in ["sandbox", "gateway"] {
                state.tracing_log_bus.publish_external(SandboxLogLine {
                    sandbox_id: child_id.clone(),
                    level: "INFO".to_string(),
                    message: format!("{source} {i}"),
                    source: source.to_string(),
                    ..Default::default()
                });
            }
        }
        let reply = crate::grpc::policy::handle_get_sandbox_logs(
            &state,
            sandbox_request(&lead_id, logs("mine", 4)),
        )
        .await
        .unwrap()
        .into_inner();
        let messages: Vec<_> = reply.logs.iter().map(|log| log.message.as_str()).collect();
        assert_eq!(
            messages,
            ["sandbox 2", "sandbox 3", "sandbox 4", "sandbox 5"]
        );
    }

    #[tokio::test]
    async fn mcp_create_retry_returns_the_child_even_at_the_limit() {
        let state = child_sandboxes_state_with_limit(1).await;
        let lead_id = member_root(&state, "lead", &[]).await;

        // The child never becomes ready here, so the short wait times out,
        // and that is not an error.
        let first = call_mcp_tool(
            &state,
            &lead_id,
            "create_sandbox",
            serde_json::json!({"name": "w1"}),
        )
        .await;
        assert_eq!(first["isError"], false, "{first}");
        let reply = &first["structuredContent"];
        assert_eq!(reply["name"], "w1");
        assert_eq!(reply["already_existed"], false);
        assert_eq!(reply["timed_out"], true);

        let retry = call_mcp_tool(
            &state,
            &lead_id,
            "create_sandbox",
            serde_json::json!({"name": "w1"}),
        )
        .await;
        assert_eq!(retry["isError"], false, "{retry}");
        assert_eq!(retry["structuredContent"]["already_existed"], true);
    }

    #[tokio::test]
    async fn mcp_create_refuses_a_name_that_is_not_the_callers_child() {
        let state = child_sandboxes_state().await;
        let lead_id = member_root(&state, "lead", &[]).await;
        put_parent_record(&state, "other-root", &[], None, false).await;

        let result = call_mcp_tool(
            &state,
            &lead_id,
            "create_sandbox",
            serde_json::json!({"name": "other-root"}),
        )
        .await;
        assert_eq!(result["isError"], true, "{result}");
        assert_eq!(result["structuredContent"]["error"], "already_exists");
        assert_eq!(
            result["structuredContent"]["message"],
            "a sandbox named 'other-root' already exists in this workspace"
        );
    }

    #[tokio::test]
    async fn mcp_create_reports_a_failed_child() {
        let state = child_sandboxes_state().await;
        let lead_id = member_root(&state, "lead", &[]).await;
        let link = openshell_core::proto::SandboxParent {
            name: "lead".to_string(),
            id: lead_id.clone(),
        };
        let child_id = put_parent_record(&state, "w1", &[], Some(link), false).await;
        let mut child = state
            .store
            .get_message::<Sandbox>(&child_id)
            .await
            .unwrap()
            .unwrap();
        child.set_phase(SandboxPhase::Error as i32);
        child.status.get_or_insert_with(Default::default).conditions =
            vec![openshell_core::proto::SandboxCondition {
                r#type: "Ready".to_string(),
                status: "False".to_string(),
                message: "image pull failed".to_string(),
                ..Default::default()
            }];
        state.store.put_message(&child).await.unwrap();

        let result = call_mcp_tool(
            &state,
            &lead_id,
            "create_sandbox",
            serde_json::json!({"name": "w1"}),
        )
        .await;
        assert_eq!(result["isError"], true, "{result}");
        assert_eq!(
            result["structuredContent"]["message"],
            "sandbox 'w1' failed: image pull failed"
        );
    }

    fn mcp_user(subject: &str, roles: &[&str]) -> crate::auth::principal::Principal {
        crate::auth::principal::Principal::User(crate::auth::principal::UserPrincipal {
            identity: crate::auth::identity::Identity {
                subject: subject.to_string(),
                display_name: None,
                roles: roles.iter().map(ToString::to_string).collect(),
                scopes: Vec::new(),
                provider: crate::auth::identity::IdentityProvider::Oidc,
            },
        })
    }

    /// A child-sandbox state whose users are checked against workspace
    /// membership (an empty admin role would make every user an admin).
    async fn member_checked_state() -> Arc<ServerState> {
        let mut state = child_sandboxes_state().await;
        Arc::get_mut(&mut state).unwrap().admin_role = "openshell-admin".to_string();
        state
    }

    fn mcp_names(result: &serde_json::Value) -> Vec<String> {
        result["structuredContent"]["sandboxes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|sandbox| sandbox["name"].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn mcp_users_act_only_in_workspaces_they_belong_to() {
        let state = member_checked_state().await;
        put_parent_record(&state, "lead", &[], None, false).await;
        let far_id = put_parent_record(&state, "far", &[], None, false).await;
        let mut far = state
            .store
            .get_message::<Sandbox>(&far_id)
            .await
            .unwrap()
            .unwrap();
        far.metadata.as_mut().unwrap().workspace = "team".to_string();
        state.store.delete("sandbox", &far_id).await.unwrap();
        state.store.put_message(&far).await.unwrap();
        put_member(&state, "alice").await;
        let alice = || mcp_user("alice", &["openshell-user"]);

        let list = call_mcp_as(&state, alice(), None, None, "list", serde_json::json!({})).await;
        assert_eq!(list["isError"], false, "{list}");
        assert_eq!(mcp_names(&list), vec!["lead".to_string()]);
        let logs = call_mcp_as(
            &state,
            alice(),
            None,
            None,
            "logs",
            serde_json::json!({"name": "lead"}),
        )
        .await;
        assert_eq!(logs["isError"], false, "{logs}");

        // Another workspace, and a sandbox there, read as missing.
        let logs = call_mcp_as(
            &state,
            alice(),
            None,
            Some("team"),
            "logs",
            serde_json::json!({"name": "far"}),
        )
        .await;
        assert_eq!(logs["structuredContent"]["error"], "not_found", "{logs}");
        let list = call_mcp_as(
            &state,
            alice(),
            None,
            Some("team"),
            "list",
            serde_json::json!({}),
        )
        .await;
        assert_eq!(list["isError"], true, "{list}");
        // So does a sandbox in a workspace the user is not a member of.
        let bob = mcp_user("bob", &["openshell-user"]);
        let logs = call_mcp_as(
            &state,
            bob,
            None,
            None,
            "logs",
            serde_json::json!({"name": "lead"}),
        )
        .await;
        assert_eq!(logs["structuredContent"]["error"], "not_found", "{logs}");
    }

    #[tokio::test]
    async fn mcp_users_need_the_role_for_each_method() {
        let state = member_checked_state().await;
        put_parent_record(&state, "lead", &[], None, false).await;
        put_member(&state, "carol").await;
        let policy = || crate::auth::authz::AuthzPolicy {
            admin_role: "openshell-admin".to_string(),
            user_role: "openshell-user".to_string(),
            scopes_enabled: false,
        };

        let refused = call_mcp_as(
            &state,
            mcp_user("carol", &[]),
            Some(policy()),
            None,
            "list",
            serde_json::json!({}),
        )
        .await;
        assert_eq!(
            refused["structuredContent"]["error"], "permission_denied",
            "{refused}"
        );
        let allowed = call_mcp_as(
            &state,
            mcp_user("carol", &["openshell-user"]),
            Some(policy()),
            None,
            "list",
            serde_json::json!({}),
        )
        .await;
        assert_eq!(allowed["isError"], false, "{allowed}");
    }

    #[tokio::test]
    async fn mcp_users_create_roots_and_children_but_no_grandchildren() {
        let state = member_checked_state().await;
        put_parent_record(&state, "lead", &[], None, false).await;
        put_member(&state, "alice").await;
        let create = |arguments| {
            call_mcp_as(
                &state,
                mcp_user("alice", &["openshell-user"]),
                None,
                None,
                "create_sandbox",
                arguments,
            )
        };

        let root = create(serde_json::json!({"name": "r1", "image": "alpine:3"})).await;
        assert_eq!(root["isError"], false, "{root}");
        let r1 = state
            .store
            .get_message_by_name::<Sandbox>("default", "r1")
            .await
            .unwrap()
            .unwrap();
        assert!(r1.parent.is_none());
        assert_eq!(r1.created_by, "alice");
        assert_eq!(
            r1.spec.as_ref().unwrap().template.as_ref().unwrap().image,
            "alpine:3"
        );

        let child = create(serde_json::json!({"name": "c1", "parent": "lead"})).await;
        assert_eq!(child["isError"], false, "{child}");
        assert_eq!(child["structuredContent"]["parent"], "lead");

        let grandchild = create(serde_json::json!({"name": "g1", "parent": "c1"})).await;
        assert_eq!(grandchild["isError"], true, "{grandchild}");
    }

    #[tokio::test]
    async fn an_mcp_sandbox_caller_ignores_a_workspace_header() {
        let state = child_sandboxes_state().await;
        let lead_id = put_parent_record(&state, "lead", &[], None, false).await;
        let link = openshell_core::proto::SandboxParent {
            name: "lead".to_string(),
            id: lead_id.clone(),
        };
        put_parent_record(&state, "w1", &[], Some(link), false).await;
        let caller =
            crate::auth::principal::Principal::Sandbox(crate::auth::principal::SandboxPrincipal {
                sandbox_id: lead_id,
                source: crate::auth::principal::SandboxIdentitySource::BootstrapJwt {
                    issuer: "openshell-gateway:test".to_string(),
                    auth_epoch: None,
                },
                trust_domain: Some("openshell".to_string()),
            });

        let list = call_mcp_as(
            &state,
            caller,
            None,
            Some("team"),
            "list",
            serde_json::json!({}),
        )
        .await;
        assert_eq!(list["isError"], false, "{list}");
        assert_eq!(mcp_names(&list), vec!["w1".to_string()]);
    }

    #[tokio::test]
    async fn a_parent_filter_needs_one_workspace_and_an_existing_parent() {
        let state = child_sandboxes_state().await;
        put_parent_record(&state, "lead", &[], None, false).await;

        let mut all_workspaces = list_children_request("lead", 100, String::new());
        all_workspaces.workspace_scope = Some(openshell_core::proto::all_workspaces_selector());
        let err = handle_list_sandboxes(&state, authed_request(all_workspaces))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(
            err.message()
                .contains("a parent filter needs a single workspace")
        );

        let err = handle_list_sandboxes(
            &state,
            authed_request(list_children_request("missing", 100, String::new())),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn a_page_token_is_tied_to_the_parent_it_was_listed_for() {
        let state = child_sandboxes_state().await;
        let lead_id = put_parent_record(&state, "lead", &[], None, false).await;
        let link = openshell_core::proto::SandboxParent {
            name: "lead".to_string(),
            id: lead_id.clone(),
        };
        for name in ["worker1", "worker2"] {
            put_parent_record(&state, name, &[], Some(link.clone()), false).await;
        }
        let list = |parent: &str, token: String| {
            handle_list_sandboxes(
                &state,
                authed_request(list_children_request(parent, 1, token)),
            )
        };

        let unfiltered = list("", String::new()).await.unwrap().into_inner();
        let err = list("lead", unfiltered.next_page_token).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let filtered = list("lead", String::new()).await.unwrap().into_inner();
        let err = list("", filtered.next_page_token.clone())
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        // A new root under the same name is a different parent.
        state
            .store
            .delete(Sandbox::object_type(), &lead_id)
            .await
            .unwrap();
        put_parent_record(&state, "lead", &[], None, false).await;
        let err = list("lead", filtered.next_page_token).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn detaching_a_provider_from_a_parent_detaches_it_from_its_children() {
        let state = child_sandboxes_state().await;
        let (_, worker_id) = lead_and_child_sharing_a_provider(&state).await;
        let before = sandbox_spec(&state, &worker_id).await;

        detach_from_lead(&state, "work-github").await;

        // The parent's policy did not change, so the child's copy is current
        // and only the provider is removed, as a detach removes it.
        eventually(|| async { sandbox_spec(&state, &worker_id).await.providers.is_empty() }).await;
        let after = sandbox_spec(&state, &worker_id).await;
        assert_ne!(
            after.provider_attachment_epoch, before.provider_attachment_epoch,
            "the supervisor must see a new attachment epoch to drop the credential"
        );
        assert_eq!(latest_policy(&state, &worker_id).await.version, 1);
    }

    #[tokio::test]
    async fn a_blocked_parents_children_still_lose_its_lost_provider() {
        let state = child_sandboxes_state().await;
        let (lead_id, worker_id) = lead_and_child_sharing_a_provider(&state).await;
        put_policy_revision_with_status(&state, &lead_id, 2, &lead_policy(false), "failed").await;

        detach_from_lead(&state, "work-github").await;

        eventually(|| async { sandbox_spec(&state, &worker_id).await.providers.is_empty() }).await;
    }

    #[tokio::test]
    async fn a_child_that_missed_a_provider_detach_loses_it_on_its_own() {
        let state = child_sandboxes_state().await;
        let (lead_id, worker_id) = lead_and_child_sharing_a_provider(&state).await;
        // The lead lost the provider, but the sync that would follow was lost.
        let mut lead = state
            .store
            .get_message::<Sandbox>(&lead_id)
            .await
            .unwrap()
            .unwrap();
        lead.spec.as_mut().unwrap().providers.clear();
        state.store.put_message(&lead).await.unwrap();
        let worker = state
            .store
            .get_message::<Sandbox>(&worker_id)
            .await
            .unwrap()
            .unwrap();

        sync_one_child(&state, &worker).await.unwrap();

        assert!(sandbox_spec(&state, &worker_id).await.providers.is_empty());
    }

    /// Wait for a background sync to reach the store.
    async fn eventually<F, Fut>(mut reached: F)
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = bool>,
    {
        for _ in 0..500 {
            if reached().await {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("not reached within 5 seconds");
    }

    async fn sandbox_record(state: &ServerState, sandbox_id: &str) -> Sandbox {
        state
            .store
            .get_message::<Sandbox>(sandbox_id)
            .await
            .unwrap()
            .unwrap()
    }

    async fn delivered_variables(state: &Arc<ServerState>, sandbox: &Sandbox) -> Vec<String> {
        super::super::policy::build_provider_environment_snapshot(state, sandbox, true, true)
            .await
            .expect("provider environment")
            .values
            .into_iter()
            .map(|value| value.name)
            .collect()
    }

    /// Take a provider from the lead's record without any sync, as when the
    /// sync after a detach is lost.
    async fn lead_loses_providers_without_a_sync(state: &ServerState, lead_id: &str) {
        let mut lead = sandbox_record(state, lead_id).await;
        lead.spec.as_mut().unwrap().providers.clear();
        state.store.put_message(&lead).await.unwrap();
    }

    #[tokio::test]
    async fn a_child_loses_a_provider_its_parent_lost_at_its_next_build() {
        let state = child_sandboxes_state().await;
        let (lead_id, worker_id) = lead_and_child_sharing_a_provider(&state).await;
        let worker = sandbox_record(&state, &worker_id).await;
        assert!(
            delivered_variables(&state, &worker)
                .await
                .contains(&"GITHUB_TOKEN".to_string())
        );

        lead_loses_providers_without_a_sync(&state, &lead_id).await;

        // No sync ran: the child's record still names the provider, but its
        // very next build serves none of it.
        assert_eq!(
            sandbox_spec(&state, &worker_id).await.providers,
            vec!["work-github"]
        );
        assert!(delivered_variables(&state, &worker).await.is_empty());
        let inputs = super::super::policy::load_sandbox_config_inputs(&state, worker.clone())
            .await
            .unwrap();
        assert!(inputs.sandbox().spec.as_ref().unwrap().providers.is_empty());
        let config = child_config(&state, &worker_id).await;
        assert!(config.configuration_admitted);
        assert!(
            !provider_attached_for_delivery(&state, &worker, "work-github")
                .await
                .unwrap(),
            "readiness reports the provider as not attached"
        );
    }

    #[tokio::test]
    async fn a_detach_rebuilds_a_push_mode_child_at_once_without_a_sync() {
        use openshell_core::proto::{SupervisorMessage, gateway_message, supervisor_message};

        let mut state = child_sandboxes_state().await;
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .config_delivery_mode = openshell_core::config::ConfigDeliveryMode::Push;
        let (_, worker_id) = lead_and_child_sharing_a_provider(&state).await;
        let mut harness = crate::grpc::test_support::connect_supervisor_stream(
            &state,
            &worker_id,
            crate::grpc::test_support::StreamFeatures::Apply,
        )
        .await
        .unwrap();
        let accepted = harness.inbound.message().await.unwrap().unwrap();
        let Some(gateway_message::Payload::SessionAccepted(accepted)) = accepted.payload else {
            panic!("expected SessionAccepted");
        };
        let bootstrap = accepted.bootstrap.expect("push bootstrap");
        assert!(
            bootstrap
                .provider_environment
                .as_ref()
                .unwrap()
                .values
                .iter()
                .any(|value| value.name == "GITHUB_TOKEN")
        );
        harness
            .outbound
            .send(SupervisorMessage {
                payload: Some(supervisor_message::Payload::ConfigUpdateResult(
                    crate::config_delivery::session::applied_result(&bootstrap),
                )),
            })
            .await
            .unwrap();
        // The acknowledgement is recorded under the child's lock; live
        // updates start once it is.
        eventually(|| async {
            !state
                .supervisor_sessions
                .config_update_in_flight(&worker_id, &accepted.session_id)
        })
        .await;
        // Holding the child's lock keeps the sync from reaching it. The
        // detach runs as its own task, as a request would.
        let _guard = state
            .compute
            .mutation_guard(MutationScope::sandbox("default", &worker_id))
            .await
            .unwrap();
        let detach_state = Arc::clone(&state);
        tokio::spawn(async move { detach_from_lead(&detach_state, "work-github").await })
            .await
            .unwrap();

        // Acknowledge each update, as a supervisor does, until one without
        // the credential arrives. The sync started on connect may push one
        // first. Well under the 30 s re-check, so only the detach's own
        // notification can explain it.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let message = harness.inbound.message().await.unwrap().unwrap();
                let Some(gateway_message::Payload::ConfigUpdate(update)) = message.payload else {
                    continue;
                };
                harness
                    .outbound
                    .send(SupervisorMessage {
                        payload: Some(supervisor_message::Payload::ConfigUpdateResult(
                            crate::config_delivery::session::applied_result(&update),
                        )),
                    })
                    .await
                    .unwrap();
                if update
                    .provider_environment
                    .unwrap()
                    .values
                    .iter()
                    .all(|value| value.name != "GITHUB_TOKEN")
                {
                    break;
                }
            }
        })
        .await
        .expect("the child is rebuilt at once, not at its 30 s re-check");
        assert_eq!(
            sandbox_spec(&state, &worker_id).await.providers,
            vec!["work-github"],
            "no sync has run"
        );
    }

    #[tokio::test]
    async fn a_connecting_childs_first_configuration_lacks_a_provider_its_parent_lost() {
        let state = child_sandboxes_state().await;
        let (lead_id, worker_id) = lead_and_child_sharing_a_provider(&state).await;
        // The record read when the child connected, before any sync.
        let read_at_connect = sandbox_record(&state, &worker_id).await;
        lead_loses_providers_without_a_sync(&state, &lead_id).await;

        let bootstrap =
            crate::config_delivery::session::build_session_bootstrap(&state, &read_at_connect)
                .await
                .unwrap();

        assert!(bootstrap.config.sandbox_config.configuration_admitted);
        assert!(
            bootstrap
                .config
                .provider_environment
                .values
                .iter()
                .all(|value| value.name != "GITHUB_TOKEN")
        );
    }

    #[tokio::test]
    async fn a_child_behind_its_parent_is_refused_until_its_copy_lands() {
        let state = child_sandboxes_state().await;
        let (lead_id, worker_id) = lead_with_copied_child(&state).await;
        // The lead loads v2, and the sync that would copy it is lost.
        put_policy_revision_with_status(&state, &lead_id, 2, &lead_policy(false), "loaded").await;
        let worker = sandbox_record(&state, &worker_id).await;
        // Hold the lead's lock, which every child sync takes, so the sync the
        // refusal starts cannot land before the checks below.
        let guard = state
            .compute
            .mutation_guard(MutationScope::sandbox("default", &lead_id))
            .await
            .unwrap();

        let config = child_config(&state, &worker_id).await;
        assert!(!config.configuration_admitted);
        assert_eq!(
            config.configuration_error,
            "Waiting for a copy of the parent sandbox's latest policy"
        );
        assert_eq!(
            config.policy_validation_failure_mode,
            openshell_core::PolicyValidationFailureMode::FailClosed.as_str()
        );
        let err =
            super::super::policy::build_provider_environment_snapshot(&state, &worker, true, true)
                .await
                .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            copied_version(&latest_policy(&state, &worker_id).await),
            Some("1")
        );

        // The refusal started a sync; once it lands, the child is admitted.
        drop(guard);
        eventually(|| async {
            copied_version(&latest_policy(&state, &worker_id).await) == Some("2")
        })
        .await;
        let config = child_config(&state, &worker_id).await;
        assert!(config.configuration_admitted);
        assert!(config.policy.unwrap().network_policies.contains_key("api"));
    }

    #[tokio::test]
    async fn a_blocked_parents_child_is_refused_its_provider_environment() {
        let state = child_sandboxes_state().await;
        let (lead_id, worker_id) = lead_and_child_sharing_a_provider(&state).await;
        put_policy_revision_with_status(&state, &lead_id, 2, &lead_policy(false), "failed").await;
        let worker = sandbox_record(&state, &worker_id).await;

        let err =
            super::super::policy::build_provider_environment_snapshot(&state, &worker, true, true)
                .await
                .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            err.message(),
            "parent sandbox 'lead' rejected its latest policy"
        );
    }

    #[tokio::test]
    async fn a_parent_policy_that_cannot_be_copied_refuses_children_and_says_why() {
        let state = child_sandboxes_state().await;
        let (lead_id, worker_id) = lead_with_copied_child(&state).await;
        let mut uncopyable = lead_policy(false);
        let rule = uncopyable.network_policies.remove("api").unwrap();
        uncopyable
            .network_policies
            .insert("_provider_github".to_string(), rule);
        put_policy_revision_with_status(&state, &lead_id, 2, &uncopyable, "loaded").await;
        let worker = sandbox_record(&state, &worker_id).await;

        let err = super::super::policy::load_sandbox_config_inputs(&state, worker)
            .await
            .err()
            .expect("refused");
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            err.message(),
            "parent sandbox 'lead' policy version 2 cannot be copied to its children"
        );
        let config = child_config(&state, &worker_id).await;
        assert_eq!(
            config.configuration_error,
            "The parent sandbox's policy cannot be copied to children; fix the parent's policy"
        );
        // No sync is started for a copy that cannot succeed.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(
            copied_version(&latest_policy(&state, &worker_id).await),
            Some("1")
        );
    }

    #[tokio::test]
    async fn setting_a_child_policy_is_refused_but_settings_are_allowed() {
        let state = child_sandboxes_state().await;
        put_lead_and_worker(&state).await;

        let err = super::super::policy::handle_update_config(
            &state,
            authed_request(openshell_core::proto::UpdateConfigRequest {
                sandbox: "worker1".to_string(),
                workspace_scope: Some(default_scope()),
                policy: Some(openshell_policy::restrictive_default_policy()),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(
            err.message()
                .contains("child sandboxes use their parent's policy"),
            "{}",
            err.message()
        );

        super::super::policy::handle_update_config(
            &state,
            authed_request(openshell_core::proto::UpdateConfigRequest {
                sandbox: "worker1".to_string(),
                workspace_scope: Some(default_scope()),
                setting_key: openshell_core::settings::PROPOSAL_APPROVAL_MODE_KEY.to_string(),
                setting_value: Some(openshell_core::proto::SettingValue {
                    value: Some(openshell_core::proto::setting_value::Value::StringValue(
                        "manual".to_string(),
                    )),
                }),
                ..Default::default()
            }),
        )
        .await
        .expect("a child's settings can still be changed");
    }

    /// A sandbox's own supervisor writing back its policy with one extra
    /// read-only path, as startup path enrichment does.
    fn supervisor_write_back(
        sandbox_id: &str,
        name: &str,
    ) -> Request<openshell_core::proto::UpdateConfigRequest> {
        let mut policy = openshell_policy::restrictive_default_policy();
        policy
            .filesystem
            .get_or_insert_with(Default::default)
            .read_only
            .push("/app".to_string());
        sandbox_request(
            sandbox_id,
            openshell_core::proto::UpdateConfigRequest {
                sandbox: name.to_string(),
                workspace_scope: Some(default_scope()),
                policy: Some(policy),
                ..Default::default()
            },
        )
    }

    /// A request made by a sandbox's own supervisor.
    fn sandbox_request<T>(sandbox_id: &str, inner: T) -> Request<T> {
        use crate::auth::principal::{Principal, SandboxIdentitySource, SandboxPrincipal};
        let mut request = Request::new(inner);
        request
            .extensions_mut()
            .insert(Principal::Sandbox(SandboxPrincipal {
                sandbox_id: sandbox_id.to_string(),
                source: SandboxIdentitySource::BootstrapJwt {
                    issuer: "openshell-gateway:test".to_string(),
                    auth_epoch: None,
                },
                trust_domain: Some("openshell".to_string()),
            }));
        request
    }

    #[tokio::test]
    async fn a_child_supervisor_write_back_is_accepted_and_dropped() {
        let state = child_sandboxes_state().await;
        let worker_id = put_lead_and_worker(&state).await;
        let before = latest_policy(&state, &worker_id).await;

        let response = super::super::policy::handle_update_config(
            &state,
            supervisor_write_back(&worker_id, "worker1"),
        )
        .await
        .expect("the child's supervisor is answered OK")
        .into_inner();

        let after = latest_policy(&state, &worker_id).await;
        assert_eq!(after.version, before.version, "no revision is written");
        assert_eq!(after.policy_payload, before.policy_payload);
        assert_eq!(i64::from(response.version), before.version);
        assert_eq!(response.policy_hash, before.policy_hash);
    }

    #[tokio::test]
    async fn a_root_supervisor_write_back_is_still_stored() {
        let state = child_sandboxes_state().await;
        let lead_id = put_parent_record(&state, "lead", &[], None, false).await;
        let before = latest_policy(&state, &lead_id).await;

        super::super::policy::handle_update_config(&state, supervisor_write_back(&lead_id, "lead"))
            .await
            .expect("a root's supervisor write-back is stored");

        assert_eq!(
            latest_policy(&state, &lead_id).await.version,
            before.version + 1
        );
    }

    /// A root `lead` with a child `worker1` created through the API, so the
    /// child's v1 is tagged as copied from the lead's v1. Returns both ids.
    async fn lead_with_copied_child(state: &Arc<ServerState>) -> (String, String) {
        let lead_id = put_parent_record(state, "lead", &[], None, false).await;
        let worker = create_child(state, "worker1", "lead").await;
        (lead_id, worker.object_id().to_string())
    }

    fn copied_version(record: &crate::persistence::PolicyRecord) -> Option<&str> {
        record
            .provenance
            .get(COPIED_FROM_PARENT_VERSION)
            .map(String::as_str)
    }

    #[tokio::test]
    async fn sync_copies_the_parents_newly_loaded_policy() {
        let state = child_sandboxes_state().await;
        let (lead_id, worker_id) = lead_with_copied_child(&state).await;
        put_policy_revision_with_status(&state, &lead_id, 2, &lead_policy(false), "loaded").await;

        sync_children(&state, &lead_id).await.unwrap();

        let parent_record = latest_policy(&state, &lead_id).await;
        let (_, parent_hash) =
            super::super::policy::canonical_policy_record_identity(&parent_record).unwrap();
        let child_record = latest_policy(&state, &worker_id).await;
        assert_eq!(child_record.version, 2);
        assert_eq!(copied_version(&child_record), Some("2"));
        assert_eq!(child_record.policy_hash, parent_hash);

        sync_children(&state, &lead_id).await.unwrap();
        assert_eq!(
            latest_policy(&state, &worker_id).await.version,
            2,
            "a second sync writes nothing"
        );
    }

    /// Give a child revision 2, tagged as a copy of parent version 5.
    async fn put_newer_child_copy(state: &ServerState, child_id: &str, parent_id: &str) {
        let provenance = HashMap::from([
            (COPIED_FROM_PARENT_ID.to_string(), parent_id.to_string()),
            (COPIED_FROM_PARENT_VERSION.to_string(), "5".to_string()),
        ]);
        let policy = openshell_policy::restrictive_default_policy();
        state
            .store
            .put_policy_revision_atomic(&crate::policy_store::AtomicPolicyRevisionWrite {
                id: uuid::Uuid::new_v4().to_string(),
                sandbox_id: child_id.to_string(),
                workspace: "default".to_string(),
                version: 2,
                policy_payload: policy.encode_to_vec(),
                policy_hash: openshell_core::policy_identity::deterministic_policy_hash(&policy),
                provenance,
                expected_resource_version: 0,
                annotations: HashMap::new(),
                backfill_policy: None,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn sync_never_replaces_a_newer_copy() {
        let state = child_sandboxes_state().await;
        let (lead_id, worker_id) = lead_with_copied_child(&state).await;
        // The child already holds a copy of a newer parent version than the
        // one this sync reads, as when an earlier sync finishes last.
        put_newer_child_copy(&state, &worker_id, &lead_id).await;
        put_policy_revision_with_status(&state, &lead_id, 2, &lead_policy(false), "loaded").await;

        sync_children(&state, &lead_id).await.unwrap();

        let child_record = latest_policy(&state, &worker_id).await;
        assert_eq!(child_record.version, 2);
        assert_eq!(copied_version(&child_record), Some("5"));
    }

    #[tokio::test]
    async fn a_fail_closed_parents_rejected_policy_blocks_its_children_until_it_loads_a_fix() {
        let state = child_sandboxes_state().await;
        let (lead_id, worker_id) = lead_with_copied_child(&state).await;
        put_policy_revision_with_status(&state, &lead_id, 2, &lead_policy(false), "pending").await;

        // The parent rejects v2; its failed report pushes the child.
        let mut pushes = state.sandbox_watch_bus.subscribe(&worker_id);
        super::super::policy::record_policy_apply_result(
            &state,
            &lead_id,
            2,
            false,
            Some("invalid"),
            "test",
        )
        .await
        .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), pushes.recv())
            .await
            .expect("the child is pushed")
            .unwrap();

        let config = child_config(&state, &worker_id).await;
        assert!(!config.configuration_admitted);
        assert!(
            config
                .configuration_error
                .contains("fix the parent's policy"),
            "{}",
            config.configuration_error
        );
        assert_eq!(config.policy_validation_failure_mode, "fail_closed");
        assert_eq!(
            latest_policy(&state, &worker_id).await.version,
            1,
            "nothing is copied"
        );

        // The parent loads a fixed v3; its report copies it into the child.
        put_policy_revision_with_status(&state, &lead_id, 3, &lead_policy(false), "pending").await;
        super::super::policy::record_policy_apply_result(&state, &lead_id, 3, true, None, "test")
            .await
            .unwrap();
        wait_for_child_version(&state, &worker_id, 2).await;

        assert_eq!(
            copied_version(&latest_policy(&state, &worker_id).await),
            Some("3")
        );
        assert!(
            child_config(&state, &worker_id)
                .await
                .configuration_admitted
        );
    }

    #[tokio::test]
    async fn a_parent_unblocking_pushes_a_child_whose_copy_is_current() {
        let state = child_sandboxes_state().await;
        let (lead_id, worker_id) = lead_with_copied_child(&state).await;
        put_policy_revision_with_status(&state, &lead_id, 2, &lead_policy(false), "failed").await;
        put_newer_child_copy(&state, &worker_id, &lead_id).await;
        assert!(
            !child_config(&state, &worker_id)
                .await
                .configuration_admitted
        );

        // A retry of v2 loads on the parent; the child needs no new copy.
        let mut pushes = state.sandbox_watch_bus.subscribe(&worker_id);
        super::super::policy::record_policy_apply_result(&state, &lead_id, 2, true, None, "test")
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), pushes.recv())
            .await
            .expect("the child is pushed")
            .unwrap();

        assert_eq!(
            latest_policy(&state, &worker_id).await.version,
            2,
            "nothing is copied"
        );
        assert!(
            child_config(&state, &worker_id)
                .await
                .configuration_admitted
        );
    }

    #[tokio::test]
    async fn a_child_that_missed_a_sync_catches_up_on_its_own() {
        let state = child_sandboxes_state().await;
        let lead_id = put_parent_record(&state, "lead", &[], None, false).await;
        let worker = create_child(&state, "worker1", "lead").await;
        let worker_id = worker.object_id().to_string();
        // The parent loaded v2, but the sync that would copy it was lost.
        put_policy_revision_with_status(&state, &lead_id, 2, &lead_policy(false), "loaded").await;
        // A nested wait on the parent's lock would time out and fail here.
        state
            .compute
            .set_mutation_lock_timeout_for_tests(std::time::Duration::from_millis(50));

        sync_one_child(&state, &worker).await.unwrap();

        let child_record = latest_policy(&state, &worker_id).await;
        assert_eq!(child_record.version, 2);
        assert_eq!(copied_version(&child_record), Some("2"));
        sync_one_child(&state, &worker).await.unwrap();
        assert_eq!(
            latest_policy(&state, &worker_id).await.version,
            2,
            "a second sync writes nothing"
        );
    }

    #[tokio::test]
    async fn a_blocked_parents_child_copies_nothing_on_its_own() {
        let state = child_sandboxes_state().await;
        let lead_id = put_parent_record(&state, "lead", &[], None, false).await;
        let worker = create_child(&state, "worker1", "lead").await;
        put_policy_revision_with_status(&state, &lead_id, 2, &lead_policy(false), "failed").await;

        sync_one_child(&state, &worker).await.unwrap();

        assert_eq!(latest_policy(&state, worker.object_id()).await.version, 1);
    }

    #[tokio::test]
    async fn startup_sync_catches_up_the_children_of_every_root() {
        let state = child_sandboxes_state().await;
        let mut children = Vec::new();
        for (lead, worker) in [("lead", "worker1"), ("lead2", "worker2")] {
            let lead_id = put_parent_record(&state, lead, &[], None, false).await;
            let worker_id = create_child(&state, worker, lead)
                .await
                .object_id()
                .to_string();
            put_policy_revision_with_status(&state, &lead_id, 2, &lead_policy(false), "loaded")
                .await;
            children.push(worker_id);
        }

        sync_all_children(&state).await.unwrap();

        for worker_id in children {
            assert_eq!(
                copied_version(&latest_policy(&state, &worker_id).await),
                Some("2")
            );
        }
    }

    #[tokio::test]
    async fn one_child_failing_to_sync_does_not_hold_back_its_siblings() {
        let state = child_sandboxes_state().await;
        let lead_id = put_parent_record(&state, "lead", &[], None, false).await;
        let stuck_id = create_child(&state, "worker1", "lead")
            .await
            .object_id()
            .to_string();
        let free_id = create_child(&state, "worker2", "lead")
            .await
            .object_id()
            .to_string();
        put_policy_revision_with_status(&state, &lead_id, 2, &lead_policy(false), "loaded").await;
        state
            .compute
            .set_mutation_lock_timeout_for_tests(std::time::Duration::from_millis(50));
        // Another task holds the stuck child's lock until the sync is done.
        let (held_tx, held_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let holder = {
            let state = Arc::clone(&state);
            let stuck_id = stuck_id.clone();
            tokio::spawn(async move {
                let _guard = state
                    .compute
                    .mutation_guard(MutationScope::sandbox("default", &stuck_id))
                    .await
                    .unwrap();
                held_tx.send(()).unwrap();
                let _ = release_rx.await;
            })
        };
        held_rx.await.unwrap();

        let err = sync_children(&state, &lead_id).await.unwrap_err();
        release_tx.send(()).unwrap();
        holder.await.unwrap();
        assert!(
            err.message().contains("1 child sandbox"),
            "{}",
            err.message()
        );

        assert_eq!(latest_policy(&state, &stuck_id).await.version, 1);
        assert_eq!(
            copied_version(&latest_policy(&state, &free_id).await),
            Some("2")
        );
    }

    #[tokio::test]
    async fn a_synced_copy_matches_a_copy_made_at_create() {
        let state = child_sandboxes_state().await;
        let lead_id = put_parent_record(&state, "lead", &[], None, false).await;
        // A marker the gateway stamps at delivery; a copy must clear it.
        let mut policy = lead_policy(false);
        policy.network_policies.get_mut("api").unwrap().endpoints[0].provider_credentialed = true;
        put_policy_revision_with_status(&state, &lead_id, 2, &policy, "loaded").await;
        let created_id = create_child(&state, "worker1", "lead")
            .await
            .object_id()
            .to_string();
        // A child whose history was not copied from this parent.
        let link = openshell_core::proto::SandboxParent {
            name: "lead".to_string(),
            id: lead_id.clone(),
        };
        let synced_id = put_parent_record(&state, "worker2", &[], Some(link), false).await;

        sync_children(&state, &lead_id).await.unwrap();

        let created = latest_policy(&state, &created_id).await;
        let synced = latest_policy(&state, &synced_id).await;
        assert_eq!(copied_version(&created), Some("2"));
        assert_eq!(copied_version(&synced), Some("2"));
        assert_eq!(synced.policy_hash, created.policy_hash);
        assert_eq!(synced.policy_payload, created.policy_payload);
    }

    /// A parent policy the child cannot load: it binds a credential from a
    /// provider the child does not have.
    fn unloadable_on_child() -> openshell_core::proto::SandboxPolicy {
        let mut policy = lead_policy(false);
        let endpoint = &mut policy.network_policies.get_mut("api").unwrap().endpoints[0];
        endpoint.protocol = "rest".to_string();
        endpoint.access = openshell_core::proto::NetworkAccessPreset::Full as i32;
        endpoint.credential_binding = Some(openshell_core::proto::NetworkCredentialBinding {
            provider: "work-cloud".to_string(),
        });
        policy
    }

    /// Wait for the background sync to give a child this revision version.
    async fn wait_for_child_version(state: &ServerState, child_id: &str, version: i64) {
        for _ in 0..100 {
            if latest_policy(state, child_id).await.version >= version {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    /// The configuration a child's own supervisor receives.
    async fn child_config(
        state: &Arc<ServerState>,
        child_id: &str,
    ) -> openshell_core::proto::GetSandboxConfigResponse {
        super::super::policy::handle_get_sandbox_config(
            state,
            sandbox_request(
                child_id,
                openshell_core::proto::GetSandboxConfigRequest {
                    name: "worker1".to_string(),
                    workspace_scope: Some(default_scope()),
                },
            ),
        )
        .await
        .expect("the child receives a configuration, not an error")
        .into_inner()
    }

    #[tokio::test]
    async fn a_parent_load_report_syncs_its_children() {
        let state = child_sandboxes_state().await;
        let (lead_id, worker_id) = lead_with_copied_child(&state).await;
        put_policy_revision_with_status(&state, &lead_id, 2, &lead_policy(false), "pending").await;

        super::super::policy::record_policy_apply_result(&state, &lead_id, 2, true, None, "test")
            .await
            .unwrap();

        wait_for_child_version(&state, &worker_id, 2).await;
        let child_record = latest_policy(&state, &worker_id).await;
        assert_eq!(copied_version(&child_record), Some("2"));
    }

    /// Load a pending parent revision through the real report handler and
    /// wait for the sync to copy it into the child.
    async fn parent_loads(
        state: &Arc<ServerState>,
        lead_id: &str,
        worker_id: &str,
        version: u32,
        policy: &openshell_core::proto::SandboxPolicy,
    ) {
        put_policy_revision_with_status(state, lead_id, i64::from(version), policy, "pending")
            .await;
        super::super::policy::record_policy_apply_result(
            state, lead_id, version, true, None, "test",
        )
        .await
        .unwrap();
        wait_for_child_version(state, worker_id, i64::from(version)).await;
    }

    async fn late_failure(state: &Arc<ServerState>, lead_id: &str, version: u32) {
        super::super::policy::record_policy_apply_result(
            state,
            lead_id,
            version,
            false,
            Some("late result"),
            "test",
        )
        .await
        .unwrap();
    }

    async fn new_child_copy(state: &Arc<ServerState>, name: &str) -> Result<i64, Status> {
        let child = handle_create_sandbox(
            state,
            authed_request(child_request(name, "lead", SandboxSpec::default())),
        )
        .await?
        .into_inner()
        .sandbox
        .unwrap();
        Ok(
            copied_version(&latest_policy(state, child.object_id()).await)
                .unwrap()
                .parse()
                .unwrap(),
        )
    }

    fn state_in_mode(
        mut state: Arc<ServerState>,
        mode: openshell_core::PolicyValidationFailureMode,
    ) -> Arc<ServerState> {
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .policy_validation_failure_mode = mode;
        state
    }

    /// A "failed" report for a version that already loaded: a re-apply that
    /// failed, or a late result from a replaced session. Upstream records it
    /// as failed either way. Children follow the version the parent last
    /// loaded: under `fail_closed` a failure of that version blocks them, as
    /// it blocks the parent; under `retain_last_valid` they keep it.
    #[tokio::test]
    async fn a_failed_report_for_a_loaded_version_follows_the_parents_failure_mode() {
        use openshell_core::PolicyValidationFailureMode::{FailClosed, RetainLastValid};
        for mode in [FailClosed, RetainLastValid] {
            for newer_loaded in [false, true] {
                let state = state_in_mode(child_sandboxes_state().await, mode);
                let (lead_id, worker_id) = lead_with_copied_child(&state).await;
                parent_loads(&state, &lead_id, &worker_id, 2, &lead_policy(false)).await;
                if newer_loaded {
                    parent_loads(&state, &lead_id, &worker_id, 3, &lead_policy(false)).await;
                }
                let enforced = if newer_loaded { 3 } else { 2 };
                let case = format!("{mode:?}, newer loaded: {newer_loaded}");

                late_failure(&state, &lead_id, 2).await;

                let config = child_config(&state, &worker_id).await;
                let created = new_child_copy(&state, "worker2").await;
                if mode == FailClosed && !newer_loaded {
                    assert!(
                        !config.configuration_admitted,
                        "{case}: blocked with the parent"
                    );
                    assert_eq!(
                        created.unwrap_err().code(),
                        tonic::Code::FailedPrecondition,
                        "{case}"
                    );
                } else {
                    assert!(
                        config.configuration_admitted,
                        "{case}: {}",
                        config.configuration_error
                    );
                    assert_eq!(
                        created.unwrap_or_else(|error| panic!("{case}: {error}")),
                        enforced,
                        "{case}: a new child copies the version the parent enforces"
                    );
                }
                assert_eq!(
                    copied_version(&latest_policy(&state, &worker_id).await),
                    Some(enforced.to_string().as_str()),
                    "{case}"
                );
            }
        }
    }

    /// v1 allows more than v2. After a failed report for v2, a parent that
    /// retains the last valid policy still enforces v2, so a new child must
    /// get v2, never the wider v1.
    #[tokio::test]
    async fn a_retained_parent_never_hands_children_an_older_wider_policy() {
        let state = state_in_mode(
            child_sandboxes_state().await,
            openshell_core::PolicyValidationFailureMode::RetainLastValid,
        );
        let lead_id = put_parent_record(&state, "lead", &[], None, false).await;
        // put_parent_record loaded v1 as the restrictive default; make v1 wide.
        let wide = lead_policy(false);
        put_policy_revision_with_status(&state, &lead_id, 2, &wide, "loaded").await;
        let worker = create_child(&state, "worker1", "lead").await;
        let narrow = openshell_policy::restrictive_default_policy();
        parent_loads(&state, &lead_id, worker.object_id(), 3, &narrow).await;

        late_failure(&state, &lead_id, 3).await;

        let created = new_child_copy(&state, "worker2").await.unwrap();
        assert_eq!(created, 3, "the new child copies v3, not the wider v2");
        let child = state
            .store
            .get_message_by_name::<Sandbox>("default", "worker2")
            .await
            .unwrap()
            .unwrap();
        let (policy, _) = super::super::policy::canonical_policy_record_identity(
            &latest_policy(&state, child.object_id()).await,
        )
        .unwrap();
        assert!(!policy.network_policies.contains_key("api"));
    }

    /// Writing a new parent revision marks the loaded one superseded before
    /// the new one loads. If the new one then fails under `fail_closed`, the
    /// parent is blocked, and so must its children be.
    #[tokio::test]
    async fn a_parent_blocked_by_a_new_revision_blocks_its_children() {
        let state = child_sandboxes_state().await;
        let (lead_id, worker_id) = lead_with_copied_child(&state).await;
        // Written as the gateway writes it, which supersedes the loaded v1.
        state
            .store
            .put_policy_revision_atomic(&crate::policy_store::AtomicPolicyRevisionWrite {
                id: uuid::Uuid::new_v4().to_string(),
                sandbox_id: lead_id.clone(),
                workspace: "default".to_string(),
                version: 2,
                policy_payload: lead_policy(false).encode_to_vec(),
                policy_hash: openshell_core::policy_identity::deterministic_policy_hash(
                    &lead_policy(false),
                ),
                provenance: HashMap::new(),
                expected_resource_version: 0,
                annotations: HashMap::new(),
                backfill_policy: None,
            })
            .await
            .unwrap();
        assert_eq!(
            state
                .store
                .get_policy_by_version(&lead_id, 1)
                .await
                .unwrap()
                .unwrap()
                .status,
            "superseded"
        );
        // The parent still enforces v1, so a new child copies it.
        assert_eq!(new_child_copy(&state, "worker2").await.unwrap(), 1);

        late_failure(&state, &lead_id, 2).await;

        let config = child_config(&state, &worker_id).await;
        assert!(
            !config.configuration_admitted,
            "{}",
            config.configuration_error
        );
        assert_eq!(
            new_child_copy(&state, "worker3").await.unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
    }

    /// Children now read the parent's enforced revision by version, so a
    /// revision must keep its policy when it is superseded or fails.
    #[tokio::test]
    async fn a_superseded_or_failed_revision_keeps_its_policy() {
        let state = child_sandboxes_state().await;
        let lead_id = put_parent_record(&state, "lead", &[], None, false).await;
        put_policy_revision_with_status(&state, &lead_id, 2, &lead_policy(false), "failed").await;
        state
            .store
            .supersede_older_policies(&lead_id, 3)
            .await
            .unwrap();

        for (version, status) in [(1, "superseded"), (2, "failed")] {
            let record = state
                .store
                .get_policy_by_version(&lead_id, version)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(record.status, status);
            assert!(
                ParentPolicyCopy::of(&record, &lead_id).is_ok(),
                "v{version} still decodes"
            );
        }
        let failed = state
            .store
            .get_policy_by_version(&lead_id, 2)
            .await
            .unwrap()
            .unwrap();
        let (policy, _) = super::super::policy::canonical_policy_record_identity(&failed).unwrap();
        assert!(policy.network_policies.contains_key("api"));
    }

    #[tokio::test]
    async fn children_fail_closed_even_when_the_gateway_retains_the_last_valid_policy() {
        let mut state = child_sandboxes_state().await;
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .policy_validation_failure_mode =
            openshell_core::PolicyValidationFailureMode::RetainLastValid;
        let (lead_id, worker_id) = lead_with_copied_child(&state).await;
        put_policy_revision_with_status(&state, &lead_id, 2, &unloadable_on_child(), "loaded")
            .await;
        sync_children(&state, &lead_id).await.unwrap();

        let config = child_config(&state, &worker_id).await;
        assert!(!config.configuration_admitted);
        assert!(
            config
                .configuration_error
                .contains("repair credential bindings"),
            "{}",
            config.configuration_error
        );
        assert_eq!(config.policy_validation_failure_mode, "fail_closed");

        let lead_config = super::super::policy::handle_get_sandbox_config(
            &state,
            sandbox_request(
                &lead_id,
                openshell_core::proto::GetSandboxConfigRequest {
                    name: "lead".to_string(),
                    workspace_scope: Some(default_scope()),
                },
            ),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(
            lead_config.policy_validation_failure_mode,
            "retain_last_valid"
        );
    }

    #[tokio::test]
    async fn child_proposals_are_rejected_and_not_stored() {
        let state = child_sandboxes_state().await;
        let worker_id = put_lead_and_worker(&state).await;

        let response = super::super::policy::handle_submit_policy_analysis(
            &state,
            authed_request(openshell_core::proto::SubmitPolicyAnalysisRequest {
                workspace_scope: Some(default_scope()),
                name: "worker1".to_string(),
                analysis_mode: "agent_authored".to_string(),
                proposed_chunks: vec![openshell_core::proto::PolicyChunk {
                    rule_name: "api".to_string(),
                    proposed_rule: lead_policy(false).network_policies.remove("api"),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        )
        .await
        .expect("the submission itself succeeds")
        .into_inner();

        assert_eq!(response.accepted_chunks, 0);
        assert_eq!(response.rejected_chunks, 1);
        assert!(
            response.rejection_reasons[0].contains("child sandboxes use their parent's policy"),
            "{:?}",
            response.rejection_reasons
        );
        let stored = state
            .store
            .list_draft_chunks(&worker_id, None)
            .await
            .unwrap();
        assert!(stored.is_empty(), "a child's proposal must not be stored");
    }

    #[tokio::test]
    async fn approving_a_proposal_on_a_child_is_refused() {
        let state = child_sandboxes_state().await;
        put_lead_and_worker(&state).await;

        let err = super::super::policy::handle_approve_draft_chunk(
            &state,
            authed_request(openshell_core::proto::ApproveDraftChunkRequest {
                sandbox: "worker1".to_string(),
                workspace_scope: Some(default_scope()),
                chunk_id: "chunk-1".to_string(),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(
            err.message()
                .contains("child sandboxes use their parent's policy"),
            "{}",
            err.message()
        );
    }

    #[tokio::test]
    async fn attaching_a_provider_the_parent_lacks_to_a_child_is_refused() {
        let state = child_sandboxes_state().await;
        put_lead_and_worker(&state).await;

        let err = handle_attach_sandbox_provider(
            &state,
            authed_request(AttachSandboxProviderRequest {
                request_id: String::new(),
                sandbox: "worker1".to_string(),
                workspace_scope: Some(default_scope()),
                provider: "work-github".to_string(),
                expected_resource_version: 0,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(
            err.message()
                .contains("provider 'work-github' is not attached to parent 'lead'"),
            "{}",
            err.message()
        );
    }

    #[tokio::test]
    async fn a_child_being_deleted_keeps_its_slot_until_its_record_is_gone() {
        let state = child_sandboxes_state_with_limit(2).await;
        let lead_id = put_parent_record(&state, "lead", &[], None, false).await;
        let link = openshell_core::proto::SandboxParent {
            name: "lead".to_string(),
            id: lead_id,
        };
        put_parent_record(&state, "worker1", &[], Some(link.clone()), false).await;
        let leaving = put_parent_record(&state, "worker2", &[], Some(link), true).await;
        let create = || {
            handle_create_sandbox(
                &state,
                authed_request(child_request("worker3", "lead", SandboxSpec::default())),
            )
        };

        let err = create().await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert_eq!(
            err.message(),
            "sandbox 'lead' has reached its limit of 2 children, \
             1 of them still being deleted; try again shortly"
        );

        // The driver finished removing it, so its record is gone.
        state
            .store
            .delete(Sandbox::object_type(), &leaving)
            .await
            .unwrap();
        create()
            .await
            .expect("the slot is free once the delete finishes");
    }

    #[tokio::test]
    async fn create_child_sandbox_stops_at_the_limit() {
        let state = child_sandboxes_state_with_limit(2).await;
        put_parent_record(&state, "lead", &[], None, false).await;
        put_parent_record(&state, "other-lead", &[], None, false).await;

        for name in ["worker1", "worker2"] {
            handle_create_sandbox(
                &state,
                authed_request(child_request(name, "lead", SandboxSpec::default())),
            )
            .await
            .expect("a child under the limit is created");
        }
        let err = handle_create_sandbox(
            &state,
            authed_request(child_request("worker3", "lead", SandboxSpec::default())),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert!(
            err.message()
                .contains("sandbox 'lead' has reached its limit of 2 children"),
            "{}",
            err.message()
        );

        // Each parent has its own limit.
        handle_create_sandbox(
            &state,
            authed_request(child_request(
                "worker4",
                "other-lead",
                SandboxSpec::default(),
            )),
        )
        .await
        .expect("another parent's children do not count");
    }

    #[tokio::test]
    async fn create_child_sandbox_with_zero_limit_is_refused() {
        let state = child_sandboxes_state_with_limit(0).await;
        put_parent_record(&state, "lead", &[], None, false).await;

        let err = handle_create_sandbox(
            &state,
            authed_request(child_request("worker1", "lead", SandboxSpec::default())),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn concurrent_child_creates_never_exceed_the_limit() {
        let state = child_sandboxes_state_with_limit(3).await;
        put_parent_record(&state, "lead", &[], None, false).await;

        let creates = (0..8).map(|index| {
            let state = state.clone();
            tokio::spawn(async move {
                handle_create_sandbox(
                    &state,
                    authed_request(child_request(
                        &format!("worker{index}"),
                        "lead",
                        SandboxSpec::default(),
                    )),
                )
                .await
            })
        });
        let successes = future::join_all(creates)
            .await
            .into_iter()
            .filter_map(|joined| joined.expect("create task").ok())
            .count();
        assert_eq!(successes, 3);
    }

    #[tokio::test]
    async fn create_child_sandbox_is_refused_when_disabled() {
        let state = test_server_state().await;
        put_parent_record(&state, "lead", &[], None, false).await;

        let err = handle_create_sandbox(
            &state,
            authed_request(child_request("worker1", "lead", SandboxSpec::default())),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(err.message().contains("child sandboxes are disabled"));
    }

    #[tokio::test]
    async fn create_child_sandbox_refuses_an_invalid_parent_or_request() {
        let state = child_sandboxes_state().await;
        let lead_id = put_parent_record(&state, "lead", &["work-github"], None, false).await;
        put_parent_record(
            &state,
            "worker1",
            &[],
            Some(openshell_core::proto::SandboxParent {
                name: "lead".to_string(),
                id: lead_id,
            }),
            false,
        )
        .await;
        put_parent_record(&state, "leaving", &[], None, true).await;

        let cases = [
            (
                "missing",
                SandboxSpec::default(),
                tonic::Code::FailedPrecondition,
                "parent sandbox 'missing' not found",
            ),
            (
                "leaving",
                SandboxSpec::default(),
                tonic::Code::FailedPrecondition,
                "parent sandbox 'leaving' is being deleted",
            ),
            (
                "worker1",
                SandboxSpec::default(),
                tonic::Code::FailedPrecondition,
                "only one level of child sandboxes is supported",
            ),
            (
                "lead",
                SandboxSpec {
                    policy: Some(openshell_core::proto::SandboxPolicy::default()),
                    ..Default::default()
                },
                tonic::Code::InvalidArgument,
                "a child sandbox uses its parent's policy",
            ),
            (
                "lead",
                SandboxSpec {
                    providers: vec!["work-slack".to_string()],
                    ..Default::default()
                },
                tonic::Code::FailedPrecondition,
                "provider 'work-slack' is not attached to parent 'lead'",
            ),
        ];
        for (parent, spec, code, message) in cases {
            let err = handle_create_sandbox(
                &state,
                authed_request(child_request("nested", parent, spec)),
            )
            .await
            .unwrap_err();
            assert_eq!(err.code(), code, "{parent}: {}", err.message());
            assert!(
                err.message().contains(message),
                "{parent}: {}",
                err.message()
            );
        }
    }

    #[tokio::test]
    async fn create_sandbox_rejects_a_provider_whose_profile_is_absent() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("orphan", "never-imported"))
            .await
            .unwrap();

        let err = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                parent: String::new(),
                request_id: String::new(),
                name: "orphan-sandbox".to_string(),
                spec: Some(SandboxSpec {
                    providers: vec!["orphan".to_string()],
                    ..Default::default()
                }),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                await_main_process_attachment: false,
                workload_template: String::new(),
                service_exposures: Vec::new(),
            }),
        )
        .await
        .expect_err("a provider with no profile must not compose a sandbox");

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        let message = err.message();
        assert!(message.contains("'orphan'"), "{message}");
        assert!(message.contains("'never-imported'"), "{message}");
        assert!(
            message.contains("openshell provider profile import"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn attach_sandbox_provider_rejects_a_provider_whose_profile_is_absent() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("orphan", "never-imported"))
            .await
            .unwrap();
        state
            .store
            .put_message(&test_sandbox("work", Vec::new()))
            .await
            .unwrap();

        let err = handle_attach_sandbox_provider(
            &state,
            authed_request(AttachSandboxProviderRequest {
                request_id: String::new(),
                sandbox: "work".to_string(),
                provider: "orphan".to_string(),
                expected_resource_version: 0,
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
            }),
        )
        .await
        .expect_err("a provider with no profile must not attach");

        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        let message = err.message();
        assert!(message.contains("'never-imported'"), "{message}");
        assert!(
            message.contains("openshell provider profile import"),
            "{message}"
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
                parent: String::new(),
                request_id: String::new(),
                name: "reserved-policy-key".to_string(),
                spec: Some(SandboxSpec {
                    policy: Some(policy),
                    ..Default::default()
                }),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                await_main_process_attachment: false,
                workload_template: String::new(),
                service_exposures: Vec::new(),
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
                    policy: Some(mcp_policy_with_versions(&[
                        "2026-07-28",
                        "2025-11-25",
                        "2025-03-26",
                    ])),
                    ..Default::default()
                }),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
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
        assert_eq!(versions, &["2025-03-26", "2025-11-25", "2026-07-28"]);
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
                    workspace_scope: Some(openshell_core::proto::workspace_selector(
                        "default".to_string(),
                    )),
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
                        workspace_scope: Some(openshell_core::proto::workspace_selector(
                            "default".to_string(),
                        )),
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
            ("mcp-unsupported-version", &["2026-07-29"]),
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
                    workspace_scope: Some(openshell_core::proto::workspace_selector(
                        "default".to_string(),
                    )),
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
                parent: String::new(),
                request_id: String::new(),
                name: "annotated".to_string(),
                spec: Some(SandboxSpec::default()),
                labels: HashMap::new(),
                annotations: HashMap::from([(annotation_key.clone(), annotation_value.clone())]),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                await_main_process_attachment: false,
                workload_template: String::new(),
                service_exposures: Vec::new(),
            }),
        )
        .await
        .expect("long annotations should be accepted")
        .into_inner();

        let created = response.sandbox.expect("created sandbox");
        assert_eq!(
            created.spec.as_ref().unwrap().restart_policy(),
            SandboxRestartPolicy::Never
        );
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
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
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
    async fn create_sandbox_rejects_reserved_annotations() {
        let state = test_server_state().await;

        let err = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                parent: String::new(),
                request_id: String::new(),
                name: "reserved".to_string(),
                spec: Some(SandboxSpec::default()),
                labels: HashMap::new(),
                annotations: HashMap::from([(
                    "internal.openshell.ai/compute-driver".to_string(),
                    "x".to_string(),
                )]),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                await_main_process_attachment: false,
                workload_template: String::new(),
                service_exposures: Vec::new(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("internal.openshell.ai/"));
        assert!(
            state
                .store
                .get_message_by_name::<Sandbox>("default", "reserved")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn single_replica_get_sandbox_sends_no_owner_hint() {
        let state = test_server_state().await;
        let mut sandbox = test_sandbox("hinted", Vec::new());
        sandbox.metadata.as_mut().unwrap().workspace = "default".to_string();
        state.store.put_message(&sandbox).await.unwrap();
        state.supervisor_sessions.register(
            sandbox.object_id().to_string(),
            "session-a".to_string(),
            mpsc::channel(1).0,
            oneshot::channel().0,
        );

        let mut request = authed_request(GetSandboxRequest {
            name: "hinted".to_string(),
            workspace_scope: Some(openshell_core::proto::workspace_selector(
                "default".to_string(),
            )),
        });
        request.metadata_mut().insert(
            openshell_core::replica_routing::OWNER_REQUEST_HEADER,
            "1".parse().unwrap(),
        );
        let response = handle_get_sandbox(&state, request).await.unwrap();
        assert!(
            response
                .metadata()
                .get(openshell_core::replica_routing::OWNER_REPLICA_HEADER)
                .is_none()
        );
    }

    #[test]
    fn owner_is_resolved_only_when_requested() {
        let mut request = Request::new(());
        assert!(!owner_requested(&request));
        request.metadata_mut().insert(
            openshell_core::replica_routing::OWNER_REQUEST_HEADER,
            "1".parse().unwrap(),
        );
        assert!(owner_requested(&request));
    }

    #[tokio::test]
    async fn create_sandbox_registers_requested_service_exposures() {
        let state = test_server_state().await;

        let response = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                name: "services".to_string(),
                spec: Some(SandboxSpec::default()),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                service_exposures: vec![
                    SandboxServiceExposure {
                        service: String::new(),
                        target_port: 4500,
                        authorization_mode: ServiceAuthorizationMode::Unspecified as i32,
                    },
                    SandboxServiceExposure {
                        service: "metrics".to_string(),
                        target_port: 9090,
                        authorization_mode: ServiceAuthorizationMode::BearerPassthrough as i32,
                    },
                ],
                ..Default::default()
            }),
        )
        .await
        .expect("sandbox with service exposures should be created")
        .into_inner();

        let sandbox = response.sandbox.expect("created sandbox");
        assert_eq!(response.service_urls.len(), 2);
        assert_eq!(
            response.service_urls.get("").map(String::as_str),
            Some("http://default--services.openshell.localhost:17670/")
        );
        assert_eq!(
            response.service_urls.get("metrics").map(String::as_str),
            Some("http://default--services--metrics.openshell.localhost:17670/")
        );
        for (service, target_port) in [("", 4500), ("metrics", 9090)] {
            let key = crate::service_routing::endpoint_key("services", service);
            let endpoint = state
                .store
                .get_message_by_name::<ServiceEndpoint>("default", &key)
                .await
                .expect("service endpoint lookup should succeed")
                .expect("service endpoint should be persisted");
            assert_eq!(endpoint.sandbox_id, sandbox.object_id());
            assert_eq!(endpoint.sandbox, "services");
            assert_eq!(endpoint.name, service);
            assert_eq!(endpoint.target_port, target_port);
            assert!(endpoint.domain);
            let expected_mode = if service.is_empty() {
                ServiceAuthorizationMode::Strip
            } else {
                ServiceAuthorizationMode::BearerPassthrough
            };
            assert_eq!(endpoint.authorization_mode(), expected_mode);
        }
    }

    #[tokio::test]
    async fn create_sandbox_rejects_unknown_service_authorization_mode_before_persisting() {
        let state = test_server_state().await;
        let error = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                name: "invalid-service-authorization".to_string(),
                spec: Some(SandboxSpec::default()),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                service_exposures: vec![SandboxServiceExposure {
                    service: String::new(),
                    target_port: 4500,
                    authorization_mode: 99,
                }],
                ..Default::default()
            }),
        )
        .await
        .expect_err("unknown service authorization mode should be rejected");

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(
            state
                .store
                .get_message_by_name::<Sandbox>("default", "invalid-service-authorization")
                .await
                .expect("sandbox lookup should succeed")
                .is_none()
        );
    }

    #[tokio::test]
    async fn create_sandbox_begins_rollback_when_service_exposure_fails() {
        let state = test_server_state().await;
        let corrupt_service_key =
            crate::service_routing::endpoint_key("rollback-services", "metrics");
        state
            .store
            .put_if(
                ServiceEndpoint::object_type(),
                "corrupt-service-endpoint",
                &corrupt_service_key,
                "default",
                b"not-a-service-endpoint",
                None,
                WriteCondition::MustCreate,
            )
            .await
            .expect("corrupt service endpoint fixture should be stored");

        let error = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                name: "rollback-services".to_string(),
                spec: Some(SandboxSpec::default()),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                service_exposures: vec![
                    SandboxServiceExposure {
                        service: "web".to_string(),
                        target_port: 8080,
                        authorization_mode: ServiceAuthorizationMode::Strip as i32,
                    },
                    SandboxServiceExposure {
                        service: "metrics".to_string(),
                        target_port: 9090,
                        authorization_mode: ServiceAuthorizationMode::Strip as i32,
                    },
                ],
                ..Default::default()
            }),
        )
        .await
        .expect_err("corrupt endpoint should fail sandbox creation");

        assert_eq!(error.code(), tonic::Code::Internal);
        assert!(error.message().contains("fetch endpoint failed"));
        let sandbox = state
            .store
            .get_message_by_name::<Sandbox>("default", "rollback-services")
            .await
            .expect("sandbox lookup should succeed")
            .expect("asynchronous driver cleanup retains a deleting record");
        assert_eq!(
            SandboxPhase::try_from(sandbox.phase()).ok(),
            Some(SandboxPhase::Deleting),
            "failed create must begin sandbox cleanup"
        );
    }

    #[tokio::test]
    async fn create_rollback_by_id_preserves_same_name_replacement() {
        let state = test_server_state().await;
        let original = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                name: "rollback-replace".to_string(),
                spec: Some(SandboxSpec::default()),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                ..Default::default()
            }),
        )
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
        let original_id = original.object_id().to_string();
        let original_name = original.object_name().to_string();

        state
            .store
            .delete(Sandbox::object_type(), &original_id)
            .await
            .unwrap();
        let mut replacement = original;
        let replacement_id = uuid::Uuid::new_v4().to_string();
        let metadata = replacement.metadata.as_mut().unwrap();
        metadata.id.clone_from(&replacement_id);
        metadata.resource_version = 0;
        state.store.put_message(&replacement).await.unwrap();

        state
            .compute
            .delete_sandbox_by_id(&original_id, &original_name)
            .await
            .unwrap();

        let stored = state
            .store
            .get_message_by_name::<Sandbox>("default", &original_name)
            .await
            .unwrap()
            .expect("replacement must survive rollback for the original ID");
        assert_eq!(stored.object_id(), replacement_id);
    }

    #[tokio::test]
    async fn create_sandbox_rejects_duplicate_service_exposures_before_persisting() {
        let state = test_server_state().await;
        let error = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                name: "duplicate-services".to_string(),
                spec: Some(SandboxSpec::default()),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                service_exposures: vec![
                    SandboxServiceExposure {
                        service: "web".to_string(),
                        target_port: 8080,
                        authorization_mode: ServiceAuthorizationMode::Strip as i32,
                    },
                    SandboxServiceExposure {
                        service: "web".to_string(),
                        target_port: 8081,
                        authorization_mode: ServiceAuthorizationMode::Strip as i32,
                    },
                ],
                ..Default::default()
            }),
        )
        .await
        .expect_err("duplicate service names should be rejected");

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("duplicate service exposure name"));
        assert!(
            state
                .store
                .get_message_by_name::<Sandbox>("default", "duplicate-services")
                .await
                .expect("sandbox lookup should succeed")
                .is_none()
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
                parent: String::new(),
                request_id: String::new(),
                name: "partial-id".to_string(),
                spec: Some(SandboxSpec {
                    policy: Some(policy),
                    ..Default::default()
                }),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                await_main_process_attachment: false,
                workload_template: String::new(),
                service_exposures: Vec::new(),
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
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
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
                parent: String::new(),
                request_id: String::new(),
                name: "kube-partial-id".to_string(),
                spec: Some(SandboxSpec {
                    policy: Some(policy),
                    ..Default::default()
                }),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                await_main_process_attachment: false,
                workload_template: String::new(),
                service_exposures: Vec::new(),
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

    #[test]
    fn create_sandbox_accepts_more_than_128_labels() {
        let request = CreateSandboxRequest {
            name: "many-labels".into(),
            spec: Some(SandboxSpec::default()),
            labels: (0..129)
                .map(|index| (format!("label-{index}"), "value".into()))
                .collect(),
            ..Default::default()
        };
        for workload_template in ["", "workload-template"] {
            validate_create_sandbox_request_pre_io(&request, workload_template).unwrap();
        }
    }

    #[tokio::test]
    async fn create_sandbox_still_rejects_long_label_values() {
        let state = test_server_state().await;
        let err = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                parent: String::new(),
                request_id: String::new(),
                name: "bad-label".to_string(),
                spec: Some(SandboxSpec::default()),
                labels: HashMap::from([("team".to_string(), "x".repeat(512))]),
                annotations: HashMap::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                await_main_process_attachment: false,
                workload_template: String::new(),
                service_exposures: Vec::new(),
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("label value exceeds"));
    }

    #[tokio::test]
    async fn create_sandbox_with_providers_waits_for_workspace_mutation_guard() {
        let state = test_server_state().await;
        state
            .store
            .put_message(&test_provider("work-github", "github"))
            .await
            .unwrap();

        // A provider writer in the workspace excludes creates that validate
        // against its providers.
        let guard = state
            .compute
            .mutation_guard(MutationScope::Workspace("default"))
            .await
            .unwrap();
        let task_state = state.clone();
        let task = tokio::spawn(async move {
            handle_create_sandbox(
                &task_state,
                authed_request(CreateSandboxRequest {
                    parent: String::new(),
                    request_id: String::new(),
                    name: "guarded-create".to_string(),
                    spec: Some(SandboxSpec {
                        providers: vec!["work-github".to_string()],
                        ..Default::default()
                    }),
                    labels: HashMap::new(),
                    annotations: HashMap::new(),
                    workspace_scope: Some(openshell_core::proto::workspace_selector(
                        "default".to_string(),
                    )),
                    await_main_process_attachment: false,
                    workload_template: String::new(),
                    service_exposures: Vec::new(),
                }),
            )
            .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            !task.is_finished(),
            "sandbox create with initial providers should wait for the workspace mutation guard"
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
                request_id: String::new(),
                template: Some(test_workload_template("gpu-kata")),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
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
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
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
                page_size: 100,
                page_token: String::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
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
                request_id: String::new(),
                allow_missing: false,
                name: "gpu-kata".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
            }),
        )
        .await
        .expect("template delete should succeed")
        .into_inner();
        assert_eq!(
            deleted.outcome(),
            openshell_core::proto::DeletionOutcome::Completed
        );

        let missing = handle_get_sandbox_template(
            &state,
            authed_request(GetSandboxTemplateRequest {
                name: "gpu-kata".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
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
                request_id: String::new(),
                template: Some(gpu),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
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
                request_id: String::new(),
                template: Some(cpu),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
            }),
        )
        .await
        .expect("cpu template create should succeed");

        let listed = handle_list_sandbox_templates(
            &state,
            authed_request(ListSandboxTemplatesRequest {
                page_size: 100,
                page_token: String::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
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
                request_id: String::new(),
                template: Some(test_workload_template(" gpu-kata ")),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
            }),
        )
        .await
        .expect_err("template names must be canonical DNS-1123 labels");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("template.metadata.name"));

        let listed = handle_list_sandbox_templates(
            &state,
            authed_request(ListSandboxTemplatesRequest {
                page_size: 100,
                page_token: String::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
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
                request_id: String::new(),
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
                request_id: String::new(),
                template: Some(template),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
            }),
        )
        .await
        .expect_err("empty request workspace must default to default, not metadata workspace");

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("template.metadata.workspace"));

        let listed = handle_list_sandbox_templates(
            &state,
            authed_request(ListSandboxTemplatesRequest {
                page_size: 100,
                page_token: String::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "beta".to_string(),
                )),
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
                request_id: String::new(),
                template: Some(template),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
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
                request_id: String::new(),
                template: Some(test_workload_template("overflow")),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
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
                        request_id: String::new(),
                        template: Some(test_workload_template(&format!("overflow-{index}"))),
                        workspace_scope: Some(openshell_core::proto::workspace_selector(
                            "default".to_string(),
                        )),
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
            &["policy", "providers", "command", "tty", "restart_policy"],
            &[
                "log_level",
                "environment",
                "template",
                "resource_requirements",
            ],
            &["provider_attachment_epoch"],
        );
    }

    fn assert_proto_fields_classified(
        message_name: &str,
        copied_from_create_request: &[&str],
        rejected_template_workload_overrides: &[&str],
        generated_by_gateway: &[&str],
    ) {
        let pool = prost_reflect::DescriptorPool::decode(openshell_core::FILE_DESCRIPTOR_SET)
            .expect("decode descriptor set");
        let message = pool
            .get_message_by_name(message_name)
            .expect("message descriptor");
        let classified: HashSet<&str> = copied_from_create_request
            .iter()
            .chain(rejected_template_workload_overrides.iter())
            .chain(generated_by_gateway.iter())
            .copied()
            .collect();
        assert_eq!(
            classified.len(),
            copied_from_create_request.len()
                + rejected_template_workload_overrides.len()
                + generated_by_gateway.len(),
            "every field must have exactly one create-time owner"
        );
        let actual: HashSet<String> = message
            .fields()
            .map(|field| field.name().to_string())
            .collect();

        for field in &actual {
            assert!(
                classified.contains(field.as_str()),
                "{message_name}.{field} is not classified for template-backed sandbox creates. \
                 Add it to copied_from_create_request when callers own the create-time value, \
                 to rejected_template_workload_overrides when the workload template owns it, \
                 or to generated_by_gateway when the gateway replaces the caller's value."
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
    async fn create_sandbox_ignores_caller_provider_attachment_epoch() {
        let state = test_server_state().await;
        handle_create_sandbox_template(
            &state,
            authed_request(CreateSandboxTemplateRequest {
                request_id: String::new(),
                template: Some(test_workload_template("epoch-template")),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
            }),
        )
        .await
        .unwrap();
        let supplied_epoch = uuid::Uuid::new_v4().to_string();
        let mut generated_epochs = HashSet::new();
        for (name, workload_template_name) in
            [("direct-epoch", ""), ("template-epoch", "epoch-template")]
        {
            let created = handle_create_sandbox(
                &state,
                authed_request(CreateSandboxRequest {
                    name: name.to_string(),
                    spec: Some(SandboxSpec {
                        provider_attachment_epoch: supplied_epoch.clone(),
                        ..Default::default()
                    }),
                    workload_template: workload_template_name.to_string(),
                    workspace_scope: Some(openshell_core::proto::workspace_selector(
                        "default".to_string(),
                    )),
                    ..Default::default()
                }),
            )
            .await
            .unwrap()
            .into_inner()
            .sandbox
            .unwrap();
            let epoch = &created.spec.as_ref().unwrap().provider_attachment_epoch;
            assert_ne!(epoch, &supplied_epoch);
            assert!(uuid::Uuid::parse_str(epoch).is_ok());
            assert!(generated_epochs.insert(epoch.clone()));
            let stored = state
                .store
                .get_message::<Sandbox>(created.object_id())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&stored.spec.unwrap().provider_attachment_epoch, epoch);
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
                request_id: String::new(),
                template: Some(test_workload_template("gpu-kata")),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
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
                parent: String::new(),
                request_id: String::new(),
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
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                workload_template: "gpu-kata".to_string(),
                await_main_process_attachment: false,
                service_exposures: Vec::new(),
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
                request_id: String::new(),
                template: Some(template),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
            }),
        )
        .await
        .expect("template create should succeed");

        let created = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                parent: String::new(),
                request_id: String::new(),
                name: "from-template".to_string(),
                spec: Some(SandboxSpec::default()),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                workload_template: "default-image".to_string(),
                await_main_process_attachment: false,
                service_exposures: Vec::new(),
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
                request_id: String::new(),
                template: Some(template),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
            }),
        )
        .await
        .expect("template create should succeed");

        let created = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                parent: String::new(),
                request_id: String::new(),
                name: "from-template".to_string(),
                spec: Some(SandboxSpec::default()),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                workload_template: "default-gpu".to_string(),
                await_main_process_attachment: false,
                service_exposures: Vec::new(),
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
                parent: String::new(),
                request_id: String::new(),
                name: "from-corrupt".to_string(),
                spec: Some(SandboxSpec::default()),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                workload_template: "corrupt-template".to_string(),
                await_main_process_attachment: false,
                service_exposures: Vec::new(),
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
                request_id: String::new(),
                template: Some(test_workload_template("gpu-kata")),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
            }),
        )
        .await
        .expect("template create should succeed");

        let err = handle_create_sandbox(
            &state,
            authed_request(CreateSandboxRequest {
                parent: String::new(),
                request_id: String::new(),
                name: "bad-template-create".to_string(),
                spec: Some(SandboxSpec {
                    environment: HashMap::from([("INLINE".to_string(), "blocked".to_string())]),
                    ..Default::default()
                }),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                workload_template: "gpu-kata".to_string(),
                await_main_process_attachment: false,
                service_exposures: Vec::new(),
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
                parent: String::new(),
                request_id: String::new(),
                name: "bad-template-create".to_string(),
                spec: Some(SandboxSpec::default()),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                workload_template: "Invalid_Template_Name".to_string(),
                await_main_process_attachment: false,
                service_exposures: Vec::new(),
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
                parent: String::new(),
                request_id: String::new(),
                name: "bad-template-create".to_string(),
                spec: Some(SandboxSpec {
                    providers: (0..=MAX_PROVIDERS).map(|i| format!("p-{i}")).collect(),
                    ..Default::default()
                }),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                workload_template: "missing-template".to_string(),
                await_main_process_attachment: false,
                service_exposures: Vec::new(),
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
                parent: String::new(),
                request_id: String::new(),
                name: "bad-direct-create".to_string(),
                spec: Some(SandboxSpec {
                    providers: (0..=MAX_PROVIDERS).map(|i| format!("p-{i}")).collect(),
                    ..Default::default()
                }),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "missing-workspace".to_string(),
                )),
                workload_template: String::new(),
                await_main_process_attachment: false,
                service_exposures: Vec::new(),
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
        import_test_profile(&state, "outlook").await;
        import_test_profile(&state, "google-drive").await;
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
                request_id: String::new(),
                sandbox: "work".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                provider: "provider-b".to_string(),
                expected_resource_version: 0,
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
        import_test_profile(&state, "generic").await;

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
                request_id: String::new(),
                sandbox: "work".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                provider: "provider-31".to_string(),
                expected_resource_version: 0,
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
        import_test_profile(&state, "generic").await;

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
                request_id: String::new(),
                sandbox: "work".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                provider: "provider-32".to_string(),
                expected_resource_version: 0,
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
        import_test_profile(&state, "generic").await;
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
                request_id: String::new(),
                sandbox: "work".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                provider: long_name,
                expected_resource_version: 0,
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
                request_id: String::new(),
                sandbox: "work".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                provider: long_name,
                expected_resource_version: 0,
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn concurrent_create_ssh_session_prevents_duplicate_tokens() {
        let state = test_server_state().await;
        let mut sandbox = test_sandbox("work", Vec::new());
        sandbox.host_key_fingerprint = "SHA256:public-host-identity".to_string();
        state.store.put_message(&sandbox).await.unwrap();

        // Both requests try to create sessions for the same sandbox
        // The token generation is random, so we can't force a collision,
        // but we can verify that both succeed with different tokens
        let state1 = state.clone();
        let handle1 = tokio::spawn(async move {
            handle_create_ssh_session(
                &state1,
                authed_request(CreateSshSessionRequest {
                    sandbox: "work".to_string(),
                    workspace_scope: Some(openshell_core::proto::workspace_selector(
                        "default".to_string(),
                    )),
                }),
            )
            .await
        });

        let state2 = state.clone();
        let handle2 = tokio::spawn(async move {
            handle_create_ssh_session(
                &state2,
                authed_request(CreateSshSessionRequest {
                    sandbox: "work".to_string(),
                    workspace_scope: Some(openshell_core::proto::workspace_selector(
                        "default".to_string(),
                    )),
                }),
            )
            .await
        });

        let result1 = handle1.await.unwrap();
        let result2 = handle2.await.unwrap();

        // Both should succeed (tokens are random UUIDs, collision is astronomically unlikely)
        assert!(result1.is_ok(), "first create should succeed");
        assert!(result2.is_ok(), "second create should succeed");

        let response1 = result1.unwrap().into_inner();
        let response2 = result2.unwrap().into_inner();
        assert_eq!(response1.host_key_fingerprint, sandbox.host_key_fingerprint);
        assert_eq!(response2.host_key_fingerprint, sandbox.host_key_fingerprint);
        let token1 = response1.token;
        let token2 = response2.token;

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
                sandbox: "work".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
            }),
        )
        .await;

        assert!(response.is_ok());

        assert!(
            state
                .supervisor_sessions
                .finalize_main_process_exit("sandbox-work")
        );
        assert!(sandbox_relay_reachable(&state, &sandbox));

        assert!(state.supervisor_sessions.disconnect("sandbox-work"));
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
                sandbox: "work".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
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
                authed_request(RevokeSshSessionRequest {
                    allow_missing: false,
                    token: token1,
                }),
            )
            .await
        });

        let state2 = state.clone();
        let token2 = token.clone();
        let handle2 = tokio::spawn(async move {
            handle_revoke_ssh_session(
                &state2,
                authed_request(RevokeSshSessionRequest {
                    allow_missing: false,
                    token: token2,
                }),
            )
            .await
        });

        let result1 = handle1.await.unwrap();
        let result2 = handle2.await.unwrap();

        // One should succeed, one may fail with ABORTED due to CAS conflict
        let successes = [&result1, &result2]
            .iter()
            .filter(|r| {
                r.is_ok()
                    && r.as_ref().unwrap().get_ref().outcome()
                        == openshell_core::proto::DeletionOutcome::Completed
            })
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn server_managed_sandbox_cas_retries_concurrent_updates() {
        use std::sync::Barrier;

        const WRITERS: usize = 5;

        let state = Arc::new(test_server_state().await);
        let sandbox = test_sandbox("server-cas-retry", Vec::new());
        let sandbox_id = sandbox.object_id().to_string();
        state.store.put_message(&sandbox).await.unwrap();

        let barrier = Arc::new(Barrier::new(WRITERS));
        let mut handles = Vec::with_capacity(WRITERS);
        for _ in 0..WRITERS {
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            let sandbox_id = sandbox_id.clone();
            handles.push(tokio::spawn(async move {
                let mut first_attempt = true;
                update_sandbox_cas(&state, &sandbox_id, 0, |sandbox| {
                    if first_attempt {
                        first_attempt = false;
                        // Hand off queued work so SQLx can return the connection to other writers.
                        tokio::task::block_in_place(|| barrier.wait());
                    }
                    let annotations = &mut sandbox.metadata.as_mut().unwrap().annotations;
                    let count = annotations
                        .get("internal-update-count")
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap_or_default();
                    annotations
                        .insert("internal-update-count".to_string(), (count + 1).to_string());
                })
                .await
            }));
        }

        for result in future::join_all(handles).await {
            result.unwrap().unwrap();
        }

        let updated = state
            .store
            .get_message::<Sandbox>(&sandbox_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            updated.metadata.as_ref().unwrap().annotations["internal-update-count"],
            WRITERS.to_string()
        );
        assert_eq!(updated.get_resource_version(), WRITERS as u64 + 1);
    }

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
                request_id: String::new(),
                sandbox: "work".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                provider: "github".to_string(),
                expected_resource_version: current_version,
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
                request_id: String::new(),
                sandbox: "work".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                provider: "github".to_string(),
                expected_resource_version: 99,
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
                request_id: String::new(),
                sandbox: "work".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                provider: "github".to_string(),
                expected_resource_version: current_version,
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
                request_id: String::new(),
                sandbox: "work".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
                provider: "github".to_string(),
                expected_resource_version: 99,
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
        import_test_profile(&state, "generic").await;

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
                        request_id: String::new(),
                        sandbox: "work".to_string(),
                        workspace_scope: Some(openshell_core::proto::workspace_selector(
                            "default".to_string(),
                        )),
                        provider: format!("provider-{i}"),
                        expected_resource_version: initial_version,
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
                request_id: String::new(),
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
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
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
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "beta".to_string(),
                )),
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
                page_size: 100,
                page_token: String::new(),
                label_selector: String::new(),
                parent: String::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
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
                page_size: 100,
                page_token: String::new(),
                label_selector: String::new(),
                parent: String::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "beta".to_string(),
                )),
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
                page_size: 100,
                page_token: String::new(),
                label_selector: String::new(),
                parent: String::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
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
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "beta".to_string(),
                )),
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
                page_size: 100,
                page_token: String::new(),
                label_selector: String::new(),
                parent: String::new(),
                workspace_scope: Some(openshell_core::proto::all_workspaces_selector()),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(listed.sandboxes.len(), 2);
        let first_page = handle_list_sandboxes(
            &state,
            authed_request(ListSandboxesRequest {
                page_size: 1,
                page_token: String::new(),
                label_selector: String::new(),
                parent: String::new(),
                workspace_scope: Some(openshell_core::proto::all_workspaces_selector()),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(first_page.sandboxes.len(), 1);
        assert!(!first_page.next_page_token.is_empty());
        let second_page = handle_list_sandboxes(
            &state,
            authed_request(ListSandboxesRequest {
                page_size: 100,
                page_token: first_page.next_page_token,
                label_selector: String::new(),
                parent: String::new(),
                workspace_scope: Some(openshell_core::proto::all_workspaces_selector()),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(second_page.sandboxes.len(), 1);
        assert!(second_page.next_page_token.is_empty());
        assert_ne!(
            first_page.sandboxes[0].object_id(),
            second_page.sandboxes[0].object_id()
        );
    }

    #[tokio::test]
    async fn sandbox_naming_another_sandbox_is_recorded_as_cross_sandbox() {
        let state = test_server_state().await;
        for name in ["own", "victim"] {
            state
                .store
                .put_message(&test_sandbox(name, vec![]))
                .await
                .unwrap();
        }
        let principal = crate::auth::principal::test_support::sandbox("sandbox-own");
        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let _guard = capture.install();

        resolve_and_authorize_sandbox_name(
            &state,
            &principal,
            "own",
            "default",
            MinWorkspaceRole::User,
        )
        .await
        .expect("a sandbox may name itself");
        assert!(capture.events().is_empty(), "own sandbox is not a denial");

        let err = resolve_and_authorize_sandbox_name(
            &state,
            &principal,
            "victim",
            "default",
            MinWorkspaceRole::User,
        )
        .await
        .expect_err("another sandbox must be refused");

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        let events = capture.json_events();
        assert_eq!(events.len(), 2, "{events:?}");
        assert_eq!(events[0]["status_detail"], "cross_sandbox");
        assert_eq!(
            events[0]["resources"],
            serde_json::json!([{"name": "victim", "type": "sandbox"}])
        );
        assert_boundary_finding(&events[0], &events[1]);
    }

    #[tokio::test]
    async fn sandbox_whose_own_record_is_gone_is_denied_without_a_finding() {
        let state = test_server_state().await;
        let principal = crate::auth::principal::test_support::sandbox("sandbox-own");
        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let _guard = capture.install();

        let err = resolve_and_authorize_sandbox_name(
            &state,
            &principal,
            "own",
            "default",
            MinWorkspaceRole::User,
        )
        .await
        .expect_err("a deleted sandbox must be refused");

        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(capture.events().is_empty(), "deletion is not misuse");
    }

    /// Workspace collection operations reject non-members, while operations on
    /// a sandbox reference hide both missing and unauthorized sandboxes as
    /// `NOT_FOUND` to avoid an object-existence oracle.
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
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "no-such-ws".to_string(),
                )),
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
                name: ("any").to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "no-such-ws".to_string(),
                )),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::NotFound,
            "handle_get_sandbox should hide unauthorized sandbox existence"
        );

        // --- handle_list_sandboxes ---
        let err = handle_list_sandboxes(
            &state,
            non_member_request(ListSandboxesRequest {
                workspace_scope: Some(openshell_core::proto::workspace_selector("no-such-ws")),
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
                sandbox: ("any").to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "no-such-ws".to_string(),
                )),
                page_size: 0,
                page_token: String::new(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::NotFound,
            "handle_list_sandbox_providers should hide unauthorized sandbox existence"
        );

        // --- handle_attach_sandbox_provider ---
        let err = handle_attach_sandbox_provider(
            &state,
            non_member_request(AttachSandboxProviderRequest {
                sandbox: ("any").to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "no-such-ws".to_string(),
                )),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::NotFound,
            "handle_attach_sandbox_provider should hide unauthorized sandbox existence"
        );

        // --- handle_detach_sandbox_provider ---
        let err = handle_detach_sandbox_provider(
            &state,
            non_member_request(DetachSandboxProviderRequest {
                sandbox: ("any").to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "no-such-ws".to_string(),
                )),
                ..Default::default()
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::NotFound,
            "handle_detach_sandbox_provider should hide unauthorized sandbox existence"
        );

        // --- handle_delete_sandbox ---
        // Provide a name so the handler passes the "name is required" check.
        let err = handle_delete_sandbox(
            &state,
            non_member_request(DeleteSandboxRequest {
                request_id: String::new(),
                allow_missing: false,
                name: ("any").to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "no-such-ws".to_string(),
                )),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.code(),
            Code::NotFound,
            "handle_delete_sandbox should hide unauthorized sandbox existence"
        );

        for result in [
            handle_stop_sandbox(
                &state,
                non_member_request(StopSandboxRequest {
                    request_id: String::new(),
                    name: ("any").to_string(),
                    workspace_scope: Some(openshell_core::proto::workspace_selector(
                        "no-such-ws".to_string(),
                    )),
                }),
            )
            .await,
            handle_start_sandbox(
                &state,
                non_member_request(StartSandboxRequest {
                    request_id: String::new(),
                    name: ("any").to_string(),
                    workspace_scope: Some(openshell_core::proto::workspace_selector(
                        "no-such-ws".to_string(),
                    )),
                }),
            )
            .await,
        ] {
            assert_eq!(
                result.unwrap_err().code(),
                Code::NotFound,
                "lifecycle handlers should hide unauthorized sandbox existence"
            );
        }
    }

    /// Name-based data-plane handlers must return `NOT_FOUND` — never
    /// `PERMISSION_DENIED` — when the caller lacks workspace access, so that
    /// cross-workspace sandbox existence cannot be inferred (CWE-203).
    #[tokio::test]
    async fn name_based_handlers_hide_cross_workspace_sandboxes() {
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
        sandbox.set_phase(SandboxPhase::Completed as i32);
        state.store.put_message(&sandbox).await.unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        let _ = state.supervisor_sessions.register(
            sandbox.object_id().to_string(),
            "retained-terminal-session".to_string(),
            tx,
            shutdown_tx,
        );

        // --- handle_watch_sandbox ---
        let err = handle_watch_sandbox(
            &state,
            non_member_request(WatchSandboxRequest {
                sandbox: "cross-ws".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "other-workspace".to_string(),
                )),
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
                sandbox: "cross-ws".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "other-workspace".to_string(),
                )),
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
                sandbox: "ws-test".to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
            }),
        )
        .await
        .unwrap();
        let token = response.into_inner().token;

        handle_revoke_ssh_session(
            &state,
            authed_request(RevokeSshSessionRequest {
                allow_missing: false,
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

#[cfg(test)]
mod image_update_tests;
