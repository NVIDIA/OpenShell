// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! What audited mutations acted on and how they ended, read from their typed
//! requests and responses.

use std::future::Future;

use openshell_core::proto::datamodel::v1::ObjectMeta;
use openshell_core::proto::{
    AddWorkspaceMemberResponse, ApproveAllDraftChunksResponse, ApproveDraftChunkResponse,
    AttachSandboxProviderResponse, BeginRootfsTarStagingResponse, ClearDraftChunksResponse,
    ConfigureProviderRefreshResponse, CreateWorkspaceResponse, DeleteProviderProfileResponse,
    DeleteProviderRefreshResponse, DeleteProviderResponse, DeleteSandboxResponse,
    DeleteSandboxTemplateResponse, DeleteSecretResponse, DeleteServiceResponse,
    DeleteWorkspaceResponse, DeletionOutcome, DetachSandboxProviderResponse,
    EditDraftChunkResponse, ImportProviderProfilesResponse, InlineProviderRefreshSecretsResponse,
    ProviderCredentialRefreshStatus, ProviderProfile, ProviderResponse, RejectDraftChunkResponse,
    RemoveWorkspaceMemberResponse, RotateProviderCredentialResponse, Sandbox, SandboxResponse,
    SandboxTemplateResponse, SecretResponse, ServiceEndpointResponse, UndoDraftChunkResponse,
    UpdateConfigRequest, UpdateConfigResponse, UpdateProviderProfilesResponse, WorkspaceSelector,
    setting_value, workspace_selector::Selection,
};
use openshell_core::proto::{
    CreateSshSessionResponse, ExecSandboxRequest, RevokeSshSessionResponse, SshSession,
    TcpForwardInit, relay_open,
};
use openshell_core::settings::{self, SettingValueKind};
use openshell_core::{GatewayAuditConfig, ObjectName, ObjectWorkspace};
use openshell_ocsf::ResourceDetails;
use tonic::{Code, Response, Status};

use super::policy::POLICY_SETTING_KEY;
pub(super) use crate::auth::audit::requested;
use crate::auth::audit::{self, Outcome};

/// A resource as the gateway stored it. Empty fields are unknown.
pub(super) struct Produced<'a> {
    type_label: &'static str,
    name: &'a str,
    uid: &'a str,
}

/// A response to an audited mutation.
pub(super) trait Audited {
    /// The resources the call produced or changed.
    fn produced(&self) -> Vec<Produced<'_>> {
        Vec::new()
    }

    /// How a call that returned OK ended, such as
    /// `Outcome::Detail("no_op:unchanged")` or a rejection in the response.
    fn outcome(&self) -> Option<Outcome> {
        None
    }
}

fn deletion_outcome(outcome: DeletionOutcome) -> Option<Outcome> {
    match outcome {
        DeletionOutcome::AlreadyAbsent => Some(Outcome::Detail("no_op:already_absent")),
        DeletionOutcome::Accepted => Some(Outcome::Detail("accepted")),
        DeletionOutcome::Completed | DeletionOutcome::Unspecified => None,
    }
}

macro_rules! deletion {
    ($($response:ty),* $(,)?) => {
        $(impl Audited for $response {
            fn outcome(&self) -> Option<Outcome> {
                deletion_outcome(self.outcome())
            }
        })*
    };
}

deletion!(
    DeleteSandboxTemplateResponse,
    DeleteSecretResponse,
    DeleteServiceResponse,
    DeleteProviderResponse,
    DeleteProviderProfileResponse,
    DeleteProviderRefreshResponse,
    DeleteWorkspaceResponse,
    RemoveWorkspaceMemberResponse,
    RevokeSshSessionResponse,
);

impl Audited for DeleteSandboxResponse {
    fn produced(&self) -> Vec<Produced<'_>> {
        vec![Produced {
            type_label: "sandbox",
            name: "",
            uid: &self.sandbox_id,
        }]
    }

    fn outcome(&self) -> Option<Outcome> {
        deletion_outcome(self.outcome())
    }
}

fn stored<'a>(type_label: &'static str, metadata: Option<&'a ObjectMeta>) -> Vec<Produced<'a>> {
    metadata
        .map(|metadata| Produced {
            type_label,
            name: &metadata.name,
            uid: &metadata.id,
        })
        .into_iter()
        .collect()
}

fn stored_profile(profile: &ProviderProfile) -> Produced<'_> {
    Produced {
        type_label: "provider_profile",
        name: &profile.id,
        uid: "",
    }
}

fn stored_sandbox(sandbox: Option<&Sandbox>) -> Vec<Produced<'_>> {
    stored(
        "sandbox",
        sandbox.and_then(|sandbox| sandbox.metadata.as_ref()),
    )
}

impl Audited for SandboxResponse {
    fn produced(&self) -> Vec<Produced<'_>> {
        stored_sandbox(self.sandbox.as_ref())
    }
}

impl Audited for SandboxTemplateResponse {
    fn produced(&self) -> Vec<Produced<'_>> {
        stored(
            "sandbox_template",
            self.template
                .as_ref()
                .and_then(|template| template.metadata.as_ref()),
        )
    }
}

/// Records who read which secret. The named target comes from the request;
/// the response carries the value and contributes nothing to the record.
impl Audited for openshell_core::proto::RevealSecretResponse {}

impl Audited for InlineProviderRefreshSecretsResponse {
    fn produced(&self) -> Vec<Produced<'_>> {
        refreshed_provider(self.status.as_ref())
    }
}

impl Audited for SecretResponse {
    fn produced(&self) -> Vec<Produced<'_>> {
        stored(
            "secret",
            self.secret
                .as_ref()
                .and_then(|secret| secret.metadata.as_ref()),
        )
    }
}

impl Audited for ServiceEndpointResponse {
    fn produced(&self) -> Vec<Produced<'_>> {
        self.endpoint
            .as_ref()
            .map(|endpoint| Produced {
                type_label: "service",
                name: &endpoint.name,
                uid: endpoint
                    .metadata
                    .as_ref()
                    .map_or("", |metadata| &metadata.id),
            })
            .into_iter()
            .collect()
    }
}

impl Audited for AttachSandboxProviderResponse {
    fn produced(&self) -> Vec<Produced<'_>> {
        stored_sandbox(self.sandbox.as_ref())
    }

    fn outcome(&self) -> Option<Outcome> {
        (!self.attached).then_some(Outcome::Detail("no_op:unchanged"))
    }
}

impl Audited for DetachSandboxProviderResponse {
    fn produced(&self) -> Vec<Produced<'_>> {
        stored_sandbox(self.sandbox.as_ref())
    }

    fn outcome(&self) -> Option<Outcome> {
        (!self.detached).then_some(Outcome::Detail("no_op:already_absent"))
    }
}

impl Audited for ImportProviderProfilesResponse {
    fn produced(&self) -> Vec<Produced<'_>> {
        self.profiles.iter().map(stored_profile).collect()
    }

    fn outcome(&self) -> Option<Outcome> {
        (!self.imported).then_some(Outcome::Rejected(Code::InvalidArgument))
    }
}

impl Audited for UpdateProviderProfilesResponse {
    fn produced(&self) -> Vec<Produced<'_>> {
        self.profile.iter().map(stored_profile).collect()
    }

    fn outcome(&self) -> Option<Outcome> {
        (!self.updated).then_some(Outcome::Rejected(Code::InvalidArgument))
    }
}

impl Audited for CreateWorkspaceResponse {
    fn produced(&self) -> Vec<Produced<'_>> {
        stored(
            "workspace",
            self.workspace
                .as_ref()
                .and_then(|workspace| workspace.metadata.as_ref()),
        )
    }
}

impl Audited for AddWorkspaceMemberResponse {
    fn produced(&self) -> Vec<Produced<'_>> {
        self.member
            .as_ref()
            .map(|member| Produced {
                type_label: "workspace_member",
                name: &member.principal_subject,
                uid: member.metadata.as_ref().map_or("", |metadata| &metadata.id),
            })
            .into_iter()
            .collect()
    }
}

impl Audited for BeginRootfsTarStagingResponse {}

impl Audited for ProviderResponse {
    fn produced(&self) -> Vec<Produced<'_>> {
        stored(
            "provider",
            self.provider
                .as_ref()
                .and_then(|provider| provider.metadata.as_ref()),
        )
    }
}

fn refreshed_provider(status: Option<&ProviderCredentialRefreshStatus>) -> Vec<Produced<'_>> {
    status
        .map(|status| Produced {
            type_label: "provider",
            name: &status.provider,
            uid: &status.provider_id,
        })
        .into_iter()
        .collect()
}

impl Audited for ConfigureProviderRefreshResponse {
    fn produced(&self) -> Vec<Produced<'_>> {
        refreshed_provider(self.status.as_ref())
    }
}

impl Audited for RotateProviderCredentialResponse {
    fn produced(&self) -> Vec<Produced<'_>> {
        refreshed_provider(self.status.as_ref())
    }
}

/// The policy a call left in place, identified by its hash.
fn stored_policy(hash: &str) -> Vec<Produced<'_>> {
    (!hash.is_empty())
        .then_some(Produced {
            type_label: "policy",
            name: "",
            uid: hash,
        })
        .into_iter()
        .collect()
}

impl Audited for UpdateConfigResponse {
    fn produced(&self) -> Vec<Produced<'_>> {
        stored_policy(&self.policy_hash)
    }
}

impl Audited for ApproveDraftChunkResponse {
    fn produced(&self) -> Vec<Produced<'_>> {
        stored_policy(&self.policy_hash)
    }
}

impl Audited for UndoDraftChunkResponse {
    fn produced(&self) -> Vec<Produced<'_>> {
        stored_policy(&self.policy_hash)
    }
}

impl Audited for ApproveAllDraftChunksResponse {
    fn produced(&self) -> Vec<Produced<'_>> {
        stored_policy(&self.policy_hash)
    }

    fn outcome(&self) -> Option<Outcome> {
        (self.chunks_approved == 0).then_some(Outcome::Detail("no_op:unchanged"))
    }
}

impl Audited for ClearDraftChunksResponse {
    fn outcome(&self) -> Option<Outcome> {
        (self.chunks_cleared == 0).then_some(Outcome::Detail("no_op:already_absent"))
    }
}

impl Audited for CreateSshSessionResponse {
    fn produced(&self) -> Vec<Produced<'_>> {
        vec![Produced {
            type_label: "sandbox",
            name: "",
            uid: &self.sandbox_id,
        }]
    }
}

impl Audited for RejectDraftChunkResponse {}
impl Audited for EditDraftChunkResponse {}

/// The resources an `UpdateConfig` call changes, with the setting value it
/// sets when `capture_values` is on.
pub(super) fn update_config_targets(
    request: &UpdateConfigRequest,
    capture_values: bool,
) -> Vec<ResourceDetails> {
    let scope = if request.global {
        "global"
    } else {
        request.sandbox.as_str()
    };
    let key = request.setting_key.trim();
    let mut targets = Vec::new();
    if !request.global {
        targets.push(requested("sandbox", &request.sandbox));
    }
    if key == POLICY_SETTING_KEY {
        targets.push(requested("policy", scope));
    } else if !key.is_empty() {
        let mut setting = requested("setting", key);
        if capture_values
            && !request.delete_setting
            && let Some(value) = request
                .setting_value
                .as_ref()
                .and_then(|value| value.value.as_ref())
            && let Some(value) = captured_value(key, value)
        {
            setting = setting.with_data(serde_json::json!({ "value": value }));
        }
        targets.push(setting);
    }
    if request.policy.is_some() || !request.merge_operations.is_empty() {
        targets.push(requested("policy", scope));
    }
    scoped(request.workspace_scope.as_ref(), targets)
}

/// The value of a registered setting when it has the registered kind and is
/// allowed. Bytes and unregistered keys are never recorded.
fn captured_value(key: &str, value: &setting_value::Value) -> Option<serde_json::Value> {
    let setting = settings::setting_for_key(key)?;
    match (setting.kind, value) {
        (SettingValueKind::String, setting_value::Value::StringValue(value))
            if setting.validate_string_value(value).is_ok() =>
        {
            Some(value.as_str().into())
        }
        (SettingValueKind::Bool, setting_value::Value::BoolValue(value)) => Some((*value).into()),
        (SettingValueKind::Int, setting_value::Value::IntValue(value)) => Some((*value).into()),
        _ => None,
    }
}

/// Whether an `UpdateConfig` call only deletes a setting.
pub(super) fn deletes_only_a_setting(request: &UpdateConfigRequest) -> bool {
    request.delete_setting && request.annotations.is_empty()
}

/// Run an `UpdateConfig` call, recording a delete that removed no setting
/// and changed nothing else as a no-op.
pub(super) async fn record_absent_delete(
    deleting_only: bool,
    call: impl Future<Output = Result<Response<UpdateConfigResponse>, Status>>,
) -> Result<Response<UpdateConfigResponse>, Status> {
    let response = call.await;
    if deleting_only
        && response
            .as_ref()
            .is_ok_and(|response| !response.get_ref().deleted)
    {
        audit::record_outcome(Outcome::Detail("no_op:already_absent"));
    }
    response
}

/// Run `call`, recording the requested `targets` that have a name before it
/// starts, then what it produced and how it ended. The call is boxed because
/// handler futures are large.
///
/// Hooks record targets here when the unary request names them. Handlers
/// record the rest: what exists only once admitted, such as a relay channel
/// or a stored session, and the targets of client-streaming requests.
pub(super) fn audited<T: Audited>(
    targets: Vec<ResourceDetails>,
    call: impl Future<Output = Result<Response<T>, Status>>,
) -> impl Future<Output = Result<Response<T>, Status>> {
    let call = Box::pin(call);
    async move {
        record_requested(targets);
        let response = call.await;
        if let Ok(response) = &response {
            let response = response.get_ref();
            let produced = response.produced();
            audit::amend_targets(|targets| complete(targets, produced));
            if let Some(outcome) = response.outcome() {
                audit::record_outcome(outcome);
            }
        }
        response
    }
}

/// Record each requested target that has a non-empty name.
fn record_requested(targets: impl IntoIterator<Item = ResourceDetails>) {
    for target in targets {
        if target.name.as_deref().is_some_and(|name| !name.is_empty()) {
            audit::record_target(target);
        }
    }
}

/// Command arguments an exec record holds at most.
const MAX_EXEC_ARGS: usize = 32;

/// Record the workspace and sandbox an exec requested, before it starts.
pub(super) fn record_exec_targets(request: &ExecSandboxRequest) {
    record_requested(scoped(
        request.workspace_scope.as_ref(),
        [requested("sandbox", &request.sandbox)],
    ));
}

/// Record the relay an exec opened, with its command when `config` captures it.
pub(super) fn record_exec_relay(
    config: &GatewayAuditConfig,
    sandbox: &Sandbox,
    channel_id: &str,
    request: &ExecSandboxRequest,
) {
    let data = exec_command(config.capture_exec_command, request);
    record_relay("exec", sandbox, channel_id, data);
}

/// Resource data holding an exec's first `MAX_EXEC_ARGS` command arguments
/// and how many it left out, when `capture` is set.
fn exec_command(capture: bool, request: &ExecSandboxRequest) -> Option<serde_json::Value> {
    capture.then(|| {
        let command: Vec<&String> = request.command.iter().take(MAX_EXEC_ARGS).collect();
        let omitted = request.command.len() - command.len();
        if omitted == 0 {
            serde_json::json!({ "command": command })
        } else {
            serde_json::json!({ "command": command, "omitted": omitted })
        }
    })
}

/// Record the workspace and sandbox a forward requested, before it starts.
/// `TcpForwardInit` names its workspace directly.
pub(super) fn record_forward_targets(init: &TcpForwardInit) {
    record_requested([
        requested("workspace", &init.workspace),
        requested("sandbox", &init.sandbox),
    ]);
}

/// Record the relay a forward opened to `target`. A TCP forward's data holds
/// its host and port.
pub(super) fn record_forward_relay(
    sandbox: &Sandbox,
    channel_id: &str,
    target: &relay_open::Target,
) {
    let data = match target {
        relay_open::Target::Tcp(target) => {
            Some(serde_json::json!({ "host": target.host, "port": target.port }))
        }
        relay_open::Target::Ssh(_) => None,
    };
    record_relay("forward", sandbox, channel_id, data);
}

/// Record the relay opened to `sandbox` as a `type_label` resource whose
/// `uid` is its channel ID.
fn record_relay(
    type_label: &str,
    sandbox: &Sandbox,
    channel_id: &str,
    data: Option<serde_json::Value>,
) {
    let produced = stored_sandbox(Some(sandbox));
    audit::amend_targets(|targets| {
        complete(targets, produced);
        targets.push(ResourceDetails {
            uid: Some(channel_id.to_string()),
            name: None,
            type_label: Some(type_label.to_string()),
            data,
        });
    });
}

/// Record an SSH session by its name, never by its ID, which is its token.
pub(super) fn record_ssh_session(name: &str) {
    record_requested([requested("ssh_session", name)]);
}

/// Record the session a revoke found: its workspace, sandbox, and name.
pub(super) fn record_revoked_ssh_session(session: &SshSession) {
    record_requested([requested("workspace", session.object_workspace())]);
    audit::record_target(ResourceDetails {
        uid: Some(session.sandbox_id.clone()),
        name: None,
        type_label: Some("sandbox".to_string()),
        data: None,
    });
    record_ssh_session(session.object_name());
}

/// Record a revoke of a session that was already revoked as a no-op.
pub(super) fn record_repeated_revoke() {
    audit::record_outcome(Outcome::Detail("no_op:already_absent"));
}

/// Fill in the first unfilled requested target of each produced
/// resource's type, or add the resource.
fn complete(targets: &mut Vec<ResourceDetails>, produced: Vec<Produced<'_>>) {
    let mut filled = vec![false; targets.len()];
    for produced in produced {
        let index = filled
            .iter()
            .zip(targets.iter())
            .position(|(filled, target)| {
                !filled && target.type_label.as_deref() == Some(produced.type_label)
            });
        let target = if let Some(index) = index {
            filled[index] = true;
            &mut targets[index]
        } else {
            targets.push(ResourceDetails {
                uid: None,
                name: None,
                type_label: Some(produced.type_label.to_string()),
                data: None,
            });
            targets.last_mut().expect("target just added")
        };
        if !produced.name.is_empty() {
            target.name = Some(produced.name.to_string());
        }
        if !produced.uid.is_empty() {
            target.uid = Some(produced.uid.to_string());
        }
    }
}

/// `targets` within the workspace `selector` names, which comes first.
pub(super) fn scoped(
    selector: Option<&WorkspaceSelector>,
    targets: impl IntoIterator<Item = ResourceDetails>,
) -> Vec<ResourceDetails> {
    let workspace = match selector.and_then(|selector| selector.selection.as_ref()) {
        Some(Selection::Workspace(name)) => Some(requested("workspace", name)),
        Some(Selection::AllWorkspaces(_)) | None => None,
    };
    workspace.into_iter().chain(targets).collect()
}

#[cfg(test)]
mod tests;
