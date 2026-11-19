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
mod tests {
    use super::*;
    use crate::auth::audit::test_support::{assert_redacted, audited_mutation, cancelled_mutation};
    use crate::auth::principal::Principal;
    use crate::grpc::OpenShellService;
    use crate::grpc::test_support::{authed_request, test_server_state};
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::open_shell_server::OpenShell;
    use openshell_core::proto::sandbox_updates_server::SandboxUpdates;
    use openshell_core::proto::{
        AddWorkspaceMemberRequest, AttachSandboxProviderRequest, AttachSandboxProviderResponse,
        BeginRootfsTarStagingRequest, CreateSandboxRequest, CreateSandboxTemplateRequest,
        CreateWorkspaceRequest, DeleteProviderProfileRequest, DeleteProviderRefreshRequest,
        DeleteProviderRequest, DeleteSandboxRequest, DeleteSandboxTemplateRequest,
        DeleteServiceRequest, DeleteWorkspaceRequest, DetachSandboxProviderRequest,
        DetachSandboxProviderResponse, ExposeServiceRequest, ImportProviderProfilesRequest,
        ImportProviderProfilesResponse, ProviderProfile, ProviderProfileCategory,
        ProviderProfileImportItem, RemoveWorkspaceMemberRequest, ResumeSandboxRequest, Sandbox,
        SandboxSpec, SandboxWorkloadConfig, SandboxWorkloadTemplate, SandboxWorkloadTemplateSpec,
        StartSandboxRequest, StopSandboxRequest, SuspendSandboxRequest,
        UpdateProviderProfilesRequest, UpdateSandboxRequest, WorkspaceRole, workspace_selector,
    };
    use openshell_core::proto::{
        ApproveAllDraftChunksRequest, ApproveDraftChunkRequest, ClearDraftChunksRequest,
        ConfigureProviderRefreshRequest, CreateProviderRequest, DraftChunkApproval,
        EditDraftChunkRequest, NetworkPolicyRule, Provider, RejectDraftChunkRequest,
        RotateProviderCredentialRequest, SandboxPolicy, SettingValue, UndoDraftChunkRequest,
        UpdateConfigRequest, UpdateProviderRequest, setting_value,
    };
    use openshell_core::proto::{
        CreateSshSessionRequest, ExecSandboxInput, ExecSandboxRequest, RevokeSshSessionRequest,
        SshRelayTarget, TcpForwardFrame, TcpForwardInit, TcpRelayTarget, tcp_forward_frame,
        tcp_forward_init,
    };
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn principal() -> Principal {
        authed_request(())
            .extensions()
            .get::<Principal>()
            .cloned()
            .unwrap()
    }

    fn path(method: &str) -> String {
        format!("/openshell.v1.OpenShell/{method}")
    }

    fn only(events: &[Value]) -> &Value {
        assert_eq!(events.len(), 1, "{events:?}");
        &events[0]
    }

    #[tokio::test]
    async fn deletes_of_absent_resources_name_the_target_and_record_a_no_op() {
        let service = OpenShellService::new(test_server_state().await);
        let principal = principal();
        let scope = || Some(workspace_selector("default"));

        let cases: Vec<(&str, Value, Vec<Value>)> = vec![
            (
                "DeleteSandbox",
                only(
                    &audited_mutation(&path("DeleteSandbox"), &principal, async {
                        service
                            .delete_sandbox(authed_request(DeleteSandboxRequest {
                                workspace_scope: scope(),
                                name: "absent-sandbox".into(),
                                allow_missing: true,
                                ..Default::default()
                            }))
                            .await
                    })
                    .await
                    .1,
                )
                .clone(),
                vec![
                    json!({"type": "workspace", "name": "default"}),
                    json!({"type": "sandbox", "name": "absent-sandbox"}),
                ],
            ),
            (
                "DeleteSandboxTemplate",
                only(
                    &audited_mutation(&path("DeleteSandboxTemplate"), &principal, async {
                        service
                            .delete_sandbox_template(authed_request(DeleteSandboxTemplateRequest {
                                workspace_scope: scope(),
                                name: "absent-template".into(),
                                allow_missing: true,
                                ..Default::default()
                            }))
                            .await
                    })
                    .await
                    .1,
                )
                .clone(),
                vec![
                    json!({"type": "workspace", "name": "default"}),
                    json!({"type": "sandbox_template", "name": "absent-template"}),
                ],
            ),
            (
                "DeleteProvider",
                only(
                    &audited_mutation(&path("DeleteProvider"), &principal, async {
                        service
                            .delete_provider(authed_request(DeleteProviderRequest {
                                workspace_scope: scope(),
                                name: "absent-provider".into(),
                                allow_missing: true,
                                ..Default::default()
                            }))
                            .await
                    })
                    .await
                    .1,
                )
                .clone(),
                vec![
                    json!({"type": "workspace", "name": "default"}),
                    json!({"type": "provider", "name": "absent-provider"}),
                ],
            ),
            (
                "DeleteProviderProfile",
                only(
                    &audited_mutation(&path("DeleteProviderProfile"), &principal, async {
                        service
                            .delete_provider_profile(authed_request(DeleteProviderProfileRequest {
                                workspace_scope: scope(),
                                id: "absent-profile".into(),
                                allow_missing: true,
                                ..Default::default()
                            }))
                            .await
                    })
                    .await
                    .1,
                )
                .clone(),
                vec![
                    json!({"type": "workspace", "name": "default"}),
                    json!({"type": "provider_profile", "name": "absent-profile"}),
                ],
            ),
            (
                "DeleteWorkspace",
                only(
                    &audited_mutation(&path("DeleteWorkspace"), &principal, async {
                        service
                            .delete_workspace(authed_request(DeleteWorkspaceRequest {
                                name: "absent-workspace".into(),
                                allow_missing: true,
                                ..Default::default()
                            }))
                            .await
                    })
                    .await
                    .1,
                )
                .clone(),
                vec![json!({"type": "workspace", "name": "absent-workspace"})],
            ),
            (
                "RemoveWorkspaceMember",
                only(
                    &audited_mutation(&path("RemoveWorkspaceMember"), &principal, async {
                        service
                            .remove_workspace_member(authed_request(RemoveWorkspaceMemberRequest {
                                workspace_scope: scope(),
                                principal_subject: "absent-member".into(),
                                allow_missing: true,
                                ..Default::default()
                            }))
                            .await
                    })
                    .await
                    .1,
                )
                .clone(),
                vec![
                    json!({"type": "workspace", "name": "default"}),
                    json!({"type": "workspace_member", "name": "absent-member"}),
                ],
            ),
        ];

        for (method, event, resources) in cases {
            assert_eq!(event["api"]["operation"], method, "{event}");
            assert_eq!(event["status_id"], 1, "{method}: {event}");
            assert_eq!(
                event["status_detail"], "no_op:already_absent",
                "{method}: {event}"
            );
            assert_eq!(event["resources"], json!(resources), "{method}: {event}");
        }
    }

    #[tokio::test]
    async fn rejected_delete_names_the_requested_target() {
        let service = OpenShellService::new(test_server_state().await);

        let (result, events) = audited_mutation(&path("DeleteProvider"), &principal(), async {
            service
                .delete_provider(authed_request(DeleteProviderRequest {
                    workspace_scope: Some(workspace_selector("default")),
                    name: "missing-provider".into(),
                    ..Default::default()
                }))
                .await
        })
        .await;

        assert_eq!(result.unwrap_err().code(), Code::NotFound);
        let event = only(&events);
        assert_eq!(event["status_detail"], "rejected:not_found", "{event}");
        assert_eq!(
            event["resources"],
            json!([{"type": "workspace", "name": "default"}, {"type": "provider", "name": "missing-provider"}])
        );

        let (result, events) =
            audited_mutation(&path("DeleteProviderRefresh"), &principal(), async {
                service
                    .delete_provider_refresh(authed_request(DeleteProviderRefreshRequest {
                        workspace_scope: Some(workspace_selector("default")),
                        provider: "missing-provider".into(),
                        credential_key: "API_TOKEN".into(),
                        allow_missing: true,
                        ..Default::default()
                    }))
                    .await
            })
            .await;

        assert_eq!(result.unwrap_err().code(), Code::NotFound);
        let event = only(&events);
        assert_eq!(event["status_detail"], "rejected:not_found", "{event}");
        assert_eq!(
            event["resources"],
            json!([
                {"type": "workspace", "name": "default"},
                {"type": "provider", "name": "missing-provider"},
                {"type": "provider_credential", "name": "API_TOKEN"},
            ])
        );

        let (result, events) = audited_mutation(&path("DeleteService"), &principal(), async {
            service
                .delete_service(authed_request(DeleteServiceRequest {
                    workspace_scope: Some(workspace_selector("default")),
                    sandbox: "missing-sandbox".into(),
                    name: "web".into(),
                    allow_missing: true,
                    ..Default::default()
                }))
                .await
        })
        .await;

        assert_eq!(result.unwrap_err().code(), Code::NotFound);
        let event = only(&events);
        assert_eq!(event["status_detail"], "rejected:not_found", "{event}");
        assert_eq!(
            event["resources"],
            json!([
                {"type": "workspace", "name": "default"},
                {"type": "sandbox", "name": "missing-sandbox"},
                {"type": "service", "name": "web"},
            ])
        );
    }

    #[tokio::test]
    async fn cancelled_delete_names_the_requested_target() {
        let targets = scoped(
            Some(&workspace_selector("default")),
            [requested("provider", "github")],
        );
        let call = audited(
            targets,
            std::future::pending::<Result<Response<DeleteProviderResponse>, Status>>(),
        );

        let events = cancelled_mutation(&path("DeleteProvider"), &principal(), call).await;

        let event = only(&events);
        assert_eq!(event["status_detail"], "unknown:cancelled", "{event}");
        assert_eq!(
            event["resources"],
            json!([
                {"type": "workspace", "name": "default"},
                {"type": "provider", "name": "github"},
            ])
        );
    }

    #[tokio::test]
    async fn denied_delete_names_the_requested_target() {
        let targets = scoped(
            Some(&workspace_selector("default")),
            [requested("provider", "github")],
        );
        let call = audited(targets, async {
            Err::<Response<DeleteProviderResponse>, _>(audit::deny(
                &principal(),
                audit::AuthzDenial::InsufficientWorkspaceRole {
                    workspace: "default",
                },
                "workspace role required",
            ))
        });

        let (result, events) = audited_mutation(&path("DeleteProvider"), &principal(), call).await;

        assert_eq!(result.unwrap_err().code(), Code::PermissionDenied);
        let event = only(&events);
        assert_eq!(
            event["status_detail"], "insufficient_workspace_role",
            "{event}"
        );
        assert_eq!(
            event["resources"],
            json!([
                {"type": "workspace", "name": "default"},
                {"type": "provider", "name": "github"},
            ])
        );
    }

    #[tokio::test]
    async fn accepted_sandbox_delete_records_the_sandbox_id() {
        let service = OpenShellService::new(test_server_state().await);
        let created = service
            .create_sandbox(authed_request(CreateSandboxRequest {
                workspace_scope: Some(workspace_selector("default")),
                name: "audit-delete-sbx".into(),
                spec: Some(SandboxSpec::default()),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        let sandbox_id = created.sandbox.unwrap().metadata.unwrap().id;

        let (result, events) = audited_mutation(&path("DeleteSandbox"), &principal(), async {
            service
                .delete_sandbox(authed_request(DeleteSandboxRequest {
                    workspace_scope: Some(workspace_selector("default")),
                    name: "audit-delete-sbx".into(),
                    ..Default::default()
                }))
                .await
        })
        .await;

        assert_eq!(
            result.unwrap().get_ref().outcome(),
            DeletionOutcome::Accepted
        );
        let event = only(&events);
        assert_eq!(event["status_detail"], "accepted", "{event}");
        assert_eq!(
            event["resources"],
            json!([{"type": "workspace", "name": "default"}, {"type": "sandbox", "name": "audit-delete-sbx", "uid": sandbox_id}])
        );
    }

    #[tokio::test]
    async fn completed_delete_records_plain_success() {
        let service = OpenShellService::new(test_server_state().await);
        service
            .create_workspace(authed_request(CreateWorkspaceRequest {
                name: "audit-delete-done".into(),
                ..Default::default()
            }))
            .await
            .unwrap();

        let (result, events) = audited_mutation(&path("DeleteWorkspace"), &principal(), async {
            service
                .delete_workspace(authed_request(DeleteWorkspaceRequest {
                    name: "audit-delete-done".into(),
                    ..Default::default()
                }))
                .await
        })
        .await;

        result.unwrap();
        let event = only(&events);
        assert_eq!(event["status_id"], 1, "{event}");
        assert!(event.get("status_detail").is_none(), "{event}");
        assert_eq!(
            event["resources"],
            json!([{"type": "workspace", "name": "audit-delete-done"}])
        );
    }

    async fn record<T>(
        method: &str,
        call: impl Future<Output = Result<Response<T>, Status>>,
    ) -> (Result<Response<T>, Status>, Value) {
        record_at(&path(method), call).await
    }

    async fn record_at<T>(
        path: &str,
        call: impl Future<Output = Result<Response<T>, Status>>,
    ) -> (Result<Response<T>, Status>, Value) {
        let (result, events) = audited_mutation(path, &principal(), call).await;
        (result, only(&events).clone())
    }

    fn default_workspace() -> Value {
        json!({"type": "workspace", "name": "default"})
    }

    fn stored_json(type_label: &str, meta: &ObjectMeta) -> Value {
        json!({"type": type_label, "name": meta.name, "uid": meta.id})
    }

    #[tokio::test]
    async fn creates_name_the_resource_they_produced() {
        let service = OpenShellService::new(test_server_state().await);

        let (result, event) = record(
            "CreateSandbox",
            service.create_sandbox(authed_request(CreateSandboxRequest {
                workspace_scope: Some(workspace_selector("default")),
                spec: Some(SandboxSpec::default()),
                ..Default::default()
            })),
        )
        .await;
        let sandbox = result.unwrap().into_inner().sandbox.unwrap();
        assert!(event.get("status_detail").is_none(), "{event}");
        assert_eq!(
            event["resources"],
            json!([
                default_workspace(),
                stored_json("sandbox", sandbox.metadata.as_ref().unwrap())
            ])
        );

        let (result, event) = record(
            "CreateWorkspace",
            service.create_workspace(authed_request(CreateWorkspaceRequest {
                name: "audit-create".into(),
                ..Default::default()
            })),
        )
        .await;
        let workspace = result.unwrap().into_inner().workspace.unwrap();
        assert_eq!(
            event["resources"],
            json!([stored_json(
                "workspace",
                workspace.metadata.as_ref().unwrap()
            )])
        );

        let (result, event) = record(
            "AddWorkspaceMember",
            service.add_workspace_member(authed_request(AddWorkspaceMemberRequest {
                workspace_scope: Some(workspace_selector("audit-create")),
                principal_subject: "bob".into(),
                role: WorkspaceRole::User.into(),
                ..Default::default()
            })),
        )
        .await;
        let member = result.unwrap().into_inner().member.unwrap();
        assert_eq!(
            event["resources"],
            json!([
                {"type": "workspace", "name": "audit-create"},
                {"type": "workspace_member", "name": "bob", "uid": member.metadata.unwrap().id},
            ])
        );

        let (result, event) = record(
            "CreateSandboxTemplate",
            service.create_sandbox_template(authed_request(CreateSandboxTemplateRequest {
                workspace_scope: Some(workspace_selector("default")),
                template: Some(SandboxWorkloadTemplate {
                    metadata: Some(ObjectMeta {
                        name: "audit-template".into(),
                        ..Default::default()
                    }),
                    spec: Some(SandboxWorkloadTemplateSpec {
                        workload: Some(SandboxWorkloadConfig {
                            image: "registry.example.com/agent:latest".into(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                }),
                ..Default::default()
            })),
        )
        .await;
        let template = result.unwrap().into_inner().template.unwrap();
        assert_eq!(
            event["resources"],
            json!([
                default_workspace(),
                stored_json("sandbox_template", template.metadata.as_ref().unwrap())
            ])
        );
    }

    #[tokio::test]
    async fn rejected_creates_and_updates_name_the_requested_targets() {
        let service = OpenShellService::new(test_server_state().await);
        let scope = || Some(workspace_selector("default"));
        let sandbox = json!({"type": "sandbox", "name": "missing-sbx"});
        let cases = vec![
            (
                "rejected:not_found",
                record(
                    "StopSandbox",
                    service.stop_sandbox(authed_request(StopSandboxRequest {
                        workspace_scope: scope(),
                        name: "missing-sbx".into(),
                        ..Default::default()
                    })),
                )
                .await
                .1,
                json!([default_workspace(), sandbox]),
            ),
            (
                "rejected:not_found",
                record(
                    "StartSandbox",
                    service.start_sandbox(authed_request(StartSandboxRequest {
                        workspace_scope: scope(),
                        name: "missing-sbx".into(),
                        ..Default::default()
                    })),
                )
                .await
                .1,
                json!([default_workspace(), sandbox]),
            ),
            (
                "rejected:not_found",
                record(
                    "SuspendSandbox",
                    service.suspend_sandbox(authed_request(SuspendSandboxRequest {
                        workspace_scope: scope(),
                        name: "missing-sbx".into(),
                    })),
                )
                .await
                .1,
                json!([default_workspace(), sandbox]),
            ),
            (
                "rejected:not_found",
                record(
                    "ResumeSandbox",
                    service.resume_sandbox(authed_request(ResumeSandboxRequest {
                        workspace_scope: scope(),
                        name: "missing-sbx".into(),
                        ..Default::default()
                    })),
                )
                .await
                .1,
                json!([default_workspace(), sandbox]),
            ),
            (
                "rejected:invalid_argument",
                record_at(
                    "/openshell.v1.SandboxUpdates/UpdateSandbox",
                    SandboxUpdates::update_sandbox(
                        &service,
                        authed_request(UpdateSandboxRequest {
                            workspace_scope: scope(),
                            name: "missing-sbx".into(),
                            image: Some("registry.example.com/agent:v2".into()),
                            ..Default::default()
                        }),
                    ),
                )
                .await
                .1,
                json!([default_workspace(), sandbox]),
            ),
            (
                "rejected:not_found",
                record(
                    "AttachSandboxProvider",
                    service.attach_sandbox_provider(authed_request(AttachSandboxProviderRequest {
                        workspace_scope: scope(),
                        sandbox: "missing-sbx".into(),
                        provider: "github".into(),
                        ..Default::default()
                    })),
                )
                .await
                .1,
                json!([default_workspace(), sandbox, {"type": "provider", "name": "github"}]),
            ),
            (
                "rejected:not_found",
                record(
                    "DetachSandboxProvider",
                    service.detach_sandbox_provider(authed_request(DetachSandboxProviderRequest {
                        workspace_scope: scope(),
                        sandbox: "missing-sbx".into(),
                        provider: "github".into(),
                        ..Default::default()
                    })),
                )
                .await
                .1,
                json!([default_workspace(), sandbox, {"type": "provider", "name": "github"}]),
            ),
            (
                "rejected:not_found",
                record(
                    "ExposeService",
                    service.expose_service(authed_request(ExposeServiceRequest {
                        workspace_scope: scope(),
                        sandbox: "missing-sbx".into(),
                        name: "web".into(),
                        target_port: 8080,
                        ..Default::default()
                    })),
                )
                .await
                .1,
                json!([default_workspace(), sandbox, {"type": "service", "name": "web"}]),
            ),
            (
                "rejected:invalid_argument",
                record(
                    "UpdateProviderProfiles",
                    service.update_provider_profiles(authed_request(
                        UpdateProviderProfilesRequest {
                            workspace_scope: scope(),
                            id: "missing-profile".into(),
                            ..Default::default()
                        },
                    )),
                )
                .await
                .1,
                json!([default_workspace(), {"type": "provider_profile", "name": "missing-profile"}]),
            ),
            (
                "rejected:invalid_argument",
                record(
                    "ImportProviderProfiles",
                    service.import_provider_profiles(authed_request(
                        ImportProviderProfilesRequest {
                            workspace_scope: scope(),
                            ..Default::default()
                        },
                    )),
                )
                .await
                .1,
                json!([default_workspace()]),
            ),
        ];

        for (detail, event, resources) in &cases {
            assert_eq!(event["status_id"], 2, "{event}");
            assert_eq!(event["severity_id"], 2, "{event}");
            assert_eq!(event["status_detail"], *detail, "{event}");
            assert_eq!(&event["resources"], resources, "{event}");
        }
    }

    #[tokio::test]
    async fn empty_requested_names_are_dropped() {
        let service = OpenShellService::new(test_server_state().await);

        let (_, event) = record(
            "UpdateProviderProfiles",
            service.update_provider_profiles(authed_request(UpdateProviderProfilesRequest {
                workspace_scope: Some(workspace_selector("default")),
                ..Default::default()
            })),
        )
        .await;

        assert_eq!(event["resources"], json!([default_workspace()]), "{event}");
    }

    #[tokio::test]
    async fn imports_name_every_profile_they_produce() {
        let service = OpenShellService::new(test_server_state().await);
        let item = |id: &str| ProviderProfileImportItem {
            profile: Some(ProviderProfile {
                id: id.into(),
                display_name: id.into(),
                category: ProviderProfileCategory::Other.into(),
                ..Default::default()
            }),
            source: format!("{id}.yaml"),
        };

        let (result, event) = record(
            "ImportProviderProfiles",
            service.import_provider_profiles(authed_request(ImportProviderProfilesRequest {
                workspace_scope: Some(workspace_selector("default")),
                profiles: vec![item("audit-a"), item("audit-b")],
                ..Default::default()
            })),
        )
        .await;

        assert!(result.unwrap().into_inner().imported);
        assert_eq!(
            event["resources"],
            json!([
                default_workspace(),
                {"type": "provider_profile", "name": "audit-a"},
                {"type": "provider_profile", "name": "audit-b"},
            ])
        );
    }

    #[tokio::test]
    async fn replayed_rejection_stays_a_failure() {
        let (_, event) = record(
            "ImportProviderProfiles",
            audited(Vec::new(), async {
                let mut response = Response::new(ImportProviderProfilesResponse::default());
                response.metadata_mut().insert(
                    crate::grpc::mutation_replay::REPLAYED_HEADER,
                    "true".parse().unwrap(),
                );
                Ok(response)
            }),
        )
        .await;

        assert_eq!(event["status_id"], 2, "{event}");
        assert_eq!(
            event["status_detail"], "rejected:invalid_argument",
            "{event}"
        );
    }

    #[tokio::test]
    async fn produced_names_are_bounded() {
        let long = "p".repeat(300);
        let (_, event) = record(
            "ImportProviderProfiles",
            audited(Vec::new(), async {
                Ok(Response::new(ImportProviderProfilesResponse {
                    profiles: vec![ProviderProfile {
                        id: long.clone(),
                        ..Default::default()
                    }],
                    imported: true,
                    ..Default::default()
                }))
            }),
        )
        .await;

        let name = event["resources"][0]["name"].as_str().unwrap();
        assert_eq!(name, format!("{}...", "p".repeat(128)));
    }

    #[tokio::test]
    async fn large_imports_list_a_bounded_number_of_resources() {
        let profiles = (0..40)
            .map(|index| ProviderProfile {
                id: format!("profile-{index}"),
                ..Default::default()
            })
            .collect();
        let (_, event) = record(
            "ImportProviderProfiles",
            audited(Vec::new(), async {
                Ok(Response::new(ImportProviderProfilesResponse {
                    profiles,
                    imported: true,
                    ..Default::default()
                }))
            }),
        )
        .await;

        assert_eq!(event["resources"].as_array().unwrap().len(), 16, "{event}");
        assert_eq!(event["resources"][14]["name"], "profile-14", "{event}");
        assert_eq!(event["resources"][15]["name"], "profile-39", "{event}");
        assert_eq!(
            event["message"], "mutation succeeded; 24 more resources not listed",
            "{event}"
        );
    }

    #[tokio::test]
    async fn rootfs_staging_names_the_requested_file() {
        let service = OpenShellService::new(test_server_state().await);

        let (_, event) = record(
            "BeginRootfsTarStaging",
            service.begin_rootfs_tar_staging(authed_request(BeginRootfsTarStagingRequest {
                workspace_scope: Some(workspace_selector("default")),
                file_name: "rootfs.tar".into(),
                size_bytes: 1024,
            })),
        )
        .await;

        assert_eq!(
            event["resources"],
            json!([default_workspace(), {"type": "rootfs_staging", "name": "rootfs.tar"}])
        );

        let (_, event) = record(
            "BeginRootfsTarStaging",
            service.begin_rootfs_tar_staging(authed_request(BeginRootfsTarStagingRequest {
                workspace_scope: Some(workspace_selector("default")),
                file_name: "/home/alice/rootfs.tar".into(),
                size_bytes: 1024,
            })),
        )
        .await;

        assert_eq!(
            event["resources"],
            json!([default_workspace(), {"type": "rootfs_staging", "name": "rootfs.tar"}])
        );
    }

    #[tokio::test]
    async fn unchanged_attachments_record_no_ops() {
        let sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: "sb-1".into(),
                name: "agent-01".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let targets = || {
            vec![
                requested("sandbox", "agent-01"),
                requested("provider", "github"),
            ]
        };
        let sandbox_with_uid = json!({"type": "sandbox", "name": "agent-01", "uid": "sb-1"});
        let provider = json!({"type": "provider", "name": "github"});

        let (_, event) = record(
            "AttachSandboxProvider",
            audited(targets(), async {
                Ok(Response::new(AttachSandboxProviderResponse {
                    sandbox: Some(sandbox.clone()),
                    attached: false,
                    ..Default::default()
                }))
            }),
        )
        .await;
        assert_eq!(event["status_detail"], "no_op:unchanged", "{event}");
        assert_eq!(event["resources"], json!([sandbox_with_uid, provider]));

        let (_, event) = record(
            "DetachSandboxProvider",
            audited(targets(), async {
                Ok(Response::new(DetachSandboxProviderResponse {
                    sandbox: Some(sandbox.clone()),
                    detached: false,
                    ..Default::default()
                }))
            }),
        )
        .await;
        assert_eq!(event["status_detail"], "no_op:already_absent", "{event}");
        assert_eq!(event["resources"], json!([sandbox_with_uid, provider]));
    }

    const CANARY: &str = "audit-canary-6c1f9e2d";

    fn named(event: &Value) -> Vec<String> {
        event["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|resource| {
                format!(
                    "{}:{}",
                    resource["type"].as_str().unwrap(),
                    resource["name"].as_str().unwrap_or_default()
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn provider_records_name_the_provider_but_never_its_secrets() {
        let service = OpenShellService::new(test_server_state().await);
        let scope = || Some(workspace_selector("default"));
        let provider = Provider {
            metadata: Some(ObjectMeta {
                name: "audit-openai".into(),
                ..Default::default()
            }),
            r#type: "openai".into(),
            credentials: HashMap::from([("OPENAI_API_KEY".into(), CANARY.into())]),
            ..Default::default()
        };

        let (result, event) = record(
            "CreateProvider",
            service.create_provider(authed_request(CreateProviderRequest {
                workspace_scope: scope(),
                provider: Some(provider),
                ..Default::default()
            })),
        )
        .await;
        let created = result.unwrap().into_inner().provider.unwrap();
        assert_eq!(
            event["resources"],
            json!([
                default_workspace(),
                stored_json("provider", created.metadata.as_ref().unwrap())
            ])
        );
        assert_redacted(&event, CANARY);

        let mut update = created.clone();
        update.credential_handles.clear();
        update.credentials = HashMap::from([("OPENAI_API_KEY".into(), format!("{CANARY}-2"))]);
        let (_, event) = record(
            "UpdateProvider",
            service.update_provider(authed_request(UpdateProviderRequest {
                workspace_scope: scope(),
                provider: Some(update),
                ..Default::default()
            })),
        )
        .await;
        assert_eq!(
            named(&event),
            ["workspace:default", "provider:audit-openai"]
        );
        assert_redacted(&event, CANARY);

        let (_, event) = record(
            "ConfigureProviderRefresh",
            service.configure_provider_refresh(authed_request(ConfigureProviderRefreshRequest {
                workspace_scope: scope(),
                provider: "audit-openai".into(),
                credential_key: "OPENAI_API_KEY".into(),
                material: HashMap::from([("client_secret".into(), CANARY.into())]),
                ..Default::default()
            })),
        )
        .await;
        assert_eq!(
            named(&event),
            [
                "workspace:default",
                "provider:audit-openai",
                "provider_credential:OPENAI_API_KEY"
            ]
        );
        assert_redacted(&event, CANARY);

        let (_, event) = record(
            "RotateProviderCredential",
            service.rotate_provider_credential(authed_request(RotateProviderCredentialRequest {
                workspace_scope: scope(),
                provider: "audit-openai".into(),
                credential_key: "OPENAI_API_KEY".into(),
                ..Default::default()
            })),
        )
        .await;
        assert_eq!(
            named(&event),
            [
                "workspace:default",
                "provider:audit-openai",
                "provider_credential:OPENAI_API_KEY"
            ]
        );
    }

    #[test]
    fn update_config_targets_name_setting_sandbox_and_policy() {
        let setting = |key: &str, value| UpdateConfigRequest {
            global: true,
            setting_key: key.into(),
            setting_value: Some(SettingValue { value: Some(value) }),
            ..Default::default()
        };
        let text = |value: &str| setting_value::Value::StringValue(value.into());
        let targets = |request: &UpdateConfigRequest, capture| {
            serde_json::to_value(update_config_targets(request, capture)).unwrap()
        };

        assert_eq!(
            targets(&setting("ocsf_schema_version", text("1.8.0")), false),
            json!([{"type": "setting", "name": "ocsf_schema_version"}])
        );
        assert_eq!(
            targets(&setting("ocsf_schema_version", text("1.8.0")), true),
            json!([{"type": "setting", "name": "ocsf_schema_version", "data": {"value": "1.8.0"}}])
        );
        assert_eq!(
            targets(
                &setting(" ocsf_json_enabled ", setting_value::Value::BoolValue(true)),
                true
            ),
            json!([{"type": "setting", "name": "ocsf_json_enabled", "data": {"value": true}}])
        );
        for rejected in [
            setting("OPENAI_API_KEY", text(CANARY)),
            setting("ocsf_json_enabled", text(CANARY)),
            setting("proposal_approval_mode", text(CANARY)),
            setting(
                "ocsf_schema_version",
                setting_value::Value::BytesValue(CANARY.into()),
            ),
        ] {
            assert!(
                targets(&rejected, true)[0].get("data").is_none(),
                "{rejected:?}"
            );
        }
        let mut delete = setting("ocsf_schema_version", text("1.8.0"));
        delete.delete_setting = true;
        assert_eq!(
            targets(&delete, true),
            json!([{"type": "setting", "name": "ocsf_schema_version"}])
        );

        let sandbox_policy = UpdateConfigRequest {
            workspace_scope: Some(workspace_selector("default")),
            sandbox: "agent-01".into(),
            policy: Some(SandboxPolicy::default()),
            ..Default::default()
        };
        assert_eq!(
            targets(&sandbox_policy, false),
            json!([
                default_workspace(),
                {"type": "sandbox", "name": "agent-01"},
                {"type": "policy", "name": "agent-01"},
            ])
        );
        let global_policy = UpdateConfigRequest {
            global: true,
            policy: Some(SandboxPolicy::default()),
            ..Default::default()
        };
        assert_eq!(
            targets(&global_policy, false),
            json!([{"type": "policy", "name": "global"}])
        );
        let global_policy_delete = UpdateConfigRequest {
            global: true,
            setting_key: "policy".into(),
            delete_setting: true,
            ..Default::default()
        };
        assert_eq!(
            targets(&global_policy_delete, true),
            json!([{"type": "policy", "name": "global"}])
        );
    }

    #[tokio::test]
    async fn gateway_records_setting_values_when_configured_to_capture_them() {
        let mut state = test_server_state().await;
        Arc::get_mut(&mut state)
            .expect("unshared test state")
            .config
            .audit
            .capture_setting_values = true;
        let service = OpenShellService::new(state);

        let (result, event) = record(
            "UpdateConfig",
            service.update_config(authed_request(UpdateConfigRequest {
                global: true,
                setting_key: "ocsf_json_enabled".into(),
                setting_value: Some(SettingValue {
                    value: Some(setting_value::Value::BoolValue(true)),
                }),
                ..Default::default()
            })),
        )
        .await;

        result.unwrap();
        assert_eq!(
            event["resources"],
            json!([{"type": "setting", "name": "ocsf_json_enabled", "data": {"value": true}}]),
            "{event}"
        );
    }

    #[tokio::test]
    async fn long_setting_values_are_bounded() {
        let request = UpdateConfigRequest {
            global: true,
            setting_key: "ocsf_schema_version".into(),
            setting_value: Some(SettingValue {
                value: Some(setting_value::Value::StringValue("v".repeat(300))),
            }),
            ..Default::default()
        };
        let (_, event) = record(
            "UpdateConfig",
            audited(update_config_targets(&request, true), async {
                Ok(Response::new(UpdateConfigResponse::default()))
            }),
        )
        .await;

        assert_eq!(
            event["resources"][0]["data"]["value"],
            format!("{}...", "v".repeat(128)),
            "{event}"
        );
    }

    #[tokio::test]
    async fn denied_setting_values_are_bounded() {
        let request = UpdateConfigRequest {
            global: true,
            setting_key: "ocsf_schema_version".into(),
            setting_value: Some(SettingValue {
                value: Some(setting_value::Value::StringValue("v".repeat(300))),
            }),
            ..Default::default()
        };
        let (result, event) = record(
            "UpdateConfig",
            audited(update_config_targets(&request, true), async {
                Err::<Response<UpdateConfigResponse>, _>(audit::deny(
                    &principal(),
                    audit::AuthzDenial::MissingRole,
                    "admin role required",
                ))
            }),
        )
        .await;

        assert_eq!(result.unwrap_err().code(), Code::PermissionDenied);
        assert_eq!(event["status_detail"], "missing_role", "{event}");
        assert_eq!(
            event["resources"][0]["data"]["value"],
            format!("{}...", "v".repeat(128)),
            "{event}"
        );
    }

    #[tokio::test]
    async fn deleting_a_setting_while_annotating_is_not_a_no_op() {
        let request = UpdateConfigRequest {
            sandbox: "agent-01".into(),
            setting_key: "ocsf_json_enabled".into(),
            delete_setting: true,
            annotations: HashMap::from([("ticket".into(), "OPS-1".into())]),
            ..Default::default()
        };
        let (_, event) = record(
            "UpdateConfig",
            record_absent_delete(deletes_only_a_setting(&request), async {
                Ok(Response::new(UpdateConfigResponse::default()))
            }),
        )
        .await;

        assert!(event.get("status_detail").is_none(), "{event}");
    }

    #[tokio::test]
    async fn deleting_an_absent_global_setting_records_a_no_op() {
        let service = OpenShellService::new(test_server_state().await);

        let (result, event) = record(
            "UpdateConfig",
            service.update_config(authed_request(UpdateConfigRequest {
                global: true,
                setting_key: "ocsf_json_enabled".into(),
                delete_setting: true,
                ..Default::default()
            })),
        )
        .await;

        assert!(!result.unwrap().into_inner().deleted);
        assert_eq!(event["status_detail"], "no_op:already_absent", "{event}");
        assert_eq!(
            event["resources"],
            json!([{"type": "setting", "name": "ocsf_json_enabled"}])
        );
    }

    #[tokio::test]
    async fn draft_chunk_records_name_chunks_but_never_tokens_or_rules() {
        let service = OpenShellService::new(test_server_state().await);
        let scope = || Some(workspace_selector("default"));
        let chunk_targets = [
            "workspace:default",
            "sandbox:missing-sbx",
            "draft_chunk:chunk-1",
        ];

        let (_, event) = record(
            "ApproveDraftChunk",
            service.approve_draft_chunk(authed_request(ApproveDraftChunkRequest {
                workspace_scope: scope(),
                sandbox: "missing-sbx".into(),
                chunk_id: "chunk-1".into(),
                review_token: CANARY.into(),
                ..Default::default()
            })),
        )
        .await;
        assert_eq!(named(&event), chunk_targets);
        assert_redacted(&event, CANARY);

        let (_, event) = record(
            "RejectDraftChunk",
            service.reject_draft_chunk(authed_request(RejectDraftChunkRequest {
                workspace_scope: scope(),
                sandbox: "missing-sbx".into(),
                chunk_id: "chunk-1".into(),
                reason: CANARY.into(),
                ..Default::default()
            })),
        )
        .await;
        assert_eq!(named(&event), chunk_targets);
        assert_redacted(&event, CANARY);

        let (_, event) = record(
            "EditDraftChunk",
            service.edit_draft_chunk(authed_request(EditDraftChunkRequest {
                workspace_scope: scope(),
                sandbox: "missing-sbx".into(),
                chunk_id: "chunk-1".into(),
                proposed_rule: Some(NetworkPolicyRule {
                    name: CANARY.into(),
                    ..Default::default()
                }),
                ..Default::default()
            })),
        )
        .await;
        assert_eq!(named(&event), chunk_targets);
        assert_redacted(&event, CANARY);

        let (_, event) = record(
            "UndoDraftChunk",
            service.undo_draft_chunk(authed_request(UndoDraftChunkRequest {
                workspace_scope: scope(),
                sandbox: "missing-sbx".into(),
                chunk_id: "chunk-1".into(),
                ..Default::default()
            })),
        )
        .await;
        assert_eq!(named(&event), chunk_targets);

        let (_, event) = record(
            "ApproveAllDraftChunks",
            service.approve_all_draft_chunks(authed_request(ApproveAllDraftChunksRequest {
                workspace_scope: scope(),
                sandbox: "missing-sbx".into(),
                approvals: vec![DraftChunkApproval {
                    chunk_id: "chunk-1".into(),
                    review_token: CANARY.into(),
                }],
                ..Default::default()
            })),
        )
        .await;
        assert_eq!(named(&event), chunk_targets);
        assert_redacted(&event, CANARY);

        let (_, event) = record(
            "ClearDraftChunks",
            service.clear_draft_chunks(authed_request(ClearDraftChunksRequest {
                workspace_scope: scope(),
                sandbox: "missing-sbx".into(),
                ..Default::default()
            })),
        )
        .await;
        assert_eq!(named(&event), ["workspace:default", "sandbox:missing-sbx"]);
    }

    #[tokio::test]
    async fn draft_chunk_responses_name_the_policy_or_record_a_no_op() {
        let (_, event) = record(
            "ApproveDraftChunk",
            audited(Vec::new(), async {
                Ok(Response::new(ApproveDraftChunkResponse {
                    policy_version: 4,
                    policy_hash: "sha256:abc".into(),
                }))
            }),
        )
        .await;
        assert_eq!(
            event["resources"],
            json!([{"type": "policy", "uid": "sha256:abc"}])
        );

        let (_, event) = record(
            "ApproveAllDraftChunks",
            audited(Vec::new(), async {
                Ok(Response::new(ApproveAllDraftChunksResponse::default()))
            }),
        )
        .await;
        assert_eq!(event["status_detail"], "no_op:unchanged", "{event}");

        let (_, event) = record(
            "ClearDraftChunks",
            audited(Vec::new(), async {
                Ok(Response::new(ClearDraftChunksResponse::default()))
            }),
        )
        .await;
        assert_eq!(event["status_detail"], "no_op:already_absent", "{event}");
    }

    #[tokio::test]
    async fn bulk_approvals_keep_the_resulting_policy() {
        let targets = scoped(
            Some(&workspace_selector("default")),
            std::iter::once(requested("sandbox", "agent-01"))
                .chain((0..20).map(|n| requested("draft_chunk", &format!("chunk-{n}")))),
        );
        let (_, event) = record(
            "ApproveAllDraftChunks",
            audited(targets, async {
                Ok(Response::new(ApproveAllDraftChunksResponse {
                    policy_hash: "sha256:abc".into(),
                    chunks_approved: 20,
                    ..Default::default()
                }))
            }),
        )
        .await;

        assert_eq!(event["resources"].as_array().unwrap().len(), 16, "{event}");
        assert_eq!(
            event["resources"][15],
            json!({"type": "policy", "uid": "sha256:abc"})
        );
        assert_eq!(
            event["message"], "mutation succeeded; 7 more resources not listed",
            "{event}"
        );
    }

    #[tokio::test]
    async fn refresh_status_errors_are_never_recorded() {
        let (_, event) = record(
            "ConfigureProviderRefresh",
            audited(Vec::new(), async {
                Ok(Response::new(ConfigureProviderRefreshResponse {
                    status: Some(ProviderCredentialRefreshStatus {
                        provider: "audit-openai".into(),
                        last_error: CANARY.into(),
                        ..Default::default()
                    }),
                }))
            }),
        )
        .await;

        assert_eq!(named(&event), ["provider:audit-openai"]);
        assert_redacted(&event, CANARY);
    }

    /// Decodes the frames `client_stream` sends.
    struct Decode<T>(std::marker::PhantomData<T>);

    impl<T: prost::Message + Default + Send + 'static> tonic::codec::Decoder for Decode<T> {
        type Item = T;
        type Error = Status;

        fn decode(&mut self, buf: &mut tonic::codec::DecodeBuf<'_>) -> Result<Option<T>, Status> {
            T::decode(buf)
                .map(Some)
                .map_err(|error| Status::internal(error.to_string()))
        }
    }

    /// A client stream that sends `frames` and ends.
    fn client_stream<T: prost::Message + Default + Send + 'static>(
        frames: &[T],
    ) -> tonic::Streaming<T> {
        let mut body = Vec::new();
        for frame in frames {
            let frame = frame.encode_to_vec();
            body.push(0);
            body.extend(u32::try_from(frame.len()).unwrap().to_be_bytes());
            body.extend(frame);
        }
        tonic::Streaming::new_request(
            Decode(std::marker::PhantomData),
            http_body_util::Full::new(bytes::Bytes::from(body)),
            None,
            None,
        )
    }

    /// A ready sandbox named `agent-01` whose supervisor session hands each
    /// relay it is asked to open to the returned receiver.
    async fn ready_sandbox(
        state: &Arc<crate::ServerState>,
    ) -> tokio::sync::mpsc::Receiver<openshell_core::proto::GatewayMessage> {
        let mut sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: "sb-agent-01".into(),
                name: "agent-01".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(openshell_core::proto::SandboxPhase::Ready as i32);
        state.store.put_message(&sandbox).await.unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        state.supervisor_sessions.register(
            "sb-agent-01".into(),
            "session-1".into(),
            tx,
            tokio::sync::oneshot::channel().0,
        );
        rx
    }

    /// The channel of the next relay the supervisor was asked to open.
    fn relay_channel(
        supervisor: &mut tokio::sync::mpsc::Receiver<openshell_core::proto::GatewayMessage>,
    ) -> String {
        use openshell_core::proto::gateway_message::Payload;
        loop {
            if let Some(Payload::RelayOpen(open)) = supervisor.try_recv().unwrap().payload {
                return open.channel_id;
            }
        }
    }

    fn exec_request() -> ExecSandboxRequest {
        ExecSandboxRequest {
            workspace_scope: Some(workspace_selector("default")),
            sandbox: "agent-01".into(),
            command: vec!["echo".into(), format!("{CANARY}-command")],
            environment: HashMap::from([("API_TOKEN".into(), format!("{CANARY}-env"))]),
            stdin: format!("{CANARY}-stdin").into_bytes(),
            ..Default::default()
        }
    }

    /// An interactive exec that starts and then sends input.
    fn interactive_exec() -> tonic::Streaming<ExecSandboxInput> {
        use openshell_core::proto::exec_sandbox_input::Payload;
        client_stream(&[
            ExecSandboxInput {
                payload: Some(Payload::Start(exec_request())),
            },
            ExecSandboxInput {
                payload: Some(Payload::Stdin(format!("{CANARY}-input").into_bytes())),
            },
        ])
    }

    fn agent_sandbox() -> Value {
        json!({"type": "sandbox", "name": "agent-01", "uid": "sb-agent-01"})
    }

    #[tokio::test]
    async fn execs_name_the_sandbox_and_relay_but_not_their_command_env_or_stdin_by_default() {
        let state = test_server_state().await;
        let mut supervisor = ready_sandbox(&state).await;
        let service = OpenShellService::new(state);

        let (result, event) = record(
            "ExecSandbox",
            service.exec_sandbox(authed_request(exec_request())),
        )
        .await;

        result.unwrap();
        assert_eq!(
            event["resources"],
            json!([
                default_workspace(),
                agent_sandbox(),
                {"type": "exec", "uid": relay_channel(&mut supervisor)},
            ]),
            "{event}"
        );
        assert_redacted(&event, CANARY);

        let (result, event) = record(
            "ExecSandboxInteractive",
            service.exec_sandbox_interactive(authed_request(interactive_exec())),
        )
        .await;

        result.unwrap();
        assert_eq!(
            event["resources"],
            json!([
                default_workspace(),
                agent_sandbox(),
                {"type": "exec", "uid": relay_channel(&mut supervisor)},
            ]),
            "{event}"
        );
        assert_redacted(&event, CANARY);
    }

    #[tokio::test]
    async fn execs_record_their_command_when_the_gateway_captures_it() {
        let mut state = test_server_state().await;
        Arc::get_mut(&mut state)
            .expect("unshared test state")
            .config
            .audit
            .capture_exec_command = true;
        let mut supervisor = ready_sandbox(&state).await;
        let service = OpenShellService::new(state);

        let (result, event) = record(
            "ExecSandbox",
            service.exec_sandbox(authed_request(exec_request())),
        )
        .await;

        result.unwrap();
        assert_eq!(
            event["resources"][2],
            json!({
                "type": "exec",
                "uid": relay_channel(&mut supervisor),
                "data": {"command": ["echo", format!("{CANARY}-command")]},
            }),
            "{event}"
        );
        for secret in [format!("{CANARY}-env"), format!("{CANARY}-stdin")] {
            assert_redacted(&event, &secret);
        }
    }

    #[test]
    fn captured_commands_count_the_arguments_left_out() {
        let request = ExecSandboxRequest {
            command: (0..40).map(|n| n.to_string()).collect(),
            ..Default::default()
        };

        let data = exec_command(true, &request).unwrap();

        assert_eq!(data["command"].as_array().unwrap().len(), 32);
        assert_eq!(data["command"][31], "31");
        assert_eq!(data["omitted"], 8);
    }

    #[tokio::test]
    async fn rejected_exec_names_the_requested_sandbox() {
        let service = OpenShellService::new(test_server_state().await);

        let (_, event) = record(
            "ExecSandboxInteractive",
            service.exec_sandbox_interactive(authed_request(interactive_exec())),
        )
        .await;

        assert_eq!(event["status_detail"], "rejected:not_found", "{event}");
        assert_eq!(named(&event), ["workspace:default", "sandbox:agent-01"]);
        assert_redacted(&event, CANARY);
    }

    #[tokio::test]
    async fn ssh_session_and_forward_records_name_the_session_but_never_its_token() {
        let state = test_server_state().await;
        let mut supervisor = ready_sandbox(&state).await;
        let service = OpenShellService::new(state);

        let (result, created) = record(
            "CreateSshSession",
            service.create_ssh_session(authed_request(CreateSshSessionRequest {
                workspace_scope: Some(workspace_selector("default")),
                sandbox: "agent-01".into(),
            })),
        )
        .await;
        let token = result.unwrap().into_inner().token;
        let session = created["resources"][2]["name"]
            .as_str()
            .unwrap()
            .to_string();
        let ssh_session = json!({"type": "ssh_session", "name": session});
        assert_eq!(
            created["resources"],
            json!([default_workspace(), agent_sandbox(), ssh_session]),
            "{created}"
        );
        assert_redacted(&created, &token);

        let forward = client_stream(&[
            TcpForwardFrame {
                payload: Some(tcp_forward_frame::Payload::Init(TcpForwardInit {
                    sandbox: "agent-01".into(),
                    workspace: "default".into(),
                    target: Some(tcp_forward_init::Target::Ssh(SshRelayTarget {})),
                    authorization_token: token.clone(),
                    ..Default::default()
                })),
            },
            TcpForwardFrame {
                payload: Some(tcp_forward_frame::Payload::Data(CANARY.into())),
            },
        ]);
        let (result, forwarded) =
            record("ForwardTcp", service.forward_tcp(authed_request(forward))).await;
        result.unwrap();
        assert_eq!(
            forwarded["resources"],
            json!([
                default_workspace(),
                agent_sandbox(),
                ssh_session,
                {"type": "forward", "uid": relay_channel(&mut supervisor)},
            ]),
            "{forwarded}"
        );
        assert_redacted(&forwarded, &token);
        assert_redacted(&forwarded, CANARY);

        let revoke = || {
            service.revoke_ssh_session(authed_request(RevokeSshSessionRequest {
                token: token.clone(),
                allow_missing: false,
            }))
        };
        let (_, revoked) = record("RevokeSshSession", revoke()).await;
        assert_eq!(
            revoked["resources"],
            json!([
                default_workspace(),
                {"type": "sandbox", "uid": "sb-agent-01"},
                ssh_session,
            ]),
            "{revoked}"
        );
        assert!(revoked.get("status_detail").is_none(), "{revoked}");
        assert_redacted(&revoked, &token);

        let (_, repeated) = record("RevokeSshSession", revoke()).await;
        assert_eq!(
            repeated["status_detail"], "no_op:already_absent",
            "{repeated}"
        );
        assert_eq!(repeated["resources"], revoked["resources"]);
    }

    #[tokio::test]
    async fn revoking_an_unknown_ssh_session_names_nothing() {
        let service = OpenShellService::new(test_server_state().await);
        let revoke = |allow_missing| {
            service.revoke_ssh_session(authed_request(RevokeSshSessionRequest {
                token: CANARY.into(),
                allow_missing,
            }))
        };

        let (_, absent) = record("RevokeSshSession", revoke(true)).await;
        let (_, rejected) = record("RevokeSshSession", revoke(false)).await;

        assert_eq!(absent["status_detail"], "no_op:already_absent", "{absent}");
        assert_eq!(
            rejected["status_detail"], "rejected:not_found",
            "{rejected}"
        );
        for event in [absent, rejected] {
            assert!(event.get("resources").is_none(), "{event}");
            assert_redacted(&event, CANARY);
        }
    }

    #[tokio::test]
    async fn tcp_forwards_record_their_target() {
        let state = test_server_state().await;
        let mut supervisor = ready_sandbox(&state).await;
        let service = OpenShellService::new(state);
        let init = TcpForwardFrame {
            payload: Some(tcp_forward_frame::Payload::Init(TcpForwardInit {
                sandbox: "agent-01".into(),
                workspace: "default".into(),
                target: Some(tcp_forward_init::Target::Tcp(TcpRelayTarget {
                    host: "127.0.0.1".into(),
                    port: 8080,
                })),
                ..Default::default()
            })),
        };

        let (result, event) = record(
            "ForwardTcp",
            service.forward_tcp(authed_request(client_stream(&[init]))),
        )
        .await;

        result.unwrap();
        assert_eq!(
            event["resources"][2],
            json!({
                "type": "forward",
                "uid": relay_channel(&mut supervisor),
                "data": {"host": "127.0.0.1", "port": 8080},
            }),
            "{event}"
        );
    }
}
