// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! What audited mutations acted on and how they ended, read from their typed
//! requests and responses.

use std::future::Future;

use openshell_core::proto::datamodel::v1::ObjectMeta;
use openshell_core::proto::{
    AddWorkspaceMemberResponse, AttachSandboxProviderResponse, BeginRootfsTarStagingResponse,
    CreateWorkspaceResponse, DeleteProviderProfileResponse, DeleteProviderRefreshResponse,
    DeleteProviderResponse, DeleteSandboxResponse, DeleteSandboxTemplateResponse,
    DeleteSecretResponse, DeleteServiceResponse, DeleteWorkspaceResponse, DeletionOutcome,
    DetachSandboxProviderResponse, ImportProviderProfilesResponse, ProviderProfile,
    RemoveWorkspaceMemberResponse, Sandbox, SandboxResponse, SandboxTemplateResponse,
    SecretResponse, ServiceEndpointResponse, UpdateProviderProfilesResponse, WorkspaceSelector,
    workspace_selector::Selection,
};
use openshell_ocsf::ResourceDetails;
use tonic::{Code, Response, Status};

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

impl Audited for openshell_core::proto::InlineProviderRefreshSecretsResponse {}

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

/// Run `call`, recording the requested `targets` that have a name before it
/// starts, then what it produced and how it ended. The call is boxed because
/// handler futures are large.
pub(super) fn audited<T: Audited>(
    mut targets: Vec<ResourceDetails>,
    call: impl Future<Output = Result<Response<T>, Status>>,
) -> impl Future<Output = Result<Response<T>, Status>> {
    let call = Box::pin(call);
    async move {
        targets.retain(|target| target.name.as_deref().is_some_and(|name| !name.is_empty()));
        for target in targets {
            audit::record_target(target);
        }
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
    use crate::auth::audit::test_support::{audited_mutation, cancelled_mutation};
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
    use serde_json::{Value, json};

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
        assert_eq!(event["resources"][15]["name"], "profile-15", "{event}");
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
}
