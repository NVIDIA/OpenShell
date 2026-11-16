// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! What audited mutations acted on and how they ended, read from their typed
//! requests and responses.

use std::future::Future;

use openshell_core::proto::{
    DeleteProviderProfileResponse, DeleteProviderRefreshResponse, DeleteProviderResponse,
    DeleteSandboxResponse, DeleteSandboxTemplateResponse, DeleteServiceResponse,
    DeleteWorkspaceResponse, DeletionOutcome, RemoveWorkspaceMemberResponse, WorkspaceSelector,
    workspace_selector::Selection,
};
use openshell_ocsf::ResourceDetails;
use tonic::{Response, Status};

use crate::auth::audit;
pub(super) use crate::auth::audit::requested;

/// A response that reports how a deletion ended.
pub(super) trait Deletion {
    fn deletion_outcome(&self) -> DeletionOutcome;

    /// The gateway ID of the deleted resource, when the response names it.
    fn deleted_uid(&self) -> Option<&str> {
        None
    }
}

macro_rules! deletion {
    ($($response:ty),* $(,)?) => {
        $(impl Deletion for $response {
            fn deletion_outcome(&self) -> DeletionOutcome {
                self.outcome()
            }
        })*
    };
}

deletion!(
    DeleteSandboxTemplateResponse,
    DeleteServiceResponse,
    DeleteProviderResponse,
    DeleteProviderProfileResponse,
    DeleteProviderRefreshResponse,
    DeleteWorkspaceResponse,
    RemoveWorkspaceMemberResponse,
);

impl Deletion for DeleteSandboxResponse {
    fn deletion_outcome(&self) -> DeletionOutcome {
        self.outcome()
    }

    fn deleted_uid(&self) -> Option<&str> {
        Some(self.sandbox_id.as_str()).filter(|id| !id.is_empty())
    }
}

/// Run a deletion of `targets`, the last being the deleted resource,
/// recording them before the call starts and how the deletion ended.
pub(super) async fn deletion<T: Deletion>(
    targets: Vec<ResourceDetails>,
    call: impl Future<Output = Result<Response<T>, Status>>,
) -> Result<Response<T>, Status> {
    for target in targets {
        audit::record_target(target);
    }
    let response = call.await;
    if let Ok(response) = &response {
        let response = response.get_ref();
        if let Some(uid) = response.deleted_uid() {
            audit::amend_targets(|targets| {
                if let Some(target) = targets.last_mut() {
                    target.uid = Some(uid.to_string());
                }
            });
        }
        match response.deletion_outcome() {
            DeletionOutcome::AlreadyAbsent => audit::record_outcome("no_op:already_absent"),
            DeletionOutcome::Accepted => audit::record_outcome("accepted"),
            DeletionOutcome::Completed | DeletionOutcome::Unspecified => {}
        }
    }
    response
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
    use openshell_core::proto::open_shell_server::OpenShell;
    use openshell_core::proto::{
        CreateSandboxRequest, CreateWorkspaceRequest, DeleteProviderProfileRequest,
        DeleteProviderRefreshRequest, DeleteProviderRequest, DeleteSandboxRequest,
        DeleteSandboxTemplateRequest, DeleteServiceRequest, DeleteWorkspaceRequest,
        DeletionOutcome, RemoveWorkspaceMemberRequest, SandboxSpec, workspace_selector,
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

        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
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

        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
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

        assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
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
        let call = deletion(
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
        let call = deletion(targets, async {
            Err::<Response<DeleteProviderResponse>, _>(audit::deny(
                &principal(),
                audit::AuthzDenial::InsufficientWorkspaceRole {
                    workspace: "default",
                },
                "workspace role required",
            ))
        });

        let (result, events) = audited_mutation(&path("DeleteProvider"), &principal(), call).await;

        assert_eq!(result.unwrap_err().code(), tonic::Code::PermissionDenied);
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
}
