// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

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
    StartSandboxRequest, StopSandboxRequest, SuspendSandboxRequest, UpdateProviderProfilesRequest,
    UpdateSandboxRequest, WorkspaceRole, workspace_selector,
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

    let (result, events) = audited_mutation(&path("DeleteProviderRefresh"), &principal(), async {
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
                service.update_provider_profiles(authed_request(UpdateProviderProfilesRequest {
                    workspace_scope: scope(),
                    id: "missing-profile".into(),
                    ..Default::default()
                })),
            )
            .await
            .1,
            json!([default_workspace(), {"type": "provider_profile", "name": "missing-profile"}]),
        ),
        (
            "rejected:invalid_argument",
            record(
                "ImportProviderProfiles",
                service.import_provider_profiles(authed_request(ImportProviderProfilesRequest {
                    workspace_scope: scope(),
                    ..Default::default()
                })),
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
