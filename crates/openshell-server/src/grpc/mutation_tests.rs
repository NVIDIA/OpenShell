// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::proto::datamodel::v1::ObjectMeta;
use openshell_core::proto::{
    DeleteProviderProfileRequest, DeleteProviderRefreshRequest, DeleteProviderRequest,
    DeleteSandboxRequest, DeleteSandboxTemplateRequest, DeleteServiceRequest,
    DeleteWorkspaceRequest, DeletionOutcome, Provider, RemoveWorkspaceMemberRequest,
    RevokeSshSessionRequest, Sandbox, SshSession,
};
use tonic::Code;

use super::test_support::{authed_request, test_server_state};
use super::{provider, sandbox, service, workspace};

fn metadata(id: &str) -> ObjectMeta {
    ObjectMeta {
        id: id.into(),
        name: id.into(),
        workspace: "default".into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn every_delete_requires_explicit_allow_missing() {
    let state = test_server_state().await;
    state
        .store
        .put_message(&Sandbox {
            metadata: Some(metadata("parent-sandbox")),
            ..Default::default()
        })
        .await
        .unwrap();
    state
        .store
        .put_message(&Provider {
            metadata: Some(metadata("parent-provider")),
            ..Default::default()
        })
        .await
        .unwrap();

    macro_rules! check {
        ($handler:path, $request:expr) => {{
            let mut request = $request;
            let err = $handler(&state, authed_request(request.clone()))
                .await
                .unwrap_err();
            assert_eq!(
                err.code(),
                Code::NotFound,
                "{}: {err}",
                stringify!($handler)
            );
            request.allow_missing = true;
            let response = $handler(&state, authed_request(request))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(
                response.outcome,
                i32::from(DeletionOutcome::AlreadyAbsent),
                "{}",
                stringify!($handler)
            );
        }};
    }
    check!(
        sandbox::handle_delete_sandbox,
        DeleteSandboxRequest {
            name: "missing".into(),
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            ..Default::default()
        }
    );
    check!(
        sandbox::handle_delete_sandbox_template,
        DeleteSandboxTemplateRequest {
            name: "missing".into(),
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            ..Default::default()
        }
    );
    check!(
        provider::handle_delete_provider,
        DeleteProviderRequest {
            name: "missing".into(),
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            ..Default::default()
        }
    );
    check!(
        provider::handle_delete_provider_profile,
        DeleteProviderProfileRequest {
            id: "custom-missing".into(),
            ..Default::default()
        }
    );
    check!(
        provider::handle_delete_provider_refresh,
        DeleteProviderRefreshRequest {
            provider: "parent-provider".into(),
            credential_key: "API_KEY".into(),
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            ..Default::default()
        }
    );
    check!(
        service::handle_delete_service,
        DeleteServiceRequest {
            sandbox: "parent-sandbox".into(),
            service: "missing".into(),
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            ..Default::default()
        }
    );
    check!(
        workspace::handle_delete_workspace,
        DeleteWorkspaceRequest {
            name: "missing".into(),
            ..Default::default()
        }
    );
    check!(
        workspace::handle_remove_workspace_member,
        RemoveWorkspaceMemberRequest {
            principal_subject: "missing".into(),
            ..Default::default()
        }
    );
    check!(
        sandbox::handle_revoke_ssh_session,
        RevokeSshSessionRequest {
            token: "missing".into(),
            ..Default::default()
        }
    );
}

#[tokio::test]
async fn allow_missing_does_not_hide_missing_parents_or_invalid_requests() {
    let state = test_server_state().await;
    let err = service::handle_delete_service(
        &state,
        authed_request(DeleteServiceRequest {
            sandbox: "missing-parent".into(),
            allow_missing: true,
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            ..Default::default()
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    let err = provider::handle_delete_provider_refresh(
        &state,
        authed_request(DeleteProviderRefreshRequest {
            provider: "missing-parent".into(),
            credential_key: "API_KEY".into(),
            allow_missing: true,
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    let err = workspace::handle_remove_workspace_member(
        &state,
        authed_request(RemoveWorkspaceMemberRequest {
            workspace: "missing-parent".into(),
            principal_subject: "missing".into(),
            allow_missing: true,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    let err = sandbox::handle_revoke_ssh_session(
        &state,
        authed_request(RevokeSshSessionRequest {
            allow_missing: true,
            ..Default::default()
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    let err = sandbox::handle_revoke_ssh_session(
        &state,
        tonic::Request::new(RevokeSshSessionRequest {
            token: "missing".into(),
            allow_missing: true,
        }),
    )
    .await
    .unwrap_err();
    // Authentication middleware must inject a principal before dispatch.
    assert_eq!(err.code(), Code::Internal);
}

#[tokio::test]
async fn repeated_revocation_completes_without_another_write() {
    let state = test_server_state().await;
    state
        .store
        .put_message(&SshSession {
            metadata: Some(metadata("session-token")),
            token: "session-token".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let request = RevokeSshSessionRequest {
        token: "session-token".into(),
        allow_missing: false,
    };
    let first = sandbox::handle_revoke_ssh_session(&state, authed_request(request.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first.outcome, i32::from(DeletionOutcome::Completed));
    let stored = state
        .store
        .get_message::<SshSession>("session-token")
        .await
        .unwrap()
        .unwrap();
    assert!(stored.revoked);
    let second = sandbox::handle_revoke_ssh_session(&state, authed_request(request))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(second.outcome, i32::from(DeletionOutcome::Completed));
    assert_eq!(
        state
            .store
            .get_message::<SshSession>("session-token")
            .await
            .unwrap()
            .unwrap(),
        stored
    );
}
