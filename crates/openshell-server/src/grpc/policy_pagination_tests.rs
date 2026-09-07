// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::policy::handle_list_sandbox_policies;
use crate::ServerState;
use crate::auth::identity::{Identity, IdentityProvider};
use crate::auth::principal::{Principal, UserPrincipal};
use crate::grpc::test_support::test_server_state;
use crate::policy_store::PolicyStoreExt;
use openshell_core::proto::datamodel::v1::ObjectMeta;
use openshell_core::proto::{
    ListSandboxPoliciesRequest, Sandbox, SandboxSpec, WorkspaceMember, WorkspaceRole,
};
use openshell_policy::restrictive_default_policy;
use prost::Message;
use std::collections::HashMap;
use std::sync::Arc;
use tonic::{Code, Request};

fn sandbox_policy_payload() -> Vec<u8> {
    restrictive_default_policy().encode_to_vec()
}

fn make_sandbox(id: &str, name: &str, workspace: &str) -> Sandbox {
    Sandbox {
        metadata: Some(ObjectMeta {
            id: id.to_string(),
            name: name.to_string(),
            created_at_ms: 1_000_000,
            labels: HashMap::new(),
            resource_version: 0,
            annotations: HashMap::new(),
            workspace: workspace.to_string(),
            deletion_timestamp_ms: 0,
        }),
        spec: Some(SandboxSpec {
            policy: Some(restrictive_default_policy()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn with_user(
    mut request: Request<ListSandboxPoliciesRequest>,
) -> Request<ListSandboxPoliciesRequest> {
    request
        .extensions_mut()
        .insert(Principal::User(UserPrincipal {
            identity: Identity {
                subject: "test-user".to_string(),
                display_name: None,
                roles: vec!["openshell-user".to_string()],
                scopes: vec![],
                provider: IdentityProvider::Oidc,
            },
        }));
    request
}

fn with_platform_admin(
    mut request: Request<ListSandboxPoliciesRequest>,
) -> Request<ListSandboxPoliciesRequest> {
    request
        .extensions_mut()
        .insert(Principal::User(UserPrincipal {
            identity: Identity {
                subject: "test-admin".to_string(),
                display_name: None,
                roles: vec!["openshell-admin".to_string()],
                scopes: vec![],
                provider: IdentityProvider::Oidc,
            },
        }));
    request
}

async fn seed_workspace_member(state: &Arc<ServerState>, workspace: &str) {
    let member = WorkspaceMember {
        metadata: Some(ObjectMeta {
            id: "member-id".to_string(),
            name: "test-user".to_string(),
            created_at_ms: 1_000_000,
            labels: HashMap::new(),
            resource_version: 0,
            annotations: HashMap::new(),
            workspace: workspace.to_string(),
            deletion_timestamp_ms: 0,
        }),
        principal_subject: "test-user".to_string(),
        role: WorkspaceRole::User.into(),
    };
    state.store.put_message(&member).await.unwrap();
}

#[tokio::test]
async fn list_sandbox_policies_uses_stable_page_tokens_for_sandbox_scope() {
    let state = test_server_state().await;
    let sandbox_id = "sandbox-page-token";
    let sandbox_name = "sandbox-page-token";
    let payload = sandbox_policy_payload();

    state
        .store
        .put_message(&make_sandbox(sandbox_id, sandbox_name, "default"))
        .await
        .unwrap();
    seed_workspace_member(&state, "default").await;

    for (version, id) in [
        (1_i64, "sandbox-page-token-revision-1"),
        (2, "sandbox-page-token-revision-2"),
        (3, "sandbox-page-token-revision-3"),
    ] {
        state
            .store
            .put_policy_revision(id, sandbox_id, "default", version, &payload, id)
            .await
            .unwrap();
    }

    let first_page = handle_list_sandbox_policies(
        &state,
        with_user(Request::new(ListSandboxPoliciesRequest {
            name: sandbox_name.to_string(),
            limit: 1,
            offset: 0,
            global: false,
            workspace: "default".to_string(),
            page_token: String::new(),
        })),
    )
    .await
    .unwrap()
    .into_inner();

    assert_eq!(first_page.revisions.len(), 1);
    assert_eq!(first_page.revisions[0].version, 3);
    assert!(!first_page.next_page_token.is_empty());

    state
        .store
        .put_policy_revision(
            "sandbox-page-token-revision-4",
            sandbox_id,
            "default",
            4,
            &payload,
            "sandbox-page-token-revision-4",
        )
        .await
        .unwrap();

    let offset_page = handle_list_sandbox_policies(
        &state,
        with_user(Request::new(ListSandboxPoliciesRequest {
            name: sandbox_name.to_string(),
            limit: 1,
            offset: 1,
            global: false,
            workspace: "default".to_string(),
            page_token: String::new(),
        })),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(offset_page.revisions.len(), 1);
    assert_eq!(offset_page.revisions[0].version, 3);

    let token_page = handle_list_sandbox_policies(
        &state,
        with_user(Request::new(ListSandboxPoliciesRequest {
            name: sandbox_name.to_string(),
            limit: 1,
            offset: 0,
            global: false,
            workspace: "default".to_string(),
            page_token: first_page.next_page_token,
        })),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(token_page.revisions.len(), 1);
    assert_eq!(token_page.revisions[0].version, 2);
}

#[tokio::test]
async fn list_sandbox_policies_uses_stable_page_tokens_for_global_scope() {
    let mut state = test_server_state().await;
    Arc::get_mut(&mut state).unwrap().admin_role = "openshell-admin".to_string();
    let payload = sandbox_policy_payload();

    for (version, id) in [
        (1_i64, "global-page-token-revision-1"),
        (2, "global-page-token-revision-2"),
        (3, "global-page-token-revision-3"),
    ] {
        state
            .store
            .put_policy_revision(id, "__global__", "", version, &payload, id)
            .await
            .unwrap();
    }

    let first_page = handle_list_sandbox_policies(
        &state,
        with_platform_admin(Request::new(ListSandboxPoliciesRequest {
            global: true,
            limit: 1,
            offset: 0,
            workspace: String::new(),
            name: String::new(),
            page_token: String::new(),
        })),
    )
    .await
    .unwrap()
    .into_inner();

    assert_eq!(first_page.revisions.len(), 1);
    assert_eq!(first_page.revisions[0].version, 3);
    assert!(!first_page.next_page_token.is_empty());

    state
        .store
        .put_policy_revision(
            "global-page-token-revision-4",
            "__global__",
            "",
            4,
            &payload,
            "global-page-token-revision-4",
        )
        .await
        .unwrap();

    let offset_page = handle_list_sandbox_policies(
        &state,
        with_platform_admin(Request::new(ListSandboxPoliciesRequest {
            global: true,
            limit: 1,
            offset: 1,
            workspace: String::new(),
            name: String::new(),
            page_token: String::new(),
        })),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(offset_page.revisions.len(), 1);
    assert_eq!(offset_page.revisions[0].version, 3);

    let token_page = handle_list_sandbox_policies(
        &state,
        with_platform_admin(Request::new(ListSandboxPoliciesRequest {
            global: true,
            limit: 1,
            offset: 0,
            workspace: String::new(),
            name: String::new(),
            page_token: first_page.next_page_token,
        })),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(token_page.revisions.len(), 1);
    assert_eq!(token_page.revisions[0].version, 2);
}

#[tokio::test]
async fn list_sandbox_policies_rejects_page_token_with_offset() {
    let mut state = test_server_state().await;
    Arc::get_mut(&mut state).unwrap().admin_role = "openshell-admin".to_string();

    let err = handle_list_sandbox_policies(
        &state,
        with_platform_admin(Request::new(ListSandboxPoliciesRequest {
            global: true,
            limit: 1,
            offset: 1,
            workspace: String::new(),
            name: String::new(),
            page_token: "opaque-token".to_string(),
        })),
    )
    .await
    .expect_err("page_token combined with offset should fail");

    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(err.message().contains("page_token cannot be combined"));
}
