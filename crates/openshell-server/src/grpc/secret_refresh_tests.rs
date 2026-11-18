// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider refresh configured with workspace-secret material.

use std::collections::HashMap;
use std::sync::Arc;

use openshell_core::proto::datamodel::v1::ObjectMeta;
use openshell_core::proto::{
    ConfigureProviderRefreshRequest, CreateSecretRequest, DeleteSecretRequest,
    GetProviderRefreshStatusRequest, ImportProviderProfilesRequest,
    InlineProviderRefreshSecretsRequest, Provider, ProviderCredentialRefresh,
    ProviderCredentialRefreshMaterial, ProviderCredentialRefreshStatus,
    ProviderCredentialRefreshStrategy, ProviderProfile, ProviderProfileCategory,
    ProviderProfileCredential, ProviderProfileImportItem, RotateProviderCredentialRequest,
    SecretRefreshUse, UpdateSecretRequest, workspace_selector,
};
use openshell_core::{ObjectId, ObjectWorkspace};
use openshell_credential_issuer::refresh::{CredentialRefresh, secret_refs};
use tonic::Code;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::provider::{
    create_provider_record, handle_configure_provider_refresh, handle_get_provider_refresh_status,
    handle_import_provider_profiles, handle_inline_provider_refresh_secrets,
    handle_rotate_provider_credential,
};
use super::secret::{handle_create_secret, handle_delete_secret, handle_update_secret};
use super::test_support::{authed_request, test_server_state};
use crate::ServerState;

const PROFILE: &str = "shared-oauth";
const PROVIDER: &str = "alice-mcp";
const KEY: &str = "MCP_ACCESS_TOKEN";

fn default_workspace() -> openshell_core::proto::WorkspaceSelector {
    workspace_selector("default".to_string())
}

async fn enabled_state() -> Arc<ServerState> {
    let mut state = test_server_state().await;
    Arc::get_mut(&mut state)
        .expect("test state is not shared yet")
        .config
        .workspace_secrets
        .enabled = true;
    state
}

fn material(name: &str, secret: bool) -> ProviderCredentialRefreshMaterial {
    ProviderCredentialRefreshMaterial {
        name: name.to_string(),
        description: String::new(),
        required: secret,
        secret,
    }
}

async fn import_profile(
    state: &Arc<ServerState>,
    strategy: ProviderCredentialRefreshStrategy,
    token_url: &str,
) {
    import_profile_with_material(state, strategy, token_url, Vec::new()).await;
}

async fn import_profile_with_material(
    state: &Arc<ServerState>,
    strategy: ProviderCredentialRefreshStrategy,
    token_url: &str,
    extra_material: Vec<ProviderCredentialRefreshMaterial>,
) {
    let credential = ProviderProfileCredential {
        token_grant_owners: Vec::new(),
        name: "access_token".to_string(),
        description: String::new(),
        env_vars: vec![KEY.to_string()],
        required: true,
        stable_placeholder: false,
        auth_style: "bearer".to_string(),
        header_name: "authorization".to_string(),
        query_param: String::new(),
        path_template: String::new(),
        refresh: Some(ProviderCredentialRefresh {
            strategy: strategy as i32,
            token_url: token_url.to_string(),
            scopes: Vec::new(),
            refresh_before: Some(prost_types::Duration {
                seconds: 300,
                nanos: 0,
            }),
            max_lifetime: Some(prost_types::Duration {
                seconds: 3600,
                nanos: 0,
            }),
            additional_outputs: Vec::new(),
            material: [
                material("client_id", false),
                material("client_secret", true),
            ]
            .into_iter()
            .chain(extra_material)
            .collect(),
        }),
        token_grant: None,
    };
    let profile = ProviderProfile {
        id: PROFILE.to_string(),
        display_name: "Shared OAuth".to_string(),
        category: ProviderProfileCategory::Other as i32,
        credentials: vec![credential],
        ..Default::default()
    };
    handle_import_provider_profiles(
        state,
        authed_request(ImportProviderProfilesRequest {
            request_id: String::new(),
            profiles: vec![ProviderProfileImportItem {
                profile: Some(profile),
                source: format!("{PROFILE}.yaml"),
            }],
            workspace_scope: Some(default_workspace()),
        }),
    )
    .await
    .expect("import profile");
    create_provider_record(
        state.store.as_ref(),
        "default",
        Provider {
            metadata: Some(ObjectMeta {
                name: PROVIDER.to_string(),
                workspace: "default".to_string(),
                ..Default::default()
            }),
            r#type: PROFILE.to_string(),
            credentials: HashMap::from([(KEY.to_string(), "initial-token".to_string())]),
            profile_workspace: "default".to_string(),
            ..Default::default()
        },
    )
    .await
    .expect("create provider");
}

async fn create_secret(state: &Arc<ServerState>, value: &str, allowed_endpoint: &str) {
    handle_create_secret(
        state,
        authed_request(CreateSecretRequest {
            workspace_scope: Some(default_workspace()),
            name: "acme".to_string(),
            description: String::new(),
            value: value.to_string(),
            refresh_use: Some(SecretRefreshUse {
                allowed_endpoints: vec![allowed_endpoint.to_string()],
            }),
            labels: HashMap::new(),
            request_id: String::new(),
        }),
    )
    .await
    .expect("create secret");
}

fn configure_request(
    strategy: ProviderCredentialRefreshStrategy,
) -> ConfigureProviderRefreshRequest {
    ConfigureProviderRefreshRequest {
        workspace_scope: Some(default_workspace()),
        provider: PROVIDER.to_string(),
        credential_key: KEY.to_string(),
        strategy: strategy as i32,
        material: HashMap::from([("client_id".to_string(), "client-id".to_string())]),
        secret_material_keys: vec!["client_secret".to_string()],
        material_secrets: HashMap::from([("client_secret".to_string(), "acme".to_string())]),
        ..Default::default()
    }
}

async fn configure(
    state: &Arc<ServerState>,
    request: ConfigureProviderRefreshRequest,
) -> Result<ProviderCredentialRefreshStatus, tonic::Status> {
    handle_configure_provider_refresh(state, authed_request(request))
        .await
        .map(|response| response.into_inner().status.expect("status"))
}

async fn rotate(state: &Arc<ServerState>) -> Result<(), tonic::Status> {
    handle_rotate_provider_credential(
        state,
        authed_request(RotateProviderCredentialRequest {
            workspace_scope: Some(default_workspace()),
            provider: PROVIDER.to_string(),
            credential_key: KEY.to_string(),
            request_id: String::new(),
        }),
    )
    .await
    .map(|_| ())
}

async fn delete_secret(state: &Arc<ServerState>) -> Result<(), tonic::Status> {
    handle_delete_secret(
        state,
        authed_request(DeleteSecretRequest {
            workspace_scope: Some(default_workspace()),
            name: "acme".to_string(),
            allow_missing: false,
            request_id: String::new(),
        }),
    )
    .await
    .map(|_| ())
}

async fn refresh_state(
    state: &Arc<ServerState>,
) -> openshell_credential_issuer::refresh::RefreshState {
    let provider = state
        .store
        .get_message_by_name::<Provider>("default", PROVIDER)
        .await
        .unwrap()
        .unwrap();
    state
        .refresh
        .get("default", provider.object_id(), KEY)
        .await
        .unwrap()
        .expect("refresh state")
}

async fn mount_token(server: &MockServer, client_secret: &str, access_token: &str) {
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains(format!(
            "client_secret={client_secret}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": access_token,
            "expires_in": 3600
        })))
        .up_to_n_times(1)
        .expect(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn refresh_uses_the_current_secret_value_and_survives_inlining() {
    let server = MockServer::start().await;
    let token_url = format!("{}/token", server.uri());
    mount_token(&server, "first-secret", "token-1").await;
    mount_token(&server, "second-secret", "token-2").await;

    let state = enabled_state().await;
    import_profile(
        &state,
        ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
        &token_url,
    )
    .await;
    create_secret(&state, "first-secret", &token_url).await;

    let status = configure(
        &state,
        configure_request(ProviderCredentialRefreshStrategy::Oauth2ClientCredentials),
    )
    .await
    .expect("configure with a workspace secret");
    assert_eq!(
        status.material_secrets,
        HashMap::from([("client_secret".to_string(), "acme".to_string())])
    );
    let stored = refresh_state(&state).await;
    assert!(
        stored
            .secret_material_keys
            .contains(&"client_secret".to_string())
    );
    assert!(!stored.secret_material_handles.contains_key("client_secret"));
    assert!(!stored.material.contains_key("client_secret"));

    rotate(&state).await.expect("mint with the first value");

    // Rotating the shared secret reaches the provider's next mint.
    handle_update_secret(
        &state,
        authed_request(UpdateSecretRequest {
            workspace_scope: Some(default_workspace()),
            name: "acme".to_string(),
            value: Some("second-secret".to_string()),
            ..Default::default()
        }),
    )
    .await
    .expect("rotate the shared secret");
    rotate(&state).await.expect("mint with the second value");

    let err = delete_secret(&state).await.unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(
        err.message().contains(&format!("{PROVIDER}/{KEY}")),
        "{}",
        err.message()
    );

    let inlined = handle_inline_provider_refresh_secrets(
        &state,
        authed_request(InlineProviderRefreshSecretsRequest {
            workspace_scope: Some(default_workspace()),
            provider: PROVIDER.to_string(),
            credential_key: KEY.to_string(),
            request_id: String::new(),
        }),
    )
    .await
    .expect("inline secrets")
    .into_inner()
    .status
    .unwrap();
    assert!(inlined.material_secrets.is_empty());
    let stored = refresh_state(&state).await;
    assert!(stored.secret_material_handles.contains_key("client_secret"));
    let constraints = secret_refs::material_endpoint_constraints(stored.metadata.as_ref()).unwrap();
    assert_eq!(
        constraints.get("client_secret"),
        Some(&vec![
            openshell_credential_issuer::endpoint::normalize_token_endpoint(&token_url).unwrap()
        ])
    );

    // The secret is no longer referenced, and the copied value still mints.
    delete_secret(&state)
        .await
        .expect("delete unreferenced secret");
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("client_secret=second-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "token-3",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    rotate(&state).await.expect("mint with the inlined value");

    let status = handle_get_provider_refresh_status(
        &state,
        authed_request(GetProviderRefreshStatusRequest {
            workspace_scope: Some(default_workspace()),
            provider: PROVIDER.to_string(),
            credential_key: KEY.to_string(),
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert!(status.credentials[0].material_secrets.is_empty());
}

#[tokio::test]
async fn configure_rejects_unsafe_secret_references() {
    let state = enabled_state().await;
    let token_url = "https://login.example.com/token";
    import_profile(
        &state,
        ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
        token_url,
    )
    .await;
    create_secret(&state, "value", "https://other.example.com/token").await;
    let strategy = ProviderCredentialRefreshStrategy::Oauth2ClientCredentials;

    let mut unlisted = configure_request(strategy);
    unlisted.secret_material_keys.clear();
    let err = configure(&state, unlisted).await.unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(err.message().contains("secret_material_keys"));

    let mut both = configure_request(strategy);
    both.material
        .insert("client_secret".to_string(), "inline".to_string());
    assert_eq!(
        configure(&state, both).await.unwrap_err().code(),
        Code::InvalidArgument
    );

    let mut not_secret = configure_request(strategy);
    not_secret.material.remove("client_id");
    not_secret
        .material_secrets
        .insert("client_id".to_string(), "acme".to_string());
    not_secret
        .secret_material_keys
        .push("client_id".to_string());
    let err = configure(&state, not_secret).await.unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(err.message().contains("not secret material"));

    let mut missing = configure_request(strategy);
    missing
        .material_secrets
        .insert("client_secret".to_string(), "absent".to_string());
    assert_eq!(
        configure(&state, missing).await.unwrap_err().code(),
        Code::NotFound
    );

    // The profile's token endpoint is not one the secret allows.
    let err = configure(&state, configure_request(strategy))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(err.message().contains("does not allow token endpoint"));

    // A Microsoft tenant override changes the endpoint the mint would call.
    let mut tenant = configure_request(strategy);
    tenant
        .material
        .insert("tenant_id".to_string(), "attacker".to_string());
    assert_eq!(
        configure(&state, tenant).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
}

#[tokio::test]
async fn rotating_refresh_tokens_stay_provider_owned() {
    let state = enabled_state().await;
    let token_url = "https://login.example.com/token";
    import_profile(
        &state,
        ProviderCredentialRefreshStrategy::Oauth2RefreshToken,
        token_url,
    )
    .await;
    create_secret(&state, "value", token_url).await;
    let mut request = configure_request(ProviderCredentialRefreshStrategy::Oauth2RefreshToken);
    request
        .material_secrets
        .insert("refresh_token".to_string(), "acme".to_string());
    request
        .secret_material_keys
        .push("refresh_token".to_string());
    let err = configure(&state, request).await.unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(err.message().contains("rotated per provider"));
}

#[tokio::test]
async fn references_require_activation() {
    let state = enabled_state().await;
    let token_url = "https://login.example.com/token";
    import_profile(
        &state,
        ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
        token_url,
    )
    .await;
    create_secret(&state, "value", token_url).await;
    let mut state = state;
    Arc::get_mut(&mut state)
        .expect("test state is not shared")
        .config
        .workspace_secrets
        .enabled = false;
    let err = configure(
        &state,
        configure_request(ProviderCredentialRefreshStrategy::Oauth2ClientCredentials),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(err.message().contains("enable_workspace_secrets"));
}

#[tokio::test]
async fn a_refresh_whose_secret_disappeared_fails_closed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let token_url = format!("{}/token", server.uri());
    let state = enabled_state().await;
    import_profile(
        &state,
        ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
        &token_url,
    )
    .await;
    create_secret(&state, "value", &token_url).await;
    configure(
        &state,
        configure_request(ProviderCredentialRefreshStrategy::Oauth2ClientCredentials),
    )
    .await
    .unwrap();

    // Simulate a secret removed behind the delete guard.
    let secret = super::secret::get_live_secret(&state.store, "default", "acme")
        .await
        .unwrap()
        .unwrap();
    state
        .store
        .delete(
            <crate::storage_proto::StoredWorkspaceSecret as crate::persistence::ObjectType>::object_type(),
            secret.object_id(),
        )
        .await
        .unwrap();
    assert_eq!(secret.object_workspace(), "default");

    let err = rotate(&state).await.unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    let stored = refresh_state(&state).await;
    assert_eq!(stored.failure_code, "referenced_secret_missing");
}

#[tokio::test]
async fn configure_time_keys_cannot_come_from_a_secret_even_when_marked_secret() {
    let state = enabled_state().await;
    let token_url = "https://login.example.com/token";
    import_profile_with_material(
        &state,
        ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
        token_url,
        vec![material("refresh_before_seconds", true)],
    )
    .await;
    create_secret(&state, "600", token_url).await;
    let mut request = configure_request(ProviderCredentialRefreshStrategy::Oauth2ClientCredentials);
    request
        .material
        .insert("client_secret".to_string(), "inline".to_string());
    request.material_secrets =
        HashMap::from([("refresh_before_seconds".to_string(), "acme".to_string())]);
    request.secret_material_keys = vec!["refresh_before_seconds".to_string()];
    let err = configure(&state, request).await.unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(
        err.message().contains("configures the refresh"),
        "{}",
        err.message()
    );
}

#[tokio::test]
async fn inlining_never_overlaps_a_rotating_mint() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("refresh_token=original-refresh"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "access_token": "token-1",
                    "refresh_token": "rotated-refresh",
                    "expires_in": 3600
                }))
                .set_delay(std::time::Duration::from_millis(500)),
        )
        .expect(1)
        .mount(&server)
        .await;
    let token_url = format!("{}/token", server.uri());
    let state = enabled_state().await;
    import_profile(
        &state,
        ProviderCredentialRefreshStrategy::Oauth2RefreshToken,
        &token_url,
    )
    .await;
    create_secret(&state, "client-secret", &token_url).await;
    let mut request = configure_request(ProviderCredentialRefreshStrategy::Oauth2RefreshToken);
    request
        .material
        .insert("refresh_token".to_string(), "original-refresh".to_string());
    configure(&state, request).await.expect("configure");

    let minter = Arc::clone(&state);
    let mint = tokio::spawn(async move { rotate(&minter).await });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while refresh_state(&state).await.status != "refresh_in_progress" {
        assert!(std::time::Instant::now() < deadline, "mint never started");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    let err = inline(&state).await.unwrap_err();
    assert_eq!(err.code(), Code::Aborted);

    mint.await
        .unwrap()
        .expect("the mint keeps its rotated refresh token");
    assert_eq!(
        stored_refresh_token(&state).await.as_deref(),
        Some("rotated-refresh")
    );

    // Once the mint finishes, inlining keeps the rotated token.
    inline(&state).await.expect("inline after the mint");
    let stored = refresh_state(&state).await;
    assert!(
        secret_refs::material_secret_bindings(stored.metadata.as_ref())
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        stored_refresh_token(&state).await.as_deref(),
        Some("rotated-refresh")
    );
}

async fn inline(
    state: &Arc<ServerState>,
) -> Result<
    tonic::Response<openshell_core::proto::InlineProviderRefreshSecretsResponse>,
    tonic::Status,
> {
    handle_inline_provider_refresh_secrets(
        state,
        authed_request(InlineProviderRefreshSecretsRequest {
            workspace_scope: Some(default_workspace()),
            provider: PROVIDER.to_string(),
            credential_key: KEY.to_string(),
            request_id: String::new(),
        }),
    )
    .await
}

async fn stored_refresh_token(state: &Arc<ServerState>) -> Option<String> {
    let stored = refresh_state(state).await;
    state
        .credentials
        .resolve_refresh_material(
            openshell_credential_issuer::refresh::refresh_material_scope(&stored),
            &stored.secret_material_handles,
        )
        .await
        .unwrap()
        .remove("refresh_token")
}

#[tokio::test]
async fn a_reveal_only_secret_cannot_supply_refresh_material() {
    let state = enabled_state().await;
    let token_url = "https://login.example.com/token";
    import_profile(
        &state,
        ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
        token_url,
    )
    .await;
    handle_create_secret(
        &state,
        authed_request(CreateSecretRequest {
            workspace_scope: Some(default_workspace()),
            name: "acme".to_string(),
            value: "value".to_string(),
            ..Default::default()
        }),
    )
    .await
    .expect("create a reveal-only secret");
    let err = configure(
        &state,
        configure_request(ProviderCredentialRefreshStrategy::Oauth2ClientCredentials),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(
        err.message().contains("not enabled for provider refresh"),
        "{}",
        err.message()
    );
}

#[tokio::test]
async fn basic_client_auth_accepts_a_client_secret_from_a_workspace_secret() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(wiremock::matchers::header(
            "authorization",
            "Basic Y2xpZW50LWlkOmJhc2ljLXNlY3JldA==",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "token-basic",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    let token_url = format!("{}/token", server.uri());
    let state = enabled_state().await;
    import_profile(
        &state,
        ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
        &token_url,
    )
    .await;
    create_secret(&state, "basic-secret", &token_url).await;
    let mut request = configure_request(ProviderCredentialRefreshStrategy::Oauth2ClientCredentials);
    request.material.insert(
        "token_endpoint_auth_method".to_string(),
        "client_secret_basic".to_string(),
    );
    configure(&state, request)
        .await
        .expect("a referenced client_secret satisfies Basic client authentication");

    rotate(&state)
        .await
        .expect("mint with Basic client authentication");
    let received = server.received_requests().await.unwrap();
    let body = String::from_utf8_lossy(&received[0].body);
    assert!(
        !body.contains("client_secret"),
        "Basic keeps the secret out of the form: {body}"
    );
}
