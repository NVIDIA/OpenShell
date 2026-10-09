// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::auth::identity::{Identity, IdentityProvider};
use crate::auth::principal::{OperatorPrincipal, Principal};
use openshell_core::proto::{
    ObjectMeta, ProviderProfile, ProviderProfileCredential, workspace_selector,
};
use tonic::Code;

fn operator() -> Principal {
    Principal::Operator(OperatorPrincipal {
        identity: Identity {
            subject: "operator-test".into(),
            display_name: None,
            roles: vec!["operator".into()],
            scopes: vec![],
            provider: IdentityProvider::Mtls,
        },
        certificate_sha256: "verified-test-certificate".into(),
    })
}

fn request(keys: &[&str]) -> GetProviderCredentialsRequest {
    GetProviderCredentialsRequest {
        workspace_scope: Some(workspace_selector("other")),
        name: "provider".into(),
        credential_keys: keys.iter().map(|key| (*key).into()).collect(),
        minimum_remaining_lifetime: None,
    }
}

fn authenticated(inner: GetProviderCredentialsRequest) -> Request<GetProviderCredentialsRequest> {
    let mut request = Request::new(inner);
    request.extensions_mut().insert(operator());
    request
}

async fn fixture() -> (Arc<ServerState>, Provider) {
    let state = crate::grpc::test_support::test_server_state().await;
    state
        .store
        .put_message(&crate::provider_profile_sources::stored_provider_profile(
            ProviderProfile {
                id: "operator-test".into(),
                credentials: vec![
                    ProviderProfileCredential {
                        name: "access_token".into(),
                        env_vars: vec!["ACCESS_TOKEN".into()],
                        ..Default::default()
                    },
                    ProviderProfileCredential {
                        name: "static_key".into(),
                        env_vars: vec!["STATIC_KEY".into()],
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        ))
        .await
        .unwrap();
    let provider = Provider {
        metadata: Some(ObjectMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: "provider".into(),
            workspace: "other".into(),
            ..Default::default()
        }),
        r#type: "operator-test".into(),
        credentials: HashMap::from([
            ("ACCESS_TOKEN".into(), "old-access-token".into()),
            ("STATIC_KEY".into(), "static-secret".into()),
            ("REFRESH_TOKEN".into(), "must-not-export".into()),
        ]),
        ..Default::default()
    };
    state.store.put_message(&provider).await.unwrap();
    (state, provider)
}

#[tokio::test]
async fn audits_exports_and_invalid_attempts_without_values() {
    struct AuditWriter(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for AuditWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (state, _) = fixture().await;
    let output = Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || AuditWriter(writer.clone()))
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    handle(
        &state,
        authenticated(request(&["ACCESS_TOKEN", "STATIC_KEY"])),
    )
    .await
    .unwrap();
    let error = handle(
        &state,
        authenticated(request(&["API_KEY=secret-from-invalid-input"])),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    assert!(output.contains("operator-test"));
    assert!(output.contains("verified-test-certificate"));
    assert!(output.contains("ACCESS_TOKEN"));
    assert!(output.contains("STATIC_KEY"));
    assert!(output.contains("delivered"));
    assert!(output.contains("invalid_request"));
    assert!(output.contains("refresh_attempts=0"));
    for secret in [
        "old-access-token",
        "static-secret",
        "must-not-export",
        "secret-from-invalid-input",
    ] {
        assert!(!output.contains(secret));
    }
}

#[tokio::test]
async fn exports_only_selected_runtime_keys_across_workspaces() {
    let (state, _) = fixture().await;
    let response = handle(&state, authenticated(request(&["STATIC_KEY"])))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.credentials.len(), 1);
    assert_eq!(response.credentials["STATIC_KEY"].value, "static-secret");
    assert!(response.credentials["STATIC_KEY"].expiration_time.is_none());
    let error = handle(
        &state,
        authenticated(request(&["STATIC_KEY", "REFRESH_TOKEN"])),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(!error.message().contains("must-not-export"));
}

#[tokio::test]
async fn rejects_ordinary_admin_and_anonymous() {
    let (state, _) = fixture().await;
    assert_eq!(
        handle(
            &state,
            crate::grpc::test_support::authed_request(request(&["STATIC_KEY"]))
        )
        .await
        .unwrap_err()
        .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        handle(&state, Request::new(request(&["STATIC_KEY"])))
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
}

#[test]
fn validates_selection_and_lifetime() {
    assert!(validate(&request(&[])).is_err());
    assert!(validate(&request(&["STATIC_KEY", "STATIC_KEY"])).is_err());
    assert!(validate(&request(&["../handle"])).is_err());
    let mut req = request(&["STATIC_KEY"]);
    req.minimum_remaining_lifetime = Some(prost_types::Duration {
        seconds: -1,
        nanos: 0,
    });
    assert!(validate(&req).is_err());
    req.minimum_remaining_lifetime = Some(prost_types::Duration {
        seconds: 86401,
        nanos: 0,
    });
    assert!(validate(&req).is_err());
    req.minimum_remaining_lifetime = Some(prost_types::Duration::default());
    assert_eq!(validate(&req).unwrap(), DEFAULT_LIFETIME);
}

#[tokio::test]
async fn lifetime_failure_does_not_return_partial_values() {
    let (state, mut provider) = fixture().await;
    provider.credential_expiration_times.insert(
        "ACCESS_TOKEN".into(),
        openshell_core::time::timestamp_from_millis(crate::persistence::current_time_ms() + 1000)
            .unwrap(),
    );
    state.store.put_message(&provider).await.unwrap();
    assert_eq!(
        handle(
            &state,
            authenticated(request(&["STATIC_KEY", "ACCESS_TOKEN"]))
        )
        .await
        .unwrap_err()
        .code(),
        Code::FailedPrecondition
    );
}

async fn refresh_fixture(
    state: &ServerState,
    provider: &Provider,
    endpoint: String,
) -> StoredProviderCredentialRefreshStateV2 {
    let refresh = crate::provider_refresh::new_refresh_state(
        provider,
        "other",
        "ACCESS_TOKEN",
        crate::provider_refresh::NewRefreshStateConfig {
            strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken,
            material: HashMap::from([
                ("refresh_token".into(), "private-refresh-token".into()),
                ("client_id".into(), "client".into()),
            ]),
            secret_material_keys: vec!["refresh_token".into()],
            expires_at_ms: 1,
            token_url: endpoint,
            scopes: vec![],
            refresh_before: None,
            max_lifetime: None,
            additional_output_keys: HashMap::new(),
        },
    )
    .unwrap();
    crate::provider_refresh::put_refresh_state(state.store.as_ref(), &refresh)
        .await
        .unwrap();
    crate::provider_refresh::get_refresh_state(
        state.store.as_ref(),
        "other",
        provider.object_id(),
        "ACCESS_TOKEN",
    )
    .await
    .unwrap()
    .unwrap()
}

#[tokio::test]
async fn refreshes_access_token_and_reuses_it() {
    let (state, mut provider) = fixture().await;
    provider.credential_expiration_times.insert(
        "ACCESS_TOKEN".into(),
        openshell_core::time::timestamp_from_millis(1).unwrap(),
    );
    state.store.put_message(&provider).await.unwrap();
    let issuer = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST")).and(wiremock::matchers::body_string_contains("refresh_token=private-refresh-token"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({"access_token":"new-access-token","refresh_token":"rotated-private-token","expires_in":3600})))
        .expect(1).mount(&issuer).await;
    refresh_fixture(&state, &provider, issuer.uri()).await;
    let (first, concurrent) = tokio::join!(
        handle(&state, authenticated(request(&["ACCESS_TOKEN"]))),
        handle(&state, authenticated(request(&["ACCESS_TOKEN"])))
    );
    assert_eq!(
        first.unwrap().into_inner().credentials["ACCESS_TOKEN"].value,
        "new-access-token"
    );
    assert_eq!(
        concurrent.unwrap().into_inner().credentials["ACCESS_TOKEN"].value,
        "new-access-token"
    );
    for _ in 0..2 {
        let values = handle(&state, authenticated(request(&["ACCESS_TOKEN"])))
            .await
            .unwrap()
            .into_inner()
            .credentials;
        assert_eq!(values["ACCESS_TOKEN"].value, "new-access-token");
        assert!(values["ACCESS_TOKEN"].expiration_time.is_some());
        assert_eq!(values.len(), 1);
    }
    issuer.verify().await;
}

#[tokio::test]
async fn missing_refresh_owned_handle_is_repaired_without_inline_fallback() {
    let (state, mut provider) = fixture().await;
    // The stored handle is authoritative, even when a usable-looking inline
    // value remains. Its absence must mint, never export that inline value.
    provider.credential_handles.insert(
        "ACCESS_TOKEN".into(),
        openshell_core::proto::CredentialHandle {
            driver: "test-static".into(),
            handle: "missing-access-token".into(),
            ..Default::default()
        },
    );
    state.store.put_message(&provider).await.unwrap();
    let issuer = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::body_string_contains(
            "refresh_token=private-refresh-token",
        ))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"access_token":"repaired-access-token","refresh_token":"replacement-grant","expires_in":3600}),
        ))
        .expect(1)
        .mount(&issuer)
        .await;
    refresh_fixture(&state, &provider, issuer.uri()).await;
    let values = handle(
        &state,
        authenticated(request(&["STATIC_KEY", "ACCESS_TOKEN"])),
    )
    .await
    .unwrap()
    .into_inner()
    .credentials;
    assert_eq!(values.len(), 2);
    assert_eq!(values["STATIC_KEY"].value, "static-secret");
    assert_eq!(values["ACCESS_TOKEN"].value, "repaired-access-token");
    assert!(values["ACCESS_TOKEN"].expiration_time.is_some());
    issuer.verify().await;
}

#[tokio::test]
async fn missing_static_handle_and_invalid_refresh_driver_fail_closed() {
    for (key, driver, expected) in [
        ("STATIC_KEY", "test-static", Code::NotFound),
        ("ACCESS_TOKEN", "unconfigured-driver", Code::InvalidArgument),
    ] {
        let (state, mut provider) = fixture().await;
        provider.credential_handles.insert(
            key.into(),
            openshell_core::proto::CredentialHandle {
                driver: driver.into(),
                handle: "missing-handle".into(),
                ..Default::default()
            },
        );
        state.store.put_message(&provider).await.unwrap();
        let issuer = wiremock::MockServer::start().await;
        refresh_fixture(&state, &provider, issuer.uri()).await;
        let error = handle(
            &state,
            authenticated(request(&["STATIC_KEY", "ACCESS_TOKEN"])),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), expected);
        assert!(!error.message().contains("missing-handle"));
        assert!(issuer.received_requests().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn bookkeeping_changes_do_not_coalesce_refresh_requests() {
    // Cover both legacy states without a mint identity and states that already
    // have one. Cleanup/metadata updates must not count as another mint.
    for previously_minted in [false, true] {
        let (state, provider) = fixture().await;
        let issuer = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"access_token":"new-access-token","expires_in":3600}),
            ))
            .expect(if previously_minted { 2 } else { 1 })
            .mount(&issuer)
            .await;
        let mut snapshot = refresh_fixture(&state, &provider, issuer.uri()).await;
        if previously_minted {
            crate::provider_refresh::refresh_from_snapshot(
                state.store.as_ref(),
                &state.credentials,
                Some(&state.compute),
                snapshot,
            )
            .await
            .unwrap();
        } else {
            snapshot.status = "refreshed".into();
            crate::provider_refresh::put_refresh_state(state.store.as_ref(), &snapshot)
                .await
                .unwrap();
        }
        let snapshot = crate::provider_refresh::get_refresh_state(
            state.store.as_ref(),
            "other",
            provider.object_id(),
            "ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .unwrap();
        let mut bookkeeping = snapshot.clone();
        bookkeeping
            .metadata
            .as_mut()
            .unwrap()
            .labels
            .insert("bookkeeping".into(), "updated".into());
        crate::provider_refresh::put_refresh_state(state.store.as_ref(), &bookkeeping)
            .await
            .unwrap();
        crate::provider_refresh::refresh_from_snapshot(
            state.store.as_ref(),
            &state.credentials,
            Some(&state.compute),
            snapshot,
        )
        .await
        .unwrap();
        issuer.verify().await;
    }
}

#[tokio::test]
async fn cancelled_retrieval_finishes_rotating_refresh_token_persistence() {
    let (state, mut provider) = fixture().await;
    provider.credential_expiration_times.insert(
        "ACCESS_TOKEN".into(),
        openshell_core::time::timestamp_from_millis(1).unwrap(),
    );
    state.store.put_message(&provider).await.unwrap();
    let issuer = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({"access_token":"after-cancel","refresh_token":"rotated-after-cancel","expires_in":3600})).set_delay(Duration::from_millis(200)))
        .expect(1).mount(&issuer).await;
    refresh_fixture(&state, &provider, issuer.uri()).await;
    let caller_state = state.clone();
    let caller = tokio::spawn(async move {
        handle(&caller_state, authenticated(request(&["ACCESS_TOKEN"]))).await
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if !issuer.received_requests().await.unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let refresh = crate::provider_refresh::get_refresh_state(
                state.store.as_ref(),
                "other",
                provider.object_id(),
                "ACCESS_TOKEN",
            )
            .await
            .unwrap()
            .unwrap();
            if refresh.status == "refreshed" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let values = handle(&state, authenticated(request(&["ACCESS_TOKEN"])))
        .await
        .unwrap()
        .into_inner()
        .credentials;
    assert_eq!(values["ACCESS_TOKEN"].value, "after-cancel");
    let refresh = crate::provider_refresh::get_refresh_state(
        state.store.as_ref(),
        "other",
        provider.object_id(),
        "ACCESS_TOKEN",
    )
    .await
    .unwrap()
    .unwrap();
    let material = state
        .credentials
        .resolve_refresh_material(
            crate::provider_refresh::refresh_material_scope(&refresh),
            &refresh.secret_material_handles,
        )
        .await
        .unwrap();
    assert_eq!(material["refresh_token"], "rotated-after-cancel");
    assert!(!refresh.material.contains_key("refresh_token"));
    issuer.verify().await;
}

#[tokio::test]
async fn coalesces_observed_refresh_generation_and_parks_uncertain_mint() {
    let (state, provider) = fixture().await;
    let issuer = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(
                    serde_json::json!({"access_token":"new-access-token","expires_in":3600}),
                )
                .set_delay(Duration::from_millis(100)),
        )
        .expect(1)
        .mount(&issuer)
        .await;
    let snapshot = refresh_fixture(&state, &provider, issuer.uri()).await;
    let (a, b) = tokio::join!(
        crate::provider_refresh::refresh_from_snapshot(
            state.store.as_ref(),
            &state.credentials,
            Some(&state.compute),
            snapshot.clone()
        ),
        crate::provider_refresh::refresh_from_snapshot(
            state.store.as_ref(),
            &state.credentials,
            Some(&state.compute),
            snapshot.clone()
        )
    );
    a.unwrap();
    b.unwrap();
    issuer.verify().await;
    let mut parked = crate::provider_refresh::get_refresh_state(
        state.store.as_ref(),
        "other",
        provider.object_id(),
        "ACCESS_TOKEN",
    )
    .await
    .unwrap()
    .unwrap();
    parked.status = "refresh_in_progress".into();
    crate::provider_refresh::put_refresh_state(state.store.as_ref(), &parked)
        .await
        .unwrap();
    let error = crate::provider_refresh::refresh_provider_credential(
        state.store.as_ref(),
        "other",
        &state.credentials,
        Some(&state.compute),
        "provider",
        "ACCESS_TOKEN",
    )
    .await
    .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    issuer.verify().await;
}

async fn automatic_waiters_honor_failed_refresh(
    response: wiremock::ResponseTemplate,
    expected_code: Code,
    expected_status: &str,
    expected_recovery: ProviderCredentialRefreshRecoveryAction,
) {
    let (state, provider) = fixture().await;
    let issuer = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(response.set_delay(Duration::from_millis(100)))
        .expect(1)
        .mount(&issuer)
        .await;
    let snapshot = refresh_fixture(&state, &provider, issuer.uri()).await;
    let (a, b) = tokio::join!(
        crate::provider_refresh::refresh_from_snapshot(
            state.store.as_ref(),
            &state.credentials,
            Some(&state.compute),
            snapshot.clone(),
        ),
        crate::provider_refresh::refresh_from_snapshot(
            state.store.as_ref(),
            &state.credentials,
            Some(&state.compute),
            snapshot.clone(),
        ),
    );
    assert_eq!(a.unwrap_err().code(), expected_code);
    assert_eq!(b.unwrap_err().code(), expected_code);
    issuer.verify().await;
    let failed = crate::provider_refresh::get_refresh_state(
        state.store.as_ref(),
        "other",
        provider.object_id(),
        "ACCESS_TOKEN",
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(failed.status, expected_status);
    assert_eq!(failed.recovery_action, expected_recovery as i32);
    assert!(!failed.failure_code.is_empty());
    assert!(failed.next_refresh_at_ms > crate::persistence::current_time_ms());
    if expected_recovery == ProviderCredentialRefreshRecoveryAction::Reauthorize {
        assert_eq!(failed.next_refresh_at_ms, i64::MAX);
    }
    // Both a stale snapshot and a fresh automatic request must respect the
    // committed failure, without changing its retry deadline or error receipt.
    for observed in [snapshot, failed.clone()] {
        let error = crate::provider_refresh::refresh_from_snapshot(
            state.store.as_ref(),
            &state.credentials,
            Some(&state.compute),
            observed,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), expected_code);
    }
    assert_eq!(
        crate::provider_refresh::get_refresh_state(
            state.store.as_ref(),
            "other",
            provider.object_id(),
            "ACCESS_TOKEN",
        )
        .await
        .unwrap()
        .unwrap(),
        failed,
    );
    issuer.verify().await;

    // A separately requested manual rotation can retry a parked grant or
    // override retry backoff; it still goes through the same coordination.
    issuer.reset().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"access_token":"manually-refreshed","expires_in":3600}),
        ))
        .expect(1)
        .mount(&issuer)
        .await;
    let rotated = crate::provider_refresh::refresh_provider_credential(
        state.store.as_ref(),
        "other",
        &state.credentials,
        Some(&state.compute),
        "provider",
        "ACCESS_TOKEN",
    )
    .await
    .unwrap();
    assert_eq!(rotated.status, "refreshed");
    assert_eq!(
        rotated.recovery_action,
        ProviderCredentialRefreshRecoveryAction::Unspecified as i32,
    );
    issuer.verify().await;
}

#[tokio::test]
async fn automatic_waiters_do_not_repeat_unusable_refresh_token_exchange() {
    automatic_waiters_honor_failed_refresh(
        wiremock::ResponseTemplate::new(200).set_body_string("not JSON"),
        Code::FailedPrecondition,
        "reauthorization_required",
        ProviderCredentialRefreshRecoveryAction::Reauthorize,
    )
    .await;
}

#[tokio::test]
async fn automatic_waiters_do_not_bypass_rate_limit_backoff() {
    automatic_waiters_honor_failed_refresh(
        wiremock::ResponseTemplate::new(429)
            .set_body_json(serde_json::json!({"error":"temporarily_unavailable"})),
        Code::Unavailable,
        "error",
        ProviderCredentialRefreshRecoveryAction::Retry,
    )
    .await;
}

#[tokio::test]
async fn rejects_supervisor_dynamic_grants_even_with_stored_values() {
    let (state, _) = fixture().await;
    let mut profile = ProviderProfile {
        id: "operator-test".into(),
        credentials: vec![ProviderProfileCredential {
            name: "dynamic".into(),
            env_vars: vec!["ACCESS_TOKEN".into()],
            token_grant: Some(openshell_core::proto::ProviderCredentialTokenGrant::default()),
            ..Default::default()
        }],
        ..Default::default()
    };
    // The fixture tests classification, without accepting or executing a grant.
    profile.source = "user".into();
    state
        .store
        .put_message(&crate::provider_profile_sources::stored_provider_profile(
            profile,
        ))
        .await
        .unwrap();
    assert_eq!(
        handle(&state, authenticated(request(&["ACCESS_TOKEN"])))
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
}

#[tokio::test]
async fn real_tls_operator_boundary_and_admin_capabilities() {
    use crate::multiplex::{
        MultiplexService, extract_peer_certificate_sha256, extract_peer_identity,
    };
    use openshell_core::proto::{
        GetCurrentUserRequest, ListWorkspacesRequest, open_shell_client::OpenShellClient,
    };
    use tonic::transport::{ClientTlsConfig, Endpoint};

    let (mut state, _) = fixture().await;
    let config = &mut Arc::get_mut(&mut state).unwrap().config;
    config.mtls_auth.operator_enabled = true;
    config.mtls_auth.enabled = false;
    let dir = tempfile::tempdir().unwrap();
    let (ca, ca_key) = crate::tls_test_utils::generate_test_certs_with_ca(dir.path());
    let acceptor = crate::TlsAcceptor::from_files(
        &dir.path().join("server-cert.pem"),
        &dir.path().join("server-key.pem"),
        Some(&dir.path().join("ca.pem")),
        false,
        None,
        None,
        vec![],
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let service = MultiplexService::new(state);
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            openshell_core::net::set_tcp_nodelay_best_effort(&stream);
            let acceptor = acceptor.acceptor();
            let service = service.clone();
            tokio::spawn(async move {
                if let Ok(stream) = acceptor.accept(stream).await {
                    let identity = extract_peer_identity(&stream);
                    let fingerprint = extract_peer_certificate_sha256(&stream);
                    let _ = service
                        .serve_with_verified_certificate(stream, identity, fingerprint)
                        .await;
                }
            });
        }
    });
    for role in [
        Some("operator"),
        Some("Operator"),
        Some("openshell-admin"),
        None,
    ] {
        let mut tls = ClientTlsConfig::new()
            .ca_certificate(tonic::transport::Certificate::from_pem(ca.pem()))
            .domain_name("localhost");
        if let Some(role) = role {
            let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "tls-test");
            params
                .distinguished_name
                .push(rcgen::DnType::OrganizationalUnitName, role);
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
            tls = tls.identity(tonic::transport::Identity::from_pem(
                cert.pem(),
                key.serialize_pem(),
            ));
        }
        let channel = Endpoint::from_shared(format!("https://localhost:{}", address.port()))
            .unwrap()
            .tls_config(tls)
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = OpenShellClient::new(channel);
        let response = client
            .get_provider_credentials(request(&["STATIC_KEY"]))
            .await;
        if role == Some("operator") {
            assert_eq!(
                response.unwrap().into_inner().credentials["STATIC_KEY"].value,
                "static-secret"
            );
            assert_eq!(
                client
                    .get_current_user(GetCurrentUserRequest {})
                    .await
                    .unwrap()
                    .into_inner()
                    .identity_provider,
                "mtls"
            );
            client
                .list_workspaces(ListWorkspacesRequest::default())
                .await
                .unwrap();
            let create = openshell_core::proto::CreateWorkspaceRequest {
                name: "operator-created".into(),
                request_id: uuid::Uuid::new_v4().to_string(),
                labels: HashMap::new(),
            };
            let first = client
                .create_workspace(create.clone())
                .await
                .unwrap()
                .into_inner();
            let replay = client.create_workspace(create).await.unwrap().into_inner();
            assert_eq!(first, replay);
            let mut mixed = Request::new(request(&["STATIC_KEY"]));
            mixed
                .metadata_mut()
                .insert("authorization", "Bearer forbidden".parse().unwrap());
            assert_eq!(
                client
                    .get_provider_credentials(mixed)
                    .await
                    .unwrap_err()
                    .code(),
                Code::Unauthenticated
            );
        } else {
            assert_eq!(response.unwrap_err().code(), Code::PermissionDenied);
            let mut spoof = Request::new(request(&["STATIC_KEY"]));
            spoof
                .metadata_mut()
                .insert("x-forwarded-client-cert", "OU=operator".parse().unwrap());
            assert_eq!(
                client
                    .get_provider_credentials(spoof)
                    .await
                    .unwrap_err()
                    .code(),
                Code::PermissionDenied
            );
        }
    }
    server.abort();
}
