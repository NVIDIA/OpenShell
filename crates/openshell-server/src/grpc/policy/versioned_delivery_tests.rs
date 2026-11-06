// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The revision and the payload must use one immutable resolution capture.

use super::*;
use crate::credentials::{ResolvedCredentialVersion, ResolvedProviderCredentials};
use crate::grpc::provider::ProviderEnvironmentRecord;

fn capture(value: &str, version: u64) -> Arc<ResolvedProviderCredentials> {
    Arc::new(ResolvedProviderCredentials {
        values: HashMap::from([("GITHUB_TOKEN".into(), value.into())]),
        versions: HashMap::from([(
            "GITHUB_TOKEN".into(),
            ResolvedCredentialVersion {
                reference: "reference-a".into(),
                version,
                authorization_epoch: "epoch-a".into(),
            },
        )]),
        ..Default::default()
    })
}

fn record(captured: Option<Arc<ResolvedProviderCredentials>>) -> ProviderEnvironmentRecord {
    let mut provider = tests::test_provider("captured", "github");
    provider.credentials.clear();
    ProviderEnvironmentRecord {
        name: "captured".into(),
        object_id: provider.object_id().into(),
        resource_version: 7,
        provider,
        refresh_states: Vec::new(),
        resolved_credentials: captured,
    }
}

#[tokio::test]
async fn version_change_without_provider_write_changes_revision_and_capture_is_exact() {
    let state = crate::grpc::test_support::test_server_state().await;
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(state.store.as_ref(), "default")
        .await
        .unwrap();
    let old = record(Some(capture("old-value", 1)));
    let mut new = old.clone();
    new.resolved_credentials = Some(capture("new-value", 2));
    let revision = |record: &ProviderEnvironmentRecord| {
        compute_provider_env_revision_from_records(&catalog, std::slice::from_ref(record)).unwrap()
    };
    assert_eq!(old.resource_version, new.resource_version);
    assert_ne!(revision(&old), revision(&new));
    for (record, expected) in [(&old, "old-value"), (&new, "new-value")] {
        let environment = crate::grpc::provider::resolve_provider_environment_from_records(
            &catalog,
            std::slice::from_ref(record),
        )
        .await
        .unwrap();
        assert_eq!(environment.environment["GITHUB_TOKEN"], expected);
    }
    let mut different_bytes_same_version = old.clone();
    different_bytes_same_version.resolved_credentials = Some(capture("not-hashed", 1));
    assert_eq!(revision(&old), revision(&different_bytes_same_version));
}

#[test]
fn capture_version_order_is_canonical_and_epoch_and_reference_are_identity() {
    let first = record(Some(capture("secret", 1)));
    let mut second = first.clone();
    let captured = Arc::make_mut(second.resolved_credentials.as_mut().unwrap());
    let another = ResolvedCredentialVersion {
        reference: "reference-b".into(),
        version: 4,
        authorization_epoch: "epoch-a".into(),
    };
    captured
        .versions
        .insert("ANOTHER_KEY".into(), another.clone());
    let mut reordered = second.clone();
    let captured = Arc::make_mut(reordered.resolved_credentials.as_mut().unwrap());
    let original = captured.versions.remove("GITHUB_TOKEN").unwrap();
    captured.versions.clear();
    captured.versions.insert("ANOTHER_KEY".into(), another);
    captured.versions.insert("GITHUB_TOKEN".into(), original);
    let revision = |record: &ProviderEnvironmentRecord| {
        extend_provider_env_revision_with_captured_versions(91, std::slice::from_ref(record))
            .unwrap()
    };
    assert_eq!(revision(&second), revision(&reordered));
    for change_epoch in [false, true] {
        let mut changed = first.clone();
        let version = Arc::make_mut(changed.resolved_credentials.as_mut().unwrap())
            .versions
            .get_mut("GITHUB_TOKEN")
            .unwrap();
        if change_epoch {
            version.authorization_epoch.push_str("-replacement");
        } else {
            version.reference.push_str("-replacement");
        }
        assert_ne!(revision(&first), revision(&changed));
    }
}

#[test]
fn legacy_revision_is_unchanged_and_partial_capture_fails_closed() {
    assert_eq!(
        extend_provider_env_revision_with_captured_versions(91, &[record(None)]).unwrap(),
        91,
    );
    assert!(
        extend_provider_env_revision_with_captured_versions(
            91,
            &[record(None), record(Some(capture("secret", 1)))],
        )
        .is_err()
    );
    let mut missing_version = record(Some(capture("secret", 1)));
    Arc::make_mut(missing_version.resolved_credentials.as_mut().unwrap())
        .versions
        .clear();
    assert!(extend_provider_env_revision_with_captured_versions(91, &[missing_version]).is_err());
}

#[tokio::test]
async fn versioned_endpoint_reports_accept_installed_capture_before_and_after_refresh() {
    use crate::config_delivery::versioned_tests::{
        adopt_provider, install_config, versioned_state,
    };
    use crate::config_delivery::{SupervisorConfig, session};
    use openshell_core::endpoint_status::endpoint_id;
    use openshell_core::proto::{
        EndpointObservation, EndpointResult, ObjectMeta, ProviderCredentialRefreshStrategy,
        ReportEndpointStatusRequest,
    };
    use openshell_credential_issuer::refresh::{RefreshState, refresh_material_scope};
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

    let (_directory, state) = versioned_state().await;
    let (provider, _) = adopt_provider(&state, "provider", "github", "GITHUB_TOKEN").await;
    let mock_server = MockServer::start().await;
    let mut grant = RefreshState {
        metadata: Some(ObjectMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: "grant".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        provider_id: provider.object_id().into(),
        provider_name: "provider".into(),
        credential_key: "GITHUB_TOKEN".into(),
        strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
        strategy_name: Some("oauth2_client_credentials".into()),
        token_url: mock_server.uri(),
        material: HashMap::from([("client_id".into(), "client".into())]),
        secret_material_keys: vec!["client_secret".into()],
        authorization_epoch: uuid::Uuid::new_v4().to_string(),
        status: "configured".into(),
        ..Default::default()
    };
    grant.secret_material_handles = state
        .credentials
        .issuer()
        .store_refresh_material_with_object_id(
            refresh_material_scope(&grant),
            &uuid::Uuid::new_v4().to_string(),
            &HashMap::from([("client_secret".into(), "secret".into())]),
            &HashMap::new(),
        )
        .await
        .unwrap();
    let configured = state
        .credentials
        .versioned()
        .unwrap()
        .configure(&provider, grant, "test-static", None, ())
        .await
        .unwrap();
    let provider_before = state
        .store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    let policy = tests::mcp_policy_with_versions(&["2025-11-25"]);
    let sandbox = tests::test_sandbox("sandbox", "sandbox", policy, vec!["provider".into()]);
    state.store.put_message(&sandbox).await.unwrap();
    let initial = session::build_session_bootstrap(&state, &sandbox)
        .await
        .unwrap();
    assert_eq!(initial.outcome, session::BootstrapOutcome::Built);
    let installed = initial.config.sandbox_config.clone();
    install_config(&state, &sandbox, initial.config).await;
    assert!(
        state
            .supervisor_sessions
            .initialize_endpoint_status_authority("sandbox", "session")
    );
    let endpoint = &installed.policy.as_ref().unwrap().network_policies["mcp"].endpoints[0];
    let id = endpoint_id(endpoint);
    let report = |snapshot: &SandboxConfigSnapshot, sequence| ReportEndpointStatusRequest {
        sandbox_id: "sandbox".into(),
        supervisor_session_id: "session".into(),
        policy_hash: snapshot.policy_hash.clone(),
        provider_env_revision: snapshot.provider_env_revision,
        report_sequence: sequence,
        observations: vec![EndpointObservation {
            endpoint_id: id.clone(),
            result: EndpointResult::HttpResponseReceived as i32,
            failure: None,
        }],
        observed_endpoint_ids: vec![id.clone()],
        token_grant_status: None,
    };
    let send = |request| {
        handle_report_endpoint_status(
            &state,
            tests::with_sandbox(Request::new(request), "sandbox"),
        )
    };
    send(report(&installed, 1)).await.unwrap();
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"access_token":"refreshed", "expires_in":3600})),
        )
        .expect(1)
        .mount(&mock_server)
        .await;
    state.refresh.ensure_fresh(configured).await.unwrap();
    assert_eq!(
        state
            .store
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .unwrap(),
        provider_before,
        "refresh must not write the provider row"
    );

    // The installed generation is still authoritative before the refresh's
    // update is delivered; endpoint reports must not trigger another read.
    let (mut hit, release) = state.credentials.gate_next_resolve();
    send(report(&installed, 2)).await.unwrap();
    assert_eq!(
        hit.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    );
    drop(release);
    let fresh_inputs = load_sandbox_config_inputs(&state, sandbox.clone())
        .await
        .unwrap();
    let fresh = build_sandbox_config_snapshot_from_inputs(&state, &fresh_inputs)
        .await
        .unwrap();
    let environment =
        build_provider_environment_snapshot_from_inputs(&state, &fresh_inputs, true, true)
            .await
            .unwrap();
    assert_ne!(installed.provider_env_revision, fresh.provider_env_revision);
    assert_eq!(
        fresh.provider_env_revision,
        environment.provider_env_revision
    );
    assert!(
        environment
            .values
            .iter()
            .any(|value| value.name == "GITHUB_TOKEN" && value.value == "refreshed")
    );
    install_config(
        &state,
        &sandbox,
        SupervisorConfig {
            sandbox_config: fresh.clone(),
            provider_environment: environment,
        },
    )
    .await;
    let rejected_revision = send(report(&installed, 3)).await.unwrap_err();
    assert_eq!(rejected_revision.code(), Code::FailedPrecondition);
    send(report(&fresh, 3)).await.unwrap();
    // Polling sessions lack an install receipt and must compute the same
    // version-aware revision, not the old metadata-only revision.
    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    state.supervisor_sessions.register(
        "sandbox".into(),
        "session".into(),
        tx,
        tokio::sync::oneshot::channel().0,
    );
    assert!(
        state
            .supervisor_sessions
            .initialize_endpoint_status_authority("sandbox", "session")
    );
    let mut legacy_records = fresh_inputs.provider_records.clone();
    for record in &mut legacy_records {
        record.resolved_credentials = None;
    }
    let bindings = policy_static_credential_endpoint_bindings(fresh.policy.as_ref()).unwrap();
    let legacy_revision = compute_provider_env_revision_from_records_and_policy_bindings(
        &fresh_inputs.catalog,
        &legacy_records,
        &bindings,
        None,
    )
    .unwrap();
    let mut legacy_report = report(&fresh, 1);
    legacy_report.provider_env_revision = legacy_revision;
    assert_eq!(
        send(legacy_report).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    send(report(&fresh, 1)).await.unwrap();

    let stored = state
        .store
        .get_message::<Sandbox>("sandbox")
        .await
        .unwrap()
        .unwrap();
    let observed = stored.status.unwrap().endpoint_statuses;
    assert!(observed.iter().any(|status| status.endpoint_id == id
        && status.last_result == EndpointResult::HttpResponseReceived as i32
        && status.last_reported_time.is_some()));
}

#[tokio::test]
async fn versioned_unavailable_or_internal_capture_discards_values_and_never_builds_an_environment()
{
    use crate::config_delivery::versioned_tests::{adopt_provider, versioned_state};
    let (_directory, state) = versioned_state().await;
    adopt_provider(&state, "provider", "github", "GITHUB_TOKEN").await;
    let sandbox = tests::test_sandbox(
        "sandbox",
        "sandbox",
        tests::mcp_policy_with_versions(&["2025-11-25"]),
        vec!["provider".into()],
    );
    state.store.put_message(&sandbox).await.unwrap();
    for error in [
        Status::unavailable("backend unavailable"),
        Status::internal("backend failed"),
    ] {
        let mut inputs = load_sandbox_config_inputs(&state, sandbox.clone())
            .await
            .unwrap();
        let complete = build_sandbox_config_snapshot_from_inputs(&state, &inputs)
            .await
            .unwrap();
        assert!(
            inputs
                .provider_records
                .iter()
                .all(|record| record.resolved_credentials.is_some())
        );
        inputs.mark_credentials_unresolved(error.clone());
        assert!(
            inputs
                .provider_records
                .iter()
                .all(|record| record.resolved_credentials.is_none())
        );
        let unresolved = build_sandbox_config_snapshot_from_inputs(&state, &inputs)
            .await
            .unwrap();
        assert_eq!(unresolved.policy, complete.policy);
        assert_eq!(unresolved.policy_hash, complete.policy_hash);
        assert!(unresolved.configuration_admitted);
        assert_ne!(
            unresolved.provider_env_revision,
            complete.provider_env_revision
        );
        let legacy = compute_provider_env_revision_from_records_and_policy_bindings(
            &inputs.catalog,
            &inputs.provider_records,
            &policy_static_credential_endpoint_bindings(unresolved.policy.as_ref()).unwrap(),
            None,
        )
        .unwrap();
        assert_ne!(
            unresolved.provider_env_revision, legacy,
            "failed capture is not legacy completeness"
        );
        let built = build_provider_environment_snapshot_from_inputs(&state, &inputs, true, true)
            .await
            .unwrap_err();
        assert_eq!(built.code(), error.code());
    }
}
