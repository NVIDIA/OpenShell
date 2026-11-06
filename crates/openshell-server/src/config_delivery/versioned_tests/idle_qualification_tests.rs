// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Real idle reconciliation after deliberately dropping a rotation hint.
//!
//! By default only the supervisor result is modeled (credential installation
//! uses the real core). With `OPENSHELL_DELIVERY_QUALIFICATION_DIR`, the companion
//! ignored supervisor test applies these exact protobuf updates in `ConfigRuntime`
//! and returns its actual results. The file rendezvous is test-only, not gRPC.

use super::*;
use crate::supervisor_session::{AcceptedSession, SessionMode};
use openshell_core::proto::{ConfigUpdate, ConfigUpdateResult, SessionAccepted};
use openshell_credential_issuer::refresh::{
    CredentialRefresh as _, RefreshState, refresh_material_scope,
};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

async fn configure(state: &Arc<ServerState>, provider: &Provider, token_url: &str) -> RefreshState {
    let mut grant = RefreshState {
        metadata: Some(ObjectMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: "qualification-grant".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        provider_id: provider.object_id().into(),
        provider_name: "provider".into(),
        credential_key: "GITHUB_TOKEN".into(),
        strategy: openshell_core::proto::ProviderCredentialRefreshStrategy::Oauth2ClientCredentials
            as i32,
        strategy_name: Some("oauth2_client_credentials".into()),
        token_url: token_url.into(),
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
            &HashMap::from([("client_secret".into(), "synthetic-client-secret".into())]),
            &Handles::new(),
        )
        .await
        .unwrap();
    state
        .credentials
        .versioned()
        .unwrap()
        .configure(provider, grant, "test-static", None, ())
        .await
        .unwrap()
}

async fn current_provider(state: &ServerState) -> Provider {
    state.store.get_message("provider").await.unwrap().unwrap()
}

async fn receive_update(
    outbound: &mut tokio::sync::mpsc::Receiver<openshell_core::proto::GatewayMessage>,
) -> ConfigUpdate {
    let message = tokio::time::timeout(Duration::from_secs(5), outbound.recv())
        .await
        .expect("real Builder queues a live update")
        .expect("session remains open");
    let Some(openshell_core::proto::gateway_message::Payload::ConfigUpdate(update)) =
        message.payload
    else {
        panic!("expected live configuration update")
    };
    update
}

/// Only the optional companion run supplies real `ConfigRuntime` results. The
/// normal unit run must not be described as executing the supervisor consumer.
async fn apply_result(step: usize, update: &ConfigUpdate) -> ConfigUpdateResult {
    let Some(directory) = std::env::var_os("OPENSHELL_DELIVERY_QUALIFICATION_DIR") else {
        return session::applied_result(update);
    };
    let directory = std::path::PathBuf::from(directory);
    let update_path = directory.join(format!("update-{step}.pb"));
    let temporary = directory.join(format!("update-{step}.tmp"));
    assert!(!update_path.exists(), "use a fresh rendezvous directory");
    std::fs::write(&temporary, update.encode_to_vec()).unwrap();
    std::fs::rename(temporary, update_path).unwrap();
    let result_path = directory.join(format!("result-{step}.pb"));
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            match std::fs::read(&result_path) {
                Ok(bytes) => return ConfigUpdateResult::decode(bytes.as_slice()).unwrap(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => panic!("read companion result: {error}"),
            }
        }
    })
    .await
    .expect("companion ConfigRuntime must return its result")
}

async fn acknowledge(accepted: &AcceptedSession, step: usize, update: &ConfigUpdate) {
    let result = apply_result(step, update).await;
    assert_eq!(result.update_id, update.update_id);
    assert_eq!(
        result.outcome,
        i32::from(openshell_core::proto::ConfigApplyOutcome::Applied)
    );
    assert!(session::handle_config_update_result(accepted, &result).await);
    let snapshot = update.sandbox_config.as_ref().unwrap();
    assert_eq!(
        accepted
            .state
            .supervisor_sessions
            .installed_endpoint_configuration("sandbox", "session"),
        Some((snapshot.policy_hash.clone(), snapshot.provider_env_revision)),
        "only an actual accepted result advances installed endpoint identity"
    );
    let persisted = accepted
        .state
        .store
        .get_message::<Sandbox>("sandbox")
        .await
        .unwrap()
        .unwrap();
    let admission = persisted
        .status
        .as_ref()
        .unwrap()
        .configuration_admission
        .as_ref()
        .unwrap();
    assert_eq!(
        admission.provider_env_revision,
        snapshot.provider_env_revision
    );
    assert_eq!(
        admission.state,
        i32::from(openshell_core::proto::ConfigurationAdmissionState::Accepted)
    );
}

fn assert_resolves(
    credentials: &openshell_core::provider_credentials::ProviderCredentialState,
    placeholder: &str,
    expected: Option<&str>,
) {
    assert_eq!(
        credentials
            .resolver_for_endpoint("github.com", 443, "/")
            .and_then(|resolver| resolver.resolve_placeholder(placeholder).map(str::to_owned)),
        expected.map(str::to_owned)
    );
    assert!(
        credentials
            .resolver_for_endpoint("unrelated.example", 443, "/")
            .and_then(|resolver| resolver.resolve_placeholder(placeholder).map(str::to_owned))
            .is_none(),
        "stable identity must not bypass endpoint authorization"
    );
}

#[tokio::test]
async fn versioned_idle_reconciliation_recovers_lost_hint_and_preserves_then_revokes_placeholder() {
    let (_directory, state) = versioned_state().await;
    let (provider, _) = adopt_provider(&state, "provider", "github", "GITHUB_TOKEN").await;
    let endpoint = MockServer::start().await;
    let configured = configure(&state, &provider, &endpoint.uri()).await;
    let provider_before = current_provider(&state).await;
    let initial_values = state
        .credentials
        .versioned()
        .unwrap()
        .references
        .resolve(
            SecretOwner::provider("default", "provider", "provider"),
            &provider_before.credential_handles,
        )
        .await
        .unwrap();
    assert_eq!(initial_values[0].version, 1);
    assert_eq!(
        initial_values[0].reference.epoch,
        configured.authorization_epoch
    );
    let mut sandbox = sandbox(&state, &["provider"]).await;
    let mut policy = openshell_policy::restrictive_default_policy();
    policy.network_policies.insert(
        "user-api".into(),
        openshell_core::proto::NetworkPolicyRule {
            name: "user-api".into(),
            endpoints: vec![openshell_core::proto::NetworkEndpoint {
                host: "allowed.example.com".into(),
                port: 443,
                protocol: "mcp".into(),
                rules: vec![openshell_core::proto::L7Rule {
                    allow: Some(openshell_core::proto::L7Allow {
                        method: "tools/list".into(),
                        ..Default::default()
                    }),
                }],
                mcp: Some(openshell_core::proto::McpOptions {
                    versions: vec!["2025-11-25".into()],
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    openshell_policy::ensure_sandbox_process_identity(&mut policy);
    sandbox.spec.as_mut().unwrap().policy = Some(policy);
    state.store.put_message(&sandbox).await.unwrap();
    let captured_seq = state.config_delivery.publications();
    let initial = session::build_session_bootstrap(&state, &sandbox)
        .await
        .unwrap();
    assert_eq!(initial.outcome, session::BootstrapOutcome::Built);
    let initial_environment = initial.config.provider_environment.clone();
    let initial_snapshot = initial.config.sandbox_config.clone();
    let credentials = prepare_recovery_credentials(initial_environment.clone());
    let placeholder = credentials.snapshot().child_env["GITHUB_TOKEN"].clone();
    assert_resolves(&credentials, &placeholder, Some("provider-secret"));

    let (tx, mut outbound) = tokio::sync::mpsc::channel(8);
    state.supervisor_sessions.register_with_mode(
        "sandbox".into(),
        "session".into(),
        tx.clone(),
        tokio::sync::oneshot::channel().0,
        SessionMode::Push,
    );
    let accepted = AcceptedSession {
        state: state.clone(),
        sandbox_id: "sandbox".into(),
        session_id: "session".into(),
        instance_id: "instance".into(),
        tx,
        supports_session_redirect: false,
        pushes_config: true,
        advertises_services: false,
    };
    let (bootstrap, in_flight) =
        session::bootstrap_update(initial.config, &SessionAccepted::default());
    state
        .supervisor_sessions
        .begin_config_bootstrap("sandbox", "session", in_flight, None);
    acknowledge(&accepted, 0, &bootstrap).await;
    assert!(
        state
            .supervisor_sessions
            .initialize_endpoint_status_authority("sandbox", "session")
    );
    report_recovery_endpoint(&state, &initial_snapshot, 1)
        .await
        .unwrap();

    // Use public registration: this launches task::run with its production
    // interval/jitter and the real Builder, not copied scheduling logic.
    register_session(
        &state,
        Registration {
            sandbox_id: "sandbox".into(),
            session_id: "session".into(),
            workspace: "default".into(),
            providers: HashSet::from(["provider".into()]),
            provider_environment: Some(initial_environment),
            captured_seq,
            rebuild: false,
        },
    );
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert!(outbound.try_recv().is_err(), "registration must stay idle");
    let publications = state.config_delivery.publications();
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"access_token":"qualification-rotated-v2", "expires_in":3600}),
        ))
        .expect(1)
        .mount(&endpoint)
        .await;
    let refreshed = state
        .refresh
        .ensure_fresh(configured.clone())
        .await
        .unwrap();
    assert_eq!(
        refreshed.authorization_epoch,
        configured.authorization_epoch
    );
    assert_eq!(refreshed.reference_generation, 2);
    assert_eq!(current_provider(&state).await, provider_before);
    assert_eq!(
        state.config_delivery.publications(),
        publications,
        "ensure_fresh deliberately does not publish an invalidation"
    );
    let resolved = state
        .credentials
        .versioned()
        .unwrap()
        .references
        .resolve(
            SecretOwner::provider("default", "provider", "provider"),
            &provider_before.credential_handles,
        )
        .await
        .unwrap();
    assert_eq!(resolved[0].version, 2);
    assert_eq!(resolved[0].reference, initial_values[0].reference);
    assert_eq!(resolved[0].reference.epoch, configured.authorization_epoch);
    assert_eq!(resolved[0].value, "qualification-rotated-v2");
    assert!(outbound.try_recv().is_err());
    assert_resolves(&credentials, &placeholder, Some("provider-secret"));

    // Freeze only to expire the idle timer. Resume before asynchronous SQLite
    // reads so fake-time auto-advance cannot consume metadata/backend budgets.
    let (hit, release) = state.credentials.gate_next_resolve();
    tokio::time::pause();
    tokio::time::advance(task::RECONCILE_INTERVAL * 2 + Duration::from_millis(1)).await;
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(5), hit)
        .await
        .unwrap()
        .unwrap();
    release.send(()).unwrap();
    let rotated = receive_update(&mut outbound).await;
    let rotated_snapshot = rotated.sandbox_config.as_ref().unwrap();
    assert_ne!(
        rotated_snapshot.provider_env_revision,
        initial_snapshot.provider_env_revision
    );
    assert_eq!(rotated_snapshot.policy_hash, initial_snapshot.policy_hash);
    assert_eq!(
        rotated_snapshot.config_revision,
        initial_snapshot.config_revision
    );
    assert_eq!(
        rotated_snapshot.provider_attachment_epoch,
        initial_snapshot.provider_attachment_epoch
    );
    assert_eq!(
        state.config_delivery.publications(),
        publications,
        "timer is the only trigger"
    );
    assert_eq!(
        state
            .supervisor_sessions
            .installed_endpoint_configuration("sandbox", "session"),
        Some((
            initial_snapshot.policy_hash.clone(),
            initial_snapshot.provider_env_revision
        ))
    );
    report_recovery_endpoint(&state, &initial_snapshot, 2)
        .await
        .unwrap();
    assert_eq!(
        report_recovery_endpoint(&state, rotated_snapshot, 3)
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition,
        "queued generation is not installed evidence"
    );
    credentials.install_prepared(&prepare_recovery_credentials(
        rotated.provider_environment.clone().unwrap(),
    ));
    assert_eq!(
        credentials.snapshot().child_env["GITHUB_TOKEN"],
        placeholder
    );
    assert_resolves(&credentials, &placeholder, Some("qualification-rotated-v2"));
    acknowledge(&accepted, 1, &rotated).await;
    report_recovery_endpoint(&state, rotated_snapshot, 3)
        .await
        .unwrap();
    assert_eq!(
        report_recovery_endpoint(&state, &initial_snapshot, 4)
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition,
        "old generation loses endpoint report authority after application"
    );
    assert_eq!(current_provider(&state).await, provider_before);

    // Explicit reconfiguration is not a value rotation: it replaces the grant
    // authorization epoch and revokes both the old reference and placeholder.
    let reconfigured = configure(&state, &provider_before, &endpoint.uri()).await;
    assert_ne!(
        reconfigured.authorization_epoch,
        configured.authorization_epoch
    );
    assert!(
        state
            .credentials
            .versioned()
            .unwrap()
            .references
            .resolve(
                SecretOwner::provider("default", "provider", "provider"),
                &configured.output_references,
            )
            .await
            .is_err()
    );
    publish_provider(&state, "default", "provider");
    let replacement = receive_update(&mut outbound).await;
    credentials.install_prepared(&prepare_recovery_credentials(
        replacement.provider_environment.clone().unwrap(),
    ));
    let replacement_placeholder = credentials.snapshot().child_env["GITHUB_TOKEN"].clone();
    assert_ne!(replacement_placeholder, placeholder);
    assert_resolves(&credentials, &placeholder, None);
    assert_resolves(
        &credentials,
        &replacement_placeholder,
        Some("qualification-rotated-v2"),
    );
    acknowledge(&accepted, 2, &replacement).await;

    // Detach, then revoke the issuer grant. Delivery must install an empty
    // environment, not retain a usable placeholder from the old attachment.
    let mut detached: Sandbox = state.store.get_message("sandbox").await.unwrap().unwrap();
    detached.spec.as_mut().unwrap().providers.clear();
    detached.spec.as_mut().unwrap().provider_attachment_epoch = uuid::Uuid::new_v4().to_string();
    state.store.put_message(&detached).await.unwrap();
    state.refresh.delete(reconfigured.clone()).await.unwrap();
    assert!(
        state
            .credentials
            .versioned()
            .unwrap()
            .references
            .resolve(
                SecretOwner::provider("default", "provider", "provider"),
                &reconfigured.output_references,
            )
            .await
            .is_err()
    );
    publish_sandbox(&state, "sandbox");
    let revoked = receive_update(&mut outbound).await;
    assert!(
        revoked
            .provider_environment
            .as_ref()
            .unwrap()
            .values
            .is_empty()
    );
    credentials.install_prepared(&prepare_recovery_credentials(
        revoked.provider_environment.clone().unwrap(),
    ));
    assert!(credentials.snapshot().child_env.is_empty());
    assert_resolves(&credentials, &placeholder, None);
    assert_resolves(&credentials, &replacement_placeholder, None);
    acknowledge(&accepted, 3, &revoked).await;
    report_recovery_endpoint(&state, revoked.sandbox_config.as_ref().unwrap(), 4)
        .await
        .unwrap();

    assert_eq!(
        state.supervisor_sessions.deliver_config(
            "sandbox",
            "session",
            SupervisorConfig {
                sandbox_config: revoked.sandbox_config.unwrap(),
                provider_environment: revoked.provider_environment.unwrap(),
            }
        ),
        DeliveryDisposition::SuppressedUnchanged
    );
    assert!(outbound.try_recv().is_err());
    unregister_session(&state, "sandbox", "session");
    state.supervisor_sessions.disconnect("sandbox");
}
