// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Activated delivery must fail closed on credentials without withholding policy.

use super::*;
use crate::credentials::CredentialRuntime;
use crate::grpc::test_support::test_server_state;
use crate::persistence::ObjectId;
use crate::policy_store::PolicyStoreExt as _;
use openshell_core::proto::{ObjectMeta, Provider, SandboxPolicy, SandboxSpec};
use openshell_credential_issuer::{Handles, SecretOwner, StoreSecrets};
use prost::Message as _;

mod idle_qualification_tests;

pub async fn versioned_state() -> (tempfile::TempDir, Arc<ServerState>) {
    let directory = tempfile::tempdir().unwrap();
    let signing_key = directory.path().join("intent-key");
    std::fs::write(
        &signing_key,
        b"test-only stable credential write intent key",
    )
    .unwrap();
    let mut state = test_server_state().await;
    let mut config = state.config.clone();
    config.enable_versioned_credentials = true;
    config.config_delivery_mode = ConfigDeliveryMode::Push;
    config.gateway_jwt = Some(openshell_core::config::GatewayJwtConfig {
        signing_key_path: signing_key,
        public_key_path: directory.path().join("public"),
        kid_path: directory.path().join("kid"),
        gateway_id: "test".into(),
        ttl_secs: None,
    });
    let credentials =
        CredentialRuntime::from_config_file_with_store(&config, None, Arc::clone(&state.store))
            .await
            .unwrap();
    let mutable = Arc::get_mut(&mut state).unwrap();
    mutable.config = config;
    mutable.refresh = crate::provider_refresh::runtime(
        &mutable.store,
        Some(&credentials),
        Some(&mutable.compute),
    );
    mutable.credentials = credentials;
    (directory, state)
}

pub async fn adopt_provider(
    state: &ServerState,
    name: &str,
    profile: &str,
    key: &str,
) -> (Provider, Handles) {
    let owner = SecretOwner::provider("default", name, name);
    let raw = state
        .credentials
        .issuer()
        .store(StoreSecrets {
            owner,
            object_id: Some(&uuid::Uuid::new_v4().to_string()),
            values: &HashMap::from([(key.into(), format!("{name}-secret"))]),
            existing_handles: &Handles::new(),
        })
        .await
        .unwrap();
    let handles = state
        .credentials
        .versioned()
        .unwrap()
        .references
        .adopt(owner, &raw, &uuid::Uuid::new_v4().to_string())
        .await
        .unwrap();
    let provider = Provider {
        metadata: Some(ObjectMeta {
            id: name.into(),
            name: name.into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        r#type: profile.into(),
        credential_handles: handles,
        ..Default::default()
    };
    state.store.put_message(&provider).await.unwrap();
    (
        state
            .store
            .get_message::<Provider>(name)
            .await
            .unwrap()
            .unwrap(),
        raw,
    )
}

async fn sandbox(state: &ServerState, providers: &[&str]) -> Sandbox {
    let sandbox = Sandbox {
        metadata: Some(ObjectMeta {
            id: "sandbox".into(),
            name: "sandbox".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        spec: Some(SandboxSpec {
            policy: Some(SandboxPolicy {
                version: 1,
                network_policies: HashMap::from([(
                    "user-api".into(),
                    openshell_core::proto::NetworkPolicyRule {
                        name: "user-api".into(),
                        endpoints: vec![openshell_core::proto::NetworkEndpoint {
                            host: "allowed.example.com".into(),
                            port: 443,
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                )]),
                ..Default::default()
            }),
            providers: providers.iter().map(|name| (*name).into()).collect(),
            provider_attachment_epoch: uuid::Uuid::new_v4().to_string(),
            ..Default::default()
        }),
        ..Default::default()
    };
    state.store.put_message(&sandbox).await.unwrap();
    sandbox
}

fn assert_unresolved(config: &SupervisorConfig) {
    assert!(config.sandbox_config.configuration_admitted);
    assert!(config.sandbox_config.policy.is_some());
    assert!(names_provider_environment(
        &config.sandbox_config,
        &config.provider_environment
    ));
    assert!(config.provider_environment.values.is_empty());
    assert!(config.provider_environment.dynamic_credentials.is_empty());
    assert_eq!(
        config.provider_environment.readiness_reason,
        i32::from(ProviderReadinessReason::CredentialInstallFailed)
    );
}

#[tokio::test]
async fn versioned_backend_failure_delivers_tightening_and_provider_removal_unresolved() {
    let (_directory, state) = versioned_state().await;
    let (_healthy, _) = adopt_provider(&state, "healthy", "github", "GITHUB_TOKEN").await;
    let (failing, raw) = adopt_provider(&state, "failing", "gitlab", "GITLAB_TOKEN").await;
    let (_removed, _) = adopt_provider(&state, "removed", "claude", "ANTHROPIC_API_KEY").await;
    let mut sandbox = sandbox(&state, &["healthy", "failing", "removed"]).await;
    let initial = session::build_session_bootstrap(&state, &sandbox)
        .await
        .unwrap();
    assert_eq!(initial.outcome, session::BootstrapOutcome::Built);
    assert!(
        initial
            .config
            .sandbox_config
            .policy
            .as_ref()
            .unwrap()
            .network_policies
            .contains_key("user-api")
    );
    let cached = initial.config.provider_environment;
    // Leave the committed reference intact but remove its physical backend
    // value: this exercises a real failed backend read, not an expired grant.
    state
        .credentials
        .issuer()
        .delete(
            SecretOwner::provider("default", failing.object_id(), "failing"),
            &raw,
        )
        .await
        .unwrap();
    let tightened = SandboxPolicy {
        version: 1,
        ..Default::default()
    };
    state
        .store
        .put_policy_revision(
            "tightened",
            "sandbox",
            "default",
            2,
            &tightened.encode_to_vec(),
            &crate::grpc::policy::deterministic_policy_hash(&tightened),
        )
        .await
        .unwrap();
    sandbox.spec.as_mut().unwrap().providers = vec!["healthy".into(), "failing".into()];
    sandbox.spec.as_mut().unwrap().provider_attachment_epoch = uuid::Uuid::new_v4().to_string();
    state.store.put_message(&sandbox).await.unwrap();

    let Some(BuiltSandboxConfig::Built(inputs, snapshot, budget)) =
        Box::pin(build_sandbox_config(&state, "sandbox"))
            .await
            .unwrap()
    else {
        panic!("build current policy")
    };
    assert_eq!(snapshot.version, 2);
    assert!(
        !snapshot
            .policy
            .as_ref()
            .unwrap()
            .network_policies
            .contains_key("user-api"),
        "tightened policy must be delivered despite the backend failure"
    );
    assert_ne!(
        snapshot.provider_attachment_epoch, cached.provider_attachment_epoch,
        "provider removal must be delivered despite the remaining provider's outage"
    );
    assert!(inputs.credential_capture_error().is_some());
    assert_ne!(snapshot.provider_env_revision, cached.provider_env_revision);
    let record = SessionRecord::new(Registration {
        sandbox_id: "sandbox".into(),
        session_id: "session".into(),
        workspace: "default".into(),
        providers: HashSet::new(),
        provider_environment: Some(cached.clone()),
        captured_seq: 0,
        rebuild: false,
    });
    let (environment, failure) =
        provider_environment(&state, &record, &inputs, &snapshot, budget).await;
    assert!(failure.is_some(), "failed captures must be retried");
    assert_unresolved(&SupervisorConfig {
        sandbox_config: snapshot,
        provider_environment: environment,
    });
    assert_eq!(
        record.provider_environment(),
        Some(cached),
        "failure must not cache partial values"
    );
    let bootstrap = session::build_session_bootstrap(&state, &sandbox)
        .await
        .unwrap();
    assert_eq!(
        bootstrap.outcome,
        session::BootstrapOutcome::ProviderEnvironmentFailed
    );
    assert!(bootstrap.needs_rebuild());
    assert!(bootstrap.resolved_provider_environment().is_none());
    assert_unresolved(&bootstrap.config);

    // Polling policy delivery also remains available while provider reads fail.
    let snapshot = crate::grpc::policy::build_sandbox_config_snapshot(&state, &sandbox)
        .await
        .unwrap();
    assert_eq!(snapshot.version, 2);
    assert!(snapshot.configuration_admitted);
}

#[tokio::test]
async fn versioned_capture_timeout_delivers_bootstrap_and_live_policy_unresolved() {
    let (_directory, state) = versioned_state().await;
    adopt_provider(&state, "provider", "github", "GITHUB_TOKEN").await;
    let sandbox = sandbox(&state, &["provider"]).await;
    for bootstrap in [false, true] {
        let (hit, _release) = state.credentials.gate_next_resolve();
        let task = tokio::spawn({
            let state = state.clone();
            let sandbox = sandbox.clone();
            async move {
                if bootstrap {
                    let built = session::build_session_bootstrap(&state, &sandbox)
                        .await
                        .unwrap();
                    assert_eq!(
                        built.outcome,
                        session::BootstrapOutcome::ProviderEnvironmentFailed
                    );
                    built.config
                } else {
                    let Some(BuiltSandboxConfig::Built(inputs, snapshot, budget)) =
                        Box::pin(build_sandbox_config(&state, "sandbox"))
                            .await
                            .unwrap()
                    else {
                        panic!("build current policy")
                    };
                    assert_eq!(
                        inputs.credential_capture_error().unwrap().code(),
                        Code::DeadlineExceeded
                    );
                    let record = SessionRecord::new(Registration {
                        sandbox_id: "sandbox".into(),
                        session_id: "session".into(),
                        workspace: "default".into(),
                        providers: HashSet::new(),
                        provider_environment: None,
                        captured_seq: 0,
                        rebuild: false,
                    });
                    let (environment, failure) =
                        provider_environment(&state, &record, &inputs, &snapshot, budget).await;
                    assert_eq!(failure, Some(("timeout", Code::DeadlineExceeded)));
                    SupervisorConfig {
                        sandbox_config: snapshot,
                        provider_environment: environment,
                    }
                }
            }
        });
        tokio::time::timeout(Duration::from_secs(5), hit)
            .await
            .unwrap()
            .unwrap();
        // Freeze only after asynchronous DB reads reached the backend, so SQL
        // worker scheduling cannot consume the metadata budget under fake time.
        tokio::time::pause();
        tokio::time::advance(PROVIDER_ENVIRONMENT_BUILD_TIMEOUT + Duration::from_millis(1)).await;
        tokio::time::resume();
        let config = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert_unresolved(&config);
    }
}

/// Exercise the actual delivered fingerprint and durable apply-result handler.
pub async fn install_config(state: &Arc<ServerState>, sandbox: &Sandbox, config: SupervisorConfig) {
    use crate::supervisor_session::{AcceptedSession, SessionMode};
    use openshell_core::proto::SessionAccepted;
    let sandbox_id = sandbox.object_id();
    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    if !state
        .supervisor_sessions
        .is_current_session(sandbox_id, "session")
    {
        state.supervisor_sessions.register_with_mode(
            sandbox_id.into(),
            "session".into(),
            tx.clone(),
            tokio::sync::oneshot::channel().0,
            SessionMode::Push,
        );
    }
    let (update, in_flight) = session::bootstrap_update(config, &SessionAccepted::default());
    state
        .supervisor_sessions
        .begin_config_bootstrap(sandbox_id, "session", in_flight, None);
    let accepted = AcceptedSession {
        state: state.clone(),
        sandbox_id: sandbox_id.into(),
        session_id: "session".into(),
        instance_id: "instance".into(),
        tx,
        supports_session_redirect: false,
        pushes_config: true,
        advertises_services: false,
    };
    assert!(
        session::handle_config_update_result(&accepted, &session::applied_result(&update)).await
    );
}

fn next_config(
    outbound: &mut tokio::sync::mpsc::Receiver<openshell_core::proto::GatewayMessage>,
) -> openshell_core::proto::ConfigUpdate {
    while let Ok(message) = outbound.try_recv() {
        if let Some(openshell_core::proto::gateway_message::Payload::ConfigUpdate(update)) =
            message.payload
        {
            return update;
        }
    }
    panic!("configuration update must be queued");
}

fn prepare_recovery_credentials(
    environment: ProviderEnvironmentSnapshot,
) -> openshell_core::provider_credentials::ProviderCredentialState {
    let environment =
        openshell_core::grpc_client::ProviderEnvironmentResult::try_from(environment).unwrap();
    let prepared = openshell_core::provider_credentials::ProviderCredentialState::from_bound_environment_with_stable_placeholders(
        environment.provider_env_revision,
        environment.environment,
        environment.credential_expires_at_ms,
        environment.dynamic_credentials,
        environment.static_credential_bindings,
        environment.non_secret_environment_keys,
        environment.stable_placeholder_environment_keys,
    ).unwrap();
    prepared.set_managed_files(environment.files);
    prepared
}

async fn report_recovery_endpoint(
    state: &Arc<ServerState>,
    snapshot: &SandboxConfigSnapshot,
    sequence: u64,
) -> Result<(), Status> {
    use openshell_core::proto::open_shell_server::OpenShell as _;
    use openshell_core::proto::{EndpointObservation, EndpointResult, ReportEndpointStatusRequest};
    let endpoint = &snapshot.policy.as_ref().unwrap().network_policies["user-api"].endpoints[0];
    let id = openshell_core::endpoint_status::endpoint_id(endpoint);
    let mut request = Request::new(ReportEndpointStatusRequest {
        sandbox_id: "sandbox".into(),
        supervisor_session_id: "session".into(),
        policy_hash: snapshot.policy_hash.clone(),
        provider_env_revision: snapshot.provider_env_revision,
        report_sequence: sequence,
        observations: vec![EndpointObservation {
            endpoint_id: id.clone(),
            result: EndpointResult::HttpResponseReceived.into(),
            failure: None,
        }],
        observed_endpoint_ids: vec![id],
        token_grant_status: None,
    });
    request
        .extensions_mut()
        .insert(crate::auth::principal::test_support::sandbox("sandbox"));
    crate::grpc::OpenShellService::new(state.clone())
        .report_endpoint_status(request)
        .await
        .map(|_| ())
}

/// Real versioned backend capture -> live Builder -> durable result handling ->
/// same-generation backend recovery. Results model the existing supervisor's
/// retained-policy/static-revocation contract, not a newly installed policy.
async fn same_generation_recovery(timeout: bool, coalesced: bool, fail_result_write: bool) {
    use crate::supervisor_session::{AcceptedSession, SessionMode};
    use openshell_core::proto::{
        ConfigApplyFailure, ConfigApplyOutcome, ConfigurationAdmissionState, SessionAccepted,
    };

    const FAIL_ADMISSION_WRITES: &str = r#"
CREATE TRIGGER fail_recovery_admission BEFORE UPDATE ON "objects"
WHEN OLD."object_type" = 'sandbox'
BEGIN SELECT RAISE(ABORT, 'database unavailable'); END;
"#;
    const RESTORE_ADMISSION_WRITES: &str = "DROP TRIGGER fail_recovery_admission;";
    let (_directory, state) = versioned_state().await;
    let (provider, raw) = adopt_provider(&state, "provider", "github", "GITHUB_TOKEN").await;
    let mut sandbox = sandbox(&state, &["provider"]).await;
    let endpoint = &mut sandbox
        .spec
        .as_mut()
        .unwrap()
        .policy
        .as_mut()
        .unwrap()
        .network_policies
        .get_mut("user-api")
        .unwrap()
        .endpoints[0];
    endpoint.protocol = "mcp".into();
    endpoint.rules = vec![openshell_core::proto::L7Rule {
        allow: Some(openshell_core::proto::L7Allow {
            method: "tools/list".into(),
            ..Default::default()
        }),
    }];
    endpoint.mcp = Some(openshell_core::proto::McpOptions {
        versions: vec!["2025-11-25".into()],
        ..Default::default()
    });
    state.store.put_message(&sandbox).await.unwrap();
    let initial = session::build_session_bootstrap(&state, &sandbox)
        .await
        .unwrap();
    assert_eq!(
        initial.outcome,
        session::BootstrapOutcome::Built,
        "{}",
        initial.config.sandbox_config.configuration_error
    );
    let healthy = initial.config.clone();
    let installed = healthy.sandbox_config.clone();
    let environment = healthy.provider_environment.clone();
    assert!(!environment.values.is_empty());
    let runtime_credentials = prepare_recovery_credentials(environment.clone());
    let first_installation = runtime_credentials.snapshot().installation_id.clone();
    assert!(runtime_credentials.resolver().is_some());
    let (tx, mut outbound) = tokio::sync::mpsc::channel(16);
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
    assert!(
        session::handle_config_update_result(&accepted, &session::applied_result(&bootstrap)).await
    );
    assert!(
        state
            .supervisor_sessions
            .initialize_endpoint_status_authority("sandbox", "session")
    );
    report_recovery_endpoint(&state, &installed, 1)
        .await
        .unwrap();
    let record = Arc::new(SessionRecord::new(Registration {
        sandbox_id: "sandbox".into(),
        session_id: "session".into(),
        workspace: "default".into(),
        providers: HashSet::from(["provider".into()]),
        provider_environment: Some(environment.clone()),
        captured_seq: 0,
        rebuild: false,
    }));

    if timeout {
        let (hit, _release) = state.credentials.gate_next_resolve();
        let build = tokio::spawn({
            let state = state.clone();
            let record = record.clone();
            async move { Builder(&state).deliver(&record).await }
        });
        tokio::time::timeout(Duration::from_secs(5), hit)
            .await
            .unwrap()
            .unwrap();
        tokio::time::pause();
        tokio::time::advance(PROVIDER_ENVIRONMENT_BUILD_TIMEOUT + Duration::from_millis(1)).await;
        tokio::time::resume();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), build)
                .await
                .unwrap()
                .unwrap()
                .0
        );
    } else {
        state
            .credentials
            .issuer()
            .delete(
                SecretOwner::provider("default", provider.object_id(), "provider"),
                &raw,
            )
            .await
            .unwrap();
        assert!(
            Builder(&state).deliver(&record).await.0,
            "backend outage must request retry"
        );
    }
    let unresolved = next_config(&mut outbound);
    let unresolved_snapshot = unresolved.sandbox_config.as_ref().unwrap();
    assert_unresolved(&SupervisorConfig {
        sandbox_config: unresolved_snapshot.clone(),
        provider_environment: unresolved.provider_environment.clone().unwrap(),
    });
    assert_ne!(
        unresolved_snapshot.provider_env_revision,
        installed.provider_env_revision
    );
    assert_eq!(record.provider_environment(), Some(environment.clone()));
    assert_eq!(
        state
            .supervisor_sessions
            .installed_endpoint_configuration("sandbox", "session"),
        Some((
            installed.policy_hash.clone(),
            installed.provider_env_revision
        )),
        "in-flight fallback is not installed evidence"
    );

    // Restore the physical object, not the committed reference/version or
    // provider row. A timeout needs no restoration: its one-shot gate expired.
    if !timeout {
        let restored = state
            .credentials
            .issuer()
            .store(StoreSecrets {
                owner: SecretOwner::provider("default", provider.object_id(), "provider"),
                object_id: Some("restore-physical-only"),
                values: &HashMap::from([("GITHUB_TOKEN".into(), "provider-secret".into())]),
                existing_handles: &raw,
            })
            .await
            .unwrap();
        assert_eq!(restored, raw);
    }
    if coalesced {
        assert!(!Builder(&state).deliver(&record).await.0);
        assert!(
            outbound.try_recv().is_err(),
            "recovery must wait behind fallback"
        );
    }
    if fail_result_write {
        state.store.execute_for_test(FAIL_ADMISSION_WRITES).await;
    }
    let mut failure = session::applied_result(&unresolved);
    failure.outcome = ConfigApplyOutcome::FailedRetainedLastKnownGood.into();
    failure.failure = Some(ConfigApplyFailure {
        code: "provider_environment_unavailable".into(),
        message: "provider environment is not ready for installation".into(),
        retryable: true,
    });
    failure.admission.as_mut().unwrap().state = ConfigurationAdmissionState::Rejected.into();
    failure.policy_load = None;
    // Use the same core revocation boundary as the existing supervisor's
    // unresolved-environment branch before it reports retained policy.
    runtime_credentials
        .revoke_static_provider_environment(unresolved_snapshot.provider_env_revision);
    assert!(runtime_credentials.snapshot().child_env.is_empty());
    assert!(runtime_credentials.resolver().is_none());
    assert!(session::handle_config_update_result(&accepted, &failure).await);
    let stored = state
        .store
        .get_message::<Sandbox>("sandbox")
        .await
        .unwrap()
        .unwrap();
    let admission = stored
        .status
        .as_ref()
        .unwrap()
        .configuration_admission
        .as_ref()
        .unwrap();
    assert_eq!(
        admission.state,
        i32::from(ConfigurationAdmissionState::Accepted),
        "durable admission retains the last accepted runtime rather than installing the failed candidate"
    );
    assert_eq!(
        admission.provider_env_revision,
        installed.provider_env_revision
    );
    assert_eq!(
        admission.error.is_empty(),
        fail_result_write,
        "the write fault must actually prevent recording the failed desired configuration"
    );
    if fail_result_write {
        state.store.execute_for_test(RESTORE_ADMISSION_WRITES).await;
    }
    assert_eq!(
        state
            .supervisor_sessions
            .installed_endpoint_configuration("sandbox", "session"),
        None,
        "retained policy plus revoked static environment has no complete installed identity"
    );
    assert_eq!(
        report_recovery_endpoint(&state, &installed, 2)
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        report_recovery_endpoint(&state, unresolved_snapshot, 2)
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    if !coalesced {
        assert!(!Builder(&state).deliver(&record).await.0);
    }
    let mut recovered = next_config(&mut outbound);
    assert_eq!(
        recovered.sandbox_config.as_ref().unwrap(),
        &installed,
        "recovery must have the identical successful fingerprint, not a new version"
    );
    assert_eq!(
        recovered.provider_environment.as_ref().unwrap(),
        &environment,
        "install update restores the original credential material"
    );
    assert_eq!(
        state
            .store
            .get_message::<Provider>("provider")
            .await
            .unwrap()
            .unwrap(),
        provider,
        "no provider write or generation bump repaired delivery"
    );
    assert_eq!(
        state
            .supervisor_sessions
            .installed_endpoint_configuration("sandbox", "session"),
        None,
        "queued recovery is not an install receipt"
    );
    let prepared = prepare_recovery_credentials(recovered.provider_environment.clone().unwrap());
    runtime_credentials.install_prepared(&prepared);
    assert_eq!(
        runtime_credentials.snapshot().revision,
        installed.provider_env_revision
    );
    assert_ne!(
        runtime_credentials.snapshot().installation_id,
        first_installation
    );
    assert!(
        runtime_credentials
            .snapshot()
            .child_env
            .contains_key("GITHUB_TOKEN")
    );
    assert!(
        runtime_credentials.resolver().is_some(),
        "same-generation recovery really reinstalls static material"
    );
    if !fail_result_write {
        // A successful runtime recovery whose admission write fails is still
        // not durably acknowledged. Retry the identical generation, then
        // accept the runtime's duplicate result once persistence recovers.
        state.store.execute_for_test(FAIL_ADMISSION_WRITES).await;
        assert!(
            session::handle_config_update_result(&accepted, &session::applied_result(&recovered))
                .await
        );
        assert_eq!(
            state
                .supervisor_sessions
                .installed_endpoint_configuration("sandbox", "session"),
            None
        );
        assert_eq!(
            report_recovery_endpoint(&state, &installed, 2)
                .await
                .unwrap_err()
                .code(),
            Code::FailedPrecondition
        );
        state.store.execute_for_test(RESTORE_ADMISSION_WRITES).await;
        assert!(!Builder(&state).deliver(&record).await.0);
        recovered = next_config(&mut outbound);
        assert_eq!(recovered.sandbox_config.as_ref().unwrap(), &installed);
        assert_eq!(
            recovered.provider_environment.as_ref().unwrap(),
            &environment
        );
    }
    let mut result = session::applied_result(&recovered);
    if !fail_result_write {
        result.outcome = ConfigApplyOutcome::IgnoredDuplicate.into();
        result.policy_load = None;
    }
    assert!(session::handle_config_update_result(&accepted, &result).await);
    assert_eq!(
        state
            .supervisor_sessions
            .installed_endpoint_configuration("sandbox", "session"),
        Some((
            installed.policy_hash.clone(),
            installed.provider_env_revision
        ))
    );
    report_recovery_endpoint(&state, &installed, 2)
        .await
        .unwrap();
    assert_eq!(
        state
            .supervisor_sessions
            .deliver_config("sandbox", "session", healthy),
        DeliveryDisposition::SuppressedUnchanged,
        "successful recovery must end duplicate retries"
    );
    assert!(!Builder(&state).deliver(&record).await.0);
    assert!(
        outbound.try_recv().is_err(),
        "unchanged reconciliation must not form a delivery loop"
    );
}

#[tokio::test]
async fn versioned_missing_backend_same_generation_recovery_restores_stream_identity() {
    Box::pin(same_generation_recovery(false, false, false)).await;
    Box::pin(same_generation_recovery(false, true, true)).await;
}

#[tokio::test]
async fn versioned_timed_out_backend_same_generation_recovery_restores_stream_identity() {
    Box::pin(same_generation_recovery(true, false, true)).await;
    Box::pin(same_generation_recovery(true, true, false)).await;
}
