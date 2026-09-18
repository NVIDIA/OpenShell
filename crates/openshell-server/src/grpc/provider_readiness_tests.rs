// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::auth::principal::{Principal, SandboxIdentitySource, SandboxPrincipal};
use crate::config_update_operation::CONFIG_UPDATE_OPERATION_OBJECT_TYPE;
use crate::grpc::test_support::{authed_request, test_server_state};
use crate::persistence::WriteCondition;
use crate::storage_proto::StoredConfigUpdateOperation;
use openshell_core::proto::SandboxSpec;
use openshell_core::proto::datamodel::v1::ObjectMeta;
use prost::Message;
use std::collections::HashMap;

// Exercise the production session registry while keeping unrelated relay
// channel setup out of each installation-state test.
#[derive(Default)]
struct TestRegistry(crate::supervisor_session::SupervisorSessionRegistry);

fn register_session(
    registry: &crate::supervisor_session::SupervisorSessionRegistry,
    hello: &SupervisorHello,
) -> Result<String, Status> {
    let evidence = ProviderReadinessEvidence::from_hello(hello)?;
    let session_id = Uuid::new_v4().to_string();
    let (sender, _receiver) = tokio::sync::mpsc::channel(1);
    let (shutdown, _shutdown_receiver) = tokio::sync::oneshot::channel();
    registry.register(
        hello.sandbox_id.clone(),
        session_id.clone(),
        sender,
        shutdown,
    );
    assert!(registry.initialize_endpoint_status_authority(&hello.sandbox_id, &session_id));
    registry.initialize_provider_readiness(&hello.sandbox_id, &session_id, evidence)?;
    Ok(session_id)
}

impl TestRegistry {
    fn register(&self, hello: &SupervisorHello) -> Result<String, Status> {
        register_session(&self.0, hello)
    }

    fn accept(
        &self,
        sandbox_id: &str,
        session_id: &str,
        observation: ProviderReadinessObservation,
    ) -> Result<(), Status> {
        assert_eq!(session_id, observation.session_id);
        let active_instance = self
            .0
            .provider_readiness(sandbox_id)?
            .map(|evidence| evidence.network_instance_id)
            .unwrap_or_default();
        self.0
            .accept_provider_readiness(sandbox_id, &active_instance, observation)
    }

    fn snapshot(&self, sandbox_id: &str) -> Result<Option<ProviderReadinessEvidence>, Status> {
        self.0.provider_readiness(sandbox_id)
    }

    fn disconnect(&self, sandbox_id: &str, session_id: &str) {
        self.0.remove_if_current(sandbox_id, session_id);
    }
}

fn hello() -> SupervisorHello {
    SupervisorHello {
        sandbox_id: Uuid::new_v4().to_string(),
        instance_id: Uuid::new_v4().to_string(),
        supports_provider_readiness: true,
    }
}

fn receipt(hello: &SupervisorHello) -> ProviderMutationReceipt {
    ProviderMutationReceipt {
        receipt_id: Uuid::new_v4().to_string(),
        mutation_id: Uuid::new_v4().to_string(),
        provider: "synthetic-provider".to_string(),
        workspace: "default".to_string(),
        kind: ProviderMutationKind::Attach.into(),
        desired: Some(ProviderDesiredIdentity {
            sandbox_id: hello.sandbox_id.clone(),
            sandbox: "synthetic".to_string(),
            attachment_epoch: Uuid::new_v4().to_string(),
            provider_id: Uuid::new_v4().to_string(),
            provider_resource_version: 2,
            provider_env_revision: u64::MAX - 1,
            config_revision: u64::MAX,
            policy_hash: "abcd".to_string(),
        }),
        persisted_time: Some(prost_types::Timestamp {
            seconds: 0,
            nanos: 1,
        }),
    }
}

fn installed(
    hello: &SupervisorHello,
    session_id: &str,
    receipt: &ProviderMutationReceipt,
) -> ProviderReadinessObservation {
    let desired = receipt.desired.as_ref().unwrap();
    ProviderReadinessObservation {
        session_id: session_id.to_string(),
        sequence: 1,
        attachment_epoch: desired.attachment_epoch.clone(),
        provider_env_revision: desired.provider_env_revision,
        config_revision: desired.config_revision,
        policy_hash: desired.policy_hash.clone(),
        credentials_installed: true,
        policy_active: true,
        launch_environment_installed: true,
        process_instance_id: hello.instance_id.clone(),
        reason: ProviderReadinessReason::Unspecified.into(),
    }
}

fn evaluate(
    receipt: &ProviderMutationReceipt,
    session: Option<&ProviderReadinessEvidence>,
) -> ProviderReadinessStatus {
    evaluate_status(
        receipt.clone(),
        ProviderReadinessReason::Unspecified,
        receipt.desired.as_ref().unwrap(),
        ProviderReadinessReason::Unspecified,
        true,
        session.map_or("", |evidence| evidence.network_instance_id.as_str()),
        session,
    )
    .unwrap()
}

#[test]
fn readiness_timestamps_distinguish_missing_observations_and_preserve_nanos() {
    let hello = hello();
    let receipt = receipt(&hello);
    let disconnected = evaluate(&receipt, None);
    assert!(disconnected.observed_time.is_none());
    assert!(disconnected.evaluated_time.is_some());

    let mut evidence = ProviderReadinessEvidence::from_hello(&hello).unwrap();
    assert!(evaluate(&receipt, Some(&evidence)).observed_time.is_none());
    let observation = installed(&hello, &Uuid::new_v4().to_string(), &receipt);
    evidence.accept(observation.clone()).unwrap();
    assert!(evidence.observed_time.is_some());

    // A captured timestamp must survive status projection and report retries
    // without millisecond truncation or a fabricated new observation time.
    let captured = prost_types::Timestamp {
        seconds: 0,
        nanos: 1,
    };
    evidence.observed_time = Some(captured);
    evidence.accept(observation).unwrap();
    let status = evaluate(&receipt, Some(&evidence));
    assert_eq!(status.observed_time, Some(captured));
    openshell_core::time::validate_timestamp(status.evaluated_time.as_ref().unwrap()).unwrap();
}

#[test]
fn reporting_requires_own_authenticated_sandbox() {
    let hello = hello();
    assert_eq!(
        authorize_provider_readiness(&authed_request(()), &hello.sandbox_id)
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        authorize_provider_readiness(&Request::new(()), &hello.sandbox_id)
            .unwrap_err()
            .code(),
        tonic::Code::Unauthenticated
    );
    let mut request = Request::new(());
    request
        .extensions_mut()
        .insert(Principal::Sandbox(SandboxPrincipal {
            sandbox_id: hello.sandbox_id.clone(),
            source: SandboxIdentitySource::BootstrapJwt {
                issuer: "test".to_string(),
            },
            trust_domain: Some("test".to_string()),
        }));
    assert!(authorize_provider_readiness(&request, &hello.sandbox_id).is_ok());
    let mut other = hello;
    other.sandbox_id = Uuid::new_v4().to_string();
    assert_eq!(
        authorize_provider_readiness(&request, &other.sandbox_id)
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
}

#[tokio::test]
async fn report_rpc_requires_the_authenticated_sandboxes_current_session() {
    let state = test_server_state().await;
    let hello = hello();
    let receipt = receipt(&hello);
    state
        .store
        .put_message(&Sandbox {
            metadata: Some(ObjectMeta {
                id: hello.sandbox_id.clone(),
                name: "report-owner".to_string(),
                workspace: "default".to_string(),
                ..Default::default()
            }),
            status: Some(openshell_core::proto::SandboxStatus {
                phase: SandboxPhase::Ready as i32,
                main_process_instance_id: hello.instance_id.clone(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    let session_id = register_session(&state.supervisor_sessions, &hello).unwrap();
    let report = ReportProviderReadinessRequest {
        sandbox_id: hello.sandbox_id.clone(),
        observation: Some(installed(&hello, &session_id, &receipt)),
    };
    let request = |report: ReportProviderReadinessRequest, sandbox_id: &str| {
        let mut request = Request::new(report);
        request
            .extensions_mut()
            .insert(Principal::Sandbox(SandboxPrincipal {
                sandbox_id: sandbox_id.to_string(),
                source: SandboxIdentitySource::BootstrapJwt {
                    issuer: "test".to_string(),
                },
                trust_domain: Some("test".to_string()),
            }));
        request
    };
    for (unauthorized, code) in [
        (Request::new(report.clone()), tonic::Code::Unauthenticated),
        (
            authed_request(report.clone()),
            tonic::Code::PermissionDenied,
        ),
        (
            request(report.clone(), &Uuid::new_v4().to_string()),
            tonic::Code::PermissionDenied,
        ),
    ] {
        assert_eq!(
            handle_report_provider_readiness(&state, unauthorized)
                .await
                .unwrap_err()
                .code(),
            code
        );
    }
    let response =
        handle_report_provider_readiness(&state, request(report.clone(), &hello.sandbox_id))
            .await
            .unwrap()
            .into_inner();
    assert_eq!(response.accepted_sequence, 1);
    assert_eq!(
        openshell_core::time::duration_to_std(response.observation_ttl.as_ref().unwrap()).unwrap(),
        Duration::from_secs(u64::from(OBSERVATION_TTL_SECONDS))
    );
    assert_eq!(
        openshell_core::time::duration_to_std(response.report_interval.as_ref().unwrap()).unwrap(),
        Duration::from_secs(u64::from(REPORT_INTERVAL_SECONDS))
    );
    // Another gateway replica can replace the persisted instance without
    // touching this process's session registry. The old report must fail.
    let mut sandbox = state
        .store
        .get_message::<Sandbox>(&hello.sandbox_id)
        .await
        .unwrap()
        .unwrap();
    sandbox.status.as_mut().unwrap().main_process_instance_id = Uuid::new_v4().to_string();
    state.store.put_message(&sandbox).await.unwrap();
    assert_eq!(
        handle_report_provider_readiness(&state, request(report.clone(), &hello.sandbox_id))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    register_session(&state.supervisor_sessions, &hello).unwrap();
    assert_eq!(
        handle_report_provider_readiness(&state, request(report, &hello.sandbox_id))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
}

#[test]
fn report_retries_preserve_evidence_and_reject_reordering_or_changed_content() {
    let registry = TestRegistry::default();
    let hello = hello();
    let receipt = receipt(&hello);
    let session = registry.register(&hello).unwrap();
    let mut observation = installed(&hello, &session, &receipt);
    observation.sequence = 2;
    registry
        .accept(&hello.sandbox_id, &session, observation.clone())
        .unwrap();
    let accepted = registry.snapshot(&hello.sandbox_id).unwrap().unwrap();
    let mut changed = observation.clone();
    changed.credentials_installed = false;
    assert_eq!(
        registry
            .accept(&hello.sandbox_id, &session, changed)
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    let mut older = observation.clone();
    older.sequence = 1;
    assert_eq!(
        registry
            .accept(&hello.sandbox_id, &session, older)
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    registry
        .accept(&hello.sandbox_id, &session, observation.clone())
        .unwrap();
    let retried = registry.snapshot(&hello.sandbox_id).unwrap().unwrap();
    assert_eq!(retried.observation, Some(observation));
    assert_eq!(retried.last_seen, accepted.last_seen);
    assert_eq!(retried.observed_time, accepted.observed_time);
}

#[test]
fn expired_evidence_requires_a_new_report_sequence() {
    let hello = hello();
    let receipt = receipt(&hello);
    let mut evidence = ProviderReadinessEvidence::from_hello(&hello).unwrap();
    let mut observation = installed(&hello, &Uuid::new_v4().to_string(), &receipt);
    evidence.accept(observation.clone()).unwrap();
    evidence.last_seen -= Duration::from_secs(u64::from(OBSERVATION_TTL_SECONDS) + 1);
    let expired_at = evidence.last_seen;
    evidence.accept(observation.clone()).unwrap();
    assert_eq!(evidence.last_seen, expired_at);
    assert_eq!(
        evaluate(&receipt, Some(&evidence)).reason,
        ProviderReadinessReason::SupervisorLeaseExpired as i32
    );
    observation.sequence += 1;
    evidence.accept(observation).unwrap();
    assert_eq!(
        evaluate(&receipt, Some(&evidence)).state,
        ProviderReadinessState::Ready as i32
    );
}

#[test]
fn unsupported_and_uninitialized_sessions_cannot_publish_evidence() {
    let registry = TestRegistry::default();
    let mut hello = hello();
    hello.supports_provider_readiness = false;
    let receipt = receipt(&hello);
    let session = registry.register(&hello).unwrap();
    assert_eq!(
        registry
            .accept(
                &hello.sandbox_id,
                &session,
                installed(&hello, &session, &receipt)
            )
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(
        evaluate(
            &receipt,
            registry.snapshot(&hello.sandbox_id).unwrap().as_ref()
        )
        .reason,
        ProviderReadinessReason::UnsupportedSupervisor as i32
    );
    let other = Uuid::new_v4().to_string();
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    let (shutdown, _shutdown_rx) = tokio::sync::oneshot::channel();
    registry
        .0
        .register(hello.sandbox_id.clone(), other.clone(), tx, shutdown);
    assert_eq!(
        registry
            .accept(
                &hello.sandbox_id,
                &other,
                installed(&hello, &other, &receipt)
            )
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    assert!(registry.snapshot(&hello.sandbox_id).unwrap().is_none());
}

#[test]
fn malformed_reports_do_not_replace_accepted_evidence() {
    let registry = TestRegistry::default();
    let hello = hello();
    let receipt = receipt(&hello);
    let session = registry.register(&hello).unwrap();
    let initial = installed(&hello, &session, &receipt);
    registry
        .accept(&hello.sandbox_id, &session, initial.clone())
        .unwrap();
    for case in 0..6 {
        let mut invalid = initial.clone();
        invalid.sequence = 2;
        match case {
            0 => invalid.sequence = 0,
            1 => invalid.reason = i32::MAX,
            2 => invalid.attachment_epoch = "untrusted-identity".to_string(),
            3 => invalid.policy_hash = "a".repeat(129),
            4 => invalid.policy_hash = "not-a-fingerprint".to_string(),
            _ => invalid.process_instance_id.clear(),
        }
        assert!(
            registry
                .accept(&hello.sandbox_id, &session, invalid)
                .is_err()
        );
        assert_eq!(
            registry
                .snapshot(&hello.sandbox_id)
                .unwrap()
                .unwrap()
                .observation,
            Some(initial.clone())
        );
    }
}

#[test]
fn replacement_disconnect_and_replayed_reports_cannot_restore_readiness() {
    let registry = TestRegistry::default();
    let hello = hello();
    let receipt = receipt(&hello);
    let first = registry.register(&hello).unwrap();
    let observation = installed(&hello, &first, &receipt);
    registry
        .accept(&hello.sandbox_id, &first, observation.clone())
        .unwrap();
    assert_eq!(
        evaluate(
            &receipt,
            registry.snapshot(&hello.sandbox_id).unwrap().as_ref()
        )
        .state,
        ProviderReadinessState::Ready as i32
    );
    let before_retry = registry.snapshot(&hello.sandbox_id).unwrap().unwrap();
    registry
        .accept(&hello.sandbox_id, &first, observation.clone())
        .unwrap();
    let after_retry = registry.snapshot(&hello.sandbox_id).unwrap().unwrap();
    assert_eq!(before_retry.last_seen, after_retry.last_seen);
    assert_eq!(before_retry.observed_time, after_retry.observed_time);

    let second = registry.register(&hello).unwrap();
    assert_ne!(first, second);
    assert!(
        registry
            .accept(&hello.sandbox_id, &first, observation)
            .is_err()
    );
    registry.disconnect(&hello.sandbox_id, &first);
    let current = registry.snapshot(&hello.sandbox_id).unwrap().unwrap();
    assert_eq!(
        registry.0.current_session_id(&hello.sandbox_id),
        Some(second.clone())
    );
    assert_eq!(
        evaluate(&receipt, Some(&current)).state,
        ProviderReadinessState::Persisted as i32
    );
    registry
        .accept(
            &hello.sandbox_id,
            &second,
            installed(&hello, &second, &receipt),
        )
        .unwrap();
    registry.disconnect(&hello.sandbox_id, &second);
    assert!(registry.snapshot(&hello.sandbox_id).unwrap().is_none());
    assert_ne!(
        evaluate(&receipt, None).state,
        ProviderReadinessState::Ready as i32
    );
}

#[test]
fn sequence_order_does_not_order_revision_fingerprints() {
    let registry = TestRegistry::default();
    let hello = hello();
    let receipt = receipt(&hello);
    let session = registry.register(&hello).unwrap();
    let mut observation = installed(&hello, &session, &receipt);
    registry
        .accept(&hello.sandbox_id, &session, observation.clone())
        .unwrap();
    observation.sequence = 2;
    observation.config_revision = 1;
    observation.provider_env_revision = 1;
    registry
        .accept(&hello.sandbox_id, &session, observation)
        .unwrap();
    assert_eq!(
        evaluate(
            &receipt,
            registry.snapshot(&hello.sandbox_id).unwrap().as_ref()
        )
        .reason,
        ProviderReadinessReason::SnapshotMismatch as i32
    );
}

#[test]
fn partial_failed_incompatible_stopped_and_expired_installations_are_not_ready() {
    let registry = TestRegistry::default();
    let hello = hello();
    let receipt = receipt(&hello);
    let session_id = registry.register(&hello).unwrap();
    let observation = installed(&hello, &session_id, &receipt);
    registry
        .accept(&hello.sandbox_id, &session_id, observation)
        .unwrap();
    let complete = registry.snapshot(&hello.sandbox_id).unwrap().unwrap();
    for reason in [
        ProviderReadinessReason::CredentialInstallFailed,
        ProviderReadinessReason::PolicyActivationFailed,
        ProviderReadinessReason::ProcessInstallFailed,
        ProviderReadinessReason::CredentialsWithheld,
        ProviderReadinessReason::LocalPolicy,
    ] {
        let mut failed = complete.clone();
        failed.observation.as_mut().unwrap().reason = reason.into();
        assert_ne!(
            evaluate(&receipt, Some(&failed)).state,
            ProviderReadinessState::Ready as i32
        );
    }
    for (credentials, policy, process, reason) in [
        (
            false,
            true,
            true,
            ProviderReadinessReason::WaitingForCredentials,
        ),
        (true, false, true, ProviderReadinessReason::WaitingForPolicy),
        (
            true,
            true,
            false,
            ProviderReadinessReason::WaitingForProcess,
        ),
    ] {
        let mut partial = complete.clone();
        let observation = partial.observation.as_mut().unwrap();
        observation.credentials_installed = credentials;
        observation.policy_active = policy;
        observation.launch_environment_installed = process;
        assert_eq!(evaluate(&receipt, Some(&partial)).reason, reason as i32);
    }
    let mut incompatible = complete.clone();
    incompatible.supported = false;
    assert_eq!(
        evaluate(&receipt, Some(&incompatible)).reason,
        ProviderReadinessReason::UnsupportedSupervisor as i32
    );
    let mut expired = complete.clone();
    expired.last_seen -= Duration::from_secs(u64::from(OBSERVATION_TTL_SECONDS) + 1);
    assert_eq!(
        evaluate(&receipt, Some(&expired)).reason,
        ProviderReadinessReason::SupervisorLeaseExpired as i32
    );
    let stopped = evaluate_status(
        receipt.clone(),
        ProviderReadinessReason::Unspecified,
        receipt.desired.as_ref().unwrap(),
        ProviderReadinessReason::Unspecified,
        false,
        &hello.instance_id,
        Some(&complete),
    )
    .unwrap();
    assert_eq!(
        stopped.reason,
        ProviderReadinessReason::SupervisorDisconnected as i32
    );
    let mut missing = complete;
    missing
        .observation
        .as_mut()
        .unwrap()
        .process_instance_id
        .clear();
    assert_eq!(
        evaluate(&receipt, Some(&missing)).reason,
        ProviderReadinessReason::WaitingForProcess as i32
    );
}

#[test]
fn boundary_ack_is_bound_to_one_supervisor_session() {
    let registry = TestRegistry::default();
    let hello = hello();
    let receipt = receipt(&hello);
    let session = registry.register(&hello).unwrap();
    let mut observation = installed(&hello, &session, &receipt);
    observation.process_instance_id.clear();
    assert!(
        registry
            .accept(&hello.sandbox_id, &session, observation.clone())
            .is_err()
    );
    observation.launch_environment_installed = false;
    registry
        .accept(&hello.sandbox_id, &session, observation.clone())
        .unwrap();
    assert_eq!(
        evaluate(
            &receipt,
            registry.snapshot(&hello.sandbox_id).unwrap().as_ref()
        )
        .reason,
        ProviderReadinessReason::WaitingForProcess as i32
    );
    observation.sequence = 2;
    observation.launch_environment_installed = true;
    observation.process_instance_id = Uuid::new_v4().to_string();
    registry
        .accept(&hello.sandbox_id, &session, observation.clone())
        .unwrap();
    assert_eq!(
        evaluate(
            &receipt,
            registry.snapshot(&hello.sandbox_id).unwrap().as_ref()
        )
        .state,
        ProviderReadinessState::Ready as i32
    );
    observation.sequence = 3;
    observation.process_instance_id = Uuid::new_v4().to_string();
    assert!(
        registry
            .accept(&hello.sandbox_id, &session, observation)
            .is_err()
    );
}

#[test]
fn superseded_authority_cannot_complete_an_older_receipt() {
    let registry = TestRegistry::default();
    let hello = hello();
    let receipt = receipt(&hello);
    let session_id = registry.register(&hello).unwrap();
    registry
        .accept(
            &hello.sandbox_id,
            &session_id,
            installed(&hello, &session_id, &receipt),
        )
        .unwrap();
    let session = registry.snapshot(&hello.sandbox_id).unwrap();
    for field in 0..5 {
        let mut current = receipt.desired.clone().unwrap();
        match field {
            0 => current.attachment_epoch = Uuid::new_v4().to_string(),
            1 => current.provider_resource_version += 1,
            2 => current.provider_env_revision = 1,
            3 => current.config_revision = 1,
            _ => current.policy_hash = "dcba".to_string(),
        }
        let status = evaluate_status(
            receipt.clone(),
            ProviderReadinessReason::Unspecified,
            &current,
            ProviderReadinessReason::Unspecified,
            true,
            &hello.instance_id,
            session.as_ref(),
        )
        .unwrap();
        assert_eq!(status.state, ProviderReadinessState::Superseded as i32);
    }
    let failed_snapshot = evaluate_status(
        receipt.clone(),
        ProviderReadinessReason::SnapshotMismatch,
        receipt.desired.as_ref().unwrap(),
        ProviderReadinessReason::Unspecified,
        true,
        &hello.instance_id,
        session.as_ref(),
    )
    .unwrap();
    assert_eq!(failed_snapshot.state, ProviderReadinessState::Failed as i32);
}

#[test]
fn older_failed_observation_keeps_new_receipt_pending_until_matching_report() {
    let registry = TestRegistry::default();
    let hello = hello();
    let original = receipt(&hello);
    let session_id = registry.register(&hello).unwrap();
    let mut failed = installed(&hello, &session_id, &original);
    failed.reason = ProviderReadinessReason::CredentialInstallFailed.into();
    registry
        .accept(&hello.sandbox_id, &session_id, failed)
        .unwrap();

    let mut replacement = receipt(&hello);
    replacement.desired = original.desired;
    let desired = replacement.desired.as_mut().unwrap();
    desired.provider_resource_version += 1;
    desired.provider_env_revision = 1;
    let pending = evaluate(
        &replacement,
        registry.snapshot(&hello.sandbox_id).unwrap().as_ref(),
    );
    assert_eq!(pending.state, ProviderReadinessState::Pending as i32);
    assert_eq!(
        pending.reason,
        ProviderReadinessReason::SnapshotMismatch as i32
    );

    let mut matching = installed(&hello, &session_id, &replacement);
    matching.sequence = 2;
    matching.reason = ProviderReadinessReason::CredentialInstallFailed.into();
    registry
        .accept(&hello.sandbox_id, &session_id, matching.clone())
        .unwrap();
    let failed = evaluate(
        &replacement,
        registry.snapshot(&hello.sandbox_id).unwrap().as_ref(),
    );
    assert_eq!(failed.state, ProviderReadinessState::Failed as i32);
    assert_eq!(
        failed.reason,
        ProviderReadinessReason::CredentialInstallFailed as i32
    );

    matching.sequence = 3;
    matching.reason = ProviderReadinessReason::Unspecified.into();
    registry
        .accept(&hello.sandbox_id, &session_id, matching)
        .unwrap();
    assert_eq!(
        evaluate(
            &replacement,
            registry.snapshot(&hello.sandbox_id).unwrap().as_ref()
        )
        .state,
        ProviderReadinessState::Ready as i32
    );
}

#[tokio::test]
async fn attach_waiting_for_update_captures_published_revision_and_becomes_ready() {
    use openshell_core::proto::{
        AttachSandboxProviderRequest, CreateProviderRequest, UpdateProviderRequest,
    };

    let state = test_server_state().await;
    let hello = hello();
    let mut sandbox = Sandbox {
        metadata: Some(ObjectMeta {
            id: hello.sandbox_id.clone(),
            name: "attach-race".to_string(),
            workspace: "default".to_string(),
            ..Default::default()
        }),
        spec: Some(SandboxSpec {
            policy: Some(openshell_policy::restrictive_default_policy()),
            ..Default::default()
        }),
        ..Default::default()
    };
    sandbox.set_phase(SandboxPhase::Ready as i32);
    sandbox
        .status
        .as_mut()
        .unwrap()
        .main_process_instance_id
        .clone_from(&hello.instance_id);
    state.store.put_message(&sandbox).await.unwrap();
    let provider = |value: &str| Provider {
        metadata: Some(ObjectMeta {
            name: "work-github".to_string(),
            workspace: "default".to_string(),
            ..Default::default()
        }),
        r#type: "github".to_string(),
        credentials: HashMap::from([("GITHUB_TOKEN".to_string(), value.to_string())]),
        ..Default::default()
    };
    let initial = super::super::provider::handle_create_provider(
        &state,
        authed_request(CreateProviderRequest {
            request_id: String::new(),
            provider: Some(provider("synthetic-first")),
            workspace_scope: Some(openshell_core::proto::workspace_selector(
                "default".to_string(),
            )),
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .provider
    .unwrap();

    // The credential driver's gate holds UpdateProvider inside the shared
    // mutation guard while the attach request reaches that same guard.
    let (store_hit, release_store) = state.credentials.gate_next_store();
    let update_state = Arc::clone(&state);
    let replacement = provider("synthetic-second");
    let update = tokio::spawn(async move {
        super::super::provider::handle_update_provider(
            &update_state,
            authed_request(UpdateProviderRequest {
                request_id: String::new(),
                provider: Some(replacement),
                credential_expiration_times: HashMap::new(),
                clear_credential_expiration_keys: Vec::new(),
                workspace_scope: Some(openshell_core::proto::workspace_selector(
                    "default".to_string(),
                )),
            }),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), store_hit)
        .await
        .unwrap()
        .unwrap();
    let attach_wait_probe = Arc::new(tokio::sync::Notify::new());
    let mut attach_request = authed_request(AttachSandboxProviderRequest {
        request_id: String::new(),
        sandbox: "attach-race".to_string(),
        provider: "work-github".to_string(),
        expected_resource_version: 0,
        workspace_scope: Some(openshell_core::proto::workspace_selector(
            "default".to_string(),
        )),
    });
    attach_request
        .extensions_mut()
        .insert(Arc::clone(&attach_wait_probe));
    let attach_state = Arc::clone(&state);
    let attach = tokio::spawn(async move {
        super::super::sandbox::handle_attach_sandbox_provider(&attach_state, attach_request).await
    });
    tokio::time::timeout(Duration::from_secs(5), attach_wait_probe.notified())
        .await
        .unwrap();
    release_store.send(()).unwrap();
    let published = tokio::time::timeout(Duration::from_secs(5), update)
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_inner()
        .provider
        .unwrap();
    let attached = tokio::time::timeout(Duration::from_secs(5), attach)
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_inner();
    assert!(attached.attached);
    let receipt = attached.receipt.unwrap();
    let desired = receipt.desired.as_ref().unwrap();
    let published_version = published.metadata.as_ref().unwrap().resource_version;
    assert_ne!(
        published_version,
        initial.metadata.as_ref().unwrap().resource_version
    );
    assert_eq!(desired.provider_resource_version, published_version);
    assert_eq!(desired.provider_id, published.object_id());

    let session_id = register_session(&state.supervisor_sessions, &hello).unwrap();
    state
        .supervisor_sessions
        .accept_provider_readiness(
            &hello.sandbox_id,
            &hello.instance_id,
            installed(&hello, &session_id, &receipt),
        )
        .unwrap();
    let status = handle_get_sandbox_provider_status(
        &state,
        authed_request(GetSandboxProviderStatusRequest {
            sandbox: "attach-race".to_string(),
            provider: "work-github".to_string(),
            receipt_id: receipt.receipt_id,
            workspace_scope: Some(openshell_core::proto::workspace_selector(
                "default".to_string(),
            )),
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .status
    .unwrap();
    assert_eq!(status.state, ProviderReadinessState::Ready as i32);
}

#[tokio::test]
async fn status_rejects_oversized_provider_name_before_persisting_receipt() {
    let state = test_server_state().await;
    let sandbox = Sandbox {
        metadata: Some(ObjectMeta {
            id: Uuid::new_v4().to_string(),
            name: "s1".to_string(),
            workspace: "default".to_string(),
            ..Default::default()
        }),
        spec: Some(SandboxSpec {
            policy: Some(openshell_policy::restrictive_default_policy()),
            ..Default::default()
        }),
        ..Default::default()
    };
    state.store.put_message(&sandbox).await.unwrap();
    let response = handle_get_sandbox_provider_status(
        &state,
        authed_request(GetSandboxProviderStatusRequest {
            sandbox: "s1".to_string(),
            provider: "x".repeat(super::super::MAX_NAME_LEN + 1),
            receipt_id: String::new(),
            workspace_scope: Some(openshell_core::proto::workspace_selector(
                "default".to_string(),
            )),
        }),
    )
    .await;
    let receipt_count = state
        .store
        .count_in_workspace(CONFIG_UPDATE_OPERATION_OBJECT_TYPE, "default")
        .await
        .unwrap();
    assert_eq!(receipt_count, 0, "invalid status query persisted a receipt");
    let error = response.unwrap_err();
    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert_eq!(error.message(), "provider exceeds maximum length");
}

#[tokio::test]
async fn status_accepts_maximum_provider_name_and_receipt_only_lookup() {
    let state = test_server_state().await;
    let sandbox = Sandbox {
        metadata: Some(ObjectMeta {
            id: Uuid::new_v4().to_string(),
            name: "s1".to_string(),
            workspace: "default".to_string(),
            ..Default::default()
        }),
        spec: Some(SandboxSpec {
            policy: Some(openshell_policy::restrictive_default_policy()),
            ..Default::default()
        }),
        ..Default::default()
    };
    state.store.put_message(&sandbox).await.unwrap();
    let provider_name = "x".repeat(super::super::MAX_NAME_LEN);
    let provider = Provider {
        metadata: Some(ObjectMeta {
            id: Uuid::new_v4().to_string(),
            name: provider_name.clone(),
            workspace: "default".to_string(),
            ..Default::default()
        }),
        ..Default::default()
    };
    state.store.put_message(&provider).await.unwrap();
    let response = handle_get_sandbox_provider_status(
        &state,
        authed_request(GetSandboxProviderStatusRequest {
            sandbox: "s1".to_string(),
            provider: provider_name.clone(),
            receipt_id: String::new(),
            workspace_scope: Some(openshell_core::proto::workspace_selector(
                "default".to_string(),
            )),
        }),
    )
    .await
    .unwrap()
    .into_inner();
    let receipt = response.status.unwrap().receipt.unwrap();
    assert_eq!(receipt.provider, provider_name);
    assert_eq!(receipt.kind, ProviderMutationKind::Observe as i32);
    assert!(receipt.desired.as_ref().unwrap().provider_id.is_empty());

    // Receipt-only requery retains the persisted detached-provider intent even
    // after its record is deleted, without creating another observation.
    state
        .store
        .delete(Provider::object_type(), provider.object_id())
        .await
        .unwrap();
    let repeated = handle_get_sandbox_provider_status(
        &state,
        authed_request(GetSandboxProviderStatusRequest {
            sandbox: "s1".to_string(),
            provider: String::new(),
            receipt_id: receipt.receipt_id.clone(),
            workspace_scope: Some(openshell_core::proto::workspace_selector(
                "default".to_string(),
            )),
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(repeated.status.unwrap().receipt, Some(receipt));
    assert_eq!(
        state
            .store
            .count_in_workspace(CONFIG_UPDATE_OPERATION_OBJECT_TYPE, "default")
            .await
            .unwrap(),
        1
    );
}

async fn observation_fixture() -> (
    Arc<ServerState>,
    Sandbox,
    Provider,
    GetSandboxProviderStatusRequest,
) {
    let state = test_server_state().await;
    let sandbox = Sandbox {
        metadata: Some(ObjectMeta {
            id: Uuid::new_v4().to_string(),
            name: "observe-sandbox".to_string(),
            workspace: "default".to_string(),
            ..Default::default()
        }),
        spec: Some(SandboxSpec {
            policy: Some(openshell_policy::restrictive_default_policy()),
            provider_attachment_epoch: Uuid::new_v4().to_string(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let provider = Provider {
        metadata: Some(ObjectMeta {
            id: Uuid::new_v4().to_string(),
            name: "observe-provider".to_string(),
            workspace: "default".to_string(),
            ..Default::default()
        }),
        ..Default::default()
    };
    state.store.put_message(&sandbox).await.unwrap();
    state.store.put_message(&provider).await.unwrap();
    let query = GetSandboxProviderStatusRequest {
        sandbox: "observe-sandbox".to_string(),
        provider: "observe-provider".to_string(),
        receipt_id: String::new(),
        workspace_scope: Some(openshell_core::proto::workspace_selector(
            "default".to_string(),
        )),
    };
    (state, sandbox, provider, query)
}

#[tokio::test]
async fn repeated_and_concurrent_receiptless_status_reuses_one_operation() {
    let (state, _, _, query) = observation_fixture().await;
    let results = futures::future::join_all(
        (0..8).map(|_| handle_get_sandbox_provider_status(&state, authed_request(query.clone()))),
    )
    .await;
    let receipts: Vec<_> = results
        .into_iter()
        .map(|result| {
            result
                .unwrap()
                .into_inner()
                .status
                .unwrap()
                .receipt
                .unwrap()
        })
        .collect();
    let first = receipts.first().unwrap();
    assert!(receipts.iter().all(|receipt| receipt == first));
    let repeated = handle_get_sandbox_provider_status(&state, authed_request(query))
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap()
        .receipt
        .unwrap();
    assert_eq!(&repeated, first);
    assert_eq!(
        state
            .store
            .count_in_workspace(CONFIG_UPDATE_OPERATION_OBJECT_TYPE, "default")
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn receiptless_status_changed_target_creates_a_distinct_operation() {
    let (state, mut sandbox, _, query) = observation_fixture().await;
    let original = handle_get_sandbox_provider_status(&state, authed_request(query.clone()))
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap()
        .receipt
        .unwrap();
    sandbox.spec.as_mut().unwrap().provider_attachment_epoch = Uuid::new_v4().to_string();
    state.store.put_message(&sandbox).await.unwrap();
    let replacement = handle_get_sandbox_provider_status(&state, authed_request(query))
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap()
        .receipt
        .unwrap();
    assert_ne!(replacement.receipt_id, original.receipt_id);
    assert_ne!(replacement.desired, original.desired);
    assert_eq!(
        state
            .store
            .count_in_workspace(CONFIG_UPDATE_OPERATION_OBJECT_TYPE, "default")
            .await
            .unwrap(),
        2
    );
}

#[tokio::test]
async fn receiptless_status_unknown_provider_does_not_persist() {
    let (state, _, provider, query) = observation_fixture().await;
    state
        .store
        .delete(Provider::object_type(), provider.object_id())
        .await
        .unwrap();
    let error = handle_get_sandbox_provider_status(&state, authed_request(query))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::NotFound);
    assert_eq!(error.message(), "provider not found");
    assert_eq!(
        state
            .store
            .count_in_workspace(CONFIG_UPDATE_OPERATION_OBJECT_TYPE, "default")
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn stored_change_is_bound_to_its_sandbox_and_provider() {
    let state = test_server_state().await;
    let mut owner = Sandbox {
        metadata: Some(ObjectMeta {
            id: Uuid::new_v4().to_string(),
            name: "owner".to_string(),
            workspace: "default".to_string(),
            ..Default::default()
        }),
        spec: Some(SandboxSpec {
            provider_attachment_epoch: Uuid::new_v4().to_string(),
            policy: Some(openshell_policy::restrictive_default_policy()),
            ..Default::default()
        }),
        ..Default::default()
    };
    state.store.put_message(&owner).await.unwrap();
    let receipt = record_provider_mutation(
        &state,
        &owner,
        "provider-owner",
        ProviderMutationKind::Detach,
        None,
        &Uuid::new_v4().to_string(),
    )
    .await
    .unwrap();
    owner.metadata.as_mut().unwrap().id = Uuid::new_v4().to_string();
    owner.metadata.as_mut().unwrap().name = "other".to_string();
    state.store.put_message(&owner).await.unwrap();
    for (sandbox_name, provider_name) in [("other", "provider-owner"), ("owner", "other-provider")]
    {
        let request = GetSandboxProviderStatusRequest {
            sandbox: sandbox_name.to_string(),
            provider: provider_name.to_string(),
            receipt_id: receipt.receipt_id.clone(),
            workspace_scope: Some(openshell_core::proto::workspace_selector(
                "default".to_string(),
            )),
        };
        assert_eq!(
            handle_get_sandbox_provider_status(&state, authed_request(request))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );
    }
}

#[tokio::test]
async fn detach_receipt_persists_but_gateway_restart_requires_fresh_installation() {
    let state = test_server_state().await;
    let hello = hello();
    let mut sandbox = Sandbox {
        metadata: Some(ObjectMeta {
            id: hello.sandbox_id.clone(),
            name: "readiness".to_string(),
            workspace: "default".to_string(),
            ..Default::default()
        }),
        spec: Some(SandboxSpec {
            provider_attachment_epoch: Uuid::new_v4().to_string(),
            policy: Some(openshell_policy::restrictive_default_policy()),
            ..Default::default()
        }),
        ..Default::default()
    };
    sandbox.set_phase(SandboxPhase::Ready as i32);
    sandbox
        .status
        .as_mut()
        .unwrap()
        .main_process_instance_id
        .clone_from(&hello.instance_id);
    state.store.put_message(&sandbox).await.unwrap();
    let receipt = record_provider_mutation(
        &state,
        &sandbox,
        "detached",
        ProviderMutationKind::Detach,
        None,
        &Uuid::new_v4().to_string(),
    )
    .await
    .unwrap();
    let record = state
        .store
        .get(CONFIG_UPDATE_OPERATION_OBJECT_TYPE, &receipt.receipt_id)
        .await
        .unwrap()
        .unwrap();
    let stored = StoredConfigUpdateOperation::decode(record.payload.as_slice()).unwrap();
    assert_eq!(
        stored.provider_snapshot_reason,
        ProviderReadinessReason::Unspecified as i32
    );
    assert!(
        state
            .store
            .put_if(
                CONFIG_UPDATE_OPERATION_OBJECT_TYPE,
                &receipt.receipt_id,
                &receipt.receipt_id,
                "default",
                &record.payload,
                None,
                WriteCondition::MustCreate
            )
            .await
            .is_err()
    );
    let query = GetSandboxProviderStatusRequest {
        sandbox: "readiness".to_string(),
        provider: "detached".to_string(),
        receipt_id: receipt.receipt_id.clone(),
        workspace_scope: Some(openshell_core::proto::workspace_selector(
            "default".to_string(),
        )),
    };
    let initial = handle_get_sandbox_provider_status(&state, authed_request(query.clone()))
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap();
    assert_eq!(initial.state, ProviderReadinessState::Persisted as i32);
    let session_id = register_session(&state.supervisor_sessions, &hello).unwrap();
    state
        .supervisor_sessions
        .accept_provider_readiness(
            &hello.sandbox_id,
            &hello.instance_id,
            installed(&hello, &session_id, &receipt),
        )
        .unwrap();
    let ready = handle_get_sandbox_provider_status(&state, authed_request(query.clone()))
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap();
    assert_eq!(ready.state, ProviderReadinessState::Revoked as i32);

    // A different replica may accept a replacement supervisor while this
    // gateway still has the old local session and matching config hashes.
    sandbox.status.as_mut().unwrap().main_process_instance_id = Uuid::new_v4().to_string();
    state.store.put_message(&sandbox).await.unwrap();
    let replaced = handle_get_sandbox_provider_status(&state, authed_request(query.clone()))
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap();
    assert_eq!(replaced.state, ProviderReadinessState::Pending as i32);
    assert_eq!(
        replaced.reason,
        ProviderReadinessReason::SupervisorDisconnected as i32
    );
    sandbox
        .status
        .as_mut()
        .unwrap()
        .main_process_instance_id
        .clone_from(&hello.instance_id);
    state.store.put_message(&sandbox).await.unwrap();

    let mut restarted = test_server_state().await;
    Arc::get_mut(&mut restarted).unwrap().store = Arc::clone(&state.store);
    let after_restart =
        handle_get_sandbox_provider_status(&restarted, authed_request(query.clone()))
            .await
            .unwrap()
            .into_inner()
            .status
            .unwrap();
    assert_eq!(
        after_restart.state,
        ProviderReadinessState::Persisted as i32
    );
    assert_eq!(after_restart.receipt, Some(receipt));
    sandbox.spec.as_mut().unwrap().provider_attachment_epoch = Uuid::new_v4().to_string();
    state.store.put_message(&sandbox).await.unwrap();
    let changed = handle_get_sandbox_provider_status(&state, authed_request(query))
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap();
    assert_eq!(changed.state, ProviderReadinessState::Superseded as i32);
}
