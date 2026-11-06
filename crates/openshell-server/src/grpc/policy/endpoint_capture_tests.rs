// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Physical secret reads must never own the revocation/mutation lock set.

use super::super::tests::{mcp_policy_with_versions, test_sandbox, with_sandbox};
use super::super::{build_sandbox_config_snapshot_from_inputs, load_sandbox_config_inputs};
use super::*;
use crate::config_delivery::versioned_tests::{adopt_provider, versioned_state};
use crate::grpc::test_support::authed_request;
use openshell_core::endpoint_status::endpoint_id;
use openshell_core::proto::{EndpointObservation, UpdateConfigRequest};
use std::time::Duration;
use tonic::Code;

async fn fixture() -> (
    tempfile::TempDir,
    Arc<ServerState>,
    ReportEndpointStatusRequest,
) {
    let (directory, state) = versioned_state().await;
    adopt_provider(&state, "provider", "github", "GITHUB_TOKEN").await;
    let sandbox = test_sandbox(
        "sandbox",
        "sandbox",
        mcp_policy_with_versions(&["2025-11-25"]),
        vec!["provider".into()],
    );
    state.store.put_message(&sandbox).await.unwrap();
    let sandbox = state
        .store
        .get_message::<Sandbox>("sandbox")
        .await
        .unwrap()
        .unwrap();
    let inputs = load_sandbox_config_inputs(&state, sandbox).await.unwrap();
    let snapshot = build_sandbox_config_snapshot_from_inputs(&state, &inputs)
        .await
        .unwrap();
    let endpoint = &snapshot.policy.as_ref().unwrap().network_policies["mcp"].endpoints[0];
    let id = endpoint_id(endpoint);
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
    (
        directory,
        state,
        ReportEndpointStatusRequest {
            sandbox_id: "sandbox".into(),
            supervisor_session_id: "session".into(),
            policy_hash: snapshot.policy_hash,
            provider_env_revision: snapshot.provider_env_revision,
            report_sequence: 1,
            observations: vec![EndpointObservation {
                endpoint_id: id.clone(),
                result: EndpointResult::HttpResponseReceived as i32,
                failure: None,
            }],
            observed_endpoint_ids: vec![id],
            token_grant_status: None,
        },
    )
}

async fn assert_no_evidence(state: &ServerState) {
    assert!(
        state
            .supervisor_sessions
            .endpoint_report_cursor("sandbox", "session")
            .is_none()
    );
    let sandbox = state
        .store
        .get_message::<Sandbox>("sandbox")
        .await
        .unwrap()
        .unwrap();
    assert!(
        sandbox
            .status
            .unwrap()
            .endpoint_statuses
            .iter()
            .all(|endpoint| endpoint.last_reported_time.is_none())
    );
}

#[tokio::test]
async fn polling_capture_allows_revocation_locks_and_unchanged_report_succeeds() {
    let (_directory, state, request) = fixture().await;
    let (hit, release) = state.credentials.gate_next_resolve();
    let report = tokio::spawn({
        let state = Arc::clone(&state);
        async move {
            handle_report_endpoint_status(&state, with_sandbox(Request::new(request), "sandbox"))
                .await
        }
    });
    hit.await.unwrap();
    state
        .compute
        .set_mutation_lock_timeout_for_tests(Duration::from_millis(100));
    for scope in [
        MutationScope::sandbox("default", "sandbox"),
        MutationScope::Workspace("default"),
        MutationScope::Global,
    ] {
        let guard =
            tokio::time::timeout(Duration::from_secs(2), state.compute.mutation_guard(scope))
                .await
                .expect("slow capture must not hold revocation locks")
                .unwrap();
        drop(guard);
    }
    assert!(
        !report.is_finished(),
        "secret read remains paused while mutations can proceed"
    );
    release.send(()).unwrap();
    report.await.unwrap().unwrap();
    assert!(
        state
            .supervisor_sessions
            .endpoint_report_cursor("sandbox", "session")
            .is_some()
    );
}

#[tokio::test]
async fn global_policy_change_during_polling_capture_commits_and_rejects_old_evidence() {
    let (_directory, state, request) = fixture().await;
    let (hit, release) = state.credentials.gate_next_resolve();
    let report = tokio::spawn({
        let state = Arc::clone(&state);
        async move {
            handle_report_endpoint_status(&state, with_sandbox(Request::new(request), "sandbox"))
                .await
        }
    });
    hit.await.unwrap();
    state
        .compute
        .set_mutation_lock_timeout_for_tests(Duration::from_millis(100));
    let mut policy = mcp_policy_with_versions(&["2025-11-25"]);
    policy.network_policies.get_mut("mcp").unwrap().endpoints[0].host =
        "narrowed.example.com".into();
    tokio::time::timeout(
        Duration::from_secs(2),
        super::super::handle_update_config(
            &state,
            authed_request(UpdateConfigRequest {
                global: true,
                policy: Some(policy),
                ..Default::default()
            }),
        ),
    )
    .await
    .expect("global policy must not wait for secret read")
    .unwrap();
    release.send(()).unwrap();
    assert_eq!(report.await.unwrap().unwrap_err().code(), Code::Aborted);
    assert_no_evidence(&state).await;
}

#[tokio::test]
async fn provider_detach_during_polling_capture_rejects_old_evidence() {
    let (_directory, state, request) = fixture().await;
    let (hit, release) = state.credentials.gate_next_resolve();
    let report = tokio::spawn({
        let state = Arc::clone(&state);
        async move {
            handle_report_endpoint_status(&state, with_sandbox(Request::new(request), "sandbox"))
                .await
        }
    });
    hit.await.unwrap();
    let guard = state
        .compute
        .sandbox_mutation_guard_by_id("sandbox")
        .await
        .unwrap()
        .unwrap();
    let mut sandbox = state
        .store
        .get_message::<Sandbox>("sandbox")
        .await
        .unwrap()
        .unwrap();
    sandbox.spec.as_mut().unwrap().providers.clear();
    state.store.put_message(&sandbox).await.unwrap();
    drop(guard);
    release.send(()).unwrap();
    assert_eq!(report.await.unwrap().unwrap_err().code(), Code::Aborted);
    assert_no_evidence(&state).await;
}

#[tokio::test]
async fn session_replacement_during_polling_capture_rejects_old_authority() {
    let (_directory, state, request) = fixture().await;
    let (hit, release) = state.credentials.gate_next_resolve();
    let report = tokio::spawn({
        let state = Arc::clone(&state);
        async move {
            handle_report_endpoint_status(&state, with_sandbox(Request::new(request), "sandbox"))
                .await
        }
    });
    hit.await.unwrap();
    let guard = state
        .compute
        .sandbox_mutation_guard_by_id("sandbox")
        .await
        .unwrap()
        .unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    state.supervisor_sessions.register(
        "sandbox".into(),
        "replacement".into(),
        tx,
        tokio::sync::oneshot::channel().0,
    );
    assert!(
        state
            .supervisor_sessions
            .initialize_endpoint_status_authority("sandbox", "replacement")
    );
    drop(guard);
    release.send(()).unwrap();
    assert_eq!(
        report.await.unwrap().unwrap_err().code(),
        Code::PermissionDenied
    );
    assert_no_evidence(&state).await;
    assert!(
        state
            .supervisor_sessions
            .endpoint_report_cursor("sandbox", "replacement")
            .is_none()
    );
}

#[tokio::test]
async fn polling_revalidation_uses_no_secret_reads_and_rejects_provider_revision_changes() {
    let (_directory, state, _) = fixture().await;
    let sandbox = state
        .store
        .get_message::<Sandbox>("sandbox")
        .await
        .unwrap()
        .unwrap();
    let inputs = load_sandbox_config_inputs(&state, sandbox.clone())
        .await
        .unwrap();
    let (mut hit, release) = state.credentials.gate_next_resolve();
    verify_polling_report_inputs(&state, &sandbox, &inputs)
        .await
        .unwrap();
    let provider = state
        .store
        .get_message::<openshell_core::proto::Provider>("provider")
        .await
        .unwrap()
        .unwrap();
    state
        .store
        .update_message_cas::<openshell_core::proto::Provider, _>(
            "provider",
            provider.metadata.as_ref().unwrap().resource_version,
            |provider| {
                provider.config.insert("nonsecret".into(), "changed".into());
            },
        )
        .await
        .unwrap();
    assert_eq!(
        verify_polling_report_inputs(&state, &sandbox, &inputs)
            .await
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    assert_eq!(
        hit.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty),
        "under-lock metadata revalidation must not resolve secrets"
    );
    drop(release);
    assert_no_evidence(&state).await;
}

#[tokio::test]
async fn polling_revalidation_rejects_reference_revocation_without_a_provider_write() {
    let (_directory, state, _) = fixture().await;
    let sandbox = state
        .store
        .get_message::<Sandbox>("sandbox")
        .await
        .unwrap()
        .unwrap();
    let inputs = load_sandbox_config_inputs(&state, sandbox.clone())
        .await
        .unwrap();
    let provider = state
        .store
        .get_message::<openshell_core::proto::Provider>("provider")
        .await
        .unwrap()
        .unwrap();
    state
        .credentials
        .versioned()
        .unwrap()
        .references
        .revoke(
            openshell_credential_issuer::SecretOwner::provider("default", "provider", "provider"),
            &provider.credential_handles,
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        state
            .store
            .get_message::<openshell_core::proto::Provider>("provider")
            .await
            .unwrap()
            .as_ref(),
        Some(&provider)
    );
    assert_eq!(
        verify_polling_report_inputs(&state, &sandbox, &inputs)
            .await
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    assert_no_evidence(&state).await;
}
