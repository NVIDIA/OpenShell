// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::grpc::mutation_replay::tests::reason;
use crate::grpc::mutation_replay::{Admission, OBJECT_TYPE, OriginalMutation, fingerprint, run};
use crate::grpc::test_support::{authed_request, test_server_state};
use openshell_core::proto::datamodel::v1::ObjectMeta;
use openshell_core::proto::{
    DeletionOutcome, DraftChunkApproval, GetDraftPolicyRequest, NetworkBinary, NetworkEndpoint,
    NetworkPolicyRule, PolicyChunk, ProviderCredentialRefresh, ProviderCredentialRefreshMaterial,
    ProviderCredentialRefreshStrategy, ProviderProfileCategory, ProviderProfileCredential,
    ProviderProfileImportItem, SandboxPhase, SandboxPolicy, SandboxSpec, ServiceEndpoint,
    SettingValue, SubmitPolicyAnalysisRequest, WorkspaceMember, WorkspaceRole, setting_value,
};
use tonic::Code;

async fn protected_state() -> (tempfile::TempDir, Arc<ServerState>) {
    let directory = tempfile::tempdir().unwrap();
    let mut state = test_server_state().await;
    configure_key(&mut state, &directory);
    (directory, state)
}

fn configure_key(state: &mut Arc<ServerState>, directory: &tempfile::TempDir) {
    let key = directory.path().join("private-key");
    std::fs::write(&key, b"test-only stable private fingerprint material").unwrap();
    Arc::get_mut(state).unwrap().config.gateway_jwt =
        Some(openshell_core::config::GatewayJwtConfig {
            signing_key_path: key,
            public_key_path: directory.path().join("public"),
            kid_path: directory.path().join("kid"),
            gateway_id: "test".into(),
            ttl_secs: None,
        });
}

pub(in crate::grpc::mutation_replay) async fn exercise_protected_backend(url: &str) {
    use crate::grpc::mutation_replay::tests::state_for;
    let directory = tempfile::tempdir().unwrap();
    let mut first = state_for(Store::connect(url).await.unwrap()).await;
    let mut second = state_for(Store::connect(url).await.unwrap()).await;
    configure_key(&mut first, &directory);
    configure_key(&mut second, &directory);
    let req = DeleteSandboxRequest {
        sandbox: "keyed-restart".into(),
        workspace: "default".to_string(),
        allow_missing: true,
        request_id: id(),
    };
    let mut tasks = Vec::new();
    for index in 0..16 {
        let state = if index % 2 == 0 {
            first.clone()
        } else {
            second.clone()
        };
        let req = req.clone();
        tasks.push(tokio::spawn(async move {
            run(&state, authed_request(req)).await
        }));
    }
    for task in tasks {
        if let Err(status) = task.await.unwrap() {
            assert_eq!(reason(&status), "REQUEST_OUTCOME_UNCERTAIN");
        }
    }
    drop(first);
    drop(second);
    let mut restarted = state_for(Store::connect(url).await.unwrap()).await;
    configure_key(&mut restarted, &directory);
    let replacement = Sandbox {
        metadata: Some(meta(&req.sandbox)),
        ..Default::default()
    };
    restarted.store.put_message(&replacement).await.unwrap();
    assert_eq!(
        replay(&restarted, req).await.outcome,
        i32::from(DeletionOutcome::AlreadyAbsent)
    );
    assert!(
        restarted
            .store
            .get_message::<Sandbox>(replacement.object_id())
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn ordinary_replay_reauthorizes_workspace_role() {
    let (_directory, mut state) = protected_state().await;
    Arc::get_mut(&mut state).unwrap().admin_role = "openshell-admin".into();
    let req = DeleteProviderRequest {
        name: "missing".into(),
        workspace: "default".to_string(),
        allow_missing: true,
        request_id: id(),
    };
    run(&state, authed_request(req.clone())).await.unwrap();
    let member = WorkspaceMember {
        metadata: Some(meta("dev-user")),
        principal_subject: "dev-user".into(),
        role: WorkspaceRole::User.into(),
    };
    state.store.put_message(&member).await.unwrap();
    let mut request = authed_request(req);
    let principal = request.extensions_mut().get_mut::<Principal>().unwrap();
    if let Principal::User(user) = principal {
        user.identity.roles.clear();
    }
    let principal = principal.clone();
    assert!(
        CreateSandboxRequest {
            workspace: "default".to_string(),
            ..Default::default()
        }
        .authorize(&state, &principal)
        .await
        .is_ok()
    );
    assert_eq!(
        run(&state, request).await.unwrap_err().code(),
        Code::PermissionDenied
    );
    for global in [false, true] {
        let req = UpdateConfigRequest {
            global,
            workspace: if global {
                String::new()
            } else {
                "default".to_string()
            },
            ..Default::default()
        };
        assert!(req.authorize(&state, &principal).await.is_err());
    }
    assert!(
        ImportProviderProfilesRequest::default()
            .authorize(&state, &principal)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn oversized_public_diagnostics_leave_a_bounded_unresolved_claim() {
    let (_directory, state) = protected_state().await;
    let request = ImportProviderProfilesRequest {
        request_id: id(),
        profiles: (0..80)
            .map(|_| ProviderProfileImportItem {
                profile: None,
                source: "public-source".repeat(100),
            })
            .collect(),
        ..Default::default()
    };
    for _ in 0..2 {
        assert_eq!(
            reason(
                &run(&state, authed_request(request.clone()))
                    .await
                    .unwrap_err()
            ),
            "REQUEST_OUTCOME_UNCERTAIN"
        );
    }
    let rows = state
        .store
        .list_by_type_after(OBJECT_TYPE, None, 100)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].payload.len() < 1024);
    assert!(
        serde_json::from_slice::<Admission>(&rows[0].payload)
            .unwrap()
            .success
            .is_none()
    );
}

fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}
fn meta(name: &str) -> ObjectMeta {
    ObjectMeta {
        id: id(),
        name: name.into(),
        workspace: "default".into(),
        ..Default::default()
    }
}

fn create_sandbox(name: &str) -> CreateSandboxRequest {
    CreateSandboxRequest {
        name: name.into(),
        request_id: id(),
        workspace: "default".to_string(),
        spec: Some(SandboxSpec {
            environment: HashMap::from([("PRIVATE_VALUE".into(), "low-entropy-secret".into())]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn replay<M: Mutation + Clone>(state: &Arc<ServerState>, req: M) -> M::Output {
    let response = run(state, authed_request(req)).await.unwrap();
    assert_eq!(
        response.metadata().get("openshell-replayed").unwrap(),
        "true"
    );
    response.into_inner()
}

#[tokio::test]
async fn sandbox_replay_survives_status_churn_but_never_selects_replacement() {
    let (_directory, state) = protected_state().await;
    let req = create_sandbox("original");
    let created = run(&state, authed_request(req.clone()))
        .await
        .unwrap()
        .into_inner()
        .sandbox
        .unwrap();
    state
        .store
        .update_message_cas::<Sandbox, _>(
            created.object_id(),
            created.get_resource_version(),
            |sandbox| {
                sandbox.status.as_mut().unwrap().phase = SandboxPhase::Ready.into();
            },
        )
        .await
        .unwrap();
    let returned = replay(&state, req.clone()).await.sandbox.unwrap();
    assert_eq!(returned.object_id(), created.object_id());
    assert!(returned.get_resource_version() > created.get_resource_version());
    let rows = state
        .store
        .list_by_type_after(OBJECT_TYPE, None, 100)
        .await
        .unwrap();
    let receipt = String::from_utf8(rows[0].payload.clone()).unwrap();
    assert!(!receipt.contains("low-entropy-secret"));
    assert!(!receipt.contains("PRIVATE_VALUE"));
    assert!(!receipt.contains(&fingerprint(&req).unwrap()));
    state
        .store
        .delete(Sandbox::object_type(), created.object_id())
        .await
        .unwrap();
    let replacement = Sandbox {
        metadata: Some(meta("original")),
        ..Default::default()
    };
    state.store.put_message(&replacement).await.unwrap();
    assert_eq!(
        reason(&run(&state, authed_request(req)).await.unwrap_err()),
        "REQUEST_REPLAY_UNAVAILABLE"
    );
    assert!(
        state
            .store
            .get_message::<Sandbox>(replacement.object_id())
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn keyed_fingerprints_fail_closed_on_missing_or_rotated_keys() {
    let missing = test_server_state().await;
    let req = DeleteSandboxRequest {
        sandbox: "missing".into(),
        workspace: "default".to_string(),
        allow_missing: true,
        request_id: id(),
    };
    assert_eq!(
        reason(
            &run(&missing, authed_request(req.clone()))
                .await
                .unwrap_err()
        ),
        "REQUEST_REPLAY_UNAVAILABLE"
    );
    assert!(
        missing
            .store
            .list_by_type_after(OBJECT_TYPE, None, 100)
            .await
            .unwrap()
            .is_empty()
    );
    let (directory, state) = protected_state().await;
    run(&state, authed_request(req.clone())).await.unwrap();
    std::fs::write(
        directory.path().join("private-key"),
        b"rotated-private-material",
    )
    .unwrap();
    assert_eq!(
        reason(&run(&state, authed_request(req)).await.unwrap_err()),
        "REQUEST_REPLAY_UNAVAILABLE"
    );
    assert_eq!(
        state
            .store
            .list_by_type_after(OBJECT_TYPE, None, 100)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn original_payload_is_identity_and_current_transformation_is_a_replay_guard() {
    let (_directory, state) = protected_state().await;
    let original = DeleteSandboxRequest {
        sandbox: "original".into(),
        workspace: "default".to_string(),
        allow_missing: true,
        request_id: id(),
    };
    let mut effective = original.clone();
    effective.sandbox = "transformed".into();
    let intercepted = |original: &DeleteSandboxRequest, effective: DeleteSandboxRequest| {
        let mut request = authed_request(effective);
        request
            .extensions_mut()
            .insert(OriginalMutation(original.encode_to_vec()));
        request
    };
    run(&state, intercepted(&original, effective.clone()))
        .await
        .unwrap();
    assert!(
        run(&state, intercepted(&original, effective.clone()))
            .await
            .unwrap()
            .metadata()
            .contains_key("openshell-replayed")
    );
    let mut changed = original.clone();
    changed.sandbox = "different-original".into();
    assert_eq!(
        reason(
            &run(&state, intercepted(&changed, effective.clone()))
                .await
                .unwrap_err()
        ),
        "REQUEST_ID_PAYLOAD_MISMATCH"
    );
    effective.sandbox = "changed-transformation".into();
    assert_eq!(
        reason(
            &run(&state, intercepted(&original, effective))
                .await
                .unwrap_err()
        ),
        "REQUEST_REPLAY_UNAVAILABLE"
    );
}

#[tokio::test]
async fn interceptors_cannot_enable_disable_or_replace_request_ids() {
    let state = test_server_state().await;
    for (original_id, effective_id) in [(String::new(), id()), (id(), String::new()), (id(), id())]
    {
        let original = CreateSandboxRequest {
            request_id: original_id,
            ..Default::default()
        };
        let mut req = authed_request(CreateSandboxRequest {
            request_id: effective_id,
            ..Default::default()
        });
        req.extensions_mut()
            .insert(OriginalMutation(original.encode_to_vec()));
        assert_eq!(
            run(&state, req).await.unwrap_err().code(),
            Code::InvalidArgument
        );
    }
    assert!(
        state
            .store
            .list_by_type_after(OBJECT_TYPE, None, 100)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn service_deletion_replays_without_parent_and_does_not_delete_replacement() {
    let (_directory, state) = protected_state().await;
    let sandbox = Sandbox {
        metadata: Some(meta("service-parent")),
        ..Default::default()
    };
    state.store.put_message(&sandbox).await.unwrap();
    let expose = ExposeServiceRequest {
        sandbox: "service-parent".into(),
        service: "web".into(),
        target_port: 8080,
        workspace: "default".to_string(),
        request_id: id(),
        ..Default::default()
    };
    let endpoint = run(&state, authed_request(expose.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(replay(&state, expose.clone()).await, endpoint);
    let delete = DeleteServiceRequest {
        sandbox: "service-parent".into(),
        service: "web".into(),
        workspace: "default".to_string(),
        request_id: id(),
        ..Default::default()
    };
    let deleted = run(&state, authed_request(delete.clone()))
        .await
        .unwrap()
        .into_inner();
    let mut fresh = expose;
    fresh.request_id = id();
    let replacement = run(&state, authed_request(fresh))
        .await
        .unwrap()
        .into_inner()
        .endpoint
        .unwrap();
    state
        .store
        .delete(Sandbox::object_type(), sandbox.object_id())
        .await
        .unwrap();
    assert_eq!(replay(&state, delete).await, deleted);
    assert!(
        state
            .store
            .get_message::<ServiceEndpoint>(replacement.object_id())
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn provider_replay_preserves_receipts_after_attachment_changes() {
    let (_directory, state) = protected_state().await;
    let created = run(
        &state,
        authed_request(CreateProviderRequest {
            provider: Some(Provider {
                metadata: Some(meta("receipt-provider")),
                r#type: "openai".into(),
                credentials: HashMap::from([("OPENAI_API_KEY".into(), "private-value".into())]),
                ..Default::default()
            }),
            workspace: "default".into(),
            request_id: id(),
        }),
    )
    .await
    .unwrap()
    .into_inner();
    let sandbox = Sandbox {
        metadata: Some(meta("receipt-sandbox")),
        spec: Some(SandboxSpec::default()),
        ..Default::default()
    };
    state.store.put_message(&sandbox).await.unwrap();
    let attach = AttachSandboxProviderRequest {
        sandbox: "receipt-sandbox".into(),
        provider_name: "receipt-provider".into(),
        workspace: "default".into(),
        request_id: id(),
        ..Default::default()
    };
    let attached = run(&state, authed_request(attach.clone()))
        .await
        .unwrap()
        .into_inner();
    assert!(attached.attached);
    assert!(attached.receipt.is_some());
    assert_eq!(replay(&state, attach.clone()).await, attached);

    let mut provider = created.provider.unwrap();
    provider.credentials = HashMap::from([("OPENAI_API_KEY".into(), "replacement-value".into())]);
    let update = UpdateProviderRequest {
        provider: Some(provider),
        workspace: "default".into(),
        request_id: id(),
        ..Default::default()
    };
    let updated = run(&state, authed_request(update.clone()))
        .await
        .unwrap()
        .into_inner();
    assert!(!updated.mutation_id.is_empty());
    assert_eq!(updated.target_receipts.len(), 1);
    assert_eq!(updated.target_receipts[0].mutation_id, updated.mutation_id);

    let detach = DetachSandboxProviderRequest {
        sandbox: "receipt-sandbox".into(),
        provider_name: "receipt-provider".into(),
        workspace: "default".into(),
        request_id: id(),
        ..Default::default()
    };
    let detached = run(&state, authed_request(detach.clone()))
        .await
        .unwrap()
        .into_inner();
    assert!(detached.detached);
    assert!(detached.receipt.is_some());
    assert_eq!(replay(&state, detach.clone()).await, detached);

    // Replay returns the original target and epoch even though it is detached
    // now. It neither selects new targets nor executes the stale attach again.
    assert_eq!(replay(&state, update.clone()).await, updated);
    let replayed_attach = replay(&state, attach).await;
    assert_eq!(replayed_attach.receipt, attached.receipt);
    assert!(replayed_attach.attached);
    assert_eq!(replayed_attach.sandbox, detached.sandbox);
    let operations = state
        .store
        .count_in_workspace(
            config_update_operation::CONFIG_UPDATE_OPERATION_OBJECT_TYPE,
            "default",
        )
        .await
        .unwrap();
    assert_eq!(operations, 3);

    // Lost operation evidence makes replay unavailable. It must not rotate
    // credentials or produce a replacement receipt to repair that evidence.
    state
        .store
        .delete(
            config_update_operation::CONFIG_UPDATE_OPERATION_OBJECT_TYPE,
            &updated.target_receipts[0].receipt_id,
        )
        .await
        .unwrap();
    assert_eq!(
        reason(&run(&state, authed_request(update)).await.unwrap_err()),
        "REQUEST_REPLAY_UNAVAILABLE"
    );
    assert_eq!(replay(&state, detach).await, detached);
    let current: Provider = state
        .store
        .get_message(updated.provider.as_ref().unwrap().object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        current.get_resource_version(),
        updated.provider.unwrap().get_resource_version()
    );
}

#[tokio::test]
async fn provider_replay_is_redacted_and_update_does_not_recheck_stale_version() {
    let (_directory, state) = protected_state().await;
    let create = CreateProviderRequest {
        provider: Some(Provider {
            metadata: Some(meta("replay-provider")),
            r#type: "openai".into(),
            credentials: HashMap::from([("OPENAI_API_KEY".into(), "provider-secret".into())]),
            ..Default::default()
        }),
        workspace: "default".to_string(),
        request_id: id(),
    };
    let first = run(&state, authed_request(create.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(replay(&state, create).await, first);
    let mut provider = first.provider.unwrap();
    provider.credentials = HashMap::from([("OPENAI_API_KEY".into(), "updated-secret".into())]);
    let update = UpdateProviderRequest {
        provider: Some(provider),
        workspace: "default".to_string(),
        request_id: id(),
        ..Default::default()
    };
    let updated = run(&state, authed_request(update.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(replay(&state, update).await, updated);
    let provider = updated.provider.unwrap();
    assert!(provider.credential_handles.is_empty());
    assert!(
        provider
            .credentials
            .values()
            .all(|value| value == "REDACTED")
    );
    for row in state
        .store
        .list_by_type_after(OBJECT_TYPE, None, 100)
        .await
        .unwrap()
    {
        let receipt = String::from_utf8(row.payload).unwrap();
        assert!(!receipt.contains("provider-secret"));
        assert!(!receipt.contains("updated-secret"));
    }
}

#[tokio::test]
async fn profile_receipts_use_private_identity_and_preserve_diagnostics() {
    let (_directory, state) = protected_state().await;
    let profile = ProviderProfile {
        id: "replay-profile".into(),
        display_name: "Replay".into(),
        category: ProviderProfileCategory::Other.into(),
        ..Default::default()
    };
    let create = ImportProviderProfilesRequest {
        profiles: vec![ProviderProfileImportItem {
            profile: Some(profile),
            source: "test.yaml".into(),
        }],
        workspace: "default".into(),
        request_id: id(),
    };
    let first = run(&state, authed_request(create.clone()))
        .await
        .unwrap()
        .into_inner();
    assert!(first.imported, "{:?}", first.diagnostics);
    assert_eq!(replay(&state, create.clone()).await, first);
    let mut profile = first.profiles[0].clone();
    profile.display_name = "Updated".into();
    let update = UpdateProviderProfilesRequest {
        id: profile.id.clone(),
        profile: Some(ProviderProfileImportItem {
            profile: Some(profile),
            source: "update.yaml".into(),
        }),
        workspace: "default".into(),
        request_id: id(),
        ..Default::default()
    };
    let updated = run(&state, authed_request(update.clone()))
        .await
        .unwrap()
        .into_inner();
    assert!(updated.updated);
    assert_eq!(replay(&state, update).await, updated);
    assert_eq!(
        reason(&run(&state, authed_request(create)).await.unwrap_err()),
        "REQUEST_REPLAY_UNAVAILABLE"
    );
    let invalid = ImportProviderProfilesRequest {
        request_id: id(),
        ..Default::default()
    };
    let diagnostics = run(&state, authed_request(invalid.clone()))
        .await
        .unwrap()
        .into_inner();
    assert!(!diagnostics.imported);
    assert!(!diagnostics.diagnostics.is_empty());
    assert_eq!(replay(&state, invalid).await, diagnostics);
}

#[tokio::test]
async fn config_and_clear_receipts_preserve_revision_and_parent_lifetime() {
    let (_directory, state) = protected_state().await;
    let sandbox = Sandbox {
        metadata: Some(meta("policy-parent")),
        ..Default::default()
    };
    state.store.put_message(&sandbox).await.unwrap();
    for global in [false, true] {
        let update = UpdateConfigRequest {
            sandbox: if global {
                String::new()
            } else {
                "policy-parent".into()
            },
            global,
            setting_key: "ocsf_json_enabled".into(),
            setting_value: Some(SettingValue {
                value: Some(setting_value::Value::BoolValue(true)),
            }),
            workspace: if global {
                String::new()
            } else {
                "default".to_string()
            },
            request_id: id(),
            ..Default::default()
        };
        let first = run(&state, authed_request(update.clone()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(replay(&state, update).await, first);
    }
    let clear = ClearDraftChunksRequest {
        sandbox: "policy-parent".into(),
        workspace: "default".to_string(),
        request_id: id(),
    };
    let first = run(&state, authed_request(clear.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(replay(&state, clear.clone()).await, first);
    state
        .store
        .delete(Sandbox::object_type(), sandbox.object_id())
        .await
        .unwrap();
    assert_eq!(
        reason(&run(&state, authed_request(clear)).await.unwrap_err()),
        "REQUEST_REPLAY_UNAVAILABLE"
    );
}

#[tokio::test]
async fn refresh_receipts_never_replay_a_new_grant_epoch() {
    let state = test_server_state().await;
    let provider = Provider {
        metadata: Some(meta("refresh-parent")),
        ..Default::default()
    };
    state.store.put_message(&provider).await.unwrap();
    let mut refresh = StoredProviderCredentialRefreshState {
        metadata: Some(meta("refresh-record")),
        provider_id: provider.object_id().into(),
        authorization_epoch: id(),
        ..Default::default()
    };
    state.store.put_message(&refresh).await.unwrap();
    let receipt = || {
        Success::Ordinary(Outcome::Refresh(Refresh {
            id: refresh.object_id().into(),
            provider_id: provider.object_id().into(),
            epoch: refresh.authorization_epoch.clone(),
        }))
    };
    ConfigureProviderRefreshRequest::restore(&state.store, receipt())
        .await
        .unwrap();
    let original = receipt();
    refresh.authorization_epoch = id();
    state.store.put_message(&refresh).await.unwrap();
    assert_eq!(
        reason(
            &ConfigureProviderRefreshRequest::restore(&state.store, original)
                .await
                .unwrap_err()
        ),
        "REQUEST_REPLAY_UNAVAILABLE"
    );
}

#[tokio::test]
async fn refresh_receipts_reject_epoch_deletion_timestamps() {
    let state = test_server_state().await;
    let provider = Provider {
        metadata: Some(meta("deleted-refresh-parent")),
        ..Default::default()
    };
    state.store.put_message(&provider).await.unwrap();
    let refresh = StoredProviderCredentialRefreshState {
        metadata: Some(ObjectMeta {
            deletion_time: Some(prost_types::Timestamp::default()),
            ..meta("deleted-refresh-record")
        }),
        provider_id: provider.object_id().into(),
        authorization_epoch: id(),
        ..Default::default()
    };
    state.store.put_message(&refresh).await.unwrap();
    let receipt = || {
        Success::Ordinary(Outcome::Refresh(Refresh {
            id: refresh.object_id().into(),
            provider_id: provider.object_id().into(),
            epoch: refresh.authorization_epoch.clone(),
        }))
    };
    for error in [
        ConfigureProviderRefreshRequest::restore(&state.store, receipt())
            .await
            .unwrap_err(),
        RotateProviderCredentialRequest::restore(&state.store, receipt())
            .await
            .unwrap_err(),
    ] {
        assert_eq!(reason(&error), "REQUEST_REPLAY_UNAVAILABLE");
    }
}

#[tokio::test]
async fn configure_and_rotate_capture_actual_grant_without_repeating_token_exchange() {
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
    let (_directory, state) = protected_state().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "minted-secret", "token_type": "Bearer", "expires_in": 3600,
        })))
        .expect(1)
        .mount(&server)
        .await;
    let strategy = ProviderCredentialRefreshStrategy::Oauth2ClientCredentials;
    let profile = ProviderProfile {
        id: "refresh-profile".into(),
        display_name: "Refresh".into(),
        category: ProviderProfileCategory::Other.into(),
        credentials: vec![ProviderProfileCredential {
            name: "access_token".into(),
            env_vars: vec!["ACCESS_TOKEN".into()],
            auth_style: "bearer".into(),
            header_name: "Authorization".into(),
            refresh: Some(ProviderCredentialRefresh {
                strategy: strategy.into(),
                token_url: server.uri(),
                material: vec![
                    ProviderCredentialRefreshMaterial {
                        name: "client_id".into(),
                        required: true,
                        ..Default::default()
                    },
                    ProviderCredentialRefreshMaterial {
                        name: "client_secret".into(),
                        secret: true,
                        required: true,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }),
            ..Default::default()
        }],
        ..Default::default()
    };
    let imported = run(
        &state,
        authed_request(ImportProviderProfilesRequest {
            workspace: "default".into(),
            profiles: vec![ProviderProfileImportItem {
                profile: Some(profile),
                source: "refresh.yaml".into(),
            }],
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert!(imported.imported, "{:?}", imported.diagnostics);
    run(
        &state,
        authed_request(CreateProviderRequest {
            workspace: "default".to_string(),
            provider: Some(Provider {
                metadata: Some(meta("refresh-provider")),
                r#type: "refresh-profile".into(),
                profile_workspace: "default".into(),
                credentials: HashMap::from([("ACCESS_TOKEN".into(), "initial-secret".into())]),
                ..Default::default()
            }),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    let configure = ConfigureProviderRefreshRequest {
        provider: "refresh-provider".into(),
        credential_key: "ACCESS_TOKEN".into(),
        strategy: strategy.into(),
        workspace: "default".to_string(),
        request_id: id(),
        material: HashMap::from([
            ("client_id".into(), "client".into()),
            ("client_secret".into(), "configured-secret".into()),
        ]),
        ..Default::default()
    };
    let configured = run(&state, authed_request(configure.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(replay(&state, configure.clone()).await, configured);
    let rotate = RotateProviderCredentialRequest {
        provider: "refresh-provider".into(),
        credential_key: "ACCESS_TOKEN".into(),
        workspace: "default".to_string(),
        request_id: id(),
    };
    let rotated = run(&state, authed_request(rotate.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(replay(&state, rotate).await, rotated);
    assert_eq!(replay(&state, configure).await.status, rotated.status);
    for row in state
        .store
        .list_by_type_after(OBJECT_TYPE, None, 100)
        .await
        .unwrap()
    {
        let receipt = String::from_utf8(row.payload).unwrap();
        for secret in ["initial-secret", "configured-secret", "minted-secret"] {
            assert!(!receipt.contains(secret));
        }
    }
    server.verify().await;
}

#[tokio::test]
async fn draft_receipts_replay_after_chunk_state_and_review_tokens_change() {
    let (_directory, state) = protected_state().await;
    let name = "draft-parent";
    let sandbox = Sandbox {
        metadata: Some(meta(name)),
        spec: Some(SandboxSpec {
            policy: Some(SandboxPolicy::default()),
            ..Default::default()
        }),
        ..Default::default()
    };
    state.store.put_message(&sandbox).await.unwrap();
    let rule = |name: &str| NetworkPolicyRule {
        name: name.into(),
        endpoints: vec![NetworkEndpoint {
            host: format!("{name}.example.com"),
            port: 443,
            ..Default::default()
        }],
        binaries: vec![NetworkBinary {
            path: "/usr/bin/curl".into(),
        }],
    };
    let submitted = policy::handle_submit_policy_analysis(
        &state,
        authed_request(SubmitPolicyAnalysisRequest {
            name: name.into(),
            analysis_mode: "agent_authored".into(),
            proposed_chunks: ["alpha", "beta", "gamma"]
                .into_iter()
                .map(|name| PolicyChunk {
                    rule_name: name.into(),
                    proposed_rule: Some(rule(name)),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(
        submitted.accepted_chunk_ids.len(),
        3,
        "{:?}",
        submitted.rejection_reasons
    );
    let edit = EditDraftChunkRequest {
        sandbox: name.into(),
        chunk_id: submitted.accepted_chunk_ids[0].clone(),
        proposed_rule: Some(rule("edited")),
        workspace: "default".to_string(),
        request_id: id(),
    };
    run(&state, authed_request(edit.clone())).await.unwrap();
    let draft = policy::handle_get_draft_policy(
        &state,
        authed_request(GetDraftPolicyRequest {
            sandbox: name.into(),
            workspace: "default".to_string(),
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .into_inner();
    let token = |id: &str| {
        draft
            .chunks
            .iter()
            .find(|chunk| chunk.id == id)
            .unwrap()
            .review_token
            .clone()
    };
    let approve = ApproveDraftChunkRequest {
        sandbox: name.into(),
        chunk_id: edit.chunk_id.clone(),
        review_token: token(&edit.chunk_id),
        workspace: "default".to_string(),
        request_id: id(),
    };
    let approved = run(&state, authed_request(approve.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(replay(&state, approve.clone()).await, approved);
    replay(&state, edit).await;
    let undo = UndoDraftChunkRequest {
        sandbox: name.into(),
        chunk_id: approve.chunk_id.clone(),
        workspace: "default".to_string(),
        request_id: id(),
    };
    let undone = run(&state, authed_request(undo.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(replay(&state, undo).await, undone);
    assert_eq!(replay(&state, approve).await, approved);
    let reject = RejectDraftChunkRequest {
        sandbox: name.into(),
        chunk_id: submitted.accepted_chunk_ids[1].clone(),
        reason: "not needed".into(),
        workspace: "default".to_string(),
        request_id: id(),
    };
    run(&state, authed_request(reject.clone())).await.unwrap();
    replay(&state, reject).await;
    let draft = policy::handle_get_draft_policy(
        &state,
        authed_request(GetDraftPolicyRequest {
            sandbox: name.into(),
            workspace: "default".to_string(),
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .into_inner();
    let chunk = draft
        .chunks
        .iter()
        .find(|chunk| chunk.id == submitted.accepted_chunk_ids[2])
        .unwrap();
    let all = ApproveAllDraftChunksRequest {
        sandbox: name.into(),
        approvals: vec![DraftChunkApproval {
            chunk_id: chunk.id.clone(),
            review_token: chunk.review_token.clone(),
        }],
        workspace: "default".to_string(),
        request_id: id(),
        ..Default::default()
    };
    let approved = run(&state, authed_request(all.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(approved.chunks_approved, 1);
    assert_eq!(replay(&state, all).await, approved);
}
