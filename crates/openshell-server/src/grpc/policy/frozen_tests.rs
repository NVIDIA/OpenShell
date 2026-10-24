// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod frozen_policy_tests {
    use super::*;
    use crate::persistence::PersistenceError;
    use openshell_core::proto::{
        AttachSandboxProviderRequest, ConfigurationAdmissionState, DetachSandboxProviderRequest,
        ProviderProfile, ProviderProfileCredential, ReportSandboxConfigurationRequest,
        SandboxConfigurationAdmission, UpdateProviderRequest,
    };

    const ID: &str = "sb-frozen-policy";
    const NAME: &str = "frozen-policy";
    const PROVIDER: &str = "frozen-provider";
    const PROFILE: &str = "frozen-profile";
    const TOKEN: &str = "FROZEN_TOKEN";

    fn profile(host: &str) -> ProviderProfile {
        ProviderProfile {
            id: PROFILE.to_string(),
            display_name: "Frozen policy test".to_string(),
            credentials: vec![ProviderProfileCredential {
                name: "access_token".to_string(),
                env_vars: vec![TOKEN.to_string()],
                auth_style: "bearer".to_string(),
                header_name: "Authorization".to_string(),
                ..Default::default()
            }],
            endpoints: vec![NetworkEndpoint {
                host: host.to_string(),
                port: 443,
                protocol: "rest".to_string(),
                access: openshell_core::proto::NetworkAccessPreset::Full.into(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    async fn seed(state: &Arc<ServerState>, frozen: bool) -> Provider {
        state
            .store
            .put_message(&crate::provider_profile_sources::stored_provider_profile(
                profile("api.original.example"),
            ))
            .await
            .unwrap();
        let mut provider = test_provider(PROVIDER, PROFILE);
        provider.profile_workspace.clear();
        provider.credentials = HashMap::from([(TOKEN.to_string(), "original-token".to_string())]);
        state.store.put_message(&provider).await.unwrap();
        let mut sandbox = test_sandbox(
            ID,
            NAME,
            openshell_policy::restrictive_default_policy(),
            vec![PROVIDER.to_string()],
        );
        sandbox.spec.as_mut().unwrap().frozen = frozen;
        state.store.put_message(&sandbox).await.unwrap();
        // Creation persists the baseline revision that supervisors acknowledge.
        let policy =
            validate_and_canonicalize_policy(openshell_policy::restrictive_default_policy())
                .unwrap();
        state
            .store
            .put_policy_revision(
                "frozen-policy-1",
                ID,
                sandbox.object_workspace(),
                1,
                &policy.encode_to_vec(),
                &deterministic_policy_hash(&policy),
            )
            .await
            .unwrap();
        provider
    }

    async fn config(state: &Arc<ServerState>) -> GetSandboxConfigResponse {
        handle_get_sandbox_config(
            state,
            with_sandbox(
                Request::new(GetSandboxConfigRequest {
                    name: NAME.to_string(),
                    workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                }),
                ID,
            ),
        )
        .await
        .unwrap()
        .into_inner()
    }

    async fn environment(state: &Arc<ServerState>) -> GetSandboxProviderEnvironmentResponse {
        handle_get_sandbox_provider_environment(
            state,
            with_sandbox(
                Request::new(GetSandboxProviderEnvironmentRequest {
                    sandbox_id: ID.to_string(),
                    supports_static_credential_bindings: true,
                    supports_stable_placeholder_environment_keys: true,
                }),
                ID,
            ),
        )
        .await
        .unwrap()
        .into_inner()
    }

    async fn register(state: &Arc<ServerState>, instance: &str, previous: &str) {
        handle_report_sandbox_configuration(
            state,
            with_sandbox(
                Request::new(ReportSandboxConfigurationRequest {
                    sandbox_id: ID.to_string(),
                    admission: Some(SandboxConfigurationAdmission {
                        instance_id: instance.to_string(),
                        state: ConfigurationAdmissionState::Pending.into(),
                        ..Default::default()
                    }),
                    expected_instance_id: previous.to_string(),
                }),
                ID,
            ),
        )
        .await
        .unwrap();
    }

    async fn accept(
        state: &Arc<ServerState>,
        instance: &str,
        config: &GetSandboxConfigResponse,
    ) -> Result<Response<openshell_core::proto::ReportSandboxConfigurationResponse>, Status> {
        handle_report_sandbox_configuration(
            state,
            with_sandbox(
                Request::new(ReportSandboxConfigurationRequest {
                    sandbox_id: ID.to_string(),
                    admission: Some(SandboxConfigurationAdmission {
                        instance_id: instance.to_string(),
                        state: ConfigurationAdmissionState::Accepted.into(),
                        policy_version: config.version,
                        policy_hash: config.policy_hash.clone(),
                        config_revision: config.config_revision,
                        provider_env_revision: config.provider_env_revision,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ID,
            ),
        )
        .await
    }

    async fn initialize(state: &Arc<ServerState>) -> (GetSandboxConfigResponse, String) {
        let instance = uuid::Uuid::new_v4().to_string();
        register(state, &instance, "").await;
        let config = config(state).await;
        assert!(
            config.configuration_admitted,
            "{}",
            config.configuration_error
        );
        assert!(frozen::snapshot(&stored_sandbox(state).await).is_none());
        accept(state, &instance, &config).await.unwrap();
        (config, instance)
    }

    async fn stored_sandbox(state: &Arc<ServerState>) -> Sandbox {
        state
            .store
            .get_message::<Sandbox>(ID)
            .await
            .unwrap()
            .unwrap()
    }

    async fn update_global(state: &Arc<ServerState>, host: &str) {
        let mut policy = openshell_policy::restrictive_default_policy();
        let mut endpoint = profile(host).endpoints.remove(0);
        endpoint.provider_credentialed = false;
        policy.network_policies.insert(
            "global_access".to_string(),
            NetworkPolicyRule {
                name: "global_access".to_string(),
                endpoints: vec![endpoint],
                ..Default::default()
            },
        );
        handle_update_config(
            state,
            with_user(Request::new(UpdateConfigRequest {
                policy: Some(policy),
                global: true,
                ..Default::default()
            })),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn frozen_policy_admission_captures_once_and_survives_restart() {
        for (frozen_requested, global) in [(false, false), (true, false), (true, true)] {
            let state = test_server_state().await;
            let mut provider = seed(&state, frozen_requested).await;
            let mut state = Arc::try_unwrap(state).ok().unwrap();
            state.provider_profile_sources = ProviderProfileSources::from_test_snapshot_sequence(
                vec![(
                    "original".to_string(),
                    vec![profile("api.original.example")],
                )],
                Arc::new(AtomicUsize::new(0)),
            );
            let state = Arc::new(state);
            config(&state).await;
            if global {
                update_global(&state, "api.original.example").await;
            }
            let instance = uuid::Uuid::new_v4().to_string();
            register(&state, &instance, "").await;
            let outdated = config(&state).await;
            assert!(
                outdated.configuration_admitted,
                "{}",
                outdated.configuration_error
            );
            provider
                .credentials
                .insert(TOKEN.to_string(), "rotated-token".to_string());
            crate::grpc::provider::handle_update_provider(
                &state,
                with_user(Request::new(UpdateProviderRequest {
                    provider: Some(provider),
                    workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                    ..Default::default()
                })),
            )
            .await
            .unwrap();
            assert_eq!(
                accept(&state, &instance, &outdated)
                    .await
                    .unwrap_err()
                    .code(),
                Code::Aborted
            );
            assert!(frozen::snapshot(&stored_sandbox(&state).await).is_none());
            let accepted = config(&state).await;
            accept(&state, &instance, &accepted).await.unwrap();
            let sandbox = stored_sandbox(&state).await;
            assert_eq!(frozen::snapshot(&sandbox).is_some(), frozen_requested);
            if !frozen_requested {
                update_global(&state, "api.changed.example").await;
                let changed = config(&state).await;
                assert_ne!(changed.policy_hash, accepted.policy_hash);
                assert_eq!(changed.policy_source, i32::from(PolicySource::Global));
                continue;
            }
            let captured = frozen::snapshot(&sandbox).unwrap().clone();
            assert_eq!(captured.policy, accepted.policy);
            assert_eq!(captured.policy_hash, accepted.policy_hash);
            assert!(captured.frozen_time.is_some());
            assert_eq!(
                captured.policy_source,
                i32::from(if global {
                    PolicySource::Global
                } else {
                    PolicySource::Sandbox
                })
            );
            assert_eq!(captured.global_policy_version, u32::from(global));
            assert_eq!(
                captured.providers[0].profile.as_ref().unwrap().endpoints[0].host,
                "api.original.example"
            );

            // Any live source read would now supply different authorization.
            let fetches = Arc::new(AtomicUsize::new(0));
            let mut state = Arc::try_unwrap(state).ok().unwrap();
            state.provider_profile_sources = ProviderProfileSources::from_test_snapshot_sequence(
                vec![("changed".to_string(), vec![profile("api.changed.example")])],
                Arc::clone(&fetches),
            );
            let state = Arc::new(state);
            update_global(&state, "api.changed.example").await;
            let delivered = config(&state).await;
            let credentials = environment(&state).await;
            assert_eq!(delivered.policy_source, i32::from(PolicySource::Frozen));
            assert_eq!(delivered.policy, accepted.policy);
            assert_eq!(delivered.policy_hash, accepted.policy_hash);
            assert_eq!(delivered.version, accepted.version);
            assert_eq!(credentials.policy_hash, accepted.policy_hash);
            assert_eq!(credentials.environment[TOKEN], "rotated-token");

            let replacement = uuid::Uuid::new_v4().to_string();
            register(&state, &replacement, &instance).await;
            let replacement_config = config(&state).await;
            assert_eq!(replacement_config.policy, accepted.policy);
            assert_eq!(replacement_config.policy_hash, accepted.policy_hash);
            assert_eq!(
                replacement_config.global_policy_version,
                captured.global_policy_version
            );
            accept(&state, &replacement, &replacement_config)
                .await
                .unwrap();
            assert_eq!(
                frozen::snapshot(&stored_sandbox(&state).await),
                Some(&captured)
            );
            assert_eq!(fetches.load(Ordering::SeqCst), 0);

            let directory = tempfile::tempdir().unwrap();
            let database_url = format!("sqlite://{}", directory.path().join("frozen.db").display());
            let store = Store::connect(&database_url).await.unwrap();
            let sandbox = stored_sandbox(&state).await;
            let bytes = sandbox.encode_to_vec();
            for secret in ["original-token", "rotated-token"] {
                assert!(!String::from_utf8_lossy(&bytes).contains(secret));
            }
            store.put_message(&sandbox).await.unwrap();
            drop(store);
            let reopened = Store::connect(&database_url).await.unwrap();
            let restored = reopened.get_message::<Sandbox>(ID).await.unwrap().unwrap();
            assert_eq!(frozen::snapshot(&restored), Some(&captured));
        }
    }

    #[tokio::test]
    async fn frozen_policy_rejects_mutation_handlers_for_user_and_sandbox() {
        let state = test_server_state().await;
        seed(&state, true).await;
        let (accepted, _) = initialize(&state).await;
        for sandbox_caller in [false, true] {
            for merge in [false, true] {
                let request = Request::new(UpdateConfigRequest {
                    sandbox: NAME.to_string(),
                    workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                    policy: (!merge).then(openshell_policy::restrictive_default_policy),
                    merge_operations: if merge {
                        vec![PolicyMergeOperation {
                            operation: Some(policy_merge_operation::Operation::RemoveRule(
                                openshell_core::proto::RemoveNetworkRule {
                                    rule_name: "unused".to_string(),
                                },
                            )),
                        }]
                    } else {
                        Vec::new()
                    },
                    ..Default::default()
                });
                let request = if sandbox_caller {
                    with_sandbox(request, ID)
                } else {
                    with_user(request)
                };
                let error = handle_update_config(&state, request).await.unwrap_err();
                if sandbox_caller && merge {
                    assert_eq!(error.code(), Code::PermissionDenied);
                } else {
                    assert_eq!(error.code(), Code::FailedPrecondition);
                    assert!(error.message().contains("frozen"));
                }
            }
        }
        for sandbox_caller in [false, true] {
            let attach = Request::new(AttachSandboxProviderRequest {
                sandbox: NAME.to_string(),
                provider: PROVIDER.to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                ..Default::default()
            });
            let detach = Request::new(DetachSandboxProviderRequest {
                sandbox: NAME.to_string(),
                provider: PROVIDER.to_string(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                ..Default::default()
            });
            let attach = if sandbox_caller {
                with_sandbox(attach, ID)
            } else {
                with_user(attach)
            };
            let detach = if sandbox_caller {
                with_sandbox(detach, ID)
            } else {
                with_user(detach)
            };
            let attach_error = crate::grpc::sandbox::handle_attach_sandbox_provider(&state, attach)
                .await
                .unwrap_err();
            let detach_error = crate::grpc::sandbox::handle_detach_sandbox_provider(&state, detach)
                .await
                .unwrap_err();
            for error in [attach_error, detach_error] {
                assert_eq!(error.code(), Code::FailedPrecondition);
                assert!(error.message().contains("frozen"));
            }
        }

        let rule = test_policy_with_rule("new_access", "proposal.example")
            .network_policies
            .remove("new_access")
            .unwrap();
        let mut chunk = pending_draft_chunk("before-freeze", ID);
        chunk.rule_name.clone_from(&rule.name);
        chunk.proposed_rule = rule.encode_to_vec();
        chunk.host = "proposal.example".to_string();
        chunk.port = 443;
        state
            .store
            .put_draft_chunk(&chunk, None, "default")
            .await
            .unwrap();
        let error = handle_approve_draft_chunk(
            &state,
            with_user(Request::new(ApproveDraftChunkRequest {
                sandbox: NAME.to_string(),
                chunk_id: chunk.id.clone(),
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                ..Default::default()
            })),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert!(error.message().contains("frozen"));
        let error = handle_approve_all_draft_chunks(
            &state,
            with_user(Request::new(ApproveAllDraftChunksRequest {
                sandbox: NAME.to_string(),
                include_security_flagged: true,
                workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                ..Default::default()
            })),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert!(error.message().contains("frozen"));
        let proposed = handle_submit_policy_analysis(
            &state,
            with_sandbox(
                Request::new(SubmitPolicyAnalysisRequest {
                    name: NAME.to_string(),
                    workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                    proposed_chunks: vec![PolicyChunk {
                        rule_name: rule.name.clone(),
                        proposed_rule: Some(rule),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
                ID,
            ),
        )
        .await
        .unwrap()
        .into_inner();
        assert_eq!(proposed.accepted_chunks, 0);
        assert_eq!(proposed.rejected_chunks, 1);
        assert_eq!(
            state
                .store
                .get_draft_chunk(&chunk.id)
                .await
                .unwrap()
                .unwrap()
                .status,
            "pending"
        );
        assert_eq!(config(&state).await.policy_hash, accepted.policy_hash);

        // A writer that read before first acceptance cannot bypass the RPC
        // guard by reaching the atomic persistence boundary afterward.
        let changed = test_policy_with_rule("raced", "raced.example");
        let error = state
            .store
            .put_policy_revision_atomic(&AtomicPolicyRevisionWrite {
                id: "raced-policy".to_string(),
                sandbox_id: ID.to_string(),
                workspace: "default".to_string(),
                version: i64::from(accepted.version) + 1,
                policy_payload: changed.encode_to_vec(),
                policy_hash: deterministic_policy_hash(&changed),
                provenance: HashMap::new(),
                expected_resource_version: 0,
                annotations: HashMap::new(),
                backfill_policy: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(error, PersistenceError::Conflict { .. }));
        assert_eq!(config(&state).await.policy_hash, accepted.policy_hash);
    }

    #[tokio::test]
    async fn frozen_policy_rotates_credentials_and_withholds_incompatible_providers() {
        use openshell_core::proto::{
            ProviderCredentialTokenGrant, ProviderCredentialTokenGrantType,
        };

        for dynamic in [false, true] {
            let state = test_server_state().await;
            let mut provider = seed(&state, true).await;
            if dynamic {
                // No static keys: a same-RV replacement must still revoke the grant.
                provider.credentials.clear();
                state.store.put_message(&provider).await.unwrap();
                let mut dynamic_profile = profile("api.original.example");
                dynamic_profile.credentials[0].env_vars.clear();
                dynamic_profile.credentials[0].token_grant = Some(ProviderCredentialTokenGrant {
                    grant_type: ProviderCredentialTokenGrantType::ClientCredentials.into(),
                    token_endpoint: "https://issuer.example/token".to_string(),
                    jwt_svid_audience: "https://issuer.example".to_string(),
                    audience: "api://original".to_string(),
                    ..Default::default()
                });
                state
                    .store
                    .put_message(&crate::provider_profile_sources::stored_provider_profile(
                        dynamic_profile,
                    ))
                    .await
                    .unwrap();
            }
            let mut other_profile = profile("api.other.example");
            other_profile.id = "other-profile".to_string();
            other_profile.credentials[0].env_vars = vec!["OTHER_TOKEN".to_string()];
            state
                .store
                .put_message(&crate::provider_profile_sources::stored_provider_profile(
                    other_profile,
                ))
                .await
                .unwrap();
            let mut other = test_provider("other-provider", "other-profile");
            other.profile_workspace.clear();
            other.credentials =
                HashMap::from([("OTHER_TOKEN".to_string(), "other-token".to_string())]);
            state.store.put_message(&other).await.unwrap();
            let mut sandbox = stored_sandbox(&state).await;
            sandbox
                .spec
                .as_mut()
                .unwrap()
                .providers
                .push("other-provider".to_string());
            state.store.put_message(&sandbox).await.unwrap();
            let (accepted, _) = initialize(&state).await;
            let before = environment(&state).await;
            assert_eq!(before.dynamic_credentials.len(), usize::from(dynamic));
            if dynamic {
                let mut rotated = provider.clone();
                rotated
                    .credentials
                    .insert(TOKEN.to_string(), "rotated-token".to_string());
                state.store.put_message(&rotated).await.unwrap();
                assert_eq!(environment(&state).await.dynamic_credentials.len(), 1);
                state.store.put_message(&provider).await.unwrap();
            } else {
                provider
                    .credentials
                    .insert(TOKEN.to_string(), "rotated-token".to_string());
                crate::grpc::provider::handle_update_provider(
                    &state,
                    with_user(Request::new(UpdateProviderRequest {
                        provider: Some(provider),
                        workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
                        ..Default::default()
                    })),
                )
                .await
                .unwrap();
                provider = state
                    .store
                    .get_message_by_name::<Provider>("default", PROVIDER)
                    .await
                    .unwrap()
                    .unwrap();
                let rotated = environment(&state).await;
                assert_eq!(rotated.environment[TOKEN], "rotated-token");
                assert_ne!(rotated.provider_env_revision, before.provider_env_revision);
                assert_eq!(
                    rotated.static_credential_bindings,
                    before.static_credential_bindings
                );
                assert_eq!(rotated.policy_hash, accepted.policy_hash);
            }
            for change in ["deleted", "identity", "config", "refresh authorization"] {
                state
                    .store
                    .delete(Provider::object_type(), provider.object_id())
                    .await
                    .unwrap();
                let mut changed = provider.clone();
                match change {
                    "identity" => {
                        changed.metadata.as_mut().unwrap().id = "replacement-provider".to_string();
                    }
                    "config" => {
                        changed
                            .config
                            .insert("region".to_string(), "changed".to_string());
                    }
                    "refresh authorization" => {
                        crate::provider_refresh::put_refresh_state(
                            state.store.as_ref(),
                            &StoredProviderCredentialRefreshState {
                                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                                    id: "new-refresh-authorization".to_string(),
                                    name: crate::provider_refresh::refresh_state_name(
                                        provider.object_id(),
                                        TOKEN,
                                    ),
                                    workspace: "default".to_string(),
                                    ..Default::default()
                                }),
                                provider_id: provider.object_id().to_string(),
                                provider_name: PROVIDER.to_string(),
                                credential_key: TOKEN.to_string(),
                                authorization_epoch: "new-authorization".to_string(),
                                ..Default::default()
                            },
                        )
                        .await
                        .unwrap();
                    }
                    _ => {}
                }
                if change != "deleted" {
                    state.store.put_message(&changed).await.unwrap();
                }
                let withheld = environment(&state).await;
                assert!(
                    !withheld.environment.contains_key(TOKEN),
                    "{dynamic}/{change}"
                );
                assert!(
                    withheld.dynamic_credentials.is_empty(),
                    "{dynamic}/{change}"
                );
                assert_ne!(
                    withheld.provider_env_revision, before.provider_env_revision,
                    "{dynamic}/{change}"
                );
                let delivered = config(&state).await;
                assert_eq!(
                    withheld.provider_env_revision,
                    delivered.provider_env_revision
                );
                assert_eq!(delivered.policy_hash, accepted.policy_hash);
                assert_eq!(withheld.environment["OTHER_TOKEN"], "other-token");
                assert_eq!(
                    withheld.readiness_reason,
                    i32::from(ProviderReadinessReason::CredentialsWithheld)
                );
                if change == "identity" {
                    state
                        .store
                        .delete(Provider::object_type(), changed.object_id())
                        .await
                        .unwrap();
                }
                state.store.put_message(&provider).await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn frozen_policy_endpoint_reports_survive_source_removal_and_reconnect() {
        use openshell_core::proto::{
            EndpointObservation, EndpointResult, ReportEndpointStatusRequest,
            ReportPolicyStatusRequest,
        };

        for global in [false, true] {
            let state = test_server_state().await;
            seed(&state, true).await;
            config(&state).await; // Persist the sandbox baseline before a global override.
            let mut policy = mcp_policy_with_versions(&["2025-11-25"]);
            policy.network_policies.get_mut("mcp").unwrap().endpoints[0].host =
                "tools.original.example".to_string();
            handle_update_config(
                &state,
                with_user(Request::new(UpdateConfigRequest {
                    sandbox: if global {
                        String::new()
                    } else {
                        NAME.to_string()
                    },
                    workspace_scope: (!global)
                        .then(|| openshell_core::proto::workspace_selector("default")),
                    policy: Some(policy),
                    global,
                    ..Default::default()
                })),
            )
            .await
            .unwrap();
            let (accepted, _) = initialize(&state).await;
            let stored_profile = state
                .store
                .get_message_by_name::<StoredProviderProfile>("", PROFILE)
                .await
                .unwrap()
                .unwrap();
            state
                .store
                .delete(
                    StoredProviderProfile::object_type(),
                    stored_profile.object_id(),
                )
                .await
                .unwrap();
            // A newly configured source supplies no captured profile. Every
            // endpoint path must bypass it, including before the first load ack.
            let fetches = Arc::new(AtomicUsize::new(0));
            let mut state = Arc::try_unwrap(state).ok().unwrap();
            state.provider_profile_sources = ProviderProfileSources::from_test_snapshot_sequence(
                vec![("unavailable".to_string(), Vec::new())],
                Arc::clone(&fetches),
            );
            let state = Arc::new(state);
            update_global(&state, "global.changed.example").await;
            let delivered = config(&state).await;
            for (index, session) in ["session-one", "session-two"].into_iter().enumerate() {
                let (sender, _receiver) = tokio::sync::mpsc::channel(1);
                let (shutdown, _shutdown_receiver) = tokio::sync::oneshot::channel();
                state.supervisor_sessions.register(
                    ID.to_string(),
                    session.to_string(),
                    sender,
                    shutdown,
                );
                reset_endpoint_status_for_supervisor_session(&state, ID, session)
                    .await
                    .unwrap();
                assert!(
                    state
                        .supervisor_sessions
                        .initialize_endpoint_status_authority(ID, session)
                );
                let sandbox = stored_sandbox(&state).await;
                let endpoints = &sandbox.status.as_ref().unwrap().endpoint_statuses;
                assert_eq!(endpoints.len(), 1);
                assert_eq!(endpoints[0].host, "tools.original.example");
                let endpoint_id = endpoints[0].endpoint_id.clone();
                handle_report_endpoint_status(
                    &state,
                    with_sandbox(
                        Request::new(ReportEndpointStatusRequest {
                            sandbox_id: ID.to_string(),
                            policy_hash: accepted.policy_hash.clone(),
                            provider_env_revision: delivered.provider_env_revision,
                            supervisor_session_id: session.to_string(),
                            report_sequence: 1,
                            observations: vec![EndpointObservation {
                                endpoint_id: endpoint_id.clone(),
                                result: EndpointResult::HttpResponseReceived.into(),
                                ..Default::default()
                            }],
                            observed_endpoint_ids: vec![endpoint_id],
                            ..Default::default()
                        }),
                        ID,
                    ),
                )
                .await
                .unwrap();
                handle_report_policy_status(
                    &state,
                    with_sandbox(
                        Request::new(ReportPolicyStatusRequest {
                            sandbox_id: ID.to_string(),
                            version: accepted.version,
                            status: PolicyStatus::Loaded.into(),
                            ..Default::default()
                        }),
                        ID,
                    ),
                )
                .await
                .unwrap();
                assert_eq!(
                    stored_sandbox(&state)
                        .await
                        .status
                        .unwrap()
                        .endpoint_statuses[0]
                        .last_result,
                    i32::from(EndpointResult::HttpResponseReceived),
                    "session {index}"
                );
            }
            assert_eq!(fetches.load(Ordering::SeqCst), 0);
        }
    }
}
