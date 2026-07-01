// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use serde_json::json;

fn service() -> GovernanceInterceptorService {
    let profiles = load_provider_profiles(&default_profiles_path()).unwrap();
    GovernanceInterceptorService::from_profiles(profiles).unwrap()
}

fn evaluation(
    method: &str,
    phase: GatewayInterceptorPhase,
    operation: Value,
) -> InterceptorEvaluation {
    InterceptorEvaluation {
        interceptor_name: "test".to_string(),
        binding_id: "binding".to_string(),
        service: SERVICE.to_string(),
        method: method.to_string(),
        phase: phase as i32,
        operation: Some(json_to_struct(&operation).unwrap()),
        current_state: Some(Struct::default()),
        principal: HashMap::new(),
    }
}

fn managed_profile_ids(service: &GovernanceInterceptorService) -> Vec<String> {
    service.current_profile_state().ids
}

fn policy_state(service: &GovernanceInterceptorService) -> PolicyState {
    service.current_policy_state()
}

fn assert_signed_profile(service: &GovernanceInterceptorService, profile: &ProviderProfile) {
    let profile_hash = profile
        .annotations
        .get(PROFILE_HASH_ANNOTATION)
        .expect("profile hash annotation");
    assert_eq!(profile_hash, &deterministic_profile_hash(profile));
    assert_eq!(
        profile
            .annotations
            .get(PROFILE_SIGNATURE_KID_ANNOTATION)
            .map(String::as_str),
        Some(service.policy_signer.kid())
    );
    let profile_signature = profile
        .annotations
        .get(PROFILE_SIGNATURE_ANNOTATION)
        .expect("profile signature annotation");
    service
        .policy_signer
        .verify_profile_signature(profile_signature, &profile.id, profile_hash)
        .expect("profile signature verifies");
}

fn governed_create_operation(
    service: &GovernanceInterceptorService,
    policy: Value,
    signature: String,
) -> Value {
    governed_create_operation_with_providers(policy, signature, managed_profile_ids(service))
}

fn governed_create_operation_with_providers(
    policy: Value,
    signature: String,
    providers: Vec<String>,
) -> Value {
    let mut operation = json!({
        "spec": {
            "policy": policy,
            "providers": providers,
        },
        "annotations": {},
    });
    operation
        .pointer_mut("/annotations")
        .and_then(Value::as_object_mut)
        .unwrap()
        .insert(
            POLICY_SIGNATURE_ANNOTATION.to_string(),
            Value::String(signature),
        );
    operation
}

fn signature_patch_token(result: &InterceptorResult) -> String {
    result
        .patches
        .iter()
        .find(|patch| {
            patch.path == "/annotations/openshell.nvidia.com~1policy-signature"
                || patch.path == "/annotations"
        })
        .and_then(|patch| patch.value.as_ref())
        .map(proto_value_to_json)
        .and_then(|value| {
            value.as_str().map(ToString::to_string).or_else(|| {
                value
                    .pointer(&format!(
                        "/{}",
                        json_pointer_escape(POLICY_SIGNATURE_ANNOTATION)
                    ))
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            })
        })
        .expect("signature patch value")
}

fn policy_yaml_with_dynamic_rule() -> String {
    let policy = include_str!("../policy.yaml");
    let changed = policy
        .replace("api-1.example.com", "api-2.example.com")
        .replace("api.example.com", "api.changed.example.com");
    if changed != policy {
        return changed;
    }

    policy.replace(
        "network_policies: {}",
        r#"network_policies:
  example_api:
name: example-api
endpoints:
- host: example.com
  port: 443
  protocol: rest
  enforcement: enforce
  access: read-only"#,
    )
}

#[test]
fn manifest_declares_governance_bindings() {
    let service = service();
    let manifest = service.manifest();
    let ids: Vec<_> = manifest
        .bindings
        .iter()
        .map(|binding| binding.id.as_str())
        .collect();
    assert!(ids.contains(&"govern-import-provider-profiles"));
    assert!(ids.contains(&"govern-update-provider-profiles"));
    assert!(ids.contains(&"govern-delete-provider-profile"));
    assert!(ids.contains(&"govern-update-config"));
    assert!(ids.contains(&"govern-create-sandbox"));
    assert!(!ids.contains(&"govern-attach-provider"));
    assert!(!ids.contains(&"govern-detach-provider"));
    assert!(!ids.contains(&"govern-update-provider"));
    assert!(!ids.contains(&"govern-delete-provider"));
    assert_eq!(manifest.failure_policy, "fail_closed");
    assert!(manifest.provider_profiles);
}

#[tokio::test]
async fn snapshot_provider_profiles_returns_current_profiles() {
    let service = service();
    let snapshot = service
        .snapshot_provider_profiles(Request::new(ProviderProfileSnapshotRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert!(!snapshot.revision.is_empty());
    let profile_ids = snapshot
        .profiles
        .iter()
        .map(|profile| profile.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(profile_ids, vec!["github", "slack"]);
    for profile in &snapshot.profiles {
        assert_signed_profile(&service, profile);
    }
}

#[test]
fn profile_loader_uses_file_name_as_profile_id() {
    let loaded = load_provider_profile_source(
        "profiles/example-api.yaml",
        r#"
id: ignored
display_name: Example API
description: Example profile
credentials: []
endpoints: []
binaries: []
"#,
        "example-api",
    )
    .unwrap();
    assert_eq!(loaded.profile.id, "example-api");

    let loaded = load_provider_profile_source(
        "profiles/no-id.yaml",
        r#"
display_name: No ID
description: Filename supplies the profile id
credentials: []
endpoints: []
binaries: []
"#,
        "no-id",
    )
    .unwrap();
    assert_eq!(loaded.profile.id, "no-id");
}

#[test]
fn create_sandbox_modify_adds_policy_and_signature_without_replacing_providers() {
    let service = service();
    let result = service
        .evaluate_inner(&evaluation(
            "CreateSandbox",
            GatewayInterceptorPhase::ModifyOperation,
            json!({
                "name": "demo",
                "spec": {"providers": ["github"]},
                "labels": {"team": "platform"},
            }),
        ))
        .unwrap();

    assert!(result.allowed);
    let paths: Vec<_> = result
        .patches
        .iter()
        .map(|patch| patch.path.as_str())
        .collect();
    assert!(paths.contains(&"/spec/policy"));
    assert!(!paths.contains(&"/spec/providers"));
    assert!(
        paths.contains(&"/annotations")
            || paths.contains(&"/annotations/openshell.nvidia.com~1policy-signature")
    );
    let token = signature_patch_token(&result);
    assert_eq!(token.split('.').count(), 3);
    assert_eq!(
        result
            .log_annotations
            .get("correlation_id")
            .map(String::as_str),
        Some("governance:create-sandbox:demo")
    );
    assert!(result.log_annotations.contains_key("policy_hash"));
    assert!(result.log_annotations.contains_key("policy_signature_kid"));
    assert!(!result.log_annotations.contains_key("policy_signature"));
}

#[test]
fn create_sandbox_validate_accepts_selected_provider_subset() {
    let service = service();
    let state = policy_state(&service);
    let result = service
        .evaluate_inner(&evaluation(
            "CreateSandbox",
            GatewayInterceptorPhase::Validate,
            governed_create_operation_with_providers(
                state.policy.clone(),
                state.policy_signature.clone(),
                vec!["github".to_string()],
            ),
        ))
        .unwrap();
    assert!(result.allowed);
}

#[test]
fn create_sandbox_validate_accepts_missing_provider_list() {
    let service = service();
    let state = policy_state(&service);
    let mut operation = json!({
        "spec": {
            "policy": state.policy.clone(),
        },
        "annotations": {},
    });
    operation
        .pointer_mut("/annotations")
        .and_then(Value::as_object_mut)
        .unwrap()
        .insert(
            POLICY_SIGNATURE_ANNOTATION.to_string(),
            Value::String(state.policy_signature.clone()),
        );

    let result = service
        .evaluate_inner(&evaluation(
            "CreateSandbox",
            GatewayInterceptorPhase::Validate,
            operation,
        ))
        .unwrap();
    assert!(result.allowed);
}

#[test]
fn create_sandbox_validate_denies_unmanaged_provider() {
    let service = service();
    let state = policy_state(&service);
    let result = service
        .evaluate_inner(&evaluation(
            "CreateSandbox",
            GatewayInterceptorPhase::Validate,
            governed_create_operation_with_providers(
                state.policy.clone(),
                state.policy_signature.clone(),
                vec!["github".to_string(), "teams".to_string()],
            ),
        ))
        .unwrap();
    assert!(!result.allowed);
    assert!(
        result
            .reason
            .contains("sandbox providers may only use vended provider profiles")
    );
}

#[test]
fn create_sandbox_validate_denies_missing_signature() {
    let service = service();
    let state = policy_state(&service);
    let result = service
        .evaluate_inner(&evaluation(
            "CreateSandbox",
            GatewayInterceptorPhase::Validate,
            json!({
                "spec": {
                    "policy": state.policy,
                    "providers": managed_profile_ids(&service),
                },
            }),
        ))
        .unwrap();
    assert!(!result.allowed);
    assert!(result.reason.contains("missing"));
}

#[test]
fn create_sandbox_validate_denies_malformed_signature() {
    let service = service();
    let state = policy_state(&service);
    let result = service
        .evaluate_inner(&evaluation(
            "CreateSandbox",
            GatewayInterceptorPhase::Validate,
            governed_create_operation(&service, state.policy.clone(), "not-a-jwt".to_string()),
        ))
        .unwrap();
    assert!(!result.allowed);
    assert!(result.reason.contains("signature"));
}

#[test]
fn create_sandbox_validate_denies_signature_from_other_key() {
    let governance = service();
    let other = service();
    let governance_state = policy_state(&governance);
    let other_state = policy_state(&other);
    let result = governance
        .evaluate_inner(&evaluation(
            "CreateSandbox",
            GatewayInterceptorPhase::Validate,
            governed_create_operation(
                &governance,
                governance_state.policy.clone(),
                other_state.policy_signature,
            ),
        ))
        .unwrap();
    assert!(!result.allowed);
    assert!(result.reason.contains("signature"));
}

#[test]
fn create_sandbox_validate_denies_signed_policy_mismatch() {
    let service = service();
    let state = policy_state(&service);
    let mut tampered_policy = state.policy.clone();
    tampered_policy
        .as_object_mut()
        .unwrap()
        .insert("version".to_string(), json!(999));
    let result = service
        .evaluate_inner(&evaluation(
            "CreateSandbox",
            GatewayInterceptorPhase::Validate,
            governed_create_operation(&service, tampered_policy, state.policy_signature.clone()),
        ))
        .unwrap();
    assert!(!result.allowed);
    assert!(result.reason.contains("signature"));
}

#[test]
fn policy_patch_uses_protobuf_json_names() {
    let service = service();
    let state = policy_state(&service);
    assert!(state.policy.get("filesystem").is_some());
    assert!(state.policy.get("networkPolicies").is_some());
    assert!(state.policy.get("filesystem_policy").is_none());
    assert!(state.policy.get("network_policies").is_none());
}

#[test]
fn policy_reload_updates_hash_and_preserves_last_valid_state_on_error() {
    let service = service();
    let before = policy_state(&service);
    let changed = service
        .reload_policy_from_yaml(&policy_yaml_with_dynamic_rule())
        .unwrap()
        .expect("policy hash should change");
    assert_ne!(before.policy_hash, changed.policy_hash);
    assert_eq!(policy_state(&service).policy_hash, changed.policy_hash);

    let err = service
        .reload_policy_from_yaml("version: not-a-number")
        .expect_err("invalid policy should be rejected");
    assert!(err.contains("failed to parse policy YAML"));
    assert_eq!(policy_state(&service).policy_hash, changed.policy_hash);
}

#[test]
fn signed_governance_policy_update_is_allowed() {
    let service = service();
    let state = policy_state(&service);
    let result = service
        .evaluate_inner(&evaluation(
            "UpdateConfig",
            GatewayInterceptorPhase::Validate,
            json!({
                "name": "demo",
                "policy": state.policy.clone(),
                "annotations": policy_update_annotations(&state, "governance:reload-policy:test"),
            }),
        ))
        .unwrap();
    assert!(result.allowed);
}

#[test]
fn stale_governance_policy_update_is_denied_after_reload() {
    let service = service();
    let stale = policy_state(&service);
    let changed = service
        .reload_policy_from_yaml(&policy_yaml_with_dynamic_rule())
        .unwrap()
        .expect("policy hash should change");
    assert_ne!(stale.policy_hash, changed.policy_hash);

    let result = service
        .evaluate_inner(&evaluation(
            "UpdateConfig",
            GatewayInterceptorPhase::Validate,
            json!({
                "name": "demo",
                "policy": stale.policy.clone(),
                "annotations": policy_update_annotations(&stale, "governance:reload-policy:stale"),
            }),
        ))
        .unwrap();
    assert!(!result.allowed);
    assert!(result.reason.contains("stale"));
}

#[test]
fn provider_creation_is_limited_to_vended_profiles() {
    let service = service();
    let github = service
        .evaluate_inner(&evaluation(
            "CreateProvider",
            GatewayInterceptorPhase::Validate,
            json!({"provider": {"metadata": {"name": "work-github"}, "type": "github"}}),
        ))
        .unwrap();
    assert!(github.allowed);

    let slack = service
        .evaluate_inner(&evaluation(
            "CreateProvider",
            GatewayInterceptorPhase::Validate,
            json!({"provider": {"metadata": {"name": "team-chat"}, "type": "slack"}}),
        ))
        .unwrap();
    assert!(slack.allowed);

    let teams = service
        .evaluate_inner(&evaluation(
            "CreateProvider",
            GatewayInterceptorPhase::Validate,
            json!({"provider": {"metadata": {"name": "teams"}, "type": "teams"}}),
        ))
        .unwrap();
    assert!(!teams.allowed);
    assert!(
        teams
            .reason
            .contains("providers may only use vended provider profiles")
    );
}

#[test]
fn provider_profile_import_is_limited_to_governed_profiles() {
    let service = service();
    let result = service
        .evaluate_inner(&evaluation(
            "ImportProviderProfiles",
            GatewayInterceptorPhase::Validate,
            json!({
                "profiles": [
                    {"profile": {"id": "github"}},
                    {"profile": {"id": "slack"}}
                ]
            }),
        ))
        .unwrap();
    assert!(result.allowed);

    let result = service
        .evaluate_inner(&evaluation(
            "ImportProviderProfiles",
            GatewayInterceptorPhase::Validate,
            json!({"profiles": [{"profile": {"id": "custom-slack"}}]}),
        ))
        .unwrap();
    assert!(!result.allowed);
}

#[test]
fn provider_profile_update_is_limited_to_matching_governed_profiles() {
    let service = service();
    let result = service
        .evaluate_inner(&evaluation(
            "UpdateProviderProfiles",
            GatewayInterceptorPhase::Validate,
            json!({
                "id": "slack",
                "profile": {"profile": {"id": "slack"}}
            }),
        ))
        .unwrap();
    assert!(result.allowed);

    let result = service
        .evaluate_inner(&evaluation(
            "UpdateProviderProfiles",
            GatewayInterceptorPhase::Validate,
            json!({
                "id": "slack",
                "profile": {"profile": {"id": "github"}}
            }),
        ))
        .unwrap();
    assert!(!result.allowed);

    let result = service
        .evaluate_inner(&evaluation(
            "UpdateProviderProfiles",
            GatewayInterceptorPhase::Validate,
            json!({
                "id": "custom-slack",
                "profile": {"profile": {"id": "custom-slack"}}
            }),
        ))
        .unwrap();
    assert!(!result.allowed);
}

#[test]
fn provider_profile_delete_is_denied() {
    let service = service();
    let result = service
        .evaluate_inner(&evaluation(
            "DeleteProviderProfile",
            GatewayInterceptorPhase::Validate,
            json!({"id": "github"}),
        ))
        .unwrap();
    assert!(!result.allowed);
    assert!(result.reason.contains("deletes are blocked"));
}

#[test]
fn provider_update_and_delete_are_not_governed() {
    let service = service();
    let update = service
        .evaluate_inner(&evaluation(
            "UpdateProvider",
            GatewayInterceptorPhase::Validate,
            json!({"provider": {"metadata": {"name": "slack"}}}),
        ))
        .unwrap();
    assert!(update.allowed);

    let delete = service
        .evaluate_inner(&evaluation(
            "DeleteProvider",
            GatewayInterceptorPhase::Validate,
            json!({"name": "github"}),
        ))
        .unwrap();
    assert!(delete.allowed);
}

#[test]
fn policy_update_and_merge_are_denied() {
    let service = service();
    for operation in [
        json!({"name": "demo", "policy": {"version": 1}}),
        json!({"name": "demo", "mergeOperations": [{"op": "add"}]}),
        json!({"name": "demo", "merge_operations": [{"op": "add"}]}),
    ] {
        let result = service
            .evaluate_inner(&evaluation(
                "UpdateConfig",
                GatewayInterceptorPhase::Validate,
                operation,
            ))
            .unwrap();
        assert!(!result.allowed);
    }

    let settings_update = service
        .evaluate_inner(&evaluation(
            "UpdateConfig",
            GatewayInterceptorPhase::Validate,
            json!({"global": true, "settingKey": "providers_v2_enabled"}),
        ))
        .unwrap();
    assert!(settings_update.allowed);

    let global_policy_update = service
        .evaluate_inner(&evaluation(
            "UpdateConfig",
            GatewayInterceptorPhase::Validate,
            json!({"global": true, "policy": {"version": 1}}),
        ))
        .unwrap();
    assert!(global_policy_update.allowed);

    let mut sandbox_policy_sync = evaluation(
        "UpdateConfig",
        GatewayInterceptorPhase::Validate,
        json!({"name": "demo", "policy": {"version": 1}}),
    );
    sandbox_policy_sync
        .principal
        .insert("kind".to_string(), "sandbox".to_string());
    sandbox_policy_sync
        .principal
        .insert("sandbox_id".to_string(), "demo-id".to_string());
    let sandbox_policy_sync = service.evaluate_inner(&sandbox_policy_sync).unwrap();
    assert!(sandbox_policy_sync.allowed);
}
