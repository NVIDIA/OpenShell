// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Verify that the gateway publishes the same authority to policy and credential consumers.

use super::*;
use crate::grpc::test_support::test_server_state;
use openshell_core::proto::{
    NetworkAccessPreset, NetworkEnforcementMode, ProviderCredentialTokenGrant,
    ProviderCredentialTokenGrantAudienceOverride, ProviderProfile, ProviderProfileCredential,
};

fn profile(id: &str, path: &str) -> ProviderProfile {
    ProviderProfile {
        id: id.into(),
        display_name: id.into(),
        credentials: vec![ProviderProfileCredential {
            name: "access_token".into(),
            auth_style: "bearer".into(),
            header_name: "Authorization".into(),
            token_grant_owners: vec!["forged-profile-owner".into()],
            token_grant: Some(ProviderCredentialTokenGrant {
                token_endpoint: "https://identity.example.test/token".into(),
                audience: "default-resource".into(),
                audience_overrides: vec![ProviderCredentialTokenGrantAudienceOverride {
                    path: format!("{}/restricted/**", path.trim_end_matches("/**")),
                    audience: "restricted-resource".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        }],
        endpoints: vec![NetworkEndpoint {
            host: "api.example.test".into(),
            port: 443,
            protocol: "rest".into(),
            access: NetworkAccessPreset::ReadOnly.into(),
            enforcement: NetworkEnforcementMode::Enforce.into(),
            path: path.into(),
            token_grant_owner: "forged-endpoint-owner".into(),
            ..Default::default()
        }],
        binaries: vec![NetworkBinary {
            path: "/usr/bin/profile-client".into(),
        }],
        ..Default::default()
    }
}

async fn store_profile(state: &Arc<ServerState>, profile: ProviderProfile) {
    let mut stored = crate::provider_profile_sources::stored_provider_profile(profile);
    if let Some(existing) = state
        .store
        .get_message_by_name::<StoredProviderProfile>("", stored.object_name())
        .await
        .unwrap()
    {
        stored.metadata = existing.metadata;
    }
    state.store.put_message(&stored).await.unwrap();
}

async fn provider_sandbox(state: &Arc<ServerState>) -> Sandbox {
    let mut providers = Vec::new();
    for (name, id, path) in [
        ("team-a", "owner-a", "/alpha/**"),
        ("team_a", "owner-b", "/beta/**"),
    ] {
        store_profile(state, profile(id, path)).await;
        let mut provider = tests::test_provider(name, id);
        provider.credentials.clear();
        provider.profile_workspace.clear();
        state.store.put_message(&provider).await.unwrap();
        providers.push(name.to_string());
    }
    let sandbox = tests::test_sandbox(
        "sb-token-grant-owner",
        "token-grant-owner",
        ProtoSandboxPolicy::default(),
        providers,
    );
    state.store.put_message(&sandbox).await.unwrap();
    sandbox
}

#[tokio::test]
async fn composed_owners_survive_name_collisions_and_audience_overrides() {
    let state = test_server_state().await;
    let sandbox = provider_sandbox(&state).await;
    let config = load_sandbox_config(&state, &sandbox).await.unwrap();
    let policy = config.policy.unwrap();
    assert!(policy.network_policies.contains_key("_provider_team_a"));
    assert!(policy.network_policies.contains_key("_provider_team_a_2"));
    let environment = load_sandbox_provider_environment(&state, &sandbox, true, true)
        .await
        .unwrap();
    assert_eq!(environment.policy_hash, deterministic_policy_hash(&policy));

    for (provider, path) in [("team-a", "/alpha/**"), ("team_a", "/beta/**")] {
        let endpoint = policy
            .network_policies
            .values()
            .flat_map(|rule| &rule.endpoints)
            .find(|endpoint| endpoint.path == path)
            .unwrap();
        assert!(endpoint.token_grant_owner.starts_with("grant-owner:v1:"));
        let credentials: Vec<_> = environment
            .dynamic_credentials
            .iter()
            .filter(|(key, _)| key.ends_with(&format!("\t{provider}:access_token")))
            .collect();
        assert_eq!(
            credentials.len(),
            2,
            "default and override must retain an owner"
        );
        for (key, credential) in credentials {
            assert_eq!(
                credential.token_grant_owners.as_slice(),
                std::slice::from_ref(&endpoint.token_grant_owner)
            );
            assert!(key.contains(&endpoint.token_grant_owner));
        }
    }
    let owners: HashSet<_> = policy
        .network_policies
        .values()
        .flat_map(|rule| &rule.endpoints)
        .map(|endpoint| &endpoint.token_grant_owner)
        .collect();
    assert_eq!(owners.len(), 2, "sanitized names cannot alias providers");
}

#[tokio::test]
async fn refreshed_profile_owners_do_not_match_the_previous_policy() {
    let state = test_server_state().await;
    let sandbox = provider_sandbox(&state).await;
    let first = load_sandbox_config(&state, &sandbox)
        .await
        .unwrap()
        .policy
        .unwrap();
    let first_owner = first
        .network_policies
        .values()
        .flat_map(|rule| &rule.endpoints)
        .find(|endpoint| endpoint.path == "/alpha/**")
        .unwrap()
        .token_grant_owner
        .clone();

    let mut replacement = profile("owner-a", "/alpha/**");
    replacement.binaries[0].path = "/usr/bin/replacement-client".into();
    store_profile(&state, replacement).await;
    let environment = load_sandbox_provider_environment(&state, &sandbox, true, true)
        .await
        .unwrap();
    let replacement_policy = load_sandbox_config(&state, &sandbox)
        .await
        .unwrap()
        .policy
        .unwrap();
    let replacement_owner = &replacement_policy
        .network_policies
        .values()
        .flat_map(|rule| &rule.endpoints)
        .find(|endpoint| endpoint.path == "/alpha/**")
        .unwrap()
        .token_grant_owner;
    assert_ne!(&first_owner, replacement_owner);
    for (key, credential) in &environment.dynamic_credentials {
        if key.ends_with("\tteam-a:access_token") {
            assert_eq!(
                credential.token_grant_owners.as_slice(),
                std::slice::from_ref(replacement_owner)
            );
            assert!(!credential.token_grant_owners.contains(&first_owner));
        }
    }
}

#[tokio::test]
async fn global_policy_replaces_grant_authorities_and_preserves_profile_destinations() {
    let state = test_server_state().await;
    let sandbox = provider_sandbox(&state).await;
    let before = load_sandbox_provider_environment(&state, &sandbox, true, true)
        .await
        .unwrap();
    let mut global = ProtoSandboxPolicy {
        network_policies: HashMap::from([(
            "global_api".into(),
            NetworkPolicyRule {
                name: "global_api".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "api.example.test".into(),
                    port: 443,
                    protocol: "rest".into(),
                    path: "/**".into(),
                    access: NetworkAccessPreset::Full.into(),
                    enforcement: NetworkEnforcementMode::Enforce.into(),
                    token_grant_owner: "forged-global-owner".into(),
                    ..Default::default()
                }],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/global-client".into(),
                }],
            },
        )]),
        ..Default::default()
    };
    // Persist an untrusted stamp to exercise the gateway's clearing path.
    let settings = StoredSettings {
        revision: 1,
        settings: BTreeMap::from([(
            POLICY_SETTING_KEY.into(),
            StoredSettingValue::Bytes(hex::encode(global.encode_to_vec())),
        )]),
        ..Default::default()
    };
    save_global_settings(state.store.as_ref(), &settings)
        .await
        .unwrap();
    let config = load_sandbox_config(&state, &sandbox).await.unwrap();
    assert_eq!(config.policy_source, PolicySource::Global as i32);
    let global_provider_revision = config.provider_env_revision;
    global = config.policy.unwrap();
    assert_eq!(global.network_policies.len(), 1);
    let global_owner = &global.network_policies["global_api"].endpoints[0].token_grant_owner;
    assert_ne!(global_owner, "forged-global-owner");
    let after = load_sandbox_provider_environment(&state, &sandbox, true, true)
        .await
        .unwrap();
    assert_ne!(before.provider_env_revision, after.provider_env_revision);
    assert_eq!(global_provider_revision, after.provider_env_revision);
    assert_eq!(after.policy_hash, deterministic_policy_hash(&global));
    assert_eq!(
        after.dynamic_credentials.len(),
        before.dynamic_credentials.len()
    );
    for (key, credential) in &after.dynamic_credentials {
        assert!(
            before.dynamic_credentials.contains_key(key),
            "global rules do not widen credential selectors"
        );
        assert_eq!(
            credential.token_grant_owners.as_slice(),
            std::slice::from_ref(global_owner)
        );
        assert_ne!(
            credential.token_grant_owners,
            before.dynamic_credentials[key].token_grant_owners
        );
    }

    let previous_owner = global_owner.clone();
    global
        .network_policies
        .get_mut("global_api")
        .unwrap()
        .binaries[0]
        .path = "/usr/bin/replacement-global-client".into();
    let mut replacement_settings = load_global_settings(state.store.as_ref()).await.unwrap();
    replacement_settings.revision += 1;
    replacement_settings.settings.insert(
        POLICY_SETTING_KEY.into(),
        StoredSettingValue::Bytes(hex::encode(global.encode_to_vec())),
    );
    save_global_settings(state.store.as_ref(), &replacement_settings)
        .await
        .unwrap();
    let replacement_config = load_sandbox_config(&state, &sandbox).await.unwrap();
    let replacement_environment = load_sandbox_provider_environment(&state, &sandbox, true, true)
        .await
        .unwrap();
    assert_ne!(
        after.provider_env_revision,
        replacement_environment.provider_env_revision
    );
    assert_eq!(
        replacement_config.provider_env_revision,
        replacement_environment.provider_env_revision
    );
    assert!(
        replacement_environment
            .dynamic_credentials
            .values()
            .all(|credential| !credential.token_grant_owners.contains(&previous_owner))
    );
}
