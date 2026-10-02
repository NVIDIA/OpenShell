// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use crate::test_helpers::MockDiscoveryContext;
use crate::{
    EnvironmentProfile, ProviderTypeProfile, discover_from_profile, parse_profile_yaml,
    profile_to_yaml, validate_profile_set,
};

fn profile() -> ProviderTypeProfile {
    parse_profile_yaml(
        r"
id: custom
display_name: Custom
credentials:
  - name: token
    env_vars: [CUSTOM_TOKEN]
environment:
  config:
    CUSTOM_PROJECT: project
  fixed:
    CUSTOM_MODE: native
discovery:
  credentials: [token]
  config_env_vars: [CUSTOM_PROJECT]
required_platform_adapter: gcp-metadata
",
    )
    .unwrap()
}

#[test]
fn environment_and_discovery_declarations_round_trip() {
    let profile = profile();
    let proto = profile.to_proto();
    let restored = ProviderTypeProfile::from_proto(&proto);
    assert_eq!(restored.to_proto(), proto);
    let yaml = profile_to_yaml(&restored).unwrap();
    assert_eq!(parse_profile_yaml(&yaml).unwrap().to_proto(), proto);
    assert!(validate_profile_set(&[("custom.yaml".into(), profile)]).is_empty());
}

#[test]
fn projection_preserves_existing_values_and_skips_blank_config() {
    let profile = profile();
    let config = HashMap::from([("project".into(), "  project-a  ".into())]);
    let mut env = HashMap::new();
    profile.environment.inject(&config, &mut env);
    assert_eq!(
        env,
        HashMap::from([
            ("CUSTOM_PROJECT".into(), "project-a".into()),
            ("CUSTOM_MODE".into(), "native".into())
        ])
    );

    let mut existing = HashMap::from([
        ("CUSTOM_PROJECT".into(), String::new()),
        ("CUSTOM_MODE".into(), "caller".into()),
    ]);
    let before = existing.clone();
    profile.environment.inject(&config, &mut existing);
    assert_eq!(existing, before);

    for config in [
        HashMap::new(),
        HashMap::from([("project".into(), " \t ".into())]),
    ] {
        let mut env = HashMap::new();
        profile.environment.inject(&config, &mut env);
        assert!(!env.contains_key("CUSTOM_PROJECT"));
        assert_eq!(env["CUSTOM_MODE"], "native");
    }
}

#[test]
fn projection_skips_legacy_private_key_defaults_in_stored_profiles() {
    let mut profile = profile();
    profile.environment.config.insert(
        crate::LEGACY_VERTEX_PRIVATE_KEY_ENV.into(),
        "private_key".into(),
    );
    let config = HashMap::from([("private_key".into(), "secret".into())]);
    let mut env = HashMap::new();
    profile.environment.inject(&config, &mut env);
    assert!(!env.contains_key(crate::LEGACY_VERTEX_PRIVATE_KEY_ENV));

    profile.environment.config.clear();
    profile
        .environment
        .fixed
        .insert(crate::LEGACY_VERTEX_PRIVATE_KEY_ENV.into(), "secret".into());
    profile.environment.inject(&config, &mut env);
    assert!(!env.contains_key(crate::LEGACY_VERTEX_PRIVATE_KEY_ENV));
}

#[test]
fn renamed_google_examples_keep_environment_and_discovery_behavior() {
    let config = HashMap::from([
        ("project_id".into(), "cloud-project".into()),
        ("region".into(), "us-east1".into()),
        ("service_account_email".into(), "sa@example.com".into()),
        ("VERTEX_AI_PROJECT_ID".into(), "vertex-project".into()),
        ("VERTEX_AI_REGION".into(), "us-central1".into()),
    ]);
    let context = MockDiscoveryContext::new()
        .with_env("GOOGLE_VERTEX_AI_TOKEN", "test-token")
        .with_env("GCP_ADC_ACCESS_TOKEN", "test-adc-token")
        .with_env("VERTEX_AI_PROJECT_ID", "vertex-project")
        .with_env("VERTEX_AI_REGION", "us-central1");
    for id in ["google-cloud", "google-vertex-ai"] {
        let canonical = crate::example_profiles::load(id);
        let mut renamed = canonical.clone();
        renamed.id = "acme-fork".into();
        let mut canonical_env = HashMap::new();
        let mut renamed_env = HashMap::new();
        canonical.environment.inject(&config, &mut canonical_env);
        renamed.environment.inject(&config, &mut renamed_env);
        assert!(!canonical_env.is_empty());
        assert_eq!(canonical_env, renamed_env);
        assert_eq!(
            canonical
                .ensure_platform_adapter_available()
                .map_err(|error| error.to_string()),
            renamed
                .ensure_platform_adapter_available()
                .map_err(|error| error.to_string()),
        );
        assert_eq!(
            discover_from_profile(&canonical, &context).unwrap(),
            discover_from_profile(&renamed, &context).unwrap()
        );
    }
}

#[test]
fn canonical_id_without_declarations_has_no_special_behavior() {
    let mut profile = profile();
    profile.id = "google-vertex-ai".into();
    profile.environment = EnvironmentProfile::default();
    profile.discovery.config_env_vars.clear();
    let mut env = HashMap::new();
    profile.environment.inject(
        &HashMap::from([("VERTEX_AI_PROJECT_ID".into(), "project".into())]),
        &mut env,
    );
    assert!(env.is_empty());
    assert!(
        discover_from_profile(
            &profile,
            &MockDiscoveryContext::new().with_env("VERTEX_AI_PROJECT_ID", "project")
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn lint_rejects_non_secret_credential_collisions_and_duplicate_targets() {
    let mut profile = profile();
    profile
        .environment
        .fixed
        .insert("CUSTOM_TOKEN".into(), "value".into());
    profile
        .environment
        .fixed
        .insert("CUSTOM_PROJECT".into(), "other".into());
    profile
        .discovery
        .config_env_vars
        .push("CUSTOM_TOKEN".into());
    let diagnostics = validate_profile_set(&[("custom.yaml".into(), profile)]);
    assert!(
        diagnostics
            .iter()
            .any(|d| d.field == "environment" && d.message.contains("credential env_vars"))
    );
    assert!(
        diagnostics
            .iter()
            .any(|d| d.message.contains("both config and fixed"))
    );
    assert!(diagnostics.iter().any(
        |d| d.field == "discovery.config_env_vars" && d.message.contains("credential env_vars")
    ));
}

#[test]
fn lint_bounds_environment_and_discovery_declarations() {
    let mut profile = profile();
    profile
        .environment
        .fixed
        .insert("INVALID=NAME".into(), "value".into());
    profile
        .environment
        .fixed
        .insert("LONG_VALUE".into(), "x".repeat(4097));
    profile
        .discovery
        .config_env_vars
        .push("CUSTOM_PROJECT".into());
    profile.discovery.config_env_vars.push(" padded ".into());
    let diagnostics = validate_profile_set(&[("custom.yaml".into(), profile)]);
    assert!(diagnostics.iter().any(|d| d.field == "environment"));
    assert!(diagnostics.iter().any(|d| d.field == "environment.fixed"));
    assert!(
        diagnostics
            .iter()
            .any(|d| d.message == "duplicate discovery config key")
    );
    assert!(
        diagnostics
            .iter()
            .any(|d| d.message.contains("discovery config keys must"))
    );
}

#[test]
fn lint_enforces_declaration_count_limits() {
    let mut profile = profile();
    profile.environment.config.clear();
    profile.environment.fixed = (0..64)
        .map(|index| (format!("CONFIG_{index}"), String::new()))
        .collect();
    profile.discovery.config_env_vars = profile.environment.fixed.keys().cloned().collect();
    assert!(validate_profile_set(&[("custom.yaml".into(), profile.clone())]).is_empty());

    profile
        .environment
        .config
        .insert("EXTRA".into(), "extra".into());
    profile.discovery.config_env_vars.push("EXTRA".into());
    let diagnostics = validate_profile_set(&[("custom.yaml".into(), profile)]);
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message == "at most 64 environment defaults are allowed")
    );
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message == "at most 64 discovery config keys are allowed")
    );
}

#[test]
fn platform_adapter_availability_and_unknown_adapter_errors() {
    let mut profile = profile();
    let availability = profile.ensure_platform_adapter_available();
    if cfg!(windows) {
        assert!(
            availability
                .unwrap_err()
                .to_string()
                .contains("unavailable")
        );
    } else {
        assert!(availability.is_ok());
    }
    profile.required_platform_adapter = "unknown".repeat(10_000);
    let diagnostics = validate_profile_set(&[("custom.yaml".into(), profile.clone())]);
    assert!(
        diagnostics
            .iter()
            .any(|d| d.field == "required_platform_adapter")
    );
    assert!(diagnostics.iter().all(|d| d.message.len() < 256));
    assert!(
        profile
            .ensure_platform_adapter_available()
            .unwrap_err()
            .to_string()
            .len()
            < 128
    );
    profile.required_platform_adapter.clear();
    assert!(profile.ensure_platform_adapter_available().is_ok());
}
