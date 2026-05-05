// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Declarative provider type profiles.

#![allow(deprecated)] // NetworkBinary::harness remains in the public proto for compatibility.

use openshell_core::proto::{
    NetworkBinary, NetworkEndpoint, NetworkPolicyRule, ProviderProfile, ProviderProfileCategory,
    ProviderProfileCredential,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::collections::HashSet;
use std::sync::OnceLock;

const BUILT_IN_PROFILE_YAMLS: &[&str] = &[
    include_str!("../../../providers/anthropic.yaml"),
    include_str!("../../../providers/claude.yaml"),
    include_str!("../../../providers/codex.yaml"),
    include_str!("../../../providers/copilot.yaml"),
    include_str!("../../../providers/github.yaml"),
    include_str!("../../../providers/gitlab.yaml"),
    include_str!("../../../providers/nvidia.yaml"),
    include_str!("../../../providers/openai.yaml"),
    include_str!("../../../providers/opencode.yaml"),
    include_str!("../../../providers/outlook.yaml"),
];

#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("failed to parse provider profile YAML: {0}")]
    Parse(#[from] serde_yml::Error),
    #[error("failed to parse provider profile JSON: {0}")]
    JsonParse(#[from] serde_json::Error),
    #[error("provider profile id is required")]
    MissingId,
    #[error("duplicate provider profile id: {0}")]
    DuplicateId(String),
    #[error("provider profile '{id}' has invalid endpoint '{host}:{port}'")]
    InvalidEndpoint { id: String, host: String, port: u32 },
    #[error("provider profile '{id}' has duplicate credential env var '{env_var}'")]
    DuplicateCredentialEnvVar { id: String, env_var: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileValidationDiagnostic {
    pub source: String,
    pub profile_id: String,
    pub field: String,
    pub message: String,
    pub severity: String,
}

impl ProfileValidationDiagnostic {
    fn error(
        source: impl Into<String>,
        profile_id: impl Into<String>,
        field: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            source: source.into(),
            profile_id: profile_id.into(),
            field: field.into(),
            message: message.into(),
            severity: "error".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialProfile {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub env_vars: Vec<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub auth_style: String,
    #[serde(default)]
    pub header_name: String,
    #[serde(default)]
    pub query_param: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct EndpointProfile {
    pub host: String,
    pub port: u32,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub access: String,
    #[serde(default)]
    pub enforcement: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProviderTypeProfile {
    pub id: String,
    pub display_name: String,
    #[serde(default)]
    pub description: String,
    #[serde(
        default = "default_category",
        deserialize_with = "deserialize_category",
        serialize_with = "serialize_category"
    )]
    pub category: ProviderProfileCategory,
    #[serde(default)]
    pub credentials: Vec<CredentialProfile>,
    #[serde(default)]
    pub endpoints: Vec<EndpointProfile>,
    #[serde(default)]
    pub binaries: Vec<String>,
    #[serde(default)]
    pub inference_capable: bool,
}

impl ProviderTypeProfile {
    #[must_use]
    pub fn from_proto(profile: &ProviderProfile) -> Self {
        Self {
            id: profile.id.clone(),
            display_name: profile.display_name.clone(),
            description: profile.description.clone(),
            category: ProviderProfileCategory::try_from(profile.category)
                .unwrap_or(ProviderProfileCategory::Other),
            credentials: profile
                .credentials
                .iter()
                .map(|credential| CredentialProfile {
                    name: credential.name.clone(),
                    description: credential.description.clone(),
                    env_vars: credential.env_vars.clone(),
                    required: credential.required,
                    auth_style: credential.auth_style.clone(),
                    header_name: credential.header_name.clone(),
                    query_param: credential.query_param.clone(),
                })
                .collect(),
            endpoints: profile.endpoints.iter().map(endpoint_from_proto).collect(),
            binaries: profile
                .binaries
                .iter()
                .map(|binary| binary.path.clone())
                .collect(),
            inference_capable: profile.inference_capable,
        }
    }

    #[must_use]
    pub fn credential_env_vars(&self) -> Vec<&str> {
        let mut vars = Vec::new();
        for credential in &self.credentials {
            for env_var in &credential.env_vars {
                if !vars.contains(&env_var.as_str()) {
                    vars.push(env_var.as_str());
                }
            }
        }
        vars
    }

    #[must_use]
    pub fn to_proto(&self) -> ProviderProfile {
        ProviderProfile {
            id: self.id.clone(),
            display_name: self.display_name.clone(),
            description: self.description.clone(),
            category: self.category as i32,
            credentials: self
                .credentials
                .iter()
                .map(|credential| ProviderProfileCredential {
                    name: credential.name.clone(),
                    description: credential.description.clone(),
                    env_vars: credential.env_vars.clone(),
                    required: credential.required,
                    auth_style: credential.auth_style.clone(),
                    header_name: credential.header_name.clone(),
                    query_param: credential.query_param.clone(),
                })
                .collect(),
            endpoints: self.endpoints.iter().map(endpoint_to_proto).collect(),
            binaries: self
                .binaries
                .iter()
                .map(|path| NetworkBinary {
                    path: path.clone(),
                    harness: false,
                })
                .collect(),
            inference_capable: self.inference_capable,
        }
    }

    #[must_use]
    pub fn network_policy_rule(&self, rule_name: &str) -> NetworkPolicyRule {
        NetworkPolicyRule {
            name: rule_name.to_string(),
            endpoints: self.endpoints.iter().map(endpoint_to_proto).collect(),
            binaries: self
                .binaries
                .iter()
                .map(|path| NetworkBinary {
                    path: path.clone(),
                    harness: false,
                })
                .collect(),
        }
    }
}

fn default_category() -> ProviderProfileCategory {
    ProviderProfileCategory::Other
}

fn deserialize_category<'de, D>(deserializer: D) -> Result<ProviderProfileCategory, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    provider_profile_category_from_yaml(&raw)
        .ok_or_else(|| de::Error::custom(format!("unsupported provider profile category: {raw}")))
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn serialize_category<S>(
    category: &ProviderProfileCategory,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(provider_profile_category_to_yaml(*category))
}

#[must_use]
pub fn provider_profile_category_from_yaml(raw: &str) -> Option<ProviderProfileCategory> {
    match raw.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "" | "other" => Some(ProviderProfileCategory::Other),
        "inference" => Some(ProviderProfileCategory::Inference),
        "agent" => Some(ProviderProfileCategory::Agent),
        "source_control" => Some(ProviderProfileCategory::SourceControl),
        "messaging" => Some(ProviderProfileCategory::Messaging),
        "data" => Some(ProviderProfileCategory::Data),
        "knowledge" => Some(ProviderProfileCategory::Knowledge),
        _ => None,
    }
}

#[must_use]
pub fn provider_profile_category_to_yaml(category: ProviderProfileCategory) -> &'static str {
    match category {
        ProviderProfileCategory::Inference => "inference",
        ProviderProfileCategory::Agent => "agent",
        ProviderProfileCategory::SourceControl => "source_control",
        ProviderProfileCategory::Messaging => "messaging",
        ProviderProfileCategory::Data => "data",
        ProviderProfileCategory::Knowledge => "knowledge",
        ProviderProfileCategory::Other | ProviderProfileCategory::Unspecified => "other",
    }
}

fn endpoint_to_proto(endpoint: &EndpointProfile) -> NetworkEndpoint {
    NetworkEndpoint {
        host: endpoint.host.clone(),
        port: endpoint.port,
        protocol: endpoint.protocol.clone(),
        tls: String::new(),
        enforcement: endpoint.enforcement.clone(),
        access: endpoint.access.clone(),
        rules: Vec::new(),
        allowed_ips: Vec::new(),
        ports: Vec::new(),
        deny_rules: Vec::new(),
        allow_encoded_slash: false,
        ..Default::default()
    }
}

fn endpoint_from_proto(endpoint: &NetworkEndpoint) -> EndpointProfile {
    let port = if endpoint.port != 0 {
        endpoint.port
    } else {
        endpoint.ports.first().copied().unwrap_or_default()
    };
    EndpointProfile {
        host: endpoint.host.clone(),
        port,
        protocol: endpoint.protocol.clone(),
        access: endpoint.access.clone(),
        enforcement: endpoint.enforcement.clone(),
    }
}

pub fn parse_profile_yaml(input: &str) -> Result<ProviderTypeProfile, ProfileError> {
    Ok(serde_yml::from_str::<ProviderTypeProfile>(input)?)
}

pub fn parse_profile_json(input: &str) -> Result<ProviderTypeProfile, ProfileError> {
    Ok(serde_json::from_str::<ProviderTypeProfile>(input)?)
}

pub fn profile_to_yaml(profile: &ProviderTypeProfile) -> Result<String, ProfileError> {
    Ok(serde_yml::to_string(profile)?)
}

pub fn profile_to_json(profile: &ProviderTypeProfile) -> Result<String, ProfileError> {
    Ok(serde_json::to_string_pretty(profile)?)
}

pub fn profiles_to_yaml(profiles: &[ProviderTypeProfile]) -> Result<String, ProfileError> {
    Ok(serde_yml::to_string(profiles)?)
}

pub fn profiles_to_json(profiles: &[ProviderTypeProfile]) -> Result<String, ProfileError> {
    Ok(serde_json::to_string_pretty(profiles)?)
}

pub fn parse_profile_catalog_yamls(
    inputs: &[&str],
) -> Result<Vec<ProviderTypeProfile>, ProfileError> {
    let mut profiles = inputs
        .iter()
        .map(|input| parse_profile_yaml(input))
        .collect::<Result<Vec<_>, _>>()?;
    validate_profiles(&profiles)?;
    profiles.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(profiles)
}

fn validate_profiles(profiles: &[ProviderTypeProfile]) -> Result<(), ProfileError> {
    let diagnostics = validate_profile_set(
        &profiles
            .iter()
            .map(|profile| (String::new(), profile.clone()))
            .collect::<Vec<_>>(),
    );
    if let Some(diagnostic) = diagnostics.first() {
        if diagnostic.field == "id" && diagnostic.message == "provider profile id is required" {
            return Err(ProfileError::MissingId);
        }
        if diagnostic.field == "id"
            && diagnostic
                .message
                .starts_with("duplicate provider profile id")
        {
            return Err(ProfileError::DuplicateId(diagnostic.profile_id.clone()));
        }
        if diagnostic.field.starts_with("credentials.env_vars") {
            return Err(ProfileError::DuplicateCredentialEnvVar {
                id: diagnostic.profile_id.clone(),
                env_var: diagnostic
                    .message
                    .trim_start_matches("duplicate credential env var '")
                    .trim_end_matches('\'')
                    .to_string(),
            });
        }
        if diagnostic.field.starts_with("endpoints")
            && let Some(profile) = profiles
                .iter()
                .find(|profile| profile.id == diagnostic.profile_id)
            && let Some(endpoint) = profile.endpoints.iter().find(|endpoint| {
                endpoint.host.trim().is_empty() || endpoint.port == 0 || endpoint.port > 65_535
            })
        {
            return Err(ProfileError::InvalidEndpoint {
                id: profile.id.clone(),
                host: endpoint.host.clone(),
                port: endpoint.port,
            });
        }
    }

    Ok(())
}

#[must_use]
pub fn validate_profile_set(
    profiles: &[(String, ProviderTypeProfile)],
) -> Vec<ProfileValidationDiagnostic> {
    let mut diagnostics = Vec::new();
    let mut ids = HashSet::new();
    for (source, profile) in profiles {
        let profile_id = profile.id.trim();
        if profile_id.is_empty() {
            diagnostics.push(ProfileValidationDiagnostic::error(
                source,
                "",
                "id",
                "provider profile id is required",
            ));
        } else if !ids.insert(profile_id.to_string()) {
            diagnostics.push(ProfileValidationDiagnostic::error(
                source,
                profile_id,
                "id",
                format!("duplicate provider profile id: {profile_id}"),
            ));
        }

        let mut credential_names = HashSet::new();
        for credential in &profile.credentials {
            let credential_name = credential.name.trim();
            if credential_name.is_empty() {
                diagnostics.push(ProfileValidationDiagnostic::error(
                    source,
                    profile_id,
                    "credentials.name",
                    "credential name is required",
                ));
            } else if !credential_names.insert(credential_name.to_string()) {
                diagnostics.push(ProfileValidationDiagnostic::error(
                    source,
                    profile_id,
                    "credentials.name",
                    format!("duplicate credential name: {credential_name}"),
                ));
            }
        }

        let mut env_vars = HashSet::new();
        for credential in &profile.credentials {
            for env_var in &credential.env_vars {
                if env_var.trim().is_empty() {
                    diagnostics.push(ProfileValidationDiagnostic::error(
                        source,
                        profile_id,
                        "credentials.env_vars",
                        "credential env var must not be empty",
                    ));
                } else if !env_vars.insert(env_var.trim().to_string()) {
                    diagnostics.push(ProfileValidationDiagnostic::error(
                        source,
                        profile_id,
                        "credentials.env_vars",
                        format!("duplicate credential env var '{env_var}'"),
                    ));
                }
            }

            let auth_style = credential.auth_style.trim().to_ascii_lowercase();
            match auth_style.as_str() {
                "" | "basic" => {}
                "bearer" | "header" => {
                    if credential.header_name.trim().is_empty() {
                        diagnostics.push(ProfileValidationDiagnostic::error(
                            source,
                            profile_id,
                            "credentials.header_name",
                            format!("header_name is required for {auth_style} auth"),
                        ));
                    }
                }
                "query" => {
                    if credential.query_param.trim().is_empty() {
                        diagnostics.push(ProfileValidationDiagnostic::error(
                            source,
                            profile_id,
                            "credentials.query_param",
                            "query_param is required for query auth",
                        ));
                    }
                }
                _ => diagnostics.push(ProfileValidationDiagnostic::error(
                    source,
                    profile_id,
                    "credentials.auth_style",
                    format!("unsupported auth_style: {}", credential.auth_style),
                )),
            }
        }

        for (index, endpoint) in profile.endpoints.iter().enumerate() {
            if endpoint.host.trim().is_empty() || endpoint.port == 0 || endpoint.port > 65_535 {
                diagnostics.push(ProfileValidationDiagnostic::error(
                    source,
                    profile_id,
                    format!("endpoints[{index}]"),
                    format!("invalid endpoint '{}:{}'", endpoint.host, endpoint.port),
                ));
            }
        }

        for (index, binary) in profile.binaries.iter().enumerate() {
            if binary.trim().is_empty() {
                diagnostics.push(ProfileValidationDiagnostic::error(
                    source,
                    profile_id,
                    format!("binaries[{index}]"),
                    "binary path must not be empty",
                ));
            }
        }
    }
    diagnostics
}

static DEFAULT_PROFILES: OnceLock<Vec<ProviderTypeProfile>> = OnceLock::new();

#[must_use]
pub fn default_profiles() -> &'static [ProviderTypeProfile] {
    DEFAULT_PROFILES
        .get_or_init(|| {
            parse_profile_catalog_yamls(BUILT_IN_PROFILE_YAMLS)
                .expect("built-in provider profiles must be valid YAML")
        })
        .as_slice()
}

#[must_use]
pub fn get_default_profile(id: &str) -> Option<&'static ProviderTypeProfile> {
    default_profiles()
        .iter()
        .find(|profile| profile.id.eq_ignore_ascii_case(id))
}

#[cfg(test)]
mod tests {
    use openshell_core::proto::ProviderProfileCategory;

    use super::{
        ProfileError, default_profiles, get_default_profile, parse_profile_catalog_yamls,
        parse_profile_json, parse_profile_yaml, profile_to_json, validate_profile_set,
    };

    #[test]
    fn default_profiles_are_sorted_by_id() {
        let ids = default_profiles()
            .iter()
            .map(|profile| profile.id.as_str())
            .collect::<Vec<_>>();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn github_profile_materializes_policy_metadata() {
        let profile = get_default_profile("github").expect("github profile");
        let proto = profile.to_proto();

        assert_eq!(proto.id, "github");
        assert_eq!(
            proto.category,
            ProviderProfileCategory::SourceControl as i32
        );
        assert_eq!(proto.endpoints.len(), 2);
        assert_eq!(proto.binaries.len(), 4);
    }

    #[test]
    fn credential_env_vars_are_deduplicated_in_profile_order() {
        let profile = get_default_profile("copilot").expect("copilot profile");
        assert_eq!(
            profile.credential_env_vars(),
            vec!["COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"]
        );
    }

    #[test]
    fn parse_profile_yaml_reads_single_provider_document() {
        let profile = parse_profile_yaml(
            r"
id: example
display_name: Example
credentials:
  - name: api_key
    env_vars: [EXAMPLE_API_KEY]
",
        )
        .expect("profile should parse");

        assert_eq!(profile.id, "example");
        assert_eq!(profile.category, ProviderProfileCategory::Other);
        assert_eq!(profile.credential_env_vars(), vec!["EXAMPLE_API_KEY"]);
    }

    #[test]
    fn profile_json_round_trip_preserves_compact_dto_shape() {
        let profile = get_default_profile("github").expect("github profile");
        let json = profile_to_json(profile).expect("profile should serialize");
        let parsed = parse_profile_json(&json).expect("profile should parse");

        assert_eq!(parsed.id, "github");
        assert_eq!(parsed.category, ProviderProfileCategory::SourceControl);
        assert_eq!(parsed.binaries[0], "/usr/bin/gh");
    }

    #[test]
    fn validate_profile_set_returns_all_discoverable_diagnostics() {
        let profile = parse_profile_yaml(
            r#"
id: broken
display_name: Broken
credentials:
  - name: api_key
    env_vars: [BROKEN_TOKEN]
    auth_style: query
  - name: api_key
    env_vars: [BROKEN_TOKEN, ""]
    auth_style: unknown
endpoints:
  - host: ""
    port: 0
binaries: ["", /usr/bin/broken]
"#,
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("broken.yaml".to_string(), profile)]);
        let messages = diagnostics
            .iter()
            .map(|diagnostic| diagnostic.message.as_str())
            .collect::<Vec<_>>();

        assert!(messages.contains(&"duplicate credential name: api_key"));
        assert!(messages.contains(&"duplicate credential env var 'BROKEN_TOKEN'"));
        assert!(messages.contains(&"credential env var must not be empty"));
        assert!(messages.contains(&"query_param is required for query auth"));
        assert!(messages.contains(&"unsupported auth_style: unknown"));
        assert!(
            messages
                .iter()
                .any(|message| message.starts_with("invalid endpoint"))
        );
        assert!(messages.contains(&"binary path must not be empty"));
    }

    #[test]
    fn parse_profile_catalog_yamls_rejects_duplicate_ids() {
        let err = parse_profile_catalog_yamls(&[
            r"
id: duplicate
display_name: First
",
            r"
id: duplicate
display_name: Second
",
        ])
        .unwrap_err();

        assert!(matches!(err, ProfileError::DuplicateId(id) if id == "duplicate"));
    }

    #[test]
    fn parse_profile_catalog_yamls_rejects_invalid_endpoint_ports() {
        let err = parse_profile_catalog_yamls(&[r"
id: bad-endpoint
display_name: Bad Endpoint
endpoints:
  - host: api.example.com
    port: 0
"])
        .unwrap_err();

        assert!(matches!(err, ProfileError::InvalidEndpoint { id, .. } if id == "bad-endpoint"));
    }
}
