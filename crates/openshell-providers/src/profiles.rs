// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Declarative provider type profiles.

#![allow(deprecated)] // NetworkBinary::harness remains in the public proto for compatibility.

use openshell_core::proto::{
    NetworkBinary, NetworkEndpoint, NetworkPolicyRule, ProviderProfile, ProviderProfileCategory,
    ProviderProfileCredential,
};
use serde::{Deserialize, Deserializer, de};
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
    #[error("provider profile id is required")]
    MissingId,
    #[error("duplicate provider profile id: {0}")]
    DuplicateId(String),
    #[error("provider profile '{id}' has invalid endpoint '{host}:{port}'")]
    InvalidEndpoint { id: String, host: String, port: u32 },
    #[error("provider profile '{id}' has duplicate credential env var '{env_var}'")]
    DuplicateCredentialEnvVar { id: String, env_var: String },
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ProviderTypeProfile {
    pub id: String,
    pub display_name: String,
    #[serde(default)]
    pub description: String,
    #[serde(
        default = "default_category",
        deserialize_with = "deserialize_category"
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

fn provider_profile_category_from_yaml(raw: &str) -> Option<ProviderProfileCategory> {
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

pub fn parse_profile_yaml(input: &str) -> Result<ProviderTypeProfile, ProfileError> {
    Ok(serde_yml::from_str::<ProviderTypeProfile>(input)?)
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
    let mut ids = HashSet::new();
    for profile in profiles {
        if profile.id.trim().is_empty() {
            return Err(ProfileError::MissingId);
        }
        if !ids.insert(profile.id.clone()) {
            return Err(ProfileError::DuplicateId(profile.id.clone()));
        }

        let mut env_vars = HashSet::new();
        for credential in &profile.credentials {
            for env_var in &credential.env_vars {
                if !env_vars.insert(env_var) {
                    return Err(ProfileError::DuplicateCredentialEnvVar {
                        id: profile.id.clone(),
                        env_var: env_var.clone(),
                    });
                }
            }
        }

        for endpoint in &profile.endpoints {
            if endpoint.host.trim().is_empty() || endpoint.port == 0 || endpoint.port > 65_535 {
                return Err(ProfileError::InvalidEndpoint {
                    id: profile.id.clone(),
                    host: endpoint.host.clone(),
                    port: endpoint.port,
                });
            }
        }
    }
    Ok(())
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
        parse_profile_yaml,
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
