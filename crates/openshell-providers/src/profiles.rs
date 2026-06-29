// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Declarative provider type profiles.

#![allow(deprecated)] // NetworkBinary::harness remains in the public proto for compatibility.

use openshell_core::proto::{
    GraphqlOperation, L7Allow, L7DenyRule, L7QueryMatcher, L7Rule, NetworkBinary, NetworkEndpoint,
    NetworkPolicyRule, ProviderCredentialRefresh, ProviderCredentialRefreshMaterial,
    ProviderCredentialRefreshStrategy, ProviderProfile, ProviderProfileCategory,
    ProviderProfileCredential, ProviderProfileDiscovery,
};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::OnceLock;

const PATH_TEMPLATE_CREDENTIAL_PLACEHOLDER: &str = "{credential}";

const BUILT_IN_PROFILE_YAMLS: &[&str] = &[
    include_str!("../../../providers/aws-bedrock.yaml"),
    include_str!("../../../providers/claude-code.yaml"),
    include_str!("../../../providers/codex.yaml"),
    include_str!("../../../providers/copilot.yaml"),
    include_str!("../../../providers/cursor.yaml"),
    include_str!("../../../providers/deepinfra.yaml"),
    include_str!("../../../providers/github.yaml"),
    include_str!("../../../providers/google-cloud.yaml"),
    include_str!("../../../providers/google-vertex-ai.yaml"),
    include_str!("../../../providers/nvidia.yaml"),
    include_str!("../../../providers/pypi.yaml"),
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<CredentialRefreshProfile>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path_template: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_grant: Option<TokenGrantProfile>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct TokenGrantProfile {
    pub token_endpoint: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub audience: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub jwt_svid_audience: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_assertion_type: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub cache_ttl_seconds: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audience_overrides: Vec<TokenGrantAudienceOverrideProfile>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct TokenGrantAudienceOverrideProfile {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub port: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    pub audience: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialRefreshProfile {
    #[serde(
        default = "default_refresh_strategy",
        deserialize_with = "deserialize_refresh_strategy",
        serialize_with = "serialize_refresh_strategy"
    )]
    pub strategy: ProviderCredentialRefreshStrategy,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token_url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub refresh_before_seconds: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub max_lifetime_seconds: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub material: Vec<CredentialRefreshMaterialProfile>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialRefreshMaterialProfile {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub secret: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct DiscoveryProfile {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<String>,
}

// These YAML/JSON DTOs mirror the network policy protos intentionally. Keep
// every lossless conversion below in sync with proto/sandbox.proto. If a field
// is added to NetworkEndpoint, L7Rule, L7Allow, L7DenyRule, L7QueryMatcher,
// GraphqlOperation, or NetworkBinary, add it here and in both conversion
// directions unless the import/lint path explicitly rejects it.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct EndpointProfile {
    pub host: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub port: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tls: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub access: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub enforcement: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<L7RuleProfile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_rules: Vec<L7DenyRuleProfile>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_encoded_slash: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub websocket_credential_rewrite: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub request_body_credential_rewrite: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub persisted_queries: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub graphql_persisted_queries: HashMap<String, GraphqlOperationProfile>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub graphql_max_body_bytes: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub credential_signing: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signing_service: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signing_region: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct L7RuleProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<L7AllowProfile>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct L7AllowProfile {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub command: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub query: HashMap<String, L7QueryMatcherProfile>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct L7DenyRuleProfile {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub command: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub query: HashMap<String, L7QueryMatcherProfile>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct L7QueryMatcherProfile {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub glob: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct GraphqlOperationProfile {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryProfile {
    pub path: String,
    pub harness: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProviderTypeProfile {
    pub id: String,
    #[serde(default, skip_serializing_if = "is_u64_zero")]
    pub resource_version: u64,
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
    pub binaries: Vec<BinaryProfile>,
    #[serde(default)]
    pub inference_capable: bool,
    #[serde(default, skip_serializing_if = "discovery_is_empty")]
    pub discovery: DiscoveryProfile,
}

// Provider profile import/export is expected to be lossless for the network
// policy fields exposed by the protobuf API. Do not collapse these DTOs into a
// narrower shape; direct gRPC imports and CLI YAML imports must preserve the
// same policy intent through storage and JIT composition.
impl ProviderTypeProfile {
    #[must_use]
    pub fn from_proto(profile: &ProviderProfile) -> Self {
        Self {
            id: profile.id.clone(),
            resource_version: profile.resource_version,
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
                    refresh: credential
                        .refresh
                        .as_ref()
                        .map(credential_refresh_from_proto),
                    path_template: credential.path_template.clone(),
                    token_grant: credential.token_grant.as_ref().map(token_grant_from_proto),
                })
                .collect(),
            endpoints: profile.endpoints.iter().map(endpoint_from_proto).collect(),
            binaries: profile.binaries.iter().map(binary_from_proto).collect(),
            inference_capable: profile.inference_capable,
            discovery: profile
                .discovery
                .as_ref()
                .map(discovery_from_proto)
                .unwrap_or_default(),
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

    /// Whether this profile can be created without initial static credentials.
    ///
    /// Empty provider creation is allowed when at least one credential can be
    /// resolved at runtime, and every required credential can be resolved at
    /// runtime. Runtime-resolvable credentials are either gateway-mintable
    /// refresh credentials or sandbox-side dynamic token grants.
    #[must_use]
    pub fn allows_empty_provider_credentials(&self) -> bool {
        let mut has_runtime_resolvable_credential = false;
        for credential in &self.credentials {
            let is_runtime_resolvable = credential.is_runtime_resolvable();
            if credential.required && !is_runtime_resolvable {
                return false;
            }
            has_runtime_resolvable_credential |= is_runtime_resolvable;
        }
        has_runtime_resolvable_credential
    }

    /// Returns the credential suitable for `--from-gcloud-adc` bootstrap, if any.
    ///
    /// A credential qualifies when its refresh strategy is `Oauth2RefreshToken`
    /// and its material declares the three gcloud ADC keys (`client_id`,
    /// `client_secret`, `refresh_token`).
    #[must_use]
    pub fn adc_credential(&self) -> Option<&CredentialProfile> {
        const ADC_MATERIAL_KEYS: &[&str] = &["client_id", "client_secret", "refresh_token"];

        self.credentials.iter().find(|cred| {
            cred.refresh.as_ref().is_some_and(|refresh| {
                refresh.strategy == ProviderCredentialRefreshStrategy::Oauth2RefreshToken
                    && ADC_MATERIAL_KEYS
                        .iter()
                        .all(|key| refresh.material.iter().any(|m| m.name == *key))
            })
        })
    }

    #[must_use]
    pub fn to_proto(&self) -> ProviderProfile {
        ProviderProfile {
            id: self.id.clone(),
            resource_version: self.resource_version,
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
                    refresh: credential.refresh.as_ref().map(credential_refresh_to_proto),
                    path_template: credential.path_template.clone(),
                    token_grant: credential.token_grant.as_ref().map(token_grant_to_proto),
                })
                .collect(),
            endpoints: self.endpoints.iter().map(endpoint_to_proto).collect(),
            binaries: self.binaries.iter().map(binary_to_proto).collect(),
            inference_capable: self.inference_capable,
            discovery: (!discovery_is_empty(&self.discovery))
                .then(|| discovery_to_proto(&self.discovery)),
        }
    }

    #[must_use]
    pub fn network_policy_rule(&self, rule_name: &str) -> NetworkPolicyRule {
        NetworkPolicyRule {
            name: rule_name.to_string(),
            endpoints: self.endpoints.iter().map(endpoint_to_proto).collect(),
            binaries: self.binaries.iter().map(binary_to_proto).collect(),
        }
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_u64_zero(value: &u64) -> bool {
    *value == 0
}

impl CredentialProfile {
    #[must_use]
    pub fn is_runtime_resolvable(&self) -> bool {
        self.token_grant.is_some()
            || self
                .refresh
                .as_ref()
                .is_some_and(CredentialRefreshProfile::is_gateway_mintable)
    }
}

impl CredentialRefreshProfile {
    #[must_use]
    pub fn is_gateway_mintable(&self) -> bool {
        matches!(
            self.strategy,
            ProviderCredentialRefreshStrategy::Oauth2RefreshToken
                | ProviderCredentialRefreshStrategy::Oauth2ClientCredentials
                | ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt
        )
    }
}

fn discovery_is_empty(discovery: &DiscoveryProfile) -> bool {
    discovery.credentials.is_empty()
}

impl Serialize for BinaryProfile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !self.harness {
            return serializer.serialize_str(&self.path);
        }
        let mut state = serializer.serialize_struct("BinaryProfile", 2)?;
        state.serialize_field("path", &self.path)?;
        state.serialize_field("harness", &self.harness)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for BinaryProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum BinaryProfileInput {
            Path(String),
            Object(BinaryProfileObject),
        }

        #[derive(Deserialize)]
        struct BinaryProfileObject {
            path: String,
            #[serde(default)]
            harness: bool,
        }

        match BinaryProfileInput::deserialize(deserializer)? {
            BinaryProfileInput::Path(path) => Ok(Self {
                path,
                harness: false,
            }),
            BinaryProfileInput::Object(binary) => Ok(Self {
                path: binary.path,
                harness: binary.harness,
            }),
        }
    }
}

fn default_category() -> ProviderProfileCategory {
    ProviderProfileCategory::Other
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(value: &bool) -> bool {
    !*value
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(value: &u32) -> bool {
    *value == 0
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

fn default_refresh_strategy() -> ProviderCredentialRefreshStrategy {
    ProviderCredentialRefreshStrategy::Unspecified
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

fn deserialize_refresh_strategy<'de, D>(
    deserializer: D,
) -> Result<ProviderCredentialRefreshStrategy, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    provider_refresh_strategy_from_yaml(&raw)
        .ok_or_else(|| de::Error::custom(format!("unsupported provider refresh strategy: {raw}")))
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn serialize_refresh_strategy<S>(
    strategy: &ProviderCredentialRefreshStrategy,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(provider_refresh_strategy_to_yaml(*strategy))
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

#[must_use]
pub fn provider_refresh_strategy_from_yaml(raw: &str) -> Option<ProviderCredentialRefreshStrategy> {
    match raw.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "" => Some(ProviderCredentialRefreshStrategy::Unspecified),
        "static" => Some(ProviderCredentialRefreshStrategy::Static),
        "external" => Some(ProviderCredentialRefreshStrategy::External),
        "oauth2_refresh_token" => Some(ProviderCredentialRefreshStrategy::Oauth2RefreshToken),
        "oauth2_client_credentials" => {
            Some(ProviderCredentialRefreshStrategy::Oauth2ClientCredentials)
        }
        "google_service_account_jwt" => {
            Some(ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt)
        }
        _ => None,
    }
}

#[must_use]
pub fn provider_refresh_strategy_to_yaml(
    strategy: ProviderCredentialRefreshStrategy,
) -> &'static str {
    match strategy {
        ProviderCredentialRefreshStrategy::Static => "static",
        ProviderCredentialRefreshStrategy::External => "external",
        ProviderCredentialRefreshStrategy::Oauth2RefreshToken => "oauth2_refresh_token",
        ProviderCredentialRefreshStrategy::Oauth2ClientCredentials => "oauth2_client_credentials",
        ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt => "google_service_account_jwt",
        ProviderCredentialRefreshStrategy::Unspecified => "unspecified",
    }
}

fn credential_refresh_from_proto(refresh: &ProviderCredentialRefresh) -> CredentialRefreshProfile {
    CredentialRefreshProfile {
        strategy: ProviderCredentialRefreshStrategy::try_from(refresh.strategy)
            .unwrap_or(ProviderCredentialRefreshStrategy::Unspecified),
        token_url: refresh.token_url.clone(),
        scopes: refresh.scopes.clone(),
        refresh_before_seconds: refresh.refresh_before_seconds,
        max_lifetime_seconds: refresh.max_lifetime_seconds,
        material: refresh
            .material
            .iter()
            .map(|material| CredentialRefreshMaterialProfile {
                name: material.name.clone(),
                description: material.description.clone(),
                required: material.required,
                secret: material.secret,
            })
            .collect(),
    }
}

fn credential_refresh_to_proto(refresh: &CredentialRefreshProfile) -> ProviderCredentialRefresh {
    ProviderCredentialRefresh {
        strategy: refresh.strategy as i32,
        token_url: refresh.token_url.clone(),
        scopes: refresh.scopes.clone(),
        refresh_before_seconds: refresh.refresh_before_seconds,
        max_lifetime_seconds: refresh.max_lifetime_seconds,
        material: refresh
            .material
            .iter()
            .map(|material| ProviderCredentialRefreshMaterial {
                name: material.name.clone(),
                description: material.description.clone(),
                required: material.required,
                secret: material.secret,
            })
            .collect(),
    }
}

fn token_grant_from_proto(
    token_grant: &openshell_core::proto::ProviderCredentialTokenGrant,
) -> TokenGrantProfile {
    TokenGrantProfile {
        token_endpoint: token_grant.token_endpoint.clone(),
        audience: token_grant.audience.clone(),
        jwt_svid_audience: token_grant.jwt_svid_audience.clone(),
        client_assertion_type: token_grant.client_assertion_type.clone(),
        scopes: token_grant.scopes.clone(),
        cache_ttl_seconds: token_grant.cache_ttl_seconds,
        audience_overrides: token_grant
            .audience_overrides
            .iter()
            .map(token_grant_audience_override_from_proto)
            .collect(),
    }
}

fn token_grant_to_proto(
    token_grant: &TokenGrantProfile,
) -> openshell_core::proto::ProviderCredentialTokenGrant {
    openshell_core::proto::ProviderCredentialTokenGrant {
        token_endpoint: token_grant.token_endpoint.clone(),
        audience: token_grant.audience.clone(),
        jwt_svid_audience: token_grant.jwt_svid_audience.clone(),
        client_assertion_type: token_grant.client_assertion_type.clone(),
        scopes: token_grant.scopes.clone(),
        cache_ttl_seconds: token_grant.cache_ttl_seconds,
        audience_overrides: token_grant
            .audience_overrides
            .iter()
            .map(token_grant_audience_override_to_proto)
            .collect(),
    }
}

fn token_grant_audience_override_from_proto(
    override_config: &openshell_core::proto::ProviderCredentialTokenGrantAudienceOverride,
) -> TokenGrantAudienceOverrideProfile {
    TokenGrantAudienceOverrideProfile {
        host: override_config.host.clone(),
        port: override_config.port,
        path: override_config.path.clone(),
        audience: override_config.audience.clone(),
        scopes: override_config.scopes.clone(),
    }
}

fn token_grant_audience_override_to_proto(
    override_config: &TokenGrantAudienceOverrideProfile,
) -> openshell_core::proto::ProviderCredentialTokenGrantAudienceOverride {
    openshell_core::proto::ProviderCredentialTokenGrantAudienceOverride {
        host: override_config.host.clone(),
        port: override_config.port,
        path: override_config.path.clone(),
        audience: override_config.audience.clone(),
        scopes: override_config.scopes.clone(),
    }
}

fn discovery_from_proto(discovery: &ProviderProfileDiscovery) -> DiscoveryProfile {
    DiscoveryProfile {
        credentials: discovery.credentials.clone(),
    }
}

fn discovery_to_proto(discovery: &DiscoveryProfile) -> ProviderProfileDiscovery {
    ProviderProfileDiscovery {
        credentials: discovery.credentials.clone(),
    }
}

fn endpoint_to_proto(endpoint: &EndpointProfile) -> NetworkEndpoint {
    NetworkEndpoint {
        host: endpoint.host.clone(),
        port: endpoint.port,
        protocol: endpoint.protocol.clone(),
        tls: endpoint.tls.clone(),
        enforcement: endpoint.enforcement.clone(),
        access: endpoint.access.clone(),
        rules: endpoint.rules.iter().map(rule_to_proto).collect(),
        allowed_ips: endpoint.allowed_ips.clone(),
        ports: endpoint.ports.clone(),
        deny_rules: endpoint.deny_rules.iter().map(deny_rule_to_proto).collect(),
        allow_encoded_slash: endpoint.allow_encoded_slash,
        websocket_credential_rewrite: endpoint.websocket_credential_rewrite,
        request_body_credential_rewrite: endpoint.request_body_credential_rewrite,
        advisor_proposed: false,
        persisted_queries: endpoint.persisted_queries.clone(),
        graphql_persisted_queries: endpoint
            .graphql_persisted_queries
            .iter()
            .map(|(name, operation)| (name.clone(), graphql_operation_to_proto(operation)))
            .collect(),
        graphql_max_body_bytes: endpoint.graphql_max_body_bytes,
        path: endpoint.path.clone(),
        credential_signing: endpoint.credential_signing.clone(),
        signing_service: endpoint.signing_service.clone(),
        signing_region: endpoint.signing_region.clone(),
    }
}

fn endpoint_from_proto(endpoint: &NetworkEndpoint) -> EndpointProfile {
    EndpointProfile {
        host: endpoint.host.clone(),
        port: endpoint.port,
        protocol: endpoint.protocol.clone(),
        tls: endpoint.tls.clone(),
        access: endpoint.access.clone(),
        enforcement: endpoint.enforcement.clone(),
        rules: endpoint.rules.iter().map(rule_from_proto).collect(),
        allowed_ips: endpoint.allowed_ips.clone(),
        ports: endpoint.ports.clone(),
        deny_rules: endpoint
            .deny_rules
            .iter()
            .map(deny_rule_from_proto)
            .collect(),
        allow_encoded_slash: endpoint.allow_encoded_slash,
        websocket_credential_rewrite: endpoint.websocket_credential_rewrite,
        request_body_credential_rewrite: endpoint.request_body_credential_rewrite,
        persisted_queries: endpoint.persisted_queries.clone(),
        graphql_persisted_queries: endpoint
            .graphql_persisted_queries
            .iter()
            .map(|(name, operation)| (name.clone(), graphql_operation_from_proto(operation)))
            .collect(),
        graphql_max_body_bytes: endpoint.graphql_max_body_bytes,
        path: endpoint.path.clone(),
        credential_signing: endpoint.credential_signing.clone(),
        signing_service: endpoint.signing_service.clone(),
        signing_region: endpoint.signing_region.clone(),
    }
}

fn binary_to_proto(binary: &BinaryProfile) -> NetworkBinary {
    NetworkBinary {
        path: binary.path.clone(),
        harness: binary.harness,
    }
}

fn binary_from_proto(binary: &NetworkBinary) -> BinaryProfile {
    BinaryProfile {
        path: binary.path.clone(),
        harness: binary.harness,
    }
}

fn rule_to_proto(rule: &L7RuleProfile) -> L7Rule {
    L7Rule {
        allow: rule.allow.as_ref().map(allow_to_proto),
    }
}

fn rule_from_proto(rule: &L7Rule) -> L7RuleProfile {
    L7RuleProfile {
        allow: rule.allow.as_ref().map(allow_from_proto),
    }
}

fn allow_to_proto(allow: &L7AllowProfile) -> L7Allow {
    L7Allow {
        method: allow.method.clone(),
        path: allow.path.clone(),
        command: allow.command.clone(),
        query: allow
            .query
            .iter()
            .map(|(name, matcher)| (name.clone(), query_matcher_to_proto(matcher)))
            .collect(),
        operation_type: allow.operation_type.clone(),
        operation_name: allow.operation_name.clone(),
        fields: allow.fields.clone(),
    }
}

fn allow_from_proto(allow: &L7Allow) -> L7AllowProfile {
    L7AllowProfile {
        method: allow.method.clone(),
        path: allow.path.clone(),
        command: allow.command.clone(),
        query: allow
            .query
            .iter()
            .map(|(name, matcher)| (name.clone(), query_matcher_from_proto(matcher)))
            .collect(),
        operation_type: allow.operation_type.clone(),
        operation_name: allow.operation_name.clone(),
        fields: allow.fields.clone(),
    }
}

fn deny_rule_to_proto(rule: &L7DenyRuleProfile) -> L7DenyRule {
    L7DenyRule {
        method: rule.method.clone(),
        path: rule.path.clone(),
        command: rule.command.clone(),
        query: rule
            .query
            .iter()
            .map(|(name, matcher)| (name.clone(), query_matcher_to_proto(matcher)))
            .collect(),
        operation_type: rule.operation_type.clone(),
        operation_name: rule.operation_name.clone(),
        fields: rule.fields.clone(),
    }
}

fn deny_rule_from_proto(rule: &L7DenyRule) -> L7DenyRuleProfile {
    L7DenyRuleProfile {
        method: rule.method.clone(),
        path: rule.path.clone(),
        command: rule.command.clone(),
        query: rule
            .query
            .iter()
            .map(|(name, matcher)| (name.clone(), query_matcher_from_proto(matcher)))
            .collect(),
        operation_type: rule.operation_type.clone(),
        operation_name: rule.operation_name.clone(),
        fields: rule.fields.clone(),
    }
}

fn query_matcher_to_proto(matcher: &L7QueryMatcherProfile) -> L7QueryMatcher {
    L7QueryMatcher {
        glob: matcher.glob.clone(),
        any: matcher.any.clone(),
    }
}

fn query_matcher_from_proto(matcher: &L7QueryMatcher) -> L7QueryMatcherProfile {
    L7QueryMatcherProfile {
        glob: matcher.glob.clone(),
        any: matcher.any.clone(),
    }
}

fn graphql_operation_to_proto(operation: &GraphqlOperationProfile) -> GraphqlOperation {
    GraphqlOperation {
        operation_type: operation.operation_type.clone(),
        operation_name: operation.operation_name.clone(),
        fields: operation.fields.clone(),
    }
}

fn graphql_operation_from_proto(operation: &GraphqlOperation) -> GraphqlOperationProfile {
    GraphqlOperationProfile {
        operation_type: operation.operation_type.clone(),
        operation_name: operation.operation_name.clone(),
        fields: operation.fields.clone(),
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
            && let Some(endpoint) = profile
                .endpoints
                .iter()
                .find(|endpoint| !endpoint_is_valid(endpoint))
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
pub fn normalize_profile_id(input: &str) -> Option<String> {
    let id = input.trim().to_ascii_lowercase();
    if is_valid_profile_id(&id) {
        Some(id)
    } else {
        None
    }
}

fn is_valid_profile_id(id: &str) -> bool {
    !id.is_empty()
        && !id.starts_with('-')
        && !id.ends_with('-')
        && id.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

#[must_use]
pub fn validate_profile_set(
    profiles: &[(String, ProviderTypeProfile)],
) -> Vec<ProfileValidationDiagnostic> {
    let mut diagnostics = Vec::new();
    let mut ids = HashSet::new();
    for (source, profile) in profiles {
        let raw_profile_id = profile.id.as_str();
        let profile_id = raw_profile_id.trim();
        if profile_id.is_empty() {
            diagnostics.push(ProfileValidationDiagnostic::error(
                source,
                "",
                "id",
                "provider profile id is required",
            ));
        } else if normalize_profile_id(raw_profile_id).as_deref() != Some(raw_profile_id) {
            diagnostics.push(ProfileValidationDiagnostic::error(
                source,
                profile_id,
                "id",
                "provider profile id must be lowercase kebab-case using only a-z, 0-9, and '-'",
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

        let mut discovery_credentials = HashSet::new();
        for (index, credential_name) in profile.discovery.credentials.iter().enumerate() {
            let credential_name = credential_name.trim();
            if credential_name.is_empty() {
                diagnostics.push(ProfileValidationDiagnostic::error(
                    source,
                    profile_id,
                    format!("discovery.credentials[{index}]"),
                    "discovery credential name must not be empty",
                ));
            } else if !discovery_credentials.insert(credential_name.to_string()) {
                diagnostics.push(ProfileValidationDiagnostic::error(
                    source,
                    profile_id,
                    format!("discovery.credentials[{index}]"),
                    format!("duplicate discovery credential: {credential_name}"),
                ));
            } else if !credential_names.contains(credential_name) {
                diagnostics.push(ProfileValidationDiagnostic::error(
                    source,
                    profile_id,
                    format!("discovery.credentials[{index}]"),
                    format!("unknown discovery credential: {credential_name}"),
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
                "path" => {
                    let path_template = credential.path_template.trim();
                    if path_template.is_empty() {
                        diagnostics.push(ProfileValidationDiagnostic::error(
                            source,
                            profile_id,
                            "credentials.path_template",
                            "path_template is required for path auth",
                        ));
                    } else {
                        let count = path_template
                            .matches(PATH_TEMPLATE_CREDENTIAL_PLACEHOLDER)
                            .count();
                        if count != 1 {
                            diagnostics.push(ProfileValidationDiagnostic::error(
                                source,
                                profile_id,
                                "credentials.path_template",
                                format!(
                                    "path_template should contain {{credential}} exactly once, {path_template} contains {{credential}} {count} times",
                                ),
                        ));
                        }
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

            if let Some(refresh) = credential.refresh.as_ref() {
                if refresh.strategy == ProviderCredentialRefreshStrategy::Unspecified {
                    diagnostics.push(ProfileValidationDiagnostic::error(
                        source,
                        profile_id,
                        "credentials.refresh.strategy",
                        "refresh strategy is required",
                    ));
                }
                if refresh.refresh_before_seconds < 0 {
                    diagnostics.push(ProfileValidationDiagnostic::error(
                        source,
                        profile_id,
                        "credentials.refresh.refresh_before_seconds",
                        "refresh_before_seconds must be greater than or equal to 0",
                    ));
                }
                if refresh.max_lifetime_seconds < 0 {
                    diagnostics.push(ProfileValidationDiagnostic::error(
                        source,
                        profile_id,
                        "credentials.refresh.max_lifetime_seconds",
                        "max_lifetime_seconds must be greater than or equal to 0",
                    ));
                }
                let mut material_names = HashSet::new();
                for material in &refresh.material {
                    let name = material.name.trim();
                    if name.is_empty() {
                        diagnostics.push(ProfileValidationDiagnostic::error(
                            source,
                            profile_id,
                            "credentials.refresh.material.name",
                            "refresh material name is required",
                        ));
                    } else if !material_names.insert(name.to_string()) {
                        diagnostics.push(ProfileValidationDiagnostic::error(
                            source,
                            profile_id,
                            "credentials.refresh.material.name",
                            format!("duplicate refresh material name: {name}"),
                        ));
                    }
                }
            }

            if let Some(token_grant) = credential.token_grant.as_ref()
                && let Err(message) = validate_token_grant_endpoint(&token_grant.token_endpoint)
            {
                diagnostics.push(ProfileValidationDiagnostic::error(
                    source,
                    profile_id,
                    "credentials.token_grant.token_endpoint",
                    message,
                ));
            }
            diagnostics.extend(validate_token_grant_audience_overrides(
                source,
                profile_id,
                credential,
                &profile.endpoints,
            ));
            if credential.token_grant.is_some()
                && let Err(message) = validate_token_grant_auth_style(credential)
            {
                diagnostics.push(ProfileValidationDiagnostic::error(
                    source,
                    profile_id,
                    "credentials.token_grant.auth_style",
                    message,
                ));
            }
            if credential.token_grant.is_some()
                && let Err(message) = validate_token_grant_header_name(credential)
            {
                diagnostics.push(ProfileValidationDiagnostic::error(
                    source,
                    profile_id,
                    "credentials.header_name",
                    message,
                ));
            }
        }

        for (index, endpoint) in profile.endpoints.iter().enumerate() {
            if !endpoint_is_valid(endpoint) {
                diagnostics.push(ProfileValidationDiagnostic::error(
                    source,
                    profile_id,
                    format!("endpoints[{index}]"),
                    format!("invalid endpoint '{}:{}'", endpoint.host, endpoint.port),
                ));
            }
        }

        for (index, binary) in profile.binaries.iter().enumerate() {
            if binary.path.trim().is_empty() {
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

fn endpoint_is_valid(endpoint: &EndpointProfile) -> bool {
    if endpoint.host.trim().is_empty() {
        return false;
    }
    if !endpoint.ports.is_empty() {
        return endpoint
            .ports
            .iter()
            .all(|port| (1..=65_535).contains(port));
    }
    (1..=65_535).contains(&endpoint.port)
}

#[derive(Debug, Clone)]
struct TokenGrantOverrideBinding {
    override_index: usize,
    host: String,
    port: u32,
    path: String,
    score: u32,
}

fn validate_token_grant_audience_overrides(
    source: &str,
    profile_id: &str,
    credential: &CredentialProfile,
    endpoints: &[EndpointProfile],
) -> Vec<ProfileValidationDiagnostic> {
    let Some(token_grant) = credential.token_grant.as_ref() else {
        return Vec::new();
    };

    let mut diagnostics = Vec::new();
    let mut bindings: Vec<TokenGrantOverrideBinding> = Vec::new();
    for (override_index, override_config) in token_grant.audience_overrides.iter().enumerate() {
        for endpoint in endpoints {
            for port in endpoint_ports(endpoint.port, &endpoint.ports) {
                if !token_grant_override_matches_endpoint(override_config, &endpoint.host, port) {
                    continue;
                }

                let host = if override_config.host.trim().is_empty() {
                    endpoint.host.trim()
                } else {
                    override_config.host.trim()
                };
                let path = if override_config.path.trim().is_empty() {
                    endpoint.path.trim()
                } else {
                    override_config.path.trim()
                };
                let candidate = TokenGrantOverrideBinding {
                    override_index,
                    host: host.to_ascii_lowercase(),
                    port,
                    path: path.to_string(),
                    score: dynamic_token_grant_match_score(host, path),
                };
                for existing in &bindings {
                    if existing.override_index == candidate.override_index {
                        continue;
                    }
                    if existing.port == candidate.port
                        && existing.score == candidate.score
                        && host_patterns_can_overlap(&existing.host, &candidate.host)
                        && path_patterns_can_overlap(&existing.path, &candidate.path)
                    {
                        diagnostics.push(ProfileValidationDiagnostic::error(
                            source,
                            profile_id,
                            "credentials.token_grant.audience_overrides",
                            format!(
                                "credential '{}' has ambiguous token_grant audience_overrides at indexes {} and {} for {}:{} path selectors '{}' and '{}'",
                                credential.name,
                                existing.override_index,
                                candidate.override_index,
                                candidate.host,
                                candidate.port,
                                existing.path,
                                candidate.path
                            ),
                        ));
                    }
                }
                bindings.push(candidate);
            }
        }
    }
    diagnostics
}

fn endpoint_ports(port: u32, ports: &[u32]) -> Vec<u32> {
    if ports.is_empty() {
        if port == 0 { Vec::new() } else { vec![port] }
    } else {
        ports.iter().copied().filter(|port| *port != 0).collect()
    }
}

fn token_grant_override_matches_endpoint(
    override_config: &TokenGrantAudienceOverrideProfile,
    endpoint_host: &str,
    endpoint_port: u32,
) -> bool {
    let override_host = override_config.host.trim();
    let host_matches = override_host.is_empty()
        || host_pattern_matches(override_host, endpoint_host)
        || host_pattern_matches(endpoint_host, override_host);
    let port_matches = override_config.port == 0 || override_config.port == endpoint_port;
    host_matches && port_matches
}

fn host_pattern_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    if pattern == host {
        return true;
    }
    if !pattern.contains('*') {
        return false;
    }

    let pattern_labels: Vec<&str> = pattern.split('.').collect();
    let host_labels: Vec<&str> = host.split('.').collect();
    host_pattern_labels_match(&pattern_labels, &host_labels)
}

fn host_pattern_labels_match(pattern: &[&str], host: &[&str]) -> bool {
    match pattern.split_first() {
        None => host.is_empty(),
        Some((label, rest)) if *label == "**" => {
            host_pattern_labels_match(rest, host)
                || (!host.is_empty() && host_pattern_labels_match(pattern, &host[1..]))
        }
        Some((label, rest)) if *label == "*" => {
            !host.is_empty() && host_pattern_labels_match(rest, &host[1..])
        }
        Some((literal, rest)) => {
            host.first().is_some_and(|label| label == literal)
                && host_pattern_labels_match(rest, &host[1..])
        }
    }
}

fn dynamic_token_grant_match_score(host: &str, path: &str) -> u32 {
    host_pattern_specificity(host) + endpoint_path_specificity(path)
}

fn host_pattern_specificity(pattern: &str) -> u32 {
    let wildcard_penalty = count_as_u32(pattern.matches('*').count());
    let label_count = count_as_u32(pattern.split('.').filter(|label| !label.is_empty()).count());
    let literal_chars = count_as_u32(pattern.chars().filter(|ch| *ch != '*').count());
    100_000u32
        .saturating_sub(wildcard_penalty.saturating_mul(10_000))
        .saturating_add(label_count.saturating_mul(100))
        .saturating_add(literal_chars)
}

fn endpoint_path_specificity(path: &str) -> u32 {
    if path.is_empty() || path == "**" {
        return 0;
    }
    1_000_000u32.saturating_add(count_as_u32(path.chars().filter(|ch| *ch != '*').count()))
}

fn count_as_u32(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

fn host_patterns_can_overlap(first: &str, second: &str) -> bool {
    let first = first.to_ascii_lowercase();
    let second = second.to_ascii_lowercase();
    if !first.contains('*') {
        return host_pattern_matches(&second, &first);
    }
    if !second.contains('*') {
        return host_pattern_matches(&first, &second);
    }
    let first_labels: Vec<&str> = first.split('.').collect();
    let second_labels: Vec<&str> = second.split('.').collect();
    host_pattern_labels_can_overlap(&first_labels, &second_labels)
}

fn host_pattern_labels_can_overlap(first: &[&str], second: &[&str]) -> bool {
    match (first.split_first(), second.split_first()) {
        (None, None) => true,
        (None, Some((label, rest))) if *label == "**" => {
            host_pattern_labels_can_overlap(first, rest)
        }
        (Some((label, rest)), None) if *label == "**" => {
            host_pattern_labels_can_overlap(rest, second)
        }
        (None, _) | (_, None) => false,
        (Some((label, rest)), _) if *label == "**" => {
            host_pattern_labels_can_overlap(rest, second)
                || host_pattern_labels_can_overlap(first, &second[1..])
        }
        (_, Some((label, rest))) if *label == "**" => {
            host_pattern_labels_can_overlap(first, rest)
                || host_pattern_labels_can_overlap(&first[1..], second)
        }
        (Some((first_label, first_rest)), Some((second_label, second_rest))) => {
            (*first_label == "*" || *second_label == "*" || first_label == second_label)
                && host_pattern_labels_can_overlap(first_rest, second_rest)
        }
    }
}

fn path_patterns_can_overlap(first: &str, second: &str) -> bool {
    if path_matches_all(first) || path_matches_all(second) {
        return true;
    }
    if !first.contains('*') {
        return endpoint_path_matches(second, first);
    }
    if !second.contains('*') {
        return endpoint_path_matches(first, second);
    }
    match (path_prefix_pattern(first), path_prefix_pattern(second)) {
        (Some(first_prefix), Some(second_prefix)) => {
            first_prefix == second_prefix
                || first_prefix.starts_with(&format!("{second_prefix}/"))
                || second_prefix.starts_with(&format!("{first_prefix}/"))
        }
        _ => true,
    }
}

fn path_matches_all(path: &str) -> bool {
    path.is_empty() || path == "**" || path == "/**"
}

fn path_prefix_pattern(path: &str) -> Option<&str> {
    path.strip_suffix("/**")
}

fn endpoint_path_matches(pattern: &str, path: &str) -> bool {
    if path_matches_all(pattern) {
        return true;
    }
    if pattern == path {
        return true;
    }
    if let Some(prefix) = path_prefix_pattern(pattern) {
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    glob::Pattern::new(pattern).is_ok_and(|glob| glob.matches(path))
}

fn validate_token_grant_endpoint(token_endpoint: &str) -> Result<(), String> {
    let url = url::Url::parse(token_endpoint)
        .map_err(|_| "token_endpoint must be an absolute URL".to_string())?;
    if token_endpoint_transport_allowed(&url) {
        return Ok(());
    }

    Err(
        "token_endpoint must use https, except http for loopback or in-cluster service hosts"
            .to_string(),
    )
}

fn validate_token_grant_auth_style(credential: &CredentialProfile) -> Result<(), String> {
    match credential.auth_style.trim().to_ascii_lowercase().as_str() {
        "" | "bearer" | "header" => Ok(()),
        _ => Err("token_grant credentials support auth_style bearer or header".to_string()),
    }
}

fn validate_token_grant_header_name(credential: &CredentialProfile) -> Result<(), String> {
    let header_name = match credential.auth_style.trim().to_ascii_lowercase().as_str() {
        "" | "bearer" if credential.header_name.trim().is_empty() => "Authorization",
        "" | "bearer" | "header" => credential.header_name.trim(),
        _ => return Ok(()),
    };
    if header_name.is_empty() {
        return Ok(());
    }
    let valid = header_name.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
    });
    if !valid {
        return Err("token_grant header_name is not a valid HTTP header name".to_string());
    }
    match header_name.to_ascii_lowercase().as_str() {
        "host" | "content-length" | "transfer-encoding" | "connection" => Err(
            "token_grant header_name may not override HTTP framing or connection headers"
                .to_string(),
        ),
        _ => Ok(()),
    }
}

fn token_endpoint_transport_allowed(url: &url::Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => url
            .host_str()
            .is_some_and(|host| is_loopback_host(host) || is_kubernetes_service_host(host)),
        _ => false,
    }
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']);
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(IpAddr::V6(v6)) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
        Err(_) => false,
    }
}

fn is_kubernetes_service_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let labels = host.split('.').collect::<Vec<_>>();
    let is_service_name = labels.len() == 3 && labels[2] == "svc";
    let is_cluster_local_service =
        labels.len() == 5 && labels[2] == "svc" && labels[3] == "cluster" && labels[4] == "local";
    (is_service_name || is_cluster_local_service) && labels.iter().all(|label| !label.is_empty())
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
        DiscoveryProfile, ProfileError, ProviderTypeProfile, default_profiles, get_default_profile,
        normalize_profile_id, parse_profile_catalog_yamls, parse_profile_json, parse_profile_yaml,
        profile_to_json, profile_to_yaml, validate_profile_set,
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
        assert_eq!(proto.endpoints.len(), 3);
        assert!(
            proto.endpoints.iter().any(|endpoint| {
                endpoint.host == "api.github.com"
                    && endpoint.protocol == "graphql"
                    && endpoint.path == "/graphql"
                    && endpoint.access == "read-only"
            }),
            "github profile should include read-only GraphQL endpoint"
        );
        assert!(
            proto
                .endpoints
                .iter()
                .all(|endpoint| endpoint.access == "read-only"),
            "github profile endpoints should all be read-only"
        );
        assert_eq!(proto.binaries.len(), 4);
    }

    #[test]
    fn credential_env_vars_are_deduplicated_in_profile_order() {
        let profile = get_default_profile("claude-code").expect("claude-code profile");
        assert_eq!(
            profile.credential_env_vars(),
            vec!["ANTHROPIC_API_KEY", "CLAUDE_API_KEY"]
        );
    }

    #[test]
    fn vertex_profile_declares_discovery_and_fallback_token_env_vars() {
        let profile = get_default_profile("google-vertex-ai").expect("vertex profile");
        let service_account_token = profile
            .credentials
            .iter()
            .find(|credential| credential.name == "service_account_token")
            .expect("vertex service-account token credential");
        let adc_credential = profile
            .credentials
            .iter()
            .find(|credential| credential.name == "gcloud_adc_token")
            .expect("vertex ADC credential");

        assert_eq!(
            service_account_token.env_vars,
            vec![
                "GOOGLE_VERTEX_AI_SERVICE_ACCOUNT_TOKEN".to_string(),
                "VERTEX_AI_SERVICE_ACCOUNT_TOKEN".to_string()
            ]
        );
        assert_eq!(
            adc_credential.env_vars,
            vec![
                "GOOGLE_VERTEX_AI_TOKEN".to_string(),
                "VERTEX_AI_TOKEN".to_string()
            ]
        );
        assert_eq!(
            profile.discovery.credentials,
            vec!["service_account_token", "gcloud_adc_token"]
        );
        assert!(
            profile.allows_empty_provider_credentials(),
            "Vertex profile should allow empty-create bootstrap via gateway-mintable credentials"
        );
    }

    #[test]
    fn empty_provider_credentials_require_a_runtime_resolvable_path_and_no_required_static_credentials()
     {
        let optional_refresh_profile = parse_profile_yaml(
            r"
id: optional-refresh
display_name: Optional Refresh
credentials:
  - name: access_token
    required: false
    refresh:
      strategy: oauth2_refresh_token
",
        )
        .expect("profile");
        assert!(optional_refresh_profile.allows_empty_provider_credentials());

        let token_grant_profile = parse_profile_yaml(
            r"
id: token-grant
display_name: Token Grant
credentials:
  - name: access_token
    required: true
    token_grant:
      token_endpoint: https://auth.example.com/token
",
        )
        .expect("profile");
        assert!(token_grant_profile.allows_empty_provider_credentials());

        let mixed_required_profile = parse_profile_yaml(
            r"
id: mixed-required
display_name: Mixed Required
credentials:
  - name: access_token
    required: true
    refresh:
      strategy: oauth2_client_credentials
  - name: static_key
    required: true
",
        )
        .expect("profile");
        assert!(!mixed_required_profile.allows_empty_provider_credentials());

        let static_only_profile = parse_profile_yaml(
            r"
id: static-only
display_name: Static Only
credentials:
  - name: api_key
    required: false
",
        )
        .expect("profile");
        assert!(!static_only_profile.allows_empty_provider_credentials());
    }

    #[test]
    fn adc_credential_returns_oauth2_refresh_token_credential_with_adc_material() {
        let profile = get_default_profile("google-cloud").expect("google-cloud profile");
        let adc = profile
            .adc_credential()
            .expect("google-cloud should have an ADC credential");
        assert_eq!(adc.env_vars[0], "GCP_ADC_ACCESS_TOKEN");

        let profile = get_default_profile("google-vertex-ai").expect("vertex profile");
        let adc = profile
            .adc_credential()
            .expect("vertex should have an ADC credential");
        assert_eq!(adc.env_vars[0], "GOOGLE_VERTEX_AI_TOKEN");
    }

    #[test]
    fn adc_credential_returns_none_for_profiles_without_adc() {
        let profile = get_default_profile("github").expect("github profile");
        assert!(profile.adc_credential().is_none());

        let profile = get_default_profile("claude-code").expect("claude-code profile");
        assert!(profile.adc_credential().is_none());
    }

    #[test]
    fn adc_credential_rejects_service_account_jwt_strategy() {
        let profile = parse_profile_yaml(
            r"
id: sa-only
display_name: SA Only
credentials:
  - name: sa_token
    env_vars: [SA_TOKEN]
    refresh:
      strategy: google_service_account_jwt
      material:
        - name: client_email
        - name: private_key
",
        )
        .expect("profile");
        assert!(profile.adc_credential().is_none());
    }

    #[test]
    fn adc_credential_requires_all_three_material_keys() {
        let profile = parse_profile_yaml(
            r"
id: partial-material
display_name: Partial Material
credentials:
  - name: token
    env_vars: [TOKEN]
    refresh:
      strategy: oauth2_refresh_token
      material:
        - name: client_id
        - name: client_secret
",
        )
        .expect("profile");
        assert!(
            profile.adc_credential().is_none(),
            "missing refresh_token material should not qualify"
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
    fn profile_discovery_metadata_round_trips_through_proto_and_yaml() {
        let profile = parse_profile_yaml(
            r"
id: example
display_name: Example
credentials:
  - name: api_key
    env_vars: [EXAMPLE_API_KEY]
discovery:
  credentials: [api_key]
",
        )
        .expect("profile should parse");

        assert_eq!(profile.discovery.credentials, vec!["api_key"]);
        let from_proto = ProviderTypeProfile::from_proto(&profile.to_proto());
        assert_eq!(from_proto.discovery.credentials, vec!["api_key"]);
        let exported = profile_to_yaml(&from_proto).expect("yaml");
        assert!(exported.contains("discovery:"));
        assert!(exported.contains("api_key"));
    }

    #[test]
    fn profile_refresh_metadata_round_trips_through_proto_and_yaml() {
        let profile = parse_profile_yaml(
            r"
id: ms-graph
display_name: Microsoft Graph
credentials:
  - name: access_token
    env_vars: [MS_GRAPH_ACCESS_TOKEN]
    refresh:
      strategy: oauth2_client_credentials
      token_url: https://login.microsoftonline.com/common/oauth2/v2.0/token
      scopes: [https://graph.microsoft.com/.default]
      refresh_before_seconds: 300
      material:
        - name: tenant_id
          required: true
        - name: client_secret
          required: true
          secret: true
",
        )
        .expect("profile should parse");

        let refresh = profile.credentials[0].refresh.as_ref().expect("refresh");
        assert_eq!(
            refresh.token_url,
            "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        );
        assert_eq!(refresh.material.len(), 2);

        let from_proto = ProviderTypeProfile::from_proto(&profile.to_proto());
        assert_eq!(
            from_proto.credentials[0].refresh,
            profile.credentials[0].refresh
        );

        let exported = profile_to_yaml(&from_proto).expect("yaml");
        assert!(exported.contains("oauth2_client_credentials"));
        assert!(exported.contains("client_secret"));
    }

    #[test]
    fn credential_fields_round_trip_through_proto_and_yaml() {
        let profile = parse_profile_yaml(
            r"
id: multi-auth
display_name: Multi Auth
credentials:
  - name: basic_cred
    env_vars: [BASIC_TOKEN]
    auth_style: basic
  - name: bearer_cred
    env_vars: [BEARER_TOKEN]
    auth_style: bearer
    header_name: authorization
  - name: query_cred
    env_vars: [QUERY_TOKEN]
    auth_style: query
    query_param: api_key
  - name: path_cred
    env_vars: [PATH_TOKEN]
    auth_style: path
    path_template: /v1/{credential}/resources
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("multi-auth.yaml".to_string(), profile.clone())]);
        assert!(
            diagnostics.is_empty(),
            "unexpected diagnostics: {diagnostics:?}"
        );

        assert_eq!(profile.credentials[1].header_name, "authorization");
        assert_eq!(profile.credentials[2].query_param, "api_key");
        assert_eq!(
            profile.credentials[3].path_template,
            "/v1/{credential}/resources"
        );

        let from_proto = ProviderTypeProfile::from_proto(&profile.to_proto());
        assert_eq!(from_proto.credentials[1].header_name, "authorization");
        assert_eq!(from_proto.credentials[2].query_param, "api_key");
        assert_eq!(
            from_proto.credentials[3].path_template,
            "/v1/{credential}/resources"
        );

        let exported = profile_to_yaml(&from_proto).expect("yaml");
        let reparsed = parse_profile_yaml(&exported).expect("re-parse");
        assert_eq!(reparsed.credentials[1].header_name, "authorization");
        assert_eq!(reparsed.credentials[2].query_param, "api_key");
        assert_eq!(
            reparsed.credentials[3].path_template,
            "/v1/{credential}/resources"
        );
    }

    #[test]
    fn token_grant_audience_overrides_round_trip_through_proto() {
        let profile = parse_profile_yaml(
            r"
id: keycloak-example
display_name: Keycloak Example
credentials:
  - name: access_token
    auth_style: bearer
    header_name: Authorization
    token_grant:
      token_endpoint: http://keycloak.default.svc.cluster.local/realms/openshell/protocol/openid-connect/token
      jwt_svid_audience: http://keycloak.default.svc.cluster.local/realms/openshell
      client_assertion_type: urn:ietf:params:oauth:client-assertion-type:jwt-spiffe
      audience: api://default
      scopes: [openid]
      cache_ttl_seconds: 300
      audience_overrides:
        - host: alpha.default.svc.cluster.local
          port: 80
          audience: api://alpha
        - host: beta.default.svc.cluster.local
          port: 80
          path: /v1/**
          audience: api://beta
          scopes: [beta.read]
",
        )
        .expect("profile should parse");

        let token_grant = profile.credentials[0]
            .token_grant
            .as_ref()
            .expect("token grant should parse");
        assert_eq!(
            token_grant.jwt_svid_audience,
            "http://keycloak.default.svc.cluster.local/realms/openshell"
        );
        assert_eq!(
            token_grant.client_assertion_type,
            "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"
        );
        assert_eq!(token_grant.audience_overrides.len(), 2);
        assert_eq!(token_grant.audience_overrides[1].path, "/v1/**");
        assert_eq!(token_grant.audience_overrides[1].scopes, vec!["beta.read"]);

        let reparsed = ProviderTypeProfile::from_proto(&profile.to_proto());
        let reparsed_token_grant = reparsed.credentials[0]
            .token_grant
            .as_ref()
            .expect("token grant should round trip");
        assert_eq!(
            reparsed_token_grant.jwt_svid_audience,
            token_grant.jwt_svid_audience
        );
        assert_eq!(
            reparsed_token_grant.audience_overrides,
            token_grant.audience_overrides
        );
    }

    #[test]
    fn validate_profile_set_rejects_plain_http_token_endpoint() {
        for token_endpoint in [
            "http://auth.example.com/token",
            "http://token-issuer.default.svc.evil.com/token",
        ] {
            let profile = parse_profile_yaml(&format!(
                r"
id: insecure-token-grant
display_name: Insecure Token Grant
credentials:
  - name: access_token
    auth_style: bearer
    header_name: Authorization
    token_grant:
      token_endpoint: {token_endpoint}
      audience: api://default
"
            ))
            .expect("profile should parse");

            let diagnostics = validate_profile_set(&[("insecure.yaml".to_string(), profile)]);
            let diagnostic = diagnostics
                .iter()
                .find(|diagnostic| diagnostic.field == "credentials.token_grant.token_endpoint")
                .expect("token endpoint diagnostic should be reported");

            assert_eq!(
                diagnostic.message,
                "token_endpoint must use https, except http for loopback or in-cluster service hosts"
            );
        }
    }

    #[test]
    fn validate_profile_set_allows_https_loopback_and_in_cluster_token_endpoints() {
        for token_endpoint in [
            "https://auth.example.com/token",
            "http://127.0.0.1:8180/token",
            "http://token-issuer.default.svc.cluster.local/token",
        ] {
            let profile = parse_profile_yaml(&format!(
                r"
id: secure-token-grant
display_name: Secure Token Grant
credentials:
  - name: access_token
    auth_style: bearer
    header_name: Authorization
    token_grant:
      token_endpoint: {token_endpoint}
      audience: api://default
"
            ))
            .expect("profile should parse");

            let diagnostics = validate_profile_set(&[("secure.yaml".to_string(), profile)]);
            assert!(
                diagnostics.is_empty(),
                "unexpected diagnostics for {token_endpoint}: {diagnostics:?}"
            );
        }
    }

    #[test]
    fn validate_profile_set_rejects_relative_token_endpoint() {
        let profile = parse_profile_yaml(
            r"
id: relative-token-grant
display_name: Relative Token Grant
credentials:
  - name: access_token
    auth_style: bearer
    header_name: Authorization
    token_grant:
      token_endpoint: /token
      audience: api://default
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("relative.yaml".to_string(), profile)]);
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.field == "credentials.token_grant.token_endpoint")
            .expect("token endpoint diagnostic should be reported");

        assert_eq!(diagnostic.message, "token_endpoint must be an absolute URL");
    }

    #[test]
    fn validate_profile_set_rejects_token_grant_query_or_path_auth_style() {
        for auth_style in ["query", "path"] {
            let profile = parse_profile_yaml(&format!(
                r"
id: unsupported-token-grant-style
display_name: Unsupported Token Grant Style
credentials:
  - name: access_token
    auth_style: {auth_style}
    token_grant:
      token_endpoint: https://auth.example.com/token
"
            ))
            .expect("profile should parse");

            let diagnostics = validate_profile_set(&[("unsupported.yaml".to_string(), profile)]);
            let diagnostic = diagnostics
                .iter()
                .find(|diagnostic| diagnostic.field == "credentials.token_grant.auth_style")
                .expect("auth style diagnostic should be reported");

            assert_eq!(
                diagnostic.message,
                "token_grant credentials support auth_style bearer or header"
            );
        }
    }

    #[test]
    fn validate_profile_set_requires_header_name_for_token_grant_header_auth_style() {
        let profile = parse_profile_yaml(
            r"
id: missing-header-token-grant
display_name: Missing Header Token Grant
credentials:
  - name: access_token
    auth_style: header
    token_grant:
      token_endpoint: https://auth.example.com/token
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("missing-header.yaml".to_string(), profile)]);
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.field == "credentials.header_name")
            .expect("header_name diagnostic should be reported");

        assert_eq!(
            diagnostic.message,
            "header_name is required for header auth"
        );
    }

    #[test]
    fn validate_profile_set_rejects_token_grant_framing_header_name() {
        let profile = parse_profile_yaml(
            r"
id: framing-header-token-grant
display_name: Framing Header Token Grant
credentials:
  - name: access_token
    auth_style: header
    header_name: Content-Length
    token_grant:
      token_endpoint: https://auth.example.com/token
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("framing.yaml".to_string(), profile)]);
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| {
                diagnostic.field == "credentials.header_name"
                    && diagnostic.message.contains("HTTP framing")
            })
            .expect("framing header diagnostic should be reported");

        assert_eq!(
            diagnostic.message,
            "token_grant header_name may not override HTTP framing or connection headers"
        );
    }

    #[test]
    fn validate_profile_set_rejects_ambiguous_same_credential_audience_overrides() {
        let profile = parse_profile_yaml(
            r"
id: ambiguous-token-grant
display_name: Ambiguous Token Grant
credentials:
  - name: access_token
    auth_style: bearer
    header_name: Authorization
    token_grant:
      token_endpoint: https://auth.example.com/token
      audience: api://default
      audience_overrides:
        - audience: api://alpha
        - host: alpha.default.svc.cluster.local
          audience: api://beta
endpoints:
  - host: alpha.default.svc.cluster.local
    port: 80
    path: /v1/**
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("ambiguous.yaml".to_string(), profile)]);
        let diagnostic = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.field == "credentials.token_grant.audience_overrides")
            .expect("audience override diagnostic should be reported");

        assert!(
            diagnostic
                .message
                .contains("ambiguous token_grant audience_overrides")
        );
        assert!(diagnostic.message.contains("indexes 0 and 1"));
    }

    #[test]
    fn validate_profile_set_allows_more_specific_audience_override_path() {
        let profile = parse_profile_yaml(
            r"
id: specific-token-grant
display_name: Specific Token Grant
credentials:
  - name: access_token
    auth_style: bearer
    header_name: Authorization
    token_grant:
      token_endpoint: https://auth.example.com/token
      audience: api://default
      audience_overrides:
        - path: /v1/**
          audience: api://alpha
        - path: /v1/admin/**
          audience: api://admin
endpoints:
  - host: alpha.default.svc.cluster.local
    port: 80
    path: /v1/**
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("specific.yaml".to_string(), profile)]);

        assert!(
            diagnostics.is_empty(),
            "unexpected diagnostics: {diagnostics:?}"
        );
    }

    #[test]
    fn profile_json_round_trip_preserves_compact_dto_shape() {
        let profile = get_default_profile("github").expect("github profile");
        let json = profile_to_json(profile).expect("profile should serialize");
        let parsed = parse_profile_json(&json).expect("profile should parse");

        assert_eq!(parsed.id, "github");
        assert_eq!(parsed.category, ProviderProfileCategory::SourceControl);
        assert_eq!(parsed.binaries[0].path, "/usr/bin/gh");
    }

    #[test]
    fn profile_yaml_round_trip_preserves_full_network_policy_fields() {
        let profile = parse_profile_yaml(
            r"
id: advanced
display_name: Advanced
category: other
endpoints:
  - host: api.example.com
    ports: [443, 8443]
    protocol: rest
    tls: terminate
    enforcement: enforce
    access: read-only
    rules:
      - allow:
          method: GET
          path: /v1/**
          query:
            state:
              any: [open, closed]
    allowed_ips: [10.0.0.0/24]
    deny_rules:
      - method: POST
        path: /admin/**
    allow_encoded_slash: true
    persisted_queries: allow_registered
    graphql_persisted_queries:
      hash-a:
        operation_type: query
        operation_name: Viewer
        fields: [viewer]
    graphql_max_body_bytes: 131072
    path: /graphql
binaries:
  - path: /usr/bin/custom
    harness: true
",
        )
        .expect("profile should parse");
        let diagnostics = validate_profile_set(&[("advanced.yaml".to_string(), profile.clone())]);
        assert!(
            diagnostics.is_empty(),
            "unexpected diagnostics: {diagnostics:?}"
        );

        let proto = profile.to_proto();
        let endpoint = proto.endpoints.first().expect("endpoint should exist");
        assert_eq!(endpoint.port, 0);
        assert_eq!(endpoint.ports, vec![443, 8443]);
        assert_eq!(endpoint.tls, "terminate");
        assert_eq!(endpoint.allowed_ips, vec!["10.0.0.0/24"]);
        assert!(endpoint.allow_encoded_slash);
        assert_eq!(endpoint.persisted_queries, "allow_registered");
        assert_eq!(endpoint.graphql_max_body_bytes, 131_072);
        assert_eq!(endpoint.path, "/graphql");
        assert_eq!(
            endpoint
                .rules
                .first()
                .and_then(|rule| rule.allow.as_ref())
                .map(|allow| allow.method.as_str()),
            Some("GET")
        );
        assert_eq!(endpoint.deny_rules[0].method, "POST");
        assert_eq!(
            endpoint
                .graphql_persisted_queries
                .get("hash-a")
                .map(|operation| operation.operation_name.as_str()),
            Some("Viewer")
        );
        assert!(proto.binaries[0].harness);

        let reparsed = parse_profile_yaml(&profile_to_yaml(&profile).expect("serialize YAML"))
            .expect("serialized profile should parse");
        let reprotoo = reparsed.to_proto();
        assert_eq!(reprotoo.endpoints[0].rules.len(), 1);
        assert_eq!(reprotoo.endpoints[0].deny_rules.len(), 1);
        assert_eq!(reprotoo.endpoints[0].ports, vec![443, 8443]);
        assert!(reprotoo.binaries[0].harness);
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
  - name: path_key
    env_vars: [PATH_TOKEN]
    auth_style: path
  - name: path_key_bad
    env_vars: [PATH_TOKEN_BAD]
    auth_style: path
    path_template: /v1/{key}/resources
discovery:
  credentials: [api_key, missing_key]
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
        assert!(messages.contains(&"path_template is required for path auth"));
        assert!(messages.iter().any(|message| {
            message.contains("should contain {credential} exactly once")
                && message.contains("0 times")
        }));
        assert!(messages.contains(&"unsupported auth_style: unknown"));
        assert!(messages.contains(&"unknown discovery credential: missing_key"));
        assert!(
            messages
                .iter()
                .any(|message| message.starts_with("invalid endpoint"))
        );
        assert!(messages.contains(&"binary path must not be empty"));
    }

    #[test]
    fn validate_profile_set_rejects_noncanonical_profile_ids() {
        let profiles = [
            (
                "space.yaml".to_string(),
                ProviderTypeProfile {
                    id: " alex-api ".to_string(),
                    resource_version: 0,
                    display_name: "Space".to_string(),
                    description: String::new(),
                    category: ProviderProfileCategory::Other,
                    credentials: Vec::new(),
                    endpoints: Vec::new(),
                    binaries: Vec::new(),
                    inference_capable: false,
                    discovery: DiscoveryProfile::default(),
                },
            ),
            (
                "underscore.yaml".to_string(),
                ProviderTypeProfile {
                    id: "alex_api".to_string(),
                    resource_version: 0,
                    display_name: "Underscore".to_string(),
                    description: String::new(),
                    category: ProviderProfileCategory::Other,
                    credentials: Vec::new(),
                    endpoints: Vec::new(),
                    binaries: Vec::new(),
                    inference_capable: false,
                    discovery: DiscoveryProfile::default(),
                },
            ),
            (
                "case.yaml".to_string(),
                ProviderTypeProfile {
                    id: "Alex-API".to_string(),
                    resource_version: 0,
                    display_name: "Case".to_string(),
                    description: String::new(),
                    category: ProviderProfileCategory::Other,
                    credentials: Vec::new(),
                    endpoints: Vec::new(),
                    binaries: Vec::new(),
                    inference_capable: false,
                    discovery: DiscoveryProfile::default(),
                },
            ),
        ];

        let diagnostics = validate_profile_set(&profiles);
        let id_errors = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.field == "id")
            .collect::<Vec<_>>();

        assert_eq!(id_errors.len(), 3);
        assert!(
            id_errors
                .iter()
                .all(|diagnostic| diagnostic.message.contains("lowercase kebab-case"))
        );
    }

    #[test]
    fn normalize_profile_id_trims_and_lowercases_valid_ids() {
        assert_eq!(
            normalize_profile_id(" Alex-API "),
            Some("alex-api".to_string())
        );
        assert_eq!(normalize_profile_id("alex_api"), None);
        assert_eq!(normalize_profile_id("-alex"), None);
        assert_eq!(normalize_profile_id("alex--api"), None);
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
