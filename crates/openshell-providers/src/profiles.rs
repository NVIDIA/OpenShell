// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Declarative provider type profiles.

#![allow(deprecated)] // NetworkBinary::harness remains in the public proto for compatibility.

use openshell_core::proto::{
    GraphqlOperation, L7Allow, L7DenyRule, L7QueryMatcher, L7Rule, McpOptions, NetworkBinary,
    NetworkEndpoint, NetworkPolicyRule, ProviderCredentialRefresh,
    ProviderCredentialRefreshMaterial, ProviderCredentialRefreshOutput,
    ProviderCredentialRefreshStrategy, ProviderProfile, ProviderProfileCategory,
    ProviderProfileCredential, ProviderProfileDiscovery,
};
use openshell_core::secrets::uses_reserved_revision_namespace;
use openshell_policy::{L7EndpointFields, validate_l7_endpoint_semantics};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::OnceLock;

const PATH_TEMPLATE_CREDENTIAL_PLACEHOLDER: &str = "{credential}";

const BUILT_IN_PROFILE_YAMLS: &[&str] = &[
    include_str!("../../../providers/aws.yaml"),
    include_str!("../../../providers/aws-bedrock.yaml"),
    include_str!("../../../providers/aws-s3.yaml"),
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
    #[error("provider profile '{id}' validation error: {field}: {message}")]
    ValidationError {
        id: String,
        field: String,
        message: String,
    },
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
    /// Additional credentials this refresh mints beyond its primary credential.
    /// Each entry maps a strategy-defined semantic output id to a sibling
    /// credential whose `env_vars` receive the minted value.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_outputs: Vec<CredentialRefreshOutputProfile>,
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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct CredentialRefreshOutputProfile {
    /// Strategy-defined semantic output id (e.g. `session_token`).
    pub output: String,
    /// Sibling credential name whose `env_vars` receive this output.
    pub credential: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<L7RuleProfile>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_rules: Option<Vec<L7DenyRuleProfile>>,
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
    #[serde(default, skip_serializing_if = "is_zero")]
    pub json_rpc_max_body_bytes: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp: Option<McpOptionsProfile>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub credential_signing: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signing_service: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signing_region: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct McpOptionsProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict_tool_names: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_all_known_mcp_methods: Option<bool>,
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
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub params: HashMap<String, L7QueryMatcherProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<L7QueryMatcherProfile>,
}

impl L7AllowProfile {
    fn has_tool_selector(&self) -> bool {
        self.params.contains_key("name") || self.tool.is_some()
    }

    fn is_effectively_empty(&self) -> bool {
        self.method.is_empty()
            && self.path.is_empty()
            && self.command.is_empty()
            && self.operation_type.is_empty()
            && self.operation_name.is_empty()
            && !self.has_tool_selector()
    }
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
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub params: HashMap<String, L7QueryMatcherProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<L7QueryMatcherProfile>,
}

impl L7DenyRuleProfile {
    fn has_tool_selector(&self) -> bool {
        self.params.contains_key("name") || self.tool.is_some()
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct L7QueryMatcherProfile {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub glob: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any: Vec<String>,
}

impl<'de> Deserialize<'de> for L7QueryMatcherProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringOrObject {
            Scalar(String),
            Object {
                #[serde(default)]
                glob: String,
                #[serde(default)]
                any: Vec<String>,
            },
        }
        match StringOrObject::deserialize(deserializer)? {
            StringOrObject::Scalar(s) => Ok(Self {
                glob: s,
                any: vec![],
            }),
            StringOrObject::Object { glob, any } => Ok(Self { glob, any }),
        }
    }
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
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
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
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
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
            annotations: profile.annotations.clone(),
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
            source: profile.source.clone(),
            scope: profile.scope.clone(),
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
    /// refresh credentials, sandbox-side dynamic token grants, or additional
    /// outputs co-minted by another credential's gateway-mintable refresh.
    #[must_use]
    pub fn allows_empty_provider_credentials(&self) -> bool {
        let co_minted = self.co_minted_credential_names();
        let mut has_runtime_resolvable_credential = false;
        for credential in &self.credentials {
            let is_runtime_resolvable =
                credential.is_runtime_resolvable() || co_minted.contains(credential.name.as_str());
            if credential.required && !is_runtime_resolvable {
                return false;
            }
            has_runtime_resolvable_credential |= is_runtime_resolvable;
        }
        has_runtime_resolvable_credential
    }

    /// Names of credentials produced as `additional_outputs` of a
    /// gateway-mintable refresh on some other credential.
    fn co_minted_credential_names(&self) -> HashSet<&str> {
        self.credentials
            .iter()
            .filter_map(|credential| credential.refresh.as_ref())
            .filter(|refresh| refresh.is_gateway_mintable())
            .flat_map(|refresh| refresh.additional_outputs.iter())
            .map(|output| output.credential.as_str())
            .collect()
    }

    /// For the credential resolved by `credential_key` (matched by name or env
    /// var) that carries a refresh with `additional_outputs`, resolve each
    /// output to the concrete env key of its target credential. Returns a map
    /// of semantic output id -> env key (empty when there is no such refresh or
    /// no additional outputs). Skips outputs whose target credential is missing
    /// or does not declare exactly one env var; `validate_profile_set` reports
    /// those as errors.
    #[must_use]
    pub fn resolved_additional_output_keys(&self, credential_key: &str) -> HashMap<String, String> {
        let Some(refresh) = self
            .credentials
            .iter()
            .find(|credential| {
                credential.name == credential_key
                    || credential.env_vars.iter().any(|env| env == credential_key)
            })
            .and_then(|credential| credential.refresh.as_ref())
        else {
            return HashMap::new();
        };
        refresh
            .additional_outputs
            .iter()
            .filter_map(|output| {
                let target = self
                    .credentials
                    .iter()
                    .find(|credential| credential.name == output.credential)?;
                let [env_key] = target.env_vars.as_slice() else {
                    return None;
                };
                Some((output.output.clone(), env_key.clone()))
            })
            .collect()
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
            annotations: self.annotations.clone(),
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
            source: self.source.clone(),
            scope: self.scope.clone(),
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

    pub fn validate_before_lowering(&self, source: &str) -> Vec<ProfileValidationDiagnostic> {
        let mut diagnostics = Vec::new();
        for (index, endpoint) in self.endpoints.iter().enumerate() {
            if endpoint.rules.as_ref().is_some_and(Vec::is_empty) {
                diagnostics.push(ProfileValidationDiagnostic::error(
                    source,
                    &self.id,
                    format!("endpoints[{index}]"),
                    "rules list cannot be empty (would deny all traffic). \
                     Use `access: full` or remove rules.",
                ));
            }
            if endpoint.deny_rules.as_ref().is_some_and(Vec::is_empty) {
                diagnostics.push(ProfileValidationDiagnostic::error(
                    source,
                    &self.id,
                    format!("endpoints[{index}]"),
                    "deny_rules list cannot be empty (would have no effect). \
                     Remove it if no denials are needed.",
                ));
            }

            if endpoint.protocol != "mcp" {
                continue;
            }
            if let Some(rules) = &endpoint.rules {
                for (rule_idx, rule) in rules.iter().enumerate() {
                    if rule
                        .allow
                        .as_ref()
                        .is_some_and(|a| a.tool.is_some() && a.params.contains_key("name"))
                    {
                        diagnostics.push(ProfileValidationDiagnostic::error(
                            source,
                            &self.id,
                            format!("endpoints[{index}].rules[{rule_idx}].allow"),
                            "MCP rules must use either tool or params.name, not both",
                        ));
                    }
                }
            }
            if let Some(deny_rules) = &endpoint.deny_rules {
                for (deny_idx, deny_rule) in deny_rules.iter().enumerate() {
                    if deny_rule.tool.is_some() && deny_rule.params.contains_key("name") {
                        diagnostics.push(ProfileValidationDiagnostic::error(
                            source,
                            &self.id,
                            format!("endpoints[{index}].deny_rules[{deny_idx}]"),
                            "MCP rules must use either tool or params.name, not both",
                        ));
                    }
                }
            }
        }
        diagnostics
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
        is_gateway_mintable_strategy(self.strategy)
    }
}

/// Whether the gateway can mint credentials for this refresh strategy (as
/// opposed to strategies resolved elsewhere, e.g. `Static`/`External`).
///
/// Single source of truth shared with `openshell-server`; keep in sync with the
/// dispatch in `provider_refresh::mint_credential`.
#[must_use]
pub fn is_gateway_mintable_strategy(strategy: ProviderCredentialRefreshStrategy) -> bool {
    matches!(
        strategy,
        ProviderCredentialRefreshStrategy::Oauth2RefreshToken
            | ProviderCredentialRefreshStrategy::Oauth2ClientCredentials
            | ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt
            | ProviderCredentialRefreshStrategy::AwsStsAssumeRole
    )
}

/// Semantic output ids a refresh strategy can produce **in addition** to its
/// primary credential, split into required and optional.
///
/// Drives `additional_outputs` validation. Strategies not listed here produce
/// only a single (primary) credential and reject any `additional_outputs`.
#[must_use]
pub fn strategy_output_spec(
    strategy: ProviderCredentialRefreshStrategy,
) -> (&'static [&'static str], &'static [&'static str]) {
    match strategy {
        ProviderCredentialRefreshStrategy::AwsStsAssumeRole => {
            (&["secret_access_key", "session_token"], &[])
        }
        _ => (&[], &[]),
    }
}

/// Expected primary env key for strategies that constrain it, or `None` when the
/// strategy accepts any caller-chosen primary key.
///
/// AWS `SigV4` signing looks up `AWS_ACCESS_KEY_ID` by name, so STS pins the
/// primary key.
#[must_use]
pub fn strategy_primary_env_key(
    strategy: ProviderCredentialRefreshStrategy,
) -> Option<&'static str> {
    match strategy {
        ProviderCredentialRefreshStrategy::AwsStsAssumeRole => Some("AWS_ACCESS_KEY_ID"),
        _ => None,
    }
}

/// Expected concrete env key for a given strategy output, when the strategy
/// constrains it (the `SigV4` signer resolves these by name).
#[must_use]
pub fn strategy_output_env_key(
    strategy: ProviderCredentialRefreshStrategy,
    output: &str,
) -> Option<&'static str> {
    match (strategy, output) {
        (ProviderCredentialRefreshStrategy::AwsStsAssumeRole, "secret_access_key") => {
            Some("AWS_SECRET_ACCESS_KEY")
        }
        (ProviderCredentialRefreshStrategy::AwsStsAssumeRole, "session_token") => {
            Some("AWS_SESSION_TOKEN")
        }
        _ => None,
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
        "aws_sts_assume_role" => Some(ProviderCredentialRefreshStrategy::AwsStsAssumeRole),
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
        ProviderCredentialRefreshStrategy::AwsStsAssumeRole => "aws_sts_assume_role",
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
        additional_outputs: refresh
            .additional_outputs
            .iter()
            .map(|output| CredentialRefreshOutputProfile {
                output: output.output.clone(),
                credential: output.credential.clone(),
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
        additional_outputs: refresh
            .additional_outputs
            .iter()
            .map(|output| ProviderCredentialRefreshOutput {
                output: output.output.clone(),
                credential: output.credential.clone(),
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
        rules: endpoint
            .rules
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(rule_to_proto)
            .collect(),
        allowed_ips: endpoint.allowed_ips.clone(),
        ports: endpoint.ports.clone(),
        deny_rules: endpoint
            .deny_rules
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(deny_rule_to_proto)
            .collect(),
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
        json_rpc_max_body_bytes: endpoint.json_rpc_max_body_bytes,
        mcp: endpoint.mcp.as_ref().map(mcp_options_to_proto),
        path: endpoint.path.clone(),
        credential_signing: endpoint.credential_signing.clone(),
        signing_service: endpoint.signing_service.clone(),
        signing_region: endpoint.signing_region.clone(),
        // Credential bindings reference a concrete sandbox provider instance
        // and therefore cannot be authored by a reusable provider profile.
        credential_binding: None,
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
        rules: if endpoint.rules.is_empty() {
            None
        } else {
            Some(endpoint.rules.iter().map(rule_from_proto).collect())
        },
        allowed_ips: endpoint.allowed_ips.clone(),
        ports: endpoint.ports.clone(),
        deny_rules: if endpoint.deny_rules.is_empty() {
            None
        } else {
            Some(
                endpoint
                    .deny_rules
                    .iter()
                    .map(deny_rule_from_proto)
                    .collect(),
            )
        },
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
        json_rpc_max_body_bytes: endpoint.json_rpc_max_body_bytes,
        mcp: endpoint.mcp.map(mcp_options_from_proto),
        path: endpoint.path.clone(),
        credential_signing: endpoint.credential_signing.clone(),
        signing_service: endpoint.signing_service.clone(),
        signing_region: endpoint.signing_region.clone(),
    }
}

fn mcp_options_to_proto(options: &McpOptionsProfile) -> McpOptions {
    McpOptions {
        strict_tool_names: options.strict_tool_names,
        allow_all_known_mcp_methods: options.allow_all_known_mcp_methods,
    }
}

fn mcp_options_from_proto(options: McpOptions) -> McpOptionsProfile {
    McpOptionsProfile {
        strict_tool_names: options.strict_tool_names,
        allow_all_known_mcp_methods: options.allow_all_known_mcp_methods,
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

fn glob_uses_wildcard(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[') || s.contains('{')
}

fn matcher_uses_glob_wildcard(matcher: &L7QueryMatcherProfile) -> bool {
    glob_uses_wildcard(&matcher.glob) || matcher.any.iter().any(|s| glob_uses_wildcard(s))
}

fn validate_mcp_matcher(
    diagnostics: &mut Vec<ProfileValidationDiagnostic>,
    source: &str,
    profile_id: &str,
    field: &str,
    matcher: &L7QueryMatcherProfile,
    strict_tool_names: bool,
) {
    if !matcher.glob.is_empty() && !matcher.any.is_empty() {
        diagnostics.push(ProfileValidationDiagnostic::error(
            source,
            profile_id,
            field.to_string(),
            "matcher cannot specify both glob and any",
        ));
    }
    if matcher.glob.is_empty() && matcher.any.is_empty() {
        diagnostics.push(ProfileValidationDiagnostic::error(
            source,
            profile_id,
            field.to_string(),
            "matcher must specify glob or any",
        ));
    }
    if !strict_tool_names && matcher_uses_glob_wildcard(matcher) {
        diagnostics.push(ProfileValidationDiagnostic::error(
            source,
            profile_id,
            field.to_string(),
            "wildcard tool-name matchers require mcp.strict_tool_names to remain enabled",
        ));
    }
}

fn method_matcher_matches_tools_call(method: &str) -> bool {
    method == "tools/call"
        || method == "*"
        || glob::Pattern::new(method).is_ok_and(|pattern| pattern.matches("tools/call"))
}

fn allow_to_proto(allow: &L7AllowProfile) -> L7Allow {
    let mut params: HashMap<String, L7QueryMatcher> = allow
        .params
        .iter()
        .map(|(name, matcher)| (name.clone(), query_matcher_to_proto(matcher)))
        .collect();
    if let Some(tool) = &allow.tool {
        params
            .entry("name".to_string())
            .or_insert_with(|| query_matcher_to_proto(tool));
    }
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
        params,
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
        params: allow
            .params
            .iter()
            .map(|(name, matcher)| (name.clone(), query_matcher_from_proto(matcher)))
            .collect(),
        tool: None,
    }
}

fn deny_rule_to_proto(rule: &L7DenyRuleProfile) -> L7DenyRule {
    let mut params: HashMap<String, L7QueryMatcher> = rule
        .params
        .iter()
        .map(|(name, matcher)| (name.clone(), query_matcher_to_proto(matcher)))
        .collect();
    if let Some(tool) = &rule.tool {
        params
            .entry("name".to_string())
            .or_insert_with(|| query_matcher_to_proto(tool));
    }
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
        params,
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
        params: rule
            .params
            .iter()
            .map(|(name, matcher)| (name.clone(), query_matcher_from_proto(matcher)))
            .collect(),
        tool: None,
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
        return Err(ProfileError::ValidationError {
            id: diagnostic.profile_id.clone(),
            field: diagnostic.field.clone(),
            message: diagnostic.message.clone(),
        });
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
                } else if uses_reserved_revision_namespace(env_var.trim()) {
                    diagnostics.push(ProfileValidationDiagnostic::error(
                        source,
                        profile_id,
                        "credentials.env_vars",
                        format!(
                            "credential env var '{env_var}' uses reserved OpenShell placeholder revision namespace"
                        ),
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

                let strategy_name = provider_refresh_strategy_to_yaml(refresh.strategy);
                let (required_outputs, optional_outputs) = strategy_output_spec(refresh.strategy);
                let known_outputs: HashSet<&str> = required_outputs
                    .iter()
                    .chain(optional_outputs.iter())
                    .copied()
                    .collect();

                if known_outputs.is_empty() && !refresh.additional_outputs.is_empty() {
                    diagnostics.push(ProfileValidationDiagnostic::error(
                        source,
                        profile_id,
                        "credentials.refresh.additional_outputs",
                        format!("strategy {strategy_name} does not support additional_outputs"),
                    ));
                }

                let mut seen_outputs = HashSet::new();
                let mut mapped_required = HashSet::new();
                for output in &refresh.additional_outputs {
                    let output_id = output.output.trim();
                    let cred_name = output.credential.trim();

                    if output_id.is_empty() {
                        diagnostics.push(ProfileValidationDiagnostic::error(
                            source,
                            profile_id,
                            "credentials.refresh.additional_outputs.output",
                            "refresh additional output id is required",
                        ));
                        continue;
                    }
                    if !seen_outputs.insert(output_id.to_string()) {
                        diagnostics.push(ProfileValidationDiagnostic::error(
                            source,
                            profile_id,
                            "credentials.refresh.additional_outputs.output",
                            format!("duplicate refresh additional output: {output_id}"),
                        ));
                    }
                    if known_outputs.contains(output_id) {
                        if required_outputs.contains(&output_id) {
                            mapped_required.insert(output_id.to_string());
                        }
                    } else if !known_outputs.is_empty() {
                        diagnostics.push(ProfileValidationDiagnostic::error(
                            source,
                            profile_id,
                            "credentials.refresh.additional_outputs.output",
                            format!(
                                "strategy {strategy_name} does not produce output '{output_id}'"
                            ),
                        ));
                    }

                    let Some(sibling) = profile.credentials.iter().find(|c| c.name == cred_name)
                    else {
                        diagnostics.push(ProfileValidationDiagnostic::error(
                            source,
                            profile_id,
                            "credentials.refresh.additional_outputs.credential",
                            format!(
                                "refresh additional output '{output_id}' references unknown credential '{cred_name}'"
                            ),
                        ));
                        continue;
                    };
                    if sibling.refresh.is_some() {
                        diagnostics.push(ProfileValidationDiagnostic::error(
                            source,
                            profile_id,
                            "credentials.refresh.additional_outputs.credential",
                            format!(
                                "credential '{cred_name}' is a refresh output and must not declare its own refresh"
                            ),
                        ));
                    }
                    if sibling.env_vars.len() != 1 {
                        diagnostics.push(ProfileValidationDiagnostic::error(
                            source,
                            profile_id,
                            "credentials.refresh.additional_outputs.credential",
                            format!(
                                "refresh output credential '{cred_name}' must declare exactly one env var"
                            ),
                        ));
                        continue;
                    }
                    let resolved = sibling.env_vars[0].as_str();
                    if let Some(expected) = strategy_output_env_key(refresh.strategy, output_id)
                        && resolved != expected
                    {
                        diagnostics.push(ProfileValidationDiagnostic::error(
                            source,
                            profile_id,
                            "credentials.refresh.additional_outputs.credential",
                            format!(
                                "refresh output '{output_id}' must map to env var {expected}, found {resolved}"
                            ),
                        ));
                    }
                }

                for required in required_outputs {
                    if !mapped_required.contains(*required) {
                        diagnostics.push(ProfileValidationDiagnostic::error(
                            source,
                            profile_id,
                            "credentials.refresh.additional_outputs",
                            format!(
                                "strategy {strategy_name} requires additional output '{required}'"
                            ),
                        ));
                    }
                }

                if let Some(expected_primary) = strategy_primary_env_key(refresh.strategy)
                    && (credential.env_vars.len() != 1
                        || credential.env_vars[0] != expected_primary)
                {
                    diagnostics.push(ProfileValidationDiagnostic::error(
                        source,
                        profile_id,
                        "credentials.env_vars",
                        format!(
                            "strategy {strategy_name} requires primary credential to map to env var {expected_primary}"
                        ),
                    ));
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

            if endpoint.rules.as_ref().is_some_and(Vec::is_empty) {
                diagnostics.push(ProfileValidationDiagnostic::error(
                    source,
                    profile_id,
                    format!("endpoints[{index}]"),
                    "rules list cannot be empty (would deny all traffic). Use `access: full` or remove rules.",
                ));
            }

            if endpoint.deny_rules.as_ref().is_some_and(Vec::is_empty) {
                diagnostics.push(ProfileValidationDiagnostic::error(
                    source,
                    profile_id,
                    format!("endpoints[{index}]"),
                    "deny_rules list cannot be empty (would have no effect). Remove it if no denials are needed.",
                ));
            }

            let l7_fields = L7EndpointFields {
                protocol: &endpoint.protocol,
                access: &endpoint.access,
                has_rules: endpoint.rules.as_ref().is_some_and(|r| !r.is_empty()),
                has_deny_rules: endpoint.deny_rules.as_ref().is_some_and(|r| !r.is_empty()),
                rules_would_deny_all: endpoint.rules.as_ref().is_some_and(|r| {
                    !r.is_empty()
                        && r.iter().all(|rule| {
                            rule.allow
                                .as_ref()
                                .is_none_or(L7AllowProfile::is_effectively_empty)
                        })
                }),
                allow_all_known_mcp_methods: endpoint
                    .mcp
                    .as_ref()
                    .and_then(|opts| opts.allow_all_known_mcp_methods)
                    .unwrap_or(false),
            };
            for msg in validate_l7_endpoint_semantics(&l7_fields) {
                diagnostics.push(ProfileValidationDiagnostic::error(
                    source,
                    profile_id,
                    format!("endpoints[{index}]"),
                    msg,
                ));
            }

            if endpoint.protocol == "mcp" {
                let strict_tool_names = endpoint
                    .mcp
                    .as_ref()
                    .and_then(|opts| opts.strict_tool_names)
                    .unwrap_or(true);

                if let Some(rules) = &endpoint.rules {
                    for (rule_idx, rule) in rules.iter().enumerate() {
                        if let Some(allow) = &rule.allow {
                            let allow_loc = format!("endpoints[{index}].rules[{rule_idx}].allow");
                            if allow.tool.is_some() && allow.params.contains_key("name") {
                                diagnostics.push(ProfileValidationDiagnostic::error(
                                    source,
                                    profile_id,
                                    &allow_loc,
                                    "MCP rules must use either tool or params.name, not both",
                                ));
                            }
                            if allow.has_tool_selector()
                                && !allow.method.is_empty()
                                && allow.method != "tools/call"
                            {
                                diagnostics.push(ProfileValidationDiagnostic::error(
                                    source,
                                    profile_id,
                                    &allow_loc,
                                    "method must be tools/call when an MCP rule uses \
                                     tool or params.name",
                                ));
                            }
                            if allow.method.is_empty() && !l7_fields.allow_all_known_mcp_methods {
                                diagnostics.push(ProfileValidationDiagnostic::error(
                                    source,
                                    profile_id,
                                    &allow_loc,
                                    "method is required when \
                                     mcp.allow_all_known_mcp_methods is false",
                                ));
                            }
                            if glob_uses_wildcard(&allow.method)
                                && !allow.method.starts_with("tools/")
                            {
                                diagnostics.push(ProfileValidationDiagnostic::error(
                                    source,
                                    profile_id,
                                    format!("{allow_loc}.method"),
                                    "MCP method globs are only valid for the tools/ \
                                     method family; omit method to use the endpoint \
                                     method profile",
                                ));
                            }
                            if !allow.path.is_empty() || !allow.query.is_empty() {
                                diagnostics.push(ProfileValidationDiagnostic::error(
                                    source,
                                    profile_id,
                                    &allow_loc,
                                    "mcp L7 rules must use method/tool, not path/query",
                                ));
                            }
                            for key in allow.params.keys() {
                                if key != "name" {
                                    diagnostics.push(ProfileValidationDiagnostic::error(
                                        source,
                                        profile_id,
                                        format!("{allow_loc}.params.{key}"),
                                        "MCP tool argument matching is not supported yet",
                                    ));
                                }
                            }
                            if let Some(tool) = &allow.tool {
                                validate_mcp_matcher(
                                    &mut diagnostics,
                                    source,
                                    profile_id,
                                    &format!("{allow_loc}.tool"),
                                    tool,
                                    strict_tool_names,
                                );
                            }
                            if let Some(params_name) = allow.params.get("name") {
                                validate_mcp_matcher(
                                    &mut diagnostics,
                                    source,
                                    profile_id,
                                    &format!("{allow_loc}.params.name"),
                                    params_name,
                                    strict_tool_names,
                                );
                            }
                        }
                    }
                }

                if let Some(deny_rules) = &endpoint.deny_rules {
                    for (deny_idx, deny_rule) in deny_rules.iter().enumerate() {
                        let deny_loc = format!("endpoints[{index}].deny_rules[{deny_idx}]");
                        if deny_rule.tool.is_some() && deny_rule.params.contains_key("name") {
                            diagnostics.push(ProfileValidationDiagnostic::error(
                                source,
                                profile_id,
                                &deny_loc,
                                "MCP rules must use either tool or params.name, not both",
                            ));
                        }
                        if deny_rule.has_tool_selector()
                            && !deny_rule.method.is_empty()
                            && deny_rule.method != "tools/call"
                        {
                            diagnostics.push(ProfileValidationDiagnostic::error(
                                source,
                                profile_id,
                                &deny_loc,
                                "method must be tools/call when an MCP rule uses \
                                 tool or params.name",
                            ));
                        }
                        if deny_rule.method.is_empty() && !l7_fields.allow_all_known_mcp_methods {
                            diagnostics.push(ProfileValidationDiagnostic::error(
                                source,
                                profile_id,
                                &deny_loc,
                                "method is required when \
                                 mcp.allow_all_known_mcp_methods is false",
                            ));
                        }
                        if glob_uses_wildcard(&deny_rule.method)
                            && !deny_rule.method.starts_with("tools/")
                        {
                            diagnostics.push(ProfileValidationDiagnostic::error(
                                source,
                                profile_id,
                                format!("{deny_loc}.method"),
                                "MCP method globs are only valid for the tools/ \
                                 method family; omit method to use the endpoint \
                                 method profile",
                            ));
                        }
                        if !deny_rule.path.is_empty() || !deny_rule.query.is_empty() {
                            diagnostics.push(ProfileValidationDiagnostic::error(
                                source,
                                profile_id,
                                &deny_loc,
                                "mcp L7 rules must use method/tool, not path/query",
                            ));
                        }
                        for key in deny_rule.params.keys() {
                            if key != "name" {
                                diagnostics.push(ProfileValidationDiagnostic::error(
                                    source,
                                    profile_id,
                                    format!("{deny_loc}.params.{key}"),
                                    "MCP tool argument matching is not supported yet",
                                ));
                            }
                        }
                        if let Some(tool) = &deny_rule.tool {
                            validate_mcp_matcher(
                                &mut diagnostics,
                                source,
                                profile_id,
                                &format!("{deny_loc}.tool"),
                                tool,
                                strict_tool_names,
                            );
                        }
                        if let Some(params_name) = deny_rule.params.get("name") {
                            validate_mcp_matcher(
                                &mut diagnostics,
                                source,
                                profile_id,
                                &format!("{deny_loc}.params.name"),
                                params_name,
                                strict_tool_names,
                            );
                        }
                    }
                }

                let has_tool_allow_selectors = endpoint.rules.as_ref().is_some_and(|r| {
                    r.iter().any(|rule| {
                        rule.allow
                            .as_ref()
                            .is_some_and(L7AllowProfile::has_tool_selector)
                    })
                });

                if has_tool_allow_selectors {
                    if let Some(rules) = &endpoint.rules {
                        for (rule_idx, rule) in rules.iter().enumerate() {
                            if let Some(allow) = &rule.allow {
                                if !allow.has_tool_selector() {
                                    let method = allow.method.as_str();
                                    if method_matcher_matches_tools_call(method)
                                        || (method.is_empty()
                                            && l7_fields.allow_all_known_mcp_methods)
                                    {
                                        diagnostics.push(ProfileValidationDiagnostic::error(
                                            source,
                                            profile_id,
                                            format!("endpoints[{index}].rules[{rule_idx}].allow"),
                                            "method matcher allows every tool call and conflicts \
                                             with MCP tool allow rules; add tool or params.name \
                                             to narrow tools/call, or remove the tool allow rules",
                                        ));
                                    }
                                }
                            } else if l7_fields.allow_all_known_mcp_methods {
                                diagnostics.push(ProfileValidationDiagnostic::error(
                                    source,
                                    profile_id,
                                    format!("endpoints[{index}].rules[{rule_idx}].allow"),
                                    "method matcher allows every tool call and conflicts \
                                     with MCP tool allow rules; add tool or params.name \
                                     to narrow tools/call, or remove the tool allow rules",
                                ));
                            }
                        }
                    }

                    if let Some(deny_rules) = &endpoint.deny_rules {
                        for (deny_idx, deny_rule) in deny_rules.iter().enumerate() {
                            if !deny_rule.has_tool_selector()
                                && method_matcher_matches_tools_call(&deny_rule.method)
                            {
                                diagnostics.push(ProfileValidationDiagnostic::error(
                                    source,
                                    profile_id,
                                    format!("endpoints[{index}].deny_rules[{deny_idx}]"),
                                    "method matcher denies every tool call and conflicts \
                                     with MCP tool allow rules; add tool or params.name to \
                                     deny specific tools, or remove the tool allow rules",
                                ));
                            }
                        }
                    }
                }
            } else {
                if endpoint.mcp.is_some() {
                    diagnostics.push(ProfileValidationDiagnostic::error(
                        source,
                        profile_id,
                        format!("endpoints[{index}]"),
                        "mcp options are only valid for protocol mcp",
                    ));
                }
                if let Some(rules) = &endpoint.rules {
                    for (rule_idx, rule) in rules.iter().enumerate() {
                        if let Some(allow) = &rule.allow {
                            if allow.tool.is_some() {
                                diagnostics.push(ProfileValidationDiagnostic::error(
                                    source,
                                    profile_id,
                                    format!("endpoints[{index}].rules[{rule_idx}].allow.tool"),
                                    "MCP tool matching is only valid for protocol mcp",
                                ));
                            }
                            if !allow.params.is_empty() {
                                diagnostics.push(ProfileValidationDiagnostic::error(
                                    source,
                                    profile_id,
                                    format!("endpoints[{index}].rules[{rule_idx}].allow.params"),
                                    "params matching is only valid for protocol mcp",
                                ));
                            }
                        }
                    }
                }
                if let Some(deny_rules) = &endpoint.deny_rules {
                    for (deny_idx, deny_rule) in deny_rules.iter().enumerate() {
                        if deny_rule.tool.is_some() {
                            diagnostics.push(ProfileValidationDiagnostic::error(
                                source,
                                profile_id,
                                format!("endpoints[{index}].deny_rules[{deny_idx}].tool"),
                                "MCP tool matching is only valid for protocol mcp",
                            ));
                        }
                        if !deny_rule.params.is_empty() {
                            diagnostics.push(ProfileValidationDiagnostic::error(
                                source,
                                profile_id,
                                format!("endpoints[{index}].deny_rules[{deny_idx}].params"),
                                "params matching is only valid for protocol mcp",
                            ));
                        }
                    }
                }
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
    openshell_core::endpoint_path::matches(pattern, path)
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

static BUILTIN_PROFILES: OnceLock<Vec<ProviderTypeProfile>> = OnceLock::new();

#[must_use]
pub fn builtin_profiles() -> &'static [ProviderTypeProfile] {
    BUILTIN_PROFILES
        .get_or_init(|| {
            parse_profile_catalog_yamls(BUILT_IN_PROFILE_YAMLS)
                .expect("built-in provider profiles must be valid YAML")
        })
        .as_slice()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use openshell_core::proto::ProviderProfileCategory;

    use super::{
        DiscoveryProfile, L7AllowProfile, L7QueryMatcherProfile, ProfileError, ProviderTypeProfile,
        builtin_profiles, normalize_profile_id, parse_profile_catalog_yamls, parse_profile_json,
        parse_profile_yaml, profile_to_json, profile_to_yaml, validate_profile_set,
    };

    fn builtin_profile(id: &str) -> &'static ProviderTypeProfile {
        builtin_profiles()
            .iter()
            .find(|profile| profile.id == id)
            .unwrap_or_else(|| panic!("built-in profile {id} should exist"))
    }

    #[test]
    fn builtin_profiles_are_sorted_by_id() {
        let ids = builtin_profiles()
            .iter()
            .map(|profile| profile.id.as_str())
            .collect::<Vec<_>>();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn github_profile_materializes_policy_metadata() {
        let profile = builtin_profile("github");
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
            proto.endpoints.iter().all(|endpoint| {
                // The REST/GraphQL API endpoints stay read-only. The git
                // transport endpoint (github.com) carries explicit rules
                // instead so it can allow clone/fetch while blocking push.
                if endpoint.host == "github.com" {
                    endpoint.access.is_empty()
                } else {
                    endpoint.access == "read-only"
                }
            }),
            "github API endpoints should be read-only; git transport uses explicit rules"
        );
        assert_eq!(proto.binaries.len(), 4);
    }

    #[test]
    fn github_git_transport_allows_clone_but_not_push() {
        let profile = builtin_profile("github");
        let proto = profile.to_proto();

        let git_transport = proto
            .endpoints
            .iter()
            .find(|endpoint| endpoint.host == "github.com" && endpoint.port == 443)
            .expect("github.com git transport endpoint");

        // The git transport carries explicit rules rather than an access preset
        // (an empty preset would otherwise expand to GET/HEAD/OPTIONS).
        assert!(
            git_transport.access.is_empty(),
            "git transport must use explicit rules, not an access preset"
        );

        // Assert the EXACT allowed rule set. Clone/fetch over git smart HTTP
        // performs GET */info/refs (ref discovery) followed by POST
        // */git-upload-pack. A substring check alone is not enough: a broader or
        // additional POST rule (e.g. POST **) would also permit push via
        // git-receive-pack while still passing a "some rule allows upload-pack"
        // check. Pinning the whole set fails on any such regression. See #1769.
        let mut allowed: Vec<(&str, &str)> = git_transport
            .rules
            .iter()
            .map(|rule| {
                let allow = rule
                    .allow
                    .as_ref()
                    .expect("git transport rules must be allow rules");
                (allow.method.as_str(), allow.path.as_str())
            })
            .collect();
        allowed.sort_unstable();

        let mut expected = vec![
            ("GET", "**"),
            ("HEAD", "**"),
            ("OPTIONS", "**"),
            ("POST", "/**/git-upload-pack"),
        ];
        expected.sort_unstable();

        assert_eq!(
            allowed, expected,
            "git transport allow rules must be exactly the read-only methods \
             plus POST */git-upload-pack (clone/fetch); a broader or extra POST \
             rule would enable push (git-receive-pack)"
        );

        // Blocking push must not depend on a deny rule, which could mask an
        // over-broad allow and hide a regression.
        assert!(
            git_transport.deny_rules.is_empty(),
            "git transport should block push via its narrow allow set, not deny rules"
        );
    }

    #[test]
    fn credential_env_vars_are_deduplicated_in_profile_order() {
        let profile = builtin_profile("claude-code");
        assert_eq!(
            profile.credential_env_vars(),
            vec!["ANTHROPIC_API_KEY", "CLAUDE_API_KEY"]
        );
    }

    #[test]
    fn vertex_profile_declares_discovery_and_fallback_token_env_vars() {
        let profile = builtin_profile("google-vertex-ai");
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
        let profile = builtin_profile("google-cloud");
        let adc = profile
            .adc_credential()
            .expect("google-cloud should have an ADC credential");
        assert_eq!(adc.env_vars[0], "GCP_ADC_ACCESS_TOKEN");

        let profile = builtin_profile("google-vertex-ai");
        let adc = profile
            .adc_credential()
            .expect("vertex should have an ADC credential");
        assert_eq!(adc.env_vars[0], "GOOGLE_VERTEX_AI_TOKEN");
    }

    #[test]
    fn adc_credential_returns_none_for_profiles_without_adc() {
        let profile = builtin_profile("github");
        assert!(profile.adc_credential().is_none());

        let profile = builtin_profile("claude-code");
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
    fn mcp_endpoint_strict_tool_names_round_trips_through_proto_and_yaml() {
        let profile = parse_profile_yaml(
            r"
id: mcp-example
display_name: MCP Example
endpoints:
  - host: mcp.example.com
    port: 443
    path: /mcp
    protocol: mcp
    mcp:
      strict_tool_names: false
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        assert_eq!(
            profile.endpoints[0]
                .mcp
                .as_ref()
                .and_then(|options| options.strict_tool_names),
            Some(false)
        );
        let from_proto = ProviderTypeProfile::from_proto(&profile.to_proto());
        assert_eq!(
            from_proto.endpoints[0]
                .mcp
                .as_ref()
                .and_then(|options| options.strict_tool_names),
            Some(false)
        );

        let exported = profile_to_yaml(&from_proto).expect("yaml");
        assert!(exported.contains("mcp:"));
        assert!(exported.contains("strict_tool_names: false"));
    }

    #[test]
    fn mcp_allow_params_round_trips_through_proto() {
        let profile = parse_profile_yaml(
            r"
id: mcp-params
display_name: MCP Params
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
    rules:
      - allow:
          params:
            name:
              glob: read_*
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let rules = profile.endpoints[0].rules.as_ref().expect("rules present");
        assert_eq!(rules.len(), 1);
        let allow = rules[0].allow.as_ref().expect("allow present");
        assert!(
            allow.params.contains_key("name"),
            "params.name should be set"
        );

        let from_proto = ProviderTypeProfile::from_proto(&profile.to_proto());
        let rt_rules = from_proto.endpoints[0]
            .rules
            .as_ref()
            .expect("rules survive proto round-trip");
        assert_eq!(rt_rules.len(), 1);
        let rt_allow = rt_rules[0]
            .allow
            .as_ref()
            .expect("allow survives proto round-trip");
        assert!(
            rt_allow.params.contains_key("name"),
            "params.name should survive proto round-trip"
        );
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
        let profile = builtin_profile("github");
        let json = profile_to_json(profile).expect("profile should serialize");
        let parsed = parse_profile_json(&json).expect("profile should parse");

        assert_eq!(parsed.id, "github");
        assert_eq!(parsed.category, ProviderProfileCategory::SourceControl);
        assert_eq!(parsed.binaries[0].path, "/usr/bin/gh");
    }

    #[test]
    fn profile_annotations_round_trip_through_proto_and_yaml() {
        let profile = parse_profile_yaml(
            r"
id: signed
annotations:
  openshell.nvidia.com/profile-hash: sha256:abc123
  openshell.nvidia.com/profile-signature: signed-token
display_name: Signed
description: Signed provider profile
credentials: []
endpoints: []
binaries: []
",
        )
        .expect("profile should parse");

        let proto = profile.to_proto();
        assert_eq!(
            proto
                .annotations
                .get("openshell.nvidia.com/profile-signature")
                .map(String::as_str),
            Some("signed-token")
        );

        let exported = profile_to_yaml(&ProviderTypeProfile::from_proto(&proto))
            .expect("profile should serialize");
        let reparsed = parse_profile_yaml(&exported).expect("exported profile should parse");
        assert_eq!(reparsed.annotations, profile.annotations);
    }

    #[test]
    fn profile_yaml_round_trip_preserves_full_network_policy_fields() {
        let profile = parse_profile_yaml(
            r"
id: advanced
display_name: Advanced
category: other
endpoints:
  - host: graphql.example.com
    port: 443
    protocol: graphql
    access: read-only
    persisted_queries: allow_registered
    graphql_persisted_queries:
      hash-a:
        operation_type: query
        operation_name: Viewer
        fields: [viewer]
    graphql_max_body_bytes: 131072
    path: /graphql
  - host: api.example.com
    ports: [443, 8443]
    protocol: rest
    tls: terminate
    enforcement: enforce
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

        let graphql_ep = &proto.endpoints[0];
        assert_eq!(graphql_ep.access, "read-only");
        assert_eq!(graphql_ep.persisted_queries, "allow_registered");
        assert_eq!(graphql_ep.graphql_max_body_bytes, 131_072);
        assert_eq!(graphql_ep.path, "/graphql");
        assert_eq!(
            graphql_ep
                .graphql_persisted_queries
                .get("hash-a")
                .map(|operation| operation.operation_name.as_str()),
            Some("Viewer")
        );

        let rest_ep = &proto.endpoints[1];
        assert_eq!(rest_ep.port, 0);
        assert_eq!(rest_ep.ports, vec![443, 8443]);
        assert_eq!(rest_ep.tls, "terminate");
        assert_eq!(rest_ep.allowed_ips, vec!["10.0.0.0/24"]);
        assert!(rest_ep.allow_encoded_slash);
        assert_eq!(
            rest_ep
                .rules
                .first()
                .and_then(|rule| rule.allow.as_ref())
                .map(|allow| allow.method.as_str()),
            Some("GET")
        );
        assert_eq!(rest_ep.deny_rules[0].method, "POST");
        assert!(proto.binaries[0].harness);

        let reparsed = parse_profile_yaml(&profile_to_yaml(&profile).expect("serialize YAML"))
            .expect("serialized profile should parse");
        let reprotoo = reparsed.to_proto();
        assert_eq!(reprotoo.endpoints[0].access, "read-only");
        assert_eq!(reprotoo.endpoints[1].rules.len(), 1);
        assert_eq!(reprotoo.endpoints[1].deny_rules.len(), 1);
        assert_eq!(reprotoo.endpoints[1].ports, vec![443, 8443]);
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
    env_vars: [BROKEN_TOKEN, "", v10_GITHUB_TOKEN]
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
        assert!(
            messages.iter().any(
                |message| message.contains("reserved OpenShell placeholder revision namespace")
            )
        );
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
                    annotations: HashMap::new(),
                    display_name: "Space".to_string(),
                    description: String::new(),
                    category: ProviderProfileCategory::Other,
                    credentials: Vec::new(),
                    endpoints: Vec::new(),
                    binaries: Vec::new(),
                    inference_capable: false,
                    discovery: DiscoveryProfile::default(),
                    source: String::new(),
                    scope: String::new(),
                },
            ),
            (
                "underscore.yaml".to_string(),
                ProviderTypeProfile {
                    id: "alex_api".to_string(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    display_name: "Underscore".to_string(),
                    description: String::new(),
                    category: ProviderProfileCategory::Other,
                    credentials: Vec::new(),
                    endpoints: Vec::new(),
                    binaries: Vec::new(),
                    inference_capable: false,
                    discovery: DiscoveryProfile::default(),
                    source: String::new(),
                    scope: String::new(),
                },
            ),
            (
                "case.yaml".to_string(),
                ProviderTypeProfile {
                    id: "Alex-API".to_string(),
                    resource_version: 0,
                    annotations: HashMap::new(),
                    display_name: "Case".to_string(),
                    description: String::new(),
                    category: ProviderProfileCategory::Other,
                    credentials: Vec::new(),
                    endpoints: Vec::new(),
                    binaries: Vec::new(),
                    inference_capable: false,
                    discovery: DiscoveryProfile::default(),
                    source: String::new(),
                    scope: String::new(),
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

    #[test]
    fn parse_profile_catalog_yamls_rejects_l7_validation_errors() {
        let err = parse_profile_catalog_yamls(&[r"
id: bad-l7
display_name: Bad L7
endpoints:
  - host: api.example.com
    port: 443
    protocol: rest
    access: read-write
    rules:
      - allow:
          method: GET
          path: /v1/**
binaries:
  - /usr/bin/example-agent
"])
        .unwrap_err();

        assert!(
            matches!(err, ProfileError::ValidationError { ref id, ref message, .. } if id == "bad-l7" && message.contains("mutually exclusive")),
            "expected L7 validation error for access+rules, got: {err}"
        );
    }

    #[test]
    fn aws_sts_strategy_serde_roundtrip() {
        use openshell_core::proto::ProviderCredentialRefreshStrategy;
        assert_eq!(
            super::provider_refresh_strategy_from_yaml("aws_sts_assume_role"),
            Some(ProviderCredentialRefreshStrategy::AwsStsAssumeRole)
        );
        assert_eq!(
            super::provider_refresh_strategy_to_yaml(
                ProviderCredentialRefreshStrategy::AwsStsAssumeRole
            ),
            "aws_sts_assume_role"
        );
    }

    #[test]
    fn aws_profile_parses_correctly() {
        let aws = builtin_profile("aws");
        assert_eq!(aws.display_name, "AWS");
        assert_eq!(aws.credentials.len(), 3);
        let access_key = aws
            .credentials
            .iter()
            .find(|c| c.name == "access_key_id")
            .unwrap();
        assert!(access_key.refresh.is_some());
        let refresh = access_key.refresh.as_ref().unwrap();
        assert_eq!(
            refresh.strategy,
            openshell_core::proto::ProviderCredentialRefreshStrategy::AwsStsAssumeRole
        );
        assert!(
            refresh
                .material
                .iter()
                .any(|m| m.name == "role_arn" && m.required)
        );
    }

    #[test]
    fn aws_s3_profile_parses_with_endpoints() {
        let aws_s3 = builtin_profile("aws-s3");
        assert_eq!(aws_s3.display_name, "AWS S3");
        assert!(!aws_s3.endpoints.is_empty());
        assert!(
            !aws_s3
                .endpoints
                .iter()
                .any(|e| e.host == "**.amazonaws.com")
        );
        assert!(
            aws_s3
                .endpoints
                .iter()
                .any(|e| e.host == "*.s3.amazonaws.com")
        );
        assert!(
            aws_s3
                .endpoints
                .iter()
                .any(|e| e.host == "s3.amazonaws.com")
        );
        assert!(
            aws_s3
                .endpoints
                .iter()
                .any(|e| e.host == "*.s3.*.amazonaws.com")
        );
        assert!(
            aws_s3
                .endpoints
                .iter()
                .any(|e| e.host == "s3.*.amazonaws.com")
        );
        assert!(
            aws_s3
                .endpoints
                .iter()
                .any(|e| e.host == "*.s3.dualstack.*.amazonaws.com")
        );
        assert!(
            aws_s3
                .endpoints
                .iter()
                .any(|e| e.host == "s3.dualstack.*.amazonaws.com")
        );
    }

    #[test]
    fn aws_profile_declares_additional_outputs() {
        for id in ["aws", "aws-s3"] {
            let profile = builtin_profile(id);
            let refresh = profile
                .credentials
                .iter()
                .find(|c| c.name == "access_key_id")
                .and_then(|c| c.refresh.as_ref())
                .expect("access_key_id refresh should exist");
            let outputs: Vec<(&str, &str)> = refresh
                .additional_outputs
                .iter()
                .map(|o| (o.output.as_str(), o.credential.as_str()))
                .collect();
            assert_eq!(
                outputs,
                vec![
                    ("secret_access_key", "secret_access_key"),
                    ("session_token", "session_token"),
                ],
                "unexpected additional_outputs for {id}"
            );
        }
    }

    #[test]
    fn aws_profiles_are_runtime_resolvable() {
        // With AwsStsAssumeRole recognized as gateway-mintable, all three
        // required credentials are runtime-resolvable, so `--runtime-credentials`
        // (empty provider creation) is allowed.
        for id in ["aws", "aws-s3"] {
            let profile = builtin_profile(id);
            assert!(
                profile.allows_empty_provider_credentials(),
                "{id} should allow empty provider credentials"
            );
        }
    }

    #[test]
    fn is_gateway_mintable_strategy_includes_aws_sts() {
        assert!(super::is_gateway_mintable_strategy(
            openshell_core::proto::ProviderCredentialRefreshStrategy::AwsStsAssumeRole
        ));
    }

    #[test]
    fn additional_outputs_round_trip_through_proto_and_yaml() {
        let profile = parse_profile_yaml(
            r"
id: aws-round-trip
display_name: AWS Round Trip
credentials:
  - name: access_key_id
    env_vars: [AWS_ACCESS_KEY_ID]
    required: true
    refresh:
      strategy: aws_sts_assume_role
      additional_outputs:
        - output: secret_access_key
          credential: secret_access_key
        - output: session_token
          credential: session_token
      material:
        - name: role_arn
          required: true
  - name: secret_access_key
    env_vars: [AWS_SECRET_ACCESS_KEY]
    required: true
  - name: session_token
    env_vars: [AWS_SESSION_TOKEN]
    required: true
",
        )
        .expect("profile should parse");

        let from_proto = ProviderTypeProfile::from_proto(&profile.to_proto());
        assert_eq!(
            from_proto.credentials[0].refresh,
            profile.credentials[0].refresh
        );

        let exported = profile_to_yaml(&from_proto).expect("yaml");
        assert!(exported.contains("additional_outputs"));
        assert!(exported.contains("session_token"));
        let reparsed = parse_profile_yaml(&exported).expect("re-parse");
        assert_eq!(
            reparsed.credentials[0].refresh,
            profile.credentials[0].refresh
        );
    }

    fn aws_output_profile(additional_outputs: &str, credentials_tail: &str) -> ProviderTypeProfile {
        parse_profile_yaml(&format!(
            r"
id: aws-outputs
display_name: AWS Outputs
credentials:
  - name: access_key_id
    env_vars: [AWS_ACCESS_KEY_ID]
    required: true
    refresh:
      strategy: aws_sts_assume_role
{additional_outputs}
      material:
        - name: role_arn
          required: true
{credentials_tail}
"
        ))
        .expect("profile should parse")
    }

    const STANDARD_AWS_OUTPUT_TAIL: &str = "  - name: secret_access_key
    env_vars: [AWS_SECRET_ACCESS_KEY]
    required: true
  - name: session_token
    env_vars: [AWS_SESSION_TOKEN]
    required: true";

    #[test]
    fn validate_rejects_additional_output_unknown_credential() {
        let profile = aws_output_profile(
            "      additional_outputs:
        - output: secret_access_key
          credential: nonexistent
        - output: session_token
          credential: session_token",
            STANDARD_AWS_OUTPUT_TAIL,
        );
        let diagnostics = validate_profile_set(&[("aws.yaml".to_string(), profile)]);
        assert!(
            diagnostics.iter().any(|d| d.field
                == "credentials.refresh.additional_outputs.credential"
                && d.message.contains("unknown credential 'nonexistent'")),
            "diagnostics: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_rejects_duplicate_additional_output() {
        let profile = aws_output_profile(
            "      additional_outputs:
        - output: secret_access_key
          credential: secret_access_key
        - output: secret_access_key
          credential: secret_access_key
        - output: session_token
          credential: session_token",
            STANDARD_AWS_OUTPUT_TAIL,
        );
        let diagnostics = validate_profile_set(&[("aws.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("duplicate refresh additional output")),
            "diagnostics: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_rejects_unknown_output_for_strategy() {
        let profile = aws_output_profile(
            "      additional_outputs:
        - output: secret_access_key
          credential: secret_access_key
        - output: session_token
          credential: session_token
        - output: bogus
          credential: session_token",
            STANDARD_AWS_OUTPUT_TAIL,
        );
        let diagnostics = validate_profile_set(&[("aws.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("does not produce output 'bogus'")),
            "diagnostics: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_rejects_missing_required_output() {
        let profile = aws_output_profile(
            "      additional_outputs:
        - output: secret_access_key
          credential: secret_access_key",
            STANDARD_AWS_OUTPUT_TAIL,
        );
        let diagnostics = validate_profile_set(&[("aws.yaml".to_string(), profile)]);
        assert!(
            diagnostics.iter().any(|d| d
                .message
                .contains("requires additional output 'session_token'")),
            "diagnostics: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_rejects_output_credential_with_own_refresh() {
        let tail = "  - name: secret_access_key
    env_vars: [AWS_SECRET_ACCESS_KEY]
    required: true
    refresh:
      strategy: oauth2_client_credentials
  - name: session_token
    env_vars: [AWS_SESSION_TOKEN]
    required: true";
        let profile = aws_output_profile(
            "      additional_outputs:
        - output: secret_access_key
          credential: secret_access_key
        - output: session_token
          credential: session_token",
            tail,
        );
        let diagnostics = validate_profile_set(&[("aws.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("must not declare its own refresh")),
            "diagnostics: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_rejects_nonstandard_aws_output_env_key() {
        let tail = "  - name: secret_access_key
    env_vars: [WRONG_SECRET]
    required: true
  - name: session_token
    env_vars: [AWS_SESSION_TOKEN]
    required: true";
        let profile = aws_output_profile(
            "      additional_outputs:
        - output: secret_access_key
          credential: secret_access_key
        - output: session_token
          credential: session_token",
            tail,
        );
        let diagnostics = validate_profile_set(&[("aws.yaml".to_string(), profile)]);
        assert!(
            diagnostics.iter().any(|d| d
                .message
                .contains("must map to env var AWS_SECRET_ACCESS_KEY, found WRONG_SECRET")),
            "diagnostics: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_rejects_wrong_primary_env_key_for_aws_sts() {
        let profile = parse_profile_yaml(
            r"
id: aws-wrong-primary
display_name: AWS Wrong Primary
credentials:
  - name: access_key_id
    env_vars: [NOT_AWS_ACCESS_KEY_ID]
    required: true
    refresh:
      strategy: aws_sts_assume_role
      additional_outputs:
        - output: secret_access_key
          credential: secret_access_key
        - output: session_token
          credential: session_token
      material:
        - name: role_arn
          required: true
  - name: secret_access_key
    env_vars: [AWS_SECRET_ACCESS_KEY]
    required: true
  - name: session_token
    env_vars: [AWS_SESSION_TOKEN]
    required: true
",
        )
        .expect("profile should parse");
        let diagnostics = validate_profile_set(&[("aws.yaml".to_string(), profile)]);
        assert!(
            diagnostics.iter().any(|d| d
                .message
                .contains("requires primary credential to map to env var AWS_ACCESS_KEY_ID")),
            "diagnostics: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_rejects_additional_outputs_on_unsupported_strategy() {
        let profile = parse_profile_yaml(
            r"
id: oauth-with-outputs
display_name: OAuth With Outputs
credentials:
  - name: access_token
    env_vars: [ACCESS_TOKEN]
    required: true
    refresh:
      strategy: oauth2_client_credentials
      additional_outputs:
        - output: extra
          credential: other
  - name: other
    env_vars: [OTHER]
    required: false
",
        )
        .expect("profile should parse");
        let diagnostics = validate_profile_set(&[("oauth.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("does not support additional_outputs")),
            "diagnostics: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_accepts_standard_aws_additional_outputs() {
        let profile = aws_output_profile(
            "      additional_outputs:
        - output: secret_access_key
          credential: secret_access_key
        - output: session_token
          credential: session_token",
            STANDARD_AWS_OUTPUT_TAIL,
        );
        let diagnostics = validate_profile_set(&[("aws.yaml".to_string(), profile)]);
        assert!(
            diagnostics.is_empty(),
            "unexpected diagnostics: {diagnostics:?}"
        );
    }

    // -- L7 endpoint semantic validation (shared with runtime) ----------------

    #[test]
    fn validate_rejects_protocol_without_rules_or_access() {
        let profile = parse_profile_yaml(
            r"
id: opencode-openrouter
display_name: OpenCode (OpenRouter)
credentials:
  - name: api_key
    env_vars: [OPENROUTER_API_KEY]
    auth_style: bearer
    header_name: authorization
discovery:
  credentials: [api_key]
endpoints:
  - host: openrouter.ai
    port: 443
    protocol: rest
    enforcement: enforce
binaries:
  - /usr/bin/opencode
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("protocol requires rules or access")),
            "expected lint to reject protocol without rules or access, got: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_accepts_protocol_with_access() {
        let profile = parse_profile_yaml(
            r"
id: valid-rest
display_name: Valid REST
credentials:
  - name: api_key
    env_vars: [API_KEY]
    auth_style: bearer
    header_name: authorization
discovery:
  credentials: [api_key]
endpoints:
  - host: api.example.com
    port: 443
    protocol: rest
    access: read-write
binaries:
  - /usr/bin/app
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        let errors: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.severity == "error")
            .collect();
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn validate_rejects_unknown_protocol() {
        let profile = parse_profile_yaml(
            r"
id: bad-protocol
display_name: Bad Protocol
credentials:
  - name: api_key
    env_vars: [API_KEY]
    auth_style: bearer
    header_name: authorization
discovery:
  credentials: [api_key]
endpoints:
  - host: api.example.com
    port: 443
    protocol: ftp
binaries:
  - /usr/bin/app
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("unknown protocol")),
            "expected lint to reject unknown protocol, got: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_rejects_rules_and_access_together() {
        let profile = parse_profile_yaml(
            r"
id: both-rules-access
display_name: Both
credentials:
  - name: api_key
    env_vars: [API_KEY]
    auth_style: bearer
    header_name: authorization
discovery:
  credentials: [api_key]
endpoints:
  - host: api.example.com
    port: 443
    protocol: rest
    access: full
    rules:
      - allow:
          method: GET
          path: /api/**
binaries:
  - /usr/bin/app
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("mutually exclusive")),
            "expected lint to reject rules + access, got: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_rejects_empty_rules_list() {
        let profile = parse_profile_yaml(
            r"
id: empty-rules
display_name: Empty Rules
credentials:
  - name: api_key
    env_vars: [API_KEY]
    auth_style: bearer
    header_name: authorization
discovery:
  credentials: [api_key]
endpoints:
  - host: api.example.com
    port: 443
    protocol: rest
    access: full
    rules: []
binaries:
  - /usr/bin/app
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("rules list cannot be empty")),
            "expected lint to reject empty rules list, got: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_rejects_empty_allow_object_as_deny_all() {
        let profile = parse_profile_yaml(
            r"
id: empty-allow
display_name: Empty Allow
credentials:
  - name: api_key
    env_vars: [API_KEY]
    auth_style: bearer
    header_name: authorization
discovery:
  credentials: [api_key]
endpoints:
  - host: api.example.com
    port: 443
    protocol: rest
    rules:
      - allow: {}
binaries:
  - /usr/bin/app
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("would deny all traffic")),
            "expected lint to reject empty allow object as deny-all, got: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_rejects_empty_deny_rules_list() {
        let profile = parse_profile_yaml(
            r"
id: empty-deny-rules
display_name: Empty Deny Rules
credentials:
  - name: api_key
    env_vars: [API_KEY]
    auth_style: bearer
    header_name: authorization
discovery:
  credentials: [api_key]
endpoints:
  - host: api.example.com
    port: 443
    protocol: rest
    access: full
    deny_rules: []
binaries:
  - /usr/bin/app
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("deny_rules list cannot be empty")),
            "expected lint to reject empty deny_rules list, got: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_mcp_params_selector_not_classified_as_deny_all() {
        let profile = parse_profile_yaml(
            r"
id: mcp-params
display_name: MCP Params
credentials:
  - name: api_key
    env_vars: [API_KEY]
    auth_style: bearer
    header_name: authorization
discovery:
  credentials: [api_key]
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
    rules:
      - allow:
          params:
            name:
              glob: read_*
binaries:
  - /usr/bin/app
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            !diagnostics
                .iter()
                .any(|d| d.message.contains("would deny all traffic")),
            "MCP rule with params.name selector should not be classified as deny-all: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_mcp_empty_allow_with_allow_all_conflicts_with_tool_rules() {
        let profile = parse_profile_yaml(
            r"
id: mcp-wildcard
display_name: MCP Wildcard
credentials:
  - name: api_key
    env_vars: [API_KEY]
    auth_style: bearer
    header_name: authorization
discovery:
  credentials: [api_key]
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
    rules:
      - allow:
          params:
            name:
              glob: read_*
      - allow: {}
binaries:
  - /usr/bin/app
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("allows every tool call")
                    && d.message.contains("conflicts with MCP tool allow rules")),
            "empty allow with allow_all should conflict with tool-specific rules: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_unsupported_params_rejected() {
        let profile = parse_profile_yaml(
            r"
id: unsupported-params
display_name: Unsupported Params
credentials:
  - name: api_key
    env_vars: [API_KEY]
    auth_style: bearer
    header_name: authorization
discovery:
  credentials: [api_key]
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
    rules:
      - allow:
          params:
            arguments:
              glob: '*'
binaries:
  - /usr/bin/app
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("not supported yet")),
            "unsupported params key should be rejected: {diagnostics:?}"
        );
        assert!(
            !diagnostics
                .iter()
                .any(|d| d.message.contains("would deny all traffic")),
            "MCP with allow_all_known_mcp_methods should not emit deny-all for empty method: {diagnostics:?}"
        );
    }

    #[test]
    fn mcp_deny_rule_params_round_trips_through_proto() {
        let profile = parse_profile_yaml(
            r"
id: mcp-deny-params
display_name: MCP Deny Params
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
    deny_rules:
      - method: tools/call
        params:
          name:
            glob: dangerous_*
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let deny_rules = profile.endpoints[0]
            .deny_rules
            .as_ref()
            .expect("deny_rules present");
        assert!(
            deny_rules[0].params.contains_key("name"),
            "params.name should be set"
        );

        let from_proto = ProviderTypeProfile::from_proto(&profile.to_proto());
        let rt_deny = from_proto.endpoints[0]
            .deny_rules
            .as_ref()
            .expect("deny_rules survive proto round-trip");
        assert!(
            rt_deny[0].params.contains_key("name"),
            "deny rule params.name should survive proto round-trip"
        );
    }

    #[test]
    fn mcp_tool_allow_round_trips_through_proto() {
        let profile = parse_profile_yaml(
            r"
id: mcp-tool
display_name: MCP Tool
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
    rules:
      - allow:
          tool:
            glob: read_*
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let rules = profile.endpoints[0].rules.as_ref().expect("rules present");
        let allow = rules[0].allow.as_ref().expect("allow present");
        assert!(allow.tool.is_some(), "tool should be parsed");
        assert_eq!(allow.tool.as_ref().unwrap().glob, "read_*");

        let from_proto = ProviderTypeProfile::from_proto(&profile.to_proto());
        let rt_allow = from_proto.endpoints[0]
            .rules
            .as_ref()
            .expect("rules survive")[0]
            .allow
            .as_ref()
            .expect("allow survives");
        assert!(
            rt_allow.params.contains_key("name"),
            "tool should be lowered to params.name in proto: {rt_allow:?}"
        );
        assert_eq!(rt_allow.params["name"].glob, "read_*");
        assert!(
            rt_allow.tool.is_none(),
            "tool should be None after round-trip"
        );
    }

    #[test]
    fn mcp_tool_deny_round_trips_through_proto() {
        let profile = parse_profile_yaml(
            r"
id: mcp-deny-tool
display_name: MCP Deny Tool
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
    deny_rules:
      - method: 'tools/call'
        tool:
          glob: dangerous_*
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let deny_rules = profile.endpoints[0]
            .deny_rules
            .as_ref()
            .expect("deny_rules present");
        assert!(deny_rules[0].tool.is_some(), "tool should be parsed");

        let from_proto = ProviderTypeProfile::from_proto(&profile.to_proto());
        let rt_deny = from_proto.endpoints[0]
            .deny_rules
            .as_ref()
            .expect("deny_rules survive")[0]
            .clone();
        assert!(
            rt_deny.params.contains_key("name"),
            "deny tool should be lowered to params.name in proto"
        );
        assert_eq!(rt_deny.params["name"].glob, "dangerous_*");
    }

    #[test]
    fn validate_mcp_tool_and_params_name_rejected() {
        let profile = parse_profile_yaml(
            r"
id: mcp-both
display_name: MCP Both
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
    rules:
      - allow:
          tool:
            glob: read_*
          params:
            name:
              glob: write_*
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics.iter().any(|d| d
                .message
                .contains("must use either tool or params.name, not both")),
            "expected mutual exclusivity error, got: {diagnostics:?}"
        );
    }

    #[test]
    fn mcp_tool_prevents_classify_as_deny_all() {
        let allow = L7AllowProfile {
            method: String::new(),
            path: String::new(),
            command: String::new(),
            query: HashMap::new(),
            operation_type: String::new(),
            operation_name: String::new(),
            fields: vec![],
            params: HashMap::new(),
            tool: Some(L7QueryMatcherProfile {
                glob: "read_*".to_string(),
                any: vec![],
            }),
        };
        assert!(
            !allow.is_effectively_empty(),
            "allow with tool selector should not be classified as deny-all"
        );
    }

    #[test]
    fn validate_mcp_explicit_broad_method_without_allow_all() {
        let profile = parse_profile_yaml(
            r"
id: mcp-broad
display_name: MCP Broad
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    rules:
      - allow:
          method: 'tools/call'
          params:
            name:
              glob: read_*
      - allow:
          method: 'tools/call'
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("allows every tool call and conflicts")),
            "explicit broad method should be detected even without allow_all_known_mcp_methods: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_mcp_glob_broad_method_detected() {
        let profile = parse_profile_yaml(
            r"
id: mcp-glob
display_name: MCP Glob
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
    rules:
      - allow:
          params:
            name:
              glob: read_*
      - allow:
          method: 'tools/*'
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("allows every tool call and conflicts")),
            "glob method tools/* should be detected: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_mcp_deny_rule_broad_method_conflict() {
        let profile = parse_profile_yaml(
            r"
id: mcp-deny-broad
display_name: MCP Deny Broad
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
    rules:
      - allow:
          params:
            name:
              glob: read_*
    deny_rules:
      - method: 'tools/call'
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("denies every tool call and conflicts")),
            "deny rule with broad method should be detected: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_mcp_deny_rule_with_tool_selector_ok() {
        let profile = parse_profile_yaml(
            r"
id: mcp-deny-ok
display_name: MCP Deny OK
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
    rules:
      - allow:
          params:
            name:
              glob: '*'
    deny_rules:
      - method: 'tools/call'
        tool:
          glob: dangerous_*
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            !diagnostics
                .iter()
                .any(|d| d.message.contains("denies every tool call")),
            "deny rule with tool selector should not trigger conflict: {diagnostics:?}"
        );
    }

    #[test]
    fn mcp_tool_scalar_matcher_round_trips_through_proto() {
        let profile = parse_profile_yaml(
            r"
id: mcp-scalar-tool
display_name: MCP Scalar Tool
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    rules:
      - allow:
          method: tools/call
          tool: search_web
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("scalar tool matcher should parse");

        let rules = profile.endpoints[0].rules.as_ref().expect("rules present");
        let allow = rules[0].allow.as_ref().expect("allow present");
        assert_eq!(
            allow.tool.as_ref().unwrap().glob,
            "search_web",
            "scalar string should deserialize to glob field"
        );

        let from_proto = ProviderTypeProfile::from_proto(&profile.to_proto());
        let rt_allow = from_proto.endpoints[0]
            .rules
            .as_ref()
            .expect("rules survive")[0]
            .allow
            .as_ref()
            .expect("allow survives");
        assert_eq!(
            rt_allow.params["name"].glob, "search_web",
            "scalar tool should lower to params.name in proto"
        );

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        let errors: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.severity == "error")
            .collect();
        assert!(
            errors.is_empty(),
            "scalar tool matcher should produce no validation errors: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_deny_tool_and_params_name_rejected() {
        let profile = parse_profile_yaml(
            r"
id: mcp-deny-both
display_name: MCP Deny Both
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
    deny_rules:
      - method: tools/call
        tool:
          glob: dangerous_*
        params:
          name:
            glob: also_dangerous_*
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("either tool or params.name")),
            "deny rule with both tool and params.name should be rejected: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_mcp_method_must_be_tools_call_with_tool_selector() {
        let profile = parse_profile_yaml(
            r"
id: mcp-bad-method
display_name: MCP Bad Method
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    rules:
      - allow:
          method: resources/read
          tool:
            glob: read_*
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("method must be tools/call")),
            "tool selector with wrong method should be rejected: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_mcp_deny_method_must_be_tools_call_with_tool_selector() {
        let profile = parse_profile_yaml(
            r"
id: mcp-deny-bad-method
display_name: MCP Deny Bad Method
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
    deny_rules:
      - method: resources/read
        tool:
          glob: dangerous_*
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("method must be tools/call")),
            "deny rule with tool selector and wrong method should be rejected: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_mcp_method_required_without_allow_all() {
        let profile = parse_profile_yaml(
            r"
id: mcp-no-method
display_name: MCP No Method
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    rules:
      - allow:
          tool:
            glob: read_*
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("method is required")),
            "missing method without allow_all should be rejected: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_before_lowering_catches_tool_params_conflict() {
        let profile = parse_profile_yaml(
            r"
id: mcp-both
display_name: MCP Both
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    rules:
      - allow:
          method: tools/call
          tool:
            glob: read_*
          params:
            name:
              glob: write_*
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = profile.validate_before_lowering("profile.yaml");
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("either tool or params.name")),
            "pre-lowering validation should catch tool + params.name conflict: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_before_lowering_ok_with_tool_only() {
        let profile = parse_profile_yaml(
            r"
id: mcp-tool-only
display_name: MCP Tool Only
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    rules:
      - allow:
          method: tools/call
          tool:
            glob: read_*
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = profile.validate_before_lowering("profile.yaml");
        assert!(
            diagnostics.is_empty(),
            "tool-only rule should pass pre-lowering validation: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_before_lowering_deny_catches_conflict() {
        let profile = parse_profile_yaml(
            r"
id: mcp-deny-both
display_name: MCP Deny Both
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
    deny_rules:
      - method: tools/call
        tool:
          glob: dangerous_*
        params:
          name:
            glob: also_dangerous_*
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = profile.validate_before_lowering("profile.yaml");
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("either tool or params.name")),
            "deny rule with both should be caught before lowering: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_rejects_deny_rules_without_protocol() {
        let profile = parse_profile_yaml(
            r"
id: deny-no-protocol
display_name: Deny No Protocol
credentials:
  - name: api_key
    env_vars: [API_KEY]
    auth_style: bearer
    header_name: authorization
discovery:
  credentials: [api_key]
endpoints:
  - host: api.example.com
    port: 443
    deny_rules:
      - method: POST
binaries:
  - /usr/bin/app
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("deny_rules require protocol")),
            "expected lint to reject deny_rules without protocol, got: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_before_lowering_catches_empty_rules() {
        let profile = parse_profile_yaml(
            r"
id: empty-rules
display_name: Empty Rules
endpoints:
  - host: api.example.com
    port: 443
    protocol: mcp
    rules: []
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = profile.validate_before_lowering("profile.yaml");
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("rules list cannot be empty")),
            "pre-lowering should catch empty rules list: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_before_lowering_catches_empty_deny_rules() {
        let profile = parse_profile_yaml(
            r"
id: empty-deny-rules
display_name: Empty Deny Rules
endpoints:
  - host: api.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
    rules:
      - allow:
          method: tools/call
    deny_rules: []
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = profile.validate_before_lowering("profile.yaml");
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("deny_rules list cannot be empty")),
            "pre-lowering should catch empty deny_rules list: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_mcp_unsupported_params_key() {
        let profile = parse_profile_yaml(
            r"
id: bad-params
display_name: Bad Params
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
    rules:
      - allow:
          method: tools/call
          params:
            arguments:
              glob: '*'
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics.iter().any(|d| d
                .message
                .contains("MCP tool argument matching is not supported yet")),
            "expected unsupported params key error: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_mcp_matcher_glob_and_any_rejected() {
        let profile = parse_profile_yaml(
            r"
id: glob-and-any
display_name: Glob And Any
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
    rules:
      - allow:
          method: tools/call
          tool:
            glob: read_*
            any:
              - write_data
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("cannot specify both glob and any")),
            "expected glob+any mutual exclusion error: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_mcp_matcher_empty_rejected() {
        let yaml = r"
id: empty-matcher
display_name: Empty Matcher
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
    rules:
      - allow:
          method: tools/call
          tool: ''
binaries:
  - /usr/bin/example-agent
";
        let profile = parse_profile_yaml(yaml).expect("profile should parse");
        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("matcher must specify glob or any")),
            "expected empty matcher error: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_mcp_wildcard_without_strict_tool_names() {
        let profile = parse_profile_yaml(
            r"
id: wildcard-no-strict
display_name: Wildcard No Strict
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
      strict_tool_names: false
    rules:
      - allow:
          method: tools/call
          tool:
            glob: '*'
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics.iter().any(|d| d
                .message
                .contains("wildcard tool-name matchers require mcp.strict_tool_names")),
            "expected wildcard policy error: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_mcp_wildcard_with_strict_tool_names_ok() {
        let profile = parse_profile_yaml(
            r"
id: wildcard-strict
display_name: Wildcard Strict
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
      strict_tool_names: true
    rules:
      - allow:
          method: tools/call
          tool:
            glob: '*'
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            !diagnostics.iter().any(|d| d
                .message
                .contains("wildcard tool-name matchers require mcp.strict_tool_names")),
            "wildcard with strict_tool_names enabled should be OK: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_mcp_method_glob_restricted_to_tools() {
        let profile = parse_profile_yaml(
            r"
id: bad-method-glob
display_name: Bad Method Glob
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
    rules:
      - allow:
          method: 'resources/*'
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics.iter().any(|d| d
                .message
                .contains("MCP method globs are only valid for the tools/ method family")),
            "expected method glob restriction error: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_mcp_path_rejected() {
        let profile = parse_profile_yaml(
            r"
id: mcp-path
display_name: MCP Path
endpoints:
  - host: mcp.example.com
    port: 443
    protocol: mcp
    mcp:
      allow_all_known_mcp_methods: true
    rules:
      - allow:
          method: tools/call
          path: /api/tools
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("must use method/tool, not path/query")),
            "expected path rejection for MCP: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_mcp_tool_on_non_mcp_rejected() {
        let profile = parse_profile_yaml(
            r"
id: rest-tool
display_name: REST Tool
endpoints:
  - host: api.example.com
    port: 443
    protocol: rest
    rules:
      - allow:
          method: GET
          tool:
            glob: read_*
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics.iter().any(|d| d
                .message
                .contains("MCP tool matching is only valid for protocol mcp")),
            "expected tool-on-non-mcp rejection: {diagnostics:?}"
        );
    }

    #[test]
    fn validate_mcp_options_on_non_mcp_rejected() {
        let profile = parse_profile_yaml(
            r"
id: rest-mcp-opts
display_name: REST MCP Options
endpoints:
  - host: api.example.com
    port: 443
    protocol: rest
    mcp:
      strict_tool_names: true
    rules:
      - allow:
          method: GET
binaries:
  - /usr/bin/example-agent
",
        )
        .expect("profile should parse");

        let diagnostics = validate_profile_set(&[("profile.yaml".to_string(), profile)]);
        assert!(
            diagnostics.iter().any(|d| d
                .message
                .contains("mcp options are only valid for protocol mcp")),
            "expected mcp-options-on-non-mcp rejection: {diagnostics:?}"
        );
    }
}
