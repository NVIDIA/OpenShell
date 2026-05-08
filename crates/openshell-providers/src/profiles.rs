// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Declarative provider type profiles.

#![allow(deprecated)] // NetworkBinary::harness remains in the public proto for compatibility.

use openshell_core::proto::{
    GraphqlOperation, L7Allow, L7DenyRule, L7QueryMatcher, L7Rule, NetworkBinary, NetworkEndpoint,
    NetworkPolicyRule, ProviderProfile, ProviderProfileCategory, ProviderProfileCredential,
};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::collections::{HashMap, HashSet};
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
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub persisted_queries: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub graphql_persisted_queries: HashMap<String, GraphqlOperationProfile>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub graphql_max_body_bytes: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
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
            binaries: profile.binaries.iter().map(binary_from_proto).collect(),
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
            binaries: self.binaries.iter().map(binary_to_proto).collect(),
            inference_capable: self.inference_capable,
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
        tls: endpoint.tls.clone(),
        enforcement: endpoint.enforcement.clone(),
        access: endpoint.access.clone(),
        rules: endpoint.rules.iter().map(rule_to_proto).collect(),
        allowed_ips: endpoint.allowed_ips.clone(),
        ports: endpoint.ports.clone(),
        deny_rules: endpoint.deny_rules.iter().map(deny_rule_to_proto).collect(),
        allow_encoded_slash: endpoint.allow_encoded_slash,
        persisted_queries: endpoint.persisted_queries.clone(),
        graphql_persisted_queries: endpoint
            .graphql_persisted_queries
            .iter()
            .map(|(name, operation)| (name.clone(), graphql_operation_to_proto(operation)))
            .collect(),
        graphql_max_body_bytes: endpoint.graphql_max_body_bytes,
        path: endpoint.path.clone(),
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
        persisted_queries: endpoint.persisted_queries.clone(),
        graphql_persisted_queries: endpoint
            .graphql_persisted_queries
            .iter()
            .map(|(name, operation)| (name.clone(), graphql_operation_from_proto(operation)))
            .collect(),
        graphql_max_body_bytes: endpoint.graphql_max_body_bytes,
        path: endpoint.path.clone(),
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
        ProfileError, ProviderTypeProfile, default_profiles, get_default_profile,
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
    fn validate_profile_set_rejects_noncanonical_profile_ids() {
        let profiles = [
            (
                "space.yaml".to_string(),
                ProviderTypeProfile {
                    id: " alex-api ".to_string(),
                    display_name: "Space".to_string(),
                    description: String::new(),
                    category: ProviderProfileCategory::Other,
                    credentials: Vec::new(),
                    endpoints: Vec::new(),
                    binaries: Vec::new(),
                    inference_capable: false,
                },
            ),
            (
                "underscore.yaml".to_string(),
                ProviderTypeProfile {
                    id: "alex_api".to_string(),
                    display_name: "Underscore".to_string(),
                    description: String::new(),
                    category: ProviderProfileCategory::Other,
                    credentials: Vec::new(),
                    endpoints: Vec::new(),
                    binaries: Vec::new(),
                    inference_capable: false,
                },
            ),
            (
                "case.yaml".to_string(),
                ProviderTypeProfile {
                    id: "Alex-API".to_string(),
                    display_name: "Case".to_string(),
                    description: String::new(),
                    category: ProviderProfileCategory::Other,
                    credentials: Vec::new(),
                    endpoints: Vec::new(),
                    binaries: Vec::new(),
                    inference_capable: false,
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
