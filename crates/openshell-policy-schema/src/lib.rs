// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Canonical representation of the `OpenShell` authored policy language.
//!
//! This dependency-light crate owns authored YAML/JSON serde, bounded parsing,
//! pure schema validation, and lexical policy-path normalization. Runtime and
//! protobuf adaptation intentionally live in `openshell-policy`.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use miette::{IntoDiagnostic, Result, WrapErr};
use serde::{Deserialize, Deserializer, Serialize};

/// Fixed batch-member bound for the MCP 2025-03-26 wire profile.
pub const MAX_MCP_LEGACY_BATCH_MESSAGES: usize = 64;

/// Stable MCP protocol revisions accepted in authored policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum McpProtocolVersion {
    V2025_03_26,
    V2025_06_18,
    V2025_11_25,
}

/// Pinned revision used when authored policy omits MCP versions.
pub const DEFAULT_MCP_PROTOCOL_VERSION: McpProtocolVersion = McpProtocolVersion::V2025_11_25;

pub const MCP_VERSION_REMEDIATION: &str = "omit mcp.versions to use the pinned default revision, use an exact supported revision, or omit protocol and mcp for deliberate uninspected L4 passthrough only when that weaker boundary is acceptable";

impl McpProtocolVersion {
    pub const ALL: &'static [Self] = &[Self::V2025_03_26, Self::V2025_06_18, Self::V2025_11_25];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2025_03_26 => "2025-03-26",
            Self::V2025_06_18 => "2025-06-18",
            Self::V2025_11_25 => "2025-11-25",
        }
    }

    #[must_use]
    pub const fn wire_profile(self) -> McpWireProfile {
        match self {
            Self::V2025_03_26 => McpWireProfile {
                version: self,
                allows_json_rpc_batches: true,
                max_batch_messages: Some(MAX_MCP_LEGACY_BATCH_MESSAGES),
            },
            Self::V2025_06_18 | Self::V2025_11_25 => McpWireProfile {
                version: self,
                allows_json_rpc_batches: false,
                max_batch_messages: None,
            },
        }
    }
}

impl fmt::Display for McpProtocolVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for McpProtocolVersion {
    type Err = ParseMcpProtocolVersionError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "2025-03-26" => Ok(Self::V2025_03_26),
            "2025-06-18" => Ok(Self::V2025_06_18),
            "2025-11-25" => Ok(Self::V2025_11_25),
            _ => Err(ParseMcpProtocolVersionError {
                value: value.to_owned(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseMcpProtocolVersionError {
    value: String,
}

impl ParseMcpProtocolVersionError {
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for ParseMcpProtocolVersionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unsupported MCP protocol version '{}'",
            self.value
        )
    }
}

impl std::error::Error for ParseMcpProtocolVersionError {}

/// Immutable batch-shape metadata for an exact MCP revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct McpWireProfile {
    version: McpProtocolVersion,
    allows_json_rpc_batches: bool,
    max_batch_messages: Option<usize>,
}

impl McpWireProfile {
    #[must_use]
    pub const fn version(self) -> McpProtocolVersion {
        self.version
    }

    #[must_use]
    pub const fn allows_json_rpc_batches(self) -> bool {
        self.allows_json_rpc_batches
    }

    #[must_use]
    pub const fn max_batch_messages(self) -> Option<usize> {
        self.max_batch_messages
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    pub version: u32,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub filesystem_policy: Option<FilesystemPolicy>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub landlock: Option<LandlockPolicy>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub process: Option<ProcessPolicy>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub network_policies: BTreeMap<String, NetworkPolicyRule>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub network_middlewares: BTreeMap<String, NetworkMiddleware>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemPolicy {
    #[serde(default)]
    pub include_workdir: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_only: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_write: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LandlockCompatibility {
    #[default]
    BestEffort,
    HardRequirement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LandlockPolicy {
    #[serde(default)]
    pub compatibility: LandlockCompatibility,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessPolicy {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub run_as_user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub run_as_group: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicyRule {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<NetworkEndpoint>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub binaries: Vec<NetworkBinary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Endpoint DTO mirrors independent policy schema toggles."
)]
#[serde(deny_unknown_fields)]
pub struct NetworkEndpoint {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// Single port (backwards compat). Mutually exclusive with `ports`.
    /// Uses `u16` to reject invalid values >65535 at parse time.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub port: u16,
    /// Multiple ports. When non-empty, this endpoint covers all listed ports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tls: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub enforcement: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub access: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<L7Rule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_rules: Vec<L7DenyRule>,
    /// When true, percent-encoded `/` (`%2F`) is preserved in path segments
    /// rather than rejected by the L7 path canonicalizer. Required for
    /// upstreams like GitLab that embed `%2F` in namespaced resource paths.
    /// Defaults to false (strict).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_encoded_slash: bool,
    /// When true, client-to-server WebSocket text messages on this REST
    /// endpoint rewrite credential placeholders after an allowed 101 upgrade.
    /// Defaults to false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub websocket_credential_rewrite: bool,
    /// When true, supported textual REST request bodies rewrite credential
    /// placeholders before forwarding upstream. Defaults to false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub request_body_credential_rewrite: bool,
    /// Explicitly permits credentials on traffic paths that `OpenShell` cannot
    /// inspect or rewrite. Defaults to false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_uninspected_credentials: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub persisted_queries: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub graphql_persisted_queries: BTreeMap<String, GraphqlOperation>,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub graphql_max_body_bytes: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub credential_signing: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signing_service: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signing_region: String,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub credential_binding: Option<NetworkCredentialBinding>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub json_rpc: Option<JsonRpcConfig>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub mcp: Option<McpConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkCredentialBinding {
    pub provider: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcConfig {
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_body_bytes: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpConfig {
    // Presence is retained until authored-policy validation so an omitted
    // allowlist can select the pinned default while an explicit empty list is
    // rejected as an authoring mistake.
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub versions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_body_bytes: u32,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub strict_tool_names: Option<bool>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub allow_all_known_mcp_methods: Option<bool>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphqlOperation {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L7Rule {
    pub allow: L7Allow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L7Allow {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub command: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub query: BTreeMap<String, QueryMatcher>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub tool: Option<QueryMatcher>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, ParameterMatcher>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum QueryMatcher {
    // Short form: `query: { repo: "NVIDIA/*" }`.
    Glob(String),
    // Expanded form: `query: { repo: { any: ["NVIDIA/*", "openai/*"] } }`.
    Any(AnyMatcher),
}

// MCP params can be authored as nested maps in YAML, but the runtime matcher
// map remains flat so the Rego policy can share query-param matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ParameterMatcher {
    Matcher(QueryMatcher),
    Object(BTreeMap<String, Self>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnyMatcher {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L7DenyRule {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub command: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub query: BTreeMap<String, QueryMatcher>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub tool: Option<QueryMatcher>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, ParameterMatcher>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkBinary {
    pub path: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkMiddleware {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    pub middleware: String,
    #[serde(default, skip_serializing_if = "is_default")]
    pub order: i32,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub config: BTreeMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub on_error: String,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    pub endpoints: Option<MiddlewareEndpointSelector>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MiddlewareEndpointSelector {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
}

// Signature dictated by serde's `skip_serializing_if`.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(value: &u16) -> bool {
    *value == 0
}

// Signature dictated by serde's `skip_serializing_if`.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    value == &T::default()
}

fn deserialize_non_null_optional_field<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

// Unknown fields are collected only to produce fail-closed diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UnknownField {
    path: String,
}

/// Resource budgets enforced while noyalib builds the YAML document.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ParseLimits {
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_events: usize,
    pub max_nodes: usize,
    pub max_scalar_bytes: usize,
    pub max_alias_expansions: usize,
    pub max_mapping_keys: usize,
    pub max_sequence_elements: usize,
    pub max_documents: usize,
    pub max_merge_keys: usize,
    pub alias_anchor_ratio: Option<f64>,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_bytes: 4 * 1024 * 1024,
            max_depth: 64,
            max_events: 300_000,
            max_nodes: 100_000,
            max_scalar_bytes: 4 * 1024 * 1024,
            max_alias_expansions: 100,
            max_mapping_keys: 10_000,
            max_sequence_elements: 10_000,
            max_documents: 1,
            max_merge_keys: 0,
            alias_anchor_ratio: Some(5.0),
        }
    }
}

fn parser_config(limits: ParseLimits) -> serde_yml::ParserConfig {
    let mut config = serde_yml::ParserConfig::new();
    config.max_document_length = limits.max_bytes;
    config.max_depth = limits.max_depth;
    config.max_events = limits.max_events;
    config.max_nodes = limits.max_nodes;
    config.max_total_scalar_bytes = limits.max_scalar_bytes;
    config.max_alias_expansions = limits.max_alias_expansions;
    config.max_mapping_keys = limits.max_mapping_keys;
    config.max_sequence_length = limits.max_sequence_elements;
    config.max_documents = limits.max_documents;
    config.max_merge_keys = limits.max_merge_keys;
    config.alias_anchor_ratio = limits.alias_anchor_ratio;
    config.duplicate_key_policy = serde_yml::DuplicateKeyPolicy::Error;
    config.merge_key_policy = serde_yml::MergeKeyPolicy::Error;
    config
}

/// Parse a UTF-8 authored policy with explicit resource budgets.
pub fn parse_policy_with_limits(source: &str, limits: ParseLimits) -> Result<PolicyDocument> {
    let value: serde_yml::Value = serde_yml::from_str_with_config(source, &parser_config(limits))
        .into_diagnostic()
        .wrap_err("failed to parse sandbox policy YAML")?;
    let unknown_fields = collect_unknown_fields(&value);
    if let Some(unknown_field) = unknown_fields.first() {
        miette::bail!("unknown field '{}' in authored policy", unknown_field.path);
    }
    let policy: PolicyDocument = serde_yml::from_value(&value)
        .into_diagnostic()
        .wrap_err("failed to decode sandbox policy fields")?;
    validate_policy(&policy)?;
    Ok(policy)
}

/// Parse a UTF-8 authored policy with the shared default budgets.
pub fn parse_policy(source: &str) -> Result<PolicyDocument> {
    parse_policy_with_limits(source, ParseLimits::default())
}

/// Parse an authored policy from a byte slice, rejecting invalid UTF-8.
pub fn parse_policy_bytes(bytes: &[u8]) -> Result<PolicyDocument> {
    let source = std::str::from_utf8(bytes)
        .into_diagnostic()
        .wrap_err("sandbox policy is not valid UTF-8")?;
    parse_policy(source)
}

/// Read and parse an authored policy without an unbounded allocation.
pub fn parse_policy_reader<R: Read>(reader: R, limits: ParseLimits) -> Result<PolicyDocument> {
    parse_document_reader(reader, limits)
}

// Read and parse a policy after enforcing the byte limit.
fn parse_document_reader<R: Read>(reader: R, limits: ParseLimits) -> Result<PolicyDocument> {
    let limit = u64::try_from(limits.max_bytes).unwrap_or(u64::MAX);
    let mut bytes = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .into_diagnostic()
        .wrap_err("failed to read sandbox policy")?;
    if bytes.len() > limits.max_bytes {
        miette::bail!("policy exceeds the {}-byte input limit", limits.max_bytes);
    }
    let source = std::str::from_utf8(&bytes)
        .into_diagnostic()
        .wrap_err("sandbox policy is not valid UTF-8")?;
    parse_policy_with_limits(source, limits)
}

/// Load a regular file with metadata and bounded-read checks.
pub fn parse_policy_file(path: &Path, limits: ParseLimits) -> Result<PolicyDocument> {
    parse_document_file(path, limits)
}

// Load and parse a policy after validating the file source.
fn parse_document_file(path: &Path, limits: ParseLimits) -> Result<PolicyDocument> {
    let metadata = path
        .metadata()
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to inspect sandbox policy {}", path.display()))?;
    if !metadata.is_file() {
        miette::bail!(
            "sandbox policy source is not a regular file: {}",
            path.display()
        );
    }
    if metadata.len() > u64::try_from(limits.max_bytes).unwrap_or(u64::MAX) {
        miette::bail!("policy exceeds the {}-byte input limit", limits.max_bytes);
    }
    let file = File::open(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read sandbox policy from {}", path.display()))?;
    parse_document_reader(file, limits)
}

fn validate_policy(document: &PolicyDocument) -> Result<()> {
    if document.version != 1 {
        miette::bail!(
            "unsupported policy version {}; expected version 1",
            document.version
        );
    }
    for (key, rule) in &document.network_policies {
        let name = rule.effective_name(key);
        for endpoint in &rule.endpoints {
            if endpoint.protocol.eq_ignore_ascii_case("mcp") {
                if let Some(config) = &endpoint.mcp {
                    validate_mcp_config(config, &format!("network policy '{name}'"))?;
                }
            } else if endpoint.mcp.is_some() {
                miette::bail!(
                    "network policy '{name}': non-MCP endpoint '{}' cannot configure mcp options",
                    endpoint.host
                );
            }
        }
    }
    Ok(())
}

fn collect_unknown_fields(root: &serde_yml::Value) -> Vec<UnknownField> {
    let mut unknown_fields = Vec::new();
    let Some(root) = inspect_closed(
        root,
        "",
        &[
            "version",
            "filesystem_policy",
            "landlock",
            "process",
            "network_policies",
            "network_middlewares",
        ],
        &mut unknown_fields,
    ) else {
        return unknown_fields;
    };

    inspect_named(
        root.get("filesystem_policy"),
        "filesystem_policy",
        &["include_workdir", "read_only", "read_write"],
        &mut unknown_fields,
    );
    inspect_named(
        root.get("landlock"),
        "landlock",
        &["compatibility"],
        &mut unknown_fields,
    );
    inspect_named(
        root.get("process"),
        "process",
        &["run_as_user", "run_as_group"],
        &mut unknown_fields,
    );

    for (name, rule) in open_map(root.get("network_policies")) {
        let path = join("network_policies", name);
        if let Some(rule) = inspect_closed(
            rule,
            &path,
            &["name", "endpoints", "binaries"],
            &mut unknown_fields,
        ) {
            for (index, endpoint) in sequence(rule.get("endpoints")).iter().enumerate() {
                inspect_endpoint(
                    endpoint,
                    &format!("{path}.endpoints[{index}]"),
                    &mut unknown_fields,
                );
            }
            for (index, binary) in sequence(rule.get("binaries")).iter().enumerate() {
                inspect_closed(
                    binary,
                    &format!("{path}.binaries[{index}]"),
                    &["path"],
                    &mut unknown_fields,
                );
            }
        }
    }

    for (name, middleware) in open_map(root.get("network_middlewares")) {
        let path = join("network_middlewares", name);
        if let Some(middleware) = inspect_closed(
            middleware,
            &path,
            &[
                "name",
                "middleware",
                "order",
                "config",
                "on_error",
                "endpoints",
            ],
            &mut unknown_fields,
        ) {
            inspect_named(
                middleware.get("endpoints"),
                &join(&path, "endpoints"),
                &["include", "exclude"],
                &mut unknown_fields,
            );
            // `config` is deliberately an open user-data map.
        }
    }
    unknown_fields
}

fn inspect_endpoint(value: &serde_yml::Value, path: &str, out: &mut Vec<UnknownField>) {
    let Some(endpoint) = inspect_closed(
        value,
        path,
        &[
            "host",
            "path",
            "port",
            "ports",
            "protocol",
            "tls",
            "enforcement",
            "access",
            "rules",
            "allowed_ips",
            "deny_rules",
            "allow_encoded_slash",
            "websocket_credential_rewrite",
            "request_body_credential_rewrite",
            "allow_uninspected_credentials",
            "persisted_queries",
            "graphql_persisted_queries",
            "graphql_max_body_bytes",
            "credential_signing",
            "signing_service",
            "signing_region",
            "credential_binding",
            "json_rpc",
            "mcp",
        ],
        out,
    ) else {
        return;
    };
    inspect_named(
        endpoint.get("credential_binding"),
        &join(path, "credential_binding"),
        &["provider"],
        out,
    );
    inspect_named(
        endpoint.get("json_rpc"),
        &join(path, "json_rpc"),
        &["max_body_bytes"],
        out,
    );
    inspect_named(
        endpoint.get("mcp"),
        &join(path, "mcp"),
        &[
            "versions",
            "max_body_bytes",
            "strict_tool_names",
            "allow_all_known_mcp_methods",
        ],
        out,
    );
    for (name, operation) in open_map(endpoint.get("graphql_persisted_queries")) {
        inspect_closed(
            operation,
            &join(&join(path, "graphql_persisted_queries"), name),
            &["operation_type", "operation_name", "fields"],
            out,
        );
    }
    for (index, rule) in sequence(endpoint.get("rules")).iter().enumerate() {
        let rule_path = format!("{path}.rules[{index}]");
        if let Some(rule) = inspect_closed(rule, &rule_path, &["allow"], out) {
            inspect_allow(rule.get("allow"), &join(&rule_path, "allow"), out);
        }
    }
    for (index, deny) in sequence(endpoint.get("deny_rules")).iter().enumerate() {
        inspect_allow(Some(deny), &format!("{path}.deny_rules[{index}]"), out);
    }
}

fn inspect_allow(value: Option<&serde_yml::Value>, path: &str, out: &mut Vec<UnknownField>) {
    let allowed = vec![
        "method",
        "path",
        "command",
        "query",
        "operation_type",
        "operation_name",
        "fields",
        "tool",
        "params",
    ];
    let Some(value) = value else { return };
    let Some(rule) = inspect_closed(value, path, &allowed, out) else {
        return;
    };
    for (name, matcher) in open_map(rule.get("query")) {
        inspect_matcher(matcher, &join(&join(path, "query"), name), out);
    }
    if let Some(matcher) = rule.get("tool") {
        inspect_matcher(matcher, &join(path, "tool"), out);
    }
    for (name, matcher) in open_map(rule.get("params")) {
        inspect_parameter(matcher, &join(&join(path, "params"), name), out);
    }
}

fn inspect_matcher(value: &serde_yml::Value, path: &str, out: &mut Vec<UnknownField>) {
    if value.as_mapping().is_some() {
        inspect_closed(value, path, &["any"], out);
    }
}

fn inspect_parameter(value: &serde_yml::Value, path: &str, out: &mut Vec<UnknownField>) {
    let Some(mapping) = value.as_mapping() else {
        return;
    };
    if mapping.contains_key("any") {
        inspect_closed(value, path, &["any"], out);
        return;
    }
    // Nested MCP parameter keys form an open recursive namespace.
    for (name, child) in string_entries(mapping) {
        inspect_parameter(child, &join(path, name), out);
    }
}

fn inspect_named(
    value: Option<&serde_yml::Value>,
    path: &str,
    allowed: &[&str],
    out: &mut Vec<UnknownField>,
) {
    if let Some(value) = value {
        inspect_closed(value, path, allowed, out);
    }
}

fn inspect_closed<'a>(
    value: &'a serde_yml::Value,
    path: &str,
    allowed: &[&str],
    out: &mut Vec<UnknownField>,
) -> Option<&'a serde_yml::Mapping> {
    let mapping = value.as_mapping()?;
    for (name, _value) in string_entries(mapping) {
        if !allowed.contains(&name) {
            out.push(UnknownField {
                path: join(path, name),
            });
        }
    }
    Some(mapping)
}

fn string_entries(mapping: &serde_yml::Mapping) -> impl Iterator<Item = (&str, &serde_yml::Value)> {
    mapping.iter().map(|(key, value)| (key.as_str(), value))
}

fn open_map(value: Option<&serde_yml::Value>) -> Vec<(&str, &serde_yml::Value)> {
    value
        .and_then(serde_yml::Value::as_mapping)
        .map(|mapping| string_entries(mapping).collect())
        .unwrap_or_default()
}

fn sequence(value: Option<&serde_yml::Value>) -> &[serde_yml::Value] {
    value
        .and_then(serde_yml::Value::as_sequence)
        .map_or(&[], Vec::as_slice)
}

fn join(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_owned()
    } else {
        format!("{parent}.{child}")
    }
}

/// Serialize the authored representation to YAML.
pub fn serialize_policy(document: &PolicyDocument) -> Result<String> {
    serde_yml::to_string(document)
        .into_diagnostic()
        .wrap_err("failed to serialize policy to YAML")
}

/// Convert the authored representation to canonical JSON.
pub fn policy_to_json_value(document: &PolicyDocument) -> Result<serde_json::Value> {
    serde_json::to_value(document)
        .into_diagnostic()
        .wrap_err("failed to serialize policy to JSON")
}

/// Deserialize a JSON-RPC fragment using the canonical authored schema.
pub fn parse_json_rpc_config(value: serde_json::Value) -> Result<JsonRpcConfig> {
    reject_json_unknown_fields(&value, &["max_body_bytes"], "json_rpc")?;
    serde_json::from_value(value)
        .into_diagnostic()
        .wrap_err("invalid json_rpc config")
}

/// Deserialize an MCP fragment using the canonical authored schema.
pub fn parse_mcp_config(value: serde_json::Value) -> Result<McpConfig> {
    reject_json_unknown_fields(
        &value,
        &[
            "versions",
            "max_body_bytes",
            "strict_tool_names",
            "allow_all_known_mcp_methods",
        ],
        "mcp",
    )?;
    let config = serde_json::from_value(value.clone())
        .map_err(|error| miette::miette!("invalid mcp config {value}: {error}"))?;
    validate_mcp_config(&config, "invalid mcp config")?;
    Ok(config)
}

/// Validate authored MCP revision presence, vocabulary, and uniqueness.
pub fn validate_mcp_config(config: &McpConfig, context: &str) -> Result<()> {
    let Some(versions) = config.versions.as_deref() else {
        return Ok(());
    };
    if versions.is_empty() {
        miette::bail!(
            "{context} has an empty mcp.versions list; omit it to use the pinned default revision"
        );
    }
    let mut seen = std::collections::BTreeSet::new();
    for value in versions {
        let version = value
            .parse::<McpProtocolVersion>()
            .map_err(|error| miette::miette!("{context}: {error}; {MCP_VERSION_REMEDIATION}"))?;
        if !seen.insert(version) {
            miette::bail!("{context} has duplicate protocol version '{value}'");
        }
    }
    Ok(())
}

fn reject_json_unknown_fields(
    value: &serde_json::Value,
    allowed: &[&str],
    stanza: &str,
) -> Result<()> {
    if let Some(object) = value.as_object()
        && let Some(field) = object
            .keys()
            .find(|field| !allowed.contains(&field.as_str()))
    {
        miette::bail!("invalid {stanza} config: unknown field '{field}'");
    }
    Ok(())
}

impl PolicyDocument {
    /// Effective filesystem policy. Absence enables the runtime workdir default;
    /// an explicitly present empty object retains `include_workdir: false`.
    #[must_use]
    pub fn effective_filesystem_policy(&self) -> FilesystemPolicy {
        self.filesystem_policy
            .clone()
            .unwrap_or_else(|| FilesystemPolicy {
                include_workdir: true,
                read_only: Vec::new(),
                read_write: Vec::new(),
            })
    }
}

impl NetworkPolicyRule {
    /// Effective rule name, falling back to the surrounding map key.
    #[must_use]
    pub fn effective_name<'a>(&'a self, key: &'a str) -> &'a str {
        if self.name.is_empty() {
            key
        } else {
            &self.name
        }
    }
}

impl NetworkEndpoint {
    /// Effective authored ports. A non-empty `ports` list takes precedence.
    #[must_use]
    pub fn effective_ports(&self) -> Vec<u16> {
        if self.ports.is_empty() {
            (self.port != 0).then_some(self.port).into_iter().collect()
        } else {
            self.ports.clone()
        }
    }

    /// Whether this endpoint is uninspected L4 traffic.
    #[must_use]
    pub fn is_l4(&self) -> bool {
        self.protocol.is_empty() || self.protocol.eq_ignore_ascii_case("tcp")
    }
}

/// Intrinsic access-preset vocabulary in the authored policy language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessPreset {
    ReadOnly,
    ReadWrite,
    Full,
}

impl AccessPreset {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "read-only" => Some(Self::ReadOnly),
            "read-write" => Some(Self::ReadWrite),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    /// Expand a preset to the authored protocol methods it represents.
    #[must_use]
    pub fn methods(self, protocol: &str) -> &'static [&'static str] {
        match (protocol, self) {
            (_, Self::Full) => &["*"],
            ("websocket", Self::ReadOnly) => &["GET"],
            ("websocket", Self::ReadWrite) => &["GET", "WEBSOCKET_TEXT"],
            (_, Self::ReadOnly) => &["GET", "HEAD", "OPTIONS"],
            (_, Self::ReadWrite) => &["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"],
        }
    }
}

/// Expand a recognized access preset for a protocol.
#[must_use]
pub fn expand_access_preset(protocol: &str, access: &str) -> Option<&'static [&'static str]> {
    AccessPreset::parse(access).map(|preset| preset.methods(protocol))
}

/// Normalize a policy path lexically without filesystem access.
#[must_use]
pub fn normalize_path(path: &str) -> String {
    use std::path::Component;

    let mut normalized = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            #[allow(clippy::path_buf_push_overwrite)]
            Component::RootDir => normalized.push("/"),
            Component::CurDir => {}
            Component::ParentDir => normalized.push(".."),
            Component::Normal(component) => normalized.push(component),
        }
    }
    let normalized = normalized.to_string_lossy();
    #[cfg(target_os = "windows")]
    {
        normalized.replace('\\', "/")
    }
    #[cfg(not(target_os = "windows"))]
    {
        normalized.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_version_one() {
        assert!(parse_policy("version: 2\n").is_err());
        assert!(parse_policy("network_policies: {}\n").is_err());
    }

    #[test]
    fn rejects_duplicate_keys() {
        let error = parse_policy("version: 1\nversion: 1\n").expect_err("duplicate key must fail");
        assert!(error.to_string().contains("parse sandbox policy"));
    }

    #[test]
    fn distinguishes_absent_and_empty_filesystem() {
        let absent = parse_policy("version: 1\n").unwrap();
        let empty = parse_policy("version: 1\nfilesystem_policy: {}\n").unwrap();
        assert!(absent.effective_filesystem_policy().include_workdir);
        assert!(!empty.effective_filesystem_policy().include_workdir);
    }

    #[test]
    fn rejects_oversized_port() {
        assert!(parse_policy(
            "version: 1\nnetwork_policies:\n  x:\n    endpoints:\n      - host: x\n        port: 65536\n",
        )
        .is_err());
    }

    #[test]
    fn explicit_null_does_not_collapse_to_omission() {
        for source in [
            "version: 1\nfilesystem_policy: null\n",
            "version: 1\nprocess: null\n",
            "version: 1\nmetadata: null\n",
            "version: 1\nnetwork_policies:\n  x:\n    endpoints:\n      - host: x\n        port: 443\n        mcp: null\n",
        ] {
            assert!(
                parse_policy(source).is_err(),
                "explicit null unexpectedly parsed: {source}"
            );
        }
    }

    #[test]
    fn truncation_paths_are_unicode_safe() {
        let oversized = "é".repeat(ParseLimits::default().max_bytes);
        let source = format!("version: 1\nunknown_{oversized}: true\n");
        assert!(parse_policy(&source).is_err());
    }

    #[test]
    fn path_normalization_is_lexical() {
        assert_eq!(normalize_path("/usr//./lib/"), "/usr/lib");
        assert_eq!(normalize_path("/usr/../etc"), "/usr/../etc");
    }

    #[test]
    fn rejects_unknown_fields_at_every_closed_schema_level() {
        let cases = [
            ("version: 1\nfuture: true\n", "future"),
            (
                "version: 1\nfilesystem_policy: { future: true }\n",
                "filesystem_policy.future",
            ),
            (
                "version: 1\nlandlock: { future: true }\n",
                "landlock.future",
            ),
            ("version: 1\nprocess: { future: true }\n", "process.future"),
            (
                "version: 1\nnetwork_policies: { api: { future: true } }\n",
                "network_policies.api.future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { endpoints: [{ host: example.com, port: 443, future: true }] } }\n",
                "network_policies.api.endpoints[0].future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { binaries: [{ path: /bin/tool, future: true }] } }\n",
                "network_policies.api.binaries[0].future",
            ),
            (
                "version: 1\nnetwork_middlewares: { audit: { middleware: logger, future: true } }\n",
                "network_middlewares.audit.future",
            ),
            (
                "version: 1\nnetwork_middlewares: { audit: { middleware: logger, endpoints: { future: true } } }\n",
                "network_middlewares.audit.endpoints.future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { endpoints: [{ host: example.com, port: 443, credential_binding: { provider: p, future: true } }] } }\n",
                "network_policies.api.endpoints[0].credential_binding.future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { endpoints: [{ host: example.com, port: 443, json_rpc: { future: true } }] } }\n",
                "network_policies.api.endpoints[0].json_rpc.future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { endpoints: [{ host: example.com, port: 443, protocol: mcp, mcp: { future: true } }] } }\n",
                "network_policies.api.endpoints[0].mcp.future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { endpoints: [{ host: example.com, port: 443, graphql_persisted_queries: { op: { future: true } } }] } }\n",
                "network_policies.api.endpoints[0].graphql_persisted_queries.op.future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { endpoints: [{ host: example.com, port: 443, rules: [{ future: true, allow: {} }] }] } }\n",
                "network_policies.api.endpoints[0].rules[0].future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { endpoints: [{ host: example.com, port: 443, rules: [{ allow: { future: true } }] }] } }\n",
                "network_policies.api.endpoints[0].rules[0].allow.future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { endpoints: [{ host: example.com, port: 443, deny_rules: [{ future: true }] }] } }\n",
                "network_policies.api.endpoints[0].deny_rules[0].future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { endpoints: [{ host: example.com, port: 443, rules: [{ allow: { query: { q: { any: [one], future: true } } } }] }] } }\n",
                "network_policies.api.endpoints[0].rules[0].allow.query.q.future",
            ),
            (
                "version: 1\nnetwork_policies: { api: { endpoints: [{ host: example.com, port: 443, rules: [{ allow: { tool: { any: [one], future: true } } }] }] } }\n",
                "network_policies.api.endpoints[0].rules[0].allow.tool.future",
            ),
        ];

        for (source, expected_path) in cases {
            let error = parse_policy(source).expect_err("unknown field must fail closed");
            assert!(
                error.to_string().contains(expected_path),
                "missing path {expected_path} in {error:?}"
            );
        }
    }

    #[test]
    fn accepts_open_user_data_maps() {
        let source = r#"
version: 1
network_middlewares:
  audit:
    middleware: logger
    config:
      arbitrary_plugin_key: { nested: true }
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        port: 443
        protocol: mcp
        mcp: {}
        rules:
          - allow:
              method: tools/call
              query:
                arbitrary_name: { any: ["one", "two"] }
              params:
                arguments:
                  nested:
                    leaf: "value-*"
"#;
        parse_policy(source).unwrap();
    }

    #[test]
    fn rejects_unsupported_managed_metadata_and_review() {
        let source = r"
version: 1
metadata:
  policy_id: managed/default
  version: 7
  allowed_modes: [audit, enforce]
  default_mode: enforce
  audit_label: production
network_policies:
  api:
    endpoints:
      - host: example.com
        port: 443
        review: { required: true, reason: human approval }
        rules:
          - allow:
              method: GET
              path: /v1/**
              review: { required: true, reason: broad path }
";
        assert!(parse_policy(source).is_err());
    }

    #[test]
    fn parser_budgets_are_enforced_during_decode() {
        let tiny = ParseLimits {
            max_bytes: 256,
            max_depth: 2,
            max_events: 8,
            max_nodes: 4,
            max_scalar_bytes: 32,
            max_alias_expansions: 0,
            max_mapping_keys: 2,
            max_sequence_elements: 2,
            max_documents: 1,
            max_merge_keys: 0,
            alias_anchor_ratio: Some(1.0),
        };
        assert!(
            parse_policy_with_limits(
                "version: 1\nnetwork_policies: {a: {}, b: {}, c: {}}\n",
                tiny,
            )
            .is_err()
        );
    }

    #[test]
    fn bounded_reader_rejects_growth_past_limit_and_invalid_utf8() {
        let limits = ParseLimits {
            max_bytes: 12,
            ..ParseLimits::default()
        };
        assert!(parse_policy_reader(&b"version: 1\nextra"[..], limits,).is_err());
        assert!(parse_policy_bytes(&[0xff]).is_err());
    }

    #[test]
    fn access_presets_expand_consistently() {
        assert_eq!(
            expand_access_preset("rest", "read-only"),
            Some(&["GET", "HEAD", "OPTIONS"][..])
        );
        assert_eq!(
            expand_access_preset("websocket", "read-write"),
            Some(&["GET", "WEBSOCKET_TEXT"][..])
        );
        assert_eq!(expand_access_preset("rest", "unknown"), None);
    }
}
