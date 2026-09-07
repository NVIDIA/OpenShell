// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared sandbox policy parsing and defaults for `OpenShell`.
//!
//! Provides bidirectional YAML↔proto conversion for sandbox policies.
//!
//! The serde types here are the **single canonical representation** of the YAML
//! policy schema. Both parsing (YAML→proto) and serialization (proto→YAML) use
//! these types, ensuring round-trip fidelity.

mod compose;
mod l7_validate;
mod merge;
mod middleware;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::net::IpAddr;
use std::path::Path;

mod ambiguity;

pub use ambiguity::{EndpointAmbiguity, find_endpoint_ambiguities};

use hickory_proto::rr::Name;
use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::mcp::{DEFAULT_MCP_PROTOCOL_VERSION, McpProtocolVersion};
use openshell_core::proto::{
    FilesystemPolicy, GraphqlOperation, L7Allow, L7DenyRule, L7QueryMatcher, L7Rule,
    LandlockPolicy, McpOptions, NetworkBinary, NetworkEndpoint, NetworkPolicyRule, ProcessPolicy,
    SandboxPolicy,
};
use serde::{Deserialize, Deserializer, Serialize};

pub use compose::{
    PROVIDER_RULE_NAME_PREFIX, ProviderPolicyLayer, compose_effective_policy,
    is_provider_rule_name, provider_rule_name, strip_provider_rule_names,
};
pub use l7_validate::{
    L7EndpointFields, L7Protocol, agent_authored_transport_rejection,
    validate_explicit_tcp_additional_fields, validate_l7_endpoint_semantics,
};
pub use merge::{
    PolicyMergeError, PolicyMergeOp, PolicyMergeResult, PolicyMergeWarning,
    canonicalize_advisor_add_rule, generated_rule_name, merge_policy, policy_covers_rule,
};
pub use middleware::middleware_host_matches;
pub use middleware::validate_json as validate_network_middleware_json;
pub use middleware::validate_json_with_config as validate_network_middleware_json_with_config;

// ---------------------------------------------------------------------------
// YAML serde types (canonical — used for both parsing and serialization)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    filesystem_policy: Option<FilesystemDef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    landlock: Option<LandlockDef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    process: Option<ProcessDef>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    network_policies: BTreeMap<String, NetworkPolicyRuleDef>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    network_middlewares: BTreeMap<String, middleware::NetworkMiddlewareConfigDef>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilesystemDef {
    #[serde(default)]
    include_workdir: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    read_only: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    read_write: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LandlockDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    compatibility: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    run_as_user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    run_as_group: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkPolicyRuleDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    endpoints: Vec<NetworkEndpointDef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    binaries: Vec<NetworkBinaryDef>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Endpoint DTO mirrors independent policy schema toggles."
)]
struct NetworkEndpointDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    host: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    path: String,
    /// Single port (backwards compat). Mutually exclusive with `ports`.
    /// Uses `u16` to reject invalid values >65535 at parse time.
    #[serde(default, skip_serializing_if = "is_zero")]
    port: u16,
    /// Multiple ports. When non-empty, this endpoint covers all listed ports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ports: Vec<u16>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    protocol: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    tls: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    enforcement: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    access: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rules: Vec<L7RuleDef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    allowed_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    deny_rules: Vec<L7DenyRuleDef>,
    /// When true, percent-encoded `/` (`%2F`) is preserved in path segments
    /// rather than rejected by the L7 path canonicalizer. Required for
    /// upstreams like GitLab that embed `%2F` in namespaced resource paths.
    /// Defaults to false (strict).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    allow_encoded_slash: bool,
    /// When true, client-to-server WebSocket text messages on this REST
    /// endpoint rewrite credential placeholders after an allowed 101 upgrade.
    /// Defaults to false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    websocket_credential_rewrite: bool,
    /// When true, supported textual REST request bodies rewrite credential
    /// placeholders before forwarding upstream. Defaults to false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    request_body_credential_rewrite: bool,
    /// Explicitly permits credentials on traffic paths that `OpenShell` cannot
    /// inspect or rewrite. Defaults to false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    allow_uninspected_credentials: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    persisted_queries: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    graphql_persisted_queries: BTreeMap<String, GraphqlOperationDef>,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    graphql_max_body_bytes: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    credential_signing: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    signing_service: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    signing_region: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_binding: Option<NetworkCredentialBindingDef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    json_rpc: Option<JsonRpcConfigDef>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    mcp: Option<McpConfigDef>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkCredentialBindingDef {
    provider: String,
}

// Signature dictated by serde's `skip_serializing_if`, which requires `&T`.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(v: &u16) -> bool {
    *v == 0
}

// Signature dictated by serde's `skip_serializing_if`, which requires `&T`.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

fn deserialize_non_null_optional_field<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    // Serde skips this function when the field is absent because the field has
    // `default`. When it is present, deserialize `T` directly so an explicit
    // YAML or JSON null is rejected instead of collapsing into omission.
    T::deserialize(deserializer).map(Some)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonRpcConfigDef {
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    max_body_bytes: u32,
}

fn json_rpc_config_from_proto(max_body_bytes: u32) -> Option<JsonRpcConfigDef> {
    (max_body_bytes > 0).then_some(JsonRpcConfigDef { max_body_bytes })
}

// MCP rides the same HTTP/JSON-RPC inspection machinery at runtime, but it
// gets its own policy stanza so user-authored YAML can name the primary
// protocol instead of treating MCP as generic JSON-RPC.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct McpConfigDef {
    // Presence is retained until authored-policy validation so an omitted
    // allowlist can select the pinned default while an explicit empty list is
    // rejected as an authoring mistake.
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional_field",
        skip_serializing_if = "Option::is_none"
    )]
    versions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    max_body_bytes: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    strict_tool_names: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allow_all_known_mcp_methods: Option<bool>,
}

const MCP_VERSION_REMEDIATION: &str = "omit mcp.versions to use the pinned default revision, use an exact supported revision, or omit protocol and mcp for deliberate uninspected L4 passthrough only when that weaker boundary is acceptable";

fn validate_authored_mcp_versions(versions: Option<&[String]>, context: &str) -> Result<()> {
    let Some(versions) = versions else {
        return Ok(());
    };
    if versions.is_empty() {
        return Err(miette::miette!(
            "{context} has an empty mcp.versions list; omit mcp.versions to use the pinned default revision"
        ));
    }

    let mut seen = BTreeSet::new();
    for value in versions {
        let version = value
            .parse::<McpProtocolVersion>()
            .map_err(|error| miette::miette!("{context}: {error}; {MCP_VERSION_REMEDIATION}"))?;
        if !seen.insert(version) {
            return Err(miette::miette!(
                "{context} has duplicate protocol version '{value}'"
            ));
        }
    }
    Ok(())
}

fn mcp_config_from_proto(max_body_bytes: u32, mcp: Option<&McpOptions>) -> Option<McpConfigDef> {
    let mut versions = mcp
        .map(|config| config.versions.clone())
        .unwrap_or_default();
    canonicalize_mcp_versions(&mut versions);
    let strict_tool_names = mcp.and_then(|config| config.strict_tool_names);
    let allow_all_known_mcp_methods = mcp.and_then(|config| config.allow_all_known_mcp_methods);
    (!versions.is_empty()
        || max_body_bytes > 0
        || strict_tool_names.is_some()
        || allow_all_known_mcp_methods.is_some())
    .then_some(McpConfigDef {
        versions: Some(versions),
        max_body_bytes,
        strict_tool_names,
        allow_all_known_mcp_methods,
    })
}

/// Nested L7 config stanzas accepted by the YAML policy schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L7ConfigStanza {
    JsonRpc,
    Mcp,
}

impl L7ConfigStanza {
    pub const ALL: [Self; 2] = [Self::JsonRpc, Self::Mcp];

    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::JsonRpc => "json_rpc",
            Self::Mcp => "mcp",
        }
    }
}

/// Parse an L7 nested config stanza and return the flattened runtime fields
/// consumed by the supervisor policy engine.
///
/// The stanza schema stays tied to this crate's canonical serde definitions, so
/// adding a new supported field requires updating this conversion next to the
/// type that parses it. MCP revision fields are validated before the alias is
/// flattened so invalid authoring cannot disappear when version metadata is
/// omitted from the returned runtime-only fields.
pub fn l7_config_alias_runtime_fields(
    stanza: L7ConfigStanza,
    value: serde_json::Value,
) -> Result<Vec<(&'static str, serde_json::Value)>> {
    match stanza {
        L7ConfigStanza::JsonRpc => {
            let JsonRpcConfigDef { max_body_bytes } = serde_json::from_value(value)
                .map_err(|error| miette::miette!("invalid json_rpc config: {error}"))?;
            let mut fields = Vec::new();
            if max_body_bytes > 0 {
                fields.push(("json_rpc_max_body_bytes", serde_json::json!(max_body_bytes)));
            }
            Ok(fields)
        }
        L7ConfigStanza::Mcp => {
            let config: McpConfigDef = serde_json::from_value(value)
                .map_err(|error| miette::miette!("invalid mcp config: {error}"))?;
            validate_authored_mcp_versions(config.versions.as_deref(), "invalid mcp config")?;
            let McpConfigDef {
                versions: _,
                max_body_bytes,
                strict_tool_names,
                allow_all_known_mcp_methods,
            } = config;
            let mut fields = Vec::new();
            if max_body_bytes > 0 {
                fields.push(("json_rpc_max_body_bytes", serde_json::json!(max_body_bytes)));
            }
            if let Some(strict_tool_names) = strict_tool_names {
                fields.push((
                    "mcp_strict_tool_names",
                    serde_json::json!(strict_tool_names),
                ));
            }
            if let Some(allow_all_known_mcp_methods) = allow_all_known_mcp_methods {
                fields.push((
                    "mcp_allow_all_known_mcp_methods",
                    serde_json::json!(allow_all_known_mcp_methods),
                ));
            }
            Ok(fields)
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphqlOperationDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    operation_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    operation_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    fields: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct L7RuleDef {
    allow: L7AllowDef,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct L7AllowDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    command: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    query: BTreeMap<String, QueryMatcherDef>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    operation_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    operation_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tool: Option<QueryMatcherDef>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    params: BTreeMap<String, ParamMatcherDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum QueryMatcherDef {
    // Short form: `query: { repo: "NVIDIA/*" }`.
    Glob(String),
    // Expanded form: `query: { repo: { any: ["NVIDIA/*", "openai/*"] } }`.
    Any(QueryAnyDef),
}

// MCP params can be authored as nested maps in YAML, but the runtime matcher
// map remains flat so the Rego policy can share query-param matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum ParamMatcherDef {
    Matcher(QueryMatcherDef),
    Object(BTreeMap<String, Self>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueryAnyDef {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    any: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct L7DenyRuleDef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    command: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    query: BTreeMap<String, QueryMatcherDef>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    operation_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    operation_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tool: Option<QueryMatcherDef>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    params: BTreeMap<String, ParamMatcherDef>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkBinaryDef {
    path: String,
    /// Deprecated: ignored. Kept for backward compat with existing YAML files.
    #[serde(default, skip_serializing)]
    #[allow(dead_code)]
    harness: bool,
}

// ---------------------------------------------------------------------------
// YAML → proto conversion
// ---------------------------------------------------------------------------

fn matcher_def_to_proto(matcher: QueryMatcherDef) -> L7QueryMatcher {
    match matcher {
        QueryMatcherDef::Glob(glob) => L7QueryMatcher { glob, any: vec![] },
        QueryMatcherDef::Any(any) => L7QueryMatcher {
            glob: String::new(),
            any: any.any,
        },
    }
}

fn matcher_proto_to_def(matcher: L7QueryMatcher) -> QueryMatcherDef {
    if matcher.any.is_empty() {
        QueryMatcherDef::Glob(matcher.glob)
    } else {
        QueryMatcherDef::Any(QueryAnyDef { any: matcher.any })
    }
}

// Convert MCP params maps into the flat proto/Rego keyspace. Only `name` is
// currently enforced for tools/call, but this keeps the YAML shape compatible
// with any future MCP-owned params selectors.
fn flatten_param_matchers(
    params: BTreeMap<String, ParamMatcherDef>,
) -> BTreeMap<String, QueryMatcherDef> {
    let mut flattened = BTreeMap::new();
    for (key, matcher) in params {
        flatten_param_matcher(&key, matcher, &mut flattened);
    }
    flattened
}

// Walk one params subtree, carrying the flattened dot-path key accumulated so
// far. Leaf matchers are inserted into the map consumed by the runtime policy.
fn flatten_param_matcher(
    key: &str,
    matcher: ParamMatcherDef,
    out: &mut BTreeMap<String, QueryMatcherDef>,
) {
    match matcher {
        ParamMatcherDef::Matcher(matcher) => {
            out.insert(key.to_string(), matcher);
        }
        ParamMatcherDef::Object(children) => {
            for (child_key, child) in children {
                let nested_key = format!("{key}.{child_key}");
                flatten_param_matcher(&nested_key, child, out);
            }
        }
    }
}

// Convert flat runtime params back to YAML. MCP gets readable nested params
// when the flat keys can be losslessly split. Non-MCP protocols keep flat keys
// only for lossless serialization; generic JSON-RPC validation rejects params
// matchers before enforcement.
fn flat_params_to_def(
    protocol: &str,
    params: BTreeMap<String, QueryMatcherDef>,
) -> BTreeMap<String, ParamMatcherDef> {
    let flat = params.into_iter().collect::<Vec<_>>();
    // MCP uses nested YAML for readability. Non-MCP protocols keep the flat
    // form for lossless serialization of existing proto data only.
    if !is_mcp_protocol(protocol) {
        return flat_param_matchers_to_def(flat);
    }

    let mut nested = BTreeMap::new();
    for (key, matcher) in &flat {
        if insert_nested_param(&mut nested, key, ParamMatcherDef::Matcher(matcher.clone())).is_err()
        {
            return flat_param_matchers_to_def(flat);
        }
    }
    nested
}

fn flat_param_matchers_to_def(
    params: Vec<(String, QueryMatcherDef)>,
) -> BTreeMap<String, ParamMatcherDef> {
    params
        .into_iter()
        .map(|(key, matcher)| (key, ParamMatcherDef::Matcher(matcher)))
        .collect()
}

// Build one nested params path from a flat key. Collisions such as `a` and
// `a.b` cannot round-trip as nested YAML, so callers fall back to the flat map.
fn insert_nested_param(
    root: &mut BTreeMap<String, ParamMatcherDef>,
    key: &str,
    matcher: ParamMatcherDef,
) -> Result<(), ()> {
    let mut parts = key.split('.').peekable();
    let Some(first) = parts.next() else {
        return Err(());
    };

    if parts.peek().is_none() {
        root.insert(first.to_string(), matcher);
        return Ok(());
    }

    let child = root
        .entry(first.to_string())
        .or_insert_with(|| ParamMatcherDef::Object(BTreeMap::new()));
    let ParamMatcherDef::Object(children) = child else {
        return Err(());
    };
    let remainder = parts.collect::<Vec<_>>().join(".");
    insert_nested_param(children, &remainder, matcher)
}

// MCP `tool` is a policy convenience for the standard `tools/call` params.name
// field. When the endpoint method profile is enabled, authored tool selectors
// can omit method and are normalized to tools/call internally. Tool arguments
// intentionally have no policy matcher yet, so every allowed tool call permits
// all argument payloads by default.
fn params_with_tool(
    mut params: BTreeMap<String, ParamMatcherDef>,
    tool: Option<QueryMatcherDef>,
) -> BTreeMap<String, ParamMatcherDef> {
    if let Some(tool) = tool {
        params
            .entry("name".to_string())
            .or_insert_with(|| ParamMatcherDef::Matcher(tool));
    }
    params
}

fn allow_def_to_proto(_protocol: &str, allow: L7AllowDef) -> L7Allow {
    let params = flatten_param_matchers(params_with_tool(allow.params, allow.tool));
    L7Allow {
        method: allow.method,
        path: allow.path,
        command: allow.command,
        operation_type: allow.operation_type,
        operation_name: allow.operation_name,
        fields: allow.fields,
        query: allow
            .query
            .into_iter()
            .map(|(key, matcher)| (key, matcher_def_to_proto(matcher)))
            .collect(),
        params: params
            .into_iter()
            .map(|(key, matcher)| (key, matcher_def_to_proto(matcher)))
            .collect(),
    }
}

fn deny_def_to_proto(_protocol: &str, deny: L7DenyRuleDef) -> L7DenyRule {
    let params = flatten_param_matchers(params_with_tool(deny.params, deny.tool));
    L7DenyRule {
        method: deny.method,
        path: deny.path,
        command: deny.command,
        operation_type: deny.operation_type,
        operation_name: deny.operation_name,
        fields: deny.fields,
        query: deny
            .query
            .into_iter()
            .map(|(key, matcher)| (key, matcher_def_to_proto(matcher)))
            .collect(),
        params: params
            .into_iter()
            .map(|(key, matcher)| (key, matcher_def_to_proto(matcher)))
            .collect(),
    }
}

fn json_rpc_max_body_bytes(json_rpc: &Option<JsonRpcConfigDef>, mcp: &Option<McpConfigDef>) -> u32 {
    // The proto has one JSON-RPC-family body limit. Prefer the MCP stanza when
    // present because MCP policies should not need a shadow `json_rpc` block.
    mcp.as_ref().map_or_else(
        || json_rpc.as_ref().map_or(0, |config| config.max_body_bytes),
        |config| config.max_body_bytes,
    )
}

fn mcp_options(protocol: &str, mcp: &Option<McpConfigDef>) -> Option<McpOptions> {
    if !is_mcp_protocol(protocol) {
        return None;
    }

    let mut versions = mcp
        .as_ref()
        .and_then(|config| config.versions.clone())
        .unwrap_or_else(default_mcp_versions);
    // Authored YAML is validated before this conversion. Sort only after that
    // boundary so duplicate or unsupported input cannot be hidden.
    canonicalize_mcp_versions(&mut versions);
    Some(McpOptions {
        strict_tool_names: mcp.as_ref().and_then(|config| config.strict_tool_names),
        allow_all_known_mcp_methods: mcp
            .as_ref()
            .and_then(|config| config.allow_all_known_mcp_methods),
        versions,
    })
}

fn is_mcp_protocol(protocol: &str) -> bool {
    protocol.eq_ignore_ascii_case("mcp")
}

fn default_mcp_versions() -> Vec<String> {
    // The single pinned constant is intentionally independent of the registry
    // size and order, so adding support for a revision cannot widen an
    // existing versionless policy.
    vec![DEFAULT_MCP_PROTOCOL_VERSION.as_str().to_string()]
}

fn canonicalize_mcp_versions(versions: &mut [String]) {
    // Unknown and duplicate values remain present so canonicalization cannot
    // erase evidence that the raw policy was invalid.
    versions.sort_by(|left, right| {
        match (
            left.parse::<McpProtocolVersion>(),
            right.parse::<McpProtocolVersion>(),
        ) {
            (Ok(left), Ok(right)) => left.cmp(&right),
            (Ok(_), Err(_)) => std::cmp::Ordering::Less,
            (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
            (Err(_), Err(_)) => left.cmp(right),
        }
    });
}

/// Sort one protobuf MCP contract without hiding invalid input.
///
/// Exact supported revisions use semantic catalog order. Duplicate and
/// unsupported identifiers remain present for subsequent validation.
pub(crate) fn canonicalize_mcp_options(options: &mut McpOptions) {
    canonicalize_mcp_versions(&mut options.versions);
}

fn split_tool_param(
    protocol: &str,
    params: BTreeMap<String, QueryMatcherDef>,
) -> (Option<QueryMatcherDef>, BTreeMap<String, QueryMatcherDef>) {
    // Only MCP has the tool-name convention. Non-MCP protocols preserve proto
    // params on round-trip without inventing MCP semantics.
    if !is_mcp_protocol(protocol) {
        return (None, params);
    }

    let mut params = params;
    let tool = params.remove("name");
    (tool, params)
}

fn allow_proto_to_def(
    protocol: &str,
    allow: L7Allow,
    mcp_allow_all_known_mcp_methods: bool,
) -> L7AllowDef {
    let params: BTreeMap<String, QueryMatcherDef> = allow
        .params
        .into_iter()
        .map(|(key, matcher)| (key, matcher_proto_to_def(matcher)))
        .collect();
    let (tool, params) = split_tool_param(protocol, params);
    let params = flat_params_to_def(protocol, params);
    let method = yaml_mcp_method(
        protocol,
        &allow.method,
        tool.is_some(),
        mcp_allow_all_known_mcp_methods,
    );
    L7AllowDef {
        method,
        path: allow.path,
        command: allow.command,
        query: allow
            .query
            .into_iter()
            .map(|(key, matcher)| (key, matcher_proto_to_def(matcher)))
            .collect(),
        operation_type: allow.operation_type,
        operation_name: allow.operation_name,
        fields: allow.fields,
        tool,
        params,
    }
}

fn deny_proto_to_def(
    protocol: &str,
    deny: &L7DenyRule,
    mcp_allow_all_known_mcp_methods: bool,
) -> L7DenyRuleDef {
    let params: BTreeMap<String, QueryMatcherDef> = deny
        .params
        .iter()
        .map(|(key, matcher)| (key.clone(), matcher_proto_to_def(matcher.clone())))
        .collect();
    let (tool, params) = split_tool_param(protocol, params);
    let params = flat_params_to_def(protocol, params);
    let method = yaml_mcp_method(
        protocol,
        &deny.method,
        tool.is_some(),
        mcp_allow_all_known_mcp_methods,
    );
    L7DenyRuleDef {
        method,
        path: deny.path.clone(),
        command: deny.command.clone(),
        query: deny
            .query
            .iter()
            .map(|(key, matcher)| (key.clone(), matcher_proto_to_def(matcher.clone())))
            .collect(),
        operation_type: deny.operation_type.clone(),
        operation_name: deny.operation_name.clone(),
        fields: deny.fields.clone(),
        tool,
        params,
    }
}

fn yaml_mcp_method(
    protocol: &str,
    method: &str,
    has_tool: bool,
    mcp_allow_all_known_mcp_methods: bool,
) -> String {
    if is_mcp_protocol(protocol) {
        if !has_tool && method == "*" {
            return String::new();
        }
        if has_tool && method == "tools/call" && mcp_allow_all_known_mcp_methods {
            return String::new();
        }
    }
    method.to_string()
}

fn to_proto(raw: PolicyFile) -> Result<SandboxPolicy> {
    let network_middlewares = middleware::into_proto(raw.network_middlewares)
        .into_diagnostic()
        .wrap_err("failed to convert network middleware config")?;

    let network_policies = raw
        .network_policies
        .into_iter()
        .map(|(key, rule)| {
            let proto_rule = NetworkPolicyRule {
                name: if rule.name.is_empty() {
                    key.clone()
                } else {
                    rule.name
                },
                endpoints: rule
                    .endpoints
                    .into_iter()
                    .map(|e| {
                        let protocol = e.protocol;
                        let allow_rules = e.rules;
                        let deny_rules = e.deny_rules;
                        // Normalize port/ports: ports takes precedence, else
                        // single port is promoted to ports array.
                        let normalized_ports: Vec<u32> = if !e.ports.is_empty() {
                            e.ports.into_iter().map(u32::from).collect()
                        } else if e.port > 0 {
                            vec![u32::from(e.port)]
                        } else {
                            vec![]
                        };
                        NetworkEndpoint {
                            host: e.host,
                            path: e.path,
                            port: normalized_ports.first().copied().unwrap_or(0),
                            ports: normalized_ports,
                            protocol: protocol.clone(),
                            tls: e.tls,
                            enforcement: e.enforcement,
                            access: e.access,
                            rules: allow_rules
                                .into_iter()
                                .map(|r| L7Rule {
                                    allow: Some(allow_def_to_proto(&protocol, r.allow)),
                                })
                                .collect(),
                            allowed_ips: e.allowed_ips,
                            deny_rules: deny_rules
                                .into_iter()
                                .map(|deny| deny_def_to_proto(&protocol, deny))
                                .collect(),
                            allow_encoded_slash: e.allow_encoded_slash,
                            websocket_credential_rewrite: e.websocket_credential_rewrite,
                            request_body_credential_rewrite: e.request_body_credential_rewrite,
                            allow_uninspected_credentials: e.allow_uninspected_credentials,
                            // Provider credential provenance is derived by the
                            // gateway and cannot be authored in policy YAML.
                            provider_credentialed: false,
                            // Advisor provenance is internal runtime state, not
                            // a user-authored policy schema field.
                            advisor_proposed: false,
                            persisted_queries: e.persisted_queries,
                            graphql_persisted_queries: e
                                .graphql_persisted_queries
                                .into_iter()
                                .map(|(key, op)| {
                                    (
                                        key,
                                        GraphqlOperation {
                                            operation_type: op.operation_type,
                                            operation_name: op.operation_name,
                                            fields: op.fields,
                                        },
                                    )
                                })
                                .collect(),
                            graphql_max_body_bytes: e.graphql_max_body_bytes,
                            credential_signing: e.credential_signing,
                            signing_service: e.signing_service,
                            signing_region: e.signing_region,
                            credential_binding: e.credential_binding.map(|binding| {
                                openshell_core::proto::NetworkCredentialBinding {
                                    provider: binding.provider,
                                }
                            }),
                            json_rpc_max_body_bytes: json_rpc_max_body_bytes(&e.json_rpc, &e.mcp),
                            mcp: mcp_options(&protocol, &e.mcp),
                        }
                    })
                    .collect(),
                binaries: rule
                    .binaries
                    .into_iter()
                    .map(|b| NetworkBinary {
                        path: b.path,
                        ..Default::default()
                    })
                    .collect(),
            };
            (key, proto_rule)
        })
        .collect();

    Ok(SandboxPolicy {
        version: raw.version,
        filesystem: raw.filesystem_policy.map(|fs| FilesystemPolicy {
            include_workdir: fs.include_workdir,
            read_only: fs.read_only,
            read_write: fs.read_write,
        }),
        landlock: raw.landlock.map(|ll| LandlockPolicy {
            compatibility: ll.compatibility,
        }),
        process: raw.process.map(|p| ProcessPolicy {
            run_as_user: p.run_as_user,
            run_as_group: p.run_as_group,
        }),
        network_policies,
        network_middlewares,
    })
}

// ---------------------------------------------------------------------------
// Proto → YAML conversion
// ---------------------------------------------------------------------------

fn from_proto(policy: &SandboxPolicy) -> PolicyFile {
    let filesystem_policy = policy.filesystem.as_ref().map(|fs| FilesystemDef {
        include_workdir: fs.include_workdir,
        read_only: fs.read_only.clone(),
        read_write: fs.read_write.clone(),
    });

    let landlock = policy.landlock.as_ref().map(|ll| LandlockDef {
        compatibility: ll.compatibility.clone(),
    });

    let process = policy.process.as_ref().and_then(|p| {
        if p.run_as_user.is_empty() && p.run_as_group.is_empty() {
            None
        } else {
            Some(ProcessDef {
                run_as_user: p.run_as_user.clone(),
                run_as_group: p.run_as_group.clone(),
            })
        }
    });

    let network_policies = policy
        .network_policies
        .iter()
        .map(|(key, rule)| {
            let yaml_rule = NetworkPolicyRuleDef {
                name: rule.name.clone(),
                endpoints: rule
                    .endpoints
                    .iter()
                    .map(|e| {
                        // Use compact form: if ports has exactly 1 element,
                        // emit port (scalar). If >1, emit ports (array).
                        // Proto uses u32; YAML uses u16. Clamp at boundary.
                        let clamp = |v: u32| -> u16 { v.min(65535) as u16 };
                        let (port, ports) = if e.ports.len() > 1 {
                            (0, e.ports.iter().map(|&p| clamp(p)).collect())
                        } else {
                            (clamp(e.ports.first().copied().unwrap_or(e.port)), vec![])
                        };
                        let protocol = e.protocol.clone();
                        let mcp_allow_all_known_mcp_methods = !is_mcp_protocol(&protocol)
                            || e.mcp
                                .as_ref()
                                .and_then(|options| options.allow_all_known_mcp_methods)
                                .unwrap_or(false);
                        let rules = e
                            .rules
                            .iter()
                            .map(|r| L7RuleDef {
                                allow: allow_proto_to_def(
                                    &protocol,
                                    r.allow.clone().unwrap_or_default(),
                                    mcp_allow_all_known_mcp_methods,
                                ),
                            })
                            .collect();
                        let deny_rules: Vec<L7DenyRuleDef> = e
                            .deny_rules
                            .iter()
                            .map(|d| {
                                deny_proto_to_def(&protocol, d, mcp_allow_all_known_mcp_methods)
                            })
                            .collect();
                        let (json_rpc, mcp) = if is_mcp_protocol(&protocol) {
                            (
                                None,
                                mcp_config_from_proto(e.json_rpc_max_body_bytes, e.mcp.as_ref()),
                            )
                        } else {
                            (json_rpc_config_from_proto(e.json_rpc_max_body_bytes), None)
                        };
                        NetworkEndpointDef {
                            host: e.host.clone(),
                            path: e.path.clone(),
                            port,
                            ports,
                            protocol,
                            tls: e.tls.clone(),
                            enforcement: e.enforcement.clone(),
                            access: e.access.clone(),
                            rules,
                            allowed_ips: e.allowed_ips.clone(),
                            deny_rules,
                            allow_encoded_slash: e.allow_encoded_slash,
                            websocket_credential_rewrite: e.websocket_credential_rewrite,
                            request_body_credential_rewrite: e.request_body_credential_rewrite,
                            allow_uninspected_credentials: e.allow_uninspected_credentials,
                            persisted_queries: e.persisted_queries.clone(),
                            graphql_persisted_queries: e
                                .graphql_persisted_queries
                                .iter()
                                .map(|(key, op)| {
                                    (
                                        key.clone(),
                                        GraphqlOperationDef {
                                            operation_type: op.operation_type.clone(),
                                            operation_name: op.operation_name.clone(),
                                            fields: op.fields.clone(),
                                        },
                                    )
                                })
                                .collect(),
                            graphql_max_body_bytes: e.graphql_max_body_bytes,
                            credential_signing: e.credential_signing.clone(),
                            signing_service: e.signing_service.clone(),
                            signing_region: e.signing_region.clone(),
                            credential_binding: e.credential_binding.as_ref().map(|binding| {
                                NetworkCredentialBindingDef {
                                    provider: binding.provider.clone(),
                                }
                            }),
                            json_rpc,
                            mcp,
                        }
                    })
                    .collect(),
                binaries: rule
                    .binaries
                    .iter()
                    .map(|b| NetworkBinaryDef {
                        path: b.path.clone(),
                        harness: false,
                    })
                    .collect(),
            };
            (key.clone(), yaml_rule)
        })
        .collect();

    let network_middlewares = middleware::from_proto(&policy.network_middlewares);

    PolicyFile {
        version: policy.version,
        filesystem_policy,
        landlock,
        process,
        network_policies,
        network_middlewares,
    }
}

// ---------------------------------------------------------------------------
// Sandbox UID/GID constants
// ---------------------------------------------------------------------------

/// Minimum accepted UID/GID for sandbox workload identity.
///
/// Linux reserves only identity `0` for root. Non-root system identities are
/// valid workload identities when selected explicitly by the operator.
pub const MIN_SANDBOX_UID: u32 = 1;

/// Maximum accepted UID/GID for sandbox workload identity.
///
/// `u32::MAX` represents an invalid or unchanged identity in Linux APIs and
/// POSIX ACLs, so the largest usable workload identity is one less.
pub const MAX_SANDBOX_UID: u32 = u32::MAX - 1;

/// Minimum UID for the Kubernetes network proxy identity.
///
/// The proxy UID is exempt from the pod egress fence, so it remains in a
/// dedicated infrastructure range even though workload identities may use
/// non-root system IDs.
pub const MIN_SANDBOX_PROXY_UID: u32 = 1000;

/// The literal string value accepted as a valid sandbox user/group name.
const SANDBOX_NAME: &str = "sandbox";

/// Validate whether a process identity field value is acceptable.
///
/// Accepts either the literal `"sandbox"` or a numeric UID/GID parsed as
/// `u32` within the range `[MIN_SANDBOX_UID, MAX_SANDBOX_UID]`.
///
/// Rejects:
/// - The empty string (represents an omitted policy field)
/// - UID/GID 0 (root)
/// - `u32::MAX`, the invalid identity sentinel
/// - Non-numeric strings other than `"sandbox"` (e.g. `"root"`, `"nobody"`)
pub fn is_valid_sandbox_identity(value: &str) -> bool {
    if value == SANDBOX_NAME {
        return true;
    }
    value
        .parse::<u32>()
        .is_ok_and(|uid| (MIN_SANDBOX_UID..=MAX_SANDBOX_UID).contains(&uid))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Validate raw authored values and their relationship to the endpoint protocol
// before conversion. Keeping validation outside the Serde error wrapper makes
// actionable MCP diagnostics the top-level user-facing error.
fn validate_mcp_version_schema(policy: &PolicyFile) -> Result<()> {
    for (policy_key, rule) in &policy.network_policies {
        let policy_name = if rule.name.is_empty() {
            policy_key
        } else {
            &rule.name
        };
        for endpoint in &rule.endpoints {
            if is_mcp_protocol(&endpoint.protocol) {
                let context = format!(
                    "network policy '{policy_name}': MCP endpoint '{}'",
                    endpoint.host
                );
                validate_authored_mcp_versions(
                    endpoint
                        .mcp
                        .as_ref()
                        .and_then(|config| config.versions.as_deref()),
                    &context,
                )?;
            } else if endpoint.mcp.is_some() {
                return Err(miette::miette!(
                    "network policy '{policy_name}': non-MCP endpoint '{}' cannot configure mcp options",
                    endpoint.host
                ));
            }
        }
    }
    Ok(())
}

/// Parse a sandbox policy from a YAML string.
pub fn parse_sandbox_policy(yaml: &str) -> Result<SandboxPolicy> {
    let raw: PolicyFile = serde_yml::from_str(yaml)
        .into_diagnostic()
        .wrap_err("failed to parse sandbox policy YAML")?;
    validate_mcp_version_schema(&raw)?;
    to_proto(raw)
}

/// Serialize a proto sandbox policy to a YAML string.
///
/// This is the inverse of [`parse_sandbox_policy`] — the output uses the
/// canonical YAML field names (e.g. `filesystem_policy`, not `filesystem`)
/// and is round-trippable through `parse_sandbox_policy`.
pub fn serialize_sandbox_policy(policy: &SandboxPolicy) -> Result<String> {
    let canonical = validate_and_canonicalize_mcp_policy_schema(policy.clone())
        .map_err(|error| miette::miette!("cannot serialize invalid sandbox policy: {error}"))?;
    let yaml_repr = from_proto(&canonical);
    serde_yml::to_string(&yaml_repr)
        .into_diagnostic()
        .wrap_err("failed to serialize policy to YAML")
}

/// Convert a proto sandbox policy into the canonical policy JSON representation.
///
/// The shape mirrors the YAML schema used by [`serialize_sandbox_policy`], so
/// automation can use the same documented field names in either format.
pub fn sandbox_policy_to_json_value(policy: &SandboxPolicy) -> Result<serde_json::Value> {
    let canonical = validate_and_canonicalize_mcp_policy_schema(policy.clone())
        .map_err(|error| miette::miette!("cannot serialize invalid sandbox policy: {error}"))?;
    let json_repr = from_proto(&canonical);
    serde_json::to_value(&json_repr)
        .into_diagnostic()
        .wrap_err("failed to serialize policy to JSON")
}

/// Serialize a proto sandbox policy to a pretty-printed JSON string.
pub fn serialize_sandbox_policy_json(policy: &SandboxPolicy) -> Result<String> {
    let json_repr = sandbox_policy_to_json_value(policy)?;
    serde_json::to_string_pretty(&json_repr)
        .into_diagnostic()
        .wrap_err("failed to serialize policy to JSON")
}

/// Load a sandbox policy from an explicit source.
///
/// Resolution order:
/// 1. `cli_path` argument (e.g. from a `--policy` flag)
/// 2. `OPENSHELL_SANDBOX_POLICY` environment variable
///
/// Returns `Ok(None)` when no policy source is configured, allowing the
/// caller to omit the policy and let the server / sandbox apply its own
/// default.
pub fn load_sandbox_policy(cli_path: Option<&str>) -> Result<Option<SandboxPolicy>> {
    let contents = if let Some(p) = cli_path {
        let path = Path::new(p);
        std::fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read sandbox policy from {}", path.display()))?
    } else if let Ok(policy_path) = std::env::var("OPENSHELL_SANDBOX_POLICY") {
        let path = Path::new(&policy_path);
        std::fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read sandbox policy from {}", path.display()))?
    } else {
        return Ok(None);
    };
    parse_sandbox_policy(&contents).map(Some)
}

/// Well-known path where a sandbox container image can ship a policy YAML file.
///
/// When the gateway provides no policy at sandbox creation time, the sandbox
/// supervisor probes this path before falling back to the restrictive default.
pub use openshell_core::container_paths::CONTAINER_POLICY_PATH;

/// Legacy path used before the navigator → openshell rename.
///
/// Existing community sandbox images still ship their policy at this path.
/// The sandbox supervisor tries [`CONTAINER_POLICY_PATH`] first, then falls
/// back to this legacy path for backward compatibility.
pub const LEGACY_CONTAINER_POLICY_PATH: &str = "/etc/navigator/policy.yaml";

/// Return a restrictive default policy suitable for sandboxes that have no
/// explicit policy configured.
///
/// This policy grants filesystem access to standard system paths, leaves
/// process identity selection to the compute runtime, enables Landlock in
/// best-effort mode, and **blocks all network access** (no network policies,
/// no inference routing).
pub fn restrictive_default_policy() -> SandboxPolicy {
    SandboxPolicy {
        version: 1,
        filesystem: Some(FilesystemPolicy {
            include_workdir: true,
            read_only: vec![
                "/usr".into(),
                "/lib".into(),
                "/proc".into(),
                "/dev/urandom".into(),
                "/app".into(),
                "/etc".into(),
                "/var/log".into(),
            ],
            read_write: vec!["/tmp".into(), "/dev/null".into()],
        }),
        landlock: Some(LandlockPolicy {
            compatibility: "best_effort".into(),
        }),
        process: None,
        network_policies: HashMap::new(),
        network_middlewares: HashMap::default(),
    }
}

/// Fill omitted process identity fields with the legacy `sandbox` defaults.
///
/// Docker and Podman preserve omission so their supervisors can fall back to
/// OCI `Config.User`. Other drivers call this before validation and
/// persistence to retain the existing public policy representation.
pub fn ensure_sandbox_process_identity(policy: &mut SandboxPolicy) {
    let process = policy.process.get_or_insert_with(ProcessPolicy::default);
    if process.run_as_user.is_empty() {
        process.run_as_user = "sandbox".into();
    }
    if process.run_as_group.is_empty() {
        process.run_as_group = "sandbox".into();
    }
}

// ---------------------------------------------------------------------------
// Policy safety validation
// ---------------------------------------------------------------------------

/// Maximum number of filesystem paths (`read_only` + `read_write` combined).
const MAX_FILESYSTEM_PATHS: usize = 256;

/// Maximum length of any single filesystem path string.
const MAX_PATH_LENGTH: usize = 4096;

/// A safety violation found in a sandbox policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyViolation {
    /// An explicit `run_as_user` or `run_as_group` is unsafe.
    InvalidProcessIdentity { field: &'static str, value: String },
    /// A filesystem path contains `..` components.
    PathTraversal { path: String },
    /// A filesystem path is not absolute (does not start with `/`).
    RelativePath { path: String },
    /// A read-write filesystem path is overly broad (e.g. `/`).
    OverlyBroadPath { path: String },
    /// A filesystem path exceeds the maximum allowed length.
    FieldTooLong { path: String, length: usize },
    /// Too many filesystem paths in the policy.
    TooManyPaths { count: usize },
    /// A network endpoint uses a TLD wildcard (e.g. `*.com`).
    TldWildcard { policy_name: String, host: String },
    /// A network endpoint has no hostname.
    MissingEndpointHost { policy_name: String },
    /// An explicit TCP endpoint has no DNS hostname.
    MissingTcpEndpointHost { policy_name: String },
    /// An explicit TCP endpoint uses an IP literal instead of a DNS hostname.
    TcpEndpointIpLiteral { policy_name: String, host: String },
    /// An explicit TCP endpoint has a hostname that policy DNS cannot resolve.
    InvalidTcpEndpointHost {
        policy_name: String,
        host: String,
        reason: String,
    },
    /// A network endpoint has no effective destination port.
    MissingEndpointPort { policy_name: String, host: String },
    /// A network endpoint contains a port outside the TCP/UDP range.
    InvalidEndpointPort {
        policy_name: String,
        host: String,
        port: u32,
    },
    /// A network endpoint uses a wildcard shape that does not match runtime semantics.
    InvalidHostWildcard { policy_name: String, host: String },
    /// `credential_signing` is set but `signing_service` is missing.
    MissingSigningService { policy_name: String, host: String },
    /// `credential_signing` has an unrecognized value.
    UnknownCredentialSigning {
        policy_name: String,
        host: String,
        value: String,
    },
    /// `credential_signing` and `request_body_credential_rewrite` are both set.
    CredentialSigningWithBodyRewrite { policy_name: String, host: String },
    /// An endpoint contains a deterministic L7 semantic error.
    InvalidL7Endpoint {
        policy_name: String,
        endpoint_index: usize,
        reason: String,
    },
    /// A middleware configuration is structurally invalid.
    InvalidMiddlewareConfig { name: String, reason: String },
    /// Too many middleware configurations are attached to one policy.
    TooManyMiddlewareConfigs { count: usize },
    /// Two middleware configurations use the same execution order.
    DuplicateMiddlewareOrder {
        order: i32,
        first_name: String,
        second_name: String,
    },
    /// Too many include and exclude patterns are attached to one middleware.
    TooManyMiddlewareSelectorPatterns { name: String, count: usize },
    /// A middleware selector conflicts with an endpoint that skips TLS inspection.
    MiddlewareTlsSkipConflict {
        middleware_name: String,
        policy_name: String,
        host: String,
    },
    /// An effective MCP endpoint has not materialized a protocol revision.
    MissingMcpVersions { policy_name: String, host: String },
    /// A non-MCP endpoint carries MCP-only configuration.
    McpOptionsOnNonMcpEndpoint {
        policy_name: String,
        host: String,
        protocol: String,
    },
    /// An MCP revision allowlist contains an unsupported exact identifier.
    UnsupportedMcpVersion {
        policy_name: String,
        host: String,
        version: String,
    },
    /// An MCP revision allowlist contains the same identifier more than once.
    DuplicateMcpVersion {
        policy_name: String,
        host: String,
        version: String,
    },
}

impl fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProcessIdentity { field, value } => {
                write!(
                    f,
                    "{field} must be 'sandbox' or a numeric UID/GID in range [{MIN_SANDBOX_UID}, {MAX_SANDBOX_UID}], got '{value}'"
                )
            }
            Self::PathTraversal { path } => {
                write!(f, "path contains '..' traversal component: {path}")
            }
            Self::RelativePath { path } => {
                write!(f, "path must be absolute (start with '/'): {path}")
            }
            Self::OverlyBroadPath { path } => {
                write!(f, "read-write path is overly broad: {path}")
            }
            Self::FieldTooLong { path, length } => {
                write!(
                    f,
                    "path exceeds maximum length ({length} > {MAX_PATH_LENGTH}): {path}"
                )
            }
            Self::TooManyPaths { count } => {
                write!(
                    f,
                    "too many filesystem paths ({count} > {MAX_FILESYSTEM_PATHS})"
                )
            }
            Self::TldWildcard { policy_name, host } => {
                write!(
                    f,
                    "network policy '{policy_name}': TLD wildcard '{host}' is not allowed; \
                     use subdomain wildcards like '*.example.com' instead"
                )
            }
            Self::MissingEndpointHost { policy_name } => {
                write!(
                    f,
                    "network policy '{policy_name}': endpoint host must not be empty unless allowed_ips constrains a non-TCP proxy endpoint"
                )
            }
            Self::MissingTcpEndpointHost { policy_name } => {
                write!(
                    f,
                    "network policy '{policy_name}': protocol tcp requires a DNS hostname; hostless allowed_ips endpoints are supported only by the forward proxy"
                )
            }
            Self::TcpEndpointIpLiteral { policy_name, host } => {
                write!(
                    f,
                    "network policy '{policy_name}': protocol tcp endpoint '{host}' must use a DNS hostname, not an IP literal; direct IP connections bypass policy DNS and are blocked"
                )
            }
            Self::InvalidTcpEndpointHost {
                policy_name,
                host,
                reason,
            } => {
                write!(
                    f,
                    "network policy '{policy_name}': protocol tcp endpoint has invalid DNS host selector '{host}': {reason}"
                )
            }
            Self::MissingEndpointPort { policy_name, host } => {
                write!(
                    f,
                    "network policy '{policy_name}': endpoint '{host}' must declare at least one port"
                )
            }
            Self::InvalidEndpointPort {
                policy_name,
                host,
                port,
            } => {
                write!(
                    f,
                    "network policy '{policy_name}': endpoint '{host}' has invalid port {port}; expected 1..=65535"
                )
            }
            Self::InvalidHostWildcard { policy_name, host } => {
                write!(
                    f,
                    "network policy '{policy_name}': invalid host wildcard '{host}'; \
                     middle DNS label wildcards must be the entire label '*' and recursive '**' \
                     is only allowed as the entire first label"
                )
            }
            Self::MissingSigningService { policy_name, host } => {
                write!(
                    f,
                    "network policy '{policy_name}': endpoint '{host}' has credential_signing \
                     set but signing_service is empty"
                )
            }
            Self::UnknownCredentialSigning {
                policy_name,
                host,
                value,
            } => {
                write!(
                    f,
                    "network policy '{policy_name}': endpoint '{host}' has unrecognized \
                     credential_signing value '{value}' (expected sigv4, sigv4:body, or sigv4:no_body)"
                )
            }
            Self::CredentialSigningWithBodyRewrite { policy_name, host } => {
                write!(
                    f,
                    "network policy '{policy_name}': endpoint '{host}' has both credential_signing \
                     and request_body_credential_rewrite set; these options are mutually exclusive"
                )
            }
            Self::InvalidL7Endpoint {
                policy_name,
                endpoint_index,
                reason,
            } => write!(
                f,
                "network policy '{policy_name}': endpoint {endpoint_index} has invalid L7 configuration: {reason}"
            ),
            Self::InvalidMiddlewareConfig { name, reason } => {
                write!(f, "middleware config '{name}' is invalid: {reason}")
            }
            Self::TooManyMiddlewareConfigs { count } => {
                write!(
                    f,
                    "too many middleware configs ({count} > {})",
                    openshell_core::middleware::MAX_MIDDLEWARE_CONFIGS
                )
            }
            Self::DuplicateMiddlewareOrder {
                order,
                first_name,
                second_name,
            } => {
                write!(
                    f,
                    "middleware configs '{first_name}' and '{second_name}' use duplicate order {order}"
                )
            }
            Self::TooManyMiddlewareSelectorPatterns { name, count } => {
                write!(
                    f,
                    "middleware config '{name}' has too many selector patterns ({count} > {})",
                    openshell_core::middleware::MAX_MIDDLEWARE_SELECTOR_PATTERNS
                )
            }
            Self::MiddlewareTlsSkipConflict {
                middleware_name,
                policy_name,
                host,
            } => {
                write!(
                    f,
                    "middleware config '{middleware_name}' selects network policy \
                     '{policy_name}' tls: skip endpoint '{host}'"
                )
            }
            Self::MissingMcpVersions { policy_name, host } => {
                write!(
                    f,
                    "network policy '{policy_name}': MCP endpoint '{host}' has no materialized protocol version"
                )
            }
            Self::McpOptionsOnNonMcpEndpoint {
                policy_name,
                host,
                protocol,
            } => {
                write!(
                    f,
                    "network policy '{policy_name}': endpoint '{host}' uses protocol '{protocol}' and cannot configure mcp options"
                )
            }
            Self::UnsupportedMcpVersion {
                policy_name,
                host,
                version,
            } => {
                write!(
                    f,
                    "network policy '{policy_name}': MCP endpoint '{host}' has unsupported protocol version '{version}'; {MCP_VERSION_REMEDIATION}"
                )
            }
            Self::DuplicateMcpVersion {
                policy_name,
                host,
                version,
            } => {
                write!(
                    f,
                    "network policy '{policy_name}': MCP endpoint '{host}' repeats protocol version '{version}'"
                )
            }
        }
    }
}

/// Validate that a sandbox policy does not contain unsafe content.
///
/// Returns `Ok(())` if the policy is safe, or `Err(violations)` listing all
/// safety violations found. Callers decide how to handle violations (hard
/// error vs. logged warning).
///
/// Checks performed:
/// - Explicit `run_as_user` / `run_as_group` fields must be safe identities
/// - Filesystem paths must be absolute (start with `/`)
/// - Filesystem paths must not contain `..` components
/// - Read-write paths must not be overly broad (just `/`)
/// - Individual path lengths must not exceed [`MAX_PATH_LENGTH`]
/// - Total path count must not exceed [`MAX_FILESYSTEM_PATHS`]
/// - Network endpoint hosts must not use TLD wildcards (e.g. `*.com`)
/// - Middleware names, implementations, failure modes, selectors, and built-in
///   configurations must be valid
/// - Middleware selectors must not match endpoints that skip TLS inspection
/// - MCP endpoints must carry a nonempty, unique allowlist of exact supported
///   revisions
/// - Non-MCP endpoints must not carry MCP options
pub fn validate_sandbox_policy(
    policy: &SandboxPolicy,
) -> std::result::Result<(), Vec<PolicyViolation>> {
    validate_sandbox_policy_with_mcp_presence(policy, McpVersionPresence::RequireMaterialized)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum McpVersionPresence {
    RequireMaterialized,
    AllowDefaultable,
}

fn validate_sandbox_policy_with_mcp_presence(
    policy: &SandboxPolicy,
    mcp_version_presence: McpVersionPresence,
) -> std::result::Result<(), Vec<PolicyViolation>> {
    let mut violations = Vec::new();

    // Omitted process identity fields are resolved by the compute runtime.
    // Explicit fields must be "sandbox" or a numeric UID/GID within the
    // acceptable sandbox range.
    if let Some(ref process) = policy.process {
        if !process.run_as_user.is_empty() && !is_valid_sandbox_identity(&process.run_as_user) {
            violations.push(PolicyViolation::InvalidProcessIdentity {
                field: "run_as_user",
                value: process.run_as_user.clone(),
            });
        }
        if !process.run_as_group.is_empty() && !is_valid_sandbox_identity(&process.run_as_group) {
            violations.push(PolicyViolation::InvalidProcessIdentity {
                field: "run_as_group",
                value: process.run_as_group.clone(),
            });
        }
    }

    // Check filesystem paths
    if let Some(ref fs) = policy.filesystem {
        let total_paths = fs.read_only.len() + fs.read_write.len();
        if total_paths > MAX_FILESYSTEM_PATHS {
            violations.push(PolicyViolation::TooManyPaths { count: total_paths });
        }

        for path_str in fs.read_only.iter().chain(fs.read_write.iter()) {
            if path_str.len() > MAX_PATH_LENGTH {
                violations.push(PolicyViolation::FieldTooLong {
                    path: truncate_for_display(path_str),
                    length: path_str.len(),
                });
                continue;
            }

            let path = Path::new(path_str);

            if !path.has_root() {
                violations.push(PolicyViolation::RelativePath {
                    path: path_str.clone(),
                });
            }

            if path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                violations.push(PolicyViolation::PathTraversal {
                    path: path_str.clone(),
                });
            }
        }

        // Only reject "/" as read-write (overly broad)
        for path_str in &fs.read_write {
            let normalized = path_str.trim_end_matches('/');
            if normalized.is_empty() {
                // Path is "/" or "///" etc.
                violations.push(PolicyViolation::OverlyBroadPath {
                    path: path_str.clone(),
                });
            }
        }
    }

    // Protobuf maps do not preserve iteration order. Sort rule keys so callers
    // receive stable validation errors for equivalent policy inputs.
    let mut network_policies: Vec<_> = policy.network_policies.iter().collect();
    network_policies.sort_by_key(|(name, _)| *name);

    // Check network policy endpoint hosts for TLD wildcards.
    for (key, rule) in network_policies {
        let name = if rule.name.is_empty() {
            key.clone()
        } else {
            rule.name.clone()
        };
        for (endpoint_index, ep) in rule.endpoints.iter().enumerate() {
            let explicit_tcp = l7_validate::is_explicit_tcp_protocol(&ep.protocol);
            if ep.host.trim().is_empty() && explicit_tcp {
                violations.push(PolicyViolation::MissingTcpEndpointHost {
                    policy_name: name.clone(),
                });
            } else if ep.host.trim().is_empty() && ep.allowed_ips.is_empty() {
                violations.push(PolicyViolation::MissingEndpointHost {
                    policy_name: name.clone(),
                });
            } else if explicit_tcp {
                if ep.host.parse::<IpAddr>().is_ok() {
                    violations.push(PolicyViolation::TcpEndpointIpLiteral {
                        policy_name: name.clone(),
                        host: ep.host.clone(),
                    });
                } else if let Err(reason) = validate_tcp_dns_host_selector(&ep.host) {
                    violations.push(PolicyViolation::InvalidTcpEndpointHost {
                        policy_name: name.clone(),
                        host: ep.host.clone(),
                        reason,
                    });
                }
            }
            let effective_ports: Vec<u32> = if ep.ports.is_empty() {
                (ep.port != 0).then_some(ep.port).into_iter().collect()
            } else {
                ep.ports.clone()
            };
            if effective_ports.is_empty() {
                violations.push(PolicyViolation::MissingEndpointPort {
                    policy_name: name.clone(),
                    host: ep.host.clone(),
                });
            }
            for port in effective_ports {
                if !(1..=u16::MAX.into()).contains(&port) {
                    violations.push(PolicyViolation::InvalidEndpointPort {
                        policy_name: name.clone(),
                        host: ep.host.clone(),
                        port,
                    });
                }
            }
            if ep.host.contains('*') && (ep.host.starts_with("*.") || ep.host.starts_with("**.")) {
                let label_count = ep.host.split('.').count();
                if label_count <= 2 {
                    violations.push(PolicyViolation::TldWildcard {
                        policy_name: name.clone(),
                        host: ep.host.clone(),
                    });
                }
            }
            if host_wildcard_shape_invalid(&ep.host) {
                violations.push(PolicyViolation::InvalidHostWildcard {
                    policy_name: name.clone(),
                    host: ep.host.clone(),
                });
            }
            if !ep.credential_signing.is_empty()
                && !matches!(
                    ep.credential_signing.as_str(),
                    "sigv4" | "sigv4:body" | "sigv4:no_body"
                )
            {
                violations.push(PolicyViolation::UnknownCredentialSigning {
                    policy_name: name.clone(),
                    host: ep.host.clone(),
                    value: ep.credential_signing.clone(),
                });
            }
            if !ep.credential_signing.is_empty() && ep.signing_service.is_empty() {
                violations.push(PolicyViolation::MissingSigningService {
                    policy_name: name.clone(),
                    host: ep.host.clone(),
                });
            }
            if !ep.credential_signing.is_empty() && ep.request_body_credential_rewrite {
                violations.push(PolicyViolation::CredentialSigningWithBodyRewrite {
                    policy_name: name.clone(),
                    host: ep.host.clone(),
                });
            }

            let rules_would_deny_all = !ep.rules.is_empty()
                && ep.rules.iter().all(|rule| {
                    rule.allow.as_ref().is_none_or(|allow| {
                        allow.method.is_empty()
                            && allow.path.is_empty()
                            && allow.command.is_empty()
                            && allow.operation_type.is_empty()
                            && allow.operation_name.is_empty()
                            && allow.fields.is_empty()
                            && allow.params.is_empty()
                    })
                });
            let fields = L7EndpointFields {
                protocol: &ep.protocol,
                access: &ep.access,
                has_rules: !ep.rules.is_empty(),
                has_deny_rules: !ep.deny_rules.is_empty(),
                rules_would_deny_all,
                allow_all_known_mcp_methods: ep
                    .mcp
                    .as_ref()
                    .and_then(|mcp| mcp.allow_all_known_mcp_methods)
                    .unwrap_or(false),
            };
            let mut l7_errors = validate_l7_endpoint_semantics(&fields);
            let mut explicit_tcp_fields = Vec::new();
            if !ep.enforcement.is_empty() {
                explicit_tcp_fields.push("enforcement");
            }
            if !ep.path.is_empty() {
                explicit_tcp_fields.push("path");
            }
            if ep.allow_encoded_slash {
                explicit_tcp_fields.push("allow_encoded_slash");
            }
            if ep.websocket_credential_rewrite {
                explicit_tcp_fields.push("websocket_credential_rewrite");
            }
            if ep.request_body_credential_rewrite {
                explicit_tcp_fields.push("request_body_credential_rewrite");
            }
            if !ep.persisted_queries.is_empty() {
                explicit_tcp_fields.push("persisted_queries");
            }
            if !ep.graphql_persisted_queries.is_empty() {
                explicit_tcp_fields.push("graphql_persisted_queries");
            }
            if ep.graphql_max_body_bytes > 0 {
                explicit_tcp_fields.push("graphql_max_body_bytes");
            }
            if ep.json_rpc_max_body_bytes > 0 {
                explicit_tcp_fields.push("json_rpc_max_body_bytes");
            }
            if ep.mcp.is_some() {
                explicit_tcp_fields.push("mcp");
            }
            l7_errors.extend(validate_explicit_tcp_additional_fields(
                &ep.protocol,
                &explicit_tcp_fields,
            ));
            if !ep.path.is_empty() && !ep.path.starts_with('/') && ep.path != "**" {
                l7_errors.push("path must start with '/' or be '**'".to_string());
            }
            if !ep.persisted_queries.is_empty()
                && !matches!(ep.persisted_queries.as_str(), "deny" | "allow_registered")
            {
                l7_errors.push(format!(
                    "persisted_queries must be 'deny' or 'allow_registered', got '{}'",
                    ep.persisted_queries
                ));
            }
            if ep.protocol == "sql" && ep.enforcement == "enforce" {
                l7_errors.push(
                    "SQL enforcement requires full SQL parsing; use enforcement: audit".to_string(),
                );
            }
            if ep.protocol == "graphql" {
                for (rule_index, rule) in ep.rules.iter().enumerate() {
                    let operation_type = rule
                        .allow
                        .as_ref()
                        .map(|allow| allow.operation_type.as_str())
                        .unwrap_or_default();
                    if !matches!(operation_type, "query" | "mutation" | "subscription") {
                        l7_errors.push(format!(
                            "rules[{rule_index}].allow.operation_type must be query, mutation, or subscription"
                        ));
                    }
                }
                for (rule_index, rule) in ep.deny_rules.iter().enumerate() {
                    if !matches!(
                        rule.operation_type.as_str(),
                        "query" | "mutation" | "subscription"
                    ) {
                        l7_errors.push(format!(
                            "deny_rules[{rule_index}].operation_type must be query, mutation, or subscription"
                        ));
                    }
                }
                for (key, operation) in &ep.graphql_persisted_queries {
                    if !matches!(
                        operation.operation_type.as_str(),
                        "query" | "mutation" | "subscription"
                    ) {
                        l7_errors.push(format!(
                            "graphql_persisted_queries[{key}].operation_type must be query, mutation, or subscription"
                        ));
                    }
                }
            }
            violations.extend(l7_errors.into_iter().map(|reason| {
                PolicyViolation::InvalidL7Endpoint {
                    policy_name: name.clone(),
                    endpoint_index,
                    reason,
                }
            }));
            collect_mcp_endpoint_violations(&name, ep, mcp_version_presence, &mut violations);
        }
    }

    violations.extend(middleware::validate(policy));

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

fn host_wildcard_shape_invalid(host: &str) -> bool {
    if host == "*" || host == "**" {
        return true;
    }
    if !host.contains('*') {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let first_label = labels.first().copied().unwrap_or_default();
    if first_label.contains("**") && first_label != "**" {
        return true;
    }
    labels
        .iter()
        .skip(1)
        .copied()
        .any(|label| label.contains("**") || (label.contains('*') && label != "*"))
}

/// Validate that an explicit-TCP host selector can produce names accepted by
/// policy DNS. Wildcards are replaced with a representative DNS label before
/// parsing because the authored selector itself is not a concrete DNS name.
fn validate_tcp_dns_host_selector(host: &str) -> std::result::Result<(), String> {
    if host.trim() != host {
        return Err("leading or trailing whitespace is not allowed".to_string());
    }
    if host.ends_with('.') {
        return Err("omit the trailing DNS root dot".to_string());
    }

    openshell_core::host_pattern::HostSelector::new(&[host.to_string()], &[])?;

    let representative = host
        .split('.')
        .map(|label| {
            if label == "**" {
                "x".to_string()
            } else {
                label.replace('*', "x")
            }
        })
        .collect::<Vec<_>>()
        .join(".");
    let absolute = format!("{representative}.");
    let parsed = Name::from_ascii(&absolute)
        .map_err(|error| format!("selector cannot represent a valid DNS name: {error}"))?;
    if parsed.is_root() {
        return Err("DNS root is not a destination hostname".to_string());
    }
    Ok(())
}

fn collect_mcp_endpoint_violations(
    policy_name: &str,
    endpoint: &NetworkEndpoint,
    mcp_version_presence: McpVersionPresence,
    violations: &mut Vec<PolicyViolation>,
) {
    if is_mcp_protocol(&endpoint.protocol) {
        let Some(mcp) = endpoint.mcp.as_ref() else {
            if mcp_version_presence == McpVersionPresence::RequireMaterialized {
                violations.push(PolicyViolation::MissingMcpVersions {
                    policy_name: policy_name.to_string(),
                    host: endpoint.host.clone(),
                });
            }
            return;
        };
        if mcp.versions.is_empty() {
            if mcp_version_presence == McpVersionPresence::RequireMaterialized {
                violations.push(PolicyViolation::MissingMcpVersions {
                    policy_name: policy_name.to_string(),
                    host: endpoint.host.clone(),
                });
            }
            return;
        }

        let mut seen = BTreeSet::new();
        for version in &mcp.versions {
            if !seen.insert(version.as_str()) {
                violations.push(PolicyViolation::DuplicateMcpVersion {
                    policy_name: policy_name.to_string(),
                    host: endpoint.host.clone(),
                    version: version.clone(),
                });
            }
            if version.parse::<McpProtocolVersion>().is_err() {
                violations.push(PolicyViolation::UnsupportedMcpVersion {
                    policy_name: policy_name.to_string(),
                    host: endpoint.host.clone(),
                    version: version.clone(),
                });
            }
        }
    } else if endpoint.mcp.is_some() {
        violations.push(PolicyViolation::McpOptionsOnNonMcpEndpoint {
            policy_name: policy_name.to_string(),
            host: endpoint.host.clone(),
            protocol: endpoint.protocol.clone(),
        });
    }
}

fn validate_mcp_policy_schema(
    policy: &SandboxPolicy,
    mcp_version_presence: McpVersionPresence,
) -> std::result::Result<(), Vec<PolicyViolation>> {
    let mut violations = Vec::new();
    let mut network_policies: Vec<_> = policy.network_policies.iter().collect();
    network_policies.sort_by_key(|(name, _)| *name);
    for (key, rule) in network_policies {
        let policy_name = if rule.name.is_empty() {
            key.as_str()
        } else {
            rule.name.as_str()
        };
        for endpoint in &rule.endpoints {
            collect_mcp_endpoint_violations(
                policy_name,
                endpoint,
                mcp_version_presence,
                &mut violations,
            );
        }
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

/// Error returned when a checked policy boundary receives invalid protobuf state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyValidationError {
    violations: Vec<PolicyViolation>,
}

impl PolicyValidationError {
    /// Borrow every violation found while validating the policy.
    #[must_use]
    pub fn violations(&self) -> &[PolicyViolation] {
        &self.violations
    }

    /// Consume the error and return every violation.
    #[must_use]
    pub fn into_violations(self) -> Vec<PolicyViolation> {
        self.violations
    }
}

impl fmt::Display for PolicyValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "sandbox policy validation failed")?;
        for violation in &self.violations {
            write!(formatter, "; {violation}")?;
        }
        Ok(())
    }
}

impl std::error::Error for PolicyValidationError {}

fn validate_and_canonicalize_mcp_policy_schema(
    mut policy: SandboxPolicy,
) -> std::result::Result<SandboxPolicy, PolicyValidationError> {
    validate_mcp_policy_schema(&policy, McpVersionPresence::AllowDefaultable)
        .map_err(|violations| PolicyValidationError { violations })?;
    materialize_default_mcp_versions(&mut policy);
    canonicalize_mcp_version_allowlists(&mut policy);
    validate_mcp_policy_schema(&policy, McpVersionPresence::RequireMaterialized)
        .map_err(|violations| PolicyValidationError { violations })?;
    Ok(policy)
}

/// Validate raw protobuf policy state, then return its canonical representation.
///
/// Validation deliberately runs before default materialization and sorting so
/// malformed, duplicate, or misplaced MCP state cannot be repaired or hidden
/// by normalization. Missing or empty protobuf MCP options select the pinned
/// default because proto3 repeated fields do not preserve authoring presence.
/// Canonicalization only inserts the known pinned default and sorts allowlists
/// that the first pass already proved valid, so it cannot invalidate another
/// policy field. Debug builds recheck that local transformation invariant
/// without imposing a second whole-policy traversal on production read paths.
pub fn validate_and_canonicalize_sandbox_policy(
    mut policy: SandboxPolicy,
) -> std::result::Result<SandboxPolicy, PolicyValidationError> {
    validate_sandbox_policy_with_mcp_presence(&policy, McpVersionPresence::AllowDefaultable)
        .map_err(|violations| PolicyValidationError { violations })?;
    materialize_default_mcp_versions(&mut policy);
    canonicalize_mcp_version_allowlists(&mut policy);
    debug_assert!(
        validate_sandbox_policy(&policy).is_ok(),
        "validated MCP canonicalization must preserve every policy invariant"
    );
    Ok(policy)
}

/// Replace absent protobuf MCP options and empty revision lists with the
/// single pinned policy default while preserving every explicit MCP option.
pub(crate) fn materialize_default_mcp_versions(policy: &mut SandboxPolicy) {
    for rule in policy.network_policies.values_mut() {
        for endpoint in &mut rule.endpoints {
            if !is_mcp_protocol(&endpoint.protocol) {
                continue;
            }
            let options = endpoint.mcp.get_or_insert_default();
            if options.versions.is_empty() {
                options.versions = default_mcp_versions();
            }
        }
    }
}

/// Canonicalize every MCP revision allowlist without deleting invalid input.
///
/// This helper is crate-private because external callers should use
/// [`validate_and_canonicalize_sandbox_policy`] and cannot safely normalize an
/// unvalidated policy in place.
pub(crate) fn canonicalize_mcp_version_allowlists(policy: &mut SandboxPolicy) {
    for rule in policy.network_policies.values_mut() {
        for endpoint in &mut rule.endpoints {
            if let Some(options) = endpoint.mcp.as_mut() {
                canonicalize_mcp_options(options);
            }
        }
    }
}

/// Truncate a string for safe inclusion in error messages.
fn truncate_for_display(s: &str) -> String {
    if s.len() <= 80 {
        s.to_string()
    } else {
        // Back off to a char boundary: slicing at a fixed byte index panics
        // on multi-byte UTF-8 (e.g. non-ASCII characters in policy paths).
        let mut end = 77;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}

/// Normalize a filesystem path by collapsing redundant separators
/// and removing trailing slashes, without requiring the path to exist on disk.
///
/// This is a lexical normalization only — it does NOT resolve symlinks or
/// check the filesystem.
///
/// Re-exported from `openshell-core` so existing call sites
/// (`openshell_policy::normalize_path`) keep resolving.
pub use openshell_core::paths::normalize_path;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_for_display_handles_multi_byte_utf8_without_panicking() {
        // Byte index 77 falls inside the multi-byte 'é'.
        let s = format!("/{}{}", "a".repeat(75), "é".repeat(100));
        let truncated = truncate_for_display(&s);
        assert!(truncated.ends_with("..."));
        assert!(truncated.len() <= 80);
    }

    #[test]
    fn truncate_for_display_leaves_short_strings_untouched() {
        let s = "short path";
        assert_eq!(truncate_for_display(s), s);
    }

    /// Verify that the serialized YAML uses `filesystem_policy` (not
    /// `filesystem`) so it can be fed back to `parse_sandbox_policy`.
    #[test]
    fn serialized_yaml_uses_filesystem_policy_key() {
        let proto = restrictive_default_policy();
        let yaml = serialize_sandbox_policy(&proto).expect("serialize failed");
        assert!(
            yaml.contains("filesystem_policy:"),
            "expected `filesystem_policy:` in YAML output, got:\n{yaml}"
        );
        assert!(
            !yaml.contains("\nfilesystem:"),
            "unexpected bare `filesystem:` key in YAML output"
        );
    }

    /// Verify that JSON serialization uses the same canonical schema keys as YAML.
    #[test]
    fn serialized_json_uses_policy_schema_keys() {
        let proto = parse_sandbox_policy(
            r"
version: 1
network_policies:
  github:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: https
    binaries:
      - path: /usr/bin/curl
",
        )
        .expect("parse failed");
        let json = sandbox_policy_to_json_value(&proto).expect("serialize failed");

        assert_eq!(json["version"], serde_json::json!(1));
        assert!(json.get("filesystem").is_none());
        assert!(json.get("network_policies").is_some());
    }

    /// Verify that `allowed_ips` survives the round-trip.
    #[test]
    fn round_trip_preserves_allowed_ips() {
        let yaml = r#"
version: 1
network_policies:
  internal:
    name: internal
    endpoints:
      - host: db.internal.corp
        port: 5432
        allowed_ips:
          - "10.0.5.0/24"
          - "10.0.6.0/24"
    binaries:
      - path: /usr/bin/curl
"#;
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");

        let ep1 = &proto1.network_policies["internal"].endpoints[0];
        let ep2 = &proto2.network_policies["internal"].endpoints[0];
        assert_eq!(ep1.allowed_ips, ep2.allowed_ips);
        assert_eq!(ep1.allowed_ips, vec!["10.0.5.0/24", "10.0.6.0/24"]);
    }

    /// Verify that the network policy `name` field survives the round-trip.
    #[test]
    fn round_trip_preserves_policy_name() {
        let yaml = r"
version: 1
network_policies:
  my_api:
    name: my-custom-api-name
    endpoints:
      - host: api.example.com
        port: 443
    binaries:
      - path: /usr/bin/curl
";
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        assert_eq!(proto1.network_policies["my_api"].name, "my-custom-api-name");

        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");
        assert_eq!(proto2.network_policies["my_api"].name, "my-custom-api-name");
    }

    #[test]
    fn round_trip_preserves_network_middlewares() {
        let yaml = r#"
version: 1
network_middlewares:
  global-redactor:
    name: Global redactor
    middleware: openshell/regex
    order: 20
    on_error: fail_open
    endpoints:
      include: ["api.example.com", "*.service.test"]
      exclude: ["internal.example.com"]
    config:
      mode: redact
  secondary-redactor:
    middleware: openshell/regex
    endpoints:
      include: ["api.example.com"]
network_policies:
  api:
    name: api
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
    binaries:
      - path: /usr/bin/curl
"#;
        let proto = parse_sandbox_policy(yaml).expect("parse failed");
        assert_eq!(proto.network_middlewares.len(), 2);
        let redactor = &proto.network_middlewares["global-redactor"];
        assert_eq!(redactor.name, "Global redactor");
        assert_eq!(redactor.middleware, "openshell/regex");
        assert_eq!(redactor.order, 20);
        assert_eq!(redactor.on_error, "fail_open");
        assert_eq!(
            redactor.endpoints.as_ref().expect("selector").include,
            vec!["api.example.com", "*.service.test"]
        );
        assert_eq!(
            redactor.endpoints.as_ref().expect("selector").exclude,
            vec!["internal.example.com"]
        );
        assert_eq!(
            redactor
                .config
                .as_ref()
                .expect("config")
                .fields
                .get("mode")
                .and_then(|value| value.kind.as_ref()),
            Some(&prost_types::value::Kind::StringValue("redact".into()))
        );
        assert_eq!(
            proto.network_middlewares["secondary-redactor"].name,
            "secondary-redactor"
        );
        let yaml_out = serialize_sandbox_policy(&proto).expect("serialize failed");
        let reparsed = parse_sandbox_policy(&yaml_out).expect("re-parse failed");
        assert_eq!(reparsed.network_middlewares, proto.network_middlewares);
    }

    #[test]
    fn restrictive_default_has_no_network_policies() {
        let policy = restrictive_default_policy();
        assert!(
            policy.network_policies.is_empty(),
            "restrictive default must block all network"
        );
    }

    #[test]
    fn restrictive_default_has_filesystem_policy() {
        let policy = restrictive_default_policy();
        let fs = policy.filesystem.expect("must have filesystem policy");
        assert!(fs.include_workdir);
        assert!(
            fs.read_only.iter().any(|p| p == "/usr"),
            "read_only should contain /usr"
        );
        assert!(
            !fs.read_write.iter().any(|p| p == "/sandbox"),
            "the workspace should be granted through include_workdir, not a literal /sandbox path"
        );
        assert!(
            fs.read_write.iter().any(|p| p == "/tmp"),
            "read_write should contain /tmp"
        );
    }

    #[test]
    fn restrictive_default_omits_process_identity() {
        let policy = restrictive_default_policy();
        assert!(policy.process.is_none());
    }

    #[test]
    fn restrictive_default_has_landlock() {
        let policy = restrictive_default_policy();
        let ll = policy.landlock.expect("must have landlock policy");
        assert_eq!(ll.compatibility, "best_effort");
    }

    #[test]
    fn restrictive_default_version_is_one() {
        let policy = restrictive_default_policy();
        assert_eq!(policy.version, 1);
    }

    #[test]
    fn parse_minimal_policy_yaml() {
        let yaml = "version: 1\n";
        let policy = parse_sandbox_policy(yaml).expect("should parse");
        assert_eq!(policy.version, 1);
        assert!(policy.network_policies.is_empty());
        assert!(policy.filesystem.is_none());
    }

    #[test]
    fn process_identity_omission_survives_yaml_round_trip() {
        let policy = parse_sandbox_policy("version: 1\nprocess:\n  run_as_user: \"1234\"\n")
            .expect("partial process identity should parse");
        let process = policy.process.as_ref().expect("process section");
        assert_eq!(process.run_as_user, "1234");
        assert!(process.run_as_group.is_empty());
        assert!(validate_sandbox_policy(&policy).is_ok());

        let yaml = serialize_sandbox_policy(&policy).expect("partial identity should serialize");
        assert!(yaml.contains("run_as_user"));
        assert!(!yaml.contains("run_as_group"));
        let reparsed = parse_sandbox_policy(&yaml).expect("round trip should parse");
        assert!(reparsed.process.unwrap().run_as_group.is_empty());
    }

    #[test]
    fn ensure_sandbox_process_identity_fills_each_omitted_field() {
        let cases = [
            (None, None, "sandbox", "sandbox"),
            (Some("1234"), None, "1234", "sandbox"),
            (None, Some("1235"), "sandbox", "1235"),
            (Some("1234"), Some("1235"), "1234", "1235"),
        ];

        for (user, group, expected_user, expected_group) in cases {
            let mut policy = restrictive_default_policy();
            policy.process = Some(ProcessPolicy {
                run_as_user: user.unwrap_or_default().to_string(),
                run_as_group: group.unwrap_or_default().to_string(),
            });

            ensure_sandbox_process_identity(&mut policy);

            let process = policy.process.expect("normalized process policy");
            assert_eq!(process.run_as_user, expected_user);
            assert_eq!(process.run_as_group, expected_group);
        }
    }

    #[test]
    fn parse_policy_with_network_rules() {
        let yaml = r"
version: 1
network_policies:
  test:
    name: test_policy
    endpoints:
      - { host: example.com, port: 443 }
    binaries:
      - { path: /usr/bin/curl }
";
        let policy = parse_sandbox_policy(yaml).expect("should parse");
        assert_eq!(policy.network_policies.len(), 1);
        let rule = &policy.network_policies["test"];
        assert_eq!(rule.name, "test_policy");
        assert_eq!(rule.endpoints.len(), 1);
        assert_eq!(rule.endpoints[0].host, "example.com");
        assert_eq!(rule.endpoints[0].port, 443);
        assert_eq!(rule.binaries.len(), 1);
        assert_eq!(rule.binaries[0].path, "/usr/bin/curl");
    }

    #[test]
    fn parse_l7_query_matchers_and_round_trip() {
        let yaml = r#"
version: 1
network_policies:
  query_test:
    name: query_test
    endpoints:
      - host: api.example.com
        port: 8080
        protocol: rest
        rules:
          - allow:
              method: GET
              path: /download
              query:
                slug: "my-*"
                tag:
                  any: ["foo-*", "bar-*"]
    binaries:
      - path: /usr/bin/curl
"#;
        let proto = parse_sandbox_policy(yaml).expect("parse failed");
        let allow = proto.network_policies["query_test"].endpoints[0].rules[0]
            .allow
            .as_ref()
            .expect("allow");
        assert_eq!(allow.query["slug"].glob, "my-*");
        assert_eq!(allow.query["slug"].any, Vec::<String>::new());
        assert_eq!(allow.query["tag"].any, vec!["foo-*", "bar-*"]);
        assert!(allow.query["tag"].glob.is_empty());

        let yaml_out = serialize_sandbox_policy(&proto).expect("serialize failed");
        let proto_round_trip = parse_sandbox_policy(&yaml_out).expect("re-parse failed");
        let allow_round_trip = proto_round_trip.network_policies["query_test"].endpoints[0].rules
            [0]
        .allow
        .as_ref()
        .expect("allow");
        assert_eq!(allow_round_trip.query["slug"].glob, "my-*");
        assert_eq!(allow_round_trip.query["tag"].any, vec!["foo-*", "bar-*"]);
    }

    #[test]
    fn parse_rejects_unknown_fields() {
        let yaml = "version: 1\nbogus_field: true\n";
        assert!(parse_sandbox_policy(yaml).is_err());
    }

    #[test]
    fn parse_rejects_middleware_attachments_on_network_policies_and_endpoints() {
        let policy_attachment = r"
version: 1
network_policies:
  api:
    middleware: [redact]
    endpoints:
      - host: api.example.com
        port: 443
";
        assert!(parse_sandbox_policy(policy_attachment).is_err());

        let endpoint_attachment = r"
version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
        middleware: [redact]
";
        assert!(parse_sandbox_policy(endpoint_attachment).is_err());
    }

    #[test]
    fn l7_config_stanza_runtime_fields_use_canonical_schema() {
        let fields = l7_config_alias_runtime_fields(
            L7ConfigStanza::Mcp,
            serde_json::json!({
                "versions": ["2025-11-25", "2025-03-26", "2025-06-18"],
                "max_body_bytes": 131_072,
                "strict_tool_names": false,
                "allow_all_known_mcp_methods": true
            }),
        )
        .expect("valid mcp config");

        assert_eq!(
            fields,
            vec![
                ("json_rpc_max_body_bytes", serde_json::json!(131_072)),
                ("mcp_strict_tool_names", serde_json::json!(false)),
                ("mcp_allow_all_known_mcp_methods", serde_json::json!(true)),
            ]
        );

        let runtime_only_fields = l7_config_alias_runtime_fields(
            L7ConfigStanza::Mcp,
            serde_json::json!({"strict_tool_names": false}),
        )
        .expect("runtime alias parsing does not select a wire profile yet");
        assert_eq!(
            runtime_only_fields,
            vec![("mcp_strict_tool_names", serde_json::json!(false))]
        );

        let err = l7_config_alias_runtime_fields(
            L7ConfigStanza::JsonRpc,
            serde_json::json!({"on_parse_error": "allow"}),
        )
        .expect_err("unknown JSON-RPC config fields must be rejected");
        assert!(err.to_string().contains("on_parse_error"));
    }

    #[test]
    fn l7_mcp_alias_rejects_invalid_raw_version_authoring() {
        let cases = [
            ("null config", serde_json::Value::Null),
            ("null versions", serde_json::json!({"versions": null})),
            ("empty versions", serde_json::json!({"versions": []})),
            (
                "duplicate revision",
                serde_json::json!({"versions": ["2025-11-25", "2025-11-25"]}),
            ),
            (
                "unsupported revision",
                serde_json::json!({"versions": ["2025-11-26"]}),
            ),
            (
                "leading whitespace",
                serde_json::json!({"versions": [" 2025-11-25"]}),
            ),
            (
                "trailing whitespace",
                serde_json::json!({"versions": ["2025-11-25 "]}),
            ),
        ];

        for (case, value) in cases {
            let error = l7_config_alias_runtime_fields(L7ConfigStanza::Mcp, value)
                .expect_err("invalid raw MCP version authoring must fail");
            assert!(
                error.to_string().contains("invalid mcp config"),
                "{case} returned an unexpected diagnostic: {error}"
            );
        }
    }

    const MCP_VERSIONS: [&str; 3] = ["2025-03-26", "2025-06-18", "2025-11-25"];

    fn mcp_version_options(versions: &[&str]) -> McpOptions {
        McpOptions {
            versions: versions.iter().map(ToString::to_string).collect(),
            ..Default::default()
        }
    }

    fn mcp_version_policy(protocol: &str, mcp: Option<McpOptions>) -> SandboxPolicy {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "versioned".to_string(),
            NetworkPolicyRule {
                name: "versioned".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "mcp.example.com".to_string(),
                    port: 443,
                    protocol: protocol.to_string(),
                    rules: vec![L7Rule {
                        allow: Some(L7Allow {
                            method: "tools/list".to_string(),
                            ..Default::default()
                        }),
                    }],
                    mcp,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        policy
    }

    fn mcp_version_endpoint_yaml(protocol: &str, mcp_body: Option<&str>) -> String {
        let mcp = mcp_body.map_or_else(String::new, |body| format!("        mcp:\n{body}"));
        format!(
            "version: 1\nnetwork_policies:\n  versioned:\n    endpoints:\n      - host: mcp.example.com\n        port: 443\n        protocol: {protocol}\n{mcp}"
        )
    }

    #[test]
    fn mcp_version_profile_fixture_round_trips_in_canonical_order() {
        let fixture = include_str!("../testdata/mcp-version-profiles.yaml");
        let policy = parse_sandbox_policy(fixture).expect("fixed MCP profile fixture must parse");
        let endpoint = &policy.network_policies["versioned_mcp"].endpoints[0];
        assert_eq!(
            endpoint.mcp.as_ref().expect("MCP options").versions,
            MCP_VERSIONS
        );

        let canonical =
            serialize_sandbox_policy(&policy).expect("MCP profile fixture must serialize");
        let positions =
            MCP_VERSIONS.map(|version| canonical.find(version).expect("serialized revision"));
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(
            parse_sandbox_policy(&canonical).expect("canonical fixture must parse"),
            policy
        );
    }

    #[test]
    fn omitted_authored_mcp_versions_materialize_the_pinned_default() {
        let omitted_stanza = parse_sandbox_policy(&mcp_version_endpoint_yaml("mcp", None))
            .expect("an omitted MCP stanza must select the default revision");
        let explicit_default = parse_sandbox_policy(&mcp_version_endpoint_yaml(
            "mcp",
            Some("          versions: [\"2025-11-25\"]\n"),
        ))
        .expect("the explicit default revision must parse");
        assert_eq!(omitted_stanza, explicit_default);

        let omitted_versions = parse_sandbox_policy(&mcp_version_endpoint_yaml(
            "mcp",
            Some("          strict_tool_names: false\n"),
        ))
        .expect("an omitted versions key must select the default revision");
        let options = omitted_versions.network_policies["versioned"].endpoints[0]
            .mcp
            .as_ref()
            .expect("MCP options must be materialized");
        assert_eq!(options.versions, default_mcp_versions());
        assert_eq!(options.strict_tool_names, Some(false));

        let yaml = serialize_sandbox_policy(&omitted_stanza)
            .expect("the materialized default must serialize");
        assert!(yaml.contains("versions:"));
        assert!(yaml.contains(DEFAULT_MCP_PROTOCOL_VERSION.as_str()));
    }

    #[test]
    fn pinned_mcp_default_does_not_expand_to_the_supported_registry() {
        assert_eq!(default_mcp_versions().len(), 1);
        assert_eq!(
            default_mcp_versions(),
            [DEFAULT_MCP_PROTOCOL_VERSION.as_str()]
        );
        assert!(McpProtocolVersion::ALL.len() > default_mcp_versions().len());
    }

    #[test]
    fn mcp_version_yaml_rejects_explicit_empty_duplicate_unknown_and_misplaced_values() {
        let cases = [
            ("null allowlist", "mcp", Some("          versions: null\n")),
            ("empty allowlist", "mcp", Some("          versions: []\n")),
            (
                "empty identifier",
                "mcp",
                Some("          versions: [\"\"]\n"),
            ),
            (
                "duplicate revision",
                "mcp",
                Some("          versions: [\"2025-03-26\", \"2025-03-26\"]\n"),
            ),
            (
                "unsupported revision",
                "mcp",
                Some("          versions: [\"2025-03-27\"]\n"),
            ),
            (
                "unsupported alias",
                "mcp",
                Some("          versions: [\"latest\"]\n"),
            ),
            (
                "moving draft alias",
                "mcp",
                Some("          versions: [\"draft\"]\n"),
            ),
            (
                "leading whitespace",
                "mcp",
                Some("          versions: [\" 2025-03-26\"]\n"),
            ),
            (
                "trailing whitespace",
                "mcp",
                Some("          versions: [\"2025-03-26 \"]\n"),
            ),
            (
                "non-MCP placement",
                "json-rpc",
                Some("          versions: [\"2025-03-26\"]\n"),
            ),
        ];

        for (case, protocol, body) in cases {
            let yaml = mcp_version_endpoint_yaml(protocol, body);
            assert!(parse_sandbox_policy(&yaml).is_err(), "{case} must fail");
        }

        let mut null_mcp = mcp_version_endpoint_yaml("mcp", None);
        null_mcp.push_str("        mcp: null\n");
        assert!(
            parse_sandbox_policy(&null_mcp).is_err(),
            "an explicit null MCP stanza must fail"
        );
    }

    #[test]
    fn mcp_version_proto_validation_preserves_raw_invalid_values() {
        let cases = [
            ("empty identifier", vec![""]),
            ("unsupported revision", vec!["2025-03-27"]),
            ("unsupported alias", vec!["latest"]),
            ("moving draft alias", vec!["draft"]),
            ("leading whitespace", vec![" 2025-03-26"]),
            ("trailing whitespace", vec!["2025-03-26 "]),
        ];
        for (case, versions) in cases {
            let policy = mcp_version_policy("mcp", Some(mcp_version_options(&versions)));
            let violations = validate_sandbox_policy(&policy).expect_err(case);
            assert!(violations.iter().any(|violation| matches!(
                violation,
                PolicyViolation::UnsupportedMcpVersion { version, .. }
                    if version == versions[0]
            )));
        }

        let duplicate = mcp_version_policy(
            "mcp",
            Some(mcp_version_options(&["2025-03-26", "2025-03-26"])),
        );
        assert!(
            validate_sandbox_policy(&duplicate)
                .expect_err("duplicate must fail")
                .iter()
                .any(|violation| matches!(
                    violation,
                    PolicyViolation::DuplicateMcpVersion { version, .. }
                        if version == "2025-03-26"
                ))
        );

        for misplaced in [McpOptions::default(), mcp_version_options(&["2025-03-26"])] {
            let policy = mcp_version_policy("rest", Some(misplaced));
            assert!(matches!(
                validate_sandbox_policy(&policy)
                    .expect_err("misplaced options must fail")
                    .as_slice(),
                [PolicyViolation::McpOptionsOnNonMcpEndpoint { .. }]
            ));
        }
    }

    #[test]
    fn protobuf_missing_and_empty_mcp_options_materialize_the_same_default() {
        let missing = mcp_version_policy("mcp", None);
        let empty = mcp_version_policy("mcp", Some(McpOptions::default()));
        let explicit = mcp_version_policy(
            "mcp",
            Some(mcp_version_options(
                &[DEFAULT_MCP_PROTOCOL_VERSION.as_str()],
            )),
        );

        for raw in [&missing, &empty] {
            assert!(matches!(
                validate_sandbox_policy(raw)
                    .expect_err("borrowed validation requires canonical effective state")
                    .as_slice(),
                [PolicyViolation::MissingMcpVersions { .. }]
            ));
            let canonical = validate_and_canonicalize_sandbox_policy(raw.clone())
                .expect("checked protobuf boundaries must materialize the default");
            assert_eq!(canonical, explicit);
            assert_eq!(
                canonical.network_policies["versioned"].endpoints[0]
                    .mcp
                    .as_ref()
                    .expect("MCP options must be materialized")
                    .versions,
                default_mcp_versions()
            );
        }

        assert_eq!(
            serialize_sandbox_policy(&missing).expect("missing options must serialize"),
            serialize_sandbox_policy(&explicit).expect("explicit options must serialize")
        );
        let defaulted_json =
            sandbox_policy_to_json_value(&empty).expect("empty options must serialize");
        assert_eq!(
            defaulted_json,
            sandbox_policy_to_json_value(&explicit).expect("explicit options must serialize")
        );
        assert_eq!(
            defaulted_json["network_policies"]["versioned"]["endpoints"][0]["mcp"]["versions"],
            serde_json::json!([DEFAULT_MCP_PROTOCOL_VERSION.as_str()])
        );
    }

    #[test]
    fn unsupported_mcp_version_errors_explain_the_explicit_l4_escape_hatch() {
        const DEFAULT_REMEDIATION: &str = "omit mcp.versions to use the pinned default revision";
        const L4_REMEDIATION: &str =
            "omit protocol and mcp for deliberate uninspected L4 passthrough";

        let yaml = mcp_version_endpoint_yaml("mcp", Some("          versions: [\"draft\"]\n"));
        let authored_diagnostic = parse_sandbox_policy(&yaml)
            .expect_err("moving draft aliases must fail closed")
            .to_string();
        assert!(
            authored_diagnostic.contains(DEFAULT_REMEDIATION)
                && authored_diagnostic.contains(L4_REMEDIATION),
            "rendered diagnostic omitted remediation choices: {authored_diagnostic}"
        );

        let policy = mcp_version_policy("mcp", Some(mcp_version_options(&["2026-07-28"])));
        let violations = validate_sandbox_policy(&policy)
            .expect_err("unsupported protobuf revisions must fail closed");
        assert!(violations.iter().map(ToString::to_string).any(|message| {
            message.contains(DEFAULT_REMEDIATION) && message.contains(L4_REMEDIATION)
        }));
    }

    #[test]
    fn mcp_version_canonicalization_preserves_invalid_and_duplicate_entries() {
        let mut policy = mcp_version_policy(
            "mcp",
            Some(mcp_version_options(&[
                "unknown-z",
                "2025-11-25",
                "2025-03-26",
                "2025-03-26",
                "unknown-a",
            ])),
        );

        canonicalize_mcp_version_allowlists(&mut policy);

        assert_eq!(
            policy.network_policies["versioned"].endpoints[0]
                .mcp
                .as_ref()
                .expect("MCP options")
                .versions,
            [
                "2025-03-26",
                "2025-03-26",
                "2025-11-25",
                "unknown-a",
                "unknown-z",
            ]
        );
        let violations = validate_sandbox_policy(&policy)
            .expect_err("normalization must not repair invalid input");
        assert!(
            violations
                .iter()
                .any(|violation| matches!(violation, PolicyViolation::DuplicateMcpVersion { .. }))
        );
        assert!(
            violations.iter().any(|violation| matches!(
                violation,
                PolicyViolation::UnsupportedMcpVersion { .. }
            ))
        );
    }

    #[test]
    fn canonical_serializers_reject_invalid_mcp_policy_before_conversion() {
        let invalid = [
            mcp_version_policy(
                "mcp",
                Some(mcp_version_options(&["2025-03-26", "2025-03-26"])),
            ),
            mcp_version_policy("mcp", Some(mcp_version_options(&["latest"]))),
            mcp_version_policy("mcp", Some(mcp_version_options(&["2025-03-26 "]))),
            mcp_version_policy("rest", Some(McpOptions::default())),
            mcp_version_policy("json-rpc", Some(mcp_version_options(&["2025-03-26"]))),
        ];

        for policy in invalid {
            assert!(serialize_sandbox_policy(&policy).is_err());
            assert!(sandbox_policy_to_json_value(&policy).is_err());
            assert!(serialize_sandbox_policy_json(&policy).is_err());
        }
    }

    #[test]
    fn canonical_serializers_do_not_enforce_unrelated_mutation_safety_rules() {
        let mut policy = mcp_version_policy(
            "mcp",
            Some(mcp_version_options(&["2025-11-25", "2025-03-26"])),
        );
        policy.process = Some(ProcessPolicy {
            run_as_user: "root".to_string(),
            run_as_group: "sandbox".to_string(),
        });
        assert!(validate_sandbox_policy(&policy).is_err());

        let yaml = serialize_sandbox_policy(&policy)
            .expect("serialization must remain available for policy inspection");
        let first = yaml.find("2025-03-26").expect("first version");
        let second = yaml.find("2025-11-25").expect("second version");
        assert!(first < second);
        assert!(sandbox_policy_to_json_value(&policy).is_ok());
    }

    #[test]
    fn mcp_version_checked_canonicalization_returns_valid_semantic_order() {
        let policy = mcp_version_policy(
            "mcp",
            Some(mcp_version_options(&[
                "2025-11-25",
                "2025-03-26",
                "2025-06-18",
            ])),
        );
        let canonical = validate_and_canonicalize_sandbox_policy(policy)
            .expect("valid policy must canonicalize");

        assert_eq!(
            canonical.network_policies["versioned"].endpoints[0]
                .mcp
                .as_ref()
                .expect("MCP options")
                .versions,
            MCP_VERSIONS
        );
        assert!(validate_sandbox_policy(&canonical).is_ok());
    }

    #[test]
    fn container_policy_path_is_expected() {
        assert_eq!(CONTAINER_POLICY_PATH, "/etc/openshell/policy.yaml");
    }

    #[test]
    fn legacy_container_policy_path_is_expected() {
        assert_eq!(LEGACY_CONTAINER_POLICY_PATH, "/etc/navigator/policy.yaml");
    }

    // ---- Policy validation tests ----

    fn middleware_config(implementation: &str) -> openshell_core::proto::NetworkMiddlewareConfig {
        openshell_core::proto::NetworkMiddlewareConfig {
            name: String::new(),
            middleware: implementation.into(),
            order: 0,
            config: None,
            on_error: String::new(),
            endpoints: Some(openshell_core::proto::MiddlewareEndpointSelector {
                include: vec!["api.example.com".into()],
                exclude: Vec::new(),
            }),
        }
    }

    fn add_middleware(
        policy: &mut SandboxPolicy,
        name: &str,
        config: openshell_core::proto::NetworkMiddlewareConfig,
    ) {
        policy.network_middlewares.insert(name.into(), config);
    }

    #[test]
    fn structural_validation_defers_implementation_owned_config() {
        let mut policy = restrictive_default_policy();
        let mut middleware = middleware_config("openshell/future");
        middleware.config = Some(
            openshell_core::proto_struct::json_object_to_struct(
                std::iter::once(("implementation_field".into(), serde_json::json!(42))).collect(),
            )
            .unwrap(),
        );
        policy
            .network_middlewares
            .insert("future".into(), middleware);

        validate_sandbox_policy(&policy)
            .expect("generic policy validation must not select installed implementations");
    }

    #[test]
    fn json_validation_delegates_implementation_owned_config() {
        let data = serde_json::json!({
            "network_middlewares": {
              "future": {
                "middleware": "openshell/future",
                "config": {"implementation_field": 42},
                "endpoints": {"include": ["api.example.com"]}
              }
            }
        });

        let violations =
            validate_network_middleware_json_with_config(&data, |implementation, _config| {
                Err(format!("{implementation} is not installed"))
            })
            .expect("parse middleware policy");
        assert!(violations.iter().any(|violation| matches!(
            violation,
            PolicyViolation::InvalidMiddlewareConfig { name, reason }
                if name == "future" && reason.contains("not installed")
        )));
    }

    #[test]
    fn json_validation_skips_config_callbacks_when_middleware_count_is_invalid() {
        let configs: serde_json::Map<String, serde_json::Value> = (0
            ..=openshell_core::middleware::MAX_MIDDLEWARE_CONFIGS)
            .map(|index| {
                (
                    format!("middleware-{index}"),
                    serde_json::json!({
                        "middleware": "openshell/regex",
                        "endpoints": {"include": ["api.example.com"]}
                    }),
                )
            })
            .collect();
        let data = serde_json::json!({"network_middlewares": configs});
        let calls = std::cell::Cell::new(0usize);

        let violations = validate_network_middleware_json_with_config(&data, |_, _| {
            calls.set(calls.get() + 1);
            Ok(())
        })
        .expect("parse middleware policy");

        assert_eq!(calls.get(), 0, "invalid policy must not invoke services");
        assert!(violations.iter().any(|violation| matches!(
            violation,
            PolicyViolation::TooManyMiddlewareConfigs { count }
                if *count == openshell_core::middleware::MAX_MIDDLEWARE_CONFIGS + 1
        )));
    }

    #[test]
    fn validate_rejects_root_run_as_user() {
        let mut policy = restrictive_default_policy();
        policy.process = Some(ProcessPolicy {
            run_as_user: "root".into(),
            run_as_group: "sandbox".into(),
        });
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(violations.iter().any(|v| matches!(
            v,
            PolicyViolation::InvalidProcessIdentity {
                field: "run_as_user",
                ..
            }
        )));
    }

    #[test]
    fn validate_rejects_uid_zero() {
        let mut policy = restrictive_default_policy();
        policy.process = Some(ProcessPolicy {
            run_as_user: "0".into(),
            run_as_group: "0".into(),
        });
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert_eq!(violations.len(), 2);
    }

    #[test]
    fn validate_rejects_invalid_middleware_control_fields() {
        let cases = [
            (
                "",
                middleware_config("openshell/regex"),
                "name must not be empty",
            ),
            (
                "redactor",
                middleware_config(""),
                "middleware must not be empty",
            ),
            (
                "redactor",
                {
                    let mut middleware = middleware_config("openshell/regex");
                    middleware.on_error = "maybe".into();
                    middleware
                },
                "invalid on_error",
            ),
            (
                "redactor",
                {
                    let mut middleware = middleware_config("openshell/regex");
                    middleware.endpoints = None;
                    middleware
                },
                "endpoint selector is required",
            ),
            (
                "redactor",
                {
                    let mut middleware = middleware_config("openshell/regex");
                    middleware.endpoints.as_mut().unwrap().include.clear();
                    middleware
                },
                "must include at least one host pattern",
            ),
        ];

        for (name, middleware, expected) in cases {
            let mut policy = restrictive_default_policy();
            add_middleware(&mut policy, name, middleware);
            let errors = validate_sandbox_policy(&policy)
                .expect_err("invalid middleware must be rejected")
                .into_iter()
                .map(|violation| violation.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            assert!(
                errors.contains(expected),
                "expected {expected:?} in {errors:?}"
            );
        }
    }

    #[test]
    fn validate_rejects_duplicate_middleware_orders() {
        let mut policy = restrictive_default_policy();
        let mut alpha = middleware_config("openshell/regex");
        alpha.order = 10;
        add_middleware(&mut policy, "alpha", alpha);
        let mut beta = middleware_config("openshell/regex");
        beta.order = 10;
        add_middleware(&mut policy, "beta", beta);

        let violations = validate_sandbox_policy(&policy).expect_err("duplicate order");
        assert!(violations.iter().any(|violation| matches!(
            violation,
            PolicyViolation::DuplicateMiddlewareOrder {
                order: 10,
                first_name,
                second_name,
            } if first_name == "alpha" && second_name == "beta"
        )));
    }

    #[test]
    fn validate_accepts_maximum_middleware_configs() {
        let mut policy = restrictive_default_policy();
        for index in 0..openshell_core::middleware::MAX_MIDDLEWARE_CONFIGS {
            let name = format!("middleware-{index}");
            let mut config = middleware_config("openshell/regex");
            config.order = i32::try_from(index).unwrap();
            add_middleware(&mut policy, &name, config);
        }

        validate_sandbox_policy(&policy).expect("maximum middleware config count");
    }

    #[test]
    fn validate_rejects_middleware_config_over_capacity() {
        let mut policy = restrictive_default_policy();
        for index in 0..=openshell_core::middleware::MAX_MIDDLEWARE_CONFIGS {
            let name = format!("middleware-{index}");
            let mut config = middleware_config("openshell/regex");
            config.order = i32::try_from(index).unwrap();
            add_middleware(&mut policy, &name, config);
        }

        let violations = validate_sandbox_policy(&policy).expect_err("config count over capacity");
        assert!(violations.iter().any(|violation| matches!(
            violation,
            PolicyViolation::TooManyMiddlewareConfigs { count }
                if *count == openshell_core::middleware::MAX_MIDDLEWARE_CONFIGS + 1
        )));
    }

    #[test]
    fn validate_accepts_maximum_middleware_selector_patterns() {
        let mut policy = restrictive_default_policy();
        let mut middleware = middleware_config("openshell/regex");
        let selector = middleware.endpoints.as_mut().expect("selector");
        selector.exclude = vec![
            "excluded.example.com".into();
            openshell_core::middleware::MAX_MIDDLEWARE_SELECTOR_PATTERNS - 1
        ];
        add_middleware(&mut policy, "redactor", middleware);

        validate_sandbox_policy(&policy).expect("maximum selector pattern count");
    }

    #[test]
    fn validate_rejects_middleware_selector_patterns_over_capacity() {
        let mut policy = restrictive_default_policy();
        let mut middleware = middleware_config("openshell/regex");
        let selector = middleware.endpoints.as_mut().expect("selector");
        selector.exclude = vec![
            "excluded.example.com".into();
            openshell_core::middleware::MAX_MIDDLEWARE_SELECTOR_PATTERNS
        ];
        add_middleware(&mut policy, "redactor", middleware);

        let violations =
            validate_sandbox_policy(&policy).expect_err("selector patterns over capacity");
        assert!(violations.iter().any(|violation| matches!(
            violation,
            PolicyViolation::TooManyMiddlewareSelectorPatterns { name, count }
                if name == "redactor"
                    && *count
                        == openshell_core::middleware::MAX_MIDDLEWARE_SELECTOR_PATTERNS + 1
        )));
    }

    #[test]
    fn validate_rejects_malformed_middleware_selector_patterns() {
        let mut policy = restrictive_default_policy();
        let mut middleware = middleware_config("openshell/regex");
        middleware.endpoints.as_mut().unwrap().include = vec!["api[.example.com".into()];
        add_middleware(&mut policy, "redactor", middleware);

        let errors = validate_sandbox_policy(&policy)
            .expect_err("malformed selector")
            .into_iter()
            .map(|violation| violation.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        assert!(errors.contains("invalid host pattern"), "{errors}");
    }

    #[test]
    fn middleware_host_selector_matching_is_case_insensitive() {
        assert!(middleware_host_matches("*.Example.COM", "API.example.com").unwrap());
        assert!(!middleware_host_matches("*.example.com", "example.com").unwrap());
        assert!(!middleware_host_matches("*.example.com", "deep.api.example.com").unwrap());
        assert!(middleware_host_matches("**.example.com", "deep.api.example.com").unwrap());
        assert!(!middleware_host_matches("**.example.com", "example.com").unwrap());
    }

    #[test]
    fn validate_rejects_middleware_selector_matching_tls_skip_endpoint() {
        let mut policy = restrictive_default_policy();
        add_middleware(
            &mut policy,
            "redactor",
            middleware_config("openshell/regex"),
        );
        policy.network_policies.insert(
            "api".into(),
            NetworkPolicyRule {
                name: "api".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "api.example.com".into(),
                    port: 443,
                    tls: "skip".into(),
                    ..Default::default()
                }],
                binaries: Vec::new(),
            },
        );

        let violations = validate_sandbox_policy(&policy).expect_err("tls skip conflict");
        assert!(violations.iter().any(|violation| matches!(
            violation,
            PolicyViolation::MiddlewareTlsSkipConflict {
                middleware_name,
                policy_name,
                host,
            } if middleware_name == "redactor" && policy_name == "api" && host == "api.example.com"
        )));
    }

    #[test]
    fn validate_accepts_fail_open_middleware_selector_matching_tls_skip_endpoint() {
        let mut policy = restrictive_default_policy();
        let mut middleware = middleware_config("openshell/regex");
        middleware.on_error = "fail_open".into();
        add_middleware(&mut policy, "redactor", middleware);
        policy.network_policies.insert(
            "api".into(),
            NetworkPolicyRule {
                name: "api".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "api.example.com".into(),
                    port: 443,
                    tls: "skip".into(),
                    ..Default::default()
                }],
                binaries: Vec::new(),
            },
        );

        validate_sandbox_policy(&policy)
            .expect("fail-open middleware may select uninspectable tls: skip traffic");
    }

    #[test]
    fn validate_rejects_explicit_fail_closed_middleware_on_tls_skip_endpoint() {
        let mut policy = restrictive_default_policy();
        let mut middleware = middleware_config("openshell/regex");
        middleware.on_error = "fail_closed".into();
        add_middleware(&mut policy, "redactor", middleware);
        policy.network_policies.insert(
            "api".into(),
            NetworkPolicyRule {
                name: "api".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "api.example.com".into(),
                    port: 443,
                    tls: "skip".into(),
                    ..Default::default()
                }],
                binaries: Vec::new(),
            },
        );

        let violations = validate_sandbox_policy(&policy).expect_err("tls skip conflict");
        assert!(violations.iter().any(|violation| matches!(
            violation,
            PolicyViolation::MiddlewareTlsSkipConflict { middleware_name, .. }
                if middleware_name == "redactor"
        )));
    }

    #[test]
    fn validate_rejects_concrete_selector_overlapping_tls_skip_wildcard() {
        let mut policy = restrictive_default_policy();
        let mut middleware = middleware_config("openshell/regex");
        middleware.endpoints.as_mut().unwrap().include = vec!["api.example.com".into()];
        add_middleware(&mut policy, "redactor", middleware);
        policy.network_policies.insert(
            "api".into(),
            NetworkPolicyRule {
                name: "api".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "*.example.com".into(),
                    port: 443,
                    tls: "skip".into(),
                    ..Default::default()
                }],
                binaries: Vec::new(),
            },
        );

        let violations = validate_sandbox_policy(&policy).expect_err("tls skip conflict");
        assert!(violations.iter().any(|violation| matches!(
            violation,
            PolicyViolation::MiddlewareTlsSkipConflict {
                middleware_name,
                policy_name,
                host,
            } if middleware_name == "redactor" && policy_name == "api" && host == "*.example.com"
        )));
    }

    #[test]
    fn validate_rejects_non_sandbox_user() {
        let mut policy = restrictive_default_policy();
        policy.process = Some(ProcessPolicy {
            run_as_user: "nobody".into(),
            run_as_group: "nogroup".into(),
        });
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert_eq!(violations.len(), 2);
        assert!(
            violations
                .iter()
                .all(|v| matches!(v, PolicyViolation::InvalidProcessIdentity { .. }))
        );
    }

    #[test]
    fn validate_accepts_sandbox_identity() {
        let policy = restrictive_default_policy();
        assert!(validate_sandbox_policy(&policy).is_ok());
    }

    #[test]
    fn validate_rejects_path_traversal() {
        let mut policy = restrictive_default_policy();
        policy.filesystem = Some(FilesystemPolicy {
            include_workdir: true,
            read_only: vec!["/usr/../etc/shadow".into()],
            read_write: vec!["/tmp".into()],
        });
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::PathTraversal { .. }))
        );
    }

    #[test]
    fn validate_rejects_relative_paths() {
        let mut policy = restrictive_default_policy();
        policy.filesystem = Some(FilesystemPolicy {
            include_workdir: true,
            read_only: vec!["usr/lib".into()],
            read_write: vec!["/tmp".into()],
        });
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::RelativePath { .. }))
        );
    }

    #[test]
    fn validate_rejects_overly_broad_read_write_path() {
        let mut policy = restrictive_default_policy();
        policy.filesystem = Some(FilesystemPolicy {
            include_workdir: true,
            read_only: vec!["/usr".into()],
            read_write: vec!["/".into()],
        });
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::OverlyBroadPath { .. }))
        );
    }

    #[test]
    fn validate_accepts_valid_policy() {
        let policy = restrictive_default_policy();
        assert!(validate_sandbox_policy(&policy).is_ok());
    }

    #[test]
    fn validate_rejects_yaml_tcp_endpoint_without_host_or_port() {
        let policy = parse_sandbox_policy(
            r#"
version: 1
network_policies:
  invalid:
    endpoints:
      - host: ""
        protocol: tcp
"#,
        )
        .expect("policy syntax should parse before semantic validation");

        let violations = validate_sandbox_policy(&policy).expect_err("endpoint is incomplete");
        assert!(violations.iter().any(|violation| matches!(
            violation,
            PolicyViolation::MissingTcpEndpointHost { policy_name } if policy_name == "invalid"
        )));
        assert!(violations.iter().any(|violation| {
            violation.to_string().contains(
                "protocol tcp requires a DNS hostname; hostless allowed_ips endpoints are supported only by the forward proxy",
            )
        }));
        assert!(violations.iter().any(|violation| matches!(
            violation,
            PolicyViolation::MissingEndpointPort { policy_name, .. } if policy_name == "invalid"
        )));
    }

    #[test]
    fn validate_accepts_hostless_allowed_ips_for_non_tcp_proxy_endpoint() {
        let policy = parse_sandbox_policy(
            r"
version: 1
network_policies:
  legacy-proxy:
    endpoints:
      - port: 9443
        allowed_ips:
          - 10.0.5.0/24
",
        )
        .expect("policy syntax should parse before semantic validation");

        validate_sandbox_policy(&policy)
            .expect("hostless allowed_ips remains valid for non-TCP proxy endpoints");
    }

    #[test]
    fn validate_rejects_hostless_allowed_ips_for_explicit_tcp() {
        let policy = parse_sandbox_policy(
            r"
version: 1
network_policies:
  native-tcp:
    endpoints:
      - port: 6379
        protocol: tcp
        allowed_ips:
          - 10.0.5.0/24
",
        )
        .expect("policy syntax should parse before semantic validation");

        let violations =
            validate_sandbox_policy(&policy).expect_err("transparent TCP requires a DNS hostname");
        let violation = violations
            .iter()
            .find(|violation| matches!(violation, PolicyViolation::MissingTcpEndpointHost { .. }))
            .expect("missing TCP hostname violation");
        assert_eq!(
            violation.to_string(),
            "network policy 'native-tcp': protocol tcp requires a DNS hostname; hostless allowed_ips endpoints are supported only by the forward proxy"
        );
    }

    #[test]
    fn validate_rejects_ip_literal_hosts_for_explicit_tcp() {
        for host in ["192.0.2.10", "2001:db8::10"] {
            let mut policy = restrictive_default_policy();
            policy.network_policies.insert(
                "native-tcp".into(),
                NetworkPolicyRule {
                    name: "native-tcp".into(),
                    endpoints: vec![NetworkEndpoint {
                        host: host.into(),
                        port: 6379,
                        protocol: "tcp".into(),
                        ..Default::default()
                    }],
                    binaries: Vec::new(),
                },
            );

            let violations = validate_sandbox_policy(&policy)
                .expect_err("transparent TCP must reject direct IP destinations");
            let violation = violations
                .iter()
                .find(|violation| matches!(violation, PolicyViolation::TcpEndpointIpLiteral { .. }))
                .expect("TCP IP-literal violation");
            assert!(
                violation
                    .to_string()
                    .contains("direct IP connections bypass policy DNS and are blocked"),
                "unexpected diagnostic: {violation}"
            );
        }
    }

    #[test]
    fn validate_rejects_malformed_dns_selectors_for_explicit_tcp() {
        for (host, expected_reason) in [
            (" db.example.com", "leading or trailing whitespace"),
            ("db.example.com.", "omit the trailing DNS root dot"),
            ("db..example.com", "empty DNS labels"),
            ("bad name.example.com", "whitespace"),
            (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com",
                "cannot represent a valid DNS name",
            ),
        ] {
            let mut policy = restrictive_default_policy();
            policy.network_policies.insert(
                "native-tcp".into(),
                NetworkPolicyRule {
                    name: "native-tcp".into(),
                    endpoints: vec![NetworkEndpoint {
                        host: host.into(),
                        port: 6379,
                        protocol: "tcp".into(),
                        ..Default::default()
                    }],
                    binaries: Vec::new(),
                },
            );

            let violations = validate_sandbox_policy(&policy)
                .expect_err("malformed transparent TCP hostname must be rejected");
            let violation = violations
                .iter()
                .find(|violation| {
                    matches!(violation, PolicyViolation::InvalidTcpEndpointHost { .. })
                })
                .expect("invalid TCP hostname violation");
            assert!(
                violation.to_string().contains(expected_reason),
                "expected {expected_reason:?} in diagnostic for {host:?}, got {violation}"
            );
        }
    }

    #[test]
    fn validate_rejects_raw_endpoint_zero_and_out_of_range_ports() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "invalid".into(),
            NetworkPolicyRule {
                name: "invalid".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "database.example.com".into(),
                    ports: vec![0, u32::from(u16::MAX) + 1],
                    protocol: "tcp".into(),
                    ..Default::default()
                }],
                binaries: Vec::new(),
            },
        );

        let violations = validate_sandbox_policy(&policy).expect_err("ports are invalid");
        assert!(violations.iter().any(|violation| matches!(
            violation,
            PolicyViolation::InvalidEndpointPort { port: 0, .. }
        )));
        assert!(violations.iter().any(|violation| matches!(
            violation,
            PolicyViolation::InvalidEndpointPort { port: 65_536, .. }
        )));
    }

    #[test]
    fn validate_rejects_raw_endpoint_without_effective_port() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "invalid".into(),
            NetworkPolicyRule {
                name: "invalid".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "database.example.com".into(),
                    ..Default::default()
                }],
                binaries: Vec::new(),
            },
        );

        let violations = validate_sandbox_policy(&policy).expect_err("port is missing");
        assert!(violations.iter().any(|violation| matches!(
            violation,
            PolicyViolation::MissingEndpointPort { policy_name, host }
                if policy_name == "invalid" && host == "database.example.com"
        )));
    }

    #[test]
    fn validate_accepts_empty_process() {
        let policy = SandboxPolicy {
            version: 1,
            process: None,
            filesystem: None,
            landlock: None,
            network_policies: HashMap::new(),
            network_middlewares: HashMap::default(),
        };
        assert!(validate_sandbox_policy(&policy).is_ok());
    }

    #[test]
    fn validate_accepts_omitted_process_fields() {
        let mut policy = restrictive_default_policy();
        policy.process = Some(ProcessPolicy {
            run_as_user: String::new(),
            run_as_group: String::new(),
        });
        assert!(validate_sandbox_policy(&policy).is_ok());

        policy.process = Some(ProcessPolicy {
            run_as_user: "sandbox".into(),
            run_as_group: String::new(),
        });
        assert!(validate_sandbox_policy(&policy).is_ok());

        policy.process = Some(ProcessPolicy {
            run_as_user: String::new(),
            run_as_group: "1234".into(),
        });
        assert!(validate_sandbox_policy(&policy).is_ok());
    }

    #[test]
    fn validate_rejects_too_many_paths() {
        let mut policy = restrictive_default_policy();
        let many_paths: Vec<String> = (0..300).map(|i| format!("/path/{i}")).collect();
        policy.filesystem = Some(FilesystemPolicy {
            include_workdir: true,
            read_only: many_paths,
            read_write: vec!["/tmp".into()],
        });
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::TooManyPaths { .. }))
        );
    }

    #[test]
    fn validate_rejects_path_too_long() {
        let mut policy = restrictive_default_policy();
        let long_path = format!("/{}", "a".repeat(5000));
        policy.filesystem = Some(FilesystemPolicy {
            include_workdir: true,
            read_only: vec![long_path],
            read_write: vec!["/tmp".into()],
        });
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::FieldTooLong { .. }))
        );
    }

    #[test]
    fn validate_rejects_tld_wildcard() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "bad".into(),
            NetworkPolicyRule {
                name: "bad-rule".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "*.com".into(),
                    port: 443,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::TldWildcard { .. }))
        );
    }

    #[test]
    fn validate_rejects_double_star_tld_wildcard() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "bad".into(),
            NetworkPolicyRule {
                name: "bad-rule".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "**.org".into(),
                    port: 443,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::TldWildcard { .. }))
        );
    }

    #[test]
    fn validate_rejects_all_host_star_wildcards() {
        for host in ["*", "**"] {
            let mut policy = restrictive_default_policy();
            policy.network_policies.insert(
                "bad".into(),
                NetworkPolicyRule {
                    name: "bad-rule".into(),
                    endpoints: vec![NetworkEndpoint {
                        host: host.into(),
                        port: 443,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            );

            let violations = validate_sandbox_policy(&policy).unwrap_err();
            assert!(
                violations
                    .iter()
                    .any(|v| matches!(v, PolicyViolation::InvalidHostWildcard { .. })),
                "expected bare host wildcard {host:?} to be rejected, got {violations:?}"
            );
        }
    }

    #[test]
    fn validate_accepts_subdomain_wildcard() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "ok".into(),
            NetworkPolicyRule {
                name: "ok-rule".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "*.example.com".into(),
                    port: 443,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        assert!(validate_sandbox_policy(&policy).is_ok());
    }

    #[test]
    fn validate_accepts_middle_label_star_wildcard() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "ok".into(),
            NetworkPolicyRule {
                name: "ok-rule".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "*.s3.*.amazonaws.com".into(),
                    port: 443,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        assert!(validate_sandbox_policy(&policy).is_ok());
    }

    #[test]
    fn validate_rejects_partial_middle_label_wildcard() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "bad".into(),
            NetworkPolicyRule {
                name: "bad-rule".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "*.s3.us-*.amazonaws.com".into(),
                    port: 443,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::InvalidHostWildcard { .. }))
        );
    }

    #[test]
    fn validate_accepts_explicit_domain() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "ok".into(),
            NetworkPolicyRule {
                name: "ok-rule".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "example.com".into(),
                    port: 443,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        assert!(validate_sandbox_policy(&policy).is_ok());
    }

    #[test]
    fn validate_rejects_credential_signing_without_signing_service() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "aws".into(),
            NetworkPolicyRule {
                name: "bedrock".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "bedrock-runtime.us-east-1.amazonaws.com".into(),
                    port: 443,
                    credential_signing: "sigv4".into(),
                    signing_service: String::new(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::MissingSigningService { .. }))
        );
    }

    #[test]
    fn validate_accepts_credential_signing_with_signing_service() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "aws".into(),
            NetworkPolicyRule {
                name: "bedrock".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "bedrock-runtime.us-east-1.amazonaws.com".into(),
                    port: 443,
                    credential_signing: "sigv4".into(),
                    signing_service: "bedrock".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        assert!(validate_sandbox_policy(&policy).is_ok());
    }

    #[test]
    fn validate_accepts_sigv4_body_with_signing_service() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "aws".into(),
            NetworkPolicyRule {
                name: "bedrock".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "bedrock-runtime.us-east-1.amazonaws.com".into(),
                    port: 443,
                    credential_signing: "sigv4:body".into(),
                    signing_service: "bedrock".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        assert!(validate_sandbox_policy(&policy).is_ok());
    }

    #[test]
    fn validate_accepts_sigv4_no_body_with_signing_service() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "aws".into(),
            NetworkPolicyRule {
                name: "s3".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "s3.us-east-1.amazonaws.com".into(),
                    port: 443,
                    credential_signing: "sigv4:no_body".into(),
                    signing_service: "s3".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        assert!(validate_sandbox_policy(&policy).is_ok());
    }

    #[test]
    fn validate_rejects_sigv4_no_body_without_signing_service() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "aws".into(),
            NetworkPolicyRule {
                name: "s3".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "s3.us-east-1.amazonaws.com".into(),
                    port: 443,
                    credential_signing: "sigv4:no_body".into(),
                    signing_service: String::new(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::MissingSigningService { .. }))
        );
    }

    #[test]
    fn validate_rejects_unknown_credential_signing() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "aws".into(),
            NetworkPolicyRule {
                name: "test".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "example.amazonaws.com".into(),
                    port: 443,
                    credential_signing: "sigv4_typo".into(),
                    signing_service: "bedrock".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::UnknownCredentialSigning { .. }))
        );
    }

    #[test]
    fn validate_rejects_credential_signing_with_body_rewrite() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "aws".into(),
            NetworkPolicyRule {
                name: "bedrock".into(),
                endpoints: vec![NetworkEndpoint {
                    host: "bedrock-runtime.us-east-1.amazonaws.com".into(),
                    port: 443,
                    credential_signing: "sigv4".into(),
                    signing_service: "bedrock".into(),
                    request_body_credential_rewrite: true,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::CredentialSigningWithBodyRewrite { .. }))
        );
    }

    #[test]
    fn normalize_path_collapses_separators() {
        assert_eq!(normalize_path("/usr//lib"), "/usr/lib");
        assert_eq!(normalize_path("/usr/./lib"), "/usr/lib");
        assert_eq!(normalize_path("/tmp/"), "/tmp");
    }

    #[test]
    fn normalize_path_preserves_parent_dir() {
        // normalize_path preserves ".." — validation catches it separately
        assert_eq!(normalize_path("/usr/../etc"), "/usr/../etc");
    }

    #[test]
    fn policy_violation_display() {
        let v = PolicyViolation::InvalidProcessIdentity {
            field: "run_as_user",
            value: "root".into(),
        };
        let s = format!("{v}");
        assert!(s.contains("root"));
        assert!(s.contains("run_as_user"));
        assert!(s.contains("sandbox"));
    }

    // ---- is_valid_sandbox_identity tests ----

    #[test]
    fn valid_identity_accepts_sandbox() {
        assert!(is_valid_sandbox_identity("sandbox"));
    }

    #[test]
    fn valid_identity_accepts_non_root_numeric_uid() {
        assert!(is_valid_sandbox_identity("1"));
        assert!(is_valid_sandbox_identity("30"));
        assert!(is_valid_sandbox_identity("500"));
        assert!(is_valid_sandbox_identity("999"));
        assert!(is_valid_sandbox_identity("1000"));
        assert!(is_valid_sandbox_identity("50000"));
        assert!(is_valid_sandbox_identity("1000660000"));
    }

    #[test]
    fn valid_identity_accepts_boundary_uids() {
        assert!(is_valid_sandbox_identity(&MIN_SANDBOX_UID.to_string()));
        assert!(is_valid_sandbox_identity(&MAX_SANDBOX_UID.to_string()));
    }

    #[test]
    fn valid_identity_rejects_zero() {
        assert!(!is_valid_sandbox_identity("0"));
    }

    #[test]
    fn valid_identity_rejects_invalid_uid_sentinel() {
        assert!(!is_valid_sandbox_identity(
            &MAX_SANDBOX_UID.saturating_add(1).to_string()
        ));
    }

    #[test]
    fn valid_identity_rejects_non_numeric_names() {
        assert!(!is_valid_sandbox_identity("root"));
        assert!(!is_valid_sandbox_identity("nobody"));
        assert!(!is_valid_sandbox_identity("user"));
    }

    #[test]
    fn valid_identity_rejects_empty_string() {
        assert!(!is_valid_sandbox_identity(""));
    }

    // ---- Policy validation with numeric UIDs ----

    #[test]
    fn validate_accepts_numeric_uid_in_range() {
        let policy = SandboxPolicy {
            version: 1,
            process: Some(ProcessPolicy {
                run_as_user: "1000".into(),
                run_as_group: "5000".into(),
            }),
            filesystem: None,
            landlock: None,
            network_policies: HashMap::new(),
            network_middlewares: HashMap::default(),
        };
        assert!(validate_sandbox_policy(&policy).is_ok());
    }

    #[test]
    fn validate_accepts_boundary_uids() {
        let policy = SandboxPolicy {
            version: 1,
            process: Some(ProcessPolicy {
                run_as_user: MIN_SANDBOX_UID.to_string(),
                run_as_group: MAX_SANDBOX_UID.to_string(),
            }),
            filesystem: None,
            landlock: None,
            network_policies: HashMap::new(),
            network_middlewares: HashMap::default(),
        };
        assert!(validate_sandbox_policy(&policy).is_ok());
    }

    #[test]
    fn validate_accepts_non_root_system_uid() {
        let mut policy = restrictive_default_policy();
        policy.process = Some(ProcessPolicy {
            run_as_user: "500".into(),
            run_as_group: "30".into(),
        });
        assert!(validate_sandbox_policy(&policy).is_ok());
    }

    #[test]
    fn validate_rejects_uid_out_of_range_high() {
        let mut policy = restrictive_default_policy();
        policy.process = Some(ProcessPolicy {
            run_as_user: (MAX_SANDBOX_UID + 1).to_string(),
            run_as_group: "sandbox".into(),
        });
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(violations.iter().any(|v| matches!(
            v,
            PolicyViolation::InvalidProcessIdentity {
                field: "run_as_user",
                ..
            }
        )));
    }

    #[test]
    fn validate_rejects_root_string() {
        let mut policy = restrictive_default_policy();
        policy.process = Some(ProcessPolicy {
            run_as_user: "root".into(),
            run_as_group: "sandbox".into(),
        });
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert!(violations.iter().any(|v| matches!(
            v,
            PolicyViolation::InvalidProcessIdentity {
                field: "run_as_user",
                ..
            }
        )));
    }

    #[test]
    fn validate_rejects_nobody_string() {
        let mut policy = restrictive_default_policy();
        policy.process = Some(ProcessPolicy {
            run_as_user: "nobody".into(),
            run_as_group: "nogroup".into(),
        });
        let violations = validate_sandbox_policy(&policy).unwrap_err();
        assert_eq!(violations.len(), 2);
    }

    #[test]
    fn validate_accepts_mixed_sandbox_name_and_uid() {
        // run_as_user as "sandbox" name, run_as_group as numeric UID
        let policy = SandboxPolicy {
            version: 1,
            process: Some(ProcessPolicy {
                run_as_user: "sandbox".into(),
                run_as_group: "1000".into(),
            }),
            filesystem: None,
            landlock: None,
            network_policies: HashMap::new(),
            network_middlewares: HashMap::default(),
        };
        assert!(validate_sandbox_policy(&policy).is_ok());
    }

    #[test]
    fn policy_violation_display_includes_range() {
        let v = PolicyViolation::InvalidProcessIdentity {
            field: "run_as_user",
            value: "root".into(),
        };
        let s = format!("{v}");
        assert!(s.contains("sandbox"));
        assert!(s.contains(&MIN_SANDBOX_UID.to_string()));
        assert!(s.contains(&MAX_SANDBOX_UID.to_string()));
        assert!(s.contains("root"));
    }

    // ---- Multi-port and host wildcard tests ----

    #[test]
    fn parse_ports_array() {
        let yaml = r"
version: 1
network_policies:
  test:
    name: test
    endpoints:
      - { host: api.example.com, ports: [80, 443] }
    binaries:
      - { path: /usr/bin/curl }
";
        let policy = parse_sandbox_policy(yaml).expect("should parse");
        let ep = &policy.network_policies["test"].endpoints[0];
        assert_eq!(ep.ports, vec![80, 443]);
        // port should be set to first element for backwards compat
        assert_eq!(ep.port, 80);
    }

    #[test]
    fn parse_single_port_normalized_to_ports() {
        let yaml = r"
version: 1
network_policies:
  test:
    name: test
    endpoints:
      - { host: api.example.com, port: 443 }
    binaries:
      - { path: /usr/bin/curl }
";
        let policy = parse_sandbox_policy(yaml).expect("should parse");
        let ep = &policy.network_policies["test"].endpoints[0];
        assert_eq!(ep.ports, vec![443]);
        assert_eq!(ep.port, 443);
    }

    #[test]
    fn round_trip_preserves_endpoint_path() {
        let yaml = r#"
version: 1
network_policies:
  test:
    name: test
    endpoints:
      - host: api.example.com
        port: 443
        path: "/graphql"
        protocol: graphql
        rules:
          - allow:
              operation_type: query
    binaries:
      - { path: /usr/bin/curl }
"#;
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");

        let ep1 = &proto1.network_policies["test"].endpoints[0];
        let ep2 = &proto2.network_policies["test"].endpoints[0];
        assert_eq!(ep1.path, "/graphql");
        assert_eq!(ep1.path, ep2.path);
    }

    #[test]
    fn round_trip_preserves_endpoint_credential_binding() {
        let yaml = r"
version: 1
network_policies:
  gcp_storage:
    endpoints:
      - host: storage.googleapis.com
        port: 443
        protocol: rest
        credential_binding:
          provider: work-gcp
";

        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        let endpoint = &proto1.network_policies["gcp_storage"].endpoints[0];
        assert_eq!(
            endpoint
                .credential_binding
                .as_ref()
                .map(|binding| binding.provider.as_str()),
            Some("work-gcp")
        );

        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");
        assert_eq!(proto1, proto2);
        assert!(yaml_out.contains("credential_binding:"));
        assert!(yaml_out.contains("provider: work-gcp"));
    }

    #[test]
    fn round_trip_preserves_multi_port() {
        let yaml = r"
version: 1
network_policies:
  test:
    name: test
    endpoints:
      - host: api.example.com
        ports:
          - 80
          - 443
    binaries:
      - { path: /usr/bin/curl }
";
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");

        let ep1 = &proto1.network_policies["test"].endpoints[0];
        let ep2 = &proto2.network_policies["test"].endpoints[0];
        assert_eq!(ep1.ports, ep2.ports);
        assert_eq!(ep1.ports, vec![80, 443]);
    }

    #[test]
    fn serialize_single_port_uses_compact_form() {
        let yaml = r"
version: 1
network_policies:
  test:
    name: test
    endpoints:
      - { host: api.example.com, port: 443 }
    binaries:
      - { path: /usr/bin/curl }
";
        let proto = parse_sandbox_policy(yaml).expect("parse failed");
        let yaml_out = serialize_sandbox_policy(&proto).expect("serialize failed");
        // Should use compact `port: 443` form, not `ports: [443]`
        assert!(
            yaml_out.contains("port: 443"),
            "Single port should serialize as compact form, got:\n{yaml_out}"
        );
        assert!(
            !yaml_out.contains("ports:"),
            "Single port should not produce ports array, got:\n{yaml_out}"
        );
    }

    #[test]
    fn parse_wildcard_host() {
        let yaml = r#"
version: 1
network_policies:
  test:
    name: test
    endpoints:
      - { host: "*.example.com", port: 443 }
    binaries:
      - { path: /usr/bin/curl }
"#;
        let policy = parse_sandbox_policy(yaml).expect("should parse");
        let ep = &policy.network_policies["test"].endpoints[0];
        assert_eq!(ep.host, "*.example.com");
    }

    #[test]
    fn round_trip_preserves_wildcard_host() {
        let yaml = r#"
version: 1
network_policies:
  test:
    name: test
    endpoints:
      - host: "*.example.com"
        port: 443
    binaries:
      - { path: /usr/bin/curl }
"#;
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");
        assert_eq!(
            proto1.network_policies["test"].endpoints[0].host,
            proto2.network_policies["test"].endpoints[0].host
        );
    }

    #[test]
    fn parse_deny_rules_from_yaml() {
        let yaml = r#"
version: 1
network_policies:
  github:
    name: github
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        access: read-write
        deny_rules:
          - method: POST
            path: "/repos/*/pulls/*/reviews"
          - method: PUT
            path: "/repos/*/branches/*/protection"
    binaries:
      - path: /usr/bin/curl
"#;
        let proto = parse_sandbox_policy(yaml).expect("parse failed");
        let ep = &proto.network_policies["github"].endpoints[0];
        assert_eq!(ep.deny_rules.len(), 2);
        assert_eq!(ep.deny_rules[0].method, "POST");
        assert_eq!(ep.deny_rules[0].path, "/repos/*/pulls/*/reviews");
        assert_eq!(ep.deny_rules[1].method, "PUT");
        assert_eq!(ep.deny_rules[1].path, "/repos/*/branches/*/protection");
    }

    #[test]
    fn round_trip_preserves_deny_rules() {
        let yaml = r#"
version: 1
network_policies:
  github:
    name: github
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        access: full
        deny_rules:
          - method: POST
            path: "/repos/*/pulls/*/reviews"
          - method: DELETE
            path: "/repos/*/branches/*/protection"
            query:
              force: "true"
    binaries:
      - path: /usr/bin/curl
"#;
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");

        let ep1 = &proto1.network_policies["github"].endpoints[0];
        let ep2 = &proto2.network_policies["github"].endpoints[0];
        assert_eq!(ep1.deny_rules.len(), ep2.deny_rules.len());
        assert_eq!(ep2.deny_rules[0].method, "POST");
        assert_eq!(ep2.deny_rules[0].path, "/repos/*/pulls/*/reviews");
        assert_eq!(ep2.deny_rules[1].method, "DELETE");
        assert_eq!(ep2.deny_rules[1].query["force"].glob, "true");
    }

    #[test]
    fn parse_deny_rules_with_query_any() {
        let yaml = r#"
version: 1
network_policies:
  test:
    name: test
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        access: full
        deny_rules:
          - method: POST
            path: /action
            query:
              type:
                any: ["admin-*", "root-*"]
    binaries:
      - path: /usr/bin/curl
"#;
        let proto = parse_sandbox_policy(yaml).expect("parse failed");
        let deny = &proto.network_policies["test"].endpoints[0].deny_rules[0];
        assert_eq!(deny.query["type"].any, vec!["admin-*", "root-*"]);
    }

    #[test]
    fn round_trip_preserves_graphql_policy_fields() {
        let yaml = r"
version: 1
network_policies:
  github_graphql:
    name: github_graphql
    endpoints:
      - host: api.github.com
        port: 443
        protocol: graphql
        enforcement: enforce
        persisted_queries: allow_registered
        graphql_max_body_bytes: 131072
        graphql_persisted_queries:
          abc123:
            operation_type: query
            operation_name: Viewer
            fields: [viewer]
        rules:
          - allow:
              operation_type: query
              fields: [viewer, repository]
          - allow:
              operation_type: mutation
              operation_name: Issue*
              fields: [createIssue]
        deny_rules:
          - operation_type: mutation
            fields: [deleteRepository]
    binaries:
      - path: /usr/bin/curl
";
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");

        let ep = &proto2.network_policies["github_graphql"].endpoints[0];
        assert_eq!(ep.protocol, "graphql");
        assert_eq!(ep.persisted_queries, "allow_registered");
        assert_eq!(ep.graphql_max_body_bytes, 131_072);
        assert_eq!(
            ep.graphql_persisted_queries["abc123"].operation_type,
            "query"
        );
        assert_eq!(ep.rules[0].allow.as_ref().unwrap().operation_type, "query");
        assert_eq!(ep.rules[1].allow.as_ref().unwrap().operation_name, "Issue*");
        assert_eq!(ep.deny_rules[0].operation_type, "mutation");
        assert_eq!(ep.deny_rules[0].fields, vec!["deleteRepository"]);
    }

    #[test]
    fn round_trip_preserves_json_rpc_max_body_bytes() {
        let yaml = r"
version: 1
network_policies:
  jsonrpc_api:
    name: jsonrpc_api
    endpoints:
      - host: jsonrpc.example.com
        port: 443
        protocol: json-rpc
        enforcement: enforce
        json_rpc:
          max_body_bytes: 131072
        rules:
          - allow:
              method: initialize
    binaries:
      - path: /usr/bin/curl
";
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");

        let ep = &proto2.network_policies["jsonrpc_api"].endpoints[0];
        assert_eq!(ep.protocol, "json-rpc");
        assert_eq!(ep.json_rpc_max_body_bytes, 131_072);
    }

    #[test]
    fn parse_mcp_rules_to_runtime_fields() {
        let yaml = r"
version: 1
network_policies:
  mcp:
    name: mcp
    endpoints:
      - host: mcp.example.com
        port: 443
        path: /mcp
        protocol: mcp
        enforcement: enforce
        mcp:
          versions: [2025-03-26]
          max_body_bytes: 131072
          strict_tool_names: false
        rules:
          - allow:
              method: initialize
          - allow:
              method: tools/list
          - allow:
              method: tools/call
              tool:
                any: [search_web, list_tools]
        deny_rules:
          - method: tools/call
            tool: send_email
    binaries:
      - path: /usr/bin/curl
";
        let proto = parse_sandbox_policy(yaml).expect("parse failed");
        let ep = &proto.network_policies["mcp"].endpoints[0];

        assert_eq!(ep.protocol, "mcp");
        assert_eq!(ep.json_rpc_max_body_bytes, 131_072);
        assert_eq!(
            ep.mcp
                .as_ref()
                .and_then(|options| options.strict_tool_names),
            Some(false)
        );
        assert_eq!(ep.rules.len(), 3);
        assert_eq!(ep.rules[2].allow.as_ref().unwrap().method, "tools/call");
        assert_eq!(
            ep.rules[2].allow.as_ref().unwrap().params["name"].any,
            vec!["search_web".to_string(), "list_tools".to_string()]
        );
        assert_eq!(ep.deny_rules.len(), 1);
        assert_eq!(ep.deny_rules[0].method, "tools/call");
        assert_eq!(ep.deny_rules[0].params["name"].glob, "send_email");
    }

    #[test]
    fn round_trip_mcp_policy_serializes_mcp_expression() {
        let yaml = r"
version: 1
network_policies:
  mcp:
    name: mcp
    endpoints:
      - host: mcp.example.com
        port: 443
        protocol: mcp
        mcp:
          versions: [2025-03-26]
          max_body_bytes: 131072
          strict_tool_names: false
        rules:
          - allow:
              method: tools/call
              tool: search_web
        deny_rules:
          - method: tools/call
            tool:
              any: [send_email, delete_resource]
    binaries:
      - path: /usr/bin/curl
";
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");

        assert!(yaml_out.contains("protocol: mcp"));
        assert!(yaml_out.contains("method: tools/call"));
        assert!(yaml_out.contains("tool: search_web"));
        assert!(yaml_out.contains("any:"));
        assert!(yaml_out.contains("- send_email"));
        assert!(yaml_out.contains("- delete_resource"));
        assert!(yaml_out.contains("deny_rules:"));
        assert!(!yaml_out.contains("arguments:"));
        assert!(yaml_out.contains("mcp:"));
        assert!(yaml_out.contains("strict_tool_names: false"));
        assert_eq!(proto1, proto2);
    }

    #[test]
    fn parse_rejects_unsupported_json_rpc_config_fields() {
        let yaml = r"
version: 1
network_policies:
  jsonrpc_api:
    endpoints:
      - host: jsonrpc.example.com
        port: 443
        protocol: json-rpc
        json_rpc:
          max_body_bytes: 131072
          on_parse_error: deny
          batch_policy: all
        access: full
    binaries:
      - path: /usr/bin/curl
";

        assert!(
            parse_sandbox_policy(yaml).is_err(),
            "unsupported json_rpc fields must not be silently accepted"
        );
    }

    #[test]
    fn round_trip_preserves_websocket_credential_rewrite() {
        let yaml = r"
version: 1
network_policies:
  discord_gateway:
    name: discord_gateway
    endpoints:
      - host: gateway.example.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
        websocket_credential_rewrite: true
    binaries:
      - path: /usr/bin/node
";
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");

        let ep = &proto2.network_policies["discord_gateway"].endpoints[0];
        assert_eq!(ep.protocol, "rest");
        assert!(ep.websocket_credential_rewrite);
        assert!(yaml_out.contains("websocket_credential_rewrite: true"));
    }

    #[test]
    fn round_trip_preserves_request_body_credential_rewrite() {
        let yaml = r"
version: 1
network_policies:
  slack_api:
    name: slack_api
    endpoints:
      - host: slack.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-write
        request_body_credential_rewrite: true
    binaries:
      - path: /usr/bin/node
";
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");

        let ep = &proto2.network_policies["slack_api"].endpoints[0];
        assert_eq!(ep.protocol, "rest");
        assert!(ep.request_body_credential_rewrite);
        assert!(yaml_out.contains("request_body_credential_rewrite: true"));
    }

    #[test]
    fn round_trip_preserves_allow_uninspected_credentials() {
        let yaml = r"
version: 1
network_policies:
  vendor_api:
    endpoints:
      - host: api.vendor.example
        port: 443
        tls: skip
        allow_uninspected_credentials: true
";
        let proto1 = parse_sandbox_policy(yaml).expect("parse failed");
        let yaml_out = serialize_sandbox_policy(&proto1).expect("serialize failed");
        let proto2 = parse_sandbox_policy(&yaml_out).expect("re-parse failed");

        let ep = &proto2.network_policies["vendor_api"].endpoints[0];
        assert!(ep.allow_uninspected_credentials);
        assert!(
            !ep.provider_credentialed,
            "provider provenance must not be authorable from policy YAML"
        );
        assert!(yaml_out.contains("allow_uninspected_credentials: true"));
        assert!(!yaml_out.contains("provider_credentialed"));
    }

    #[test]
    fn websocket_credential_rewrite_defaults_false() {
        let yaml = r"
version: 1
network_policies:
  gateway:
    endpoints:
      - host: gateway.example.com
        port: 443
        protocol: rest
        access: full
    binaries:
      - path: /usr/bin/node
";
        let proto = parse_sandbox_policy(yaml).expect("parse failed");
        let ep = &proto.network_policies["gateway"].endpoints[0];
        assert!(!ep.websocket_credential_rewrite);
        assert!(!ep.request_body_credential_rewrite);
        assert!(!ep.allow_uninspected_credentials);
        assert!(!ep.provider_credentialed);
    }

    #[test]
    fn parse_rejects_unknown_fields_in_deny_rule() {
        let yaml = r"
version: 1
network_policies:
  test:
    endpoints:
      - host: example.com
        port: 443
        deny_rules:
          - method: POST
            path: /foo
            bogus: true
";
        assert!(parse_sandbox_policy(yaml).is_err());
    }

    #[test]
    fn rejects_port_above_65535() {
        let yaml = r"
version: 1
network_policies:
  test:
    endpoints:
      - host: example.com
        port: 70000
";
        assert!(
            parse_sandbox_policy(yaml).is_err(),
            "port >65535 should fail to parse"
        );
    }
}
