// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Parsed request metadata and policy configuration, independent of transport.

use crate::policy_types::{
    AccessSetting, EndpointConfig, EndpointProtocol, EnforcementSetting, TlsSetting,
};
use openshell_core::mcp::McpProtocolVersion;
pub use openshell_core::policy_l7::L7Protocol;
use openshell_core::policy_l7::{
    L7EndpointFields, validate_endpoint_modes, validate_explicit_tcp_additional_fields,
    validate_l7_endpoint_semantics,
};
pub mod graphql;
pub mod jsonrpc;
pub mod websocket;
/// TLS handling mode for proxy connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsMode {
    /// Auto-detect TLS by peeking the first bytes. If TLS is detected,
    /// terminate it transparently. This is the default for all endpoints.
    #[default]
    Auto,
    /// Explicit opt-out: raw tunnel with no TLS termination and no credential
    /// injection. Use for client-cert mTLS to upstream or non-standard protocols.
    Skip,
}

/// Credential signing mode for proxy-side request signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CredentialSigning {
    #[default]
    None,
    /// Auto-detect: include body in signature when Content-Length is present,
    /// skip body when Transfer-Encoding is chunked or body is absent.
    SigV4,
    /// Always include body in signature (buffer body, compute SHA-256 hash).
    SigV4Body,
    /// Never include body in signature (use UNSIGNED-PAYLOAD, stream through).
    SigV4NoBody,
}

impl CredentialSigning {
    pub fn is_sigv4(&self) -> bool {
        matches!(self, Self::SigV4 | Self::SigV4Body | Self::SigV4NoBody)
    }
}

/// Enforcement mode for L7 policy decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EnforcementMode {
    /// Log violations but allow traffic through (safe migration path).
    #[default]
    Audit,
    /// Deny violations — blocked requests never reach upstream.
    Enforce,
}

/// L7 configuration for an endpoint, extracted from policy data.
#[allow(
    clippy::struct_excessive_bools,
    reason = "Endpoint config mirrors independent policy schema toggles."
)]
#[derive(Debug, Clone)]
pub struct L7EndpointConfig {
    pub protocol: L7Protocol,
    /// Opaque endpoint identity derived from the matched policy endpoint.
    ///
    /// The value is added to the supervisor's internal OPA data and carried
    /// through path selection unchanged. It is never derived from the concrete
    /// request host because that host may have matched a wildcard selector.
    pub endpoint_id: String,
    /// Hash of the complete canonical policy that supplied this endpoint.
    ///
    /// Internal OPA metadata binds a selected endpoint to its observation
    /// inventory even while policy activation and inventory publication overlap.
    pub policy_hash: String,
    /// Optional endpoint-level HTTP path glob used to select between L7
    /// protocols that share the same host:port.
    pub path: String,
    pub tls: TlsMode,
    pub enforcement: EnforcementMode,
    /// Maximum GraphQL request body bytes to buffer for inspection.
    pub graphql_max_body_bytes: usize,
    /// Maximum JSON-RPC request body bytes to buffer for inspection.
    pub json_rpc_max_body_bytes: usize,
    /// MCP-only strict validation for tools/call params.name. Defaults to true
    /// for MCP endpoints and is ignored by other JSON-RPC-family protocols.
    pub mcp_strict_tool_names: bool,
    /// Canonical MCP protocol revisions allowed by this endpoint.
    ///
    /// Non-MCP endpoints always carry an empty list.
    pub mcp_versions: Vec<McpProtocolVersion>,
    /// When true, percent-encoded `/` (`%2F`) is preserved in path segments
    /// rather than rejected at the parser. Needed by upstreams like GitLab
    /// that embed `%2F` in namespaced project paths. Defaults to false.
    pub allow_encoded_slash: bool,
    /// Opt-in rewrite of credential placeholders in client-to-server
    /// WebSocket text messages after an allowed HTTP 101 upgrade.
    pub websocket_credential_rewrite: bool,
    /// Opt-in rewrite of credential placeholders in supported textual REST
    /// request bodies before forwarding upstream.
    pub request_body_credential_rewrite: bool,
    /// Explicit opt-in to credential-bearing traffic that cannot be inspected.
    pub allow_uninspected_credentials: bool,
    /// Internal gateway-derived credential provenance for this endpoint.
    pub provider_credentialed: bool,
    /// When true, client-to-server GraphQL-over-WebSocket operation messages
    /// are classified with the same operation policy used by GraphQL-over-HTTP.
    pub websocket_graphql_policy: bool,
    /// Proxy-side credential signing mode for this endpoint.
    pub credential_signing: CredentialSigning,
    /// AWS signing service name (e.g. `"bedrock"`). Required when
    /// `credential_signing` is `SigV4`.
    pub signing_service: String,
    /// AWS region override for `SigV4` signing. When set, takes precedence
    /// over hostname-based region extraction.
    pub signing_region: String,
}

/// Result of an L7 policy decision for a single request.
#[derive(Debug, Clone)]
pub struct L7Decision {
    pub allowed: bool,
    pub reason: String,
    pub matched_rule: Option<String>,
}

/// Parsed L7 request metadata used for policy evaluation and logging.
#[derive(Debug, Clone)]
pub struct L7RequestInfo {
    /// Protocol action: HTTP method (GET, POST, ...) or SQL command (SELECT, INSERT, ...).
    pub action: String,
    /// Target: URL path for REST, or empty for SQL.
    pub target: String,
    /// Decoded query parameter multimap for REST requests.
    pub query_params: std::collections::HashMap<String, Vec<String>>,
    /// Parsed GraphQL operation metadata for GraphQL endpoints.
    pub graphql: Option<graphql::GraphqlRequestInfo>,
    /// Parsed JSON-RPC request metadata for JSON-RPC endpoints.
    pub jsonrpc: Option<jsonrpc::JsonRpcRequestInfo>,
}

/// Parse an L7 endpoint config from a policy endpoint config.
///
/// Returns `None` for an endpoint without an inspected L7 protocol, or
/// whose settings the runtime rejects: an unknown `tls`, `enforcement`,
/// `access`, or `credential_signing` value, a signing mode without its
/// service, or an MCP endpoint without a canonical revision list.
pub fn parse_l7_config(config: &EndpointConfig) -> Option<L7EndpointConfig> {
    let protocol = config.protocol.l7()?;

    if config.tls == TlsSetting::Unknown
        || config.enforcement == EnforcementSetting::Unknown
        || config.access == AccessSetting::Unknown
    {
        return None;
    }

    let tls = match config.tls {
        TlsSetting::Skip => TlsMode::Skip,
        TlsSetting::Auto => TlsMode::Auto,
        TlsSetting::Unknown => unreachable!("endpoint modes were validated above"),
    };

    let enforcement = match config.enforcement {
        EnforcementSetting::Enforce => EnforcementMode::Enforce,
        EnforcementSetting::Default | EnforcementSetting::Audit => EnforcementMode::Audit,
        EnforcementSetting::Unknown => unreachable!("endpoint modes were validated above"),
    };

    // A YAML endpoint opts in through its GraphQL rules or persisted-query
    // settings. A Cedar endpoint carries no rules, so the Cedar engine sets
    // the flag for a `websocket-graphql` endpoint.
    let websocket_graphql_policy = protocol == L7Protocol::Websocket
        && (config.websocket_graphql_policy || endpoint_has_graphql_policy(config));
    let graphql_max_body_bytes = usize::try_from(config.graphql_max_body_bytes)
        .ok()
        .filter(|v| *v > 0)
        .unwrap_or(graphql::DEFAULT_MAX_BODY_BYTES);
    let json_rpc_max_body_bytes = usize::try_from(config.json_rpc_max_body_bytes)
        .ok()
        .filter(|v| *v > 0)
        .unwrap_or(jsonrpc::DEFAULT_MAX_BODY_BYTES);
    let mcp_strict_tool_names =
        protocol == L7Protocol::Mcp && config.mcp_strict_tool_names.unwrap_or(true);
    let mcp_versions = if protocol == L7Protocol::Mcp {
        parse_canonical_mcp_versions(&config.mcp_versions)?
    } else {
        Vec::new()
    };

    let credential_signing = match config.credential_signing.as_str() {
        "sigv4" => CredentialSigning::SigV4,
        "sigv4:body" => CredentialSigning::SigV4Body,
        "sigv4:no_body" => CredentialSigning::SigV4NoBody,
        "" => CredentialSigning::None,
        other => {
            let event = openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                .severity(openshell_ocsf::SeverityId::High)
                .status(openshell_ocsf::StatusId::Failure)
                .state(openshell_ocsf::StateId::Disabled, "invalid")
                .message(format!(
                    "rejecting endpoint: unrecognized credential_signing value {other:?}"
                ))
                .build();
            openshell_ocsf::ocsf_emit!(event);
            return None;
        }
    };

    if credential_signing.is_sigv4() && config.signing_service.is_empty() {
        let event = openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
            .severity(openshell_ocsf::SeverityId::High)
            .status(openshell_ocsf::StatusId::Failure)
            .state(openshell_ocsf::StateId::Disabled, "invalid")
            .message("rejecting endpoint: credential_signing requires signing_service".to_string())
            .build();
        openshell_ocsf::ocsf_emit!(event);
        return None;
    }

    Some(L7EndpointConfig {
        protocol,
        endpoint_id: config.endpoint_id.clone(),
        policy_hash: config.policy_hash.clone(),
        path: config.path.clone(),
        tls,
        enforcement,
        graphql_max_body_bytes,
        json_rpc_max_body_bytes,
        mcp_strict_tool_names,
        mcp_versions,
        allow_encoded_slash: config.allow_encoded_slash,
        websocket_credential_rewrite: config.websocket_credential_rewrite,
        request_body_credential_rewrite: config.request_body_credential_rewrite,
        allow_uninspected_credentials: config.allow_uninspected_credentials,
        provider_credentialed: config.provider_credentialed,
        websocket_graphql_policy,
        credential_signing,
        signing_service: config.signing_service.clone(),
        signing_region: config.signing_region.clone(),
    })
}

impl L7EndpointConfig {
    pub fn matches_path(&self, path: &str) -> bool {
        endpoint_path_matches(&self.path, path)
    }

    pub fn path_specificity(&self) -> usize {
        openshell_core::endpoint_path::path_specificity(&self.path)
    }

    pub fn deny_uninspected_body_credentials(&self, has_resolver: bool) -> bool {
        !self.allow_uninspected_credentials && (self.provider_credentialed || has_resolver)
    }
}

pub fn endpoint_path_matches(pattern: &str, path: &str) -> bool {
    openshell_core::endpoint_path::matches(pattern, path)
}

/// Parse the `tls` field from an endpoint config, independent of L7 protocol.
///
/// Used to check for `tls: skip` even on L4-only endpoints (no `protocol`
/// field) that explicitly opt out of TLS auto-detection.
pub fn parse_tls_mode(config: &EndpointConfig) -> TlsMode {
    match config.tls {
        TlsSetting::Skip => TlsMode::Skip,
        TlsSetting::Auto | TlsSetting::Unknown => TlsMode::Auto,
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EndpointCredentialGuard {
    pub provider_credentialed: bool,
    pub allow_uninspected_credentials: bool,
    pub has_l7_protocol: bool,
    pub tls: TlsMode,
}

impl EndpointCredentialGuard {
    pub fn blocks_uninspected(self) -> bool {
        self.provider_credentialed && !self.allow_uninspected_credentials
    }

    pub fn blocks_connect(self) -> bool {
        self.blocks_uninspected() && (!self.has_l7_protocol || self.tls == TlsMode::Skip)
    }
}

pub fn parse_endpoint_credential_guard(config: &EndpointConfig) -> EndpointCredentialGuard {
    EndpointCredentialGuard {
        provider_credentialed: config.provider_credentialed,
        allow_uninspected_credentials: config.allow_uninspected_credentials,
        // Any declared protocol counts, including explicit TCP.
        has_l7_protocol: config.protocol != EndpointProtocol::None,
        tls: parse_tls_mode(config),
    }
}

pub fn parse_canonical_mcp_versions(labels: &[String]) -> Option<Vec<McpProtocolVersion>> {
    let versions = labels
        .iter()
        .map(|label| label.parse::<McpProtocolVersion>().ok())
        .collect::<Option<Vec<_>>>()?;

    // Both policy ingress paths promise a non-empty, strictly ordered list.
    // Rechecking that runtime contract prevents a dropped or corrupted
    // projection from silently selecting a different wire profile.
    if versions.is_empty() || !versions.windows(2).all(|pair| pair[0] < pair[1]) {
        return None;
    }
    Some(versions)
}

pub fn endpoint_has_graphql_policy(config: &EndpointConfig) -> bool {
    !config.graphql_persisted_queries.is_empty()
        || has_graphql_persisted_query_mode(config)
        || config
            .rules
            .iter()
            .any(|rule| rule.graphql_selectors().is_set())
        || config.deny_rules.iter().any(|rule| rule.selectors.is_set())
}

pub fn has_graphql_persisted_query_mode(config: &EndpointConfig) -> bool {
    !config.persisted_queries.is_empty() && config.persisted_queries != "deny"
}

/// Check a glob pattern for obvious syntax issues.
///
/// Returns `Some(warning_message)` if the pattern looks malformed.
/// OPA's `glob.match` is forgiving, so these are warnings (not errors)
/// to surface likely typos without blocking policy loading.
pub fn check_glob_syntax(pattern: &str) -> Option<String> {
    let mut bracket_depth: i32 = 0;
    for c in pattern.chars() {
        match c {
            '[' => bracket_depth += 1,
            ']' => {
                if bracket_depth == 0 {
                    return Some(format!("glob pattern '{pattern}' has unmatched ']'"));
                }
                bracket_depth -= 1;
            }
            _ => {}
        }
    }
    if bracket_depth > 0 {
        return Some(format!("glob pattern '{pattern}' has unclosed '['"));
    }

    let mut brace_depth: i32 = 0;
    for c in pattern.chars() {
        match c {
            '{' => brace_depth += 1,
            '}' => {
                if brace_depth == 0 {
                    return Some(format!("glob pattern '{pattern}' has unmatched '}}'"));
                }
                brace_depth -= 1;
            }
            _ => {}
        }
    }
    if brace_depth > 0 {
        return Some(format!("glob pattern '{pattern}' has unclosed '{{'"));
    }

    None
}

pub fn validate_host_wildcard(errors: &mut Vec<String>, loc: &str, host: &str) {
    if !host.contains('*') {
        return;
    }

    if host == "*" || host == "**" {
        errors.push(format!(
            "{loc}: host wildcard '{host}' matches all hosts; use specific patterns like '*.example.com'"
        ));
        return;
    }

    let labels: Vec<&str> = host.split('.').collect();
    let first_label = labels.first().copied().unwrap_or_default();
    if first_label.contains("**") && first_label != "**" {
        errors.push(format!(
            "{loc}: recursive host wildcard '**' is only allowed as the entire first DNS label, got '{host}'"
        ));
        return;
    }
    for label in labels.iter().skip(1).copied() {
        if label.contains("**") {
            errors.push(format!(
                "{loc}: recursive host wildcard '**' is only allowed as the entire first DNS label, got '{host}'"
            ));
            return;
        }
        if label.contains('*') && label != "*" {
            errors.push(format!(
                "{loc}: middle DNS label wildcard must be the entire label '*', got '{host}'"
            ));
            return;
        }
    }

    // Reject TLD or single-label wildcards. They are accepted by the policy
    // engine but silently fail at the proxy layer (see #787).
    if labels.len() <= 2 {
        errors.push(format!(
            "{loc}: TLD wildcard '{host}' is not allowed; \
             use subdomain wildcards like '*.example.com' instead"
        ));
    }
}

pub fn validate_graphql_operation_type(
    errors: &mut Vec<String>,
    loc: &str,
    value: Option<&str>,
    required: bool,
) {
    let Some(value) = value.filter(|v| !v.is_empty()) else {
        if required {
            errors.push(format!(
                "{loc}.operation_type: required for GraphQL L7 rules"
            ));
        }
        return;
    };

    let valid = ["query", "mutation", "subscription", "*"];
    if !valid.contains(&value.to_ascii_lowercase().as_str()) {
        errors.push(format!(
            "{loc}.operation_type: expected query, mutation, subscription, or *, got '{value}'"
        ));
    }
}

pub fn validate_graphql_fields(
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
    loc: &str,
    fields: Option<&serde_json::Value>,
) {
    let Some(fields) = fields else {
        return;
    };
    let Some(items) = fields.as_array() else {
        errors.push(format!(
            "{loc}.fields: expected array of GraphQL root field globs"
        ));
        return;
    };
    if items.is_empty() {
        errors.push(format!(
            "{loc}.fields: list must not be empty; omit fields to match all root fields"
        ));
        return;
    }
    for item in items {
        let Some(field) = item.as_str() else {
            errors.push(format!("{loc}.fields: all values must be strings"));
            continue;
        };
        if field.is_empty() {
            errors.push(format!("{loc}.fields: field glob must not be empty"));
        } else if let Some(warning) = check_glob_syntax(field) {
            warnings.push(format!("{loc}.fields: {warning}"));
        }
    }
}

pub fn validate_graphql_rule(
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
    loc: &str,
    rule: &serde_json::Value,
    required: bool,
) {
    validate_graphql_operation_type(
        errors,
        loc,
        rule.get("operation_type").and_then(|v| v.as_str()),
        required,
    );
    if let Some(name) = rule.get("operation_name").and_then(|v| v.as_str())
        && !name.is_empty()
        && let Some(warning) = check_glob_syntax(name)
    {
        warnings.push(format!("{loc}.operation_name: {warning}"));
    }
    validate_graphql_fields(errors, warnings, loc, rule.get("fields"));
}

// Validate a matcher map when it exists. Null is treated like omission because
// policy loading normalizes absent optional maps the same way.
pub fn validate_matcher_map(
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
    loc: &str,
    value: Option<&serde_json::Value>,
) {
    let Some(value) = value.filter(|v| !v.is_null()) else {
        return;
    };
    let Some(obj) = value.as_object() else {
        errors.push(format!("{loc}: expected map of matchers"));
        return;
    };

    for (key, matcher) in obj {
        validate_matcher_value(errors, warnings, &format!("{loc}.{key}"), matcher);
    }
}

// Validate one matcher leaf. Objects must use the explicit matcher keys.
pub fn validate_matcher_value(
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
    loc: &str,
    matcher: &serde_json::Value,
) {
    if let Some(glob_str) = matcher.as_str() {
        if let Some(warning) = check_glob_syntax(glob_str) {
            warnings.push(format!("{loc}: {warning}"));
        }
        return;
    }

    let Some(matcher_obj) = matcher.as_object() else {
        errors.push(format!("{loc}: expected string glob or matcher object"));
        return;
    };

    let has_any = matcher_obj.get("any").is_some();
    let has_glob = matcher_obj.get("glob").is_some();
    if !has_any && !has_glob {
        errors.push(format!(
            "{loc}: unknown matcher keys; only `glob` or `any` are supported"
        ));
        return;
    }

    let has_unknown = matcher_obj.keys().any(|k| k != "any" && k != "glob");
    if has_unknown {
        errors.push(format!(
            "{loc}: unknown matcher keys; only `glob` or `any` are supported"
        ));
        return;
    }

    if has_glob && has_any {
        errors.push(format!(
            "{loc}: matcher cannot specify both `glob` and `any`"
        ));
        return;
    }

    if has_glob {
        match matcher_obj.get("glob").and_then(|v| v.as_str()) {
            None => errors.push(format!("{loc}.glob: expected glob string")),
            Some(glob_str) => {
                if let Some(warning) = check_glob_syntax(glob_str) {
                    warnings.push(format!("{loc}.glob: {warning}"));
                }
            }
        }
        return;
    }

    let Some(any) = matcher_obj.get("any").and_then(|v| v.as_array()) else {
        errors.push(format!("{loc}.any: expected array of glob strings"));
        return;
    };
    if any.is_empty() {
        errors.push(format!("{loc}.any: list must not be empty"));
        return;
    }
    if any.iter().any(|v| v.as_str().is_none()) {
        errors.push(format!("{loc}.any: all values must be strings"));
    }
    for item in any.iter().filter_map(|v| v.as_str()) {
        if let Some(warning) = check_glob_syntax(item) {
            warnings.push(format!("{loc}.any: {warning}"));
        }
    }
}

// Validate the shared JSON-RPC-family rule surface. Generic JSON-RPC requires
// an explicit method but does not support authored params matchers yet. MCP
// keeps method optional while the endpoint-level method profile is enabled;
// disabling that profile makes method explicit on every authored MCP rule. MCP
// does not expose tool-argument matching.
pub fn validate_jsonrpc_rule_fields(
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
    loc: &str,
    rule: &serde_json::Value,
    protocol: &str,
    mcp_strict_tool_names: bool,
    mcp_allow_all_known_mcp_methods: bool,
) {
    let method = rule.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let has_params = rule.get("params").is_some_and(|v| !v.is_null());
    let has_tool = rule.get("tool").is_some_and(|v| !v.is_null());
    let has_tool_selector = mcp_rule_has_tool_selector(rule);

    if protocol == "json-rpc" {
        if method.is_empty() {
            errors.push(format!("{loc}.method: required for {protocol} L7 rules"));
        } else if method != "*" && glob_uses_wildcard(method) {
            errors.push(format!(
                "{loc}.method: generic JSON-RPC method rules do not support glob or wildcard matchers; use \"*\" to allow all methods or an exact method name"
            ));
        }
        if has_params {
            errors.push(format!(
                "{loc}: JSON-RPC rules do not support params matchers yet"
            ));
        }
        if has_tool {
            errors.push(format!(
                "{loc}.tool: MCP tool matching is only valid for protocol mcp"
            ));
        }
        if json_rule_has_non_empty_path_or_query(rule) {
            errors.push(format!(
                "{loc}: {protocol} L7 rules must use method, not path/query"
            ));
        }
        return;
    }

    if protocol == "mcp" {
        validate_mcp_method_field(errors, warnings, loc, method);
        if method.is_empty() && !mcp_allow_all_known_mcp_methods {
            errors.push(format!(
                "{loc}.method: required when mcp.allow_all_known_mcp_methods is false"
            ));
        } else if has_tool_selector && !method.is_empty() && method != "tools/call" {
            errors.push(format!(
                "{loc}.method: must be tools/call when an MCP rule uses tool or params.name, got '{method}'"
            ));
        }
        validate_mcp_tool_field(errors, warnings, loc, rule, mcp_strict_tool_names);
        validate_mcp_params_field(errors, warnings, loc, rule, has_tool, mcp_strict_tool_names);
        if json_rule_has_non_empty_path_or_query(rule) {
            errors.push(format!(
                "{loc}: {protocol} L7 rules must use method/tool, not path/query"
            ));
        }
        return;
    }

    if has_tool {
        errors.push(format!(
            "{loc}.tool: MCP tool matching is only valid for protocol mcp"
        ));
    }

    if has_params {
        errors.push(format!(
            "{loc}.params: params matching is only valid for protocol mcp"
        ));
    }
}

pub fn validate_mcp_method_field(
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
    loc: &str,
    method: &str,
) {
    if method.is_empty() {
        return;
    }
    if let Some(warning) = check_glob_syntax(method) {
        warnings.push(format!("{loc}.method: {warning}"));
    }
    if glob_uses_wildcard(method) && !method.starts_with("tools/") {
        errors.push(format!(
            "{loc}.method: MCP method globs are only valid for the tools/ method family; omit method to use the endpoint method profile"
        ));
    }
}

pub fn method_matcher_matches_tools_call(method: &str) -> bool {
    method == "tools/call"
        || method == "*"
        || glob::Pattern::new(method).is_ok_and(|pattern| pattern.matches("tools/call"))
}

pub fn mcp_rule_has_tool_selector(rule: &serde_json::Value) -> bool {
    rule.get("tool").is_some_and(|v| !v.is_null())
        || rule
            .get("params")
            .and_then(serde_json::Value::as_object)
            .and_then(|params| params.get("name"))
            .is_some_and(|v| !v.is_null())
}

pub fn mcp_endpoint_has_tool_allow_selectors(ep: &serde_json::Value) -> bool {
    ep.get("rules")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|rules| {
            rules.iter().any(|rule| {
                let allow = rule.get("allow").unwrap_or(rule);
                mcp_rule_has_tool_selector(allow)
            })
        })
}

pub fn validate_mcp_tool_field(
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
    loc: &str,
    rule: &serde_json::Value,
    mcp_strict_tool_names: bool,
) {
    let Some(tool) = rule.get("tool").filter(|v| !v.is_null()) else {
        return;
    };
    validate_matcher_value(errors, warnings, &format!("{loc}.tool"), tool);
    validate_mcp_tool_name_wildcard_policy(
        errors,
        &format!("{loc}.tool"),
        tool,
        mcp_strict_tool_names,
    );
}

pub fn validate_mcp_params_field(
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
    loc: &str,
    rule: &serde_json::Value,
    has_tool: bool,
    mcp_strict_tool_names: bool,
) {
    let Some(params) = rule.get("params") else {
        return;
    };
    // Explicit params must be a map: tool alias lowering inserts params.name
    // into it, so accepting null would discard the tool selector.
    let Some(params_obj) = params.as_object() else {
        errors.push(format!("{loc}.params: expected map of matchers"));
        return;
    };

    if has_tool && params_obj.contains_key("name") {
        errors.push(format!(
            "{loc}: MCP rules must use either tool or params.name, not both"
        ));
    }

    for key in params_obj.keys() {
        if key != "name" {
            errors.push(format!(
                "{loc}.params.{key}: MCP tool argument matching is not supported yet"
            ));
        }
    }

    if let Some(name_matcher) = params_obj.get("name") {
        validate_matcher_value(
            errors,
            warnings,
            &format!("{loc}.params.name"),
            name_matcher,
        );
        validate_mcp_tool_name_wildcard_policy(
            errors,
            &format!("{loc}.params.name"),
            name_matcher,
            mcp_strict_tool_names,
        );
    }
}

pub fn validate_mcp_tool_name_wildcard_policy(
    errors: &mut Vec<String>,
    loc: &str,
    matcher: &serde_json::Value,
    mcp_strict_tool_names: bool,
) {
    if !mcp_strict_tool_names && matcher_uses_glob_wildcard(matcher) {
        errors.push(format!(
            "{loc}: wildcard tool-name matchers require mcp.strict_tool_names to remain enabled"
        ));
    }
}

pub fn matcher_uses_glob_wildcard(matcher: &serde_json::Value) -> bool {
    if let Some(glob) = matcher.as_str() {
        return glob_uses_wildcard(glob);
    }

    let Some(obj) = matcher.as_object() else {
        return false;
    };
    if obj
        .get("glob")
        .and_then(serde_json::Value::as_str)
        .is_some_and(glob_uses_wildcard)
    {
        return true;
    }
    obj.get("any")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .any(glob_uses_wildcard)
        })
}

pub fn glob_uses_wildcard(glob: &str) -> bool {
    glob.bytes()
        .any(|b| matches!(b, b'*' | b'?' | b'[' | b']' | b'{' | b'}'))
}

pub fn json_rule_has_graphql_fields(rule: &serde_json::Value) -> bool {
    rule.get("operation_type")
        .and_then(|v| v.as_str())
        .is_some_and(|v| !v.is_empty())
        || rule
            .get("operation_name")
            .and_then(|v| v.as_str())
            .is_some_and(|v| !v.is_empty())
        || rule.get("fields").is_some()
}

pub fn json_rule_has_transport_fields(rule: &serde_json::Value) -> bool {
    rule.get("method").is_some() || rule.get("path").is_some() || rule.get("query").is_some()
}

pub fn json_rule_has_non_empty_path_or_query(rule: &serde_json::Value) -> bool {
    rule.get("path")
        .and_then(|v| v.as_str())
        .is_some_and(|v| !v.is_empty())
        || rule
            .get("query")
            .and_then(|v| v.as_object())
            .is_some_and(|v| !v.is_empty())
}

pub fn json_endpoint_has_graphql_policy(ep: &serde_json::Value) -> bool {
    ep.get("graphql_persisted_queries")
        .and_then(|v| v.as_object())
        .is_some_and(|v| !v.is_empty())
        || ep
            .get("persisted_queries")
            .and_then(|v| v.as_str())
            .is_some_and(|v| !v.is_empty() && v != "deny")
        || ep
            .get("rules")
            .and_then(|v| v.as_array())
            .is_some_and(|rules| {
                rules.iter().any(|rule| {
                    rule.get("allow")
                        .or(Some(rule))
                        .is_some_and(json_rule_has_graphql_fields)
                })
            })
        || ep
            .get("deny_rules")
            .and_then(|v| v.as_array())
            .is_some_and(|rules| rules.iter().any(json_rule_has_graphql_fields))
}

/// Validate L7 policy configuration in the loaded OPA data.
///
/// Returns a list of errors and warnings. Errors should prevent sandbox startup;
/// warnings are logged but don't block.
pub fn additional_l7_fields(ep: &serde_json::Value) -> Vec<&'static str> {
    let mut fields = Vec::new();
    let non_empty_string = |name| {
        ep.get(name)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| !value.is_empty())
    };
    let enabled = |name| {
        ep.get(name)
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    };

    for (name, present) in [
        ("enforcement", non_empty_string("enforcement")),
        ("path", non_empty_string("path")),
        ("allow_encoded_slash", enabled("allow_encoded_slash")),
        (
            "websocket_credential_rewrite",
            enabled("websocket_credential_rewrite"),
        ),
        (
            "request_body_credential_rewrite",
            enabled("request_body_credential_rewrite"),
        ),
        ("persisted_queries", non_empty_string("persisted_queries")),
        (
            "graphql_persisted_queries",
            ep.get("graphql_persisted_queries").is_some(),
        ),
        (
            "graphql_max_body_bytes",
            ep.get("graphql_max_body_bytes").is_some(),
        ),
        (
            "json_rpc_max_body_bytes",
            ep.get("json_rpc_max_body_bytes").is_some(),
        ),
        (
            "mcp.strict_tool_names",
            ep.get("mcp_strict_tool_names").is_some(),
        ),
        (
            "mcp.allow_all_known_mcp_methods",
            ep.get("mcp_allow_all_known_mcp_methods").is_some(),
        ),
        ("credential_signing", non_empty_string("credential_signing")),
        ("signing_service", non_empty_string("signing_service")),
        ("signing_region", non_empty_string("signing_region")),
        (
            "credential_binding",
            ep.get("credential_binding")
                .is_some_and(|value| !value.is_null()),
        ),
    ] {
        if present {
            fields.push(name);
        }
    }

    fields
}

pub fn validate_l7_policies(data_json: &serde_json::Value) -> (Vec<String>, Vec<String>) {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let Some(policies) = data_json
        .get("network_policies")
        .and_then(|v| v.as_object())
    else {
        return (errors, warnings);
    };

    for (name, policy) in policies {
        let Some(endpoints) = policy.get("endpoints").and_then(|v| v.as_array()) else {
            continue;
        };

        for (i, ep) in endpoints.iter().enumerate() {
            let protocol = ep.get("protocol").and_then(|v| v.as_str()).unwrap_or("");
            let l7_protocol = L7Protocol::parse(protocol);
            let jsonrpc_family = l7_protocol.is_some_and(L7Protocol::is_jsonrpc_family);
            let tls = ep.get("tls").and_then(|v| v.as_str()).unwrap_or("");
            let enforcement = ep.get("enforcement").and_then(|v| v.as_str()).unwrap_or("");
            let access = ep.get("access").and_then(|v| v.as_str()).unwrap_or("");
            let has_rules = ep
                .get("rules")
                .and_then(|v| v.as_array())
                .is_some_and(|a| !a.is_empty());
            let websocket_has_graphql_policy =
                protocol == "websocket" && json_endpoint_has_graphql_policy(ep);
            let host = ep.get("host").and_then(|v| v.as_str()).unwrap_or("");
            let endpoint_path = ep.get("path").and_then(|v| v.as_str()).unwrap_or("");

            // Read ports from either "ports" array or scalar "port".
            let ports: Vec<u64> = ep.get("ports").and_then(|v| v.as_array()).map_or_else(
                || {
                    ep.get("port")
                        .and_then(serde_json::Value::as_u64)
                        .filter(|p| *p > 0)
                        .into_iter()
                        .collect()
                },
                |arr| arr.iter().filter_map(serde_json::Value::as_u64).collect(),
            );
            let loc = format!("{name}.endpoints[{i}]");

            errors.extend(
                validate_endpoint_modes(tls, enforcement, access)
                    .into_iter()
                    .map(|reason| format!("{loc}: {reason}")),
            );

            if protocol == "mcp" {
                if host.trim().is_empty() {
                    errors.push(format!(
                        "{loc}: protocol mcp requires host; protocol alone is not a wildcard endpoint"
                    ));
                }
                if !ports.iter().any(|port| *port > 0) {
                    errors.push(format!(
                        "{loc}: protocol mcp requires port or ports; protocol alone is not a wildcard endpoint"
                    ));
                }
            }

            if !endpoint_path.is_empty() {
                if !endpoint_path.starts_with('/') && endpoint_path != "**" {
                    errors.push(format!(
                        "{loc}: endpoint path must start with '/' or be '**', got '{endpoint_path}'"
                    ));
                }
                if let Some(warning) = check_glob_syntax(endpoint_path) {
                    warnings.push(format!("{loc}.path: {warning}"));
                }
            }

            validate_host_wildcard(&mut errors, &loc, host);

            // port + ports mutual exclusion
            let has_scalar_port = ep
                .get("port")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|p| p > 0);
            let has_ports_array = ep
                .get("ports")
                .and_then(|v| v.as_array())
                .is_some_and(|a| !a.is_empty());
            if has_scalar_port && has_ports_array {
                errors.push(format!(
                    "{loc}: port and ports are mutually exclusive; use ports for multiple ports"
                ));
            }

            // L7 endpoint semantic validation (shared with profile lint).
            // Computed lazily: has_deny_rules and rules_would_deny_all are
            // needed here but also referenced by per-rule checks below.
            let has_deny_rules = ep
                .get("deny_rules")
                .and_then(|v| v.as_array())
                .is_some_and(|a| !a.is_empty());
            let rules_would_deny_all =
                ep.get("rules")
                    .and_then(|v| v.as_array())
                    .is_some_and(|rules| {
                        !rules.is_empty()
                            && rules.iter().all(|rule| {
                                let allow = rule.get("allow");
                                allow.is_none_or(serde_json::Value::is_null)
                                    || allow.is_some_and(|v| {
                                        let str_empty = |key| {
                                            v.get(key)
                                                .and_then(|s| s.as_str())
                                                .unwrap_or("")
                                                .is_empty()
                                        };
                                        str_empty("method")
                                            && str_empty("path")
                                            && str_empty("command")
                                            && str_empty("operation_type")
                                            && str_empty("operation_name")
                                            && !mcp_rule_has_tool_selector(v)
                                    })
                            })
                    });
            let mcp_allow_all_known_mcp_methods = ep
                .get("mcp_allow_all_known_mcp_methods")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let l7_fields = L7EndpointFields {
                protocol,
                access,
                has_rules,
                has_deny_rules,
                rules_would_deny_all,
                allow_all_known_mcp_methods: mcp_allow_all_known_mcp_methods,
            };
            for msg in validate_l7_endpoint_semantics(&l7_fields) {
                errors.push(format!("{loc}: {msg}"));
            }
            for msg in validate_explicit_tcp_additional_fields(protocol, &additional_l7_fields(ep))
            {
                errors.push(format!("{loc}: {msg}"));
            }

            if let Some(mode) = ep.get("persisted_queries").and_then(|v| v.as_str())
                && !mode.is_empty()
                && mode != "deny"
                && mode != "allow_registered"
            {
                errors.push(format!(
                    "{loc}: persisted_queries must be 'deny' or 'allow_registered', got '{mode}'"
                ));
            }

            if ep.get("graphql_max_body_bytes").is_some() {
                let valid_max = ep
                    .get("graphql_max_body_bytes")
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|v| v > 0);
                if !valid_max {
                    errors.push(format!(
                        "{loc}: graphql_max_body_bytes must be a positive integer"
                    ));
                }
            }

            if ep.get("json_rpc_max_body_bytes").is_some() {
                let valid_max = ep
                    .get("json_rpc_max_body_bytes")
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|v| v > 0);
                if !valid_max {
                    errors.push(format!(
                        "{loc}: json_rpc_max_body_bytes must be a positive integer"
                    ));
                }
            }

            if protocol != "graphql"
                && protocol != "websocket"
                && (ep.get("persisted_queries").is_some()
                    || ep.get("graphql_persisted_queries").is_some()
                    || ep.get("graphql_max_body_bytes").is_some())
            {
                warnings.push(format!(
                    "{loc}: GraphQL-specific endpoint fields are ignored unless protocol is graphql or websocket"
                ));
            }

            if !jsonrpc_family && ep.get("json_rpc_max_body_bytes").is_some() {
                warnings.push(format!(
                    "{loc}: JSON-RPC-specific endpoint fields are ignored unless protocol is json-rpc or mcp"
                ));
            }
            validate_mcp_versions_field(&mut errors, &loc, ep, l7_protocol);
            let has_mcp_strict_tool_names = ep.get("mcp_strict_tool_names").is_some();
            let has_mcp_allow_all_known_mcp_methods =
                ep.get("mcp_allow_all_known_mcp_methods").is_some();
            if has_mcp_strict_tool_names {
                if ep
                    .get("mcp_strict_tool_names")
                    .and_then(serde_json::Value::as_bool)
                    .is_none()
                {
                    errors.push(format!("{loc}: mcp.strict_tool_names must be boolean"));
                }
                if protocol != "mcp" {
                    errors.push(format!(
                        "{loc}: mcp.strict_tool_names is only valid for protocol mcp"
                    ));
                }
            }
            if has_mcp_allow_all_known_mcp_methods {
                if ep
                    .get("mcp_allow_all_known_mcp_methods")
                    .and_then(serde_json::Value::as_bool)
                    .is_none()
                {
                    errors.push(format!(
                        "{loc}: mcp.allow_all_known_mcp_methods must be boolean"
                    ));
                }
                if protocol != "mcp" {
                    errors.push(format!(
                        "{loc}: mcp.allow_all_known_mcp_methods is only valid for protocol mcp"
                    ));
                }
            }
            let mcp_strict_tool_names = ep
                .get("mcp_strict_tool_names")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            if ep
                .get("websocket_credential_rewrite")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
                && protocol != "rest"
                && protocol != "websocket"
            {
                warnings.push(format!(
                    "{loc}: websocket_credential_rewrite is ignored unless protocol is rest or websocket"
                ));
            }

            if ep
                .get("request_body_credential_rewrite")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
                && protocol != "rest"
            {
                warnings.push(format!(
                    "{loc}: request_body_credential_rewrite is ignored unless protocol is rest"
                ));
            }

            if let Some(registry_value) = ep.get("graphql_persisted_queries") {
                let Some(registry) = registry_value.as_object() else {
                    errors.push(format!(
                        "{loc}: graphql_persisted_queries must be a map keyed by hash or saved-query id"
                    ));
                    continue;
                };
                for (key, op) in registry {
                    let registry_loc = format!("{loc}.graphql_persisted_queries[{key}]");
                    validate_graphql_rule(&mut errors, &mut warnings, &registry_loc, op, true);
                }
            }

            // tls: skip with L7 on port 443 won't work
            if tls == "skip" && !protocol.is_empty() && ports.contains(&443) {
                warnings.push(format!(
                    "{loc}: 'tls: skip' with L7 rules on port 443 — L7 inspection cannot work on encrypted traffic"
                ));
            }

            // sql + enforce blocked in v1
            if protocol == "sql" && enforcement == "enforce" {
                errors.push(format!(
                    "{loc}: SQL enforcement requires full SQL parsing (not available in v1). Use `enforcement: audit`."
                ));
            }

            // Per-rule deny_rules validation (semantic checks handled by
            // shared validator above).
            if has_deny_rules {
                let has_mcp_tool_allow_selectors =
                    protocol == "mcp" && mcp_endpoint_has_tool_allow_selectors(ep);

                if let Some(deny_rules) = ep.get("deny_rules").and_then(|v| v.as_array()) {
                    for (deny_idx, deny_rule) in deny_rules.iter().enumerate() {
                        let deny_loc = format!("{loc}.deny_rules[{deny_idx}]");

                        if has_mcp_tool_allow_selectors
                            && deny_rule
                                .get("method")
                                .and_then(serde_json::Value::as_str)
                                .is_some_and(method_matcher_matches_tools_call)
                            && !mcp_rule_has_tool_selector(deny_rule)
                        {
                            errors.push(format!(
                                "{deny_loc}: method matcher denies every tool call and conflicts with MCP tool allow rules; add tool or params.name to deny specific tools, or remove the tool allow rules"
                            ));
                        }

                        // Validate method
                        if let Some(method) = deny_rule.get("method").and_then(|m| m.as_str())
                            && !method.is_empty()
                            && (protocol == "rest" || protocol == "websocket")
                        {
                            let valid_methods = valid_methods_for_protocol(protocol);
                            if !valid_methods.contains(&method.to_ascii_uppercase().as_str()) {
                                warnings.push(format!(
                                    "{deny_loc}: Unknown HTTP/WebSocket method '{method}'. Standard methods: {}."
                                    , valid_methods.join(", ")
                                ));
                            }
                        }

                        // Validate path glob syntax
                        if let Some(path) = deny_rule.get("path").and_then(|p| p.as_str())
                            && let Some(warning) = check_glob_syntax(path)
                        {
                            warnings.push(format!("{deny_loc}.path: {warning}"));
                        }

                        // Validate query matchers — mirrors allow-side validation exactly
                        if let Some(query) = deny_rule.get("query").filter(|v| !v.is_null()) {
                            validate_matcher_map(
                                &mut errors,
                                &mut warnings,
                                &format!("{deny_loc}.query"),
                                Some(query),
                            );
                        }

                        validate_jsonrpc_rule_fields(
                            &mut errors,
                            &mut warnings,
                            &deny_loc,
                            deny_rule,
                            protocol,
                            mcp_strict_tool_names,
                            mcp_allow_all_known_mcp_methods,
                        );

                        // SQL command validation
                        if let Some(command) = deny_rule.get("command").and_then(|c| c.as_str())
                            && !command.is_empty()
                            && protocol == "rest"
                        {
                            warnings
                                .push(format!("{deny_loc}: command is for SQL protocol, not REST"));
                        }

                        let deny_has_graphql = json_rule_has_graphql_fields(deny_rule);
                        if protocol == "websocket"
                            && deny_has_graphql
                            && json_rule_has_transport_fields(deny_rule)
                        {
                            errors.push(format!(
                                "{deny_loc}: WebSocket GraphQL deny rules must not combine method/path/query with operation_type/operation_name/fields"
                            ));
                        }

                        if protocol == "graphql" || (protocol == "websocket" && deny_has_graphql) {
                            validate_graphql_rule(
                                &mut errors,
                                &mut warnings,
                                &deny_loc,
                                deny_rule,
                                true,
                            );
                        } else if deny_has_graphql {
                            warnings.push(format!(
                                "{deny_loc}: GraphQL rule fields are ignored unless protocol is graphql or websocket"
                            ));
                        }
                    }
                }
            }

            // Empty rules list (explicitly set but empty)
            if ep
                .get("rules")
                .and_then(|v| v.as_array())
                .is_some_and(Vec::is_empty)
            {
                errors.push(format!(
                    "{loc}: rules list cannot be empty (would deny all traffic). Use `access: full` or remove rules."
                ));
            }

            // Empty deny_rules list (explicitly set but empty)
            if ep
                .get("deny_rules")
                .and_then(|v| v.as_array())
                .is_some_and(Vec::is_empty)
            {
                errors.push(format!(
                    "{loc}: deny_rules list cannot be empty (would have no effect). Remove it if no denials are needed."
                ));
            }

            // Validate HTTP methods in rules
            if has_rules && (protocol == "rest" || protocol == "websocket") {
                let valid_methods = valid_methods_for_protocol(protocol);
                if let Some(rules) = ep.get("rules").and_then(|v| v.as_array()) {
                    for (rule_idx, rule) in rules.iter().enumerate() {
                        if let Some(method) = rule
                            .get("allow")
                            .and_then(|a| a.get("method"))
                            .and_then(|m| m.as_str())
                            && !method.is_empty()
                            && !valid_methods.contains(&method.to_ascii_uppercase().as_str())
                        {
                            warnings.push(format!(
                                    "{loc}: Unknown HTTP/WebSocket method '{method}'. Standard methods: {}."
                                    , valid_methods.join(", ")
                                ));
                        }

                        let Some(query) = rule
                            .get("allow")
                            .and_then(|a| a.get("query"))
                            .filter(|v| !v.is_null())
                        else {
                            continue;
                        };

                        validate_matcher_map(
                            &mut errors,
                            &mut warnings,
                            &format!("{loc}.rules[{rule_idx}].allow.query"),
                            Some(query),
                        );
                    }
                }
            }

            let has_mcp_tool_allow_selectors =
                protocol == "mcp" && mcp_endpoint_has_tool_allow_selectors(ep);
            if has_rules && let Some(rules) = ep.get("rules").and_then(|v| v.as_array()) {
                for (rule_idx, rule) in rules.iter().enumerate() {
                    let allow = rule.get("allow").unwrap_or(rule);
                    let rule_loc = format!("{loc}.rules[{rule_idx}].allow");
                    if has_mcp_tool_allow_selectors && !mcp_rule_has_tool_selector(allow) {
                        let method = allow
                            .get("method")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("");
                        if method_matcher_matches_tools_call(method)
                            || (method.is_empty() && mcp_allow_all_known_mcp_methods)
                        {
                            errors.push(format!(
                                "{rule_loc}: method matcher allows every tool call and conflicts \
                                 with MCP tool allow rules; add tool or params.name to narrow \
                                 tools/call, or remove the tool allow rules"
                            ));
                        }
                    }
                    validate_jsonrpc_rule_fields(
                        &mut errors,
                        &mut warnings,
                        &rule_loc,
                        allow,
                        protocol,
                        mcp_strict_tool_names,
                        mcp_allow_all_known_mcp_methods,
                    );
                    let allow_has_graphql = json_rule_has_graphql_fields(allow);
                    if websocket_has_graphql_policy
                        && allow
                            .get("method")
                            .and_then(|m| m.as_str())
                            .is_some_and(|method| method.eq_ignore_ascii_case("WEBSOCKET_TEXT"))
                    {
                        errors.push(format!(
                            "{rule_loc}: WebSocket endpoints with GraphQL operation policy must use operation_type/operation_name/fields rules for client messages instead of WEBSOCKET_TEXT"
                        ));
                    }
                    if protocol == "websocket"
                        && allow_has_graphql
                        && json_rule_has_transport_fields(allow)
                    {
                        errors.push(format!(
                            "{rule_loc}: WebSocket GraphQL allow rules must not combine method/path/query with operation_type/operation_name/fields"
                        ));
                    }
                    if protocol == "graphql" || (protocol == "websocket" && allow_has_graphql) {
                        validate_graphql_rule(&mut errors, &mut warnings, &rule_loc, allow, true);
                    } else if allow_has_graphql {
                        warnings.push(format!(
                            "{rule_loc}: GraphQL rule fields are ignored unless protocol is graphql or websocket"
                        ));
                    }
                }
            }
        }
    }

    (errors, warnings)
}

pub fn validate_mcp_versions_field(
    errors: &mut Vec<String>,
    loc: &str,
    endpoint: &serde_json::Value,
    protocol: Option<L7Protocol>,
) {
    let Some(value) = endpoint.get("mcp_versions") else {
        return;
    };
    if protocol != Some(L7Protocol::Mcp) {
        errors.push(format!(
            "{loc}: mcp.versions is only valid for protocol mcp"
        ));
        return;
    }
    let Some(values) = value.as_array() else {
        errors.push(format!("{loc}: mcp.versions must be an array"));
        return;
    };
    if values.is_empty() {
        errors.push(format!("{loc}: mcp.versions must not be empty"));
        return;
    }

    let mut versions = Vec::with_capacity(values.len());
    for value in values {
        let Some(value) = value.as_str() else {
            errors.push(format!("{loc}: mcp.versions entries must be strings"));
            return;
        };
        let Ok(version) = value.parse::<McpProtocolVersion>() else {
            errors.push(format!(
                "{loc}: mcp.versions contains an unsupported protocol version"
            ));
            return;
        };
        versions.push(version);
    }

    // Runtime ingress has already normalized the allowlist. Requiring strict
    // order here catches duplicates and bypasses that could otherwise fail
    // later by removing L7 inspection from the selected route.
    if !versions.windows(2).all(|pair| pair[0] < pair[1]) {
        errors.push(format!(
            "{loc}: mcp.versions must be unique and in canonical order"
        ));
    }
}

/// Map a supported L7 `access` preset to explicit rules for `protocol`.
///
/// Returns `None` when `access` is not `read-only`, `read-write`, or `full`.
/// Graphql and websocket presets differ from REST; all other protocols use
/// REST presets. Requires prior `validate_l7_policies` so mcp/json-rpc `access`
/// is rejected before expansion runs.
pub fn access_preset_rules(protocol: &str, access: &str) -> Option<Vec<serde_json::Value>> {
    if protocol == "graphql" {
        match access {
            "read-only" => Some(vec![graphql_rule_json("query")]),
            "read-write" => Some(vec![
                graphql_rule_json("query"),
                graphql_rule_json("mutation"),
            ]),
            "full" => Some(vec![graphql_rule_json("*")]),
            _ => None,
        }
    } else if protocol == "websocket" {
        match access {
            "read-only" => Some(vec![rule_json("GET", "**")]),
            "read-write" => Some(vec![
                rule_json("GET", "**"),
                rule_json("WEBSOCKET_TEXT", "**"),
            ]),
            "full" => Some(vec![rule_json("*", "**")]),
            _ => None,
        }
    } else {
        match access {
            "read-only" => Some(vec![
                rule_json("GET", "**"),
                rule_json("HEAD", "**"),
                rule_json("OPTIONS", "**"),
            ]),
            "read-write" => Some(vec![
                rule_json("GET", "**"),
                rule_json("HEAD", "**"),
                rule_json("OPTIONS", "**"),
                rule_json("POST", "**"),
                rule_json("PUT", "**"),
                rule_json("PATCH", "**"),
            ]),
            "full" => Some(vec![rule_json("*", "**")]),
            _ => None,
        }
    }
}

/// Expand `access` presets into explicit `rules` in the policy data.
///
/// This preprocesses the JSON data so Rego only needs to handle explicit rules.
/// Returns warnings for unsupported `access` values that were ignored.
///
/// Unsupported preset detection lives here rather than in `validate_l7_policies`
/// so supported presets stay defined only in `access_preset_rules`.
pub fn expand_access_presets(data: &mut serde_json::Value) -> Vec<String> {
    let mut warnings = Vec::new();
    let Some(policies) = data
        .get_mut("network_policies")
        .and_then(|v| v.as_object_mut())
    else {
        return warnings;
    };

    for (name, policy) in policies.iter_mut() {
        let Some(endpoints) = policy.get_mut("endpoints").and_then(|v| v.as_array_mut()) else {
            continue;
        };

        for (i, ep) in endpoints.iter_mut().enumerate() {
            let protocol = ep
                .get("protocol")
                .and_then(|v| v.as_str())
                .unwrap_or("rest");
            let has_rules = ep
                .get("rules")
                .and_then(|v| v.as_array())
                .is_some_and(|a| !a.is_empty());
            let access = ep
                .get("access")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let mcp_allow_all_known_mcp_methods = ep
                .get("mcp_allow_all_known_mcp_methods")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);

            if protocol == "mcp"
                && access.is_empty()
                && !has_rules
                && mcp_allow_all_known_mcp_methods
            {
                ep.as_object_mut().unwrap().insert(
                    "rules".to_string(),
                    serde_json::Value::Array(vec![jsonrpc_rule_json("*")]),
                );
                continue;
            }

            if access.is_empty() {
                continue;
            }

            // Don't expand if rules already exist (validation will catch this)
            if has_rules {
                continue;
            }

            let Some(rules) = access_preset_rules(protocol, &access) else {
                let loc = format!("{name}.endpoints[{i}]");
                let warning = format!(
                    "{loc}: unsupported L7 access preset '{access}' ignored; expected one of: read-only, read-write, full"
                );
                warnings.push(warning);
                continue;
            };

            ep.as_object_mut()
                .unwrap()
                .insert("rules".to_string(), serde_json::Value::Array(rules));
        }
    }

    warnings
}

pub fn rule_json(method: &str, path: &str) -> serde_json::Value {
    serde_json::json!({
        "allow": {
            "method": method,
            "path": path
        }
    })
}

pub fn jsonrpc_rule_json(method: &str) -> serde_json::Value {
    serde_json::json!({
        "allow": {
            "method": method
        }
    })
}

pub fn valid_methods_for_protocol(protocol: &str) -> &'static [&'static str] {
    match protocol {
        "websocket" => &["GET", "WEBSOCKET_TEXT", "*"],
        _ => &[
            "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "*",
        ],
    }
}

pub fn graphql_rule_json(operation_type: &str) -> serde_json::Value {
    serde_json::json!({
        "allow": {
            "operation_type": operation_type
        }
    })
}

pub fn jsonrpc_policy_input(info: &jsonrpc::JsonRpcRequestInfo) -> serde_json::Value {
    let call = if info.is_batch {
        None
    } else {
        info.calls.first()
    };
    serde_json::json!({
        "method": call.map(|call| call.method.as_str()),
        "params": call.map(|call| &call.params),
        "tool": call.and_then(|call| call.tool.as_deref()),
        "mcp_method_classification": call
            .and_then(|call| call.mcp_classification),
        "receive_stream": info.receive_stream,
        "has_response": info.has_response,
        // Rust keeps the inspection failure kind typed. Rego's stable boundary is
        // still the original diagnostic string or null.
        "error": info
            .error
            .as_ref()
            .map(jsonrpc::JsonRpcInspectionError::detail),
    })
}

pub fn l7_request_policy_input(
    ctx: &crate::L7PolicyContext,
    request: &L7RequestInfo,
) -> serde_json::Value {
    serde_json::json!({
        "network": { "host": ctx.host, "port": ctx.port },
        "exec": {
            "path": ctx.binary_path,
            "ancestors": ctx.ancestors,
            "cmdline_paths": ctx.cmdline_paths,
        },
        "request": {
            "method": request.action,
            "path": request.target,
            "query_params": request.query_params.clone(),
            "graphql": request.graphql.clone(),
            "jsonrpc": request.jsonrpc.as_ref().map(jsonrpc_policy_input),
        }
    })
}
