// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! L7 protocol-aware inspection for the CONNECT proxy.
//!
//! When an endpoint is configured with a `protocol` field (e.g. `rest`, `sql`),
//! the proxy inspects application-layer traffic within the tunnel instead of
//! doing a raw `copy_bidirectional`. Each request within the tunnel is parsed,
//! evaluated against OPA policy, and either forwarded or denied.

pub mod graphql;
pub(crate) mod http;
pub mod inference;
pub mod jsonrpc;
pub mod path;
pub mod provider;
pub mod relay;
pub mod rest;
pub mod tls;
pub(crate) mod token_grant_injection;
pub(crate) mod websocket;

/// Application-layer protocol for L7 inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L7Protocol {
    Rest,
    Websocket,
    Graphql,
    Sql,
    JsonRpc,
    Mcp,
}

impl L7Protocol {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "rest" => Some(Self::Rest),
            "websocket" => Some(Self::Websocket),
            "graphql" => Some(Self::Graphql),
            "sql" => Some(Self::Sql),
            "json-rpc" => Some(Self::JsonRpc),
            "mcp" => Some(Self::Mcp),
            _ => None,
        }
    }

    pub fn is_jsonrpc_family(self) -> bool {
        matches!(self, Self::JsonRpc | Self::Mcp)
    }
}

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

/// Parse an L7 endpoint config from a regorus Value (returned by Rego query).
///
/// The value is expected to be the raw endpoint object from the Rego data,
/// containing fields: `protocol`, optionally `tls`, `enforcement`.
pub fn parse_l7_config(val: &regorus::Value) -> Option<L7EndpointConfig> {
    let protocol_val = get_object_str(val, "protocol")?;
    let protocol = L7Protocol::parse(&protocol_val)?;

    let tls = match get_object_str(val, "tls").as_deref() {
        Some("skip") => TlsMode::Skip,
        Some("terminate") => {
            let event = openshell_ocsf::NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(openshell_ocsf::ActivityId::Other)
                .severity(openshell_ocsf::SeverityId::Medium)
                .message(
                    "'tls: terminate' is deprecated; TLS termination is now automatic. \
                     Use 'tls: skip' to explicitly disable. This field will be removed in a future version.",
                )
                .build();
            openshell_ocsf::ocsf_emit!(event);
            TlsMode::Auto
        }
        Some("passthrough") => {
            let event = openshell_ocsf::NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(openshell_ocsf::ActivityId::Other)
                .severity(openshell_ocsf::SeverityId::Medium)
                .message(
                    "'tls: passthrough' is deprecated; TLS termination is now automatic. \
                     Use 'tls: skip' to explicitly disable. This field will be removed in a future version.",
                )
                .build();
            openshell_ocsf::ocsf_emit!(event);
            TlsMode::Auto
        }
        _ => TlsMode::Auto,
    };

    let enforcement = match get_object_str(val, "enforcement").as_deref() {
        Some("enforce") => EnforcementMode::Enforce,
        _ => EnforcementMode::Audit,
    };

    let allow_encoded_slash = get_object_bool(val, "allow_encoded_slash").unwrap_or(false);
    let websocket_credential_rewrite =
        get_object_bool(val, "websocket_credential_rewrite").unwrap_or(false);
    let request_body_credential_rewrite =
        get_object_bool(val, "request_body_credential_rewrite").unwrap_or(false);
    let websocket_graphql_policy =
        protocol == L7Protocol::Websocket && endpoint_has_graphql_policy(val);
    let graphql_max_body_bytes = get_object_u64(val, "graphql_max_body_bytes")
        .and_then(|v| usize::try_from(v).ok())
        .filter(|v| *v > 0)
        .unwrap_or(graphql::DEFAULT_MAX_BODY_BYTES);
    let json_rpc_max_body_bytes = get_object_u64(val, "json_rpc_max_body_bytes")
        .and_then(|v| usize::try_from(v).ok())
        .filter(|v| *v > 0)
        .unwrap_or(jsonrpc::DEFAULT_MAX_BODY_BYTES);
    let mcp_strict_tool_names = protocol == L7Protocol::Mcp
        && get_object_bool(val, "mcp_strict_tool_names").unwrap_or(true);

    let credential_signing = match get_object_str(val, "credential_signing").as_deref() {
        Some("sigv4") => CredentialSigning::SigV4,
        Some("sigv4:body") => CredentialSigning::SigV4Body,
        Some("sigv4:no_body") => CredentialSigning::SigV4NoBody,
        Some(other) if !other.is_empty() => {
            let event = openshell_ocsf::NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(openshell_ocsf::ActivityId::Other)
                .severity(openshell_ocsf::SeverityId::High)
                .message(format!(
                    "rejecting endpoint: unrecognized credential_signing value {other:?}"
                ))
                .build();
            openshell_ocsf::ocsf_emit!(event);
            return None;
        }
        _ => CredentialSigning::None,
    };

    let signing_service = get_object_str(val, "signing_service").unwrap_or_default();
    let signing_region = get_object_str(val, "signing_region").unwrap_or_default();

    if credential_signing.is_sigv4() && signing_service.is_empty() {
        let event = openshell_ocsf::NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .activity(openshell_ocsf::ActivityId::Other)
            .severity(openshell_ocsf::SeverityId::High)
            .message("rejecting endpoint: credential_signing requires signing_service".to_string())
            .build();
        openshell_ocsf::ocsf_emit!(event);
        return None;
    }

    Some(L7EndpointConfig {
        protocol,
        path: get_object_str(val, "path").unwrap_or_default(),
        tls,
        enforcement,
        graphql_max_body_bytes,
        json_rpc_max_body_bytes,
        mcp_strict_tool_names,
        allow_encoded_slash,
        websocket_credential_rewrite,
        request_body_credential_rewrite,
        websocket_graphql_policy,
        credential_signing,
        signing_service,
        signing_region,
    })
}

impl L7EndpointConfig {
    pub fn matches_path(&self, path: &str) -> bool {
        endpoint_path_matches(&self.path, path)
    }

    pub fn path_specificity(&self) -> usize {
        if self.path.is_empty() {
            0
        } else {
            self.path.chars().filter(|c| *c != '*').count()
        }
    }
}

pub fn endpoint_path_matches(pattern: &str, path: &str) -> bool {
    if pattern.is_empty() || pattern == "**" || pattern == "/**" {
        return true;
    }
    if pattern == path {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    glob::Pattern::new(pattern).is_ok_and(|glob| glob.matches(path))
}

/// Parse the `tls` field from an endpoint config, independent of L7 protocol.
///
/// Used to check for `tls: skip` even on L4-only endpoints (no `protocol`
/// field) that explicitly opt out of TLS auto-detection.
pub fn parse_tls_mode(val: &regorus::Value) -> TlsMode {
    match get_object_str(val, "tls").as_deref() {
        Some("skip") => TlsMode::Skip,
        // "terminate" and "passthrough" are deprecated aliases (logged by parse_l7_config); fall through to Auto.
        _ => TlsMode::Auto,
    }
}

/// Extract a bool value from a regorus object. Returns `None` when the key
/// is absent or not a boolean.
fn get_object_bool(val: &regorus::Value, key: &str) -> Option<bool> {
    let key_val = regorus::Value::String(key.into());
    match val {
        regorus::Value::Object(map) => match map.get(&key_val) {
            Some(regorus::Value::Bool(b)) => Some(*b),
            _ => None,
        },
        _ => None,
    }
}

fn get_object_u64(val: &regorus::Value, key: &str) -> Option<u64> {
    let key_val = regorus::Value::String(key.into());
    match val {
        regorus::Value::Object(map) => match map.get(&key_val) {
            Some(regorus::Value::Number(n)) => n.as_u64(),
            _ => None,
        },
        _ => None,
    }
}

/// Extract a string value from a regorus object.
fn get_object_str(val: &regorus::Value, key: &str) -> Option<String> {
    let key_val = regorus::Value::String(key.into());
    match val {
        regorus::Value::Object(map) => match map.get(&key_val) {
            Some(regorus::Value::String(s)) => {
                let s = s.to_string();
                if s.is_empty() { None } else { Some(s) }
            }
            _ => None,
        },
        _ => None,
    }
}

fn endpoint_has_graphql_policy(val: &regorus::Value) -> bool {
    has_non_empty_object_field(val, "graphql_persisted_queries")
        || has_graphql_persisted_query_mode(val)
        || rules_have_graphql_policy(val, "rules", true)
        || rules_have_graphql_policy(val, "deny_rules", false)
}

fn rules_have_graphql_policy(val: &regorus::Value, key: &str, allow_wrapped: bool) -> bool {
    let Some(regorus::Value::Array(rules)) = get_object_value(val, key) else {
        return false;
    };
    rules.iter().any(|rule| {
        let rule = if allow_wrapped {
            get_object_value(rule, "allow").unwrap_or(rule)
        } else {
            rule
        };
        has_graphql_rule_fields(rule)
    })
}

fn has_graphql_rule_fields(val: &regorus::Value) -> bool {
    has_non_empty_string_field(val, "operation_type")
        || has_non_empty_string_field(val, "operation_name")
        || has_non_empty_array_field(val, "fields")
}

fn has_non_empty_string_field(val: &regorus::Value, key: &str) -> bool {
    matches!(get_object_value(val, key), Some(regorus::Value::String(s)) if !s.is_empty())
}

fn has_non_empty_array_field(val: &regorus::Value, key: &str) -> bool {
    matches!(get_object_value(val, key), Some(regorus::Value::Array(values)) if !values.is_empty())
}

fn has_non_empty_object_field(val: &regorus::Value, key: &str) -> bool {
    matches!(get_object_value(val, key), Some(regorus::Value::Object(values)) if !values.is_empty())
}

fn has_graphql_persisted_query_mode(val: &regorus::Value) -> bool {
    matches!(
        get_object_value(val, "persisted_queries"),
        Some(regorus::Value::String(mode)) if !mode.is_empty() && mode.as_ref() != "deny"
    )
}

fn get_object_value<'a>(val: &'a regorus::Value, key: &str) -> Option<&'a regorus::Value> {
    let key_val = regorus::Value::String(key.into());
    match val {
        regorus::Value::Object(map) => map.get(&key_val),
        _ => None,
    }
}

/// Check a glob pattern for obvious syntax issues.
///
/// Returns `Some(warning_message)` if the pattern looks malformed.
/// OPA's `glob.match` is forgiving, so these are warnings (not errors)
/// to surface likely typos without blocking policy loading.
fn check_glob_syntax(pattern: &str) -> Option<String> {
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

fn validate_host_wildcard(errors: &mut Vec<String>, loc: &str, host: &str) {
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

fn validate_graphql_operation_type(
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

fn validate_graphql_fields(
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

fn validate_graphql_rule(
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
fn validate_matcher_map(
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
fn validate_matcher_value(
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
fn validate_jsonrpc_rule_fields(
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

fn validate_mcp_method_field(
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

fn method_matcher_matches_tools_call(method: &str) -> bool {
    method == "tools/call"
        || method == "*"
        || glob::Pattern::new(method).is_ok_and(|pattern| pattern.matches("tools/call"))
}

fn mcp_rule_has_tool_selector(rule: &serde_json::Value) -> bool {
    rule.get("tool").is_some_and(|v| !v.is_null())
        || rule
            .get("params")
            .and_then(serde_json::Value::as_object)
            .and_then(|params| params.get("name"))
            .is_some_and(|v| !v.is_null())
}

fn mcp_endpoint_has_tool_allow_selectors(ep: &serde_json::Value) -> bool {
    ep.get("rules")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|rules| {
            rules.iter().any(|rule| {
                let allow = rule.get("allow").unwrap_or(rule);
                mcp_rule_has_tool_selector(allow)
            })
        })
}

fn validate_mcp_tool_field(
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

fn validate_mcp_params_field(
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
    loc: &str,
    rule: &serde_json::Value,
    has_tool: bool,
    mcp_strict_tool_names: bool,
) {
    let Some(params) = rule.get("params").filter(|v| !v.is_null()) else {
        return;
    };
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

fn validate_mcp_tool_name_wildcard_policy(
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

fn matcher_uses_glob_wildcard(matcher: &serde_json::Value) -> bool {
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

fn glob_uses_wildcard(glob: &str) -> bool {
    glob.bytes()
        .any(|b| matches!(b, b'*' | b'?' | b'[' | b']' | b'{' | b'}'))
}

fn json_rule_has_graphql_fields(rule: &serde_json::Value) -> bool {
    rule.get("operation_type")
        .and_then(|v| v.as_str())
        .is_some_and(|v| !v.is_empty())
        || rule
            .get("operation_name")
            .and_then(|v| v.as_str())
            .is_some_and(|v| !v.is_empty())
        || rule.get("fields").is_some()
}

fn json_rule_has_transport_fields(rule: &serde_json::Value) -> bool {
    rule.get("method").is_some() || rule.get("path").is_some() || rule.get("query").is_some()
}

fn json_rule_has_non_empty_path_or_query(rule: &serde_json::Value) -> bool {
    rule.get("path")
        .and_then(|v| v.as_str())
        .is_some_and(|v| !v.is_empty())
        || rule
            .get("query")
            .and_then(|v| v.as_object())
            .is_some_and(|v| !v.is_empty())
}

fn json_endpoint_has_graphql_policy(ep: &serde_json::Value) -> bool {
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

            // rules + access mutual exclusion
            if has_rules && !access.is_empty() {
                errors.push(format!("{loc}: rules and access are mutually exclusive"));
            }

            if jsonrpc_family && !access.is_empty() {
                if protocol == "mcp" {
                    errors.push(format!(
                        "{loc}: protocol {protocol} does not support access presets; use rules/deny_rules or set mcp.allow_all_known_mcp_methods: true for an allow-all MCP policy"
                    ));
                } else {
                    errors.push(format!(
                        "{loc}: protocol {protocol} does not support access presets; use explicit rules with allow.method such as \"*\""
                    ));
                }
            }

            if protocol == "json-rpc" && !has_rules {
                errors.push(format!(
                    "{loc}: protocol {protocol} requires explicit rules with allow.method"
                ));
            }

            // protocol requires rules or access
            if !protocol.is_empty() && protocol != "mcp" && !has_rules && access.is_empty() {
                errors.push(format!(
                    "{loc}: protocol requires rules or access to define allowed traffic"
                ));
            }

            if !protocol.is_empty() && l7_protocol.is_none() {
                errors.push(format!(
                    "{loc}: unknown protocol '{protocol}' (expected rest, websocket, graphql, sql, json-rpc, or mcp)"
                ));
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
            let mcp_allow_all_known_mcp_methods = ep
                .get("mcp_allow_all_known_mcp_methods")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if protocol == "mcp"
                && !has_rules
                && access.is_empty()
                && !mcp_allow_all_known_mcp_methods
            {
                errors.push(format!(
                    "{loc}: protocol mcp requires rules when mcp.allow_all_known_mcp_methods is false"
                ));
            }

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

            // Deprecated tls values: warn but don't error
            if tls == "terminate" || tls == "passthrough" {
                warnings.push(format!(
                    "{loc}: 'tls: {tls}' is deprecated; TLS termination is now automatic. Use 'tls: skip' to disable."
                ));
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

            // rules with empty list
            if ep
                .get("rules")
                .and_then(|v| v.as_array())
                .is_some_and(Vec::is_empty)
            {
                errors.push(format!(
                    "{loc}: rules list cannot be empty (would deny all traffic). Use `access: full` or remove rules."
                ));
            }

            // port 443 + rest + tls: skip — L7 won't work (already handled above)
            // The old warning about missing `tls: terminate` is no longer needed
            // because TLS termination is now automatic.

            // Validate deny_rules
            let has_deny_rules = ep
                .get("deny_rules")
                .and_then(|v| v.as_array())
                .is_some_and(|a| !a.is_empty());
            if has_deny_rules {
                // deny_rules require L7 inspection
                if protocol.is_empty() {
                    errors.push(format!(
                        "{loc}: deny_rules require protocol (L7 inspection must be enabled)"
                    ));
                }

                // deny_rules require some allow base (access or rules)
                if protocol != "mcp" && !has_rules && access.is_empty() {
                    errors.push(format!(
                        "{loc}: deny_rules require rules or access to define the base allow set"
                    ));
                }

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
                    if has_mcp_tool_allow_selectors
                        && allow
                            .get("method")
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(method_matcher_matches_tools_call)
                        && !mcp_rule_has_tool_selector(allow)
                    {
                        errors.push(format!(
                            "{rule_loc}: method matcher allows every tool call and conflicts with MCP tool allow rules; add tool or params.name to narrow tools/call, or remove the tool allow rules"
                        ));
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

/// Expand `access` presets into explicit `rules` in the policy data.
///
/// This preprocesses the JSON data so Rego only needs to handle explicit rules.
pub fn expand_access_presets(data: &mut serde_json::Value) {
    let Some(policies) = data
        .get_mut("network_policies")
        .and_then(|v| v.as_object_mut())
    else {
        return;
    };

    for (_name, policy) in policies.iter_mut() {
        let Some(endpoints) = policy.get_mut("endpoints").and_then(|v| v.as_array_mut()) else {
            continue;
        };

        for ep in endpoints.iter_mut() {
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

            let rules = if protocol == "graphql" {
                match access.as_str() {
                    "read-only" => vec![graphql_rule_json("query")],
                    "read-write" => vec![graphql_rule_json("query"), graphql_rule_json("mutation")],
                    "full" => vec![graphql_rule_json("*")],
                    _ => continue,
                }
            } else if protocol == "websocket" {
                match access.as_str() {
                    "read-only" => vec![rule_json("GET", "**")],
                    "read-write" => vec![rule_json("GET", "**"), rule_json("WEBSOCKET_TEXT", "**")],
                    "full" => vec![rule_json("*", "**")],
                    _ => continue,
                }
            } else {
                match access.as_str() {
                    "read-only" => vec![
                        rule_json("GET", "**"),
                        rule_json("HEAD", "**"),
                        rule_json("OPTIONS", "**"),
                    ],
                    "read-write" => vec![
                        rule_json("GET", "**"),
                        rule_json("HEAD", "**"),
                        rule_json("OPTIONS", "**"),
                        rule_json("POST", "**"),
                        rule_json("PUT", "**"),
                        rule_json("PATCH", "**"),
                    ],
                    "full" => vec![rule_json("*", "**")],
                    _ => continue,
                }
            };

            ep.as_object_mut()
                .unwrap()
                .insert("rules".to_string(), serde_json::Value::Array(rules));
        }
    }
}

fn rule_json(method: &str, path: &str) -> serde_json::Value {
    serde_json::json!({
        "allow": {
            "method": method,
            "path": path
        }
    })
}

fn jsonrpc_rule_json(method: &str) -> serde_json::Value {
    serde_json::json!({
        "allow": {
            "method": method
        }
    })
}

fn valid_methods_for_protocol(protocol: &str) -> &'static [&'static str] {
    match protocol {
        "websocket" => &["GET", "WEBSOCKET_TEXT", "*"],
        _ => &[
            "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "*",
        ],
    }
}

fn graphql_rule_json(operation_type: &str) -> serde_json::Value {
    serde_json::json!({
        "allow": {
            "operation_type": operation_type
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_l7_config_rest_enforce() {
        let val = regorus::Value::from_json_str(
            r#"{"protocol": "rest", "tls": "terminate", "enforcement": "enforce", "host": "api.example.com", "port": 443}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert_eq!(config.protocol, L7Protocol::Rest);
        // "terminate" is deprecated and treated as Auto.
        assert_eq!(config.tls, TlsMode::Auto);
        assert_eq!(config.enforcement, EnforcementMode::Enforce);
    }

    #[test]
    fn parse_l7_config_defaults() {
        let val = regorus::Value::from_json_str(
            r#"{"protocol": "rest", "host": "api.example.com", "port": 80}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert_eq!(config.protocol, L7Protocol::Rest);
        assert_eq!(config.tls, TlsMode::Auto);
        assert_eq!(config.enforcement, EnforcementMode::Audit);
    }

    #[test]
    fn parse_credential_signing_sigv4() {
        let val = regorus::Value::from_json_str(
            r#"{"protocol": "rest", "credential_signing": "sigv4", "signing_service": "bedrock", "host": "bedrock.us-east-1.amazonaws.com", "port": 443}"#,
        ).unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert_eq!(config.credential_signing, CredentialSigning::SigV4);
        assert!(config.credential_signing.is_sigv4());
    }

    #[test]
    fn parse_credential_signing_sigv4_body() {
        let val = regorus::Value::from_json_str(
            r#"{"protocol": "rest", "credential_signing": "sigv4:body", "signing_service": "bedrock", "host": "bedrock.us-east-1.amazonaws.com", "port": 443}"#,
        ).unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert_eq!(config.credential_signing, CredentialSigning::SigV4Body);
        assert!(config.credential_signing.is_sigv4());
    }

    #[test]
    fn parse_credential_signing_sigv4_no_body() {
        let val = regorus::Value::from_json_str(
            r#"{"protocol": "rest", "credential_signing": "sigv4:no_body", "signing_service": "s3", "host": "s3.us-east-1.amazonaws.com", "port": 443}"#,
        ).unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert_eq!(config.credential_signing, CredentialSigning::SigV4NoBody);
        assert!(config.credential_signing.is_sigv4());
    }

    #[test]
    fn is_sigv4_false_for_none() {
        assert!(!CredentialSigning::None.is_sigv4());
    }

    #[test]
    fn parse_l7_config_websocket_protocol() {
        let val = regorus::Value::from_json_str(
            r#"{"protocol": "websocket", "host": "gateway.example.com", "port": 443}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert_eq!(config.protocol, L7Protocol::Websocket);
    }

    #[test]
    fn parse_l7_config_skip() {
        let val = regorus::Value::from_json_str(
            r#"{"protocol": "rest", "tls": "skip", "host": "api.example.com", "port": 443}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert_eq!(config.tls, TlsMode::Skip);
    }

    #[test]
    fn parse_l7_config_no_protocol() {
        let val =
            regorus::Value::from_json_str(r#"{"host": "api.example.com", "port": 443}"#).unwrap();
        assert!(parse_l7_config(&val).is_none());
    }

    #[test]
    fn parse_l7_config_allow_encoded_slash_defaults_false() {
        let val = regorus::Value::from_json_str(
            r#"{"protocol": "rest", "host": "api.example.com", "port": 443}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert!(!config.allow_encoded_slash);
    }

    #[test]
    fn parse_l7_config_allow_encoded_slash_opt_in() {
        let val = regorus::Value::from_json_str(
            r#"{"protocol": "rest", "host": "gitlab.example.com", "port": 443, "allow_encoded_slash": true}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert!(config.allow_encoded_slash);
    }

    #[test]
    fn parse_l7_config_mcp_strict_tool_names_defaults_true() {
        let val = regorus::Value::from_json_str(
            r#"{"protocol": "mcp", "host": "mcp.example.com", "port": 443}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert!(config.mcp_strict_tool_names);
    }

    #[test]
    fn parse_l7_config_mcp_strict_tool_names_can_disable() {
        let val = regorus::Value::from_json_str(
            r#"{"protocol": "mcp", "host": "mcp.example.com", "port": 443, "mcp_strict_tool_names": false}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert!(!config.mcp_strict_tool_names);
    }

    #[test]
    fn parse_l7_config_websocket_credential_rewrite_defaults_false() {
        let val = regorus::Value::from_json_str(
            r#"{"protocol": "rest", "host": "gateway.example.com", "port": 443}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert!(!config.websocket_credential_rewrite);
    }

    #[test]
    fn parse_l7_config_websocket_credential_rewrite_opt_in() {
        let val = regorus::Value::from_json_str(
            r#"{"protocol": "rest", "host": "gateway.example.com", "port": 443, "websocket_credential_rewrite": true}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert!(config.websocket_credential_rewrite);
    }

    #[test]
    fn parse_l7_config_request_body_credential_rewrite_defaults_false() {
        let val = regorus::Value::from_json_str(
            r#"{"protocol": "rest", "host": "slack.com", "port": 443}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert!(!config.request_body_credential_rewrite);
    }

    #[test]
    fn parse_l7_config_request_body_credential_rewrite_opt_in() {
        let val = regorus::Value::from_json_str(
            r#"{"protocol": "rest", "host": "slack.com", "port": 443, "request_body_credential_rewrite": true}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert!(config.request_body_credential_rewrite);
    }

    #[test]
    fn parse_l7_config_websocket_graphql_policy_defaults_false() {
        let val = regorus::Value::from_json_str(
            r#"{"protocol": "websocket", "host": "gateway.example.com", "port": 443, "rules": [{"allow": {"method": "GET", "path": "/graphql"}}, {"allow": {"method": "WEBSOCKET_TEXT", "path": "/graphql"}}]}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert!(!config.websocket_graphql_policy);
    }

    #[test]
    fn parse_l7_config_websocket_graphql_policy_detects_operation_rules() {
        let val = regorus::Value::from_json_str(
            r#"{"protocol": "websocket", "host": "gateway.example.com", "port": 443, "rules": [{"allow": {"method": "GET", "path": "/graphql"}}, {"allow": {"operation_type": "subscription", "fields": ["messageAdded"]}}]}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert!(config.websocket_graphql_policy);
    }

    #[test]
    fn validate_websocket_credential_rewrite_warns_unless_rest_or_websocket() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "gateway.example.com",
                        "port": 443,
                        "websocket_credential_rewrite": true
                    }],
                    "binaries": []
                }
            }
        });
        let (_errors, warnings) = validate_l7_policies(&data);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("websocket_credential_rewrite is ignored")),
            "expected websocket_credential_rewrite warning: {warnings:?}"
        );
    }

    #[test]
    fn validate_request_body_credential_rewrite_warns_unless_rest() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "gateway.example.com",
                        "port": 443,
                        "protocol": "websocket",
                        "request_body_credential_rewrite": true
                    }],
                    "binaries": []
                }
            }
        });
        let (_errors, warnings) = validate_l7_policies(&data);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("request_body_credential_rewrite is ignored")),
            "expected request_body_credential_rewrite warning: {warnings:?}"
        );
    }

    #[test]
    fn expand_websocket_read_write_access_includes_text_messages() {
        let mut data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "gateway.example.com",
                        "port": 443,
                        "protocol": "websocket",
                        "access": "read-write"
                    }],
                    "binaries": []
                }
            }
        });

        expand_access_presets(&mut data);
        let rules = data["network_policies"]["test"]["endpoints"][0]["rules"]
            .as_array()
            .unwrap();
        let methods: Vec<&str> = rules
            .iter()
            .map(|r| r["allow"]["method"].as_str().unwrap())
            .collect();
        assert!(methods.contains(&"GET"));
        assert!(methods.contains(&"WEBSOCKET_TEXT"));
    }

    #[test]
    fn validate_websocket_accepts_graphql_operation_rules() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "gateway.example.com",
                        "port": 443,
                        "protocol": "websocket",
                        "rules": [
                            {"allow": {"method": "GET", "path": "/graphql"}},
                            {"allow": {"operation_type": "subscription", "fields": ["messageAdded"]}}
                        ]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(errors.is_empty(), "expected no errors: {errors:?}");
        assert!(warnings.is_empty(), "expected no warnings: {warnings:?}");
    }

    #[test]
    fn validate_websocket_graphql_rule_requires_operation_type() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "gateway.example.com",
                        "port": 443,
                        "protocol": "websocket",
                        "rules": [
                            {"allow": {"method": "GET", "path": "/graphql"}},
                            {"allow": {"fields": ["messageAdded"]}}
                        ]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("operation_type")),
            "expected missing operation_type error: {errors:?}"
        );
    }

    #[test]
    fn validate_websocket_graphql_rule_rejects_mixed_transport_fields() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "gateway.example.com",
                        "port": 443,
                        "protocol": "websocket",
                        "rules": [
                            {"allow": {"method": "GET", "path": "/graphql"}},
                            {"allow": {"method": "WEBSOCKET_TEXT", "path": "/graphql", "operation_type": "subscription"}}
                        ]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("must not combine")),
            "expected mixed-field error: {errors:?}"
        );
    }

    #[test]
    fn validate_websocket_graphql_policy_rejects_raw_text_message_rule() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "gateway.example.com",
                        "port": 443,
                        "protocol": "websocket",
                        "rules": [
                            {"allow": {"method": "GET", "path": "/graphql"}},
                            {"allow": {"method": "WEBSOCKET_TEXT", "path": "/graphql"}},
                            {"allow": {"operation_type": "query"}}
                        ]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("instead of WEBSOCKET_TEXT")),
            "expected raw WEBSOCKET_TEXT rejection: {errors:?}"
        );
    }

    #[test]
    fn validate_rules_and_access_mutual_exclusion() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "rest",
                        "access": "read-only",
                        "rules": [{"allow": {"method": "GET", "path": "**"}}]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(errors.iter().any(|e| e.contains("mutually exclusive")));
    }

    #[test]
    fn validate_jsonrpc_rejects_access_presets() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "jsonrpc.example.com",
                        "port": 443,
                        "path": "/rpc",
                        "protocol": "json-rpc",
                        "access": "full"
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| {
                e.contains("json-rpc")
                    && e.contains("does not support access presets")
                    && e.contains("method")
            }),
            "JSON-RPC access presets should be rejected: {errors:?}"
        );
    }

    #[test]
    fn validate_jsonrpc_requires_method_rules() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "jsonrpc.example.com",
                        "port": 443,
                        "path": "/rpc",
                        "protocol": "json-rpc",
                        "rules": [{
                            "allow": {
                                "path": "/rpc"
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| { e.contains("rules[0].allow.method") && e.contains("required") }),
            "JSON-RPC allow rules without method should be rejected: {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| { e.contains("must use method, not path/query") }),
            "JSON-RPC allow rules with path/query should be rejected: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_tool_selectors_use_endpoint_method_profile_and_reject_arguments() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "mcp.example.com",
                        "port": 443,
                        "path": "/mcp",
                        "protocol": "mcp",
                        "mcp_allow_all_known_mcp_methods": true,
                        "rules": [{
                            "allow": {
                                "tool": { "any": ["read_status", "submit_*"] }
                            }
                        }, {
                            "allow": {
                                "method": "tools/call",
                                "tool": "submit_report",
                                "params": {
                                    "arguments": {
                                        "scope": "workspace/main"
                                    }
                                }
                            }
                        }, {
                            "allow": {
                                "method": "initialize"
                            }
                        }, {
                            "allow": {
                                "method": "tools/call",
                                "tool": "list_reports"
                            }
                        }],
                        "deny_rules": [{
                            "tool": "delete_*"
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            !errors
                .iter()
                .any(|e| e.contains("rules[0].allow.method") && e.contains("required")),
            "MCP tool rules can omit method while allow_all_known_mcp_methods is enabled: {errors:?}"
        );
        assert!(
            errors.iter().any(|e| {
                e.contains("rules[1].allow.params.arguments")
                    && e.contains("argument matching is not supported")
            }),
            "MCP argument params should be rejected: {errors:?}"
        );
        assert!(
            !errors.iter().any(|e| e.contains("rules[2].allow.method")),
            "MCP method-only rules should not require a tool selector: {errors:?}"
        );
        assert!(
            !errors.iter().any(|e| e.contains("rules[3].allow.method")),
            "MCP tool rules with method: tools/call should validate: {errors:?}"
        );
        assert!(
            !errors
                .iter()
                .any(|e| e.contains("deny_rules[0].method") && e.contains("tools/call")),
            "MCP deny tool rules can omit method while allow_all_known_mcp_methods is enabled: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_tool_selectors_require_method_by_default() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "mcp.example.com",
                        "port": 443,
                        "path": "/mcp",
                        "protocol": "mcp",
                        "rules": [{
                            "allow": {
                                "tool": "read_status"
                            }
                        }],
                        "deny_rules": [{
                            "tool": "delete_*"
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| {
                e.contains("rules[0].allow.method")
                    && e.contains("mcp.allow_all_known_mcp_methods is false")
            }),
            "MCP allow tool rules should require method when method profile is disabled: {errors:?}"
        );
        assert!(
            errors.iter().any(|e| {
                e.contains("deny_rules[0].method")
                    && e.contains("mcp.allow_all_known_mcp_methods is false")
            }),
            "MCP deny tool rules should require method when method profile is disabled: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_method_globs_are_tools_family_only() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "mcp.example.com",
                        "port": 443,
                        "path": "/mcp",
                        "protocol": "mcp",
                        "rules": [{
                            "allow": {
                                "method": "vendor/extension"
                            }
                        }, {
                            "allow": {
                                "method": "vendor/*"
                            }
                        }, {
                            "allow": {
                                "method": "*"
                            }
                        }, {
                            "allow": {
                                "method": "tools/*"
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            !errors.iter().any(|e| e.contains("rules[0].allow.method")),
            "literal extension methods should stay addressable: {errors:?}"
        );
        assert!(
            errors.iter().any(|e| {
                e.contains("rules[1].allow.method")
                    && e.contains("only valid for the tools/ method family")
            }),
            "non-tools method globs should be rejected: {errors:?}"
        );
        assert!(
            errors.iter().any(|e| {
                e.contains("rules[2].allow.method")
                    && e.contains("only valid for the tools/ method family")
            }),
            "authored method: * should be rejected for MCP: {errors:?}"
        );
        assert!(
            !errors.iter().any(|e| e.contains("rules[3].allow.method")),
            "tools-family method globs should validate: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_wildcard_tool_requires_strict_tool_names() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "mcp.example.com",
                        "port": 443,
                        "path": "/mcp",
                        "protocol": "mcp",
                        "mcp_strict_tool_names": false,
                        "rules": [{
                            "allow": {
                                "method": "tools/call",
                                "tool": "read_*"
                            }
                        }, {
                            "allow": {
                                "method": "tools/call",
                                "params": {
                                    "name": { "any": ["safe_tool", "list_*"] }
                                }
                            }
                        }],
                        "deny_rules": [{
                            "method": "tools/call",
                            "tool": "delete_resource"
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| {
                e.contains("rules[0].allow.tool")
                    && e.contains("strict_tool_names to remain enabled")
            }),
            "wildcard tool aliases should require strict tool names: {errors:?}"
        );
        assert!(
            errors.iter().any(|e| {
                e.contains("rules[1].allow.params.name")
                    && e.contains("strict_tool_names to remain enabled")
            }),
            "wildcard params.name should require strict tool names: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_protocol_requires_endpoint_target() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "protocol": "mcp"
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("protocol mcp requires host")),
            "MCP protocol-only endpoint should require host: {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("protocol mcp requires port or ports")),
            "MCP protocol-only endpoint should require port: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_broad_tools_call_deny_rejects_tool_allow_rules() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "mcp.example.com",
                        "port": 443,
                        "path": "/mcp",
                        "protocol": "mcp",
                        "rules": [{
                            "allow": {
                                "method": "tools/call",
                                "tool": "read_status"
                            }
                        }],
                        "deny_rules": [{
                            "method": "tools/call"
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| {
                e.contains("deny_rules[0]")
                    && e.contains("denies every tool call")
                    && e.contains("conflicts with MCP tool allow rules")
            }),
            "broad tools/call deny should reject tool allow rules with a reason: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_broad_tools_call_allow_rejects_tool_allow_rules() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "mcp.example.com",
                        "port": 443,
                        "path": "/mcp",
                        "protocol": "mcp",
                        "rules": [{
                            "allow": {
                                "method": "tools/*"
                            }
                        }, {
                            "allow": {
                                "tool": "read_status"
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| {
                e.contains("rules[0].allow")
                    && e.contains("allows every tool call")
                    && e.contains("conflicts with MCP tool allow rules")
            }),
            "broad tools/call allow should reject tool allow rules with a reason: {errors:?}"
        );
    }

    #[test]
    fn validate_jsonrpc_rejects_params_matchers() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "jsonrpc.example.com",
                        "port": 443,
                        "path": "/rpc",
                        "protocol": "json-rpc",
                        "rules": [{
                            "allow": {
                                "method": "reports.search",
                                "params": { "query": "quarterly" }
                            }
                        }],
                        "deny_rules": [{
                            "method": "reports.archive",
                            "params": { "report_id": "rpt-123" }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| { e.contains("rules[0].allow") && e.contains("do not support params") }),
            "JSON-RPC allow params should be rejected: {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| { e.contains("deny_rules[0]") && e.contains("do not support params") }),
            "JSON-RPC deny params should be rejected: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_strict_tool_names_is_mcp_only() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [
                        {
                            "host": "mcp.example.com",
                            "port": 443,
                            "path": "/mcp",
                            "protocol": "mcp",
                            "mcp_strict_tool_names": false,
                            "rules": [{ "allow": { "method": "tools/call" } }]
                        },
                        {
                            "host": "api.example.com",
                            "port": 443,
                            "protocol": "rest",
                            "mcp_strict_tool_names": false,
                            "mcp_allow_all_known_mcp_methods": true,
                            "access": "full"
                        }
                    ],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert_eq!(
            errors
                .iter()
                .filter(|error| error.contains("is only valid for protocol mcp"))
                .count(),
            2,
            "only the REST endpoint should reject MCP-specific options: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_options_require_bool() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "mcp.example.com",
                        "port": 443,
                        "path": "/mcp",
                        "protocol": "mcp",
                        "mcp_strict_tool_names": "false",
                        "mcp_allow_all_known_mcp_methods": "false",
                        "rules": [{ "allow": { "method": "tools/call" } }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("mcp.strict_tool_names must be boolean")),
            "expected bool validation error: {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("mcp.allow_all_known_mcp_methods must be boolean")),
            "expected bool validation error: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_requires_rules_by_default() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "mcp.example.com",
                        "port": 443,
                        "path": "/mcp",
                        "protocol": "mcp"
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|error| {
                error.contains("protocol mcp requires rules")
                    && error.contains("mcp.allow_all_known_mcp_methods is false")
            }),
            "expected disabled method profile to require rules: {errors:?}"
        );
    }

    #[test]
    fn validate_jsonrpc_deny_rules_require_method() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "jsonrpc.example.com",
                        "port": 443,
                        "path": "/rpc",
                        "protocol": "json-rpc",
                        "rules": [{
                            "allow": {
                                "method": "*"
                            }
                        }],
                        "deny_rules": [{
                            "params": { "name": "delete_resource" }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("deny_rules[0].method") && e.contains("required")),
            "JSON-RPC deny rules without method should be rejected: {errors:?}"
        );
    }

    #[test]
    fn validate_jsonrpc_method_rejects_globs_except_allow_all() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "jsonrpc.example.com",
                        "port": 443,
                        "path": "/rpc",
                        "protocol": "json-rpc",
                        "rules": [{
                            "allow": {
                                "method": "*"
                            }
                        }, {
                            "allow": {
                                "method": "reports.*"
                            }
                        }],
                        "deny_rules": [{
                            "method": "reports/{archive,delete}"
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            !errors.iter().any(|e| e.contains("rules[0].allow.method")),
            "JSON-RPC method: * should remain the allow-all sentinel: {errors:?}"
        );
        assert!(
            errors.iter().any(|e| {
                e.contains("rules[1].allow.method")
                    && e.contains("do not support glob or wildcard matchers")
            }),
            "JSON-RPC allow method globs should be rejected: {errors:?}"
        );
        assert!(
            errors.iter().any(|e| {
                e.contains("deny_rules[0].method")
                    && e.contains("do not support glob or wildcard matchers")
            }),
            "JSON-RPC deny method globs should be rejected: {errors:?}"
        );
    }

    #[test]
    fn validate_protocol_requires_rules_or_access() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "rest"
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("requires rules or access"))
        );
    }

    #[test]
    fn validate_sql_enforce_blocked() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "db.internal",
                        "port": 5432,
                        "protocol": "sql",
                        "enforcement": "enforce",
                        "rules": [{"allow": {"command": "SELECT"}}]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(errors.iter().any(|e| e.contains("SQL enforcement")));
    }

    #[test]
    fn validate_tls_terminate_deprecated_warning() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "tls": "terminate",
                        "protocol": "rest",
                        "access": "full"
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "deprecated tls should not error: {errors:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("deprecated")),
            "should warn about deprecated tls: {warnings:?}"
        );
    }

    #[test]
    fn validate_tls_skip_with_l7_on_443_warns() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "tls": "skip",
                        "protocol": "rest",
                        "access": "read-only"
                    }],
                    "binaries": []
                }
            }
        });
        let (_errors, warnings) = validate_l7_policies(&data);
        assert!(
            warnings.iter().any(|w| w.contains("tls: skip")),
            "should warn about skip + L7 on 443: {warnings:?}"
        );
    }

    #[test]
    fn validate_port_443_rest_no_tls_no_warning() {
        // With auto-TLS, no warning is needed for port 443 + rest without
        // explicit tls field — TLS will be auto-detected.
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "rest",
                        "access": "read-only"
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(errors.is_empty(), "should have no errors: {errors:?}");
        assert!(
            !warnings.iter().any(|w| w.contains("tls")),
            "should have no tls warnings with auto-detect: {warnings:?}"
        );
    }

    #[test]
    fn expand_read_only_preset() {
        let mut data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 80,
                        "protocol": "rest",
                        "access": "read-only"
                    }],
                    "binaries": []
                }
            }
        });
        expand_access_presets(&mut data);
        let rules = data["network_policies"]["test"]["endpoints"][0]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 3);
        let methods: Vec<&str> = rules
            .iter()
            .map(|r| r["allow"]["method"].as_str().unwrap())
            .collect();
        assert!(methods.contains(&"GET"));
        assert!(methods.contains(&"HEAD"));
        assert!(methods.contains(&"OPTIONS"));
    }

    #[test]
    fn expand_full_preset() {
        let mut data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 80,
                        "protocol": "rest",
                        "access": "full"
                    }],
                    "binaries": []
                }
            }
        });
        expand_access_presets(&mut data);
        let rules = data["network_policies"]["test"]["endpoints"][0]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["allow"]["method"].as_str().unwrap(), "*");
        assert_eq!(rules[0]["allow"]["path"].as_str().unwrap(), "**");
    }

    #[test]
    fn expand_graphql_readonly_preset() {
        let mut data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "graphql",
                        "access": "read-only"
                    }],
                    "binaries": []
                }
            }
        });
        expand_access_presets(&mut data);
        let rules = data["network_policies"]["test"]["endpoints"][0]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0]["allow"]["operation_type"].as_str().unwrap(),
            "query"
        );
    }

    #[test]
    fn validate_graphql_rule_requires_operation_type() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "graphql",
                        "rules": [{
                            "allow": {
                                "fields": ["viewer"]
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("operation_type")),
            "GraphQL rules should require operation_type: {errors:?}"
        );
    }

    #[test]
    fn validate_graphql_persisted_query_mode() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "graphql",
                        "access": "full",
                        "persisted_queries": "allow_all"
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("persisted_queries")),
            "invalid persisted query mode should be rejected: {errors:?}"
        );
    }

    #[test]
    fn l4_only_endpoint_untouched() {
        let mut data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        expand_access_presets(&mut data);
        assert!(
            data["network_policies"]["test"]["endpoints"][0]
                .get("rules")
                .is_none()
        );
    }

    // ---- Host wildcard validation tests ----

    #[test]
    fn validate_wildcard_host_star_only_error() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "*",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("matches all hosts")),
            "Bare * host should be rejected, got errors: {errors:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_double_star_only_error() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "**",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("matches all hosts")),
            "Bare ** host should be rejected, got errors: {errors:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_middle_label_star_valid_no_error() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "*.s3.*.amazonaws.com",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "*.s3.*.amazonaws.com should be valid, got errors: {errors:?}"
        );
        assert!(
            warnings.is_empty(),
            "*.s3.*.amazonaws.com should not warn, got warnings: {warnings:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_middle_label_partial_star_error() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "*.s3.us-*.amazonaws.com",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("middle DNS label wildcard")),
            "Partial middle-label wildcard should be rejected, got errors: {errors:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_middle_label_double_star_error() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "*.s3.**.amazonaws.com",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("recursive host wildcard")),
            "Middle-label ** wildcard should be rejected, got errors: {errors:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_single_label_error() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "*com",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("TLD wildcard")),
            "Single-label wildcard should be rejected, got errors: {errors:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_recursive_intra_label_error() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "foo**.example.com",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("recursive host wildcard")),
            "Recursive intra-label wildcard should be rejected, got errors: {errors:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_tld_rejected() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "*.com",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("TLD wildcard")),
            "*.com should be rejected as TLD wildcard, got errors: {errors:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_double_star_tld_rejected() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "**.org",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("TLD wildcard")),
            "**.org should be rejected as TLD wildcard, got errors: {errors:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_valid_no_error() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "*.example.com",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "*.example.com should be valid, got errors: {errors:?}"
        );
        assert!(
            warnings.is_empty(),
            "*.example.com should not warn, got warnings: {warnings:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_double_star_valid_no_error() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "**.example.com",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "**.example.com should be valid, got errors: {errors:?}"
        );
        assert!(
            warnings.is_empty(),
            "**.example.com should not warn, got warnings: {warnings:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_intra_label_valid_no_error() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "*-aiplatform.googleapis.com",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "*-aiplatform.googleapis.com should be valid, got errors: {errors:?}"
        );
        assert!(
            warnings.is_empty(),
            "*-aiplatform.googleapis.com should not warn, got warnings: {warnings:?}"
        );
    }

    #[test]
    fn validate_port_and_ports_mutually_exclusive() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "ports": [443, 8443]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("port and ports are mutually exclusive")),
            "Should reject both port and ports, got errors: {errors:?}"
        );
    }

    #[test]
    fn validate_ports_array_rest_443_no_warning() {
        // With auto-TLS, no warning needed for ports array containing 443.
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "ports": [443, 8080],
                        "protocol": "rest",
                        "access": "read-only"
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(errors.is_empty(), "should have no errors: {errors:?}");
        assert!(
            !warnings.iter().any(|w| w.contains("tls")),
            "should have no tls warnings with auto-detect: {warnings:?}"
        );
    }

    #[test]
    fn validate_query_any_requires_non_empty_array() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 8080,
                        "protocol": "rest",
                        "rules": [{
                            "allow": {
                                "method": "GET",
                                "path": "/download",
                                "query": {
                                    "tag": { "any": [] }
                                }
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("allow.query.tag.any")),
            "expected query any validation error, got: {errors:?}"
        );
    }

    #[test]
    fn validate_query_object_rejects_unknown_keys() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 8080,
                        "protocol": "rest",
                        "rules": [{
                            "allow": {
                                "method": "GET",
                                "path": "/download",
                                "query": {
                                    "tag": { "mode": "foo-*" }
                                }
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("unknown matcher keys")),
            "expected unknown query matcher key error, got: {errors:?}"
        );
    }

    #[test]
    fn validate_query_glob_warns_on_unclosed_bracket() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 8080,
                        "protocol": "rest",
                        "rules": [{
                            "allow": {
                                "method": "GET",
                                "path": "/download",
                                "query": {
                                    "tag": "[unclosed"
                                }
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "malformed glob should warn, not error: {errors:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("unclosed '['") && w.contains("allow.query.tag")),
            "expected glob syntax warning, got: {warnings:?}"
        );
    }

    #[test]
    fn validate_query_glob_warns_on_unclosed_brace() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 8080,
                        "protocol": "rest",
                        "rules": [{
                            "allow": {
                                "method": "GET",
                                "path": "/download",
                                "query": {
                                    "format": { "glob": "{json,xml" }
                                }
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "malformed glob should warn, not error: {errors:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("unclosed '{'") && w.contains("allow.query.format.glob")),
            "expected glob syntax warning, got: {warnings:?}"
        );
    }

    #[test]
    fn validate_query_any_warns_on_malformed_glob_item() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 8080,
                        "protocol": "rest",
                        "rules": [{
                            "allow": {
                                "method": "GET",
                                "path": "/download",
                                "query": {
                                    "tag": { "any": ["valid-*", "[bad"] }
                                }
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "malformed glob in any should warn, not error: {errors:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("unclosed '['") && w.contains("allow.query.tag.any")),
            "expected glob syntax warning for any item, got: {warnings:?}"
        );
    }

    #[test]
    fn validate_query_string_and_any_matchers_are_accepted() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 8080,
                        "protocol": "rest",
                        "rules": [{
                            "allow": {
                                "method": "GET",
                                "path": "/download",
                                "query": {
                                    "slug": "my-*",
                                    "tag": { "any": ["foo-*", "bar-*"] },
                                    "owner": { "glob": "org-*" }
                                }
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "valid query matcher shapes should not error: {errors:?}"
        );
    }

    #[test]
    fn validate_jsonrpc_nested_params_matchers_are_rejected() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "jsonrpc.example.com",
                        "port": 443,
                        "protocol": "json-rpc",
                        "rules": [{
                            "allow": {
                                "method": "reports.search",
                                "params": {
                                    "query": "quarterly",
                                    "filters": {
                                        "scope": "workspace/main",
                                        "repository": { "any": ["NVIDIA/OpenShell", "NVIDIA/*"] }
                                    }
                                }
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| { e.contains("rules[0].allow") && e.contains("do not support params") }),
            "JSON-RPC nested params matchers should be rejected: {errors:?}"
        );
        assert!(
            warnings.is_empty(),
            "unsupported params should not emit warnings: {warnings:?}"
        );
    }

    // --- Deny rules validation tests ---

    #[test]
    fn validate_deny_rules_require_protocol() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "deny_rules": [{ "method": "POST", "path": "/admin" }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("deny_rules require protocol")),
            "should require protocol for deny_rules: {errors:?}"
        );
    }

    #[test]
    fn validate_deny_rules_require_allow_base() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "rest",
                        "deny_rules": [{ "method": "POST", "path": "/admin" }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("deny_rules require rules or access")),
            "should require rules or access for deny_rules: {errors:?}"
        );
    }

    #[test]
    fn validate_deny_rules_empty_list_rejected() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "rest",
                        "access": "full",
                        "deny_rules": []
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("deny_rules list cannot be empty")),
            "should reject empty deny_rules: {errors:?}"
        );
    }

    #[test]
    fn validate_deny_rules_valid_config_accepted() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "rest",
                        "access": "read-write",
                        "deny_rules": [
                            { "method": "POST", "path": "/repos/*/pulls/*/reviews" },
                            { "method": "PUT", "path": "/repos/*/branches/*/protection" }
                        ]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "valid deny_rules should not error: {errors:?}"
        );
    }

    #[test]
    fn validate_deny_rules_query_empty_any_rejected() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "rest",
                        "access": "full",
                        "deny_rules": [{
                            "method": "POST",
                            "path": "/admin",
                            "query": { "type": { "any": [] } }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("any: list must not be empty")),
            "should reject empty any list in deny query: {errors:?}"
        );
    }

    #[test]
    fn validate_deny_rules_query_non_string_rejected() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "rest",
                        "access": "full",
                        "deny_rules": [{
                            "method": "POST",
                            "path": "/admin",
                            "query": { "force": 123 }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("expected string glob or matcher object")),
            "should reject non-string/non-object matcher in deny query: {errors:?}"
        );
    }

    #[test]
    fn validate_deny_rules_query_valid_matchers_accepted() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "rest",
                        "access": "full",
                        "deny_rules": [{
                            "method": "POST",
                            "path": "/admin/**",
                            "query": {
                                "force": "true",
                                "type": { "any": ["admin-*", "root-*"] },
                                "scope": { "glob": "org-*" }
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "valid deny query matchers should not error: {errors:?}"
        );
    }
}
