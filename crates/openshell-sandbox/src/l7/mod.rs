// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! L7 protocol-aware inspection for the CONNECT proxy.
//!
//! When an endpoint is configured with a `protocol` field (e.g. `rest`, `sql`),
//! the proxy inspects application-layer traffic within the tunnel instead of
//! doing a raw `copy_bidirectional`. Each request within the tunnel is parsed,
//! evaluated against OPA policy, and either forwarded or denied.

pub mod inference;
pub mod provider;
pub mod relay;
pub mod rest;
pub mod tls;

/// Application-layer protocol for L7 inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L7Protocol {
    Rest,
    Sql,
}

impl L7Protocol {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "rest" => Some(Self::Rest),
            "sql" => Some(Self::Sql),
            _ => None,
        }
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
#[derive(Debug, Clone)]
pub struct L7EndpointConfig {
    pub protocol: L7Protocol,
    pub tls: TlsMode,
    pub enforcement: EnforcementMode,
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
            let event = openshell_ocsf::NetworkActivityBuilder::new(crate::ocsf_ctx())
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
            let event = openshell_ocsf::NetworkActivityBuilder::new(crate::ocsf_ctx())
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

    Some(L7EndpointConfig {
        protocol,
        tls,
        enforcement,
    })
}

/// Parse the `tls` field from an endpoint config, independent of L7 protocol.
///
/// Used to check for `tls: skip` even on L4-only endpoints (no `protocol`
/// field) that explicitly opt out of TLS auto-detection.
pub fn parse_tls_mode(val: &regorus::Value) -> TlsMode {
    match get_object_str(val, "tls").as_deref() {
        Some("skip") => TlsMode::Skip,
        Some("terminate") | Some("passthrough") => TlsMode::Auto, // deprecation logged by parse_l7_config
        _ => TlsMode::Auto,
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
            let tls = ep.get("tls").and_then(|v| v.as_str()).unwrap_or("");
            let enforcement = ep.get("enforcement").and_then(|v| v.as_str()).unwrap_or("");
            let access = ep.get("access").and_then(|v| v.as_str()).unwrap_or("");
            let has_rules = ep
                .get("rules")
                .and_then(|v| v.as_array())
                .is_some_and(|a| !a.is_empty());
            let host = ep.get("host").and_then(|v| v.as_str()).unwrap_or("");

            // Read ports from either "ports" array or scalar "port".
            let ports: Vec<u64> = ep
                .get("ports")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_u64()).collect())
                .unwrap_or_else(|| {
                    ep.get("port")
                        .and_then(serde_json::Value::as_u64)
                        .filter(|p| *p > 0)
                        .into_iter()
                        .collect()
                });
            let loc = format!("{name}.endpoints[{i}]");

            // Validate host wildcard patterns.
            if host.contains('*') {
                if host == "*" || host == "**" {
                    errors.push(format!(
                        "{loc}: host wildcard '{host}' matches all hosts; use specific patterns like '*.example.com'"
                    ));
                } else if !host.starts_with("*.") && !host.starts_with("**.") {
                    errors.push(format!(
                        "{loc}: host wildcard must start with '*.' or '**.' (e.g., '*.example.com'), got '{host}'"
                    ));
                } else {
                    // Reject TLD wildcards like *.com (2 labels) — they are
                    // accepted by the policy engine but silently fail at the
                    // proxy layer (see #787).
                    let label_count = host.split('.').count();
                    if label_count <= 2 {
                        errors.push(format!(
                            "{loc}: TLD wildcard '{host}' is not allowed; \
                             use subdomain wildcards like '*.example.com' instead"
                        ));
                    }
                }
            }

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

            // protocol requires rules or access
            if !protocol.is_empty() && !has_rules && access.is_empty() {
                errors.push(format!(
                    "{loc}: protocol requires rules or access to define allowed traffic"
                ));
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
                if !has_rules && access.is_empty() {
                    errors.push(format!(
                        "{loc}: deny_rules require rules or access to define the base allow set"
                    ));
                }

                if let Some(deny_rules) = ep.get("deny_rules").and_then(|v| v.as_array()) {
                    for (deny_idx, deny_rule) in deny_rules.iter().enumerate() {
                        let deny_loc = format!("{loc}.deny_rules[{deny_idx}]");

                        // Validate method
                        if let Some(method) = deny_rule.get("method").and_then(|m| m.as_str())
                            && !method.is_empty()
                            && protocol == "rest"
                        {
                            let valid_methods = [
                                "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "*",
                            ];
                            if !valid_methods.contains(&method.to_ascii_uppercase().as_str()) {
                                warnings.push(format!(
                                    "{deny_loc}: Unknown HTTP method '{method}'. Standard methods: GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS."
                                ));
                            }
                        }

                        // Validate path glob syntax
                        if let Some(path) = deny_rule.get("path").and_then(|p| p.as_str()) {
                            if let Some(warning) = check_glob_syntax(path) {
                                warnings.push(format!("{deny_loc}.path: {warning}"));
                            }
                        }

                        // Validate query matchers — mirrors allow-side validation exactly
                        if let Some(query) = deny_rule.get("query").filter(|v| !v.is_null()) {
                            let Some(query_obj) = query.as_object() else {
                                errors.push(format!(
                                    "{deny_loc}.query: expected map of query matchers"
                                ));
                                continue;
                            };

                            for (param, matcher) in query_obj {
                                if let Some(glob_str) = matcher.as_str() {
                                    if let Some(warning) = check_glob_syntax(glob_str) {
                                        warnings
                                            .push(format!("{deny_loc}.query.{param}: {warning}"));
                                    }
                                    continue;
                                }

                                let Some(matcher_obj) = matcher.as_object() else {
                                    errors.push(format!(
                                        "{deny_loc}.query.{param}: expected string glob or object with `any`"
                                    ));
                                    continue;
                                };

                                let has_any = matcher_obj.get("any").is_some();
                                let has_glob = matcher_obj.get("glob").is_some();
                                let has_unknown =
                                    matcher_obj.keys().any(|k| k != "any" && k != "glob");
                                if has_unknown {
                                    errors.push(format!(
                                        "{deny_loc}.query.{param}: unknown matcher keys; only `glob` or `any` are supported"
                                    ));
                                    continue;
                                }

                                if has_glob && has_any {
                                    errors.push(format!(
                                        "{deny_loc}.query.{param}: matcher cannot specify both `glob` and `any`"
                                    ));
                                    continue;
                                }

                                if !has_glob && !has_any {
                                    errors.push(format!(
                                        "{deny_loc}.query.{param}: object matcher requires `glob` string or non-empty `any` list"
                                    ));
                                    continue;
                                }

                                if has_glob {
                                    match matcher_obj.get("glob").and_then(|v| v.as_str()) {
                                        None => {
                                            errors.push(format!(
                                                "{deny_loc}.query.{param}.glob: expected glob string"
                                            ));
                                        }
                                        Some(g) => {
                                            if let Some(warning) = check_glob_syntax(g) {
                                                warnings.push(format!(
                                                    "{deny_loc}.query.{param}.glob: {warning}"
                                                ));
                                            }
                                        }
                                    }
                                    continue;
                                }

                                let any = matcher_obj.get("any").and_then(|v| v.as_array());
                                let Some(any) = any else {
                                    errors.push(format!(
                                        "{deny_loc}.query.{param}.any: expected array of glob strings"
                                    ));
                                    continue;
                                };

                                if any.is_empty() {
                                    errors.push(format!(
                                        "{deny_loc}.query.{param}.any: list must not be empty"
                                    ));
                                    continue;
                                }

                                if any.iter().any(|v| v.as_str().is_none()) {
                                    errors.push(format!(
                                        "{deny_loc}.query.{param}.any: all values must be strings"
                                    ));
                                }

                                for item in any.iter().filter_map(|v| v.as_str()) {
                                    if let Some(warning) = check_glob_syntax(item) {
                                        warnings.push(format!(
                                            "{deny_loc}.query.{param}.any: {warning}"
                                        ));
                                    }
                                }
                            }
                        }

                        // SQL command validation
                        if let Some(command) = deny_rule.get("command").and_then(|c| c.as_str()) {
                            if !command.is_empty() && protocol == "rest" {
                                warnings.push(format!(
                                    "{deny_loc}: command is for SQL protocol, not REST"
                                ));
                            }
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
            if has_rules && protocol == "rest" {
                let valid_methods = [
                    "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "*",
                ];
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
                                    "{loc}: Unknown HTTP method '{method}'. Standard methods: GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS."
                                ));
                        }

                        let Some(query) = rule
                            .get("allow")
                            .and_then(|a| a.get("query"))
                            .filter(|v| !v.is_null())
                        else {
                            continue;
                        };

                        let Some(query_obj) = query.as_object() else {
                            errors.push(format!(
                                "{loc}.rules[{rule_idx}].allow.query: expected map of query matchers"
                            ));
                            continue;
                        };

                        for (param, matcher) in query_obj {
                            if let Some(glob_str) = matcher.as_str() {
                                if let Some(warning) = check_glob_syntax(glob_str) {
                                    warnings.push(format!(
                                        "{loc}.rules[{rule_idx}].allow.query.{param}: {warning}"
                                    ));
                                }
                                continue;
                            }

                            let Some(matcher_obj) = matcher.as_object() else {
                                errors.push(format!(
                                    "{loc}.rules[{rule_idx}].allow.query.{param}: expected string glob or object with `any`"
                                ));
                                continue;
                            };

                            let has_any = matcher_obj.get("any").is_some();
                            let has_glob = matcher_obj.get("glob").is_some();
                            let has_unknown = matcher_obj.keys().any(|k| k != "any" && k != "glob");
                            if has_unknown {
                                errors.push(format!(
                                    "{loc}.rules[{rule_idx}].allow.query.{param}: unknown matcher keys; only `glob` or `any` are supported"
                                ));
                                continue;
                            }

                            if has_glob && has_any {
                                errors.push(format!(
                                    "{loc}.rules[{rule_idx}].allow.query.{param}: matcher cannot specify both `glob` and `any`"
                                ));
                                continue;
                            }

                            if !has_glob && !has_any {
                                errors.push(format!(
                                    "{loc}.rules[{rule_idx}].allow.query.{param}: object matcher requires `glob` string or non-empty `any` list"
                                ));
                                continue;
                            }

                            if has_glob {
                                match matcher_obj.get("glob").and_then(|v| v.as_str()) {
                                    None => {
                                        errors.push(format!(
                                            "{loc}.rules[{rule_idx}].allow.query.{param}.glob: expected glob string"
                                        ));
                                    }
                                    Some(g) => {
                                        if let Some(warning) = check_glob_syntax(g) {
                                            warnings.push(format!(
                                                "{loc}.rules[{rule_idx}].allow.query.{param}.glob: {warning}"
                                            ));
                                        }
                                    }
                                }
                                continue;
                            }

                            let any = matcher_obj.get("any").and_then(|v| v.as_array());
                            let Some(any) = any else {
                                errors.push(format!(
                                    "{loc}.rules[{rule_idx}].allow.query.{param}.any: expected array of glob strings"
                                ));
                                continue;
                            };

                            if any.is_empty() {
                                errors.push(format!(
                                    "{loc}.rules[{rule_idx}].allow.query.{param}.any: list must not be empty"
                                ));
                                continue;
                            }

                            if any.iter().any(|v| v.as_str().is_none()) {
                                errors.push(format!(
                                    "{loc}.rules[{rule_idx}].allow.query.{param}.any: all values must be strings"
                                ));
                            }

                            for item in any.iter().filter_map(|v| v.as_str()) {
                                if let Some(warning) = check_glob_syntax(item) {
                                    warnings.push(format!(
                                        "{loc}.rules[{rule_idx}].allow.query.{param}.any: {warning}"
                                    ));
                                }
                            }
                        }
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
            let access = ep
                .get("access")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if access.is_empty() {
                continue;
            }

            // Don't expand if rules already exist (validation will catch this)
            if ep
                .get("rules")
                .and_then(|v| v.as_array())
                .is_some_and(|a| !a.is_empty())
            {
                continue;
            }

            let rules = match access.as_str() {
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
    fn validate_wildcard_host_no_star_dot_error() {
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
            errors.iter().any(|e| e.contains("must start with")),
            "Malformed wildcard should be rejected, got errors: {errors:?}"
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
                .any(|e| e.contains("expected string glob or object")),
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
