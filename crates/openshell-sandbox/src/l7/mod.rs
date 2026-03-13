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

/// TLS handling mode for L7-inspected endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsMode {
    /// No TLS termination — L7 inspection on plaintext only.
    #[default]
    Passthrough,
    /// Proxy terminates TLS, inspects plaintext, re-encrypts to upstream.
    Terminate,
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
}

/// Parse an L7 endpoint config from a regorus Value (returned by Rego query).
///
/// The value is expected to be the raw endpoint object from the Rego data,
/// containing fields: `protocol`, optionally `tls`, `enforcement`.
pub fn parse_l7_config(val: &regorus::Value) -> Option<L7EndpointConfig> {
    let protocol_val = get_object_str(val, "protocol")?;
    let protocol = L7Protocol::parse(&protocol_val)?;

    let tls = match get_object_str(val, "tls").as_deref() {
        Some("terminate") => TlsMode::Terminate,
        _ => TlsMode::Passthrough,
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
            let port = ep
                .get("port")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let loc = format!("{name}.endpoints[{i}]");

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

            // tls: terminate requires protocol
            if tls == "terminate" && protocol.is_empty() {
                errors.push(format!(
                    "{loc}: TLS termination requires a protocol for L7 inspection"
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

            // port 443 + rest + no tls: terminate
            if protocol == "rest" && port == 443 && tls != "terminate" {
                warnings.push(format!(
                    "{loc}: L7 rules won't be evaluated on encrypted traffic without `tls: terminate`"
                ));
            }

            // Validate HTTP methods in rules
            if has_rules && protocol == "rest" {
                let valid_methods = [
                    "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "*",
                ];
                if let Some(rules) = ep.get("rules").and_then(|v| v.as_array()) {
                    for rule in rules {
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
        assert_eq!(config.tls, TlsMode::Terminate);
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
        assert_eq!(config.tls, TlsMode::Passthrough);
        assert_eq!(config.enforcement, EnforcementMode::Audit);
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
    fn validate_tls_terminate_requires_protocol() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "tls": "terminate"
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("TLS termination requires"))
        );
    }

    #[test]
    fn validate_port_443_rest_no_tls_warns() {
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
        let (_errors, warnings) = validate_l7_policies(&data);
        assert!(warnings.iter().any(|w| w.contains("tls: terminate")));
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
}
