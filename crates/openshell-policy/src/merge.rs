// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};

use openshell_core::proto::{
    L7Allow, L7DenyRule, L7Rule, NetworkBinary, NetworkEndpoint, NetworkPolicyRule, SandboxPolicy,
};

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyMergeOp {
    AddRule {
        rule_name: String,
        rule: NetworkPolicyRule,
    },
    RemoveEndpoint {
        rule_name: Option<String>,
        host: String,
        port: u32,
    },
    RemoveRule {
        rule_name: String,
    },
    AddDenyRules {
        host: String,
        port: u32,
        deny_rules: Vec<L7DenyRule>,
    },
    AddAllowRules {
        host: String,
        port: u32,
        rules: Vec<L7Rule>,
    },
    RemoveBinary {
        rule_name: String,
        binary_path: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyMergeWarning {
    ExistingProtocolRetained {
        host: String,
        port: u32,
        existing: String,
        incoming: String,
    },
    ExistingEnforcementRetained {
        host: String,
        port: u32,
        existing: String,
        incoming: String,
    },
    ExistingTlsRetained {
        host: String,
        port: u32,
        existing: String,
        incoming: String,
    },
    ExistingAccessRetained {
        host: String,
        port: u32,
        existing: String,
        incoming: String,
    },
    ExpandedAccessPreset {
        host: String,
        port: u32,
        access: String,
    },
    IgnoredIncomingAccessBecauseRulesExist {
        host: String,
        port: u32,
        incoming: String,
    },
}

impl std::fmt::Display for PolicyMergeWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExistingProtocolRetained {
                host,
                port,
                existing,
                incoming,
            } => write!(
                f,
                "endpoint {host}:{port} keeps existing protocol '{existing}' and ignores incoming '{incoming}'"
            ),
            Self::ExistingEnforcementRetained {
                host,
                port,
                existing,
                incoming,
            } => write!(
                f,
                "endpoint {host}:{port} keeps existing enforcement '{existing}' and ignores incoming '{incoming}'"
            ),
            Self::ExistingTlsRetained {
                host,
                port,
                existing,
                incoming,
            } => write!(
                f,
                "endpoint {host}:{port} keeps existing tls mode '{existing}' and ignores incoming '{incoming}'"
            ),
            Self::ExistingAccessRetained {
                host,
                port,
                existing,
                incoming,
            } => write!(
                f,
                "endpoint {host}:{port} keeps existing access preset '{existing}' and ignores incoming '{incoming}'"
            ),
            Self::ExpandedAccessPreset { host, port, access } => write!(
                f,
                "expanded access preset '{access}' to explicit rules for endpoint {host}:{port}"
            ),
            Self::IgnoredIncomingAccessBecauseRulesExist {
                host,
                port,
                incoming,
            } => write!(
                f,
                "endpoint {host}:{port} already uses explicit rules; incoming access preset '{incoming}' was ignored"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyMergeError {
    MissingRuleNameForAddRule,
    InvalidEndpointReference {
        host: String,
        port: u32,
    },
    EndpointNotFound {
        host: String,
        port: u32,
    },
    EndpointHasNoL7Inspection {
        host: String,
        port: u32,
    },
    UnsupportedEndpointProtocol {
        host: String,
        port: u32,
        protocol: String,
    },
    EndpointHasNoAllowBase {
        host: String,
        port: u32,
    },
    UnsupportedAccessPreset {
        host: String,
        port: u32,
        access: String,
    },
}

impl std::fmt::Display for PolicyMergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingRuleNameForAddRule => write!(f, "add-rule operation requires a rule name"),
            Self::InvalidEndpointReference { host, port } => {
                write!(f, "invalid endpoint reference '{host}:{port}'")
            }
            Self::EndpointNotFound { host, port } => {
                write!(
                    f,
                    "endpoint {host}:{port} was not found in the current policy"
                )
            }
            Self::EndpointHasNoL7Inspection { host, port } => write!(
                f,
                "endpoint {host}:{port} has no L7 inspection configured (protocol is empty)"
            ),
            Self::UnsupportedEndpointProtocol {
                host,
                port,
                protocol,
            } => write!(
                f,
                "endpoint {host}:{port} uses unsupported protocol '{protocol}'; this operation currently supports only protocol 'rest'"
            ),
            Self::EndpointHasNoAllowBase { host, port } => write!(
                f,
                "endpoint {host}:{port} has no base allow set; configure access or explicit allow rules before adding deny rules"
            ),
            Self::UnsupportedAccessPreset { host, port, access } => write!(
                f,
                "endpoint {host}:{port} uses unsupported access preset '{access}'"
            ),
        }
    }
}

impl std::error::Error for PolicyMergeError {}

#[derive(Debug, Clone, PartialEq)]
pub struct PolicyMergeResult {
    pub policy: SandboxPolicy,
    pub warnings: Vec<PolicyMergeWarning>,
    pub changed: bool,
}

pub fn merge_policy(
    policy: SandboxPolicy,
    operations: &[PolicyMergeOp],
) -> Result<PolicyMergeResult, PolicyMergeError> {
    let mut merged = policy.clone();
    let mut warnings = Vec::new();

    for operation in operations {
        apply_operation(&mut merged, operation, &mut warnings)?;
    }

    let changed = merged != policy;
    Ok(PolicyMergeResult {
        policy: merged,
        warnings,
        changed,
    })
}

pub fn generated_rule_name(host: &str, port: u32) -> String {
    let sanitized = host
        .replace(['.', '-'], "_")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .collect::<String>();
    format!("allow_{sanitized}_{port}")
}

fn apply_operation(
    policy: &mut SandboxPolicy,
    operation: &PolicyMergeOp,
    warnings: &mut Vec<PolicyMergeWarning>,
) -> Result<(), PolicyMergeError> {
    match operation {
        PolicyMergeOp::AddRule { rule_name, rule } => {
            add_rule(policy, rule_name, rule, warnings)?;
        }
        PolicyMergeOp::RemoveEndpoint {
            rule_name,
            host,
            port,
        } => {
            remove_endpoint(policy, rule_name.as_deref(), host, *port);
        }
        PolicyMergeOp::RemoveRule { rule_name } => {
            policy.network_policies.remove(rule_name);
        }
        PolicyMergeOp::AddDenyRules {
            host,
            port,
            deny_rules,
        } => {
            let endpoint = find_endpoint_mut(policy, host, *port).ok_or_else(|| {
                PolicyMergeError::EndpointNotFound {
                    host: host.clone(),
                    port: *port,
                }
            })?;
            ensure_rest_endpoint(endpoint, host, *port)?;
            if endpoint.access.is_empty() && endpoint.rules.is_empty() {
                return Err(PolicyMergeError::EndpointHasNoAllowBase {
                    host: host.clone(),
                    port: *port,
                });
            }
            append_unique_deny_rules(&mut endpoint.deny_rules, deny_rules);
        }
        PolicyMergeOp::AddAllowRules { host, port, rules } => {
            let endpoint = find_endpoint_mut(policy, host, *port).ok_or_else(|| {
                PolicyMergeError::EndpointNotFound {
                    host: host.clone(),
                    port: *port,
                }
            })?;
            ensure_rest_endpoint(endpoint, host, *port)?;
            expand_existing_access(endpoint, host, *port, warnings)?;
            append_unique_l7_rules(&mut endpoint.rules, rules);
        }
        PolicyMergeOp::RemoveBinary {
            rule_name,
            binary_path,
        } => {
            let should_remove = if let Some(rule) = policy.network_policies.get_mut(rule_name) {
                let original_len = rule.binaries.len();
                rule.binaries.retain(|binary| binary.path != *binary_path);
                original_len != rule.binaries.len() && rule.binaries.is_empty()
            } else {
                false
            };
            if should_remove {
                policy.network_policies.remove(rule_name);
            }
        }
    }
    Ok(())
}

fn add_rule(
    policy: &mut SandboxPolicy,
    rule_name: &str,
    incoming_rule: &NetworkPolicyRule,
    warnings: &mut Vec<PolicyMergeWarning>,
) -> Result<(), PolicyMergeError> {
    if rule_name.trim().is_empty() {
        return Err(PolicyMergeError::MissingRuleNameForAddRule);
    }

    let mut incoming_rule = incoming_rule.clone();
    normalize_rule(&mut incoming_rule);
    if incoming_rule.name.is_empty() {
        incoming_rule.name = rule_name.to_string();
    }

    let target_key = if policy.network_policies.contains_key(rule_name) {
        Some(rule_name.to_string())
    } else {
        let mut keys: Vec<_> = policy.network_policies.keys().cloned().collect();
        keys.sort();
        keys.into_iter().find(|key| {
            policy
                .network_policies
                .get(key)
                .is_some_and(|existing_rule| rules_share_endpoint(existing_rule, &incoming_rule))
        })
    };

    if let Some(key) = target_key {
        let existing_rule = policy
            .network_policies
            .get_mut(&key)
            .expect("existing rule must be present");
        merge_rules(existing_rule, &incoming_rule, warnings)?;
    } else {
        policy
            .network_policies
            .insert(rule_name.to_string(), incoming_rule);
    }

    Ok(())
}

fn merge_rules(
    existing_rule: &mut NetworkPolicyRule,
    incoming_rule: &NetworkPolicyRule,
    warnings: &mut Vec<PolicyMergeWarning>,
) -> Result<(), PolicyMergeError> {
    append_unique_binaries(&mut existing_rule.binaries, &incoming_rule.binaries);

    for incoming_endpoint in &incoming_rule.endpoints {
        let mut incoming_endpoint = incoming_endpoint.clone();
        normalize_endpoint(&mut incoming_endpoint);
        if let Some(existing_endpoint) =
            find_matching_endpoint_mut(&mut existing_rule.endpoints, &incoming_endpoint)
        {
            merge_endpoint(existing_endpoint, &incoming_endpoint, warnings)?;
        } else {
            existing_rule.endpoints.push(incoming_endpoint);
        }
    }

    Ok(())
}

fn merge_endpoint(
    existing: &mut NetworkEndpoint,
    incoming: &NetworkEndpoint,
    warnings: &mut Vec<PolicyMergeWarning>,
) -> Result<(), PolicyMergeError> {
    let host = if existing.host.is_empty() {
        incoming.host.clone()
    } else {
        existing.host.clone()
    };
    let port = canonical_ports(existing)
        .into_iter()
        .next()
        .or_else(|| canonical_ports(incoming).into_iter().next())
        .unwrap_or(0);

    if existing.host.is_empty() {
        existing.host.clone_from(&incoming.host);
    }

    merge_endpoint_ports(existing, incoming);
    let existing_protocol = existing.protocol.clone();
    merge_string_field(
        &mut existing.protocol,
        &incoming.protocol,
        PolicyMergeWarning::ExistingProtocolRetained {
            host: host.clone(),
            port,
            existing: existing_protocol,
            incoming: incoming.protocol.clone(),
        },
        warnings,
    );
    let existing_enforcement = existing.enforcement.clone();
    merge_string_field(
        &mut existing.enforcement,
        &incoming.enforcement,
        PolicyMergeWarning::ExistingEnforcementRetained {
            host: host.clone(),
            port,
            existing: existing_enforcement,
            incoming: incoming.enforcement.clone(),
        },
        warnings,
    );
    let existing_tls = existing.tls.clone();
    merge_string_field(
        &mut existing.tls,
        &incoming.tls,
        PolicyMergeWarning::ExistingTlsRetained {
            host: host.clone(),
            port,
            existing: existing_tls,
            incoming: incoming.tls.clone(),
        },
        warnings,
    );

    if !incoming.rules.is_empty() {
        expand_existing_access(existing, &host, port, warnings)?;
        append_unique_l7_rules(&mut existing.rules, &incoming.rules);
        if !incoming.access.is_empty() {
            warnings.push(PolicyMergeWarning::IgnoredIncomingAccessBecauseRulesExist {
                host,
                port,
                incoming: incoming.access.clone(),
            });
        }
    } else if !incoming.access.is_empty() {
        if !existing.rules.is_empty() {
            warnings.push(PolicyMergeWarning::IgnoredIncomingAccessBecauseRulesExist {
                host,
                port,
                incoming: incoming.access.clone(),
            });
        } else if existing.access.is_empty() {
            existing.access.clone_from(&incoming.access);
        } else if existing.access != incoming.access {
            warnings.push(PolicyMergeWarning::ExistingAccessRetained {
                host,
                port,
                existing: existing.access.clone(),
                incoming: incoming.access.clone(),
            });
        }
    }

    append_unique_deny_rules(&mut existing.deny_rules, &incoming.deny_rules);
    append_unique_strings(&mut existing.allowed_ips, &incoming.allowed_ips);
    normalize_endpoint(existing);
    Ok(())
}

fn merge_string_field(
    existing: &mut String,
    incoming: &str,
    warning: PolicyMergeWarning,
    warnings: &mut Vec<PolicyMergeWarning>,
) {
    if incoming.is_empty() {
        return;
    }
    if existing.is_empty() {
        *existing = incoming.to_string();
    } else if *existing != incoming {
        warnings.push(warning);
    }
}

fn merge_endpoint_ports(existing: &mut NetworkEndpoint, incoming: &NetworkEndpoint) {
    let mut ports = canonical_ports(existing);
    for port in canonical_ports(incoming) {
        if !ports.contains(&port) {
            ports.push(port);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    existing.port = ports.first().copied().unwrap_or(0);
    existing.ports = ports;
}

fn rules_share_endpoint(
    existing_rule: &NetworkPolicyRule,
    incoming_rule: &NetworkPolicyRule,
) -> bool {
    incoming_rule.endpoints.iter().any(|incoming_endpoint| {
        existing_rule
            .endpoints
            .iter()
            .any(|existing_endpoint| endpoints_overlap(existing_endpoint, incoming_endpoint))
    })
}

fn endpoints_overlap(left: &NetworkEndpoint, right: &NetworkEndpoint) -> bool {
    if !left.host.eq_ignore_ascii_case(&right.host) {
        return false;
    }

    let left_ports = canonical_ports(left);
    let right_ports = canonical_ports(right);
    left_ports.iter().any(|port| right_ports.contains(port))
}

fn canonical_ports(endpoint: &NetworkEndpoint) -> Vec<u32> {
    if !endpoint.ports.is_empty() {
        endpoint.ports.clone()
    } else if endpoint.port > 0 {
        vec![endpoint.port]
    } else {
        vec![]
    }
}

fn find_matching_endpoint_mut<'a>(
    endpoints: &'a mut [NetworkEndpoint],
    target: &NetworkEndpoint,
) -> Option<&'a mut NetworkEndpoint> {
    endpoints
        .iter_mut()
        .find(|endpoint| endpoints_overlap(endpoint, target))
}

fn find_endpoint_mut<'a>(
    policy: &'a mut SandboxPolicy,
    host: &str,
    port: u32,
) -> Option<&'a mut NetworkEndpoint> {
    let mut keys: Vec<_> = policy.network_policies.keys().cloned().collect();
    keys.sort();
    let target_key = keys.into_iter().find(|key| {
        policy.network_policies.get(key).is_some_and(|rule| {
            rule.endpoints
                .iter()
                .any(|endpoint| endpoint_matches_host_port(endpoint, host, port))
        })
    })?;

    policy
        .network_policies
        .get_mut(&target_key)
        .and_then(|rule| {
            rule.endpoints
                .iter_mut()
                .find(|endpoint| endpoint_matches_host_port(endpoint, host, port))
        })
}

fn endpoint_matches_host_port(endpoint: &NetworkEndpoint, host: &str, port: u32) -> bool {
    endpoint.host.eq_ignore_ascii_case(host) && canonical_ports(endpoint).contains(&port)
}

fn ensure_rest_endpoint(
    endpoint: &NetworkEndpoint,
    host: &str,
    port: u32,
) -> Result<(), PolicyMergeError> {
    if endpoint.protocol.is_empty() {
        return Err(PolicyMergeError::EndpointHasNoL7Inspection {
            host: host.to_string(),
            port,
        });
    }
    if endpoint.protocol != "rest" {
        return Err(PolicyMergeError::UnsupportedEndpointProtocol {
            host: host.to_string(),
            port,
            protocol: endpoint.protocol.clone(),
        });
    }
    Ok(())
}

fn expand_existing_access(
    endpoint: &mut NetworkEndpoint,
    host: &str,
    port: u32,
    warnings: &mut Vec<PolicyMergeWarning>,
) -> Result<(), PolicyMergeError> {
    if endpoint.access.is_empty() {
        return Ok(());
    }

    let access = endpoint.access.clone();
    let expanded =
        expand_access_preset(&access).ok_or_else(|| PolicyMergeError::UnsupportedAccessPreset {
            host: host.to_string(),
            port,
            access: access.clone(),
        })?;
    endpoint.access.clear();
    append_unique_l7_rules(&mut endpoint.rules, &expanded);
    warnings.push(PolicyMergeWarning::ExpandedAccessPreset {
        host: host.to_string(),
        port,
        access,
    });
    Ok(())
}

fn expand_access_preset(access: &str) -> Option<Vec<L7Rule>> {
    let methods = match access {
        "read-only" => vec!["GET", "HEAD", "OPTIONS"],
        "read-write" => vec!["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"],
        "full" => vec!["*"],
        _ => return None,
    };

    Some(
        methods
            .into_iter()
            .map(|method| L7Rule {
                allow: Some(L7Allow {
                    method: method.to_string(),
                    path: "**".to_string(),
                    command: String::new(),
                    query: HashMap::default(),
                }),
            })
            .collect(),
    )
}

fn append_unique_binaries(existing: &mut Vec<NetworkBinary>, incoming: &[NetworkBinary]) {
    let mut seen: HashSet<String> = existing.iter().map(|binary| binary.path.clone()).collect();
    for binary in incoming {
        if seen.insert(binary.path.clone()) {
            existing.push(binary.clone());
        }
    }
}

fn append_unique_strings(existing: &mut Vec<String>, incoming: &[String]) {
    let mut seen: HashSet<String> = existing.iter().cloned().collect();
    for value in incoming {
        if seen.insert(value.clone()) {
            existing.push(value.clone());
        }
    }
}

fn append_unique_l7_rules(existing: &mut Vec<L7Rule>, incoming: &[L7Rule]) {
    for rule in incoming {
        if !existing.contains(rule) {
            existing.push(rule.clone());
        }
    }
}

fn append_unique_deny_rules(existing: &mut Vec<L7DenyRule>, incoming: &[L7DenyRule]) {
    for rule in incoming {
        if !existing.contains(rule) {
            existing.push(rule.clone());
        }
    }
}

fn normalize_rule(rule: &mut NetworkPolicyRule) {
    for endpoint in &mut rule.endpoints {
        normalize_endpoint(endpoint);
    }
    dedup_binaries(&mut rule.binaries);
}

fn normalize_endpoint(endpoint: &mut NetworkEndpoint) {
    let mut ports = canonical_ports(endpoint);
    ports.sort_unstable();
    ports.dedup();
    endpoint.port = ports.first().copied().unwrap_or(0);
    endpoint.ports = ports;
    dedup_strings(&mut endpoint.allowed_ips);
    dedup_l7_rules(&mut endpoint.rules);
    dedup_deny_rules(&mut endpoint.deny_rules);
}

fn dedup_strings(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn dedup_binaries(values: &mut Vec<NetworkBinary>) {
    let mut seen = HashSet::new();
    values.retain(|binary| seen.insert(binary.path.clone()));
}

fn dedup_l7_rules(values: &mut Vec<L7Rule>) {
    let mut deduped = Vec::with_capacity(values.len());
    for value in std::mem::take(values) {
        if !deduped.contains(&value) {
            deduped.push(value);
        }
    }
    *values = deduped;
}

fn dedup_deny_rules(values: &mut Vec<L7DenyRule>) {
    let mut deduped = Vec::with_capacity(values.len());
    for value in std::mem::take(values) {
        if !deduped.contains(&value) {
            deduped.push(value);
        }
    }
    *values = deduped;
}

fn remove_endpoint(policy: &mut SandboxPolicy, rule_name: Option<&str>, host: &str, port: u32) {
    let target_keys: Vec<String> = if let Some(rule_name) = rule_name {
        if policy.network_policies.contains_key(rule_name) {
            vec![rule_name.to_string()]
        } else {
            vec![]
        }
    } else {
        let mut keys: Vec<_> = policy.network_policies.keys().cloned().collect();
        keys.sort();
        keys
    };

    let mut empty_rules = Vec::new();
    for key in target_keys {
        if let Some(rule) = policy.network_policies.get_mut(&key) {
            rule.endpoints.retain_mut(|endpoint| {
                if !endpoint_matches_host_port(endpoint, host, port) {
                    return true;
                }

                let mut remaining_ports = canonical_ports(endpoint);
                remaining_ports.retain(|existing_port| *existing_port != port);
                remaining_ports.sort_unstable();
                remaining_ports.dedup();

                if remaining_ports.is_empty() {
                    return false;
                }

                endpoint.port = remaining_ports[0];
                endpoint.ports = remaining_ports;
                true
            });

            if rule.endpoints.is_empty() {
                empty_rules.push(key);
            }
        }
    }

    for key in empty_rules {
        policy.network_policies.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{
        PolicyMergeError, PolicyMergeOp, PolicyMergeWarning, generated_rule_name, merge_policy,
    };
    use crate::restrictive_default_policy;
    use openshell_core::proto::{
        L7Allow, L7DenyRule, L7Rule, NetworkBinary, NetworkEndpoint, NetworkPolicyRule,
    };

    fn endpoint(host: &str, port: u32) -> NetworkEndpoint {
        NetworkEndpoint {
            host: host.to_string(),
            port,
            ports: vec![port],
            ..Default::default()
        }
    }

    fn rule_with_endpoint(name: &str, host: &str, port: u32) -> NetworkPolicyRule {
        NetworkPolicyRule {
            name: name.to_string(),
            endpoints: vec![endpoint(host, port)],
            ..Default::default()
        }
    }

    fn rest_rule(method: &str, path: &str) -> L7Rule {
        L7Rule {
            allow: Some(L7Allow {
                method: method.to_string(),
                path: path.to_string(),
                command: String::new(),
                query: HashMap::new(),
            }),
        }
    }

    #[test]
    fn generated_rule_name_sanitizes_host() {
        assert_eq!(
            generated_rule_name("api.github.com", 443),
            "allow_api_github_com_443"
        );
    }

    #[test]
    fn add_rule_merges_l7_fields_into_existing_endpoint() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "existing".to_string(),
            NetworkPolicyRule {
                name: "existing".to_string(),
                endpoints: vec![endpoint("api.github.com", 443)],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/curl".to_string(),
                    ..Default::default()
                }],
            },
        );

        let incoming = NetworkPolicyRule {
            name: "incoming".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.github.com".to_string(),
                port: 443,
                ports: vec![443],
                protocol: "rest".to_string(),
                enforcement: "enforce".to_string(),
                rules: vec![rest_rule("GET", "/repos/**")],
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/gh".to_string(),
                ..Default::default()
            }],
        };

        let result = merge_policy(
            policy,
            &[PolicyMergeOp::AddRule {
                rule_name: "allow_api_github_com_443".to_string(),
                rule: incoming,
            }],
        )
        .expect("merge should succeed");

        let rule = &result.policy.network_policies["existing"];
        let endpoint = &rule.endpoints[0];
        assert_eq!(endpoint.protocol, "rest");
        assert_eq!(endpoint.enforcement, "enforce");
        assert_eq!(endpoint.rules.len(), 1);
        assert_eq!(rule.binaries.len(), 2);
    }

    #[test]
    fn add_allow_expands_access_preset() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "github".to_string(),
            NetworkPolicyRule {
                name: "github".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "api.github.com".to_string(),
                    port: 443,
                    ports: vec![443],
                    protocol: "rest".to_string(),
                    access: "read-only".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );

        let result = merge_policy(
            policy,
            &[PolicyMergeOp::AddAllowRules {
                host: "api.github.com".to_string(),
                port: 443,
                rules: vec![rest_rule("POST", "/repos/*/issues")],
            }],
        )
        .expect("merge should succeed");

        let endpoint = &result.policy.network_policies["github"].endpoints[0];
        assert!(endpoint.access.is_empty());
        assert_eq!(endpoint.rules.len(), 4);
        assert!(result.warnings.iter().any(|warning| matches!(
            warning,
            PolicyMergeWarning::ExpandedAccessPreset { access, .. } if access == "read-only"
        )));
    }

    #[test]
    fn add_deny_requires_rest_protocol() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "db".to_string(),
            NetworkPolicyRule {
                name: "db".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "db.example.com".to_string(),
                    port: 5432,
                    ports: vec![5432],
                    protocol: "sql".to_string(),
                    access: "full".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );

        let error = merge_policy(
            policy,
            &[PolicyMergeOp::AddDenyRules {
                host: "db.example.com".to_string(),
                port: 5432,
                deny_rules: vec![L7DenyRule {
                    method: "POST".to_string(),
                    path: "/admin".to_string(),
                    ..Default::default()
                }],
            }],
        )
        .expect_err("merge should fail");

        assert!(matches!(
            error,
            PolicyMergeError::UnsupportedEndpointProtocol { protocol, .. } if protocol == "sql"
        ));
    }

    #[test]
    fn remove_endpoint_drops_only_requested_port() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "multi".to_string(),
            NetworkPolicyRule {
                name: "multi".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "api.example.com".to_string(),
                    port: 80,
                    ports: vec![80, 443],
                    ..Default::default()
                }],
                ..Default::default()
            },
        );

        let result = merge_policy(
            policy,
            &[PolicyMergeOp::RemoveEndpoint {
                rule_name: None,
                host: "api.example.com".to_string(),
                port: 443,
            }],
        )
        .expect("merge should succeed");

        let endpoint = &result.policy.network_policies["multi"].endpoints[0];
        assert_eq!(endpoint.ports, vec![80]);
        assert_eq!(endpoint.port, 80);
    }

    #[test]
    fn remove_binary_removes_rule_when_last_binary_is_deleted() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "github".to_string(),
            NetworkPolicyRule {
                name: "github".to_string(),
                endpoints: vec![endpoint("api.github.com", 443)],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/gh".to_string(),
                    ..Default::default()
                }],
            },
        );

        let result = merge_policy(
            policy,
            &[PolicyMergeOp::RemoveBinary {
                rule_name: "github".to_string(),
                binary_path: "/usr/bin/gh".to_string(),
            }],
        )
        .expect("merge should succeed");

        assert!(!result.policy.network_policies.contains_key("github"));
    }

    #[test]
    fn add_rule_without_existing_match_inserts_requested_key() {
        let policy = restrictive_default_policy();
        let result = merge_policy(
            policy,
            &[PolicyMergeOp::AddRule {
                rule_name: "allow_api_example_com_443".to_string(),
                rule: rule_with_endpoint("custom", "api.example.com", 443),
            }],
        )
        .expect("merge should succeed");

        assert!(
            result
                .policy
                .network_policies
                .contains_key("allow_api_example_com_443")
        );
    }
}
