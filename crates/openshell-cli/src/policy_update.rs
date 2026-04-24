// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use miette::{Result, miette};
use openshell_core::proto::policy_merge_operation;
use openshell_core::proto::{
    AddAllowRules, AddDenyRules, AddNetworkRule, L7Allow, L7DenyRule, L7Rule, NetworkBinary,
    NetworkEndpoint, NetworkPolicyRule, PolicyMergeOperation, RemoveNetworkEndpoint,
    RemoveNetworkRule,
};
use openshell_policy::{PolicyMergeOp, generated_rule_name};

#[derive(Debug, Clone)]
pub(crate) struct PolicyUpdatePlan {
    pub merge_operations: Vec<PolicyMergeOperation>,
    pub preview_operations: Vec<PolicyMergeOp>,
}

pub(crate) fn build_policy_update_plan(
    add_endpoints: &[String],
    remove_endpoints: &[String],
    add_deny: &[String],
    add_allow: &[String],
    remove_rules: &[String],
    binaries: &[String],
    rule_name: Option<&str>,
) -> Result<PolicyUpdatePlan> {
    if binaries.iter().any(|binary| binary.trim().is_empty()) {
        return Err(miette!("--binary values must not be empty"));
    }
    if !binaries.is_empty() && add_endpoints.is_empty() {
        return Err(miette!("--binary can only be used with --add-endpoint"));
    }
    if rule_name.is_some() && add_endpoints.is_empty() {
        return Err(miette!("--rule-name can only be used with --add-endpoint"));
    }
    if rule_name.is_some() && add_endpoints.len() > 1 {
        return Err(miette!(
            "--rule-name is only supported when exactly one --add-endpoint is provided"
        ));
    }

    let mut merge_operations = Vec::new();
    let mut preview_operations = Vec::new();

    let deduped_binaries = dedup_strings(binaries);
    for spec in add_endpoints {
        let endpoint = parse_add_endpoint_spec(spec)?;
        let target_rule_name = rule_name
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| generated_rule_name(&endpoint.host, endpoint.port));
        let rule = NetworkPolicyRule {
            name: target_rule_name.clone(),
            endpoints: vec![endpoint.clone()],
            binaries: deduped_binaries
                .iter()
                .map(|path| NetworkBinary {
                    path: path.clone(),
                    ..Default::default()
                })
                .collect(),
        };
        merge_operations.push(PolicyMergeOperation {
            operation: Some(policy_merge_operation::Operation::AddRule(AddNetworkRule {
                rule_name: target_rule_name.clone(),
                rule: Some(rule.clone()),
            })),
        });
        preview_operations.push(PolicyMergeOp::AddRule {
            rule_name: target_rule_name,
            rule,
        });
    }

    for spec in remove_endpoints {
        let (host, port) = parse_remove_endpoint_spec(spec)?;
        merge_operations.push(PolicyMergeOperation {
            operation: Some(policy_merge_operation::Operation::RemoveEndpoint(
                RemoveNetworkEndpoint {
                    rule_name: String::new(),
                    host: host.clone(),
                    port,
                },
            )),
        });
        preview_operations.push(PolicyMergeOp::RemoveEndpoint {
            rule_name: None,
            host,
            port,
        });
    }

    for name in remove_rules {
        let rule_name = name.trim();
        if rule_name.is_empty() {
            return Err(miette!("--remove-rule values must not be empty"));
        }
        merge_operations.push(PolicyMergeOperation {
            operation: Some(policy_merge_operation::Operation::RemoveRule(
                RemoveNetworkRule {
                    rule_name: rule_name.to_string(),
                },
            )),
        });
        preview_operations.push(PolicyMergeOp::RemoveRule {
            rule_name: rule_name.to_string(),
        });
    }

    for ((host, port), rules) in group_allow_rules(add_allow)? {
        merge_operations.push(PolicyMergeOperation {
            operation: Some(policy_merge_operation::Operation::AddAllowRules(
                AddAllowRules {
                    host: host.clone(),
                    port,
                    rules: rules.clone(),
                },
            )),
        });
        preview_operations.push(PolicyMergeOp::AddAllowRules { host, port, rules });
    }

    for ((host, port), deny_rules) in group_deny_rules(add_deny)? {
        merge_operations.push(PolicyMergeOperation {
            operation: Some(policy_merge_operation::Operation::AddDenyRules(
                AddDenyRules {
                    host: host.clone(),
                    port,
                    deny_rules: deny_rules.clone(),
                },
            )),
        });
        preview_operations.push(PolicyMergeOp::AddDenyRules {
            host,
            port,
            deny_rules,
        });
    }

    if merge_operations.is_empty() {
        return Err(miette!(
            "policy update requires at least one operation flag"
        ));
    }

    Ok(PolicyUpdatePlan {
        merge_operations,
        preview_operations,
    })
}

fn group_allow_rules(specs: &[String]) -> Result<BTreeMap<(String, u32), Vec<L7Rule>>> {
    let mut grouped = BTreeMap::new();
    for spec in specs {
        let parsed = parse_l7_rule_spec("--add-allow", spec)?;
        grouped
            .entry((parsed.host, parsed.port))
            .or_insert_with(Vec::new)
            .push(L7Rule {
                allow: Some(L7Allow {
                    method: parsed.method,
                    path: parsed.path,
                    command: String::new(),
                    query: Default::default(),
                }),
            });
    }
    Ok(grouped)
}

fn group_deny_rules(specs: &[String]) -> Result<BTreeMap<(String, u32), Vec<L7DenyRule>>> {
    let mut grouped = BTreeMap::new();
    for spec in specs {
        let parsed = parse_l7_rule_spec("--add-deny", spec)?;
        grouped
            .entry((parsed.host, parsed.port))
            .or_insert_with(Vec::new)
            .push(L7DenyRule {
                method: parsed.method,
                path: parsed.path,
                command: String::new(),
                query: Default::default(),
            });
    }
    Ok(grouped)
}

#[derive(Debug, Clone)]
struct ParsedL7RuleSpec {
    host: String,
    port: u32,
    method: String,
    path: String,
}

fn parse_l7_rule_spec(flag: &str, spec: &str) -> Result<ParsedL7RuleSpec> {
    let parts = spec.split(':').collect::<Vec<_>>();
    if parts.len() != 4 {
        return Err(miette!(
            "{flag} expects host:port:METHOD:path_glob, got '{spec}'"
        ));
    }

    let host = parse_host(flag, spec, parts[0])?;
    let port = parse_port(flag, spec, parts[1])?;
    let method = parts[2].trim();
    if method.is_empty() {
        return Err(miette!("{flag} has an empty METHOD segment in '{spec}'"));
    }
    if method.contains(char::is_whitespace) {
        return Err(miette!(
            "{flag} METHOD must not contain whitespace in '{spec}'"
        ));
    }

    let path = parts[3].trim();
    if path.is_empty() {
        return Err(miette!("{flag} has an empty path segment in '{spec}'"));
    }
    if !path.starts_with('/') && path != "**" && !path.starts_with("**/") {
        return Err(miette!(
            "{flag} path must start with '/' or be '**', got '{path}' in '{spec}'"
        ));
    }

    Ok(ParsedL7RuleSpec {
        host,
        port,
        method: method.to_ascii_uppercase(),
        path: path.to_string(),
    })
}

fn parse_remove_endpoint_spec(spec: &str) -> Result<(String, u32)> {
    let parts = spec.split(':').collect::<Vec<_>>();
    if parts.len() != 2 {
        return Err(miette!("--remove-endpoint expects host:port, got '{spec}'"));
    }

    Ok((
        parse_host("--remove-endpoint", spec, parts[0])?,
        parse_port("--remove-endpoint", spec, parts[1])?,
    ))
}

fn parse_add_endpoint_spec(spec: &str) -> Result<NetworkEndpoint> {
    let parts = spec.split(':').collect::<Vec<_>>();
    if !(2..=5).contains(&parts.len()) {
        return Err(miette!(
            "--add-endpoint expects host:port[:access[:protocol[:enforcement]]], got '{spec}'"
        ));
    }

    let host = parse_host("--add-endpoint", spec, parts[0])?;
    let port = parse_port("--add-endpoint", spec, parts[1])?;

    let access = parts.get(2).copied().unwrap_or("").trim();
    let protocol = parts.get(3).copied().unwrap_or("").trim();
    let enforcement = parts.get(4).copied().unwrap_or("").trim();

    if parts.len() == 3 && access.is_empty() {
        return Err(miette!(
            "--add-endpoint has an empty access segment in '{spec}'; omit it entirely if you do not need access or protocol fields"
        ));
    }
    if !enforcement.is_empty() && protocol.is_empty() {
        return Err(miette!(
            "--add-endpoint cannot set enforcement without protocol in '{spec}'"
        ));
    }
    if !access.is_empty() && !matches!(access, "read-only" | "read-write" | "full") {
        return Err(miette!(
            "--add-endpoint access segment must be one of read-only, read-write, or full; got '{access}' in '{spec}'"
        ));
    }
    if !protocol.is_empty() && !matches!(protocol, "rest" | "sql") {
        return Err(miette!(
            "--add-endpoint protocol segment must be 'rest' or 'sql'; got '{protocol}' in '{spec}'"
        ));
    }
    if !enforcement.is_empty() && !matches!(enforcement, "enforce" | "audit") {
        return Err(miette!(
            "--add-endpoint enforcement segment must be 'enforce' or 'audit'; got '{enforcement}' in '{spec}'"
        ));
    }

    Ok(NetworkEndpoint {
        host,
        port,
        ports: vec![port],
        protocol: protocol.to_string(),
        enforcement: enforcement.to_string(),
        access: access.to_string(),
        ..Default::default()
    })
}

fn parse_host(flag: &str, spec: &str, host: &str) -> Result<String> {
    let host = host.trim();
    if host.is_empty() {
        return Err(miette!("{flag} has an empty host segment in '{spec}'"));
    }
    if host.contains(char::is_whitespace) {
        return Err(miette!(
            "{flag} host must not contain whitespace in '{spec}'"
        ));
    }
    if host.contains('/') {
        return Err(miette!("{flag} host must not contain '/' in '{spec}'"));
    }
    Ok(host.to_string())
}

fn parse_port(flag: &str, spec: &str, port: &str) -> Result<u32> {
    let port = port.trim();
    if port.is_empty() {
        return Err(miette!("{flag} has an empty port segment in '{spec}'"));
    }
    let parsed = port.parse::<u32>().map_err(|_| {
        miette!("{flag} port segment must be a base-10 integer, got '{port}' in '{spec}'")
    })?;
    if parsed == 0 || parsed > 65535 {
        return Err(miette!(
            "{flag} port must be in the range 1-65535, got '{parsed}' in '{spec}'"
        ));
    }
    Ok(parsed)
}

fn dedup_strings(values: &[String]) -> Vec<String> {
    let mut deduped = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if !trimmed.is_empty() && !deduped.iter().any(|existing| existing == trimmed) {
            deduped.push(trimmed.to_string());
        }
    }
    deduped
}

#[cfg(test)]
mod tests {
    use super::build_policy_update_plan;

    #[test]
    fn parse_add_endpoint_basic_l4() {
        let plan =
            build_policy_update_plan(&["ghcr.io:443".to_string()], &[], &[], &[], &[], &[], None)
                .expect("plan should build");
        assert_eq!(plan.merge_operations.len(), 1);
        assert_eq!(plan.preview_operations.len(), 1);
    }

    #[test]
    fn parse_add_endpoint_rejects_bad_access() {
        let error = build_policy_update_plan(
            &["api.github.com:443:write-ish".to_string()],
            &[],
            &[],
            &[],
            &[],
            &[],
            None,
        )
        .expect_err("plan should fail");
        assert!(error.to_string().contains("access segment"));
    }

    #[test]
    fn parse_add_endpoint_allows_empty_access_when_protocol_present() {
        build_policy_update_plan(
            &["api.github.com:443::rest:enforce".to_string()],
            &[],
            &[],
            &[],
            &[],
            &[],
            None,
        )
        .expect("plan should build");
    }

    #[test]
    fn parse_add_deny_rejects_empty_method() {
        let error = build_policy_update_plan(
            &[],
            &[],
            &["api.github.com:443::/repos/**".to_string()],
            &[],
            &[],
            &[],
            None,
        )
        .expect_err("plan should fail");
        assert!(error.to_string().contains("METHOD"));
    }

    #[test]
    fn parse_add_allow_rejects_non_absolute_path() {
        let error = build_policy_update_plan(
            &[],
            &[],
            &[],
            &["api.github.com:443:GET:repos/**".to_string()],
            &[],
            &[],
            None,
        )
        .expect_err("plan should fail");
        assert!(error.to_string().contains("path must start with '/'"));
    }

    #[test]
    fn parse_add_endpoint_rejects_enforcement_without_protocol() {
        let error = build_policy_update_plan(
            &["api.github.com:443:read-only::enforce".to_string()],
            &[],
            &[],
            &[],
            &[],
            &[],
            None,
        )
        .expect_err("plan should fail");
        assert!(
            error
                .to_string()
                .contains("cannot set enforcement without protocol")
        );
    }

    #[test]
    fn parse_remove_endpoint_rejects_out_of_range_port() {
        let error = build_policy_update_plan(
            &[],
            &["api.github.com:70000".to_string()],
            &[],
            &[],
            &[],
            &[],
            None,
        )
        .expect_err("plan should fail");
        assert!(error.to_string().contains("range 1-65535"));
    }

    #[test]
    fn binary_requires_add_endpoint() {
        let error =
            build_policy_update_plan(&[], &[], &[], &[], &[], &["/usr/bin/gh".to_string()], None)
                .expect_err("plan should fail");
        assert!(error.to_string().contains("--binary"));
    }

    #[test]
    fn rule_name_rejects_multiple_add_endpoints() {
        let error = build_policy_update_plan(
            &["api.github.com:443".to_string(), "ghcr.io:443".to_string()],
            &[],
            &[],
            &[],
            &[],
            &[],
            Some("shared"),
        )
        .expect_err("plan should fail");
        assert!(error.to_string().contains("exactly one --add-endpoint"));
    }
}
