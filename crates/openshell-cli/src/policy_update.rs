// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap};

use miette::{Result, miette};
use openshell_core::proto::policy_merge_operation;
use openshell_core::proto::{
    AddAllowRules, AddDenyRules, AddNetworkRule, L7Allow, L7DenyRule, L7Rule, NetworkBinary,
    NetworkEndpoint, NetworkPolicyRule, PolicyMergeOperation, RemoveNetworkEndpoint,
    RemoveNetworkRule,
};
use openshell_policy::{PolicyMergeOp, generated_rule_name};

#[derive(Debug, Clone)]
pub struct PolicyUpdatePlan {
    pub merge_operations: Vec<PolicyMergeOperation>,
    pub preview_operations: Vec<PolicyMergeOp>,
}

#[allow(clippy::too_many_arguments)]
pub fn build_policy_update_plan(
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
            .map_or_else(
                || generated_rule_name(&endpoint.host, endpoint.port),
                ToString::to_string,
            );
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

fn ensure_websocket_credential_rewrite_protocol(
    spec: &str,
    endpoint: &NetworkEndpoint,
) -> Result<()> {
    if matches!(endpoint.protocol.as_str(), "rest" | "websocket") {
        return Ok(());
    }
    let protocol = if endpoint.protocol.is_empty() {
        "<empty>"
    } else {
        endpoint.protocol.as_str()
    };
    Err(miette!(
        "websocket-credential-rewrite endpoint option requires --add-endpoint protocol segment to be 'rest' or 'websocket'; got '{protocol}' in '{spec}'"
    ))
}

fn ensure_request_body_credential_rewrite_protocol(
    spec: &str,
    endpoint: &NetworkEndpoint,
) -> Result<()> {
    if endpoint.protocol == "rest" {
        return Ok(());
    }
    let protocol = if endpoint.protocol.is_empty() {
        "<empty>"
    } else {
        endpoint.protocol.as_str()
    };
    Err(miette!(
        "request-body-credential-rewrite endpoint option requires --add-endpoint protocol segment to be 'rest'; got '{protocol}' in '{spec}'"
    ))
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
                    query: HashMap::default(),
                    operation_type: String::new(),
                    operation_name: String::new(),
                    fields: Vec::new(),
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
                query: HashMap::default(),
                operation_type: String::new(),
                operation_name: String::new(),
                fields: Vec::new(),
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
    if !(2..=6).contains(&parts.len()) {
        return Err(miette!(
            "--add-endpoint expects host:port[:access[:protocol[:enforcement[:options]]]], got '{spec}'"
        ));
    }

    let host = parse_host("--add-endpoint", spec, parts[0])?;
    let port = parse_port("--add-endpoint", spec, parts[1])?;

    let access = parts.get(2).copied().unwrap_or("").trim();
    let protocol = parts.get(3).copied().unwrap_or("").trim();
    let enforcement = parts.get(4).copied().unwrap_or("").trim();
    let options = parts.get(5).copied().unwrap_or("").trim();

    if parts.len() == 3 && access.is_empty() {
        return Err(miette!(
            "--add-endpoint has an empty access segment in '{spec}'; omit it entirely if you do not need access or protocol fields"
        ));
    }
    if parts.len() == 6 && options.is_empty() {
        return Err(miette!(
            "--add-endpoint has an empty options segment in '{spec}'; omit it entirely if you do not need endpoint options"
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
    if !protocol.is_empty() && !matches!(protocol, "rest" | "websocket" | "sql") {
        return Err(miette!(
            "--add-endpoint protocol segment must be 'rest', 'websocket', or 'sql'; got '{protocol}' in '{spec}'"
        ));
    }
    if !enforcement.is_empty() && !matches!(enforcement, "enforce" | "audit") {
        return Err(miette!(
            "--add-endpoint enforcement segment must be 'enforce' or 'audit'; got '{enforcement}' in '{spec}'"
        ));
    }

    let mut endpoint = NetworkEndpoint {
        host,
        port,
        ports: vec![port],
        protocol: protocol.to_string(),
        enforcement: enforcement.to_string(),
        access: access.to_string(),
        ..Default::default()
    };
    apply_add_endpoint_options(spec, &mut endpoint, options)?;
    Ok(endpoint)
}

fn apply_add_endpoint_options(
    spec: &str,
    endpoint: &mut NetworkEndpoint,
    options: &str,
) -> Result<()> {
    if options.is_empty() {
        return Ok(());
    }

    for option in options.split(',') {
        let option = option.trim();
        if option.is_empty() {
            return Err(miette!(
                "--add-endpoint options segment must not contain empty options in '{spec}'"
            ));
        }
        match option {
            "websocket-credential-rewrite" => {
                ensure_websocket_credential_rewrite_protocol(spec, endpoint)?;
                endpoint.websocket_credential_rewrite = true;
            }
            "request-body-credential-rewrite" => {
                ensure_request_body_credential_rewrite_protocol(spec, endpoint)?;
                endpoint.request_body_credential_rewrite = true;
            }
            _ => {
                let Some(allowed_ip) = option.strip_prefix("allowed-ip=") else {
                    return Err(miette!(
                        "--add-endpoint options segment supports only 'websocket-credential-rewrite', 'request-body-credential-rewrite', and 'allowed-ip=<CIDR-or-IP>'; got '{option}' in '{spec}'"
                    ));
                };
                let allowed_ip = allowed_ip.trim();
                if allowed_ip.is_empty() {
                    return Err(miette!(
                        "--add-endpoint allowed-ip option must include a CIDR or IP value in '{spec}'"
                    ));
                }
                if allowed_ip.contains(char::is_whitespace) {
                    return Err(miette!(
                        "--add-endpoint allowed-ip option must not contain whitespace in '{spec}'"
                    ));
                }
                if !endpoint
                    .allowed_ips
                    .iter()
                    .any(|existing| existing == allowed_ip)
                {
                    endpoint.allowed_ips.push(allowed_ip.to_string());
                }
            }
        }
    }

    Ok(())
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
    use super::{
        PolicyUpdatePlan, build_policy_update_plan as build_policy_update_plan_with_options,
    };
    use openshell_policy::PolicyMergeOp;

    fn build_policy_update_plan(
        add_endpoints: &[String],
        remove_endpoints: &[String],
        add_deny: &[String],
        add_allow: &[String],
        remove_rules: &[String],
        binaries: &[String],
        rule_name: Option<&str>,
    ) -> miette::Result<PolicyUpdatePlan> {
        build_policy_update_plan_with_options(
            add_endpoints,
            remove_endpoints,
            add_deny,
            add_allow,
            remove_rules,
            binaries,
            rule_name,
        )
    }

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
    fn parse_add_endpoint_accepts_websocket_protocol() {
        let plan = build_policy_update_plan(
            &["realtime.example.com:443:read-write:websocket:enforce".to_string()],
            &[],
            &[],
            &[],
            &[],
            &[],
            None,
        )
        .expect("plan should build");

        let PolicyMergeOp::AddRule { rule, .. } = &plan.preview_operations[0] else {
            panic!("expected add-rule preview");
        };
        let endpoint = &rule.endpoints[0];
        assert_eq!(endpoint.host, "realtime.example.com");
        assert_eq!(endpoint.protocol, "websocket");
        assert_eq!(endpoint.access, "read-write");
        assert_eq!(endpoint.enforcement, "enforce");
    }

    #[test]
    fn parse_add_endpoint_enables_websocket_credential_rewrite() {
        let plan = build_policy_update_plan(
            &["realtime.example.com:443:read-write:websocket:enforce:websocket-credential-rewrite"
                .to_string()],
            &[],
            &[],
            &[],
            &[],
            &[],
            None,
        )
        .expect("plan should build");

        let PolicyMergeOp::AddRule { rule, .. } = &plan.preview_operations[0] else {
            panic!("expected add-rule preview");
        };
        assert!(rule.endpoints[0].websocket_credential_rewrite);
    }

    #[test]
    fn parse_add_endpoint_enables_websocket_credential_rewrite_on_rest_compat_endpoint() {
        let plan = build_policy_update_plan(
            &[
                "realtime.example.com:443:read-write:rest:enforce:websocket-credential-rewrite"
                    .to_string(),
            ],
            &[],
            &[],
            &[],
            &[],
            &[],
            None,
        )
        .expect("plan should build");

        let PolicyMergeOp::AddRule { rule, .. } = &plan.preview_operations[0] else {
            panic!("expected add-rule preview");
        };
        assert!(rule.endpoints[0].websocket_credential_rewrite);
    }

    #[test]
    fn parse_add_endpoint_enables_request_body_credential_rewrite_on_rest_endpoint() {
        let plan = build_policy_update_plan(
            &[
                "api.example.com:443:read-write:rest:enforce:request-body-credential-rewrite"
                    .to_string(),
            ],
            &[],
            &[],
            &[],
            &[],
            &[],
            None,
        )
        .expect("plan should build");

        let PolicyMergeOp::AddRule { rule, .. } = &plan.preview_operations[0] else {
            panic!("expected add-rule preview");
        };
        let endpoint = &rule.endpoints[0];
        assert_eq!(endpoint.protocol, "rest");
        assert!(endpoint.request_body_credential_rewrite);
    }

    #[test]
    fn parse_add_endpoint_merges_allowed_ips_with_websocket_options() {
        let plan = build_policy_update_plan(
            &[
                "realtime.example.com:443:read-write:websocket:enforce:websocket-credential-rewrite,allowed-ip=10.0.0.0/8,allowed-ip=172.16.0.0/12,allowed-ip=10.0.0.0/8"
                    .to_string(),
            ],
            &[],
            &[],
            &[],
            &[],
            &[],
            None,
        )
        .expect("plan should build");

        let PolicyMergeOp::AddRule { rule, .. } = &plan.preview_operations[0] else {
            panic!("expected add-rule preview");
        };
        let endpoint = &rule.endpoints[0];
        assert!(endpoint.websocket_credential_rewrite);
        assert_eq!(
            endpoint.allowed_ips,
            vec!["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()]
        );
    }

    #[test]
    fn parse_add_endpoint_accepts_allowed_ip_on_rest_endpoint() {
        let plan = build_policy_update_plan(
            &["api.example.com:443:read-write:rest:enforce:allowed-ip=192.168.0.0/16".to_string()],
            &[],
            &[],
            &[],
            &[],
            &[],
            None,
        )
        .expect("plan should build");

        let PolicyMergeOp::AddRule { rule, .. } = &plan.preview_operations[0] else {
            panic!("expected add-rule preview");
        };
        assert_eq!(rule.endpoints[0].allowed_ips, vec!["192.168.0.0/16"]);
    }

    #[test]
    fn parse_add_endpoint_rejects_empty_allowed_ip() {
        let error = build_policy_update_plan(
            &["api.example.com:443:read-write:rest:enforce:allowed-ip=".to_string()],
            &[],
            &[],
            &[],
            &[],
            &[],
            None,
        )
        .expect_err("plan should fail");
        assert!(error.to_string().contains("allowed-ip option"));
    }

    #[test]
    fn websocket_credential_rewrite_rejects_l4_endpoint() {
        let error = build_policy_update_plan(
            &["realtime.example.com:443::::websocket-credential-rewrite".to_string()],
            &[],
            &[],
            &[],
            &[],
            &[],
            None,
        )
        .expect_err("plan should fail");
        assert!(error.to_string().contains("protocol segment"));
    }

    #[test]
    fn request_body_credential_rewrite_rejects_non_rest_endpoint() {
        let error = build_policy_update_plan(
            &[
                "realtime.example.com:443:read-write:websocket:enforce:request-body-credential-rewrite"
                    .to_string(),
            ],
            &[],
            &[],
            &[],
            &[],
            &[],
            None,
        )
        .expect_err("plan should fail");

        assert!(error.to_string().contains("protocol segment"));
        assert!(error.to_string().contains("'rest'"));
    }

    #[test]
    fn parse_add_endpoint_rejects_unknown_options() {
        let error = build_policy_update_plan(
            &["realtime.example.com:443:read-write:websocket:enforce:future-option".to_string()],
            &[],
            &[],
            &[],
            &[],
            &[],
            None,
        )
        .expect_err("plan should fail");
        assert!(error.to_string().contains("options segment"));
    }

    #[test]
    fn parse_add_allow_accepts_websocket_text_method() {
        let plan = build_policy_update_plan(
            &[],
            &[],
            &[],
            &["realtime.example.com:443:websocket_text:/v1/messages/**".to_string()],
            &[],
            &[],
            None,
        )
        .expect("plan should build");

        let PolicyMergeOp::AddAllowRules { host, port, rules } = &plan.preview_operations[0] else {
            panic!("expected add-allow preview");
        };
        assert_eq!(host, "realtime.example.com");
        assert_eq!(*port, 443);
        let allow = rules[0].allow.as_ref().expect("allow rule");
        assert_eq!(allow.method, "WEBSOCKET_TEXT");
        assert_eq!(allow.path, "/v1/messages/**");
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
