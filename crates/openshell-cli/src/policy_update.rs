// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap};

use miette::{Result, miette};
use openshell_core::proto::policy_merge_operation;
use openshell_core::proto::{
    AddAllowRules, AddDenyRules, AddNetworkRule, L7Allow, L7DenyRule, L7Rule,
    L7RuleTarget as ProtoL7RuleTarget, NetworkBinary, NetworkEndpoint, NetworkPolicyRule,
    PolicyMergeOperation, RemoveNetworkEndpoint, RemoveNetworkRule,
};
use openshell_policy::{L7BinaryScope, L7RuleTarget, PolicyMergeOp, generated_rule_name};

/// Equivalent gateway and local-preview operations for one policy update.
#[derive(Debug, Clone)]
pub struct PolicyUpdatePlan {
    pub merge_operations: Vec<PolicyMergeOperation>,
    pub preview_operations: Vec<PolicyMergeOp>,
}

/// Parse operation flags and require explicit scope for every L7 append.
#[allow(clippy::too_many_arguments)]
pub fn build_policy_update_plan(
    add_endpoints: &[String],
    remove_endpoints: &[String],
    add_deny: &[String],
    add_allow: &[String],
    remove_rules: &[String],
    binaries: &[String],
    rule_name: Option<&str>,
    any_binary: bool,
    endpoint_path: Option<&str>,
) -> Result<PolicyUpdatePlan> {
    let has_l7_append = !add_allow.is_empty() || !add_deny.is_empty();
    if binaries.iter().any(|binary| binary.trim().is_empty()) {
        return Err(miette!("--binary values must not be empty"));
    }
    if any_binary && !binaries.is_empty() {
        return Err(miette!("--any-binary and --binary are mutually exclusive"));
    }
    // Scope flags describe the existing rule for L7 appends, but create scope
    // for AddRule. Reject mixed use so one declaration cannot mean both.
    if has_l7_append && !add_endpoints.is_empty() {
        return Err(miette!(
            "--add-endpoint cannot be combined with --add-allow or --add-deny; submit separate updates"
        ));
    }
    if has_l7_append {
        if rule_name.is_none_or(|name| name.trim().is_empty()) {
            return Err(miette!(
                "--add-allow and --add-deny require a nonempty --rule-name"
            ));
        }
        if binaries.is_empty() && !any_binary {
            return Err(miette!(
                "--add-allow and --add-deny require the complete --binary list or explicit --any-binary"
            ));
        }
    } else {
        if any_binary {
            return Err(miette!(
                "--any-binary can only be used with --add-allow or --add-deny"
            ));
        }
        if endpoint_path.is_some() {
            return Err(miette!(
                "--endpoint-path can only be used with --add-allow or --add-deny"
            ));
        }
        if !binaries.is_empty() && add_endpoints.is_empty() {
            return Err(miette!(
                "--binary requires --add-endpoint, --add-allow, or --add-deny"
            ));
        }
        if rule_name.is_some() && add_endpoints.is_empty() {
            return Err(miette!(
                "--rule-name requires --add-endpoint, --add-allow, or --add-deny"
            ));
        }
    }
    if rule_name.is_some() && add_endpoints.len() > 1 {
        return Err(miette!(
            "--rule-name is only supported when exactly one --add-endpoint is provided"
        ));
    }
    let mut merge_operations = Vec::new();
    let mut preview_operations = Vec::new();

    let deduped_binaries = if has_l7_append {
        // L7 scope acknowledges stored paths exactly; whitespace can be part
        // of an executable filename and must survive preview and transport.
        let mut paths = Vec::new();
        for path in binaries {
            if !paths.contains(path) {
                paths.push(path.clone());
            }
        }
        paths
    } else {
        dedup_strings(binaries)
    };
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
                .map(|path| NetworkBinary { path: path.clone() })
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

    for ((host, ports), rules) in group_allow_rules(add_allow)? {
        let target = build_l7_target(
            rule_name,
            host,
            ports,
            endpoint_path,
            &deduped_binaries,
            any_binary,
            merge_operations.len(),
        )?;
        merge_operations.push(PolicyMergeOperation {
            operation: Some(policy_merge_operation::Operation::AddAllowRules(
                AddAllowRules {
                    target: Some(l7_target_to_proto(&target)),
                    rules: rules.clone(),
                },
            )),
        });
        preview_operations.push(PolicyMergeOp::AddAllowRules { target, rules });
    }

    for ((host, ports), deny_rules) in group_deny_rules(add_deny)? {
        let target = build_l7_target(
            rule_name,
            host,
            ports,
            endpoint_path,
            &deduped_binaries,
            any_binary,
            merge_operations.len(),
        )?;
        merge_operations.push(PolicyMergeOperation {
            operation: Some(policy_merge_operation::Operation::AddDenyRules(
                AddDenyRules {
                    target: Some(l7_target_to_proto(&target)),
                    deny_rules: deny_rules.clone(),
                },
            )),
        });
        preview_operations.push(PolicyMergeOp::AddDenyRules { target, deny_rules });
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

/// Build the target once so preview and RPC cannot disagree about affected scope.
#[allow(clippy::too_many_arguments)]
fn build_l7_target(
    rule_name: Option<&str>,
    host: String,
    ports: Vec<u32>,
    path: Option<&str>,
    binaries: &[String],
    any_binary: bool,
    operation_index: usize,
) -> Result<L7RuleTarget> {
    let target = L7RuleTarget {
        rule_name: rule_name.unwrap_or_default().trim().to_string(),
        host,
        ports,
        // An explicit empty string selects the unscoped endpoint; None leaves
        // endpoint selection to the unique-match check in the policy engine.
        path: path.map(ToString::to_string),
        binaries: if any_binary {
            L7BinaryScope::Any
        } else {
            L7BinaryScope::Restricted(
                binaries
                    .iter()
                    .map(|path| NetworkBinary { path: path.clone() })
                    .collect(),
            )
        },
    };
    target
        .validate(operation_index)
        .map_err(|error| miette!("{error}"))?;
    Ok(target)
}

fn l7_target_to_proto(target: &L7RuleTarget) -> ProtoL7RuleTarget {
    let (binaries, any_binary) = match &target.binaries {
        L7BinaryScope::Any => (Vec::new(), true),
        L7BinaryScope::Restricted(binaries) => (binaries.clone(), false),
    };
    ProtoL7RuleTarget {
        rule_name: target.rule_name.clone(),
        host: target.host.clone(),
        ports: target.ports.clone(),
        path: target.path.clone(),
        binaries,
        any_binary,
    }
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

/// L7 payloads grouped by normalized host and complete canonical port set.
type GroupedL7Rules<T> = BTreeMap<(String, Vec<u32>), Vec<T>>;

fn group_allow_rules(specs: &[String]) -> Result<GroupedL7Rules<L7Rule>> {
    let mut grouped = BTreeMap::new();
    for spec in specs {
        let parsed = parse_l7_rule_spec("--add-allow", spec)?;
        grouped
            .entry((parsed.host, parsed.ports))
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
                    params: HashMap::default(),
                }),
            });
    }
    Ok(grouped)
}

fn group_deny_rules(specs: &[String]) -> Result<GroupedL7Rules<L7DenyRule>> {
    let mut grouped = BTreeMap::new();
    for spec in specs {
        let parsed = parse_l7_rule_spec("--add-deny", spec)?;
        grouped
            .entry((parsed.host, parsed.ports))
            .or_insert_with(Vec::new)
            .push(L7DenyRule {
                method: parsed.method,
                path: parsed.path,
                command: String::new(),
                query: HashMap::default(),
                operation_type: String::new(),
                operation_name: String::new(),
                fields: Vec::new(),
                params: HashMap::default(),
            });
    }
    Ok(grouped)
}

#[derive(Debug, Clone)]
struct ParsedL7RuleSpec {
    host: String,
    ports: Vec<u32>,
    method: String,
    path: String,
}

fn parse_l7_rule_spec(flag: &str, spec: &str) -> Result<ParsedL7RuleSpec> {
    // Only the first three colons delimit fields; request paths may contain
    // literal colons and must survive both preview and RPC unchanged.
    let segments = spec.splitn(4, ':').collect::<Vec<_>>();
    if segments.len() != 4 {
        return Err(miette!(
            "{flag} expects host:port[,port...]:METHOD:path_glob, got '{spec}'"
        ));
    }

    let host = parse_host(flag, spec, segments[0])?.to_ascii_lowercase();
    let mut ports = segments[1]
        .split(',')
        .map(|port| parse_port(flag, spec, port))
        .collect::<Result<Vec<_>>>()?;
    // Equivalent port declarations must group into the same endpoint update.
    ports.sort_unstable();
    ports.dedup();
    let method = segments[2].trim();
    if method.is_empty() {
        return Err(miette!("{flag} has an empty METHOD segment in '{spec}'"));
    }
    if method.contains(char::is_whitespace) {
        return Err(miette!(
            "{flag} METHOD must not contain whitespace in '{spec}'"
        ));
    }

    let path = segments[3].trim();
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
        ports,
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
    if !protocol.is_empty() && !matches!(protocol, "tcp" | "rest" | "websocket" | "sql") {
        return Err(miette!(
            "--add-endpoint protocol segment must be 'tcp', 'rest', 'websocket', or 'sql'; got '{protocol}' in '{spec}'"
        ));
    }
    if protocol == "tcp" && (!access.is_empty() || !enforcement.is_empty()) {
        return Err(miette!(
            "--add-endpoint protocol 'tcp' does not support access or enforcement in '{spec}'"
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

const ALLOWED_IP_OPTION_PREFIX: &str = "allowed-ip=";

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
            "allow-uninspected-credentials" => {
                endpoint.allow_uninspected_credentials = true;
            }
            "websocket-credential-rewrite" => {
                ensure_websocket_credential_rewrite_protocol(spec, endpoint)?;
                endpoint.websocket_credential_rewrite = true;
            }
            "request-body-credential-rewrite" => {
                ensure_request_body_credential_rewrite_protocol(spec, endpoint)?;
                endpoint.request_body_credential_rewrite = true;
            }
            _ if option.starts_with(ALLOWED_IP_OPTION_PREFIX) => {
                let allowed_ip =
                    parse_allowed_ip_value(spec, &option[ALLOWED_IP_OPTION_PREFIX.len()..])?;
                if !endpoint.allowed_ips.contains(&allowed_ip) {
                    endpoint.allowed_ips.push(allowed_ip);
                }
            }
            _ => {
                return Err(miette!(
                    "--add-endpoint options segment supports only 'allow-uninspected-credentials', 'websocket-credential-rewrite', 'request-body-credential-rewrite', and 'allowed-ip=<CIDR-or-IP>'; got '{option}' in '{spec}'"
                ));
            }
        }
    }

    Ok(())
}

/// Validate the value part of an `allowed-ip=<CIDR-or-IP>` endpoint option.
fn parse_allowed_ip_value(spec: &str, value: &str) -> Result<String> {
    let allowed_ip = value.trim();
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
    Ok(allowed_ip.to_string())
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
        parse_allowed_ip_value,
    };
    use openshell_core::proto::policy_merge_operation::Operation;
    use openshell_policy::{L7BinaryScope, PolicyMergeOp};

    #[test]
    fn l7_appends_preserve_literal_binary_paths() {
        use openshell_core::proto::{NetworkBinary, NetworkEndpoint, NetworkPolicyRule};
        use openshell_policy::{merge_policy, restrictive_default_policy};

        for binary_path in ["/opt/tools/curl", "/opt/tools/curl ", "/opt/tools/curl\t"] {
            for is_deny in [false, true] {
                let mut policy = restrictive_default_policy();
                policy.network_policies.insert(
                    "api".to_string(),
                    NetworkPolicyRule {
                        name: "api".to_string(),
                        binaries: vec![NetworkBinary {
                            path: binary_path.to_string(),
                        }],
                        endpoints: vec![NetworkEndpoint {
                            host: "api.example.com".to_string(),
                            port: 443,
                            ports: vec![443],
                            protocol: "rest".to_string(),
                            access: "read-only".to_string(),
                            ..Default::default()
                        }],
                    },
                );
                let specs = ["api.example.com:443:POST:/v1/**".to_string()];
                let plan = build_policy_update_plan(
                    &[],
                    &[],
                    if is_deny { &specs } else { &[] },
                    if is_deny { &[] } else { &specs },
                    &[],
                    &[binary_path.to_string(), binary_path.to_string()],
                    Some("api"),
                )
                .expect("literal nonempty binary paths must parse");

                // The merge compares the declaration with the stored literal
                // path, so this also detects normalization in the preview.
                let merged = merge_policy(policy, &plan.preview_operations)
                    .expect("the exact stored binary scope must merge");
                assert!(merged.changed);
                assert_eq!(
                    merged.policy.network_policies["api"].binaries[0].path,
                    binary_path
                );
                let target = match plan.merge_operations[0].operation.as_ref() {
                    Some(Operation::AddAllowRules(wire)) => wire.target.as_ref(),
                    Some(Operation::AddDenyRules(wire)) => wire.target.as_ref(),
                    other => panic!("expected L7 append, got {other:?}"),
                }
                .expect("explicit wire target");
                assert_eq!(target.binaries.len(), 1);
                assert_eq!(target.binaries[0].path, binary_path);
            }
        }
    }

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
            false,
            None,
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
    fn parse_add_endpoint_accepts_explicit_tcp_protocol() {
        let plan = build_policy_update_plan(
            &["database.example.com:5432::tcp".to_string()],
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
        assert_eq!(rule.endpoints[0].protocol, "tcp");
        assert!(rule.endpoints[0].access.is_empty());
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
    fn parse_add_endpoint_enables_allow_uninspected_credentials() {
        let plan = build_policy_update_plan(
            &["api.vendor.example:443::::allow-uninspected-credentials".to_string()],
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
        assert!(rule.endpoints[0].allow_uninspected_credentials);
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
    fn parse_allowed_ip_value_accepts_trimmed_cidr_and_ip() {
        assert_eq!(
            parse_allowed_ip_value("spec", "10.0.0.0/8").expect("CIDR should parse"),
            "10.0.0.0/8"
        );
        assert_eq!(
            parse_allowed_ip_value("spec", "  192.168.1.10  ").expect("IP should parse"),
            "192.168.1.10"
        );
    }

    #[test]
    fn parse_allowed_ip_value_rejects_empty_and_interior_whitespace() {
        let empty = parse_allowed_ip_value("spec", "   ").expect_err("empty value must fail");
        assert!(empty.to_string().contains("must include a CIDR or IP"));

        let spaced =
            parse_allowed_ip_value("spec", "10.0.0.0/8 172.16.0.0/12").expect_err("must fail");
        assert!(spaced.to_string().contains("must not contain whitespace"));
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
            &["/usr/bin/curl".to_string()],
            Some("realtime"),
        )
        .expect("plan should build");

        let PolicyMergeOp::AddAllowRules { target, rules } = &plan.preview_operations[0] else {
            panic!("expected add-allow preview");
        };
        assert_eq!(target.host, "realtime.example.com");
        assert_eq!(target.ports, vec![443]);
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
            &["/usr/bin/gh".to_string()],
            Some("github"),
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
            &["/usr/bin/gh".to_string()],
            Some("github"),
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
    fn parse_add_endpoint_rejects_l7_fields_with_tcp() {
        let error = build_policy_update_plan(
            &["database.example.com:5432::tcp:enforce".to_string()],
            &[],
            &[],
            &[],
            &[],
            &[],
            None,
        )
        .expect_err("TCP must reject L7 enforcement");

        assert!(
            error
                .to_string()
                .contains("does not support access or enforcement")
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
    fn binary_requires_endpoint_addition_or_l7_append() {
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

    #[test]
    fn l7_appends_require_each_scope_declaration_independently() {
        for (rule_name, binaries, any_binary, expected_error) in [
            (
                None,
                vec!["/usr/bin/curl".to_string()],
                false,
                "--rule-name",
            ),
            (
                Some("  "),
                vec!["/usr/bin/curl".to_string()],
                false,
                "--rule-name",
            ),
            (Some("api"), vec![], false, "complete --binary list"),
            (
                Some("api"),
                vec!["/usr/bin/curl".to_string()],
                true,
                "mutually exclusive",
            ),
            (
                Some("api"),
                vec![" ".to_string()],
                false,
                "must not be empty",
            ),
        ] {
            for is_deny in [false, true] {
                let specs = ["api.example.com:443:POST:/admin".to_string()];
                let error = build_policy_update_plan_with_options(
                    &[],
                    &[],
                    if is_deny { &specs } else { &[] },
                    if is_deny { &[] } else { &specs },
                    &[],
                    &binaries,
                    rule_name,
                    any_binary,
                    None,
                )
                .expect_err("each L7 append must explicitly declare target scope");
                assert!(error.to_string().contains(expected_error), "{error}");
            }
        }
    }

    #[test]
    fn l7_appends_reject_each_invalid_port() {
        for ports in ["", "0", "65536", "443,", "443,,8443", "443,no"] {
            let error = build_policy_update_plan(
                &[],
                &[],
                &[],
                &[format!("api.example.com:{ports}:GET:/v1/**")],
                &[],
                &["/usr/bin/curl".to_string()],
                Some("api"),
            )
            .expect_err("all declared ports must be valid");
            assert!(error.to_string().contains("port"), "{error}");
        }
    }

    #[test]
    fn l7_scope_flags_reject_non_l7_operations() {
        for (any_binary, endpoint_path, expected_error) in [
            (true, None, "--any-binary"),
            (false, Some(""), "--endpoint-path"),
            (false, Some("/v1/**"), "--endpoint-path"),
        ] {
            let error = build_policy_update_plan_with_options(
                &["api.example.com:443".to_string()],
                &[],
                &[],
                &[],
                &[],
                &[],
                None,
                any_binary,
                endpoint_path,
            )
            .expect_err("L7-only flags must not be ignored for AddRule");
            assert!(error.to_string().contains(expected_error), "{error}");
        }
    }

    #[test]
    fn l7_appends_reject_mixed_add_endpoint_scope() {
        for is_deny in [false, true] {
            let specs = ["api.example.com:443:POST:/admin".to_string()];
            let error = build_policy_update_plan(
                &["api.example.com:443".to_string()],
                &[],
                if is_deny { &specs } else { &[] },
                if is_deny { &[] } else { &specs },
                &[],
                &["/usr/bin/curl".to_string()],
                Some("api"),
            )
            .expect_err("one binary declaration cannot both create and acknowledge scope");
            assert!(error.to_string().contains("cannot be combined"), "{error}");
        }
    }

    #[test]
    fn l7_appends_group_canonical_ports_and_preserve_preview_wire_scope() {
        let plan = build_policy_update_plan_with_options(
            &[],
            &[],
            &[
                "API.EXAMPLE.COM:8443,443:DELETE:/v1/a:b".to_string(),
                "api.example.com:443,8443,443:PUT:/v1/a:b".to_string(),
            ],
            &[
                "API.EXAMPLE.COM:8443,443,443:POST:/v1/a:b".to_string(),
                "api.example.com:443,8443:GET:/v1/a:b".to_string(),
            ],
            &[],
            &[
                "/usr/bin/curl".to_string(),
                "/usr/bin/python3".to_string(),
                "/usr/bin/curl".to_string(),
            ],
            Some("api"),
            false,
            Some("/v1/**"),
        )
        .expect("complete repeated scope should build");
        assert_eq!(plan.merge_operations.len(), 2);
        assert_eq!(plan.preview_operations.len(), 2);
        for (wire, preview) in plan.merge_operations.iter().zip(&plan.preview_operations) {
            let (wire_target, target) = match (wire.operation.as_ref(), preview) {
                (
                    Some(Operation::AddAllowRules(wire)),
                    PolicyMergeOp::AddAllowRules { target, rules },
                ) => {
                    assert_eq!(wire.rules, *rules);
                    assert_eq!(rules.len(), 2);
                    assert_eq!(
                        rules[0].allow.as_ref().expect("allow matcher").path,
                        "/v1/a:b"
                    );
                    (wire.target.as_ref().expect("wire target"), target)
                }
                (
                    Some(Operation::AddDenyRules(wire)),
                    PolicyMergeOp::AddDenyRules { target, deny_rules },
                ) => {
                    assert_eq!(wire.deny_rules, *deny_rules);
                    assert_eq!(deny_rules.len(), 2);
                    assert_eq!(deny_rules[0].path, "/v1/a:b");
                    (wire.target.as_ref().expect("wire target"), target)
                }
                _ => panic!("preview and wire operation kinds must agree"),
            };
            assert_eq!(target.rule_name, "api");
            assert_eq!(target.host, "api.example.com");
            assert_eq!(target.ports, vec![443, 8443]);
            assert_eq!(target.path.as_deref(), Some("/v1/**"));
            let L7BinaryScope::Restricted(binaries) = &target.binaries else {
                panic!("the explicit binary list must remain restricted");
            };
            assert_eq!(binaries.len(), 2);
            assert_eq!(binaries[0].path, "/usr/bin/curl");
            assert_eq!(binaries[1].path, "/usr/bin/python3");
            assert_eq!(wire_target.rule_name, target.rule_name);
            assert_eq!(wire_target.host, target.host);
            assert_eq!(wire_target.ports, target.ports);
            assert_eq!(wire_target.path, target.path);
            assert_eq!(wire_target.binaries, *binaries);
            assert!(!wire_target.any_binary);
        }
    }

    #[test]
    fn l7_any_binary_and_endpoint_path_presence_survive_preview_and_wire() {
        for endpoint_path in [None, Some(""), Some("/v1/**")] {
            let plan = build_policy_update_plan_with_options(
                &[],
                &[],
                &["api.example.com:443:DELETE:/v1/a:b".to_string()],
                &["api.example.com:443:POST:/v1/a:b".to_string()],
                &[],
                &[],
                Some("api"),
                true,
                endpoint_path,
            )
            .expect("any-binary and endpoint selector should build");
            for (wire, preview) in plan.merge_operations.iter().zip(&plan.preview_operations) {
                let (wire_target, target) = match (wire.operation.as_ref(), preview) {
                    (
                        Some(Operation::AddAllowRules(wire)),
                        PolicyMergeOp::AddAllowRules { target, .. },
                    ) => (wire.target.as_ref().expect("wire target"), target),
                    (
                        Some(Operation::AddDenyRules(wire)),
                        PolicyMergeOp::AddDenyRules { target, .. },
                    ) => (wire.target.as_ref().expect("wire target"), target),
                    _ => panic!("preview and wire operation kinds must agree"),
                };
                assert_eq!(target.path.as_deref(), endpoint_path);
                assert!(matches!(target.binaries, L7BinaryScope::Any));
                assert_eq!(wire_target.rule_name, target.rule_name);
                assert_eq!(wire_target.host, target.host);
                assert_eq!(wire_target.ports, target.ports);
                assert_eq!(wire_target.path, target.path);
                assert!(wire_target.any_binary);
                assert!(wire_target.binaries.is_empty());
            }
        }
    }
}
