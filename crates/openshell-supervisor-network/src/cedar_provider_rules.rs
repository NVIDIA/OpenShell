// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider rules of a Cedar sandbox, compiled to Cedar for token grants.
//!
//! The gateway delivers attached providers' rules to a Cedar sandbox in
//! `provider_credential_rules`, with each endpoint stamped with the owner of
//! its token grants. `openshell_policy::cedar` validates them and compiles
//! them to Cedar; this module supplies the sandbox-specific preparation in
//! between: symlinked binaries resolved in the sandbox, and the protocol
//! spellings, L7 checks, MCP tool aliases, and access presets the YAML engine
//! applies when it loads the same rules. No Rego is involved.

use std::collections::HashMap;

use miette::Result;
use openshell_core::proto::{NetworkPolicyRule, SandboxPolicy as ProtoSandboxPolicy};
use openshell_ocsf::{ConfigStateChangeBuilder, SeverityId, StateId, StatusId, ocsf_emit};
use openshell_policy_cedar::TokenGrantRules;
use serde_json::Value;

use crate::policy_data::{
    endpoint_policy_value, normalize_endpoint_protocols, normalize_l7_policy_rule_aliases,
};

/// Compiles provider rules for token-grant owner selection.
///
/// Returns `None` when no provider endpoint carries an owner. Binary paths
/// are resolved in the root filesystem of `entrypoint_pid` (none when it is
/// 0), as a YAML sandbox resolves them.
///
/// # Errors
///
/// Returns an error when the rules fail the validation a YAML sandbox
/// applies to them, or the generated Cedar does not load.
pub fn compile(
    rules: &HashMap<String, NetworkPolicyRule>,
    entrypoint_pid: u32,
) -> Result<Option<TokenGrantRules>> {
    let Some(policy) = openshell_policy::cedar::provider_token_grant_policy(rules)? else {
        return Ok(None);
    };
    let data = normalized_rules(&policy, entrypoint_pid)?;
    let compiled = openshell_policy::cedar::compile_provider_token_grants(&data)?;
    report(&compiled);
    Ok(Some(compiled))
}

/// Normalizes validated provider rules as the YAML engine loads them.
fn normalized_rules(policy: &ProtoSandboxPolicy, entrypoint_pid: u32) -> Result<Value> {
    let network_policies: serde_json::Map<String, Value> = policy
        .network_policies
        .iter()
        .map(|(key, rule)| {
            let binaries: Vec<Value> = rule
                .binaries
                .iter()
                .flat_map(|binary| {
                    let resolved = crate::binary_resolution::resolve_policy_binary(
                        &binary.path,
                        entrypoint_pid,
                    );
                    std::iter::once(binary.path.clone()).chain(resolved)
                })
                .map(|path| serde_json::json!({ "path": path }))
                .collect();
            let endpoints: Vec<Value> = rule
                .endpoints
                .iter()
                .map(|endpoint| endpoint_policy_value(endpoint, ""))
                .collect();
            (
                key.clone(),
                serde_json::json!({ "endpoints": endpoints, "binaries": binaries }),
            )
        })
        .collect();
    let mut data = serde_json::json!({ "network_policies": network_policies });
    normalize_endpoint_protocols(&mut data);
    let (errors, _) = crate::l7::validate_l7_policies(&data);
    if !errors.is_empty() {
        return Err(miette::miette!(
            "provider credential rules have {} invalid L7 configurations",
            errors.len()
        ));
    }
    normalize_l7_policy_rule_aliases(&mut data);
    let _ = crate::l7::expand_access_presets(&mut data);
    Ok(data)
}

/// Reports provider selectors compiled other than exactly.
fn report(compiled: &TokenGrantRules) {
    if compiled.untranslated().is_empty() {
        return;
    }
    let notes: Vec<String> = compiled
        .untranslated()
        .iter()
        .map(ToString::to_string)
        .collect();
    let (severity, summary) = if compiled.fail_closed_reason().is_some() {
        (
            SeverityId::Medium,
            "no token grant is admitted for any request",
        )
    } else {
        (
            SeverityId::Low,
            "some token grants are admitted for fewer requests",
        )
    };
    tracing::warn!(rules = ?notes, "provider rules not translated exactly to Cedar; {summary}");
    ocsf_emit!(
        ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
            .severity(severity)
            .status(StatusId::Success)
            .state(StateId::Enabled, "provider token grants compiled")
            .unmapped("untranslated_provider_rules", serde_json::json!(notes))
            .message(format!(
                "CONFIG:TOKEN_GRANTS provider rules not translated exactly to Cedar [count:{}]; {summary}",
                notes.len()
            ))
            .build()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{
        L7Allow, L7DenyRule, L7QueryMatcher, L7Rule, McpOptions, NetworkBinary, NetworkEndpoint,
    };
    use openshell_policy_cedar::{ProviderEndpoint, ProviderPolicy, RuleMatcher, ValueMatcher};

    #[test]
    fn normalized_rules_round_trip_through_the_provider_compiler() {
        let matcher = L7QueryMatcher {
            glob: String::new(),
            any: vec!["prod*".into(), "staging".into()],
        };
        let rest = NetworkEndpoint {
            host: "api.example.com".into(),
            ports: vec![443, 8443],
            path: "/v1/**".into(),
            protocol: "rest".into(),
            token_grant_owner: "rest-owner".into(),
            rules: vec![L7Rule {
                allow: Some(L7Allow {
                    method: "GET".into(),
                    path: "/v1/items/*".into(),
                    query: HashMap::from([
                        ("env".into(), matcher.clone()),
                        (
                            "region".into(),
                            L7QueryMatcher {
                                glob: "us*".into(),
                                ..Default::default()
                            },
                        ),
                    ]),
                    ..Default::default()
                }),
            }],
            deny_rules: vec![L7DenyRule {
                method: "DELETE".into(),
                path: "/v1/private/**".into(),
                query: HashMap::from([
                    ("env".into(), matcher),
                    (
                        "region".into(),
                        L7QueryMatcher {
                            glob: "us*".into(),
                            ..Default::default()
                        },
                    ),
                ]),
                ..Default::default()
            }],
            ..Default::default()
        };
        let mcp = NetworkEndpoint {
            host: "mcp.example.com".into(),
            port: 443,
            protocol: "mcp".into(),
            token_grant_owner: "mcp-owner".into(),
            mcp: Some(McpOptions {
                versions: vec![
                    openshell_policy_schema::DEFAULT_MCP_PROTOCOL_VERSION
                        .as_str()
                        .to_string(),
                ],
                allow_all_known_mcp_methods: Some(true),
                ..Default::default()
            }),
            rules: vec![L7Rule {
                allow: Some(L7Allow {
                    method: "tools/call".into(),
                    params: HashMap::from([(
                        "name".into(),
                        L7QueryMatcher {
                            glob: "read_*".into(),
                            ..Default::default()
                        },
                    )]),
                    ..Default::default()
                }),
            }],
            ..Default::default()
        };
        let graphql = NetworkEndpoint {
            host: "graphql.example.com".into(),
            port: 443,
            protocol: "graphql".into(),
            token_grant_owner: "graphql-owner".into(),
            rules: vec![L7Rule {
                allow: Some(L7Allow {
                    operation_type: "query".into(),
                    operation_name: "List*".into(),
                    fields: vec!["items".into()],
                    ..Default::default()
                }),
            }],
            ..Default::default()
        };
        let ip_only = NetworkEndpoint {
            port: 9443,
            allowed_ips: vec!["192.0.2.0/24".into()],
            token_grant_owner: "ip-owner".into(),
            ..Default::default()
        };
        let policy = ProtoSandboxPolicy {
            network_policies: HashMap::from([(
                "provider".into(),
                NetworkPolicyRule {
                    binaries: vec![NetworkBinary {
                        path: "/usr/bin/client".into(),
                    }],
                    endpoints: vec![rest, mcp, graphql, ip_only],
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        let data = normalized_rules(&policy, 0).expect("normalize provider rules");
        let actual = openshell_policy::cedar::compile_provider_token_grants(&data)
            .expect("compile normalized rules");
        let mut query = std::collections::BTreeMap::from([(
            "env".into(),
            ValueMatcher {
                globs: vec!["prod*".into(), "staging".into()],
            },
        )]);
        query.insert(
            "region".into(),
            ValueMatcher {
                globs: vec!["us*".into()],
            },
        );
        let expected = TokenGrantRules::compile(&[ProviderPolicy {
            name: "provider".into(),
            binaries: vec!["/usr/bin/client".into()],
            endpoints: vec![
                ProviderEndpoint {
                    host: "api.example.com".into(),
                    ports: vec![443, 8443],
                    path: "/v1/**".into(),
                    protocol: "rest".into(),
                    token_grant_owner: "rest-owner".into(),
                    rules: vec![RuleMatcher {
                        method: Some("GET".into()),
                        path: Some("/v1/items/*".into()),
                        query: query.clone(),
                        ..Default::default()
                    }],
                    deny_rules: vec![RuleMatcher {
                        method: Some("DELETE".into()),
                        path: Some("/v1/private/**".into()),
                        query,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                ProviderEndpoint {
                    host: "mcp.example.com".into(),
                    ports: vec![443],
                    protocol: "mcp".into(),
                    token_grant_owner: "mcp-owner".into(),
                    mcp_allow_all_known_methods: true,
                    rules: vec![RuleMatcher {
                        method: Some("tools/call".into()),
                        params: std::collections::BTreeMap::from([(
                            "name".into(),
                            ValueMatcher {
                                globs: vec!["read_*".into()],
                            },
                        )]),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                ProviderEndpoint {
                    host: "graphql.example.com".into(),
                    ports: vec![443],
                    protocol: "graphql".into(),
                    token_grant_owner: "graphql-owner".into(),
                    rules: vec![RuleMatcher {
                        operation_type: Some("query".into()),
                        operation_name: Some("List*".into()),
                        fields: vec!["items".into()],
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                ProviderEndpoint {
                    ports: vec![9443],
                    has_allowed_ips: true,
                    token_grant_owner: "ip-owner".into(),
                    ..Default::default()
                },
            ],
        }])
        .expect("compile independently typed provider rules");
        assert!(
            actual.untranslated().is_empty(),
            "{:?}",
            actual.untranslated()
        );
        assert_eq!(actual.policy_text(), expected.policy_text());
    }
}
