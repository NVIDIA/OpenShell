// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};

use openshell_core::proto::{
    L7Allow, L7DenyRule, L7Rule, NetworkBinary, NetworkEndpoint, NetworkPolicyRule, SandboxPolicy,
};

use crate::is_provider_rule_name;

const DEFAULT_JSON_RPC_MAX_BODY_BYTES: u32 = 64 * 1024;

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
    /// An `AddRule` operation has no endpoint authorization to merge.
    EmptyAddRuleEndpoints {
        operation_index: usize,
        rule_name: String,
    },
    /// Overlapping endpoints have different effective MCP inspection contracts.
    McpContractConflict {
        operation_index: usize,
        host: String,
        port: u32,
        /// Rendered effective contract already established at this endpoint.
        existing: String,
        /// Rendered effective contract the operation asked for.
        incoming: String,
    },
    /// A newly added binary would inherit an existing endpoint authorization
    /// that the incoming rule did not declare.
    NewBinaryWouldInheritAuthorization {
        operation_index: usize,
        rule_name: String,
        binary_path: String,
        host: String,
        ports: Vec<u32>,
    },
    /// Existing binaries would inherit a new or changed endpoint authorization,
    /// but the incoming rule did not declare the existing binary scope.
    ExistingBinariesWouldInheritAuthorization {
        operation_index: usize,
        rule_name: String,
        host: String,
        ports: Vec<u32>,
        /// Existing binary scope the operation must also declare to proceed.
        undeclared_binaries: Vec<String>,
    },
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
            Self::EmptyAddRuleEndpoints {
                operation_index,
                rule_name,
            } => write!(
                f,
                "merge operation {operation_index} add-rule '{rule_name}' must contain at least one endpoint"
            ),
            Self::McpContractConflict {
                operation_index,
                host,
                port,
                existing,
                incoming,
            } => write!(
                f,
                "merge operation {operation_index} cannot combine MCP contracts at {host}:{port}: existing {existing}, incoming {incoming}"
            ),
            Self::NewBinaryWouldInheritAuthorization {
                operation_index,
                rule_name,
                binary_path,
                host,
                ports,
            } => write!(
                f,
                "merge operation {operation_index} add-rule '{rule_name}' would grant new binary '{binary_path}' undeclared authorization for {host} on ports {ports:?}"
            ),
            Self::ExistingBinariesWouldInheritAuthorization {
                operation_index,
                rule_name,
                host,
                ports,
                undeclared_binaries,
            } => write!(
                f,
                "merge operation {operation_index} add-rule '{rule_name}' would grant existing binaries new or changed authorization for {host} on ports {ports:?}; also declare {}",
                undeclared_binaries.join(", ")
            ),
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
                "endpoint {host}:{port} uses unsupported protocol '{protocol}'; this operation currently supports only protocol 'rest' or 'websocket'"
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

/// Returns true iff `policy` semantically contains the rule an `AddRule`
/// merge of `proposed` would produce.
///
/// "Contains" means: for every endpoint in `proposed`, some rule in
/// `policy.network_policies` has an endpoint whose authorization covers the
/// full proposed endpoint and whose binaries cover every proposed binary.
///
/// The sandbox's `policy.local /wait` long-poll uses this to decide when
/// the local supervisor has actually loaded a policy that includes the
/// chunk the agent just had approved. A whole-policy hash compare is wrong
/// in both directions: it can wake the wait on unrelated reloads (false
/// wakeup) and can fail to wake when the supervisor reloaded between two
/// `/wait` calls (false sleep). This check is the property the agent
/// actually cares about — "is my rule in effect right now?".
///
/// Coverage is intentionally stricter than endpoint overlap used during
/// merging. Every proposed port and every complete protobuf allow/deny matcher
/// must be loaded. Runtime-defaulted scalars are compared by effective value so
/// omitted defaults do not cause false negatives while explicit policy changes
/// do not become wildcards. Different loaded rules may jointly cover the
/// proposal, but every binary-by-endpoint pair must be present in that union.
///
/// Coverage asks whether the loaded policy contains the proposal, not whether
/// the two are identical. The loaded endpoint is a superset of any proposal
/// that merged into an endpoint carrying earlier authorizations, so
/// `endpoint_authorization_covers` compares merge-widened fields by containment
/// and only exact-matches the fields the merge never widens.
pub fn policy_covers_rule(policy: &SandboxPolicy, proposed: &NetworkPolicyRule) -> bool {
    if proposed.endpoints.is_empty() {
        return false;
    }
    proposed.endpoints.iter().all(|target_endpoint| {
        if proposed.binaries.is_empty() {
            return policy.network_policies.values().any(|rule| {
                rule.binaries.is_empty()
                    && rule
                        .endpoints
                        .iter()
                        .any(|endpoint| endpoint_authorization_covers(endpoint, target_endpoint))
            });
        }

        proposed.binaries.iter().all(|target_binary| {
            policy.network_policies.values().any(|rule| {
                binary_scope_covers(rule, target_binary)
                    && rule
                        .endpoints
                        .iter()
                        .any(|endpoint| endpoint_authorization_covers(endpoint, target_endpoint))
            })
        })
    })
}

fn binary_scope_covers(rule: &NetworkPolicyRule, proposed: &NetworkBinary) -> bool {
    rule.binaries.is_empty()
        || rule
            .binaries
            .iter()
            .any(|binary| binary.path == proposed.path)
}

fn endpoint_authorization_covers(loaded: &NetworkEndpoint, proposed: &NetworkEndpoint) -> bool {
    if !loaded.host.eq_ignore_ascii_case(&proposed.host)
        || loaded.path != proposed.path
        || !ports_cover(loaded, proposed)
        || !protocols_match(&loaded.protocol, &proposed.protocol)
        || effective_tls(&loaded.tls) != effective_tls(&proposed.tls)
        || effective_enforcement(&loaded.enforcement)
            != effective_enforcement(&proposed.enforcement)
        || !mcp_contracts_match(loaded, proposed)
    {
        return false;
    }

    if !proposed.access.is_empty() && loaded.access != proposed.access {
        return false;
    }

    // Split by how `merge_endpoint` treats each field.
    //
    // Widened fields (list appends and `|=` flags) use containment: merging
    // into an endpoint that already carries them leaves the loaded copy a
    // superset of the proposal, so equality would report "not covered" for a
    // proposal that did land and leave the `/wait` long-poll spinning until
    // its deadline.
    //
    // Retained fields keep exact comparison: the merge never widens them, so a
    // difference means the incoming value was dropped in favor of the existing
    // one and the proposal genuinely is not loaded.
    contains_all(&loaded.rules, &proposed.rules)
        && contains_all(&loaded.deny_rules, &proposed.deny_rules)
        && contains_all(&loaded.allowed_ips, &proposed.allowed_ips)
        && flag_covers(loaded.allow_encoded_slash, proposed.allow_encoded_slash)
        && flag_covers(
            loaded.websocket_credential_rewrite,
            proposed.websocket_credential_rewrite,
        )
        && flag_covers(
            loaded.request_body_credential_rewrite,
            proposed.request_body_credential_rewrite,
        )
        && flag_covers(loaded.advisor_proposed, proposed.advisor_proposed)
        && loaded.persisted_queries == proposed.persisted_queries
        && loaded.graphql_persisted_queries == proposed.graphql_persisted_queries
        && loaded.graphql_max_body_bytes == proposed.graphql_max_body_bytes
        && loaded.credential_signing == proposed.credential_signing
        && loaded.signing_service == proposed.signing_service
        && loaded.signing_region == proposed.signing_region
        && (endpoint_uses_mcp(loaded)
            || loaded.json_rpc_max_body_bytes == proposed.json_rpc_max_body_bytes)
}

/// Containment for a field the merge appends to: every proposed entry must be
/// loaded, but the loaded endpoint may carry entries from earlier merges.
fn contains_all<T: PartialEq>(loaded: &[T], proposed: &[T]) -> bool {
    proposed.iter().all(|item| loaded.contains(item))
}

/// Containment for a field the merge combines with `|=`: the loaded flag only
/// ever gains bits, so coverage holds unless the proposal set a bit that is
/// missing from the loaded endpoint.
fn flag_covers(loaded: bool, proposed: bool) -> bool {
    loaded || !proposed
}

fn endpoint_authorizations_equivalent(left: &NetworkEndpoint, right: &NetworkEndpoint) -> bool {
    endpoint_authorization_covers(left, right) && endpoint_authorization_covers(right, left)
}

fn ports_cover(loaded: &NetworkEndpoint, proposed: &NetworkEndpoint) -> bool {
    let loaded_ports = canonical_ports(loaded);
    canonical_ports(proposed)
        .iter()
        .all(|port| loaded_ports.contains(port))
}

fn protocols_match(left: &str, right: &str) -> bool {
    if left.eq_ignore_ascii_case("mcp") || right.eq_ignore_ascii_case("mcp") {
        left.eq_ignore_ascii_case("mcp") && right.eq_ignore_ascii_case("mcp")
    } else {
        left == right
    }
}

fn effective_tls(value: &str) -> &str {
    match value {
        "" | "terminate" | "passthrough" => "auto",
        value => value,
    }
}

fn effective_enforcement(value: &str) -> &str {
    if value.is_empty() { "audit" } else { value }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EffectiveMcpContract {
    strict_tool_names: bool,
    allow_all_known_mcp_methods: bool,
    max_body_bytes: u32,
}

fn effective_mcp_contract(endpoint: &NetworkEndpoint) -> Option<EffectiveMcpContract> {
    endpoint
        .protocol
        .eq_ignore_ascii_case("mcp")
        .then(|| EffectiveMcpContract {
            strict_tool_names: endpoint
                .mcp
                .as_ref()
                .and_then(|options| options.strict_tool_names)
                .unwrap_or(true),
            allow_all_known_mcp_methods: endpoint
                .mcp
                .as_ref()
                .and_then(|options| options.allow_all_known_mcp_methods)
                .unwrap_or(false),
            max_body_bytes: effective_json_rpc_max_body_bytes(endpoint.json_rpc_max_body_bytes),
        })
}

fn effective_json_rpc_max_body_bytes(value: u32) -> u32 {
    if value == 0 {
        DEFAULT_JSON_RPC_MAX_BODY_BYTES
    } else {
        value
    }
}

fn endpoint_uses_mcp(endpoint: &NetworkEndpoint) -> bool {
    endpoint.protocol.eq_ignore_ascii_case("mcp") || endpoint.mcp.is_some()
}

fn mcp_contracts_match(left: &NetworkEndpoint, right: &NetworkEndpoint) -> bool {
    match (effective_mcp_contract(left), effective_mcp_contract(right)) {
        (None, None) => !endpoint_uses_mcp(left) && !endpoint_uses_mcp(right),
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

pub fn merge_policy(
    policy: SandboxPolicy,
    operations: &[PolicyMergeOp],
) -> Result<PolicyMergeResult, PolicyMergeError> {
    let mut merged = policy.clone();
    let mut warnings = Vec::new();

    // Validate and apply in request order. `merged` is private until every
    // operation succeeds, so failures remain atomic without allowing a later
    // malformed operation to replace the error from an earlier operation.
    for (operation_index, operation) in operations.iter().enumerate() {
        validate_operation(operation_index, operation)?;
        apply_operation(&mut merged, operation_index, operation, &mut warnings)?;
    }

    let changed = merged != policy;
    Ok(PolicyMergeResult {
        policy: merged,
        warnings,
        changed,
    })
}

fn validate_operation(
    operation_index: usize,
    operation: &PolicyMergeOp,
) -> Result<(), PolicyMergeError> {
    if let PolicyMergeOp::AddRule { rule_name, rule } = operation {
        if rule_name.trim().is_empty() {
            return Err(PolicyMergeError::MissingRuleNameForAddRule);
        }
        if rule.endpoints.is_empty() {
            return Err(PolicyMergeError::EmptyAddRuleEndpoints {
                operation_index,
                rule_name: rule_name.clone(),
            });
        }
    }
    Ok(())
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
    operation_index: usize,
    operation: &PolicyMergeOp,
    warnings: &mut Vec<PolicyMergeWarning>,
) -> Result<(), PolicyMergeError> {
    match operation {
        PolicyMergeOp::AddRule { rule_name, rule } => {
            add_rule(policy, operation_index, rule_name, rule, warnings)?;
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
            ensure_method_path_endpoint(endpoint, host, *port)?;
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
            ensure_method_path_endpoint(endpoint, host, *port)?;
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
    operation_index: usize,
    rule_name: &str,
    incoming_rule: &NetworkPolicyRule,
    warnings: &mut Vec<PolicyMergeWarning>,
) -> Result<(), PolicyMergeError> {
    let mut incoming_rule = incoming_rule.clone();
    normalize_rule(&mut incoming_rule);
    if incoming_rule.name.is_empty() {
        incoming_rule.name = rule_name.to_string();
    }

    // Endpoint-overlap fallback: when a chunk arrives with a new rule_name
    // that doesn't already exist, fold it into a same-host/port rule if one
    // is present. This is intentional for user-authored policies (incremental
    // refinements live under one rule name).
    //
    // Provider-injected rules (`_provider_*` — see `compose.rs::provider_rule_name`)
    // are deliberately EXCLUDED from this fallback. Provider profiles supply a
    // baseline layer that should stay separate from agent/user contributions;
    // merging an agent's narrow proposal into a provider's broad rule would
    // (a) expand the provider rule's `access` shorthand into wildcard
    // `path: "**"` rules at the prover's input, masking the agent's narrow
    // scope behind the existing broad coverage, and (b) silently widen the
    // provider rule's binary list. The agent's contribution is kept on its
    // own rule key, the prover sees the actual narrow proposal, and the
    // reviewer gets honest signal about what's being added.
    let target_key = if policy.network_policies.contains_key(rule_name) {
        Some(rule_name.to_string())
    } else {
        let mut keys: Vec<_> = policy.network_policies.keys().cloned().collect();
        keys.sort();
        keys.into_iter()
            .filter(|k| !is_provider_rule_name(k))
            .find(|key| {
                policy
                    .network_policies
                    .get(key)
                    .is_some_and(|existing_rule| {
                        rules_share_endpoint(existing_rule, &incoming_rule)
                    })
            })
    };

    if let Some(key) = target_key {
        let existing_rule = policy
            .network_policies
            .get_mut(&key)
            .expect("existing rule must be present");
        merge_rules(
            existing_rule,
            &incoming_rule,
            operation_index,
            rule_name,
            warnings,
        )?;
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
    operation_index: usize,
    rule_name: &str,
    warnings: &mut Vec<PolicyMergeWarning>,
) -> Result<(), PolicyMergeError> {
    // A rule authorizes the Cartesian product of its binaries and endpoints.
    // Build the final endpoint set off to the side, then reject any implicit
    // grants before publishing either half of that product.
    let mut merged_endpoints = existing_rule.endpoints.clone();
    let mut endpoint_warnings = Vec::new();
    for incoming_endpoint in &incoming_rule.endpoints {
        let mut incoming_endpoint = incoming_endpoint.clone();
        normalize_endpoint(&mut incoming_endpoint);
        if let Some(existing_endpoint) =
            find_matching_endpoint_mut(&mut merged_endpoints, &incoming_endpoint)
        {
            merge_endpoint(
                existing_endpoint,
                &incoming_endpoint,
                operation_index,
                &mut endpoint_warnings,
            )?;
        } else {
            merged_endpoints.push(incoming_endpoint);
        }
    }

    ensure_authorization_inheritance_is_declared(
        existing_rule,
        incoming_rule,
        &merged_endpoints,
        operation_index,
        rule_name,
    )?;

    existing_rule.endpoints = merged_endpoints;
    append_unique_binaries(&mut existing_rule.binaries, &incoming_rule.binaries);
    warnings.extend(endpoint_warnings);
    Ok(())
}

fn merge_endpoint(
    existing: &mut NetworkEndpoint,
    incoming: &NetworkEndpoint,
    operation_index: usize,
    warnings: &mut Vec<PolicyMergeWarning>,
) -> Result<(), PolicyMergeError> {
    let host = if existing.host.is_empty() {
        incoming.host.clone()
    } else {
        existing.host.clone()
    };
    let existing_ports = canonical_ports(existing);
    let incoming_ports = canonical_ports(incoming);
    let port = existing_ports
        .into_iter()
        .find(|port| incoming_ports.contains(port))
        .or_else(|| incoming_ports.first().copied())
        .unwrap_or(0);

    let promotes_l4_to_mcp = promotes_l4_endpoint_to_mcp(existing, incoming);
    ensure_mcp_contract_compatible(existing, incoming, operation_index, &host, port)?;

    if existing.host.is_empty() {
        existing.host.clone_from(&incoming.host);
    }
    if existing.path.is_empty() {
        existing.path.clone_from(&incoming.path);
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
    if promotes_l4_to_mcp {
        existing.mcp.clone_from(&incoming.mcp);
        existing.json_rpc_max_body_bytes = incoming.json_rpc_max_body_bytes;
    }
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
    existing.allow_encoded_slash |= incoming.allow_encoded_slash;
    existing.websocket_credential_rewrite |= incoming.websocket_credential_rewrite;
    existing.request_body_credential_rewrite |= incoming.request_body_credential_rewrite;
    existing.advisor_proposed |= incoming.advisor_proposed;
    normalize_endpoint(existing);
    Ok(())
}

fn ensure_mcp_contract_compatible(
    existing: &NetworkEndpoint,
    incoming: &NetworkEndpoint,
    operation_index: usize,
    host: &str,
    port: u32,
) -> Result<(), PolicyMergeError> {
    if promotes_l4_endpoint_to_mcp(existing, incoming) || mcp_contracts_match(existing, incoming) {
        return Ok(());
    }

    Err(PolicyMergeError::McpContractConflict {
        operation_index,
        host: host.to_string(),
        port,
        existing: describe_mcp_contract(existing),
        incoming: describe_mcp_contract(incoming),
    })
}

/// Renders the values `mcp_contracts_match` compares, so the reported conflict
/// names the fields that have to agree. The effective contract is rendered
/// rather than the raw options because an omitted option and its default are
/// the same contract.
fn describe_mcp_contract(endpoint: &NetworkEndpoint) -> String {
    effective_mcp_contract(endpoint).map_or_else(
        || format!("non-mcp(protocol='{}')", endpoint.protocol),
        |contract| {
            format!(
                "mcp(strict_tool_names={}, allow_all_known_mcp_methods={}, max_body_bytes={})",
                contract.strict_tool_names,
                contract.allow_all_known_mcp_methods,
                contract.max_body_bytes
            )
        },
    )
}

fn promotes_l4_endpoint_to_mcp(existing: &NetworkEndpoint, incoming: &NetworkEndpoint) -> bool {
    // Only an endpoint without an established inspection contract can adopt
    // the complete incoming MCP contract instead of combining two contracts.
    existing.protocol.is_empty()
        && existing.mcp.is_none()
        && existing.json_rpc_max_body_bytes == 0
        && effective_mcp_contract(incoming).is_some()
}

fn ensure_authorization_inheritance_is_declared(
    existing_rule: &NetworkPolicyRule,
    incoming_rule: &NetworkPolicyRule,
    merged_endpoints: &[NetworkEndpoint],
    operation_index: usize,
    rule_name: &str,
) -> Result<(), PolicyMergeError> {
    let existing_binary_paths: HashSet<&str> = existing_rule
        .binaries
        .iter()
        .map(|binary| binary.path.as_str())
        .collect();
    // An existing empty list already authorizes any binary, so no incoming
    // concrete path can expand that side of the Cartesian product.
    let new_binary = if existing_rule.binaries.is_empty() {
        None
    } else {
        incoming_rule
            .binaries
            .iter()
            .find(|binary| !existing_binary_paths.contains(binary.path.as_str()))
    };
    let undeclared_binaries = undeclared_existing_binaries(existing_rule, incoming_rule);

    for endpoint in merged_endpoints {
        if let Some(binary) = new_binary
            && !incoming_rule
                .endpoints
                .iter()
                .any(|declared| endpoint_authorization_covers(declared, endpoint))
        {
            return Err(PolicyMergeError::NewBinaryWouldInheritAuthorization {
                operation_index,
                rule_name: rule_name.to_string(),
                binary_path: binary.path.clone(),
                host: endpoint.host.clone(),
                ports: canonical_ports(endpoint),
            });
        }

        let endpoint_is_new_or_changed = !existing_rule
            .endpoints
            .iter()
            .any(|existing| endpoint_authorizations_equivalent(existing, endpoint));
        if endpoint_is_new_or_changed && !undeclared_binaries.is_empty() {
            return Err(
                PolicyMergeError::ExistingBinariesWouldInheritAuthorization {
                    operation_index,
                    rule_name: rule_name.to_string(),
                    host: endpoint.host.clone(),
                    ports: canonical_ports(endpoint),
                    undeclared_binaries,
                },
            );
        }
    }

    Ok(())
}

/// Existing binary scope the incoming rule failed to declare. Empty means the
/// operation covers the whole existing scope and no binary can inherit a new
/// endpoint implicitly.
///
/// An empty binary list means any binary: an incoming any-binary scope covers
/// every existing binary, while a specific incoming list can never claim an
/// existing any-binary scope.
fn undeclared_existing_binaries(
    existing_rule: &NetworkPolicyRule,
    incoming_rule: &NetworkPolicyRule,
) -> Vec<String> {
    if incoming_rule.binaries.is_empty() {
        return Vec::new();
    }
    if existing_rule.binaries.is_empty() {
        return vec!["the existing any-binary scope".to_string()];
    }

    existing_rule
        .binaries
        .iter()
        .filter(|existing| {
            !incoming_rule
                .binaries
                .iter()
                .any(|incoming| incoming.path == existing.path)
        })
        .map(|existing| existing.path.clone())
        .collect()
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
    if left.path != right.path {
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
    // `_provider_*` rules are excluded from this lookup for the same reason
    // they're excluded from `add_rule`'s endpoint-overlap fallback: callers
    // (`AddAllowRules`, `AddDenyRules`) must not mutate provider-injected
    // rules in place. If the operation should target a provider rule, the
    // caller should reference it by its exact name through the merge ops
    // that take a `rule_name`. Defense-in-depth: even if a future caller
    // accidentally passes a composed policy here, `AddAllowRules` would no
    // longer be able to expand a provider rule's `access` shorthand into
    // wildcard `path: "**"` rules (which would mask the prover's narrowness
    // verdict on agent contributions).
    let mut keys: Vec<_> = policy.network_policies.keys().cloned().collect();
    keys.sort();
    let target_key = keys
        .into_iter()
        .filter(|k| !is_provider_rule_name(k))
        .find(|key| {
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

fn ensure_method_path_endpoint(
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
    if !matches!(endpoint.protocol.as_str(), "rest" | "websocket") {
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
    let expanded = expand_access_preset(&endpoint.protocol, &access).ok_or_else(|| {
        PolicyMergeError::UnsupportedAccessPreset {
            host: host.to_string(),
            port,
            access: access.clone(),
        }
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

fn expand_access_preset(protocol: &str, access: &str) -> Option<Vec<L7Rule>> {
    let methods = match (protocol, access) {
        (_, "full") => vec!["*"],
        ("websocket", "read-only") => vec!["GET"],
        ("websocket", "read-write") => vec!["GET", "WEBSOCKET_TEXT"],
        (_, "read-only") => vec!["GET", "HEAD", "OPTIONS"],
        (_, "read-write") => vec!["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"],
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
                    operation_type: String::new(),
                    operation_name: String::new(),
                    fields: Vec::new(),
                    params: HashMap::default(),
                }),
            })
            .collect(),
    )
}

fn append_unique_binaries(existing: &mut Vec<NetworkBinary>, incoming: &[NetworkBinary]) {
    let mut seen: HashSet<String> = existing.iter().map(|binary| binary.path.clone()).collect();
    for binary in incoming {
        if let Some(existing_binary) = existing.iter_mut().find(|item| item.path == binary.path) {
            if !is_advisor_proposed_binary(binary) {
                mark_user_declared_binary(existing_binary);
            }
            continue;
        }
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
    let mut deduped: Vec<NetworkBinary> = Vec::with_capacity(values.len());
    for binary in std::mem::take(values) {
        if let Some(existing) = deduped.iter_mut().find(|item| item.path == binary.path) {
            if !is_advisor_proposed_binary(&binary) {
                mark_user_declared_binary(existing);
            }
        } else {
            deduped.push(binary);
        }
    }
    *values = deduped;
}

fn is_advisor_proposed_binary(binary: &NetworkBinary) -> bool {
    #[allow(deprecated)]
    let advisor_proposed = binary.harness;
    advisor_proposed
}

fn mark_user_declared_binary(binary: &mut NetworkBinary) {
    #[allow(deprecated)]
    {
        binary.harness = false;
    }
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
        DEFAULT_JSON_RPC_MAX_BODY_BYTES, PolicyMergeError, PolicyMergeOp, PolicyMergeWarning,
        generated_rule_name, merge_policy, policy_covers_rule,
    };
    use crate::restrictive_default_policy;
    use openshell_core::proto::{
        L7Allow, L7DenyRule, L7QueryMatcher, L7Rule, McpOptions, NetworkBinary, NetworkEndpoint,
        NetworkPolicyRule, SandboxPolicy,
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

    fn advisor_binary(path: &str) -> NetworkBinary {
        let mut binary = NetworkBinary {
            path: path.to_string(),
            ..Default::default()
        };
        #[allow(deprecated)]
        {
            binary.harness = true;
        }
        binary
    }

    fn rest_rule(method: &str, path: &str) -> L7Rule {
        L7Rule {
            allow: Some(L7Allow {
                method: method.to_string(),
                path: path.to_string(),
                command: String::new(),
                query: HashMap::new(),
                operation_type: String::new(),
                operation_name: String::new(),
                fields: Vec::new(),
                params: HashMap::default(),
            }),
        }
    }

    fn binary(path: &str) -> NetworkBinary {
        NetworkBinary {
            path: path.to_string(),
            ..Default::default()
        }
    }

    fn mcp_tool_rule(tool: &str) -> L7Rule {
        L7Rule {
            allow: Some(L7Allow {
                method: "tools/call".to_string(),
                params: HashMap::from([(
                    "name".to_string(),
                    L7QueryMatcher {
                        glob: tool.to_string(),
                        any: Vec::new(),
                    },
                )]),
                ..Default::default()
            }),
        }
    }

    fn mcp_endpoint(
        host: &str,
        ports: &[u32],
        strict_tool_names: Option<bool>,
        allow_all_known_mcp_methods: Option<bool>,
        max_body_bytes: u32,
        rules: Vec<L7Rule>,
    ) -> NetworkEndpoint {
        NetworkEndpoint {
            host: host.to_string(),
            port: ports.first().copied().unwrap_or_default(),
            ports: ports.to_vec(),
            protocol: "mcp".to_string(),
            rules,
            json_rpc_max_body_bytes: max_body_bytes,
            mcp: Some(McpOptions {
                strict_tool_names,
                allow_all_known_mcp_methods,
            }),
            ..Default::default()
        }
    }

    fn rule_with_authorizations(
        name: &str,
        endpoints: Vec<NetworkEndpoint>,
        binaries: &[&str],
    ) -> NetworkPolicyRule {
        NetworkPolicyRule {
            name: name.to_string(),
            endpoints,
            binaries: binaries.iter().map(|path| binary(path)).collect(),
        }
    }

    fn policy_with_rule(rule_name: &str, rule: NetworkPolicyRule) -> SandboxPolicy {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(rule_name.to_string(), rule);
        policy
    }

    #[test]
    fn generated_rule_name_sanitizes_host() {
        assert_eq!(
            generated_rule_name("api.github.com", 443),
            "allow_api_github_com_443"
        );
    }

    #[test]
    fn add_rule_rejects_empty_endpoints_at_the_library_boundary() {
        let error = merge_policy(
            restrictive_default_policy(),
            &[PolicyMergeOp::AddRule {
                rule_name: "empty".to_string(),
                rule: rule_with_authorizations("empty", Vec::new(), &["/usr/bin/client"]),
            }],
        )
        .expect_err("an AddRule without authorization endpoints must fail");

        assert_eq!(
            error,
            PolicyMergeError::EmptyAddRuleEndpoints {
                operation_index: 0,
                rule_name: "empty".to_string(),
            }
        );
    }

    #[test]
    fn merge_reports_the_first_failing_operation_in_request_order() {
        let operations = [
            PolicyMergeOp::AddAllowRules {
                host: "missing.example.com".to_string(),
                port: 443,
                rules: vec![rest_rule("GET", "/")],
            },
            PolicyMergeOp::AddRule {
                rule_name: "empty".to_string(),
                rule: NetworkPolicyRule::default(),
            },
        ];

        assert_eq!(
            merge_policy(restrictive_default_policy(), &operations),
            Err(PolicyMergeError::EndpointNotFound {
                host: "missing.example.com".to_string(),
                port: 443,
            })
        );
    }

    #[test]
    fn new_binary_cannot_inherit_an_undeclared_existing_rest_endpoint() {
        let existing_endpoint = NetworkEndpoint {
            protocol: "rest".to_string(),
            rules: vec![rest_rule("GET", "/admin")],
            ..endpoint("admin.example.com", 443)
        };
        let existing =
            rule_with_authorizations("existing", vec![existing_endpoint], &["/usr/bin/trusted"]);
        let incoming = rule_with_authorizations(
            "existing",
            vec![endpoint("public.example.com", 443)],
            &["/usr/bin/untrusted"],
        );

        let error = merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming,
            }],
        )
        .expect_err("the new binary did not declare the existing REST endpoint");

        assert!(matches!(
            error,
            PolicyMergeError::NewBinaryWouldInheritAuthorization {
                operation_index: 0,
                binary_path,
                host,
                ports,
                ..
            } if binary_path == "/usr/bin/untrusted"
                && host == "admin.example.com"
                && ports == vec![443]
        ));
    }

    #[test]
    fn new_binary_cannot_inherit_an_undeclared_existing_mcp_endpoint() {
        let existing = rule_with_authorizations(
            "existing",
            vec![mcp_endpoint(
                "mcp.example.com",
                &[443],
                None,
                None,
                0,
                vec![mcp_tool_rule("existing-tool")],
            )],
            &["/usr/bin/trusted"],
        );
        let incoming = rule_with_authorizations(
            "existing",
            vec![endpoint("unrelated.example.com", 443)],
            &["/usr/bin/untrusted"],
        );

        let error = merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming,
            }],
        )
        .expect_err("the new binary did not declare the existing MCP endpoint");

        assert!(matches!(
            error,
            PolicyMergeError::NewBinaryWouldInheritAuthorization {
                operation_index: 0,
                binary_path,
                host,
                ..
            } if binary_path == "/usr/bin/untrusted" && host == "mcp.example.com"
        ));
    }

    #[test]
    fn new_binary_must_declare_every_existing_mcp_endpoint() {
        let endpoint_a = mcp_endpoint(
            "a.example.com",
            &[443],
            None,
            None,
            0,
            vec![mcp_tool_rule("a")],
        );
        let endpoint_b = mcp_endpoint(
            "b.example.com",
            &[443],
            None,
            None,
            0,
            vec![mcp_tool_rule("b")],
        );
        let existing = rule_with_authorizations(
            "existing",
            vec![endpoint_a.clone(), endpoint_b],
            &["/usr/bin/trusted"],
        );
        let incoming =
            rule_with_authorizations("existing", vec![endpoint_a], &["/usr/bin/untrusted"]);

        let error = merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming,
            }],
        )
        .expect_err("declaring only one endpoint must not grant the second endpoint");

        assert!(matches!(
            error,
            PolicyMergeError::NewBinaryWouldInheritAuthorization { host, .. }
                if host == "b.example.com"
        ));
    }

    #[test]
    fn existing_binary_scope_must_be_declared_for_a_new_mcp_endpoint() {
        let existing = rule_with_authorizations(
            "existing",
            vec![endpoint("rest.example.com", 443)],
            &["/usr/bin/first", "/usr/bin/second"],
        );
        let incoming = rule_with_authorizations(
            "existing",
            vec![mcp_endpoint(
                "mcp.example.com",
                &[443],
                None,
                None,
                0,
                vec![mcp_tool_rule("new-tool")],
            )],
            &["/usr/bin/first"],
        );

        let error = merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming,
            }],
        )
        .expect_err("the undeclared second binary would inherit the new MCP endpoint");

        assert!(matches!(
            error,
            PolicyMergeError::ExistingBinariesWouldInheritAuthorization { host, .. }
                if host == "mcp.example.com"
        ));
    }

    #[test]
    fn existing_any_binary_scope_requires_an_incoming_any_binary_declaration() {
        let existing =
            rule_with_authorizations("existing", vec![endpoint("rest.example.com", 443)], &[]);
        let incoming_endpoint = mcp_endpoint(
            "mcp.example.com",
            &[443],
            None,
            None,
            0,
            vec![mcp_tool_rule("new-tool")],
        );
        let specific_incoming = rule_with_authorizations(
            "existing",
            vec![incoming_endpoint.clone()],
            &["/usr/bin/client"],
        );

        assert!(matches!(
            merge_policy(
                policy_with_rule("existing", existing.clone()),
                &[PolicyMergeOp::AddRule {
                    rule_name: "existing".to_string(),
                    rule: specific_incoming,
                }]
            ),
            Err(PolicyMergeError::ExistingBinariesWouldInheritAuthorization { .. })
        ));

        let any_binary_incoming =
            rule_with_authorizations("existing", vec![incoming_endpoint], &[]);
        assert!(
            merge_policy(
                policy_with_rule("existing", existing),
                &[PolicyMergeOp::AddRule {
                    rule_name: "existing".to_string(),
                    rule: any_binary_incoming,
                }]
            )
            .is_ok(),
            "an explicit any-binary proposal covers the existing any-binary scope"
        );
    }

    #[test]
    fn l4_endpoint_promotion_to_mcp_requires_the_complete_existing_binary_scope() {
        let existing = rule_with_authorizations(
            "existing",
            vec![endpoint("mcp.example.com", 443)],
            &["/usr/bin/first", "/usr/bin/second"],
        );
        let incoming = rule_with_authorizations(
            "existing",
            vec![mcp_endpoint(
                "mcp.example.com",
                &[443],
                None,
                None,
                0,
                vec![mcp_tool_rule("new-tool")],
            )],
            &["/usr/bin/first"],
        );

        let error = merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming,
            }],
        )
        .expect_err("the second binary did not declare the MCP promotion");

        assert!(matches!(
            error,
            PolicyMergeError::ExistingBinariesWouldInheritAuthorization {
                operation_index: 0,
                host,
                ports,
                ..
            } if host == "mcp.example.com" && ports == vec![443]
        ));
    }

    #[test]
    fn l4_endpoint_promotion_to_mcp_preserves_the_declared_contract() {
        let existing = rule_with_authorizations(
            "existing",
            vec![endpoint("mcp.example.com", 443)],
            &["/usr/bin/first", "/usr/bin/second"],
        );
        let incoming = rule_with_authorizations(
            "existing",
            vec![mcp_endpoint(
                "mcp.example.com",
                &[443],
                Some(false),
                Some(true),
                128 * 1024,
                vec![mcp_tool_rule("new-tool")],
            )],
            &["/usr/bin/first", "/usr/bin/second"],
        );

        let result = merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming,
            }],
        )
        .expect("the complete binary scope explicitly accepts the MCP promotion");

        let promoted = &result.policy.network_policies["existing"].endpoints[0];
        assert_eq!(promoted.protocol, "mcp");
        assert_eq!(promoted.json_rpc_max_body_bytes, 128 * 1024);
        assert_eq!(
            promoted.mcp,
            Some(McpOptions {
                strict_tool_names: Some(false),
                allow_all_known_mcp_methods: Some(true),
            })
        );
        assert_eq!(promoted.rules, vec![mcp_tool_rule("new-tool")]);
    }

    #[test]
    fn established_rest_endpoint_cannot_be_reinterpreted_as_mcp() {
        let existing_endpoint = NetworkEndpoint {
            protocol: "rest".to_string(),
            rules: vec![rest_rule("GET", "/")],
            ..endpoint("api.example.com", 443)
        };
        let existing =
            rule_with_authorizations("existing", vec![existing_endpoint], &["/usr/bin/client"]);
        let incoming = rule_with_authorizations(
            "existing",
            vec![mcp_endpoint(
                "api.example.com",
                &[443],
                None,
                None,
                0,
                vec![mcp_tool_rule("tool")],
            )],
            &["/usr/bin/client"],
        );

        assert!(matches!(
            merge_policy(
                policy_with_rule("existing", existing),
                &[PolicyMergeOp::AddRule {
                    rule_name: "existing".to_string(),
                    rule: incoming,
                }]
            ),
            Err(PolicyMergeError::McpContractConflict {
                existing, incoming, ..
            }) if existing == "non-mcp(protocol='rest')" && incoming.starts_with("mcp(")
        ));
    }

    #[test]
    fn mcp_overlap_uses_effective_defaults_and_rejects_body_limit_changes() {
        let existing_endpoint = mcp_endpoint(
            "mcp.example.com",
            &[443, 8443],
            None,
            None,
            0,
            vec![mcp_tool_rule("tool")],
        );
        let explicit_defaults = mcp_endpoint(
            "mcp.example.com",
            &[8443],
            Some(true),
            Some(false),
            DEFAULT_JSON_RPC_MAX_BODY_BYTES,
            vec![mcp_tool_rule("tool")],
        );
        let existing =
            rule_with_authorizations("existing", vec![existing_endpoint], &["/usr/bin/client"]);
        let equivalent = rule_with_authorizations(
            "incoming",
            vec![explicit_defaults.clone()],
            &["/usr/bin/client"],
        );
        assert!(
            merge_policy(
                policy_with_rule("existing", existing.clone()),
                &[PolicyMergeOp::AddRule {
                    rule_name: "incoming".to_string(),
                    rule: equivalent,
                }]
            )
            .is_ok(),
            "omitted MCP booleans and body limit must equal their runtime defaults"
        );

        let mut different_body_limit = explicit_defaults;
        different_body_limit.json_rpc_max_body_bytes = 128 * 1024;
        let conflicting =
            rule_with_authorizations("incoming", vec![different_body_limit], &["/usr/bin/client"]);
        assert!(matches!(
            merge_policy(
                policy_with_rule("existing", existing),
                &[PolicyMergeOp::AddRule {
                    rule_name: "incoming".to_string(),
                    rule: conflicting,
                }]
            ),
            // The existing endpoint omitted the limit, so the conflict reports
            // its effective default rather than the raw zero.
            Err(PolicyMergeError::McpContractConflict {
                port: 8443,
                existing,
                incoming,
                ..
            }) if existing.contains("max_body_bytes=65536")
                && incoming.contains("max_body_bytes=131072")
        ));
    }

    #[test]
    fn non_overlapping_mcp_endpoints_may_use_different_contracts() {
        let existing = rule_with_authorizations(
            "existing",
            vec![mcp_endpoint(
                "first.example.com",
                &[443, 8443],
                None,
                None,
                0,
                vec![mcp_tool_rule("first-tool")],
            )],
            &["/usr/bin/client"],
        );
        let incoming = rule_with_authorizations(
            "existing",
            vec![mcp_endpoint(
                "second.example.com",
                &[443],
                Some(false),
                Some(true),
                128 * 1024,
                vec![mcp_tool_rule("second-tool")],
            )],
            &["/usr/bin/client"],
        );

        let result = merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming,
            }],
        )
        .expect("contract differences on disjoint endpoints are independent");

        assert_eq!(
            result.policy.network_policies["existing"].endpoints.len(),
            2
        );
    }

    #[test]
    fn policy_coverage_checks_full_mcp_matchers_ports_contract_and_defaults() {
        let loaded_endpoint = mcp_endpoint(
            "mcp.example.com",
            &[443],
            None,
            None,
            0,
            vec![mcp_tool_rule("loaded-tool")],
        );
        let loaded = policy_with_rule(
            "loaded",
            rule_with_authorizations(
                "loaded",
                vec![loaded_endpoint.clone()],
                &["/usr/bin/client"],
            ),
        );

        let wrong_tool = rule_with_authorizations(
            "proposed",
            vec![mcp_endpoint(
                "mcp.example.com",
                &[443],
                Some(true),
                Some(false),
                DEFAULT_JSON_RPC_MAX_BODY_BYTES,
                vec![mcp_tool_rule("different-tool")],
            )],
            &["/usr/bin/client"],
        );
        assert!(!policy_covers_rule(&loaded, &wrong_tool));

        let extra_port = rule_with_authorizations(
            "proposed",
            vec![mcp_endpoint(
                "mcp.example.com",
                &[443, 8443],
                None,
                None,
                0,
                vec![mcp_tool_rule("loaded-tool")],
            )],
            &["/usr/bin/client"],
        );
        assert!(!policy_covers_rule(&loaded, &extra_port));

        let equivalent_defaults = rule_with_authorizations(
            "proposed",
            vec![mcp_endpoint(
                "mcp.example.com",
                &[443],
                Some(true),
                Some(false),
                DEFAULT_JSON_RPC_MAX_BODY_BYTES,
                vec![mcp_tool_rule("loaded-tool")],
            )],
            &["/usr/bin/client"],
        );
        assert!(policy_covers_rule(&loaded, &equivalent_defaults));

        let different_body = rule_with_authorizations(
            "proposed",
            vec![mcp_endpoint(
                "mcp.example.com",
                &[443],
                None,
                None,
                128 * 1024,
                vec![mcp_tool_rule("loaded-tool")],
            )],
            &["/usr/bin/client"],
        );
        assert!(!policy_covers_rule(&loaded, &different_body));

        let mut explicit_defaults = loaded_endpoint;
        explicit_defaults.tls = "passthrough".to_string();
        explicit_defaults.enforcement = "audit".to_string();
        let runtime_defaults = rule_with_authorizations(
            "proposed",
            vec![explicit_defaults.clone()],
            &["/usr/bin/client"],
        );
        assert!(policy_covers_rule(&loaded, &runtime_defaults));

        explicit_defaults.tls = "terminate".to_string();
        let legacy_terminate = rule_with_authorizations(
            "proposed",
            vec![explicit_defaults.clone()],
            &["/usr/bin/client"],
        );
        assert!(policy_covers_rule(&loaded, &legacy_terminate));

        explicit_defaults.tls = "skip".to_string();
        let skip_tls = rule_with_authorizations(
            "proposed",
            vec![explicit_defaults.clone()],
            &["/usr/bin/client"],
        );
        assert!(!policy_covers_rule(&loaded, &skip_tls));

        explicit_defaults.tls.clear();
        explicit_defaults.enforcement = "enforce".to_string();
        let different_runtime_scalars =
            rule_with_authorizations("proposed", vec![explicit_defaults], &["/usr/bin/client"]);
        assert!(!policy_covers_rule(&loaded, &different_runtime_scalars));
    }

    /// `policy_covers_rule` answers "is my rule in effect?" for the sandbox's
    /// `/wait` long-poll, so anything `merge_policy` accepts must read back as
    /// covered once loaded. Otherwise the poll spins to its deadline and the
    /// agent is told its approved rule never landed.
    #[test]
    fn merged_policy_covers_the_rule_it_merged() {
        // Every field `merge_endpoint` widens rather than replaces, set on the
        // existing endpoint and absent from the proposal.
        let existing_endpoint = NetworkEndpoint {
            protocol: "rest".to_string(),
            rules: vec![rest_rule("GET", "/health")],
            deny_rules: vec![L7DenyRule {
                method: "DELETE".to_string(),
                path: "/*".to_string(),
                ..Default::default()
            }],
            allowed_ips: vec!["10.0.0.1".to_string()],
            allow_encoded_slash: true,
            websocket_credential_rewrite: true,
            request_body_credential_rewrite: true,
            advisor_proposed: true,
            ..endpoint("api.example.com", 443)
        };
        let proposed = rule_with_authorizations(
            "api",
            vec![NetworkEndpoint {
                protocol: "rest".to_string(),
                rules: vec![rest_rule("GET", "/users")],
                ..endpoint("api.example.com", 443)
            }],
            &["/usr/bin/client"],
        );

        let merged = merge_policy(
            policy_with_rule(
                "api",
                rule_with_authorizations("api", vec![existing_endpoint], &["/usr/bin/client"]),
            ),
            &[PolicyMergeOp::AddRule {
                rule_name: "api".to_string(),
                rule: proposed.clone(),
            }],
        )
        .expect("merge must accept a proposal that declares the full binary scope");

        assert!(policy_covers_rule(&merged.policy, &proposed));
    }

    #[test]
    fn policy_coverage_requires_proposed_denies_but_allows_loaded_only_denies() {
        let deny = |path: &str| L7DenyRule {
            method: "GET".to_string(),
            path: path.to_string(),
            ..Default::default()
        };
        let proposed_endpoint = NetworkEndpoint {
            protocol: "rest".to_string(),
            rules: vec![rest_rule("GET", "/users")],
            deny_rules: vec![deny("/users/secret")],
            ..endpoint("api.example.com", 443)
        };
        let proposed = rule_with_authorizations(
            "proposed",
            vec![proposed_endpoint.clone()],
            &["/usr/bin/client"],
        );
        let cover_with = |deny_rules: Vec<L7DenyRule>| {
            let loaded_endpoint = NetworkEndpoint {
                deny_rules,
                ..proposed_endpoint.clone()
            };
            policy_covers_rule(
                &policy_with_rule(
                    "loaded",
                    rule_with_authorizations("loaded", vec![loaded_endpoint], &["/usr/bin/client"]),
                ),
                &proposed,
            )
        };

        assert!(
            !cover_with(Vec::new()),
            "a proposed deny that is not loaded means the proposal is not in effect"
        );
        assert!(
            cover_with(vec![deny("/users/secret")]),
            "the proposed deny alone is coverage"
        );
        assert!(
            cover_with(vec![deny("/users/secret"), deny("/admin")]),
            "a deny carried by the loaded endpoint from an earlier merge must not block coverage"
        );
    }

    #[test]
    fn policy_coverage_requires_endpoint_advisor_provenance_to_be_loaded() {
        let loaded_endpoint = endpoint("api.example.com", 443);
        let mut proposed_endpoint = loaded_endpoint.clone();
        proposed_endpoint.advisor_proposed = true;
        let loaded = policy_with_rule(
            "loaded",
            rule_with_authorizations("loaded", vec![loaded_endpoint], &["/usr/bin/client"]),
        );
        let proposed =
            rule_with_authorizations("proposed", vec![proposed_endpoint], &["/usr/bin/client"]);

        assert!(!policy_covers_rule(&loaded, &proposed));
    }

    #[test]
    fn policy_coverage_checks_every_binary_endpoint_pair_across_rule_union() {
        let proposed = rule_with_authorizations(
            "proposed",
            vec![
                endpoint("a.example.com", 443),
                endpoint("b.example.com", 443),
            ],
            &["/usr/bin/first", "/usr/bin/second"],
        );
        let mut loaded = restrictive_default_policy();
        for (name, host, binary_path) in [
            ("a-first", "a.example.com", "/usr/bin/first"),
            ("a-second", "a.example.com", "/usr/bin/second"),
            ("b-first", "b.example.com", "/usr/bin/first"),
        ] {
            loaded.network_policies.insert(
                name.to_string(),
                rule_with_authorizations(name, vec![endpoint(host, 443)], &[binary_path]),
            );
        }

        assert!(
            !policy_covers_rule(&loaded, &proposed),
            "the missing b.example.com × /usr/bin/second pair must fail coverage"
        );

        loaded.network_policies.insert(
            "b-second".to_string(),
            rule_with_authorizations(
                "b-second",
                vec![endpoint("b.example.com", 443)],
                &["/usr/bin/second"],
            ),
        );
        assert!(
            policy_covers_rule(&loaded, &proposed),
            "separate loaded rules may jointly cover the complete Cartesian product"
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
            binaries: vec![binary("/usr/bin/curl"), binary("/usr/bin/gh")],
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
    fn add_rule_user_binary_clears_advisor_marker_for_same_path() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "existing".to_string(),
            NetworkPolicyRule {
                name: "existing".to_string(),
                endpoints: vec![endpoint("api.github.com", 443)],
                binaries: vec![advisor_binary("/usr/bin/curl")],
            },
        );

        let incoming = NetworkPolicyRule {
            name: "incoming".to_string(),
            endpoints: vec![endpoint("api.github.com", 443)],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        let result = merge_policy(
            policy,
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming,
            }],
        )
        .expect("merge should succeed");

        let rule = &result.policy.network_policies["existing"];
        assert_eq!(rule.binaries.len(), 1);
        #[allow(deprecated)]
        {
            assert!(!rule.binaries[0].harness);
        }
    }

    #[test]
    fn add_rule_duplicate_binaries_prefer_user_declared_marker() {
        let incoming = NetworkPolicyRule {
            name: "incoming".to_string(),
            endpoints: vec![endpoint("api.github.com", 443)],
            binaries: vec![
                advisor_binary("/usr/bin/curl"),
                NetworkBinary {
                    path: "/usr/bin/curl".to_string(),
                    ..Default::default()
                },
            ],
        };

        let result = merge_policy(
            restrictive_default_policy(),
            &[PolicyMergeOp::AddRule {
                rule_name: "github".to_string(),
                rule: incoming,
            }],
        )
        .expect("merge should succeed");

        let rule = &result.policy.network_policies["github"];
        assert_eq!(rule.binaries.len(), 1);
        #[allow(deprecated)]
        {
            assert!(!rule.binaries[0].harness);
        }
    }

    #[test]
    fn add_rule_preserves_advisor_endpoint_marker_when_binary_is_deduped() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "app-api".to_string(),
            NetworkPolicyRule {
                name: "app-api".to_string(),
                endpoints: vec![endpoint("api.example.com", 443)],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/python".to_string(),
                    ..Default::default()
                }],
            },
        );

        let incoming = NetworkPolicyRule {
            name: "app-api".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "internal-admin.local".to_string(),
                port: 443,
                ports: vec![443],
                advisor_proposed: true,
                ..Default::default()
            }],
            binaries: vec![advisor_binary("/usr/bin/python")],
        };

        let result = merge_policy(
            policy,
            &[PolicyMergeOp::AddRule {
                rule_name: "app-api".to_string(),
                rule: incoming,
            }],
        )
        .expect("merge should succeed");

        let rule = &result.policy.network_policies["app-api"];
        assert_eq!(rule.binaries.len(), 1, "binary should still dedupe");
        #[allow(deprecated)]
        {
            assert!(
                !rule.binaries[0].harness,
                "existing user binary provenance should be retained"
            );
        }
        let internal_endpoint = rule
            .endpoints
            .iter()
            .find(|endpoint| endpoint.host == "internal-admin.local")
            .expect("advisor endpoint should be appended");
        assert!(
            internal_endpoint.advisor_proposed,
            "endpoint provenance must survive merge even when binary provenance is deduped"
        );
    }

    #[test]
    fn add_rule_merges_websocket_credential_rewrite_flag() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "existing".to_string(),
            NetworkPolicyRule {
                name: "existing".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "realtime.example.com".to_string(),
                    port: 443,
                    ports: vec![443],
                    protocol: "websocket".to_string(),
                    access: "read-write".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );

        let incoming = NetworkPolicyRule {
            name: "incoming".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "realtime.example.com".to_string(),
                port: 443,
                ports: vec![443],
                protocol: "websocket".to_string(),
                websocket_credential_rewrite: true,
                ..Default::default()
            }],
            ..Default::default()
        };

        let result = merge_policy(
            policy,
            &[PolicyMergeOp::AddRule {
                rule_name: "allow_realtime_example_com_443".to_string(),
                rule: incoming,
            }],
        )
        .expect("merge should succeed");

        let endpoint = &result.policy.network_policies["existing"].endpoints[0];
        assert!(endpoint.websocket_credential_rewrite);
    }

    #[test]
    fn add_rule_merges_request_body_credential_rewrite_flag() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "existing".to_string(),
            NetworkPolicyRule {
                name: "existing".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "slack.com".to_string(),
                    port: 443,
                    ports: vec![443],
                    protocol: "rest".to_string(),
                    access: "read-write".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );

        let incoming = NetworkPolicyRule {
            name: "incoming".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "slack.com".to_string(),
                port: 443,
                ports: vec![443],
                protocol: "rest".to_string(),
                request_body_credential_rewrite: true,
                ..Default::default()
            }],
            ..Default::default()
        };

        let result = merge_policy(
            policy,
            &[PolicyMergeOp::AddRule {
                rule_name: "allow_slack_com_443".to_string(),
                rule: incoming,
            }],
        )
        .expect("merge should succeed");

        let endpoint = &result.policy.network_policies["existing"].endpoints[0];
        assert!(endpoint.request_body_credential_rewrite);
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
    fn add_allow_expands_websocket_access_preset() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "realtime".to_string(),
            NetworkPolicyRule {
                name: "realtime".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "realtime.example.com".to_string(),
                    port: 443,
                    ports: vec![443],
                    protocol: "websocket".to_string(),
                    access: "read-write".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );

        let result = merge_policy(
            policy,
            &[PolicyMergeOp::AddAllowRules {
                host: "realtime.example.com".to_string(),
                port: 443,
                rules: vec![rest_rule("WEBSOCKET_TEXT", "/rooms/private/**")],
            }],
        )
        .expect("merge should succeed");

        let endpoint = &result.policy.network_policies["realtime"].endpoints[0];
        assert!(endpoint.access.is_empty());
        assert_eq!(endpoint.rules.len(), 3);
        assert!(endpoint.rules.contains(&rest_rule("GET", "**")));
        assert!(endpoint.rules.contains(&rest_rule("WEBSOCKET_TEXT", "**")));
        assert!(
            endpoint
                .rules
                .contains(&rest_rule("WEBSOCKET_TEXT", "/rooms/private/**"))
        );
        assert!(!endpoint.rules.contains(&rest_rule("POST", "**")));
        assert!(result.warnings.iter().any(|warning| matches!(
            warning,
            PolicyMergeWarning::ExpandedAccessPreset { access, .. } if access == "read-write"
        )));
    }

    #[test]
    fn add_deny_accepts_websocket_protocol() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "realtime".to_string(),
            NetworkPolicyRule {
                name: "realtime".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "realtime.example.com".to_string(),
                    port: 443,
                    ports: vec![443],
                    protocol: "websocket".to_string(),
                    access: "read-write".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );

        let result = merge_policy(
            policy,
            &[PolicyMergeOp::AddDenyRules {
                host: "realtime.example.com".to_string(),
                port: 443,
                deny_rules: vec![L7DenyRule {
                    method: "WEBSOCKET_TEXT".to_string(),
                    path: "/admin/**".to_string(),
                    ..Default::default()
                }],
            }],
        )
        .expect("merge should succeed");

        let endpoint = &result.policy.network_policies["realtime"].endpoints[0];
        assert_eq!(endpoint.deny_rules.len(), 1);
        assert_eq!(endpoint.deny_rules[0].method, "WEBSOCKET_TEXT");
        assert_eq!(endpoint.deny_rules[0].path, "/admin/**");
    }

    #[test]
    fn add_deny_rejects_unsupported_protocol() {
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
    fn policy_covers_rule_returns_true_when_merged_rule_present() {
        let proposed = NetworkPolicyRule {
            name: "agent_proposed".to_string(),
            endpoints: vec![endpoint("api.github.com", 443)],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        let merged = merge_policy(
            restrictive_default_policy(),
            &[PolicyMergeOp::AddRule {
                rule_name: "allow_api_github_com_443".to_string(),
                rule: proposed.clone(),
            }],
        )
        .expect("merge should succeed");

        assert!(policy_covers_rule(&merged.policy, &proposed));
    }

    #[test]
    fn policy_covers_rule_returns_false_when_unrelated_rule_present() {
        let proposed = NetworkPolicyRule {
            name: "agent_proposed".to_string(),
            endpoints: vec![endpoint("api.github.com", 443)],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        // Merge an *unrelated* rule for a different host. The proposed rule
        // for api.github.com is still not present — this is John's
        // "false-wakeup" case: an unrelated policy reload must not signal
        // that the agent's rule is loaded.
        let merged = merge_policy(
            restrictive_default_policy(),
            &[PolicyMergeOp::AddRule {
                rule_name: "allow_api_example_com_443".to_string(),
                rule: rule_with_endpoint("unrelated", "api.example.com", 443),
            }],
        )
        .expect("merge should succeed");

        assert!(!policy_covers_rule(&merged.policy, &proposed));
    }

    #[test]
    fn policy_covers_rule_handles_merge_into_existing_endpoint() {
        // The merge logic folds a new rule into an existing rule when their
        // endpoints overlap, even under a different network_policies key.
        // Coverage must survive that fold — name-keyed checks would miss it.
        let proposed = NetworkPolicyRule {
            name: "agent_proposed".to_string(),
            endpoints: vec![endpoint("api.github.com", 443)],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "preexisting_github".to_string(),
            NetworkPolicyRule {
                name: "preexisting_github".to_string(),
                endpoints: vec![endpoint("api.github.com", 443)],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/git".to_string(),
                    ..Default::default()
                }],
            },
        );

        let merged = merge_policy(
            policy,
            &[PolicyMergeOp::AddRule {
                rule_name: "allow_api_github_com_443".to_string(),
                rule: proposed.clone(),
            }],
        )
        .expect("merge should succeed");

        assert!(
            !merged
                .policy
                .network_policies
                .contains_key("allow_api_github_com_443"),
            "proposed rule should have been folded into the existing key"
        );
        assert!(policy_covers_rule(&merged.policy, &proposed));
    }

    #[test]
    fn policy_covers_rule_returns_false_when_binary_missing() {
        let proposed = NetworkPolicyRule {
            name: "agent_proposed".to_string(),
            endpoints: vec![endpoint("api.github.com", 443)],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        // Endpoint exists in the policy but with a *different* binary. The
        // agent's retry would still be denied; reload coverage should
        // reflect that.
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "existing".to_string(),
            NetworkPolicyRule {
                name: "existing".to_string(),
                endpoints: vec![endpoint("api.github.com", 443)],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/git".to_string(),
                    ..Default::default()
                }],
            },
        );

        assert!(!policy_covers_rule(&policy, &proposed));
    }

    #[test]
    fn policy_covers_rule_returns_false_for_empty_proposed_endpoints() {
        // Defensive: a rule with no endpoints carries no signal we can match
        // on, so coverage is never true.
        let proposed = NetworkPolicyRule::default();
        let policy = restrictive_default_policy();
        assert!(!policy_covers_rule(&policy, &proposed));
    }

    #[test]
    fn policy_covers_rule_returns_false_when_proposed_l7_method_not_loaded() {
        // John's false-wakeup mode at L7: the supervisor has an
        // overlapping endpoint loaded (e.g. read-only GET), but the
        // chunk's proposed PUT method is not in the merged endpoint's
        // rules yet. Coverage must NOT return true here, or the agent
        // retries the PUT and hits another policy_denied.
        let proposed = NetworkPolicyRule {
            name: "agent_put".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.github.com".to_string(),
                port: 443,
                ports: vec![443],
                protocol: "rest".to_string(),
                rules: vec![rest_rule("PUT", "/repos/foo/bar/contents/x.md")],
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "existing_readonly".to_string(),
            NetworkPolicyRule {
                name: "existing_readonly".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "api.github.com".to_string(),
                    port: 443,
                    ports: vec![443],
                    protocol: "rest".to_string(),
                    rules: vec![rest_rule("GET", "/repos/foo/bar/contents/x.md")],
                    ..Default::default()
                }],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/curl".to_string(),
                    ..Default::default()
                }],
            },
        );

        assert!(
            !policy_covers_rule(&policy, &proposed),
            "endpoint overlaps but L7 PUT not loaded yet; must not signal coverage"
        );
    }

    #[test]
    fn policy_covers_rule_returns_true_after_l7_merge_lands() {
        // Same setup as above, but with the proposed L7 rule merged in.
        // Coverage must now return true.
        let proposed = NetworkPolicyRule {
            name: "agent_put".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.github.com".to_string(),
                port: 443,
                ports: vec![443],
                protocol: "rest".to_string(),
                rules: vec![rest_rule("PUT", "/repos/foo/bar/contents/x.md")],
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };

        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "existing".to_string(),
            NetworkPolicyRule {
                name: "existing".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "api.github.com".to_string(),
                    port: 443,
                    ports: vec![443],
                    protocol: "rest".to_string(),
                    rules: vec![
                        rest_rule("GET", "/repos/foo/bar/contents/x.md"),
                        rest_rule("PUT", "/repos/foo/bar/contents/x.md"),
                    ],
                    ..Default::default()
                }],
                binaries: vec![NetworkBinary {
                    path: "/usr/bin/curl".to_string(),
                    ..Default::default()
                }],
            },
        );

        assert!(policy_covers_rule(&policy, &proposed));
    }

    #[test]
    fn policy_covers_rule_returns_true_for_l4_only_proposed_when_endpoint_present() {
        // A chunk that targets a non-REST surface (no L7 rules) needs
        // only the L4 endpoint match to be considered covered. Empty
        // proposed.rules must not be treated as "no method matches".
        let proposed = NetworkPolicyRule {
            name: "ssh_clone".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "github.com".to_string(),
                port: 22,
                ports: vec![22],
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/git".to_string(),
                ..Default::default()
            }],
        };

        let merged = merge_policy(
            restrictive_default_policy(),
            &[PolicyMergeOp::AddRule {
                rule_name: "allow_github_com_22".to_string(),
                rule: proposed.clone(),
            }],
        )
        .expect("merge should succeed");

        assert!(policy_covers_rule(&merged.policy, &proposed));
    }

    #[test]
    fn policy_covers_rule_requires_loaded_any_binary_scope_for_any_binary_proposal() {
        // A proposed rule with no binaries is the "any binary" shape.
        // A specific loaded binary list cannot cover that Cartesian scope.
        let proposed = NetworkPolicyRule {
            name: "any_binary_rule".to_string(),
            endpoints: vec![endpoint("api.github.com", 443)],
            binaries: vec![],
        };

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

        assert!(
            !policy_covers_rule(&policy, &proposed),
            "a specific loaded binary list must not cover an any-binary proposal"
        );

        policy
            .network_policies
            .get_mut("existing")
            .expect("existing rule")
            .binaries
            .clear();
        assert!(policy_covers_rule(&policy, &proposed));
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

    /// Provider-injected rules (`_provider_*`) are excluded from the
    /// endpoint-overlap fallback: an agent chunk for the same `(host, port)`
    /// as a provider rule lands as its own key instead of being merged into
    /// the provider's rule. This keeps agent contributions honestly narrow
    /// (no silent expansion via the provider rule's `access` shorthand) and
    /// preserves binary-list separation.
    #[test]
    fn add_rule_does_not_merge_agent_chunk_into_provider_rule() {
        use crate::compose::{ProviderPolicyLayer, compose_effective_policy};
        use openshell_core::proto::SandboxPolicy;

        // Compose a policy where the github provider profile contributes a
        // `_provider_*` rule for api.github.com with `access: read-write`
        // and gh/git binaries.
        let provider_rule = NetworkPolicyRule {
            name: "_provider_work_github".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.github.com".to_string(),
                port: 443,
                protocol: "rest".to_string(),
                enforcement: "enforce".to_string(),
                access: "read-write".to_string(),
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/gh".to_string(),
                ..Default::default()
            }],
        };
        let composed = compose_effective_policy(
            &SandboxPolicy::default(),
            &[ProviderPolicyLayer {
                rule_name: "_provider_work_github".to_string(),
                rule: provider_rule,
            }],
        );
        assert!(
            composed
                .network_policies
                .contains_key("_provider_work_github"),
            "precondition: provider rule must be present in baseline"
        );

        // Agent submits a narrow PUT rule targeting the same host/port via
        // curl. Without the filter, this would merge into the provider rule.
        let agent_rule = NetworkPolicyRule {
            name: "github_contents_put".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.github.com".to_string(),
                port: 443,
                protocol: "rest".to_string(),
                enforcement: "enforce".to_string(),
                rules: vec![rest_rule("PUT", "/repos/owner/repo/contents/file.md")],
                ..Default::default()
            }],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };
        let result = merge_policy(
            composed,
            &[PolicyMergeOp::AddRule {
                rule_name: "github_contents_put".to_string(),
                rule: agent_rule,
            }],
        )
        .expect("merge should succeed");

        // The agent's chunk lands as its own rule key.
        assert!(
            result
                .policy
                .network_policies
                .contains_key("github_contents_put"),
            "agent chunk must land as a separate rule (not merged into the provider rule); \
             got keys: {:?}",
            result.policy.network_policies.keys().collect::<Vec<_>>()
        );

        // The provider rule is unchanged: still has only gh as a binary
        // (no silent broadening), still has the read-write shorthand
        // intact (no preset expansion into wildcard paths).
        let provider_rule_after = result
            .policy
            .network_policies
            .get("_provider_work_github")
            .expect("provider rule must still be present");
        assert_eq!(
            provider_rule_after.binaries.len(),
            1,
            "provider rule's binary list must NOT have been merged with the agent's binaries"
        );
        assert_eq!(provider_rule_after.binaries[0].path, "/usr/bin/gh");
        assert_eq!(
            provider_rule_after.endpoints[0].access, "read-write",
            "provider rule's `access` shorthand must remain intact"
        );
        assert!(
            provider_rule_after.endpoints[0].rules.is_empty(),
            "provider rule must NOT have had its access expanded into explicit wildcard rules"
        );

        // The agent's rule retains its narrow scope.
        let agent_rule_after = &result.policy.network_policies["github_contents_put"];
        assert_eq!(agent_rule_after.binaries[0].path, "/usr/bin/curl");
        assert_eq!(agent_rule_after.endpoints[0].rules.len(), 1);
    }

    /// Non-provider rules still merge by endpoint overlap when the incoming
    /// `rule_name` doesn't match an existing key. This preserves the
    /// long-standing behavior for user-authored and mechanistic chunks.
    #[test]
    fn add_rule_still_merges_user_chunk_into_user_rule_by_endpoint_overlap() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "custom_github".to_string(),
            rule_with_endpoint("custom_github", "api.github.com", 443),
        );

        let incoming = NetworkPolicyRule {
            name: "ignored_when_merging".to_string(),
            endpoints: vec![endpoint("api.github.com", 443)],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/curl".to_string(),
                ..Default::default()
            }],
        };
        let result = merge_policy(
            policy,
            &[PolicyMergeOp::AddRule {
                rule_name: "different_name".to_string(),
                rule: incoming,
            }],
        )
        .expect("merge should succeed");

        // No new rule entry was created — the chunk merged into the
        // existing user rule via endpoint overlap.
        assert!(
            !result
                .policy
                .network_policies
                .contains_key("different_name"),
            "user-authored rule overlap should still merge (no new key); \
             got keys: {:?}",
            result.policy.network_policies.keys().collect::<Vec<_>>()
        );
        let merged = &result.policy.network_policies["custom_github"];
        assert!(
            merged.binaries.iter().any(|b| b.path == "/usr/bin/curl"),
            "user rule should have absorbed the incoming curl binary"
        );
    }
}
