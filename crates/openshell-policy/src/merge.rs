// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap, HashSet};

use openshell_core::proto::{
    L7Allow, L7DenyRule, L7Rule, NetworkBinary, NetworkEndpoint, NetworkPolicyRule, SandboxPolicy,
};

use crate::is_provider_rule_name;

const DEFAULT_JSON_RPC_MAX_BODY_BYTES: u32 = 64 * 1024;

/// Rewrite an observation-only advisor rule against the live effective policy.
///
/// A denial reports only `(host, port, binary)`. If that destination already
/// has one unambiguous endpoint contract, proposing a second generic L4
/// endpoint loses inspection metadata and can make the effective policy
/// ambiguous. Preserve the existing contract instead. Sandbox-owned rules are
/// expanded in place; provider-owned rules remain immutable and are mirrored
/// into the requested sandbox-owned overlay.
pub fn canonicalize_advisor_add_rule(
    base_policy: &SandboxPolicy,
    effective_policy: &SandboxPolicy,
    requested_rule_name: &str,
    incoming_rule: &NetworkPolicyRule,
) -> Result<(String, NetworkPolicyRule), String> {
    if incoming_rule.endpoints.len() != 1 || incoming_rule.binaries.is_empty() {
        return Ok((requested_rule_name.to_string(), incoming_rule.clone()));
    }

    let incoming_endpoint = &incoming_rule.endpoints[0];
    let incoming_ports = canonical_ports(incoming_endpoint);
    if incoming_endpoint.host.trim().is_empty() || incoming_ports.len() != 1 {
        return Ok((requested_rule_name.to_string(), incoming_rule.clone()));
    }
    let port = incoming_ports[0];
    let contracts = effective_policy
        .network_policies
        .values()
        .flat_map(|rule| &rule.endpoints)
        .filter(|endpoint| {
            endpoint.host.eq_ignore_ascii_case(&incoming_endpoint.host)
                && canonical_ports(endpoint).contains(&port)
        })
        .cloned()
        .map(|mut endpoint| {
            // This marker is derived from provider/credential context by the
            // gateway and must never be persisted from an advisor proposal.
            endpoint.provider_credentialed = false;
            // A denial observes one binary-to-port authorization. Preserve the
            // existing inspection contract, but never copy sibling ports from
            // a multi-port endpoint into the proposal.
            endpoint.port = port;
            endpoint.ports = vec![port];
            normalize_endpoint(&mut endpoint);
            endpoint
        })
        .collect::<Vec<_>>();
    let mut unique_contracts = Vec::new();
    for contract in contracts {
        if !unique_contracts.contains(&contract) {
            unique_contracts.push(contract);
        }
    }

    let Some(contract) = unique_contracts.first().cloned() else {
        return Ok((requested_rule_name.to_string(), incoming_rule.clone()));
    };
    if unique_contracts.len() != 1 {
        return Err(format!(
            "cannot infer one existing endpoint contract for {}:{}",
            incoming_endpoint.host, port
        ));
    }

    let mut sandbox_owners = base_policy
        .network_policies
        .iter()
        .filter(|(name, _)| !is_provider_rule_name(name))
        .filter_map(|(name, rule)| {
            rule.endpoints
                .iter()
                .any(|endpoint| {
                    let mut normalized = endpoint.clone();
                    normalized.provider_credentialed = false;
                    normalize_endpoint(&mut normalized);
                    normalized == contract
                })
                .then_some(name.clone())
        })
        .collect::<Vec<_>>();
    sandbox_owners.sort();

    let target_name = sandbox_owners
        .first()
        .cloned()
        .unwrap_or_else(|| requested_rule_name.to_string());
    let mut canonical = incoming_rule.clone();
    canonical.name.clone_from(&target_name);
    canonical.endpoints = vec![contract];
    Ok((target_name, canonical))
}

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
    /// An `AddRule` named binaries for a rule that already authorizes any
    /// binary, so the wider existing scope was kept rather than narrowed.
    ExistingAnyBinaryScopeRetained {
        rule_name: String,
        /// Binary paths the operation named.
        incoming: Vec<String>,
    },
    /// An `AddRule` operation that would normally fold into an overlapping rule
    /// stayed on its requested rule name, because folding would have granted a
    /// binary-to-endpoint pair the operation never declared.
    KeptRequestedRuleNameToAvoidWidening {
        rule_name: String,
        /// Rule the endpoint-overlap fallback would otherwise have folded into.
        overlapping_rule_name: String,
        /// Rendered inheritance conflict that folding would have caused.
        reason: String,
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
            Self::ExistingAnyBinaryScopeRetained {
                rule_name,
                incoming,
            } => write!(
                f,
                "rule '{rule_name}' already authorizes any binary; kept that scope instead of narrowing it to {}",
                incoming.join(", ")
            ),
            Self::KeptRequestedRuleNameToAvoidWidening {
                rule_name,
                overlapping_rule_name,
                reason,
            } => write!(
                f,
                "kept add-rule '{rule_name}' on its own rule instead of folding it into overlapping rule '{overlapping_rule_name}': {reason}"
            ),
        }
    }
}

/// Rendered name for the any-binary scope in operator-facing merge errors. An
/// empty binary list on a rule authorizes every binary, which has no path to
/// print.
pub const ANY_BINARY_SCOPE: &str = "any binary";

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
    /// Newly added binary scope would inherit an existing endpoint
    /// authorization that the incoming rule did not declare.
    NewBinaryWouldInheritAuthorization {
        operation_index: usize,
        rule_name: String,
        /// Rendered binary scope the operation adds, either a concrete path or
        /// [`ANY_BINARY_SCOPE`].
        binary_scope: String,
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
    /// A widened field would land on a port the operation never named, because
    /// the field merges into an endpoint carrying more ports than were declared.
    UndeclaredPortWouldChange {
        operation_index: usize,
        rule_name: String,
        host: String,
        ports: Vec<u32>,
    },
    /// One host and port would carry more than one effective L7 inspection
    /// contract, which the supervisor resolves by match order rather than policy.
    ConflictingInspectionContracts {
        host: String,
        port: u32,
        /// Rendered effective contracts found at this host and port, sorted.
        contracts: Vec<String>,
    },
    /// Several rules carry the same endpoint, so an operation that identifies
    /// its target by host and port alone cannot say which binary scope it means.
    AmbiguousEndpointRule {
        host: String,
        port: u32,
        /// Rendered rule, and path where one is set, for each endpoint the host
        /// and port resolves to. Sorted.
        targets: Vec<String>,
    },
    /// A remove-binary operation targeted a rule that authorizes any binary,
    /// where there is no binary entry to remove.
    CannotRemoveBinaryFromAnyBinaryScope {
        operation_index: usize,
        rule_name: String,
        binary_path: String,
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
                binary_scope,
                host,
                ports,
            } => write!(
                f,
                "merge operation {operation_index} add-rule '{rule_name}' would grant {binary_scope} undeclared authorization for {host} on ports {ports:?}"
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
            Self::UndeclaredPortWouldChange {
                operation_index,
                rule_name,
                host,
                ports,
            } => write!(
                f,
                "merge operation {operation_index} add-rule '{rule_name}' would change authorization for {host} on undeclared ports {ports:?}; declare every port of the endpoint it modifies"
            ),
            Self::ConflictingInspectionContracts {
                host,
                port,
                contracts,
            } => write!(
                f,
                "{host}:{port} would carry more than one L7 inspection contract ({}); the sandbox resolves one contract per host and port, so these cannot coexist even in different rules or under different paths",
                contracts.join(", ")
            ),
            Self::AmbiguousEndpointRule {
                host,
                port,
                targets,
            } => write!(
                f,
                "endpoint {host}:{port} resolves to {}; this operation selects its target by host and port alone, so it cannot say which binary scope and L7 surface to widen. Replace the policy with the full YAML instead",
                targets.join(", ")
            ),
            Self::CannotRemoveBinaryFromAnyBinaryScope {
                operation_index,
                rule_name,
                binary_path,
            } => write!(
                f,
                "merge operation {operation_index} cannot remove binary '{binary_path}' from rule '{rule_name}' because the rule authorizes any binary; replace the policy with an explicit binary list or remove the rule"
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
/// proposal, but every binary-by-port pair must be present in that union.
///
/// The atomic authorization unit is one binary reaching one host, path, and
/// port. Ports travel as a set on the wire, but the loaded policy may spread
/// them across rules, so each port resolves independently against the whole
/// union instead of requiring one loaded endpoint to carry them all.
///
/// Coverage asks whether the loaded policy contains the proposal, not whether
/// the two are identical. The loaded endpoint is a superset of any proposal
/// that merged into an endpoint carrying earlier authorizations, so
/// `endpoint_attributes_cover` compares merge-widened fields by containment,
/// treats an unset proposal value as unspecified for fields the merge retains,
/// and exact-matches only the fields the proposal actually set.
pub fn policy_covers_rule(policy: &SandboxPolicy, proposed: &NetworkPolicyRule) -> bool {
    if proposed.endpoints.is_empty() {
        return false;
    }
    proposed.endpoints.iter().all(|target_endpoint| {
        authorization_ports(target_endpoint)
            .into_iter()
            .all(|target_port| {
                if proposed.binaries.is_empty() {
                    // An any-binary proposal needs a loaded any-binary scope. A
                    // rule restricted to named binaries authorizes only those
                    // binaries, so it can never stand in for "any".
                    return policy.network_policies.values().any(|rule| {
                        rule.binaries.is_empty()
                            && rule_authorizes(rule, target_endpoint, target_port)
                    });
                }

                proposed.binaries.iter().all(|target_binary| {
                    policy.network_policies.values().any(|rule| {
                        binary_scope_covers(rule, target_binary)
                            && rule_authorizes(rule, target_endpoint, target_port)
                    })
                })
            })
    })
}

/// True when some endpoint on `rule` authorizes `proposed` at `port`.
fn rule_authorizes(
    rule: &NetworkPolicyRule,
    proposed: &NetworkEndpoint,
    port: Option<u32>,
) -> bool {
    rule.endpoints
        .iter()
        .any(|endpoint| endpoint_authorization_covers_port(endpoint, proposed, port))
}

/// The authorization units an endpoint declares, one per port.
///
/// `None` represents an endpoint that declares no port at all. Returning it
/// keeps the unit list non-empty, because an empty list would make the callers'
/// `all()` vacuously true and report an endpoint that no loaded rule matches as
/// covered.
fn authorization_ports(endpoint: &NetworkEndpoint) -> Vec<Option<u32>> {
    let ports = canonical_ports(endpoint);
    if ports.is_empty() {
        vec![None]
    } else {
        ports.into_iter().map(Some).collect()
    }
}

fn binary_scope_covers(rule: &NetworkPolicyRule, proposed: &NetworkBinary) -> bool {
    rule.binaries.is_empty()
        || rule
            .binaries
            .iter()
            .any(|binary| binary.path == proposed.path)
}

/// Coverage for a single atomic authorization unit: `loaded` authorizes
/// `proposed` at `port`. `None` means the proposal declares no port, which
/// places no constraint on the loaded port set.
fn endpoint_authorization_covers_port(
    loaded: &NetworkEndpoint,
    proposed: &NetworkEndpoint,
    port: Option<u32>,
) -> bool {
    if let Some(port) = port
        && !canonical_ports(loaded).contains(&port)
    {
        return false;
    }
    endpoint_attributes_cover(loaded, proposed)
}

/// Coverage for everything about an endpoint except its ports.
fn endpoint_attributes_cover(loaded: &NetworkEndpoint, proposed: &NetworkEndpoint) -> bool {
    // Host and path identify the endpoint rather than describe it:
    // `endpoints_overlap` only ever merges endpoints that already agree on
    // both, so a difference here is a different endpoint, not an unmet request.
    if !loaded.host.eq_ignore_ascii_case(&proposed.host) || loaded.path != proposed.path {
        return false;
    }

    // Fields `merge_endpoint` retains rather than widens. An unset proposal
    // value is unspecified, not a request for the default: the merge leaves the
    // loaded value in place and reports success, so comparing effective values
    // would report a proposal that did land as uncovered and leave the
    // `policy.local /wait` long poll spinning until its deadline. A set value
    // still has to match, because the merge would have kept the loaded value
    // and the proposal genuinely is not in effect.
    if !proposed.protocol.is_empty() && !protocols_match(&loaded.protocol, &proposed.protocol) {
        return false;
    }
    if !proposed.tls.is_empty() && effective_tls(&loaded.tls) != effective_tls(&proposed.tls) {
        return false;
    }
    if !proposed.enforcement.is_empty()
        && effective_enforcement(&loaded.enforcement)
            != effective_enforcement(&proposed.enforcement)
    {
        return false;
    }
    if !proposed.access.is_empty() && loaded.access != proposed.access {
        return false;
    }

    // The MCP contract is compared unconditionally in both directions because
    // `ensure_mcp_contract_compatible` rejects a merge that would give one host
    // and port two contracts. A mismatch here therefore cannot be a proposal
    // that landed, in either direction.
    if !mcp_contracts_match(loaded, proposed) {
        return false;
    }

    // Widened fields (list appends and authorization flags) use containment:
    // merging
    // into an endpoint that already carries them leaves the loaded copy a
    // superset of the proposal, so equality would report "not covered" for a
    // proposal that did land.
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
        // Fields the merge neither widens nor retains: it drops them entirely.
        // An unset proposal value asks for nothing and is satisfied by whatever
        // is loaded; a set value that differs was dropped, so the proposal is
        // not in effect and coverage must stay false until it is resubmitted in
        // a form the merge preserves.
        && unset_or_equal(&proposed.persisted_queries, &loaded.persisted_queries, String::is_empty)
        && unset_or_equal(
            &proposed.graphql_persisted_queries,
            &loaded.graphql_persisted_queries,
            HashMap::is_empty,
        )
        && unset_or_equal(
            &proposed.graphql_max_body_bytes,
            &loaded.graphql_max_body_bytes,
            |value| *value == 0,
        )
        && unset_or_equal(
            &proposed.credential_signing,
            &loaded.credential_signing,
            String::is_empty,
        )
        && unset_or_equal(
            &proposed.signing_service,
            &loaded.signing_service,
            String::is_empty,
        )
        && unset_or_equal(
            &proposed.signing_region,
            &loaded.signing_region,
            String::is_empty,
        )
        && (endpoint_uses_mcp(loaded)
            || unset_or_equal(
                &proposed.json_rpc_max_body_bytes,
                &loaded.json_rpc_max_body_bytes,
                |value| *value == 0,
            ))
}

/// Coverage for a field whose proposal value may be unset. An unset proposal
/// value expresses no requirement, so it is covered by any loaded value.
fn unset_or_equal<T: PartialEq>(proposed: &T, loaded: &T, is_unset: impl Fn(&T) -> bool) -> bool {
    is_unset(proposed) || proposed == loaded
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
    let conflicts_before = conflicting_inspection_contracts(&policy);
    for (operation_index, operation) in operations.iter().enumerate() {
        validate_operation(operation_index, operation)?;
        apply_operation(&mut merged, operation_index, operation, &mut warnings)?;
    }
    ensure_no_new_inspection_conflicts(&merged, &conflicts_before)?;

    let changed = merged != policy;
    Ok(PolicyMergeResult {
        policy: merged,
        warnings,
        changed,
    })
}

/// The MCP inspection contract an endpoint establishes for its host and port.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EffectiveInspection {
    protocol: String,
    /// Present only when the endpoint is inspected as MCP.
    mcp: Option<EffectiveMcpContract>,
}

/// Host and port pairs whose inspected endpoints cannot coexist, mapped to the
/// rendered contracts in play.
///
/// `merge_endpoint` cannot catch these on its own, because it only compares
/// endpoints that fold together, and a differing path or a separate rule keeps
/// them apart. Provider-composed rules are deliberately included: the supervisor
/// resolves inspection per host and port regardless of which rule contributed
/// the endpoint.
fn conflicting_inspection_contracts(
    policy: &SandboxPolicy,
) -> BTreeMap<(String, u32), Vec<String>> {
    let mut contracts: BTreeMap<(String, u32), Vec<(EffectiveInspection, String)>> =
        BTreeMap::new();
    for rule in policy.network_policies.values() {
        for endpoint in &rule.endpoints {
            // Uninspected endpoints carry no L7 contract and never compete.
            if endpoint.protocol.is_empty() {
                continue;
            }
            let inspection = EffectiveInspection {
                protocol: endpoint.protocol.to_ascii_lowercase(),
                mcp: effective_mcp_contract(endpoint),
            };
            for port in canonical_ports(endpoint) {
                contracts
                    .entry((endpoint.host.to_ascii_lowercase(), port))
                    .or_default()
                    .push((inspection.clone(), describe_mcp_contract(endpoint)));
            }
        }
    }

    contracts
        .into_iter()
        .filter_map(|(key, found)| {
            if !inspections_conflict(&found) {
                return None;
            }
            let mut rendered: Vec<String> =
                found.into_iter().map(|(_, rendered)| rendered).collect();
            rendered.sort();
            rendered.dedup();
            Some((key, rendered))
        })
        .collect()
}

/// True when the inspections established for one host and port cannot coexist.
///
/// Authorization is evaluated existentially across every endpoint matching a
/// request, while the parser is chosen by most-specific path. Two non-MCP
/// endpoints share the same method-and-path rule vocabulary, so the broader one
/// authorizing what the narrower one covers is the documented behaviour and
/// stays supported.
///
/// MCP is different. Its allow rules address JSON-RPC methods and tool names, so
/// a plain REST rule on an overlapping path can satisfy authorization for a tool
/// call the MCP endpoint never allowed, and the relay forwards it. MCP therefore
/// cannot share a host and port with a differently inspected endpoint. Two MCP
/// endpoints must also agree on one contract, because MCP options are not
/// path-selected.
fn inspections_conflict(found: &[(EffectiveInspection, String)]) -> bool {
    let mut mcp_contracts = found
        .iter()
        .filter_map(|(inspection, _)| inspection.mcp.as_ref());
    let Some(first) = mcp_contracts.next() else {
        return false;
    };
    if found.iter().any(|(inspection, _)| inspection.mcp.is_none()) {
        return true;
    }
    mcp_contracts.any(|contract| contract != first)
}

/// Rejects an operation that introduces an L7 inspection-contract conflict.
///
/// Only conflicts absent from `before` are rejected. A policy that already
/// carries one, for instance through a provider profile composed outside this
/// merge, would otherwise make every later update fail with an error the
/// operation did nothing to cause.
fn ensure_no_new_inspection_conflicts(
    merged: &SandboxPolicy,
    before: &BTreeMap<(String, u32), Vec<String>>,
) -> Result<(), PolicyMergeError> {
    for ((host, port), contracts) in conflicting_inspection_contracts(merged) {
        if before.contains_key(&(host.clone(), port)) {
            continue;
        }
        return Err(PolicyMergeError::ConflictingInspectionContracts {
            host,
            port,
            contracts,
        });
    }
    Ok(())
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
            ensure_endpoint_target_is_unambiguous(policy, host, *port)?;
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
            ensure_endpoint_target_is_unambiguous(policy, host, *port)?;
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
            // An empty binary list authorizes every binary, so there is no entry
            // to drop and narrowing the rule would mean naming every binary that
            // should keep access. Reject instead of reporting a success that
            // leaves the target binary authorized.
            if policy
                .network_policies
                .get(rule_name)
                .is_some_and(|rule| rule.binaries.is_empty())
            {
                return Err(PolicyMergeError::CannotRemoveBinaryFromAnyBinaryScope {
                    operation_index,
                    rule_name: rule_name.clone(),
                    binary_path: binary_path.clone(),
                });
            }

            let should_remove = if let Some(rule) = policy.network_policies.get_mut(rule_name) {
                let original_len = rule.binaries.len();
                rule.binaries.retain(|binary| binary.path != *binary_path);
                // Removing the last named binary deletes the rule rather than
                // leaving an empty list behind, which would silently widen the
                // rule to every binary.
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
    let requested_key_exists = policy.network_policies.contains_key(rule_name);
    let target_key = if requested_key_exists {
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

    match target_key {
        // The operation named this rule, so an inheritance conflict is the
        // answer the proposer needs: declare the rule's whole binary and
        // endpoint scope, or target a different rule.
        Some(key) if requested_key_exists => {
            let existing_rule = policy
                .network_policies
                .get_mut(&key)
                .expect("existing rule must be present");
            merge_rules(
                existing_rule,
                &incoming_rule,
                operation_index,
                rule_name,
                &key,
                warnings,
            )?;
        }
        // The overlap fallback chose this rule. Folding is a convenience for
        // incremental refinement, not something the operation asked for, so a
        // conflict it creates is not the proposer's error to fix: keeping the
        // proposal on its requested key authorizes exactly the product the
        // operation declared and nothing else. Merging into a copy keeps the
        // rejected attempt from leaving partial edits behind.
        Some(key) => {
            let mut candidate = policy
                .network_policies
                .get(&key)
                .expect("existing rule must be present")
                .clone();
            let mut candidate_warnings = Vec::new();
            match merge_rules(
                &mut candidate,
                &incoming_rule,
                operation_index,
                rule_name,
                &key,
                &mut candidate_warnings,
            ) {
                Ok(()) => {
                    policy.network_policies.insert(key, candidate);
                    warnings.extend(candidate_warnings);
                }
                Err(error) if is_authorization_inheritance_conflict(&error) => {
                    // Surface the skipped fold. The operator asked for one rule
                    // and gets two, and the same host and port now appears in
                    // both, which changes which rule later host-and-port
                    // operations resolve to.
                    warnings.push(PolicyMergeWarning::KeptRequestedRuleNameToAvoidWidening {
                        rule_name: rule_name.to_string(),
                        overlapping_rule_name: key,
                        reason: error.to_string(),
                    });
                    policy
                        .network_policies
                        .insert(rule_name.to_string(), incoming_rule);
                }
                Err(error) => return Err(error),
            }
        }
        None => {
            policy
                .network_policies
                .insert(rule_name.to_string(), incoming_rule);
        }
    }

    Ok(())
}

/// True for the merge errors that exist only because two authorizations share
/// one rule, so moving the incoming authorization to its own rule resolves them.
///
/// `UndeclaredPortWouldChange` belongs here for the same reason as the two
/// inheritance variants. The undeclared port exists only on the endpoint the
/// fold would merge into; an operation kept on its own rule carries exactly the
/// ports it declared, so nothing reaches a port it did not name. Leaving it out
/// makes a narrow update against a multi-port endpoint fail outright instead of
/// landing on its own rule.
///
/// An MCP contract conflict is deliberately excluded. The supervisor establishes
/// one inspection contract per host and port rather than per rule, so two
/// contracts for the same endpoint stay ambiguous in separate rules and the
/// operation has to be rejected wherever it lands.
///
/// The match is exhaustive on purpose. A catch-all would let a new variant
/// default to "not fold-only" and silently withdraw the separate-rule remedy
/// for whichever updates start hitting it first, so adding a variant has to be
/// an explicit decision here.
// The three groups returning `false` are kept apart on purpose: each declines
// for a different reason, and merging them into one arm would leave a future
// variant with no guidance on which group it belongs to.
#[allow(clippy::match_same_arms)]
fn is_authorization_inheritance_conflict(error: &PolicyMergeError) -> bool {
    match error {
        // Scope conflicts that exist only because the fold puts two
        // authorizations in one rule. Kept on its own rule, the incoming
        // authorization grants exactly the binaries, endpoints, and ports it
        // declared, and the conflict disappears.
        PolicyMergeError::NewBinaryWouldInheritAuthorization { .. }
        | PolicyMergeError::ExistingBinariesWouldInheritAuthorization { .. }
        | PolicyMergeError::UndeclaredPortWouldChange { .. } => true,

        // Separating the rules does not help. The supervisor establishes one MCP
        // inspection contract per host and port rather than per rule, so two
        // contracts stay ambiguous however they are split.
        PolicyMergeError::McpContractConflict { .. }
        | PolicyMergeError::ConflictingInspectionContracts { .. } => false,

        // Reports an unsupported or missing state in the policy the fold
        // targeted rather than a scope conflict. Routing around it would leave
        // the operator with a rule they did not ask for and an existing endpoint
        // still needing attention.
        PolicyMergeError::UnsupportedAccessPreset { .. }
        | PolicyMergeError::UnsupportedEndpointProtocol { .. }
        | PolicyMergeError::EndpointHasNoL7Inspection { .. }
        | PolicyMergeError::EndpointHasNoAllowBase { .. }
        | PolicyMergeError::EndpointNotFound { .. }
        | PolicyMergeError::InvalidEndpointReference { .. }
        | PolicyMergeError::AmbiguousEndpointRule { .. } => false,

        // Malformed operations, and operations `merge_rules` never produces.
        // Neither is answered by choosing a different rule to write to.
        PolicyMergeError::MissingRuleNameForAddRule
        | PolicyMergeError::EmptyAddRuleEndpoints { .. }
        | PolicyMergeError::CannotRemoveBinaryFromAnyBinaryScope { .. } => false,
    }
}

fn merge_rules(
    existing_rule: &mut NetworkPolicyRule,
    incoming_rule: &NetworkPolicyRule,
    operation_index: usize,
    rule_name: &str,
    // Key of the rule actually being modified. Differs from `rule_name` when the
    // endpoint-overlap fallback folded the operation into another rule, so
    // warnings name the rule the operator would have to inspect.
    target_rule_name: &str,
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
    if existing_rule.binaries.is_empty() {
        // The rule already authorizes any binary, so an incoming named list is
        // a subset of what is already granted. Appending it would make the list
        // non-empty and revoke every binary the operation did not name, turning
        // an additive operation into a silent mass revocation. Keep the wider
        // scope and say so; narrowing is `RemoveBinary` or a full replacement.
        if !incoming_rule.binaries.is_empty() {
            warnings.push(PolicyMergeWarning::ExistingAnyBinaryScopeRetained {
                rule_name: target_rule_name.to_string(),
                incoming: incoming_rule
                    .binaries
                    .iter()
                    .map(|binary| binary.path.clone())
                    .collect(),
            });
        }
    } else if incoming_rule.binaries.is_empty() {
        // An incoming any-binary scope replaces the restricted scope instead of
        // appending to it. Appending an empty list would leave the existing
        // binaries in place, so the operation would report success while never
        // authorizing the scope it asked for and coverage would never converge.
        // The inheritance check above already required this operation to
        // declare every merged endpoint before the widening is allowed.
        existing_rule.binaries.clear();
    } else {
        append_unique_binaries(&mut existing_rule.binaries, &incoming_rule.binaries);
    }
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
    existing.allow_uninspected_credentials |= incoming.allow_uninspected_credentials;
    // Provenance is not an authorization bit. If either declaration came
    // directly from a user or provider, keep the endpoint explicit. This
    // mirrors binary provenance and prevents an advisor overlay from tainting
    // an already explicit endpoint for exact-host SSRF evaluation.
    existing.advisor_proposed &= incoming.advisor_proposed;
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
    // Binary scope the operation adds to the rule. An empty incoming list means
    // any binary, which introduces every binary outside the existing list, so it
    // widens this side of the Cartesian product just as a new concrete path does
    // and has to declare the endpoints it will reach. An existing empty list
    // already authorizes any binary, so nothing incoming can widen it further.
    let new_binary_scope = if existing_rule.binaries.is_empty() {
        None
    } else if incoming_rule.binaries.is_empty() {
        Some(ANY_BINARY_SCOPE.to_string())
    } else {
        incoming_rule
            .binaries
            .iter()
            .find(|binary| !existing_binary_paths.contains(binary.path.as_str()))
            .map(|binary| format!("binary '{}'", binary.path))
    };
    let undeclared_binaries = undeclared_existing_binaries(existing_rule, incoming_rule);

    for endpoint in merged_endpoints {
        let units = authorization_ports(endpoint);

        if let Some(binary_scope) = &new_binary_scope {
            // Adoption depends on the declaration and this endpoint, not on the
            // port, so it is resolved once per endpoint rather than per port.
            let declarations: Vec<NetworkEndpoint> = incoming_rule
                .endpoints
                .iter()
                .map(|declared| adopt_unset_retained_fields(declared, endpoint))
                .collect();
            // The operation may declare one endpoint's ports across several
            // incoming endpoints, so each port is checked against every
            // declaration rather than against a single one.
            let undeclared_ports: Vec<Option<u32>> = units
                .iter()
                .copied()
                .filter(|port| !operation_declares(&declarations, endpoint, *port))
                .collect();
            if !undeclared_ports.is_empty() {
                return Err(PolicyMergeError::NewBinaryWouldInheritAuthorization {
                    operation_index,
                    rule_name: rule_name.to_string(),
                    binary_scope: binary_scope.clone(),
                    host: endpoint.host.clone(),
                    ports: undeclared_ports.into_iter().flatten().collect(),
                });
            }
        }

        let changed_ports: Vec<Option<u32>> = units
            .iter()
            .copied()
            .filter(|port| {
                !existing_rule
                    .endpoints
                    .iter()
                    .any(|existing| authorization_unit_unchanged(existing, endpoint, *port))
            })
            .collect();

        // Every changed port must be named by the operation, whether or not the
        // rule's binary scope is fully declared. Widened fields merge into the
        // endpoint as a whole, so a change declared for one port of a
        // multi-port endpoint reaches that endpoint's other ports too. Checking
        // this only alongside undeclared binaries would let an operation that
        // lists every existing binary widen an undeclared port.
        let undeclared_changed_ports: Vec<Option<u32>> = changed_ports
            .iter()
            .copied()
            .filter(|port| !operation_names_port(incoming_rule, endpoint, *port))
            .collect();
        if !undeclared_changed_ports.is_empty() {
            return Err(PolicyMergeError::UndeclaredPortWouldChange {
                operation_index,
                rule_name: rule_name.to_string(),
                host: endpoint.host.clone(),
                ports: undeclared_changed_ports.into_iter().flatten().collect(),
            });
        }

        if !changed_ports.is_empty() && !undeclared_binaries.is_empty() {
            return Err(
                PolicyMergeError::ExistingBinariesWouldInheritAuthorization {
                    operation_index,
                    rule_name: rule_name.to_string(),
                    host: endpoint.host.clone(),
                    ports: changed_ports.into_iter().flatten().collect(),
                    undeclared_binaries,
                },
            );
        }
    }

    Ok(())
}

/// True when the operation names `port` on an endpoint matching `merged`'s host
/// and path.
///
/// This asks only whether the operation addressed the port, not whether it
/// restated the endpoint's authorization. Pre-existing authorization on a port
/// the operation names is not something the operation granted, but a widened
/// field landing on a port the operation never named is.
fn operation_names_port(
    incoming_rule: &NetworkPolicyRule,
    merged: &NetworkEndpoint,
    port: Option<u32>,
) -> bool {
    incoming_rule.endpoints.iter().any(|declared| {
        declared.host.eq_ignore_ascii_case(&merged.host)
            && declared.path == merged.path
            && port.is_none_or(|port| canonical_ports(declared).contains(&port))
    })
}

/// True when the operation itself declares the authorization `merged` grants at
/// `port`, anywhere in `declarations`.
///
/// `declarations` must already have been through `adopt_unset_retained_fields`
/// against `merged`.
fn operation_declares(
    declarations: &[NetworkEndpoint],
    merged: &NetworkEndpoint,
    port: Option<u32>,
) -> bool {
    declarations
        .iter()
        .any(|declared| endpoint_authorization_covers_port(declared, merged, port))
}

/// Fills a declaration's unset carry-over fields from the endpoint it is being
/// judged against.
///
/// A carry-over field is one the merge never widens: it either retains the
/// existing value (`protocol`, `tls`, `enforcement`, `access`) or ignores the
/// incoming value entirely (the signing and GraphQL fields). Either way the new
/// binary receives whatever the endpoint already carried, and the operation
/// cannot change it, so a declaration that leaves the field unset expresses no
/// opinion rather than a request for the default. Comparing the unset value
/// against the merged one would reject a complete declaration over a field the
/// operation never tried to change, and for `enforcement` it would reject
/// specifically because the binary is about to receive the stricter mode.
///
/// Every carry-over field has to be listed here. Missing one costs a false
/// rejection of a complete declaration, which is why adoption is written as an
/// explicit allow-list rather than by copying `merged` and restoring the widened
/// fields: forgetting a field in that direction would silently satisfy the
/// declaration instead.
///
/// This is the declaration direction only. Coverage still exact-matches a value
/// the proposal actually set, because there the question is whether the
/// proposer's own request took effect.
fn adopt_unset_retained_fields(
    declared: &NetworkEndpoint,
    merged: &NetworkEndpoint,
) -> NetworkEndpoint {
    let mut adopted = declared.clone();
    if adopted.protocol.is_empty() {
        adopted.protocol.clone_from(&merged.protocol);
    }
    if adopted.tls.is_empty() {
        adopted.tls.clone_from(&merged.tls);
    }
    if adopted.enforcement.is_empty() {
        adopted.enforcement.clone_from(&merged.enforcement);
    }
    // `merge_endpoint` only touches `access` when the incoming endpoint carries
    // an access preset or explicit rules, so an endpoint declaring neither keeps
    // whatever preset is already loaded.
    if adopted.access.is_empty() && adopted.rules.is_empty() {
        adopted.access.clone_from(&merged.access);
    }
    if adopted.persisted_queries.is_empty() {
        adopted
            .persisted_queries
            .clone_from(&merged.persisted_queries);
    }
    if adopted.graphql_persisted_queries.is_empty() {
        adopted
            .graphql_persisted_queries
            .clone_from(&merged.graphql_persisted_queries);
    }
    if adopted.graphql_max_body_bytes == 0 {
        adopted.graphql_max_body_bytes = merged.graphql_max_body_bytes;
    }
    if adopted.credential_signing.is_empty() {
        adopted
            .credential_signing
            .clone_from(&merged.credential_signing);
    }
    if adopted.signing_service.is_empty() {
        adopted.signing_service.clone_from(&merged.signing_service);
    }
    if adopted.signing_region.is_empty() {
        adopted.signing_region.clone_from(&merged.signing_region);
    }
    if adopted.json_rpc_max_body_bytes == 0 {
        adopted.json_rpc_max_body_bytes = merged.json_rpc_max_body_bytes;
    }
    adopted
}

/// True when `existing` already authorizes exactly what `merged` authorizes at
/// `port`. Equivalence rather than coverage: an existing endpoint authorizing
/// strictly less has changed, and the rule's other binaries would inherit the
/// difference.
fn authorization_unit_unchanged(
    existing: &NetworkEndpoint,
    merged: &NetworkEndpoint,
    port: Option<u32>,
) -> bool {
    endpoint_authorization_covers_port(existing, merged, port)
        && endpoint_authorization_covers_port(merged, existing, port)
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

/// Every endpoint `host:port` resolves to, rendered with its owning rule.
///
/// `endpoint_matches_host_port` deliberately ignores `path`, and
/// `endpoints_overlap` treats a different path as a different endpoint, so one
/// rule can own several matching endpoints. Counting rules alone would miss
/// that, so this counts endpoints.
fn matching_endpoint_targets(policy: &SandboxPolicy, host: &str, port: u32) -> Vec<String> {
    let mut targets: Vec<String> = policy
        .network_policies
        .iter()
        .filter(|(key, _)| !is_provider_rule_name(key))
        .flat_map(|(key, rule)| {
            rule.endpoints
                .iter()
                .filter(|endpoint| endpoint_matches_host_port(endpoint, host, port))
                .map(move |endpoint| {
                    if endpoint.path.is_empty() {
                        key.clone()
                    } else {
                        format!("{key} (path '{}')", endpoint.path)
                    }
                })
        })
        .collect();
    targets.sort();
    targets
}

/// Fails closed when `host:port` resolves to more than one endpoint, because
/// appending an L7 rule widens authorization for every binary on whichever
/// endpoint is picked, and the operation cannot say which one it means.
fn ensure_endpoint_target_is_unambiguous(
    policy: &SandboxPolicy,
    host: &str,
    port: u32,
) -> Result<(), PolicyMergeError> {
    let targets = matching_endpoint_targets(policy, host, port);
    if targets.len() > 1 {
        return Err(PolicyMergeError::AmbiguousEndpointRule {
            host: host.to_string(),
            port,
            targets,
        });
    }
    Ok(())
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
        ANY_BINARY_SCOPE, DEFAULT_JSON_RPC_MAX_BODY_BYTES, PolicyMergeError, PolicyMergeOp,
        PolicyMergeWarning, canonical_ports, canonicalize_advisor_add_rule, generated_rule_name,
        merge_policy, policy_covers_rule,
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

    #[test]
    fn canonicalize_advisor_expands_existing_inspected_rule_without_l7_downgrade() {
        let mut existing_endpoint = endpoint("index.crates.io", 443);
        existing_endpoint.protocol = "rest".to_string();
        existing_endpoint.enforcement = "enforce".to_string();
        existing_endpoint.access = "read-only".to_string();
        let existing = NetworkPolicyRule {
            name: "cargo-registry".to_string(),
            endpoints: vec![existing_endpoint.clone()],
            binaries: vec![NetworkBinary {
                path: "/usr/bin/cargo".to_string(),
                ..Default::default()
            }],
        };
        let mut base = SandboxPolicy::default();
        base.network_policies
            .insert("cargo_registry".to_string(), existing);
        let effective = base.clone();
        let mut observed = endpoint("index.crates.io", 443);
        observed.advisor_proposed = true;
        let incoming = NetworkPolicyRule {
            name: "allow_index_crates_io_443".to_string(),
            endpoints: vec![observed],
            binaries: vec![advisor_binary("/usr/bin/curl")],
        };

        let (rule_name, canonical) = canonicalize_advisor_add_rule(
            &base,
            &effective,
            "allow_index_crates_io_443",
            &incoming,
        )
        .unwrap();

        assert_eq!(rule_name, "cargo_registry");
        assert_eq!(canonical.endpoints, vec![existing_endpoint]);
        assert_eq!(canonical.binaries[0].path, "/usr/bin/curl");
        #[allow(deprecated)]
        {
            assert!(canonical.binaries[0].harness);
        }
    }

    #[test]
    fn canonicalize_advisor_mirrors_provider_contract_into_sandbox_overlay() {
        let base = SandboxPolicy::default();
        let mut provider_endpoint = endpoint("api.example.com", 443);
        provider_endpoint.protocol = "rest".to_string();
        provider_endpoint.enforcement = "enforce".to_string();
        provider_endpoint.access = "read-only".to_string();
        provider_endpoint.provider_credentialed = true;
        let mut effective = SandboxPolicy::default();
        effective.network_policies.insert(
            "_provider_example".to_string(),
            NetworkPolicyRule {
                name: "provider-example".to_string(),
                endpoints: vec![provider_endpoint.clone()],
                binaries: Vec::new(),
            },
        );
        let incoming = NetworkPolicyRule {
            name: "advisor_example".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.example.com".to_string(),
                port: 443,
                advisor_proposed: true,
                ..Default::default()
            }],
            binaries: vec![advisor_binary("/usr/bin/curl")],
        };

        let (rule_name, canonical) =
            canonicalize_advisor_add_rule(&base, &effective, "advisor_example", &incoming).unwrap();

        assert_eq!(rule_name, "advisor_example");
        assert_eq!(canonical.endpoints[0].protocol, "rest");
        assert_eq!(canonical.endpoints[0].access, "read-only");
        assert!(!canonical.endpoints[0].provider_credentialed);
        assert_eq!(
            effective.network_policies["_provider_example"].endpoints[0],
            provider_endpoint
        );
    }

    #[test]
    fn canonicalize_advisor_narrows_multi_port_contract_and_keeps_overlay() {
        let mut existing_endpoint = endpoint("index.crates.io", 443);
        existing_endpoint.port = 80;
        existing_endpoint.ports = vec![80, 443];
        existing_endpoint.protocol = "rest".to_string();
        existing_endpoint.enforcement = "enforce".to_string();
        existing_endpoint.access = "read-only".to_string();
        let existing = NetworkPolicyRule {
            name: "cargo-registry".to_string(),
            endpoints: vec![existing_endpoint],
            binaries: vec![binary("/usr/bin/cargo")],
        };
        let mut base = SandboxPolicy::default();
        base.network_policies
            .insert("cargo_registry".to_string(), existing);
        let effective = base.clone();
        let incoming = NetworkPolicyRule {
            name: "allow_index_crates_io_443".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "index.crates.io".to_string(),
                port: 443,
                advisor_proposed: true,
                ..Default::default()
            }],
            binaries: vec![advisor_binary("/usr/bin/curl")],
        };

        let (rule_name, canonical) = canonicalize_advisor_add_rule(
            &base,
            &effective,
            "allow_index_crates_io_443",
            &incoming,
        )
        .unwrap();

        assert_eq!(rule_name, "allow_index_crates_io_443");
        assert_eq!(canonical.endpoints[0].ports, vec![443]);
        assert_eq!(canonical.endpoints[0].protocol, "rest");
        assert_eq!(canonical.endpoints[0].access, "read-only");

        let merged = merge_policy(
            base,
            &[PolicyMergeOp::AddRule {
                rule_name,
                rule: canonical,
            }],
        )
        .unwrap()
        .policy;
        assert_eq!(
            merged.network_policies["cargo_registry"].endpoints[0].ports,
            vec![80, 443]
        );
        assert_eq!(
            merged.network_policies["allow_index_crates_io_443"].endpoints[0].ports,
            vec![443]
        );
        assert_eq!(
            merged.network_policies["allow_index_crates_io_443"].binaries[0].path,
            "/usr/bin/curl"
        );
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
                binary_scope,
                host,
                ports,
                ..
            } if binary_scope == "binary '/usr/bin/untrusted'"
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
                binary_scope,
                host,
                ..
            } if binary_scope == "binary '/usr/bin/untrusted'" && host == "mcp.example.com"
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
    fn policy_coverage_ignores_endpoint_advisor_provenance() {
        let loaded_endpoint = endpoint("api.example.com", 443);
        let mut proposed_endpoint = loaded_endpoint.clone();
        proposed_endpoint.advisor_proposed = true;
        let loaded = policy_with_rule(
            "loaded",
            rule_with_authorizations("loaded", vec![loaded_endpoint], &["/usr/bin/client"]),
        );
        let proposed =
            rule_with_authorizations("proposed", vec![proposed_endpoint], &["/usr/bin/client"]);

        assert!(policy_covers_rule(&loaded, &proposed));
    }

    #[test]
    fn explicit_endpoint_provenance_wins_in_either_merge_order() {
        let explicit_endpoint = endpoint("api.example.com", 443);
        let mut proposed_endpoint = explicit_endpoint.clone();
        proposed_endpoint.advisor_proposed = true;

        for (existing_endpoint, incoming_endpoint) in [
            (explicit_endpoint.clone(), proposed_endpoint.clone()),
            (proposed_endpoint, explicit_endpoint),
        ] {
            let incoming =
                rule_with_authorizations("api", vec![incoming_endpoint], &["/usr/bin/client"]);
            let merged = merge_policy(
                policy_with_rule(
                    "api",
                    rule_with_authorizations("api", vec![existing_endpoint], &["/usr/bin/client"]),
                ),
                &[PolicyMergeOp::AddRule {
                    rule_name: "api".to_string(),
                    rule: incoming.clone(),
                }],
            )
            .expect("compatible explicit and advisor rules should merge");

            let endpoint = &merged.policy.network_policies["api"].endpoints[0];
            assert!(!endpoint.advisor_proposed);
            assert!(policy_covers_rule(&merged.policy, &incoming));
        }
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
    fn add_rule_merges_allow_uninspected_credentials_flag() {
        let mut policy = restrictive_default_policy();
        policy.network_policies.insert(
            "existing".to_string(),
            NetworkPolicyRule {
                name: "existing".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "api.vendor.example".to_string(),
                    port: 443,
                    ports: vec![443],
                    ..Default::default()
                }],
                ..Default::default()
            },
        );

        let incoming = NetworkPolicyRule {
            name: "incoming".to_string(),
            endpoints: vec![NetworkEndpoint {
                host: "api.vendor.example".to_string(),
                port: 443,
                ports: vec![443],
                allow_uninspected_credentials: true,
                ..Default::default()
            }],
            ..Default::default()
        };

        let result = merge_policy(
            policy,
            &[PolicyMergeOp::AddRule {
                rule_name: "allow_api_vendor_example_443".to_string(),
                rule: incoming,
            }],
        )
        .expect("merge should succeed");

        let endpoint = &result.policy.network_policies["existing"].endpoints[0];
        assert!(endpoint.allow_uninspected_credentials);
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
        // The existing rule declares no binaries, which authorizes any binary.
        // Absorbing the incoming path would make the list non-empty and revoke
        // every other process, so the wider scope is kept and reported instead.
        let merged = &result.policy.network_policies["custom_github"];
        assert!(
            merged.binaries.is_empty(),
            "an any-binary rule must not be narrowed by an additive operation; got {:?}",
            merged.binaries
        );
        assert!(
            result.warnings.iter().any(|warning| matches!(
                warning,
                PolicyMergeWarning::ExistingAnyBinaryScopeRetained { rule_name, incoming }
                    if rule_name == "custom_github"
                        && incoming == &["/usr/bin/curl".to_string()]
            )),
            "got warnings: {:?}",
            result.warnings
        );
    }

    fn endpoint_with_ports(host: &str, ports: &[u32]) -> NetworkEndpoint {
        NetworkEndpoint {
            host: host.to_string(),
            port: ports.first().copied().unwrap_or_default(),
            ports: ports.to_vec(),
            ..Default::default()
        }
    }

    /// A proposal that omits a field the merge retains still has to read back as
    /// covered. The merge keeps the loaded value and reports success, so
    /// requiring the proposal to match the loaded value would leave the
    /// `policy.local /wait` long poll spinning against a policy that did load.
    #[test]
    fn coverage_treats_an_omitted_retained_field_as_unspecified() {
        for (field, loaded_endpoint) in [
            (
                "enforcement",
                NetworkEndpoint {
                    enforcement: "enforce".to_string(),
                    ..endpoint("api.example.com", 443)
                },
            ),
            (
                "protocol",
                NetworkEndpoint {
                    protocol: "rest".to_string(),
                    ..endpoint("api.example.com", 443)
                },
            ),
            (
                "tls",
                NetworkEndpoint {
                    tls: "skip".to_string(),
                    ..endpoint("api.example.com", 443)
                },
            ),
        ] {
            let existing =
                rule_with_authorizations("existing", vec![loaded_endpoint], &["/usr/bin/trusted"]);
            // The proposal declares the whole binary scope and leaves the
            // retained field unset, so the merge accepts it unchanged.
            let proposal = rule_with_authorizations(
                "existing",
                vec![endpoint("api.example.com", 443)],
                &["/usr/bin/trusted"],
            );

            let result = merge_policy(
                policy_with_rule("existing", existing),
                &[PolicyMergeOp::AddRule {
                    rule_name: "existing".to_string(),
                    rule: proposal.clone(),
                }],
            )
            .unwrap_or_else(|error| panic!("omitting {field} should merge cleanly: {error}"));

            assert!(
                policy_covers_rule(&result.policy, &proposal),
                "a proposal omitting {field} merged cleanly, so it must read back as covered"
            );
        }
    }

    /// A rule's port list is a set of independent authorizations, so the loaded
    /// policy may spread one proposed endpoint's ports across several rules.
    #[test]
    fn coverage_resolves_each_port_across_the_loaded_rule_union() {
        let mut policy = policy_with_rule(
            "https",
            rule_with_authorizations(
                "https",
                vec![endpoint_with_ports("api.example.com", &[443])],
                &["/usr/bin/client"],
            ),
        );
        policy.network_policies.insert(
            "alt_https".to_string(),
            rule_with_authorizations(
                "alt_https",
                vec![endpoint_with_ports("api.example.com", &[8443])],
                &["/usr/bin/client"],
            ),
        );

        let proposed = rule_with_authorizations(
            "combined",
            vec![endpoint_with_ports("api.example.com", &[443, 8443])],
            &["/usr/bin/client"],
        );

        assert!(
            policy_covers_rule(&policy, &proposed),
            "two loaded rules covering one port each authorize the same traffic \
             as one rule covering both"
        );
    }

    /// An endpoint that declares no port at all still needs a matching loaded
    /// endpoint. Iterating an empty port list would make the coverage `all()`
    /// vacuously true and report an unmatched proposal as covered.
    #[test]
    fn coverage_rejects_a_portless_endpoint_no_loaded_rule_matches() {
        let policy = policy_with_rule(
            "existing",
            rule_with_authorizations(
                "existing",
                vec![endpoint("api.example.com", 443)],
                &["/usr/bin/client"],
            ),
        );
        let proposed = rule_with_authorizations(
            "other",
            vec![NetworkEndpoint {
                host: "unrelated.example.com".to_string(),
                ..Default::default()
            }],
            &["/usr/bin/client"],
        );

        assert!(
            !policy_covers_rule(&policy, &proposed),
            "no loaded rule mentions the proposed host, so coverage must fail closed"
        );
    }

    /// A complete declaration may arrive split across several incoming
    /// endpoints. Requiring one declaration to cover the whole merged endpoint
    /// would reject a new binary that did declare every port it will reach.
    #[test]
    fn new_binary_may_declare_one_endpoints_ports_across_several_declarations() {
        let existing = rule_with_authorizations(
            "existing",
            vec![endpoint_with_ports("api.example.com", &[443, 8443])],
            &["/usr/bin/trusted"],
        );
        let incoming = rule_with_authorizations(
            "existing",
            vec![
                endpoint_with_ports("api.example.com", &[443]),
                endpoint_with_ports("api.example.com", &[8443]),
            ],
            &["/usr/bin/trusted", "/usr/bin/second"],
        );

        let result = merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming,
            }],
        )
        .expect("the new binary declared both ports, just in separate endpoints");

        let merged = &result.policy.network_policies["existing"];
        assert!(merged.binaries.iter().any(|b| b.path == "/usr/bin/second"));
    }

    /// The complement: a split declaration that misses a port is still an
    /// implicit grant and must be rejected, naming the port left undeclared.
    #[test]
    fn new_binary_split_declaration_must_still_cover_every_port() {
        let existing = rule_with_authorizations(
            "existing",
            vec![endpoint_with_ports("api.example.com", &[443, 8443])],
            &["/usr/bin/trusted"],
        );
        let incoming = rule_with_authorizations(
            "existing",
            vec![endpoint_with_ports("api.example.com", &[443])],
            &["/usr/bin/trusted", "/usr/bin/second"],
        );

        let error = merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming,
            }],
        )
        .expect_err("port 8443 was never declared for the new binary");

        assert!(matches!(
            error,
            PolicyMergeError::NewBinaryWouldInheritAuthorization { ports, .. }
                if ports == vec![8443]
        ));
    }

    /// An incoming empty binary list means any binary, which widens a
    /// restricted rule to every binary on the system. It has to declare the
    /// rule's whole endpoint scope first, exactly like a new concrete path.
    #[test]
    fn any_binary_proposal_cannot_inherit_undeclared_endpoints() {
        let existing = rule_with_authorizations(
            "existing",
            vec![
                endpoint("api.example.com", 443),
                endpoint("admin.example.com", 443),
            ],
            &["/usr/bin/trusted"],
        );
        let incoming =
            rule_with_authorizations("existing", vec![endpoint("api.example.com", 443)], &[]);

        let error = merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming,
            }],
        )
        .expect_err("any-binary scope would reach the undeclared admin endpoint");

        assert!(matches!(
            error,
            PolicyMergeError::NewBinaryWouldInheritAuthorization { binary_scope, host, .. }
                if binary_scope == ANY_BINARY_SCOPE && host == "admin.example.com"
        ));
    }

    /// Once the declaration is complete the promotion has to be applied.
    /// Appending an empty binary list would leave the restricted scope in place,
    /// so the operation would report success while authorizing nothing it asked
    /// for and coverage would never converge.
    #[test]
    fn any_binary_proposal_replaces_a_restricted_scope_once_fully_declared() {
        let existing = rule_with_authorizations(
            "existing",
            vec![endpoint("api.example.com", 443)],
            &["/usr/bin/trusted"],
        );
        let incoming =
            rule_with_authorizations("existing", vec![endpoint("api.example.com", 443)], &[]);

        let result = merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming.clone(),
            }],
        )
        .expect("the proposal declared the rule's only endpoint");

        assert!(
            result.policy.network_policies["existing"]
                .binaries
                .is_empty(),
            "the any-binary scope the operation asked for must be applied"
        );
        assert!(
            policy_covers_rule(&result.policy, &incoming),
            "an applied any-binary scope must read back as covered"
        );
    }

    /// The overlap fallback is a convenience for incremental refinement, not
    /// something the operation requested. When folding would grant undeclared
    /// authorization, the proposal keeps its own rule name instead, which
    /// authorizes exactly the product it declared. Without this the documented
    /// "put the new authorization in a separate rule" remediation is
    /// unreachable for any endpoint that overlaps an existing rule.
    #[test]
    fn overlapping_partial_authorization_keeps_its_requested_rule_name() {
        let existing = rule_with_authorizations(
            "existing",
            vec![
                endpoint("api.example.com", 443),
                endpoint("admin.example.com", 443),
            ],
            &["/usr/bin/trusted"],
        );

        let result = merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "narrow_grant".to_string(),
                rule: rule_with_authorizations(
                    "narrow_grant",
                    vec![endpoint("api.example.com", 443)],
                    &["/usr/bin/limited"],
                ),
            }],
        )
        .expect("a partial grant must land on its own rule rather than be rejected");

        let narrow = result
            .policy
            .network_policies
            .get("narrow_grant")
            .expect("the requested key must be preserved when folding would widen");
        assert_eq!(narrow.binaries.len(), 1);
        assert_eq!(narrow.endpoints.len(), 1);

        // Skipping the fold has to be visible: the operator asked for one rule
        // and got two, and later host-and-port operations now have two
        // candidate rules to resolve against.
        assert!(
            result.warnings.iter().any(|warning| matches!(
                warning,
                PolicyMergeWarning::KeptRequestedRuleNameToAvoidWidening {
                    rule_name,
                    overlapping_rule_name,
                    ..
                } if rule_name == "narrow_grant" && overlapping_rule_name == "existing"
            )),
            "got warnings: {:?}",
            result.warnings
        );

        // The existing rule keeps its own product untouched: the limited binary
        // never gains the admin endpoint.
        let untouched = &result.policy.network_policies["existing"];
        assert_eq!(untouched.binaries.len(), 1);
        assert!(
            untouched
                .binaries
                .iter()
                .all(|b| b.path != "/usr/bin/limited")
        );
    }

    /// Folding stays the default when it grants nothing new, so incremental
    /// refinement under a fresh rule name still consolidates.
    #[test]
    fn overlapping_complete_authorization_still_folds_into_the_existing_rule() {
        let existing = rule_with_authorizations(
            "existing",
            vec![endpoint("api.example.com", 443)],
            &["/usr/bin/trusted"],
        );

        let result = merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "refinement".to_string(),
                rule: rule_with_authorizations(
                    "refinement",
                    vec![endpoint("api.example.com", 443)],
                    &["/usr/bin/trusted", "/usr/bin/second"],
                ),
            }],
        )
        .expect("the operation declared the rule's whole scope");

        assert!(
            !result.policy.network_policies.contains_key("refinement"),
            "a complete declaration should still fold into the overlapping rule"
        );
        assert_eq!(result.policy.network_policies["existing"].binaries.len(), 2);
    }

    /// An MCP contract conflict is not resolved by moving the authorization to
    /// another rule, because the supervisor establishes one contract per host
    /// and port. It must propagate even on the fallback path.
    #[test]
    fn overlapping_mcp_contract_conflict_is_not_deflected_to_a_separate_rule() {
        let existing = rule_with_authorizations(
            "existing",
            vec![mcp_endpoint(
                "mcp.example.com",
                &[443],
                None,
                None,
                65536,
                vec![mcp_tool_rule("existing-tool")],
            )],
            &["/usr/bin/trusted"],
        );

        let error = merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "second_contract".to_string(),
                rule: rule_with_authorizations(
                    "second_contract",
                    vec![mcp_endpoint(
                        "mcp.example.com",
                        &[443],
                        None,
                        None,
                        131_072,
                        vec![mcp_tool_rule("other-tool")],
                    )],
                    &["/usr/bin/trusted"],
                ),
            }],
        )
        .expect_err("one host and port cannot carry two inspection contracts");

        assert!(matches!(
            error,
            PolicyMergeError::McpContractConflict { .. }
        ));
    }

    /// The round-trip property the whole design rests on: whatever the gateway
    /// accepts must immediately read back as covered, or `/wait` hangs.
    #[test]
    fn every_accepted_merge_reads_back_as_covered() {
        let cases: Vec<(&str, NetworkPolicyRule, NetworkPolicyRule)> = vec![
            (
                "omitted enforcement against an enforced endpoint",
                rule_with_authorizations(
                    "existing",
                    vec![NetworkEndpoint {
                        enforcement: "enforce".to_string(),
                        ..endpoint("api.example.com", 443)
                    }],
                    &["/usr/bin/trusted"],
                ),
                rule_with_authorizations(
                    "existing",
                    vec![endpoint("api.example.com", 443)],
                    &["/usr/bin/trusted"],
                ),
            ),
            (
                "split ports declared across two endpoints",
                rule_with_authorizations(
                    "existing",
                    vec![endpoint_with_ports("api.example.com", &[443, 8443])],
                    &["/usr/bin/trusted"],
                ),
                rule_with_authorizations(
                    "existing",
                    vec![
                        endpoint_with_ports("api.example.com", &[443]),
                        endpoint_with_ports("api.example.com", &[8443]),
                    ],
                    &["/usr/bin/trusted", "/usr/bin/second"],
                ),
            ),
            (
                "any-binary promotion",
                rule_with_authorizations(
                    "existing",
                    vec![endpoint("api.example.com", 443)],
                    &["/usr/bin/trusted"],
                ),
                rule_with_authorizations("existing", vec![endpoint("api.example.com", 443)], &[]),
            ),
        ];

        for (label, existing, proposal) in cases {
            let result = merge_policy(
                policy_with_rule("existing", existing),
                &[PolicyMergeOp::AddRule {
                    rule_name: "existing".to_string(),
                    rule: proposal.clone(),
                }],
            )
            .unwrap_or_else(|error| panic!("{label} should merge: {error}"));

            assert!(
                policy_covers_rule(&result.policy, &proposal),
                "{label}: the merge was accepted, so coverage must report it loaded"
            );
        }
    }

    /// A declaration that leaves a retained field unset expresses no opinion
    /// about it. Rejecting on that field would refuse a complete declaration
    /// over a mode the operation never tried to change, and for enforcement it
    /// would refuse specifically because the binary receives the stricter mode.
    #[test]
    fn declaration_may_omit_retained_fields_it_does_not_change() {
        for (field, loaded_endpoint) in [
            (
                "enforcement",
                NetworkEndpoint {
                    enforcement: "enforce".to_string(),
                    ..endpoint("api.example.com", 443)
                },
            ),
            (
                "protocol",
                NetworkEndpoint {
                    protocol: "rest".to_string(),
                    ..endpoint("api.example.com", 443)
                },
            ),
            (
                "tls",
                NetworkEndpoint {
                    tls: "skip".to_string(),
                    ..endpoint("api.example.com", 443)
                },
            ),
            (
                "access",
                NetworkEndpoint {
                    protocol: "rest".to_string(),
                    access: "read-only".to_string(),
                    ..endpoint("api.example.com", 443)
                },
            ),
            (
                "credential_signing",
                NetworkEndpoint {
                    credential_signing: "sigv4".to_string(),
                    signing_service: "s3".to_string(),
                    signing_region: "us-west-2".to_string(),
                    ..endpoint("api.example.com", 443)
                },
            ),
            (
                "persisted_queries",
                NetworkEndpoint {
                    persisted_queries: "allow_registered".to_string(),
                    graphql_max_body_bytes: 4096,
                    ..endpoint("api.example.com", 443)
                },
            ),
            (
                "json_rpc_max_body_bytes",
                NetworkEndpoint {
                    json_rpc_max_body_bytes: 65536,
                    ..endpoint("api.example.com", 443)
                },
            ),
        ] {
            let existing =
                rule_with_authorizations("existing", vec![loaded_endpoint], &["/usr/bin/trusted"]);
            // Declares the whole scope, but says nothing about the carry-over
            // field the endpoint already carries.
            let incoming = rule_with_authorizations(
                "existing",
                vec![endpoint("api.example.com", 443)],
                &["/usr/bin/trusted", "/usr/bin/second"],
            );

            merge_policy(
                policy_with_rule("existing", existing),
                &[PolicyMergeOp::AddRule {
                    rule_name: "existing".to_string(),
                    rule: incoming,
                }],
            )
            .unwrap_or_else(|error| {
                panic!("a declaration omitting {field} covers the whole scope: {error}")
            });
        }
    }

    /// Omitting a retained field is not the same as contradicting one. A
    /// declaration that names a different protocol still has to be rejected.
    #[test]
    fn declaration_that_contradicts_a_retained_field_is_still_rejected() {
        let existing = rule_with_authorizations(
            "existing",
            vec![NetworkEndpoint {
                protocol: "rest".to_string(),
                ..endpoint("api.example.com", 443)
            }],
            &["/usr/bin/trusted"],
        );
        let incoming = rule_with_authorizations(
            "existing",
            vec![NetworkEndpoint {
                protocol: "websocket".to_string(),
                ..endpoint("api.example.com", 443)
            }],
            &["/usr/bin/trusted", "/usr/bin/second"],
        );

        let error = merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming,
            }],
        )
        .expect_err("the declaration describes a protocol the merge will not apply");

        assert!(matches!(
            error,
            PolicyMergeError::NewBinaryWouldInheritAuthorization { .. }
        ));
    }

    /// `AddAllowRules` and `AddDenyRules` name their target by host and port
    /// alone, so when two rules carry that endpoint they cannot say which binary
    /// scope to widen. Picking one silently would add the rule to whichever key
    /// sorts first.
    #[test]
    fn l7_operations_reject_an_endpoint_carried_by_several_rules() {
        let mut policy = policy_with_rule(
            "broad",
            rule_with_authorizations(
                "broad",
                vec![NetworkEndpoint {
                    protocol: "rest".to_string(),
                    rules: vec![rest_rule("GET", "/public")],
                    ..endpoint("api.example.com", 443)
                }],
                &["/usr/bin/trusted", "/usr/bin/limited"],
            ),
        );
        policy.network_policies.insert(
            "narrow".to_string(),
            rule_with_authorizations(
                "narrow",
                vec![NetworkEndpoint {
                    protocol: "rest".to_string(),
                    rules: vec![rest_rule("GET", "/public")],
                    ..endpoint("api.example.com", 443)
                }],
                &["/usr/bin/other"],
            ),
        );

        for operation in [
            PolicyMergeOp::AddAllowRules {
                host: "api.example.com".to_string(),
                port: 443,
                rules: vec![rest_rule("POST", "/admin")],
            },
            PolicyMergeOp::AddDenyRules {
                host: "api.example.com".to_string(),
                port: 443,
                deny_rules: Vec::new(),
            },
        ] {
            let error = merge_policy(policy.clone(), &[operation])
                .expect_err("two rules carry this endpoint, so the target is ambiguous");

            assert!(
                matches!(
                    &error,
                    PolicyMergeError::AmbiguousEndpointRule { targets, .. }
                        if targets == &["broad".to_string(), "narrow".to_string()]
                ),
                "got {error:?}"
            );
        }
    }

    /// A single rule can own several endpoints on one host and port, because
    /// `endpoints_overlap` treats a different path as a different endpoint.
    /// Counting owning rules would miss this and let the operation land on
    /// whichever endpoint happens to sit first in the vector.
    #[test]
    fn l7_operations_reject_two_paths_on_one_host_and_port_within_a_rule() {
        let policy = policy_with_rule(
            "versioned",
            rule_with_authorizations(
                "versioned",
                vec![
                    NetworkEndpoint {
                        protocol: "rest".to_string(),
                        path: "/v1".to_string(),
                        rules: vec![rest_rule("GET", "/public")],
                        ..endpoint("api.example.com", 443)
                    },
                    NetworkEndpoint {
                        protocol: "rest".to_string(),
                        path: "/v2".to_string(),
                        rules: vec![rest_rule("GET", "/public")],
                        ..endpoint("api.example.com", 443)
                    },
                ],
                &["/usr/bin/trusted"],
            ),
        );

        let error = merge_policy(
            policy,
            &[PolicyMergeOp::AddAllowRules {
                host: "api.example.com".to_string(),
                port: 443,
                rules: vec![rest_rule("POST", "/admin")],
            }],
        )
        .expect_err("one host and port resolves to two endpoints on this rule");

        assert!(
            matches!(
                &error,
                PolicyMergeError::AmbiguousEndpointRule { targets, .. }
                    if targets == &[
                        "versioned (path '/v1')".to_string(),
                        "versioned (path '/v2')".to_string(),
                    ]
            ),
            "got {error:?}"
        );
    }

    /// The unambiguous case must keep working, or every incremental L7 update
    /// breaks.
    #[test]
    fn l7_operations_still_apply_when_one_rule_carries_the_endpoint() {
        let policy = policy_with_rule(
            "only",
            rule_with_authorizations(
                "only",
                vec![NetworkEndpoint {
                    protocol: "rest".to_string(),
                    rules: vec![rest_rule("GET", "/public")],
                    ..endpoint("api.example.com", 443)
                }],
                &["/usr/bin/trusted"],
            ),
        );

        let result = merge_policy(
            policy,
            &[PolicyMergeOp::AddAllowRules {
                host: "api.example.com".to_string(),
                port: 443,
                rules: vec![rest_rule("POST", "/issues")],
            }],
        )
        .expect("a single owning rule is unambiguous");

        assert_eq!(
            result.policy.network_policies["only"].endpoints[0]
                .rules
                .len(),
            2
        );
    }

    /// Removing a binary from an any-binary rule has no entry to drop, so
    /// reporting success would leave the operator believing a revocation landed
    /// while the rule still authorizes every binary.
    #[test]
    fn remove_binary_rejects_an_any_binary_rule_instead_of_doing_nothing() {
        let policy = policy_with_rule(
            "wide",
            rule_with_authorizations("wide", vec![endpoint("api.example.com", 443)], &[]),
        );

        let error = merge_policy(
            policy,
            &[PolicyMergeOp::RemoveBinary {
                rule_name: "wide".to_string(),
                binary_path: "/usr/bin/untrusted".to_string(),
            }],
        )
        .expect_err("an any-binary rule has no binary entry to remove");

        assert!(matches!(
            error,
            PolicyMergeError::CannotRemoveBinaryFromAnyBinaryScope { rule_name, binary_path, .. }
                if rule_name == "wide" && binary_path == "/usr/bin/untrusted"
        ));
    }

    /// Removing the last named binary deletes the rule rather than leaving an
    /// empty list, which would silently widen it to every binary.
    #[test]
    fn remove_binary_deletes_the_rule_rather_than_widening_it() {
        let policy = policy_with_rule(
            "narrow",
            rule_with_authorizations(
                "narrow",
                vec![endpoint("api.example.com", 443)],
                &["/usr/bin/only"],
            ),
        );

        let result = merge_policy(
            policy,
            &[PolicyMergeOp::RemoveBinary {
                rule_name: "narrow".to_string(),
                binary_path: "/usr/bin/only".to_string(),
            }],
        )
        .expect("removing the last binary is a valid revocation");

        assert!(
            !result.policy.network_policies.contains_key("narrow"),
            "an emptied rule must be removed, not left authorizing any binary"
        );
    }

    /// Widened fields merge into an endpoint as a whole, so a change declared
    /// for one port of a multi-port endpoint reaches the endpoint's other ports.
    /// Declaring every existing binary must not exempt the operation from
    /// naming the ports its change lands on.
    #[test]
    fn declaring_every_binary_does_not_license_an_undeclared_port() {
        let existing = rule_with_authorizations(
            "existing",
            vec![NetworkEndpoint {
                protocol: "rest".to_string(),
                rules: vec![rest_rule("GET", "/x")],
                ..endpoint_with_ports("api.example.com", &[443, 8443])
            }],
            &["/usr/bin/only"],
        );
        let incoming = rule_with_authorizations(
            "existing",
            vec![NetworkEndpoint {
                protocol: "rest".to_string(),
                rules: vec![rest_rule("POST", "/y")],
                ..endpoint_with_ports("api.example.com", &[443])
            }],
            &["/usr/bin/only"],
        );

        let error = merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming,
            }],
        )
        .expect_err("POST would also land on the undeclared port 8443");

        assert!(
            matches!(
                &error,
                PolicyMergeError::UndeclaredPortWouldChange { ports, host, .. }
                    if ports == &[8443] && host == "api.example.com"
            ),
            "got {error:?}"
        );
    }

    /// Naming every port the change lands on is accepted, so the incremental
    /// flow still works once the operation is explicit about its scope.
    #[test]
    fn naming_every_changed_port_is_accepted() {
        let existing = rule_with_authorizations(
            "existing",
            vec![NetworkEndpoint {
                protocol: "rest".to_string(),
                rules: vec![rest_rule("GET", "/x")],
                ..endpoint_with_ports("api.example.com", &[443, 8443])
            }],
            &["/usr/bin/only"],
        );
        let incoming = rule_with_authorizations(
            "existing",
            vec![NetworkEndpoint {
                protocol: "rest".to_string(),
                rules: vec![rest_rule("POST", "/y")],
                ..endpoint_with_ports("api.example.com", &[443, 8443])
            }],
            &["/usr/bin/only"],
        );

        let result = merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming,
            }],
        )
        .expect("the operation named both ports the change reaches");

        assert_eq!(
            result.policy.network_policies["existing"].endpoints[0]
                .rules
                .len(),
            2
        );
    }

    /// The supervisor resolves one MCP contract per host and port, matching on
    /// host and port without consulting the path, so two contracts cannot
    /// coexist even under different paths on the same rule.
    #[test]
    fn two_mcp_contracts_on_one_host_and_port_are_rejected_across_paths() {
        let existing = rule_with_authorizations(
            "existing",
            vec![NetworkEndpoint {
                path: "/a".to_string(),
                ..mcp_endpoint(
                    "mcp.example.com",
                    &[443],
                    None,
                    None,
                    65536,
                    vec![mcp_tool_rule("first")],
                )
            }],
            &["/usr/bin/only"],
        );
        let incoming = rule_with_authorizations(
            "existing",
            vec![NetworkEndpoint {
                path: "/b".to_string(),
                ..mcp_endpoint(
                    "mcp.example.com",
                    &[443],
                    None,
                    None,
                    131_072,
                    vec![mcp_tool_rule("second")],
                )
            }],
            &["/usr/bin/only"],
        );

        let error = merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming,
            }],
        )
        .expect_err("a differing path does not license a second inspection contract");

        assert!(
            matches!(
                &error,
                PolicyMergeError::ConflictingInspectionContracts { host, port, contracts }
                    if host == "mcp.example.com" && *port == 443 && contracts.len() == 2
            ),
            "got {error:?}"
        );
    }

    /// The same conflict across two rules is equally unsafe, because the
    /// supervisor does not care which rule contributed the endpoint.
    #[test]
    fn two_mcp_contracts_on_one_host_and_port_are_rejected_across_rules() {
        let policy = policy_with_rule(
            "first_rule",
            rule_with_authorizations(
                "first_rule",
                vec![mcp_endpoint(
                    "mcp.example.com",
                    &[443],
                    None,
                    None,
                    65536,
                    vec![mcp_tool_rule("first")],
                )],
                &["/usr/bin/a"],
            ),
        );

        let error = merge_policy(
            policy,
            &[PolicyMergeOp::AddRule {
                rule_name: "second_rule".to_string(),
                rule: rule_with_authorizations(
                    "second_rule",
                    vec![NetworkEndpoint {
                        path: "/other".to_string(),
                        ..mcp_endpoint(
                            "mcp.example.com",
                            &[443],
                            None,
                            None,
                            131_072,
                            vec![mcp_tool_rule("second")],
                        )
                    }],
                    &["/usr/bin/b"],
                ),
            }],
        )
        .expect_err("a separate rule does not license a second inspection contract");

        assert!(matches!(
            error,
            PolicyMergeError::ConflictingInspectionContracts { .. }
        ));
    }

    /// Matching contracts on one host and port are fine, so splitting an MCP
    /// surface across paths or rules stays possible when the contract agrees.
    #[test]
    fn matching_mcp_contracts_on_one_host_and_port_are_accepted() {
        let existing = rule_with_authorizations(
            "existing",
            vec![NetworkEndpoint {
                path: "/a".to_string(),
                ..mcp_endpoint(
                    "mcp.example.com",
                    &[443],
                    None,
                    None,
                    65536,
                    vec![mcp_tool_rule("first")],
                )
            }],
            &["/usr/bin/only"],
        );
        let incoming = rule_with_authorizations(
            "existing",
            vec![NetworkEndpoint {
                path: "/b".to_string(),
                ..mcp_endpoint(
                    "mcp.example.com",
                    &[443],
                    None,
                    None,
                    65536,
                    vec![mcp_tool_rule("second")],
                )
            }],
            &["/usr/bin/only"],
        );

        merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming,
            }],
        )
        .expect("identical contracts resolve the same way whichever endpoint matches first");
    }

    /// A conflict already present in the baseline must not make every later
    /// update fail with an error the operation did nothing to cause.
    #[test]
    fn a_preexisting_mcp_conflict_does_not_block_an_unrelated_update() {
        let mut policy = policy_with_rule(
            "first_rule",
            rule_with_authorizations(
                "first_rule",
                vec![mcp_endpoint(
                    "mcp.example.com",
                    &[443],
                    None,
                    None,
                    65536,
                    vec![mcp_tool_rule("first")],
                )],
                &["/usr/bin/a"],
            ),
        );
        policy.network_policies.insert(
            "second_rule".to_string(),
            rule_with_authorizations(
                "second_rule",
                vec![NetworkEndpoint {
                    path: "/other".to_string(),
                    ..mcp_endpoint(
                        "mcp.example.com",
                        &[443],
                        None,
                        None,
                        131_072,
                        vec![mcp_tool_rule("second")],
                    )
                }],
                &["/usr/bin/b"],
            ),
        );

        merge_policy(
            policy,
            &[PolicyMergeOp::AddRule {
                rule_name: "unrelated".to_string(),
                rule: rule_with_authorizations(
                    "unrelated",
                    vec![endpoint("other.example.com", 443)],
                    &["/usr/bin/c"],
                ),
            }],
        )
        .expect("an unrelated endpoint must not inherit a baseline conflict");
    }

    /// An additive operation must never revoke access. Appending a named binary
    /// to a rule that authorizes any binary would restrict it to that one path.
    #[test]
    fn naming_binaries_does_not_narrow_an_any_binary_rule() {
        let existing =
            rule_with_authorizations("existing", vec![endpoint("api.example.com", 443)], &[]);
        let incoming = rule_with_authorizations(
            "existing",
            vec![endpoint("api.example.com", 443)],
            &["/usr/bin/a"],
        );

        let result = merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming.clone(),
            }],
        )
        .expect("naming a binary already covered by any-binary is additive");

        assert!(
            result.policy.network_policies["existing"]
                .binaries
                .is_empty(),
            "the any-binary scope must survive; got {:?}",
            result.policy.network_policies["existing"].binaries
        );
        assert!(result.warnings.iter().any(|warning| matches!(
            warning,
            PolicyMergeWarning::ExistingAnyBinaryScopeRetained { .. }
        )));
        assert!(
            policy_covers_rule(&result.policy, &incoming),
            "an any-binary rule covers the named binary, so coverage must converge"
        );
    }

    /// A narrow update under its own rule name must survive an undeclared-port
    /// conflict the fold would create. The undeclared port belongs to the
    /// endpoint the fold merges into; a separate rule carries only the ports it
    /// declared, so nothing reaches a port the operation did not name.
    #[test]
    fn undeclared_port_conflict_keeps_a_differently_named_rule_separate() {
        let broad = rule_with_authorizations(
            "broad",
            vec![NetworkEndpoint {
                protocol: "rest".to_string(),
                rules: vec![rest_rule("GET", "/x")],
                ..endpoint_with_ports("api.example.com", &[443, 8443])
            }],
            &["/usr/bin/a", "/usr/bin/b"],
        );

        let result = merge_policy(
            policy_with_rule("broad", broad),
            &[PolicyMergeOp::AddRule {
                rule_name: "narrow".to_string(),
                rule: rule_with_authorizations(
                    "narrow",
                    vec![NetworkEndpoint {
                        protocol: "rest".to_string(),
                        rules: vec![rest_rule("POST", "/y")],
                        ..endpoint_with_ports("api.example.com", &[443])
                    }],
                    &["/usr/bin/a"],
                ),
            }],
        )
        .expect("a differently named narrow rule must land rather than be rejected");

        let narrow = result
            .policy
            .network_policies
            .get("narrow")
            .expect("the requested key must be preserved when folding would widen");
        assert_eq!(narrow.binaries.len(), 1);
        assert_eq!(canonical_ports(&narrow.endpoints[0]), vec![443]);

        // The broad rule keeps its own product: neither binary gains POST, and
        // port 8443 is untouched.
        let broad_after = &result.policy.network_policies["broad"];
        assert_eq!(broad_after.endpoints[0].rules.len(), 1);
        assert_eq!(canonical_ports(&broad_after.endpoints[0]), vec![443, 8443]);
    }

    /// The same conflict against the rule's own name is still an error: there
    /// the operation chose the target, so the undeclared port is real.
    #[test]
    fn undeclared_port_conflict_still_fails_on_a_same_key_update() {
        let existing = rule_with_authorizations(
            "existing",
            vec![NetworkEndpoint {
                protocol: "rest".to_string(),
                rules: vec![rest_rule("GET", "/x")],
                ..endpoint_with_ports("api.example.com", &[443, 8443])
            }],
            &["/usr/bin/a"],
        );

        let error = merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: rule_with_authorizations(
                    "existing",
                    vec![NetworkEndpoint {
                        protocol: "rest".to_string(),
                        rules: vec![rest_rule("POST", "/y")],
                        ..endpoint_with_ports("api.example.com", &[443])
                    }],
                    &["/usr/bin/a"],
                ),
            }],
        )
        .expect_err("the operation named this rule, so the undeclared port stands");

        assert!(matches!(
            error,
            PolicyMergeError::UndeclaredPortWouldChange { ports, .. } if ports == vec![8443]
        ));
    }

    /// Endpoints agreeing on protocol are fine, so splitting one REST surface
    /// across paths stays supported.
    #[test]
    fn same_protocol_on_one_host_and_port_across_paths_is_accepted() {
        let existing = rule_with_authorizations(
            "existing",
            vec![NetworkEndpoint {
                path: "/v1".to_string(),
                protocol: "rest".to_string(),
                rules: vec![rest_rule("GET", "/x")],
                ..endpoint("api.example.com", 443)
            }],
            &["/usr/bin/only"],
        );
        let incoming = rule_with_authorizations(
            "existing",
            vec![NetworkEndpoint {
                path: "/v2".to_string(),
                protocol: "rest".to_string(),
                rules: vec![rest_rule("GET", "/y")],
                ..endpoint("api.example.com", 443)
            }],
            &["/usr/bin/only"],
        );

        merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming,
            }],
        )
        .expect("two REST endpoints resolve to the same inspection contract");
    }

    /// An uninspected L4 endpoint supplies no L7 configuration, so it never
    /// competes with an inspected endpoint on the same host and port.
    #[test]
    fn an_l4_endpoint_does_not_conflict_with_an_inspected_one() {
        let existing = rule_with_authorizations(
            "existing",
            vec![NetworkEndpoint {
                protocol: "rest".to_string(),
                rules: vec![rest_rule("GET", "/x")],
                ..endpoint("api.example.com", 443)
            }],
            &["/usr/bin/only"],
        );
        let incoming = rule_with_authorizations(
            "existing",
            vec![NetworkEndpoint {
                path: "/raw".to_string(),
                ..endpoint("api.example.com", 443)
            }],
            &["/usr/bin/only"],
        );

        merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming,
            }],
        )
        .expect("an endpoint with no protocol carries no inspection contract");
    }

    /// The supervisor picks among matching configs by most-specific path, so a
    /// broad REST endpoint and a narrow GraphQL endpoint on one host and port
    /// are unambiguous. Rejecting them would refuse an update whose equivalent
    /// full policy the runtime supports.
    #[test]
    fn path_disambiguated_protocols_on_one_host_and_port_are_accepted() {
        let existing = rule_with_authorizations(
            "existing",
            vec![NetworkEndpoint {
                path: "/**".to_string(),
                protocol: "rest".to_string(),
                rules: vec![rest_rule("GET", "/repos/**")],
                ..endpoint("api.github.com", 443)
            }],
            &["/usr/bin/only"],
        );
        let incoming = rule_with_authorizations(
            "existing",
            vec![NetworkEndpoint {
                path: "/graphql".to_string(),
                protocol: "graphql".to_string(),
                ..endpoint("api.github.com", 443)
            }],
            &["/usr/bin/only"],
        );

        merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming,
            }],
        )
        .expect("path selectors disambiguate these protocols at request time");
    }

    /// Authorization is evaluated across every matching endpoint, but the parser
    /// is chosen by most-specific path. A broad REST rule can therefore satisfy
    /// authorization for a JSON-RPC tool call that the MCP endpoint selected to
    /// parse it never allowed, and the relay forwards it. MCP cannot share a
    /// host and port with a differently inspected endpoint.
    #[test]
    fn mcp_alongside_a_broader_rest_endpoint_is_rejected() {
        let existing = rule_with_authorizations(
            "existing",
            vec![NetworkEndpoint {
                path: "/**".to_string(),
                protocol: "rest".to_string(),
                enforcement: "enforce".to_string(),
                rules: vec![rest_rule("POST", "/**")],
                ..endpoint("svc.example.com", 443)
            }],
            &["/usr/bin/agent"],
        );
        let incoming = rule_with_authorizations(
            "existing",
            vec![NetworkEndpoint {
                path: "/mcp".to_string(),
                ..mcp_endpoint(
                    "svc.example.com",
                    &[443],
                    None,
                    None,
                    0,
                    vec![mcp_tool_rule("safe")],
                )
            }],
            &["/usr/bin/agent"],
        );

        let error = merge_policy(
            policy_with_rule("existing", existing),
            &[PolicyMergeOp::AddRule {
                rule_name: "existing".to_string(),
                rule: incoming,
            }],
        )
        .expect_err("a broader REST endpoint would authorize tool calls MCP denies");

        assert!(matches!(
            error,
            PolicyMergeError::ConflictingInspectionContracts { .. }
        ));
    }

    /// The same bypass is reachable when the two endpoints live in separate
    /// rules, so the scan has to span the whole merged policy.
    #[test]
    fn mcp_alongside_a_broader_rest_endpoint_in_another_rule_is_rejected() {
        let policy = policy_with_rule(
            "rest_rule",
            rule_with_authorizations(
                "rest_rule",
                vec![NetworkEndpoint {
                    path: "/**".to_string(),
                    protocol: "rest".to_string(),
                    rules: vec![rest_rule("POST", "/**")],
                    ..endpoint("svc.example.com", 443)
                }],
                &["/usr/bin/agent"],
            ),
        );

        let error = merge_policy(
            policy,
            &[PolicyMergeOp::AddRule {
                rule_name: "mcp_rule".to_string(),
                rule: rule_with_authorizations(
                    "mcp_rule",
                    vec![NetworkEndpoint {
                        path: "/mcp".to_string(),
                        ..mcp_endpoint(
                            "svc.example.com",
                            &[443],
                            None,
                            None,
                            0,
                            vec![mcp_tool_rule("safe")],
                        )
                    }],
                    &["/usr/bin/agent"],
                ),
            }],
        )
        .expect_err("a separate rule does not make the mixed inspection safe");

        assert!(matches!(
            error,
            PolicyMergeError::ConflictingInspectionContracts { .. }
        ));
    }
}
