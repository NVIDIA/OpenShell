// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Maximum-policy containment checks.
//!
//! This module answers a different question than the existing prover findings:
//! given a security-approved maximum policy and a candidate policy, does the
//! candidate allow any modeled action outside the maximum envelope?

use std::{collections::BTreeSet, str::FromStr};

use crate::credentials::CredentialSet;
use crate::policy::{Endpoint, L7Rule, NetworkPolicyRule, PolicyModel};
use z3::ast::{Bool, Int, Regexp, String as Z3String};
use z3::{Context, SatResult, Solver};

const READ_ONLY_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS"];
const READ_WRITE_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"];
const ALL_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"];
const WEBSOCKET_METHODS: &[&str] = &["GET", "WEBSOCKET_TEXT"];
const ACTION_METHODS: &[&str] = &[
    "GET",
    "HEAD",
    "OPTIONS",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "WEBSOCKET_TEXT",
];
const LAYER_L4: &str = "l4";
const LAYER_REST: &str = "rest";
const LAYER_WEBSOCKET: &str = "websocket";

/// Result of checking whether a candidate policy is inside a maximum policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaximumPolicyCheck {
    /// Every modeled candidate action is contained by the maximum policy.
    WithinMax,
    /// The candidate allows at least one modeled action outside the maximum.
    ExceedsMax {
        /// Concrete action allowed by the candidate but not by the maximum.
        counterexample: PolicyCounterexample,
    },
    /// The policy uses a surface the first containment slice does not model.
    Unsupported {
        /// Human-readable reason. The check must fail closed at callers.
        reason: String,
    },
}

/// A representative action that witnesses maximum-policy violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyCounterexample {
    pub binary: String,
    pub host: String,
    pub port: u16,
    /// Modeled action layer (`l4`, `rest`, or `websocket`) retained under the
    /// policy protocol field name for this spike.
    pub protocol: String,
    pub method: String,
    pub path: String,
    pub reason: String,
}

/// Budget for a candidate policy's modeled scope increase over the current policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarrownessBudget {
    /// Maximum number of modeled candidate grants that add new reach.
    pub max_delta_grants: usize,
    /// Maximum total score across all modeled delta grants.
    pub max_total_score: u32,
    /// Whether candidate delta grants may use modeled recursive globs (`**`).
    pub allow_recursive_globs: bool,
}

impl NarrownessBudget {
    /// Conservative spike budget: one small exact grant.
    pub const fn one_exact_grant() -> Self {
        Self {
            max_delta_grants: 1,
            max_total_score: 1,
            allow_recursive_globs: false,
        }
    }
}

/// Result of checking whether a candidate policy is a narrow update over current.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NarrownessCheck {
    /// The candidate adds no modeled reach over the current policy.
    NoIncrease,
    /// The candidate adds modeled reach, but it fits the supplied budget.
    WithinBudget {
        /// Summary of the modeled scope increase.
        summary: NarrownessSummary,
    },
    /// The candidate adds modeled reach outside the supplied budget.
    ExceedsBudget {
        /// Summary of the modeled scope increase.
        summary: NarrownessSummary,
    },
    /// The policy uses a surface the first narrowness slice does not model.
    Unsupported {
        /// Human-readable reason. The check must fail closed at callers.
        reason: String,
    },
}

/// Result of checking for credentialed authority over uninspected L4 egress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialedL4Check {
    /// No modeled L4 action reaches a credential target.
    NoUninspectedCredentialedL4,
    /// The policy allows at least one uninspected L4 action to a credential target.
    HasUninspectedCredentialedL4 {
        /// Representative action allowed by the policy.
        counterexample: PolicyCounterexample,
    },
    /// The policy uses a surface the first credentialed-L4 slice does not model.
    Unsupported {
        /// Human-readable reason. The check must fail closed at callers.
        reason: String,
    },
}

/// Summary of the modeled scope increase from current policy to candidate policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarrownessSummary {
    pub total_score: u32,
    pub delta_grants: Vec<ScopeDelta>,
}

/// One modeled candidate grant that adds reach over the current policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeDelta {
    pub rule_name: String,
    pub binary: String,
    pub host: String,
    pub port: u16,
    /// Modeled action layer (`l4`, `rest`, or `websocket`) retained under the
    /// policy protocol field name for this spike.
    pub protocol: String,
    pub method: String,
    pub path: String,
    pub score: u32,
    pub reasons: Vec<ScopeIncreaseReason>,
    pub counterexample: PolicyCounterexample,
}

/// Coarse reasons used by the spike budget scorer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeIncreaseReason {
    NewGrant,
    PathWildcard,
    HostWildcard,
    BinaryWildcard,
    RecursivePathGlob,
    RecursiveHostGlob,
    RecursiveBinaryGlob,
    L7ToL4Broadening,
}

impl ScopeIncreaseReason {
    fn score(self) -> u32 {
        match self {
            Self::NewGrant => 1,
            Self::PathWildcard => 2,
            Self::HostWildcard | Self::BinaryWildcard => 3,
            Self::RecursivePathGlob | Self::RecursiveHostGlob | Self::RecursiveBinaryGlob => 6,
            Self::L7ToL4Broadening => 8,
        }
    }

    fn is_recursive(self) -> bool {
        matches!(
            self,
            Self::RecursivePathGlob | Self::RecursiveHostGlob | Self::RecursiveBinaryGlob
        )
    }
}

struct SymbolicAction {
    binary: Z3String,
    host: Z3String,
    port: Int,
    layer: Z3String,
    method: Z3String,
    path: Z3String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ModeledGrant {
    rule_name: String,
    binary: String,
    host: String,
    port: u16,
    layer: String,
    method_label: String,
    methods: Vec<String>,
    path: String,
}

/// Check whether `candidate` is semantically contained by `maximum` for the
/// currently modeled allow surface.
pub fn check_within_maximum(maximum: &PolicyModel, candidate: &PolicyModel) -> MaximumPolicyCheck {
    if let Some(reason) = unsupported_reason("maximum", maximum) {
        return MaximumPolicyCheck::Unsupported { reason };
    }
    if let Some(reason) = unsupported_reason("candidate", candidate) {
        return MaximumPolicyCheck::Unsupported { reason };
    }

    match find_z3_violation(maximum, candidate) {
        Z3EnvelopeResult::WithinMax => MaximumPolicyCheck::WithinMax,
        Z3EnvelopeResult::ExceedsMax { counterexample } => {
            MaximumPolicyCheck::ExceedsMax { counterexample }
        }
        Z3EnvelopeResult::Unsupported { reason } => MaximumPolicyCheck::Unsupported { reason },
    }
}

/// Check whether `candidate` is a narrow modeled update over `current`.
///
/// The spike budget is intentionally coarse: Z3 proves whether each candidate
/// grant adds any action outside the current policy, then Rust scores the shape
/// of those delta grants so broad globs consume more budget than exact grants.
pub fn check_narrowness(
    current: &PolicyModel,
    candidate: &PolicyModel,
    budget: &NarrownessBudget,
) -> NarrownessCheck {
    if let Some(reason) = unsupported_reason("current", current) {
        return NarrownessCheck::Unsupported { reason };
    }
    if let Some(reason) = unsupported_reason("candidate", candidate) {
        return NarrownessCheck::Unsupported { reason };
    }

    let mut delta_grants = Vec::new();
    for grant in modeled_grants(candidate) {
        match find_z3_grant_delta(current, &grant) {
            Z3GrantDelta::NoIncrease => {}
            Z3GrantDelta::Increases { counterexample } => {
                let (score, reasons) = score_grant(current, &grant);
                delta_grants.push(ScopeDelta {
                    rule_name: grant.rule_name,
                    binary: grant.binary,
                    host: grant.host,
                    port: grant.port,
                    protocol: grant.layer,
                    method: grant.method_label,
                    path: grant.path,
                    score,
                    reasons,
                    counterexample,
                });
            }
            Z3GrantDelta::Unsupported { reason } => {
                return NarrownessCheck::Unsupported { reason };
            }
        }
    }

    if delta_grants.is_empty() {
        return NarrownessCheck::NoIncrease;
    }

    let total_score = delta_grants.iter().map(|delta| delta.score).sum();
    let exceeds_budget = delta_grants.len() > budget.max_delta_grants
        || total_score > budget.max_total_score
        || (!budget.allow_recursive_globs
            && delta_grants
                .iter()
                .flat_map(|delta| delta.reasons.iter())
                .any(|reason| reason.is_recursive()));
    let summary = NarrownessSummary {
        total_score,
        delta_grants,
    };

    if exceeds_budget {
        NarrownessCheck::ExceedsBudget { summary }
    } else {
        NarrownessCheck::WithinBudget { summary }
    }
}

/// Check whether a policy grants uninspected L4 reach to any host with an
/// injected credential in scope.
pub fn check_uninspected_credentialed_l4(
    policy: &PolicyModel,
    credentials: &CredentialSet,
) -> CredentialedL4Check {
    if let Some(reason) = unsupported_reason("policy", policy) {
        return CredentialedL4Check::Unsupported { reason };
    }

    let solver = Solver::new();
    let action = symbolic_action("credentialed_l4_action");
    assert_action_domain(&solver, &action);
    solver.assert(Bool::and(&[
        policy_allows(policy, &action),
        action.layer.eq(LAYER_L4),
        credential_target_matches(credentials, &action),
    ]));

    match solver.check() {
        SatResult::Unsat => CredentialedL4Check::NoUninspectedCredentialedL4,
        SatResult::Unknown => CredentialedL4Check::Unsupported {
            reason: "Z3 returned unknown while checking uninspected credentialed L4 reach"
                .to_owned(),
        },
        SatResult::Sat => {
            let Some(model) = solver.get_model() else {
                return CredentialedL4Check::Unsupported {
                    reason: "Z3 returned sat without a model for uninspected credentialed L4 reach"
                        .to_owned(),
                };
            };
            let Some(counterexample) = counterexample_from_model(
                &model,
                &action,
                "policy allows uninspected L4 reach to a credential target",
            ) else {
                return CredentialedL4Check::Unsupported {
                    reason: "Z3 returned sat but the model could not be decoded into an uninspected credentialed L4 counterexample".to_owned(),
                };
            };
            CredentialedL4Check::HasUninspectedCredentialedL4 { counterexample }
        }
    }
}

enum Z3EnvelopeResult {
    WithinMax,
    ExceedsMax {
        counterexample: PolicyCounterexample,
    },
    Unsupported {
        reason: String,
    },
}

enum Z3GrantDelta {
    NoIncrease,
    Increases {
        counterexample: PolicyCounterexample,
    },
    Unsupported {
        reason: String,
    },
}

fn find_z3_violation(maximum: &PolicyModel, candidate: &PolicyModel) -> Z3EnvelopeResult {
    let solver = Solver::new();
    let action = symbolic_action("action");
    assert_action_domain(&solver, &action);

    let candidate_allows = policy_allows(candidate, &action);
    let maximum_allows = policy_allows(maximum, &action);
    let violation = Bool::and(&[candidate_allows, !maximum_allows]);
    solver.assert(&violation);

    match solver.check() {
        SatResult::Unsat => Z3EnvelopeResult::WithinMax,
        SatResult::Unknown => Z3EnvelopeResult::Unsupported {
            reason: "Z3 returned unknown while checking maximum-policy containment".to_owned(),
        },
        SatResult::Sat => {
            let Some(model) = solver.get_model() else {
                return Z3EnvelopeResult::Unsupported {
                    reason: "Z3 returned sat without a model for maximum-policy containment"
                        .to_owned(),
                };
            };
            let Some(counterexample) = counterexample_from_model(
                &model,
                &action,
                "candidate allows an action outside the maximum policy",
            ) else {
                return Z3EnvelopeResult::Unsupported {
                    reason: "Z3 returned sat but the model could not be decoded into a maximum-policy counterexample".to_owned(),
                };
            };
            Z3EnvelopeResult::ExceedsMax { counterexample }
        }
    }
}

fn find_z3_grant_delta(current: &PolicyModel, grant: &ModeledGrant) -> Z3GrantDelta {
    let solver = Solver::new();
    let action = symbolic_action("narrowness_action");
    assert_action_domain(&solver, &action);

    let current_allows = policy_allows(current, &action);
    let grant_allows = grant_allows(grant, &action);
    solver.assert(Bool::and(&[grant_allows, !current_allows]));

    match solver.check() {
        SatResult::Unsat => Z3GrantDelta::NoIncrease,
        SatResult::Unknown => Z3GrantDelta::Unsupported {
            reason: "Z3 returned unknown while checking policy narrowness".to_owned(),
        },
        SatResult::Sat => {
            let Some(model) = solver.get_model() else {
                return Z3GrantDelta::Unsupported {
                    reason: "Z3 returned sat without a model for policy narrowness".to_owned(),
                };
            };
            let Some(counterexample) = counterexample_from_model(
                &model,
                &action,
                "candidate grant allows an action outside the current policy",
            ) else {
                return Z3GrantDelta::Unsupported {
                    reason: "Z3 returned sat but the model could not be decoded into a policy narrowness counterexample".to_owned(),
                };
            };
            Z3GrantDelta::Increases { counterexample }
        }
    }
}

fn symbolic_action(name: &str) -> SymbolicAction {
    let _ctx = Context::thread_local();
    SymbolicAction {
        binary: Z3String::new_const(format!("{name}_binary")),
        host: Z3String::new_const(format!("{name}_host")),
        port: Int::new_const(format!("{name}_port")),
        layer: Z3String::new_const(format!("{name}_layer")),
        method: Z3String::new_const(format!("{name}_method")),
        path: Z3String::new_const(format!("{name}_path")),
    }
}

fn assert_action_domain(solver: &Solver, action: &SymbolicAction) {
    solver.assert(action.binary.regex_matches(&glob_regex("/**", "/")));
    solver.assert(action.host.regex_matches(&Regexp::full()));
    solver.assert(Int::from_u64(1).le(&action.port));
    solver.assert(action.port.le(65535));
    solver.assert(str_eq_any(
        &action.layer,
        &[LAYER_L4, LAYER_REST, LAYER_WEBSOCKET],
    ));
    solver.assert(str_eq_any(&action.method, ACTION_METHODS));
    solver.assert(
        Z3String::from_str("/")
            .expect("literal")
            .prefix(&action.path),
    );
}

fn policy_allows(policy: &PolicyModel, action: &SymbolicAction) -> Bool {
    bool_or(
        policy
            .network_policies
            .values()
            .map(|rule| rule_allows(rule, action)),
    )
}

fn rule_allows(rule: &NetworkPolicyRule, action: &SymbolicAction) -> Bool {
    Bool::and(&[
        bool_or(
            rule.binaries
                .iter()
                .map(|binary| action.binary.regex_matches(&glob_regex(&binary.path, "/"))),
        ),
        bool_or(
            rule.endpoints
                .iter()
                .map(|endpoint| endpoint_allows(endpoint, action)),
        ),
    ])
}

fn endpoint_allows(endpoint: &Endpoint, action: &SymbolicAction) -> Bool {
    let mut constraints = vec![
        bool_or(
            endpoint
                .effective_ports()
                .into_iter()
                .map(|port| action.port.eq(Int::from_u64(u64::from(port)))),
        ),
        action
            .host
            .regex_matches(&glob_regex(&endpoint.host.to_ascii_lowercase(), ".")),
    ];

    if let Some(layer) = endpoint_layer(endpoint) {
        constraints.push(action.layer.eq(layer));
        constraints.push(bool_or(effective_l7_allows(endpoint).into_iter().map(
            |(method, path)| {
                Bool::and(&[
                    action.method.eq(method.as_str()),
                    action.path.regex_matches(&glob_regex(&path, "/")),
                ])
            },
        )));
    }

    Bool::and(&constraints)
}

fn grant_allows(grant: &ModeledGrant, action: &SymbolicAction) -> Bool {
    let mut constraints = vec![
        action.binary.regex_matches(&glob_regex(&grant.binary, "/")),
        action
            .host
            .regex_matches(&glob_regex(&grant.host.to_ascii_lowercase(), ".")),
        action.port.eq(Int::from_u64(u64::from(grant.port))),
    ];

    if grant.layer == LAYER_L4 {
        constraints.push(str_eq_any(
            &action.layer,
            &[LAYER_L4, LAYER_REST, LAYER_WEBSOCKET],
        ));
    } else {
        constraints.push(action.layer.eq(grant.layer.as_str()));
        constraints.push(str_eq_any_owned(&action.method, &grant.methods));
        constraints.push(action.path.regex_matches(&glob_regex(&grant.path, "/")));
    }

    Bool::and(&constraints)
}

fn credential_target_matches(credentials: &CredentialSet, action: &SymbolicAction) -> Bool {
    bool_or(
        credentials
            .credentials
            .iter()
            .flat_map(|credential| credential.target_hosts.iter())
            .filter_map(|target| {
                let normalized = target.trim().trim_end_matches('.');
                if normalized.is_empty() {
                    return None;
                }
                Some(
                    action
                        .host
                        .regex_matches(&glob_regex(&normalized.to_ascii_lowercase(), ".")),
                )
            }),
    )
}

fn counterexample_from_model(
    model: &z3::Model,
    action: &SymbolicAction,
    reason: &str,
) -> Option<PolicyCounterexample> {
    let port = model.eval(&action.port, true)?.as_u64()?;
    let layer = model.eval(&action.layer, true)?.as_string()?;
    let method = if layer == LAYER_L4 {
        String::new()
    } else {
        model.eval(&action.method, true)?.as_string()?
    };
    let path = if layer == LAYER_L4 {
        String::new()
    } else {
        model.eval(&action.path, true)?.as_string()?
    };
    Some(PolicyCounterexample {
        binary: model.eval(&action.binary, true)?.as_string()?,
        host: model.eval(&action.host, true)?.as_string()?,
        port: u16::try_from(port).ok()?,
        protocol: layer,
        method,
        path,
        reason: reason.to_owned(),
    })
}

fn bool_or(values: impl IntoIterator<Item = Bool>) -> Bool {
    let values: Vec<Bool> = values.into_iter().collect();
    if values.is_empty() {
        Bool::from_bool(false)
    } else {
        Bool::or(&values)
    }
}

fn str_eq_any(value: &Z3String, options: &[&str]) -> Bool {
    bool_or(options.iter().map(|option| value.eq(*option)))
}

fn str_eq_any_owned(value: &Z3String, options: &[String]) -> Bool {
    bool_or(options.iter().map(|option| value.eq(option.as_str())))
}

fn glob_regex(pattern: &str, separator: &str) -> Regexp {
    if pattern == "**" {
        return Regexp::full();
    }

    let mut parts = Vec::new();
    let mut chars = pattern.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '*' && chars.peek() == Some(&'*') {
            chars.next();
            parts.push(Regexp::full());
        } else if ch == '*' {
            parts.push(non_separator_regex(separator).star());
        } else {
            parts.push(Regexp::literal(&ch.to_string()));
        }
    }

    if parts.is_empty() {
        Regexp::literal("")
    } else {
        let refs: Vec<&Regexp> = parts.iter().collect();
        Regexp::concat(&refs)
    }
}

fn non_separator_regex(separator: &str) -> Regexp {
    match separator {
        "/" => Regexp::union(&[&Regexp::range(&' ', &'.'), &Regexp::range(&'0', &'~')]),
        "." => Regexp::union(&[&Regexp::range(&' ', &'-'), &Regexp::range(&'/', &'~')]),
        _ => Regexp::full(),
    }
}

fn unsupported_reason(prefix: &str, policy: &PolicyModel) -> Option<String> {
    for (rule_name, rule) in &policy.network_policies {
        for endpoint in &rule.endpoints {
            if !endpoint.path.is_empty() {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses endpoint path scoping, which policy envelope checks do not model yet"
                ));
            }
            if unsupported_glob_pattern(&endpoint.host) {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses a host glob pattern outside the modeled subset"
                ));
            }
            if !endpoint.allowed_ips.is_empty() {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses allowed_ips/CIDR scoping, which policy envelope checks do not model yet"
                ));
            }
            if !endpoint.deny_rules.is_empty() {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses deny_rules, which policy envelope checks do not model yet"
                ));
            }
            if endpoint.effective_ports().is_empty() {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' endpoint {} has no modeled port",
                    endpoint_label(endpoint)
                ));
            }
            if !endpoint.tls.is_empty() {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses tls '{}', which policy envelope checks do not model yet",
                    endpoint.tls
                ));
            }
            if endpoint.allow_encoded_slash {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses endpoint behavior flags that policy envelope checks do not model yet"
                ));
            }
            if endpoint.request_body_credential_rewrite || endpoint.websocket_credential_rewrite {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses credential rewrite flags that policy envelope checks do not model yet"
                ));
            }
            if !endpoint.persisted_queries.is_empty()
                || !endpoint.graphql_persisted_queries.is_empty()
                || endpoint.graphql_max_body_bytes != 0
            {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses GraphQL persisted-query controls, which policy envelope checks do not model yet"
                ));
            }
            if !endpoint.mcp_server.is_empty()
                || !endpoint.mcp_tool.is_empty()
                || !endpoint.mcp_resource.is_empty()
            {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses MCP controls, which policy envelope checks do not model yet"
                ));
            }
            if normalized_protocol(&endpoint.protocol) == "graphql" {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses GraphQL protocol controls, which policy envelope checks do not model yet"
                ));
            }
            let protocol = normalized_protocol(&endpoint.protocol);
            if !protocol.is_empty()
                && !protocol.eq_ignore_ascii_case("rest")
                && !protocol.eq_ignore_ascii_case("websocket")
            {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses protocol '{}', which policy envelope checks do not model yet",
                    endpoint.protocol
                ));
            }
            if !protocol.is_empty() && endpoint.enforcement != "enforce" {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses L7 protocol '{}' without enforcement mode 'enforce'",
                    endpoint.protocol
                ));
            }
            for rule in &endpoint.rules {
                if l7_rule_is_unsupported(rule) {
                    return Some(format!(
                        "{prefix} policy rule '{rule_name}' uses L7 query, SQL, or GraphQL allow controls, which policy envelope checks do not model yet"
                    ));
                }
                if !rule.method.is_empty() && !modeled_l7_method(protocol, &rule.method) {
                    return Some(format!(
                        "{prefix} policy rule '{rule_name}' uses method '{}', which policy envelope checks do not model yet",
                        rule.method
                    ));
                }
                if unsupported_glob_pattern(&rule.path) {
                    return Some(format!(
                        "{prefix} policy rule '{rule_name}' uses a path glob pattern outside the modeled subset"
                    ));
                }
            }
        }
        for binary in &rule.binaries {
            if unsupported_glob_pattern(&binary.path) {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses a binary glob pattern outside the modeled subset"
                ));
            }
        }
    }
    None
}

fn modeled_grants(policy: &PolicyModel) -> Vec<ModeledGrant> {
    let mut grants = BTreeSet::new();
    for (rule_name, rule) in &policy.network_policies {
        for binary in &rule.binaries {
            for endpoint in &rule.endpoints {
                for port in endpoint.effective_ports() {
                    for (method_label, methods, path) in grant_method_groups(endpoint) {
                        grants.insert(ModeledGrant {
                            rule_name: rule_name.clone(),
                            binary: binary.path.clone(),
                            host: endpoint.host.clone(),
                            port,
                            layer: endpoint_layer(endpoint).unwrap_or(LAYER_L4).to_owned(),
                            method_label,
                            methods,
                            path,
                        });
                    }
                }
            }
        }
    }
    grants.into_iter().collect()
}

fn grant_method_groups(endpoint: &Endpoint) -> Vec<(String, Vec<String>, String)> {
    if normalized_protocol(&endpoint.protocol).is_empty() {
        return vec![(
            "*".to_owned(),
            ACTION_METHODS
                .iter()
                .map(|method| (*method).to_owned())
                .collect(),
            "**".to_owned(),
        )];
    }

    if normalized_protocol(&endpoint.protocol).eq_ignore_ascii_case("websocket") {
        return websocket_grant_method_groups(endpoint);
    }

    match endpoint.access.as_str() {
        "read-only" => vec![(
            "read-only".to_owned(),
            READ_ONLY_METHODS
                .iter()
                .map(|method| (*method).to_owned())
                .collect(),
            "**".to_owned(),
        )],
        "read-write" => vec![(
            "read-write".to_owned(),
            READ_WRITE_METHODS
                .iter()
                .map(|method| (*method).to_owned())
                .collect(),
            "**".to_owned(),
        )],
        "full" => vec![(
            "full".to_owned(),
            ALL_METHODS
                .iter()
                .map(|method| (*method).to_owned())
                .collect(),
            "**".to_owned(),
        )],
        _ if endpoint.rules.is_empty() => Vec::new(),
        _ => endpoint
            .rules
            .iter()
            .filter_map(|rule| {
                if rule.method.is_empty() {
                    return None;
                }
                let path = if rule.path.is_empty() {
                    "**".to_owned()
                } else {
                    rule.path.clone()
                };
                let method = rule.method.to_ascii_uppercase();
                if method == "*" {
                    Some((
                        "*".to_owned(),
                        ALL_METHODS
                            .iter()
                            .map(|method| (*method).to_owned())
                            .collect(),
                        path,
                    ))
                } else if method == "GET" {
                    Some((
                        "GET".to_owned(),
                        vec!["GET".to_owned(), "HEAD".to_owned()],
                        path,
                    ))
                } else {
                    Some((method.clone(), vec![method], path))
                }
            })
            .collect(),
    }
}

fn score_grant(current: &PolicyModel, grant: &ModeledGrant) -> (u32, Vec<ScopeIncreaseReason>) {
    let mut reasons = vec![ScopeIncreaseReason::NewGrant];

    if grant.layer == LAYER_L4 {
        if grant_broadens_inspected_l7_to_l4(current, grant) {
            reasons.push(ScopeIncreaseReason::L7ToL4Broadening);
        }
    } else {
        add_glob_reasons(
            &mut reasons,
            &grant.path,
            ScopeIncreaseReason::PathWildcard,
            ScopeIncreaseReason::RecursivePathGlob,
        );
    }
    add_glob_reasons(
        &mut reasons,
        &grant.host,
        ScopeIncreaseReason::HostWildcard,
        ScopeIncreaseReason::RecursiveHostGlob,
    );
    add_glob_reasons(
        &mut reasons,
        &grant.binary,
        ScopeIncreaseReason::BinaryWildcard,
        ScopeIncreaseReason::RecursiveBinaryGlob,
    );

    let score = reasons.iter().map(|reason| reason.score()).sum();
    (score, reasons)
}

fn grant_broadens_inspected_l7_to_l4(current: &PolicyModel, grant: &ModeledGrant) -> bool {
    if grant.layer != LAYER_L4 {
        return false;
    }

    let solver = Solver::new();
    let action = symbolic_action("l7_to_l4_overlap");
    assert_action_domain(&solver, &action);
    solver.assert(Bool::and(&[
        grant_allows(grant, &action),
        policy_allows(current, &action),
        !action.layer.eq(LAYER_L4),
    ]));

    matches!(solver.check(), SatResult::Sat)
}

fn add_glob_reasons(
    reasons: &mut Vec<ScopeIncreaseReason>,
    pattern: &str,
    wildcard: ScopeIncreaseReason,
    recursive: ScopeIncreaseReason,
) {
    if pattern.contains("**") {
        reasons.push(recursive);
    } else if pattern.contains('*') {
        reasons.push(wildcard);
    }
}

fn l7_rule_is_unsupported(rule: &L7Rule) -> bool {
    !rule.command.is_empty()
        || !rule.query.is_empty()
        || !rule.operation_type.is_empty()
        || !rule.operation_name.is_empty()
        || !rule.fields.is_empty()
}

fn websocket_grant_method_groups(endpoint: &Endpoint) -> Vec<(String, Vec<String>, String)> {
    match endpoint.access.as_str() {
        "read-only" => vec![(
            "read-only".to_owned(),
            vec!["GET".to_owned()],
            "**".to_owned(),
        )],
        "read-write" | "full" => vec![(
            endpoint.access.clone(),
            WEBSOCKET_METHODS
                .iter()
                .map(|method| (*method).to_owned())
                .collect(),
            "**".to_owned(),
        )],
        _ if endpoint.rules.is_empty() => Vec::new(),
        _ => endpoint
            .rules
            .iter()
            .filter_map(|rule| {
                if rule.method.is_empty() {
                    return None;
                }
                let path = if rule.path.is_empty() {
                    "**".to_owned()
                } else {
                    rule.path.clone()
                };
                let method = rule.method.to_ascii_uppercase();
                if method == "*" {
                    Some((
                        "*".to_owned(),
                        WEBSOCKET_METHODS
                            .iter()
                            .map(|method| (*method).to_owned())
                            .collect(),
                        path,
                    ))
                } else {
                    Some((method.clone(), vec![method], path))
                }
            })
            .collect(),
    }
}

fn effective_l7_allows(endpoint: &Endpoint) -> Vec<(String, String)> {
    if normalized_protocol(&endpoint.protocol).is_empty() {
        return ACTION_METHODS
            .iter()
            .map(|method| ((*method).to_owned(), "**".to_owned()))
            .collect();
    }

    if normalized_protocol(&endpoint.protocol).eq_ignore_ascii_case("websocket") {
        return websocket_grant_method_groups(endpoint)
            .into_iter()
            .flat_map(|(_, methods, path)| {
                methods
                    .into_iter()
                    .map(move |method| (method, path.clone()))
            })
            .collect();
    }

    match endpoint.access.as_str() {
        "read-only" => methods_with_path(READ_ONLY_METHODS, "**"),
        "read-write" => methods_with_path(READ_WRITE_METHODS, "**"),
        "full" => methods_with_path(ALL_METHODS, "**"),
        _ if endpoint.rules.is_empty() => Vec::new(),
        _ => {
            let mut allows = Vec::new();
            for rule in &endpoint.rules {
                if rule.method.is_empty() {
                    continue;
                }
                let path = if rule.path.is_empty() {
                    "**".to_owned()
                } else {
                    rule.path.clone()
                };
                if rule.method == "*" {
                    allows.extend(methods_with_path(ALL_METHODS, &path));
                } else if rule.method.eq_ignore_ascii_case("GET") {
                    allows.extend(methods_with_path(&["GET", "HEAD"], &path));
                } else {
                    allows.push((rule.method.to_ascii_uppercase(), path));
                }
            }
            allows
        }
    }
}

fn methods_with_path(methods: &[&str], path: &str) -> Vec<(String, String)> {
    methods
        .iter()
        .map(|method| ((*method).to_owned(), path.to_owned()))
        .collect()
}

fn modeled_l7_method(protocol: &str, method: &str) -> bool {
    if method == "*" {
        return true;
    }
    let method = method.to_ascii_uppercase();
    if protocol.eq_ignore_ascii_case("websocket") {
        return WEBSOCKET_METHODS.contains(&method.as_str());
    }
    ALL_METHODS.contains(&method.as_str())
}

fn unsupported_glob_pattern(pattern: &str) -> bool {
    pattern
        .chars()
        .any(|ch| matches!(ch, '?' | '[' | ']' | '{' | '}' | '\\'))
}

fn normalized_protocol(protocol: &str) -> &str {
    protocol.trim()
}

fn endpoint_layer(endpoint: &Endpoint) -> Option<&'static str> {
    let protocol = normalized_protocol(&endpoint.protocol);
    if protocol.is_empty() {
        None
    } else if protocol.eq_ignore_ascii_case("websocket") {
        Some(LAYER_WEBSOCKET)
    } else {
        Some(LAYER_REST)
    }
}

fn endpoint_label(endpoint: &Endpoint) -> String {
    if endpoint.host.is_empty() {
        "<hostless>".to_owned()
    } else {
        endpoint.host.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{Credential, CredentialSet};
    use crate::policy::parse_policy_str;
    use std::collections::HashMap;

    fn policy(endpoint: &str, binaries: &str) -> PolicyModel {
        parse_policy_str(&format!(
            r"
version: 1
network_policies:
  test:
    name: test
    endpoints:
{endpoint}
    binaries:
{binaries}
"
        ))
        .expect("parse policy")
    }

    fn policy_doc(network_policies: &str) -> PolicyModel {
        parse_policy_str(&format!(
            r"
version: 1
network_policies:
{network_policies}
"
        ))
        .expect("parse policy")
    }

    fn one_rest_endpoint(extra: &str) -> String {
        format!(
            r"      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
{extra}"
        )
    }

    fn gh_binary() -> &'static str {
        "      - path: /usr/bin/gh"
    }

    fn github_credentials() -> CredentialSet {
        CredentialSet {
            credentials: vec![Credential {
                name: "github".to_owned(),
                cred_type: "github-pat".to_owned(),
                scopes: vec!["repo".to_owned()],
                injected_via: "env".to_owned(),
                target_hosts: vec!["api.github.com".to_owned()],
            }],
            api_registries: HashMap::new(),
        }
    }

    #[test]
    fn exact_rest_rule_is_within_maximum() {
        let maximum = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/*",
            ),
            gh_binary(),
        );
        let candidate = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/123",
            ),
            gh_binary(),
        );

        assert_eq!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::WithinMax
        );
    }

    #[test]
    fn broader_rest_path_exceeds_maximum() {
        let maximum = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/*",
            ),
            gh_binary(),
        );
        let candidate = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/**",
            ),
            gh_binary(),
        );

        let MaximumPolicyCheck::ExceedsMax { counterexample } =
            check_within_maximum(&maximum, &candidate)
        else {
            panic!("expected candidate to exceed maximum");
        };
        assert_eq!(counterexample.method, "GET");
        assert_eq!(counterexample.host, "api.github.com");
        assert!(counterexample.path.starts_with("/repos/NVIDIA/"));
        assert!(
            !counterexample
                .path
                .starts_with("/repos/NVIDIA/OpenShell/issues/")
        );
    }

    #[test]
    fn method_escalation_exceeds_maximum() {
        let maximum = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/**",
            ),
            gh_binary(),
        );
        let candidate = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: POST
              path: /repos/NVIDIA/OpenShell/issues",
            ),
            gh_binary(),
        );

        let MaximumPolicyCheck::ExceedsMax { counterexample } =
            check_within_maximum(&maximum, &candidate)
        else {
            panic!("expected method escalation");
        };
        assert_eq!(counterexample.method, "POST");
    }

    #[test]
    fn head_is_contained_by_get_like_runtime_method_matching() {
        let maximum = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/**",
            ),
            gh_binary(),
        );
        let candidate = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: HEAD
              path: /repos/NVIDIA/OpenShell/issues",
            ),
            gh_binary(),
        );

        assert_eq!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::WithinMax
        );
    }

    #[test]
    fn custom_rest_methods_are_unsupported_until_modeled() {
        let maximum = policy(&one_rest_endpoint("        access: read-only"), gh_binary());
        let candidate = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: TRACE
              path: /repos/NVIDIA/OpenShell/issues",
            ),
            gh_binary(),
        );

        assert!(matches!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::Unsupported { .. }
        ));
    }

    #[test]
    fn host_wildcard_broadening_exceeds_maximum() {
        let maximum = policy(&one_rest_endpoint("        access: read-only"), gh_binary());
        let candidate = policy(
            r#"      - host: "*.github.com"
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only"#,
            gh_binary(),
        );

        assert!(matches!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::ExceedsMax { .. }
        ));
    }

    #[test]
    fn binary_wildcard_broadening_exceeds_maximum() {
        let maximum = policy(&one_rest_endpoint("        access: read-only"), gh_binary());
        let candidate = policy(
            &one_rest_endpoint("        access: read-only"),
            "      - path: /usr/bin/*",
        );

        assert!(matches!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::ExceedsMax { .. }
        ));
    }

    #[test]
    fn port_broadening_exceeds_maximum() {
        let maximum = policy(&one_rest_endpoint("        access: read-only"), gh_binary());
        let candidate = policy(
            r"      - host: api.github.com
        ports: [443, 8443]
        protocol: rest
        enforcement: enforce
        access: read-only",
            gh_binary(),
        );

        let MaximumPolicyCheck::ExceedsMax { counterexample } =
            check_within_maximum(&maximum, &candidate)
        else {
            panic!("expected port broadening");
        };
        assert_eq!(counterexample.port, 8443);
    }

    #[test]
    fn l4_candidate_exceeds_l7_maximum() {
        let maximum = policy(&one_rest_endpoint("        access: read-only"), gh_binary());
        let candidate = policy(
            r"      - host: api.github.com
        port: 443",
            gh_binary(),
        );

        let MaximumPolicyCheck::ExceedsMax { counterexample } =
            check_within_maximum(&maximum, &candidate)
        else {
            panic!("expected L4 candidate to exceed REST maximum");
        };
        assert_eq!(counterexample.protocol, LAYER_L4);
        assert_eq!(counterexample.host, "api.github.com");
    }

    #[test]
    fn l4_maximum_covers_rest_candidate_within_modeled_rest_domain() {
        let maximum = policy(
            r"      - host: api.github.com
        port: 443",
            gh_binary(),
        );
        let candidate = policy(
            &one_rest_endpoint("        access: read-write"),
            gh_binary(),
        );

        assert_eq!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::WithinMax
        );
    }

    #[test]
    fn exact_l4_rule_is_within_l4_maximum() {
        let maximum = policy(
            r"      - host: api.github.com
        port: 443",
            gh_binary(),
        );
        let candidate = policy(
            r"      - host: api.github.com
        port: 443",
            gh_binary(),
        );

        assert_eq!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::WithinMax
        );
    }

    #[test]
    fn rest_full_maximum_does_not_silently_cover_l4_candidate() {
        let maximum = policy(&one_rest_endpoint("        access: full"), gh_binary());
        let candidate = policy(
            r"      - host: api.github.com
        port: 443",
            gh_binary(),
        );

        let MaximumPolicyCheck::ExceedsMax { counterexample } =
            check_within_maximum(&maximum, &candidate)
        else {
            panic!("expected L4 candidate to exceed REST maximum");
        };
        assert_eq!(counterexample.protocol, LAYER_L4);
        assert_eq!(counterexample.method, "");
        assert_eq!(counterexample.path, "");
    }

    #[test]
    fn l4_host_wildcard_broadening_exceeds_maximum() {
        let maximum = policy(
            r"      - host: api.github.com
        port: 443",
            gh_binary(),
        );
        let candidate = policy(
            r#"      - host: "*.github.com"
        port: 443"#,
            gh_binary(),
        );

        assert!(matches!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::ExceedsMax { .. }
        ));
    }

    #[test]
    fn l4_port_broadening_exceeds_maximum() {
        let maximum = policy(
            r"      - host: api.github.com
        port: 443",
            gh_binary(),
        );
        let candidate = policy(
            r"      - host: api.github.com
        ports: [443, 8443]",
            gh_binary(),
        );

        let MaximumPolicyCheck::ExceedsMax { counterexample } =
            check_within_maximum(&maximum, &candidate)
        else {
            panic!("expected L4 port broadening");
        };
        assert_eq!(counterexample.protocol, LAYER_L4);
        assert_eq!(counterexample.port, 8443);
    }

    #[test]
    fn maximum_wildcards_cover_exact_candidate() {
        let maximum = policy(
            r#"      - host: "*.github.com"
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/**"#,
            "      - path: /usr/bin/*",
        );
        let candidate = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/123",
            ),
            gh_binary(),
        );

        assert_eq!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::WithinMax
        );
    }

    #[test]
    fn deny_rules_are_unsupported_until_modeled() {
        let maximum = policy(
            r"      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: full
        deny_rules:
          - method: POST
            path: /admin/**",
            gh_binary(),
        );
        let candidate = policy(&one_rest_endpoint("        access: read-only"), gh_binary());

        let MaximumPolicyCheck::Unsupported { reason } = check_within_maximum(&maximum, &candidate)
        else {
            panic!("expected unsupported deny rule");
        };
        assert!(reason.contains("deny_rules"));
    }

    #[test]
    fn query_graphql_cidr_and_mcp_surfaces_are_unsupported() {
        let maximum = policy(&one_rest_endpoint("        access: read-only"), gh_binary());

        let query_candidate = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /search/issues
              query:
                org: NVIDIA",
            ),
            gh_binary(),
        );
        assert!(matches!(
            check_within_maximum(&maximum, &query_candidate),
            MaximumPolicyCheck::Unsupported { .. }
        ));

        let graphql_candidate = policy(
            r"      - host: api.github.com
        port: 443
        protocol: graphql
        enforcement: enforce
        rules:
          - allow:
              operation_type: query
              fields: [repository]",
            gh_binary(),
        );
        assert!(matches!(
            check_within_maximum(&maximum, &graphql_candidate),
            MaximumPolicyCheck::Unsupported { .. }
        ));

        let cidr_candidate = policy(
            r#"      - port: 443
        allowed_ips: ["10.0.5.0/24"]"#,
            gh_binary(),
        );
        assert!(matches!(
            check_within_maximum(&maximum, &cidr_candidate),
            MaximumPolicyCheck::Unsupported { .. }
        ));

        let mcp_candidate = policy(
            r"      - host: github.mcp.local
        port: 443
        protocol: rest
        mcp_server: github
        mcp_tool: get_issue",
            gh_binary(),
        );
        assert!(matches!(
            check_within_maximum(&maximum, &mcp_candidate),
            MaximumPolicyCheck::Unsupported { .. }
        ));
    }

    #[test]
    fn non_enforcing_l7_modes_are_unsupported_until_modeled() {
        let enforced_maximum = policy(&one_rest_endpoint("        access: read-only"), gh_binary());

        let audit_candidate = policy(
            r"      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: audit
        access: read-only",
            gh_binary(),
        );
        assert!(matches!(
            check_within_maximum(&enforced_maximum, &audit_candidate),
            MaximumPolicyCheck::Unsupported { .. }
        ));

        let tls_skip_candidate = policy(
            r"      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        tls: skip
        access: read-only",
            gh_binary(),
        );
        assert!(matches!(
            check_within_maximum(&enforced_maximum, &tls_skip_candidate),
            MaximumPolicyCheck::Unsupported { .. }
        ));
    }

    #[test]
    fn websocket_endpoint_with_text_rules_is_modeled() {
        let maximum = policy(
            r#"      - host: wss-primary.slack.com
        port: 443
        protocol: websocket
        enforcement: enforce
        rules:
          - allow: { method: GET, path: "/**" }
          - allow: { method: WEBSOCKET_TEXT, path: "/**" }"#,
            r#"      - path: "/**""#,
        );
        let candidate = policy(
            r#"      - host: wss-primary.slack.com
        port: 443
        protocol: websocket
        enforcement: enforce
        rules:
          - allow: { method: WEBSOCKET_TEXT, path: "/rooms/alerts" }"#,
            "      - path: /usr/bin/node",
        );

        assert_eq!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::WithinMax
        );
    }

    #[test]
    fn websocket_read_only_does_not_cover_text_send() {
        let maximum = policy(
            r"      - host: wss-primary.slack.com
        port: 443
        protocol: websocket
        enforcement: enforce
        access: read-only",
            "      - path: /usr/bin/node",
        );
        let candidate = policy(
            r#"      - host: wss-primary.slack.com
        port: 443
        protocol: websocket
        enforcement: enforce
        rules:
          - allow: { method: WEBSOCKET_TEXT, path: "/rooms/alerts" }"#,
            "      - path: /usr/bin/node",
        );

        let MaximumPolicyCheck::ExceedsMax { counterexample } =
            check_within_maximum(&maximum, &candidate)
        else {
            panic!("expected text send to exceed read-only websocket maximum");
        };
        assert_eq!(counterexample.protocol, LAYER_WEBSOCKET);
        assert_eq!(counterexample.method, "WEBSOCKET_TEXT");
    }

    #[test]
    fn endpoint_behavior_flags_are_unsupported_until_modeled() {
        let maximum = policy(&one_rest_endpoint("        access: read-only"), gh_binary());
        let candidate = policy(
            r"      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
        allow_encoded_slash: true",
            gh_binary(),
        );

        assert!(matches!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::Unsupported { .. }
        ));

        let rewrite_candidate = policy(
            r"      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
        request_body_credential_rewrite: true",
            gh_binary(),
        );
        assert!(matches!(
            check_within_maximum(&maximum, &rewrite_candidate),
            MaximumPolicyCheck::Unsupported { .. }
        ));

        let websocket_rewrite_candidate = policy(
            r"      - host: wss-primary.slack.com
        port: 443
        protocol: websocket
        enforcement: enforce
        access: read-write
        websocket_credential_rewrite: true",
            "      - path: /usr/bin/node",
        );
        assert!(matches!(
            check_within_maximum(&websocket_rewrite_candidate, &websocket_rewrite_candidate),
            MaximumPolicyCheck::Unsupported { .. }
        ));
    }

    #[test]
    fn unsupported_glob_syntax_fails_closed() {
        let maximum = policy(&one_rest_endpoint("        access: read-only"), gh_binary());
        let candidate = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/?",
            ),
            gh_binary(),
        );

        assert!(matches!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::Unsupported { .. }
        ));
    }

    #[test]
    fn narrowness_reports_no_increase_for_same_policy() {
        let current = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/123",
            ),
            gh_binary(),
        );

        assert_eq!(
            check_narrowness(&current, &current, &NarrownessBudget::one_exact_grant()),
            NarrownessCheck::NoIncrease
        );
    }

    #[test]
    fn narrowness_allows_one_exact_path_delta_within_budget() {
        let current = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/123",
            ),
            gh_binary(),
        );
        let candidate = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/123
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/456",
            ),
            gh_binary(),
        );

        let NarrownessCheck::WithinBudget { summary } =
            check_narrowness(&current, &candidate, &NarrownessBudget::one_exact_grant())
        else {
            panic!("expected one exact path delta to fit budget");
        };
        assert_eq!(summary.total_score, 1);
        assert_eq!(summary.delta_grants.len(), 1);
        assert_eq!(summary.delta_grants[0].method, "GET");
        assert_eq!(
            summary.delta_grants[0].path,
            "/repos/NVIDIA/OpenShell/issues/456"
        );
        assert_eq!(
            summary.delta_grants[0].reasons,
            vec![ScopeIncreaseReason::NewGrant]
        );
    }

    #[test]
    fn narrowness_allows_one_exact_method_delta_within_budget() {
        let current = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/123",
            ),
            gh_binary(),
        );
        let candidate = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/123
          - allow:
              method: POST
              path: /repos/NVIDIA/OpenShell/issues/123",
            ),
            gh_binary(),
        );

        let NarrownessCheck::WithinBudget { summary } =
            check_narrowness(&current, &candidate, &NarrownessBudget::one_exact_grant())
        else {
            panic!("expected one exact method delta to fit budget");
        };
        assert_eq!(summary.total_score, 1);
        assert_eq!(summary.delta_grants.len(), 1);
        assert_eq!(summary.delta_grants[0].method, "POST");
        assert_eq!(
            summary.delta_grants[0].counterexample.reason,
            "candidate grant allows an action outside the current policy"
        );
    }

    #[test]
    fn narrowness_rejects_multiple_exact_grants_over_budget() {
        let current = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/123",
            ),
            gh_binary(),
        );
        let candidate = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/123
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/456
          - allow:
              method: POST
              path: /repos/NVIDIA/OpenShell/issues/123",
            ),
            gh_binary(),
        );

        let NarrownessCheck::ExceedsBudget { summary } =
            check_narrowness(&current, &candidate, &NarrownessBudget::one_exact_grant())
        else {
            panic!("expected two exact deltas to exceed one-grant budget");
        };
        assert_eq!(summary.total_score, 2);
        assert_eq!(summary.delta_grants.len(), 2);
    }

    #[test]
    fn narrowness_rejects_recursive_path_glob_as_too_broad() {
        let current = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/123",
            ),
            gh_binary(),
        );
        let candidate = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/**",
            ),
            gh_binary(),
        );

        let NarrownessCheck::ExceedsBudget { summary } =
            check_narrowness(&current, &candidate, &NarrownessBudget::one_exact_grant())
        else {
            panic!("expected recursive path glob to exceed budget");
        };
        assert_eq!(summary.delta_grants.len(), 1);
        assert_eq!(summary.total_score, 7);
        assert_eq!(
            summary.delta_grants[0].reasons,
            vec![
                ScopeIncreaseReason::NewGrant,
                ScopeIncreaseReason::RecursivePathGlob
            ]
        );
    }

    #[test]
    fn narrowness_recursive_glob_can_fit_when_budget_explicitly_allows_it() {
        let current = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/OpenShell/issues/123",
            ),
            gh_binary(),
        );
        let candidate = policy(
            &one_rest_endpoint(
                r"        rules:
          - allow:
              method: GET
              path: /repos/NVIDIA/**",
            ),
            gh_binary(),
        );
        let budget = NarrownessBudget {
            max_delta_grants: 1,
            max_total_score: 7,
            allow_recursive_globs: true,
        };

        assert!(matches!(
            check_narrowness(&current, &candidate, &budget),
            NarrownessCheck::WithinBudget { .. }
        ));
    }

    #[test]
    fn narrowness_exact_l4_candidate_fits_one_grant_budget_without_l7_overlap() {
        let current = policy(&one_rest_endpoint("        access: full"), gh_binary());
        let candidate = policy(
            r"      - host: files.pythonhosted.org
        port: 443",
            gh_binary(),
        );

        let NarrownessCheck::WithinBudget { summary } =
            check_narrowness(&current, &candidate, &NarrownessBudget::one_exact_grant())
        else {
            panic!("expected exact L4 delta to fit one-grant budget");
        };
        assert_eq!(summary.total_score, 1);
        assert_eq!(summary.delta_grants.len(), 1);
        assert_eq!(summary.delta_grants[0].protocol, LAYER_L4);
        assert_eq!(
            summary.delta_grants[0].reasons,
            vec![ScopeIncreaseReason::NewGrant]
        );
        assert_eq!(summary.delta_grants[0].counterexample.protocol, LAYER_L4);
    }

    #[test]
    fn narrowness_l7_to_l4_broadening_is_high_cost() {
        let current = policy(&one_rest_endpoint("        access: full"), gh_binary());
        let candidate = policy(
            r"      - host: api.github.com
        port: 443",
            gh_binary(),
        );

        let NarrownessCheck::ExceedsBudget { summary } =
            check_narrowness(&current, &candidate, &NarrownessBudget::one_exact_grant())
        else {
            panic!("expected L7-to-L4 broadening to exceed one-grant budget");
        };
        assert_eq!(summary.total_score, 9);
        assert_eq!(summary.delta_grants.len(), 1);
        assert_eq!(summary.delta_grants[0].protocol, LAYER_L4);
        assert_eq!(
            summary.delta_grants[0].reasons,
            vec![
                ScopeIncreaseReason::NewGrant,
                ScopeIncreaseReason::L7ToL4Broadening
            ]
        );

        let broader_budget = NarrownessBudget {
            max_delta_grants: 1,
            max_total_score: 9,
            allow_recursive_globs: false,
        };
        assert!(matches!(
            check_narrowness(&current, &candidate, &broader_budget),
            NarrownessCheck::WithinBudget { .. }
        ));
    }

    #[test]
    fn narrowness_l4_current_covers_rest_candidate_within_modeled_rest_domain() {
        let current = policy(
            r"      - host: api.github.com
        port: 443",
            gh_binary(),
        );
        let candidate = policy(&one_rest_endpoint("        access: full"), gh_binary());

        assert_eq!(
            check_narrowness(&current, &candidate, &NarrownessBudget::one_exact_grant()),
            NarrownessCheck::NoIncrease
        );
    }

    #[test]
    fn narrowness_websocket_delta_preserves_modeled_layer() {
        let current = policy(
            r#"      - host: wss-primary.slack.com
        port: 443
        protocol: websocket
        enforcement: enforce
        rules:
          - allow: { method: WEBSOCKET_TEXT, path: "/rooms/alerts" }"#,
            "      - path: /usr/bin/node",
        );
        let candidate = policy(
            r#"      - host: wss-primary.slack.com
        port: 443
        protocol: websocket
        enforcement: enforce
        rules:
          - allow: { method: WEBSOCKET_TEXT, path: "/rooms/alerts" }
          - allow: { method: WEBSOCKET_TEXT, path: "/rooms/incidents" }"#,
            "      - path: /usr/bin/node",
        );

        let NarrownessCheck::WithinBudget { summary } =
            check_narrowness(&current, &candidate, &NarrownessBudget::one_exact_grant())
        else {
            panic!("expected one exact websocket delta to fit budget");
        };
        assert_eq!(summary.total_score, 1);
        assert_eq!(summary.delta_grants.len(), 1);
        assert_eq!(summary.delta_grants[0].protocol, LAYER_WEBSOCKET);
        assert_eq!(
            summary.delta_grants[0].counterexample.protocol,
            LAYER_WEBSOCKET
        );
        assert_eq!(summary.delta_grants[0].method, "WEBSOCKET_TEXT");
    }

    #[test]
    fn mixed_l4_and_rest_fixture_is_modelable() {
        let policy = parse_policy_str(include_str!("../testdata/policy.yaml"))
            .expect("parse prover fixture");

        assert_eq!(
            check_within_maximum(&policy, &policy),
            MaximumPolicyCheck::WithinMax
        );
    }

    #[test]
    fn credentialed_rest_is_not_uninspected_l4() {
        let policy = policy(
            &one_rest_endpoint("        access: read-write"),
            gh_binary(),
        );

        assert_eq!(
            check_uninspected_credentialed_l4(&policy, &github_credentials()),
            CredentialedL4Check::NoUninspectedCredentialedL4
        );
    }

    #[test]
    fn exact_l4_to_credential_target_is_reported() {
        let policy = policy(
            r"      - host: api.github.com
        port: 443",
            gh_binary(),
        );

        let CredentialedL4Check::HasUninspectedCredentialedL4 { counterexample } =
            check_uninspected_credentialed_l4(&policy, &github_credentials())
        else {
            panic!("expected uninspected credentialed L4 finding");
        };
        assert_eq!(counterexample.protocol, LAYER_L4);
        assert_eq!(counterexample.host, "api.github.com");
    }

    #[test]
    fn broad_l4_to_credential_target_is_reported_with_symbolic_host() {
        let policy = policy(
            r#"      - host: "**"
        port: 443"#,
            gh_binary(),
        );

        let CredentialedL4Check::HasUninspectedCredentialedL4 { counterexample } =
            check_uninspected_credentialed_l4(&policy, &github_credentials())
        else {
            panic!("expected broad L4 to overlap credential target");
        };
        assert_eq!(counterexample.protocol, LAYER_L4);
        assert_eq!(counterexample.host, "api.github.com");
    }

    #[test]
    fn credential_target_matching_normalizes_trailing_dot() {
        let policy = policy(
            r"      - host: api.github.com
        port: 443",
            gh_binary(),
        );
        let credentials = CredentialSet {
            credentials: vec![Credential {
                name: "github".to_owned(),
                cred_type: "github-pat".to_owned(),
                scopes: vec!["repo".to_owned()],
                injected_via: "env".to_owned(),
                target_hosts: vec![" API.GITHUB.COM. ".to_owned()],
            }],
            api_registries: HashMap::new(),
        };

        let CredentialedL4Check::HasUninspectedCredentialedL4 { counterexample } =
            check_uninspected_credentialed_l4(&policy, &credentials)
        else {
            panic!("expected normalized credential target to match L4 policy host");
        };
        assert_eq!(counterexample.host, "api.github.com");
    }

    #[test]
    fn provider_shaped_cursor_allows_known_download_but_rejects_new_url() {
        let maximum = policy_doc(
            r#"  _provider_cursor:
    name: _provider_cursor
    endpoints:
      - host: cursor.blob.core.windows.net
        port: 443
      - host: api2.cursor.sh
        port: 443
      - host: repo.cursor.sh
        port: 443
      - host: download.cursor.sh
        port: 443
      - host: cursor.download.prss.microsoft.com
        port: 443
    binaries:
      - path: /usr/bin/curl
      - path: /usr/bin/wget
      - path: "/sandbox/.cursor-server/**""#,
        );
        let known_candidate = policy_doc(
            r"  cursor_bootstrap:
    name: cursor_bootstrap
    endpoints:
      - host: repo.cursor.sh
        port: 443
    binaries:
      - path: /usr/bin/curl",
        );
        let new_url_candidate = policy_doc(
            r"  cursor_bootstrap:
    name: cursor_bootstrap
    endpoints:
      - host: updates.example.com
        port: 443
    binaries:
      - path: /usr/bin/curl",
        );

        assert_eq!(
            check_within_maximum(&maximum, &known_candidate),
            MaximumPolicyCheck::WithinMax
        );
        let MaximumPolicyCheck::ExceedsMax { counterexample } =
            check_within_maximum(&maximum, &new_url_candidate)
        else {
            panic!("expected new URL to exceed Cursor provider maximum");
        };
        assert_eq!(counterexample.protocol, LAYER_L4);
        assert_eq!(counterexample.host, "updates.example.com");
    }

    #[test]
    fn provider_shaped_copilot_mixed_rest_and_l4_are_modelable() {
        let maximum = policy_doc(
            r#"  _provider_copilot:
    name: _provider_copilot
    endpoints:
      - host: api.githubcopilot.com
        port: 443
        protocol: rest
        access: read-write
        enforcement: enforce
      - host: api.individual.githubcopilot.com
        port: 443
        protocol: rest
        access: read-write
        enforcement: enforce
      - host: api.business.githubcopilot.com
        port: 443
        protocol: rest
        access: read-write
        enforcement: enforce
      - host: api.enterprise.githubcopilot.com
        port: 443
        protocol: rest
        access: read-write
        enforcement: enforce
      - host: copilot-proxy.githubusercontent.com
        port: 443
        protocol: rest
        access: read-write
        enforcement: enforce
      - host: telemetry.enterprise.githubcopilot.com
        port: 443
      - host: default.exp-tas.com
        port: 443
    binaries:
      - path: /usr/bin/copilot
      - path: "/usr/lib/node_modules/@github/copilot/node_modules/@github/**/copilot""#,
        );
        let rest_candidate = policy_doc(
            r"  copilot_api:
    name: copilot_api
    endpoints:
      - host: api.githubcopilot.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: POST
              path: /chat/completions
    binaries:
      - path: /usr/bin/copilot",
        );
        let l4_candidate = policy_doc(
            r"  copilot_telemetry:
    name: copilot_telemetry
    endpoints:
      - host: telemetry.enterprise.githubcopilot.com
        port: 443
    binaries:
      - path: /usr/bin/copilot",
        );

        assert_eq!(
            check_within_maximum(&maximum, &rest_candidate),
            MaximumPolicyCheck::WithinMax
        );
        assert_eq!(
            check_within_maximum(&maximum, &l4_candidate),
            MaximumPolicyCheck::WithinMax
        );
    }
}
