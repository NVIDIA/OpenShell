// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Semantic containment for the initial managed-maximum surface.
//!
//! The first implementation models filesystem paths, L4 host/port/binary
//! authority, and enforced REST method/path authority. Other network
//! protocols fail closed so the admission contract can grow without changing
//! its callers.

use std::str::FromStr;

use z3::ast::{Bool, Int, Regexp, String as Z3String};
use z3::{Context, SatResult, Solver};

use crate::policy::{Endpoint, L7DenyRule, L7Rule, NetworkPolicyRule, PolicyModel};

const READ_ONLY_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS"];
const READ_WRITE_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"];
const LAYER_L4: &str = "l4";
const LAYER_REST: &str = "rest";

/// Result of proving a candidate policy against a managed maximum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaximumPolicyCheck {
    WithinMax,
    ExceedsMax {
        counterexample: Box<PolicyCounterexample>,
    },
    Unsupported {
        reason: String,
    },
}

/// One concrete L4, REST, or filesystem action outside the maximum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyCounterexample {
    pub binary: String,
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub method: String,
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy)]
enum MaximumView {
    All,
    AutoEligible,
}

struct SymbolicAction {
    binary: Z3String,
    host: Z3String,
    port: Int,
    layer: Z3String,
    method: Z3String,
    path: Z3String,
}

#[must_use]
pub fn check_within_maximum(maximum: &PolicyModel, candidate: &PolicyModel) -> MaximumPolicyCheck {
    check(maximum, candidate, MaximumView::All)
}

#[must_use]
pub fn check_within_auto_eligible_maximum(
    maximum: &PolicyModel,
    requested_delta: &PolicyModel,
) -> MaximumPolicyCheck {
    check(maximum, requested_delta, MaximumView::AutoEligible)
}

fn check(
    maximum: &PolicyModel,
    candidate: &PolicyModel,
    maximum_view: MaximumView,
) -> MaximumPolicyCheck {
    if let Some(reason) = unsupported_reason("maximum", maximum) {
        return MaximumPolicyCheck::Unsupported { reason };
    }
    if let Some(reason) = unsupported_reason("candidate", candidate) {
        return MaximumPolicyCheck::Unsupported { reason };
    }
    if let Some(counterexample) = filesystem_counterexample(maximum, candidate) {
        return MaximumPolicyCheck::ExceedsMax {
            counterexample: Box::new(counterexample),
        };
    }

    let solver = Solver::new();
    let action = symbolic_action("maximum_policy_action");
    assert_action_domain(&solver, &action);
    solver.assert(Bool::and(&[
        policy_allows(candidate, &action, MaximumView::All),
        !policy_allows(maximum, &action, maximum_view),
    ]));

    match solver.check() {
        SatResult::Unsat => MaximumPolicyCheck::WithinMax,
        SatResult::Unknown => MaximumPolicyCheck::Unsupported {
            reason: "Z3 returned unknown while checking maximum-policy containment".to_owned(),
        },
        SatResult::Sat => {
            let Some(model) = solver.get_model() else {
                return MaximumPolicyCheck::Unsupported {
                    reason: "Z3 returned sat without a maximum-policy model".to_owned(),
                };
            };
            let Some(counterexample) = counterexample_from_model(&model, &action) else {
                return MaximumPolicyCheck::Unsupported {
                    reason: "Z3 returned a model that could not be decoded".to_owned(),
                };
            };
            MaximumPolicyCheck::ExceedsMax {
                counterexample: Box::new(counterexample),
            }
        }
    }
}

fn symbolic_action(name: &str) -> SymbolicAction {
    let _context = Context::thread_local();
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
    solver.assert(action.port.le(65_535));
    solver.assert(str_eq_any(&action.layer, &[LAYER_L4, LAYER_REST]));
    solver.assert(!action.method.eq(""));
    solver.assert(
        Z3String::from_str("/")
            .expect("valid Z3 string literal")
            .prefix(&action.path),
    );
}

fn policy_allows(policy: &PolicyModel, action: &SymbolicAction, view: MaximumView) -> Bool {
    let allowed = bool_or(
        policy
            .network_policies
            .values()
            .map(|rule| rule_allows(rule, action, view)),
    );
    let denied = bool_or(
        policy
            .network_policies
            .values()
            .map(|rule| rule_denies(rule, action)),
    );
    Bool::and(&[allowed, !denied])
}

fn rule_allows(rule: &NetworkPolicyRule, action: &SymbolicAction, view: MaximumView) -> Bool {
    Bool::and(&[
        binaries_match(rule, action),
        bool_or(
            rule.endpoints
                .iter()
                .map(|endpoint| endpoint_allows(endpoint, action, view)),
        ),
    ])
}

fn rule_denies(rule: &NetworkPolicyRule, action: &SymbolicAction) -> Bool {
    Bool::and(&[
        binaries_match(rule, action),
        bool_or(
            rule.endpoints
                .iter()
                .map(|endpoint| endpoint_denies(endpoint, action)),
        ),
    ])
}

fn binaries_match(rule: &NetworkPolicyRule, action: &SymbolicAction) -> Bool {
    bool_or(
        rule.binaries
            .iter()
            .map(|binary| action.binary.regex_matches(&glob_regex(&binary.path, "/"))),
    )
}

fn endpoint_allows(endpoint: &Endpoint, action: &SymbolicAction, view: MaximumView) -> Bool {
    let common = endpoint_matches_connection(endpoint, action);
    if matches!(view, MaximumView::AutoEligible) && endpoint.review.required {
        return Bool::from_bool(false);
    }

    match endpoint.protocol.trim().to_ascii_lowercase().as_str() {
        "" => common,
        "rest" => Bool::and(&[
            common,
            action.layer.eq(LAYER_REST),
            endpoint_path_matches(endpoint, action),
            rest_endpoint_allows(endpoint, action, view),
        ]),
        _ => Bool::from_bool(false),
    }
}

fn endpoint_denies(endpoint: &Endpoint, action: &SymbolicAction) -> Bool {
    if !endpoint.protocol.eq_ignore_ascii_case("rest") || endpoint.deny_rules.is_empty() {
        return Bool::from_bool(false);
    }
    Bool::and(&[
        endpoint_matches_connection(endpoint, action),
        action.layer.eq(LAYER_REST),
        endpoint_path_matches(endpoint, action),
        bool_or(
            endpoint
                .deny_rules
                .iter()
                .map(|deny| method_and_path_match(&deny.method, &deny.path, action)),
        ),
    ])
}

fn rest_endpoint_allows(endpoint: &Endpoint, action: &SymbolicAction, view: MaximumView) -> Bool {
    match endpoint.access.as_str() {
        "read-only" => methods_match(action, READ_ONLY_METHODS, "**"),
        "read-write" => methods_match(action, READ_WRITE_METHODS, "**"),
        "full" => any_method_matches(action, "**"),
        _ => bool_or(endpoint.rules.iter().map(|rule| {
            if matches!(view, MaximumView::AutoEligible) && rule.review.required {
                Bool::from_bool(false)
            } else {
                method_and_path_match(&rule.method, &rule.path, action)
            }
        })),
    }
}

fn endpoint_matches_connection(endpoint: &Endpoint, action: &SymbolicAction) -> Bool {
    Bool::and(&[
        bool_or(
            endpoint
                .effective_ports()
                .into_iter()
                .map(|port| action.port.eq(Int::from_u64(u64::from(port)))),
        ),
        action
            .host
            .regex_matches(&glob_regex(&endpoint.host.to_ascii_lowercase(), ".")),
    ])
}

fn endpoint_path_matches(endpoint: &Endpoint, action: &SymbolicAction) -> Bool {
    let path = if endpoint.path.is_empty() {
        "**"
    } else {
        &endpoint.path
    };
    action.path.regex_matches(&glob_regex(path, "/"))
}

fn method_and_path_match(method: &str, path: &str, action: &SymbolicAction) -> Bool {
    if method.is_empty() {
        return Bool::from_bool(false);
    }
    let path = if path.is_empty() { "**" } else { path };
    if method == "*" {
        any_method_matches(action, path)
    } else if method.eq_ignore_ascii_case("GET") {
        methods_match(action, &["GET", "HEAD"], path)
    } else {
        methods_match(action, &[method], path)
    }
}

fn any_method_matches(action: &SymbolicAction, path: &str) -> Bool {
    action.path.regex_matches(&glob_regex(path, "/"))
}

fn methods_match(action: &SymbolicAction, methods: &[&str], path: &str) -> Bool {
    Bool::and(&[
        str_eq_any_case_insensitive(&action.method, methods),
        action.path.regex_matches(&glob_regex(path, "/")),
    ])
}

fn counterexample_from_model(
    model: &z3::Model,
    action: &SymbolicAction,
) -> Option<PolicyCounterexample> {
    let port = model.eval(&action.port, true)?.as_u64()?;
    let protocol = model.eval(&action.layer, true)?.as_string()?;
    let is_l4 = protocol == LAYER_L4;
    Some(PolicyCounterexample {
        binary: model.eval(&action.binary, true)?.as_string()?,
        host: model.eval(&action.host, true)?.as_string()?,
        port: u16::try_from(port).ok()?,
        protocol,
        method: if is_l4 {
            String::new()
        } else {
            model.eval(&action.method, true)?.as_string()?
        },
        path: if is_l4 {
            String::new()
        } else {
            model.eval(&action.path, true)?.as_string()?
        },
        reason: "candidate allows an action outside the managed maximum".to_owned(),
    })
}

fn filesystem_counterexample(
    maximum: &PolicyModel,
    candidate: &PolicyModel,
) -> Option<PolicyCounterexample> {
    let maximum_read_write = filesystem_paths(maximum, true);
    let mut maximum_read = filesystem_paths(maximum, false);
    maximum_read.extend(maximum_read_write.iter().cloned());

    if let Some(path) = filesystem_paths(candidate, true)
        .iter()
        .find(|path| !path_is_covered(path, &maximum_read_write))
    {
        return Some(filesystem_counterexample_value(path, "write"));
    }
    filesystem_paths(candidate, false)
        .iter()
        .find(|path| !path_is_covered(path, &maximum_read))
        .map(|path| filesystem_counterexample_value(path, "read"))
}

fn filesystem_paths(policy: &PolicyModel, write: bool) -> Vec<String> {
    let mut paths = if write {
        policy.filesystem_policy.read_write.clone()
    } else {
        policy.filesystem_policy.read_only.clone()
    };
    if write
        && policy.filesystem_policy.include_workdir
        && !paths.iter().any(|path| path == "/sandbox")
    {
        paths.push("/sandbox".to_owned());
    }
    paths
}

fn path_is_covered(candidate: &str, maximum_paths: &[String]) -> bool {
    maximum_paths.iter().any(|maximum| {
        candidate == maximum
            || candidate
                .strip_prefix(maximum.trim_end_matches('/'))
                .is_some_and(|suffix| suffix.starts_with('/'))
    })
}

fn filesystem_counterexample_value(path: &str, access: &str) -> PolicyCounterexample {
    PolicyCounterexample {
        binary: String::new(),
        host: String::new(),
        port: 0,
        protocol: "filesystem".to_owned(),
        method: access.to_owned(),
        path: path.to_owned(),
        reason: format!("candidate allows filesystem {access} outside the managed maximum"),
    }
}

fn unsupported_reason(prefix: &str, policy: &PolicyModel) -> Option<String> {
    if !policy.extra_fields.is_empty() {
        return Some(format!(
            "{prefix} policy uses unsupported top-level fields: {}",
            policy.extra_fields.join(", ")
        ));
    }
    if !policy.filesystem_policy.extra_fields.is_empty() {
        return Some(format!(
            "{prefix} policy uses unsupported filesystem fields: {}",
            policy.filesystem_policy.extra_fields.join(", ")
        ));
    }
    for (rule_name, rule) in &policy.network_policies {
        if !rule.extra_fields.is_empty() {
            return Some(format!(
                "{prefix} policy rule '{rule_name}' uses unsupported fields: {}",
                rule.extra_fields.join(", ")
            ));
        }
        for endpoint in &rule.endpoints {
            let context = format!("{prefix} policy rule '{rule_name}'");
            if endpoint.host.is_empty() || endpoint.effective_ports().is_empty() {
                return Some(format!("{context} has no modeled host or port"));
            }
            if unsupported_glob_pattern(&endpoint.host) || unsupported_glob_pattern(&endpoint.path)
            {
                return Some(format!("{context} uses an unsupported endpoint glob"));
            }
            if !endpoint.allowed_ips.is_empty() {
                return Some(format!(
                    "{context} uses allowed_ips/CIDR authority, which containment does not model"
                ));
            }
            if !endpoint.extra_fields.is_empty() {
                return Some(format!(
                    "{context} uses unsupported endpoint fields: {}",
                    endpoint.extra_fields.join(", ")
                ));
            }
            if !endpoint.review.extra_fields.is_empty() {
                return Some(format!("{context} uses unsupported review metadata"));
            }
            if !endpoint.tls.is_empty() {
                return Some(format!(
                    "{context} uses TLS behavior that containment does not model"
                ));
            }

            let protocol = endpoint.protocol.trim().to_ascii_lowercase();
            if !matches!(protocol.as_str(), "" | "rest") {
                return Some(format!(
                    "{context} uses protocol '{}'; this initial managed maximum supports only L4 and REST",
                    endpoint.protocol
                ));
            }
            if protocol.is_empty() {
                if !endpoint.path.is_empty()
                    || !endpoint.access.is_empty()
                    || !endpoint.rules.is_empty()
                    || !endpoint.deny_rules.is_empty()
                {
                    return Some(format!("{context} mixes REST controls into an L4 endpoint"));
                }
            } else {
                if endpoint.enforcement != "enforce" {
                    return Some(format!(
                        "{context} uses REST without enforcement mode 'enforce'"
                    ));
                }
                if !endpoint.access.is_empty() && !endpoint.rules.is_empty() {
                    return Some(format!("{context} combines REST access and rules"));
                }
                if endpoint.access.is_empty() && endpoint.rules.is_empty() {
                    return Some(format!("{context} has no REST allow rules"));
                }
                if !endpoint.access.is_empty()
                    && !matches!(
                        endpoint.access.as_str(),
                        "read-only" | "read-write" | "full"
                    )
                {
                    return Some(format!(
                        "{context} uses unsupported REST access preset '{}'",
                        endpoint.access
                    ));
                }
            }

            for allow in &endpoint.rules {
                if unsupported_rest_allow(allow) {
                    return Some(format!(
                        "{context} uses an unsupported REST allow-rule field"
                    ));
                }
                if unsupported_glob_pattern(&allow.path) {
                    return Some(format!("{context} uses an unsupported allow-rule glob"));
                }
            }
            for deny in &endpoint.deny_rules {
                if unsupported_rest_deny(deny) {
                    return Some(format!(
                        "{context} uses an unsupported REST deny-rule field"
                    ));
                }
                if unsupported_glob_pattern(&deny.path) {
                    return Some(format!("{context} uses an unsupported deny-rule glob"));
                }
            }
        }
        for binary in &rule.binaries {
            if !binary.extra_fields.is_empty() {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses unsupported binary fields: {}",
                    binary.extra_fields.join(", ")
                ));
            }
            if unsupported_glob_pattern(&binary.path) {
                return Some(format!(
                    "{prefix} policy rule '{rule_name}' uses an unsupported binary glob"
                ));
            }
        }
    }
    None
}

fn unsupported_rest_allow(rule: &L7Rule) -> bool {
    rule.method.is_empty()
        || !rule.command.is_empty()
        || !rule.extra_fields.is_empty()
        || !rule.review.extra_fields.is_empty()
}

fn unsupported_rest_deny(rule: &L7DenyRule) -> bool {
    rule.method.is_empty() || !rule.command.is_empty() || !rule.extra_fields.is_empty()
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

fn str_eq_any_case_insensitive(value: &Z3String, options: &[&str]) -> Bool {
    bool_or(
        options
            .iter()
            .map(|option| value.eq(option.to_ascii_uppercase())),
    )
}

// Reused from the maximal-policy spike. `*` does not cross the selected
// separator; `**` does. That matches OpenShell's host, path, and binary globs.
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

fn unsupported_glob_pattern(pattern: &str) -> bool {
    pattern
        .chars()
        .any(|character| matches!(character, '?' | '[' | ']' | '{' | '}' | '\\'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::parse_policy_str;

    fn policy(endpoint: &str) -> PolicyModel {
        parse_policy_str(&format!(
            r"version: 1
network_policies:
  test:
    endpoints:
{endpoint}
    binaries:
      - path: /usr/bin/gh
"
        ))
        .expect("policy should parse")
    }

    fn filesystem(read_only: &str, read_write: &str) -> PolicyModel {
        parse_policy_str(&format!(
            r"version: 1
filesystem_policy:
  include_workdir: false
  read_only: [{read_only}]
  read_write: [{read_write}]
"
        ))
        .expect("filesystem policy should parse")
    }

    fn rest(rules: &str) -> PolicyModel {
        policy(&format!(
            r"      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
{rules}"
        ))
    }

    #[test]
    fn policy_is_contained_by_itself() {
        let value = rest("          - allow: { method: GET, path: /repos/** }");
        assert_eq!(
            check_within_maximum(&value, &value),
            MaximumPolicyCheck::WithinMax
        );
    }

    #[test]
    fn filesystem_paths_are_contained_by_parent_authority() {
        let maximum = filesystem("/usr", "/sandbox, /tmp");
        let candidate = filesystem("/usr/bin", "/sandbox/project");
        assert_eq!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::WithinMax
        );
    }

    #[test]
    fn filesystem_write_cannot_use_read_only_maximum() {
        let maximum = filesystem("/usr", "/sandbox");
        let candidate = filesystem("", "/usr/bin");
        let MaximumPolicyCheck::ExceedsMax { counterexample } =
            check_within_maximum(&maximum, &candidate)
        else {
            panic!("write under read-only maximum should fail");
        };
        assert_eq!(counterexample.protocol, "filesystem");
        assert_eq!(counterexample.method, "write");
    }

    #[test]
    fn narrower_rest_path_is_contained() {
        let maximum = rest("          - allow: { method: GET, path: /repos/** }");
        let candidate = rest("          - allow: { method: GET, path: /repos/NVIDIA/OpenShell }");
        assert_eq!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::WithinMax
        );
    }

    #[test]
    fn broader_rest_path_returns_counterexample() {
        let maximum = rest("          - allow: { method: GET, path: /repos/NVIDIA/** }");
        let candidate = rest("          - allow: { method: GET, path: /repos/** }");
        let MaximumPolicyCheck::ExceedsMax { counterexample } =
            check_within_maximum(&maximum, &candidate)
        else {
            panic!("broader path should exceed maximum");
        };
        assert_eq!(counterexample.protocol, "rest");
        assert_eq!(counterexample.method, "GET");
    }

    #[test]
    fn l4_maximum_covers_rest_but_rest_does_not_cover_l4() {
        let l4 = policy("      - host: api.github.com\n        port: 443");
        let rest = rest("          - allow: { method: GET, path: /repos/** }");
        assert_eq!(
            check_within_maximum(&l4, &rest),
            MaximumPolicyCheck::WithinMax
        );
        assert!(matches!(
            check_within_maximum(&rest, &l4),
            MaximumPolicyCheck::ExceedsMax { .. }
        ));
    }

    #[test]
    fn explicit_deny_removes_authority() {
        let maximum = rest(
            "          - allow: { method: \"*\", path: /** }\n        deny_rules:\n          - { method: DELETE, path: /** }",
        );
        let candidate =
            rest("          - allow: { method: DELETE, path: /repos/NVIDIA/OpenShell }");
        assert!(matches!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::ExceedsMax { .. }
        ));
    }

    #[test]
    fn full_rest_access_contains_extension_methods() {
        let maximum = policy(
            "      - host: api.github.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        access: full",
        );
        let candidate = rest("          - allow: { method: PROPFIND, path: /repos/acme }");
        assert_eq!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::WithinMax
        );
    }

    #[test]
    fn finite_method_rules_do_not_contain_wildcard_authority() {
        let maximum = rest(
            "          - allow: { method: GET, path: /** }\n          - allow: { method: HEAD, path: /** }\n          - allow: { method: OPTIONS, path: /** }\n          - allow: { method: POST, path: /** }\n          - allow: { method: PUT, path: /** }\n          - allow: { method: PATCH, path: /** }\n          - allow: { method: DELETE, path: /** }",
        );
        let candidate = rest("          - allow: { method: \"*\", path: /** }");
        let MaximumPolicyCheck::ExceedsMax { counterexample } =
            check_within_maximum(&maximum, &candidate)
        else {
            panic!("finite method rules must not contain wildcard authority");
        };
        assert!(!counterexample.method.is_empty());
        assert!(
            !["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
                .contains(&counterexample.method.as_str())
        );
    }

    #[test]
    fn wildcard_deny_blocks_extension_methods() {
        let maximum = policy(
            "      - host: api.github.com\n        port: 443\n        protocol: rest\n        enforcement: enforce\n        access: full\n        deny_rules:\n          - { method: \"*\", path: /private/** }",
        );
        let candidate = rest("          - allow: { method: PROPFIND, path: /private/data }");
        assert!(matches!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::ExceedsMax { .. }
        ));
    }

    #[test]
    fn review_required_region_is_not_auto_eligible() {
        let maximum = rest(
            "          - allow:\n              method: POST\n              path: /repos/*/pulls\n              review: { required: true }",
        );
        let delta = rest("          - allow: { method: POST, path: /repos/acme/pulls }");
        assert_eq!(
            check_within_maximum(&maximum, &delta),
            MaximumPolicyCheck::WithinMax
        );
        assert!(matches!(
            check_within_auto_eligible_maximum(&maximum, &delta),
            MaximumPolicyCheck::ExceedsMax { .. }
        ));
    }

    #[test]
    fn endpoint_path_scopes_rest_authority() {
        let maximum = policy(
            "      - host: api.github.com\n        port: 443\n        path: /repos/NVIDIA/**\n        protocol: rest\n        enforcement: enforce\n        access: full",
        );
        let candidate = rest("          - allow: { method: GET, path: /repos/** }");
        assert!(matches!(
            check_within_maximum(&maximum, &candidate),
            MaximumPolicyCheck::ExceedsMax { .. }
        ));
    }

    #[test]
    fn graphql_and_mcp_fail_closed_in_initial_scope() {
        for protocol in ["graphql", "mcp"] {
            let value = policy(&format!(
                "      - host: api.example.com\n        port: 443\n        protocol: {protocol}\n        enforcement: enforce\n        rules:\n          - allow: {{ operation_type: query }}"
            ));
            assert!(matches!(
                check_within_maximum(&value, &value),
                MaximumPolicyCheck::Unsupported { reason }
                    if reason.contains("only L4 and REST")
            ));
        }
    }

    #[test]
    fn rest_query_matchers_fail_closed() {
        let value =
            rest("          - allow: { method: GET, path: /repos/**, query: { page: \"*\" } }");
        assert!(matches!(
            check_within_maximum(&value, &value),
            MaximumPolicyCheck::Unsupported { .. }
        ));
    }

    #[test]
    fn unknown_authority_surfaces_fail_closed() {
        let value = parse_policy_str(
            "version: 1\nnetwork_policies: {}\nfuture_authority: { allow: all }\n",
        )
        .expect("generic parser should preserve unknown fields");
        assert!(matches!(
            check_within_maximum(&value, &value),
            MaximumPolicyCheck::Unsupported { reason }
                if reason.contains("future_authority")
        ));
    }
}
