// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exact finite abstraction of decoded REST query parameters for exact / `*`
//! matchers. Each key has one Boolean per literal mentioned by either policy,
//! plus separate wildcard-matching and nonmatching classes for other values.
//! The runtime's `glob.match(pattern, [], value)` uses `.` as a delimiter,
//! so `*` does not match dotted values. Multiple classes may be present:
//! runtime allow rules require ALL repeated values to match, while deny rules
//! require ANY value to match. Multiplicity and order do not affect either rule.
//! All-false represents an absent key. The REST parser never produces a present
//! key with an empty value list (a bare key instead has one empty-string value).

use std::collections::{BTreeMap, BTreeSet};

use openshell_policy_schema::QueryMatcher;
use z3::ast::Bool;

use super::{ContainmentPolicy, bool_or, unsupported_glob, unsupported_network_literal};

pub(super) type QueryRules = BTreeMap<String, QueryMatcher>;
pub(super) type QueryValues = BTreeMap<String, Vec<String>>;

/// One satisfying decoded request for supported query constraints. This is a
/// heuristic seed only: full-policy replay must account for all other controls.
pub(super) fn sample(rules: &QueryRules) -> QueryValues {
    rules
        .iter()
        .map(|(key, matcher)| {
            let QueryMatcher::Glob(value) = matcher else {
                unreachable!("query matchers must be validated before sampling")
            };
            (
                key.clone(),
                vec![if value == "*" {
                    String::new()
                } else {
                    value.clone()
                }],
            )
        })
        .collect()
}

#[derive(Default)]
pub(super) struct SymbolicQuery(BTreeMap<String, QueryKey>);

struct QueryKey {
    literals: BTreeMap<String, Bool>,
    // Index 0 matches `*`; index 1 does not.
    other: [Bool; 2],
    other_values: [String; 2],
}

fn wildcard_matches(value: &str) -> bool {
    !value.contains('.')
}

pub(super) fn supported(rules: &QueryRules) -> bool {
    rules.iter().all(|(key, matcher)| {
        unsupported_network_literal(key).is_none()
            && matches!(matcher, QueryMatcher::Glob(value)
                if unsupported_network_literal(value).is_none()
                    && (value == "*" || (!value.contains('*') && !unsupported_glob(value))))
    })
}

/// Sufficient implication check for the structural REST fast path. Both maps
/// have already passed shape validation. Extra candidate constraints narrow it.
pub(super) fn contains(boundary: &QueryRules, candidate: &QueryRules) -> bool {
    boundary.iter().all(|(key, required)| {
        candidate.get(key).is_some_and(|proposed| {
            required == proposed
                || (matches!(required, QueryMatcher::Glob(value) if value == "*")
                    && matches!(proposed, QueryMatcher::Glob(value) if wildcard_matches(value)))
        })
    })
}

fn literals(
    boundary: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut keys: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for policy in [boundary, candidate] {
        for endpoint in policy
            .network_policies
            .values()
            .flat_map(|rule| &rule.endpoints)
        {
            for rules in endpoint
                .rules
                .iter()
                .map(|rule| &rule.allow.query)
                .chain(endpoint.deny_rules.iter().map(|rule| &rule.query))
            {
                for (key, matcher) in rules {
                    let values = keys.entry(key.clone()).or_default();
                    if let QueryMatcher::Glob(value) = matcher
                        && value != "*"
                    {
                        values.insert(value.clone());
                    }
                }
            }
        }
    }
    keys
}

impl SymbolicQuery {
    pub(super) fn new(
        name: &str,
        boundary: &ContainmentPolicy,
        candidate: &ContainmentPolicy,
    ) -> Self {
        Self(
            literals(boundary, candidate)
                .into_iter()
                .enumerate()
                .map(|(key_index, (key, values))| {
                    let mut other_values = [String::new(), ".".to_owned()];
                    for value in &mut other_values {
                        while values.contains(value) {
                            value.push('a');
                        }
                    }
                    (
                        key,
                        QueryKey {
                            literals: values
                                .into_iter()
                                .enumerate()
                                .map(|(value_index, value)| {
                                    (
                                        value,
                                        Bool::new_const(format!(
                                            "{name}_query_{key_index}_{value_index}"
                                        )),
                                    )
                                })
                                .collect(),
                            other: std::array::from_fn(|class| {
                                Bool::new_const(format!("{name}_query_{key_index}_other_{class}"))
                            }),
                            other_values,
                        },
                    )
                })
                .collect(),
        )
    }

    pub(super) fn concrete(
        boundary: &ContainmentPolicy,
        candidate: &ContainmentPolicy,
        values: &QueryValues,
    ) -> Self {
        let mut query = Self::new("concrete", boundary, candidate);
        for (key, classes) in &mut query.0 {
            let present = values.get(key).map_or(&[][..], Vec::as_slice);
            classes.other = std::array::from_fn(|class| {
                Bool::from_bool(present.iter().any(|value| {
                    !classes.literals.contains_key(value)
                        && usize::from(!wildcard_matches(value)) == class
                }))
            });
            for (value, flag) in &mut classes.literals {
                *flag = Bool::from_bool(present.contains(value));
            }
        }
        query
    }

    pub(super) fn matches(&self, rules: &QueryRules, deny: bool) -> Bool {
        Bool::and(
            &rules
                .iter()
                .map(|(key, matcher)| {
                    let classes = &self.0[key];
                    let QueryMatcher::Glob(value) = matcher else {
                        unreachable!("query matchers must be validated before modeling")
                    };
                    if value == "*" {
                        let matching = bool_or(
                            classes
                                .literals
                                .iter()
                                .filter(|(literal, _)| wildcard_matches(literal))
                                .map(|(_, flag)| flag.clone())
                                .chain([classes.other[0].clone()]),
                        );
                        if deny {
                            matching
                        } else {
                            Bool::and(&[
                                matching,
                                !bool_or(
                                    classes
                                        .literals
                                        .iter()
                                        .filter(|(literal, _)| !wildcard_matches(literal))
                                        .map(|(_, flag)| flag.clone())
                                        .chain([classes.other[1].clone()]),
                                ),
                            ])
                        }
                    } else if deny {
                        classes.literals[value].clone()
                    } else {
                        Bool::and(&[
                            classes.literals[value].clone(),
                            !bool_or(classes.other.iter().cloned()),
                            !bool_or(
                                classes
                                    .literals
                                    .iter()
                                    .filter(|(literal, _)| *literal != value)
                                    .map(|(_, flag)| flag.clone()),
                            ),
                        ])
                    }
                })
                .collect::<Vec<_>>(),
        )
    }

    pub(super) fn decode(&self, model: &z3::Model) -> Option<QueryValues> {
        let mut query = BTreeMap::new();
        for (key, classes) in &self.0 {
            let mut values = Vec::new();
            for (literal, flag) in &classes.literals {
                if model.eval(flag, true)?.as_bool()? {
                    values.push(literal.clone());
                }
            }
            for (flag, value) in classes.other.iter().zip(&classes.other_values) {
                if model.eval(flag, true)?.as_bool()? {
                    values.push(value.clone());
                }
            }
            if !values.is_empty() {
                query.insert(key.clone(), values);
            }
        }
        Some(query)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use regorus::{Engine, Value};
    use serde_json::json;
    use z3::ast::Ast;

    #[test]
    fn symbolic_wildcard_preserves_mixed_other_values_in_witness() {
        let policy = super::super::parse_policy_str(
            r#"{"version":1,"network_policies":{"n":{"endpoints":[{
                "host":"example.com","port":443,"protocol":"rest","enforcement":"enforce",
                "rules":[{"allow":{"method":"GET","path":"/**","query":{"q":"*"}}}]
            }]}}}"#,
        )
        .unwrap();
        let query = SymbolicQuery::new("mixed", &policy, &policy);
        let rules = BTreeMap::from([("q".to_owned(), QueryMatcher::Glob("*".to_owned()))]);
        let solver = z3::Solver::new();
        solver.assert(&query.0["q"].other[0]);
        solver.assert(&query.0["q"].other[1]);
        solver.assert(!query.matches(&rules, false));
        solver.assert(query.matches(&rules, true));
        assert_eq!(solver.check(), z3::SatResult::Sat);
        let decoded = query.decode(&solver.get_model().unwrap()).unwrap();
        assert_eq!(decoded["q"], ["", "."]);
        let concrete = SymbolicQuery::concrete(&policy, &policy, &decoded);
        assert_eq!(
            concrete.matches(&rules, false).simplify().as_bool(),
            Some(false)
        );
        assert_eq!(
            concrete.matches(&rules, true).simplify().as_bool(),
            Some(true)
        );
    }

    #[test]
    fn decoded_query_model_matches_runtime_for_missing_and_repeated_values() {
        let mut engine = Engine::new();
        engine
            .add_policy(
                "runtime.rego".into(),
                include_str!("../../../openshell-supervisor-network/data/sandbox-policy.rego")
                    .into(),
            )
            .unwrap();
        engine
            .add_policy(
                "query-test.rego".into(),
                r"
package query_test
import rego.v1
allow := data.openshell.sandbox.query_params_match(input.request, input.rule)
deny := data.openshell.sandbox.deny_query_params_match(input.request, input.rule.allow)
"
                .into(),
            )
            .unwrap();
        for rules in [
            json!({}),
            json!({"service":"*"}),
            json!({"service":"a"}),
            json!({"service":"a.b"}),
            json!({"service":""}),
            json!({"service":"a", "v":"2"}),
            json!({"":"*"}),
            json!({"service":"a b+c%&="}),
        ] {
            let policy = super::super::parse_policy_str(&json!({
                "version":1,
                "network_policies":{"n":{"endpoints":[{
                    "host":"example.com", "port":443, "protocol":"rest", "enforcement":"enforce",
                    "rules":[{"allow":{"method":"GET", "path":"/", "query":rules}}]
                }]}}
            }).to_string()).unwrap();
            let rules: QueryRules = serde_json::from_value(rules).unwrap();
            for values in [
                json!({}),
                json!({"service":["a"]}),
                json!({"service":["b"]}),
                json!({"service":["a.b"]}),
                json!({"service":["a", "a.b"]}),
                json!({"service":["a.b", "a"]}),
                json!({"service":["a.b", "a.b"]}),
                json!({"service":["."]}),
                json!({"service":["/", "a/b", "é", "\n"]}),
                json!({"service":["a","a"]}),
                json!({"service":["a","b"]}),
                json!({"service":[""]}),
                json!({"service":["","a"]}),
                json!({"service":["a"],"v":["2"]}),
                json!({"service":["a"],"v":["2","3"]}),
                json!({"service":["a"],"other":["x"]}),
                json!({"service":["é"]}),
                json!({"service":["a b+c%&="]}),
                json!({"":[""]}),
            ] {
                let query = SymbolicQuery::concrete(
                    &policy,
                    &policy,
                    &serde_json::from_value(values.clone()).unwrap(),
                );
                engine.set_input_json(&json!({"request":{"query_params":values}, "rule":{"allow":{"query":rules}}}).to_string()).unwrap();
                for (deny, rule) in [
                    (false, "data.query_test.allow"),
                    (true, "data.query_test.deny"),
                ] {
                    let runtime = engine.eval_rule(rule.into()).unwrap() == Value::from(true);
                    assert_eq!(
                        query.matches(&rules, deny).simplify().as_bool(),
                        Some(runtime),
                        "rules={rules:?} values={values} deny={deny}"
                    );
                }
            }
        }
    }
}
