// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn fixtures() -> (Value, Value) {
    (
        serde_json::from_str(include_str!(
            "../../tests/fixtures/github-parent-discovery.json"
        ))
        .unwrap(),
        serde_yml::from_str(include_str!("../../tests/fixtures/github-child-clone.yaml")).unwrap(),
    )
}

fn parse(value: &Value) -> ContainmentPolicy {
    parse_policy_str(&value.to_string()).unwrap()
}

fn probe(parent: &Value, child: &Value) -> Option<Counterexample> {
    concrete_network_witness(
        &parse(parent),
        &parse(child),
        false,
        Instant::now(),
        Duration::from_secs(5),
        None,
    )
}

fn check(parent: &Value, child: &Value) -> CheckResult {
    check_within_boundary(
        &parse(parent),
        &parse(child),
        CheckOptions::new(Duration::from_secs(5)),
    )
}

#[test]
fn github_regression_all_rule_orders_find_a_replayed_violation() {
    let (parent, original) = fixtures();
    let rules = original["network_policies"]["github_repository"]["endpoints"][0]["rules"]
        .as_array()
        .unwrap();
    let mut count = 0;
    for a in 0..4 {
        for b in 0..4 {
            for c in 0..4 {
                for d in 0..4 {
                    if BTreeSet::from([a, b, c, d]).len() != 4 {
                        continue;
                    }
                    let mut child = original.clone();
                    child["network_policies"]["github_repository"]["endpoints"][0]["rules"] =
                        json!([rules[a], rules[b], rules[c], rules[d]]);
                    let witness = probe(&parent, &child)
                        .expect("bounded probes must find the GitHub expansion without SMT");
                    assert!(counterexample_satisfies_predicate(
                        &parse(&parent),
                        &parse(&child),
                        &witness
                    ));
                    assert!(matches!(check(&parent, &child), CheckResult::Exceeds(_)));
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 24);
}

#[test]
fn query_probe_contains_required_values_and_checks_later_rules() {
    let (parent, mut child) = fixtures();
    let witness = probe(&parent, &child).unwrap();
    let Counterexample::Network { query_params, .. } = witness else {
        panic!("network witness")
    };
    assert_eq!(query_params["service"], ["git-upload-pack"]);
    let rules = &mut child["network_policies"]["github_repository"]["endpoints"][0]["rules"];
    // Covered query-constrained discovery first, missing POST second.
    *rules = json!([rules[2], rules[1]]);
    let Counterexample::Network { method, .. } = probe(&parent, &child).unwrap() else {
        panic!("network witness")
    };
    assert_eq!(method.as_deref(), Some("POST"));
}

#[test]
fn probe_replays_other_boundary_grants_and_candidate_denies() {
    let (mut parent, mut child) = fixtures();
    parent["network_policies"]["other_grant"] =
        child["network_policies"]["github_repository"].clone();
    assert!(probe(&parent, &child).is_none());
    assert!(matches!(check(&parent, &child), CheckResult::Within(_)));
    parent["network_policies"] = json!({});
    let endpoint = &mut child["network_policies"]["github_repository"]["endpoints"][0];
    endpoint["deny_rules"] = json!(
        endpoint["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|rule| rule["allow"].clone())
            .collect::<Vec<_>>()
    );
    assert!(
        probe(&parent, &child).is_none(),
        "candidate denies must block sample requests"
    );
    assert!(matches!(check(&parent, &child), CheckResult::Within(_)));
}

#[test]
fn wildcard_seed_blocked_by_deny_falls_back_to_solver() {
    let (mut parent, mut child) = fixtures();
    parent["network_policies"] = json!({});
    let endpoint = &mut child["network_policies"]["github_repository"]["endpoints"][0];
    endpoint["rules"] =
        json!([{"allow":{"method":"GET", "path":"/info/refs", "query":{"service":"*"}}}]);
    endpoint["deny_rules"] = json!([{"method":"GET", "path":"/info/refs", "query":{"service":""}}]);
    assert!(probe(&parent, &child).is_none());
    assert!(
        matches!(check(&parent, &child), CheckResult::Exceeds(_)),
        "no sample is not proof of containment"
    );
}

#[test]
fn probe_budget_exhaustion_falls_back_to_solver() {
    let (mut parent, mut child) = fixtures();
    parent["network_policies"]
        .as_object_mut()
        .unwrap()
        .remove("openshell_tool_service");
    parent["network_policies"]["github_pi_subagents_clone_discovery"]["endpoints"][0]["rules"][0]
        ["allow"]["query"] = json!({"service":"a"});
    let endpoint = &mut child["network_policies"]["github_repository"]["endpoints"][0];
    let mut covered = endpoint["rules"][2].clone();
    covered["allow"]["query"] = json!({"service":"a"});
    let mut rules = vec![covered.clone(); MAX_CONCRETE_PROBES];
    covered["allow"]["query"] = json!({"service":"b"});
    rules.push(covered);
    endpoint["rules"] = json!(rules);
    assert!(probe(&parent, &child).is_none());
    assert!(
        matches!(check(&parent, &child), CheckResult::Exceeds(_)),
        "exhausting probes must not authorize"
    );
}

#[test]
fn probes_stop_on_cancellation_and_expired_deadline() {
    let (parent, child) = fixtures();
    let (parent, child) = (parse(&parent), parse(&child));
    let cancelled = AtomicBool::new(true);
    assert!(
        concrete_network_witness(
            &parent,
            &child,
            false,
            Instant::now(),
            Duration::from_secs(5),
            Some(&cancelled)
        )
        .is_none()
    );
    assert!(
        concrete_network_witness(&parent, &child, false, Instant::now(), Duration::ZERO, None)
            .is_none()
    );
    assert!(
        matches!(solve_network_mode(&parent, &child, false, Instant::now(), Duration::ZERO, Some(&cancelled)), NetworkSolve::Incomplete(CheckResult::Inconclusive(ref evidence)) if evidence.reason_code() == ReasonCode::Cancelled)
    );
}

#[test]
fn probes_respect_endpoint_paths_and_destination_ips() {
    let (mut parent, mut child) = fixtures();
    parent["network_policies"] = json!({});
    child["network_policies"]["github_repository"]["endpoints"][0]["path"] =
        json!("/different-path");
    assert!(probe(&parent, &child).is_none());
    child["network_policies"]["github_repository"]["endpoints"][0]
        .as_object_mut()
        .unwrap()
        .remove("path");
    child["network_policies"]["github_repository"]["endpoints"][0]["allowed_ips"] =
        json!(["10.10.10.10/32"]);
    let Counterexample::Network { destination_ip, .. } = probe(&parent, &child).unwrap() else {
        panic!("network witness")
    };
    assert_eq!(destination_ip.to_string(), "10.10.10.10");
}
