// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_prover::containment::{
    CheckOptions, CheckResult, Counterexample, ReasonCode, check_within_boundary, parse_policy_str,
};
use serde_json::{Value, json};
use std::time::Duration;

fn policy(queries: &[Value], denies: &[Value]) -> String {
    json!({
        "version": 1,
        "network_policies": {"git": {
            "binaries": [{"path": "/usr/bin/git"}],
            "endpoints": [{
                "host": "github.com", "port": 443,
                "protocol": "rest", "enforcement": "enforce",
                "rules": queries.iter().map(|q| json!({"allow": {
                    "method": "GET", "path": "/org/repo.git/info/refs", "query": q
                }})).collect::<Vec<_>>(),
                "deny_rules": denies.iter().map(|q| json!({
                    "method": "GET", "path": "/org/repo.git/info/refs", "query": q
                })).collect::<Vec<_>>()
            }]
        }}
    })
    .to_string()
}

fn check(boundary: &str, candidate: &str) -> CheckResult {
    check_within_boundary(
        &parse_policy_str(boundary).unwrap(),
        &parse_policy_str(candidate).unwrap(),
        CheckOptions::new(Duration::from_secs(5)),
    )
}

#[test]
fn exact_wildcard_and_required_keys() {
    for (parent, child, within) in [
        (json!({"service":"*"}), json!({"service":"a.b"}), false),
        (json!({"service":"*"}), json!({"service":"a/b"}), true),
        (
            json!({"service":"git-upload-pack"}),
            json!({"service":"git-upload-pack"}),
            true,
        ),
        (
            json!({"service":"git-upload-pack"}),
            json!({"service":"git-receive-pack"}),
            false,
        ),
        (
            json!({"service":"git-receive-pack"}),
            json!({"service":"git-upload-pack"}),
            false,
        ),
        (
            json!({"service":"*"}),
            json!({"service":"git-upload-pack"}),
            true,
        ),
        (
            json!({"service":"git-upload-pack"}),
            json!({"service":"*"}),
            false,
        ),
        (json!({}), json!({"service":"git-upload-pack"}), true),
        (json!({"service":"*"}), json!({}), false),
        (json!({"service":"*"}), json!({"service":""}), true),
        (
            json!({"service":""}),
            json!({"service":"git-upload-pack"}),
            false,
        ),
        (
            json!({"service":"git-upload-pack"}),
            json!({"service":"git-upload-pack", "version":"2"}),
            true,
        ),
        (
            json!({"service":"git-upload-pack", "version":"2"}),
            json!({"service":"git-upload-pack"}),
            false,
        ),
        (
            json!({"service":"git-upload-pack"}),
            json!({"Service":"git-upload-pack"}),
            false,
        ),
        (
            json!({"service":"git-upload-pack"}),
            json!({"service":"GIT-UPLOAD-PACK"}),
            false,
        ),
        (json!({"":"*"}), json!({"":""}), true),
        (json!({"x":"*"}), json!({"x":"a b+c%&="}), true),
    ] {
        let result = check(
            &policy(std::slice::from_ref(&parent), &[]),
            &policy(std::slice::from_ref(&child), &[]),
        );
        assert!(
            if within {
                matches!(result, CheckResult::Within(_))
            } else {
                matches!(result, CheckResult::Exceeds(_))
            },
            "parent={parent}, child={child}: {result:?}"
        );
    }
}

#[test]
fn query_denies_and_allow_unions() {
    for (parent, child, within) in [
        (
            policy(&[json!({})], &[json!({"service":"a.b"})]),
            policy(&[json!({})], &[json!({"service":"*"})]),
            false,
        ),
        (
            policy(&[json!({})], &[json!({"service":"git-receive-pack"})]),
            policy(&[json!({"service":"git-upload-pack"})], &[]),
            true,
        ),
        (
            policy(&[json!({})], &[json!({"service":"git-receive-pack"})]),
            policy(&[json!({})], &[]),
            false,
        ),
        (
            policy(&[json!({})], &[]),
            policy(&[json!({})], &[json!({"service":"git-receive-pack"})]),
            true,
        ),
        (
            policy(&[json!({})], &[json!({"service":"*"})]),
            policy(&[json!({})], &[json!({"service":"git-receive-pack"})]),
            false,
        ),
        (
            policy(&[json!({})], &[json!({"service":"git-receive-pack"})]),
            policy(&[json!({})], &[json!({"service":"*"})]),
            true,
        ),
        (
            policy(
                &[
                    json!({"service":"git-upload-pack"}),
                    json!({"service":"git-receive-pack"}),
                ],
                &[],
            ),
            policy(&[json!({"service":"git-upload-pack"})], &[]),
            true,
        ),
        (
            policy(&[json!({})], &[json!({"service":"git-receive-pack"})]),
            policy(
                &[json!({})],
                &[json!({"service":"git-receive-pack", "version":"2"})],
            ),
            false,
        ),
    ] {
        let result = check(&parent, &child);
        assert!(
            if within {
                matches!(result, CheckResult::Within(_))
            } else {
                matches!(result, CheckResult::Exceeds(_))
            },
            "{result:?}"
        );
    }
}

#[test]
fn witness_preserves_query_values() {
    let parent = policy(&[json!({"service":"git-upload-pack"})], &[]);
    let child = policy(&[json!({"service":"git-receive-pack"})], &[]);
    let CheckResult::Exceeds(evidence) = check(&parent, &child) else {
        panic!("expected expansion")
    };
    let Counterexample::Network { query_params, .. } = evidence.counterexample() else {
        panic!("expected network witness")
    };
    assert_eq!(query_params["service"], ["git-receive-pack"]);
}

#[test]
fn unsupported_query_matchers_fail_closed_in_either_policy() {
    let supported = policy(&[json!({})], &[]);
    for matcher in [
        json!("git-*"),
        json!("?"),
        json!("[ab]"),
        json!("{a,b}"),
        json!("a\\b"),
        json!("é"),
        json!("\u{0000}"),
        json!({"any":["a","b"]}),
    ] {
        for unsupported in [
            policy(&[json!({"service":matcher})], &[]),
            policy(&[json!({})], &[json!({"service":matcher})]),
        ] {
            for (parent, child) in [
                (&unsupported, &supported),
                (&supported, &unsupported),
                (&unsupported, &unsupported),
            ] {
                let result = check(parent, child);
                assert!(matches!(result, CheckResult::Unsupported(_)), "{result:?}");
            }
        }
    }
    for key in ["é", "\u{0000}"] {
        let unsupported = policy(&[json!({key: "*"})], &[]);
        assert!(matches!(
            check(&unsupported, &unsupported),
            CheckResult::Unsupported(_)
        ));
    }
}

#[test]
fn query_resources_are_bounded_before_equality_or_shape_shortcuts() {
    let at_limit: serde_json::Map<String, Value> =
        (0..128).map(|i| (format!("key{i}"), json!("*"))).collect();
    let at_limit = policy(&[Value::Object(at_limit)], &[]);
    assert!(matches!(
        check(&at_limit, &at_limit),
        CheckResult::Within(_)
    ));
    let queries: serde_json::Map<String, Value> =
        (0..129).map(|i| (format!("key{i}"), json!("*"))).collect();
    let oversized = policy(&[Value::Object(queries)], &[]);
    let result = check(&oversized, &oversized);
    assert!(
        matches!(result, CheckResult::Inconclusive(ref e) if e.reason_code() == ReasonCode::ResourceLimit),
        "{result:?}"
    );
    for query in [
        json!({"key": "a".repeat(4097)}),
        json!({"a".repeat(4097): "*"}),
        json!({"key":{"any":["a".repeat(4097)]}}),
    ] {
        let oversized = policy(&[query], &[]);
        let result = check(&oversized, &oversized);
        assert!(
            matches!(result, CheckResult::Inconclusive(ref e) if e.reason_code() == ReasonCode::ResourceLimit),
            "{result:?}"
        );
    }
}
