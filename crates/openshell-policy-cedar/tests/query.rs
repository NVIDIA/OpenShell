// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checks for `HttpRequest` query parameters: `context.query` tags, one
//! evaluation per combination of repeated values, the cap on combinations,
//! and how the combined decision interacts with audit-only policies.

use std::collections::BTreeMap;

use openshell_policy_cedar::{
    CedarEngine, CedarEngineError, Decision, L7Request, MAX_QUERY_COMBINATIONS,
};

const ENDPOINT: &str = r#"Sandbox::NetworkEndpoint::"api.example.com:443""#;

fn engine(policy: &str) -> CedarEngine {
    CedarEngine::from_policy_str(policy).expect("policy must load")
}

/// An `HttpRequest` policy on the test endpoint.
fn http_policy(annotations: &str, effect: &str, condition: &str) -> String {
    format!(
        r#"{annotations}
{effect} (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == {ENDPOINT}
)
when {{ {condition} }};
"#
    )
}

/// The condition that `key` is present and its value matches `pattern`, a
/// glob whose `*` stays within one `.`-separated segment, as YAML query
/// globs do.
fn tag_like(key: &str, pattern: &str) -> String {
    format!(
        r#"context.query.hasTag("{key}") && context.query.getTag("{key}") like("{pattern}", ".")"#
    )
}

/// A `GET /` request with `query`.
fn request(query: &[(&str, &[&str])]) -> L7Request {
    L7Request {
        user: "sandbox".to_string(),
        group: "sandbox".to_string(),
        binary_path: "/usr/bin/curl".to_string(),
        host: "api.example.com".to_string(),
        port: 443,
        method: "GET".to_string(),
        path: "/".to_string(),
        query: query
            .iter()
            .map(|(key, values)| {
                (
                    (*key).to_string(),
                    values.iter().map(ToString::to_string).collect(),
                )
            })
            .collect::<BTreeMap<_, _>>(),
        ..Default::default()
    }
}

fn allows(engine: &CedarEngine, query: &[(&str, &[&str])]) -> bool {
    engine
        .evaluate_l7(&request(query))
        .expect("request evaluates")
        .is_allow()
}

#[test]
fn query_values_are_tags_of_context_query() {
    let engine = engine(&http_policy("", "permit", &tag_like("tag", "foo-*")));
    assert!(allows(&engine, &[("tag", &["foo-a"])]));
    assert!(!allows(&engine, &[("tag", &["bar"])]));
    assert!(!allows(&engine, &[]), "a missing key has no tag");
    assert!(
        allows(&engine, &[("tag", &["foo-a"]), ("extra", &["x"])]),
        "other keys do not matter"
    );
}

#[test]
fn a_permit_must_allow_every_repeated_value() {
    let engine = engine(&http_policy("", "permit", &tag_like("tag", "foo-*")));
    assert!(allows(&engine, &[("tag", &["foo-a", "foo-b"])]));
    assert!(!allows(&engine, &[("tag", &["foo-a", "evil"])]));
}

#[test]
fn one_permit_must_allow_every_combination() {
    // As with two YAML allow rules, each value matching some rule is not
    // enough: one rule must match them all.
    let split = format!(
        "{}{}",
        http_policy("", "permit", &tag_like("tag", "foo-*")),
        http_policy("", "permit", &tag_like("tag", "bar-*")),
    );
    assert!(!allows(&engine(&split), &[("tag", &["foo-a", "bar-b"])]));
    assert!(allows(&engine(&split), &[("tag", &["foo-a", "foo-b"])]));

    let any = http_policy(
        "",
        "permit",
        r#"context.query.hasTag("tag")
           && (context.query.getTag("tag") like("foo-*", ".")
               || context.query.getTag("tag") like("bar-*", "."))"#,
    );
    assert!(allows(&engine(&any), &[("tag", &["foo-a", "bar-b"])]));
}

#[test]
fn a_forbid_denies_when_any_value_matches() {
    let policy = format!(
        "{}{}",
        http_policy("", "permit", "true"),
        http_policy("", "forbid", &tag_like("force", "true")),
    );
    let engine = engine(&policy);
    assert!(!allows(&engine, &[("force", &["true", "false"])]));
    assert!(!allows(&engine, &[("force", &["false", "true"])]));
    assert!(allows(&engine, &[("force", &["false"])]));
    assert!(
        allows(&engine, &[]),
        "a forbid on a missing key does not apply"
    );
}

#[test]
fn keys_combine_independently() {
    // A forbid fires when each of its keys has one matching value.
    let forbid = format!(
        "{}{}",
        http_policy("", "permit", "true"),
        http_policy(
            "",
            "forbid",
            &format!("{} && {}", tag_like("a", "x"), tag_like("b", "y")),
        ),
    );
    let forbid = engine(&forbid);
    assert!(!allows(&forbid, &[("a", &["x", "z"]), ("b", &["w", "y"])]));
    assert!(allows(&forbid, &[("a", &["x", "z"]), ("b", &["w"])]));

    // A permit must allow every value of each key.
    let permit = engine(&http_policy(
        "",
        "permit",
        &format!("{} && {}", tag_like("a", "x*"), tag_like("b", "y*")),
    ));
    assert!(allows(&permit, &[("a", &["x1", "x2"]), ("b", &["y1"])]));
    assert!(!allows(
        &permit,
        &[("a", &["x1", "x2"]), ("b", &["y1", "n"])]
    ));
}

#[test]
fn empty_values_are_matched_as_written() {
    let policy = format!(
        "{}{}",
        http_policy("", "permit", "true"),
        http_policy("", "forbid", &tag_like("name", "")),
    );
    let engine = engine(&policy);
    assert!(!allows(&engine, &[("name", &[""])]));
    assert!(allows(&engine, &[("name", &["present"])]));
}

#[test]
fn a_key_without_values_denies() {
    let engine = engine(&http_policy("", "permit", "!context.query.hasTag(\"tag\")"));
    assert!(allows(&engine, &[]));
    assert!(
        !allows(&engine, &[("tag", &[])]),
        "no combination to evaluate"
    );
}

#[test]
fn an_allow_names_the_permits_that_allowed_every_combination() {
    let policy = format!(
        "{}{}",
        http_policy(r#"@id("foo")"#, "permit", &tag_like("tag", "foo-*")),
        http_policy(r#"@id("any")"#, "permit", "true"),
    );
    let evaluation = engine(&policy)
        .evaluate_l7(&request(&[("tag", &["foo-a", "bar"])]))
        .unwrap();
    assert_eq!(
        evaluation.decision,
        Decision::Allow {
            matched_policies: vec!["any".to_string()]
        }
    );
}

#[test]
fn combinations_over_the_cap_are_not_evaluated() {
    let engine = engine(&http_policy(
        "",
        "permit",
        &format!("{} && {}", tag_like("a", "*"), tag_like("b", "*")),
    ));
    let values: Vec<String> = (0..9).map(|value| value.to_string()).collect();
    let values: Vec<&str> = values.iter().map(String::as_str).collect();
    assert!(allows(&engine, &[("a", &values[..8]), ("b", &values[..8])]));
    let error = engine
        .evaluate_l7(&request(&[("a", &values), ("b", &values[..8])]))
        .unwrap_err();
    assert!(
        matches!(
            error,
            CedarEngineError::TooManyQueryCombinations {
                combinations: 72,
                limit: MAX_QUERY_COMBINATIONS,
            }
        ),
        "{error}"
    );
}

#[test]
fn keys_no_policy_reads_do_not_multiply_evaluations() {
    let values: Vec<String> = (0..100).map(|value| value.to_string()).collect();
    let values: Vec<&str> = values.iter().map(String::as_str).collect();
    let engine_reading = |condition: &str| engine(&http_policy("", "permit", condition));

    assert!(allows(
        &engine_reading(&tag_like("tag", "*")),
        &[("tag", &["a"]), ("ids", &values)]
    ));
    // A computed key may be any key, so every key counts.
    let computed = engine_reading("!context.query.hasTag(context.method)");
    assert!(allows(&computed, &[("ids", &values[..2])]));
    assert!(matches!(
        computed.evaluate_l7(&request(&[("ids", &values)])),
        Err(CedarEngineError::TooManyQueryCombinations { .. })
    ));
}

#[test]
fn audit_endpoints_decide_over_every_combination() {
    let engine = engine(&http_policy(
        r#"@enforcement("audit")"#,
        "permit",
        &tag_like("tag", "foo-*"),
    ));
    let evaluation = engine
        .evaluate_l7(&request(&[("tag", &["foo-a", "evil"])]))
        .unwrap();
    assert!(!evaluation.is_allow(), "the relay logs this denial");
    assert_eq!(evaluation.staged, None);
}

#[test]
fn staged_audit_policies_combine_like_enforced_ones() {
    // A staged forbid that matches one value is reported.
    let staged_forbid = format!(
        "{}{}",
        http_policy("", "permit", "true"),
        http_policy(
            r#"@enforcement("audit") @id("no-force")"#,
            "forbid",
            &tag_like("force", "true"),
        ),
    );
    let evaluation = engine(&staged_forbid)
        .evaluate_l7(&request(&[("force", &["false", "true"])]))
        .unwrap();
    assert!(evaluation.is_allow(), "a staged forbid never denies");
    assert_eq!(
        evaluation.staged,
        Some(Decision::Deny {
            matched_policies: vec!["no-force".to_string()]
        })
    );

    // A staged permit that, with the enforced one, allows each value but not
    // every value would not allow the request, so nothing is staged.
    let staged_permit = format!(
        "{}{}",
        http_policy("", "permit", &tag_like("tag", "foo-*")),
        http_policy(
            r#"@enforcement("audit")"#,
            "permit",
            &tag_like("tag", "bar-*")
        ),
    );
    let engine = engine(&staged_permit);
    let evaluation = engine
        .evaluate_l7(&request(&[("tag", &["foo-a", "bar-b"])]))
        .unwrap();
    assert!(!evaluation.is_allow());
    assert_eq!(evaluation.staged, None);
    let evaluation = engine
        .evaluate_l7(&request(&[("tag", &["bar-a", "bar-b"])]))
        .unwrap();
    assert!(!evaluation.is_allow());
    assert!(
        matches!(evaluation.staged, Some(Decision::Allow { .. })),
        "{evaluation:?}"
    );
}

#[test]
fn query_is_not_part_of_network_connect() {
    let error = CedarEngine::from_policy_str(
        r#"permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { context.query.hasTag("tag") };"#,
    )
    .unwrap_err();
    assert!(
        matches!(error, CedarEngineError::PolicyValidation { .. }),
        "{error}"
    );
}

#[test]
fn get_tag_requires_has_tag() {
    let error = CedarEngine::from_policy_str(&http_policy(
        "",
        "permit",
        r#"context.query.getTag("tag") like "foo-*""#,
    ))
    .unwrap_err();
    assert!(
        matches!(error, CedarEngineError::PolicyValidation { .. }),
        "{error}"
    );
}
