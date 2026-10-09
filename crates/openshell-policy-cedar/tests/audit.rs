// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checks for `@enforcement("audit")` on `HttpRequest` policies: an endpoint
//! whose policies are all audit-only is an audit endpoint, and audit-only
//! policies on an enforced endpoint are staged and never change a decision.

use openshell_policy_cedar::{
    CedarEngine, CedarEngineError, Decision, L7Enforcement, L7Protocol, L7Request,
};

const ENDPOINT: &str = r#"Sandbox::NetworkEndpoint::"api.github.com:443""#;

fn engine(policy: &str) -> CedarEngine {
    CedarEngine::from_policy_str(policy).expect("policy must load")
}

/// An `HttpRequest` policy on the test endpoint.
fn http_policy(annotation: &str, effect: &str, condition: &str) -> String {
    format!(
        r#"{annotation}
{effect} (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"HttpRequest",
    resource  == {ENDPOINT}
)
when {{ {condition} }};
"#
    )
}

fn request(method: &str, path: &str) -> L7Request {
    L7Request {
        user: "sandbox".to_string(),
        group: "sandbox".to_string(),
        binary_path: "/usr/bin/curl".to_string(),
        ancestors: Vec::new(),
        host: "api.github.com".to_string(),
        port: 443,
        method: method.to_string(),
        path: path.to_string(),
        command: String::new(),
        jsonrpc_method: String::new(),
        ..Default::default()
    }
}

const AUDIT: &str = r#"@enforcement("audit")"#;
const GET_REPOS: &str = r#"context.method == "GET" && context.path like("/repos/**", "/")"#;

#[test]
fn an_endpoint_whose_policies_are_all_audit_only_is_an_audit_endpoint() {
    let engine = engine(&http_policy(AUDIT, "permit", GET_REPOS));
    let endpoint = engine
        .l7_endpoint("api.github.com", 443)
        .expect("endpoint is inspected");
    assert_eq!(endpoint.enforcement, L7Enforcement::Audit);
    assert_eq!(endpoint.protocol, L7Protocol::Rest);

    // The audit endpoint's own policies decide, so the relay can log the deny.
    let evaluation = engine
        .evaluate_l7(&request("DELETE", "/repos/a/b"))
        .unwrap();
    assert!(!evaluation.is_allow());
    assert_eq!(evaluation.staged, None);
    assert!(
        engine
            .evaluate_l7(&request("GET", "/repos/a/b"))
            .unwrap()
            .is_allow()
    );
}

#[test]
fn enforced_and_explicitly_enforced_endpoints_are_enforced() {
    for annotation in ["", r#"@enforcement("enforce")"#] {
        let engine = engine(&http_policy(annotation, "permit", GET_REPOS));
        assert_eq!(
            engine
                .l7_endpoint("api.github.com", 443)
                .unwrap()
                .enforcement,
            L7Enforcement::Enforce,
            "{annotation:?}"
        );
    }
}

#[test]
fn staged_audit_forbid_logs_without_denying() {
    let policy = format!(
        "{}{}",
        http_policy("", "permit", GET_REPOS),
        http_policy(
            &format!(r#"{AUDIT} @id("no-hooks")"#),
            "forbid",
            r#"context.path like("/repos/*/*/hooks", "/")"#
        ),
    );
    let engine = engine(&policy);
    assert_eq!(
        engine
            .l7_endpoint("api.github.com", 443)
            .unwrap()
            .enforcement,
        L7Enforcement::Enforce
    );

    let hooks = engine
        .evaluate_l7(&request("GET", "/repos/nvidia/openshell/hooks"))
        .unwrap();
    assert!(hooks.is_allow(), "a staged forbid never denies");
    assert!(
        matches!(&hooks.staged, Some(Decision::Deny { matched_policies }) if matched_policies == &["no-hooks"]),
        "{hooks:?}"
    );
}

#[test]
fn staged_audit_forbid_reports_nothing_when_it_does_not_match() {
    // Cedar denies by default, so evaluating the audit-only policies on their
    // own would deny this clean request. Only a changed decision is staged.
    let policy = format!(
        "{}{}",
        http_policy("", "permit", GET_REPOS),
        http_policy(
            AUDIT,
            "forbid",
            r#"context.path like("/repos/*/*/hooks", "/")"#
        ),
    );
    let evaluation = engine(&policy)
        .evaluate_l7(&request("GET", "/repos/nvidia/openshell"))
        .unwrap();
    assert!(evaluation.is_allow());
    assert_eq!(evaluation.staged, None);
}

#[test]
fn staged_audit_permit_logs_without_allowing() {
    let policy = format!(
        "{}{}",
        http_policy("", "permit", GET_REPOS),
        http_policy(AUDIT, "permit", r#"context.method == "POST""#),
    );
    let evaluation = engine(&policy)
        .evaluate_l7(&request("POST", "/repos/nvidia/openshell/issues"))
        .unwrap();
    assert!(!evaluation.is_allow(), "a staged permit never allows");
    assert!(
        matches!(evaluation.staged, Some(Decision::Allow { .. })),
        "{evaluation:?}"
    );
}

#[test]
fn audit_only_policies_never_affect_network_connect() {
    let policy = format!(
        r#"permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == {ENDPOINT}
);
{}"#,
        http_policy(AUDIT, "permit", GET_REPOS)
    );
    let decision = engine(&policy)
        .evaluate_network(&openshell_policy_cedar::NetworkRequest {
            user: "sandbox".to_string(),
            group: "sandbox".to_string(),
            host: "api.github.com".to_string(),
            port: 443,
            binary_path: "/usr/bin/curl".to_string(),
            ancestors: Vec::new(),
        })
        .unwrap();
    assert!(decision.is_allow());
}

#[test]
fn rejects_unknown_enforcement_values() {
    let error = CedarEngine::from_policy_str(&http_policy(
        r#"@enforcement("observe")"#,
        "permit",
        GET_REPOS,
    ))
    .expect_err("unknown value");
    assert!(
        matches!(error, CedarEngineError::UnsupportedEnforcement { .. }),
        "{error}"
    );
}

#[test]
fn rejects_enforcement_outside_http_request_only_policies() {
    for policy in [
        format!(
            r#"@enforcement("audit")
permit (principal, action == Sandbox::Action::"NetworkConnect", resource == {ENDPOINT});"#
        ),
        format!(
            r#"@enforcement("audit")
permit (
    principal,
    action in [Sandbox::Action::"NetworkConnect", Sandbox::Action::"HttpRequest"],
    resource == {ENDPOINT}
);"#
        ),
    ] {
        let error = CedarEngine::from_policy_str(&policy).expect_err("rejected");
        assert!(
            matches!(error, CedarEngineError::UnsupportedPolicy { .. }),
            "{error}"
        );
    }
}
