// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checks for `HttpRequest` policies that name their endpoint as a host glob
//! in their conditions, which inspects every host the glob matches, as a
//! YAML wildcard endpoint with request rules does.

use openshell_policy_cedar::{
    CedarEngine, CedarEngineError, Decision, HttpRequestInput, L7Enforcement, L7Protocol,
};

fn engine(policy: &str) -> CedarEngine {
    CedarEngine::from_policy_str(policy).expect("policy must load")
}

fn rejection(policy: &str) -> CedarEngineError {
    CedarEngine::from_policy_str(policy).expect_err("policy must be rejected")
}

/// An `HttpRequest` policy whose endpoint is `condition`, a host and port
/// condition, joined with `extra`.
fn glob_policy(annotations: &str, effect: &str, condition: &str, extra: &str) -> String {
    format!(
        r#"{annotations}
{effect} (principal, action == Sandbox::Action::"HttpRequest",
          resource is Sandbox::NetworkEndpoint)
when {{ {condition} && {extra} }};
"#
    )
}

const WILDCARD_443: &str = r#"resource.host like("*.example.com", ".") && resource.port == 443"#;

#[test]
fn oversized_selectors_are_rejected_before_overlap_analysis() {
    let host = "a".repeat(100_000);
    let scoped = format!(
        r#"permit (principal, action == Sandbox::Action::"HttpRequest",
              resource == Sandbox::NetworkEndpoint::"{host}:443");"#
    );
    assert!(matches!(
        rejection(&format!("{scoped}{scoped}")),
        CedarEngineError::InvalidEndpoint { .. }
    ));
    let glob = format!(r#"resource.host like("*.{host}.com", ".") && resource.port == 443"#);
    assert!(matches!(
        rejection(&glob_policy("", "permit", &glob, "true")),
        CedarEngineError::InvalidEndpoint { .. }
    ));
}

/// A request from curl to `host:443`, routed to the Cedar path `endpoint_path`.
fn request(host: &str, method: &str, path: &str, endpoint_path: &str) -> HttpRequestInput {
    HttpRequestInput {
        user: "sandbox".to_string(),
        group: "sandbox".to_string(),
        binary_path: "/usr/bin/curl".to_string(),
        host: host.to_string(),
        port: 443,
        method: method.to_string(),
        path: path.to_string(),
        endpoint_path: endpoint_path.to_string(),
        ..Default::default()
    }
}

/// `(path, protocol, enforcement)` for every inspected path of `host:443`.
fn inspected(engine: &CedarEngine, host: &str) -> Vec<(String, L7Protocol, L7Enforcement)> {
    engine
        .l7_endpoints(host, 443)
        .map(|(path, endpoint)| (path, endpoint.protocol, endpoint.enforcement))
        .collect()
}

#[test]
fn a_host_glob_inspects_every_matching_host() {
    let engine = engine(&glob_policy(
        "",
        "permit",
        WILDCARD_443,
        r#"context.method == "GET""#,
    ));
    for host in ["api.example.com", "other.example.com", "API.example.com."] {
        assert_eq!(
            engine.l7_protocol(host, 443),
            Some(L7Protocol::Rest),
            "{host} matches the glob"
        );
    }
    for host in ["example.com", "deep.api.example.com", "api.example.org"] {
        assert_eq!(
            engine.l7_protocol(host, 443),
            None,
            "{host} is outside the glob"
        );
    }
    assert_eq!(
        engine.l7_protocol("api.example.com", 8443),
        None,
        "another port is not inspected"
    );

    // The entity Cedar sees is the actual host, so the condition decides.
    let allowed = engine
        .evaluate_l7(&request("other.example.com", "GET", "/x", ""))
        .expect("evaluates");
    assert!(allowed.decision.is_allow(), "{allowed:?}");
    let denied = engine
        .evaluate_l7(&request("other.example.com", "POST", "/x", ""))
        .expect("evaluates");
    assert!(
        matches!(denied.decision, Decision::Deny { .. }),
        "{denied:?}"
    );
}

#[test]
fn configured_endpoints_preserve_host_globs_and_paths() {
    let engine = engine(&glob_policy(
        r#"@path("/mcp/**") @protocol("mcp")"#,
        "permit",
        WILDCARD_443,
        "true",
    ));
    let configured: Vec<_> = engine.configured_l7_endpoints().collect();
    assert_eq!(configured.len(), 1);
    assert_eq!(configured[0].0, "*.example.com");
    assert_eq!(configured[0].1, 443);
    assert_eq!(configured[0].2, "/mcp/**");
    assert_eq!(configured[0].3.protocol, L7Protocol::Mcp);
}

#[test]
fn a_forbid_with_a_host_glob_inspects_too() {
    let engine = engine(&glob_policy(
        "",
        "forbid",
        WILDCARD_443,
        r#"context.method == "DELETE""#,
    ));
    assert_eq!(
        engine.l7_protocol("api.example.com", 443),
        Some(L7Protocol::Rest)
    );
}

#[test]
fn rejects_host_conditions_the_proxy_cannot_route() {
    let cases = [
        // Undelimited `like`: `*` would cross labels.
        r#"resource.host like "*.example.com" && resource.port == 443"#,
        // A wildcard top-level domain, rejected for YAML hosts too.
        r#"resource.host like("*.com", ".") && resource.port == 443"#,
        // No port.
        r#"resource.host like("*.example.com", ".")"#,
        // Hosts joined with `||` are not one glob.
        r#"(resource.host like("*.example.com", ".") || resource.host like("*.example.org", "."))
           && resource.port == 443"#,
        // Two host conjuncts.
        r#"resource.host like("*.example.com", ".") && resource.host like("**.example.com", ".")
           && resource.port == 443"#,
        // A port set is not one port.
        r#"resource.host like("*.example.com", ".") && [443, 8443].contains(resource.port)"#,
        // An exact host belongs in the scope.
        r#"resource.host == "api.example.com" && resource.port == 443"#,
        // A `*` outside the first label.
        r#"resource.host like("api.*-prod.example.com", ".") && resource.port == 443"#,
    ];
    for condition in cases {
        let policy = glob_policy("", "permit", condition, r#"context.method == "GET""#);
        let error = rejection(&policy);
        assert!(
            matches!(&error, CedarEngineError::UnsupportedPolicy { reason, .. }
                if reason.contains("must name its endpoint")),
            "{condition}: {error}"
        );
    }
}

#[test]
fn glob_endpoints_take_paths_protocols_and_enforcement() {
    let policy = format!(
        "{}{}{}",
        glob_policy("", "permit", WILDCARD_443, r#"context.method == "GET""#),
        glob_policy(
            r#"@path("/graphql") @protocol("graphql")"#,
            "permit",
            WILDCARD_443,
            r#"context.path == "/graphql" && context.graphql_operation_type == "query""#
        ),
        glob_policy(
            r#"@path("/legacy/**") @enforcement("audit")"#,
            "permit",
            WILDCARD_443,
            r#"context.path like("/legacy/**", "/")"#
        ),
    );
    let engine = engine(&policy);
    assert_eq!(
        inspected(&engine, "other.example.com"),
        vec![
            (String::new(), L7Protocol::Rest, L7Enforcement::Enforce),
            (
                "/graphql".to_string(),
                L7Protocol::Graphql,
                L7Enforcement::Enforce
            ),
            (
                "/legacy/**".to_string(),
                L7Protocol::Rest,
                L7Enforcement::Audit
            ),
        ]
    );
    assert_eq!(
        engine
            .l7_endpoint_at("api.example.com", 443, "/graphql")
            .map(|endpoint| endpoint.protocol),
        Some(L7Protocol::Graphql)
    );
    assert!(inspected(&engine, "example.com").is_empty());
    for operation in ["query", "mutation"] {
        let request = HttpRequestInput {
            graphql_request: true,
            graphql_operation_type: operation.to_string(),
            ..request("other.example.com", "GET", "/graphql", "/graphql")
        };
        assert_eq!(
            engine.evaluate_l7(&request).unwrap().is_allow(),
            operation == "query",
            "a REST host-glob permit must not allow a GraphQL {operation}"
        );
    }
}

#[test]
fn an_exact_endpoint_and_a_matching_glob_inspect_a_host_together() {
    let policy = format!(
        r#"{}
@path("/api/**")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when {{ context.method == "GET" && context.path like("/api/**", "/") }};
"#,
        glob_policy("", "permit", WILDCARD_443, r#"context.method == "GET""#),
    );
    let engine = engine(&policy);
    assert_eq!(
        inspected(&engine, "api.example.com"),
        vec![
            (String::new(), L7Protocol::Rest, L7Enforcement::Enforce),
            (
                "/api/**".to_string(),
                L7Protocol::Rest,
                L7Enforcement::Enforce
            ),
        ],
        "the exact host gets the glob's paths and its own"
    );
    assert_eq!(
        inspected(&engine, "other.example.com"),
        vec![(String::new(), L7Protocol::Rest, L7Enforcement::Enforce)],
        "another matching host gets only the glob's paths"
    );
}

#[test]
fn rejects_overlapping_globs_that_inspect_a_path_differently() {
    let policy = format!(
        "{}{}",
        glob_policy("", "permit", WILDCARD_443, "true"),
        glob_policy(
            r#"@protocol("json-rpc")"#,
            "permit",
            r#"resource.host like("**.example.com", ".") && resource.port == 443"#,
            "true"
        ),
    );
    let error = rejection(&policy);
    assert!(
        matches!(&error, CedarEngineError::AmbiguousL7Hosts { first, second, first_path, second_path }
            if [first.as_str(), second.as_str()].contains(&"*.example.com:443")
                && [first.as_str(), second.as_str()].contains(&"**.example.com:443")
                && first_path.is_empty() && second_path.is_empty()),
        "{error}"
    );

    // Equally specific overlapping paths conflict too.
    let policy = format!(
        "{}{}",
        glob_policy(
            r#"@path("/v1/**") @protocol("json-rpc")"#,
            "permit",
            WILDCARD_443,
            "true"
        ),
        glob_policy(
            r#"@path("/v1/**") @enforcement("audit")"#,
            "permit",
            r#"resource.host like("**.example.com", ".") && resource.port == 443"#,
            "true"
        ),
    );
    assert!(
        matches!(
            rejection(&policy),
            CedarEngineError::AmbiguousL7Hosts { .. }
        ),
        "{policy}"
    );
}

#[test]
fn rejects_an_exact_endpoint_that_inspects_a_glob_path_differently() {
    let policy = format!(
        r#"{}
@protocol("json-rpc")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
"#,
        glob_policy("", "permit", WILDCARD_443, "true"),
    );
    assert!(
        matches!(
            rejection(&policy),
            CedarEngineError::AmbiguousL7Hosts { .. }
        ),
        "{policy}"
    );
}

#[test]
fn accepts_entries_that_cannot_select_one_host_or_agree() {
    // Disjoint globs with different protocols.
    let policy = format!(
        "{}{}",
        glob_policy("", "permit", WILDCARD_443, "true"),
        glob_policy(
            r#"@protocol("json-rpc")"#,
            "permit",
            r#"resource.host like("*.example.org", ".") && resource.port == 443"#,
            "true"
        ),
    );
    let disjoint = engine(&policy);
    assert_eq!(
        disjoint.l7_protocol("rpc.example.org", 443),
        Some(L7Protocol::JsonRpc)
    );
    assert_eq!(
        disjoint.l7_protocol("api.example.com", 443),
        Some(L7Protocol::Rest)
    );

    // Overlapping globs on different ports.
    let policy = format!(
        "{}{}",
        glob_policy("", "permit", WILDCARD_443, "true"),
        glob_policy(
            r#"@protocol("json-rpc")"#,
            "permit",
            r#"resource.host like("**.example.com", ".") && resource.port == 8443"#,
            "true"
        ),
    );
    engine(&policy);

    // Overlapping globs that inspect the same way, or paths of different
    // specificity.
    let policy = format!(
        "{}{}{}",
        glob_policy("", "permit", WILDCARD_443, "true"),
        glob_policy(
            "",
            "forbid",
            r#"resource.host like("**.example.com", ".") && resource.port == 443"#,
            r#"context.method == "DELETE""#
        ),
        glob_policy(
            r#"@path("/rpc") @protocol("json-rpc")"#,
            "permit",
            r#"resource.host like("**.example.com", ".") && resource.port == 443"#,
            r#"context.path == "/rpc""#
        ),
    );
    let agreeing = engine(&policy);
    assert_eq!(
        inspected(&agreeing, "api.example.com"),
        vec![
            (String::new(), L7Protocol::Rest, L7Enforcement::Enforce),
            (
                "/rpc".to_string(),
                L7Protocol::JsonRpc,
                L7Enforcement::Enforce
            ),
        ]
    );
}

#[test]
fn a_glob_inspected_endpoint_cannot_also_be_native_tcp() {
    let policy = format!(
        r#"{}
@transport("tcp")
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"db.example.com:443");
"#,
        glob_policy("", "permit", WILDCARD_443, "true"),
    );
    assert!(
        matches!(
            rejection(&policy),
            CedarEngineError::ConflictingTransport { .. }
        ),
        "{policy}"
    );
}
