// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checks for `@path` on `HttpRequest` policies, which gives one
//! `host:port` a protocol and enforcement per path, and for the WebSocket
//! protocols.

use openshell_policy_cedar::{CedarEngine, CedarEngineError, L7Enforcement, L7Protocol, L7Request};

const HOST: &str = "api.example.com";

fn engine(policy: &str) -> CedarEngine {
    CedarEngine::from_policy_str(policy).expect("policy must load")
}

fn rejection(policy: &str) -> CedarEngineError {
    CedarEngine::from_policy_str(policy).expect_err("policy must be rejected")
}

/// An `HttpRequest` policy on the test endpoint.
fn http_policy(annotations: &str, effect: &str, condition: &str) -> String {
    format!(
        r#"{annotations}
{effect} (principal, action == Sandbox::Action::"HttpRequest",
          resource == Sandbox::NetworkEndpoint::"{HOST}:443")
when {{ {condition} }};
"#
    )
}

/// A request routed to the Cedar path `endpoint_path`.
fn request(method: &str, path: &str, endpoint_path: &str) -> L7Request {
    L7Request {
        user: "sandbox".to_string(),
        group: "sandbox".to_string(),
        binary_path: "/usr/bin/curl".to_string(),
        host: HOST.to_string(),
        port: 443,
        method: method.to_string(),
        path: path.to_string(),
        endpoint_path: endpoint_path.to_string(),
        ..Default::default()
    }
}

/// `(path, protocol, enforcement)` for every inspected path of the endpoint.
fn inspected(engine: &CedarEngine) -> Vec<(String, L7Protocol, L7Enforcement)> {
    engine
        .l7_endpoints(HOST, 443)
        .map(|(path, endpoint)| (path.to_string(), endpoint.protocol, endpoint.enforcement))
        .collect()
}

#[test]
fn each_path_is_inspected_with_its_own_protocol() {
    let policy = format!(
        "{}{}",
        http_policy(
            r#"@path("/repos/**")"#,
            "permit",
            r#"context.path like("/repos/**", "/")"#
        ),
        http_policy(
            r#"@path("/graphql") @protocol("graphql")"#,
            "permit",
            r#"context.graphql_operation_type == "query""#
        ),
    );
    let engine = engine(&policy);
    assert_eq!(
        inspected(&engine),
        vec![
            (
                "/graphql".to_string(),
                L7Protocol::Graphql,
                L7Enforcement::Enforce
            ),
            (
                "/repos/**".to_string(),
                L7Protocol::Rest,
                L7Enforcement::Enforce
            ),
        ]
    );
    assert_eq!(
        engine.l7_endpoint(HOST, 443),
        None,
        "no policy without @path"
    );
    assert_eq!(
        engine
            .l7_endpoint_at("API.example.com.", 443, "/graphql")
            .map(|endpoint| endpoint.protocol),
        Some(L7Protocol::Graphql),
        "lookup normalizes the requested host"
    );
}

#[test]
fn policies_without_a_path_declare_the_path_less_endpoint() {
    let policy = format!(
        "{}{}",
        http_policy(r#"@protocol("json-rpc")"#, "permit", "true"),
        http_policy(
            r#"@path("/v1/**")"#,
            "forbid",
            r#"context.method == "DELETE""#
        ),
    );
    let engine = engine(&policy);
    assert_eq!(
        inspected(&engine),
        vec![
            (String::new(), L7Protocol::JsonRpc, L7Enforcement::Enforce),
            (
                "/v1/**".to_string(),
                L7Protocol::Rest,
                L7Enforcement::Enforce
            ),
        ]
    );
}

#[test]
fn path_selects_inspection_but_not_which_policies_apply() {
    // The /admin forbid applies to a request routed to any path; only its
    // condition limits it.
    let policy = format!(
        "{}{}",
        http_policy(r#"@path("/api/**")"#, "permit", "true"),
        http_policy(
            r#"@path("/admin/**")"#,
            "forbid",
            r#"context.method == "DELETE""#
        ),
    );
    let engine = engine(&policy);
    let evaluate = |method, path, endpoint_path| {
        engine
            .evaluate_l7(&request(method, path, endpoint_path))
            .unwrap()
            .is_allow()
    };
    assert!(!evaluate("DELETE", "/admin/x", "/admin/**"));
    assert!(!evaluate("DELETE", "/api/x", "/api/**"));
    assert!(evaluate("GET", "/api/x", "/api/**"));
}

#[test]
fn enforcement_is_computed_per_path() {
    let policy = format!(
        "{}{}{}",
        http_policy(
            r#"@path("/graphql") @protocol("graphql") @enforcement("audit")"#,
            "permit",
            r#"context.path == "/graphql" && context.graphql_operation_type == "query""#
        ),
        http_policy(
            r#"@path("/api/**")"#,
            "permit",
            r#"context.method == "GET" && context.path like("/api/**", "/")"#
        ),
        http_policy(
            r#"@path("/api/**") @enforcement("audit") @id("no-delete")"#,
            "forbid",
            r#"context.path like("/api/private/**", "/")"#
        ),
    );
    let engine = engine(&policy);
    assert_eq!(
        inspected(&engine),
        vec![
            (
                "/api/**".to_string(),
                L7Protocol::Rest,
                L7Enforcement::Enforce
            ),
            (
                "/graphql".to_string(),
                L7Protocol::Graphql,
                L7Enforcement::Audit
            ),
        ]
    );

    // Routed to the audit path, every policy decides, so the relay can log
    // the denial it then forwards.
    let mut mutation = request("POST", "/graphql", "/graphql");
    mutation.graphql_operation_type = "mutation".to_string();
    let evaluation = engine.evaluate_l7(&mutation).unwrap();
    assert!(!evaluation.is_allow());
    assert_eq!(evaluation.staged, None);

    // Routed to the enforced path, its audit-only forbid is staged.
    let private = engine
        .evaluate_l7(&request("GET", "/api/private/x", "/api/**"))
        .unwrap();
    assert!(private.is_allow());
    assert!(private.staged.is_some_and(|staged| !staged.is_allow()));
}

#[test]
fn resource_protocol_is_the_routed_paths_protocol() {
    let policy = format!(
        "{}{}",
        http_policy(
            r#"@path("/graphql") @protocol("graphql")"#,
            "permit",
            r#"resource.protocol == "graphql""#
        ),
        http_policy(
            r#"@path("/ws") @protocol("websocket-graphql")"#,
            "permit",
            "false"
        ),
    );
    let engine = engine(&policy);
    let allowed = |endpoint_path| {
        engine
            .evaluate_l7(&request("POST", "/graphql", endpoint_path))
            .unwrap()
            .is_allow()
    };
    assert!(allowed("/graphql"));
    assert!(!allowed("/ws"));
}

#[test]
fn websocket_protocols_are_accepted() {
    for (annotation, protocol, config_label, graphql_messages) in [
        ("websocket", L7Protocol::Websocket, "websocket", false),
        (
            "websocket-graphql",
            L7Protocol::WebsocketGraphql,
            "websocket",
            true,
        ),
    ] {
        let engine = engine(&http_policy(
            &format!(r#"@protocol("{annotation}")"#),
            "permit",
            r#"context.method == "GET" || context.method == "WEBSOCKET_TEXT""#,
        ));
        let declared = engine.l7_protocol(HOST, 443).expect("inspected");
        assert_eq!(declared, protocol, "{annotation}");
        assert_eq!(declared.as_str(), annotation);
        assert_eq!(declared.config_label(), config_label);
        assert_eq!(declared.websocket_graphql_messages(), graphql_messages);
    }
}

#[test]
fn rejects_conflicting_protocols_for_one_path_only() {
    let error = rejection(&format!(
        "{}{}",
        http_policy(r#"@path("/rpc") @protocol("json-rpc")"#, "permit", "true"),
        http_policy(r#"@path("/rpc") @protocol("mcp")"#, "permit", "true"),
    ));
    assert!(
        matches!(&error, CedarEngineError::ConflictingL7Protocol { endpoint, .. }
            if endpoint == "api.example.com:443/rpc"),
        "{error}"
    );
}

#[test]
fn rejects_invalid_paths() {
    for path in ["", "repos/**", "*"] {
        let error = rejection(&http_policy(
            &format!(r#"@path("{path}")"#),
            "permit",
            "true",
        ));
        assert!(
            matches!(error, CedarEngineError::InvalidL7Path { .. }),
            "{path:?}: {error}"
        );
    }
    for path in ["**", "/**", "/v1/*/items", "/graphql"] {
        engine(&http_policy(
            &format!(r#"@path("{path}")"#),
            "permit",
            "true",
        ));
    }
}

#[test]
fn rejects_path_on_other_actions() {
    let error = rejection(
        r#"
@path("/v1/**")
permit(principal, action == Sandbox::Action::"NetworkConnect",
       resource == Sandbox::NetworkEndpoint::"api.example.com:443");
"#,
    );
    assert!(
        matches!(error, CedarEngineError::UnsupportedPolicy { .. }),
        "{error}"
    );
}

#[test]
fn rejects_equally_specific_overlapping_paths_that_inspect_differently() {
    let policy = |first: &str, second: &str, second_protocol: &str| {
        format!(
            "{}{}",
            http_policy(&format!(r#"@path("{first}")"#), "permit", "true"),
            http_policy(
                &format!(r#"@path("{second}") @protocol("{second_protocol}")"#),
                "permit",
                "true"
            ),
        )
    };
    // `""` and `**` both match every path with no specificity.
    for (first, second) in [("/a/*", "/*/b"), ("/ab/**", "/ab/*")] {
        let error = rejection(&policy(first, second, "graphql"));
        assert!(
            matches!(error, CedarEngineError::AmbiguousL7Paths { .. }),
            "{first} {second}: {error}"
        );
    }
    let error = rejection(&format!(
        "{}{}",
        http_policy("", "permit", "true"),
        http_policy(r#"@path("**") @protocol("mcp")"#, "permit", "true"),
    ));
    assert!(
        matches!(error, CedarEngineError::AmbiguousL7Paths { .. }),
        "{error}"
    );

    // Literal paths that differ never match one request, and paths with the
    // same inspection agree whichever the relay picks.
    engine(&policy("/rest", "/rpcs", "json-rpc"));
    engine(&policy("/a/*", "/*/b", "rest"));
    engine(&policy("/x/**", "/y/**", "graphql"));
}
