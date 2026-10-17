// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checks for `@path` on `HttpRequest` policies, which gives one
//! `host:port` a protocol and enforcement per path, and for the WebSocket
//! protocols.

use openshell_policy_cedar::{
    AnalysisWarning, CedarEngine, CedarEngineError, Decision, HttpRequestInput, L7Enforcement,
    L7Protocol,
};

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
fn request(method: &str, path: &str, endpoint_path: &str) -> HttpRequestInput {
    HttpRequestInput {
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
        .map(|(path, endpoint)| (path, endpoint.protocol, endpoint.enforcement))
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
    // An audit path beside an enforced path: as with YAML endpoints sharing
    // a host:port, the routed path's mode decides whether a denial blocks.
    // The audit path is reported as a warning. A staged forbid on the
    // enforced path never decides.
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
            r#"@path("/api/**") @enforcement("staged") @id("no-delete")"#,
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
    assert_eq!(
        engine.warnings(),
        [AnalysisWarning::AuditPathOnEnforcedEndpoint {
            endpoint: format!("{HOST}:443"),
            path: "/graphql".to_string(),
        }]
    );
    let warning = engine.warnings()[0].to_string();
    assert!(
        warning.starts_with(&format!("path `/graphql` of {HOST}:443 is audit-only")),
        "{warning}"
    );

    // Routed to the audit path, every deciding policy decides, so the relay
    // can log the denial it then forwards.
    let mut mutation = request("POST", "/graphql", "/graphql");
    mutation.graphql_operation_type = "mutation".to_string();
    mutation.graphql_request = true;
    let evaluation = engine.evaluate_l7(&mutation).unwrap();
    assert!(!evaluation.is_allow());
    assert_eq!(evaluation.staged, None);

    // Routed to the enforced path, its staged forbid is only compared.
    let private = engine
        .evaluate_l7(&request("GET", "/api/private/x", "/api/**"))
        .unwrap();
    assert!(private.is_allow());
    assert!(private.staged.is_some_and(|staged| !staged.is_allow()));
}

#[test]
fn enforced_path_less_forbid_does_not_block_on_an_audit_only_path() {
    // `/admin/**` is an audit path: the enforced forbid's denial is
    // returned, and the relay logs and forwards the request, as YAML does for
    // a request routed to an `enforcement: audit` endpoint. The load-time
    // warning tells the author. The audit path's own forbid decides requests
    // routed to the enforced path-less endpoint.
    let policy = format!(
        "{}{}{}",
        http_policy("", "permit", r#"context.method == "GET""#),
        http_policy(
            r#"@id("no-admin")"#,
            "forbid",
            r#"context.path like("/admin/**", "/")"#
        ),
        http_policy(
            r#"@path("/admin/**") @enforcement("audit")"#,
            "forbid",
            r#"context.method == "DELETE""#
        ),
    );
    let engine = engine(&policy);
    assert_eq!(
        inspected(&engine),
        vec![
            (String::new(), L7Protocol::Rest, L7Enforcement::Enforce),
            (
                "/admin/**".to_string(),
                L7Protocol::Rest,
                L7Enforcement::Audit
            ),
        ]
    );
    assert_eq!(
        engine.warnings(),
        [AnalysisWarning::AuditPathOnEnforcedEndpoint {
            endpoint: format!("{HOST}:443"),
            path: "/admin/**".to_string(),
        }]
    );
    let evaluation = engine
        .evaluate_l7(&request("GET", "/admin/users", "/admin/**"))
        .unwrap();
    assert!(
        !evaluation.is_allow(),
        "the enforced forbid denies; the audit path forwards the denial"
    );
    assert_eq!(evaluation.staged, None, "nothing is staged");
    let evaluation = engine
        .evaluate_l7(&request("DELETE", "/users/1", ""))
        .unwrap();
    assert!(
        !evaluation.is_allow(),
        "the audit path's forbid blocks a request routed to the enforced path-less endpoint"
    );
    assert!(
        engine.warnings()[0]
            .to_string()
            .contains("@enforcement(\"staged\")"),
        "the warning names the staging annotation"
    );

    // The path-less endpoint can be the audit-only one too.
    let policy = format!(
        "{}{}",
        http_policy(r#"@enforcement("audit")"#, "permit", "true"),
        http_policy(
            r#"@path("/api/**")"#,
            "permit",
            r#"context.method == "GET""#
        ),
    );
    let path_less = CedarEngine::from_policy_str(&policy).expect("policy must load");
    assert_eq!(
        path_less.warnings(),
        [AnalysisWarning::AuditPathOnEnforcedEndpoint {
            endpoint: format!("{HOST}:443"),
            path: String::new(),
        }]
    );
    assert!(
        path_less.warnings()[0].to_string().starts_with(&format!(
            "the path-less endpoint of {HOST}:443 is audit-only"
        )),
        "{}",
        path_less.warnings()[0]
    );
}

#[test]
fn no_warning_for_an_all_enforced_or_all_audit_endpoint() {
    // Enforced paths, with a staged policy on one of them.
    let enforced = format!(
        "{}{}{}",
        http_policy(
            r#"@path("/api/**")"#,
            "permit",
            r#"context.method == "GET""#
        ),
        http_policy(
            r#"@path("/api/**") @enforcement("staged")"#,
            "forbid",
            r#"context.method == "DELETE""#
        ),
        http_policy(
            r#"@path("/graphql") @protocol("graphql")"#,
            "permit",
            "true"
        ),
    );
    assert_eq!(engine(&enforced).warnings(), []);

    // Audit-only paths with no enforced policy anywhere on the endpoint.
    let audited = format!(
        "{}{}",
        http_policy(
            r#"@enforcement("audit")"#,
            "permit",
            r#"context.method == "GET""#
        ),
        http_policy(
            r#"@path("/api/**") @enforcement("audit")"#,
            "forbid",
            r#"context.method == "DELETE""#
        ),
    );
    assert_eq!(engine(&audited).warnings(), []);
}

#[test]
fn an_endpoint_of_only_audit_policies_audits_every_path() {
    let policy = format!(
        "{}{}{}",
        http_policy(
            r#"@enforcement("audit")"#,
            "permit",
            r#"context.method == "GET""#
        ),
        http_policy(
            r#"@path("/graphql") @protocol("graphql") @enforcement("audit")"#,
            "permit",
            r#"context.graphql_operation_type == "query""#
        ),
        http_policy(
            r#"@path("/api/**") @enforcement("audit")"#,
            "forbid",
            r#"context.method == "DELETE""#
        ),
    );
    let engine = engine(&policy);
    assert_eq!(
        inspected(&engine),
        vec![
            (String::new(), L7Protocol::Rest, L7Enforcement::Audit),
            (
                "/api/**".to_string(),
                L7Protocol::Rest,
                L7Enforcement::Audit
            ),
            (
                "/graphql".to_string(),
                L7Protocol::Graphql,
                L7Enforcement::Audit
            ),
        ]
    );
    // On an audit endpoint every deciding policy decides, so the relay can
    // log the denial it then forwards, and nothing is staged.
    let evaluation = engine
        .evaluate_l7(&request("DELETE", "/api/x", "/api/**"))
        .unwrap();
    assert!(!evaluation.is_allow());
    assert_eq!(evaluation.staged, None);
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
            r#"context.method == "GET"
               || (context.method == "WEBSOCKET_TEXT" && context.graphql_operation_type == "query")"#,
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

#[test]
fn rejects_a_generic_message_permit_on_a_websocket_graphql_path() {
    // YAML rejects a `WEBSOCKET_TEXT` rule on a WebSocket endpoint with
    // GraphQL operation policy, so a permit that could allow a message
    // without a GraphQL condition is rejected.
    let ws = r#"@path("/ws") @protocol("websocket-graphql") @id("ws")"#;
    for condition in [
        "true",
        r#"context.path == "/ws""#,
        r#"context.method == "WEBSOCKET_TEXT""#,
        r#"context.method == "GET" || context.method == "WEBSOCKET_TEXT""#,
        r#"["GET", "WEBSOCKET_TEXT"].contains(context.method)"#,
        r#"context.method != "POST""#,
        // A message disjunct without a GraphQL condition beside one with.
        r#"context.method == "GET" || context.method == "WEBSOCKET_TEXT"
           || (context.graphql_operation_type == "query" && context.graphql_fields.contains("viewer"))"#,
        r#"context.graphql_operation_type == "query" || context.method == "WEBSOCKET_TEXT""#,
        r#"context.graphql_operation_type == "query" || context.path == "/ws""#,
        r#"!(context.method == "GET") && context.path == "/ws""#,
        r#"if context.method == "GET" then true else context.path == "/ws""#,
    ] {
        let error = rejection(&http_policy(ws, "permit", condition));
        assert!(
            matches!(&error, CedarEngineError::GenericWebsocketGraphqlPermit { policy_id, path }
                if policy_id == "ws" && path == "/ws"),
            "{condition}: {error}"
        );
    }
    // The protocol may come from another policy of the path.
    let error = rejection(&format!(
        "{}{}",
        http_policy(
            r#"@path("/ws") @protocol("websocket-graphql")"#,
            "forbid",
            "false"
        ),
        http_policy(
            r#"@path("/ws") @id("upgrade")"#,
            "permit",
            r#"context.path == "/ws""#
        ),
    ));
    assert!(
        matches!(&error, CedarEngineError::GenericWebsocketGraphqlPermit { policy_id, .. }
            if policy_id == "upgrade"),
        "{error}"
    );
    // Permits that condition on a GraphQL field, pin the method away from
    // WEBSOCKET_TEXT in a top-level conjunct, or sit on another protocol
    // load; so do forbids.
    for (annotations, effect, condition) in [
        (
            ws,
            "permit",
            r#"context.graphql_operation_type == "subscription""#,
        ),
        // Every disjunct reads a GraphQL field.
        (
            ws,
            "permit",
            r#"context.graphql_operation_type == "query" || context.graphql_fields.contains("messageAdded")"#,
        ),
        (
            ws,
            "permit",
            r#"(context.method == "WEBSOCKET_TEXT" && context.graphql_operation_type == "query")
               || (context.path == "/ws" && context.graphql_operation_name == "Feed")"#,
        ),
        (
            ws,
            "permit",
            r#"context.method == "GET" || (context.method == "WEBSOCKET_TEXT" && context.graphql_fields.contains("x"))"#,
        ),
        (
            ws,
            "permit",
            r#"context.method == "GET" && context.path == "/ws""#,
        ),
        (ws, "permit", r#""GET" == context.method"#),
        (ws, "permit", r#"["GET", "HEAD"].contains(context.method)"#),
        (ws, "permit", "false"),
        (
            ws,
            "permit",
            r#"context.path == "/ws" && !(context.method != "GET")"#,
        ),
        (
            ws,
            "permit",
            r#"if context.method == "GET" then context.path == "/ws" else context.graphql_operation_type == "query""#,
        ),
        (
            ws,
            "permit",
            r#"context.path == "/ws" && (context.method == "GET" || !(context.graphql_operation_type == "mutation"))"#,
        ),
        (ws, "forbid", "true"),
        (r#"@path("/ws") @protocol("websocket")"#, "permit", "true"),
        (
            r#"@path("/graphql") @protocol("graphql")"#,
            "permit",
            "true",
        ),
    ] {
        engine(&http_policy(annotations, effect, condition));
    }
}

/// A broad REST path beside a GraphQL path, with `rest_scope` appended to
/// the REST permit's condition.
fn rest_and_graphql(rest_scope: &str) -> String {
    format!(
        "{}{}{}",
        http_policy(
            r#"@path("/**") @id("rest")"#,
            "permit",
            &format!(r#"context.method == "GET" && context.path like("/**", "/"){rest_scope}"#)
        ),
        http_policy(
            r#"@path("/graphql") @protocol("graphql") @id("graphql")"#,
            "permit",
            r#"context.path == "/graphql" && context.graphql_operation_type == "query""#
        ),
        http_policy(
            r#"@path("/**") @id("no-delete")"#,
            "forbid",
            r#"context.graphql_fields.contains("deleteRepository")"#
        ),
    )
}

/// A GraphQL `operation` with `fields`, sent as `GET /graphql`.
fn graphql(operation: &str, fields: &[&str]) -> HttpRequestInput {
    HttpRequestInput {
        graphql_operation_type: operation.to_string(),
        graphql_fields: fields.iter().map(ToString::to_string).collect(),
        graphql_request: true,
        ..request("GET", "/graphql", "/graphql")
    }
}

#[test]
fn a_graphql_path_is_authoritative_for_the_requests_it_parses() {
    // A permit of another path that is not aware of GraphQL never allows a
    // GraphQL operation, as a YAML GraphQL endpoint is authoritative for the
    // requests it parses. Forbids still apply.
    let engine = engine(&rest_and_graphql(""));
    let mutation = engine
        .evaluate_l7(&graphql("mutation", &["createIssue"]))
        .unwrap();
    assert_eq!(
        mutation.decision,
        Decision::Deny {
            matched_policies: Vec::new()
        },
        "the REST permit is left out"
    );
    let query = engine.evaluate_l7(&graphql("query", &["viewer"])).unwrap();
    assert!(
        matches!(&query.decision, Decision::Allow { matched_policies } if matched_policies == &["graphql"]),
        "{query:?}"
    );
    let delete = engine
        .evaluate_l7(&graphql("query", &["deleteRepository"]))
        .unwrap();
    assert!(
        matches!(&delete.decision, Decision::Deny { matched_policies } if matched_policies == &["no-delete"]),
        "{delete:?}"
    );
    // A request on the GraphQL path the proxy did not parse as GraphQL, and
    // requests on the REST path, see every permit.
    let plain = HttpRequestInput {
        graphql_request: false,
        ..request("GET", "/graphql", "/graphql")
    };
    assert!(engine.evaluate_l7(&plain).unwrap().is_allow());
    assert!(
        engine
            .evaluate_l7(&request("GET", "/repos", "/**"))
            .unwrap()
            .is_allow()
    );
}

#[test]
fn graphql_aware_permits_of_other_paths_still_apply() {
    for rest_scope in [
        r#" && resource.protocol != "sql""#,
        r#" && context.graphql_operation_type != "subscription""#,
    ] {
        let engine = engine(&rest_and_graphql(rest_scope));
        let mutation = engine
            .evaluate_l7(&graphql("mutation", &["createIssue"]))
            .unwrap();
        assert!(
            matches!(&mutation.decision, Decision::Allow { matched_policies } if matched_policies == &["rest"]),
            "{rest_scope}: {mutation:?}"
        );
    }
    // A permit attached to the GraphQL path itself always applies.
    let own = format!(
        "{}{}",
        http_policy(
            r#"@path("/graphql") @protocol("graphql") @id("all")"#,
            "permit",
            r#"context.path == "/graphql""#
        ),
        http_policy(r#"@path("/**")"#, "permit", "false"),
    );
    let evaluation = engine(&own)
        .evaluate_l7(&graphql("mutation", &["x"]))
        .unwrap();
    assert!(evaluation.is_allow(), "{evaluation:?}");
}

#[test]
fn other_resource_attributes_do_not_make_rest_permits_graphql_aware() {
    for rest_scope in [
        " && resource.port == 443",
        " && resource has port",
        r#" && resource.host like("*.example.com", ".")"#,
        r#" && resource == Sandbox::NetworkEndpoint::"api.example.com:443""#,
        " && resource == resource",
    ] {
        let engine = engine(&rest_and_graphql(rest_scope));
        assert!(
            !engine
                .evaluate_l7(&graphql("mutation", &["createIssue"]))
                .unwrap()
                .is_allow(),
            "{rest_scope}"
        );
        assert!(
            engine
                .evaluate_l7(&graphql("query", &["viewer"]))
                .unwrap()
                .is_allow(),
            "{rest_scope}"
        );
    }
}

#[test]
fn websocket_graphql_messages_are_authoritative_but_the_upgrade_is_not() {
    let policy = format!(
        "{}{}",
        http_policy(
            r#"@path("/**") @id("rest")"#,
            "permit",
            r#"["GET", "WEBSOCKET_TEXT"].contains(context.method) && resource.port == 443"#
        ),
        http_policy(
            r#"@path("/ws") @protocol("websocket-graphql") @id("ws")"#,
            "permit",
            r#"context.path == "/ws" && context.graphql_operation_type == "subscription""#
        ),
    );
    let engine = engine(&policy);
    // The upgrade is a GET the proxy does not parse as GraphQL.
    let upgrade = engine.evaluate_l7(&request("GET", "/ws", "/ws")).unwrap();
    assert!(
        matches!(&upgrade.decision, Decision::Allow { matched_policies } if matched_policies == &["rest"]),
        "{upgrade:?}"
    );
    let message = |operation: &str| HttpRequestInput {
        graphql_operation_type: operation.to_string(),
        graphql_request: true,
        ..request("WEBSOCKET_TEXT", "/ws", "/ws")
    };
    assert!(
        matches!(&engine.evaluate_l7(&message("subscription")).unwrap().decision,
            Decision::Allow { matched_policies } if matched_policies == &["ws"])
    );
    assert!(!engine.evaluate_l7(&message("mutation")).unwrap().is_allow());
}
