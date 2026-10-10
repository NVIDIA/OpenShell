// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Ported YAML tests for per-path protocols and WebSocket inspection (Cedar
//! parity plan, phase 3).
//!
//! YAML endpoints that share a `host:port` with different `path`s become
//! Cedar `HttpRequest` policies with `@path`, which gives each path its own
//! inspection. `@path` selects inspection only, so each translation also
//! spells out the YAML endpoint path as a `context.path` condition, as the
//! other ports do. Every policy of a translated endpoint carries the
//! endpoint's `@path`, so a translated `forbid` does not add a path-less
//! inspection the YAML policy lacks.
//!
//! A YAML `protocol: websocket` endpoint whose rules name GraphQL operations
//! becomes `@protocol("websocket-graphql")`; one without becomes
//! `@protocol("websocket")`. WebSocket messages are probed through the relay
//! with [`Probe::WebSocket`] where the original sends frames, and as
//! `WEBSOCKET_TEXT` requests where it evaluates the message directly.

use super::ported_opa_a::{L7_TEST_CEDAR, L7_TEST_DATA};
use super::ported_phase1::{self as phase1, native_request, native_scenario};
use super::ported_relay::mcp_body;
use super::*;

use crate::l7::jsonrpc::McpMethodClassification::Available;

const NODE: &str = "/usr/bin/node";
const PYTHON: &str = "/usr/bin/python3";

/// The Cedar condition for a YAML binary entry with an exact path.
fn binary(path: &str) -> String {
    phase1::binary(path)
}

/// The Cedar condition for a YAML REST rule allowing `GET` (and so `HEAD`).
const GET: &str = phase1::GET;

/// The Cedar condition for a YAML GraphQL rule listing `fields`.
fn fields_within(fields: &[&str]) -> String {
    let list = fields
        .iter()
        .map(|field| format!("\"{field}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "(context.graphql_fields.containsAny([{list}]) && [{list}].containsAll(context.graphql_fields))"
    )
}

/// A `NetworkConnect` permit for `host:port` under `condition`.
fn connect(host: &str, port: u16, condition: &str) -> String {
    format!(
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"{host}:{port}")
when {{ {condition} }};
"#
    )
}

/// An `HttpRequest` policy on `host:port`, with `annotations` before it.
fn http(host: &str, port: u16, annotations: &str, effect: &str, condition: &str) -> String {
    format!(
        r#"
{annotations}
{effect} (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"{host}:{port}")
when {{ {condition} }};
"#
    )
}

/// A client text message on the WebSocket opened at `target`, as the relay
/// evaluates it.
fn ws_text(target: &str) -> L7RequestInfo {
    rest("WEBSOCKET_TEXT", target)
}

/// A GraphQL-over-WebSocket operation message on the WebSocket opened at
/// `target`, as the relay classifies and evaluates it.
fn ws_graphql(target: &str, operations: Vec<GraphqlOperationInfo>) -> L7RequestInfo {
    L7RequestInfo {
        graphql: Some(GraphqlRequestInfo {
            operations,
            error: None,
        }),
        ..ws_text(target)
    }
}

/// A GraphQL-over-WebSocket `subscribe` message carrying `query`.
fn subscribe(query: &str) -> String {
    serde_json::json!({"id": "1", "type": "subscribe", "payload": {"query": query}}).to_string()
}

/// A WebSocket upgrade request for `target` on `host:port`.
fn upgrade_request(host: &str, port: u16, target: &str) -> String {
    format!(
        "GET {target} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
}

/// A WebSocket session at `target` that sends `message` after the upgrade.
fn websocket(ctx: L7EvalContext, target: &str, message: &str) -> Probe {
    Probe::WebSocket(Box::new(WebSocketExchange {
        upgrade: upgrade_request(&ctx.host, ctx.port, target),
        ctx,
        route_selected: false,
        message: message.to_string(),
    }))
}

/// One HTTP/1 exchange, answered by the upstream with no content.
fn exchange(ctx: L7EvalContext, request: String, marker: Option<&'static str>) -> Probe {
    Probe::Relay(Box::new(RelayExchange {
        ctx,
        route_selected: false,
        request,
        upstream_response: NO_CONTENT.to_string(),
        marker,
    }))
}

/// The marker of the relay's refusal of an HTTP upgrade on a JSON-RPC-family
/// or GraphQL endpoint.
const UPGRADE_REFUSAL: &str = "unsupported_l7_protocol";

// ---------------------------------------------------------------------------
// opa.rs: `graphql_ws` in `L7_TEST_DATA`
// ---------------------------------------------------------------------------

/// The Cedar translation of `graphql_ws` in [`L7_TEST_DATA`], which
/// `L7_TEST_CEDAR` leaves out.
const GRAPHQL_WS_CEDAR: &str = r#"
// graphql_ws
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"realtime.graphql.com:443")
when { context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl") };
@path("/graphql")
@protocol("websocket-graphql")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"realtime.graphql.com:443")
when {
    (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
    && context.path == "/graphql"
    && (["GET", "HEAD"].contains(context.method)
        || (context.graphql_operation_type == "query"
            && context.graphql_fields.containsAny(["viewer"])
            && ["viewer"].containsAll(context.graphql_fields))
        || (context.graphql_operation_type == "subscription"
            && context.graphql_fields.containsAny(["messageAdded"])
            && ["messageAdded"].containsAll(context.graphql_fields)))
};
@path("/graphql")
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"realtime.graphql.com:443")
when {
    (context.binary_path == "/usr/bin/curl" || context.ancestors.contains("/usr/bin/curl"))
    && context.path == "/graphql"
    && context.graphql_operation_type == "mutation"
};
"#;

#[test]
fn ported_l7_test_data_graphql_ws() {
    let ctx = l7_ctx("realtime.graphql.com", 443, BINARY);
    let message = |operation_type, name, fields| {
        request_in(
            ctx.clone(),
            ws_graphql("/graphql", vec![operation(operation_type, name, fields)]),
        )
    };
    assert_parity(&Scenario {
        name: "opa.rs L7_TEST_DATA graphql_ws",
        host: "realtime.graphql.com",
        yaml: L7_TEST_DATA,
        cedar: &format!("{L7_TEST_CEDAR}{GRAPHQL_WS_CEDAR}"),
        cases: vec![
            same_probe(
                "opa.rs::l7_websocket_graphql_subscription_allowed_by_field_rule",
                message("subscription", Some("NewMessages"), &["messageAdded"]),
            )
            .asserting_yaml("allow"),
            same_probe(
                "opa.rs::l7_websocket_graphql_unlisted_field_denied",
                message("query", None, &["adminAuditLog"]),
            )
            .asserting_yaml("deny"),
            same_probe(
                "opa.rs::l7_websocket_graphql_deny_rule_takes_precedence",
                message("mutation", Some("DeleteRepo"), &["deleteRepository"]),
            )
            .asserting_yaml("deny"),
            same_probe(
                "graphql_ws/upgrade",
                request_in(ctx.clone(), rest("GET", "/graphql")),
            )
            .asserting_yaml("allow"),
            same_probe(
                "graphql_ws/inspection",
                Probe::Inspection(network("realtime.graphql.com", 443, BINARY)),
            )
            .asserting_yaml("Websocket/Enforce"),
            same_probe(
                "graphql_ws/relay forwards an allowed subscription",
                websocket(
                    ctx.clone(),
                    "/graphql",
                    &subscribe("subscription { messageAdded }"),
                ),
            )
            .asserting_yaml("101/message-forwarded"),
            same_probe(
                "graphql_ws/relay blocks a denied mutation",
                websocket(
                    ctx.clone(),
                    "/graphql",
                    &subscribe("mutation { deleteRepository }"),
                ),
            )
            .asserting_yaml("101/message-blocked"),
            same_probe(
                "graphql_ws/relay forwards a control message",
                websocket(ctx.clone(), "/graphql", r#"{"type":"connection_init"}"#),
            )
            .asserting_yaml("101/message-forwarded"),
            same_probe(
                "graphql_ws/relay blocks a message that is not GraphQL over WebSocket",
                websocket(ctx, "/graphql", "not json"),
            )
            .asserting_yaml("101/message-blocked"),
        ],
    });
}

/// `l7_websocket_graphql_not_bypassed_by_generic_text_rule` loads its policy
/// without validation, since YAML validation rejects a `WEBSOCKET_TEXT` rule
/// on a WebSocket endpoint with GraphQL operation rules. The port does the
/// same.
#[test]
fn ported_websocket_graphql_generic_text_rule() {
    const YAML: &str = r#"
network_policies:
  graphql_ws:
    name: graphql_ws
    endpoints:
      - host: realtime.graphql.com
        ports: [443]
        path: "/graphql"
        protocol: websocket
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/graphql"
          - allow:
              method: WEBSOCKET_TEXT
              path: "/graphql"
          - allow:
              operation_type: query
              fields: [viewer]
    binaries:
      - { path: /usr/bin/curl }
"#;
    let curl = binary(BINARY);
    let host = "realtime.graphql.com";
    let mut cedar = connect(host, 443, &curl);
    cedar.push_str(&http(
        host,
        443,
        r#"@path("/graphql") @protocol("websocket-graphql")"#,
        "permit",
        &format!(
            r#"{curl} && context.path == "/graphql"
                && ({GET} || context.method == "WEBSOCKET_TEXT"
                    || (context.graphql_operation_type == "query" && {viewer}))"#,
            viewer = fields_within(&["viewer"]),
        ),
    ));
    assert!(
        OpaEngine::from_strings(REGO, YAML).is_err(),
        "YAML validation rejects the generic WEBSOCKET_TEXT rule"
    );
    let engines = Engines::new(
        OpaEngine::from_strings_unvalidated(REGO, YAML).expect("YAML data loads"),
        CedarOnlyEngine::from_policy_str(&cedar).expect("Cedar policy loads"),
    );
    let ctx = l7_ctx(host, 443, BINARY);
    let message = |fields: &[&str]| {
        request_in(
            ctx.clone(),
            ws_graphql("/graphql", vec![operation("query", None, fields)]),
        )
    };
    report_parity(run(
        "GraphQL WebSocket generic text rule",
        host,
        &engines,
        &[
            diverges_probe(
                "opa.rs::l7_websocket_graphql_not_bypassed_by_generic_text_rule",
                message(&["adminAuditLog"]),
                "CEDAR ALLOWS WHAT YAML DENIES: Rego denies a GraphQL-over-WebSocket message \
                 the endpoint's operation rules do not allow even when a generic \
                 WEBSOCKET_TEXT rule matches (and YAML validation rejects the rule); Cedar has \
                 no protocol-authoritative rule, so the generic WEBSOCKET_TEXT permit allows \
                 every GraphQL message",
            )
            .asserting_yaml("deny"),
            // Positive control: an operation the operation rules allow.
            same_probe("generic text rule/allowed operation", message(&["viewer"]))
                .asserting_yaml("allow"),
        ],
    ));
}

// ---------------------------------------------------------------------------
// opa.rs: endpoints sharing a host:port
// ---------------------------------------------------------------------------

#[test]
fn ported_l7_endpoint_path_scopes_rest_and_graphql() {
    const NAME: &str = "opa.rs::l7_endpoint_path_scopes_rest_and_graphql_on_same_host";
    let host = "api.github.test";
    let curl = binary(BINARY);
    let mut cedar = connect(host, 443, &curl);
    // The REST rule `method: "*"`, `path: "/**"` on endpoint path `/repos/**`.
    cedar.push_str(&http(
        host,
        443,
        r#"@path("/repos/**")"#,
        "permit",
        &format!(
            r#"{curl} && (context.path == "/repos" || context.path like("/repos/**", "/"))
                && context.path like("/**", "/")"#
        ),
    ));
    cedar.push_str(&http(
        host,
        443,
        r#"@path("/graphql") @protocol("graphql")"#,
        "permit",
        &format!(
            r#"{curl} && context.path == "/graphql" && context.graphql_operation_type == "query""#
        ),
    ));
    assert_parity(&Scenario {
        name: "REST and GraphQL paths",
        host,
        yaml: r#"
network_policies:
  mixed_api:
    name: mixed_api
    endpoints:
      - host: api.github.test
        port: 443
        path: "/repos/**"
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: "*"
              path: "/**"
      - host: api.github.test
        port: 443
        path: "/graphql"
        protocol: graphql
        enforcement: enforce
        rules:
          - allow:
              operation_type: query
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: &cedar,
        cases: vec![
            same(NAME, rest("POST", "/repos/org/repo/issues")).asserting_yaml("allow"),
            same(NAME, graphql(vec![operation("query", None, &["viewer"])]))
                .asserting_yaml("allow"),
            same(
                NAME,
                graphql(vec![operation("mutation", None, &["deleteRepository"])]),
            )
            .asserting_yaml("deny"),
            same_probe(
                "REST and GraphQL paths/inspection",
                Probe::Inspection(network(host, 443, BINARY)),
            )
            .asserting_yaml("Graphql/Enforce,Rest/Enforce"),
            same(
                "REST and GraphQL paths/no endpoint path matches",
                rest("GET", "/orgs/nvidia"),
            )
            .asserting_yaml("deny"),
        ],
    });
}

#[test]
fn ported_l7_mcp_denial_paths_and_protocols() {
    const NAME: &str = "opa.rs::l7_mcp_denial_reason_matches_request_path_and_protocol";
    const HOST: &str = "mcp.reasons.test";
    const PORT: u16 = 8000;
    let curl = binary(BINARY);
    let mut cedar = connect(HOST, PORT, &curl);
    cedar.push_str(&http(
        HOST,
        PORT,
        r#"@path("/rpc") @protocol("json-rpc")"#,
        "permit",
        &format!(
            r#"{curl} && context.path == "/rpc" && !context.jsonrpc_response
                && context.jsonrpc_method == "reports.list""#
        ),
    ));
    cedar.push_str(&http(
        HOST,
        PORT,
        r#"@path("/rest")"#,
        "permit",
        &format!(r#"{curl} && context.path == "/rest" && {GET}"#),
    ));
    // `allow_all_known_mcp_methods` allows every core method, except that a
    // `tool` rule narrows `tools/call` to its tools.
    cedar.push_str(&http(
        HOST,
        PORT,
        r#"@path("/mcp") @protocol("mcp")"#,
        "permit",
        &format!(
            r#"{curl} && context.path == "/mcp" && !context.jsonrpc_response
                && context.mcp_method_class == "available"
                && (context.jsonrpc_method != "tools/call" || context.mcp_tool == "read_status")"#
        ),
    ));
    // A YAML MCP endpoint also allows its receive stream and client response
    // frames on the endpoint path.
    cedar.push_str(&http(
        HOST,
        PORT,
        r#"@path("/mcp")"#,
        "permit",
        &format!(
            r#"{curl} && context.path == "/mcp"
                && ((context.method == "GET" && context.jsonrpc_receive_stream)
                    || context.jsonrpc_response)"#
        ),
    ));
    let ctx = l7_ctx(HOST, PORT, BINARY);
    let call_at = |path: &str, method: &str, tool: Option<&str>| {
        request_in(
            ctx.clone(),
            jsonrpc_request(path, vec![call(method, tool, Some(Available))]),
        )
    };
    let mcp_info = |info: JsonRpcRequestInfo| {
        request_in(
            ctx.clone(),
            L7RequestInfo {
                jsonrpc: Some(info),
                ..rest("POST", "/mcp")
            },
        )
    };
    let response_frame = |path: &str| {
        request_in(
            ctx.clone(),
            L7RequestInfo {
                jsonrpc: Some(JsonRpcRequestInfo {
                    has_response: true,
                    ..jsonrpc_info(Vec::new())
                }),
                ..rest("POST", path)
            },
        )
    };
    let mut cases = vec![
        same_probe(
            format!("{NAME}/unmatched tool"),
            call_at("/mcp", "tools/call", Some("other_tool")),
        )
        .asserting_yaml("deny"),
    ];
    for path in ["/rest", "/rpc", "/other"] {
        cases.push(
            same_probe(
                format!("{NAME}/tools/call on {path}"),
                call_at(path, "tools/call", None),
            )
            .asserting_yaml("deny"),
        );
    }
    cases.extend([
        same_probe(
            format!("{NAME}/no selected call"),
            mcp_info(jsonrpc_info(Vec::new())),
        )
        .asserting_yaml("deny"),
        same_probe(
            format!("{NAME}/inspection error"),
            request_in(ctx.clone(), mcp_body("POST", "/mcp", "{not json")),
        )
        .asserting_yaml("deny"),
        same_probe(
            format!("{NAME}/unavailable method"),
            request_in(
                ctx.clone(),
                jsonrpc_request("/mcp", vec![call("tools/call", Some("other_tool"), None)]),
            ),
        )
        .asserting_yaml("deny"),
        same_probe(
            format!("{NAME}/JSON-RPC response frame"),
            response_frame("/rpc"),
        )
        .asserting_yaml("deny"),
        same_probe(format!("{NAME}/MCP response frame"), response_frame("/mcp"))
            .asserting_yaml("allow"),
        same_probe(
            format!("{NAME}/MCP tools/list"),
            call_at("/mcp", "tools/list", None),
        )
        .asserting_yaml("allow"),
        // Positive controls for each path's own protocol.
        same_probe(
            "MCP, JSON-RPC, and REST paths/allowed tool",
            call_at("/mcp", "tools/call", Some("read_status")),
        )
        .asserting_yaml("allow"),
        same_probe(
            "MCP, JSON-RPC, and REST paths/allowed JSON-RPC method",
            request_in(
                ctx.clone(),
                jsonrpc_request("/rpc", vec![call("reports.list", None, None)]),
            ),
        )
        .asserting_yaml("allow"),
        same_probe(
            "MCP, JSON-RPC, and REST paths/allowed REST request",
            request_in(ctx, rest("GET", "/rest")),
        )
        .asserting_yaml("allow"),
        same_probe(
            "MCP, JSON-RPC, and REST paths/inspection",
            Probe::Inspection(network(HOST, PORT, BINARY)),
        )
        .asserting_yaml("JsonRpc/Enforce,Mcp/Enforce,Rest/Enforce"),
    ]);
    assert_parity(&Scenario {
        name: "MCP, JSON-RPC, and REST paths",
        host: HOST,
        yaml: r"
network_policies:
  mixed:
    name: mixed
    endpoints:
      - host: mcp.reasons.test
        port: 8000
        path: /rpc
        protocol: json-rpc
        enforcement: enforce
        rules: [{allow: {method: reports.list}}]
      - host: mcp.reasons.test
        port: 8000
        path: /rest
        protocol: rest
        enforcement: enforce
        rules: [{allow: {method: GET, path: /rest}}]
      - host: mcp.reasons.test
        port: 8000
        path: /mcp
        protocol: mcp
        enforcement: enforce
        mcp:
          allow_all_known_mcp_methods: true
        rules: [{allow: {tool: read_status}}]
    binaries:
      - {path: /usr/bin/curl}
",
        cedar: &cedar,
        cases,
    });
}

#[test]
fn ported_yaml_and_proto_protocol_parity() {
    const NAME: &str = "opa.rs::yaml_and_proto_loads_have_protocol_config_and_authorization_parity";
    let curl = binary(BINARY);
    let mut cedar = String::new();
    for host in [
        "rest.parity.test",
        "graphql.parity.test",
        "websocket.parity.test",
        "jsonrpc.parity.test",
        "mcp.parity.test",
    ] {
        cedar.push_str(&connect(host, 443, &curl));
    }
    cedar.push_str(&http(
        "rest.parity.test",
        443,
        r#"@path("/items/**")"#,
        "permit",
        &format!(r#"{curl} && {GET} && context.path like("/items/**", "/")"#),
    ));
    cedar.push_str(&http(
        "graphql.parity.test",
        443,
        r#"@path("/graphql") @protocol("graphql")"#,
        "permit",
        &format!(
            r#"{curl} && context.path == "/graphql" && context.graphql_operation_type == "query"
                && context.graphql_operation_name == "GetWidget" && {fields}"#,
            fields = fields_within(&["id", "name"]),
        ),
    ));
    cedar.push_str(&http(
        "websocket.parity.test",
        443,
        r#"@path("/graphql") @protocol("websocket-graphql")"#,
        "permit",
        &format!(
            r#"{curl} && context.path == "/graphql"
                && ({GET} || (context.graphql_operation_type == "subscription" && {fields}))"#,
            fields = fields_within(&["messageAdded"]),
        ),
    ));
    cedar.push_str(&http(
        "jsonrpc.parity.test",
        443,
        r#"@path("/rpc") @protocol("json-rpc")"#,
        "permit",
        &format!(
            r#"{curl} && context.path == "/rpc" && !context.jsonrpc_response
                && context.jsonrpc_method == "status.get""#
        ),
    ));
    cedar.push_str(&http(
        "mcp.parity.test",
        443,
        r#"@path("/mcp") @protocol("mcp")"#,
        "permit",
        &format!(
            r#"{curl} && context.path == "/mcp" && !context.jsonrpc_response
                && context.mcp_method_class == "available"
                && context.jsonrpc_method == "tools/call" && context.mcp_tool == "read_status""#
        ),
    ));
    cedar.push_str(&http(
        "mcp.parity.test",
        443,
        r#"@path("/mcp")"#,
        "permit",
        &format!(
            r#"{curl} && context.path == "/mcp"
                && ((context.method == "GET" && context.jsonrpc_receive_stream)
                    || context.jsonrpc_response)"#
        ),
    ));
    let at = |host: &str, request: L7RequestInfo| request_in(l7_ctx(host, 443, BINARY), request);
    let graphql_at = |operation_type, name| L7RequestInfo {
        graphql: Some(GraphqlRequestInfo {
            operations: vec![operation(operation_type, Some(name), &["id"])],
            error: None,
        }),
        ..rest("POST", "/graphql")
    };
    let websocket_message =
        |fields: &[&str]| ws_graphql("/graphql", vec![operation("subscription", None, fields)]);
    let cases = vec![
        (
            "REST",
            at("rest.parity.test", rest("GET", "/items/one")),
            at("rest.parity.test", rest("DELETE", "/items/one")),
        ),
        (
            "GraphQL",
            at("graphql.parity.test", graphql_at("query", "GetWidget")),
            at(
                "graphql.parity.test",
                graphql_at("mutation", "DeleteWidget"),
            ),
        ),
        (
            "WebSocket",
            at(
                "websocket.parity.test",
                websocket_message(&["messageAdded"]),
            ),
            at(
                "websocket.parity.test",
                websocket_message(&["adminAuditLog"]),
            ),
        ),
        (
            "JSON-RPC",
            at(
                "jsonrpc.parity.test",
                jsonrpc_request("/rpc", vec![call("status.get", None, None)]),
            ),
            at(
                "jsonrpc.parity.test",
                jsonrpc_request("/rpc", vec![call("status.delete", None, None)]),
            ),
        ),
        (
            "MCP",
            at(
                "mcp.parity.test",
                jsonrpc_request(
                    "/mcp",
                    vec![call("tools/call", Some("read_status"), Some(Available))],
                ),
            ),
            at(
                "mcp.parity.test",
                jsonrpc_request(
                    "/mcp",
                    vec![call("tools/call", Some("delete_status"), Some(Available))],
                ),
            ),
        ),
    ]
    .into_iter()
    .flat_map(|(protocol, allowed, denied)| {
        [
            same_probe(format!("{NAME}/{protocol} allowed"), allowed).asserting_yaml("allow"),
            same_probe(format!("{NAME}/{protocol} denied"), denied).asserting_yaml("deny"),
        ]
    })
    .chain([same_probe(
        format!("{NAME}/WebSocket inspection"),
        Probe::Inspection(network("websocket.parity.test", 443, BINARY)),
    )
    .asserting_yaml("Websocket/Enforce")])
    .collect();
    assert_parity(&Scenario {
        name: "YAML and proto protocol parity",
        host: "rest.parity.test",
        yaml: r"
version: 1
network_policies:
  parity:
    name: parity
    endpoints:
      - host: rest.parity.test
        port: 443
        path: /items/**
        protocol: rest
        enforcement: enforce
        allow_encoded_slash: true
        rules:
          - allow: { method: GET, path: /items/** }
      - host: graphql.parity.test
        port: 443
        path: /graphql
        protocol: graphql
        enforcement: enforce
        graphql_max_body_bytes: 65536
        rules:
          - allow:
              operation_type: query
              operation_name: GetWidget
              fields: [id, name]
      - host: websocket.parity.test
        port: 443
        path: /graphql
        protocol: websocket
        enforcement: enforce
        websocket_credential_rewrite: true
        rules:
          - allow: { method: GET, path: /graphql }
          - allow:
              operation_type: subscription
              fields: [messageAdded]
      - host: jsonrpc.parity.test
        port: 443
        path: /rpc
        protocol: json-rpc
        enforcement: enforce
        json_rpc: { max_body_bytes: 32768 }
        rules:
          - allow: { method: status.get }
      - host: mcp.parity.test
        port: 443
        path: /mcp
        protocol: mcp
        enforcement: enforce
        mcp:
          max_body_bytes: 16384
          strict_tool_names: false
        rules:
          - allow:
              method: tools/call
              tool: read_status
    binaries:
      - { path: /usr/bin/curl }
",
        cedar: &cedar,
        cases,
    });
}

// ---------------------------------------------------------------------------
// proxy.rs: route selection and forward-proxy WebSocket policy
// ---------------------------------------------------------------------------

/// The original builds the two configs by hand and checks only which one
/// the relay selects. The port declares the same endpoints, with a GET rule
/// on the REST endpoint and a query rule on the GraphQL one, and checks the
/// selection through the relay: a GraphQL mutation sent with POST is parsed
/// and denied as GraphQL.
#[test]
fn ported_l7_route_selection_prefers_path_specific_graphql() {
    const NAME: &str = "proxy.rs::l7_route_selection_prefers_path_specific_graphql_endpoint";
    let host = "api.example.com";
    let curl = binary(BINARY);
    let mut cedar = connect(host, 443, &curl);
    cedar.push_str(&http(
        host,
        443,
        r#"@path("/**")"#,
        "permit",
        &format!(r#"{curl} && {GET} && context.path like("/**", "/")"#),
    ));
    cedar.push_str(&http(
        host,
        443,
        r#"@path("/graphql") @protocol("graphql")"#,
        "permit",
        &format!(
            r#"{curl} && context.path == "/graphql" && context.graphql_operation_type == "query""#
        ),
    ));
    let ctx = l7_ctx(host, 443, BINARY);
    let body = r#"{"query":"mutation { deleteRepository }"}"#;
    assert_parity(&Scenario {
        name: "path-specific GraphQL route",
        host,
        yaml: r#"
network_policies:
  mixed:
    name: mixed
    endpoints:
      - host: api.example.com
        port: 443
        path: "/**"
        protocol: rest
        enforcement: enforce
        rules:
          - allow: { method: GET, path: "/**" }
      - host: api.example.com
        port: 443
        path: "/graphql"
        protocol: graphql
        enforcement: enforce
        rules:
          - allow: { operation_type: query }
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: &cedar,
        cases: vec![
            same_probe(NAME, Probe::Inspection(network(host, 443, BINARY)))
                .asserting_yaml("Graphql/Enforce,Rest/Enforce"),
            same_probe(
                NAME,
                exchange(
                    ctx.clone(),
                    format!(
                        "POST /graphql HTTP/1.1\r\nHost: {host}:443\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    ),
                    None,
                ),
            )
            .asserting_yaml("403/blocked"),
            same_probe(
                NAME,
                exchange(
                    ctx,
                    format!(
                        "GET /repos/org/repo HTTP/1.1\r\nHost: {host}:443\r\nConnection: close\r\n\r\n"
                    ),
                    None,
                ),
            )
            .asserting_yaml("204/forwarded"),
        ],
    });
}

/// A GraphQL request on a path a broader REST endpoint also matches.
///
/// Not a port: YAML makes a GraphQL endpoint authoritative for the requests
/// it parses, so a REST rule of a broader endpoint never allows them. Cedar
/// policies apply to every request on their endpoint, so the literal
/// translation of the REST rule allows them. Conditioning the REST policy on
/// `resource.protocol == "rest"`, the protocol of the request's routed path,
/// restores the YAML decision.
#[test]
fn graphql_path_authority_over_a_broader_rest_path() {
    let host = "api.example.com";
    let curl = binary(BINARY);
    let yaml = r#"
network_policies:
  mixed:
    name: mixed
    endpoints:
      - host: api.example.com
        port: 443
        path: "/**"
        protocol: rest
        enforcement: enforce
        rules:
          - allow: { method: GET, path: "/**" }
      - host: api.example.com
        port: 443
        path: "/graphql"
        protocol: graphql
        enforcement: enforce
        rules:
          - allow: { operation_type: query }
    binaries:
      - { path: /usr/bin/curl }
"#;
    let cedar = |rest_scope: &str| {
        let mut cedar = connect(host, 443, &curl);
        cedar.push_str(&http(
            host,
            443,
            r#"@path("/**")"#,
            "permit",
            &format!(r#"{curl} && {GET} && context.path like("/**", "/"){rest_scope}"#),
        ));
        cedar.push_str(&http(
            host,
            443,
            r#"@path("/graphql") @protocol("graphql")"#,
            "permit",
            &format!(
                r#"{curl} && context.path == "/graphql" && context.graphql_operation_type == "query""#
            ),
        ));
        cedar
    };
    let mutation = || {
        exchange(
            l7_ctx(host, 443, BINARY),
            format!(
                "GET /graphql?query=mutation%7BdeleteRepository%7D HTTP/1.1\r\nHost: {host}:443\r\nConnection: close\r\n\r\n"
            ),
            None,
        )
    };
    let query = || {
        exchange(
            l7_ctx(host, 443, BINARY),
            format!(
                "GET /graphql?query=%7Bviewer%7D HTTP/1.1\r\nHost: {host}:443\r\nConnection: close\r\n\r\n"
            ),
            None,
        )
    };
    assert_parity(&Scenario {
        name: "GraphQL authority, literal REST translation",
        host,
        yaml,
        cedar: &cedar(""),
        cases: vec![
            diverges_probe(
                "GET GraphQL mutation",
                mutation(),
                "CEDAR ALLOWS WHAT YAML DENIES: YAML denies a parsed GraphQL request the \
                 GraphQL endpoint's rules do not allow, even when a broader REST endpoint's \
                 rule matches it; a Cedar permit applies to every request on its endpoint",
            )
            .asserting_yaml("403/blocked"),
            same_probe("GET GraphQL query", query()).asserting_yaml("204/forwarded"),
        ],
    });
    assert_parity(&Scenario {
        name: "GraphQL authority, REST translation scoped by resource.protocol",
        host,
        yaml,
        cedar: &cedar(r#" && resource.protocol == "rest""#),
        cases: vec![
            same_probe("GET GraphQL mutation", mutation()).asserting_yaml("403/blocked"),
            same_probe("GET GraphQL query", query()).asserting_yaml("204/forwarded"),
        ],
    });
}

/// An audit endpoint whose path also matches a more specific enforced one.
///
/// Not a port. YAML applies the rules of every endpoint whose path matches a
/// request, and the selected endpoint's enforcement decides whether a denial
/// blocks: an audit endpoint's deny rule blocks requests routed to an
/// overlapping enforced endpoint, and its allow rules allow them. A Cedar
/// policy is audit-only everywhere or nowhere, so the literal translation
/// differs: an audit-only `forbid` never blocks. Writing those rules again as
/// enforced policies scoped to the enforced path matches YAML.
#[test]
fn audit_endpoint_rules_on_an_overlapping_enforced_path() {
    let host = "api.example.com";
    let curl = binary(BINARY);
    let mut cedar = connect(host, 443, &curl);
    cedar.push_str(&http(
        host,
        443,
        r#"@path("/**") @enforcement("audit")"#,
        "permit",
        &format!(r#"{curl} && {GET} && context.path like("/**", "/")"#),
    ));
    cedar.push_str(&http(
        host,
        443,
        r#"@path("/**") @enforcement("audit")"#,
        "forbid",
        &format!(r#"{curl} && context.method == "DELETE""#),
    ));
    cedar.push_str(&http(
        host,
        443,
        r#"@path("/api/**")"#,
        "permit",
        &format!(
            r#"{curl} && ["DELETE", "POST"].contains(context.method)
                && (context.path == "/api" || context.path like("/api/**", "/"))"#
        ),
    ));
    let ctx = l7_ctx(host, 443, BINARY);
    let send = |method: &str, path: &str| {
        exchange(
            ctx.clone(),
            format!("{method} {path} HTTP/1.1\r\nHost: {host}:443\r\nConnection: close\r\n\r\n"),
            None,
        )
    };
    assert_parity(&Scenario {
        name: "audit endpoint beside an enforced path",
        host,
        yaml: AUDIT_OVERLAP_YAML,
        cedar: &cedar,
        cases: vec![
            diverges_probe(
                "audit deny rule on the enforced path",
                send("DELETE", "/api/item"),
                "CEDAR ALLOWS WHAT YAML DENIES: the audit endpoint's deny rule blocks a request \
                 YAML routes to the overlapping enforced endpoint; a Cedar audit-only forbid \
                 never blocks",
            )
            .asserting_yaml("403/blocked"),
            diverges_probe(
                "audit allow rule on the enforced path",
                send("GET", "/api/item"),
                "the audit endpoint's allow rule allows a request YAML routes to the \
                 overlapping enforced endpoint; a Cedar audit-only permit is left out of an \
                 enforced path's decision (Cedar denies)",
            )
            .asserting_yaml("204/forwarded"),
            same_probe("allowed on the enforced path", send("POST", "/api/item"))
                .asserting_yaml("204/forwarded"),
            same_probe("audited denial on the audit path", send("DELETE", "/other"))
                .asserting_yaml("204/forwarded"),
        ],
    });

    // The faithful translation: the audit endpoint's rules that YAML enforces
    // on the overlapping path are written again as enforced policies scoped
    // to that path.
    let mut faithful = cedar.clone();
    faithful.push_str(&http(
        host,
        443,
        r#"@path("/api/**")"#,
        "forbid",
        &format!(
            r#"{curl} && context.method == "DELETE"
                && (context.path == "/api" || context.path like("/api/**", "/"))"#
        ),
    ));
    faithful.push_str(&http(
        host,
        443,
        r#"@path("/api/**")"#,
        "permit",
        &format!(
            r#"{curl} && {GET}
                && (context.path == "/api" || context.path like("/api/**", "/"))"#
        ),
    ));
    assert_parity(&Scenario {
        name: "audit endpoint beside an enforced path, rules split by enforcement",
        host,
        yaml: AUDIT_OVERLAP_YAML,
        cedar: &faithful,
        cases: vec![
            same_probe(
                "audit deny rule on the enforced path",
                send("DELETE", "/api/item"),
            )
            .asserting_yaml("403/blocked"),
            same_probe(
                "audit allow rule on the enforced path",
                send("GET", "/api/item"),
            )
            .asserting_yaml("204/forwarded"),
            same_probe("allowed on the enforced path", send("POST", "/api/item"))
                .asserting_yaml("204/forwarded"),
            same_probe("audited denial on the audit path", send("DELETE", "/other"))
                .asserting_yaml("204/forwarded"),
        ],
    });
}

const AUDIT_OVERLAP_YAML: &str = r#"
network_policies:
  mixed:
    name: mixed
    endpoints:
      - host: api.example.com
        port: 443
        path: "/**"
        protocol: rest
        enforcement: audit
        rules:
          - allow: { method: GET, path: "/**" }
        deny_rules:
          - { method: DELETE, path: "/**" }
      - host: api.example.com
        port: 443
        path: "/api/**"
        protocol: rest
        enforcement: enforce
        rules:
          - allow: { method: DELETE, path: "/api/**" }
          - allow: { method: POST, path: "/api/**" }
    binaries:
      - { path: /usr/bin/curl }
"#;

/// The `ws_api` WebSocket policy of
/// `forward_websocket_upgrade_blocks_text_frame_by_policy`, with or without
/// its `WEBSOCKET_TEXT` deny rule.
fn ws_api(deny_rule: bool) -> (String, String) {
    let deny_yaml = if deny_rule {
        "\n        deny_rules:\n          - method: WEBSOCKET_TEXT\n            path: \"/ws\""
    } else {
        ""
    };
    let yaml = format!(
        r#"
network_policies:
  ws_api:
    name: ws_api
    endpoints:
      - host: gateway.example.test
        port: 80
        path: "/ws"
        protocol: websocket
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/ws"
          - allow:
              method: WEBSOCKET_TEXT
              path: "/ws"{deny_yaml}
    binaries:
      - {{ path: /usr/bin/node }}
"#
    );
    let node = binary(NODE);
    let host = "gateway.example.test";
    let mut cedar = connect(host, 80, &node);
    cedar.push_str(&http(
        host,
        80,
        r#"@path("/ws") @protocol("websocket")"#,
        "permit",
        &format!(
            r#"{node} && context.path == "/ws" && ({GET} || context.method == "WEBSOCKET_TEXT")"#
        ),
    ));
    if deny_rule {
        cedar.push_str(&http(
            host,
            80,
            r#"@path("/ws")"#,
            "forbid",
            &format!(r#"{node} && context.method == "WEBSOCKET_TEXT" && context.path == "/ws""#),
        ));
    }
    (yaml, cedar)
}

#[test]
fn ported_forward_websocket_text_frame_policy() {
    const NAME: &str = "proxy.rs::forward_websocket_upgrade_blocks_text_frame_by_policy";
    let ctx = l7_ctx("gateway.example.test", 80, NODE);
    let message = r#"{"type":"unsafe"}"#;
    let (yaml, cedar) = ws_api(true);
    assert_parity(&Scenario {
        name: "WebSocket text deny rule",
        host: "gateway.example.test",
        yaml: &yaml,
        cedar: &cedar,
        cases: vec![
            same_probe(NAME, websocket(ctx.clone(), "/ws", message))
                .asserting_yaml("101/message-blocked"),
            same_probe(NAME, request_in(ctx.clone(), ws_text("/ws"))).asserting_yaml("deny"),
            same_probe(
                "WebSocket text deny rule/upgrade",
                request_in(ctx.clone(), rest("GET", "/ws")),
            )
            .asserting_yaml("allow"),
        ],
    });
    // Positive control: without the deny rule the message is forwarded.
    let (yaml, cedar) = ws_api(false);
    assert_parity(&Scenario {
        name: "WebSocket text allow rule",
        host: "gateway.example.test",
        yaml: &yaml,
        cedar: &cedar,
        cases: vec![
            same_probe(
                "WebSocket text allow rule/message",
                websocket(ctx, "/ws", message),
            )
            .asserting_yaml("101/message-forwarded"),
        ],
    });
}

#[test]
fn ported_forward_graphql_websocket_operation_policy() {
    const NAME: &str = "proxy.rs::forward_graphql_websocket_upgrade_blocks_unallowed_operation";
    let host = "gateway.example.test";
    let node = binary(NODE);
    let mut cedar = connect(host, 80, &node);
    cedar.push_str(&http(
        host,
        80,
        r#"@path("/graphql") @protocol("websocket-graphql")"#,
        "permit",
        &format!(
            r#"{node} && context.path == "/graphql"
                && ({GET} || (context.graphql_operation_type == "query" && {viewer}))"#,
            viewer = fields_within(&["viewer"]),
        ),
    ));
    cedar.push_str(&http(
        host,
        80,
        r#"@path("/graphql")"#,
        "forbid",
        &format!(
            r#"{node} && context.path == "/graphql" && context.graphql_operation_type == "query"
                && context.graphql_fields.containsAny(["admin"])"#
        ),
    ));
    let ctx = l7_ctx(host, 80, NODE);
    assert_parity(&Scenario {
        name: "GraphQL WebSocket operation rules",
        host,
        yaml: r#"
network_policies:
  graphql_ws:
    name: graphql_ws
    endpoints:
      - host: gateway.example.test
        port: 80
        path: "/graphql"
        protocol: websocket
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/graphql"
          - allow:
              operation_type: query
              fields: [viewer]
        deny_rules:
          - operation_type: query
            fields: [admin]
    binaries:
      - { path: /usr/bin/node }
"#,
        cedar: &cedar,
        cases: vec![
            same_probe(
                NAME,
                websocket(ctx.clone(), "/graphql", &subscribe("query { admin }")),
            )
            .asserting_yaml("101/message-blocked"),
            same_probe(
                "GraphQL WebSocket operation rules/allowed operation",
                websocket(ctx, "/graphql", &subscribe("query { viewer }")),
            )
            .asserting_yaml("101/message-forwarded"),
        ],
    });
}

// ---------------------------------------------------------------------------
// websocket.rs and relay.rs: WebSocket message policy
// ---------------------------------------------------------------------------

#[test]
fn ported_graphql_websocket_message_policy() {
    let host = "realtime.graphql.test";
    let node = binary(NODE);
    let mut cedar = connect(host, 443, &node);
    cedar.push_str(&http(
        host,
        443,
        r#"@path("/graphql") @protocol("websocket-graphql")"#,
        "permit",
        &format!(
            r#"{node} && context.path == "/graphql"
                && ({GET}
                    || (context.graphql_operation_type == "query" && {viewer})
                    || (context.graphql_operation_type == "subscription" && {added}))"#,
            viewer = fields_within(&["viewer"]),
            added = fields_within(&["messageAdded"]),
        ),
    ));
    let ctx = l7_ctx(host, 443, NODE);
    let admin = subscribe("query Admin { adminAuditLog }");
    assert_parity(&Scenario {
        name: "websocket.rs GRAPHQL_WS_POLICY",
        host,
        yaml: r#"
network_policies:
  graphql_ws:
    name: graphql_ws
    endpoints:
      - host: realtime.graphql.test
        port: 443
        path: "/graphql"
        protocol: websocket
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/graphql"
          - allow:
              operation_type: query
              fields: [viewer]
          - allow:
              operation_type: subscription
              fields: [messageAdded]
    binaries:
      - { path: /usr/bin/node }
"#,
        cedar: &cedar,
        cases: vec![
            same_probe(
                "websocket.rs::graphql_websocket_policy_allows_subscription_operation",
                websocket(
                    ctx.clone(),
                    "/graphql",
                    &subscribe("subscription NewMessages { messageAdded }"),
                ),
            )
            .asserting_yaml("101/message-forwarded"),
            same_probe(
                "websocket.rs::graphql_websocket_policy_denies_unlisted_operation_field",
                websocket(ctx.clone(), "/graphql", &admin),
            )
            .asserting_yaml("101/message-blocked"),
            same_probe(
                "websocket.rs::graphql_policy_denial_reports_policy_denial_to_middleware",
                websocket(ctx, "/graphql", &admin),
            )
            .asserting_yaml("101/message-blocked"),
        ],
    });
}

#[test]
fn ported_websocket_text_requires_message_rule() {
    const NAME: &str = "relay.rs::websocket_text_policy_requires_explicit_message_rule";
    let host = "gateway.example.test";
    let node = binary(NODE);
    let mut cedar = connect(host, 443, &node);
    cedar.push_str(&http(
        host,
        443,
        r#"@protocol("websocket")"#,
        "permit",
        &format!(r#"{node} && {GET} && context.path == "/ws""#),
    ));
    let ctx = l7_ctx(host, 443, NODE);
    assert_parity(&Scenario {
        name: "WebSocket without a message rule",
        host,
        yaml: r#"
network_policies:
  ws_api:
    name: ws_api
    endpoints:
      - host: gateway.example.test
        port: 443
        protocol: websocket
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/ws"
    binaries:
      - { path: /usr/bin/node }
"#,
        cedar: &cedar,
        cases: vec![
            same_probe(NAME, request_in(ctx.clone(), ws_text("/ws"))).asserting_yaml("deny"),
            same_probe(NAME, websocket(ctx.clone(), "/ws", "hello"))
                .asserting_yaml("101/message-blocked"),
            same_probe(
                "WebSocket without a message rule/upgrade",
                request_in(ctx.clone(), rest("GET", "/ws")),
            )
            .asserting_yaml("allow"),
            same_probe(
                "WebSocket without a message rule/plain GET",
                exchange(
                    ctx,
                    format!("GET /ws HTTP/1.1\r\nHost: {host}:443\r\nConnection: close\r\n\r\n"),
                    None,
                ),
            )
            .asserting_yaml("403/blocked"),
        ],
    });
}

// ---------------------------------------------------------------------------
// relay.rs: per-request route selection
// ---------------------------------------------------------------------------

/// `jsonrpc_and_rest_route_configs(protocol, enforcement)`: a JSON-RPC-family
/// endpoint at `/mcp` allowing only `initialize`, and a REST endpoint at
/// `/api/**`, on `mcp.example.test:8000`.
fn jsonrpc_and_rest(protocol: &str, enforcement: &str) -> (String, String) {
    let yaml = format!(
        r#"
network_policies:
  shared_api:
    name: shared_api
    endpoints:
      - host: mcp.example.test
        port: 8000
        path: "/mcp"
        protocol: {protocol}
        enforcement: {enforcement}
        rules:
          - allow:
              method: initialize
      - host: mcp.example.test
        port: 8000
        path: "/api/**"
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/api/**"
    binaries:
      - {{ path: /usr/bin/python3 }}
"#
    );
    let host = "mcp.example.test";
    let python = binary(PYTHON);
    let audit = if enforcement == "audit" {
        r#"@enforcement("audit")"#
    } else {
        ""
    };
    let available = if protocol == "mcp" {
        r#" && context.mcp_method_class == "available""#
    } else {
        ""
    };
    let mut cedar = connect(host, 8000, &python);
    cedar.push_str(&http(
        host,
        8000,
        &format!(r#"@path("/mcp") @protocol("{protocol}") {audit}"#),
        "permit",
        &format!(
            r#"{python} && context.path == "/mcp" && !context.jsonrpc_response{available}
                && context.jsonrpc_method == "initialize""#
        ),
    ));
    if protocol == "mcp" {
        cedar.push_str(&http(
            host,
            8000,
            &format!(r#"@path("/mcp") {audit}"#),
            "permit",
            &format!(
                r#"{python} && context.path == "/mcp"
                    && ((context.method == "GET" && context.jsonrpc_receive_stream)
                        || context.jsonrpc_response)"#
            ),
        ));
    }
    cedar.push_str(&http(
        host,
        8000,
        r#"@path("/api/**")"#,
        "permit",
        &format!(r#"{python} && {GET} && context.path like("/api/**", "/")"#),
    ));
    (yaml, cedar)
}

/// The receive-stream `GET` of the MCP relay originals, with or without
/// WebSocket upgrade headers.
fn mcp_receive_stream(upgrade: bool) -> String {
    let upgrade = if upgrade {
        "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
    } else {
        "Connection: close\r\n"
    };
    format!(
        "GET /mcp HTTP/1.1\r\nHost: mcp.example.test:8000\r\nAccept: text/event-stream\r\nMCP-Protocol-Version: 2025-11-25\r\n{upgrade}\r\n"
    )
}

#[test]
fn ported_route_selected_jsonrpc_and_rest() {
    let ctx = l7_ctx("mcp.example.test", 8000, PYTHON);
    let (yaml, cedar) = jsonrpc_and_rest("mcp", "enforce");
    assert_parity(&Scenario {
        name: "MCP and REST routes",
        host: "mcp.example.test",
        yaml: &yaml,
        cedar: &cedar,
        cases: vec![
            same_probe(
                "relay.rs::route_selected_mcp_websocket_upgrade_is_denied_before_forwarding",
                exchange(
                    ctx.clone(),
                    mcp_receive_stream(true),
                    Some(UPGRADE_REFUSAL),
                ),
            )
            .asserting_yaml("403/blocked/marker"),
            same_probe(
                "relay.rs::route_selected_rest_websocket_upgrade_still_relays_beside_mcp",
                websocket(ctx.clone(), "/api/ws", r#"{"type":"ping"}"#),
            )
            .asserting_yaml("101/message-forwarded"),
            same_probe(
                "relay.rs::route_selected_mcp_receive_stream_without_upgrade_is_still_forwarded",
                exchange(ctx.clone(), mcp_receive_stream(false), None),
            )
            .asserting_yaml("204/forwarded"),
            same_probe(
                "MCP and REST routes/no endpoint path matches",
                exchange(
                    ctx,
                    "GET /other HTTP/1.1\r\nHost: mcp.example.test:8000\r\nConnection: close\r\n\r\n"
                        .to_string(),
                    None,
                ),
            )
            .asserting_yaml("403/blocked"),
        ],
    });
    let ctx = l7_ctx("mcp.example.test", 8000, PYTHON);
    let (yaml, cedar) = jsonrpc_and_rest("json-rpc", "audit");
    assert_parity(&Scenario {
        name: "audited JSON-RPC and REST routes",
        host: "mcp.example.test",
        yaml: &yaml,
        cedar: &cedar,
        cases: vec![
            same_probe(
                "relay.rs::route_selected_audit_jsonrpc_websocket_upgrade_is_denied_before_forwarding",
                exchange(ctx, mcp_receive_stream(true), Some(UPGRADE_REFUSAL)),
            )
            .asserting_yaml("403/blocked/marker"),
            same_probe(
                "audited JSON-RPC and REST routes/inspection",
                Probe::Inspection(network("mcp.example.test", 8000, PYTHON)),
            )
            .asserting_yaml("JsonRpc/Audit,Rest/Enforce"),
        ],
    });
}

/// `graphql_and_rest_route_configs(enforcement)`: a GraphQL endpoint at
/// `/graphql` allowing only `query { viewer }`, and a REST endpoint at
/// `/api/**`, on `graphql.example.test:8000`.
fn graphql_and_rest(enforcement: &str) -> (String, String) {
    let yaml = format!(
        r#"
network_policies:
  shared_graphql:
    name: shared_graphql
    endpoints:
      - host: graphql.example.test
        port: 8000
        path: "/graphql"
        protocol: graphql
        enforcement: {enforcement}
        rules:
          - allow:
              operation_type: query
              fields: [viewer]
      - host: graphql.example.test
        port: 8000
        path: "/api/**"
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/api/**"
    binaries:
      - {{ path: /usr/bin/python3 }}
"#
    );
    let host = "graphql.example.test";
    let python = binary(PYTHON);
    let audit = if enforcement == "audit" {
        r#"@enforcement("audit")"#
    } else {
        ""
    };
    let mut cedar = connect(host, 8000, &python);
    cedar.push_str(&http(
        host,
        8000,
        &format!(r#"@path("/graphql") @protocol("graphql") {audit}"#),
        "permit",
        &format!(
            r#"{python} && context.path == "/graphql" && context.graphql_operation_type == "query"
                && {viewer}"#,
            viewer = fields_within(&["viewer"]),
        ),
    ));
    cedar.push_str(&http(
        host,
        8000,
        r#"@path("/api/**")"#,
        "permit",
        &format!(r#"{python} && {GET} && context.path like("/api/**", "/")"#),
    ));
    (yaml, cedar)
}

/// A `GET` of `target` on the GraphQL route host, as a WebSocket upgrade or
/// a plain request.
fn graphql_get(target: &str, upgrade: bool) -> String {
    let headers = if upgrade {
        "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
    } else {
        "Connection: close\r\n"
    };
    format!("GET {target} HTTP/1.1\r\nHost: graphql.example.test:8000\r\n{headers}\r\n")
}

#[test]
fn ported_route_selected_graphql_and_rest() {
    const UPGRADE: &str =
        "relay.rs::route_selected_graphql_websocket_upgrade_is_denied_before_forwarding";
    let ctx = l7_ctx("graphql.example.test", 8000, PYTHON);
    let viewer = "/graphql?query=%7Bviewer%7D";
    let admin = "/graphql?query=%7Badmin%7D";
    let (yaml, cedar) = graphql_and_rest("enforce");
    assert_parity(&Scenario {
        name: "GraphQL and REST routes",
        host: "graphql.example.test",
        yaml: &yaml,
        cedar: &cedar,
        cases: vec![
            same_probe(
                format!("{UPGRADE}/enforce"),
                exchange(
                    ctx.clone(),
                    graphql_get(viewer, true),
                    Some(UPGRADE_REFUSAL),
                ),
            )
            .asserting_yaml("403/blocked/marker"),
            same_probe(
                "relay.rs::route_selected_graphql_query_without_upgrade_is_still_forwarded",
                exchange(ctx.clone(), graphql_get(viewer, false), None),
            )
            .asserting_yaml("204/forwarded"),
            same_probe(
                "GraphQL and REST routes/denied query",
                exchange(ctx.clone(), graphql_get(admin, false), None),
            )
            .asserting_yaml("403/blocked"),
            same_probe(
                "GraphQL and REST routes/REST route",
                exchange(ctx.clone(), graphql_get("/api/items", false), None),
            )
            .asserting_yaml("204/forwarded"),
        ],
    });
    let (yaml, cedar) = graphql_and_rest("audit");
    assert_parity(&Scenario {
        name: "audited GraphQL and REST routes",
        host: "graphql.example.test",
        yaml: &yaml,
        cedar: &cedar,
        cases: vec![
            same_probe(
                format!("{UPGRADE}/audit"),
                exchange(ctx.clone(), graphql_get(viewer, true), Some(UPGRADE_REFUSAL)),
            )
            .asserting_yaml("403/blocked/marker"),
            same_probe(
                "relay.rs::route_selected_audit_graphql_upgrade_with_denied_query_is_refused",
                exchange(ctx.clone(), graphql_get(admin, true), Some(UPGRADE_REFUSAL)),
            )
            .asserting_yaml("403/blocked/marker"),
            // The audit path logs and forwards the denied query; the REST
            // path beside it stays enforced.
            same_probe(
                "audited GraphQL and REST routes/denied query is forwarded",
                exchange(ctx.clone(), graphql_get(admin, false), None),
            )
            .asserting_yaml("204/forwarded"),
            same_probe(
                "audited GraphQL and REST routes/enforced REST route",
                exchange(
                    ctx,
                    "DELETE /api/items HTTP/1.1\r\nHost: graphql.example.test:8000\r\nConnection: close\r\n\r\n"
                        .to_string(),
                    None,
                ),
            )
            .asserting_yaml("403/blocked"),
        ],
    });
}

// ---------------------------------------------------------------------------
// l7/relay/token_grant_ownership_tests.rs: native protocols beside REST
// ---------------------------------------------------------------------------

#[test]
fn ported_native_protocol_grants_beside_an_unrelated_route() {
    const PRESERVE: &str = "relay/token_grant_ownership_tests.rs::native_protocol_grants_preserve_auth_when_an_unrelated_route_is_added/multiple routes";
    const DENIALS: &str = "relay/token_grant_ownership_tests.rs::native_protocol_denials_do_not_resolve_grants_or_forward_bytes/multiple routes";
    const MISSING: &str = "relay/token_grant_ownership_tests.rs::missing_grant_owner_metadata_rejects_only_matching_requests/multiple routes";
    for protocol in ["graphql", "json-rpc", "mcp"] {
        let (rules, cedar) = native_scenario(protocol, true);
        let native = |operation| phase1::request(native_request(protocol, operation));
        let owners = |operation| phase1::owners(native_request(protocol, operation));
        let mut cases = vec![
            same_probe(PRESERVE, native("echo")).asserting_yaml("allow"),
            same_probe(PRESERVE, owners("echo")).asserting_yaml("native"),
            same_probe(DENIALS, native("blocked")).asserting_yaml("deny"),
            same_probe(DENIALS, owners("blocked")).asserting_yaml("none"),
            same_probe(
                "native protocol beside REST/unrelated route",
                phase1::owners(rest("GET", "/other/item")),
            )
            .asserting_yaml("unrelated"),
            same_probe(
                "native protocol beside REST/inspection",
                Probe::Inspection(network(phase1::HOST, phase1::PORT, BINARY)),
            ),
        ];
        if protocol == "mcp" {
            // The original installs an extra grant without owner metadata;
            // which grant is rejected is decided after owner selection.
            cases.push(same_probe(MISSING, owners("echo")).asserting_yaml("native"));
        }
        assert_provider_parity(&ProviderScenario {
            name: protocol,
            host: phase1::HOST,
            rules,
            cedar: &cedar,
            cases,
        });
    }
}
