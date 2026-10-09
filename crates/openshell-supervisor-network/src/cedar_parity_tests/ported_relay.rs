// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Ported YAML decision tests from the L7 relay, GraphQL inspection, and proxy
//! compatibility tests.
//!
//! Most originals send bytes through the relay. Each port checks the policy
//! decision the original asserts (forwarded or 403) as a request probe built
//! from the same body, parsed by the same inspector the relay uses. Relay
//! behavior that does not depend on the policy engine (middleware chains,
//! credential resolution, authority checks, framing) is not ported.

use super::*;

use crate::l7::jsonrpc::{
    JsonRpcInspectionMode, JsonRpcInspectionOptions, parse_jsonrpc_body,
    parse_jsonrpc_body_with_options,
};
use openshell_core::mcp::McpProtocolVersion;

const NODE: &str = "/usr/bin/node";
const PYTHON: &str = "/usr/bin/python3";

/// A request case the engines must agree on, in an explicit context.
fn same_in(name: &'static str, ctx: &L7EvalContext, request: L7RequestInfo) -> Case {
    same_probe(name, request_in(ctx.clone(), request))
}

/// A request carrying `body` parsed as generic JSON-RPC, as the relay does.
fn jsonrpc_body(method: &str, target: &str, body: &str) -> L7RequestInfo {
    L7RequestInfo {
        jsonrpc: Some(parse_jsonrpc_body(
            body.as_bytes(),
            JsonRpcInspectionMode::JsonRpc,
        )),
        ..rest(method, target)
    }
}

/// A request carrying `body` parsed as MCP at the 2025-11-25 revision.
fn mcp_body(method: &str, target: &str, body: &str) -> L7RequestInfo {
    L7RequestInfo {
        jsonrpc: Some(parse_jsonrpc_body_with_options(
            body.as_bytes(),
            JsonRpcInspectionOptions::mcp_selected(McpProtocolVersion::V2025_11_25, true),
        )),
        ..rest(method, target)
    }
}

/// A POST carrying a GraphQL JSON envelope, classified as the relay does.
fn graphql_body(target: &str, body: &serde_json::Value) -> L7RequestInfo {
    L7RequestInfo {
        graphql: Some(crate::l7::graphql::classify_json_envelope_value(body)),
        ..rest("POST", target)
    }
}

/// Call `index` of a JSON-RPC batch as the relay evaluates it.
///
/// The relay authorizes a batch by evaluating each call as its own request
/// (`jsonrpc_request_for_call` in `l7/relay.rs`), so a batch probe must do
/// the same rather than send the whole batch to the engine.
fn batch_call(request: &L7RequestInfo, index: usize) -> L7RequestInfo {
    let info = request.jsonrpc.as_ref().expect("JSON-RPC request");
    assert!(
        info.is_batch && !info.has_response,
        "batch without responses"
    );
    L7RequestInfo {
        jsonrpc: Some(JsonRpcRequestInfo {
            mcp_revision: info.mcp_revision,
            ..jsonrpc_info(vec![info.calls[index].clone()])
        }),
        ..request.clone()
    }
}

/// The empty `GET` an MCP client sends to open its receive stream.
fn mcp_receive_stream(target: &str) -> L7RequestInfo {
    L7RequestInfo {
        jsonrpc: Some(JsonRpcRequestInfo::receive_stream()),
        ..rest("GET", target)
    }
}

#[test]
fn ported_graphql_field_policy_allows_absolute_form_chunked_post() {
    // The original also declares a persisted-query registry, which Cedar
    // cannot express. This request is not a persisted query, so the registry
    // does not affect its decision.
    let ctx = l7_ctx("host.openshell.internal", 8080, PYTHON);
    assert_parity(&Scenario {
        name: "graphql.rs field policy",
        host: "host.openshell.internal",
        yaml: r"
network_policies:
  test_graphql_l7:
    name: test_graphql_l7
    endpoints:
      - host: host.openshell.internal
        port: 8080
        protocol: graphql
        enforcement: enforce
        persisted_queries: allow_registered
        graphql_persisted_queries:
          abc123:
            operation_type: query
            operation_name: Viewer
            fields: [viewer]
        rules:
          - allow:
              operation_type: query
              fields: [viewer]
          - allow:
              operation_type: mutation
              fields: [createIssue]
        deny_rules:
          - operation_type: mutation
            fields: [deleteRepository]
    binaries:
      - { path: /usr/bin/python3 }
",
        cedar: r#"
@protocol("graphql")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"host.openshell.internal:8080")
when {
    context.binary_path == "/usr/bin/python3"
    && ((context.graphql_operation_type == "query"
         && context.graphql_fields.containsAny(["viewer"])
         && ["viewer"].containsAll(context.graphql_fields))
        || (context.graphql_operation_type == "mutation"
            && context.graphql_fields.containsAny(["createIssue"])
            && ["createIssue"].containsAll(context.graphql_fields)))
};
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"host.openshell.internal:8080")
when {
    context.graphql_operation_type == "mutation"
    && context.graphql_fields.containsAny(["deleteRepository"])
};
"#,
        cases: vec![same_in(
            "graphql.rs::absolute_form_chunked_graphql_post_is_allowed_by_field_policy",
            &ctx,
            graphql_body(
                "/graphql",
                &serde_json::json!({"query": "query Viewer { viewer { login } }"}),
            ),
        )],
    });
}

#[test]
fn ported_identity_required_policy_binary_match() {
    assert_parity(&Scenario {
        name: "compatibility.rs identity",
        host: "target.example",
        yaml: r"
network_policies:
  proxy_compatibility:
    name: proxy_compatibility
    endpoints:
      - host: target.example
        port: 443
    binaries:
      - path: /usr/bin/curl
",
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"target.example:443")
when { context.binary_path == "/usr/bin/curl" };
"#,
        cases: vec![
            same_probe(
                "compatibility.rs::identity_required_policy_accepts_real_binary_and_rejects_empty_exec_path/real binary",
                Probe::Connect(network("target.example", 443, BINARY)),
            ),
            same_probe(
                "compatibility.rs::identity_required_policy_accepts_real_binary_and_rejects_empty_exec_path/empty path",
                Probe::Connect(network("target.example", 443, "")),
            ),
        ],
    });
}

/// The `rest_api` policy from `middleware_relay_context_with_enforcement`,
/// without its middleware chain, which does not take part in the policy
/// decision.
fn middleware_rest_yaml(enforcement: &str) -> String {
    format!(
        r#"
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: api.example.test
        port: 8080
        protocol: rest
        enforcement: {enforcement}
        rules:
          - allow:
              method: POST
              path: "/v1/**"
    binaries:
      - {{ path: /usr/bin/curl }}
"#
    )
}

fn middleware_rest_cedar(enforcement_annotation: &str) -> String {
    format!(
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.test:8080")
when {{ context.binary_path == "/usr/bin/curl" }};
@protocol("rest"){enforcement_annotation}
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.test:8080")
when {{
    context.binary_path == "/usr/bin/curl"
    && context.method == "POST"
    && context.path like("/v1/**", "/")
}};
"#
    )
}

#[test]
fn ported_l7_denial_precedes_credential_endpoint_resolution() {
    // The original checks that the policy denial comes before credential
    // resolution; the engine-independent ordering is not ported.
    let ctx = l7_ctx("api.example.test", 8080, BINARY);
    let yaml = middleware_rest_yaml("enforce");
    let cedar = middleware_rest_cedar("");
    assert_parity(&Scenario {
        name: "relay.rs rest_api enforce",
        host: "api.example.test",
        yaml: &yaml,
        cedar: &cedar,
        cases: vec![same_in(
            "relay.rs::l7_denial_precedes_credential_endpoint_resolution",
            &ctx,
            rest("GET", "/outside"),
        )],
    });
}

#[test]
fn ported_audit_endpoint_forwards_policy_denied_request() {
    // The relay forwards the request because the policy denies it on an
    // audit endpoint: both engines must deny it and select audit enforcement.
    let ctx = l7_ctx("api.example.test", 8080, BINARY);
    let yaml = middleware_rest_yaml("audit");
    let cedar = middleware_rest_cedar("\n@enforcement(\"audit\")");
    assert_parity(&Scenario {
        name: "relay.rs rest_api audit",
        host: "api.example.test",
        yaml: &yaml,
        cedar: &cedar,
        cases: vec![
            same_in(
                "relay.rs::audit_endpoint_forwards_policy_denied_request_through_healthy_chain/decision",
                &ctx,
                rest("GET", "/other"),
            ),
            same_probe(
                "relay.rs::audit_endpoint_forwards_policy_denied_request_through_healthy_chain/enforcement",
                Probe::Inspection(network("api.example.test", 8080, BINARY)),
            ),
        ],
    });
}

/// The `jsonrpc_api` policy from `jsonrpc_transforming_relay_parts`, without
/// the rewriting middleware.
fn transforming_jsonrpc_yaml(enforcement: &str) -> String {
    format!(
        r"
network_policies:
  jsonrpc_api:
    name: jsonrpc_api
    endpoints:
      - host: api.example.test
        port: 443
        protocol: json-rpc
        enforcement: {enforcement}
        rules:
          - allow:
              method: reports.list
    binaries:
      - {{ path: /usr/bin/node }}
"
    )
}

fn transforming_jsonrpc_cedar(enforcement_annotation: &str) -> String {
    format!(
        r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.test:443")
when {{ context.binary_path == "/usr/bin/node" }};
@protocol("json-rpc"){enforcement_annotation}
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.test:443")
when {{
    context.binary_path == "/usr/bin/node"
    && !context.jsonrpc_response
    && context.jsonrpc_method == "reports.list"
}};
"#
    )
}

const ORIGINAL_JSONRPC_BODY: &str = r#"{"jsonrpc":"2.0","id":1,"method":"reports.list"}"#;
const REWRITTEN_JSONRPC_BODY: &str = r#"{"jsonrpc":"2.0","id":1,"method":"admin.delete"}"#;

#[test]
fn ported_transformed_jsonrpc_body_is_reevaluated_and_denied() {
    let ctx = l7_ctx("api.example.test", 443, NODE);
    let yaml = transforming_jsonrpc_yaml("enforce");
    let cedar = transforming_jsonrpc_cedar("");
    assert_parity(&Scenario {
        name: "relay.rs transformed JSON-RPC enforce",
        host: "api.example.test",
        yaml: &yaml,
        cedar: &cedar,
        cases: vec![
            same_in(
                "relay.rs::transformed_jsonrpc_body_is_reevaluated_and_denied/original",
                &ctx,
                jsonrpc_body("POST", "/rpc", ORIGINAL_JSONRPC_BODY),
            ),
            same_in(
                "relay.rs::transformed_jsonrpc_body_is_reevaluated_and_denied/rewritten",
                &ctx,
                jsonrpc_body("POST", "/rpc", REWRITTEN_JSONRPC_BODY),
            ),
        ],
    });
}

#[test]
fn ported_transformed_jsonrpc_body_policy_deny_forwards_under_audit() {
    let ctx = l7_ctx("api.example.test", 443, NODE);
    let yaml = transforming_jsonrpc_yaml("audit");
    let cedar = transforming_jsonrpc_cedar("\n@enforcement(\"audit\")");
    assert_parity(&Scenario {
        name: "relay.rs transformed JSON-RPC audit",
        host: "api.example.test",
        yaml: &yaml,
        cedar: &cedar,
        cases: vec![
            same_in(
                "relay.rs::transformed_jsonrpc_body_policy_deny_forwards_under_audit/rewritten",
                &ctx,
                jsonrpc_body("POST", "/rpc", REWRITTEN_JSONRPC_BODY),
            ),
            same_probe(
                "relay.rs::transformed_jsonrpc_body_policy_deny_forwards_under_audit/enforcement",
                Probe::Inspection(network("api.example.test", 443, NODE)),
            ),
        ],
    });
}

#[test]
fn ported_transformed_graphql_body_is_reevaluated_and_denied() {
    let ctx = l7_ctx("api.example.test", 443, NODE);
    assert_parity(&Scenario {
        name: "relay.rs transformed GraphQL",
        host: "api.example.test",
        yaml: r"
network_policies:
  graphql_api:
    name: graphql_api
    endpoints:
      - host: api.example.test
        port: 443
        protocol: graphql
        enforcement: enforce
        rules:
          - allow:
              operation_type: query
              fields: [viewer]
    binaries:
      - { path: /usr/bin/node }
",
        cedar: r#"
@protocol("graphql")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.test:443")
when {
    context.binary_path == "/usr/bin/node"
    && context.graphql_operation_type == "query"
    && context.graphql_fields.containsAny(["viewer"])
    && ["viewer"].containsAll(context.graphql_fields)
};
"#,
        cases: vec![
            same_in(
                "relay.rs::transformed_graphql_body_is_reevaluated_and_denied/original",
                &ctx,
                graphql_body(
                    "/graphql",
                    &serde_json::json!({"query": "query { viewer }"}),
                ),
            ),
            same_in(
                "relay.rs::transformed_graphql_body_is_reevaluated_and_denied/rewritten",
                &ctx,
                graphql_body(
                    "/graphql",
                    &serde_json::json!({"query": "mutation { deleteRepository }"}),
                ),
            ),
        ],
    });
}

#[test]
fn ported_jsonrpc_batch_evaluates_each_call() {
    // The original's log-format assertions do not depend on the engine. A
    // batch containing a response frame is evaluated whole first, and a batch
    // of calls is evaluated call by call, as `evaluate_l7_request` does.
    let ctx = l7_ctx("api.example.test", 443, NODE);
    let allowed_batch = jsonrpc_body(
        "POST",
        "/rpc",
        r#"[
            {"jsonrpc":"2.0","id":1,"method":"reports.list"},
            {"jsonrpc":"2.0","id":2,"method":"reports.search","params":{"query":"private_query_value"}}
        ]"#,
    );
    let denied_batch = jsonrpc_body(
        "POST",
        "/rpc",
        r#"[
            {"jsonrpc":"2.0","id":1,"method":"reports.list"},
            {"jsonrpc":"2.0","id":2,"method":"reports.search","params":{"query":"private_query_value"}},
            {"jsonrpc":"2.0","id":3,"method":"reports.delete","params":{"id":"purge_cache"}}
        ]"#,
    );
    assert_parity(&Scenario {
        name: "relay.rs JSON-RPC batch",
        host: "api.example.test",
        yaml: r#"
network_policies:
  jsonrpc_api:
    name: jsonrpc_api
    endpoints:
      - host: api.example.test
        port: 443
        protocol: json-rpc
        enforcement: enforce
        rules:
          - allow:
              method: "reports.list"
          - allow:
              method: "reports.search"
        deny_rules:
          - method: "reports.delete"
    binaries:
      - { path: /usr/bin/node }
"#,
        cedar: r#"
@protocol("json-rpc")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.test:443")
when {
    context.binary_path == "/usr/bin/node"
    && !context.jsonrpc_response
    && ["reports.list", "reports.search"].contains(context.jsonrpc_method)
};
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.test:443")
when { context.jsonrpc_method == "reports.delete" };
"#,
        cases: vec![
            same_in(
                "relay.rs::jsonrpc_batch_evaluates_each_call/allowed batch, call 1",
                &ctx,
                batch_call(&allowed_batch, 0),
            ),
            same_in(
                "relay.rs::jsonrpc_batch_evaluates_each_call/allowed batch, call 2",
                &ctx,
                batch_call(&allowed_batch, 1),
            ),
            same_in(
                "relay.rs::jsonrpc_batch_evaluates_each_call/batch with response",
                &ctx,
                jsonrpc_body(
                    "POST",
                    "/rpc",
                    r#"[
                        {"jsonrpc":"2.0","id":1,"method":"reports.list"},
                        {"jsonrpc":"2.0","id":2,"result":{"ok":true}}
                    ]"#,
                ),
            ),
            same_in(
                "relay.rs::jsonrpc_batch_evaluates_each_call/response only",
                &ctx,
                jsonrpc_body(
                    "POST",
                    "/rpc",
                    r#"{"jsonrpc":"2.0","id":2,"result":{"ok":true}}"#,
                ),
            ),
            same_in(
                "relay.rs::jsonrpc_batch_evaluates_each_call/denied batch, call 1",
                &ctx,
                batch_call(&denied_batch, 0),
            ),
            same_in(
                "relay.rs::jsonrpc_batch_evaluates_each_call/denied batch, call 2",
                &ctx,
                batch_call(&denied_batch, 1),
            ),
            same_in(
                "relay.rs::jsonrpc_batch_evaluates_each_call/denied batch, call 3",
                &ctx,
                batch_call(&denied_batch, 2),
            ),
        ],
    });
}

#[test]
fn ported_jsonrpc_request_params_do_not_affect_method_policy() {
    let ctx = l7_ctx("api.example.test", 443, NODE);
    assert_parity(&Scenario {
        name: "relay.rs JSON-RPC params",
        host: "api.example.test",
        yaml: r#"
network_policies:
  jsonrpc_api:
    name: jsonrpc_api
    endpoints:
      - host: api.example.test
        port: 443
        protocol: json-rpc
        enforcement: enforce
        rules:
          - allow:
              method: "reports.search"
    binaries:
      - { path: /usr/bin/node }
"#,
        cedar: r#"
@protocol("json-rpc")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.test:443")
when {
    context.binary_path == "/usr/bin/node"
    && !context.jsonrpc_response
    && context.jsonrpc_method == "reports.search"
};
"#,
        cases: vec![
            same_in(
                "relay.rs::jsonrpc_request_params_do_not_affect_method_policy/object params",
                &ctx,
                jsonrpc_body(
                    "POST",
                    "/rpc",
                    r#"{"jsonrpc":"2.0","id":1,"method":"reports.search","params":{"query":"delete_resource","filters":{"scope":"workspace/secret"}}}"#,
                ),
            ),
            same_in(
                "relay.rs::jsonrpc_request_params_do_not_affect_method_policy/array params",
                &ctx,
                jsonrpc_body(
                    "POST",
                    "/rpc",
                    r#"{"jsonrpc":"2.0","id":1,"method":"reports.search","params":["ignored",{"nested":true}]}"#,
                ),
            ),
        ],
    });
}

#[test]
fn ported_mcp_tool_deny_rule_blocks_tools_call() {
    // MCP endpoints in YAML implicitly admit the receive stream and response
    // frames; the second Cedar permit states that explicitly.
    let ctx = l7_ctx("api.example.test", 443, NODE);
    assert_parity(&Scenario {
        name: "relay.rs MCP tool deny",
        host: "api.example.test",
        yaml: r#"
network_policies:
  mcp_api:
    name: mcp_api
    endpoints:
      - host: api.example.test
        port: 443
        path: "/mcp"
        protocol: mcp
        enforcement: enforce
        mcp:
          max_body_bytes: 131072
        rules:
          - allow:
              method: initialize
          - allow:
              method: tools/list
          - allow:
              method: tools/call
              tool: read_status
        deny_rules:
          - method: tools/call
            tool: delete_resource
    binaries:
      - { path: /usr/bin/node }
"#,
        cedar: r#"
@protocol("mcp")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.test:443")
when {
    context.binary_path == "/usr/bin/node"
    && context.path == "/mcp"
    && !context.jsonrpc_response
    && context.mcp_method_class == "available"
    && (["initialize", "tools/list"].contains(context.jsonrpc_method)
        || (context.jsonrpc_method == "tools/call" && context.mcp_tool == "read_status"))
};
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.test:443")
when {
    context.binary_path == "/usr/bin/node"
    && context.path == "/mcp"
    && ((context.method == "GET" && context.jsonrpc_receive_stream)
        || context.jsonrpc_response)
};
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.test:443")
when { context.jsonrpc_method == "tools/call" && context.mcp_tool == "delete_resource" };
"#,
        cases: vec![
            same_in(
                "relay.rs::mcp_tool_deny_rule_blocks_tools_call/read_status",
                &ctx,
                mcp_body(
                    "POST",
                    "/mcp",
                    r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_status","arguments":{}}}"#,
                ),
            ),
            same_in(
                "relay.rs::mcp_tool_deny_rule_blocks_tools_call/delete_resource",
                &ctx,
                mcp_body(
                    "POST",
                    "/mcp",
                    r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_resource","arguments":{"scope":"workspace/main"}}}"#,
                ),
            ),
        ],
    });
}

#[test]
fn ported_mcp_legacy_receive_stream_get() {
    // `mcp.versions: ["2025-11-25"]` has no Cedar counterpart; every request
    // here uses that revision, which is also the default.
    let ctx = l7_ctx("mcp.example.test", 8000, PYTHON);
    let delete_body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_resource","arguments":{}}}"#;
    let read_body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_status","arguments":{}}}"#;
    assert_parity(&Scenario {
        name: "relay.rs MCP legacy receive stream",
        host: "mcp.example.test",
        yaml: r#"
network_policies:
  mcp_api:
    name: mcp_api
    endpoints:
      - host: mcp.example.test
        port: 8000
        path: /mcp
        protocol: mcp
        enforcement: enforce
        mcp:
          versions: ["2025-11-25"]
        rules:
          - allow:
              method: tools/call
              tool: read_status
        deny_rules:
          - method: tools/call
            tool: delete_resource
    binaries:
      - { path: /usr/bin/python3 }
"#,
        cedar: r#"
@protocol("mcp")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"mcp.example.test:8000")
when {
    context.binary_path == "/usr/bin/python3"
    && context.path == "/mcp"
    && !context.jsonrpc_response
    && context.mcp_method_class == "available"
    && context.jsonrpc_method == "tools/call"
    && context.mcp_tool == "read_status"
};
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"mcp.example.test:8000")
when {
    context.binary_path == "/usr/bin/python3"
    && context.path == "/mcp"
    && ((context.method == "GET" && context.jsonrpc_receive_stream)
        || context.jsonrpc_response)
};
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"mcp.example.test:8000")
when { context.jsonrpc_method == "tools/call" && context.mcp_tool == "delete_resource" };
"#,
        cases: vec![
            same_in(
                "relay.rs::mcp_legacy_receive_stream_get_does_not_admit_tool_bodies_or_delete/empty GET",
                &ctx,
                mcp_receive_stream("/mcp"),
            ),
            same_in(
                "relay.rs::mcp_legacy_receive_stream_get_does_not_admit_tool_bodies_or_delete/GET with denied tool",
                &ctx,
                mcp_body("GET", "/mcp", delete_body),
            ),
            same_in(
                "relay.rs::mcp_legacy_receive_stream_get_does_not_admit_tool_bodies_or_delete/GET with allowed tool",
                &ctx,
                mcp_body("GET", "/mcp", read_body),
            ),
            // The relay rejects this unparseable body with 400 before policy
            // runs; this checks that neither engine allows it on its own.
            same_in(
                "relay.rs::mcp_legacy_receive_stream_get_does_not_admit_tool_bodies_or_delete/empty DELETE",
                &ctx,
                mcp_body("DELETE", "/mcp", ""),
            ),
        ],
    });
}

#[test]
fn ported_mcp_relay_forwards_jsonrpc_response_frame() {
    let ctx = l7_ctx("mcp.example.test", 8000, PYTHON);
    assert_parity(&Scenario {
        name: "relay.rs MCP response frame",
        host: "mcp.example.test",
        yaml: r"
network_policies:
  mcp_api:
    name: mcp_api
    endpoints:
      - host: mcp.example.test
        port: 8000
        path: /mcp
        protocol: mcp
        enforcement: enforce
        rules:
          - allow:
              method: initialize
    binaries:
      - { path: /usr/bin/python3 }
",
        cedar: r#"
@protocol("mcp")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"mcp.example.test:8000")
when {
    context.binary_path == "/usr/bin/python3"
    && context.path == "/mcp"
    && !context.jsonrpc_response
    && context.mcp_method_class == "available"
    && context.jsonrpc_method == "initialize"
};
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"mcp.example.test:8000")
when {
    context.binary_path == "/usr/bin/python3"
    && context.path == "/mcp"
    && ((context.method == "GET" && context.jsonrpc_receive_stream)
        || context.jsonrpc_response)
};
"#,
        cases: vec![same_in(
            "relay.rs::mcp_relay_forwards_jsonrpc_response_frame",
            &ctx,
            mcp_body(
                "POST",
                "/mcp",
                r#"{"jsonrpc":"2.0","id":7,"result":{"action":"accept","content":{}}}"#,
            ),
        )],
    });
}

#[test]
fn ported_jsonrpc_relay_initialize_allow_list() {
    let ctx = l7_ctx("jsonrpc.example.test", 8000, PYTHON);
    assert_parity(&Scenario {
        name: "relay.rs JSON-RPC relay",
        host: "jsonrpc.example.test",
        yaml: r#"
network_policies:
  jsonrpc_api:
    name: jsonrpc_api
    endpoints:
      - host: jsonrpc.example.test
        port: 8000
        path: "/rpc"
        protocol: json-rpc
        enforcement: enforce
        rules:
          - allow:
              method: initialize
    binaries:
      - { path: /usr/bin/python3 }
"#,
        cedar: r#"
@protocol("json-rpc")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"jsonrpc.example.test:8000")
when {
    context.binary_path == "/usr/bin/python3"
    && context.path == "/rpc"
    && !context.jsonrpc_response
    && context.jsonrpc_method == "initialize"
};
"#,
        cases: vec![
            same_in(
                "relay.rs::jsonrpc_relay_forwards_allowed_method",
                &ctx,
                jsonrpc_body(
                    "POST",
                    "/rpc",
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
                ),
            ),
            same_in(
                "relay.rs::jsonrpc_relay_denies_method_not_in_allow_list",
                &ctx,
                jsonrpc_body(
                    "POST",
                    "/rpc",
                    r#"{"jsonrpc":"2.0","id":1,"method":"reports.search","params":{"query":"list_repos"}}"#,
                ),
            ),
        ],
    });
}

/// The per-protocol policy from `chunked_http_pipeline_authorizes_each_request`.
fn pipeline_yaml(protocol: &str, endpoint_path: &str, rules: &str) -> String {
    format!(
        r"
network_policies:
  mcp_api:
    name: mcp_api
    endpoints:
      - host: mcp.example.test
        port: 8000
        path: {endpoint_path}
        protocol: {protocol}
        enforcement: enforce
        rules:
          - allow: {{ {rules} }}
    binaries:
      - {{ path: /usr/bin/python3 }}
"
    )
}

#[test]
fn ported_chunked_http_pipeline_authorizes_each_request() {
    // Each pipeline sends an allowed first request and a second request that
    // is allowed (`echo`) or denied (`blocked`); the original asserts the
    // policy decision for each.
    let ctx = l7_ctx("mcp.example.test", 8000, PYTHON);
    let mcp_call = |name: &str| {
        mcp_body(
            "POST",
            "/mcp",
            &serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": name, "arguments": {}}
            })
            .to_string(),
        )
    };
    let jsonrpc_call = |name: &str| {
        jsonrpc_body(
            "POST",
            "/mcp",
            &serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": name}).to_string(),
        )
    };
    let graphql_query = |name: &str| {
        graphql_body(
            "/mcp",
            &serde_json::json!({"query": format!("query {{ {name} }}")}),
        )
    };

    let yaml = pipeline_yaml("mcp", "/mcp", "method: tools/call, tool: echo");
    assert_parity(&Scenario {
        name: "relay.rs pipeline mcp",
        host: "mcp.example.test",
        yaml: &yaml,
        cedar: r#"
@protocol("mcp")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"mcp.example.test:8000")
when {
    context.binary_path == "/usr/bin/python3"
    && context.path == "/mcp"
    && !context.jsonrpc_response
    && context.mcp_method_class == "available"
    && context.jsonrpc_method == "tools/call"
    && context.mcp_tool == "echo"
};
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"mcp.example.test:8000")
when {
    context.binary_path == "/usr/bin/python3"
    && context.path == "/mcp"
    && ((context.method == "GET" && context.jsonrpc_receive_stream)
        || context.jsonrpc_response)
};
"#,
        cases: vec![
            same_in(
                "relay.rs::chunked_http_pipeline_authorizes_each_request/mcp echo",
                &ctx,
                mcp_call("echo"),
            ),
            same_in(
                "relay.rs::chunked_http_pipeline_authorizes_each_request/mcp blocked",
                &ctx,
                mcp_call("blocked"),
            ),
        ],
    });

    let yaml = pipeline_yaml("json-rpc", "/mcp", "method: echo");
    assert_parity(&Scenario {
        name: "relay.rs pipeline json-rpc",
        host: "mcp.example.test",
        yaml: &yaml,
        cedar: r#"
@protocol("json-rpc")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"mcp.example.test:8000")
when {
    context.binary_path == "/usr/bin/python3"
    && context.path == "/mcp"
    && !context.jsonrpc_response
    && context.jsonrpc_method == "echo"
};
"#,
        cases: vec![
            same_in(
                "relay.rs::chunked_http_pipeline_authorizes_each_request/json-rpc echo",
                &ctx,
                jsonrpc_call("echo"),
            ),
            same_in(
                "relay.rs::chunked_http_pipeline_authorizes_each_request/json-rpc blocked",
                &ctx,
                jsonrpc_call("blocked"),
            ),
        ],
    });

    let yaml = pipeline_yaml("graphql", "/mcp", "operation_type: query, fields: [echo]");
    assert_parity(&Scenario {
        name: "relay.rs pipeline graphql",
        host: "mcp.example.test",
        yaml: &yaml,
        cedar: r#"
@protocol("graphql")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"mcp.example.test:8000")
when {
    context.binary_path == "/usr/bin/python3"
    && context.path == "/mcp"
    && context.graphql_operation_type == "query"
    && context.graphql_fields.containsAny(["echo"])
    && ["echo"].containsAll(context.graphql_fields)
};
"#,
        cases: vec![
            same_in(
                "relay.rs::chunked_http_pipeline_authorizes_each_request/graphql echo",
                &ctx,
                graphql_query("echo"),
            ),
            same_in(
                "relay.rs::chunked_http_pipeline_authorizes_each_request/graphql blocked",
                &ctx,
                graphql_query("blocked"),
            ),
        ],
    });

    let yaml = pipeline_yaml("rest", "/mcp/**", "method: POST, path: /mcp/allowed");
    assert_parity(&Scenario {
        name: "relay.rs pipeline rest",
        host: "mcp.example.test",
        yaml: &yaml,
        cedar: r#"
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"mcp.example.test:8000")
when {
    context.binary_path == "/usr/bin/python3"
    && context.method == "POST"
    && context.path == "/mcp/allowed"
};
"#,
        cases: vec![
            same_in(
                "relay.rs::chunked_http_pipeline_authorizes_each_request/rest allowed",
                &ctx,
                rest("POST", "/mcp/allowed"),
            ),
            same_in(
                "relay.rs::chunked_http_pipeline_authorizes_each_request/rest blocked",
                &ctx,
                rest("POST", "/mcp/blocked"),
            ),
        ],
    });
}

/// The `route_api` policy from `assert_endpoint_path_deny`: an endpoint scoped
/// to `selector` that denies POST, and an unscoped endpoint that allows all.
fn endpoint_path_deny_yaml(selector: &str) -> String {
    format!(
        r#"
network_policies:
  route_api:
    endpoints:
      - host: gateway.example.test
        port: 443
        path: "{selector}"
        protocol: rest
        enforcement: enforce
        rules:
          - allow: {{ method: "*", path: "**" }}
        deny_rules:
          - {{ method: POST, path: "**" }}
      - host: gateway.example.test
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow: {{ method: "*", path: "**" }}
    binaries:
      - {{ path: /usr/bin/node }}
"#
    )
}

/// Both endpoints are REST with enforcement, so one Cedar endpoint permits
/// everything and forbids POST under the selector.
fn endpoint_path_deny_cedar(selector_condition: &str) -> String {
    format!(
        r#"
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"gateway.example.test:443")
when {{ context.binary_path == "/usr/bin/node" }};
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"gateway.example.test:443")
when {{ context.method == "POST" && ({selector_condition}) }};
"#
    )
}

#[test]
fn ported_endpoint_path_deny_subtree_selector() {
    let ctx = l7_ctx("gateway.example.test", 443, NODE);
    let yaml = endpoint_path_deny_yaml("/p/**");
    let cedar =
        endpoint_path_deny_cedar(r#"context.path == "/p" || context.path like("/p/**", "/")"#);
    assert_parity(&Scenario {
        name: "relay.rs endpoint path deny /p/**",
        host: "gateway.example.test",
        yaml: &yaml,
        cedar: &cedar,
        cases: vec![
            same_in(
                "relay.rs::endpoint_path_deny_covers_subtree_root",
                &ctx,
                rest("POST", "/p"),
            ),
            same_in(
                "relay.rs::endpoint_path_deny_preserves_matching_and_nonmatching_controls/POST /p/child",
                &ctx,
                rest("POST", "/p/child"),
            ),
            same_in(
                "relay.rs::endpoint_path_deny_preserves_matching_and_nonmatching_controls/GET /p",
                &ctx,
                rest("GET", "/p"),
            ),
            same_in(
                "relay.rs::endpoint_path_deny_preserves_matching_and_nonmatching_controls/POST /public",
                &ctx,
                rest("POST", "/public"),
            ),
            same_in(
                "relay.rs::endpoint_path_deny_preserves_matching_and_nonmatching_controls/POST /prefix",
                &ctx,
                rest("POST", "/prefix"),
            ),
        ],
    });
}

#[test]
fn ported_endpoint_path_deny_single_star_selector() {
    // YAML treats a trailing `/*` endpoint selector as multi-segment, so the
    // Cedar translation uses `/v1/**`.
    let ctx = l7_ctx("gateway.example.test", 443, NODE);
    let yaml = endpoint_path_deny_yaml("/v1/*");
    let cedar = endpoint_path_deny_cedar(r#"context.path like("/v1/**", "/")"#);
    assert_parity(&Scenario {
        name: "relay.rs endpoint path deny /v1/*",
        host: "gateway.example.test",
        yaml: &yaml,
        cedar: &cedar,
        cases: vec![
            same_in(
                "relay.rs::endpoint_path_deny_covers_multisegment_star",
                &ctx,
                rest("POST", "/v1/a/b"),
            ),
            same_in(
                "control: GET under the selector",
                &ctx,
                rest("GET", "/v1/a/b"),
            ),
            same_in(
                "control: POST outside the selector",
                &ctx,
                rest("POST", "/v2/a"),
            ),
            same_in(
                "relay.rs::endpoint_path_deny_preserves_matching_and_nonmatching_controls/POST /v1/a",
                &ctx,
                rest("POST", "/v1/a"),
            ),
        ],
    });
}

#[test]
fn ported_route_selected_unmatched_path_is_denied() {
    // The original also checks the denied policy activity; emission does not
    // depend on the engine. `allow_encoded_slash` has no Cedar counterpart and
    // does not affect this unencoded path.
    let ctx = l7_ctx("gateway.example.test", 443, NODE);
    assert_parity(&Scenario {
        name: "relay.rs route selection",
        host: "gateway.example.test",
        yaml: r#"
network_policies:
  route_api:
    name: route_api
    endpoints:
      - host: gateway.example.test
        port: 443
        path: /repos/**
        protocol: rest
        enforcement: enforce
        allow_encoded_slash: true
        rules:
          - allow:
              method: GET
              path: "/repos/**"
      - host: gateway.example.test
        port: 443
        path: /admin/**
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/admin/**"
    binaries:
      - { path: /usr/bin/node }
"#,
        cedar: r#"
@protocol("rest")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"gateway.example.test:443")
when {
    context.binary_path == "/usr/bin/node"
    && context.method == "GET"
    && (context.path like("/repos/**", "/") || context.path like("/admin/**", "/"))
};
"#,
        cases: vec![same_in(
            "relay.rs::route_selected_unmatched_path_emits_denied_policy_activity",
            &ctx,
            rest("GET", "/other"),
        )],
    });
}

#[test]
fn ported_single_endpoint_graphql_post_still_inspects_body() {
    // The original's authority-mismatch cases (no Host header, credential
    // marker) do not depend on the engine and are not ported.
    let ctx = l7_ctx("graphql.example.test", 8000, PYTHON);
    let query = |field: &str| {
        graphql_body(
            "/graphql",
            &serde_json::json!({"query": format!("{{{field}}}"), "variables": {"token": ""}}),
        )
    };
    assert_parity(&Scenario {
        name: "relay.rs single-endpoint GraphQL",
        host: "graphql.example.test",
        yaml: r"
network_policies:
  graphql_api:
    name: graphql_api
    endpoints:
      - host: graphql.example.test
        port: 8000
        path: /graphql
        protocol: graphql
        enforcement: enforce
        rules:
          - allow:
              operation_type: query
              fields: [viewer]
    binaries:
      - { path: /usr/bin/python3 }
",
        cedar: r#"
@protocol("graphql")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"graphql.example.test:8000")
when {
    context.binary_path == "/usr/bin/python3"
    && context.path == "/graphql"
    && context.graphql_operation_type == "query"
    && context.graphql_fields.containsAny(["viewer"])
    && ["viewer"].containsAll(context.graphql_fields)
};
"#,
        cases: vec![
            same_in(
                "relay.rs::single_endpoint_graphql_post_still_inspects_body/viewer",
                &ctx,
                query("viewer"),
            ),
            same_in(
                "relay.rs::single_endpoint_graphql_post_still_inspects_body/admin",
                &ctx,
                query("admin"),
            ),
        ],
    });
}
