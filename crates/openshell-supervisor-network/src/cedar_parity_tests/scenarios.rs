// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Hand-written parity scenarios for REST, JSON-RPC, MCP, and GraphQL.

use super::*;

#[test]
fn rest_parity() {
    assert_parity(&Scenario {
        name: "REST",
        host: "api.example.com",
        yaml: r#"
network_policies:
  api:
    name: api
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow: { method: GET, path: "/repos/**" }
          - allow: { method: POST, path: "/repos/*/*/issues" }
          - allow: { method: GET, path: "/files/report**" }
        deny_rules:
          - { method: "*", path: "/repos/*/*/hooks/**" }
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: r#"
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when {
    context.binary_path == "/usr/bin/curl"
    && ((context.method == "GET" && context.path like("/repos/**", "/"))
        || (context.method == "POST" && context.path like("/repos/*/*/issues", "/"))
        || (context.method == "GET" && context.path like("/files/report**", "/")))
};
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.path like("/repos/*/*/hooks/**", "/") };
"#,
        cases: vec![
            same("GET under /repos", rest("GET", "/repos/nvidia/openshell")),
            same(
                "POST to issues",
                rest("POST", "/repos/nvidia/openshell/issues"),
            ),
            same(
                "POST to pulls",
                rest("POST", "/repos/nvidia/openshell/pulls"),
            ),
            same(
                "deny rule on hooks",
                rest("GET", "/repos/nvidia/openshell/hooks/1"),
            ),
            same("other method", rest("DELETE", "/repos/nvidia/openshell")),
            same("other path", rest("GET", "/orgs/nvidia")),
            same("lowercase method", rest("get", "/repos/nvidia/openshell")),
            diverges(
                "HEAD under a GET rule",
                rest("HEAD", "/repos/nvidia/openshell"),
                "YAML lets a GET rule allow HEAD; a Cedar policy must list HEAD",
            ),
            same("empty trailing segment", rest("GET", "/repos/")),
            same("no trailing segment", rest("GET", "/repos")),
            same(
                "`**` inside a segment, same segment",
                rest("GET", "/files/report-2024"),
            ),
            diverges(
                "`**` inside a segment, deeper path",
                rest("GET", "/files/report/2024/q1"),
                "YAML treats `**` next to other characters as `*`; Cedar's `**` crosses segments",
            ),
        ],
    });
}

#[test]
fn json_rpc_parity() {
    let response_frame = L7RequestInfo {
        jsonrpc: Some(JsonRpcRequestInfo {
            has_response: true,
            ..jsonrpc_info(Vec::new())
        }),
        ..rest("POST", "/rpc")
    };
    assert_parity(&Scenario {
        name: "JSON-RPC",
        host: "rpc.example.com",
        yaml: r"
network_policies:
  rpc:
    name: rpc
    endpoints:
      - host: rpc.example.com
        port: 443
        path: /rpc
        protocol: json-rpc
        enforcement: enforce
        rules:
          - allow: { method: eth_call }
          - allow: { method: eth_blockNumber }
    binaries:
      - { path: /usr/bin/curl }
",
        cedar: r#"
@protocol("json-rpc")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"rpc.example.com:443")
when {
    context.binary_path == "/usr/bin/curl"
    && context.path == "/rpc"
    && !context.jsonrpc_response
    && ["eth_call", "eth_blockNumber"].contains(context.jsonrpc_method)
};
"#,
        cases: vec![
            same(
                "listed method",
                jsonrpc_request("/rpc", vec![call("eth_call", None, None)]),
            ),
            same(
                "listed method sent with GET",
                L7RequestInfo {
                    action: "GET".to_string(),
                    ..jsonrpc_request("/rpc", vec![call("eth_call", None, None)])
                },
            ),
            same(
                "unlisted method",
                jsonrpc_request("/rpc", vec![call("eth_sendTransaction", None, None)]),
            ),
            same(
                "other path",
                jsonrpc_request("/other", vec![call("eth_call", None, None)]),
            ),
            same("response frame", response_frame),
        ],
    });
}

#[test]
fn mcp_parity() {
    use McpMethodClassification::{Available, Extension};
    let receive_stream = L7RequestInfo {
        jsonrpc: Some(JsonRpcRequestInfo {
            receive_stream: true,
            ..jsonrpc_info(Vec::new())
        }),
        ..rest("GET", "/mcp")
    };
    let response_frame = L7RequestInfo {
        jsonrpc: Some(JsonRpcRequestInfo {
            has_response: true,
            ..jsonrpc_info(Vec::new())
        }),
        ..rest("POST", "/mcp")
    };
    assert_parity(&Scenario {
        name: "MCP",
        host: "mcp.example.com",
        yaml: r#"
network_policies:
  mcp:
    name: mcp
    endpoints:
      - host: mcp.example.com
        port: 443
        path: /mcp
        protocol: mcp
        enforcement: enforce
        rules:
          - allow: { method: initialize }
          - allow: { method: tools/list }
          - allow: { method: tools/call, tool: "github.*" }
        deny_rules:
          - { method: tools/call, tool: github.delete_repo }
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: r#"
@protocol("mcp")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"mcp.example.com:443")
when {
    context.binary_path == "/usr/bin/curl"
    && context.path == "/mcp"
    && !context.jsonrpc_response
    && context.mcp_method_class == "available"
    && (["initialize", "tools/list"].contains(context.jsonrpc_method)
        || (context.jsonrpc_method == "tools/call" && context.mcp_tool like("github.*", ".")))
};
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"mcp.example.com:443")
when {
    context.binary_path == "/usr/bin/curl"
    && context.path == "/mcp"
    && ((context.method == "GET" && context.jsonrpc_receive_stream)
        || context.jsonrpc_response)
};
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"mcp.example.com:443")
when { context.jsonrpc_method == "tools/call" && context.mcp_tool == "github.delete_repo" };
"#,
        cases: vec![
            same("initialize", mcp("initialize", None, Available)),
            same(
                "allowed tool call sent with GET",
                L7RequestInfo {
                    action: "GET".to_string(),
                    ..mcp("tools/call", Some("github.search"), Available)
                },
            ),
            same("tools/list", mcp("tools/list", None, Available)),
            same(
                "tool matching the glob",
                mcp("tools/call", Some("github.search"), Available),
            ),
            same(
                "tool glob does not cross a dot",
                mcp("tools/call", Some("github.search.code"), Available),
            ),
            same(
                "tool deny rule",
                mcp("tools/call", Some("github.delete_repo"), Available),
            ),
            same(
                "tool outside the glob",
                mcp("tools/call", Some("slack.post"), Available),
            ),
            same(
                "unlisted core method",
                mcp("resources/read", None, Available),
            ),
            same("extension method", mcp("x/custom", None, Extension)),
            same("receive stream", receive_stream),
            same("response frame", response_frame.clone()),
            same(
                "response frame sent with GET",
                L7RequestInfo {
                    action: "GET".to_string(),
                    ..response_frame
                },
            ),
        ],
    });
}

#[test]
fn graphql_parity() {
    let persisted = GraphqlOperationInfo {
        persisted_query: true,
        persisted_query_hash: Some("abc123".to_string()),
        ..operation("", None, &[])
    };
    let parse_error = L7RequestInfo {
        graphql: Some(GraphqlRequestInfo {
            operations: Vec::new(),
            error: Some("syntax error".to_string()),
        }),
        ..rest("POST", "/graphql")
    };
    assert_parity(&Scenario {
        name: "GraphQL",
        host: "api.github.com",
        yaml: r#"
network_policies:
  github:
    name: github
    endpoints:
      - host: api.github.com
        port: 443
        path: /graphql
        protocol: graphql
        enforcement: enforce
        rules:
          - allow: { operation_type: query }
          - allow: { operation_type: mutation, fields: [createIssue, commentOnIssue] }
          - allow: { operation_type: subscription, operation_name: "Watch*" }
        deny_rules:
          - { operation_type: mutation, fields: [deleteRepository] }
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: r#"
@protocol("graphql")
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.github.com:443")
when {
    context.binary_path == "/usr/bin/curl"
    && context.path == "/graphql"
    && (context.graphql_operation_type == "query"
        || (context.graphql_operation_type == "mutation"
            && context.graphql_fields.containsAny(["createIssue", "commentOnIssue"])
            && ["createIssue", "commentOnIssue"].containsAll(context.graphql_fields))
        || (context.graphql_operation_type == "subscription"
            && context.graphql_operation_name like "Watch*"))
};
forbid (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.github.com:443")
when {
    context.graphql_operation_type == "mutation"
    && context.graphql_fields.containsAny(["deleteRepository"])
};
"#,
        cases: vec![
            same(
                "query",
                graphql(vec![operation("query", Some("Viewer"), &["viewer"])]),
            ),
            same(
                "query type in uppercase",
                graphql(vec![operation("QUERY", None, &["viewer"])]),
            ),
            same(
                "mutation with listed fields",
                graphql(vec![operation(
                    "mutation",
                    None,
                    &["createIssue", "commentOnIssue"],
                )]),
            ),
            same(
                "mutation with an unlisted field",
                graphql(vec![operation(
                    "mutation",
                    None,
                    &["createIssue", "unknownField"],
                )]),
            ),
            same(
                "mutation with a denied field",
                graphql(vec![operation(
                    "mutation",
                    None,
                    &["createIssue", "deleteRepository"],
                )]),
            ),
            same(
                "mutation with no fields",
                graphql(vec![operation("mutation", None, &[])]),
            ),
            same(
                "subscription matching the name glob",
                graphql(vec![operation(
                    "subscription",
                    Some("WatchIssues"),
                    &["issueAdded"],
                )]),
            ),
            same(
                "subscription outside the name glob",
                graphql(vec![operation(
                    "subscription",
                    Some("Other"),
                    &["issueAdded"],
                )]),
            ),
            same(
                "batch with one disallowed operation",
                graphql(vec![
                    operation("query", None, &["viewer"]),
                    operation("mutation", None, &["unknownField"]),
                ]),
            ),
            same("hash-only persisted query", graphql(vec![persisted])),
            // The relay rejects a request that failed GraphQL parsing before
            // policy runs; this case checks that neither engine allows it on
            // its own. Rego reports conflicting deny reasons here, which the
            // relay would also treat as a denial.
            same("parse error", parse_error),
        ],
    });
}

#[test]
fn connection_dns_and_inspection_parity() {
    assert_parity(&Scenario {
        name: "Connections",
        host: "api.example.com",
        yaml: r#"
network_policies:
  api:
    name: api
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
      - host: "*.cdn.example.com"
        port: 443
    binaries:
      - { path: /usr/bin/curl }
"#,
        cedar: r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.binary_path == "/usr/bin/curl" };
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when {
    resource.host like("*.cdn.example.com", ".")
    && resource.port == 443
    && context.binary_path == "/usr/bin/curl"
};
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { ["GET", "HEAD", "OPTIONS"].contains(context.method) };
"#,
        cases: vec![
            same_probe(
                "declared binary connects",
                Probe::Connect(network("api.example.com", 443, BINARY)),
            ),
            same_probe(
                "other binary is refused",
                Probe::Connect(network("api.example.com", 443, "/usr/bin/wget")),
            ),
            same_probe(
                "other port is refused",
                Probe::Connect(network("api.example.com", 8443, BINARY)),
            ),
            same_probe(
                "glob host connects",
                Probe::Connect(network("img.cdn.example.com", 443, BINARY)),
            ),
            same_probe(
                "glob does not cross a label",
                Probe::Connect(network("a.b.cdn.example.com", 443, BINARY)),
            ),
            same_probe(
                "exact host is exactly declared",
                Probe::ExactHost(network("api.example.com", 443, BINARY)),
            ),
            same_probe(
                "glob host is not exactly declared",
                Probe::ExactHost(network("img.cdn.example.com", 443, BINARY)),
            ),
            same_probe(
                "inspected endpoint",
                Probe::Inspection(network("api.example.com", 443, BINARY)),
            ),
            same_probe(
                "uninspected endpoint",
                Probe::Inspection(network("img.cdn.example.com", 443, BINARY)),
            ),
            same_probe(
                "exact host is DNS eligible",
                Probe::DnsEligible {
                    name: "api.example.com".to_string(),
                    port: 443,
                },
            ),
            same_probe(
                "glob host is DNS eligible",
                Probe::DnsEligible {
                    name: "img.cdn.example.com".to_string(),
                    port: 443,
                },
            ),
            same_probe(
                "undeclared host is not DNS eligible",
                Probe::DnsEligible {
                    name: "example.org".to_string(),
                    port: 443,
                },
            ),
            same_probe(
                "read-only preset allows GET",
                request_in(
                    l7_ctx("api.example.com", 443, BINARY),
                    rest("GET", "/anything"),
                ),
            ),
            same_probe(
                "read-only preset denies POST",
                request_in(
                    l7_ctx("api.example.com", 443, BINARY),
                    rest("POST", "/anything"),
                ),
            ),
        ],
    });
}
