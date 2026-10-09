// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Decision parity between YAML policies evaluated by Rego and equivalent
//! Cedar policies.
//!
//! Each scenario pairs a YAML policy with a Cedar policy written to mean the
//! same thing, and runs every request through both engines' per-tunnel
//! `evaluate_request`, the call the L7 relay makes. A case marked
//! [`Expect::Same`] fails if the decisions differ. A case marked
//! [`Expect::Diverges`] records a known difference and fails if the engines
//! start to agree, so the list stays accurate.

use std::collections::HashMap;
use std::fmt::Write as _;

use crate::cedar_only::CedarOnlyEngine;
use crate::l7::L7RequestInfo;
use crate::l7::graphql::{GraphqlOperationInfo, GraphqlRequestInfo};
use crate::l7::jsonrpc::{JsonRpcCallInfo, JsonRpcRequestInfo, McpMethodClassification};
use crate::l7::relay::L7EvalContext;
use crate::opa::OpaEngine;

const REGO: &str = include_str!("../data/sandbox-policy.rego");
const BINARY: &str = "/usr/bin/curl";

/// Whether both engines are expected to decide a case the same way.
#[derive(Debug, Clone, Copy)]
enum Expect {
    Same,
    /// A known difference, with the reason it exists.
    Diverges(&'static str),
}

struct Case {
    name: &'static str,
    request: L7RequestInfo,
    expect: Expect,
}

struct Scenario {
    name: &'static str,
    host: &'static str,
    yaml: &'static str,
    cedar: &'static str,
    cases: Vec<Case>,
}

fn same(name: &'static str, request: L7RequestInfo) -> Case {
    Case {
        name,
        request,
        expect: Expect::Same,
    }
}

fn diverges(name: &'static str, request: L7RequestInfo, reason: &'static str) -> Case {
    Case {
        name,
        request,
        expect: Expect::Diverges(reason),
    }
}

fn ctx(host: &str) -> L7EvalContext {
    L7EvalContext {
        host: host.to_string(),
        port: 443,
        binary_path: BINARY.to_string(),
        ..Default::default()
    }
}

fn rest(method: &str, path: &str) -> L7RequestInfo {
    L7RequestInfo {
        action: method.to_string(),
        target: path.to_string(),
        query_params: HashMap::new(),
        graphql: None,
        jsonrpc: None,
    }
}

fn operation(operation_type: &str, name: Option<&str>, fields: &[&str]) -> GraphqlOperationInfo {
    GraphqlOperationInfo {
        operation_type: operation_type.to_string(),
        operation_name: name.map(str::to_string),
        fields: fields.iter().map(ToString::to_string).collect(),
        persisted_query: false,
        persisted_query_hash: None,
        persisted_query_id: None,
    }
}

fn graphql(operations: Vec<GraphqlOperationInfo>) -> L7RequestInfo {
    L7RequestInfo {
        graphql: Some(GraphqlRequestInfo {
            operations,
            error: None,
        }),
        ..rest("POST", "/graphql")
    }
}

fn jsonrpc_info(calls: Vec<JsonRpcCallInfo>) -> JsonRpcRequestInfo {
    JsonRpcRequestInfo {
        calls,
        is_batch: false,
        receive_stream: false,
        has_response: false,
        mcp_revision: None,
        mcp_http_metadata: None,
        error: None,
    }
}

fn call(
    method: &str,
    tool: Option<&str>,
    class: Option<McpMethodClassification>,
) -> JsonRpcCallInfo {
    let mut params = HashMap::new();
    if let Some(tool) = tool {
        params.insert("name".to_string(), tool.to_string());
    }
    JsonRpcCallInfo {
        method: method.to_string(),
        params,
        tool: tool.map(str::to_string),
        mcp_classification: class,
        is_notification: false,
    }
}

fn jsonrpc_request(path: &str, calls: Vec<JsonRpcCallInfo>) -> L7RequestInfo {
    L7RequestInfo {
        jsonrpc: Some(jsonrpc_info(calls)),
        ..rest("POST", path)
    }
}

fn mcp(method: &str, tool: Option<&str>, class: McpMethodClassification) -> L7RequestInfo {
    jsonrpc_request("/mcp", vec![call(method, tool, Some(class))])
}

/// Returns the YAML decision, or the evaluation error. The relay treats an
/// evaluation error as a denial.
fn opa_decision(yaml: &str, host: &str, request: &L7RequestInfo) -> Result<bool, String> {
    let engine = OpaEngine::from_strings(REGO, yaml).expect("YAML policy loads");
    let tunnel = engine
        .clone_engine_for_tunnel(engine.current_generation())
        .expect("tunnel engine");
    tunnel
        .evaluate_request(&ctx(host), request)
        .map(|(allowed, _)| allowed)
        .map_err(|error| {
            error
                .to_string()
                .lines()
                .find(|l| l.contains("error:"))
                .unwrap_or("evaluation error")
                .trim()
                .to_string()
        })
}

fn cedar_allows(cedar: &str, host: &str, request: &L7RequestInfo) -> bool {
    let engine = CedarOnlyEngine::from_policy_str(cedar).expect("Cedar policy loads");
    engine
        .l7_handle(engine.current_generation())
        .evaluate_request(&ctx(host), request)
        .expect("Cedar request evaluates")
        .0
}

/// Runs a scenario and returns its report rows and any failures.
fn run(scenario: &Scenario) -> (String, Vec<String>) {
    let mut report = String::new();
    let mut failures = Vec::new();
    for case in &scenario.cases {
        let yaml_result = opa_decision(scenario.yaml, scenario.host, &case.request);
        if let Err(error) = &yaml_result {
            println!(
                "YAML evaluation error in {} / {}: {error}",
                scenario.name, case.name
            );
        }
        let yaml = yaml_result.unwrap_or(false);
        let cedar = cedar_allows(scenario.cedar, scenario.host, &case.request);
        let decision = |allowed: bool| if allowed { "allow" } else { "deny" };
        let outcome = match (case.expect, yaml == cedar) {
            (Expect::Same, true) => "same".to_string(),
            (Expect::Diverges(reason), false) => format!("known difference: {reason}"),
            (Expect::Same, false) => {
                failures.push(format!(
                    "{} / {}: YAML {} but Cedar {}",
                    scenario.name,
                    case.name,
                    decision(yaml),
                    decision(cedar)
                ));
                "MISMATCH".to_string()
            }
            (Expect::Diverges(reason), true) => {
                failures.push(format!(
                    "{} / {}: expected a difference ({reason}) but both {}",
                    scenario.name,
                    case.name,
                    decision(yaml)
                ));
                "UNEXPECTEDLY SAME".to_string()
            }
        };
        let _ = writeln!(
            report,
            "| {} | {} | {} | {} | {outcome} |",
            scenario.name,
            case.name,
            decision(yaml),
            decision(cedar)
        );
    }
    (report, failures)
}

fn assert_parity(scenario: &Scenario) {
    let (report, failures) = run(scenario);
    println!("| Scenario | Case | YAML | Cedar | Result |\n|---|---|---|---|---|\n{report}");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

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
