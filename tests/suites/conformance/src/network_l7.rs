// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! L7 network policy: REST, GraphQL, and JSON-RPC rules the sandbox enforces
//! on requests a workload sends straight to a server, without a proxy.
//!
//! Ported from the `forward_proxy_l7_bypass`, `forward_proxy_graphql_l7`,
//! and `forward_proxy_jsonrpc_l7` e2e tests. The upstream servers run on the
//! test host ([`host_server_support`]) and implement none of the protocols:
//! the sandbox parses and enforces them before forwarding, so a server that
//! answers is enough to tell an allowed request from a denied one.

mod mcp;

use host_server_support::{HttpRecorder, Request, Response};
use serde_json::json;
use testkit::{Context, Result, ResultExt as _, policy};

use crate::support::{
    TEST_HOST, expect_values, json_result, python_binaries_yaml, python_sandbox, run_python,
};

const REST_CLIENT: &str = include_str!("scripts/rest_client.py");
const REST_UPGRADE_CLIENT: &str = include_str!("scripts/rest_upgrade_client.py");
const GRAPHQL_CLIENT: &str = include_str!("scripts/graphql_client.py");
const JSONRPC_CLIENT: &str = include_str!("scripts/jsonrpc_client.py");
const JSONRPC_AUDIT_CLIENT: &str = include_str!("scripts/jsonrpc_audit_client.py");

/// A REST endpoint that allows only `GET /allowed` passes that request and
/// answers a `POST` to the same path with `403` before it reaches upstream.
#[testkit::test]
async fn rest_rules_allow_get_and_deny_post(cx: &mut Context) -> testkit::Result {
    let server = HttpRecorder::serve(rest_upstream).await?;
    let sandbox = python_sandbox(cx, "rest", rest_policy(server.port, "enforce")?).await?;
    let output = run_python(&sandbox, REST_CLIENT, &[TEST_HOST, &port(&server)]).await?;
    expect_values(
        &json_result(&output)?,
        &[("get", json!(200)), ("post", json!(403))],
    )?;
    let methods: Vec<String> = server
        .requests()
        .iter()
        .map(|request| request.method().to_string())
        .collect();
    testkit::ensure!(
        methods == ["GET"],
        "expected only the GET upstream; got {methods:?}"
    );
    Ok(())
}

/// A permitted `GET` can't switch a REST endpoint into an uninspected
/// WebSocket tunnel, in enforce or audit mode: the sandbox answers the
/// upgrade with `403` and `unsupported_l7_protocol`.
#[testkit::test]
async fn rest_upgrade_is_refused_in_enforce_and_audit_modes(cx: &mut Context) -> testkit::Result {
    let server = HttpRecorder::serve(rest_upstream).await?;
    for enforcement in ["enforce", "audit"] {
        let sandbox =
            python_sandbox(cx, enforcement, rest_policy(server.port, enforcement)?).await?;
        run_python(&sandbox, REST_UPGRADE_CLIENT, &[TEST_HOST, &port(&server)])
            .await
            .context(format!("{enforcement} mode"))?
            .expect_stdout("REST_UPGRADE_REFUSED\n")?;
    }
    Ok(())
}

/// GraphQL rules allow listed query and mutation fields and registered
/// persisted queries, and deny unlisted fields, deny-rule mutations,
/// unregistered persisted queries, and a GET with a second, denied query.
/// Bodies sent with Content-Length and chunked both work, through urllib
/// and raw sockets.
#[testkit::test]
async fn graphql_rules_allow_and_deny_operations(cx: &mut Context) -> testkit::Result {
    let server = HttpRecorder::serve(|request| match request.method() {
        "GET" if request.path() == "/" || request.path().starts_with("/graphql?") => ok_json(),
        "GET" => ok_json().status(418),
        _ => ok_json(),
    })
    .await?;
    let policy = policy::base_with(&format!(
        r"network_policies:
  graphql:
    name: graphql
    endpoints:
      - host: {TEST_HOST}
        port: {port}
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
    binaries: {binaries}
",
        port = server.port,
        binaries = python_binaries_yaml(),
    ))?;
    let sandbox = python_sandbox(cx, "graphql", policy).await?;
    let output = run_python(&sandbox, GRAPHQL_CLIENT, &[TEST_HOST, &port(&server)]).await?;
    let mut expected = Vec::new();
    for path in ["forward", "raw"] {
        for (key, status) in [
            ("query_allowed", 200),
            ("get_query_allowed", 200),
            ("duplicate_get_denied", 403),
            ("persisted_get_allowed", 200),
            ("unregistered_persisted_get_denied", 403),
            ("chunked_query_allowed", 200),
            ("unlisted_field_denied", 403),
            ("mutation_allowed", 200),
            ("deny_rule_denied", 403),
        ] {
            expected.push((format!("{path}_{key}"), json!(status)));
        }
    }
    expect_values(&json_result(&output)?, &expected)
}

/// JSON-RPC rules allow listed methods whatever their params, deny a
/// deny-rule method, a batch with one denied call, and invalid JSON, through
/// urllib and raw sockets.
#[testkit::test]
async fn jsonrpc_rules_allow_and_deny_methods(cx: &mut Context) -> testkit::Result {
    let server = HttpRecorder::serve(jsonrpc_upstream).await?;
    let policy = policy::base_with(&format!(
        r"network_policies:
  jsonrpc:
    name: jsonrpc
    endpoints:
      - host: {TEST_HOST}
        port: {port}
        path: /rpc
        protocol: json-rpc
        enforcement: enforce
        json_rpc:
          max_body_bytes: 65536
        rules:
          - allow:
              method: initialize
          - allow:
              method: tools/list
          - allow:
              method: tools/call
        deny_rules:
          - method: tools/delete
    binaries: {binaries}
",
        port = server.port,
        binaries = python_binaries_yaml(),
    ))?;
    let sandbox = python_sandbox(cx, "jsonrpc", policy).await?;
    let output = run_python(&sandbox, JSONRPC_CLIENT, &[TEST_HOST, &port(&server)]).await?;
    let mut expected = Vec::new();
    for path in ["forward", "raw"] {
        for (key, status) in [
            ("method_initialize_allowed", 200),
            ("method_tools_list_allowed", 200),
            ("method_tools_call_allowed", 200),
            ("method_tools_call_with_unmatched_params_allowed", 200),
            ("method_tools_delete_denied", 403),
        ] {
            expected.push((format!("{path}_{key}"), json!(status)));
        }
    }
    for (key, status) in [
        ("forward_batch_all_allowed", 200),
        ("forward_batch_one_denied", 403),
        ("forward_invalid_json_denied", 403),
    ] {
        expected.push((key.to_string(), json!(status)));
    }
    expect_values(&json_result(&output)?, &expected)
}

/// A JSON-RPC endpoint without `enforcement` audits an unlisted method and
/// passes it, but still denies a response frame sent as a request.
#[testkit::test]
async fn jsonrpc_default_audit_mode_still_denies_response_frames(
    cx: &mut Context,
) -> testkit::Result {
    let server = HttpRecorder::serve(jsonrpc_upstream).await?;
    let policy = policy::base_with(&format!(
        r"network_policies:
  jsonrpc_audit:
    name: jsonrpc_audit
    endpoints:
      - host: {TEST_HOST}
        port: {port}
        path: /rpc
        protocol: json-rpc
        json_rpc:
          max_body_bytes: 65536
        rules:
          - allow:
              method: initialize
    binaries: {binaries}
",
        port = server.port,
        binaries = python_binaries_yaml(),
    ))?;
    let sandbox = python_sandbox(cx, "jsonaudit", policy).await?;
    let output = run_python(&sandbox, JSONRPC_AUDIT_CLIENT, &[TEST_HOST, &port(&server)]).await?;
    expect_values(
        &json_result(&output)?,
        &[
            ("forward_unknown_method_audited", json!(200)),
            ("forward_response_frame_hard_denied", json!(403)),
        ],
    )
}

/// A REST endpoint on `port` in `enforcement` mode that allows only
/// `GET /allowed`.
fn rest_policy(port: u16, enforcement: &str) -> Result<testkit::sdk::raw::proto::SandboxPolicy> {
    policy::base_with(&format!(
        r"network_policies:
  rest:
    name: rest
    endpoints:
      - host: {TEST_HOST}
        port: {port}
        protocol: rest
        enforcement: {enforcement}
        rules:
          - allow:
              method: GET
              path: /allowed
    binaries: {binaries}
",
        binaries = python_binaries_yaml(),
    ))
}

/// Answers a WebSocket upgrade with `101`, and `GET` or `DELETE` with
/// `200`, so that a refused upgrade shows the sandbox refused it.
fn rest_upstream(request: &Request) -> Response {
    match request.method() {
        "GET" if request.header("upgrade").is_some() => Response::new(101)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
        "GET" | "DELETE" => ok_json(),
        _ => Response::new(405),
    }
}

fn jsonrpc_upstream(request: &Request) -> Response {
    match request.method() {
        "POST" => Response::json(&json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
        _ => Response::new(200),
    }
}

fn ok_json() -> Response {
    Response::json(&json!({"ok": true}))
}

fn port(server: &HttpRecorder) -> String {
    server.port.to_string()
}
