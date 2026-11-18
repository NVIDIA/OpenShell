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

use host_server_support::{HttpRecorder, Request, Response, TEST_HOST};
use sandbox_clients_support::{self as clients, http, http_raw, scripts};
use serde_json::{Value, json};
use testkit::{Context, PYTHON_BINARIES, Result, ResultExt as _, Sandbox, policy};

/// A REST endpoint that allows only `GET /allowed` passes that request and
/// answers a `POST` to the same path with `403` before it reaches upstream.
#[testkit::test]
async fn rest_rules_allow_get_and_deny_post(cx: &mut Context) -> testkit::Result {
    let server = HttpRecorder::serve(rest_upstream).await?;
    let sandbox = cx
        .sandbox("rest")
        .image(testkit::python_image())
        .command(["sleep", "infinity"])
        .policy(rest_policy(server.port, "enforce")?)
        .create_ready()
        .await?;
    for (request, (status, error)) in [
        (clients::Request::get("/allowed"), ALLOWED),
        (
            clients::Request::new("POST", "/allowed").body("test"),
            POLICY_DENIED,
        ),
    ] {
        let reply = http(&sandbox, TEST_HOST, server.port, &request).await?;
        testkit::ensure!(
            reply.status() == Some(status) && error_code(&reply).as_deref() == error,
            "expected {status} with error {error:?} for {request:?}; got {reply:?}"
        );
    }
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
    for (suffix, enforcement) in [("enfrc", "enforce"), ("audit", "audit")] {
        let sandbox = cx
            .sandbox(suffix)
            .image(testkit::python_image())
            .command(["sleep", "infinity"])
            .policy(rest_policy(server.port, enforcement)?)
            .create_ready()
            .await?;
        expect_upgrade_refused(&sandbox, server.port)
            .await
            .context(format!("{enforcement} mode"))?;
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
        binaries = policy::binaries_yaml(PYTHON_BINARIES),
    ))?;
    let sandbox = cx
        .sandbox("gql")
        .image(testkit::python_image())
        .command(["sleep", "infinity"])
        .policy(policy)
        .create_ready()
        .await?;
    let output = sandbox
        .run_python(scripts::GRAPHQL_CLIENT, &[TEST_HOST, &port(&server)])
        .await?;
    let mut expected = Vec::new();
    for path in ["forward", "raw"] {
        for (key, outcome) in [
            ("query_allowed", ALLOWED),
            ("get_query_allowed", ALLOWED),
            ("duplicate_get_denied", POLICY_DENIED),
            ("persisted_get_allowed", ALLOWED),
            ("unregistered_persisted_get_denied", POLICY_DENIED),
            ("chunked_query_allowed", ALLOWED),
            ("unlisted_field_denied", POLICY_DENIED),
            ("mutation_allowed", ALLOWED),
            ("deny_rule_denied", POLICY_DENIED),
        ] {
            expected.push((format!("{path}_{key}"), outcome));
        }
    }
    expect_outcomes(&output, expected)
}

/// JSON-RPC rules allow listed methods whatever their params, deny a
/// deny-rule method, an unlisted method, a batch with one denied call, and
/// invalid JSON, through urllib and raw sockets. A REST endpoint on the same
/// port still allows requests outside the RPC path.
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
        protocol: rest
        enforcement: enforce
        access: read-write
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
        binaries = policy::binaries_yaml(PYTHON_BINARIES),
    ))?;
    let sandbox = cx
        .sandbox("jrpc")
        .image(testkit::python_image())
        .command(["sleep", "infinity"])
        .policy(policy)
        .create_ready()
        .await?;
    let output = sandbox
        .run_python(scripts::JSONRPC_CLIENT, &[TEST_HOST, &port(&server)])
        .await?;
    let mut expected = Vec::new();
    for path in ["forward", "raw"] {
        for (key, outcome) in [
            ("method_initialize_allowed", ALLOWED),
            ("method_tools_list_allowed", ALLOWED),
            ("method_tools_call_allowed", ALLOWED),
            ("method_tools_call_with_unmatched_params_allowed", ALLOWED),
            ("method_tools_delete_denied", POLICY_DENIED),
            ("unlisted_method_denied", POLICY_DENIED),
        ] {
            expected.push((format!("{path}_{key}"), outcome));
        }
    }
    for (key, outcome) in [
        ("rest_route_allowed", ALLOWED),
        ("forward_batch_all_allowed", ALLOWED),
        ("forward_batch_one_denied", POLICY_DENIED),
        ("forward_invalid_json_denied", POLICY_DENIED),
    ] {
        expected.push((key.to_string(), outcome));
    }
    expect_outcomes(&output, expected)
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
        binaries = policy::binaries_yaml(PYTHON_BINARIES),
    ))?;
    let sandbox = cx
        .sandbox("jaud")
        .image(testkit::python_image())
        .command(["sleep", "infinity"])
        .policy(policy)
        .create_ready()
        .await?;
    let output = sandbox
        .run_python(scripts::JSONRPC_AUDIT_CLIENT, &[TEST_HOST, &port(&server)])
        .await?;
    expect_outcomes(
        &output,
        [
            ("forward_unknown_method_audited".to_string(), ALLOWED),
            (
                "forward_response_frame_hard_denied".to_string(),
                POLICY_DENIED,
            ),
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
        binaries = policy::binaries_yaml(PYTHON_BINARIES),
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

/// Send a WebSocket upgrade for `/allowed`, in origin and absolute form,
/// and fail unless the sandbox refuses each as unsupported on a REST
/// endpoint.
async fn expect_upgrade_refused(sandbox: &Sandbox, port: u16) -> Result {
    for target in [
        "/allowed".to_string(),
        format!("http://{TEST_HOST}:{port}/allowed"),
    ] {
        let request = format!(
            "GET {target} HTTP/1.1\r\nHost: {TEST_HOST}:{port}\r\n\
             Connection: Upgrade\r\nUpgrade: websocket\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        let reply = http_raw(sandbox, TEST_HOST, port, request.as_bytes()).await?;
        testkit::ensure!(
            reply.status() == Some(403)
                && error_code(&reply).as_deref() == Some("unsupported_l7_protocol")
                && reply.received_text().contains("REST endpoints"),
            "expected the upgrade to {target} refused; got {reply:?}"
        );
    }
    Ok(())
}

/// A response's status and the `error` code in its JSON body, if any.
type Outcome = (u16, Option<&'static str>);

/// Upstream answered.
const ALLOWED: Outcome = (200, None);

/// The sandbox denied the request by policy, as documented under "Proxy
/// Error Responses" in `docs/observability/logging.mdx`.
const POLICY_DENIED: Outcome = (403, Some("policy_denied"));

/// Fail unless the client's JSON result maps exactly the keys in
/// `expected` to their statuses and `error` codes.
fn expect_outcomes(
    output: &testkit::ExecOutput,
    expected: impl IntoIterator<Item = (String, Outcome)>,
) -> Result {
    let result = output.last_json()?;
    let expected: Value = expected
        .into_iter()
        .map(|(key, (status, error))| (key, json!({"status": status, "error": error})))
        .collect::<serde_json::Map<_, _>>()
        .into();
    testkit::ensure!(
        result == expected,
        "unexpected outcomes:\nexpected: {expected}\ngot:      {result}"
    );
    Ok(())
}

/// The `error` code in the JSON body of `reply`'s response, if any.
pub(crate) fn error_code(reply: &clients::Http) -> Option<String> {
    let body = &reply.response.as_ref()?.body;
    let error = serde_json::from_slice::<Value>(body)
        .ok()?
        .get("error")?
        .clone();
    error.as_str().map(str::to_owned)
}

fn ok_json() -> Response {
    Response::json(&json!({"ok": true}))
}

fn port(server: &HttpRecorder) -> String {
    server.port.to_string()
}
