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
use sandbox_clients_support::{self as clients, http, http_raw};
use serde_json::{Value, json};
use testkit::{Context, PYTHON_BINARIES, Result, ResultExt as _, Sandbox, policy};

/// A REST endpoint that allows only `GET /allowed` passes that request and
/// answers a `POST` to the same path with `403` before it reaches upstream.
#[testkit::test]
async fn rest_rules_allow_get_and_deny_post(cx: &mut Context) -> testkit::Result {
    let server = HttpRecorder::serve(rest_upstream).await?;
    let sandbox = cx
        .python_sandbox("rest", rest_policy(&[(server.port, "enforce")])?)
        .create_ready()
        .await?;
    expect_outcomes(
        &sandbox,
        server.port,
        [
            ("GET", clients::Request::get("/allowed"), ALLOWED),
            (
                "POST",
                clients::Request::new("POST", "/allowed").body("test"),
                POLICY_DENIED,
            ),
        ],
    )
    .await?;
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
    let enforced = HttpRecorder::serve(rest_upstream).await?;
    let audited = HttpRecorder::serve(rest_upstream).await?;
    let policy = rest_policy(&[(enforced.port, "enforce"), (audited.port, "audit")])?;
    let sandbox = cx.python_sandbox("upgrd", policy).create_ready().await?;
    for (server, enforcement) in [(&enforced, "enforce"), (&audited, "audit")] {
        expect_upgrade_refused(&sandbox, server.port)
            .await
            .context(format!("{enforcement} mode"))?;
    }
    Ok(())
}

/// GraphQL rules allow listed query and mutation fields and registered
/// persisted queries, and deny unlisted fields, deny-rule mutations,
/// unregistered persisted queries, and a GET with a second, denied query.
/// Bodies sent with Content-Length and chunked both work.
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
    let sandbox = cx.python_sandbox("gql", policy).create_ready().await?;
    let viewer = "query Viewer { viewer { login } }";
    let delete =
        r#"mutation Delete { deleteRepository(input:{repositoryId:"r"}) { clientMutationId } }"#;
    let persisted = |hash: &str| {
        let extensions = json!({"persistedQuery": {"version": 1, "sha256Hash": hash}});
        graphql_get(&[
            ("operationName", "Viewer"),
            ("extensions", &extensions.to_string()),
        ])
    };
    let viewer_body = json!({"query": viewer}).to_string();
    let chunked = clients::Request::new("POST", "/graphql")
        .header("Content-Type", "application/json")
        .header("Transfer-Encoding", "chunked")
        .body(format!(
            "{:x}\r\n{viewer_body}\r\n0\r\n\r\n",
            viewer_body.len()
        ));
    expect_outcomes(
        &sandbox,
        server.port,
        [
            ("query", graphql_post(viewer), ALLOWED),
            ("GET query", graphql_get(&[("query", viewer)]), ALLOWED),
            (
                "GET with a second, denied query",
                graphql_get(&[("query", viewer), ("query", delete)]),
                POLICY_DENIED,
            ),
            ("registered persisted query", persisted("abc123"), ALLOWED),
            ("unregistered persisted query", persisted("missing"), POLICY_DENIED),
            ("chunked query", chunked, ALLOWED),
            (
                "unlisted field",
                graphql_post(r#"query Repo { repository(owner:"o", name:"r") { id } }"#),
                POLICY_DENIED,
            ),
            (
                "allowed mutation",
                graphql_post(
                    r#"mutation Create { createIssue(input:{repositoryId:"r", title:"t", body:"b"}) { issue { id } } }"#,
                ),
                ALLOWED,
            ),
            ("deny-rule mutation", graphql_post(delete), POLICY_DENIED),
        ],
    )
    .await
}

/// JSON-RPC rules allow listed methods whatever their params, deny a
/// deny-rule method, an unlisted method, a batch with one denied call, and
/// invalid JSON. A REST endpoint on the same port still allows requests
/// outside the RPC path.
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
    let sandbox = cx.python_sandbox("jrpc", policy).create_ready().await?;
    let call = |method: &str| json!({"jsonrpc": "2.0", "id": 1, "method": method});
    let call_with = |method: &str, params: Value| {
        let mut message = call(method);
        message["params"] = params;
        message
    };
    expect_outcomes(
        &sandbox,
        server.port,
        [
            (
                "initialize",
                rpc(&call_with(
                    "initialize",
                    json!({"protocolVersion": "2025-11-25", "capabilities": {}}),
                )),
                ALLOWED,
            ),
            ("tools/list", rpc(&call("tools/list")), ALLOWED),
            (
                "tools/call",
                rpc(&call_with("tools/call", json!({"name": "read_status"}))),
                ALLOWED,
            ),
            (
                "tools/call with params no rule matches",
                rpc(&call_with(
                    "tools/call",
                    json!({"name": "blocked_action", "arguments": {"scope": "ignored"}}),
                )),
                ALLOWED,
            ),
            (
                "deny-rule method",
                rpc(&call_with("tools/delete", json!({"name": "purge_cache"}))),
                POLICY_DENIED,
            ),
            ("unlisted method", rpc(&call("admin.delete")), POLICY_DENIED),
            (
                "batch of allowed calls",
                rpc(&json!([
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "read_status"}},
                ])),
                ALLOWED,
            ),
            // One denied call in a batch denies the whole batch.
            (
                "batch with a denied call",
                rpc(&json!([
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/delete", "params": {"name": "purge_cache"}},
                ])),
                POLICY_DENIED,
            ),
            (
                "invalid JSON",
                clients::Request::new("POST", "/rpc")
                    .header("Content-Type", "application/json")
                    .body("not valid json {"),
                POLICY_DENIED,
            ),
            // The REST endpoint allows requests outside the RPC path.
            (
                "REST route",
                clients::Request::new("POST", "/api/status"),
                ALLOWED,
            ),
        ],
    )
    .await
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
    let sandbox = cx.python_sandbox("jaud", policy).create_ready().await?;
    expect_outcomes(
        &sandbox,
        server.port,
        [
            (
                "unlisted method",
                rpc(&json!({"jsonrpc": "2.0", "id": 1, "method": "unknown/method"})),
                ALLOWED,
            ),
            (
                "response frame",
                rpc(&json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
                POLICY_DENIED,
            ),
        ],
    )
    .await
}

/// A REST endpoint for each port, in its `enforcement` mode, that allows
/// only `GET /allowed`.
fn rest_policy(endpoints: &[(u16, &str)]) -> Result<testkit::sdk::raw::proto::SandboxPolicy> {
    let endpoints: String = endpoints
        .iter()
        .map(|(port, enforcement)| {
            format!(
                "      - host: {TEST_HOST}
        port: {port}
        protocol: rest
        enforcement: {enforcement}
        rules:
          - allow:
              method: GET
              path: /allowed
"
            )
        })
        .collect();
    policy::base_with(&format!(
        "network_policies:
  rest:
    name: rest
    endpoints:
{endpoints}    binaries: {binaries}
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

/// Send each named request to `port` on the test host, and fail, listing
/// every mismatch, unless each gets its expected outcome.
async fn expect_outcomes(
    sandbox: &Sandbox,
    port: u16,
    cases: impl IntoIterator<Item = (&str, clients::Request, Outcome)>,
) -> Result {
    let mut mismatches = Vec::new();
    for (name, request, (status, error)) in cases {
        let reply = http(sandbox, TEST_HOST, port, &request).await?;
        if reply.status() != Some(status) || error_code(&reply).as_deref() != error {
            mismatches.push(format!(
                "{name}: expected {status} with error {error:?}; got {reply:?}"
            ));
        }
    }
    testkit::ensure!(
        mismatches.is_empty(),
        "unexpected outcomes:\n{}",
        mismatches.join("\n")
    );
    Ok(())
}

/// A GraphQL `query` in a JSON `POST /graphql`.
fn graphql_post(query: &str) -> clients::Request {
    json_post("/graphql", &json!({"query": query}))
}

/// `GET /graphql` with `params` form-encoded in the query string.
fn graphql_get(params: &[(&str, &str)]) -> clients::Request {
    let query = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params)
        .finish();
    clients::Request::get(format!("/graphql?{query}"))
}

/// A JSON-RPC message in a `POST /rpc`.
fn rpc(message: &Value) -> clients::Request {
    json_post("/rpc", message)
}

fn json_post(path: &str, body: &Value) -> clients::Request {
    clients::Request::new("POST", path)
        .header("Content-Type", "application/json")
        .body(body.to_string())
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
