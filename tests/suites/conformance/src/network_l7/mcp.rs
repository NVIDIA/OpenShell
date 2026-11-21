// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MCP request profiles: the sandbox authorizes tool calls by MCP revision,
//! for the sessionless revision, legacy initialization, and an endpoint that
//! accepts several revisions.
//!
//! Ported from the `mcp_sessionless` e2e test. The fixture on the test host
//! serves initialization, discovery, tools, and a bounded subscription
//! stream, and reports the requests it received in each tool result, so the
//! client can tell a policy denial from a request the fixture accepted.

use std::sync::{Arc, Mutex, PoisonError};

use host_server_support::{HttpRecorder, Request, Response, TEST_HOST};
use sandbox_clients_support::scripts::MCP_CLIENT;
use serde_json::{Value, json};
use testkit::{Context, PYTHON_BINARIES, Result, ResultExt as _, policy};

/// The sessionless MCP revision, which needs no initialization and carries
/// request metadata in headers and `_meta`.
const SESSIONLESS: &str = "2026-07-28";

/// The sessionless revision: discovery, an allowed and a denied tool, and a
/// subscription stream, with the request metadata the revision requires.
#[testkit::test]
async fn mcp_sessionless_discovery_tools_and_subscription(cx: &mut Context) -> testkit::Result {
    run_profile(cx, "mcpsl", &[SESSIONLESS]).await
}

/// Each legacy revision: initialization, then an allowed and a denied tool.
#[testkit::test]
async fn mcp_legacy_revisions_authorize_tools(cx: &mut Context) -> testkit::Result {
    for (suffix, version) in [("m0326", "2025-03-26"), ("m0618", "2025-06-18")] {
        run_profile(cx, suffix, &[version]).await?;
    }
    Ok(())
}

/// An endpoint that accepts a legacy and the sessionless revision authorizes
/// tools under each, against one fixture.
#[testkit::test]
async fn mcp_multi_version_endpoint_authorizes_tools(cx: &mut Context) -> testkit::Result {
    run_profile(cx, "mcpmv", &["2025-11-25", SESSIONLESS]).await
}

/// Start a fresh fixture for `versions`, and run [`MCP_CLIENT`] for them in
/// a sandbox whose policy accepts them.
async fn run_profile(cx: &Context, suffix: &str, versions: &[&str]) -> Result {
    let supported: Vec<String> = versions.iter().map(ToString::to_string).collect();
    let received = Arc::new(Mutex::new(Vec::new()));
    let server =
        HttpRecorder::serve(move |request| fixture(request, &supported, &received)).await?;

    let mut rules = Vec::new();
    if versions.iter().any(|version| *version != SESSIONLESS) {
        rules.push(json!({"allow": {"method": "initialize"}}));
        rules.push(json!({"allow": {"method": "notifications/initialized"}}));
    }
    rules.extend([
        json!({"allow": {"method": "server/discover"}}),
        json!({"allow": {"method": "tools/call", "tool": "read_status"}}),
        json!({"allow": {"method": "subscriptions/listen"}}),
    ]);
    let binaries: Vec<Value> = PYTHON_BINARIES
        .iter()
        .map(|path| json!({"path": path}))
        .collect();
    let rule = json!({
        "mcp": {
            "name": "mcp",
            "endpoints": [{
                "host": TEST_HOST,
                "port": server.port,
                "path": "/mcp",
                "protocol": "mcp",
                "enforcement": "enforce",
                "mcp": {"versions": versions, "max_body_bytes": 65536},
                "rules": rules,
                "deny_rules": [{"method": "tools/call", "tool": "read_details"}],
            }],
            "binaries": binaries,
        }
    });
    // JSON is YAML, so the rule can follow the base policy's YAML.
    let policy = policy::base_with(&format!("network_policies: {rule}\n"))?;
    let sandbox = cx.python_sandbox(suffix, policy).create_ready().await?;
    let output = sandbox
        .run_python(
            MCP_CLIENT,
            &[
                TEST_HOST,
                &server.port.to_string(),
                &json!(versions).to_string(),
            ],
        )
        .await
        .context(format!("MCP revisions {versions:?}"))?;
    for version in versions {
        let marker = format!("MCP_OK version={version}");
        testkit::ensure!(
            output.stdout.lines().any(|line| line == marker),
            "{versions:?}: the client didn't finish {version}:\n{}",
            output.stdout
        );
    }
    Ok(())
}

/// The MCP fixture. It records each parsed request as `[version, method,
/// tool]` in `received` before checking it, so rejected requests stay
/// visible in later tool results.
fn fixture(request: &Request, supported: &[String], received: &Mutex<Vec<Value>>) -> Response {
    if request.method() == "GET" {
        return Response::new(if request.path() == "/" { 200 } else { 405 });
    }
    let Ok(message) = serde_json::from_str::<Value>(&request.body) else {
        return bad_request("the request body is not JSON");
    };
    let method = message["method"].as_str().unwrap_or_default();
    let params = &message["params"];
    let version = if method == "initialize" {
        params["protocolVersion"].as_str().map(ToString::to_string)
    } else {
        request.header("mcp-protocol-version")
    };
    let received_now = {
        let mut received = received.lock().unwrap_or_else(PoisonError::into_inner);
        received.push(json!([version, method, params.get("name")]));
        received.clone()
    };
    // The revision, and for the sessionless revision its metadata, must
    // arrive as the client sent them.
    let Some(version) = version.filter(|version| {
        request.path() == "/mcp"
            && supported.contains(version)
            && (version != SESSIONLESS || sessionless_metadata_intact(request, &message, version))
    }) else {
        return bad_request("request revision or metadata did not reach the fixture intact");
    };
    let sessionless = version == SESSIONLESS;

    let result = match method {
        "initialize" if !sessionless => json!({
            "protocolVersion": version,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "openshell-profile-fixture", "version": "1"},
        }),
        "notifications/initialized" if !sessionless => return Response::new(202),
        "server/discover" if sessionless => json!({
            "supportedVersions": [version],
            "capabilities": {"tools": {"listChanged": true}},
            "ttlMs": 0,
            "cacheScope": "private",
            "_meta": {
                "io.modelcontextprotocol/serverInfo": {
                    "name": "openshell-sessionless-fixture", "version": "1"
                }
            },
        }),
        // Both tool names work upstream; the sandbox owns the policy denial.
        "tools/call" => {
            let mut result = json!({
                "content": [{"type": "text", "text": params["name"]}],
                "isError": false,
                "_meta": {"fixtureRequests": received_now},
            });
            if sessionless {
                result["resultType"] = json!("complete");
            }
            result
        }
        "subscriptions/listen" if sessionless => return subscription(&message),
        _ => return bad_request("unexpected method for the selected fixture revision"),
    };
    Response::json(&json!({"jsonrpc": "2.0", "id": message["id"], "result": result}))
}

/// A subscription stream that acknowledges, sends one notification, and
/// completes.
fn subscription(message: &Value) -> Response {
    let meta = json!({"io.modelcontextprotocol/subscriptionId": message["id"]});
    let events = [
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/subscriptions/acknowledged",
            "params": {"notifications": message["params"]["notifications"], "_meta": meta},
        }),
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/tools/list_changed",
            "params": {"_meta": meta},
        }),
        json!({
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"resultType": "complete", "_meta": meta},
        }),
    ];
    let body: String = events
        .iter()
        .map(|event| format!("event: message\ndata: {event}\n\n"))
        .collect();
    Response::new(200)
        .header("Content-Type", "text/event-stream")
        .body(body)
}

/// Whether a sessionless request carries its `version` and method in the
/// MCP headers and `_meta`, and a tool call its tool name in `Mcp-Name`.
fn sessionless_metadata_intact(request: &Request, message: &Value, version: &str) -> bool {
    let method = message["method"].as_str().unwrap_or_default();
    let params = &message["params"];
    let meta = &params["_meta"];
    request.header("mcp-protocol-version").as_deref() == Some(version)
        && request.header("mcp-method").as_deref() == Some(method)
        && meta["io.modelcontextprotocol/protocolVersion"] == version
        && meta["io.modelcontextprotocol/clientCapabilities"] == json!({})
        && (method != "tools/call"
            || request.header("mcp-name").as_deref() == params["name"].as_str())
}

fn bad_request(reason: &str) -> Response {
    Response::new(400)
        .header("Content-Type", "text/plain")
        .body(reason)
}
