// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MCP request profiles through the sandbox's transparent network interception.
//!
//! A shared fixture serves legacy initialization, sessionless discovery, named
//! tools, and a bounded subscription stream. Upstream receipts distinguish a
//! policy denial from a tool request accepted by the fixture.

#![cfg(feature = "e2e-host-gateway")]

use std::io::Write;

use openshell_e2e::harness::container::ContainerHttpServer;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;

const SERVER_ALIAS: &str = "mcp-sessionless.openshell.test";

const SERVER_SCRIPT: &str = r#"
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

SESSIONLESS_VERSION = "2026-07-28"
received = []

class Handler(BaseHTTPRequestHandler):
    def reply(self, status, payload, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        # The container fixture's readiness probe uses the root URL.
        self.reply(200 if self.path == "/" else 405, b"")

    def read_body(self):
        if self.headers.get("Transfer-Encoding", "").lower() != "chunked":
            return self.rfile.read(int(self.headers.get("Content-Length", "0")))
        body = bytearray()
        while True:
            size = int(self.rfile.readline().split(b";", 1)[0].strip(), 16)
            if size == 0:
                while self.rfile.readline().strip():
                    pass
                return bytes(body)
            body.extend(self.rfile.read(size))
            self.rfile.read(2)

    def do_POST(self):
        message = json.loads(self.read_body())
        method = message["method"]
        params = message.get("params", {})
        version = (params.get("protocolVersion") if method == "initialize"
                   else self.headers.get("MCP-Protocol-Version"))
        # Record parsed requests before fixture admission so rejected revisions
        # and tool attempts stay visible. HTTPServer handles requests serially.
        received.append([version, method, params.get("name")])
        if self.path != "/mcp" or version not in SUPPORTED_VERSIONS:
            self.reply(400, b"request revision did not reach the fixture intact")
            return
        if version == SESSIONLESS_VERSION:
            meta = params.get("_meta", {})
            if (self.headers.get("MCP-Protocol-Version") != version
                or self.headers.get("Mcp-Method") != method
                or meta.get("io.modelcontextprotocol/protocolVersion") != version
                or meta.get("io.modelcontextprotocol/clientCapabilities") != {}
                or (method == "tools/call"
                    and self.headers.get("Mcp-Name") != params["name"])):
                self.reply(400, b"request metadata did not reach the fixture intact")
                return

        if method == "initialize" and version != SESSIONLESS_VERSION:
            result = {
                "protocolVersion": version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "openshell-profile-fixture", "version": "1"},
            }
        elif method == "notifications/initialized" and version != SESSIONLESS_VERSION:
            self.reply(202, b"")
            return
        elif method == "server/discover" and version == SESSIONLESS_VERSION:
            result = {
                "supportedVersions": [version],
                "capabilities": {"tools": {"listChanged": True}},
                "ttlMs": 0,
                "cacheScope": "private",
                "_meta": {
                    "io.modelcontextprotocol/serverInfo": {
                        "name": "openshell-sessionless-fixture", "version": "1"
                    }
                },
            }
        elif method == "tools/call":
            # Both tool names work upstream; OpenShell owns the policy denial.
            result = {
                "content": [{"type": "text", "text": params["name"]}],
                "isError": False,
                "_meta": {"fixtureRequests": list(received)},
            }
            if version == SESSIONLESS_VERSION:
                result["resultType"] = "complete"
        elif method == "subscriptions/listen" and version == SESSIONLESS_VERSION:
            subscription_meta = {"io.modelcontextprotocol/subscriptionId": message["id"]}
            events = [
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/subscriptions/acknowledged",
                    "params": {"notifications": params["notifications"], "_meta": subscription_meta},
                },
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/tools/list_changed",
                    "params": {"_meta": subscription_meta},
                },
                {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {"resultType": "complete", "_meta": subscription_meta},
                },
            ]
            body = "".join("event: message\ndata: " + json.dumps(event) + "\n\n" for event in events)
            self.reply(200, body.encode(), "text/event-stream")
            return
        else:
            self.reply(400, b"unexpected method for the selected fixture revision")
            return

        self.reply(200, json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode())

    def log_message(self, format, *args):
        pass

HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
"#;

const CLIENT_HELPERS: &str = r#"
import json
import urllib.error
import urllib.request
# Direct client connections pass through the sandbox's transparent interception.
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def post(request_id, method, params, version):
    params = dict(params)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if method != "initialize":
        headers["MCP-Protocol-Version"] = version
    if version == "2026-07-28":
        params["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": "openshell-e2e", "version": "1"},
        }
        headers["Mcp-Method"] = method
        if method == "tools/call":
            headers["Mcp-Name"] = params["name"]
    message = {"jsonrpc": "2.0", "method": method, "params": params}
    if request_id is not None:
        message["id"] = request_id
    request = urllib.request.Request(
        f"http://{HOST}:{PORT}/mcp",
        data=json.dumps(message).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with opener.open(request, timeout=15) as response:
            return response.status, response.headers.get_content_type(), response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.headers.get_content_type(), error.read()
"#;

const CLIENT_SCRIPT: &str = r#"
VERSION = "2026-07-28"

status, content_type, body = post(1, "server/discover", {}, VERSION)
assert status == 200, ("discovery", status, body)
assert content_type == "application/json", content_type
discovery = json.loads(body)
assert discovery["id"] == 1, discovery
assert discovery["result"]["supportedVersions"] == [VERSION], discovery

status, _, body = post(2, "tools/call", {"name": "read_status", "arguments": {}}, VERSION)
assert status == 200, ("allowed tool", status, body)
tool = json.loads(body)
assert tool["id"] == 2, tool
assert tool["result"]["content"] == [{"type": "text", "text": "read_status"}], tool

status, _, body = post(3, "tools/call", {"name": "read_details", "arguments": {}}, VERSION)
assert status == 403, ("denied tool", status, body)

status, content_type, body = post(4, "subscriptions/listen", {"notifications": {"toolsListChanged": True}}, VERSION)
assert status == 200, ("subscription", status, body)
assert content_type == "text/event-stream", (content_type, body)
events = [json.loads(line[6:]) for line in body.decode().splitlines() if line.startswith("data: ")]
assert len(events) == 3, events
assert events[0]["method"] == "notifications/subscriptions/acknowledged", events
assert events[0]["params"]["notifications"] == {"toolsListChanged": True}, events
assert events[1]["method"] == "notifications/tools/list_changed", events
assert events[1]["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"] == 4, events
assert events[2]["id"] == 4 and events[2]["result"]["resultType"] == "complete", events

print("MCP_SESSIONLESS_OK discovery=200 allowed_tool=200 denied_tool=403 subscription=200")
"#;

const PROFILE_CLIENT_SCRIPT: &str = r#"
expected_receipts = []
for version in SELECTED_VERSIONS:
    if version == "2026-07-28":
        status, _, body = post(1, "server/discover", {}, version)
        assert status == 200, (version, "discovery", status, body)
        assert json.loads(body)["result"]["supportedVersions"] == [version], body
        expected_receipts.append([version, "server/discover", None])
    else:
        status, _, body = post(1, "initialize", {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": {"name": "openshell-e2e", "version": "1"},
        }, version)
        assert status == 200, (version, "initialize", status, body)
        assert json.loads(body)["result"]["protocolVersion"] == version, body
        expected_receipts.append([version, "initialize", None])
        status, _, body = post(None, "notifications/initialized", {}, version)
        assert status == 202, (version, "initialized", status, body)
        expected_receipts.append([version, "notifications/initialized", None])

    status, _, body = post(2, "tools/call", {"name": "read_status", "arguments": {}}, version)
    assert status == 200, (version, "allowed tool", status, body)
    tool = json.loads(body)
    assert tool["id"] == 2, tool
    assert tool["result"]["content"] == [{"type": "text", "text": "read_status"}], tool
    expected_receipts.append([version, "tools/call", "read_status"])
    assert tool["result"]["_meta"]["fixtureRequests"] == expected_receipts, tool

    status, _, body = post(3, "tools/call", {"name": "read_details", "arguments": {}}, version)
    assert status == 403, (version, "denied tool", status, body)

    # The fixture accepts both tools. A later allowed call proves the denial
    # came from the proxy and no denied operation reached the upstream.
    status, _, body = post(4, "tools/call", {"name": "read_status", "arguments": {}}, version)
    assert status == 200, (version, "receipt tool", status, body)
    receipt = json.loads(body)
    assert receipt["id"] == 4, receipt
    expected_receipts.append([version, "tools/call", "read_status"])
    assert receipt["result"]["_meta"]["fixtureRequests"] == expected_receipts, receipt
    print(f"MCP_PROFILE_OK version={version} allowed_tool=200 denied_tool=403 receipts=verified")
"#;

async fn start_server(alias: &str, versions: &[&str]) -> Result<ContainerHttpServer, String> {
    let versions = serde_json::to_string(versions).map_err(|err| err.to_string())?;
    let script = format!("SUPPORTED_VERSIONS = {versions}\n{SERVER_SCRIPT}");
    ContainerHttpServer::start_python(alias, &script).await
}

fn write_policy(host: &str, port: u16, versions: &[&str]) -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|err| format!("create temp policy: {err}"))?;
    let legacy_rules = if versions.iter().any(|version| *version != "2026-07-28") {
        "          - allow:\n              method: initialize\n          - allow:\n              method: notifications/initialized\n"
    } else {
        ""
    };
    let versions = serde_json::to_string(versions).map_err(|err| err.to_string())?;
    let policy = format!(
        r#"version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_policies:
  mcp_sessionless:
    name: mcp_sessionless
    endpoints:
      - host: {host}
        port: {port}
        path: /mcp
        protocol: mcp
        enforcement: enforce
        allowed_ips: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
        mcp:
          versions: {versions}
          max_body_bytes: 65536
        rules:
{legacy_rules}          - allow:
              method: server/discover
          - allow:
              method: tools/call
              tool: read_status
          - allow:
              method: subscriptions/listen
        deny_rules:
          - method: tools/call
            tool: read_details
    binaries:
      - path: /usr/bin/python*
      - path: /usr/local/bin/python*
      - path: /sandbox/.uv/python/*/bin/python*
"#
    );
    file.write_all(policy.as_bytes())
        .map_err(|err| format!("write temp policy: {err}"))?;
    file.flush()
        .map_err(|err| format!("flush temp policy: {err}"))?;
    Ok(file)
}

async fn run_client(
    server: &ContainerHttpServer,
    versions: &[&str],
    client: &str,
) -> Result<SandboxGuard, String> {
    let policy = write_policy(&server.host, server.port, versions)?;
    let policy_path = policy
        .path()
        .to_str()
        .ok_or("temp policy path is not UTF-8")?;
    let selected_versions = serde_json::to_string(versions).map_err(|err| err.to_string())?;
    let script = format!(
        "HOST = {:?}\nPORT = {}\nSELECTED_VERSIONS = {selected_versions}\n{CLIENT_HELPERS}\n{client}",
        server.host, server.port
    );
    SandboxGuard::create(&["--policy", policy_path, "--", "python3", "-c", &script]).await
}

#[tokio::test]
async fn sessionless_discovery_tools_and_subscription_use_request_metadata() {
    let versions = ["2026-07-28"];
    let server = start_server(SERVER_ALIAS, &versions)
        .await
        .expect("start sessionless MCP fixture");
    let sandbox = run_client(&server, &versions, CLIENT_SCRIPT)
        .await
        .expect("run sessionless MCP client in sandbox");

    assert!(
        sandbox.create_output.contains(
            "MCP_SESSIONLESS_OK discovery=200 allowed_tool=200 denied_tool=403 subscription=200"
        ),
        "expected completed sessionless MCP assertions, got:\n{}",
        sandbox.create_output
    );
}

#[tokio::test]
async fn legacy_and_multi_version_profiles_authorize_tools_through_sandbox() {
    for versions in [
        &["2025-03-26"][..],
        &["2025-06-18"][..],
        &["2025-11-25", "2026-07-28"][..],
    ] {
        // Each scenario starts with fresh upstream receipts. Its distinct alias
        // avoids the sessionless test's fixture, and cleanup precedes alias reuse.
        let server = start_server("mcp-profiles.openshell.test", versions)
            .await
            .unwrap_or_else(|err| panic!("{versions:?}: start MCP fixture: {err}"));
        let mut sandbox = run_client(&server, versions, PROFILE_CLIENT_SCRIPT)
            .await
            .unwrap_or_else(|err| panic!("{versions:?}: run MCP sandbox client: {err}"));
        for version in versions {
            let marker = format!(
                "MCP_PROFILE_OK version={version} allowed_tool=200 denied_tool=403 receipts=verified"
            );
            assert!(
                sandbox.create_output.contains(&marker),
                "{versions:?}: expected completed {version} assertions, got:\n{}",
                sandbox.create_output
            );
        }
        sandbox.cleanup().await;
    }
}
