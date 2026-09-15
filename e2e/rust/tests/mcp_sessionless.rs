// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sessionless MCP requests through the sandbox's transparent network interception.
//!
//! A local fixture serves discovery, named tools, and a bounded subscription
//! stream. The client starts with discovery and sends the protocol metadata on
//! every POST; no initialization handshake or session ID is involved.

#![cfg(feature = "e2e-host-gateway")]

use std::io::Write;

use openshell_e2e::harness::container::ContainerHttpServer;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;

const SERVER_ALIAS: &str = "mcp-sessionless.openshell.test";

const SERVER_SCRIPT: &str = r#"
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

VERSION = "2026-07-28"

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
        params = message["params"]
        meta = params["_meta"]
        if (self.path != "/mcp"
            or self.headers.get("MCP-Protocol-Version") != VERSION
            or self.headers.get("Mcp-Method") != method
            or meta.get("io.modelcontextprotocol/protocolVersion") != VERSION
            or meta.get("io.modelcontextprotocol/clientCapabilities") != {}
            or (method == "tools/call"
                and self.headers.get("Mcp-Name") != params["name"])):
            self.reply(400, b"request metadata did not reach the fixture intact")
            return

        if method == "server/discover":
            result = {
                "supportedVersions": [VERSION],
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
                "resultType": "complete",
                "content": [{"type": "text", "text": params["name"]}],
                "isError": False,
            }
        elif method == "subscriptions/listen":
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
            self.reply(400, b"unexpected method; this fixture has no initialization handshake")
            return

        self.reply(200, json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode())

    def log_message(self, format, *args):
        pass

HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
"#;

const CLIENT_SCRIPT: &str = r#"
import json
import urllib.error
import urllib.request

VERSION = "2026-07-28"
# Direct client connections pass through the sandbox's transparent interception.
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def post(request_id, method, params):
    params = dict(params)
    params["_meta"] = {
        "io.modelcontextprotocol/protocolVersion": VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "openshell-e2e", "version": "1"},
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": VERSION,
        "Mcp-Method": method,
    }
    if method == "tools/call":
        headers["Mcp-Name"] = params["name"]
    request = urllib.request.Request(
        f"http://{HOST}:{PORT}/mcp",
        data=json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with opener.open(request, timeout=15) as response:
            return response.status, response.headers.get_content_type(), response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.headers.get_content_type(), error.read()

status, content_type, body = post(1, "server/discover", {})
assert status == 200, ("discovery", status, body)
assert content_type == "application/json", content_type
discovery = json.loads(body)
assert discovery["id"] == 1, discovery
assert discovery["result"]["supportedVersions"] == [VERSION], discovery

status, _, body = post(2, "tools/call", {"name": "read_status", "arguments": {}})
assert status == 200, ("allowed tool", status, body)
tool = json.loads(body)
assert tool["id"] == 2, tool
assert tool["result"]["content"] == [{"type": "text", "text": "read_status"}], tool

status, _, body = post(3, "tools/call", {"name": "read_details", "arguments": {}})
assert status == 403, ("denied tool", status, body)

status, content_type, body = post(4, "subscriptions/listen", {"notifications": {"toolsListChanged": True}})
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

fn write_policy(host: &str, port: u16) -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|err| format!("create temp policy: {err}"))?;
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
          versions: ["2026-07-28"]
          max_body_bytes: 65536
        rules:
          - allow:
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

#[tokio::test]
async fn sessionless_discovery_tools_and_subscription_use_request_metadata() {
    let server = ContainerHttpServer::start_python(SERVER_ALIAS, SERVER_SCRIPT)
        .await
        .expect("start sessionless MCP fixture");
    let policy = write_policy(&server.host, server.port).expect("write sessionless MCP policy");
    let policy_path = policy.path().to_str().expect("temp policy path is UTF-8");
    let script = format!(
        "HOST = {:?}\nPORT = {}\n{CLIENT_SCRIPT}",
        server.host, server.port
    );
    let sandbox = SandboxGuard::create(&["--policy", policy_path, "--", "python3", "-c", &script])
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
