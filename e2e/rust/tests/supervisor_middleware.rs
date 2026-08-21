// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Black-box happy-path coverage for authenticated supervisor middleware.

#![cfg(feature = "e2e-docker")]

use std::io::Write;

use openshell_e2e::harness::container::ContainerHttpServer;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::Value;
use tempfile::NamedTempFile;

async fn start_test_server() -> Result<ContainerHttpServer, String> {
    let script = r#"from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        parsed = json.loads(body)
        response = json.dumps({
            "received_payload": parsed.get("payload"),
            "fixture_header": self.headers.get("x-openshell-middleware-fixture"),
        }, sort_keys=True).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format, *args):
        pass

HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
"#;
    ContainerHttpServer::start_python("middleware-happy.openshell.test", script).await
}

fn write_policy(host: &str, port: u16) -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|error| format!("create policy: {error}"))?;
    let policy = format!(
        r#"version: 1

network_middlewares:
  scripted-e2e:
    name: Scripted E2E middleware
    middleware: e2e-scripted
    order: 10
    config: {{}}
    on_error: fail_closed
    endpoints:
      include:
        - {host}

network_policies:
  middleware_target:
    name: middleware_target
    endpoints:
      - host: {host}
        port: {port}
        protocol: rest
        enforcement: enforce
        allowed_ips:
          - "10.0.0.0/8"
          - "172.0.0.0/8"
          - "192.168.0.0/16"
          - "fc00::/7"
        rules:
          - allow:
              method: POST
              path: "/inspect"
    binaries:
      - path: /usr/bin/python*
      - path: /usr/local/bin/python*
      - path: /sandbox/.uv/python/*/bin/python*
"#
    );
    file.write_all(policy.as_bytes())
        .map_err(|error| format!("write policy: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush policy: {error}"))?;
    Ok(file)
}

#[tokio::test]
async fn authenticated_middleware_mutates_request_body_and_headers() {
    let server = start_test_server().await.expect("start upstream server");
    let policy = write_policy(&server.host, server.port).expect("write middleware policy");
    let script = format!(
        r#"import json, urllib.request
request = urllib.request.Request(
    "http://{host}:{port}/inspect",
    data=json.dumps({{"payload": "raw-secret"}}).encode(),
    headers={{"Content-Type": "application/json"}},
    method="POST",
)
with urllib.request.urlopen(request, timeout=15) as response:
    print("MIDDLEWARE_RESULT=" + response.read().decode())
"#,
        host = server.host,
        port = server.port,
    );
    let policy_path = policy.path().to_string_lossy().into_owned();

    let sandbox = SandboxGuard::create(&["--policy", &policy_path, "--", "python3", "-c", &script])
        .await
        .expect("create middleware sandbox");
    let result = sandbox
        .create_output
        .lines()
        .find_map(|line| line.split_once("MIDDLEWARE_RESULT=").map(|(_, json)| json))
        .expect("sandbox output should contain the upstream response");
    let result: Value = serde_json::from_str(result).expect("upstream response should be JSON");

    assert_eq!(result["received_payload"], "[REDACTED]");
    assert_eq!(result["fixture_header"], "evaluated");
}
