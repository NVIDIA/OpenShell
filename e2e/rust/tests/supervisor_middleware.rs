// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Focused black-box coverage for an operator-run supervisor middleware.

#![cfg(feature = "e2e-docker")]

use std::io::Write;
use std::process::Stdio;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::container::ContainerHttpServer;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::Value;
use tempfile::NamedTempFile;

async fn start_test_server(alias: &str) -> Result<ContainerHttpServer, String> {
    let script = r#"from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {}
        response = json.dumps({
            "received_action": parsed.get("_e2e_action"),
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
    ContainerHttpServer::start_python(alias, script).await
}

fn write_policy(
    host: &str,
    port: u16,
    on_error: &str,
    reject_fixture_config: bool,
) -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|error| format!("create policy: {error}"))?;
    let rejection = if reject_fixture_config {
        "      reject_fixture_config: true\n"
    } else {
        ""
    };
    let policy = format!(
        r#"version: 1

filesystem_policy:
  include_workdir: true
  read_only:
    - /usr
    - /lib
    - /proc
    - /dev/urandom
    - /app
    - /etc
    - /var/log
  read_write:
    - /sandbox
    - /tmp
    - /dev/null

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_middlewares:
  scripted-e2e:
    name: Scripted E2E middleware
    middleware: e2e-scripted
    order: 10
    config:
{rejection}    on_error: {on_error}
    endpoints:
      include: ["{host}"]

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
              path: "/**"
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

fn policy_path(policy: &NamedTempFile) -> String {
    policy
        .path()
        .to_str()
        .expect("temporary policy path should be UTF-8")
        .to_string()
}

fn result_json(output: &str) -> Value {
    let result = output
        .lines()
        .find_map(|line| {
            line.split_once("MIDDLEWARE_RESULTS=")
                .map(|(_, value)| value)
        })
        .expect("sandbox output should contain middleware results");
    serde_json::from_str(result).expect("middleware results should be valid JSON")
}

#[tokio::test]
async fn external_middleware_mutates_denies_and_fails_open() {
    let server = start_test_server("middleware-behavior.openshell.test")
        .await
        .expect("start upstream server");
    let policy = write_policy(&server.host, server.port, "fail_open", false)
        .expect("write middleware policy");
    let script = format!(
        r#"
import json, urllib.error, urllib.request

URL = "http://{host}:{port}/inspect"

def post(action, payload):
    request = urllib.request.Request(
        URL,
        data=json.dumps({{"_e2e_action": action, "payload": payload}}).encode(),
        headers={{"Content-Type": "application/json"}},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return {{"status": response.status, "body": json.loads(response.read())}}
    except urllib.error.HTTPError as error:
        return {{"status": error.code, "body": error.read().decode()}}

results = {{
    "redact": post("redact", "raw-secret"),
    "deny": post("deny", "blocked"),
    "error": post("error", "original"),
}}
print("MIDDLEWARE_RESULTS=" + json.dumps(results, sort_keys=True))
"#,
        host = server.host,
        port = server.port,
    );

    let sandbox = SandboxGuard::create(&[
        "--policy",
        &policy_path(&policy),
        "--",
        "python3",
        "-c",
        &script,
    ])
    .await
    .expect("create middleware sandbox");
    let results = result_json(&sandbox.create_output);

    assert_eq!(results["redact"]["status"], 200);
    assert_eq!(results["redact"]["body"]["received_payload"], "[REDACTED]");
    assert_eq!(results["redact"]["body"]["fixture_header"], "redacted");
    assert!(results["redact"]["body"]["received_action"].is_null());

    assert_eq!(results["deny"]["status"], 403);

    assert_eq!(results["error"]["status"], 200);
    assert_eq!(results["error"]["body"]["received_action"], "error");
    assert_eq!(results["error"]["body"]["received_payload"], "original");
    assert!(results["error"]["body"]["fixture_header"].is_null());
}

#[tokio::test]
async fn external_middleware_timeout_fails_closed() {
    let server = start_test_server("middleware-timeout.openshell.test")
        .await
        .expect("start upstream server");
    let policy = write_policy(&server.host, server.port, "fail_closed", false)
        .expect("write middleware policy");
    let script = format!(
        r#"
import json, urllib.error, urllib.request
request = urllib.request.Request(
    "http://{host}:{port}/inspect",
    data=json.dumps({{"_e2e_action": "timeout", "payload": "blocked"}}).encode(),
    headers={{"Content-Type": "application/json"}},
    method="POST",
)
try:
    with urllib.request.urlopen(request, timeout=15) as response:
        print("TIMEOUT_STATUS=" + str(response.status))
except urllib.error.HTTPError as error:
    print("TIMEOUT_STATUS=" + str(error.code))
"#,
        host = server.host,
        port = server.port,
    );

    let sandbox = SandboxGuard::create(&[
        "--policy",
        &policy_path(&policy),
        "--",
        "python3",
        "-c",
        &script,
    ])
    .await
    .expect("create timeout sandbox");
    assert!(
        sandbox.create_output.contains("TIMEOUT_STATUS=403"),
        "expected fail-closed timeout denial, got:\n{}",
        sandbox.create_output
    );
}

#[tokio::test]
async fn external_middleware_rejects_invalid_config_during_admission() {
    let server = start_test_server("middleware-validation.openshell.test")
        .await
        .expect("start upstream server");
    let policy = write_policy(&server.host, server.port, "fail_closed", true)
        .expect("write invalid middleware policy");
    let mut command = openshell_cmd();
    command
        .arg("sandbox")
        .arg("create")
        .arg("--policy")
        .arg(policy.path())
        .arg("--")
        .arg("true")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = command.output().await.expect("run sandbox create");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !output.status.success(),
        "invalid config should be rejected"
    );
    assert!(
        combined.contains("fixture") && combined.contains("configuration rejected"),
        "expected fixture validation reason, got:\n{combined}"
    );
}
