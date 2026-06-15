// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! E2E tests for JSON-RPC L7 inspection across both proxy entry points.
//!
//! The upstream server deliberately does not implement JSON-RPC. `OpenShell`
//! parses and enforces JSON-RPC before forwarding, so any HTTP server that
//! accepts POST /mcp is enough to prove allowed requests reach upstream
//! and denied requests are stopped by the sandbox proxy.

#![cfg(feature = "e2e")]

use std::io::Write;

use openshell_e2e::harness::container::ContainerHttpServer;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;

const TEST_SERVER_ALIAS: &str = "jsonrpc-l7.openshell.test";

async fn start_test_server() -> Result<ContainerHttpServer, String> {
    let script = r#"from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def read_body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            data = b""
            while True:
                size_line = self.rfile.readline()
                if not size_line:
                    break
                size = int(size_line.split(b";", 1)[0].strip(), 16)
                if size == 0:
                    while self.rfile.readline().strip():
                        pass
                    break
                data += self.rfile.read(size)
                self.rfile.read(2)
            return data
        return self.rfile.read(int(self.headers.get("Content-Length", "0")))

    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        self.read_body()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"jsonrpc":"2.0","id":1,"result":{}}')

    def log_message(self, format, *args):
        pass

HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
"#;

    ContainerHttpServer::start_python(TEST_SERVER_ALIAS, script).await
}

fn write_jsonrpc_policy(host: &str, port: u16) -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|e| format!("create temp policy file: {e}"))?;
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

network_policies:
  test_jsonrpc_l7:
    name: test_jsonrpc_l7
    endpoints:
      - host: {host}
        port: {port}
        path: /mcp
        protocol: json-rpc
        enforcement: enforce
        allowed_ips:
          - "10.0.0.0/8"
          - "172.0.0.0/8"
          - "192.168.0.0/16"
          - "fc00::/7"
        json_rpc:
          max_body_bytes: 65536
        rules:
          - allow:
              rpc_method: initialize
          - allow:
              rpc_method: tools/list
          - allow:
              rpc_method: tools/call
              params:
                name: read_status
          - allow:
              rpc_method: tools/call
              params:
                name: submit_report
                arguments.scope: workspace/main
        deny_rules:
          - rpc_method: tools/call
            params:
              name: blocked_action
    binaries:
      - path: /usr/bin/python*
      - path: /usr/local/bin/python*
      - path: /sandbox/.uv/python/*/bin/python*
"#
    );
    file.write_all(policy.as_bytes())
        .map_err(|e| format!("write temp policy file: {e}"))?;
    file.flush()
        .map_err(|e| format!("flush temp policy file: {e}"))?;
    Ok(file)
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn jsonrpc_l7_enforces_method_and_params_rules_on_forward_and_connect_paths() {
    let server = start_test_server().await.expect("start test server");
    let policy = write_jsonrpc_policy(&server.host, server.port).expect("write custom policy");
    let policy_path = policy
        .path()
        .to_str()
        .expect("temp policy path should be utf-8")
        .to_string();

    let script = format!(
        r#"
import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

HOST = {host:?}
PORT = {port}
DETAILS = {{}}

def post_jsonrpc(method, params=None, req_id=1):
    body = {{"jsonrpc": "2.0", "id": req_id, "method": method}}
    if params is not None:
        body["params"] = params
    encoded = json.dumps(body).encode()
    request = urllib.request.Request(
        f"http://{{HOST}}:{{PORT}}/mcp",
        data=encoded,
        headers={{"Content-Type": "application/json"}},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        error.read()
        return error.code

def post_jsonrpc_batch(requests):
    encoded = json.dumps(requests).encode()
    request = urllib.request.Request(
        f"http://{{HOST}}:{{PORT}}/mcp",
        data=encoded,
        headers={{"Content-Type": "application/json"}},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        error.read()
        return error.code

def post_invalid_json():
    encoded = b"not valid json {{"
    request = urllib.request.Request(
        f"http://{{HOST}}:{{PORT}}/mcp",
        data=encoded,
        headers={{"Content-Type": "application/json", "Content-Length": str(len(encoded))}},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        error.read()
        return error.code

def proxy_parts(*names):
    proxy_url = next((os.environ.get(name) for name in names if os.environ.get(name)), None)
    parsed = urllib.parse.urlparse(proxy_url)
    return parsed.hostname, parsed.port or 80

def read_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def read_response(sock):
    response = read_until(sock, b"\r\n\r\n")
    headers, _, body = response.partition(b"\r\n\r\n")
    content_length = 0
    for line in headers.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            content_length = int(line.split(b":", 1)[1].strip())
            break
    while len(body) < content_length:
        chunk = sock.recv(4096)
        if not chunk:
            break
        body += chunk
    return response, body

def status_code(response, label):
    parts = response.split()
    if len(parts) < 2:
        DETAILS[f"{{label}}_raw"] = response.decode(errors="replace")
        raise RuntimeError(f"{{label}}: malformed HTTP response: {{response!r}}")
    try:
        return int(parts[1])
    except ValueError as error:
        DETAILS[f"{{label}}_raw"] = response.decode(errors="replace")
        raise RuntimeError(f"{{label}}: non-numeric HTTP status: {{response!r}}") from error

def connect_http_status(label, request):
    proxy_host, proxy_port = proxy_parts("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy")
    target = f"{{HOST}}:{{PORT}}"

    last_error = None
    for attempt in range(5):
        try:
            with socket.create_connection((proxy_host, proxy_port), timeout=15) as sock:
                sock.sendall(
                    f"CONNECT {{target}} HTTP/1.1\r\nHost: {{target}}\r\n\r\n".encode()
                )
                connect_response = read_until(sock, b"\r\n\r\n")
                connect_code = status_code(connect_response, f"{{label}}_connect")
                if connect_code != 200:
                    return connect_code
                sock.sendall(request)
                sock.shutdown(socket.SHUT_WR)
                response = read_until(sock, b"\r\n\r\n")
                return status_code(response, f"{{label}}_response")
        except (OSError, RuntimeError) as error:
            last_error = error
            DETAILS[f"{{label}}_attempt_{{attempt + 1}}_error"] = str(error)
            time.sleep(0.2)

    raise RuntimeError(f"{{label}}: failed after 5 attempts: {{last_error}}")

def connect_jsonrpc_status(method, params, label):
    target = f"{{HOST}}:{{PORT}}"
    body = {{"jsonrpc": "2.0", "id": 1, "method": method}}
    if params is not None:
        body["params"] = params
    encoded = json.dumps(body).encode()
    request = (
        f"POST /mcp HTTP/1.1\r\n"
        f"Host: {{target}}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {{len(encoded)}}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + encoded
    return connect_http_status(label, request)

results = {{
    # forward proxy — method-only allow rules
    "forward_method_initialize_allowed": post_jsonrpc("initialize", {{"protocolVersion": "2025-11-25", "capabilities": {{}}}}),
    "forward_method_tools_list_allowed": post_jsonrpc("tools/list"),

    # forward proxy — params allow rules
    "forward_tools_call_params_name_no_args_allowed": post_jsonrpc("tools/call", {{"name": "read_status"}}),
    "forward_tools_call_params_nested_args_allowed": post_jsonrpc("tools/call", {{"name": "submit_report", "arguments": {{"scope": "workspace/main", "title": "test"}}}}),

    # forward proxy — params denied
    "forward_tools_call_params_name_no_args_denied": post_jsonrpc("tools/call", {{"name": "blocked_action"}}),
    "forward_tools_call_params_name_with_args_denied": post_jsonrpc("tools/call", {{"name": "blocked_action", "arguments": {{"reason": "test"}}}}),

    # forward proxy — batch: all requests allowed
    "forward_batch_all_allowed": post_jsonrpc_batch([
        {{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}},
        {{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {{"name": "read_status"}}}},
    ]),

    # forward proxy — batch: one denied request causes full batch denial
    "forward_batch_one_denied": post_jsonrpc_batch([
        {{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}},
        {{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {{"name": "blocked_action"}}}},
    ]),

    # forward proxy — invalid JSON body fails closed before generic rules apply
    "forward_invalid_json_denied": post_invalid_json(),

    # CONNECT path — representative allowed and denied cases
    "connect_method_initialize_allowed": connect_jsonrpc_status("initialize", {{"protocolVersion": "2025-11-25", "capabilities": {{}}}}, "connect_method_initialize_allowed"),
    "connect_method_tools_list_allowed": connect_jsonrpc_status("tools/list", None, "connect_method_tools_list_allowed"),
    "connect_tools_call_params_name_no_args_allowed": connect_jsonrpc_status("tools/call", {{"name": "read_status"}}, "connect_tools_call_params_name_no_args_allowed"),
    "connect_tools_call_params_nested_args_allowed": connect_jsonrpc_status("tools/call", {{"name": "submit_report", "arguments": {{"scope": "workspace/main"}}}}, "connect_tools_call_params_nested_args_allowed"),
    "connect_tools_call_params_name_no_args_denied": connect_jsonrpc_status("tools/call", {{"name": "blocked_action"}}, "connect_tools_call_params_name_no_args_denied"),
    "connect_tools_call_params_name_with_args_denied": connect_jsonrpc_status("tools/call", {{"name": "blocked_action", "arguments": {{"reason": "test"}}}}, "connect_tools_call_params_name_with_args_denied"),
}}
results.update(DETAILS)
print(json.dumps(results, sort_keys=True))
"#,
        host = server.host,
        port = server.port,
    );

    let guard = SandboxGuard::create(&["--policy", &policy_path, "--", "python3", "-c", &script])
        .await
        .expect("sandbox create");

    for (key, expected) in [
        // forward proxy — allowed
        ("forward_method_initialize_allowed", 200),
        ("forward_method_tools_list_allowed", 200),
        ("forward_tools_call_params_name_no_args_allowed", 200),
        ("forward_tools_call_params_nested_args_allowed", 200),
        // forward proxy — params denied
        ("forward_tools_call_params_name_no_args_denied", 403),
        ("forward_tools_call_params_name_with_args_denied", 403),
        // forward proxy — batch
        ("forward_batch_all_allowed", 200),
        ("forward_batch_one_denied", 403),
        // forward proxy — parse error
        ("forward_invalid_json_denied", 403),
        // CONNECT path — allowed
        ("connect_method_initialize_allowed", 200),
        ("connect_method_tools_list_allowed", 200),
        ("connect_tools_call_params_name_no_args_allowed", 200),
        ("connect_tools_call_params_nested_args_allowed", 200),
        // CONNECT path — params denied
        ("connect_tools_call_params_name_no_args_denied", 403),
        ("connect_tools_call_params_name_with_args_denied", 403),
    ] {
        let expected_fragment = format!(r#""{key}": {expected}"#);
        assert!(
            guard.create_output.contains(&expected_fragment),
            "expected {key}={expected}, got:\n{}",
            guard.create_output
        );
    }
}
