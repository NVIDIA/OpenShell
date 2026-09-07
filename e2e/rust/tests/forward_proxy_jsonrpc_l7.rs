// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! E2E tests for JSON-RPC L7 inspection across both proxy entry points.
//!
//! The upstream server deliberately does not implement JSON-RPC. `OpenShell`
//! parses and enforces JSON-RPC before forwarding, so any HTTP server that
//! accepts POST /rpc is enough to prove allowed requests reach upstream
//! and denied requests are stopped by the sandbox proxy.

#![cfg(feature = "e2e")]

use std::io::Write;

use openshell_e2e::harness::container::ContainerHttpServer;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;

const RULES_TEST_SERVER_ALIAS: &str = "jsonrpc-l7-rules.openshell.test";
const AUDIT_TEST_SERVER_ALIAS: &str = "jsonrpc-l7-audit.openshell.test";

async fn start_test_server(alias: &str) -> Result<ContainerHttpServer, String> {
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

    ContainerHttpServer::start_python(alias, script).await
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
        path: /rpc
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
              method: initialize
          - allow:
              method: tools/list
          - allow:
              method: tools/call
        deny_rules:
          - method: tools/delete
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

fn write_jsonrpc_default_audit_policy(host: &str, port: u16) -> Result<NamedTempFile, String> {
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
  test_jsonrpc_l7_audit:
    name: test_jsonrpc_l7_audit
    endpoints:
      - host: {host}
        port: {port}
        path: /rpc
        protocol: json-rpc
        allowed_ips:
          - "10.0.0.0/8"
          - "100.64.0.0/10"
          - "172.0.0.0/8"
          - "198.18.0.0/15"
          - "192.168.0.0/16"
          - "fc00::/7"
        json_rpc:
          max_body_bytes: 65536
        rules:
          - allow:
              method: initialize
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
async fn jsonrpc_l7_enforces_method_rules_on_forward_and_connect_paths() {
    let server = start_test_server(RULES_TEST_SERVER_ALIAS)
        .await
        .expect("start test server");
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
DETAILS = {{
    "debug_target": {{"host": HOST, "port": PORT}},
    "debug_proxy_env": {{
        "http_proxy": os.environ.get("http_proxy"),
        "https_proxy": os.environ.get("https_proxy"),
        "HTTP_PROXY": os.environ.get("HTTP_PROXY"),
        "HTTPS_PROXY": os.environ.get("HTTPS_PROXY"),
        "NO_PROXY": os.environ.get("NO_PROXY"),
        "no_proxy": os.environ.get("no_proxy"),
    }},
}}

def text(data):
    return data.decode(errors="replace")

def selected_headers(headers):
    return {{
        key.lower(): value
        for key, value in headers.items()
        if key.lower() in ("content-type", "content-length", "server")
    }}

def record_http_error(label, error, request_body):
    response_body = error.read()
    DETAILS[f"{{label}}_request"] = request_body
    DETAILS[f"{{label}}_response"] = {{
        "status": error.code,
        "reason": str(error.reason),
        "headers": selected_headers(error.headers),
        "body": text(response_body),
    }}
    return error.code

def post_jsonrpc(label, method, params=None, req_id=1):
    body = {{"jsonrpc": "2.0", "id": req_id, "method": method}}
    if params is not None:
        body["params"] = params
    encoded = json.dumps(body).encode()
    request = urllib.request.Request(
        f"http://{{HOST}}:{{PORT}}/rpc",
        data=encoded,
        headers={{"Content-Type": "application/json"}},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        return record_http_error(label, error, body)

def post_jsonrpc_batch(label, requests):
    encoded = json.dumps(requests).encode()
    request = urllib.request.Request(
        f"http://{{HOST}}:{{PORT}}/rpc",
        data=encoded,
        headers={{"Content-Type": "application/json"}},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        return record_http_error(label, error, requests)

def post_invalid_json(label):
    encoded = b"not valid json {{"
    request = urllib.request.Request(
        f"http://{{HOST}}:{{PORT}}/rpc",
        data=encoded,
        headers={{"Content-Type": "application/json", "Content-Length": str(len(encoded))}},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        return record_http_error(label, error, text(encoded))

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

def record_raw_response(label, response, body=b""):
    code = status_code(response, label)
    if code != 200:
        DETAILS[f"{{label}}_raw"] = text(response)
        if body:
            DETAILS[f"{{label}}_body"] = text(body)
    return code

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
                connect_code = record_raw_response(f"{{label}}_connect", connect_response)
                if connect_code != 200:
                    return connect_code
                sock.sendall(request)
                sock.shutdown(socket.SHUT_WR)
                response, body = read_response(sock)
                return record_raw_response(f"{{label}}_response", response, body)
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
        f"POST /rpc HTTP/1.1\r\n"
        f"Host: {{target}}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {{len(encoded)}}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + encoded
    return connect_http_status(label, request)

results = {{
    # forward proxy — method-only allow rules
    "forward_method_initialize_allowed": post_jsonrpc("forward_method_initialize_allowed", "initialize", {{"protocolVersion": "2025-11-25", "capabilities": {{}}}}),
    "forward_method_tools_list_allowed": post_jsonrpc("forward_method_tools_list_allowed", "tools/list"),

    # forward proxy — method allow/deny rules
    "forward_method_tools_call_allowed": post_jsonrpc("forward_method_tools_call_allowed", "tools/call", {{"name": "read_status"}}),
    "forward_method_tools_call_with_unmatched_params_allowed": post_jsonrpc("forward_method_tools_call_with_unmatched_params_allowed", "tools/call", {{"name": "blocked_action", "arguments": {{"scope": "ignored"}}}}),
    "forward_method_tools_delete_denied": post_jsonrpc("forward_method_tools_delete_denied", "tools/delete", {{"name": "purge_cache"}}),

    # forward proxy — batch: all requests allowed
    "forward_batch_all_allowed": post_jsonrpc_batch("forward_batch_all_allowed", [
        {{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}},
        {{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {{"name": "read_status"}}}},
    ]),

    # forward proxy — batch: one denied request causes full batch denial
    "forward_batch_one_denied": post_jsonrpc_batch("forward_batch_one_denied", [
        {{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}},
        {{"jsonrpc": "2.0", "id": 2, "method": "tools/delete", "params": {{"name": "purge_cache"}}}},
    ]),

    # forward proxy — invalid JSON body fails closed before generic rules apply
    "forward_invalid_json_denied": post_invalid_json("forward_invalid_json_denied"),

    # CONNECT path — representative allowed and denied cases
    "connect_method_initialize_allowed": connect_jsonrpc_status("initialize", {{"protocolVersion": "2025-11-25", "capabilities": {{}}}}, "connect_method_initialize_allowed"),
    "connect_method_tools_list_allowed": connect_jsonrpc_status("tools/list", None, "connect_method_tools_list_allowed"),
    "connect_method_tools_call_allowed": connect_jsonrpc_status("tools/call", {{"name": "read_status"}}, "connect_method_tools_call_allowed"),
    "connect_method_tools_call_with_unmatched_params_allowed": connect_jsonrpc_status("tools/call", {{"name": "blocked_action", "arguments": {{"scope": "ignored"}}}}, "connect_method_tools_call_with_unmatched_params_allowed"),
    "connect_method_tools_delete_denied": connect_jsonrpc_status("tools/delete", {{"name": "purge_cache"}}, "connect_method_tools_delete_denied"),
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
        ("forward_method_tools_call_allowed", 200),
        (
            "forward_method_tools_call_with_unmatched_params_allowed",
            200,
        ),
        // forward proxy — method denied
        ("forward_method_tools_delete_denied", 403),
        // forward proxy — batch
        ("forward_batch_all_allowed", 200),
        ("forward_batch_one_denied", 403),
        // forward proxy — parse error
        ("forward_invalid_json_denied", 403),
        // CONNECT path — allowed
        ("connect_method_initialize_allowed", 200),
        ("connect_method_tools_list_allowed", 200),
        ("connect_method_tools_call_allowed", 200),
        (
            "connect_method_tools_call_with_unmatched_params_allowed",
            200,
        ),
        // CONNECT path — method denied
        ("connect_method_tools_delete_denied", 403),
    ] {
        let expected_fragment = format!(r#""{key}": {expected}"#);
        assert!(
            guard.create_output.contains(&expected_fragment),
            "expected {key}={expected}, got:\n{}",
            guard.create_output
        );
    }
}

#[tokio::test]
async fn jsonrpc_forward_proxy_hard_denies_response_frames_in_default_audit_mode() {
    let server = start_test_server(AUDIT_TEST_SERVER_ALIAS)
        .await
        .expect("start test server");
    let policy =
        write_jsonrpc_default_audit_policy(&server.host, server.port).expect("write custom policy");
    let policy_path = policy
        .path()
        .to_str()
        .expect("temp policy path should be utf-8")
        .to_string();

    let script = format!(
        r#"
import json
import urllib.error
import urllib.request

HOST = {host:?}
PORT = {port}

def post_jsonrpc(body):
    encoded = json.dumps(body).encode()
    request = urllib.request.Request(
        f"http://{{HOST}}:{{PORT}}/rpc",
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

results = {{
    "forward_unknown_method_audited": post_jsonrpc({{"jsonrpc": "2.0", "id": 1, "method": "unknown/method"}}),
    "forward_response_frame_hard_denied": post_jsonrpc({{"jsonrpc": "2.0", "id": 1, "result": {{}}}}),
}}
print(json.dumps(results, sort_keys=True))
"#,
        host = server.host,
        port = server.port,
    );

    let guard = SandboxGuard::create(&["--policy", &policy_path, "--", "python3", "-c", &script])
        .await
        .expect("sandbox create");

    for (key, expected) in [
        ("forward_unknown_method_audited", 200),
        ("forward_response_frame_hard_denied", 403),
    ] {
        let expected_fragment = format!(r#""{key}": {expected}"#);
        assert!(
            guard.create_output.contains(&expected_fragment),
            "expected {key}={expected}, got:\n{}",
            guard.create_output
        );
    }
}
