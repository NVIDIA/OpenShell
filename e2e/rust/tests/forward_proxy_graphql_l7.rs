// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! E2E tests for GraphQL L7 inspection across both proxy entry points.
//!
//! The upstream server deliberately does not implement GraphQL. `OpenShell`
//! parses and enforces GraphQL before forwarding, so any HTTP server that
//! accepts POST /graphql is enough to prove allowed requests reach upstream
//! and denied requests are stopped by the sandbox proxy.

#![cfg(feature = "e2e")]

use std::io::Write;

use openshell_e2e::harness::container::ContainerHttpServer;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;

const TEST_SERVER_ALIAS: &str = "graphql-l7.openshell.test";

async fn start_test_server() -> Result<ContainerHttpServer, String> {
    let script = r#"from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def read_chunked(self):
        while True:
            size_line = self.rfile.readline()
            if not size_line:
                return
            size = int(size_line.split(b";", 1)[0].strip(), 16)
            if size == 0:
                while self.rfile.readline().strip():
                    pass
                return
            self.rfile.read(size)
            self.rfile.read(2)
    def do_GET(self):
        if self.path == "/" or self.path.startswith("/graphql?"):
            self.send_response(200)
        else:
            self.send_response(418)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')
    def do_POST(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            self.read_chunked()
        else:
            _ = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')
    def log_message(self, format, *args):
        pass

HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
"#;

    ContainerHttpServer::start_python(TEST_SERVER_ALIAS, script).await
}

fn write_graphql_policy(host: &str, port: u16) -> Result<NamedTempFile, String> {
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
  test_graphql_l7:
    name: test_graphql_l7
    endpoints:
      - host: {host}
        port: {port}
        protocol: graphql
        enforcement: enforce
        persisted_queries: allow_registered
        graphql_persisted_queries:
          abc123:
            operation_type: query
            operation_name: Viewer
            fields: [viewer]
        allowed_ips:
          - "10.0.0.0/8"
          - "172.0.0.0/8"
          - "192.168.0.0/16"
          - "fc00::/7"
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
async fn graphql_l7_enforces_allow_and_deny_rules_on_forward_and_connect_paths() {
    let server = start_test_server().await.expect("start test server");
    let policy = write_graphql_policy(&server.host, server.port).expect("write custom policy");
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

QUERY_VIEWER = "query Viewer {{ viewer {{ login }} }}"
QUERY_REPOSITORY = "query Repo {{ repository(owner:\"o\", name:\"r\") {{ id }} }}"
MUTATION_CREATE = "mutation Create {{ createIssue(input:{{repositoryId:\"r\", title:\"t\", body:\"b\"}}) {{ issue {{ id }} }} }}"
MUTATION_DELETE = "mutation Delete {{ deleteRepository(input:{{repositoryId:\"r\"}}) {{ clientMutationId }} }}"

def forward_status(query):
    body = json.dumps({{"query": query}}).encode()
    request = urllib.request.Request(
        f"http://{{HOST}}:{{PORT}}/graphql",
        data=body,
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

def forward_get_status(query):
    encoded = urllib.parse.urlencode({{"query": query}})
    request = urllib.request.Request(
        f"http://{{HOST}}:{{PORT}}/graphql?{{encoded}}",
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        error.read()
        return error.code

def forward_duplicate_get_status():
    safe = urllib.parse.quote_plus(QUERY_VIEWER)
    unsafe = urllib.parse.quote_plus(MUTATION_DELETE)
    request = urllib.request.Request(
        f"http://{{HOST}}:{{PORT}}/graphql?query={{safe}}&query={{unsafe}}",
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        error.read()
        return error.code

def forward_persisted_get_status(hash_value):
    extensions = json.dumps({{"persistedQuery": {{"version": 1, "sha256Hash": hash_value}}}})
    encoded = urllib.parse.urlencode({{"operationName": "Viewer", "extensions": extensions}})
    request = urllib.request.Request(
        f"http://{{HOST}}:{{PORT}}/graphql?{{encoded}}",
        method="GET",
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

def forward_proxy_parts():
    return proxy_parts("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy")

def connect_proxy_parts():
    return proxy_parts("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy")

def forward_chunked_status(query):
    proxy_host, proxy_port = forward_proxy_parts()
    target = f"{{HOST}}:{{PORT}}"
    body = json.dumps({{"query": query}}).encode()
    chunk = f"{{len(body):x}}\r\n".encode() + body + b"\r\n0\r\n\r\n"

    with socket.create_connection((proxy_host, proxy_port), timeout=15) as sock:
        request = (
            f"POST http://{{target}}/graphql HTTP/1.1\r\n"
            f"Host: {{target}}\r\n"
            f"Content-Type: application/json\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + chunk
        sock.sendall(request)
        response, body = read_response(sock)
        DETAILS["forward_chunked_query_allowed_detail"] = body.decode(errors="replace")
        return status_code(response, "forward_chunked_response")

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
    proxy_host, proxy_port = connect_proxy_parts()
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

def connect_status(query, label):
    target = f"{{HOST}}:{{PORT}}"
    body = json.dumps({{"query": query}}).encode()

    request = (
        f"POST /graphql HTTP/1.1\r\n"
        f"Host: {{target}}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {{len(body)}}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + body
    return connect_http_status(label, request)

def connect_get_status(query, label):
    target = f"{{HOST}}:{{PORT}}"
    encoded = urllib.parse.urlencode({{"query": query}})

    request = (
        f"GET /graphql?{{encoded}} HTTP/1.1\r\n"
        f"Host: {{target}}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    return connect_http_status(label, request)

def connect_duplicate_get_status():
    target = f"{{HOST}}:{{PORT}}"
    safe = urllib.parse.quote_plus(QUERY_VIEWER)
    unsafe = urllib.parse.quote_plus(MUTATION_DELETE)

    request = (
        f"GET /graphql?query={{safe}}&query={{unsafe}} HTTP/1.1\r\n"
        f"Host: {{target}}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    return connect_http_status("connect_duplicate_get_denied", request)

def connect_persisted_get_status(hash_value, label):
    target = f"{{HOST}}:{{PORT}}"
    extensions = json.dumps({{"persistedQuery": {{"version": 1, "sha256Hash": hash_value}}}})
    encoded = urllib.parse.urlencode({{"operationName": "Viewer", "extensions": extensions}})

    request = (
        f"GET /graphql?{{encoded}} HTTP/1.1\r\n"
        f"Host: {{target}}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    return connect_http_status(label, request)

def connect_chunked_status(query):
    target = f"{{HOST}}:{{PORT}}"
    body = json.dumps({{"query": query}}).encode()
    chunk = f"{{len(body):x}}\r\n".encode() + body + b"\r\n0\r\n\r\n"

    request = (
        f"POST /graphql HTTP/1.1\r\n"
        f"Host: {{target}}\r\n"
        f"Content-Type: application/json\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + chunk
    return connect_http_status("connect_chunked_query_allowed", request)

results = {{
    "forward_query_allowed": forward_status(QUERY_VIEWER),
    "forward_get_query_allowed": forward_get_status(QUERY_VIEWER),
    "forward_duplicate_get_denied": forward_duplicate_get_status(),
    "forward_persisted_get_allowed": forward_persisted_get_status("abc123"),
    "forward_unregistered_persisted_get_denied": forward_persisted_get_status("missing"),
    "forward_chunked_query_allowed": forward_chunked_status(QUERY_VIEWER),
    "forward_unlisted_field_denied": forward_status(QUERY_REPOSITORY),
    "forward_mutation_allowed": forward_status(MUTATION_CREATE),
    "forward_deny_rule_denied": forward_status(MUTATION_DELETE),
    "connect_query_allowed": connect_status(QUERY_VIEWER, "connect_query_allowed"),
    "connect_get_query_allowed": connect_get_status(QUERY_VIEWER, "connect_get_query_allowed"),
    "connect_duplicate_get_denied": connect_duplicate_get_status(),
    "connect_persisted_get_allowed": connect_persisted_get_status("abc123", "connect_persisted_get_allowed"),
    "connect_unregistered_persisted_get_denied": connect_persisted_get_status("missing", "connect_unregistered_persisted_get_denied"),
    "connect_chunked_query_allowed": connect_chunked_status(QUERY_VIEWER),
    "connect_unlisted_field_denied": connect_status(QUERY_REPOSITORY, "connect_unlisted_field_denied"),
    "connect_mutation_allowed": connect_status(MUTATION_CREATE, "connect_mutation_allowed"),
    "connect_deny_rule_denied": connect_status(MUTATION_DELETE, "connect_deny_rule_denied"),
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
        ("forward_query_allowed", 200),
        ("forward_get_query_allowed", 200),
        ("forward_duplicate_get_denied", 403),
        ("forward_persisted_get_allowed", 200),
        ("forward_unregistered_persisted_get_denied", 403),
        ("forward_chunked_query_allowed", 200),
        ("forward_unlisted_field_denied", 403),
        ("forward_mutation_allowed", 200),
        ("forward_deny_rule_denied", 403),
        ("connect_query_allowed", 200),
        ("connect_get_query_allowed", 200),
        ("connect_duplicate_get_denied", 403),
        ("connect_persisted_get_allowed", 200),
        ("connect_unregistered_persisted_get_denied", 403),
        ("connect_chunked_query_allowed", 200),
        ("connect_unlisted_field_denied", 403),
        ("connect_mutation_allowed", 200),
        ("connect_deny_rule_denied", 403),
    ] {
        let expected_fragment = format!(r#""{key}": {expected}"#);
        assert!(
            guard.create_output.contains(&expected_fragment),
            "expected {key}={expected}, got:\n{}",
            guard.create_output
        );
    }
}
